"""
LFIBay - Analyzer Module
Response analysis and LFI detection logic
"""

import re


def baseline_request(url, cookies, headers, form_info, scanner):
    """
    Make a normal upload to establish baseline metrics
    Args:
        url: Target URL
        cookies: Session cookies
        headers: Request headers
        form_info: Form information
        scanner: Scanner module reference
    Returns: Dictionary with baseline metrics
    """
    try:
        # Use a benign payload
        benign_payload = "normal_test_file.txt"
        
        # Find file field
        file_field = None
        for field_name, field_info in form_info['fields'].items():
            if field_info['type'] == 'file':
                file_field = field_name
                break
        
        if not file_field:
            file_field = 'file'
        
        # Prepare form data
        form_data = {}
        for field_name, field_info in form_info['fields'].items():
            if field_name != file_field and field_info['type'] not in ['file', 'submit', 'button']:
                form_data[field_name] = field_info.get('value', '')
        
        # Test benign payload
        result = scanner.test_payload(
            form_info['action'],
            benign_payload,
            file_field,
            cookies,
            headers,
            form_data
        )
        
        return {
            'content_length': result['content_length'],
            'response_time': result['response_time'],
            'status_code': result['status_code']
        }
        
    except Exception as e:
        return {
            'content_length': 0,
            'response_time': 0,
            'status_code': 200
        }


def analyze_response(response, payload, baseline=None):
    """
    Detect if LFI was successful using multiple detection methods
    Args:
        response: Response dictionary from test_payload
        payload: The payload that was tested
        baseline: Baseline metrics (optional)
    Returns: Dictionary with detection results
    """
    detection = {
        'vulnerable': False,
        'confidence': 'none',  # none, low, medium, high
        'evidence': [],
        'method': []
    }
    
    content = response.get('content', '').lower()
    status_code = response.get('status_code', 0)
    content_length = response.get('content_length', 0)
    response_time = response.get('response_time', 0)
    
    # Skip if error
    if 'error' in response:
        return detection
    
    # 1. Check for PHP/File inclusion error messages
    error_patterns = [
        r'failed to open stream',
        r'include\(\)',
        r'require\(\)',
        r'require_once\(\)',
        r'include_once\(\)',
        r'failed opening',
        r'no such file or directory',
        r'permission denied',
        r'warning:.*include',
        r'fatal error:.*include'
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            detection['vulnerable'] = True
            detection['evidence'].append(f"Error pattern found: {pattern}")
            detection['method'].append('error_pattern')
            detection['confidence'] = 'high'
    
    # 2. Check for system file content patterns
    system_file_patterns = {
        'linux_passwd': r'root:x:\d+:\d+',
        'linux_shadow': r'root:\$',
        'linux_group': r'root:x:0:',
        'windows_ini': r'\[extensions\]',
        'windows_hosts': r'127\.0\.0\.1\s+localhost',
        'php_code': r'<\?php',
        'config_files': r'(mysql|database|db).*password',
    }
    
    for pattern_name, pattern in system_file_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            detection['vulnerable'] = True
            detection['evidence'].append(f"System file pattern found: {pattern_name}")
            detection['method'].append('content_pattern')
            detection['confidence'] = 'high'
    
    # 3. Check for base64 encoded content (php://filter wrappers)
    if 'php://filter' in payload.lower():
        # Look for base64 content (long strings of base64 characters)
        base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
        if re.search(base64_pattern, content):
            detection['vulnerable'] = True
            detection['evidence'].append("Base64 encoded content detected (php://filter)")
            detection['method'].append('base64_content')
            detection['confidence'] = 'high'
    
    # 4. Response size anomaly detection
    if baseline and baseline['content_length'] > 0:
        size_diff_percent = abs(content_length - baseline['content_length']) / baseline['content_length'] * 100
        
        # If response is significantly different (>30% change)
        if size_diff_percent > 30:
            if content_length > baseline['content_length']:
                detection['evidence'].append(f"Response size increased by {size_diff_percent:.1f}%")
                if not detection['vulnerable']:
                    detection['vulnerable'] = True
                    detection['confidence'] = 'medium'
                detection['method'].append('size_anomaly')
    
    # 5. Timing anomaly (for wrapper timeouts)
    if response_time > 10:  # 10 seconds
        detection['evidence'].append(f"Slow response time: {response_time:.2f}s (possible wrapper execution)")
        if not detection['vulnerable']:
            detection['vulnerable'] = True
            detection['confidence'] = 'low'
        detection['method'].append('timing_anomaly')
    
    # 6. Check for directory traversal success indicators
    if '../' in payload or '..\\' in payload:
        # Look for directory listing patterns
        dir_patterns = [
            r'drwxr-xr-x',  # Unix permissions
            r'total \d+',    # ls output
            r'\d{2}:\d{2}',  # Time stamps
        ]
        
        for pattern in dir_patterns:
            if re.search(pattern, content):
                detection['vulnerable'] = True
                detection['evidence'].append("Directory listing pattern detected")
                detection['method'].append('directory_listing')
                detection['confidence'] = 'high'
    
    # 7. Check for null byte success (file extension bypass)
    if '%00' in payload or '\\x00' in payload:
        # If we got content that looks like it bypassed extension check
        if len(content) > 100 and status_code == 200:
            detection['evidence'].append("Possible null byte injection success")
            if not detection['vulnerable']:
                detection['vulnerable'] = True
                detection['confidence'] = 'medium'
            detection['method'].append('null_byte')
    
    return detection


def generate_findings(results, baseline=None):
    """
    Compile all successful payloads with evidence
    Args:
        results: List of response dictionaries
        baseline: Baseline metrics
    Returns: List of findings
    """
    findings = []
    
    for result in results:
        payload = result.get('payload', '')
        detection = analyze_response(result, payload, baseline)
        
        if detection['vulnerable']:
            finding = {
                'payload': payload,
                'confidence': detection['confidence'],
                'evidence': detection['evidence'],
                'detection_methods': detection['method'],
                'status_code': result.get('status_code'),
                'response_time': result.get('response_time'),
                'content_length': result.get('content_length'),
                'response_preview': result.get('content', '')[:500]  # First 500 chars
            }
            findings.append(finding)
    
    # Sort by confidence (high > medium > low)
    confidence_order = {'high': 3, 'medium': 2, 'low': 1, 'none': 0}
    findings.sort(key=lambda x: confidence_order.get(x['confidence'], 0), reverse=True)
    
    return findings
