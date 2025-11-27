"""
LFIBay - Analyzer Module
Response analysis and LFI detection logic
Enhanced with entropy analysis, similarity checking, and header anomaly detection
"""

import re
import math
import hashlib
from difflib import SequenceMatcher


def calculate_content_hash(content):
    """
    Calculate SHA256 hash of response content
    Args:
        content: String content to hash
    Returns: SHA256 hex digest or None if content is empty
    """
    if not content:
        return None
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def are_responses_identical(response1, response2):
    """
    Check if two responses are identical using content hash comparison
    Args:
        response1: First response dictionary
        response2: Second response dictionary
    Returns: True if responses have identical content, False otherwise
    """
    content1 = response1.get('content', '')
    content2 = response2.get('content', '')
    
    hash1 = calculate_content_hash(content1)
    hash2 = calculate_content_hash(content2)
    
    if hash1 and hash2:
        return hash1 == hash2
    
    return False


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
    
    # 5. Enhanced timing detection with threshold
    if response_time > 5:  # 5 seconds (lowered threshold)
        detection['evidence'].append(f"Slow response time: {response_time:.2f}s (possible wrapper execution)")
        if not detection['vulnerable']:
            detection['vulnerable'] = True
            detection['confidence'] = 'medium' if response_time > 10 else 'low'
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
    if '%00' in payload or '\x00' in payload:
        # More strict check - verify actual bypass occurred
        # Look for actual file content patterns, not just response size
        if len(content) > 100 and status_code == 200:
            # Check if response contains actual file content indicators
            has_file_content = any([
                re.search(pattern, content, re.IGNORECASE) 
                for pattern in error_patterns + list(system_file_patterns.values())
            ])
            
            if has_file_content:
                detection['evidence'].append("Null byte injection bypassed extension check")
                if not detection['vulnerable']:
                    detection['vulnerable'] = True
                    detection['confidence'] = 'high'
                detection['method'].append('null_byte')
            else:
                # Just size anomaly, lower confidence
                detection['evidence'].append("Possible null byte effect (low confidence)")
                if not detection['vulnerable']:
                    detection['vulnerable'] = True
                    detection['confidence'] = 'low'
                detection['method'].append('null_byte_maybe')
    
    # 8. Entropy analysis for base64 content
    entropy = calculate_entropy(content)
    if entropy > 5.0 and len(content) > 200:  # High entropy suggests base64/compressed data
        detection['evidence'].append(f"High content entropy: {entropy:.2f} (possible base64/encoded data)")
        if 'base64' not in [m for m in detection['method']]:
            if not detection['vulnerable']:
                detection['vulnerable'] = True
                detection['confidence'] = 'medium'
            detection['method'].append('entropy_analysis')
    
    # 9. Header anomaly detection
    headers = response.get('headers', {})
    if headers:
        header_anomalies = detect_header_anomalies(headers, baseline)
        if header_anomalies:
            detection['evidence'].extend([f"Header anomaly: {a}" for a in header_anomalies])
            if not detection['vulnerable']:
                detection['vulnerable'] = True
                detection['confidence'] = 'low'
            detection['method'].append('header_anomaly')
    
    # 10. Calculate final confidence score based on all detection methods
    if detection['vulnerable']:
        detection['confidence'] = calculate_confidence_score(
            detection['method'],
            detection['evidence'],
            content,
            baseline
        )
    
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


def calculate_entropy(data):
    """
    Calculate Shannon entropy of data
    Args:
        data: String data
    Returns: Float entropy value
    """
    if not data:
        return 0.0
    
    entropy = 0.0
    data_len = len(data)
    
    # Count character frequencies
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    for count in freq.values():
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
    
    return entropy


def compare_similarity(response1, response2):
    """
    Compare similarity between two responses
    Args:
        response1: First response dictionary
        response2: Second response dictionary
    Returns: Float similarity score (0.0 to 1.0)
    """
    content1 = response1.get('content', '')
    content2 = response2.get('content', '')
    
    if not content1 or not content2:
        return 0.0
    
    # Use difflib SequenceMatcher
    similarity = SequenceMatcher(None, content1, content2).ratio()
    
    return similarity


def detect_header_anomalies(headers, baseline=None):
    """
    Detect anomalies in response headers (improved to reduce false positives)
    Args:
        headers: Response headers dictionary
        baseline: Baseline metrics (optional)
    Returns: List of detected anomalies
    """
    anomalies = []
    
    # Check for unusual Content-Type that suggests file read
    content_type = headers.get('Content-Type', '').lower()
    if content_type:
        # Only flag truly suspicious content types
        suspicious_types = ['application/octet-stream', 'application/binary']
        if any(susp in content_type for susp in suspicious_types):
            # But not if it's from a legitimate file upload response
            if 'download' not in headers.get('Content-Disposition', '').lower():
                anomalies.append(f"Suspicious Content-Type: {content_type}")
    
    # Check for X-Powered-By headers indicating PHP errors
    if 'X-Powered-By' in headers:
        powered_by = headers['X-Powered-By']
        # Only useful info, not an anomaly by itself
        pass
    
    # Check for error-indicating headers
    if headers.get('X-Error'):
        anomalies.append(f"Error header present: {headers['X-Error']}")
    
    return anomalies


def calculate_confidence_score(detection_methods, evidence_list, content='', baseline=None):
    """
    Calculate confidence score based on multiple factors
    Args:
        detection_methods: List of detection methods that triggered
        evidence_list: List of evidence strings
        content: Response content for additional analysis
        baseline: Baseline metrics for comparison
    Returns: String confidence level (high/medium/low/none)
    """
    score = 0
    
    # High-confidence detection methods (30 points each)
    high_confidence_methods = [
        'error_pattern',
        'content_pattern',
        'base64_content',
        'directory_listing'
    ]
    
    # Medium-confidence methods (15 points each)
    medium_confidence_methods = [
        'size_anomaly',
        'null_byte',
        'entropy_analysis'
    ]
    
    # Low-confidence methods (5 points each)
    low_confidence_methods = [
        'timing_anomaly',
        'header_anomaly',
        'similarity_check',
        'null_byte_maybe'
    ]
    
    # Score based on detection methods
    for method in detection_methods:
        if method in high_confidence_methods:
            score += 30
        elif method in medium_confidence_methods:
            score += 15
        elif method in low_confidence_methods:
            score += 5
    
    # Bonus for multiple methods (more methods = higher confidence)
    unique_methods = len(set(detection_methods))
    if unique_methods >= 3:
        score += 20
    elif unique_methods >= 2:
        score += 10
    
    # Evidence quality boost
    high_quality_evidence = [
        'root:x:',
        'failed to open stream',
        'include()',
        'require()',
        'base64'
    ]
    
    for evidence in evidence_list:
        if any(keyword in evidence.lower() for keyword in high_quality_evidence):
            score += 10
            break  # Only count once
    
    # Classify score
    if score >= 80:
        return 'high'
    elif score >= 50:
        return 'medium'
    elif score >= 30:
        return 'low'
    else:
        return 'none'


def analyze_response_advanced(response, payload, baseline=None, history=None):
    """
    Advanced analysis with historical comparison
    Args:
        response: Response dictionary from test_payload
        payload: The payload that was tested
        baseline: Baseline metrics (optional)
        history: List of previous responses for similarity checking
    Returns: Dictionary with detection results
    """
    # Start with standard analysis
    detection = analyze_response(response, payload, baseline)
    
    # Add similarity checking if we have history
    if history and len(history) > 0:
        similarities = []
        for hist_resp in history[-5:]:  # Check last 5 responses
            sim = compare_similarity(response, hist_resp)
            similarities.append(sim)
        
        avg_similarity = sum(similarities) / len(similarities)
        
        # If response is very different from recent responses
        if avg_similarity < 0.5:  # Less than 50% similar
            detection['evidence'].append(f"Response differs significantly from baseline (similarity: {avg_similarity:.2%})")
            if not detection['vulnerable']:
                detection['vulnerable'] = True
                detection['confidence'] = 'low'
            detection['method'].append('similarity_check')
    
    return detection
