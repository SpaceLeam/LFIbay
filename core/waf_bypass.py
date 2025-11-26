"""
LFIBay - WAF Bypass Module
WAF evasion techniques and stealth utilities
"""

import random
import time
import urllib.parse


# User-Agent pool for rotation
USER_AGENTS = [
    # Chrome on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    
    # Chrome on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    
    # Firefox on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    
    # Firefox on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    
    # Safari on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    
    # Chrome on Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    
    # Firefox on Linux
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    
    # Edge
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
]


def get_random_user_agent():
    """
    Get random User-Agent from pool
    Returns: User-Agent string
    """
    return random.choice(USER_AGENTS)


def add_random_delay(min_delay=1, max_delay=3):
    """
    Add random delay between requests
    Args:
        min_delay: Minimum delay in seconds
        max_delay: Maximum delay in seconds
    """
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)


def encode_payload(payload, technique='url'):
    """
    Encode payload using various techniques
    Args:
        payload: Original payload string
        technique: Encoding technique (url, double, unicode)
    Returns: Encoded payload
    """
    if technique == 'url':
        # Single URL encoding
        return urllib.parse.quote(payload)
    
    elif technique == 'double':
        # Double URL encoding
        encoded_once = urllib.parse.quote(payload)
        return urllib.parse.quote(encoded_once)
    
    elif technique == 'unicode':
        # Unicode encoding for backslashes
        return payload.replace('\\', '%5c').replace('/', '%2f')
    
    elif technique == 'mixed':
        # Mix of encoded and non-encoded characters
        result = ''
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result += urllib.parse.quote(char)
            else:
                result += char
        return result
    
    return payload


def add_junk_params(url):
    """
    Add dummy parameters to evade signature detection
    Args:
        url: Original URL
    Returns: URL with junk parameters
    """
    junk_params = [
        f'cache={random.randint(1000, 9999)}',
        f'ref={random.randint(1000, 9999)}',
        f'timestamp={int(time.time())}',
        f'rand={random.randint(10000, 99999)}',
        f'session={random.randint(1000, 9999)}',
    ]
    
    # Select 2-3 random junk params
    selected = random.sample(junk_params, random.randint(2, 3))
    
    # Check if URL already has params
    separator = '&' if '?' in url else '?'
    
    return url + separator + '&'.join(selected)


def generate_encoded_payloads(base_payloads):
    """
    Generate multiple encoded variations of base payloads
    Args:
        base_payloads: List of base payload strings
    Returns: List with original and encoded variations
    """
    all_payloads = []
    
    for payload in base_payloads:
        # Add original
        all_payloads.append(payload)
        
        # Add URL encoded version
        all_payloads.append(encode_payload(payload, 'url'))
        
        # Add double encoded version (for specific payloads)
        if '../' in payload or '..' in payload:
            all_payloads.append(encode_payload(payload, 'double'))
    
    return all_payloads


def evasion_headers():
    """
    Generate headers that may help bypass WAF
    Returns: Dictionary of headers
    """
    headers = {
        'X-Originating-IP': f'127.0.0.{random.randint(1, 254)}',
        'X-Forwarded-For': f'127.0.0.{random.randint(1, 254)}',
        'X-Remote-IP': f'127.0.0.{random.randint(1, 254)}',
        'X-Remote-Addr': f'127.0.0.{random.randint(1, 254)}',
    }
    
    # Randomly select 1-2 headers to use
    selected_keys = random.sample(list(headers.keys()), random.randint(1, 2))
    
    return {k: headers[k] for k in selected_keys}


def should_use_evasion(waf_detected=False):
    """
    Determine if evasion techniques should be used
    Args:
        waf_detected: Boolean indicating if WAF was detected
    Returns: Boolean
    """
    if waf_detected:
        return True
    
    # 30% chance to use evasion even without WAF detection
    return random.random() < 0.3
