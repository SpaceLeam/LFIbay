"""
LFIBay - Config Module
Configuration settings and constants
"""

# Default request delays (seconds)
DEFAULT_MIN_DELAY = 1
DEFAULT_MAX_DELAY = 3

# Request timeout (seconds)
REQUEST_TIMEOUT = 15

# Default headers
DEFAULT_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}

# Detection patterns for LFI
DETECTION_PATTERNS = {
    # Linux system files
    'linux_passwd': r'root:x:\d+:\d+',
    'linux_shadow': r'root:\$',
    'linux_group': r'root:x:0:',
    
    # Windows system files
    'windows_ini': r'\[extensions\]',
    'windows_hosts': r'127\.0\.0\.1\s+localhost',
    
    # PHP code
    'php_code': r'<\?php',
    
    # Configuration files
    'config_db': r'(mysql|database|db).*password',
}

# Error message patterns indicating LFI
ERROR_PATTERNS = [
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

# WAF signatures
WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf_clearance'],
    'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
    'Akamai': ['akamai', 'x-akamai'],
    'Imperva': ['incapsula', 'visid_incap', '_incap'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'Wordfence': ['wordfence'],
    'Sucuri': ['sucuri', 'x-sucuri'],
    'Barracuda': ['barra_counter_session'],
    'F5 BIG-IP': ['bigip', 'f5'],
}

# Payload files
PAYLOAD_FILES = {
    'path_traversal': 'payloads/path_traversal.txt',
    'php_wrappers': 'payloads/php_wrappers.txt',
    'null_bytes': 'payloads/null_bytes.txt',
    'double_encoding': 'payloads/double_encoding.txt'
}

# Report settings
REPORT_DIR = 'output/reports'
RESPONSE_PREVIEW_LENGTH = 500  # Characters to include in report

# Baseline anomaly thresholds
SIZE_ANOMALY_THRESHOLD = 30  # Percentage change
TIMING_ANOMALY_THRESHOLD = 10  # Seconds

# Selenium settings
SELENIUM_IMPLICIT_WAIT = 10  # Seconds
SELENIUM_PAGE_LOAD_TIMEOUT = 30  # Seconds

# Common file upload field names
COMMON_FILE_FIELDS = [
    'file',
    'upload',
    'attachment',
    'document',
    'image',
    'photo',
    'avatar',
    'userfile',
    'uploadfile'
]
