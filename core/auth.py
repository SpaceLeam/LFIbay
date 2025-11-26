"""
LFIBay - Authentication Module
Handles Selenium browser automation, cookie extraction, and WAF detection
"""

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import time

# Global browser instance
browser = None

def start_selenium():
    """
    Launch Chrome browser with stealth options
    Returns: WebDriver instance
    """
    global browser
    
    options = Options()
    # Stealth options
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)
    
    # User preferences
    options.add_argument('--start-maximized')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--no-sandbox')
    
    try:
        browser = webdriver.Chrome(options=options)
        # Override navigator.webdriver flag
        browser.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        return browser
    except Exception as e:
        raise Exception(f"Failed to start browser: {str(e)}")


def manual_login_wait(url):
    """
    Open URL and wait for user to login manually
    Args:
        url: Login page URL
    Returns: True when user confirms login complete
    """
    global browser
    
    if not browser:
        raise Exception("Browser not initialized. Call start_selenium() first.")
    
    browser.get(url)
    print(f"[*] Browser opened at: {url}")
    print("[*] Please login manually in the browser window")
    input("[*] Press Enter after you've logged in...")
    
    return True


def extract_cookies():
    """
    Extract all cookies from current browser session
    Returns: Dictionary of cookies
    """
    global browser
    
    if not browser:
        raise Exception("Browser not initialized.")
    
    cookies = browser.get_cookies()
    cookie_dict = {}
    
    for cookie in cookies:
        cookie_dict[cookie['name']] = cookie['value']
    
    return cookie_dict


def extract_headers():
    """
    Get User-Agent and other headers from browser
    Returns: Dictionary with headers
    """
    global browser
    
    if not browser:
        raise Exception("Browser not initialized.")
    
    user_agent = browser.execute_script("return navigator.userAgent;")
    
    headers = {
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    return headers


def detect_waf(url):
    """
    Test if WAF exists by checking common WAF signatures
    Args:
        url: URL to test
    Returns: Tuple (waf_detected: bool, waf_name: str or None)
    """
    global browser
    
    if not browser:
        raise Exception("Browser not initialized.")
    
    # WAF signatures to check in headers and page source
    waf_signatures = {
        'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
        'Akamai': ['akamai', 'x-akamai'],
        'Imperva': ['incapsula', 'visid_incap'],
        'ModSecurity': ['mod_security', 'modsecurity'],
        'Wordfence': ['wordfence'],
        'Sucuri': ['sucuri', 'x-sucuri']
    }
    
    try:
        browser.get(url)
        time.sleep(2)
        
        # Check page source
        page_source = browser.page_source.lower()
        
        # Check for WAF signatures
        for waf_name, signatures in waf_signatures.items():
            for signature in signatures:
                if signature in page_source:
                    return True, waf_name
        
        # Check cookies for WAF signatures
        cookies = browser.get_cookies()
        cookie_names = [cookie['name'].lower() for cookie in cookies]
        
        for waf_name, signatures in waf_signatures.items():
            for signature in signatures:
                if any(signature in cookie_name for cookie_name in cookie_names):
                    return True, waf_name
        
        return False, None
        
    except Exception as e:
        print(f"[!] Error during WAF detection: {str(e)}")
        return False, None


def close_browser():
    """
    Clean shutdown of browser
    """
    global browser
    
    if browser:
        try:
            browser.quit()
            browser = None
            return True
        except Exception as e:
            print(f"[!] Error closing browser: {str(e)}")
            return False
    return True


def get_session_data(login_url, upload_url):
    """
    Complete authentication flow and return session data
    Args:
        login_url: URL of login page
        upload_url: URL to check for WAF
    Returns: Dictionary with cookies, headers, and WAF info
    """
    session_data = {
        'cookies': {},
        'headers': {},
        'waf_detected': False,
        'waf_name': None
    }
    
    try:
        # Start browser
        start_selenium()
        
        # Manual login
        manual_login_wait(login_url)
        
        # Extract session data
        session_data['cookies'] = extract_cookies()
        session_data['headers'] = extract_headers()
        
        # Detect WAF
        waf_detected, waf_name = detect_waf(upload_url)
        session_data['waf_detected'] = waf_detected
        session_data['waf_name'] = waf_name
        
        return session_data
        
    except Exception as e:
        raise Exception(f"Authentication failed: {str(e)}")
    finally:
        close_browser()
