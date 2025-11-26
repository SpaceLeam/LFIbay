"""
LFIBay - Scanner Module
Handles payload injection, form field detection, and batch testing
"""

import requests
from bs4 import BeautifulSoup
import time
import io
from core.waf_bypass import get_random_user_agent, add_random_delay


def detect_form_fields(url, cookies):
    """
    Parse HTML and find all input fields in upload form
    Args:
        url: Upload form URL
        cookies: Session cookies
    Returns: Dictionary with form action and fields
    """
    try:
        headers = {'User-Agent': get_random_user_agent()}
        response = requests.get(url, cookies=cookies, headers=headers, timeout=10)
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find first form element
        form = soup.find('form')
        if not form:
            return None
        
        # Extract form action
        form_action = form.get('action', '')
        if form_action and not form_action.startswith('http'):
            # Handle relative URLs
            from urllib.parse import urljoin
            form_action = urljoin(url, form_action)
        else:
            form_action = url
        
        # Find all input fields
        fields = {}
        for input_field in form.find_all('input'):
            field_name = input_field.get('name')
            field_type = input_field.get('type', 'text')
            field_value = input_field.get('value', '')
            
            if field_name:
                fields[field_name] = {
                    'type': field_type,
                    'value': field_value
                }
        
        # Also check for textarea and select fields
        for textarea in form.find_all('textarea'):
            field_name = textarea.get('name')
            if field_name:
                fields[field_name] = {
                    'type': 'textarea',
                    'value': textarea.text
                }
        
        return {
            'action': form_action,
            'fields': fields,
            'method': form.get('method', 'post').upper()
        }
        
    except Exception as e:
        raise Exception(f"Failed to detect form fields: {str(e)}")


def generate_test_file(payload, filename="test.txt"):
    """
    Create file object with payload content
    Args:
        payload: Payload string to include in file
        filename: Name for the file
    Returns: File-like object
    """
    file_content = payload.encode('utf-8')
    return io.BytesIO(file_content)


def test_payload(url, payload, field_name, cookies, headers, form_data=None):
    """
    Send single payload via requests
    Args:
        url: Target URL
        payload: LFI payload to test
        field_name: Name of the file upload field
        cookies: Session cookies
        headers: Request headers
        form_data: Additional form fields
    Returns: Dictionary with response data
    """
    try:
        start_time = time.time()
        
        # Prepare form data
        data = form_data.copy() if form_data else {}
        
        # Create file upload
        files = {
            field_name: (payload, generate_test_file(payload), 'text/plain')
        }
        
        # Update headers (remove Content-Type to let requests set it for multipart)
        request_headers = headers.copy()
        if 'Content-Type' in request_headers:
            del request_headers['Content-Type']
        
        # Send request
        response = requests.post(
            url,
            data=data,
            files=files,
            cookies=cookies,
            headers=request_headers,
            timeout=15,
            allow_redirects=True
        )
        
        end_time = time.time()
        response_time = end_time - start_time
        
        return {
            'payload': payload,
            'status_code': response.status_code,
            'response_time': response_time,
            'content_length': len(response.content),
            'content': response.text,
            'headers': dict(response.headers),
            'url': response.url
        }
        
    except requests.exceptions.Timeout:
        return {
            'payload': payload,
            'status_code': 0,
            'response_time': 15.0,
            'content_length': 0,
            'content': '',
            'headers': {},
            'url': url,
            'error': 'Timeout'
        }
    except Exception as e:
        return {
            'payload': payload,
            'status_code': 0,
            'response_time': 0,
            'content_length': 0,
            'content': '',
            'headers': {},
            'url': url,
            'error': str(e)
        }


def batch_test(url, payloads, form_info, cookies, headers, delay_min=1, delay_max=3, progress_callback=None):
    """
    Test all payloads with rate limiting and delays
    Args:
        url: Target URL
        payloads: List of payloads to test
        form_info: Form information from detect_form_fields
        cookies: Session cookies
        headers: Request headers
        delay_min: Minimum delay between requests (seconds)
        delay_max: Maximum delay between requests (seconds)
        progress_callback: Function to call after each test
    Returns: List of response dictionaries
    """
    results = []
    
    # Find file upload field
    file_field = None
    for field_name, field_info in form_info['fields'].items():
        if field_info['type'] == 'file':
            file_field = field_name
            break
    
    if not file_field:
        # If no explicit file field, try common names
        common_file_fields = ['file', 'upload', 'attachment', 'document', 'image']
        for field in common_file_fields:
            if field in form_info['fields']:
                file_field = field
                break
        
        # If still not found, use first field or default to 'file'
        if not file_field:
            file_field = list(form_info['fields'].keys())[0] if form_info['fields'] else 'file'
    
    # Prepare other form fields
    form_data = {}
    for field_name, field_info in form_info['fields'].items():
        if field_name != file_field and field_info['type'] not in ['file', 'submit', 'button']:
            form_data[field_name] = field_info.get('value', '')
    
    target_url = form_info['action']
    
    # Test each payload
    for i, payload in enumerate(payloads, 1):
        # Random User-Agent rotation
        test_headers = headers.copy()
        test_headers['User-Agent'] = get_random_user_agent()
        
        # Test payload
        result = test_payload(
            target_url,
            payload,
            file_field,
            cookies,
            test_headers,
            form_data
        )
        
        results.append(result)
        
        # Progress callback
        if progress_callback:
            progress_callback(i, len(payloads), result)
        
        # Random delay (except for last request)
        if i < len(payloads):
            add_random_delay(delay_min, delay_max)
    
    return results
