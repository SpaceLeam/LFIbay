
# LFIBay

Automated LFI testing tool for bug bounty. Uses Selenium for auth, tests 760+ payloads.

## Legal

For authorized security testing only. Use on systems you own or have written permission.

## Features

- Selenium browser automation for cookie extraction
- 764 base payloads (1500+ with mutations)
- 13 detection methods
- Multiple attack chains (filter chains, log poisoning, session poisoning)
- WAF detection (13+ types)
- JSON and HTML reports

## What's New in v3.0

Added exploitation modules:
- PHP filter chains for RCE without upload
- Log poisoning (Apache, Nginx, SSH, FTP, Mail)
- Session poisoning attacks
- /proc/ filesystem exploitation
- Advanced WAF bypass (13 techniques)
- Payload mutation engine

Improved detection from 7 to 13 methods.
Payloads increased from 164 to 764.

## Requirements

- Python 3.11 or 3.12
- Chrome or Chromium browser

## Installation

```bash
git clone https://github.com/SpaceLeam/LFIbay
cd LFIbay
pip install -r requirements.txt
```

ChromeDriver installs automatically via Selenium Manager.

## Usage

```bash
python lfibay.py
```

1. Enter login URL
2. Login manually in browser, press Enter when done
3. Enter upload form URL
4. Tool tests payloads automatically
5. Check results in terminal and HTML report

Example output:
```
[?] Enter login URL: https://target.com/login
[*] Opening browser... Login manually then press Enter
[+] Cookies extracted: 5 cookies
[*] WAF detected: Cloudflare

[?] Enter upload form URL: https://target.com/upload
[*] Loading payloads... 764 payloads loaded
[*] Starting tests with 2s delay...

[SUCCESS] Payload worked! Found pattern: root:x:0:0
...
[+] Report saved: output/reports/report_2025-11-26.html
```

## Structure

```
LFIbay/
├── lfibay.py              # Main script
├── core/                  # Core modules
│   ├── auth.py           # Selenium authentication
│   ├── scanner.py        # Payload testing
│   ├── analyzer.py       # Response analysis
│   ├── filter_chain.py   # Filter chain RCE
│   ├── log_poisoning.py  # Log injection
│   ├── session_poisoning.py
│   ├── proc_exploitation.py
│   ├── chain_detector.py
│   └── waf_bypass_advanced.py
├── payloads/             # 764 payloads
│   ├── path_traversal.txt
│   ├── php_wrappers.txt
│   ├── filter_chains.txt
│   ├── log_poisoning.txt
│   ├── waf_bypass.txt
│   └── ... (more)
├── utils/
└── output/reports/
```

## Attack Vectors

Traditional:
- Path traversal: `../../../etc/passwd`
- PHP wrappers: `php://filter/resource=index.php`
- Null bytes: `../../../etc/passwd%00.jpg`
- Double encoding: `..%252f..%252fetc%252fpasswd`

New in v3.0:
- Filter chains (RCE without file upload)
- Log poisoning (inject PHP in logs)
- Session poisoning (hijack PHP sessions)
- /proc/ exploitation (env vars, file descriptors)
- Advanced wrappers (zip, phar, data)
- Payload mutations (auto WAF bypass)

## Detection Methods

The tool uses 13 detection methods:

1. PHP error patterns
2. System file content patterns
3. Response size anomalies
4. Timing analysis
5. Directory listing patterns
6. Null byte success
7. Base64 content detection
8. Entropy analysis
9. Response similarity
10. Header anomalies
11. Enhanced timing
12. Status code patterns
13. Historical comparison

## Configuration

Edit `utils/config.py` to customize:
- User-Agent pool
- Request delays
- Detection patterns
- WAF signatures

## Output

Reports saved to `output/reports/`:
- JSON (machine readable)
- HTML (human readable with syntax highlighting)

## Known Issues

- Filter chains may not work on all PHP versions
- Some payloads need specific server configurations
- Mutations can be slow with large payload sets

## Tech Stack

- Python 3.11-3.12
- Selenium 4.30+
- Requests 2.31+
- BeautifulSoup4 4.12+
- Colorama 0.4.6+

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

For educational and authorized security testing only.
```


**MAU GUE BIKININ PULL REQUEST BUAT FIX README?** Atau lo prefer manual edit? 🚀

Btw, **conflict markers (`<<<<<<<`)** itu **#1 sign** kalo lo gak tau git properly. HARUS DIHAPUS! 😅
