# LFIBay - Automated LFI Testing Tool

An automated Local File Inclusion (LFI) testing tool for upload forms. Uses Selenium for authentication and cookie extraction, then switches to requests library for fast payload testing.

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.** Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

## Features

- 🔐 **Selenium-based Authentication** - Manual login with automatic cookie extraction
- 🚀 **Fast Payload Testing** - 247+ LFI payloads across multiple attack vectors
- 🛡️ **WAF Detection** - Identifies common WAF signatures
- 🎭 **Stealth Mode** - User-Agent rotation, random delays, encoding techniques
- 📊 **Smart Analysis** - Multiple detection methods (patterns, size anomalies, timing)
- 📈 **Progress Tracking** - Real-time progress with colored terminal output
- 📄 **Comprehensive Reports** - JSON and HTML output formats

## Installation

**Requirements:**
- Python 3.11 or 3.12 (recommended)
- Chrome or Chromium browser installed

```bash
# Clone or navigate to LFIBay directory
cd LFIBay

# Install dependencies
pip install -r requirements.txt

# ChromeDriver will be auto-installed by Selenium Manager
# No manual ChromeDriver setup needed!
```

## Usage

```bash
python lfibay.py
```

### Workflow

1. **Enter Login URL** - Provide the target authentication page
2. **Manual Login** - Browser opens, login manually, press Enter when done
3. **Cookie Extraction** - Automatically extracts session cookies and headers
4. **Enter Upload Form URL** - Provide the vulnerable upload form URL
5. **Automated Testing** - Tool tests all payloads with rate limiting
6. **Results** - View findings in terminal and generated reports

### Example Session

```
$ python lfibay.py

[*] Enter login URL: https://target.com/login
[*] Opening browser... Login manually then press Enter
[+] Cookies extracted: 5 cookies
[+] WAF detected: Cloudflare
[*] Browser closed

[*] Enter upload form URL: https://target.com/upload
[*] Detecting form fields...
[+] Found fields: file, submit
[*] Loading payloads... 247 payloads loaded
[*] Starting tests with 2s delay...

[TESTING] 1/247 - ../../../etc/passwd
[SUCCESS] Payload worked! Found pattern: root:x:0:0
...

[+] Testing complete!
[+] Found 12 successful payloads
[+] Report saved: output/reports/report_2025-11-25_14-30.html
```

## Project Structure

```
LFIBay/
│
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── lfibay.py                 # Main entry point
│
├── core/                     # Core functionality
│   ├── auth.py              # Selenium auth & cookie extraction
│   ├── scanner.py           # Payload injection & testing
│   ├── analyzer.py          # Response analysis & detection
│   └── waf_bypass.py        # WAF evasion techniques
│
├── payloads/                 # Attack payloads
│   ├── path_traversal.txt   # Path traversal attacks
│   ├── php_wrappers.txt     # PHP wrapper exploits
│   ├── null_bytes.txt       # Null byte injection
│   └── double_encoding.txt  # Encoded payloads
│
├── utils/                    # Utilities
│   ├── logger.py            # Colored output & logging
│   ├── config.py            # Configuration settings
│   └── reporter.py          # Report generation
│
└── output/
    └── reports/              # Generated reports (JSON/HTML)
```

## Attack Vectors

- **Path Traversal** - `../../../etc/passwd`, `..\\..\\..\\windows\\win.ini`
- **PHP Wrappers** - `php://filter`, `php://input`, `expect://`
- **Null Bytes** - `../../../etc/passwd%00.jpg`
- **Double Encoding** - `..%252f..%252fetc%252fpasswd`

## Detection Methods

- **Error Pattern Matching** - PHP error messages, failed includes
- **Content Analysis** - System file patterns (root:x:0:0, <?php)
- **Size Anomalies** - Response size comparison with baseline
- **Timing Analysis** - Wrapper timeout detection

## Configuration

Edit `utils/config.py` to customize:
- User-Agent pool
- Request delays (min/max)
- Detection patterns
- WAF signatures

## Output

Reports are saved to `output/reports/` with timestamp:
- **JSON** - Machine-readable format for further processing
- **HTML** - Human-readable with syntax highlighting

## 2025 Enhancements

### ✨ Latest Updates
- **Python 3.11-3.12 Support** - Optimized for latest stable Python versions
- **Selenium 4 Auto-Driver** - ChromeDriver auto-managed by Selenium Manager
- **Headless Mode** - Run without GUI for server environments
- **Enhanced WAF Detection** - Now detects 13+ WAF types including Fortinet, Radware, F5 ASM, Citrix
- **Improved Stealth** - Rate limiting with jitter for more natural request patterns
- **Better Error Handling** - Specific exception handling for more reliable operation
- **Proxy Support** - Ready for proxy configuration (see `utils/config.py`)

## Tech Stack

- **Python 3.11-3.12** (recommended)
- **Selenium 4.30+** (browser automation)
- **Requests 2.31+** (HTTP client)
- **BeautifulSoup4 4.12+** (HTML parsing)
- **Colorama 0.4.6+** (terminal colors)
- **LXML 5.0+** (fast XML/HTML processing)

## Contributing

This is a security research tool. Use responsibly and ethically.

## License

For educational and authorized security testing purposes only.
