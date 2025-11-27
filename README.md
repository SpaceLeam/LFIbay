# LFIBay

Automated LFI scanner for bug bounty and pentesting.

[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0-orange.svg)](CHANGELOG.md)

## Features

- Selenium browser automation for auth
- 764 base payloads, 1500+ with mutations
- 13 detection methods
- PHP filter chains, log poisoning, session poisoning
- /proc/ exploitation
- WAF bypass (13+ techniques)
- JSON + HTML reports

## Installation
```bash
git clone https://github.com/SpaceLeam/LFIbay.git
cd LFIbay
pip install -r requirements.txt
```

ChromeDriver installs automatically.

## Usage
```bash
python lfibay.py
```

1. Enter login URL, login manually
2. Enter target URL
3. Wait for scan
4. Check `output/reports/` for results

## Tech Stack

- Python 3.11-3.12
- Selenium 4.30+
- Requests 2.31+
- BeautifulSoup4 4.12+
- lxml 5.0+
- Colorama 0.4.6+

## Attack Types

**Basic:**
- Path traversal
- PHP wrappers
- Null bytes
- Double encoding

**Advanced:**
- Filter chains (RCE without upload)
- Log poisoning (Apache/Nginx/SSH/FTP)
- Session poisoning
- /proc/ exploitation
- Wrapper abuse (zip, phar, data)

## Detection Methods

13 methods including error patterns, content analysis, timing, entropy, size anomalies, and more.

## Structure
```
LFIbay/
├── lfibay.py              # Main
├── core/                  # Modules
├── payloads/              # 764 payloads
├── utils/                 # Helpers
└── output/reports/        # Results
```

## Configuration

Edit `utils/config.py` for:
- Request delays
- Detection patterns
- WAF signatures
- User-Agent pool

## Known Issues

- Filter chains need specific PHP versions
- Some payloads require certain server configs
- Mutations can be slow on large sets

## Legal

**For authorized testing only.** Get written permission before testing any system. Unauthorized use is illegal.

## License

MIT License - see [LICENSE](LICENSE) file.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

