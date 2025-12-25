# WPHunter v2.0

> **Professional WordPress Security Scanner for Penetration Testing & Bug Bounty Hunting**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

WPHunter is an enterprise-grade WordPress vulnerability scanner designed for professional penetration testers and bug bounty hunters. Built with **~9,500 lines of production-ready code**, it implements **31+ advanced security testing techniques** across 13 specialized modules.

---

## 🔥 Key Features

### 🎯 Professional Scanners (13 Modules)

- **Authentication Bypass** (11 techniques) - SQLi, JWT, cookies, headers, REST API, XML-RPC, default creds
- **CSRF Detection** (10 techniques + PoCs) - WordPress nonce validation, AJAX, REST API, bypass testing
- **File Upload** (10 bypass techniques) - Real uploads with execution verification, extension/MIME/magic bytes bypass
- **LFI/RFI** (100+ payloads) - 5 LFI-to-RCE chains, log poisoning, session poisoning, wrapper exploitation
- **XSS** (500+ payloads) - Reflected, Stored, DOM, Blind, Mutation XSS with context-aware validation
- **WAF Detection** - 15 WAFs, 5 bot protections, challenge detection, stealth mode
- **Nginx Misconfigurations** - Alias LFI, merge_slashes, off-by-slash, CRLF injection
- **SSRF** - XML-RPC pingback, oEmbed, cloud metadata extraction
- **SQL Injection** - Time-based, union-based, error-based with WordPress-specific payloads

### 🛡️ Advanced Features

- **WPScan API Integration** - CVE lookup with rate limiting (25/day), 24h caching, smart prioritization
- **Global Rate Limiting** - Adaptive delays, exponential backoff, WAF-aware throttling
- **User Enumeration** - 8 methods including login errors, REST API, sitemaps, author archives
- **Plugin/Theme Detection** - CVE database, vulnerability testing, nulled plugin detection
- **Version Detection** - Weighted scoring system for accurate WordPress version identification

---

## 📊 Statistics

| Component | Lines of Code | Techniques | Quality |
|-----------|---------------|------------|---------|
| **Auth Scanner** | 700+ | 11 | 10/10 |
| **CSRF Scanner** | 650+ | 10 + PoCs | 10/10 |
| **Upload Scanner** | 650+ | 10 + Real Tests | 10/10 |
| **LFI Scanner** | 600+ | 100+ payloads | 10/10 |
| **XSS Scanner** | 700+ | 500+ payloads | 10/10 |
| **WAF Detector** | 700+ | 20 signatures | 10/10 |
| **WPScan API** | 700+ | Rate limit + Cache | 10/10 |
| **Total** | **~9,500** | **31+ techniques** | **Enterprise** |

---

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/Steph-ux/wphunter.git
cd wphunter

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure (optional)
cp config.yaml.example config.yaml
# Edit config.yaml with your settings
```

---

## 💻 Usage

### Basic Scan

```bash
# Full scan
python wphunter.py scan -u https://target.com -m full

# Specific modules
python wphunter.py scan -u https://target.com -m auth,csrf,upload

# Stealth mode (WAF-aware)
python wphunter.py scan -u https://target.com -p stealthy
```

### Advanced Options

```bash
# With WPScan API token
python wphunter.py scan -u https://target.com --wpscan-token YOUR_TOKEN

# Custom rate limiting
python wphunter.py scan -u https://target.com --delay 2 --max-requests 100

# Output to JSON
python wphunter.py scan -u https://target.com -o report.json

# Verbose mode
python wphunter.py scan -u https://target.com -v
```

---

## 🎯 Scan Modules

### Authentication Bypass (`auth`)
- ✅ Protected endpoint access (correct detection logic)
- ✅ SQL injection auth bypass (9 payloads)
- ✅ JWT/Token manipulation (none algorithm)
- ✅ Cookie manipulation & session fixation
- ✅ Header-based bypass (6 types)
- ✅ Password reset vulnerabilities
- ✅ REST API authentication bypass
- ✅ XML-RPC vulnerabilities (multicall, pingback)
- ✅ Plugin-specific bypasses
- ✅ Default credentials testing
- ✅ Session security validation

### CSRF Detection (`csrf`)
- ✅ WordPress nonce validation (10 char hex format)
- ✅ Generic CSRF token detection
- ✅ GET form CSRF (state-changing operations)
- ✅ AJAX endpoint testing (5 critical actions)
- ✅ REST API CSRF (3 endpoints)
- ✅ SameSite cookie validation
- ✅ CSRF bypass techniques (empty nonce, JSON)
- ✅ Plugin form scanning
- ✅ Automatic PoC generation (GET/POST/AJAX/REST)

### File Upload (`upload`)
- ✅ Direct PHP upload + execution verification
- ✅ Extension bypass (14 variants: double ext, null byte, case, trailing)
- ✅ MIME type bypass (4 safe types)
- ✅ Magic bytes bypass (polyglot GIF/JPEG+PHP)
- ✅ Path traversal in filename
- ✅ .htaccess upload → RCE
- ✅ SVG with JavaScript (XSS)
- ✅ Plugin upload forms (3 vulnerable plugins)
- ✅ Automatic cleanup of uploaded files

### LFI/RFI (`lfi`)
- ✅ 100+ LFI/RFI payloads
- ✅ PHP wrappers (php://filter, php://input, data://)
- ✅ Log poisoning (Apache, Nginx, SSH)
- ✅ Session poisoning
- ✅ /proc/self/environ exploitation
- ✅ Path traversal techniques
- ✅ Null byte injection
- ✅ Smart rate limiting

### XSS (`xss`)
- ✅ 500+ context-aware payloads
- ✅ Reflected XSS
- ✅ Stored XSS (comments, profiles)
- ✅ DOM-based XSS
- ✅ Blind XSS (callback URL)
- ✅ Mutation XSS
- ✅ WAF bypass techniques
- ✅ Context detection (HTML, attribute, JavaScript, URL)

### WAF Detection (`waf`)
- ✅ 15 WAF signatures (Cloudflare, Akamai, Imperva, AWS WAF, etc.)
- ✅ 5 bot protections (DataDome, PerimeterX, Kasada, etc.)
- ✅ Challenge detection (CAPTCHA, JavaScript)
- ✅ Rate limiting detection
- ✅ Stealth mode with subtle payloads
- ✅ Bypass recommendations

---

## 📝 Configuration

### config.yaml

```yaml
# Target configuration
target:
  url: "https://target.com"
  verify_ssl: false

# Scanning options
scanning:
  threads: 10
  timeout: 10
  delay: 1
  max_requests: 1000

# WPScan API (optional)
tools:
  wpscan:
    api_token: "YOUR_WPSCAN_API_TOKEN"

# Rate limiting
rate_limiting:
  enabled: true
  requests_per_second: 5
  adaptive: true

# Output
output:
  format: "json"
  verbose: true
  save_findings: true
```

---

## 🛠️ Requirements

- Python 3.8+
- httpx
- beautifulsoup4
- typer
- rich
- pyyaml
- packaging

---

## 📖 Documentation

- [Installation Guide](docs/installation.md)
- [Usage Examples](docs/usage.md)
- [Module Documentation](docs/modules.md)
- [Configuration Guide](docs/configuration.md)
- [Contributing](CONTRIBUTING.md)

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

---

## ⚠️ Legal Disclaimer

**WPHunter is intended for authorized security testing only.**

- ✅ Use only on systems you own or have explicit permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Respect responsible disclosure practices
- ❌ Unauthorized access to computer systems is illegal

The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [WPScan](https://wpscan.com/) - Vulnerability database API
- WordPress Security Team
- Bug bounty community

---

## 📧 Contact

- **Author**: Your Name
- **GitHub**: [@yourusername](https://github.com/yourusername)
- **Twitter**: [@yourhandle](https://twitter.com/yourhandle)

---

**⭐ If you find WPHunter useful, please consider giving it a star!**
