# 🔬 React2Shell Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/React-Security-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React">
  <img src="https://img.shields.io/badge/Next.js-Assessment-000000?style=for-the-badge&logo=nextdotjs&logoColor=white" alt="Next.js">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<p align="center">
  <b>Web Application Security Assessment Framework for React and Next.js Applications</b>
</p>

---

## ⚠️ Important Notice

**This tool is designed for authorized security testing only.**

- ✅ Authorized penetration testing
- ✅ Bug bounty programs within scope
- ✅ Security research with permission
- ✅ Testing your own applications
- ❌ Unauthorized access attempts
- ❌ Testing without explicit permission

Users are solely responsible for ensuring compliance with all applicable laws.

---

## 📋 Description

React2Shell Scanner is a command-line security assessment framework designed to help security professionals identify potential vulnerabilities in React and Next.js web applications. It focuses on analyzing React Server Components (RSC) implementations for common security misconfigurations.

### Use Cases

- **Penetration Testing** - Assess React/Next.js applications during engagements
- **Bug Bounty** - Discover reportable security issues
- **Security Audits** - Comprehensive security reviews
- **DevSecOps** - Integrate into CI/CD security pipelines

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🎯 **Multi-Target Scanning** | Scan single URLs or lists of targets |
| 🔄 **Concurrent Testing** | Multi-threaded for efficient assessment |
| 🛡️ **WAF Detection** | Identify and analyze WAF responses |
| 📊 **Progress Tracking** | Visual progress bar with tqdm |
| 🔧 **Configurable Headers** | Custom header injection |
| 🌐 **Proxy Support** | Route through HTTP/HTTPS proxies |
| 📝 **Output Formats** | JSON and text report generation |
| 🎨 **Colorful CLI** | Clear, color-coded terminal output |

### Security Assessment Capabilities

- RSC (React Server Components) analysis
- Server-side rendering evaluation  
- Redirect behavior testing
- Response header analysis
- Content-type validation

## 🚀 Installation

### **For users on Windows and macOS:** The standard installation method is manual (see below). macOS provides an alternative: a direct install from the [DMG file](../../releases).


### Prerequisites

- Python 3.8 or higher
- pip package manager
- Internet connection

### Quick Install

```bash
# Clone repository
git clone https://github.com/tybalt30mul/React2Shell-Scanner.git
cd React2Shell-Scanner

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

```
requests>=2.28.0    # HTTP client library
tqdm>=4.64.0        # Progress bar visualization
urllib3>=1.26.0     # URL handling
```

## 📖 Usage

### Basic Scan

```bash
# Single target
python react2shell.py.py -u https://example.com

# With verbose output
python react2shell.py.py -u https://example.com -v
```

### Batch Scanning

```bash
# Scan from file
python react2shell.py.py -l targets.txt

# With concurrent threads
python react2shell.py.py -l targets.txt -t 10
```

### Advanced Options

```bash
# Custom headers
python react2shell.py.py -u https://example.com -H "Authorization: Bearer token"

# Through proxy
python react2shell.py.py -u https://example.com --proxy http://127.0.0.1:8080

# Skip SSL verification
python react2shell.py.py -u https://example.com --no-verify

# Output to file
python react2shell.py.py -u https://example.com -o results.json
```

### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--url` | `-u` | Single target URL | - |
| `--list` | `-l` | File with target URLs | - |
| `--threads` | `-t` | Concurrent threads | 5 |
| `--timeout` | - | Request timeout (seconds) | 10 |
| `--proxy` | - | Proxy URL (http/https) | - |
| `--headers` | `-H` | Custom headers | - |
| `--output` | `-o` | Output file path | - |
| `--no-verify` | - | Skip SSL verification | False |
| `--verbose` | `-v` | Verbose output | False |
| `--waf-bypass` | - | WAF bypass mode | False |
| `--bypass-size` | - | Bypass payload size (KB) | 128 |

## 📊 Output Example

### Console Output

```
React2Shell Web Application Security Assessment Framework

[*] Starting assessment of https://example.com
[*] Analyzing React Server Components...
[*] Testing redirect behavior...
[+] Assessment complete

Target: https://example.com
Status: Analyzed
Response Code: 200
Server: Next.js
React Version: 18.2.0
RSC Detected: Yes
Assessment Time: 1.23s
```

### JSON Output

```json
{
  "target": "https://example.com",
  "timestamp": "2025-01-15T10:30:00Z",
  "results": {
    "status_code": 200,
    "server": "Next.js",
    "rsc_detected": true,
    "headers": {
      "content-type": "text/html",
      "x-powered-by": "Next.js"
    },
    "assessment_time": 1.23
  }
}
```

## 🏗️ Project Structure

```
React2Shell-Scanner/
├── react2shell.py.py      # Main scanner script
├── requirements.txt       # Python dependencies
└── README.md             # Documentation
```

## ⚙️ Configuration

### Target File Format

Create a text file with one URL per line:

```
https://target1.com
https://target2.com
https://target3.com/api
```

### Custom Headers

Pass multiple headers with repeated `-H` flags:

```bash
python react2shell.py.py -u https://example.com \
  -H "Authorization: Bearer token123" \
  -H "X-Custom-Header: value" \
  -H "Cookie: session=abc123"
```

### Proxy Configuration

```bash
# HTTP Proxy
--proxy http://127.0.0.1:8080

# HTTPS Proxy
--proxy https://proxy.example.com:8443

# Authenticated Proxy
--proxy http://user:pass@proxy.example.com:8080
```

## 🔧 Integration

### CI/CD Pipeline

```yaml
# GitHub Actions example
security-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v3
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    - name: Install dependencies
      run: pip install -r requirements.txt
    - name: Run security scan
      run: python react2shell.py.py -u ${{ secrets.TARGET_URL }} -o results.json
```

### Script Integration

```python
import subprocess
import json

# Run scanner
result = subprocess.run(
    ['python', 'react2shell.py.py', '-u', 'https://example.com', '-o', 'results.json'],
    capture_output=True,
    text=True
)

# Parse results
with open('results.json') as f:
    findings = json.load(f)
```

## 🛡️ Responsible Use

### Before Testing

1. **Get Authorization** - Written permission required
2. **Define Scope** - Know what's in/out of bounds
3. **Coordinate** - Work with the target organization
4. **Document** - Keep records of your testing

### During Testing

1. **Stay in Scope** - Only test authorized targets
2. **Minimize Impact** - Use appropriate thread counts
3. **Monitor** - Watch for unintended effects
4. **Stop if Needed** - Halt testing if issues arise

### After Testing

1. **Report Findings** - Document everything professionally
2. **Follow Disclosure** - Respect disclosure timelines
3. **Clean Up** - Remove any test data created

## 🐛 Troubleshooting

### Common Issues

**Connection Timeout**
```bash
# Increase timeout
python react2shell.py.py -u https://example.com --timeout 30
```

**SSL Certificate Errors**
```bash
# Skip verification (testing only)
python react2shell.py.py -u https://example.com --no-verify
```

**Rate Limiting**
```bash
# Reduce threads
python react2shell.py.py -l targets.txt -t 2
```

## 🤝 Contributing

We welcome contributions that improve:

- Scanning accuracy
- Performance optimization
- Documentation
- Safety features

Please submit issues and pull requests on GitHub.

## 📄 License

This project is licensed under the MIT License.

## 📚 References

- [Next.js Security Best Practices](https://nextjs.org/docs/security)
- [React Security Documentation](https://react.dev/reference/react-dom)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

<p align="center">
  <b>Security Testing Made Efficient</b>
  <br>
  🔒 Always Test Responsibly 🔒
</p>