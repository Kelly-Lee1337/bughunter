# 🐛 BugHunter

An automated bug bounty reconnaissance and vulnerability scanner with report generation.

> ⚠️ **Legal Notice:** Only use this tool against targets you have **explicit permission** to test, such as those listed in-scope on a bug bounty program. Unauthorized testing is illegal under the CFAA and similar laws. The tool enforces a scope confirmation prompt before any scanning begins.

---

## Features

- **Recon** — Subdomain enumeration (wordlist + certificate transparency), live host detection, tech fingerprinting, endpoint discovery, port scanning
- **Scanning** — XSS, SQL injection, IDOR, open redirects, CORS misconfiguration, sensitive file exposure, missing security headers
- **Verification** — Automatically re-tests each finding to confirm and reduce false positives
- **Reporting** — Generates formatted Markdown write-ups ready to submit to HackerOne, Bugcrowd, Intigriti, or Huntr

---

## Installation

```bash
git clone https://github.com/yourusername/bughunter.git
cd bughunter
pip install -r requirements.txt
```

---

## Usage

### Full scan (recon + scan + verify + report)
```bash
python main.py example.com --platform hackerone
```

### Recon only
```bash
python main.py example.com --mode recon
```

### Scan only (skip recon)
```bash
python main.py example.com --mode scan
```

### Custom output directory
```bash
python main.py example.com --output ~/bug-bounty/reports --platform bugcrowd
```

### Verbose mode
```bash
python main.py example.com --verbose
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target domain or URL | Required |
| `--mode` | `full`, `recon`, `scan`, `report` | `full` |
| `--platform` | `hackerone`, `bugcrowd`, `intigriti`, `huntr`, `generic` | `generic` |
| `--output` | Output directory for reports | `reports/` |
| `--timeout` | Request timeout (seconds) | `10` |
| `--threads` | Concurrent threads | `10` |
| `--verbose` | Verbose output | Off |
| `--skip-verify` | Skip verification step | Off |

---

## Output

Each scan creates a timestamped session folder under `reports/`:

```
reports/
└── example_com_20260309_120000/
    ├── SUMMARY.md                          # Overview of all findings
    ├── findings.json                       # Raw JSON data
    ├── finding_01_reflected_xss.md         # Per-finding write-up
    ├── finding_02_sql_injection.md
    └── finding_03_sensitive_file_exposure.md
```

Write-ups are pre-formatted for your chosen platform and ready to copy-paste into your submission.

---

## Vulnerability Coverage

| Type | Severity |
|------|----------|
| SQL Injection | Critical |
| Sensitive File Exposure | Critical / High |
| Reflected XSS | High |
| IDOR | High |
| CORS Misconfiguration | High / Medium |
| Open Redirect | Medium |
| Missing Security Headers | Low |
| Server Version Disclosure | Info |

---

## Supported Platforms

- [HackerOne](https://hackerone.com)
- [Bugcrowd](https://bugcrowd.com)
- [Intigriti](https://intigriti.com)
- [Huntr](https://huntr.com)

---

## Disclaimer

This tool is intended for **authorized security testing only**. The author is not responsible for any misuse or damage caused by this tool. Always obtain written permission before testing any system you do not own.
