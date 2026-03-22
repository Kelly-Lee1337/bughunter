"""
Reporter Module - Generates formatted bug bounty write-ups per platform
"""
import os
import json
from datetime import datetime
from modules.utils import print_info

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

CVSS_SCORES = {
    "critical": "9.0-10.0",
    "high": "7.0-8.9",
    "medium": "4.0-6.9",
    "low": "0.1-3.9",
    "info": "0.0",
}

class Reporter:
    def __init__(self, recon_data, findings, platform, output_dir):
        self.recon_data = recon_data
        self.findings = findings
        self.platform = platform
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.confirmed = [f for f in findings if f.get("confirmed")]

    def generate(self):
        # Save raw JSON findings
        json_path = os.path.join(self.output_dir, "findings.json")
        with open(json_path, "w") as f:
            json.dump({
                "recon": self.recon_data,
                "findings": self.findings,
                "generated": self.timestamp,
            }, f, indent=2)

        # Generate platform-specific reports for each confirmed finding
        report_paths = []
        for i, finding in enumerate(self.confirmed):
            path = self._generate_finding_report(finding, i + 1)
            report_paths.append(path)

        # Generate summary report
        summary_path = self._generate_summary()
        return summary_path

    def save_recon(self):
        path = os.path.join(self.output_dir, "recon.json")
        with open(path, "w") as f:
            json.dump(self.recon_data, f, indent=2)

    def _generate_summary(self):
        path = os.path.join(self.output_dir, "SUMMARY.md")

        severity_counts = {}
        for f in self.confirmed:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines = [
            f"# Bug Bounty Scan Summary",
            f"",
            f"**Target:** {self.recon_data.get('target_url')}  ",
            f"**Date:** {self.timestamp}  ",
            f"**Platform:** {self.platform.upper()}  ",
            f"",
            f"---",
            f"",
            f"## Findings Overview",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"| {SEVERITY_EMOJI.get(sev, '')} {sev.capitalize()} | {count} |")

        lines += [
            f"",
            f"**Total confirmed:** {len(self.confirmed)} / {len(self.findings)} potential findings",
            f"",
            f"---",
            f"",
            f"## Recon Summary",
            f"",
            f"- **Subdomains found:** {len(self.recon_data.get('subdomains', []))}",
            f"- **Live hosts:** {len(self.recon_data.get('live_hosts', []))}",
            f"- **Endpoints discovered:** {len(self.recon_data.get('endpoints', []))}",
            f"- **Technologies detected:** {', '.join(self.recon_data.get('technologies', [])) or 'None'}",
            f"- **Open ports:** {', '.join(map(str, self.recon_data.get('open_ports', []))) or 'None'}",
            f"",
            f"---",
            f"",
            f"## Confirmed Findings",
            f"",
        ]

        for i, finding in enumerate(self.confirmed):
            sev = finding.get("severity", "info")
            lines.append(f"### {i+1}. {SEVERITY_EMOJI.get(sev, '')} {finding['type']} ({sev.capitalize()})")
            lines.append(f"**URL:** `{finding['url']}`  ")
            lines.append(f"**Description:** {finding['description']}")
            lines.append(f"")
            lines.append(f"> See `finding_{i+1:02d}_{finding['type'].lower().replace(' ', '_')}.md` for full write-up")
            lines.append(f"")

        with open(path, "w") as f:
            f.write("\n".join(lines))

        return path

    def _generate_finding_report(self, finding, index):
        fname = f"finding_{index:02d}_{finding['type'].lower().replace(' ', '_').replace('/', '_')}.md"
        path = os.path.join(self.output_dir, fname)

        sev = finding.get("severity", "info")

        if self.platform == "hackerone":
            content = self._format_hackerone(finding, sev)
        elif self.platform == "bugcrowd":
            content = self._format_bugcrowd(finding, sev)
        elif self.platform == "intigriti":
            content = self._format_intigriti(finding, sev)
        elif self.platform == "huntr":
            content = self._format_huntr(finding, sev)
        else:
            content = self._format_generic(finding, sev)

        with open(path, "w") as f:
            f.write(content)

        return path

    def _format_hackerone(self, f, sev):
        return f"""# {f['type']}

## Summary
{f['description']}

## Severity
**{sev.capitalize()}** (CVSS {CVSS_SCORES.get(sev, 'N/A')})

## Steps to Reproduce
1. Navigate to the affected URL: `{f['url']}`
2. {self._get_steps(f)}

## Impact
{self._get_impact(f)}

## Evidence
```
{f.get('evidence', 'See attached screenshots')}
```

## Affected URL
`{f['url']}`

## Remediation
{f.get('remediation', 'See OWASP guidelines for remediation advice.')}

---
*Report generated by BugHunter on {self.timestamp}*
"""

    def _format_bugcrowd(self, f, sev):
        return f"""# Vulnerability Report: {f['type']}

**Target:** {self.recon_data.get('target_url')}
**Severity:** {sev.capitalize()}
**Date Found:** {self.timestamp}

---

## Description
{f['description']}

## Proof of Concept
{self._get_steps(f)}

**Evidence:**
```
{f.get('evidence', 'N/A')}
```

## Impact
{self._get_impact(f)}

## Suggested Fix
{f.get('remediation', 'See OWASP guidelines.')}
"""

    def _format_intigriti(self, f, sev):
        return f"""## {f['type']}

**Severity:** {sev.capitalize()}
**Affected Endpoint:** `{f['url']}`

### Description
{f['description']}

### Reproduction Steps
{self._get_steps(f)}

### Proof
```
{f.get('evidence', 'N/A')}
```

### Impact
{self._get_impact(f)}

### Remediation
{f.get('remediation', 'See OWASP guidelines.')}
"""

    def _format_huntr(self, f, sev):
        return f"""# {f['type']} - Security Vulnerability Report

## Vulnerability Type
{f['type']}

## Severity
{sev.capitalize()}

## Description
{f['description']}

## Affected Component
`{f['url']}`

## Steps to Reproduce
{self._get_steps(f)}

## Proof of Concept
```
{f.get('evidence', 'N/A')}
```

## Impact Assessment
{self._get_impact(f)}

## Remediation Recommendation
{f.get('remediation', 'See OWASP guidelines.')}

## References
- OWASP: https://owasp.org/www-project-top-ten/
- CWE: https://cwe.mitre.org/

*Reported via BugHunter on {self.timestamp}*
"""

    def _format_generic(self, f, sev):
        return f"""# {f['type']}

**Severity:** {sev.capitalize()}
**URL:** `{f['url']}`
**Date:** {self.timestamp}

## Description
{f['description']}

## Evidence
```
{f.get('evidence', 'N/A')}
```

## Steps to Reproduce
{self._get_steps(f)}

## Impact
{self._get_impact(f)}

## Remediation
{f.get('remediation', 'See OWASP guidelines.')}
"""

    def _get_steps(self, finding):
        vuln_type = finding["type"]
        url = finding["url"]
        evidence = finding.get("evidence", "")

        # Extract payload from evidence if present
        payload = ""
        for line in evidence.split("\n"):
            if "Payload:" in line:
                payload = line.replace("Payload:", "").strip()
                break

        steps_map = {
            "Reflected XSS": f"1. Send a GET request to `{url}`\n2. Observe the payload `{payload}` is reflected in the response without encoding\n3. The script executes in the browser context",
            "SQL Injection": f"1. Send a GET request to `{url}`\n2. Observe the SQL error message in the response\n3. The database error confirms unsanitized input reaches the SQL query",
            "Sensitive File Exposure": f"1. Send a GET request to `{url}`\n2. Observe that the file returns HTTP 200 with sensitive content\n3. No authentication or authorization is required",
            "CORS Misconfiguration": f"1. Send a GET request to `{url}` with header `Origin: https://evil.com`\n2. Observe that the response includes `Access-Control-Allow-Origin: https://evil.com`\n3. This allows cross-origin requests from arbitrary domains",
            "Open Redirect": f"1. Send a GET request to `{url}`\n2. Observe the HTTP 3xx redirect to an external domain\n3. An attacker can craft a link to redirect victims to a malicious site",
            "Missing Security Headers": f"1. Send a GET request to `{url}`\n2. Inspect the response headers\n3. Observe the missing security headers listed in the description",
            "Potential IDOR": f"1. Authenticate as a user and note the object ID in the URL\n2. Modify the ID to another user's ID: `{url}`\n3. Observe that the server returns another user's data without authorization check",
        }

        return steps_map.get(vuln_type, f"1. Navigate to `{url}`\n2. Observe the vulnerability as described")

    def _get_impact(self, finding):
        impact_map = {
            "Reflected XSS": "An attacker can execute arbitrary JavaScript in a victim's browser, potentially stealing session cookies, credentials, or performing actions on behalf of the user.",
            "SQL Injection": "An attacker can read, modify, or delete database contents, bypass authentication, and potentially gain remote code execution on the database server.",
            "Sensitive File Exposure": "Sensitive configuration data, credentials, or source code is exposed to unauthenticated attackers, potentially enabling further compromise.",
            "CORS Misconfiguration": "An attacker-controlled website can make cross-origin requests to this API on behalf of authenticated users, potentially exfiltrating sensitive data.",
            "Open Redirect": "An attacker can craft a trusted-looking URL that redirects users to a malicious site, facilitating phishing attacks.",
            "Missing Security Headers": "Missing headers increase exposure to clickjacking, MIME-type sniffing, and other client-side attacks.",
            "Potential IDOR": "An attacker can access, modify, or delete other users' data without authorization, leading to data breach and privacy violations.",
            "Server Version Disclosure": "Version information aids attackers in identifying known vulnerabilities for the specific software version.",
            "Command Injection": "An attacker can execute arbitrary operating system commands on the server, leading to full system compromise, data exfiltration, or lateral movement.",
            "Server-Side Request Forgery (SSRF)": "An attacker can make the server issue requests to internal services, cloud metadata endpoints, or other internal infrastructure, potentially exposing credentials and sensitive data.",
            "Path Traversal": "An attacker can read arbitrary files on the server, including configuration files, credentials, and source code outside the intended webroot.",
            "XML External Entity (XXE) Injection": "An attacker can read local files, perform SSRF, or cause denial of service by supplying malicious XML with external entity references.",
            "Server-Side Template Injection (SSTI)": "An attacker can execute arbitrary code on the server by injecting malicious template expressions, potentially leading to full remote code execution.",
            "JWT 'none' Algorithm Vulnerability": "An attacker can forge JWT tokens with arbitrary claims (including admin privileges) by setting the algorithm to 'none', bypassing all signature verification.",
            "Sensitive Data in JWT Payload": "Sensitive user data stored in JWT payloads is readable by anyone who intercepts the token, as JWTs are only signed, not encrypted.",
            "Insecure Deserialization (PHP)": "An attacker can manipulate serialized PHP objects to achieve remote code execution, authentication bypass, or other critical impacts via PHP magic methods.",
            "Insecure Deserialization (Java)": "An attacker can craft malicious Java serialized objects to achieve remote code execution through gadget chains in common Java libraries.",
            "Insecure Deserialization (Error Disclosure)": "Deserialization error disclosure reveals implementation details that aid attackers in crafting targeted deserialization exploits.",
        }
        return impact_map.get(finding["type"], "This vulnerability could allow an attacker to compromise the confidentiality, integrity, or availability of the application.")
