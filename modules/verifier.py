"""
Verifier Module - Confirms findings and reduces false positives
"""
import requests
import time
from modules.utils import print_info, print_success, print_warning

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BugHunter/1.0)",
}

class Verifier:
    def __init__(self, findings, timeout=10, verbose=False):
        self.findings = findings
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def run(self):
        for finding in self.findings:
            vuln_type = finding["type"]
            print_info(f"  Verifying: {vuln_type} at {finding['url'][:60]}...")

            if vuln_type == "Reflected XSS":
                finding["confirmed"] = self._verify_xss(finding)
            elif vuln_type == "SQL Injection":
                finding["confirmed"] = self._verify_sqli(finding)
            elif vuln_type == "Sensitive File Exposure":
                finding["confirmed"] = self._verify_sensitive_file(finding)
            elif vuln_type == "CORS Misconfiguration":
                finding["confirmed"] = self._verify_cors(finding)
            elif vuln_type == "Open Redirect":
                finding["confirmed"] = self._verify_redirect(finding)
            elif vuln_type in ["Missing Security Headers", "Server Version Disclosure"]:
                finding["confirmed"] = self._verify_headers(finding)
            elif vuln_type == "Potential IDOR":
                finding["confirmed"] = self._verify_idor(finding)
            else:
                finding["confirmed"] = True  # Pass through unknowns

            status = "CONFIRMED" if finding["confirmed"] else "FALSE POSITIVE"
            print_info(f"    -> {status}")

        return self.findings

    def _verify_xss(self, finding):
        """Re-test XSS with a unique canary to confirm reflection"""
        try:
            url = finding["url"]
            # Re-request and check if payload still reflects
            r = self.session.get(url, timeout=self.timeout)
            evidence = finding.get("evidence", "")
            # Extract original payload from evidence
            payload_line = [l for l in evidence.split("\n") if "Payload:" in l]
            if payload_line:
                payload = payload_line[0].replace("Payload:", "").strip()
                return payload in r.text
        except Exception:
            pass
        return False

    def _verify_sqli(self, finding):
        """Re-test SQLi to confirm error still present"""
        try:
            r = self.session.get(finding["url"], timeout=self.timeout)
            sqli_errors = ["sql syntax", "mysql_fetch", "ora-", "sqlite_", "pg_query",
                           "you have an error in your sql", "warning: mysql", "sqlexception"]
            return any(e in r.text.lower() for e in sqli_errors)
        except Exception:
            pass
        return False

    def _verify_sensitive_file(self, finding):
        """Re-check sensitive file is still accessible"""
        try:
            r = self.session.get(finding["url"], timeout=self.timeout)
            return r.status_code == 200 and len(r.content) > 0
        except Exception:
            pass
        return False

    def _verify_cors(self, finding):
        """Re-verify CORS misconfiguration"""
        try:
            headers = {"Origin": "https://evil.com"}
            r = self.session.get(finding["url"], headers=headers, timeout=self.timeout)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            return acao in ["https://evil.com", "*"]
        except Exception:
            pass
        return False

    def _verify_redirect(self, finding):
        """Re-verify open redirect"""
        try:
            r = self.session.get(finding["url"], timeout=self.timeout, allow_redirects=False)
            location = r.headers.get("Location", "")
            return "evil.com" in location or location.startswith("//")
        except Exception:
            pass
        return False

    def _verify_headers(self, finding):
        """Re-check headers are still missing"""
        try:
            r = self.session.get(finding["url"], timeout=self.timeout)
            missing_headers = ["X-Content-Type-Options", "X-Frame-Options",
                               "Content-Security-Policy", "Strict-Transport-Security"]
            missing = [h for h in missing_headers if h not in r.headers]
            return len(missing) > 0
        except Exception:
            pass
        return False

    def _verify_idor(self, finding):
        """Re-verify IDOR by re-requesting the test URL"""
        try:
            r = self.session.get(finding["url"], timeout=self.timeout)
            return r.status_code == 200 and len(r.content) > 100
        except Exception:
            pass
        return False
