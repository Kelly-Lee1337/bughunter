"""
Recon Module - Subdomain enumeration, endpoint discovery, tech fingerprinting
"""
import socket
import ssl
import concurrent.futures
import requests
import re
from urllib.parse import urljoin, urlparse
from modules.utils import print_info, print_success, print_warning, print_error

# Common subdomains wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
    "app", "portal", "dashboard", "secure", "vpn", "remote", "m", "mobile",
    "shop", "store", "blog", "forum", "support", "help", "docs", "cdn",
    "static", "assets", "media", "images", "uploads", "download", "files",
    "auth", "login", "sso", "account", "my", "internal", "intranet", "corp",
    "git", "gitlab", "github", "jenkins", "jira", "confluence", "wiki",
    "monitor", "metrics", "grafana", "kibana", "elastic", "search",
    "api-v1", "api-v2", "api2", "v1", "v2", "v3", "sandbox", "uat",
    "qa", "preprod", "pre-prod", "demo", "old", "backup", "legacy",
    "smtp", "pop", "imap", "ns1", "ns2", "mx", "webmail",
]

# Common web paths for endpoint discovery
ENDPOINT_WORDLIST = [
    "/", "/admin", "/api", "/api/v1", "/api/v2", "/login", "/signin",
    "/register", "/signup", "/logout", "/dashboard", "/profile",
    "/users", "/user", "/account", "/settings", "/config",
    "/search", "/upload", "/download", "/files", "/docs",
    "/swagger", "/swagger-ui.html", "/api-docs", "/openapi.json",
    "/graphql", "/graphiql", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
    "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/health", "/healthz", "/status", "/metrics", "/debug",
    "/console", "/manager", "/admin/login", "/administrator",
    "/backup", "/backup.zip", "/backup.sql", "/dump.sql",
    "/.htaccess", "/.htpasswd", "/web.config", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/security.txt", "/humans.txt",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BugHunter/1.0; +https://github.com/kellylee/bughunter)",
    "Accept": "*/*",
}

class Recon:
    def __init__(self, target, target_url, timeout=10, threads=10, verbose=False):
        self.target = target
        self.target_url = target_url
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def run(self):
        data = {
            "target": self.target,
            "target_url": self.target_url,
            "subdomains": [],
            "live_hosts": [],
            "endpoints": [],
            "technologies": [],
            "open_ports": [],
            "headers": {},
            "certificates": {},
        }

        print_info("  [1/5] Enumerating subdomains...")
        data["subdomains"] = self._enumerate_subdomains()
        print_success(f"        Found {len(data['subdomains'])} subdomains")

        print_info("  [2/5] Checking live hosts...")
        all_hosts = [self.target_url] + [f"https://{s}" for s in data["subdomains"]]
        data["live_hosts"] = self._check_live_hosts(all_hosts)
        print_success(f"        {len(data['live_hosts'])} live hosts")

        print_info("  [3/5] Fingerprinting technologies...")
        data["technologies"], data["headers"] = self._fingerprint(data["live_hosts"])
        print_success(f"        Detected {len(data['technologies'])} technologies")

        print_info("  [4/5] Discovering endpoints...")
        data["endpoints"] = self._discover_endpoints(data["live_hosts"])
        print_success(f"        Found {len(data['endpoints'])} endpoints")

        print_info("  [5/5] Checking common ports...")
        data["open_ports"] = self._check_ports()
        print_success(f"        {len(data['open_ports'])} open ports")

        return data

    def _enumerate_subdomains(self):
        found = []

        def check_subdomain(sub):
            hostname = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(hostname)
                return hostname
            except socket.gaierror:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(check_subdomain, SUBDOMAIN_WORDLIST)

        found = [r for r in results if r]

        # Also try DNS brute force via certificate transparency
        try:
            ct_subs = self._ct_lookup()
            for s in ct_subs:
                if s not in found:
                    found.append(s)
        except Exception:
            pass

        return found

    def _ct_lookup(self):
        """Query crt.sh for certificate transparency subdomains"""
        found = []
        try:
            r = self.session.get(
                f"https://crt.sh/?q=%.{self.target}&output=json",
                timeout=self.timeout
            )
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.splitlines():
                        line = line.strip().lstrip("*.")
                        if line.endswith(self.target) and line != self.target:
                            if line not in found:
                                found.append(line)
        except Exception:
            pass
        return found

    def _check_live_hosts(self, hosts):
        live = []

        def check(url):
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code < 500:
                    return url
            except Exception:
                try:
                    http_url = url.replace("https://", "http://")
                    r = self.session.get(http_url, timeout=self.timeout, allow_redirects=True)
                    if r.status_code < 500:
                        return http_url
                except Exception:
                    pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(check, hosts)

        return [r for r in results if r]

    def _fingerprint(self, live_hosts):
        technologies = set()
        all_headers = {}

        for host in live_hosts[:5]:  # Fingerprint top 5 hosts
            try:
                r = self.session.get(host, timeout=self.timeout)
                headers = dict(r.headers)
                all_headers[host] = headers
                body = r.text.lower()

                # Server / framework detection
                server = headers.get("Server", "")
                if server: technologies.add(f"Server: {server}")

                powered_by = headers.get("X-Powered-By", "")
                if powered_by: technologies.add(f"X-Powered-By: {powered_by}")

                # Common framework fingerprints
                tech_signatures = {
                    "WordPress": ["wp-content", "wp-includes", "wordpress"],
                    "React": ["__react", "_next", "react-dom"],
                    "Angular": ["ng-version", "angular"],
                    "Vue.js": ["vue.js", "__vue__"],
                    "jQuery": ["jquery"],
                    "Bootstrap": ["bootstrap"],
                    "Laravel": ["laravel_session", "laravel"],
                    "Django": ["csrfmiddlewaretoken", "django"],
                    "Ruby on Rails": ["x-runtime", "_rails"],
                    "ASP.NET": ["__viewstate", "asp.net"],
                    "PHP": [".php", "phpsessid"],
                    "GraphQL": ["graphql", "__typename"],
                    "Nginx": ["nginx"],
                    "Apache": ["apache"],
                    "Cloudflare": ["cf-ray", "cloudflare"],
                    "AWS": ["x-amz", "amazonaws"],
                }

                for tech, sigs in tech_signatures.items():
                    if any(s in body or s in str(headers).lower() for s in sigs):
                        technologies.add(tech)

            except Exception:
                pass

        return list(technologies), all_headers

    def _discover_endpoints(self, live_hosts):
        found = []

        def check_endpoint(args):
            host, path = args
            url = host.rstrip("/") + path
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code not in [404, 410]:
                    return {"url": url, "status": r.status_code, "length": len(r.content)}
            except Exception:
                pass
            return None

        tasks = [(host, path) for host in live_hosts[:3] for path in ENDPOINT_WORDLIST]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(check_endpoint, tasks)

        found = [r for r in results if r]

        # Also parse links from homepage
        for host in live_hosts[:3]:
            try:
                r = self.session.get(host, timeout=self.timeout)
                links = re.findall(r'href=["\']([^"\']+)["\']', r.text)
                for link in links:
                    if link.startswith("/") or link.startswith(host):
                        full = urljoin(host, link)
                        if urlparse(full).netloc == urlparse(host).netloc:
                            if not any(e["url"] == full for e in found):
                                found.append({"url": full, "status": 0, "length": 0, "source": "crawled"})
            except Exception:
                pass

        return found

    def _check_ports(self):
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]
        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_port, common_ports)

        return [p for p in results if p]
