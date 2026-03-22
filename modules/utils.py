"""
Utility functions for BugHunter
"""
import sys

# ANSI color codes
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

def banner():
    print(f"""{CYAN}{BOLD}
  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RESET}
  {BOLD}Bug Bounty Recon & Vulnerability Scanner{RESET}
  {YELLOW}Only test targets you have EXPLICIT permission to test.{RESET}
  {YELLOW}Unauthorized testing is illegal under the CFAA and similar laws.{RESET}
""")

def confirm_scope(target: str) -> bool:
    print(f"{YELLOW}{BOLD}⚠  SCOPE CONFIRMATION REQUIRED{RESET}")
    print(f"{YELLOW}   Target: {target}{RESET}")
    print(f"{YELLOW}   Before proceeding, confirm:{RESET}")
    print(f"{YELLOW}   1. This target is listed in-scope on a bug bounty program, OR{RESET}")
    print(f"{YELLOW}   2. You have written permission from the owner to test this target.{RESET}\n")
    response = input(f"{BOLD}   Type 'YES I HAVE PERMISSION' to continue: {RESET}").strip()
    return response == "YES I HAVE PERMISSION"

def print_success(msg): print(f"{GREEN}[+]{RESET} {msg}")
def print_error(msg):   print(f"{RED}[-]{RESET} {msg}", file=sys.stderr)
def print_info(msg):    print(f"{BLUE}[*]{RESET} {msg}")
def print_warning(msg): print(f"{YELLOW}[!]{RESET} {msg}")
def print_finding(msg): print(f"{RED}{BOLD}[VULN]{RESET} {msg}")
