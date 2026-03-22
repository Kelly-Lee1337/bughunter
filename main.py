#!/usr/bin/env python3
"""
BugHunter - Automated Bug Bounty Reconnaissance & Vulnerability Scanner
Author: Kelly Lee
For use ONLY against targets you have explicit permission to test.
"""

import argparse
import sys
import os
from datetime import datetime
from modules.recon import Recon
from modules.scanner import Scanner
from modules.verifier import Verifier
from modules.reporter import Reporter
from modules.utils import banner, confirm_scope, print_success, print_error, print_info, print_warning

def parse_args():
    parser = argparse.ArgumentParser(
        description="BugHunter - Bug Bounty Recon & Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target domain or URL (e.g. example.com)")
    parser.add_argument("--mode", choices=["full", "recon", "scan", "report"], default="full",
                        help="Run mode:\n  full   = recon + scan + verify + report\n  recon  = recon only\n  scan   = scan only (skip recon)\n  report = generate report from previous scan")
    parser.add_argument("--platform", choices=["hackerone", "bugcrowd", "intigriti", "huntr", "generic"],
                        default="generic", help="Bug bounty platform (formats report accordingly)")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--skip-verify", action="store_true", help="Skip verification step")
    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    # Normalize target
    target = args.target.strip().rstrip("/")
    if not target.startswith("http"):
        target_url = f"https://{target}"
    else:
        target_url = target
        target = target.replace("https://", "").replace("http://", "").split("/")[0]

    # Scope confirmation — required before any scanning
    if not confirm_scope(target):
        print_error("Scope not confirmed. Exiting. Only test targets you have explicit permission to test.")
        sys.exit(0)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_id = f"{target.replace('.', '_')}_{timestamp}"
    output_dir = os.path.join(args.output, session_id)
    os.makedirs(output_dir, exist_ok=True)

    print_info(f"Target: {target_url}")
    print_info(f"Platform: {args.platform.upper()}")
    print_info(f"Session: {session_id}")
    print_info(f"Output: {output_dir}\n")

    findings = []

    # ── RECON ──────────────────────────────────────────────
    if args.mode in ["full", "recon"]:
        print_info("Starting reconnaissance...")
        recon = Recon(target, target_url, timeout=args.timeout, threads=args.threads, verbose=args.verbose)
        recon_data = recon.run()
        recon_data["session_id"] = session_id
        recon_data["target"] = target
        recon_data["target_url"] = target_url
        print_success(f"Recon complete. Found {len(recon_data.get('subdomains', []))} subdomains, "
                      f"{len(recon_data.get('endpoints', []))} endpoints.\n")
    else:
        recon_data = {"target": target, "target_url": target_url,
                      "subdomains": [], "endpoints": [target_url], "session_id": session_id}

    if args.mode == "recon":
        Reporter(recon_data, [], args.platform, output_dir).save_recon()
        print_success("Recon data saved.")
        sys.exit(0)

    # ── SCAN ───────────────────────────────────────────────
    if args.mode in ["full", "scan"]:
        print_info("Starting vulnerability scan...")
        scanner = Scanner(recon_data, timeout=args.timeout, threads=args.threads, verbose=args.verbose)
        findings = scanner.run()
        print_success(f"Scan complete. Found {len(findings)} potential vulnerabilities.\n")

    # ── VERIFY ─────────────────────────────────────────────
    if not args.skip_verify and findings:
        print_info("Verifying findings...")
        verifier = Verifier(findings, timeout=args.timeout, verbose=args.verbose)
        findings = verifier.run()
        confirmed = [f for f in findings if f.get("confirmed")]
        print_success(f"Verification complete. {len(confirmed)}/{len(findings)} findings confirmed.\n")

    # ── REPORT ─────────────────────────────────────────────
    print_info("Generating report...")
    reporter = Reporter(recon_data, findings, args.platform, output_dir)
    report_path = reporter.generate()
    print_success(f"Report saved to: {report_path}")

    confirmed = [f for f in findings if f.get("confirmed")]
    print_info(f"\n{'='*50}")
    print_info(f"SUMMARY")
    print_info(f"{'='*50}")
    print_info(f"Target:              {target_url}")
    print_info(f"Subdomains found:    {len(recon_data.get('subdomains', []))}")
    print_info(f"Endpoints tested:    {len(recon_data.get('endpoints', []))}")
    print_info(f"Findings:            {len(findings)}")
    print_info(f"Confirmed:           {len(confirmed)}")
    print_info(f"Report:              {report_path}")
    print_info(f"{'='*50}\n")


if __name__ == "__main__":
    main()
