#!/usr/bin/env python3
import argparse, subprocess, json, sys

parser = argparse.ArgumentParser(description="Wrapper cho wpscan")
parser.add_argument("--url", required=True, help="Full target URL")
parser.add_argument("--api-token", help="WPScan API token (nếu cần)")
args = parser.parse_args()

cmd = ["wpscan", "--url", args.url, "--format", "json", "--random-user-agent"]
if args.api_token:
    cmd += ["--api-token", args.api_token]

proc = subprocess.run(cmd, capture_output=True, text=True)
if proc.returncode not in (0, 5):   # 5 = vulnerabilities found
    sys.exit(proc.returncode)

print(proc.stdout.strip())
