#!/usr/bin/env python3
import argparse, json, subprocess, sys, tempfile, os

parser = argparse.ArgumentParser(description="Wrapper cho nuclei")
parser.add_argument("--target", required=True, help="URL hoặc IP")
parser.add_argument("--tags", default="", help="Tag template (optional)")
args = parser.parse_args()

cmd = ["nuclei", "-u", args.target, "-json"]
if args.tags:
    cmd += ["-tags", args.tags]

proc = subprocess.run(cmd, capture_output=True, text=True)
if proc.returncode not in (0, 1):           
    sys.exit(proc.returncode)

print(proc.stdout.strip())
