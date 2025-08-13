#!/usr/bin/env python3
import argparse, subprocess, sys, json, tempfile, re, os, requests
from vpn_manager import VPNManager

def has_json_report():
    try:
        help_txt = subprocess.run(
            ["python3", "/opt/dirsearch/dirsearch.py", "-h"],
            capture_output=True, text=True
        ).stdout.lower()
        return "--json-report" in help_txt
    except Exception:
        return False

def run(cmd):
    """Chạy lệnh, nếu lỗi thì trả JSON báo lỗi kèm stderr"""
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip()
        print(json.dumps({"error": "dirsearch failed", "code": p.returncode, "stderr": err}, ensure_ascii=False))
        sys.exit(p.returncode)
    return p

# ví dụ chạy test nhanh
# docker run --rm dirsearch-scan:dev `
#   --url http://testphp.vulnweb.com `
#   --no-extensions `
#   --wordlist /opt/dirsearch/db/dicc.txt `
#   --include-status 200,204,301,302,307,401,403 `
#   --threads 5


if __name__ == "__main__":
    print("[*] Starting dirsearch scan with VPN...")
    # Setup VPN trước khi scan
    vpn_manager = VPNManager()
    vpn_connected = False
    network_info = {}
    assigned_vpn = None
    controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
    vpn_assignment = os.getenv("VPN_ASSIGNMENT")
    if vpn_assignment:
        try:
            assigned_vpn = json.loads(vpn_assignment)
            print(f"[*] Received VPN assignment from Controller: {assigned_vpn.get('hostname', 'Unknown')}")
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse VPN assignment: {e}")
    try:
        print("[*] Checking initial network status...")
        initial_info = vpn_manager.get_network_info()
        print(f"[*] Initial IP: {initial_info['public_ip']}")
        if assigned_vpn:
            if vpn_manager.setup_specific_vpn(assigned_vpn):
                print(f"[+] Connected to assigned VPN: {assigned_vpn.get('hostname', 'Unknown')}")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
            else:
                print("[!] Failed to connect to assigned VPN, trying random...")
                if vpn_manager.setup_random_vpn():
                    print("[+] Connected to random VPN as fallback!")
                    vpn_manager.print_vpn_status()
                    network_info = vpn_manager.get_network_info()
                    vpn_connected = True
        else:
            print("[*] No VPN assignment from Controller, using random VPN...")
            if vpn_manager.setup_random_vpn():
                print("[+] VPN setup completed!")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
            else:
                print("[!] VPN connection failed, continuing without VPN...")
        # Parse arguments
        parser = argparse.ArgumentParser(description="Wrapper cho dirsearch -> JSON")
        parser.add_argument("--url", help="URL đơn lẻ")
        parser.add_argument("--url-file", help="File chứa nhiều URL, mỗi dòng một URL")
        parser.add_argument("--threads", type=int, default=30)
        parser.add_argument("--recursive", action="store_true")
        parser.add_argument("--wordlist", help="Đường dẫn wordlist trong container")
        parser.add_argument("--include-status", help="VD: 200,204,301,302,307,401,403")
        parser.add_argument("--extensions", default=None, help="VD: php,js,txt (mặc định None)")
        parser.add_argument("--no-extensions", action="store_true", help="Không dùng -e để quét cả đường dẫn không đuôi")
        args = parser.parse_args()

        if not args.url and not args.url_file:
            print(json.dumps({"error":"missing --url or --url-file"})); sys.exit(2)
        if args.extensions and args.no_extensions:
            print(json.dumps({"error":"conflict: --extensions và --no-extensions"})); sys.exit(2)

        # Base command
        base_cmd = ["python3", "/opt/dirsearch/dirsearch.py", "-t", str(args.threads)]
        if args.recursive:
            base_cmd += ["-r"]
        if args.wordlist:
            base_cmd += ["-w", args.wordlist]
        if args.include_status:
            base_cmd += ["-i", args.include_status]
        if args.extensions and not args.no_extensions:
            base_cmd += ["-e", args.extensions]
        # Mục tiêu
        if args.url_file:
            base_cmd += ["-l", args.url_file]
        else:
            base_cmd += ["-u", args.url]

        # Ưu tiên JSON-report nếu có
        findings = []
        if has_json_report():
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
                out = f.name
            cmd = base_cmd + ["--json-report", out]
            run(cmd)
            with open(out, "r", encoding="utf-8", errors="ignore") as fh:
                raw = fh.read().strip()
            try:
                # In ra nội dung JSON report nguyên trạng
                findings = json.loads(raw).get("results", []) if raw else []
                print(raw)
            except Exception:
                print(json.dumps({"error":"invalid json report", "path": out}, ensure_ascii=False))
        else:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
                out = f.name
            cmd = base_cmd + ["-o", out]
            run(cmd)
            pat = re.compile(
                r"^(?:\[[^\]]+\]\s*)?"               # optional [time] prefix
                r"(?P<code>\d{3})\s+"                # status
                r"(?P<size>\S+)?\s*"                 # optional size "169B", "5KB"
                r"(?P<url>https?://\S+?)"            # source URL (non-greedy)
                r"(?:\s*->\s*(?P<redirect>\S+))?"    # optional "-> target"
                r"\s*$",
                re.IGNORECASE
            )
            with open(out, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    m = pat.search(line)
                    if not m:
                        continue
                    code = int(m.group("code"))
                    url  = m.group("url").rstrip(",);")
                    size = (m.group("size") or "").strip()
                    red  = m.group("redirect")
                    if red:
                        red = red.rstrip(",);")
                    item = {"status": code, "url": url}
                    if size:
                        item["size"] = size
                    if red:
                        item["redirect_to"] = red
                    findings.append(item)
            print(json.dumps({"findings": findings}, ensure_ascii=False))

        # Gửi metadata về Controller nếu có
        job_id = os.getenv("JOB_ID")
        workflow_id = os.getenv("WORKFLOW_ID")
        target_url = args.url if args.url else None
        if controller_url and target_url:
            try:
                payload = {
                    "target": target_url,
                    "resolved_ips": [],
                    "open_ports": [],
                    "workflow_id": workflow_id,
                    "scan_metadata": {
                        "tool": "dirsearch-scan",
                        "job_id": job_id,
                        "vpn_used": vpn_connected,
                        "scan_ip": network_info.get("public_ip", "Unknown"),
                        "vpn_local_ip": network_info.get("local_ip"),
                        "tun_interface": network_info.get("tun_interface", False),
                        "dirsearch_results": findings,
                        "total_findings": len(findings)
                    }
                }
                print(f"[*] Sending result to Controller for {target_url}: {len(findings)} findings")
                response = requests.post(f"{controller_url}/api/scan_results", json=payload, timeout=30)
                print(f"[*] Controller response: {response.status_code}")
            except Exception as e:
                print(f"[!] Error sending results to Controller: {e}")
    finally:
        if vpn_connected:
            print("[*] Disconnecting VPN...")
            vpn_manager.disconnect_vpn()
else:
    # ...existing code...
    pass

if not args.url and not args.url_file:
    print(json.dumps({"error":"missing --url or --url-file"})); sys.exit(2)
if args.extensions and args.no_extensions:
    print(json.dumps({"error":"conflict: --extensions và --no-extensions"})); sys.exit(2)

# Base command
base_cmd = ["python3", "/opt/dirsearch/dirsearch.py", "-t", str(args.threads)]
if args.recursive:
    base_cmd += ["-r"]
if args.wordlist:
    base_cmd += ["-w", args.wordlist]
if args.include_status:
    base_cmd += ["-i", args.include_status]
if args.extensions and not args.no_extensions:
    base_cmd += ["-e", args.extensions]

# Mục tiêu
if args.url_file:
    base_cmd += ["-l", args.url_file]
else:
    base_cmd += ["-u", args.url]

# Ưu tiên JSON-report nếu có
if has_json_report():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
        out = f.name
    cmd = base_cmd + ["--json-report", out]
    run(cmd)  # lỗi sẽ in JSON error & exit
    with open(out, "r", encoding="utf-8", errors="ignore") as fh:
        raw = fh.read().strip()
    try:
        # In ra nội dung JSON report nguyên trạng
        json.loads(raw)  # validate
        print(raw)
    except Exception:
        # Nếu vì lý do gì file không phải JSON, fallback parse text (ít gặp)
        print(json.dumps({"error":"invalid json report", "path": out}, ensure_ascii=False))
else:
    # Fallback: xuất text rồi parse
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        out = f.name
    cmd = base_cmd + ["-o", out]
    run(cmd)

    findings = []
    # Ví dụ dòng: "301   169B http://...  ->  http://.../"
    pat = re.compile(
        r"^(?:\[[^\]]+\]\s*)?"               # optional [time] prefix
        r"(?P<code>\d{3})\s+"                # status
        r"(?P<size>\S+)?\s*"                 # optional size "169B", "5KB"
        r"(?P<url>https?://\S+?)"            # source URL (non-greedy)
        r"(?:\s*->\s*(?P<redirect>\S+))?"    # optional "-> target"
        r"\s*$",
        re.IGNORECASE
    )

    with open(out, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = pat.search(line)
            if not m:
                continue
            code = int(m.group("code"))
            url  = m.group("url").rstrip(",);")
            size = (m.group("size") or "").strip()
            red  = m.group("redirect")
            if red:
                red = red.rstrip(",);")
            item = {"status": code, "url": url}
            if size:
                item["size"] = size
            if red:
                item["redirect_to"] = red
            findings.append(item)

    print(json.dumps({"findings": findings}, ensure_ascii=False))

