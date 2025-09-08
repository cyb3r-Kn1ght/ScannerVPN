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
    vpn_profile_info = None
    if vpn_assignment:
        try:
            assigned_vpn = json.loads(vpn_assignment)
            vpn_profile_info = assigned_vpn
            print(f"[*] Received VPN assignment from Controller: {assigned_vpn.get('hostname', 'Unknown')}")
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse VPN assignment: {e}")
    try:
        # ...existing VPN setup and scan logic...
        print("[*] Checking initial network status...")
        initial_info = vpn_manager.get_network_info()
        print(f"[*] Initial IP: {initial_info['public_ip']}")
        if assigned_vpn:
            if vpn_manager.setup_specific_vpn(assigned_vpn):
                print(f"[+] Connected to assigned VPN: {assigned_vpn.get('hostname', 'Unknown')}")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                # Notify controller: connect
                if controller_url and vpn_profile_info:
                    try:
                        job_id = os.getenv("JOB_ID")
                        payload = {
                            "filename": vpn_profile_info.get("filename"),
                            "action": "connect",
                            "scanner_id": job_id
                        }
                        print(f"[+] Notify controller: connect {payload}")
                        resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                        print(f"[+] Controller connect response: {resp.status_code}")
                    except Exception as notify_err:
                        print(f"[!] Failed to notify controller connect: {notify_err}")
            else:
                print("[!] Failed to connect to assigned VPN, trying random...")
                if vpn_manager.setup_random_vpn():
                    print("[+] Connected to random VPN as fallback!")
                    vpn_manager.print_vpn_status()
                    network_info = vpn_manager.get_network_info()
                    vpn_connected = True
                    # Notify controller: connect (random)
                    vpn_profile_info = {
                        "filename": network_info.get("vpn_filename", "random"),
                        "hostname": network_info.get("vpn_hostname", "random")
                    }
                    if controller_url and vpn_profile_info:
                        try:
                            job_id = os.getenv("JOB_ID")
                            payload = {
                                "filename": vpn_profile_info.get("filename"),
                                "action": "connect",
                                "scanner_id": job_id
                            }
                            print(f"[+] Notify controller: connect {payload}")
                            resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                            print(f"[+] Controller connect response: {resp.status_code}")
                        except Exception as notify_err:
                            print(f"[!] Failed to notify controller connect: {notify_err}")
        else:
            print("[*] No VPN assignment from Controller, using random VPN...")
            if vpn_manager.setup_random_vpn():
                print("[+] VPN setup completed!")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = {
                    "filename": network_info.get("vpn_filename", "random"),
                    "hostname": network_info.get("vpn_hostname", "random")
                }
                if controller_url and vpn_profile_info:
                    try:
                        job_id = os.getenv("JOB_ID")
                        payload = {
                            "filename": vpn_profile_info.get("filename"),
                            "action": "connect",
                            "scanner_id": job_id
                        }
                        print(f"[+] Notify controller: connect {payload}")
                        resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                        print(f"[+] Controller connect response: {resp.status_code}")
                    except Exception as notify_err:
                        print(f"[!] Failed to notify controller connect: {notify_err}")

        # --- Robust argument handling: convert positional/ENV targets to --url/--url-file ---
        targets_env = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else []
        targets_env = [t.strip() for t in targets_env if t.strip()]

        import shlex
        extra_targets = []
        new_argv = [sys.argv[0]]
        i = 1
        while i < len(sys.argv):
            arg = sys.argv[i]
            if arg.startswith('-'):
                new_argv.append(arg)
                i += 1
                # copy value nếu là flag có value
                if arg in ["--url", "--url-file", "--threads", "--wordlist", "--include-status", "--extensions", "--wordlist-start", "--wordlist-end"]:
                    if i < len(sys.argv):
                        new_argv.append(sys.argv[i])
                        i += 1
            else:
                extra_targets.append(arg)
                i += 1

        # Nếu có extra_targets, ưu tiên --url-file nếu nhiều target, --url nếu 1 target
        if extra_targets:
            if len(extra_targets) == 1:
                new_argv.extend(["--url", extra_targets[0]])
            else:
                with open('/tmp/targets.txt', 'w') as f:
                    for t in extra_targets:
                        f.write(f"{t}\n")
                new_argv.extend(["--url-file", '/tmp/targets.txt'])

        # Nếu có targets_env, ghi ra file tạm (ưu tiên targets_env hơn positional)
        if targets_env:
            with open('/tmp/targets.txt', 'w') as f:
                for target in targets_env:
                    f.write(f"{target}\n")
            if '--url-file' not in new_argv:
                new_argv.extend(['--url-file', '/tmp/targets.txt'])

        sys.argv = new_argv

        parser = argparse.ArgumentParser(description="Wrapper cho dirsearch -> JSON")
        parser.add_argument("--url", help="URL đơn lẻ")
        parser.add_argument("--url-file", help="File chứa nhiều URL, mỗi dòng một URL")
        parser.add_argument("--threads", type=int, default=30)
        parser.add_argument("--recursive", action="store_true")
        parser.add_argument("--wordlist", help="Đường dẫn wordlist trong container")
        parser.add_argument("--wordlist-start", type=int, default=None, help="Dòng bắt đầu (0-based)")
        parser.add_argument("--wordlist-end", type=int, default=None, help="Dòng kết thúc (0-based, inclusive)")
        parser.add_argument("--include-status", help="VD: 200,204,301,302,307,401,403")
        parser.add_argument("--extensions", default=None, help="VD: php,js,txt (mặc định None)")
        parser.add_argument("--no-extensions", action="store_true", help="Không dùng -e để quét cả đường dẫn không đuôi")
        args = parser.parse_args()

        # Debug thông tin scan ngay sau khi parse args
        print(f"[DEBUG] job_id: {os.getenv('JOB_ID')}")
        print(f"[DEBUG] wordlist_path: {getattr(args, 'wordlist', None)}")
        print(f"[DEBUG] wordlist_start: {getattr(args, 'wordlist_start', None)}")
        print(f"[DEBUG] wordlist_end: {getattr(args, 'wordlist_end', None)}")
        try:
            if getattr(args, 'wordlist', None):
                with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    debug_lines = f.readlines()
                print(f"[DEBUG] wordlist_lines: {len(debug_lines)}")
        except Exception as e:
            print(f"[DEBUG] wordlist read error: {e}")
        print(f"[DEBUG] targets: {getattr(args, 'url', None) or getattr(args, 'url_file', None)}")
        print(f"[DEBUG] threads: {getattr(args, 'threads', None)}")
        print(f"[DEBUG] extensions: {getattr(args, 'extensions', None)}")
        print(f"[DEBUG] include_status: {getattr(args, 'include_status', None)}")
        print(f"[DEBUG] recursive: {getattr(args, 'recursive', None)}")

        if not args.url and not args.url_file:
            print(json.dumps({"error":"missing --url or --url-file"})); sys.exit(2)
        if args.extensions and args.no_extensions:
            print(json.dumps({"error":"conflict: --extensions và --no-extensions"})); sys.exit(2)

        # Xử lý wordlist_start/end nếu có
        wordlist_path = args.wordlist
        if args.wordlist and args.wordlist_start is not None and args.wordlist_end is not None:
            # Tạo file wordlist tạm chỉ chứa các dòng từ start đến end
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start = max(0, args.wordlist_start)
            end = min(len(lines)-1, args.wordlist_end)
            subset = lines[start:end+1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8") as tf:
                for line in subset:
                    tf.write(line)
                wordlist_path = tf.name
        # Prepare allowed_status for post-filtering
        # Lấy đúng tham số include_status từ request (params)
        include_status_raw = getattr(args, "include_status", None)
        if include_status_raw:
            allowed_status = set(int(s.strip()) for s in include_status_raw.split(",") if s.strip().isdigit())
        else:
            allowed_status = set()
        # Base command
        base_cmd = ["python3", "/opt/dirsearch/dirsearch.py", "-t", str(args.threads)]
        if args.recursive:
            base_cmd += ["-r"]
        if wordlist_path:
            base_cmd += ["-w", wordlist_path]
        if include_status_raw:
            base_cmd += ["-i", include_status_raw]
        if args.extensions and not args.no_extensions:
            base_cmd += ["-e", args.extensions]
        # Mục tiêu
        if args.url_file:
            base_cmd += ["-l", args.url_file]
        else:
            base_cmd += ["-u", args.url]

        # Debug thông tin quét
        print(f"[DEBUG] job_id: {os.getenv('JOB_ID')}")
        print(f"[DEBUG] wordlist_path: {wordlist_path}")
        print(f"[DEBUG] wordlist_start: {getattr(args, 'wordlist_start', None)}")
        print(f"[DEBUG] wordlist_end: {getattr(args, 'wordlist_end', None)}")
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                debug_lines = f.readlines()
            print(f"[DEBUG] wordlist_lines: {len(debug_lines)}")
        except Exception as e:
            print(f"[DEBUG] wordlist read error: {e}")
        print(f"[DEBUG] targets: {args.url or args.url_file}")
        print(f"[DEBUG] threads: {args.threads}")
        print(f"[DEBUG] extensions: {args.extensions}")
        print(f"[DEBUG] include_status: {getattr(args, 'include_status', None)}")
        print(f"[DEBUG] recursive: {args.recursive}")

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
                all_results = json.loads(raw).get("results", []) if raw else []
                # Post-filter by allowed_status
                if allowed_status:
                    findings = [item for item in all_results if int(item.get("status", 0)) in allowed_status]
                else:
                    findings = all_results
                print(json.dumps({"findings": findings}, ensure_ascii=False))
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
                    if allowed_status and code not in allowed_status:
                        continue
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
                has_findings = bool(findings)
                payload = {
                    "target": target_url,
                    "resolved_ips": [],
                    "open_ports": [],
                    "workflow_id": workflow_id,
                    "has_findings": has_findings,
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
    except Exception as main_err:
        print(f"[!] Unhandled error: {main_err}")
    finally:
        # Notify controller: disconnect
        if vpn_connected and controller_url and vpn_profile_info:
            try:
                job_id = os.getenv("JOB_ID")
                payload = {
                    "filename": vpn_profile_info.get("filename"),
                    "action": "disconnect",
                    "scanner_id": job_id
                }
                print(f"[+] Notify controller: disconnect {payload}")
                resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                print(f"[+] Controller disconnect response: {resp.status_code}")
            except Exception as notify_err:
                print(f"[!] Failed to notify controller disconnect: {notify_err}")
        if vpn_connected:
            print("[*] Disconnecting VPN...")
            vpn_manager.disconnect_vpn()


