#!/usr/bin/env python3
import argparse, subprocess, sys, json, tempfile, re, os, requests
from vpn_manager import VPNManager

def run(cmd):
    """Chạy lệnh, nếu lỗi thì trả JSON báo lỗi kèm stderr"""
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip()
        print(json.dumps({"error": "sqlmap failed", "code": p.returncode, "stderr": err}, ensure_ascii=False))
        sys.exit(p.returncode)
    return p

# ví dụ chạy test nhanh
# docker run --rm sqlmap-scan:dev `
#   --url "http://testphp.vulnweb.com/search.php?test=query" `
#   --batch `
#   --level 1 `
#   --risk 1

if __name__ == "__main__":
    print("[*] Starting sqlmap scan with VPN...")
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
                if arg in ["--url", "--url-file", "--threads", "--level", "--risk", "--technique", "--dbms"]:
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

        parser = argparse.ArgumentParser(description="Wrapper cho sqlmap -> JSON")
        parser.add_argument("--url", help="URL đơn lẻ")
        parser.add_argument("--url-file", help="File chứa nhiều URL, mỗi dòng một URL")
        parser.add_argument("--threads", type=int, default=1, help="Số threads (mặc định 1)")
        parser.add_argument("--level", type=int, default=1, help="Level kiểm tra (1-5)")
        parser.add_argument("--risk", type=int, default=1, help="Risk level (1-3)")
        parser.add_argument("--technique", help="Technique: B,E,U,S,T")
        parser.add_argument("--dbms", help="Force DBMS: mysql,oracle,postgresql,mssql,etc")
        parser.add_argument("--batch", action="store_true", help="Non-interactive mode")
        parser.add_argument("--random-agent", action="store_true", help="Use random User-Agent")
        parser.add_argument("--tamper", help="Tamper scripts")
        parser.add_argument("--delay", type=float, help="Delay giữa requests (seconds)")
        args = parser.parse_args()

        if not args.url and not args.url_file:
            print(json.dumps({"error":"missing --url or --url-file"})); sys.exit(2)

        # Tạo output directory tạm
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "sqlmap_output")
            os.makedirs(output_dir, exist_ok=True)

            # Base command
            base_cmd = ["python3", "/opt/sqlmap/sqlmap.py"]
            base_cmd += ["--output-dir", output_dir]
            base_cmd += ["--threads", str(args.threads)]
            base_cmd += ["--level", str(args.level)]
            base_cmd += ["--risk", str(args.risk)]
            
            if args.batch:
                base_cmd += ["--batch"]
            if args.random_agent:
                base_cmd += ["--random-agent"]
            if args.technique:
                base_cmd += ["--technique", args.technique]
            if args.dbms:
                base_cmd += ["--dbms", args.dbms]
            if args.tamper:
                base_cmd += ["--tamper", args.tamper]
            if args.delay:
                base_cmd += ["--delay", str(args.delay)]

            # Mục tiêu
            if args.url_file:
                base_cmd += ["-m", args.url_file]
            else:
                base_cmd += ["-u", args.url]

            # Chạy sqlmap
            print(f"[*] Running: {' '.join(base_cmd)}")
            p = subprocess.run(base_cmd, capture_output=True, text=True)
            
            # Parse kết quả
            findings = []
            vulnerabilities = []
            
            # Tìm log files trong output directory
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    if file.endswith('.log'):
                        log_path = os.path.join(root, file)
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            log_content = f.read()
                            
                            # Parse vulnerabilities từ log
                            if 'sqlmap identified the following injection point' in log_content:
                                vuln_match = re.findall(
                                    r'Parameter: ([^\n]+).*?Type: ([^\n]+).*?Title: ([^\n]+)',
                                    log_content, re.DOTALL
                                )
                                for param, vuln_type, title in vuln_match:
                                    vulnerabilities.append({
                                        "parameter": param.strip(),
                                        "type": vuln_type.strip(),
                                        "title": title.strip(),
                                        "url": args.url if args.url else "multiple"
                                    })
                            
                            # Parse databases nếu có
                            db_match = re.findall(r'available databases \[(\d+)\]:(.*?)(?:\[|$)', log_content, re.DOTALL)
                            for count, db_list in db_match:
                                databases = [db.strip() for db in db_list.split('\n') if db.strip() and not db.strip().startswith('[')]
                                if databases:
                                    findings.append({
                                        "type": "databases",
                                        "count": int(count),
                                        "databases": databases
                                    })

            # Chuẩn bị kết quả JSON
            result = {
                "vulnerabilities": vulnerabilities,
                "findings": findings,
                "stdout": p.stdout,
                "stderr": p.stderr,
                "returncode": p.returncode,
                "has_vulnerabilities": len(vulnerabilities) > 0
            }

            print(json.dumps(result, ensure_ascii=False))

            # Gửi metadata về Controller nếu có
            job_id = os.getenv("JOB_ID")
            workflow_id = os.getenv("WORKFLOW_ID")
            target_url = args.url if args.url else None
            
            if controller_url and target_url:
                try:
                    has_findings = len(vulnerabilities) > 0
                    payload = {
                        "target": target_url,
                        "resolved_ips": [],
                        "open_ports": [],
                        "workflow_id": workflow_id,
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "sqlmap-scan",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "vpn_local_ip": network_info.get("local_ip"),
                            "tun_interface": network_info.get("tun_interface", False),
                            "sqlmap_results": vulnerabilities,
                            "total_vulnerabilities": len(vulnerabilities),
                            "databases_found": len(findings)
                        }
                    }
                    print(f"[*] Sending result to Controller for {target_url}: {len(vulnerabilities)} vulnerabilities")
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload, timeout=30)
                    print(f"[*] Controller response: {response.status_code}")
                except Exception as e:
                    print(f"[!] Error sending results to Controller: {e}")

    finally:
        if vpn_connected:
            print("[*] Disconnecting VPN...")
            vpn_manager.disconnect_vpn()