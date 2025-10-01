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


        # Luôn lấy danh sách target từ ENV TARGETS
        targets_env = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else []
        targets_env = [t.strip() for t in targets_env if t.strip()]
        if not targets_env:
            print(json.dumps({"error": "missing TARGETS env"})); sys.exit(2)



        # Luôn lấy tham số từ ENV SCAN_OPTIONS
        scan_options = os.getenv("SCAN_OPTIONS")
        if not scan_options:
            print(json.dumps({"error": "missing SCAN_OPTIONS env"})); sys.exit(2)
        try:
            options = json.loads(scan_options)
        except Exception as e:
            print(json.dumps({"error": f"invalid SCAN_OPTIONS: {e}"})); sys.exit(2)

        threads = options.get("threads", 1)
        level = options.get("level", 1)
        risk = options.get("risk", 1)
        technique = options.get("technique")
        dbms = options.get("dbms")
        batch = options.get("batch", False)
        random_agent = options.get("random_agent", False)
        tamper = options.get("tamper")
        delay = options.get("delay")
        data = options.get("data")
        cookie = options.get("cookie")
        headers = options.get("headers")
        timeout = options.get("timeout", 30)
        retries = options.get("retries", 2)
        identify_waf = options.get("identify_waf", False)
        skip_urlencode = options.get("skip_urlencode", False)
        parameter = options.get("parameter")


        # Lặp qua từng target, quét và gửi kết quả từng target một
        for target_url in targets_env:
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = os.path.join(temp_dir, "sqlmap_output")
                os.makedirs(output_dir, exist_ok=True)

                base_cmd = ["python3", "/opt/sqlmap/sqlmap.py"]
                base_cmd += ["--output-dir", output_dir]
                base_cmd += ["--threads", str(threads)]
                base_cmd += ["--level", str(level)]
                base_cmd += ["--risk", str(risk)]
                if batch:
                    base_cmd += ["--batch"]
                if random_agent:
                    base_cmd += ["--random-agent"]
                if technique:
                    base_cmd += ["--technique", technique]
                if dbms:
                    base_cmd += ["--dbms", dbms]
                if tamper:
                    base_cmd += ["--tamper", tamper]
                if delay:
                    base_cmd += ["--delay", str(delay)]
                if parameter:
                    base_cmd += ["-p", parameter]
                base_cmd += ["-u", target_url]

                print(f"[*] Running: {' '.join(base_cmd)}")
                p = subprocess.run(base_cmd, capture_output=True, text=True)

                findings = []
                vulnerabilities = []

                for root, dirs, files in os.walk(output_dir):
                    for file in files:
                        if file.endswith('.log'):
                            log_path = os.path.join(root, file)
                            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                log_content = f.read()
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
                                            "url": target_url
                                        })
                                db_match = re.findall(r'available databases \[(\d+)\]:(.*?)(?:\[|$)', log_content, re.DOTALL)
                                for count, db_list in db_match:
                                    databases = [db.strip() for db in db_list.split('\n') if db.strip() and not db.strip().startswith('[')]
                                    if databases:
                                        findings.append({
                                            "type": "databases",
                                            "count": int(count),
                                            "databases": databases
                                        })

                result = {
                    "vulnerabilities": vulnerabilities,
                    "findings": findings,
                    "stdout": p.stdout,
                    "stderr": p.stderr,
                    "returncode": p.returncode,
                    "has_vulnerabilities": len(vulnerabilities) > 0
                }

                print(json.dumps(result, ensure_ascii=False))

                job_id = os.getenv("JOB_ID")
                workflow_id = os.getenv("WORKFLOW_ID")

                if controller_url:
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