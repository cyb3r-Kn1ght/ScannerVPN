#!/usr/bin/env python3
import json
import subprocess
import sys
import os
import requests
from vpn_manager import VPNManager

def scan_wpscan(url, api_token=None, options=None):
    """
    Execute WPScan với options tùy chỉnh.
    """
    try:
        cmd = ["wpscan", "--url", url, "--format", "json", "--random-user-agent"]
        
        # Thêm API token nếu có
        if api_token:
            cmd += ["--api-token", api_token]
        elif os.getenv("WPSCAN_API_TOKEN"):
            cmd += ["--api-token", os.getenv("WPSCAN_API_TOKEN")]
        
        # Thêm các options khác
        if options:
            if options.get("enumerate"):
                enum_val = options["enumerate"]
                if isinstance(enum_val, list):
                    enum_val = ",".join(enum_val)
                cmd += ["--enumerate", enum_val]
            if options.get("plugins-detection"):
                cmd += ["--plugins-detection", options["plugins-detection"]]
            if options.get("themes-detection"):
                cmd += ["--themes-detection", options["themes-detection"]]
            if options.get("disable-tls-checks"):
                cmd += ["--disable-tls-checks"]
            if options.get("force"):
                cmd += ["--force"]
        
        print(f"[*] Running WPScan command: {' '.join(cmd[:6])}... (API token hidden)")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # WPScan returns 0 for success, 5 for vulnerabilities found
        if proc.returncode not in (0, 5):
            print(f"[!] WPScan exited with code {proc.returncode}")
            print(f"[!] Stderr: {proc.stderr}")
            return {}
        
        # Parse JSON result
        if proc.stdout.strip():
            try:
                result = json.loads(proc.stdout)
                print(f"[+] WPScan completed for {url}")
                return result
            except json.JSONDecodeError as e:
                print(f"[!] Failed to parse WPScan JSON output: {e}")
                print(f"[!] Output: {proc.stdout[:500]}...")
                return {}
        
        return {}
        
    except subprocess.TimeoutExpired:
        print(f"[!] WPScan timeout for {url}")
        return {}
    except Exception as e:
        print(f"[!] Error running WPScan: {e}")
        return {}

if __name__ == "__main__":
    print("[*] Starting WPScan with VPN...")
    
    # Setup VPN trước khi scan
    vpn_manager = VPNManager()
    vpn_connected = False
    network_info = {}
    
    # Lấy VPN assignment từ Controller (nếu có)
    assigned_vpn = None
    controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
    vpn_assignment = os.getenv("VPN_ASSIGNMENT")  # VPN được assign từ Controller
    
    if vpn_assignment:
        try:
            assigned_vpn = json.loads(vpn_assignment)
            print(f"[*] Received VPN assignment from Controller: {assigned_vpn.get('hostname', 'Unknown')}")
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse VPN assignment: {e}")
    
    # Thử setup VPN (optional - có thể skip nếu proxy server không available)
    try:
        print("[*] Checking initial network status...")
        initial_info = vpn_manager.get_network_info()
        print(f"[*] Initial IP: {initial_info['public_ip']}")
        
        # Sử dụng assigned VPN nếu có, nếu không thì dùng random
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
            # Fallback to random VPN nếu không có assignment
            print("[*] No VPN assignment from Controller, using random VPN...")
            if vpn_manager.setup_random_vpn():
                print("[+] VPN setup completed!")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
            else:
                print("[!] VPN connection failed, continuing without VPN...")
    except Exception as e:
        print(f"[!] VPN setup error: {e}, continuing without VPN...")
    
    try:
        # Đọc targets và options từ environment variables
        targets = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else sys.argv[1:]
        controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
        job_id = os.getenv("JOB_ID")
        workflow_id = os.getenv("WORKFLOW_ID")
        
        # Parse scan options từ environment
        options_str = os.getenv("SCAN_OPTIONS", "{}")
        try:
            options = json.loads(options_str)
        except json.JSONDecodeError:
            options = {}
        
        api_token = options.get("api_token")
        
        print(f"WPScan starting for targets: {targets}")
        print(f"Options: {options}")
        
        # Scan từng target
        all_results = []
        for target in targets:
            if target.strip():
                print(f"Scanning {target.strip()}...")
                wp_result = scan_wpscan(target.strip(), api_token, options)
                
                # Extract key information từ WPScan result
                vulnerabilities = []
                if wp_result.get("vulnerabilities"):
                    for vuln_category, vulns in wp_result["vulnerabilities"].items():
                        if isinstance(vulns, list):
                            vulnerabilities.extend(vulns)
                        elif isinstance(vulns, dict):
                            vulnerabilities.append(vulns)
                
                # Format results for Controller
                result = {
                    "target": target.strip(),
                    "wp_scan_result": wp_result,
                    "vulnerabilities": vulnerabilities,
                    "vulnerability_count": len(vulnerabilities),
                    "wordpress_version": wp_result.get("version", {}).get("number") if wp_result.get("version") else None,
                    "theme": wp_result.get("main_theme", {}).get("style_name") if wp_result.get("main_theme") else None
                }
                all_results.append(result)
                print(f"Found {len(vulnerabilities)} vulnerabilities for {target.strip()}")
        
        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and all_results:
            try:
                for result in all_results:
                    has_findings = bool(result["vulnerabilities"])
                    payload = {
                        "target": result["target"],
                        "workflow_id": workflow_id,
                        "wp_scan_result": result["wp_scan_result"],
                        "vulnerabilities": result["vulnerabilities"],
                        "vulnerability_count": result["vulnerability_count"],
                        "wordpress_version": result["wordpress_version"],
                        "theme": result["theme"],
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "wpscan-scan",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "vpn_local_ip": network_info.get("local_ip"),
                            "tun_interface": network_info.get("tun_interface", False),
                            "scan_options": options
                        }
                    }
                    print(f"Sending result to Controller: {payload}")
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                    print(f"Controller response: {response.status_code}")
            except Exception as e:
                print(f"Error sending results to Controller: {e}")
        
        print("WPScan completed")
        
    finally:
        # Cleanup VPN
        if vpn_connected:
            print("[*] Disconnecting VPN...")
            vpn_manager.disconnect_vpn()
