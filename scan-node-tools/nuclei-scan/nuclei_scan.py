#!/usr/bin/env python3
import json
import subprocess
import sys
import os
import requests
from vpn_manager import VPNManager

def scan_nuclei(target, tags="", severity="", templates=None):
    """
    Execute nuclei scan với options tùy chỉnh.
    """
    try:
        cmd = ["nuclei", "-u", target, "-json"]
        
        if tags:
            cmd += ["-tags", tags]
        
        if severity:
            cmd += ["-severity", severity]
            
        if templates:
            if isinstance(templates, list):
                for template in templates:
                    cmd += ["-t", template]
            else:
                cmd += ["-t", templates]
        
        print(f"[*] Running nuclei command: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Nuclei returns 0 for no vulnerabilities found, and may return non-zero for various conditions
        if proc.returncode not in (0, 1):
            print(f"[!] Nuclei exited with code {proc.returncode}")
            print(f"[!] Stderr: {proc.stderr}")
        
        # Parse JSON results từ stdout
        results = []
        if proc.stdout.strip():
            for line in proc.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        result = json.loads(line)
                        results.append(result)
                    except json.JSONDecodeError:
                        print(f"[!] Failed to parse line: {line}")
        
        print(f"[+] Nuclei scan completed for {target}, found {len(results)} issues")
        return results
        
    except subprocess.TimeoutExpired:
        print(f"[!] Nuclei scan timeout for {target}")
        return []
    except Exception as e:
        print(f"[!] Error running nuclei scan: {e}")
        return []

if __name__ == "__main__":
    print("[*] Starting Nuclei scan with VPN...")
    
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
        
        tags = options.get("tags", "")
        severity = options.get("severity", "")
        templates = options.get("templates", [])
        
        print(f"Nuclei scan starting for targets: {targets}")
        print(f"Options: tags={tags}, severity={severity}, templates={templates}")
        
        # Scan từng target
        all_results = []
        for target in targets:
            if target.strip():
                print(f"Scanning {target.strip()}...")
                vulnerabilities = scan_nuclei(target.strip(), tags, severity, templates)
                
                # Format results for Controller
                result = {
                    "target": target.strip(),
                    "vulnerabilities": vulnerabilities,
                    "vulnerability_count": len(vulnerabilities)
                }
                all_results.append(result)
                print(f"Found {len(vulnerabilities)} vulnerabilities for {target.strip()}")
        
        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and all_results:
            try:
                for result in all_results:
                    payload = {
                        "target": result["target"],
                        "workflow_id": workflow_id,
                        "vulnerabilities": result["vulnerabilities"],
                        "vulnerability_count": result["vulnerability_count"],
                        "scan_metadata": {
                            "tool": "nuclei-scan",
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
        
        print("Nuclei scan completed")
        
    finally:
        # Cleanup VPN
        if vpn_connected:
            print("[*] Disconnecting VPN...")
            vpn_manager.disconnect_vpn()
