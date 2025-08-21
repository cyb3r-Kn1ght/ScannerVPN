# modules/dns_lookup.py
import socket
import os
import sys
import json
import requests
from vpn_manager import VPNManager

def scan(target):
    """
    Resolve domain → list IP.
    Nếu input đã là IP thì vẫn trả về chính nó.
    """
    try:
        # Thử resolve domain name với Python socket
        ips = socket.gethostbyname_ex(target)[2]
        print(f"[+] Resolved {target} to: {ips}")
        return {'resolved_ips': ips}
    except socket.gaierror as e:
        print(f"[!] Socket resolution failed for {target}: {e}")
        
        # Fallback: thử dùng nslookup command
        try:
            import subprocess
            result = subprocess.run(['nslookup', target], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Parse nslookup output
                lines = result.stdout.split('\n')
                ips = []
                for line in lines:
                    if 'Address:' in line and not 'server' in line.lower():
                        ip = line.split('Address:')[1].strip()
                        if ip and not ip.startswith('#'):
                            ips.append(ip)
                
                if ips:
                    print(f"[+] nslookup resolved {target} to: {ips}")
                    return {'resolved_ips': ips}
        except Exception as lookup_error:
            print(f"[!] nslookup failed: {lookup_error}")
        
        # Check if target is already an IP
        try:
            socket.inet_aton(target)
            print(f"[+] {target} is already an IP address")
            return {'resolved_ips': [target]}
        except socket.error:
            # Không phải IP và không resolve được
            print(f"[!] Cannot resolve {target} - returning original")
            return {'resolved_ips': [target]}  # Return original target

if __name__ == "__main__":
    print("[*] Starting DNS Lookup scan with VPN...")
    
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

        vpn_profile_info = None
        # Sử dụng assigned VPN nếu có, nếu không thì dùng random
        if assigned_vpn:
            if vpn_manager.setup_specific_vpn(assigned_vpn):
                print(f"[+] Connected to assigned VPN: {assigned_vpn.get('hostname', 'Unknown')}")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = assigned_vpn
            else:
                print("[!] Failed to connect to assigned VPN, trying random...")
        if not vpn_connected:
            print("[*] No VPN assignment from Controller or failed, using random VPN...")
            if vpn_manager.setup_random_vpn():
                print("[+] VPN setup completed!")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                # Tạo info tối thiểu cho random VPN (nếu có thể lấy được filename/hostname)
                vpn_profile_info = {
                    "filename": network_info.get("vpn_filename", "random"),
                    "hostname": network_info.get("vpn_hostname", "random")
                }
            else:
                print("[!] VPN connection failed, continuing without VPN...")

        # Gửi thông báo connect VPN về controller nếu kết nối thành công
        if vpn_connected and controller_url and vpn_profile_info:
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
    except Exception as e:
        print(f"[!] VPN setup error: {e}, continuing without VPN...")
    
    try:
        # Đọc targets từ environment variable hoặc command line
        targets = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else sys.argv[1:]
        controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
        job_id = os.getenv("JOB_ID")
        workflow_id = os.getenv("WORKFLOW_ID")
        
        print(f"DNS Lookup scan starting for targets: {targets}")
        
        # Scan từng target
        all_results = []
        for target in targets:
            if target.strip():
                print(f"Scanning {target.strip()}...")
                result = scan(target.strip())
                print(f"Result for {target.strip()}: {result}")
                all_results.append({
                    "target": target.strip(),
                    "resolved_ips": result.get("resolved_ips", [])
                })
        
        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and all_results:
            try:
                for result in all_results:
                    has_findings = bool(result["resolved_ips"])
                    payload = {
                        "target": result["target"],
                        "resolved_ips": result["resolved_ips"],
                        "open_ports": [],
                        "workflow_id": workflow_id,
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "dns-lookup",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "vpn_local_ip": network_info.get("local_ip"),
                            "tun_interface": network_info.get("tun_interface", False)
                        }
                    }
                    print(f"Sending result to Controller: {payload}")
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                    print(f"Controller response: {response.status_code}")
            except Exception as e:
                print(f"Error sending results to Controller: {e}")
        
        print("DNS Lookup scan completed")
        
    finally:
        # Gửi thông báo disconnect VPN về controller nếu đã connect VPN
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
        # Cleanup VPN
        if vpn_connected:
            print("[*] Disconnecting VPN...")
            vpn_manager.disconnect_vpn()
