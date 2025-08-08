# modules/httpx_scan.py
import subprocess
import json
import os
import sys
import requests
from vpn_manager import VPNManager

def scan(target, options=None):
    """
    Dùng httpx để quét HTTP:
      - ip, port, service, status-code, headers, protocol
    """
    # httpx đầu ra JSON, mỗi dòng là 1 object
    cmd = [
        'httpx',
        '-silent',
        '-json',
        '-u', target
    ]
    
    # Add options if provided
    if options:
        if options.get("follow_redirects"):
            cmd.append('-fr')
        if options.get("include_response"):
            cmd.append('-include-response')
        if options.get("timeout"):
            cmd.extend(['-timeout', str(options["timeout"])])
        if options.get("retries"):
            cmd.extend(['-retries', str(options["retries"])])
        if options.get("ports"):
            cmd.extend(['-ports', options["ports"]])
    
    try:
        print(f"[*] Running httpx command: {' '.join(cmd[:4])}... {target}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        
        if not lines:
            print(f"[!] No response from httpx for {target}")
            return {}

        # Parse multiple results if available
        results = []
        for line in lines:
            try:
                data = json.loads(line)
                results.append({
                    'ip': data.get('ip'),
                    'port': data.get('port'),
                    'service': data.get('service'),
                    'responseHeaders': data.get('headers', {}),
                    'statusCode': data.get('status-code'),
                    'protocol': data.get('http-protocol'),
                    'url': data.get('url'),
                    'title': data.get('title'),
                    'content_length': data.get('content-length'),
                    'webserver': data.get('webserver')
                })
            except json.JSONDecodeError as e:
                print(f"[!] Failed to parse line: {line}, error: {e}")
        
        print(f"[+] HTTPx scan found {len(results)} endpoints for {target}")
        return {
            'metadata': results[0] if results else {},
            'all_endpoints': results
        }
        
    except subprocess.TimeoutExpired:
        print(f"[!] HTTPx scan timeout for {target}")
        return {}
    except Exception as e:
        print(f"[!] Error running httpx scan: {e}")
        return {}

if __name__ == "__main__":
    print("[*] Starting HTTPx scan with VPN...")
    
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
        
        # Parse scan options từ environment
        options_str = os.getenv("SCAN_OPTIONS", "{}")
        try:
            options = json.loads(options_str)
        except json.JSONDecodeError:
            options = {}
        
        print(f"HTTPx scan starting for targets: {targets}")
        print(f"Options: {options}")
        
        # Scan từng target
        all_results = []
        for target in targets:
            if target.strip():
                print(f"Scanning {target.strip()}...")
                result = scan(target.strip(), options)
                print(f"Result for {target.strip()}: {len(result.get('all_endpoints', []))} endpoints found")
                all_results.append({
                    "target": target.strip(),
                    "metadata": result.get("metadata", {}),
                    "all_endpoints": result.get("all_endpoints", [])
                })
        
        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and all_results:
            try:
                for result in all_results:
                    payload = {
                        "target": result["target"],
                        "resolved_ips": [],
                        "open_ports": [],
                        "http_metadata": result["metadata"],
                        "http_endpoints": result["all_endpoints"],
                        "scan_metadata": {
                            "tool": "httpx-scan",
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
        
        print("HTTPx scan completed")
        
    finally:
        # Cleanup VPN
        if vpn_connected:
            print("[*] Disconnecting VPN...")
            vpn_manager.disconnect_vpn()
