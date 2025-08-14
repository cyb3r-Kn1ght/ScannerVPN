# modules/port_scan.py
import subprocess, tempfile, os, xml.etree.ElementTree as ET
import sys
import json
import requests
from vpn_manager import VPNManager

def scan(target, options=None):
    """
    Dùng nmap SYN scan top 1000 ports.
    Trả về {'open_ports': [port,…]}
    """
    # Parse options for port scanning
    ports = "1000"  # default
    scan_type = "-sS"  # default SYN scan
    
    if options:
        if options.get("ports"):
            ports = options["ports"]
        if options.get("scan_type"):
            scan_type = options["scan_type"]
        if options.get("all_ports"):
            ports = "-"  # scan all ports
    
    # Thử SYN scan trước, nếu fail thì fallback sang TCP connect scan
    temp_fd, temp_path = tempfile.mkstemp(suffix='.xml')
    os.close(temp_fd)
    
    try:
        # Thử scan type được chỉ định (cần root cho SYN scan)
        if ports == "-":
            cmd = ['nmap', scan_type, '-p-', '-oX', temp_path, target]
        elif ports.isdigit():
            cmd = ['nmap', scan_type, '--top-ports', ports, '-oX', temp_path, target]
        else:
            cmd = ['nmap', scan_type, '-p', ports, '-oX', temp_path, target]
            
        print(f"[*] Running nmap command: {' '.join(cmd[:4])}... {target}")
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # Fallback sang TCP connect scan (không cần root)
        print("[!] SYN scan failed, falling back to TCP connect scan...")
        try:
            if ports == "-":
                cmd = ['nmap', '-sT', '-p-', '-oX', temp_path, target]
            elif ports.isdigit():
                cmd = ['nmap', '-sT', '--top-ports', ports, '-oX', temp_path, target]
            else:
                cmd = ['nmap', '-sT', '-p', ports, '-oX', temp_path, target]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        except Exception as e:
            print(f"[!] Both scan methods failed: {e}")
            os.remove(temp_path)
            return {'open_ports': []}

    # parse XML
    try:
        tree = ET.parse(temp_path)
        os.remove(temp_path)
        ports_found = []
        for p in tree.findall(".//port"):
            if p.find('state').attrib.get('state') == 'open':
                port_info = {
                    "port": int(p.attrib['portid']),
                    "protocol": p.attrib.get('protocol', 'tcp')
                }
                # Get service info if available
                service = p.find('service')
                if service is not None:
                    port_info["service"] = service.attrib.get('name', 'unknown')
                    port_info["version"] = service.attrib.get('version', '')
                ports_found.append(port_info)
        
        print(f"[+] Found {len(ports_found)} open ports for {target}")
        return {'open_ports': ports_found}
    except Exception as e:
        print(f"[!] Error parsing nmap XML: {e}")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return {'open_ports': []}

if __name__ == "__main__":
    print("[*] Starting Port scan with VPN...")
    
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
        
        print(f"Port scan starting for targets: {targets}")
        print(f"Options: {options}")
        
        # Scan từng target
        all_results = []
        for target in targets:
            if target.strip():
                print(f"Scanning {target.strip()}...")
                result = scan(target.strip(), options)
                print(f"Result for {target.strip()}: {len(result.get('open_ports', []))} open ports")
                all_results.append({
                    "target": target.strip(),
                    "open_ports": result.get("open_ports", [])
                })
        
        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and all_results:
            try:
                for result in all_results:
                    has_findings = bool(result["open_ports"])
                    payload = {
                        "target": result["target"],
                        "resolved_ips": [],
                        "open_ports": result["open_ports"],
                        "workflow_id": workflow_id,
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "port-scan",
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
        
        print("Port scan completed")
        
    finally:
        # Cleanup VPN
        if vpn_connected:
            print("[*] Disconnecting VPN...")
            vpn_manager.disconnect_vpn()
