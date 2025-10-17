# modules/dns_lookup.py
import socket
import os
import sys
import json
import requests
import logging
from vpn_manager import VPNManager

# Configure concise logger
logger = logging.getLogger("dns_lookup")
if not logger.handlers:
    h = logging.StreamHandler(stream=sys.stdout)
    h.setFormatter(logging.Formatter("[DNS] %(levelname)s: %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

def scan(target):
    """
    Resolve domain → list IP.
    Nếu input đã là IP thì vẫn trả về chính nó.
    """
    try:
        # Thử resolve domain name với Python socket
        ips = socket.gethostbyname_ex(target)[2]
        logger.debug(f"Resolved {target} to {ips}")
        return {'resolved_ips': ips}
    except socket.gaierror as e:
        logger.debug(f"Socket resolution failed for {target}: {e}")
        
        # Fallback: thử dùng nslookup command
        try:
            import subprocess
            result = subprocess.run(['nslookup', target], capture_output=True, text=True, timeout=10)
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
                    logger.debug(f"nslookup resolved {target} to {ips}")
                    return {'resolved_ips': ips}
        except Exception as lookup_error:
            logger.debug(f"nslookup failed: {lookup_error}")
        
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
    logger.info("Starting DNS Lookup scan with VPN")

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
            logger.info(f"Received VPN assignment: {assigned_vpn.get('hostname', 'Unknown')}")
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse VPN assignment: {e}")

    vpn_profile_info = None
    # Thử setup VPN (optional - có thể skip nếu proxy server không available)
    try:
        logger.debug("Checking initial network status")
        initial_info = vpn_manager.get_network_info()
        logger.debug(f"Initial IP: {initial_info['public_ip']}")

        # Sử dụng assigned VPN nếu có, nếu không thì dùng random
        if assigned_vpn:
            meta = vpn_manager.setup_specific_vpn(assigned_vpn)
            if meta:
                logger.info("Connected to assigned VPN")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
            else:
                logger.info("Failed to connect to assigned VPN, will try random")

        if not vpn_connected:
            logger.info("No VPN assignment from Controller or failed, using random VPN")
            meta = vpn_manager.setup_random_vpn()
            if meta:
                logger.info("VPN setup completed")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
            else:
                logger.info("VPN connection failed, continuing without VPN")

        # Gửi thông báo connect VPN về controller nếu kết nối thành công
        if vpn_connected and controller_url and vpn_profile_info:
            try:
                job_id = os.getenv("JOB_ID")
                payload = {"action": "connect", "scanner_id": job_id}
                if vpn_profile_info.get("filename"):
                    payload["filename"] = vpn_profile_info["filename"]
                logger.info(f"Notify controller connect: {payload}")
                resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                logger.debug(f"Controller connect response: {resp.status_code}")
            except Exception as notify_err:
                logger.warning(f"Failed to notify controller connect: {notify_err}")
    except Exception as e:
        logger.warning(f"VPN setup error: {e}, continuing without VPN...")

    try:
        # Đọc targets từ environment variable hoặc command line
        targets = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else sys.argv[1:]
        controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
        job_id = os.getenv("JOB_ID")
        workflow_id = os.getenv("WORKFLOW_ID")

        logger.info(f"DNS Lookup starting for targets: {targets}")

        # Scan từng target
        all_results = []
        for target in targets:
            if not target or not target.strip():
                continue
            # Tạo biến mới loại bỏ tiền tố http/https
            def strip_http_prefix(t):
                t = t.strip()
                if t.startswith("http://"):
                    return t[7:]
                elif t.startswith("https://"):
                    return t[8:]
                return t
            scan_target = strip_http_prefix(target)
            logger.debug(f"Scanning {target.strip()}")
            result = scan(scan_target)
            logger.debug(f"Result for {target.strip()}: {result}")
            all_results.append({"target": target.strip(), "resolved_ips": result.get("resolved_ips", [])})

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
                    logger.debug(f"Sending result to Controller: {payload}")
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                    logger.debug(f"Controller response: {response.status_code}")
            except Exception as e:
                logger.warning(f"Error sending results to Controller: {e}")

        logger.info("DNS Lookup completed")

    except Exception as e:
        logger.warning(f"Scan error: {e}")

    finally:
        # Gửi thông báo disconnect VPN về controller nếu đã connect VPN
        if vpn_connected and controller_url and vpn_profile_info:
            try:
                job_id = os.getenv("JOB_ID")
                payload = {"action": "disconnect", "scanner_id": job_id}
                if vpn_profile_info.get("filename"):
                    payload["filename"] = vpn_profile_info["filename"]
                logger.info(f"Notify controller disconnect: {payload}")
                resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                logger.debug(f"Controller disconnect response: {resp.status_code}")
            except Exception as notify_err:
                logger.warning(f"Failed to notify controller disconnect: {notify_err}")
        # Cleanup VPN
        if vpn_connected:
            logger.info("Disconnecting VPN")
            vpn_manager.disconnect_vpn()
