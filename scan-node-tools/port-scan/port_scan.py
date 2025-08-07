# modules/port_scan.py
import subprocess, tempfile, os, xml.etree.ElementTree as ET
import sys
import json
import requests

def scan(target):
    """
    Dùng nmap SYN scan top 1000 ports.
    Trả về {'open_ports': [port,…]}
    """
    # Thử SYN scan trước, nếu fail thì fallback sang TCP connect scan
    temp_fd, temp_path = tempfile.mkstemp(suffix='.xml')
    os.close(temp_fd)
    
    try:
        # Thử SYN scan (cần root)
        cmd = ['nmap', '-sS', '--top-ports', '1000', '-oX', temp_path, target]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        # Fallback sang TCP connect scan (không cần root)
        cmd = ['nmap', '-sT', '--top-ports', '1000', '-oX', temp_path, target]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # parse XML
    tree = ET.parse(temp_path)
    os.remove(temp_path)
    ports = []
    for p in tree.findall(".//port"):
        if p.find('state').attrib.get('state') == 'open':
            ports.append(int(p.attrib['portid']))
    return {'open_ports': ports}

if __name__ == "__main__":
    # Đọc targets từ environment variable hoặc command line
    targets = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else sys.argv[1:]
    controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
    job_id = os.getenv("JOB_ID")
    
    print(f"Port scan starting for targets: {targets}")
    
    # Scan từng target
    all_results = []
    for target in targets:
        if target.strip():
            print(f"Scanning {target.strip()}...")
            result = scan(target.strip())
            print(f"Result for {target.strip()}: {result}")
            all_results.append({
                "target": target.strip(),
                "open_ports": result.get("open_ports", [])
            })
    
    # Gửi kết quả về Controller nếu có callback URL
    if controller_url and all_results:
        try:
            for result in all_results:
                payload = {
                    "target": result["target"],
                    "resolved_ips": [],
                    "open_ports": result["open_ports"],
                    "scan_metadata": {
                        "tool": "port-scan",
                        "job_id": job_id
                    }
                }
                print(f"Sending result to Controller: {payload}")
                response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                print(f"Controller response: {response.status_code}")
        except Exception as e:
            print(f"Error sending results to Controller: {e}")
    
    print("Port scan completed")
