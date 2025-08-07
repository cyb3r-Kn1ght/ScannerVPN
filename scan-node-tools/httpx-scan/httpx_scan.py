# modules/httpx_scan.py
import subprocess
import json
import os
import sys
import requests

def scan(target):
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
    proc = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l for l in proc.stdout.splitlines() if l.strip()]
    if not lines:
        return {}

    # chỉ lấy dòng đầu tiên
    data = json.loads(lines[0])
    return {
        'metadata': {
            'ip': data.get('ip'),
            'port': data.get('port'),
            'service': data.get('service'),
            'responseHeaders': data.get('headers', {}),
            'statusCode': data.get('status-code'),
            'protocol': data.get('http-protocol'),
        }
    }

if __name__ == "__main__":
    # Đọc targets từ environment variable hoặc command line
    targets = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else sys.argv[1:]
    controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
    job_id = os.getenv("JOB_ID")
    
    print(f"HTTPx scan starting for targets: {targets}")
    
    # Scan từng target
    all_results = []
    for target in targets:
        if target.strip():
            print(f"Scanning {target.strip()}...")
            result = scan(target.strip())
            print(f"Result for {target.strip()}: {result}")
            all_results.append({
                "target": target.strip(),
                "metadata": result.get("metadata", {})
            })
    
    # Gửi kết quả về Controller nếu có callback URL
    if controller_url and all_results:
        try:
            for result in all_results:
                payload = {
                    "target": result["target"],
                    "resolved_ips": [],
                    "open_ports": [],
                    "scan_metadata": {
                        "tool": "httpx-scan",
                        "job_id": job_id,
                        "http_metadata": result["metadata"]
                    }
                }
                print(f"Sending result to Controller: {payload}")
                response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                print(f"Controller response: {response.status_code}")
        except Exception as e:
            print(f"Error sending results to Controller: {e}")
    
    print("HTTPx scan completed")
