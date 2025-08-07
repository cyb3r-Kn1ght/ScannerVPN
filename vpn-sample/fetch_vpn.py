import requests
import random
import subprocess
import os
import time
import signal
import sys

PROXY_NODE = "http://10.102.199.36:8000"  # Sửa nếu cần
ROTATE_INTERVAL = 100 # 100 giây

vpn_process = None  # Biến lưu tiến trình openvpn

def fetch_vpns():
    response = requests.get(f"{PROXY_NODE}/vpns")
    response.raise_for_status()
    return response.json()

def download_vpn(filename):
    r = requests.get(f"{PROXY_NODE}/vpn/{filename}")
    vpn_path = f"/tmp/{filename}"
    with open(vpn_path, "wb") as f:
        f.write(r.content)
    return vpn_path

def connect_vpn(vpn_file):
    global vpn_process
    print(f"[+] Kết nối tới VPN profile: {vpn_file}")
    vpn_process = subprocess.Popen([
        "openvpn", "--config", vpn_file,
        "--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC"
    ])
    print(f"[+] VPN PID: {vpn_process.pid}")

def disconnect_vpn():
    global vpn_process
    if vpn_process and vpn_process.poll() is None:
        print("[*] Ngắt kết nối VPN hiện tại...")
        vpn_process.terminate()
        try:
            vpn_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            vpn_process.kill()
        print("[*] VPN đã ngắt.")
        vpn_process = None

def handle_exit(signum, frame):
    print("\n[!] Đang thoát...")
    disconnect_vpn()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    while True:
        vpns = fetch_vpns()
        if not vpns:
            print("Không tìm thấy VPN profile nào.")
            sys.exit(1)

        chosen_vpn = random.choice(vpns)
        print(f"[+] VPN được chọn: {chosen_vpn}")
        vpn_path = download_vpn(chosen_vpn)

        connect_vpn(vpn_path)

        # Đợi trong khoảng thời gian rotate, nếu người dùng không bấm Ctrl+C
        try:
            for _ in range(ROTATE_INTERVAL):
                time.sleep(1)
                if vpn_process.poll() is not None:
                    print("[!] VPN process bị dừng sớm.")
                    break
        except KeyboardInterrupt:
            handle_exit(None, None)

        disconnect_vpn()
        print("[*] Đang rotate VPN...\n")