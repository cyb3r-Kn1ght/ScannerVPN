import requests
import random
import subprocess
import os
import time
import sys

class VPNManager:
    def __init__(self, proxy_node="http://10.102.199.36:8000"):
        self.proxy_node = proxy_node
        self.vpn_process = None
        
    def fetch_vpns(self):
        """Lấy danh sách VPN từ proxy server"""
        try:
            response = requests.get(f"{self.proxy_node}/vpns", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[!] Lỗi khi fetch VPN list: {e}")
            return []
    
    def download_vpn(self, filename):
        """Download VPN config file"""
        try:
            r = requests.get(f"{self.proxy_node}/vpn/{filename}", timeout=30)
            r.raise_for_status()
            vpn_path = f"/tmp/{filename}"
            with open(vpn_path, "wb") as f:
                f.write(r.content)
            return vpn_path
        except Exception as e:
            print(f"[!] Lỗi khi download VPN {filename}: {e}")
            return None
    
    def connect_vpn(self, vpn_file):
        """Kết nối VPN"""
        print(f"[+] Kết nối VPN: {vpn_file}")
        try:
            self.vpn_process = subprocess.Popen([
                "openvpn", "--config", vpn_file,
                "--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC",
                "--verb", "3"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Đợi VPN kết nối (tối đa 30 giây)
            for i in range(30):
                if self.is_vpn_connected():
                    print("[+] VPN đã kết nối thành công!")
                    return True
                time.sleep(1)
                
            print("[!] VPN không thể kết nối trong 30 giây")
            self.disconnect_vpn()
            return False
            
        except Exception as e:
            print(f"[!] Lỗi khi kết nối VPN: {e}")
            return False
    
    def is_vpn_connected(self):
        """Kiểm tra VPN đã kết nối chưa"""
        try:
            # Kiểm tra interface tun
            result = subprocess.run(['ip', 'addr', 'show', 'tun0'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def disconnect_vpn(self):
        """Ngắt kết nối VPN"""
        if self.vpn_process and self.vpn_process.poll() is None:
            print("[*] Ngắt kết nối VPN...")
            self.vpn_process.terminate()
            try:
                self.vpn_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.vpn_process.kill()
            self.vpn_process = None
    
    def setup_random_vpn(self):
        """Setup VPN ngẫu nhiên"""
        vpns = self.fetch_vpns()
        if not vpns:
            print("[!] Không có VPN nào available")
            return False
            
        # Thử tối đa 3 VPN ngẫu nhiên
        for attempt in range(3):
            chosen_vpn = random.choice(vpns)
            print(f"[+] Thử VPN: {chosen_vpn} (lần {attempt + 1})")
            
            vpn_path = self.download_vpn(chosen_vpn)
            if vpn_path and self.connect_vpn(vpn_path):
                return True
                
        print("[!] Không thể kết nối VPN nào")
        return False

def main():
    """Main function để test VPN manager"""
    manager = VPNManager()
    
    if manager.setup_random_vpn():
        print("[+] VPN setup thành công!")
        
        # Test IP
        try:
            result = subprocess.run(['curl', '-s', 'https://api.ipify.org'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] IP hiện tại: {result.stdout.strip()}")
        except:
            print("[!] Không thể check IP")
            
        # Giữ kết nối
        print("[*] VPN đang chạy. Nhấn Ctrl+C để thoát...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            manager.disconnect_vpn()
    else:
        print("[!] Không thể setup VPN")
        sys.exit(1)

if __name__ == "__main__":
    main()
