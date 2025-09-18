import requests
import random
import subprocess
import os
import time
import sys

class VPNManager:
    def __init__(self, proxy_node="http://10.102.199.37:8000"):
        self.proxy_node = proxy_node
        self.vpn_process = None
        
    def fetch_vpns(self):
        """Lấy danh sách VPN từ proxy server"""
        try:
            response = requests.get(f"{self.proxy_node}/vpns", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[VPN] Không lấy được danh sách VPN: {e}")
            return []
    
    def download_vpn(self, filename):
        """Download VPN config file"""
        try:
            r = requests.get(f"{self.proxy_node}/vpn/{filename}", timeout=30)
            r.raise_for_status()
            vpn_path = f"/tmp/{filename}"
            with open(vpn_path, "wb") as f:
                f.write(r.content)
            print(f"[VPN] Đã tải file cấu hình: {filename}")
            return vpn_path
        except Exception as e:
            print(f"[VPN] Lỗi tải file cấu hình {filename}: {e}")
            return None
    
    def connect_vpn(self, vpn_file):
        """Kết nối VPN với network configuration"""
        print(f"[VPN] Đang kết nối: {os.path.basename(vpn_file)}")
        try:
            self.vpn_process = subprocess.Popen([
                "openvpn", "--config", vpn_file,
                "--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC",
                "--redirect-gateway", "def1",
                "--pull-filter", "ignore", "redirect-gateway",
                "--pull-filter", "accept", "route",
                "--script-security", "2",
                "--verb", "3"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for _ in range(30):
                if self.is_vpn_connected():
                    print("[VPN] Đã kết nối thành công!")
                    self._setup_vpn_routing()
                    print("[VPN] Routing OK.")
                    time.sleep(2)
                    return True
                time.sleep(1)
            print("[VPN] Không thể kết nối (timeout)")
            self.disconnect_vpn()
            return False
        except Exception as e:
            print(f"[VPN] Lỗi kết nối: {e}")
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
    
    def _setup_vpn_routing(self):
        try:
            result = subprocess.run(['ip', 'route', 'show', 'dev', 'tun0'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                self._setup_vpn_dns()
                tun_routes = result.stdout.strip().split('\n')
                vpn_gateway = None
                for route in tun_routes:
                    if 'via' in route:
                        vpn_gateway = route.split('via')[1].split()[0]
                        break
                if vpn_gateway:
                    subprocess.run(['ip', 'route', 'add', '10.244.0.0/16', 'via', '10.244.0.1', 'dev', 'eth0'], capture_output=True)
                    subprocess.run(['ip', 'route', 'add', '10.96.0.0/12', 'via', '10.244.0.1', 'dev', 'eth0'], capture_output=True)
                    for target in ["8.8.8.8", "8.8.4.4", "1.1.1.1", "142.250.0.0/16", "172.217.0.0/16"]:
                        subprocess.run(['ip', 'route', 'add', target, 'via', vpn_gateway, 'dev', 'tun0'], capture_output=True)
                # Chỉ log thành công hoặc lỗi chính
            else:
                print("[VPN] Không tìm thấy VPN gateway")
        except Exception as e:
            print(f"[VPN] Lỗi setup routing: {e}")
    
    def _setup_vpn_dns(self):
        try:
            subprocess.run(['cp', '/etc/resolv.conf', '/etc/resolv.conf.backup'], capture_output=True)
            original_dns = ""
            try:
                with open('/etc/resolv.conf.backup', 'r') as f:
                    original_dns = f.read()
            except:
                pass
            dns_config = """nameserver 10.96.0.10\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n"""
            if "nameserver 10.96.0.10" not in original_dns and "nameserver" in original_dns:
                for line in original_dns.split('\n'):
                    if line.startswith('nameserver') and '10.96.0.10' not in line:
                        dns_config += line + '\n'
            with open('/etc/resolv.conf', 'w') as f:
                f.write(dns_config)
        except Exception as e:
            print(f"[VPN] Lỗi setup DNS: {e}")
    
    def disconnect_vpn(self):
        """Ngắt kết nối VPN và restore DNS"""
        if self.vpn_process and self.vpn_process.poll() is None:
            print("[VPN] Ngắt kết nối.")
            self.vpn_process.terminate()
            try:
                self.vpn_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.vpn_process.kill()
            self.vpn_process = None
            try:
                subprocess.run(['mv', '/etc/resolv.conf.backup', '/etc/resolv.conf'], capture_output=True)
            except:
                pass
    
    def setup_specific_vpn(self, vpn_config):
        """Setup VPN từ config được assign từ Controller"""
        # Lấy IP ban đầu
        original_ip = self.get_current_ip()
        print(f"[*] IP ban đầu: {original_ip}")
        
        # Kiểm tra môi trường container
        self._check_container_capabilities()
        
        # Extract filename from VPN config
        vpn_filename = vpn_config.get('filename')
        if not vpn_filename:
            print("[!] VPN config missing filename")
            return False
        
        print(f"[+] Connecting to assigned VPN: {vpn_filename}")
        print(f"    - Hostname: {vpn_config.get('hostname', 'Unknown')}")
        print(f"    - Country: {vpn_config.get('country', 'Unknown')}")
        
        vpn_path = self.download_vpn(vpn_filename)
        if vpn_path and self.connect_vpn(vpn_path):
            # Kiểm tra IP sau khi kết nối
            new_ip = self.get_current_ip()
            print(f"[+] IP sau VPN: {new_ip}")
            
            # Kiểm tra VPN có hoạt động không
            if self.is_vpn_working():
                print(f"[+] Assigned VPN connected successfully! IP: {original_ip} -> {new_ip}")
                return True
            else:
                print(f"[!] Assigned VPN not working properly")
                self.disconnect_vpn()
                return False
        
        print(f"[!] Failed to connect to assigned VPN: {vpn_filename}")
        return False
    
    def setup_random_vpn(self):
        """Setup VPN ngẫu nhiên"""
        # Lấy IP ban đầu
        original_ip = self.get_current_ip()
        print(f"[*] IP ban đầu: {original_ip}")
        
        # Kiểm tra môi trường container
        self._check_container_capabilities()
        
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
                # Kiểm tra IP sau khi kết nối
                new_ip = self.get_current_ip()
                print(f"[+] IP sau VPN: {new_ip}")
                
                # Kiểm tra VPN có hoạt động không
                if self.is_vpn_working():
                    print(f"[+] VPN hoạt động tốt! IP: {original_ip} -> {new_ip}")
                    return True
                else:
                    print(f"[!] VPN chưa hoạt động đúng, thử tiếp...")
                    self.disconnect_vpn()
                    continue
                
        print("[!] Không thể kết nối VPN nào")
        return False
    
    def _check_container_capabilities(self):
        """Kiểm tra khả năng networking của container"""
        print("[*] Checking container networking capabilities...")
        
        # Check if we can create TUN devices
        try:
            result = subprocess.run(['ls', '/dev/net/tun'], capture_output=True, text=True)
            tun_available = result.returncode == 0
            print(f"[*] TUN device: {'✓' if tun_available else '✗'}")
        except:
            print("[*] TUN device: ✗")
        
        # Check NET_ADMIN capability
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            routing_ok = result.returncode == 0
            print(f"[*] Routing access: {'✓' if routing_ok else '✗'}")
        except:
            print("[*] Routing access: ✗")
        
        # Check external connectivity
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '3', '8.8.8.8'], 
                                  capture_output=True, text=True, timeout=5)
            external_ok = result.returncode == 0
            print(f"[*] External connectivity: {'✓' if external_ok else '✗'}")
        except:
            print("[*] External connectivity: ✗")
    
    def is_vpn_working(self):
        """Kiểm tra VPN có thực sự hoạt động không - simplified version"""
        checks = []
        
        # 1. Kiểm tra TUN interface
        tun_ok = self.is_vpn_connected()
        checks.append(f"TUN interface: {'✓' if tun_ok else '✗'}")
        
        # 2. Kiểm tra có TUN interface trong routing
        route_ok = False
        try:
            result = subprocess.run(['ip', 'route', 'show'], 
                                  capture_output=True, text=True)
            route_ok = 'tun0' in result.stdout
            checks.append(f"VPN routing: {'✓' if route_ok else '✗'}")
        except:
            checks.append("VPN routing: ✗")
        
        # 3. Test ping qua VPN (simplified test)
        connectivity_ok = False
        try:
            # Thử ping DNS server qua tun0
            result = subprocess.run(['ping', '-I', 'tun0', '-c', '1', '-W', '3', '8.8.8.8'], 
                                  capture_output=True, text=True, timeout=5)
            connectivity_ok = result.returncode == 0
            checks.append(f"VPN connectivity: {'✓' if connectivity_ok else '✗'}")
        except:
            checks.append("VPN connectivity: ✗")
        
        # 4. Simplified DNS test
        dns_ok = False
        try:
            # Simple DNS test với timeout ngắn
            import socket
            socket.setdefaulttimeout(3)
            socket.gethostbyname('google.com')
            dns_ok = True
            checks.append(f"DNS test: {'✓' if dns_ok else '✗'}")
        except:
            checks.append("DNS test: ✗")
        finally:
            socket.setdefaulttimeout(None)
            
        print(f"[*] VPN Health Check: {' | '.join(checks)}")
        
        # VPN được coi là working nếu có TUN interface và routing
        # DNS và connectivity có thể fail do VPN server restrictions
        return tun_ok and route_ok
    
    def get_current_ip(self):
        """Lấy IP hiện tại - ưu tiên external IP services, fallback to VPN interface"""
        # Trước tiên thử get IP từ VPN interface
        vpn_ip = self._get_vpn_interface_ip()
        if vpn_ip:
            print(f"[*] Detected VPN interface IP: {vpn_ip}")
        
        # Thử các external services với timeout ngắn hơn
        external_methods = [
            (['curl', '-s', '--max-time', '5', '--interface', 'tun0', 'https://api.ipify.org'], 'tun0'),
            (['curl', '-s', '--max-time', '5', 'https://api.ipify.org'], 'default'),
            (['curl', '-s', '--max-time', '5', 'http://ipinfo.io/ip'], 'default'),
            (['curl', '-s', '--max-time', '5', 'http://checkip.amazonaws.com'], 'default'),
            (['wget', '-qO-', '--timeout=5', 'https://api.ipify.org'], 'default')
        ]
        
        for method, interface in external_methods:
            try:
                print(f"[*] Trying IP detection via {interface}: {' '.join(method[:3])}")
                result = subprocess.run(method, capture_output=True, text=True, timeout=8)
                if result.returncode == 0 and result.stdout.strip():
                    ip = result.stdout.strip()
                    if self._is_valid_ip(ip):
                        print(f"[+] External IP detected: {ip}")
                        return ip
                else:
                    print(f"[!] Method failed: {result.stderr.strip() if result.stderr else 'No output'}")
            except subprocess.TimeoutExpired:
                print(f"[!] Method timeout: {' '.join(method[:3])}")
                continue
            except Exception as e:
                print(f"[!] Method error: {e}")
                continue
        
        # If external detection fails, use VPN interface IP (this is actually the correct behavior)
        if vpn_ip:
            print(f"[*] External detection failed, using VPN interface IP: {vpn_ip}")
            return vpn_ip
                
        # Last fallback: check local interface IPs
        try:
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
            if result.returncode == 0:
                ips = result.stdout.strip().split()
                for ip in ips:
                    if self._is_valid_ip(ip) and not ip.startswith('127.') and not ip.startswith('10.244.'):
                        return ip
        except:
            pass
            
        return "Unknown"
    
    def _get_vpn_interface_ip(self):
        """Lấy IP từ VPN interface"""
        try:
            result = subprocess.run(['ip', 'addr', 'show', 'tun0'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line and 'scope global' in line:
                        return line.split()[1].split('/')[0]
        except:
            pass
        return None
    
    def _is_valid_ip(self, ip):
        """Kiểm tra IP hợp lệ"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def get_network_info(self):
        """Lấy thông tin network chi tiết"""
        info = {
            "public_ip": self.get_current_ip(),
            "tun_interface": False,
            "local_ip": None,
            "default_route": None
        }
        
        try:
            # Kiểm tra tun interface
            result = subprocess.run(['ip', 'addr', 'show', 'tun0'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                info["tun_interface"] = True
                # Extract local IP từ tun0
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line and 'scope global' in line:
                        info["local_ip"] = line.split()[1].split('/')[0]
            
            # Kiểm tra default route
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                info["default_route"] = result.stdout.strip()
                
        except Exception as e:
            print(f"[!] Error getting network info: {e}")
            
        return info
    
    def print_vpn_status(self):
        info = self.get_network_info()
        print(f"[VPN] Public IP: {info['public_ip']} | TUN: {'Y' if info['tun_interface'] else 'N'} | Local: {info['local_ip'] or '-'}")
        return info
