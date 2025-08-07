import requests
import re
import os
from typing import List, Dict, Optional
from collections import defaultdict

class VPNService:
    """
    VPN Service cho Controller.
    
    Controller KHÔNG kết nối VPN trực tiếp, chỉ:
    1. Lấy danh sách VPN từ proxy node
    2. Assign VPN cho scan jobs
    3. Forward VPN config đến Scanner nodes
    
    Scanner nodes mới thực sự kết nối VPN.
    """
    def __init__(self, proxy_node_url: str = None):
        # Controller chỉ làm trung gian điều phối VPN, không kết nối trực tiếp
        self.proxy_node = proxy_node_url or os.getenv("VPN_PROXY_NODE", "http://10.102.199.36:8000")
    
    def clear_proxy_env(self):
        """Xóa proxy khỏi environment variables"""
        proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']
        old_proxies = {}
        for var in proxy_vars:
            if var in os.environ:
                old_proxies[var] = os.environ[var]
                del os.environ[var]
        return old_proxies
    
    def restore_proxy_env(self, old_proxies: Dict[str, str]):
        """Restore proxy environment"""
        for var, value in old_proxies.items():
            os.environ[var] = value
    
    def fetch_vpns_sync(self) -> List[Dict]:
        """
        Sync version - Lấy danh sách VPN từ proxy server.
        """
        old_proxies = self.clear_proxy_env()
        
        try:
            import requests
            response = requests.get(f"{self.proxy_node}/vpns", timeout=10)
            response.raise_for_status()
            
            vpn_list = response.json()
            print(f"[*] Controller fetched {len(vpn_list)} VPNs from proxy node")
            
            # Convert to standard format nếu cần
            if isinstance(vpn_list, list) and vpn_list:
                if isinstance(vpn_list[0], str):
                    # Convert filename list to VPN objects
                    return [{"filename": vpn, "hostname": vpn.replace('.ovpn', '')} for vpn in vpn_list]
                else:
                    return vpn_list
            return []
            
        except Exception as e:
            print(f"[!] Controller error fetching VPNs from proxy: {e}")
            return []
        finally:
            self.restore_proxy_env(old_proxies)

    async def fetch_vpns(self) -> List[Dict]:
        """
        Async wrapper cho sync method
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.fetch_vpns_sync)
    
    def fetch_proxies(self) -> List[str]:
        """Lấy danh sách proxy từ proxy server"""
        old_proxies = self.clear_proxy_env()
        
        try:
            response = requests.get(f"{self.proxy_node}/proxies", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[!] Lỗi khi fetch proxy list: {e}")
            return []
        finally:
            self.restore_proxy_env(old_proxies)
    
    def get_country_from_ip(self, ip: str) -> str:
        """Lấy mã quốc gia từ IP address"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", 
                                  timeout=5, proxies={'http': None, 'https': None})
            if response.status_code == 200:
                data = response.json()
                return data.get('countryCode', 'Unknown')
            return 'Unknown'
        except:
            return 'Unknown'
    
    async def categorize_vpns_by_country(self, vpns: List[Dict]) -> Dict[str, List[Dict]]:
        """Phân loại VPN theo quốc gia dựa trên IP trong tên file"""
        categorized = defaultdict(list)
        
        for vpn in vpns:
            if isinstance(vpn, dict):
                # VPN object format
                filename = vpn.get('filename', '')
                hostname = vpn.get('hostname', '')
            else:
                # String format
                filename = str(vpn)
                hostname = filename.replace('.ovpn', '')
            
            # Trích xuất IP từ tên file VPN
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', filename)
            if ip_match:
                ip = ip_match.group(1)
                country = self.get_country_from_ip(ip)
                categorized[country].append({
                    'filename': filename,
                    'hostname': hostname,
                    'ip': ip,
                    'country': country
                })
            else:
                categorized['Unknown'].append({
                    'filename': filename,
                    'hostname': hostname,
                    'ip': 'Unknown',
                    'country': 'Unknown'
                })
        
        return dict(categorized)
    
    def categorize_proxies_by_country(self, proxies: List[str]) -> Dict[str, List[str]]:
        """Phân loại proxy theo quốc gia"""
        categorized = defaultdict(list)
        
        for proxy in proxies:
            try:
                ip = proxy.strip().split()[0]
                country = self.get_country_from_ip(ip)
                categorized[country].append({
                    'proxy': proxy.strip(),
                    'ip': ip,
                    'country': country
                })
            except:
                categorized['Unknown'].append({
                    'proxy': proxy.strip(),
                    'ip': 'Unknown',
                    'country': 'Unknown'
                })
        
        return dict(categorized)
    
    def get_random_vpn(self, country: str = None) -> Optional[Dict[str, str]]:
        """Lấy random VPN, có thể filter theo country"""
        import random
        
        vpns = self.fetch_vpns()
        if not vpns:
            return None
        
        if country:
            categorized = self.categorize_vpns_by_country(vpns)
            if country in categorized and categorized[country]:
                return random.choice(categorized[country])
            return None
        else:
            # Random VPN từ tất cả
            categorized = self.categorize_vpns_by_country(vpns)
            all_vpns = []
            for country_vpns in categorized.values():
                all_vpns.extend(country_vpns)
            
            return random.choice(all_vpns) if all_vpns else None
    
    def download_vpn_content(self, filename: str) -> Optional[bytes]:
        """Download VPN config content"""
        old_proxies = self.clear_proxy_env()
        
        try:
            response = requests.get(f"{self.proxy_node}/vpn/{filename}", timeout=30)
            response.raise_for_status()
            return response.content
        except Exception as e:
            print(f"[!] Lỗi khi download VPN {filename}: {e}")
            return None
        finally:
            self.restore_proxy_env(old_proxies)
