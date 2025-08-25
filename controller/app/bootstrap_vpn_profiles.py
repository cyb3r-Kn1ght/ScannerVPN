# bootstrap_vpn_profiles.py
"""
Script để thêm/cập nhật các VPN profile (có ip, country) vào database.
Chạy script này bên trong container controller (đã mount volume /data).
"""
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, VpnProfile

# Đường dẫn DB đúng với môi trường container controller
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////data/scan_results.db")

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

VPN_PROFILES_BOOTSTRAP = {
    "VN": [
        {"filename": "103.57.130.113.ovpn", "hostname": "103.57.130.113", "ip": "103.57.130.113", "country": "VN"},
        {"filename": "vpngate_42.115.224.83_udp_1457.ovpn", "hostname": "vpngate_42.115.224.83_udp_1457", "ip": "42.115.224.83", "country": "VN"},
        {"filename": "vpngate_42.115.224.83_tcp_1416.ovpn", "hostname": "vpngate_42.115.224.83_tcp_1416", "ip": "42.115.224.83", "country": "VN"},
        {"filename": "vpngate_42.114.45.17_udp_1233.ovpn", "hostname": "vpngate_42.114.45.17_udp_1233", "ip": "42.114.45.17", "country": "VN"},
        {"filename": "vpngate_42.114.45.17_tcp_1443.ovpn", "hostname": "vpngate_42.114.45.17_tcp_1443", "ip": "42.114.45.17", "country": "VN"}
    ],
    "KR": [
        {"filename": "vpngate_221.168.226.24_tcp_1353.ovpn", "hostname": "vpngate_221.168.226.24_tcp_1353", "ip": "221.168.226.24", "country": "KR"},
        {"filename": "vpngate_61.255.180.199_udp_1619.ovpn", "hostname": "vpngate_61.255.180.199_udp_1619", "ip": "61.255.180.199", "country": "KR"},
        {"filename": "vpngate_61.255.180.199_tcp_1909.ovpn", "hostname": "vpngate_61.255.180.199_tcp_1909", "ip": "61.255.180.199", "country": "KR"},
        {"filename": "vpngate_221.168.226.24_udp_1670.ovpn", "hostname": "vpngate_221.168.226.24_udp_1670", "ip": "221.168.226.24", "country": "KR"},
        {"filename": "vpngate_121.139.214.237_tcp_1961.ovpn", "hostname": "vpngate_121.139.214.237_tcp_1961", "ip": "121.139.214.237", "country": "KR"}
    ],
    "JP": [
        {"filename": "vpngate_106.155.167.26_udp_1635.ovpn", "hostname": "vpngate_106.155.167.26_udp_1635", "ip": "106.155.167.26", "country": "JP"},
        {"filename": "vpngate_106.155.167.26_tcp_1878.ovpn", "hostname": "vpngate_106.155.167.26_tcp_1878", "ip": "106.155.167.26", "country": "JP"},
        {"filename": "vpngate_180.35.137.120_tcp_5555.ovpn", "hostname": "vpngate_180.35.137.120_tcp_5555", "ip": "180.35.137.120", "country": "JP"},
        {"filename": "vpngate_219.100.37.113_tcp_443.ovpn", "hostname": "vpngate_219.100.37.113_tcp_443", "ip": "219.100.37.113", "country": "JP"}
    ],
    "GB": [
        {"filename": "45.149.184.180.ovpn", "hostname": "45.149.184.180", "ip": "45.149.184.180", "country": "GB"}
    ],
    "HK": [
        {"filename": "70.36.97.79.ovpn", "hostname": "70.36.97.79", "ip": "70.36.97.79", "country": "HK"}
    ]
}

update_count = 0
for country, profiles in VPN_PROFILES_BOOTSTRAP.items():
    for p in profiles:
        obj = session.query(VpnProfile).filter_by(filename=p["filename"]).first()
        if obj:
            changed = False
            if obj.ip != p["ip"]:
                obj.ip = p["ip"]
                changed = True
            if obj.country != p["country"]:
                obj.country = p["country"]
                changed = True
            if changed:
                update_count += 1
session.commit()
print(f"Đã cập nhật ip/country cho {update_count} VPN profile.")
