#!/bin/bash
set -e

echo "[*] Starting scan with VPN..."

# Import VPN manager
python3 -c "
import sys
sys.path.append('/app')
from vpn_manager import VPNManager
import subprocess
import os
import time

# Setup VPN
manager = VPNManager()
if not manager.setup_random_vpn():
    print('[!] Không thể setup VPN, thoát...')
    exit(1)

print('[+] VPN đã sẵn sàng, bắt đầu scan...')

# Đọc targets và scan parameters
targets = os.getenv('TARGETS', '').split(',')
tool = os.getenv('TOOL', 'dns-lookup')
controller_url = os.getenv('CONTROLLER_CALLBACK_URL')
job_id = os.getenv('JOB_ID')

print(f'[+] Tool: {tool}')
print(f'[+] Targets: {targets}')
print(f'[+] Job ID: {job_id}')

# Thực hiện scan theo tool
try:
    if tool == 'dns-lookup':
        exec(open('/app/dns_lookup.py').read())
    elif tool == 'port-scan':
        exec(open('/app/port_scan.py').read())
    elif tool == 'httpx-scan':
        exec(open('/app/httpx_scan.py').read())
    else:
        print(f'[!] Unknown tool: {tool}')
        exit(1)
finally:
    # Cleanup VPN
    print('[*] Cleaning up VPN...')
    manager.disconnect_vpn()
"
