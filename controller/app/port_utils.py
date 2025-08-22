from typing import List

def split_ports(port_list: List[int], n: int) -> List[List[int]]:
    """
    Chia đều list port thành n phần (chia dư thì phần đầu nhiều hơn 1 port).
    Nếu n > số port, chỉ tạo n = số port phần (mỗi phần 1 port).
    """
    if n <= 0:
        return []
    total = len(port_list)
    if n >= total:
        # Mỗi phần 1 port, phần dư không tạo
        return [[p] for p in port_list]
    k, m = divmod(total, n)
    result = []
    start = 0
    for i in range(n):
        end = start + k + (1 if i < m else 0)
        result.append(port_list[start:end])
        start = end
    return result

if __name__ == "__main__":
    print("\nTest split_ports:")
    test_ports = list(range(1, 11))  # 10 ports
    print("10 ports chia 3:", split_ports(test_ports, 3))
    print("10 ports chia 1:", split_ports(test_ports, 1))
    print("10 ports chia 10:", split_ports(test_ports, 10))
    print("10 ports chia 12:", split_ports(test_ports, 12))
import os
from typing import List

def parse_nmap_top_ports(file_path: str) -> List[int]:
    """
    Đọc file nmap-ports-top1000.txt, parse chuỗi port, range thành list số nguyên.
    File có thể chứa: 1,3-4,6-7,9,13,...
    """
    ports = set()
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            for part in line.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = part.split('-')
                    ports.update(range(int(start), int(end)+1))
                elif part.isdigit():
                    ports.add(int(part))
    return sorted(ports)

def parse_ports_all(file_path: str) -> List[int]:
    """
    Đọc file Ports-1-To-65535.txt, mỗi dòng 1 port, thành list số nguyên.
    """
    ports = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.isdigit():
                ports.append(int(line))
    return ports

def parse_ports_custom(port_str: str) -> List[int]:
    """
    Parse chuỗi port chỉ định từ user (ví dụ: "80,443,8080") thành list số nguyên.
    """
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end)+1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(ports)

# Example usage:
if __name__ == "__main__":
    nmap_ports = parse_nmap_top_ports("nmap-ports-top1000.txt")
    print(f"Nmap top 1000 ports: {nmap_ports[:10]} ... {len(nmap_ports)} ports")
    all_ports = parse_ports_all("Ports-1-To-65535.txt")
    print(f"All ports: {all_ports[:10]} ... {len(all_ports)} ports")
    custom_ports = parse_ports_custom("22,80,443,1000-1005")
    print(f"Custom ports: {custom_ports}")
