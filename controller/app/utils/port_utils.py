# app/utils/port_utils.py
import os
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
        return [[p] for p in port_list]

    k, m = divmod(total, n)
    result = []
    start = 0
    for i in range(n):
        end = start + k + (1 if i < m else 0)
        result.append(port_list[start:end])
        start = end
    return result

def parse_nmap_top_ports(file_path: str) -> List[int]:
    """
    Đọc file nmap-ports-top1000.txt, parse chuỗi port và range thành list số nguyên.
    """
    ports = set()
    with open(file_path, 'r') as f:
        for line in f:
            for part in line.strip().split(','):
                part = part.strip()
                if '-' in part:
                    start, end = part.split('-')
                    ports.update(range(int(start), int(end) + 1))
                elif part.isdigit():
                    ports.add(int(part))
    return sorted(list(ports))

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
            ports.update(range(int(start), int(end) + 1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(list(ports))