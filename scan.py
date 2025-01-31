#scans ip address for address and pings for information on up or down

# pip install scapy dnspython

import subprocess
import sys
import time
import csv
import math
from ipaddress import ip_network, ip_address
from scapy.all import ARP, Ether, srp 
import dns.resolver
import dns.reversename

# a = sys.argv[1]
# b = sys.argv[2]

def scan_net(ip_range):
    results = []
    for ip in ip_range.hosts():
        ip_str = str(ip)
        result, elapsed_time, mac_address = ping(ip_str)
        hostname = reverse_dns_lookup(ip_str) if result == 'UP' else 'N/A'
        status_output = format_output(ip_str, result, elapsed_time, hostname, mac_address)
        print(status_output)
        results.append({'IP': ip_str, 'Status': result, 'Time': elapsed_time, 'Hostname': hostname, 'MAC': mac_address})
    return

def ping(ip):
    # Measure the time it takes to ping the IP address with a timeout of 30 seconds
    start_time = time.time()
    try:
        # Execute the ping command and check the result
        result = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        end_time = time.time()
        elapsed_time = math.floor((end_time - start_time) * 1000)  # Convert to milliseconds and floor to the nearest tenth
        if result.returncode == 0:
            mac = mac_address(ip)
            return 'UP', elapsed_time, mac
        else:
            return 'DOWN', elapsed_time, 'N/A'
    except subprocess.TimeoutExpired:
        end_time = time.time()
        elapsed_time = math.floor((end_time - start_time) * 1000)  # Convert to milliseconds and floor to the nearest tenth
        return 'ERROR (Connection timeout)', elapsed_time, 'N/A'

def reverse_dns_lookup():

    return

def mac_address():

    return

def format_output(ip, status, elapsed_time, hostname, mac_address):
    if status == 'UP':
        return f"{ip} - {status} ({elapsed_time}ms)\n  Hostname: {hostname}\n  MAC: {mac_address}"
    elif status == 'DOWN':
        return f"{ip} - {status} (NO response)"
    else:
        return f"{ip} - {status}"

def csv_export():

    return



# print(ip_network("192.168.1.0/24", strict=False))