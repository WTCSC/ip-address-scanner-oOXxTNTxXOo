#scans ip address for address and pings for information on up or down

# python scan.py 192.168.1.0/24

# pip install scapy dnspython

import socket
import sys
import time
import csv
import math
from ipaddress import ip_network, ip_address
from scapy.all import ARP, Ether, srp 
import dns.resolver
import dns.reversename

a = sys.argv[1] # ip range to scan 
# b = sys.argv[2] # save to csv 

def scan_net():
    ip_range = ip_network(a, strict=False)
    print(f"DEBUG: User input IP range: {ip_range}")
    total_start_time = time.time()
    for ip in ip_range.hosts():
        pinged = ping(ip)
        responsTime = 0
        status = 0




        print(f"{ip} - {status} ({responsTime}ms)")
        total_end_time = time.time()

    total_elapsed_time = math.floor((total_end_time - total_start_time) * 1000)  # Convert to milliseconds and floor to the nearest tenth 
        
    # result, elapsed_time, mac_address = ping(ip_str)
    # hostname = reverse_dns_lookup(ip_str) if result == 'UP' else 'N/A'
    # print(f"\nTotal scan completed in {total_elapsed_time:.1f} ms.")
    # print(f"Scan complete. Found {active_hosts} active hosts, {down_hosts} down, {errors} errors")



    # status_output = format_output(ip_str, result, elapsed_time, hostname, mac_address)
    # print(status_output)
    # results.append({'IP': ip_str, 'Status': result, 'Time': elapsed_time, 'Hostname': hostname, 'MAC': mac_address})
    


def ping(ip):
    # Measure the time it takes to ping the IP address with a timeout of 30 seconds
    start_time = time.time()
    # try:
    #     # Execute the ping command and check the result
    #     result = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    #     end_time = time.time()
    #     elapsed_time = math.floor((end_time - start_time) * 1000)  # Convert to milliseconds and floor to the nearest tenth
    #     if result.returncode == 0:
    #         mac = mac_address(ip)
    #         return 'UP', elapsed_time, mac
    #     else:
    #         return 'DOWN', elapsed_time, 'N/A'
    # except subprocess.TimeoutExpired:
    #     end_time = time.time()
    #     elapsed_time = math.floor((end_time - start_time) * 1000)  # Convert to milliseconds and floor to the nearest tenth
    #     return 'ERROR (Connection timeout)', elapsed_time, 'N/A'

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
        return f"{ip} - {status} (Timed out)"

def csv_export(result):
    filename = "scan_results.csv"
    ipKey = result[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=ipKey)
        dict_writer.writeheader()
        dict_writer.writerows(result)

    

# ip_range = ip_network("192.168.1.0/24", strict=False)
# print(f"DEBUG: User input IP range: {ip_range}")

# for ip in ip_range.hosts():
#     print (ip)
# print(ip_network("192.168.1.0/24", strict=False))