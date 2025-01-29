#scans ip address for address and pings for information on up or down

# pip install scapy dnspython

import os
import time
import socket
import subprocess
import csv
import math
from ipaddress import ip_network, ip_address
from scapy.all import ARP, Ether, srp
import dns.resolver
import dns.reversename

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_network_range(ip):
    # Determine the network range based on local IP
    ip_addr = ip_address(ip)
    network = ip_network(ip_addr, strict=False)
    return network

def scan_network(ip_range):
    results = []
    for ip in ip_range.hosts():
        ip_str = str(ip)
        result, elapsed_time, mac_address = ping(ip_str)
        hostname = reverse_dns_lookup(ip_str) if result == 'UP' else 'N/A'
        status_output = format_status(ip_str, result, elapsed_time, hostname, mac_address)
        print(status_output)
        results.append({'IP': ip_str, 'Status': result, 'Time': elapsed_time, 'Hostname': hostname, 'MAC': mac_address})

    return results

def ping(ip):
    # Measure the time it takes to ping the IP address with a timeout of 30 seconds
    start_time = time.time()
    try:
        # Execute the ping command and check the result
        result = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        end_time = time.time()
        elapsed_time = math.floor((end_time - start_time) * 10000) / 10  # Convert to milliseconds and floor to the nearest tenth
        if result.returncode == 0:
            mac_address = get_mac_address(ip)
            return 'UP', elapsed_time, mac_address
        else:
            return 'DOWN', elapsed_time, 'N/A'
    except subprocess.TimeoutExpired:
        end_time = time.time()
        elapsed_time = math.floor((end_time - start_time) * 10000) / 10  # Convert to milliseconds and floor to the nearest tenth
        return 'ERROR (Connection timeout)', elapsed_time, 'N/A'

def reverse_dns_lookup(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        hostname = str(dns.resolver.resolve(rev_name, 'PTR')[0])
        return hostname
    except:
        return 'N/A'

def get_mac_address(ip):
    # Use ARP to get the MAC address of the IP
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv[Ether].src
    return 'N/A'

def format_status(ip, status, elapsed_time, hostname, mac_address):
    if status == 'UP':
        return f"{ip} - {status} ({elapsed_time}ms)\n  Hostname: {hostname}\n  MAC: {mac_address}"
    elif status == 'DOWN':
        return f"{ip} - {status} (NO response)"
    else:
        return f"{ip} - {status}"

def export_to_csv(results, filename='scan_results.csv'):
    keys = results[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)

def main():
    # Get user input for the IP range, with default value
    local_ip = get_local_ip()
    network_range = get_network_range(local_ip)
    default_range = f"{network_range.network_address}/{network_range.prefixlen}"
    ip_range_input = input(f"Enter the IP range to scan (default is {default_range}): ") or default_range

    print(f"DEBUG: User input IP range: {ip_range_input}")

    try:
        # Parse the network range
        ip_range = ip_network(ip_range_input, strict=False)
        print(f"DEBUG: Parsed network range: {ip_range}")
    except ValueError as e:
        print(f"ERROR: Invalid IP range: {e}")
        return

    # Start time
    total_start_time = time.time()

    # Scan the network
    print(f"Scanning network {ip_range}...\n")
    results = scan_network(ip_range)

    # End time
    total_end_time = time.time()
    total_elapsed_time = math.floor((total_end_time - total_start_time) * 10000) / 10  # Convert to milliseconds and floor to the nearest tenth

    # Export results to CSV
    export_to_csv(results)
    print("\nResults exported to scan_results.csv")
    print(f"\nTotal scan completed in {total_elapsed_time:.1f} ms.")
    active_hosts = sum(1 for result in results if result['Status'] == 'UP')
    down_hosts = sum(1 for result in results if result['Status'] == 'DOWN')
    errors = sum(1 for result in results if 'ERROR' in result['Status'])
    print(f"Scan complete. Found {active_hosts} active hosts, {down_hosts} down, {errors} errors")

if __name__ == "__main__":
    main()
