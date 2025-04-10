# This script scans IP addresses in a given range, pings them to check if they are up or down,
# performs reverse DNS lookups, and retrieves MAC addresses using ARP.
# Dependencies: scapy, dnspython (install using `pip install scapy dnspython`)

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
import sys

def scan_network(ip_range):
    """
    Scans the provided IP range for active hosts. For each IP, it pings the address,
    performs a reverse DNS lookup if the host is up, and retrieves the MAC address.

    Why multiple functions? 
    - Breaking the logic into smaller functions (e.g., `ping`, `reverse_dns_lookup`) makes the code modular, 
      easier to debug, and reusable. Each function has a single responsibility, adhering to the Single Responsibility Principle.
    """
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
    """
    Pings the given IP address to check if it is reachable.

    Why use subprocess over os.system?
    - `subprocess.run` is preferred over `os.system` because it provides more control over the execution of commands, 
      allows capturing output, and is safer (e.g., avoids shell injection vulnerabilities).
    - It also allows setting a timeout, which is critical for ensuring the script doesn't hang indefinitely.
    """
    start_time = time.time()
    try:
        result = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        end_time = time.time()
        elapsed_time = math.floor((end_time - start_time) * 1000)  # Convert to milliseconds
        if result.returncode == 0:
            mac_address = get_mac_address(ip)
            return 'UP', elapsed_time, mac_address
        else:
            return 'DOWN', elapsed_time, 'N/A'
    except subprocess.TimeoutExpired:
        end_time = time.time()
        elapsed_time = math.floor((end_time - start_time) * 1000)
        return 'ERROR (Connection timeout)', elapsed_time, 'N/A'

def reverse_dns_lookup(ip):
    """
    Performs a reverse DNS lookup to find the hostname for the given IP address.

    Why use dnspython?
    - The `dnspython` library is used because it provides a simple and efficient way to perform DNS lookups, 
      including reverse lookups. It is more flexible and feature-rich compared to using `socket.gethostbyaddr`.
    """
    try:
        rev_name = dns.reversename.from_address(ip)
        hostname = str(dns.resolver.resolve(rev_name, 'PTR')[0])
        return hostname
    except:
        return 'N/A'

def get_mac_address(ip):
    """
    Retrieves the MAC address of the given IP address using ARP.

    Why use scapy for ARP?
    - The `scapy` library is used because it provides low-level access to network packets, 
      making it easy to send ARP requests and parse responses. This is more efficient and reliable 
      than trying to parse the output of system commands like `arp -a`.
    """
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv[Ether].src
    return 'N/A'

def format_status(ip, status, elapsed_time, hostname, mac_address):
    """
    Formats the scan result for a given IP address into a readable string.

    Why separate formatting logic?
    - Keeping the formatting logic in its own function makes it easier to modify the output format 
      without affecting the rest of the code. It also improves readability and maintainability.
    """
    if status == 'UP':
        return f"{ip} - {status} ({elapsed_time}ms)\n  Hostname: {hostname}\n  MAC: {mac_address}"
    elif status == 'DOWN':
        return f"{ip} - {status} (NO response)"
    else:
        return f"{ip} - {status} (Timed out)"

def export_to_csv(results, filename='scan_results.csv'):
    """
    Exports the scan results to a CSV file.

    Why use CSV for output?
    - CSV is a widely supported format that can be easily opened in spreadsheet software like Excel 
      or processed by other scripts. Using Python's built-in `csv` module ensures compatibility and simplicity.
    """
    keys = results[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)

# Main script execution
a = sys.argv[1]
print(a)

# Parse the user-provided IP range
ip_range_input = a
print(f"DEBUG: User input IP range: {ip_range_input}")
try:
    ip_range = ip_network(ip_range_input, strict=False)
    print(f"DEBUG: Parsed network range: {ip_range}")
except ValueError as e:
    print(f"ERROR: Invalid IP range: {e}")
    sys.exit(1)

# Start the scan
total_start_time = time.time()
print(f"Scanning network {ip_range}...\n")
results = scan_network(ip_range)

# Calculate total scan time
total_end_time = time.time()
total_elapsed_time = math.floor((total_end_time - total_start_time) * 1000)

# Export results to a CSV file
export_to_csv(results)
print("\nResults exported to scan_results.csv")
print(f"\nTotal scan completed in {total_elapsed_time:.1f} ms.")

# Print a summary of the scan
active_hosts = sum(1 for result in results if result['Status'] == 'UP')
down_hosts = sum(1 for result in results if result['Status'] == 'DOWN')
errors = sum(1 for result in results if 'ERROR' in result['Status'])
print(f"Scan complete. Found {active_hosts} active hosts, {down_hosts} down, {errors} errors.")