[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/cYbEVSqo)
[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=17897227)


# IP Address Scanner

This script scans a given range of IP addresses to determine which hosts are active, performs reverse DNS lookups to retrieve hostnames, and detects MAC addresses of devices on the local network. The results are displayed in the terminal and can also be exported to a CSV file for further analysis.

## Features
- **Ping Scanning**: Checks if an IP address is reachable by sending a single ping request.
- **Reverse DNS Lookup**: Retrieves the hostname associated with an IP address (if available).
- **MAC Address Detection**: Identifies the MAC address of devices on the local network using ARP.
- **CSV Export**: Saves the scan results to a CSV file for easy sharing and analysis.

## Example Usage
Run the script from the command line by providing an IP range as an argument:

python scanner.py 192.168.1.0/24

The results will be displayed in the terminal and automatically exported to a CSV file named `scan_results.csv` in the same directory as the script.

## Example Output

### Terminal Output:
192.168.1.0/30
DEBUG: User input IP range: 192.168.1.0/30
DEBUG: Parsed network range: 192.168.1.0/30
Scanning network 192.168.1.0/30...

192.168.1.1 - DOWN (NO response)
192.168.1.2 - DOWN (NO response)

Results exported to scan_results.csv

Total scan completed in 8013.0 ms.
Scan complete. Found 0 active hosts, 2 down, 0 errors.

### CSV Output:
IP,Status,Time,Hostname,MAC
192.168.1.1,DOWN,4016,N/A,N/A
192.168.1.2,DOWN,3995,N/A,N/A

## How to Export to CSV
The script automatically exports the scan results to a CSV file named `scan_results.csv` in the same directory as the script. No additional steps are required. Simply run the script, and the file will be created or overwritten with the latest results.

## Notes
- The script uses ICMP (ping) to check if a host is reachable. Ensure that ICMP is not blocked by firewalls on the target network.
- Reverse DNS lookups may fail if the DNS server does not have a PTR record for the IP address.
- MAC address detection works only for devices on the local network.