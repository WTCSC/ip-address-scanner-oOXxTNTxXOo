#scans ip address for address and pings for information on up or down

# pip install scapy dnspython

import subprocess
import sys

result = subprocess.run(["arp", "-a"], capture_output=True, text=True)

if result.returncode == 0:
    print(result.stdout)
else:
    print("Error:", result.stderr)

a = sys.argv[1]

print(a)