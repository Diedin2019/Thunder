# Thunder
ThunderScan
 
ThunderScan is a high-performance, multi-threaded port scanner designed for network reconnaissance and security auditing. Built with Python, it offers speed, stealth, and flexibility, making it ideal for scanning single IPs, CIDR ranges, or large networks. This tool was developed as a college project to demonstrate advanced network programming and cybersecurity concepts.

Table of Contents

Features
Installation
Usage
Command-Line Options
Examples
Output Formats
Contributing
License
Acknowledgements


Features

Ultra-Fast Scanning: Utilizes multi-threading and asynchronous I/O for rapid port scanning.
Flexible Input: Supports single IPs, IP ranges, CIDR notation, and IP lists from files.
Port Options:
Default scans top 100 common ports.
Option to scan top 1000 ports with --top-1000.
Custom ports with Nmap-style syntax (e.g., -p 80,445, -p 1-100, -p- for all ports).


Advanced Detection:
Service detection (-S) for identifying running services (e.g., HTTP, SSH).
Version detection (-sV) for detailed service versioning.
OS detection (-O) using TTL-based fingerprinting.


Stealth Features: Randomized port scanning and jitter to bypass firewalls.
Output Management:
Rich console output with color-coded results.
Save results as text (-o) or JSON (--json).
Quiet mode (-q) for minimal output.


Notifications: Send scan results to Discord via webhook (-d).
Live Host Detection: Efficiently filters out unreachable hosts before scanning.
Cross-Platform: Optimized for Linux (tested on Kali), with Windows support.


Installation
Prerequisites

Python 3.8 or higher
pip (Python package manager)
Linux (recommended, e.g., Kali, Ubuntu) or Windows

Steps

Clone the Repository
git clone https://github.com/yourusername/thunderscan.git
cd thunderscan


Create a Virtual Environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install Dependencies
pip install -r requirements.txt

The requirements.txt includes:

click>=8.1.3
rich>=13.3.5
alive_progress>=3.1.1
aiohttp>=3.8.4
urllib3>=2.0.7


Verify InstallationRun the tool to ensure it’s set up correctly:
python3 port_scanner.py --help



Notes

On Linux, you may need sudo for ICMP ping operations due to permissions.
Ensure you have internet access for Discord notifications (if used).


Usage
Run ThunderScan using the port_scanner.py script with various command-line options to customize your scan.
python3 port_scanner.py [OPTIONS]

Command-Line Options



Option
Description
Example



-p, --ports
Specify ports to scan (e.g., 80, 80,445, 1-100, - for all). Default: top 100 ports.
-p 80,443


-i, --ip
Single IP, range, or CIDR to scan.
-i 192.168.1.1 or -i 192.168.1.0/24


-L, --ip-list
File containing IPs or ranges (one per line).
-L ips.txt


-t, --threads
Number of threads (1-1000, default: 200).
-t 500


-o, --output
Output file name (without extension).
-o scan_results


-S, --service
Enable service detection.
-S


-sV, --version
Enable service version detection.
-sV


-O, --os
Enable OS detection.
-O


-d, --discord
Discord webhook URL for notifications.
-d https://discord.com/api/webhooks/...


--open
Show only IPs with open ports.
--open


--top-1000
Scan top 1000 ports instead of top 100.
--top-1000


--json
Save output as JSON instead of text.
--json


-q, --quiet
Suppress console output except errors and summary.
-q


Examples

Scan Top 100 Ports on a Single IP
python3 port_scanner.py -i 192.168.1.1


Scan Specific Ports on a CIDR Range
python3 port_scanner.py -i 192.168.1.0/24 -p 80,443,445


Scan Top 1000 Ports with Service and OS Detection
python3 port_scanner.py -i 192.168.1.1 --top-1000 -S -O


Scan All Ports with JSON Output
python3 port_scanner.py -i 192.168.1.1 -p- -o results --json


Quiet Scan with Discord Notification
python3 port_scanner.py -i 192.168.1.0/24 -p 80,443 -d https://discord.com/api/webhooks/... -q


Scan IPs from a File
python3 port_scanner.py -L ips.txt -p 22,80,443 -S -sV

Example ips.txt:
192.168.1.1
192.168.1.2-192.168.1.10
10.0.0.0/24




Output Formats
Console Output

Displays a colorful table with IP, port, status, service, version, and OS.
Includes a summary of total hosts scanned, hosts with open ports, and total open ports.
Status is green for open ports, red for no open ports.

Text Output (-o)

Saves results to a timestamped .txt file (e.g., scan_results_20250414_123456.txt).
Format:Scan started: 2025-04-14 12:34:56
Scan ended: 2025-04-14 12:35:00

IP: 192.168.1.1 (OS: Linux/Unix)
  Port 80: Open, Service: HTTP, Version: 2.4
  Port 443: Open, Service: HTTPS, Version: Unknown



JSON Output (--json)

Saves results to a timestamped .json file (e.g., scan_results_20250414_123456.json).
Format:{
  "start_time": "2025-04-14 12:34:56",
  "end_time": "2025-04-14 12:35:00",
  "results": {
    "192.168.1.1": {
      "ports": [
        [80, "Open", "HTTP", "2.4"],
        [443, "Open", "HTTPS", "Unknown"]
      ],
      "os": "Linux/Unix"
    }
  }
}




Contributing
Contributions are welcome! Please follow these steps:

Fork the repository.
Create a new branch (git checkout -b feature/your-feature).
Commit your changes (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a pull request.

For bugs or feature requests, open an issue with a detailed description.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgements

Built for a college project to explore network security and Python programming.
Inspired by tools like Nmap and Masscan.
Thanks to the open-source community for libraries like rich, aiohttp, and alive_progress.


Disclaimer: Use ThunderScan responsibly and only on networks you have permission to scan. Unauthorized scanning may violate laws or terms of service.
