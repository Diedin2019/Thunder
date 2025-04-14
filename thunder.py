import ipaddress
import socket
import asyncio
import aiohttp
import json
from concurrent.futures import ThreadPoolExecutor
from alive_progress import alive_bar
import click
from rich.console import Console
from rich.table import Table
from rich.text import Text
import urllib3
import sys
import time
from datetime import datetime, timezone
import re
import os
import subprocess
import random
import math
import selectors

# Disable urllib3 warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# Top 100 and 1000 ports
TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443, 3306, 1433,
    1521, 5432, 5900, 6379, 11211, 27017, 9200, 9300, 389, 636, 88, 123, 137, 138,
    139, 161, 162, 445, 548, 631, 993, 995, 1723, 2049, 2181, 2375, 2376, 3128,
    3260, 3307, 3388, 3690, 4369, 5433, 5555, 5984, 6378, 6666, 8000, 8001, 8081,
    8082, 8088, 8444, 8888, 9000, 9042, 9092, 9100, 9201, 9301, 9418, 9999, 10000,
    11212, 12345, 27018, 28017, 50000, 50070, 50090, 6000, 6001, 6377, 7000, 7001,
    8008, 8010, 8089, 8090, 8091, 8445, 8880, 9001, 9043, 9090, 9091, 9202, 9302,
    9998, 10001
]
TOP_1000_PORTS = TOP_100_PORTS + list(range(1000, 2000, 10))[:900]

def display_banner(quiet):
    """Display an attractive ASCII art banner unless quiet mode."""
    if quiet:
        return
    banner = Text()
    banner.append("╔════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║        ThunderScan                 ║\n", style="bold magenta")
    banner.append("║   Ultra-Fast Network Scanner       ║\n", style="bold yellow")
    banner.append("║   Built for Speed & Stealth        ║\n", style="bold green")
    banner.append("╚════════════════════════════════════╝\n", style="bold cyan")
    console.print(banner)
    console.print("Optimized for Linux and large networks\n", style="italic blue")

def parse_ip_input(ip_input):
    """Parse single IP, range, or CIDR efficiently."""
    try:
        network = ipaddress.ip_network(ip_input, strict=False)
        for ip in network:
            yield str(ip)
    except ValueError:
        if '-' in ip_input:
            try:
                start_ip, end_ip = ip_input.split('-')
                start = int(ipaddress.ip_address(start_ip.strip()))
                end = int(ipaddress.ip_address(end_ip.strip()))
                if start > end:
                    raise ValueError("Invalid IP range: start IP greater than end IP")
                for i in range(start, end + 1):
                    yield str(ipaddress.ip_address(i))
            except ValueError as e:
                raise ValueError(f"Invalid IP range format: {e}")
        else:
            try:
                ipaddress.ip_address(ip_input)
                yield ip_input
            except ValueError:
                raise ValueError(f"Invalid IP address: {ip_input}")

def parse_port_input(port_input, top_1000):
    """Parse single port, port range, comma-separated ports, all ports, or top 1000."""
    if not port_input and not top_1000:
        return TOP_100_PORTS
    if top_1000:
        return TOP_1000_PORTS
    if port_input == "-":
        return list(range(1, 65536))
    ports = set()
    try:
        for part in port_input.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError("Ports must be between 1 and 65535")
                if start > end:
                    raise ValueError("Start port cannot be greater than end port")
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError("Port must be between 1 and 65535")
                ports.add(port)
        return sorted(ports)
    except ValueError as e:
        raise ValueError(f"Invalid port format: {e}")

def is_host_alive(ip, timeout=0.1):
    """Fast check if host is alive using ICMP and TCP ping."""
    try:
        ping_cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
        result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=timeout + 0.2)
        if result.returncode == 0:
            return True
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, PermissionError):
        pass
    sel = selectors.DefaultSelector()
    for port in [80, 443]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.connect_ex((ip, port))
            sel.register(sock, selectors.EVENT_WRITE)
            events = sel.select(timeout=timeout)
            if events:
                return True
            sock.close()
        except Exception:
            pass
        finally:
            sel.unregister(sock) if sock.fileno() != -1 else None
    return False

async def get_service(ip, port, timeout=0.6):
    """Detect service and version asynchronously."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        service_checks = {
            21: b"220 FTP\r\n",
            22: b"SSH-2.0-",
            23: b"Telnet",
            25: b"HELO localhost\r\n",
            80: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            443: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            110: b"+OK POP3\r\n",
            143: b"* OK IMAP\r\n",
            3306: b"MySQL",
        }
        service = "Unknown"
        version = ""
        if port in service_checks:
            sock.send(service_checks[port])
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                for check_port, check_banner in service_checks.items():
                    if check_banner.decode().lower() in banner.lower():
                        service = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP", 3306: "MySQL"}.get(check_port, "Unknown")
                        break
                version_match = re.search(r"(\d+\.\d+\.\d+|\d+\.\d+)", banner)
                version = version_match.group(0) if version_match else ""
        sock.close()
        return service, version
    except Exception:
        return "Unknown", ""
    finally:
        sock.close()

def get_os(ip, timeout=0.1):
    """Detect OS using TTL."""
    try:
        ping_cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
        result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=timeout + 0.2)
        ttl_match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if 0 <= ttl <= 64:
                return "Linux/Unix"
            elif 65 <= ttl <= 128:
                return "Windows"
            elif 129 <= ttl <= 255:
                return "Android/iOS/macOS"
        return "Unknown"
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, PermissionError):
        return "Unknown"

def scan_port(ip, port, service_detect, version_detect, timeout=0.2, retries=1):
    """Scan a single port with minimal overhead."""
    sel = selectors.DefaultSelector()
    for attempt in range(retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.connect_ex((ip, port))
            sel.register(sock, selectors.EVENT_WRITE)
            events = sel.select(timeout=timeout)
            if events:
                if sock.getpeername():
                    service, version = ("Unknown", "") if not service_detect else asyncio.run(get_service(ip, port))
                    if version_detect and not version:
                        _, version = asyncio.run(get_service(ip, port))
                    sock.close()
                    return port, True, service, version
            break
        except Exception:
            if attempt == retries - 1:
                return port, False, "", ""
        finally:
            sel.unregister(sock) if sock.fileno() != -1 else None
            sock.close()
        time.sleep(random.uniform(0.02, 0.06))
    return port, False, "", ""

def scan_ip(ip, ports, threads, service_detect, version_detect, os_detect, bar):
    """Scan all specified ports for a single IP."""
    results = []
    os_guess = get_os(ip) if os_detect else "N/A"
    common_ports = [p for p in ports if p in [21, 22, 23, 25, 80, 443, 110, 143, 3306]]
    other_ports = [p for p in ports if p not in common_ports]
    randomized_ports = random.sample(common_ports + other_ports, len(ports))
    with ThreadPoolExecutor(max_workers=min(threads, len(ports))) as executor:
        futures = [executor.submit(scan_port, ip, port, service_detect, version_detect) for port in randomized_ports]
        for future in futures:
            port, is_open, service, version = future.result()
            if is_open:
                results.append((port, "Open", service, version))
            bar()
    return ip, results, os_guess

def save_output(results, filename, start_time, end_time, json_output):
    """Save scan results to a file in text or JSON format."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        if json_output:
            output_data = {
                "start_time": start_time,
                "end_time": end_time,
                "results": {
                    ip: {"ports": [(p, s, srv, v) for p, s, srv, v in data[0]], "os": data[1]}
                    for ip, data in results.items()
                }
            }
            with open(f"{filename}_{timestamp}.json", "w") as f:
                json.dump(output_data, f, indent=2)
        else:
            with open(f"{filename}_{timestamp}.txt", "w") as f:
                f.write(f"Scan started: {start_time}\n")
                f.write(f"Scan ended: {end_time}\n\n")
                for ip, data in results.items():
                    ports, os_guess = data
                    f.write(f"IP: {ip} (OS: {os_guess})\n")
                    if ports:
                        for port, status, service, version in ports:
                            f.write(f"  Port {port}: {status}, Service: {service}, Version: {version}\n")
                    else:
                        f.write("  No open ports\n")
                    f.write("\n")
        return True
    except (IOError, PermissionError) as e:
        console.print(f"[red]Error saving output: {e}[/red]")
        return False

async def send_discord_notification(webhook_url, results, start_time, end_time):
    """Send scan results to Discord webhook with retry logic."""
    async with aiohttp.ClientSession() as session:
        for attempt in range(3):
            try:
                embed = {
                    "title": "ThunderScan Results",
                    "description": f"Scan started: {start_time}\nScan ended: {end_time}",
                    "color": 0x00ff00,
                    "fields": [],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                for ip, data in list(results.items())[:25]:
                    ports, os_guess = data
                    if ports:
                        value = "\n".join([f"Port {p}: {s}, {v} (OS: {os_guess})" for p, _, s, v in ports])
                        value = value[:1024]
                    else:
                        value = "No open ports"
                    embed["fields"].append({"name": f"IP: {ip}", "value": value})
                payload = {"embeds": [embed]}
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 204:
                        return
                    elif response.status == 429:
                        retry_after = (await response.json()).get("retry_after", 1)
                        await asyncio.sleep(retry_after / 1000)
                    else:
                        console.print(f"[red]Error sending Discord notification: {await response.text()}[/red]")
                        return
            except Exception as e:
                console.print(f"[red]Error sending Discord notification: {e}[/red]")
                if attempt == 2:
                    return
            await asyncio.sleep(0.5)

def display_results(results, start_time, end_time, open_only, quiet):
    """Display scan results with summary and rich table."""
    if quiet:
        return
    # Summary
    total_hosts = len(results)
    open_port_hosts = sum(1 for ip, data in results.items() if data[0])
    total_open_ports = sum(len(data[0]) for ip, data in results.items())
    console.print(f"[bold green]Summary: Scanned {total_hosts} hosts, found {open_port_hosts} with open ports, {total_open_ports} total open ports[/bold green]\n")

    table = Table(title=f"ThunderScan Results\nStarted: {start_time} | Ended: {end_time}", show_lines=True, show_edge=False, show_footer=False)
    table.add_column("IP", style="cyan")
    table.add_column("Port", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Version", style="blue")
    table.add_column("OS", style="white")

    for ip, data in sorted(results.items()):
        ports, os_guess = data
        if open_only and not ports:
            continue
        if ports:
            for port, status, service, version in sorted(ports):
                table.add_row(ip, str(port), Text(status, style="green" if status == "Open" else "red"), service, version, os_guess)
        else:
            table.add_row(ip, "-", Text("No open ports", style="red"), "-", "-", os_guess)

    console.print(table)

@click.command()
@click.option("-p", "--ports", default="", help="Ports (e.g., 80, 80,445, 1-100, - for all; default: top 100)")
@click.option("-i", "--ip", help="Single IP, range, or CIDR (e.g., 192.168.1.1, 192.168.1.1-10, 192.168.1.0/24)")
@click.option("-L", "--ip-list", type=click.File('r'), help="File with IPs or ranges")
@click.option("-t", "--threads", default=200, type=int, help="Threads (1-1000, default: 200)")
@click.option("-o", "--output", help="Output file name (without extension)")
@click.option("-S", "--service", is_flag=True, help="Enable service detection")
@click.option("-sV", "--version", is_flag=True, help="Enable service version detection")
@click.option("-O", "--os", is_flag=True, help="Enable OS detection")
@click.option("-d", "--discord", help="Discord webhook URL for notifications")
@click.option("--open", is_flag=True, help="Show only IPs with open ports")
@click.option("--top-1000", is_flag=True, help="Scan top 1000 ports")
@click.option("--json", is_flag=True, help="Save output as JSON")
@click.option("-q", "--quiet", is_flag=True, help="Suppress console output except errors and summary")
def main(ports, ip, ip_list, threads, output, service, version, os, discord, open, top_1000, json, quiet):
    """ThunderScan: Ultra-fast port scanner for large networks."""
    display_banner(quiet)
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Validate threads
    if not 1 <= threads <= 1000:
        console.print("[red]Error: Threads must be between 1 and 1000.[/red]")
        sys.exit(1)

    # Validate Discord webhook if provided
    if discord:
        try:
            parsed_url = urllib3.util.parse_url(discord)
            if not (parsed_url.scheme in ["http", "https"] and parsed_url.host):
                raise ValueError("Invalid Discord webhook URL")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)

    # Parse IPs
    ip_addresses = []
    try:
        if ip:
            ip_addresses.extend(list(parse_ip_input(ip)))
        if ip_list:
            for line in ip_list:
                line = line.strip()
                if line:
                    ip_addresses.extend(list(parse_ip_input(line)))
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    if not ip_addresses:
        console.print("[red]Error: No valid IPs provided.[/red]")
        sys.exit(1)

    # Deduplicate IPs
    ip_addresses = sorted(list(set(ip_addresses)))

    # Adjust threads for large networks
    threads = min(threads, max(10, math.ceil(len(ip_addresses) / 5)))

    # Check live hosts in batches
    if not quiet:
        console.print("[yellow]Checking live hosts...[/yellow]")
    live_ips = []
    batch_size = 200
    with alive_bar(len(ip_addresses), title="Pinging", bar="classic", spinner="dots", disable=quiet) as bar:
        for i in range(0, len(ip_addresses), batch_size):
            batch = ip_addresses[i:i + batch_size]
            with ThreadPoolExecutor(max_workers=min(threads, len(batch))) as executor:
                futures = [executor.submit(is_host_alive, ip) for ip in batch]
                for future, ip in zip(futures, batch):
                    if future.result():
                        live_ips.append(ip)
                    bar()

    if not live_ips:
        console.print("[red]Error: No live hosts found.[/red]")
        sys.exit(1)

    if not quiet:
        console.print(f"[green]Found {len(live_ips)} live hosts.[/green]")

    # Parse ports
    try:
        port_list = parse_port_input(ports, top_1000)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    # Total tasks for progress bar
    total_tasks = len(live_ips) * len(port_list)
    results = {}

    if not quiet:
        console.print("[yellow]Starting port scan...[/yellow]")
    scan_start = time.time()

    with alive_bar(total_tasks, title="Scanning", bar="bubbles", spinner="pulse", stats=True, disable=quiet) as bar:
        with ThreadPoolExecutor(max_workers=min(threads, len(live_ips))) as executor:
            futures = [executor.submit(scan_ip, ip, port_list, threads, service, version, os, bar) for ip in live_ips]
            for future in futures:
                ip, scan_results, os_guess = future.result()
                results[ip] = (scan_results, os_guess)

    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Display results
    display_results(results, start_time, end_time, open, quiet)

    # Save output if specified
    if output:
        if save_output(results, output, start_time, end_time, json):
            console.print(f"[green]Results saved to {output}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{'json' if json else 'txt'}[/green]")

    # Send Discord notification if specified
    if discord:
        asyncio.run(send_discord_notification(discord, results, start_time, end_time))
        console.print("[green]Discord notification sent.[/green]")

    # Display scan time
    console.print(f"[blue]Scan completed in {time.time() - scan_start:.2f} seconds.[/blue]")

if __name__ == "__main__":
    main()
