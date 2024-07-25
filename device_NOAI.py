import socket
import nmap
from collections import defaultdict
from prettytable import PrettyTable
import concurrent.futures
import time
from colorama import Fore, Style, init

# ASCII Art
a = r"""
 ░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██████████████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
"""

print(a)

# Initialize colorama
init()

# Function to get the local IP address
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()
    return ip

# Function to calculate the subnet
def calculate_subnet(ip):
    ip_parts = ip.split('.')
    subnet = '.'.join(ip_parts[:-1]) + '.0/24'
    return subnet

# Function to scan the network for devices using nmap
def scan_network(subnet):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=subnet, arguments='-sn -T4')  # -sn for ping scan, -T4 for faster execution
    except Exception as e:
        print(f"Failed to scan network: {e}")
        return []

    devices = []
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            device = {'ip': host, 'mac': nm[host]['addresses']['mac']}
            devices.append(device)
    return devices

# Function to detect the OS and open ports of a device
def scan_device(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sS -O -p- -T4')  # Scan all ports, -T4 for faster execution
    except Exception as e:
        print(f"Failed to scan device {ip}: {e}")
        return 'Unknown', []

    if ip not in nm.all_hosts():
        return 'Unknown', []

    os = 'Unknown'
    if 'osclass' in nm[ip]:
        os = nm[ip]['osclass'][0]['osfamily']
    elif 'osmatch' in nm[ip] and nm[ip]['osmatch']:
        os = nm[ip]['osmatch'][0]['name']

    ports = []
    if 'tcp' in nm[ip]:
        for port in nm[ip]['tcp']:
            service = nm[ip]['tcp'][port]['name']
            banner = nm[ip]['tcp'][port].get('product', 'Unknown')
            version = nm[ip]['tcp'][port].get('version', 'Unknown')
            ports.append({'port': port, 'service': service, 'banner': banner, 'version': version})
    return os, ports

# Function to handle scanning in a thread
def scan_ip(ip):
    os, ports = scan_device(ip)
    return {'ip': ip, 'os': os, 'ports': ports}

# Main function to orchestrate the scanning and printing
def main():
    start_time = time.time()

    local_ip = get_local_ip()
    if not local_ip or local_ip.startswith('127.'):
        print("Failed to determine local IP address.")
        return

    subnet = calculate_subnet(local_ip)

    print(f"{Fore.YELLOW}Scanning subnet: {Fore.RESET}{subnet}")
    devices = scan_network(subnet)
    if not devices:
        print("No devices found.")
        return

    # Add the local device manually
    devices.append({'ip': local_ip, 'mac': None})

    os_summary = defaultdict(list)
    device_summary = []

    # Use multi-threading for device scanning
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_ip, device['ip']) for device in devices]
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                ip = result['ip']
                os = result['os']
                ports = result['ports']

                os_summary[os].append({'ip': ip, 'mac': None, 'ports': ports})
                device_summary.append({'ip': ip, 'mac': None, 'os': os})
            except Exception as e:
                print(f"Error processing device: {e}")

    # Printing results using PrettyTable
    for os_type in os_summary:
        print(f"\n{Fore.CYAN}The following devices run {os_type}:{Fore.RESET}")
        table = PrettyTable()
        table.field_names = ["Index", "IP Address", "MAC Address", "Open Ports and Services"]

        for index, device in enumerate(os_summary[os_type], start=1):
            open_ports = "\n".join([f"Port: {port['port']}, Service: {port['service']}, Version: {port['version']}, Banner: {port['banner']}" for port in device['ports']])
            table.add_row([index, device['ip'], device['mac'], open_ports])

        print(table)

    # Unified Summary Table of All Devices
    summary_table = PrettyTable()
    summary_table.field_names = ["IP Address", "MAC Address", "Device OS", "Hostname"]

    for device in device_summary:
        try:
            hostname = socket.gethostbyaddr(device['ip'])[0]
        except (socket.herror, socket.gaierror):
            hostname = "Unknown"
        # Ensure consistent formatting
        ip = device['ip'].ljust(15)
        mac = (device['mac'] or "None").ljust(17)
        os = device['os'].ljust(15)
        summary_table.add_row([ip, mac, os, hostname])

    print(f"\n{Fore.GREEN}Unified Summary of All Devices:{Fore.RESET}")
    print(summary_table)

    elapsed_time = time.time() - start_time
    print(f"{Fore.MAGENTA}Elapsed Time: {Fore.RESET}{elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()
