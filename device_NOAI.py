import os
import socket
import nmap
from collections import defaultdict
from prettytable import PrettyTable


# Function to get the local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
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
        nm.scan(hosts=subnet, arguments='-sP')
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
        nm.scan(ip, arguments='-sS -O -p-')
    except Exception as e:
        print(f"Failed to scan device {ip}: {e}")
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
            ports.append({'port': port, 'service': service})
    return os, ports


# Main function to orchestrate the scanning and printing
def main():
    local_ip = get_local_ip()
    if not local_ip or local_ip.startswith('127.'):
        print("Failed to determine local IP address.")
        return

    subnet = calculate_subnet(local_ip)

    print(f"Scanning subnet: {subnet}")
    devices = scan_network(subnet)

    # Add the local device manually
    devices.append({'ip': local_ip, 'mac': None})

    os_summary = defaultdict(list)
    device_summary = []

    for device in devices:
        ip = device['ip']
        mac = device['mac']
        os, ports = scan_device(ip)

        os_summary[os].append({'ip': ip, 'mac': mac, 'ports': ports})
        device_summary.append({'ip': ip, 'mac': mac, 'os': os})

    # Printing results using PrettyTable
    for os_type in os_summary:
        print(f"\nThe following devices run {os_type}:")
        table = PrettyTable()
        table.field_names = ["Index", "IP Address", "MAC Address", "Open Ports and Services"]

        for index, device in enumerate(os_summary[os_type], start=1):
            open_ports = "\n".join([f"Port: {port['port']}, Service: {port['service']}" for port in device['ports']])
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

    print("\nSummary Table of All Devices:")
    print(summary_table)


if __name__ == "__main__":
    main()
