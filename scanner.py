import socket
import nmap
from collections import defaultdict
from prettytable import PrettyTable
import concurrent.futures
import time
from colorama import Fore, Style, init
from scapy.all import ARP, Ether, srp

init()

a = r"""

     ___      .__   __.   ______   .__   __. ____    ____ .___  ___.   ______    __    __       _______.__   _  _    
    /   \     |  \ |  |  /  __  \  |  \ |  | \   \  /   / |   \/   |  /  __  \  |  |  |  |     /       /_ | | || |   
   /  ^  \    |   \|  | |  |  |  | |   \|  |  \   \/   /  |  \  /  | |  |  |  | |  |  |  |    |   (----`| | | || |_  
  /  /_\  \   |  . `  | |  |  |  | |  . `  |   \_    _/   |  |\/|  | |  |  |  | |  |  |  |     \   \    | | |__   _| 
 /  _____  \  |  |\   | |  `--'  | |  |\   |     |  |     |  |  |  | |  `--'  | |  `--'  | .----)   |   | |    | |   
/__/     \__\ |__| \__|  \______/  |__| \__|     |__|     |__|  |__|  \______/   \______/  |_______/    |_|    |_|   
                                                                                                               

"""

print(a + f"{Fore.CYAN}A little patience as we comprehensively scan your network as requested!!\n")


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


# Function to scan the network for devices using scapy
def scan_network(subnet):
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices


# Function to detect the OS and open ports of a device
def scan_device(ip):
    nm = nmap.PortScanner()
    try:
        # Aggressive OS detection
        nm.scan(ip, arguments='-sS -O --fuzzy -p- -T4')  # --fuzzy for more aggressive OS detection
    except Exception as e:
        print(f"Failed to scan device {ip}: {e}")
        return 'Unknown', []

    if ip not in nm.all_hosts():
        return 'Unknown', []

    os = 'Unknown'
    if 'osclass' in nm[ip]:
        os = nm[ip]['osclass'][0]['osfamily'] + " " + nm[ip]['osclass'][0]['osgen']
    elif 'osmatch' in nm[ip] and nm[ip]['osmatch']:
        os = nm[ip]['osmatch'][0]['name']

    ports = []
    if 'tcp' in nm[ip]:
        for port in nm[ip]['tcp']:
            service = nm[ip]['tcp'][port]['name']
            ports.append({'port': port, 'service': service})
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

    # Use multi-threading for device scanning
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_ip, device['ip']) for device in devices]
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                ip = result['ip']
                os = result['os']
                ports = result['ports']

                for device in devices:
                    if device['ip'] == ip:
                        mac = device['mac']
                        break
                else:
                    mac = "Unknown"

                os_summary[os].append({'ip': ip, 'mac': mac, 'ports': ports})
            except Exception as e:
                print(f"Error processing device: {e}")

    # Print summary of found devices
    os_counts = defaultdict(int)
    for os_type in os_summary:
        os_counts[os_type] += len(os_summary[os_type])

    if not any(os_counts.values()):
        print("No devices detected on the network.")
        return

    # Print devices categorized by OS
    for os_type, devices in os_summary.items():
        print(f"\n{Fore.CYAN}The following devices run {os_type}:{Fore.RESET}")
        for device in devices:
            ip = device['ip']
            mac = device['mac']
            print(f"- {ip} (MAC: {mac})")
            for port in device['ports']:
                print(f"   - Port: {port['port']}, Service: {port['service']}")

    # Print a summary table of all devices
    summary_table = PrettyTable()
    summary_table.field_names = [f"{Fore.YELLOW}IP Address{Fore.RESET}", f"{Fore.YELLOW}MAC Address{Fore.RESET}",
                                 f"{Fore.YELLOW}Device OS{Fore.RESET}", f"{Fore.YELLOW}Hostname{Fore.RESET}"]
    for os_type, devices in os_summary.items():
        for device in devices:
            ip = device['ip']
            mac = device['mac'] or "Unknown"
            try:
                hostname = socket.gethostbyaddr(ip)[0] if ip != local_ip else socket.gethostname()
            except socket.herror:
                hostname = "Unknown"
            summary_table.add_row([ip, mac, os_type, hostname])

    print(f"\n{Fore.MAGENTA}Summary of all discovered devices:{Fore.RESET}")
    print(summary_table)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\n{Fore.GREEN}Elapsed time: {Fore.RESET}{elapsed_time:.2f} seconds")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user.{Fore.RESET}")
    except Exception as e:
        print(f"\n{Fore.RED}An error occurred: {e}{Fore.RESET}")
