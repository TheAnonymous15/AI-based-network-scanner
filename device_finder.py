import pickle
import csv
from scapy.all import ARP, Ether, srp
import nmap

# Load the trained model
try:
    with open('os_classifier.pkl', 'rb') as model_file:
        model = pickle.load(model_file)
except FileNotFoundError:
    print("Error: 'os_classifier.pkl' file not found.")
    exit(1)
except Exception as e:
    print(f"Error loading model: {e}")
    exit(1)

# Function to predict OS
def predict_os(open_ports):
    features = [1 if port in open_ports else 0 for port in range(1, 65536)]
    features.append(len(open_ports))
    return model.predict([features])[0]

# Function to scan the network
def scan_network(nm):
    arp = ARP(pdst='192.168.100.0/24')
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp
    try:
        result = srp(packet, timeout=3, verbose=0)[0]
    except Exception as e:
        print(f"Error in network scan: {e}")
        return []

    devices = []
    for sent, received in result:
        device = {'ip': received.psrc, 'mac': received.hwsrc}
        devices.append(device)

    for device in devices:
        ip = device['ip']
        try:
            nm.scan(ip, '1-65535')
        except Exception as e:
            print(f"Error scanning IP {ip}: {e}")
            continue

        open_ports = []
        for proto in nm[ip].all_protocols():
            ports = nm[ip][proto].keys()
            open_ports.extend(ports)

        os_prediction = predict_os(open_ports)
        device['os'] = os_prediction
        device['open_ports'] = open_ports
        device['hostname'] = nm[ip].hostname()

    return devices

# Function to print results and save to CSV
def main():
    nm = nmap.PortScanner()
    devices = scan_network(nm)
    os_count = {'Android': 0, 'iOS': 0, 'Linux': 0, 'Windows': 0, 'MacOS': 0, 'Unknown': 0}

    print("Scanning subnet: 192.168.100.0/24")
    for device in devices:
        os_count[device['os']] += 1
        print(f"IP address: {device['ip']}, MAC Address: {device['mac']}, OS: {device['os']}")
        for port in device['open_ports']:
            try:
                service = nm[device['ip']].tcp(port)['name']
            except KeyError:
                service = 'Unknown'
            print(f"    Open port: {port}, Service running on the port: {service}")

    print("\nSummary Table of All Devices:")
    print(f"{'IP Address':<25}{'MAC Address':<25}{'Device OS':<25}{'Hostname':<25}")
    for device in devices:
        print(f"{device['ip']:<25}{device['mac']:<25}{device['os']:<25}{device['hostname']:<25}")

if __name__ == '__main__':
    main()
