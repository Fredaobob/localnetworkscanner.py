from scapy.all import ARP, Ether, srp, conf
import os
import sys

def scan_network(ip_range):
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and get the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Extract and return the IP and MAC addresses from the response
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root or with sudo.")
        sys.exit(1)

    # Define the IP range to scan (e.g., '192.168.1.1/24')
    ip_range = "192.168.1.1/24"
    devices = scan_network(ip_range)

    # Print the devices found
    print("Devices found:")
    for device in devices:
        print(f"IP: {device['ip']} - MAC: {device['mac']}")

