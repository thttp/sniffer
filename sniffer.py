import pyfiglet
from colorama import Fore, Style
from scapy.all import sniff, Ether, IP, TCP, UDP
import argparse

# Gerar o ASCII Art com "SNIFFER"
banner = pyfiglet.figlet_format("SNIFFER")
print(Fore.GREEN + banner + Style.RESET_ALL)

def packet_callback(packet):
    if Ether in packet:
        print(f"Ethernet Frame: {packet[Ether].src} -> {packet[Ether].dst}")

    if IP in packet:
        print(f"IP Packet: {packet[IP].src} -> {packet[IP].dst}")

    if TCP in packet:
        print(f"TCP Segment: {packet[TCP].sport} -> {packet[TCP].dport}")

    if UDP in packet:
        print(f"UDP Datagram: {packet[UDP].sport} -> {packet[UDP].dport}")

    print("-" * 40)

def start_sniffer(interface=None, count=0):
    print(Fore.GREEN + "Starting network sniffer..." + Style.RESET_ALL)
    sniff(iface=interface, prn=packet_callback, count=count)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default=None)
    parser.add_argument("-c", "--count", help="Number of packets to capture", type=int, default=0)
    args = parser.parse_args()

    start_sniffer(interface=args.interface, count=args.count)
