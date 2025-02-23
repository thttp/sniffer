import pyfiglet
import time
import sys
from colorama import Fore, Style
from scapy.all import sniff, Ether, IP, TCP, UDP, wrpcap

banner = pyfiglet.figlet_format("SNIFFER")
print(Fore.LIGHTGREEN_EX + banner + Style.RESET_ALL)

print(Fore.LIGHTGREEN_EX + "Network Sniffer\n" + Style.RESET_ALL)

def loading_animation(text="[*] Starting sniffer on interface"):
    for _ in range(3): 
        sys.stdout.write(Fore.LIGHTGREEN_EX + f"\r{text} .  " + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.5)
        sys.stdout.write(Fore.LIGHTGREEN_EX + f"\r{text} .. " + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.5)
        sys.stdout.write(Fore.LIGHTGREEN_EX + f"\r{text} ..." + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.5)
    print() 

def packet_callback(packet):
    print("=" * 50)
    
    if Ether in packet:
        print(Fore.LIGHTGREEN_EX + "[+] Ethernet Frame:" + Style.RESET_ALL)
        print(f"   |- Source MAC: {packet[Ether].src}")
        print(f"   |- Destination MAC: {packet[Ether].dst}")

    if IP in packet:
        print(Fore.LIGHTGREEN_EX + "[+] IP Packet:" + Style.RESET_ALL)
        print(f"   |- Source IP: {packet[IP].src}")
        print(f"   |- Destination IP: {packet[IP].dst}")
        print(f"   |- Protocol: {packet[IP].proto}")

    if TCP in packet:
        print(Fore.LIGHTGREEN_EX + "[+] TCP Segment:" + Style.RESET_ALL)
        print(f"   |- Source Port: {packet[TCP].sport}")
        print(f"   |- Destination Port: {packet[TCP].dport}")
        print(f"   |- Flags: {packet[TCP].flags}")

    if UDP in packet:
        print(Fore.LIGHTGREEN_EX + "[+] UDP Datagram:" + Style.RESET_ALL)
        print(f"   |- Source Port: {packet[UDP].sport}")
        print(f"   |- Destination Port: {packet[UDP].dport}")

def start_sniffer(interface, count, protocol, output_file):
    loading_animation(f"[*] Starting sniffer on interface {interface}")

    time.sleep(2)

    filter_proto = None
    if protocol.lower() == "tcp":
        filter_proto = "tcp"
    elif protocol.lower() == "udp":
        filter_proto = "udp"
    elif protocol.lower() == "icmp":
        filter_proto = "icmp"

    packets = sniff(iface=interface, prn=packet_callback, count=count, filter=filter_proto)

    if output_file:
        wrpcap(output_file, packets)
        print(Fore.LIGHTGREEN_EX + f"\nPacotes salvos em: {output_file}" + Style.RESET_ALL)

def menu():
    interface = input("Digite a interface de rede: ")
    
    count_input = input("Número de pacotes a capturar: ")
    count = int(count_input) if count_input.strip() else 0
    
    protocol = input("Filtrar por protocolo: ")
    output_file = input("Salvar pacotes em arquivo: ")

    start_sniffer(interface, count, protocol, output_file if output_file else None)

if __name__ == "__main__":
    menu()

