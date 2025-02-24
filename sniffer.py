import pyfiglet
import time
import sys
import psutil
from colorama import Fore, Style
from scapy.all import sniff, Ether, IP, TCP, UDP, wrpcap

banner = pyfiglet.figlet_format("SNIFFER")
print(Fore.LIGHTGREEN_EX + banner + Style.RESET_ALL)

def typewriter_effect(text, delay=0.1):
    for char in text:
        sys.stdout.write(Fore.LIGHTGREEN_EX + char + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(delay)
    print()

typewriter_effect("Network Sniffer\n")

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
    line_color = Fore.LIGHTGREEN_EX 
    content_color = Fore.LIGHTYELLOW_EX 
    flags_color = Fore.LIGHTRED_EX

    print(f"\n{line_color}╒═[{time.strftime('%H:%M:%S')}]═{'═'*50}{Style.RESET_ALL}")
    
    if not hasattr(packet_callback, "count"):
        packet_callback.count = 0
    packet_callback.count += 1
    print(f"{line_color}│ Packet #{packet_callback.count}{Style.RESET_ALL}")

    summary = []
    if IP in packet:
        summary.append(f"{packet[IP].src} → {packet[IP].dst}")
    if TCP in packet:
        summary.append(f"TCP {packet[TCP].sport} → {packet[TCP].dport}")
    elif UDP in packet:
        summary.append(f"UDP {packet[UDP].sport} → {packet[UDP].dport}")
    
    if summary:
        print(f"{line_color}│ {' | '.join(summary)}{Style.RESET_ALL}")
    
    print(f"{line_color}╞═{'═'*60}{Style.RESET_ALL}")

    if Ether in packet:
        print(f"{content_color}├─ Ethernet Frame{Style.RESET_ALL}")
        print(f"{content_color}│  Source: {packet[Ether].src:20} Destination: {packet[Ether].dst}{Style.RESET_ALL}")

    if IP in packet:
        print(f"{content_color}├─ IP Packet{Style.RESET_ALL}")
        print(f"{content_color}│  Version: {packet[IP].version}   TTL: {packet[IP].ttl}{Style.RESET_ALL}")
        print(f"{content_color}│  Source: {packet[IP].src:20} Destination: {packet[IP].dst}{Style.RESET_ALL}")

    if TCP in packet:
        print(f"{content_color}├─ TCP Segment{Style.RESET_ALL}")
        print(f"{content_color}│  Sport: {packet[TCP].sport:<5} Dport: {packet[TCP].dport:<5}{Style.RESET_ALL}")
        print(f"{flags_color}│  Flags: {parse_tcp_flags(packet[TCP].flags)}{Style.RESET_ALL}")

    elif UDP in packet:
        print(f"{content_color}├─ UDP Datagram{Style.RESET_ALL}")
        print(f"{content_color}│  Sport: {packet[UDP].sport:<5} Dport: {packet[UDP].dport}{Style.RESET_ALL}")

    print(f"{line_color}├─ Packet Size: {len(packet)} bytes{Style.RESET_ALL}")
    print(f"{line_color}╘═{'═'*60}{Style.RESET_ALL}\n")

def parse_tcp_flags(flags):
    flag_names = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PUSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR'
    }
    return ', '.join([flag_names.get(flag, flag) for flag in str(flags)])

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

def listar_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def menu():
    interface_list = []
    count = 0
    protocol = ''
    output_file = None
    interface = None

    while True:
        print(Fore.GREEN + "[1] " + Style.RESET_ALL + "Executar", end="  ")
        print(Fore.LIGHTGREEN_EX + "[2] " + Style.RESET_ALL + "Filtrar por Interface", end="  ")
        print(Fore.LIGHTGREEN_EX + "[3] " + Style.RESET_ALL + "Limitar Pacotes", end="  ")
        print(Fore.LIGHTGREEN_EX + "[4] " + Style.RESET_ALL + "Filtrar Protocolos", end="  ")
        print(Fore.LIGHTGREEN_EX + "[5] " + Style.RESET_ALL + "Salvar Pacotes em Arquivo", end="  ")
        print(Fore.GREEN + "[6] " + Style.RESET_ALL + "Sair")

        choice = input("\n")

        if choice == '1':
            if interface:
                start_sniffer(interface, count, protocol, output_file)
            else:
                print(Fore.RED + "Selecione uma interface antes de começar!" + Style.RESET_ALL)

        elif choice == '2':
            interface_list = listar_interfaces()
            print(Fore.LIGHTGREEN_EX + "Interfaces disponíveis:" + Style.RESET_ALL)
            for idx, interface in enumerate(interface_list):
                print(Fore.LIGHTGREEN_EX + f"[{idx+1}] " + Style.RESET_ALL + f"{interface}")
            interface_choice = int(input()) - 1
            interface = interface_list[interface_choice] if 0 <= interface_choice < len(interface_list) else None
            if interface:
                print(Fore.LIGHTGREEN_EX + f"Interface selecionada: {interface}" + Style.RESET_ALL)
            else:
                print(Fore.RED + "Opção inválida!" + Style.RESET_ALL)

        elif choice == '3':
            count_input = input("Quantidade de pacotes: ")
            count = int(count_input) if count_input.strip() else 0
            print(Fore.LIGHTGREEN_EX + f"Limite de pacotes definido: {count}" + Style.RESET_ALL)

        elif choice == '4':
            protocol = input("Filtrar por protocolo (tcp/udp/icmp): ")
            print(Fore.LIGHTGREEN_EX + f"Filtro de protocolo definido: {protocol}" + Style.RESET_ALL)

        elif choice == '5':
            output_file = input("Salvar pacotes em arquivo: ")
            print(Fore.LIGHTGREEN_EX + f"Arquivo de saída definido: {output_file}" + Style.RESET_ALL)

        elif choice == '6':
            print(Fore.LIGHTGREEN_EX + "Saindo", end="", flush=True)
            for _ in range(3):  
                time.sleep(0.5)
                print(Fore.LIGHTGREEN_EX + ".", end="", flush=True)
            print(Style.RESET_ALL)
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    menu()