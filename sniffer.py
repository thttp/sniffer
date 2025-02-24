import pyfiglet
import time
import sys
import psutil
from colorama import Fore, Style
from scapy.all import sniff, Ether, IP, TCP, UDP, wrpcap

# Exibir banner
banner = pyfiglet.figlet_format("SNIFFER")
print(Fore.LIGHTGREEN_EX + banner + Style.RESET_ALL)

def typewriter_effect(text, delay=0.1):
    for char in text:
        sys.stdout.write(Fore.LIGHTGREEN_EX + char + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(delay)
    print()

typewriter_effect("Network Sniffer\n")

# Função para animação de carregamento
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

# Função para exibir informações do pacote capturado
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

# Função para iniciar o sniffer
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

# Função para listar interfaces disponíveis
def listar_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

# Menu de opções
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
            print(Fore.BLUE + "Saindo..." + Style.RESET_ALL)
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    menu()
