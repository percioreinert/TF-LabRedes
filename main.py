import socket
import struct
import csv
from datetime import datetime

# Constantes de protocolo
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# Nomes dos arquivos CSV
CAMADA2_CSV = "camada2.csv"
CAMADA3_CSV = "camada3.csv"
CAMADA4_CSV = "camada4.csv"


def mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)


def eth_protocol_name(proto):
    names = {
        0x0800: "IPv4",
        0x86DD: "IPv6",
        0x0806: "ARP",
    }
    return names.get(proto, f"0x{proto:04x}")


def init_csvs():
    with open(CAMADA2_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "mac_origem", "mac_destino", "ether_type", "tamanho_quadro_bytes"])

    with open(CAMADA3_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "protocolo_rede", "ip_origem", "ip_destino", "protocolo_transporte_num",
                         "tamanho_pacote_bytes"])

    with open(CAMADA4_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(
            ["timestamp", "protocolo_transporte", "ip_origem", "porta_origem", "ip_destino", "porta_destino",
             "tamanho_segmento_bytes"])


# Contadores de pacotes
ipv4_counter = 0
ipv6_counter = 0
eth_counter = 0
tcp_counter = 0
udp_counter = 0
arp_counter = 0
ICMP_counter = 0
ICMPv6_counter = 0


def parse_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Ethernet (Camada 2)
    eth_header = packet[:14]
    if len(eth_header) < 14:
        return

    global eth_counter
    eth_counter += 1
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", eth_header)
    ether_type = f"0x{proto:04x} - {eth_protocol_name(proto)}"
    tamanho_quadro = len(packet)

    with open(CAMADA2_CSV, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp,
            mac_addr(src_mac),
            mac_addr(dest_mac),
            ether_type,
            tamanho_quadro
        ])

    if proto == 0x0800:  # IPv4
        global ipv4_counter
        ipv4_counter += 1
        ip_header = packet[14:34]
        if len(ip_header) < 20:
            return

        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        protocolo_transporte = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        total_length = iph[2]

        with open(CAMADA3_CSV, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                "IPv4",
                src_ip,
                dest_ip,
                protocolo_transporte,
                total_length
            ])

        global tcp_counter, udp_counter, ICMP_counter
        start = 14 + ((iph[0] & 0x0F) * 4)
        if protocolo_transporte == IPPROTO_TCP:
            protocolo_nome = "TCP"
            tcp_counter += 1
            src_port, dest_port = struct.unpack("!HH", packet[start:start + 4])
            with open(CAMADA4_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    protocolo_nome,
                    src_ip,
                    src_port,
                    dest_ip,
                    dest_port,
                    total_length
                ])
        elif protocolo_transporte == IPPROTO_UDP:
            protocolo_nome = "UDP"
            udp_counter += 1
            src_port, dest_port = struct.unpack("!HH", packet[start:start + 4])
            with open(CAMADA4_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    protocolo_nome,
                    src_ip,
                    src_port,
                    dest_ip,
                    dest_port,
                    total_length
                ])
        elif protocolo_transporte == 1:  # ICMP
            ICMP_counter += 1
            protocolo_nome = "ICMP"
            with open(CAMADA4_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    protocolo_nome,
                    src_ip,
                    "-",
                    dest_ip,
                    "-",
                    total_length
                ])

    elif proto == 0x86DD:  # IPv6
        global ipv6_counter, ICMPv6_counter
        ipv6_counter += 1
        ip_header = packet[14:54]
        if len(ip_header) < 40:
            return

        iph = struct.unpack("!IHBB16s16s", ip_header)
        payload_length = iph[1]
        protocolo_transporte = iph[2]
        src_ip = socket.inet_ntop(socket.AF_INET6, iph[4])
        dest_ip = socket.inet_ntop(socket.AF_INET6, iph[5])
        total_length = payload_length + 40

        with open(CAMADA3_CSV, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                "IPv6",
                src_ip,
                dest_ip,
                protocolo_transporte,
                total_length
            ])

        start = 14 + 40
        if protocolo_transporte in [IPPROTO_TCP, IPPROTO_UDP] and len(packet) >= start + 4:
            src_port, dest_port = struct.unpack("!HH", packet[start:start + 4])
            protocolo_nome = "TCP" if protocolo_transporte == IPPROTO_TCP else "UDP"
            with open(CAMADA4_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    protocolo_nome,
                    src_ip,
                    src_port,
                    dest_ip,
                    dest_port,
                    total_length
                ])
        elif protocolo_transporte == 58:  # ICMPv6
            ICMPv6_counter += 1
            protocolo_nome = "ICMPv6"
            with open(CAMADA4_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    protocolo_nome,
                    src_ip,
                    "-",
                    dest_ip,
                    "-",
                    total_length
                ])

    elif proto == 0x0806:  # ARP
        global arp_counter
        arp_counter += 1
        arp_header = packet[14:42]
        if len(arp_header) < 28:
            return
        htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = struct.unpack("!HHBBH6s4s6s4s", arp_header)
        src_ip = socket.inet_ntoa(spa)
        dest_ip = socket.inet_ntoa(tpa)
        with open(CAMADA3_CSV, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                "ARP",
                src_ip,
                dest_ip,
                "-",
                len(packet)
            ])


def main():
    global eth_counter
    global ipv4_counter
    global ipv6_counter
    global tcp_counter
    global udp_counter
    global arp_counter
    global ICMP_counter
    global ICMPv6_counter

    init_csvs()
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        while True:
            print(f"🔍 {eth_counter} pacotes Ethernet capturados.")
            print(f"🔍 {ipv4_counter} pacotes IPv4 capturados.")
            print(f"🔍 {ipv6_counter} pacotes IPv6 capturados.")
            print(f"🔍 {tcp_counter} pacotes TCP capturados.")
            print(f"🔍 {udp_counter} pacotes UDP capturados.")
            print(f"🔍 {arp_counter} pacotes ARP capturados.")
            print(f"🔍 {ICMP_counter} pacotes ICMP capturados.")
            print(f"🔍 {ICMPv6_counter} pacotes ICMPv6 capturados.")
            print(f"Pressione Ctrl+C para encerrar.")
            raw_data, addr = conn.recvfrom(65535)
            parse_packet(raw_data)
    except PermissionError:
        print("❌ Permissão negada: execute com sudo.")
    except KeyboardInterrupt:
        print("\n📥 Captura encerrada.")


if __name__ == "__main__":
    main()
