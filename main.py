import socket
import struct
from datetime import datetime

# Protocol numbers (from IP protocol numbers)
IPPROTO_TCP = 6
IPPROTO_UDP = 17

def eth_protocol_name(proto):
    if proto == 0x0800:
        return "IPv4"
    elif proto == 0x86DD:
        return "IPv6"
    elif proto == 0x0806:
        return "ARP"
    else:
        return f"Unknown (0x{proto:04x})"

def parse_packet(packet):
    protocols = []

    # Timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    # Ethernet header (first 14 bytes)
    eth_header = packet[:14]
    eth = struct.unpack("!6s6sH", eth_header)
    eth_proto = eth[2]
    protocols.append("Ethernet")

    proto_name = eth_protocol_name(eth_proto)
    protocols.append(proto_name)

    # If IPv4
    if eth_proto == 0x0800:
        ip_header = packet[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        protocol_num = iph[6]

        if protocol_num == IPPROTO_TCP:
            protocols.append("TCP")
        elif protocol_num == IPPROTO_UDP:
            protocols.append("UDP")

    print(f"[{timestamp}] {' -> '.join(protocols)}")

def main():
    try:
        # Create raw socket (Ethernet-level, receive all protocols)
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        print("Listening for packets... Press Ctrl+C to stop.")
        while True:
            raw_data, addr = conn.recvfrom(65535)
            parse_packet(raw_data)
    except PermissionError:
        print("❌ Error: Run this script with root privileges (e.g., sudo).")
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
