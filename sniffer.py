import time
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from utils import format_payload

class PacketSniffer:
    def __init__(self, packet_queue):
        self.packet_queue = packet_queue
        self.sniffing = False

    def analyze_packet(self, packet):
        protocols_map = {
            1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6"
        }

        capture_time = time.strftime("%H:%M:%S")
        src_ip = dst_ip = protocol = payload = ""
        s_port = d_port = "-"
        length = len(packet)

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto

            if packet.haslayer(TCP):
                s_port = packet[TCP].sport
                d_port = packet[TCP].dport
                protocol = "TCP"
            elif packet.haslayer(UDP):
                s_port = packet[UDP].sport
                d_port = packet[UDP].dport
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            elif packet.haslayer(DNS):
                protocol = "DNS"
                try:
                    dns_layer = packet[DNS]
                    if dns_layer.qr == 0:
                        payload = f"Query: {dns_layer.qd.qname.decode()}"
                    elif dns_layer.qr == 1:
                        if dns_layer.an:
                            answer = dns_layer.an.rdata
                            payload = f"Response: {dns_layer.qd.qname.decode()} → {answer}"
                        else:
                            payload = "No DNS Answer"
                except:
                    payload = "DNS Packet"
            else:
                protocol = protocols_map.get(proto, f"Unknown({proto})")

            if not payload and packet.haslayer(Raw):
                payload = format_payload(packet[Raw].load)

        elif packet.haslayer(ARP):
            src_ip = packet.psrc
            dst_ip = packet.pdst
            protocol = "ARP"
            payload = "Address Resolution"

        else:
            src_ip = dst_ip = "N/A"
            protocol = packet.name if hasattr(packet, "name") else "Unknown"
            payload = "N/A"

        self.packet_queue.put((capture_time, src_ip, dst_ip, protocol, s_port, d_port, length, payload))

    def start_sniffing(self):
        self.sniffing = True
        sniff(prn=self.packet_callback, store=False, stop_filter=self.stop_callback)

    def stop_sniffing(self):
        self.sniffing = False

    def packet_callback(self, packet):
        if self.sniffing:
            self.analyze_packet(packet)

    def stop_callback(self, packet):
        return not self.sniffing
