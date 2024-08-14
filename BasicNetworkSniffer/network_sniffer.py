from scapy.all import sniff, IP, TCP, UDP, ARP
import logging

#SETTING THE LOG
logging.basicConfig(filename='network_sniffer.log', 
level= logging.INFO, format='%(asctime)s - %(message)s')

def packet_callback(packet):
    """This is the callback function to process captured packets"""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_proto = packet[IP].proto
        if TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            logging.info(f'IP Packet: {ip_src} -> {ip_dst} | TCP {tcp_src_port} -> {tcp_dst_port}')
        elif UDP in packet:
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            logging.info(f'IP Packet: {ip_src} -> {ip_dst} | UDP {udp_src_port} -> {udp_dst_port}')
        else:
            logging.info(f'IP Packet: {ip_src} -> {ip_dst} \ Protocol: {ip_proto}')
    elif ARP in packet:
        arp_src_ip = packet[ARP].psrc
        arp_dst_ip = packet[ARP].pdst
        arp_op = packet[ARP].op
        logging.info(f"ARP Packet: {arp_src_ip} -> {arp_dst_ip} | Operation: {'Request' if arp_op == 1 else 'Reply'}")
    else:
        logging.info(f'Other Packet: {packet.summary()}')

def start_sniffer(interface):
    """Starting the nSniffer on the specified interface"""
    print(f'Starting network sniffer on interface: {interface}')
    sniff(iface=interface, prn = packet_callback, store = 0)

if __name__ == "__main__":
    network_interface = 'Wi-Fi' #this is my systems network_interface
    start_sniffer(network_interface)

