# Network-packet-analyzer
import logging
import argparse
from scapy.all import sniff, TCP, UDP, ICMP, IP

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Protocol mapping
protocol_map = {
    6: "TCP",
    17: "UDP",
    1: "ICMP"
}

def get_protocol_name(protocol):
    """Return the protocol name from the protocol number"""
    return protocol_map.get(protocol, "Unknown")

def packet_sniffer(packet):
    """Callback function for each packet sniffed"""
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_length = len(packet)
            protocol_name = get_protocol_name(protocol)
            logging.info(f"Source IP: {src_ip}")
            logging.info(f"Destination IP: {dst_ip}")
            logging.info(f"Protocol: {protocol_name}")
            logging.info(f"Packet Length: {packet_length}")
            logging.info("------------------------")
    except Exception as e:
        logging.error(f"Error: {e}")

def main():
    """Main function to start the packet sniffer"""
    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Interface to sniff')
    parser.add_argument('-f', '--filter', help='Filter to apply')
    parser.add_argument('-l', '--log-level', help='Logging level')
    args = parser.parse_args()
    if args.interface:
        interface = args.interface
    else:
        interface = 'eth0'
    if args.filter:
        filter = args.filter
    else:
        filter = 'ip'
    if args.log_level:
        log_level = args.log_level
    else:
        log_level = 'INFO'
    # Input validation
    if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        logging.error("Invalid log level")
        return
    logging.basicConfig(level=getattr(logging, log_level.upper()))
    sniff(prn=packet_sniffer, store=False, filter=filter, iface=interface)

if _name_ == "_main_":
    main()
