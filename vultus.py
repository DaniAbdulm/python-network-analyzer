from scapy.all import sniff, wrpcap
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, ICMP
import argparse
from collections import Counter

def main(): 
    parser = argparse.ArgumentParser(description='Vultus Network Analyser 1.1.0')  

    #Adding arguments 
    parser.add_argument('-c', '--capture', help='Capture packets on the network', action='store_true')
    parser.add_argument('-n', '--num_packets', type=int, default=10, help='Number of packets to capture (default: 10)')
    parser.add_argument('--save', type=str, help='Save the captured packets to a PCAP file')
    parser.add_argument('--load', type=str, help='Load and analyse packets from a PCAP file')
    parser.add_argument('-ap', '--analyse-protocol', action='store_true', help='Analyse the distribution of protocols')
    parser.add_argument('-att', '--analyse-top-talkers', action='store_true', help='Identify the top talkers')
    parser.add_argument('-d', '--discover', help='Discover devices on the network', action='store_true')
    parser.add_argument('-p', '--portscan', type=str, help='Scan ports on a specific IP address')
    args = parser.parse_args()

    #initializing packet variable
    packets = None

    if args.capture:
        if args.save:
            capture_packets(args.save, args.num_packets)
        else:
            #analyse packets without saving them
            packets = sniff(count=args.num_packets)

    if args.load:
        packets = load_packets(args.load)

    if args.analyse_protocol: 
        if packets is not None:
            analyse_protocol_distribution(packets)
        else:
            print("No packets loaded for analysis.")
    
    if args.analyse_top_talkers:
        if packets is not None:
            analyse_top_talkers(packets)
        else:
            print("No packets loaded for analysis.")

    if args.discover:
        #Call device discover analyses function
        print("Discovering devices...")

    if args.portscan:
        #Call port scanning function with the provided IP address
        print("Scanning ports on IP...")

#function to capture packets
def capture_packets(file_name="captured_packets.pcap", count=10):
    print(f"Capturing {count} packets...")

    #capture packets
    packets = sniff(count=count)

    #print summary of each packet
    for packet in packets: 
        print(packet.summary())

    wrpcap(file_name, packets)
    print(f"Captured packets saved to {file_name}")

#function to load packet file 
def load_packets(file_name="captured_packets.pcap"):
    packets = rdpcap(file_name)
    return packets

#functions to analyse network traffic
def analyse_protocol_distribution(packets): 
    protocols = []
    for packet in packets:
        if packet.haslayer(TCP): 
            protocols.append("TCP")
        elif packet.haslayer(UDP): 
            protocols.append("UDP")
        elif packet.haslayer(ICMP):
            protocols.append("ICMP")

    distribution = Counter(protocols)
    print("Protocol Distribution:")
    for protocol, count in distribution.items(): 
        print(f"{protocol}: {count}")

#function to identify top talkers 
def analyse_top_talkers(packets): 
    ips = [packet['IP'].src for packet in packets if packet.haslayer("IP")]
    top_talkers = Counter(ips).most_common(5)
    print("Top Talkers:")
    for ip, count in top_talkers:
        print(f"{ip}: {count}")

if __name__ == "__main__":
    main()