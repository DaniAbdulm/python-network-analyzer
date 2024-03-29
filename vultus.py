from scapy.all import sniff, wrpcap
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
import argparse
import time
from colorama import Fore, Style, init
from collections import Counter

#initialize colorama 
init(autoreset=True)

def main(): 
    parser = argparse.ArgumentParser(description= Fore.LIGHTYELLOW_EX + 'Vultus Network Analyser 1.1.0')  

    #Adding arguments 
    #packet capture 
    parser.add_argument('-c', '--capture', help='Capture packets on the network', action='store_true')
    parser.add_argument('-n', '--num_packets', type=int, default=10, help='Number of packets to capture (default: 10)')
    #file saving
    parser.add_argument('--save', type=str, help='Save the captured packets to a PCAP file')
    parser.add_argument('--load', type=str, help='Load and analyse packets from a PCAP file')
    #analysis arguments
    parser.add_argument('-ap', '--analyse-protocol', action='store_true', help='Analyse the distribution of protocols')
    parser.add_argument('-att', '--analyse-top-talkers', action='store_true', help='Identify the top talkers')
    parser.add_argument('-ab', '--analyse_bandwidth_usage', action='store_true', help='Analyse the bandwidth usage')
    parser.add_argument('--duration', type=int, default=10, help='Duration of capture for bandwidth/connection analysis in seconds (default: 10s)')
    parser.add_argument('--interval', type=int, default=1, help='Interval for bandwidth calculation in seconds (default: 1s)')
    parser.add_argument('-ac', '--analyse_connections', action='store_true', help='Analyse connection frequencies')
    #device discovery
    parser.add_argument('-d', '--discover', help='Discover devices on the network', action='store_true')
    #scanning ports
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
            print(Fore.RED + "No packets loaded for analysis.")
    
    if args.analyse_top_talkers:
        if packets is not None:
            analyse_top_talkers(packets)
        else:
            print(Fore.RED + "No packets loaded for analysis.")
    
    if args.analyse_bandwidth_usage:
            analyse_bandwidth_usage(file_name=args.load, capture_duration=args.duration, interval=args.interval)

    if args.analyse_connections:
        analyse_connection_frequency(file_name=args.load, capture_duration=args.duration)

    if args.discover:
        #Call device discover analyses function
        print("Discovering devices...")

    if args.portscan:
        #Call port scanning function with the provided IP address
        print("Scanning ports on IP...")

#function to capture packets
def capture_packets(file_name="captured_packets.pcap", count=10):
    print(f"{Fore.LIGHTBLACK_EX}Capturing {count} packets...")

    #capture packets
    packets = sniff(count=count)

    #print summary of each packet
    for packet in packets: 
        print(Fore.GREEN + packet.summary())

    wrpcap(file_name, packets)
    print(f"{Fore.LIGHTYELLOW_EX}Captured packets saved to {file_name}")

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
    print(Fore.LIGHTYELLOW_EX + "Protocol Distribution:")
    for protocol, count in distribution.items(): 
        print(f"{Fore.GREEN}{protocol}: {count}")

#function to identify top talkers 
def analyse_top_talkers(packets): 
    ips = [packet['IP'].src for packet in packets if packet.haslayer("IP")]
    top_talkers = Counter(ips).most_common(5)
    print(Fore.LIGHTYELLOW_EX + "Top Talkers:")
    for ip, count in top_talkers:
        print(f"{Fore.GREEN}{ip}: {count}")

def analyse_bandwidth_usage(file_name=None, capture_duration=10, interval=1): 
    if file_name: 
        print(f"{Fore.LIGHTBLACK_EX}Bandwidth analysis from {file_name}:")
        packets = rdpcap(file_name)
    else:
        print(f"{Fore.LIGHTBLACK_EX}Capturing packets for {capture_duration}s...")
        packets = sniff(timeout=capture_duration)

    start_time = time.time()
    bytes_per_interval = []
    current_interval_bytes = 0
    current_interval_start = start_time

    for packet in packets: 
        if file_name: 
            #if reading from a file, get the timestamp from the pcap header
            packet_time = packet.time
        else:
            #if sniffing live, calculatrre the time since the start of the capture
            packet_time = time.time() - start_time
        
        #checking if the packet belongs to the current interval
        if packet_time < current_interval_start + interval:
            current_interval_bytes += len(packet)
        else:
            #if no, finalize the current interval and start a new one
            while packet_time >= current_interval_start + interval:
                bytes_per_interval.append((current_interval_start, current_interval_bytes))
                current_interval_start += interval
                current_interval_bytes = 0
            current_interval_bytes += len(packet)

    #adding the last interval
    bytes_per_interval.append((current_interval_start, current_interval_bytes))

    #printing out the bandwidth usage
    print(Fore.LIGHTYELLOW_EX + "Bandwidth usage (bytes per interval):")
    for interval_start, bytes_count in bytes_per_interval:
        print(f"{Fore.GREEN}Time: {interval_start - start_time:.2f}s, Bytes: {bytes_count}")

def analyse_connection_frequency(file_name=None, capture_duration=10): 
    #capture packets
    if file_name: 
        packets = rdpcap(file_name)
    else: 
        print(f"{Fore.LIGHTBLACK_EX}Analysing connection frequencies for {capture_duration}s...")
        packets = sniff(timeout=capture_duration)

    #dictionary that hold connection frequency 
    connections = Counter()

    #analyse packets
    for packet in packets: 
        if packet.haslayer(IP): 
            if packet.haslayer(TCP) or packet.haslayer(UDP): 
                #extract packet info base on the transport layer protocol
                transport_layer = packet[UDP] if packet.haslayer(UDP) else packet[TCP]
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = transport_layer.sport
                dst_port = transport_layer.dport 
                protocol = 'UDP' if packet.haslayer(UDP) else 'TCP'

                #creating a tuple that represents the connection
                connection = (src_ip, dst_ip, src_port, dst_port, protocol)

                #increment the count for this connection 
                connections[connection] += 1
    
    print(Fore.LIGHTYELLOW_EX + "Connection Frequencies (src ip, dst ip, src port, dst port, protocol):")
    for connection, count in connections.items(): 
        print(f"{Fore.GREEN}{connection}: {count}")

    return connections #returning the result in case of further processing 


if __name__ == "__main__":
    main()