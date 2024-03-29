from scapy.all import sniff, wrpcap
import argparse

def main(): 
    parser = argparse.ArgumentParser(description='Network Analyzer Tool') 

    #Adding arguments 
    parser.add_argument('-c', '--capture', help='Capture packets on the network', action='store_true')
    parser.add_argument('-n', '--num_packets', type=int, default=10, help='Number of packets to capture (default: 10)')
    parser.add_argument('-a', '--analyse', help='Analyse captured packets', action='store_true')
    parser.add_argument('-d', '--discover', help='Discover devices on the network', action='store_true')
    parser.add_argument('-p', '--portscan', type=str, help='Scan ports on a specific IP address')
    args = parser.parse_args()

    if args.capture:
        #Call packet capturing function 
        capture_packets(count=args.num_packets)

    if args.analyse: 
        #Call traffic analyses function 
        print("Analysing network...")

    if args.discover:
        #Call device discover analyses function
        print("Discovering devices...")

    if args.portscan:
        #Call port scanning function with the provided IP address
        print("Scanning ports on IP...")

#function to capture packets
def capture_packets(count=10, save_to_file=False):
    print(f"Capturing {count} packets...")

    #capture packets
    packets = sniff(count=count)

    #print summary of each packet
    for packet in packets: 
        print(packet.summary())
    
    #Save to file if requested
    if save_to_file:
        filename = "captured_packets.pcap"
        wrpcap(filename, packets)
        print(f"Captured packets were save to {filename}")

if __name__ == "__main__":
    main()