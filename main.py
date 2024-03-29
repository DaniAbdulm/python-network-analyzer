from scapy.all import sniff
import argparse

def main(): 
    parser = argparse.ArgumentParser(description='Network Analyzer Tool') 

    #Adding arguments 
    parser.add_argument('-c', '--capture', help='Capture packets on the network', action='store_true')
    parser.add_argument('-a', '--analyse', help='Analyse captured packets', action='store_true')
    parser.add_argument('-d', '--discover', help='Discover devices on the network', action='store_true')
    parser.add_argument('-p', '--portscan', type=str, help='Scan ports on a specific IP address')
    args = parser.parse_args()

    if args.capture:
        #Call packet capturing function 
        print("Capturing packets...")

    if args.analyse: 
        #Call traffic analyses function 
        print("Analysing network...")

    if args.discover:
        #Call device discover analyses function
        print("Discovering devices...")

    if args.portscan:
        #Call port scanning function with the provided IP address
        print("Scanning ports on IP...")


if __name__ == "__main__":
    main()