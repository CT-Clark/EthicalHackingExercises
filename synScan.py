'''
Performs a SYN scan on target IP address and then displays open ports
(Ports tyhat respond to a TCP SYN packet with a SYN ACK)
'''

from scapy.all import IP, ICMP, TCP, sr1, sr
import sys

# Send out an icmp packet to check if the target is online
def icmp_probe(ip):
    icmp_packet = IP(dst=ip)/ICMP()
    resp_packet = sr1(icmp_packet, timeout=10)
    return resp_packet != None

# Send out TCP SYN packets to see if the port is open
def syn_scan(ip, port):
    syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
    resp_packet = sr1(syn_packet, verbose = 0)
    if resp_packet != None:
        if resp_packet.getlayer('TCP').flags == 0x12: # Response flag set to "SA - SYN ACK"
            return resp_packet
    else:
        # Port is probably not online
        return None

if __name__ == "__main__":
    ip = sys.argv[1]
    if icmp_probe(ip):
        # If target is online scan ports for SYTN, ACK responses
        for port in range(0, 65536):
            syn_ack_packet = syn_scan(ip, port)
            if syn_ack_packet != None:
                print(syn_ack_packet.getlayer("TCP").sport)
    else:
        print("ICMP Probe Failed")