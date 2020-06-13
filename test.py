from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.l2 import *
import pcap
import netifaces
import socket
import psutil
from rule import *

# sniff(count=3, iface=list(psutil.net_if_addrs().keys())[2],  prn=lambda pkt: pkt.show())
# print(socket.if_nametoindex(netifaces.interfaces()[0]))
# print(list(psutil.net_if_addrs().keys())[0])

target_ip = "10.0.0.11"
server_ip = "10.0.0.7"
# arpcachepoison("10.0.0.11", ("8.8.8.8", "2C-56-DC-4C-F8-60"))

st = "(dst host {}) and (src host {})".format(server_ip, target_ip)
print(st)
