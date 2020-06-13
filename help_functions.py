from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from datetime import datetime


"""I didn't comment here, the functions' names are self explaining."""


def print_packet_length(pkt):
    print("packet length: " + str(len(pkt)))


def print_packet_arrival_time(pkt):
    dt = str(datetime.fromtimestamp(pkt.time)).split()[1]  # .time is in timestamp format
    print("arrival time: " + dt)


def print_packet_src_socket(pkt):
    sport = "UNKNOWN"
    if TCP in pkt:
        sport = str(pkt[TCP].sport)
    if UDP in pkt:
        sport = str(pkt[UDP].sport)
    print("source port: " + sport)


def print_packet_src_ip(pkt):
    msg = "IP: "
    if IP in pkt:
        msg += pkt[IP].src
    else:
        msg += "not an IP packet."
    print(msg)


def print_all_packet_info(pkt):
    pkt.show()
