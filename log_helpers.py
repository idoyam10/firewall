from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.dns import DNS
from scapy.layers.l2 import *
import pathlib

LOG_FILE_PATH = str(pathlib.Path(__file__).parent.absolute()) + "\\Text files\\log.txt"

"""help functions to edit the log file."""


def write_ip_black_white_list_to_log(pkt, is_white):
    print("packet unmatching to black\\white list. writing to log")
    # print("black listing a packet from " + pkt[IP].src)
    msg = str(datetime.fromtimestamp(pkt.time)).split()[1] + \
        ": Packet from %s was ignored " % pkt[IP].src
    if is_white:
        msg += "(not in whitelist).\n"
    else:
        msg += "(in IP blacklist).\n"
    write_to_log(msg)


def write_to_log(msg):
    log = open(LOG_FILE_PATH, 'a')
    log.write(msg)
    log.close()


def clear_log():
    open(LOG_FILE_PATH, 'w').close()


def write_new_run_log():
    msg = "\r\n" + datetime.now().strftime("%H:%M:%S") + ": new run started.\n"
    write_to_log(msg)
