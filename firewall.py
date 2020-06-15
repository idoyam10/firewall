from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import *
import pcap
import help_functions
from log_helpers import *
import pathlib
from rule import *
from man_in_middle import *

man_in_middle_flag = False  # if True, run man in middle

command_flags = {}
"""after initialize_flags_from_user(), command_flags element will be: 
key: command number; value: True if execute this command on packets, else False;"""

ip_white_black_list = []  # list of ips for executing commands on packets.
is_white_list = False  # determines if ip_white_black_list is black or white list.

# All available commands:
# each element: key: number; value: tuple of (description, function);
command_dic = {1: ("packet length", getattr(help_functions, "print_packet_length")),
               2: ("time of arrival", getattr(help_functions, "print_packet_arrival_time")),
               3: ("src port", getattr(help_functions, "print_packet_src_socket")),
               4: ("source IP", getattr(help_functions, "print_packet_src_ip")),
               5: ("all packet info", getattr(help_functions, "print_all_packet_info"))
               }


def main():
    welcome_msg()

    write_to_log("Run ended.")
    write_new_run_log()
    initialize_flags_from_user()
    filt = get_all_filters()
    print("filtering by: " + filt)

    print("starting to sniff...")
    while True:
        sniff(count=1, filter=filt, prn=handle_packet)


def handle_packet(pkt):
    """gets a sniffed packet, acts by the black or white list,
    reports to log if needed,
    calls to command execution on each packet"""

    act_by_rule(pkt)

    if man_in_middle_flag:
        act_by_man_in_middle(pkt)

    if IP not in pkt:  # if not an IP protocol packet
        execute_commands(pkt)

    elif is_white_list:  # if the given list is a white list
        if pkt[IP].src in ip_white_black_list:  # if src ip of pkt in white list
            execute_commands(pkt)
        else:
            write_ip_black_white_list_to_log(pkt, True)  # if src ip of pkt not in whitelist

    else:  # if black list
        if pkt[IP].src in ip_white_black_list:  # if packet in black list
            write_ip_black_white_list_to_log(pkt, False)
        else:
            execute_commands(pkt)


# initialization functions:

def welcome_msg():
    print("welcome to my firewall \\ Man In The Middle Framework!")
    print("Made by Ido Yamner, as a Cyber project.")
    print("Enjoy!")
    print("--------------------------")


def get_all_filters():
    """returns the final filter from the man in the middle, rules and user input"""
    man_in_middle_filter = initialize_man_in_middle()
    user_filter = get_user_filters()  # gets white\black list and bpf filter
    rules_filter = handle_rules()  # get all filters from all the rules

    if rules_filter != '' and user_filter != '':  # if both filter types are not empty
        # join user and rules filters to one filter:
        user_filter = '(' + ') or ('.join([user_filter, rules_filter]) + ')'

    elif rules_filter != '' and rules_filter != '()':  # if user entered no filter and there is rules filter
        user_filter = rules_filter

    if man_in_middle_flag:  # add man in middle filter
        if user_filter != '' and user_filter != '()':  # if there is user or rules filter
            user_filter = '(' + ') or ('.join([user_filter, man_in_middle_filter]) + ')'
        else:  # man in middle filter is the only filter
            user_filter = man_in_middle_filter

    return user_filter


def initialize_man_in_middle():
    """get input from user weather or not run man in the middle
    returns the man in the middle filter"""

    global man_in_middle_flag
    flag = input("run as firewall? " + " y/n : ")
    print("--------------------------")
    if flag == "y":
        man_in_middle_flag = True
        return get_man_in_middle_filter()
    return ''


def initialize_flags_from_user():
    """gets information from user about which commands to execute for each packet sniffed.
    info saved in command_flags (dictionary)."""

    for cmd in command_dic.keys():
        flag = input("track " + command_dic[cmd][0] + "? y/n : ")
        if flag == 'y':
            command_flags[cmd] = True
    print("-----------------------")


def get_user_filters():
    """gets from the user an ip list, whether its a black or white list, and returns users' BPF filter"""

    initialize_ip_whitelist()
    # print(ip_white_black_list)
    if not is_white_list:
        initialize_ip_blacklist()
    bpf_input = input("enter BPF filter")
    print("--------------------------")
    return bpf_input


def initialize_ip_whitelist():
    """gets ip whitelist from user. enter leaves it empty."""

    global ip_white_black_list
    global is_white_list
    user_ls = input("enter whitelist of IPs (separated with ','). ENTER to keep empty.").split(',')
    if user_ls != ['']:  # if entered a whitelist
        ip_white_black_list = user_ls
        is_white_list = True


def initialize_ip_blacklist():
    """gets ip blacklist from user. enter leaves it empty."""

    global ip_white_black_list
    ip_white_black_list += input("enter blacklist of IPs (separated with ',')").split(',')
    # print(ip_white_black_list)


# end of initialization functions.


# rules related functions:


def handle_rules():
    """getting new rules from user
    return a joined BPF filter made of all the rules"""
    Rule.config_into_rules()
    create_new_rules()
    return Rule.load_rules()


def create_new_rules():
    """gets new rule from the user. when finished, calls the function again, until '-c' is entered"""

    print("available commands:")
    for key in command_dic.keys():  # prints available commands
        print(str(key) + ": " + command_dic[key][0])
    print("to close, type: -c")
    rule = input("enter rule in format: Capture_filter//'B'[or]'W'(black or white list)//0.0.0.0,127.0.0.1//command")

    if rule != "-c":

        if Rule.check_rule(rule):  # if the rule in the correct format
            Rule(rule, True)  # create the rule and add to config file
        else:
            print("invalid rule format.")
            create_new_rules()


def act_by_rule(pkt):
    """acts by the command of the rules."""
    for rule in Rule.rules_ls:  # all rules available.
        sniffed = sniff(count=1, offline=pkt, filter=rule.filter)
        for pk in sniffed:
            if rule.is_white and IP in pk and pk[IP].src in rule.ip_list:  # if white and src ip in it
                special_rules_passed(pk, rule)
            elif not rule.is_white and IP in pkt and pkt[IP].src not in rule.ip_list:  # if black and src ip not in it
                special_rules_passed(pk, rule)
            elif IP not in pk:
                special_rules_passed(pk, rule)
            else:
                print("writing to log")
                write_ip_black_white_list_to_log(pk, is_white_list)


def special_rules_passed(pkt, rule):
    print("special rule passed:")
    if IP in pkt:
        if rule.is_white:
            if pkt[IP].src in rule.ip_list:
                execute_one_command(pkt, rule.command)
            else:
                print("ip not in whitelist")
        else:  # if black list
            if pkt[IP].src not in rule.ip_list:
                execute_one_command(pkt, rule.command)
            else:
                print("ip in blacklist")
    else:  # if there is no ip in the packet
        execute_one_command(pkt, rule.command)


def execute_commands(pkt):
    """runs commands (as defined at the beginning) on the given packet."""

    for cmd in command_flags.keys():
        if command_flags[cmd]:
            execute_one_command(pkt, cmd)
    print("--------------------------")


def execute_one_command(pkt, cmd):
    command_dic[cmd][1](pkt)


# end of rule related functions.
def act_by_man_in_middle(pkt):
    """checking if pkt came from the target
     if its a dns request: returning custom response,
     else: forward pkt to destination"""

    pk = sniff(count=1, offline=pkt, filter=get_man_in_middle_filter())
    if pk:
        pk = pk[0]  # sniff returns a list, count=1 so only 1 pkt sniffed
        print("found packet from man in the middle target:")

        act_by_rule(pk)

        # pk.show()  # print pkt
        if DNS in pk:  # if found a query pkt unanswered
            print("DNS query found, sending custom response.")
            for i in range(4):
                send_custom_dns_response(pk)
        # else:
        #    forward_pkt_to_server(pk)
        # pk = sniff(count=1, offline=pkt, filter=get_man_in_middle_answer_filter())


if __name__ == "__main__":
    main()
