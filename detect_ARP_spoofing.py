from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import threading
import datetime

IP_MAC_PAIRS = {}
ARP_REQ_TABLE = {}


def sniff_requests():
    """
    This sniffs all ARP requests (op 1, who has) the machine made on the network

    :return:
    """
    sniff(filter='arp', lfilter=outgoing_req, prn=add_req, iface=conf.iface)


def sniff_replays():
    """
    This sniffs all ARP replays (op 2, is at) the machine received from the network

    :return:
    """
    sniff(filter='arp', lfilter=incoming_reply, prn=check_arp_header, iface=conf.iface)


def print_arp(pkt):
    """
    This module prints the ARP messages for debugging purposes

    :param pkt:
    :return:
    """
    if pkt[ARP].op == 1:
        print(pkt[ARP].hwsrc, ' who has ', pkt[ARP].pdst)
    else:
        print(pkt[ARP].psrc, ' is at ', pkt[ARP].hwsrc)


def incoming_reply(pkt):
    """
    checks if the packet is an incoming ARP reply message

    :param pkt: sniffed packet
    :return: the packet is an incoming ARP reply message (True od False)
    """
    return pkt[ARP].psrc != str(get_if_addr(conf.iface)) and pkt[ARP].op == 2


def outgoing_req(pkt):
    """
    checks if the packet is an outgoing ARP request message

    :param pkt: sniffed packet
    :return: the packet is an incoming ARP reply message (True od False)
    """
    return pkt[ARP].psrc == str(get_if_addr(conf.iface)) and pkt[ARP].op == 1


def add_req(pkt):
    """
    This module adds ARP requests made by the machine to the "arp_req table"

    :param pkt:
    :return:
    """
    ARP_REQ_TABLE[pkt[ARP].pdst] = datetime.datetime.now()


def check_arp_header(pkt):
    """
    MAC - ARP header anomaly detector module: This module classifies the ARP traffic into Inconsistent Header ARP
    packets and Consistent Header ARP packets.

    :return:
    """
    if not pkt[Ether].src == pkt[ARP].hwsrc or not pkt[Ether].dst == pkt[ARP].hwdst:
        return alarm('inconsistent ARP message')
    return known_traffic(pkt)


def known_traffic(pkt):
    """
    Known Traffic Filter module: This filters all the traffic, which is already learnt. It will either drop the 
    packet if the Ip to MAC mapping is coherent with the learnt Host Database or raise an alarm if there are any 
    contradictions. All the new ARP packets with unknown addresses are sent to the Spoof Detection Engine for 
    verification. 
    
    :param pkt: 
    :return: 
    """
    # If the packet's ip source not in the safe pairs table, check if the ARP message genuine
    if pkt[ARP].psrc not in IP_MAC_PAIRS.keys():
        return spoof_detection(pkt)
    # If the packet's ip source is in the safe pairs table, it is a genuine ARP message
    elif IP_MAC_PAIRS[pkt[ARP].psrc] == pkt[ARP].hwsrc:
        return
    # If the packet's ip source is in the safe pairs table, but the MAC address doesn't match, raise an alarm
    return alarm('IP-MAC pair change detected')


def spoof_detection(pkt):
    """
    Spoof Detection Engine module: This is the main detection engine.

    :param pkt:
    :return:
    """
    ip_ = pkt[ARP].psrc
    t = datetime.datetime.now()
    mac = pkt[0][ARP].hwsrc
    # If the reply is an answer for an ARP request message, i.e. Full Cycle, check if the source is genuine by
    # sending a TCP SYN
    if ip_ in ARP_REQ_TABLE.keys() and (t - ARP_REQ_TABLE[ip_]).total_seconds() <= 5:
        ip = IP(dst=ip_)
        SYN = TCP(sport=40508, dport=40508, flags="S", seq=12345)
        E = Ether(dst=mac)
        # If we don't receive a TCP ACK, we raise an alarm message
        if not srp1(E / ip / SYN, verbose=False, timeout=2):
            alarm('No TCP ACK, fake IP-MAC pair')
        # If we receive a TCP ACK, we add the ip and mac pair to our IP_MAC_PAIRS table
        else:
            IP_MAC_PAIRS[ip_] = pkt[ARP].hwsrc
    # If the message is an ARP reply without an ARP request message, i.e. Half Cycle, send an ARP request for the IP
    # of the source, thus causing the real owner of the IP on the network respond with an ARP reply so we can treat
    # it as a Full Cycle.
    else:
        send(ARP(op=1, pdst=ip_), verbose=False)


def alarm(alarm_type):
    """
    This module raises an alarm on detection of ARP spoofing

    :return:
    """
    print('Under Attack ', alarm_type)


if __name__ == "__main__":
    req_ = threading.Thread(target=sniff_requests, args=())
    req_.start()
    rep_ = threading.Thread(target=sniff_replays, args=())
    rep_.start()
