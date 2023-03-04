#!/usr/bin/python

import sys
from scapy.all import IP, ICMP, sr1

# Give IP when running this

if len(sys.argv) != 3:
    print("Usage: " + sys.argv[0] + " ip command_in_quotes")
    sys.exit(1)

command = sys.argv[2]
# Craft IP header

ip_packet = IP()
ip_packet.dst = sys.argv[1]
icmp_packet = ICMP()
icmp_packet.type = 8
sr1(ip_packet/icmp_packet/f"__{command};")
