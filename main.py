import sys
import re
from scapy.all import *

packetList = rdpcap("test.pcap")

packet = packetList[1]

print(packet)

print( hexdump(packet) )