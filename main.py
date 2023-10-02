import sys
import re
import scapy.all
from ruamel.yaml import YAML
import binascii
def analyzePackets():
    packetList = scapy.all.rdpcap("test.pcap")

    packetOrder = 0

    for packet in packetList:
        prettyPacket = binascii.hexlify(scapy.all.raw(packet)).decode()

        packetOrder = packetOrder + 1
        print(prettyPacket)

    with open("output.yaml","w") as file:
        yaml = YAML()
        yaml.dump(prettyPacket,file)


analyzePackets()