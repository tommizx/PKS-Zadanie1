import ruamel.yaml.scalarstring
import scapy.all
from ruamel.yaml import YAML
import binascii


def get_destination_address(current_packet):
    initial_destination_address = current_packet[:12]
    final_destination_address = ""

    # insert a character after every pair of characters,
    # from https://www.geeksforgeeks.org/python-insert-character-after-every-character-pair/
    for i in range(0, len(initial_destination_address), 2):
        final_destination_address += initial_destination_address[i:i + 2] + ":"

    final_destination_address = final_destination_address[:-1]
    return final_destination_address


def get_source_address(current_packet):
    initial_source_address = current_packet[12:24]
    final_source_address = ""

    # insert a character after every pair of characters,
    # from https://www.geeksforgeeks.org/python-insert-character-after-every-character-pair/
    for i in range(0, len(initial_source_address), 2):
        final_source_address += initial_source_address[i:i + 2] + ":"

    final_source_address = final_source_address[:-1]
    return final_source_address


def get_pcap_length(pretty_packet):

    return int(len(pretty_packet)/2)


def get_medium_length(pcap_length):
    if pcap_length > 59:
        medium_length = pcap_length + 4
    else:
        medium_length = 64
    return medium_length


def get_hexa_frame(pretty_packet):
    initial_packet = pretty_packet
    hexa_packet = ""

    # insert a character after every pair of characters,
    # from https://www.geeksforgeeks.org/python-insert-character-after-every-character-pair/
    for i in range(0, len(initial_packet), 2):
        hexa_packet += initial_packet[i:i + 2] + " "
    hexa_packet = hexa_packet[:-1]

    counter = 0
    for i in range(len(hexa_packet)):
        if hexa_packet[i] == ' ':
            counter = counter + 1
            if counter % 16 == 0 and counter != 0:
                temp_list = list(hexa_packet)
                temp_list[i] = '\n'
                hexa_packet = ''.join(temp_list)

    hexa_packet = ruamel.yaml.scalarstring.LiteralScalarString(hexa_packet)

    return hexa_packet


def get_frame_type(pretty_packet):
    frame_type_hex = pretty_packet[24:28]
    frame_type_decimal = int(frame_type_hex, 16)

    if frame_type_decimal > 1500:
        frame_type = "ETHERNET II"
    elif frame_type_hex == "FFFF":
        frame_type = "Novell 802.3 RAW"
    elif frame_type_hex == "AAAA":
        frame_type = "IEEE 802.3 LLC + SNAP"
    else:
        frame_type = "IEEE 802.3 LLC"

    return frame_type


def get_sap(pretty_packet):
    sap_bytes = pretty_packet[28:32]
    if sap_bytes == "4242":
        return "STP"
    elif sap_bytes == "F0F0":
        return "NETBIOS"
    elif sap_bytes == "E0E0":
        return "IPX"
    else:
        return "Unknown"


def get_pid(pretty_packet):
    pid_bytes = pretty_packet[28:32]
    if pid_bytes == "089B":
        return "AppleTalk"
    elif pid_bytes == "2000":
        return "CDP"
    elif pid_bytes == "2004":
        return "DTP"
    elif pid_bytes == "010B":
        return "PVSTP+"
    else:
        return "Unknown"


def analyze_packets():
    packet_list = scapy.all.rdpcap("test_pcap_files/vzorky_pcap_na_analyzu/eth-1.pcap")

    packets = []

    for current_packet_number in range(0, len(packet_list)):
        packet = packet_list[current_packet_number]
        pretty_packet = binascii.hexlify(scapy.all.raw(packet)).decode()
        pretty_packet = pretty_packet.upper()
        current_packet_data = [
            ('frame_number', current_packet_number + 1),
            ('pcap_length', get_pcap_length(pretty_packet)),
            ('medium_length', get_medium_length(get_pcap_length(pretty_packet))),
            ('frame_type',  get_frame_type(pretty_packet)),
            ('source_mac', get_source_address(pretty_packet)),
            ('destination_mac', get_destination_address(pretty_packet)),
            ('sap', get_sap(pretty_packet)),
            ('pid', get_pid(pretty_packet)),
            ('hexa_frame', get_hexa_frame(pretty_packet))
        ]

        current_data = dict(current_packet_data)
        packets.append(current_data)

    with open("output.yaml", "w") as file:
        yaml = YAML()
        yaml.dump(packets, file)
    print("\nDone, check output.yaml")


analyze_packets()
