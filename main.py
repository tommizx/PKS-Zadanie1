import scapy.all
from ruamel.yaml import YAML
import binascii


def get_destination_address(current_packet):
    initial_destination_address = current_packet[:12].upper()
    final_destination_address = ""

    # insert a character after every pair of characters,
    # from https://www.geeksforgeeks.org/python-insert-character-after-every-character-pair/
    for i in range(0, len(initial_destination_address), 2):
        final_destination_address += initial_destination_address[i:i + 2] + ":"

    final_destination_address = final_destination_address[:-1]
    return final_destination_address


def get_source_address(current_packet):
    initial_source_address = current_packet[12:24].upper()
    final_source_address = ""

    # insert a character after every pair of characters,
    # from https://www.geeksforgeeks.org/python-insert-character-after-every-character-pair/
    for i in range(0, len(initial_source_address), 2):
        final_source_address += initial_source_address[i:i + 2] + ":"

    final_source_address = final_source_address[:-1]
    return final_source_address


def get_pcap_length(pretty_packet):
    return len(pretty_packet)


def get_medium_length(pcap_length):
    if pcap_length > 59:
        medium_length = pcap_length + 4
    else:
        medium_length = 64
    return medium_length


def get_hexa_frame(pretty_packet):
    initial_packet = pretty_packet.upper()
    hexa_packet = ""

    # insert a character after every pair of characters,
    # from https://www.geeksforgeeks.org/python-insert-character-after-every-character-pair/
    for i in range(0, len(initial_packet), 2):
        hexa_packet += initial_packet[i:i + 2] + " "
    hexa_packet = hexa_packet[:-1]
    return hexa_packet


def analyze_packets():
    packet_list = scapy.all.rdpcap("test.pcap")
    current_packet_number = 0
    packet = packet_list[current_packet_number]
    pretty_packet = binascii.hexlify(scapy.all.raw(packet)).decode()

    current_data_list = [
        ('1_order', current_packet_number + 1),
        ('2_pcap_length', get_pcap_length(pretty_packet)),
        ('3_medium_length', get_medium_length(get_pcap_length(pretty_packet))),
        ('3_protocol', "coming soon"),
        ('4_source_mac', get_source_address(pretty_packet)),
        ('5_destination_mac', get_destination_address(pretty_packet)),
        ('6_bytes', get_hexa_frame(pretty_packet))
    ]
    current_data = dict(current_data_list)

    with open("output.yaml", "w") as file:
        yaml = YAML()
        yaml.dump(current_data, file)


analyze_packets()
