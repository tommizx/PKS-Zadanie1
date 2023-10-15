import ruamel.yaml.scalarstring
import scapy.all
from ruamel.yaml import YAML
import binascii


class UniqueIpSender:
    def __init__(self, ip_addr, packets_sent):
        self.ip_addr = ip_addr
        self.packets_sent = packets_sent


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
    frame_type_hex = pretty_packet[28:32]
    frame_length = int(pretty_packet[24:28], 16)

    if frame_length > 1500:
        frame_type = "ETHERNET II"
    elif frame_type_hex == "FFFF":
        frame_type = "Novell 802.3 RAW"
    elif frame_type_hex == "AAAA":
        frame_type = "IEEE 802.3 LLC & SNAP"
    else:
        frame_type = "IEEE 802.3 LLC"

    return frame_type


def get_sap(pretty_packet, protocols):
    sap_bytes = pretty_packet[28:32]

    for sap_type, sap_value in protocols["sap"].items():
        if sap_type == sap_bytes:
            return sap_value


def get_pid(pretty_packet, protocols):
    pid_bytes = pretty_packet[40:44]

    for pid_type, pid_value in protocols["pid"].items():
        if pid_type == pid_bytes:
            return pid_value


def get_ether_type(pretty_packet, protocols):
    ether_type_bytes = pretty_packet[24:28]

    for ether_type, ether_type_value in protocols["ether_type"].items():
        if ether_type == ether_type_bytes:
            return ether_type_value


def get_source_ip_address(pretty_packet):
    source_ip_bytes = []
    for i in range(0, 4):
        source_ip_bytes.append(int(pretty_packet[52+(i*2):54+(i*2)], 16))

    source_ip_address = ""
    for byte in source_ip_bytes:
        source_ip_address = source_ip_address + str(byte) + "."

    source_ip_address = source_ip_address[:-1]
    return source_ip_address


def get_destination_ip_address(pretty_packet):
    destination_ip_bytes = []
    for i in range(0, 4):
        destination_ip_bytes.append(int(pretty_packet[60+(i*2):62+(i*2)], 16))

    destination_ip_address = ""
    for byte in destination_ip_bytes:
        destination_ip_address = destination_ip_address + str(byte) + "."

    destination_ip_address = destination_ip_address[:-1]
    return destination_ip_address


def get_ipv4_protocol(pretty_packet, protocols):
    protocol_bytes = pretty_packet[46:48]

    for protocol_type, protocol_value in protocols["ipv4_protocol"].items():
        if protocol_type == protocol_bytes:
            return protocol_value


def get_src_port(pretty_packet):
    return int(pretty_packet[68:72], 16)


def get_dst_port(pretty_packet):
    return int(pretty_packet[72:76], 16)


def get_arp_opcode(pretty_packet):
    if int(pretty_packet[40:44]) == 1:
        return "REQUEST"
    else:
        return "REPLY"


def is_port_known(src_port, dst_port, protocols, ipv4_protocol):
    if ipv4_protocol == "TCP":
        for protocol_type, protocol_value in protocols["tcp_protocol"].items():
            if str(src_port) == protocol_type or str(dst_port) == protocol_type:
                return protocol_value
        return
    elif ipv4_protocol == "UDP":
        for protocol_type, protocol_value in protocols["udp_protocol"].items():
            if str(src_port) == protocol_type or str(dst_port) == protocol_type:
                return protocol_value
        return


def analyze_file(file_name):  # chata sesh
    protocols = {}
    with open(file_name, 'r') as file:
        lines = file.readlines()
        current_key = None
        for line in lines:
            if line.strip() and not line.startswith("  "):
                # This line contains a new section identifier
                current_key = line.strip()[:-1]  # Remove the trailing colon
                protocols[current_key] = {}
            elif line.startswith("  ") and current_key:
                # This line contains a mapping for the current section
                key, value = map(str.strip, line.strip().split(":"))
                protocols[current_key][key] = value
    return protocols


def analyze_packets():
    packet_list = scapy.all.rdpcap("test_pcap_files/vzorky_pcap_na_analyzu/eth-1.pcap")
    packets = []
    unique_senders = []
    protocols = analyze_file("protocols.txt")
    is_valid_filter = False
    filter_name = ""
    results_count = 0

    # print("Analyze all packets : 'a'\nFilter by protocol : 'f'\nExit program : 'x'\n")
    # program_mode = input()

    while not is_valid_filter:
        print("Enter filter name : ")
        filter_name = input()  # Get filter name

        for value in protocols["tcp_protocol"].values():  # Check if this protocol exists
            if filter_name == value:
                is_valid_filter = True
                break
        if not is_valid_filter:
            print("Not an existing protocol!")

    frame_number = 1

    for current_packet_number in range(0, len(packet_list)):
        packet = packet_list[current_packet_number]
        pretty_packet = binascii.hexlify(scapy.all.raw(packet)).decode()
        pretty_packet = pretty_packet.upper()

        current_frame_type = get_frame_type(pretty_packet)
        current_app_protocol = ""

        current_packet_data = [
            ('frame_number', frame_number),
            ('pcap_length', get_pcap_length(pretty_packet)),
            ('medium_length', get_medium_length(get_pcap_length(pretty_packet))),
            ('frame_type',  current_frame_type),
            ('source_mac', get_source_address(pretty_packet)),
            ('destination_mac', get_destination_address(pretty_packet))
        ]

        if current_frame_type == "ETHERNET II":
            current_ether_type = get_ether_type(pretty_packet, protocols)
            current_packet_data.append(('ether_type', current_ether_type))

            if current_ether_type == "IPv4":
                current_src_ip = get_source_ip_address(pretty_packet)
                current_packet_data.append(('src_ip', current_src_ip))
                current_packet_data.append(('dst_ip', get_destination_ip_address(pretty_packet)))

                contains = False
                for sender in unique_senders:
                    if current_src_ip == sender.ip_addr:
                        sender.packets_sent += 1
                        contains = True
                        break
                if not contains:
                    unique_senders.append(UniqueIpSender(current_src_ip, 1))

                current_ipv4_protocol = get_ipv4_protocol(pretty_packet, protocols)
                current_packet_data.append(('protocol', current_ipv4_protocol))

                if current_ipv4_protocol == "UDP" or current_ipv4_protocol == "TCP":
                    current_src_port = get_src_port(pretty_packet)
                    current_dst_port = get_dst_port(pretty_packet)

                    current_packet_data.append(('src_port', current_src_port))
                    current_packet_data.append(('dst_port', current_dst_port))

                    known_port = is_port_known(current_src_port, current_dst_port, protocols, current_ipv4_protocol)
                    if known_port:
                        current_app_protocol = known_port
                        current_packet_data.append(('app_protocol', current_app_protocol))
                elif current_ether_type == "ARP":
                    current_arp_opcode = get_arp_opcode(pretty_packet)
                    current_packet_data.append(('arp_opcode', current_arp_opcode))

        elif current_frame_type == "IEEE 802.3 LLC":
            current_packet_data.append(('sap', get_sap(pretty_packet, protocols)))

        elif current_frame_type == "IEEE 802.3 LLC & SNAP":
            current_packet_data.append(('pid', get_pid(pretty_packet, protocols)))

        current_packet_data.append(('hexa_frame', get_hexa_frame(pretty_packet)))
        current_data = dict(current_packet_data)
        if current_app_protocol == filter_name:  # Append packet only if app_protocol is same as filtered protocol
            packets.append(current_data)
            frame_number += 1
            results_count += 1

    ipv4_senders = []
    for sender in unique_senders:
        ipv4_senders.append({"node": sender.ip_addr, "number_of_sent_packets": sender.packets_sent})

    max_send_packets = []
    key_function = lambda obj: obj.packets_sent
    max_packets_sent = max(unique_senders, key=key_function).packets_sent
    max_objects = [obj for obj in unique_senders if obj.packets_sent == max_packets_sent]
    for i in max_objects:
        max_send_packets.append({"ip_addr": i.ip_addr, "packets_sent": i.packets_sent})

    with open("output.yaml", "w") as file:
        yaml = YAML()
        yaml.dump({"filter_name": filter_name}, file)
        if results_count > 0:
            yaml.dump(packets, file)
            yaml.dump({"ipv4_senders": ipv4_senders}, file)
            yaml.dump({"max_send_packets_by": max_send_packets}, file)
        else:
            yaml.dump("No packets found with this protocol!", file)
    print("\nDone, check output.yaml")


analyze_packets()
