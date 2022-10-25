import binascii
import logging
import os
from time import time
from scapy.all import wrpcap, rdpcap
from scapy.packet import Packet


def scapy_reader(hex_str: bytes | str) -> list[Packet]:
    hex_str = binascii.unhexlify(hex_str)
    if not isinstance(hex_str, bytes):
        raise Exception("ERR:: hex_str must be in bytes!")

    temp_filename = f"pcap_{time()}"
    wrpcap(temp_filename, hex_str)
    pcap_object = rdpcap(temp_filename)

    #  try to clean after all
    try:
        os.remove(temp_filename)
    except OSError as os_err:
        logging.error(f"Cannot remove {temp_filename}: {os_err}")

    converted_packets = []
    current = pcap_object[0]
    while current:
        converted_packets.append(current)
        if current.payload is not None:
            current = current.payload

    return converted_packets
