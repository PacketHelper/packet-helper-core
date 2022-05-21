import binascii
import logging
import os
from time import time
from typing import List
from typing import Union
from scapy.all import wrpcap, rdpcap
from scapy.packet import Packet


def scapy_reader(hex_str: Union[str, bytes]) -> List[Packet]:
    hex_str = binascii.unhexlify(hex_str)
    if not isinstance(hex_str, bytes):
        raise Exception("ERR:: hex_str must be in bytes!")

    temp_filename = f"pcap_{time()}"
    wrpcap(temp_filename, hex_str)
    pcap_object = rdpcap(temp_filename)

    #  try to clean after all
    try:
        os.remove(temp_filename)
    except Exception:
        logging.error(f"Cannot remove {temp_filename}")

    converted_packets = []
    current = pcap_object[0]
    while current:
        converted_packets.append(current)
        if current.payload is not None:
            current = current.payload

    return converted_packets
