import functools

from pyshark import InMemCapture
from pyshark.packet.packet import Packet


@functools.cache
def decode_string(hex_str: str) -> Packet:
    """
    Decode string (in string-hex format) using 'InMemCapture' using a tshark.
    """
    _custom_params = [
        "-o",
        "tcp.check_checksum:TRUE",
        "-o",
        "ip.check_checksum:TRUE",
        "-o",
        "stt.check_checksum:TRUE",
        "-o",
        "udp.check_checksum:TRUE",
        "-o",
        "wlan.check_checksum:TRUE",
    ]
    # only interested with the first packet
    packet = InMemCapture(custom_parameters=_custom_params)
    decoded_packet: Packet = packet.parse_packet(
        bytes.fromhex(hex_str.replace(" ", ""))
    )
    packet.close()
    return decoded_packet
