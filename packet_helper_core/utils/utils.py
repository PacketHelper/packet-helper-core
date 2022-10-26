import pyshark
from pyshark.packet.packet import Packet
from scapy_helper import get_hex


def hex_str_operation(h_string, with_new_line: bool = False):
    z = ""
    tmp = []
    for e, x in enumerate(h_string.replace(" ", "")):
        z += x
        if e % 2:
            tmp.append(z)
            z = ""
    if with_new_line:
        temp_list = []
        for e, v in enumerate(tmp, 1):
            if not e % 16:
                temp_list.append(f"{v}\n")
                continue
            temp_list.append(f"{v} ")
        return "".join(temp_list)
    return " ".join(tmp)


def decode_hex(hex_str: str, use_json: bool = False) -> Packet:
    frame_bytes: bytes = bytes.fromhex(hex_str)
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
    packet = pyshark.InMemCapture(custom_parameters=_custom_params)
    return packet.parse_packet(frame_bytes)


def better_scapy_summary(scapy_summary) -> list:
    list_ = []
    for frame in scapy_summary:
        temp_frame = {
            "name": frame.name,
            "bytes": frame.raw_packet_cache,
            "hex": get_hex(frame.raw_packet_cache),
            "length": len(frame.raw_packet_cache),
            "repr": f"{repr(frame).split(' |')[0]}>",
        }
        list_.append(temp_frame)
    return list_
