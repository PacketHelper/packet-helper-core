from dataclasses import dataclass

from packet_helper_core.packet_data import PacketData
from packet_helper_core.packet_data_scapy import PacketDataScapy
from packet_helper_core.utils.utils import decode_hex


@dataclass
class Core:
    """
    Class Core is just a wrapper to create a handy-shortcut
    for preparing a data from hex string
    """

    hex_string: str = ""

    def __post_init__(self):
        self.hex_string = self.hex_string.replace(" ", "")
        self.tshark_data = PacketData(raw=str(decode_hex(self.hex_string)))
        self.scapy_data = PacketDataScapy(self.hex_string, self.tshark_data)
