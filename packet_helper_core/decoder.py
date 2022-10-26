from packet_helper_core.packet_data import PacketData
from packet_helper_core.packet_data_scapy import PacketDataScapy
from packet_helper_core.utils.utils import decode_hex


class Decoder:
    """
    Class Decoder is just a wrapper to create a handy-shortcut
    for preparing a data from hex string
    """

    def __init__(self, hex_string: str) -> None:
        self.hex_string = hex_string.replace(" ", "")

        self.__decoded_by_tshark, self.__decoded_by_scapy = (None,) * 2

    def run(self, extend_with_scapy: bool = True) -> None:
        self.__decoded_by_tshark = PacketData(raw=str(decode_hex(self.hex_string)))
        if extend_with_scapy:
            self.__decoded_by_scapy = PacketDataScapy(
                raw=self.hex_string, packet_data=self.tshark_data
            )

    @property
    def tshark_data(self) -> PacketData | None:
        return self.__decoded_by_tshark

    @property
    def scapy_data(self) -> PacketDataScapy | None:
        return self.__decoded_by_scapy
