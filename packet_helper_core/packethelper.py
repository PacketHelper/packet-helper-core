from packet_helper_core.decoders.decode_string import decode_string
from packet_helper_core.decoders.tshark_data import TSharkData
from packet_helper_core.decoders.scapy_data import ScapyData


class PacketHelper:
    """
    Class PacketHelper is just a wrapper to create a handy-shortcut
    for preparing a data from hex string
    """

    def __init__(self) -> None:
        self.hex_string, self.__decoded_by_tshark, self.__decoded_by_scapy = (None,) * 3

    def decode(self, hex_string: str, extend_with_scapy: bool = True) -> None:
        self.hex_string = hex_string.replace(" ", "")
        decoded_string = decode_string(self.hex_string)
        self.__decoded_by_tshark = TSharkData(decoded_packet=decoded_string)
        if extend_with_scapy:
            self.__decoded_by_scapy = ScapyData(
                raw=self.hex_string, packet_data=self.__decoded_by_tshark
            )

    @property
    def tshark_data(self) -> TSharkData | None:
        return self.__decoded_by_tshark

    @property
    def scapy_data(self) -> ScapyData | None:
        return self.__decoded_by_scapy
