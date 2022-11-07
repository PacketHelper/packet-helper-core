from dataclasses import dataclass

from scapy.packet import Packet
from scapy_helper import get_hex

from packet_helper_core.decoders.tshark_data import TSharkData
from packet_helper_core.models.scapy_response import ScapyResponse
from packet_helper_core.utils.scapy_reader import scapy_reader


@dataclass
class ScapyData:
    raw: str
    packet_data: TSharkData

    def __post_init__(self):
        self.headers: list[str] = [x.replace("\r", "") for x in self.packet_data.header]
        self.scapy_headers: list[Packet] = scapy_reader(self.raw)

        self.full_scapy_representation_headers: list[str] = [
            repr(x) for x in self.scapy_headers
        ]
        self.single_scapy_representation_headers = [
            f"{x.split(' |')[0]}>" for x in self.full_scapy_representation_headers
        ]

        self.packet_structure = self.__make_structure()

    def __make_structure(self) -> list[ScapyResponse]:
        scapy_responses: list[ScapyResponse] = []

        for index, header in enumerate(self.scapy_headers):
            scapy_header = self.scapy_headers[index].copy()
            scapy_header.remove_payload()  # payload is not necessary for our usage in this case
            scapy_data_dict: ScapyResponse = ScapyResponse(
                **{
                    "name": header.name,
                    "bytes_record": str(header),
                    "hex_record": get_hex(header),
                    "hex_record_full": get_hex(scapy_header),
                    "length": len(header),
                    "length_unit": "B",
                    "representation": f"{repr(header).split(' |')[0]}>",
                    "representation_full": repr(header),
                }
            )

            # RAW elements on the end are added to the last package as data!
            try:
                scapy_data_dict.tshark_name = self.packet_data.body2[index][0]
                scapy_data_dict.tshark_raw_summary = self.packet_data.body2[index][1:]
            except IndexError:
                break

            scapy_data_dict.chksum_status = self.packet_data.chksum_list[index]

            scapy_responses.append(scapy_data_dict)
        return scapy_responses
