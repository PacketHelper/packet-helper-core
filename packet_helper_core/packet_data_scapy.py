from dataclasses import dataclass
from operator import index
from typing import Literal, Optional
from pydantic import BaseModel
from scapy_helper import get_hex

from packet_helper_core.packet_data import PacketData
from packet_helper_core.utils.scapy_reader import scapy_reader


class ScapyData(BaseModel):
    name: str
    bytes_record: str  # bytes
    hex_record: str  # hex
    hex_record_full: str  # hex_one
    length: int
    length_unit: Literal[
        "B",
    ]  # length_unit
    represantation: str  # repr
    represantation_full: str  # repr_full

    tshark_name: Optional[str]
    tshark_raw_summary: Optional[str]
    chksum_status: Optional[bool]


@dataclass
class PacketDataScapy:
    raw: str
    packet_data: PacketData

    def __post_init__(self):
        self.header = [x.replace("\r", "") for x in self.packet_data.header]
        self.headers_scapy = scapy_reader(self.raw)

        self.headers_full = [repr(x) for x in self.headers_scapy]
        self.headers_single = [f"{x.split(' |')[0]}>" for x in self.headers_full]

        self.structure = self.__make_structure()

    def __make_structure(self):
        temp_structure = []

        for index, header in enumerate(self.headers_scapy):
            scapy_header = self.headers_scapy[index].copy()
            scapy_header.remove_payload()
            scapy_data_dict: ScapyData = {
                "name": header.name,
                "bytes": str(header),
                "hex": get_hex(header),
                "hex_one": get_hex(scapy_header),
                "length": len(header),
                "length_unit": "B",
                "repr": f"{repr(header).split(' |')[0]}>",
                "repr_full": repr(header),
            }

            # RAW elements on the end are added to the last package as data!
            try:
                scapy_data_dict["tshark_name"] = self.packet_data.body2[e][0]
                scapy_data_dict["tshark_raw_summary"] = self.packet_data.body2[e][1:]
            except IndexError:
                break

            scapy_data_dict["chksum_status"] = self.packet_data.chksum_list[e]

            temp_structure.append(scapy_data_dict)
        return temp_structure
