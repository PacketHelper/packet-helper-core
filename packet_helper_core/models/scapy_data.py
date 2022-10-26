from typing import Literal

from pydantic import BaseModel

from packet_helper_core.checksum_status import ChecksumStatus


class ScapyData(BaseModel):
    name: str
    bytes_record: str  # bytes
    hex_record: str  # hex
    hex_record_full: str  # hex_one
    length: int
    length_unit: Literal[
        "B",
    ]  # length_unit
    representation: str  # repr
    representation_full: str  # repr_full
    tshark_name: str = ""
    tshark_raw_summary: str = ""
    chksum_status: ChecksumStatus | None = None
