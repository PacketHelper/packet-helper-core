from typing import Literal

from pydantic import BaseModel, Field

from core.models.checksum_status import ChecksumStatus


class ScapyResponse(BaseModel):
    name: str
    bytes_record: str  # bytes
    hex_record: str  # hex
    hex_record_full: str  # hex_one
    length: int
    length_unit: Literal["B", "b"]  # length_unit
    representation: str  # repr
    representation_full: str  # repr_full
    tshark_name: str = ""
    tshark_raw_summary: list[str] = Field(default_factory=list)
    chksum_status: ChecksumStatus | None = None
