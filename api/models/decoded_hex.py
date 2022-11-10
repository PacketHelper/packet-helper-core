from typing import Literal

from pydantic import BaseModel

from core.models.scapy_response import ScapyResponse


class HexSummary(BaseModel):
    length: int
    length_unit: Literal["B", "b"]
    hexdump: str


class DecodedHexResponse(BaseModel):
    hex: str
    summary: HexSummary
    structure: list[ScapyResponse]
