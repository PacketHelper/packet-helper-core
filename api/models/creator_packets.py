from typing import Any

from pydantic import BaseModel


class CreatorPacketsRequest(BaseModel):
    packets: list[Any]


class CreatorPacketsResponse(BaseModel):
    packets: list[dict[str, Any]] | None


class CreatorPacketsObjectsRequest(BaseModel):
    packets: list[dict[str, Any]]


class CreatorPacketsObjectsResponse(BaseModel):
    builtpacket: dict[str, str]  # FIXME rename => built_packet
