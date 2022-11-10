from pydantic import BaseModel


class InfoResponse(BaseModel):
    version: str
    revision: str | None


class VersionResponse(BaseModel):
    packethelper: str  # FIXME rename => packet_helper
    framework: str
