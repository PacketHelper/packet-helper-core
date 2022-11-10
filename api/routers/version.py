from fastapi import APIRouter, status


from api.models.info_response import VersionResponse

version = APIRouter()


@version.get(
    "/version", status_code=status.HTTP_200_OK, include_in_schema=False, deprecated=True
)
def get_version() -> VersionResponse:
    """Return information about version of the Packet Helper"""
    return VersionResponse(packethelper="0.1", framework="fastapi")
