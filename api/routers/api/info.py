from os import getenv

from fastapi import APIRouter, status

from api.models.info_response import InfoResponse

api = APIRouter()


@api.get(
    "/info",
    description="Get information about packet helper version and revision",
    status_code=status.HTTP_200_OK,
    tags=["api"],
)
def get_info() -> InfoResponse:
    ph_version = getenv("PH_VERSION", "v1.0.0:00000000").split(":")
    return InfoResponse(version=ph_version[0], revision=ph_version[1])
