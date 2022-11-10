from fastapi import APIRouter, HTTPException, status
from core.utils.conversion import from_sh_list
from scapy_helper import get_hex

from api.models.creator_packets import (
    CreatorPacketsObjectsRequest,
    CreatorPacketsObjectsResponse,
)

api = APIRouter()


@api.post("/create", status_code=status.HTTP_201_CREATED, tags=["api"])
def post_api_create(
    request: CreatorPacketsObjectsRequest,
) -> CreatorPacketsObjectsResponse:
    _hex = None
    try:
        _hex = get_hex(from_sh_list(request.packets))
    except AttributeError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": f"Layer is not supported {str(error).split()[-1]}"},
        )
    return CreatorPacketsObjectsResponse(builtpacket={"hex": _hex})
