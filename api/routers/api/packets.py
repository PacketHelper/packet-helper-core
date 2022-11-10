import importlib

from fastapi import APIRouter, HTTPException, status
from scapy_helper import to_list

from api.models.creator_packets import CreatorPacketsRequest, CreatorPacketsResponse

api = APIRouter()


@api.post("/packets", status_code=status.HTTP_201_CREATED, tags=["api"])
def post_api_packets(request: CreatorPacketsRequest) -> CreatorPacketsResponse:
    imported_all = importlib.import_module("scapy.all")
    packet = None
    try:
        for protocol in request.packets:
            new_layer = imported_all.__getattribute__(protocol)
            if packet is None:
                packet = new_layer()
                continue
            packet /= new_layer()
    except AttributeError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": f"Layer is not supported {str(error).split()[-1]}"},
        )

    return CreatorPacketsResponse(packets=to_list(packet))
