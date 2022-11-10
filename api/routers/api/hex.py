import functools

import pydantic
from fastapi import APIRouter, HTTPException, status
from core.decoders.scapy_data import ScapyData
from core.decoders.tshark_data import TSharkData
from core.decoders.decode_string import decode_string
from scapy_helper import hexdump

from api.models.decoded_hex import DecodedHexResponse
from core.models.scapy_response import ScapyResponse

api = APIRouter()


@api.get("/hex/{hex_string}", status_code=status.HTTP_200_OK, tags=["api"])
def get_api_hex(hex_string: str) -> DecodedHexResponse:
    @functools.cache
    def prepare_api_response(hex_to_decode: str) -> list[ScapyResponse]:
        packet = decode_string(hex_to_decode)
        packet_data = TSharkData(packet)
        scapy_data = ScapyData(hex_to_decode, packet_data)

        return scapy_data.packet_structure

    h = " ".join(
        [
            "".join([hex_string[e - 1], hex_string[e]])
            for e, _ in enumerate(hex_string)
            if e % 2
        ]
    )

    try:
        response = DecodedHexResponse(
            hex=hex_string,
            summary={
                "length": len(h.split()),
                "length_unit": "B",
                "hexdump": hexdump(h, dump=True),
            },
            structure=prepare_api_response(hex_string),
        )
    except IndexError:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={
                "error": f"Hex <{hex_string}> is incorrect. Is packet length is correct?"
            },
        )
    except pydantic.error_wrappers.ValidationError as ve:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": f"Incorrect response from engine: <{ve}>"},
        )
    return response
