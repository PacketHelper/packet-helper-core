import pytest
from fastapi import status
from fastapi.testclient import TestClient

from api.main import app
from api.models.decoded_hex import DecodedHexResponse

client = TestClient(app)


@pytest.mark.parametrize(
    "hex_to_decode",
    (
        "ffffffaaa9ff00000000001208004500003c0001000040047cbb7f0000017f00000145"
        "0000280001000040067ccd7f0000017f00000100140050000000000000000050022000"
        "917c0000",
    ),
)
def test_get_packet(hex_to_decode: str):
    response = client.get(f"api/hex/{hex_to_decode}")
    assert response.status_code == status.HTTP_200_OK
    assert DecodedHexResponse.parse_obj(
        response.json()
    ), "Response should be parsed to the 'DecodedHexResponse' without problems"
