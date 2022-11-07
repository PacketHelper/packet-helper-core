from fastapi import status
from fastapi.testclient import TestClient

from api.main import app
from api.models.creator_packets import CreatorPacketsRequest, CreatorPacketsResponse

client = TestClient(app)


def test_post_api_packets__success():
    response = client.post(
        "/api/packets",
        json=CreatorPacketsRequest(packets=["Ether"]).dict(),
    )
    assert response.status_code == status.HTTP_201_CREATED
    json_response = CreatorPacketsResponse(**response.json())
    assert len(json_response.packets) == 1
    assert json_response.packets[0]["Ethernet"]
    assert len(json_response.packets[0]["Ethernet"]) == 3


def test_post_api_packets__negative__packet_not_exists_in_scapy():
    response = client.post(
        "/api/packets",
        json=CreatorPacketsRequest(packets=["NonExistingPacket"]).dict(),
    )
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert (
        response.json()["detail"]["error"]
        == "Layer is not supported 'NonExistingPacket'"
    )
