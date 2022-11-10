from fastapi import status
from fastapi.testclient import TestClient

from api.main import app
from api.models.creator_packets import (
    CreatorPacketsObjectsRequest,
    CreatorPacketsObjectsResponse,
)

client = TestClient(app)


def test_post_api__success():
    response = client.post(
        "/api/create",
        json=CreatorPacketsObjectsRequest(
            packets=[
                {
                    "Ethernet": {
                        "src": "ff:ff:ff:ff:ff:ff",
                        "dst": "ff:ff:ff:ff:ff:ff",
                        "type": 0,
                    }
                },
            ]
        ).dict(),
    )
    assert response.status_code == status.HTTP_201_CREATED
    creator_packets_response = CreatorPacketsObjectsResponse.parse_obj(response.json())
    assert (
        creator_packets_response.builtpacket.get("hex", "")
        == "ff ff ff ff ff ff ff ff ff ff ff ff 00 00"
    )


def test_post_api_create__negative__packet_not_exists_in_scapy():
    response = client.post(
        "/api/create",
        json=CreatorPacketsObjectsRequest(
            packets=[
                {
                    "NonExistingLayer": {
                        "src": "ff:ff:ff:ff:ff:ff",
                        "dst": "ff:ff:ff:ff:ff:ff",
                        "type": 0,
                    }
                },
            ]
        ).dict(),
    )
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert (
        response.json()["detail"]["error"]
        == "Layer is not supported 'NonExistingLayer'"
    )
