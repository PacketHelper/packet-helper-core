from fastapi import status
from fastapi.testclient import TestClient

from api.main import app
from api.models.info_response import VersionResponse

client = TestClient(app)


def test_version():
    response = client.get("/version")
    assert response.status_code == status.HTTP_200_OK
    version_response = VersionResponse.parse_obj(response.json())
    assert version_response.packethelper == "0.1"
    assert version_response.framework == "fastapi"
