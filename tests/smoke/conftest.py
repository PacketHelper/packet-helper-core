import os

import pytest


@pytest.fixture
def instance_uri() -> str:
    return os.getenv("PACKET_HELPER_URI", "https://www.packethelper.com")


@pytest.fixture
def api_uri(instance_uri: str) -> str:
    return f"{instance_uri}/api"
