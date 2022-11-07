from http import HTTPStatus

import requests


def test_smoke(api_uri: str) -> None:
    simple_packet = (
        "00001Cffffff0000000000000800450000340001000040047cc37f0000017f00000"
        "14500002000010000402f7cac7f0000017f00000100000000"
    )  # Ethernet / IP / IPv6 / GRE
    response = requests.get(f"{api_uri}/hex/{simple_packet}")
    assert response.status_code == HTTPStatus.OK
