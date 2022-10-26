from typing import Any

import pytest
from scapy.base_classes import BasePacket

from packet_helper_core.utils.conversion import from_sh_list
from scapy.packet import Packet
from scapy_helper import get_hex, to_list

from tests.utils.example_packets import SIMPLE_IP_IN_IP_PACKET


@pytest.mark.parametrize(
    "packet", (SIMPLE_IP_IN_IP_PACKET, SIMPLE_IP_IN_IP_PACKET / SIMPLE_IP_IN_IP_PACKET)
)
def test_from_sh_list(packet: Packet) -> None:
    packet_list: list[dict[str, Any]] = to_list(packet)
    packet_generated_from_scapy_helper = from_sh_list(packet_list)

    assert isinstance(packet_generated_from_scapy_helper, BasePacket)
    assert get_hex(packet) == get_hex(
        packet_generated_from_scapy_helper
    ), "Packets should return same hex results"
    assert packet_list == to_list(packet_generated_from_scapy_helper)
