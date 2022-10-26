import pytest
from packet_helper_core.utils.conversion import from_sh_list
from scapy.packet import Packet
from scapy_helper import get_hex, to_list

from tests.utils.example_packets import SIMPLE_IP_IN_IP_PACKET


@pytest.mark.parametrize(
    "packet", (SIMPLE_IP_IN_IP_PACKET, SIMPLE_IP_IN_IP_PACKET / SIMPLE_IP_IN_IP_PACKET)
)
def test_from_sh_list(packet: Packet) -> None:
    packet_list = to_list(packet)
    new_packet = from_sh_list(packet_list)

    assert get_hex(packet) == get_hex(new_packet)
    assert packet_list == to_list(new_packet)
