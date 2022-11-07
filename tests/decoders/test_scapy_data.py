import pytest
from scapy.all import IP, TCP, Ether  # noqa
from scapy_helper import get_hex

from packet_helper_core import PacketHelper
from packet_helper_core.decoders.scapy_data import ScapyData


@pytest.fixture
def decode_example_packet() -> PacketHelper:
    ph = PacketHelper()
    ph.decode(get_hex(Ether() / IP() / IP() / TCP()))
    return ph


def test_scapy_data(decode_example_packet: PacketHelper) -> None:
    scapy_data = ScapyData(
        decode_example_packet.hex_string, decode_example_packet.tshark_data
    )
    assert scapy_data
    assert scapy_data.headers
    assert scapy_data.scapy_headers
    assert scapy_data.full_scapy_representation_headers
    assert scapy_data.single_scapy_representation_headers
    assert scapy_data.packet_structure
