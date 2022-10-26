from packet_helper_core.packet_data import PacketData
from packet_helper_core.utils.utils import decode_hex
from scapy.layers.all import IP, TCP, Ether, IPv6  # type: ignore
from scapy_helper import get_hex

from tests.utils.example_packets import EXAMPLE_ETHER, EXAMPLE_ETHER_IP_IPV6_GRE_DATA


def test_packet_data():
    packet = decode_hex(EXAMPLE_ETHER)
    assert packet.__getitem__("eth"), "Layer Ether should be available in decoded hex"

    pd = PacketData(raw=str(packet))
    assert "ETH" in pd.header, "Ether header should be found at packet"


def test_decode_hex__data_should_be_present_after_gre_packet():
    expected_data = (
        "0035003500310000736f6d652072616e646f6d20737472696"
        "e672031313233343435393832373334393832373334323334"
    )

    packet = decode_hex(EXAMPLE_ETHER_IP_IPV6_GRE_DATA)
    pd = PacketData(raw=str(packet))
    packet_raw_data = pd.body.get("RAW", [])
    assert packet_raw_data, "RAW block should be available"
    extracted_data_from_raw = packet_raw_data[0].split()[-1]
    assert (
        len(extracted_data_from_raw) == len(expected_data)
        and extracted_data_from_raw == expected_data
    ), "Data should be equal in len and value"


def test_custom_packet_data():
    frame = Ether() / IP() / IPv6() / TCP()
    packet = decode_hex(get_hex(frame))
    list_of_expected_packets = ("ETH", "IP", "IPV6", "TCP")
    list_of_layers_from_packet = [x.layer_name.upper() for x in packet.layers]
    for expected_packet in list_of_expected_packets:
        if expected_packet not in list_of_layers_from_packet:
            raise Exception(
                f"Missing layer ${expected_packet} in packet. PyShark decode correctly?"
            )
