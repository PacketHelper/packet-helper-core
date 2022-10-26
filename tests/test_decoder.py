import pytest

from packet_helper_core import PacketData, PacketDataScapy
from packet_helper_core.checksum_status import ChecksumStatus
from packet_helper_core.decoder import Decoder
from scapy.all import IP, TCP, Ether  # noqa
from scapy_helper import get_hex


def test_core_post_init():
    expected_headers = [
        "ETH",
        "IP",
        "TCP",
    ]
    decoder = Decoder(get_hex(Ether() / IP() / TCP()))
    decoder.run()

    assert isinstance(decoder.hex_string, str), "Should be String"
    assert isinstance(decoder.scapy_data, PacketDataScapy), "Should be PacketDataScapy"
    assert isinstance(decoder.tshark_data, PacketData), "Should be PacketData"
    assert decoder.scapy_data.header == expected_headers, "Should be properly decoded"
    assert decoder.tshark_data.header == expected_headers, "Should be properly decoded"


def test_core_chksum_verification():
    decoder = Decoder(get_hex(Ether() / IP() / IP() / TCP()))
    decoder.run()
    assert decoder.tshark_data.chksum_list
    assert len(decoder.tshark_data.chksum_list) == 4


@pytest.mark.parametrize(
    "packet, position_to_check, expected_chksum_value",
    (
        (get_hex(Ether() / IP() / IP(chksum=0) / TCP()), 2, "0x0000"),
        (
            (
                "ffffffaaa9ff00000000001208004500003c0001000040047cbb7f0000017f"
                "000001450000280001000040067ccd7f0000017f0000010014005000000000"
                "0000000050022000917d0000"
            ),
            3,
            "0x917d",
        ),
    ),
)
def test_negative_core_chksum_verification_with_wrong_chksum(
    packet: str, position_to_check: int, expected_chksum_value: str
):
    decoder = Decoder(packet)
    decoder.run()
    assert (
        decoder.tshark_data.chksum_list[position_to_check].chksum
        == expected_chksum_value
    )


def test_ethernet_ip_udp_dns():
    decoder = Decoder(
        "00E01CCCCCC2001F33D9736108004500008000004000401124550A0A01010"
        "A0A01040035DB66006C2D2E795681800001000200020000046D61696C0870"
        "617472696F747302696E0000010001C00C0005000100002A4B0002C011C01"
        "10001000100002A4C00044A358C99C011000200010001438C0006036E7332"
        "C011C011000200010001438C0006036E7331C011"
    )
    decoder.run()
    chksum_obj: ChecksumStatus = decoder.tshark_data.chksum_list[2]

    assert chksum_obj.chksum == "0x2d2e"
    assert chksum_obj.chksum_calculated == "0x2d2d"
    assert chksum_obj.status is False
