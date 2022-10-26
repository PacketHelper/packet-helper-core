from packet_helper_core import PacketData, PacketDataScapy
from packet_helper_core.core import Core
from scapy.all import IP, TCP, Ether  # type: ignore
from scapy_helper import get_hex


class TestCore:
    simple_ether_ip_tcp_hex_string = get_hex(Ether() / IP() / TCP())

    def test_core_post_init(self):
        core_results = Core(TestCore.simple_ether_ip_tcp_hex_string)

        assert isinstance(core_results.hex_string, str), "Should be String"
        assert isinstance(
            core_results.scapy_data, PacketDataScapy
        ), "Should be PacketDataScapy"
        assert isinstance(core_results.tshark_data, PacketData), "Should be PacketData"

        assert core_results.scapy_data.header == [
            "ETH",
            "IP",
            "TCP",
        ], "Should be properly decoded"
        assert core_results.tshark_data.header == [
            "ETH",
            "IP",
            "TCP",
        ], "Should be properly decoded"

    def test_core_chksum_verification(self):
        core_results = Core(get_hex(Ether() / IP() / IP() / TCP()))
        assert core_results.tshark_data.chksum_list

    def test_negative_core_chksum_verification_with_wrong_chksum(self):
        core_results2 = Core(get_hex(Ether() / IP() / IP(chksum=0) / TCP()))
        assert core_results2.tshark_data.chksum_list[2]["chksum"] == "0x0000"

    def test_one_of_custom_problematic_cases(self):
        core_results = Core(
            "ffffffaaa9ff00000000001208004500003c0001000040047cbb7f0000017f"
            "000001450000280001000040067ccd7f0000017f0000010014005000000000"
            "0000000050022000917d0000"
        )
        assert core_results.tshark_data.chksum_list[3]["chksum"] == "0x917d"

    def test_Ethernet_IP_UDP_DNS(self):
        core_result = Core(
            "00E01CCCCCC2001F33D9736108004500008000004000401124550A0A01010"
            "A0A01040035DB66006C2D2E795681800001000200020000046D61696C0870"
            "617472696F747302696E0000010001C00C0005000100002A4B0002C011C01"
            "10001000100002A4C00044A358C99C011000200010001438C0006036E7332"
            "C011C011000200010001438C0006036E7331C011"
        )
        chksum_obj = core_result.tshark_data.chksum_list[2]

        assert chksum_obj["chksum"] == "0x2d2e"
        assert chksum_obj["chksum_calculated"] == "0x2d2d"
        assert chksum_obj["status"] is False
