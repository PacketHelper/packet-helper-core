from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy_helper import get_hex

from packet_helper_core import PacketDataScapy, PacketData
from packet_helper_core.core import Core


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

