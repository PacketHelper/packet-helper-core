from unittest import TestCase

from src.packet_data import PacketData
from tests.utils.example_packets import EXAMPLE_ETHER

from ptf.testutils import *


class TestPacketData(TestCase):
    def test_packet_data(self):
        pd = PacketData(raw=EXAMPLE_ETHER)
        assert pd

    def test(self):
        pkt = simple_tcp_packet(
            eth_dst="00:11:11:11:11:11",
            eth_src="00:22:22:22:22:22",
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dst="10.0.0.1",
            ip_id=102,
            ip_ttl=64,
        )
        print("test")


if __name__ == "__main__":
    packet = TestPacketData()
    packet.test()
