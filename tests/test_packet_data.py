from unittest import TestCase

from src.packet_data import PacketData
from tests.example_packets import EXAMPLE_ETHER


class TestPacketData(TestCase):
    def test_packet_data(self):
        pd = PacketData(raw=EXAMPLE_ETHER)
        assert pd
