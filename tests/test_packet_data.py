from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy_helper import get_hex

from packet_helper_core.packet_data import PacketData
from packet_helper_core.utils.utils import decode_hex
from tests.utils.example_packets import EXAMPLE_ETHER
from ptf.testutils import (
    simple_tcp_packet,
    simple_ip_packet,
    simple_udp_packet,
    simple_eth_packet,
)


class TestPacketData:
    def test_packet_data(self):
        packet = decode_hex(EXAMPLE_ETHER)
        assert packet.__getitem__(
            "eth"
        ), "Layer Ether should be available in decoded hex"

        pd = PacketData(raw=str(packet))
        assert "ETH" in pd.header, "Ether header should be found at packet"

    def test_custom_packet_data(self):
        frame = Ether() / IP() / IPv6() / TCP()
        packet = decode_hex(get_hex(frame))
        list_of_expected_packets = ("ETH", "IP", "IPV6", "TCP")
        list_of_layers_from_packet = [x.layer_name.upper() for x in packet.layers]
        for expected_packet in list_of_expected_packets:
            if expected_packet not in list_of_layers_from_packet:
                raise Exception(
                    f"Missing layer ${expected_packet} in packet. PyShark decode correctly?"
                )

    def test_tcp_packet(self):
        dport = 81
        pkt = simple_tcp_packet(tcp_dport=dport)
        packet = decode_hex(get_hex(pkt))
        list_of_expected_packets = ("ETH", "IP", "TCP")
        list_of_layers_from_packet = [x.layer_name.upper() for x in packet.layers]
        for expected_packet in list_of_expected_packets:
            if expected_packet not in list_of_layers_from_packet:
                raise Exception(
                    f"Missing layer ${expected_packet} in packet. PyShark decode correctly?"
                )
        if packet.tcp.dstport != str(dport):
            raise Exception(
                f"TCP destination port mismatch. Is {packet.tcp.dstport}, should be {dport}."
            )

    def test_ip_packet(self):
        ttl = 32
        pkt = simple_ip_packet(ip_ttl=ttl)
        packet = decode_hex(get_hex(pkt))
        list_of_expected_packets = ("ETH", "IP")
        list_of_layers_from_packet = [x.layer_name.upper() for x in packet.layers]
        for expected_packet in list_of_expected_packets:
            if expected_packet not in list_of_layers_from_packet:
                raise Exception(
                    f"Missing layer ${expected_packet} in packet. PyShark decode correctly?"
                )
        if packet.ip.ttl != str(ttl):
            raise Exception(f"IP ttl mismatch. Is {packet.ip.ttl}, should be {ttl}.")

    def test_udp_packet(self):
        dport = 81
        pkt = simple_udp_packet(udp_dport=dport)
        packet = decode_hex(get_hex(pkt))
        list_of_expected_packets = ("ETH", "IP", "UDP")
        list_of_layers_from_packet = [x.layer_name.upper() for x in packet.layers]
        for expected_packet in list_of_expected_packets:
            if expected_packet not in list_of_layers_from_packet:
                raise Exception(
                    f"Missing layer ${expected_packet} in packet. PyShark decode correctly?"
                )
        if packet.udp.dstport != str(dport):
            raise Exception(
                f"UDP destination port mismatch. Is {packet.udp.dstport}, should be {dport}."
            )

    def test_eth_packet(self):
        dst = "01:02:03:04:05:06"
        pkt = simple_eth_packet(eth_dst=dst)
        packet = decode_hex(get_hex(pkt))
        list_of_expected_packets = ("ETH", "LLDP")
        list_of_layers_from_packet = [x.layer_name.upper() for x in packet.layers]
        for expected_packet in list_of_expected_packets:
            if expected_packet not in list_of_layers_from_packet:
                raise Exception(
                    f"Missing layer ${expected_packet} in packet. PyShark decode correctly?"
                )
        if packet.eth.dst != dst:
            raise Exception(
                f"ETH destination mismatch. Is {packet.eth.dst}, should be {dst}."
            )
