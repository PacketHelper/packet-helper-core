from scapy.all import Ether, IP, TCP  # noqa
from scapy_helper import to_list, get_hex

from packet_helper_core.utils.conversion import from_sh_list


class TestFromSHList:
    def test_from_sh_list(self):
        packet = Ether() / IP() / IP() / TCP()
        packet_list = to_list(packet)
        new_packet = from_sh_list(packet_list)

        assert get_hex(packet) == get_hex(new_packet)
        assert packet_list == to_list(new_packet)

    def test_from_sh_list_additional_packet(self):
        packet = Ether() / IP() / IP() / TCP() / Ether() / IP() / IP() / TCP()
        packet_list = to_list(packet)
        new_packet = from_sh_list(packet_list)

        assert get_hex(packet) == get_hex(new_packet)
        assert packet_list == to_list(new_packet)
