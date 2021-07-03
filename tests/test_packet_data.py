from packet_helper_core.packet_data import PacketData
from packet_helper_core.utils.utils import decode_hex
from tests.utils.example_packets import EXAMPLE_ETHER


class TestPacketData:
    def test_packet_data(self):
        packet = decode_hex(EXAMPLE_ETHER)
        assert packet.__getitem__(
            "eth"
        ), "Layer Ether should be available in decoded hex"

        pd = PacketData(raw=str(packet))
        assert "ETH" in pd.header, "Ether header should be found at packet"
