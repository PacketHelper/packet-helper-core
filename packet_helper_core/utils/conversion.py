import importlib
from typing import Any

from scapy.base_classes import BasePacket


def from_sh_list(packet_list: list[dict[str, Any]]) -> BasePacket:
    imported_all = importlib.import_module("scapy.all")

    def remove_none() -> dict[str, Any]:
        if not _value:
            return {}
        return {k: v for k, v in _value.items() if v is not None}

    new_packet = None
    for layer in packet_list:
        if isinstance(layer, dict):
            _key: str = [x for x in layer.keys()][0]
            _value: dict[str, Any] = layer.get(_key, {})
            _value = remove_none()
            if _key == "Ethernet":
                _key = "Ether"
            new_layer = imported_all.__getattribute__(_key)
            if new_packet is None:
                new_packet = new_layer(**_value)
                continue
            new_packet /= new_layer(**_value)
    return new_packet
