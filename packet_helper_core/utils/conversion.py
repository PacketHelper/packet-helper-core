import importlib


def from_sh_list(packet_list):
    imported_all = importlib.import_module("scapy.all")

    def remove_none():
        return {k: v for k, v in _value.items() if v is not None}

    new_packet = None
    for layer in packet_list:
        if isinstance(layer, dict):
            _key = [x for x in layer.keys()][0]
            _value = layer.get(_key)
            _value = remove_none()
            if _key == "Ethernet":
                _key = "Ether"
            new_layer = imported_all.__getattribute__(_key)
            if new_packet is None:
                new_packet = new_layer(**_value)
                continue
            new_packet /= new_layer(**_value)
    return new_packet
