from dataclasses import asdict, dataclass, field
from typing import Any

from packet_helper_core.checksum_status import ChecksumStatus


@dataclass
class PacketData:
    raw: str
    chksum_list: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.raw_array = self.raw.split("\n")
        self.length = self.raw_array[0].replace(")", "").split()[2]
        self.array = self.raw_array[1:]

        self.header = self.compose_header()
        self.body = self.compose_body()
        self.body2 = self.compose_body_list()

    def compose_header(self):
        return [
            a.replace("Layer", "").replace(":", "").replace(" ", "")
            for a in self.array
            if a.startswith("Layer")
        ]

    def compose_body(self):
        temp_body_dict = {}
        actual_layer: str = ""
        for x in self.array:
            if x.startswith("Layer"):
                actual_layer = x.replace(":", "").split()[1]
                temp_body_dict[actual_layer] = []
                continue
            temp_body_dict[actual_layer].append(x)
        return temp_body_dict

    def compose_body_list(self):
        temp_body_dict = []
        line = []
        ckhsum_flag = False
        for arr in self.array:
            arr = arr.strip()
            if arr == "" and line:
                temp_body_dict.append(line)
                break

            if arr.startswith("Layer"):
                if line:
                    temp_body_dict.append(line)
                line = []
                actual_layer = arr.replace(":", "").split()[1]
                line.append(actual_layer)
                continue
            line.append(arr)
            if "checksum" in arr:
                ckhsum_flag = True

        if ckhsum_flag:
            for y in temp_body_dict:
                self.chksum_verification(y)
        return temp_body_dict

    def chksum_verification(self, element):
        chksum_status = ChecksumStatus()
        for x in element:
            x = x.lower()
            if "header checksum" in x and "incorrect" in x:
                chksum_status.chksum = x.split(":")[1].split()[0]
                continue
            if "bad checksum" in x and not chksum_status.chksum:
                continue
            if "checksum" in x and "status" not in x and not chksum_status.chksum:
                chksum_status.chksum = x.split(":")[1].split()[0]
            if "calculated checksum" in x:
                chksum_status.chksum_calculated = x.split(":")[1].split()[0]
        else:
            chksum_status()
            self.chksum_list.append(asdict(chksum_status))
