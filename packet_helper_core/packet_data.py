from dataclasses import dataclass, field

from packet_helper_core.checksum_status import ChecksumStatus


@dataclass
class PacketData:
    raw: str
    chksum_list: list[ChecksumStatus] = field(default_factory=list)

    _data_layer: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.raw_array = self.raw.split("\n")
        self.length = self.raw_array[0].replace(")", "").split()[2]
        self.array = self.raw_array[1:]

        self.header = self.compose_header()
        self.body = self.compose_body()
        self.body2 = self.compose_body_list()

        self.update_header()

    def compose_header(self):
        return [
            a.replace("Layer", "").replace(":", "").replace(" ", "")
            for a in self.array
            if a.startswith("Layer")
        ]

    def __is_data_element(self, layer_fragment: str) -> bool:
        potential_data_element_fragment = ("data:", "Data:", "Length")
        if layer_fragment.lstrip().startswith(potential_data_element_fragment):
            self._data_layer.append(layer_fragment)
            return True
        return False

    def compose_body(self) -> dict[str, list[str]]:
        temp_body_dict: dict[str, list[str]] = {}
        actual_layer: str = ""
        for x in self.array:
            if x.startswith("Layer"):
                actual_layer = x.replace(":", "").split()[1]
                temp_body_dict[actual_layer] = []
                continue
            if self.__is_data_element(layer_fragment=x):
                if not temp_body_dict.get("RAW", False):
                    temp_body_dict["RAW"] = []
                temp_body_dict["RAW"].append(x)
                continue
            temp_body_dict[actual_layer].append(x)
        return temp_body_dict

    def compose_body_list(self) -> list[list[str]]:
        temp_body_dict = []
        line = []
        ckhsum_flag = False
        data_found: list[str] = [
            "RAW",
        ]
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

            if self.__is_data_element(layer_fragment=arr):
                data_found.append(arr)
                continue

            line.append(arr)
            if "checksum" in arr:
                ckhsum_flag = True

        if ckhsum_flag:
            for y in temp_body_dict:
                self.chksum_verification(y)

        temp_body_dict.append(data_found)
        return temp_body_dict

    def chksum_verification(self, element) -> None:
        chksum_status: ChecksumStatus = ChecksumStatus()
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
            chksum_status.verify()
            self.chksum_list.append(chksum_status)

    def update_header(self):
        """Update header with data layer which is 'hidden' in the tshark output"""
        if self._data_layer:
            self.header.append("RAW")
