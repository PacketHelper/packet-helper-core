from dataclasses import dataclass


@dataclass
class PacketData:
    raw: str

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
        return temp_body_dict
