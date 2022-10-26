from dataclasses import dataclass


@dataclass
class ChecksumStatus:
    chksum: str = ""
    chksum_calculated: str = ""
    status: bool | None = None

    def __call__(self, *args, **kwargs):
        def clean_chksum(element: str):
            return element.replace("0x", "")

        if self.chksum == "" or self.chksum_calculated == "":
            return
        self.status = clean_chksum(self.chksum) == clean_chksum(self.chksum_calculated)
