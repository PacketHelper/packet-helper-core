from dataclasses import dataclass


@dataclass
class ChecksumStatus:
    chksum: str = ""
    chksum_calculated: str = ""
    status: bool = None

    def __call__(self, *args, **kwargs):
        def clean_chksum(element: str):
            return element.replace("0x", "")

        self.status = clean_chksum(self.chksum) == clean_chksum(self.chksum_calculated)
