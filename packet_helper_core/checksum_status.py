from dataclasses import dataclass
from typing import Optional


@dataclass
class ChecksumStatus:
    chksum: str = ""
    chksum_calculated: str = ""
    status: Optional[bool] = None

    def __call__(self, *args, **kwargs) -> None:
        def clean_chksum(element: str):
            return element.replace("0x", "")

        if self.chksum == "" or self.chksum_calculated == "":
            return
        self.status = clean_chksum(self.chksum) == clean_chksum(self.chksum_calculated)
