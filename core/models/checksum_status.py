from pydantic import BaseModel


class ChecksumStatus(BaseModel):
    chksum: str = ""
    chksum_calculated: str = ""
    status: bool | None = None

    def verify(self) -> None:
        def clean_chksum(element: str):
            return element.replace("0x", "")

        if self.chksum and self.chksum_calculated:
            self.status = clean_chksum(self.chksum) == clean_chksum(
                self.chksum_calculated
            )
        else:
            self.status = None