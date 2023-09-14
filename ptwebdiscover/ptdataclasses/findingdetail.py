from dataclasses import dataclass
from requests.structures import CaseInsensitiveDict



@dataclass
class FindingDetail:
    url: str
    status_code: int
    headers: CaseInsensitiveDict[str]