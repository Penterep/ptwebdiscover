from dataclasses import dataclass

from ptdataclasses.argumentoptions import ArgumentOptions


@dataclass
class ProcessedArgumentOptions(ArgumentOptions):
    is_star: bool
    nochanged_url: str
    position: int
    headers: dict[str,str]
    proxies: dict[str,str]
    charset: list[str]
    is_star_in_domain: bool
    auth: tuple[str,str]