from dataclasses import dataclass, field
from typing import List

@dataclass
class GatewayRecord:
    site: str
    gw_ip: str
    prefixes: List[str] = field(default_factory=list)
    community: str = ""