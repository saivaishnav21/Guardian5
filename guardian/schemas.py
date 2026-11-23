from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    id: str                          # prefixed per agent: VULN-001, SUSP-001, CTR-001, CI-001
    type: str                        # vulnerability | suspicious_change | container | ci_cd
    title: str
    component: str                   # name@version
    dependency_path: list[str]       # root -> ... -> component (empty if not applicable)
    evidence: dict                   # raw tool output / supporting data
    severity: str = "unknown"        # critical | high | medium | low | unknown
    risk_level: str = "unrated"      # filled later by the Evidence & Risk agent
    source_agent: str = ""
    fix: Optional[str] = None
    notes: list[str] = field(default_factory=list)   # room for agent negotiation later

    def to_dict(self) -> dict:
        return asdict(self)