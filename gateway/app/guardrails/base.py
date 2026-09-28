from dataclasses import dataclass, field
from typing import Literal, Protocol


Decision = Literal["allow", "warn", "deny"]


@dataclass
class GuardrailResult:
    decision: Decision
    content: str
    redacted_content: str
    risk_score: float = 0.0
    signals: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)


class Detector(Protocol):
    name: str
    version: str

    def evaluate(self, content: str) -> GuardrailResult: ...
