from dataclasses import dataclass

@dataclass(frozen=True)
class PacketVerdict:
    action: str
    reason: str
    confidence: float = 1.0
