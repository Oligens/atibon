"""TPM 2.0 attestation contract."""
from dataclasses import dataclass

@dataclass(frozen=True)
class TpmAttestation:
    pcr_profile: tuple[int, ...] = (0, 2, 7)
    require_quote: bool = True

    def verify(self, quote: bytes | None) -> bool:
        return bool(quote) if self.require_quote else True
