"""ATIBON mTLS policy. PQC is a deployment capability, not a claim made by Python ssl."""
from dataclasses import dataclass

@dataclass(frozen=True)
class MtlsPolicy:
    require_client_auth: bool = True
    require_pqc_provider: bool = True
    minimum_tls: str = "1.3"

    def validate(self, provider_configured: bool) -> None:
        if self.require_pqc_provider and not provider_configured:
            raise RuntimeError("PQC mTLS provider is not configured")
