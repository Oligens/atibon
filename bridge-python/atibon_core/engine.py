"""Fail-closed application facade for the ATIBON native core."""
try:
    from . import _native
except ImportError as exc:
    _native = None
    _native_error = exc

class AtibonEngine:
    def __init__(self, max_packet_size: int = 65535):
        if _native is None:
            raise RuntimeError(f"ATIBON native core unavailable: {_native_error}")
        self.dpi = _native.DpiEngine(max_packet_size)
        self.consensus = _native.HoneyBadgerState(1)
        self.crypto = _native.PqcFacade()

    def inspect(self, packet: bytes) -> dict:
        import json
        return json.loads(self.dpi.inspect(packet))

    def commit_policy(self, payload: bytes, approvals: int = 1) -> bool:
        return bool(self.consensus.propose(payload, approvals))
