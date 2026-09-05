"""Python/Rust boundary with fail-closed semantics."""
try:
    import defensive_ai_core as core
except ImportError:
    core = None

class DefensiveEngine:
    def __init__(self, max_packet_size=65535):
        if core is None:
            raise RuntimeError("defensive_ai_core is unavailable; refusing silent insecure fallback")
        self.engine = core.FilterEngine(max_packet_size)
    def add_rule(self, pattern: bytes, action: int, priority: int = 100, rule_id: str = "rule"):
        if action not in range(5): raise ValueError("invalid action")
        import json
        self.engine.add_rule(json.dumps({"id":rule_id,"priority":priority,"pattern":list(pattern),"action":action}))
    def analyze_packet(self, packet: bytes):
        return self.engine.analyze_packet(packet)
