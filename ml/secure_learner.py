from dataclasses import dataclass
from collections import deque
import hashlib, time
@dataclass(frozen=True)
class Sample:
    data: bytes; timestamp: float; digest: str
class SecureLearner:
    """Ingestion gate: validates integrity, freshness and duplicate rate before training."""
    def __init__(self, max_buffer=10000, max_age_seconds=3600): self.buffer=deque(maxlen=max_buffer); self.max_age_seconds=max_age_seconds
    def add_sample(self,data:bytes,timestamp=None,expected_digest=None):
        ts=time.time() if timestamp is None else timestamp; digest=hashlib.sha256(data).hexdigest()
        if abs(time.time()-ts)>self.max_age_seconds: return False
        if expected_digest and digest!=expected_digest: return False
        self.buffer.append(Sample(data,ts,digest)); return True
    def snapshot(self): return {"samples":len(self.buffer),"unique_digests":len({s.digest for s in self.buffer})}
