"""Training-data integrity gates. Rejects suspicious distribution shifts before learning."""
from statistics import mean

class PoisoningGuard:
    def __init__(self, max_deviation: float = 6.0): self.max_deviation = max_deviation
    def validate(self, baseline, candidate) -> bool:
        if not baseline or not candidate: return False
        b = mean(baseline); scale = max(abs(x-b) for x in baseline) or 1.0
        return all(abs(x-b) <= self.max_deviation * scale for x in candidate)
