"""Lightweight robust anomaly model primitives for ATIBON."""
import math

class RobustAutoencoder:
    def __init__(self, threshold: float = 0.15): self.threshold = threshold
    def score(self, vector):
        if not vector: return 0.0
        mean = sum(vector) / len(vector)
        return math.sqrt(sum((x-mean)**2 for x in vector) / len(vector))
    def is_anomalous(self, vector): return self.score(vector) > self.threshold
