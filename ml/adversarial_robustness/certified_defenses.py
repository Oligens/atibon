class CertifiedDefense:
    """Evidence-oriented wrapper; certification requires a formally verified method."""
    def certify(self, score:float, threshold:float): return score <= threshold
