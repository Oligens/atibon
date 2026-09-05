class TPMAttestation:
    def __init__(self,device='/dev/tpm0'): self.device=device
    def verify(self,quote:bytes,expected_digest:str)->bool: return False
