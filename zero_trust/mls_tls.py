from .policy_engine import PolicyEngine
class PostQuantumTLS:
    def __init__(self,*args,**kwargs): self.enabled=False
    def status(self): return {'enabled':self.enabled,'provider_required':True}
