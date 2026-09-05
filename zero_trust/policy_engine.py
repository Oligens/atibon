"""Zero Trust policy primitives. Default deny; identity and attestation are mandatory in production."""
class PolicyEngine:
    def __init__(self, default_deny=True): self.default_deny=default_deny; self.policies={}
    def set_policy(self, subject, resource, action, allowed, require_attestation=True): self.policies[(subject,resource,action)]={"allowed":bool(allowed),"require_attestation":require_attestation}
    def authorize(self, subject, resource, action, attested=False):
        p=self.policies.get((subject,resource,action))
        if not p: return False if self.default_deny else True
        return p["allowed"] and (not p["require_attestation"] or attested)
