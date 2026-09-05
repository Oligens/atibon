class CommonCriteriaEAL4:
    controls=['audit','access_control','configuration_management','cryptographic_support','self_protection']
    def report(self): return {'target':'EAL4+','status':'not_certified','evidence_required':self.controls}
