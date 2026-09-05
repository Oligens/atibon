import hashlib
class ModelSigner:
    def digest(self, model_bytes:bytes)->str:return hashlib.sha256(model_bytes).hexdigest()
    def verify_digest(self, model_bytes:bytes,digest:str)->bool:return self.digest(model_bytes)==digest
