import hashlib, json, time
class AuditTrail:
    def __init__(self): self.records=[]
    def append(self,event_type,actor,action,outcome):
        prev=self.records[-1]["hash"] if self.records else "0"*64
        body={"timestamp":time.time(),"event_type":event_type,"actor":actor,"action":action,"outcome":outcome,"previous_hash":prev}
        body["hash"]=hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest(); self.records.append(body); return body["hash"]
    def verify(self):
        prev="0"*64
        for r in self.records:
            expected=hashlib.sha256(json.dumps({k:r[k] for k in ("timestamp","event_type","actor","action","outcome","previous_hash")},sort_keys=True).encode()).hexdigest()
            if r["previous_hash"]!=prev or r["hash"]!=expected:return False
            prev=r["hash"]
        return True
