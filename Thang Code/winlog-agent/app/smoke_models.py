"""Explicit synthetic smoke experiment; not a classifier accuracy benchmark."""
from pathlib import Path
from .config import Settings, MODELS
from .context_tokens import ContextGuard
from .inference import Inference
from .ollama import Ollama
from .payload import build_payload
from .storage import canonical


def smoke(root=Path('data')):
    settings=Settings()
    guard=ContextGuard(root/'tokenizers')
    client=Ollama()
    metadata=[client.inspect(model) for model in MODELS]
    runtime=Inference(client,guard)
    if runtime.loaded():
        raise RuntimeError('External model loaded; smoke must not interrupt it')
    def payload(text):
        event={'event_ref':'synthetic-1','event_id':4104,'host':'synthetic-vm',
               'time':'2026-01-01T00:00:00+00:00','process_id':42,'script_text':text,
               'quality_errors':['missing_logon_context']}
        return build_payload([event],[{'event_refs':['synthetic-1'],'links':[]}])
    low,high=0,1000
    while low<high:
        mid=(low+high+1)//2
        sample=payload('Write-Output "demo"; '*mid)
        checks=[guard.check(m,sample['messages'],settings) for m in metadata]
        if any(c['error']=='CONTEXT_UNVERIFIED' for c in checks):
            raise RuntimeError('Tokenizer must be verified before smoke')
        if all(c['allowed'] for c in checks): low=mid
        else: high=mid-1
    fixtures=[('small',payload('Get-Date')),('near_limit',payload('Write-Output "demo"; '*low))]
    results=[]
    for meta in metadata:
        for name,sample in fixtures:
            result=runtime.analyze(meta,sample,settings)
            results.append({'synthetic':True,'fixture':name,'result':result})
            (root/'model-smoke.json').write_text(canonical(results),encoding='utf-8')
            print(meta['model'],name,result['label'],result['technical_error'],flush=True)
            if runtime.degraded:
                raise RuntimeError('Inference degraded; stopped without loading another model')
        runtime.unload()
    client.close()
    return results


if __name__=='__main__':
    smoke()
