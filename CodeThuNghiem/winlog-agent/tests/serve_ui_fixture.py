"""Manual browser test server, mock only, loopback port 18081."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uvicorn
from app.api import create_app
from app.config import Settings
from app.service import Service
from app.storage import Store


class MockRuntime:
    degraded=False
    def __init__(self): self.client=self
    def inspect(self,model): return {'model':model,'digest':'mock','template_sha256':'mock','ollama_version':'mock'}
    def unload(self): pass
    def analyze(self,metadata,payload,settings):
        return {'label':'UNKNOWN','reason':'MOCK TEST: <script>window.invalid_execution=true</script>',
                'evidence_refs':list(payload['reference_map'].values()),'technical_error':None,
                'raw_output':'mock only','wall_seconds':0.01,'metadata':metadata,'payload':payload}


if __name__=='__main__':
    settings=Settings(data_root='data/ui-mock')
    store=Store(settings.data_root)
    app=create_app(settings,Service(store,settings,MockRuntime()),'synthetic-ui-token-for-tests-only-0001')
    uvicorn.run(app,host='127.0.0.1',port=18081)
