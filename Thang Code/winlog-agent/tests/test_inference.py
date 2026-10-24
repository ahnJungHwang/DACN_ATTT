import pytest
from app.inference import validate_output, Inference
from app.config import Settings, MODELS


@pytest.mark.parametrize('raw', ['{}','{"label":"BAD","reason":"x","evidence_refs":[]}',
    '{"label":"ALERT","reason":"x","evidence_refs":[]}',
    '{"label":"ALERT","reason":"x","evidence_refs":["E999"]}',
    '{"label":"NORMAL","reason":" ","evidence_refs":[]}',
    '{"label":"NORMAL","reason":"x","evidence_refs":[],"extra":1}',
    '{"label":"NORMAL","label":"ALERT","reason":"x","evidence_refs":["E001"]}',
    '{"label":"NORMAL"'])
def test_invalid_outputs(raw):
    with pytest.raises(ValueError): validate_output(raw,{'E001':'ref'})


def test_valid_reference_mapping():
    assert validate_output('{"label":"ALERT","reason":"observed","evidence_refs":["E001"]}',{'E001':'ref'})['evidence_refs'] == ['ref']


@pytest.mark.parametrize('error',['CONTEXT_UNVERIFIED','INPUT_TOO_LARGE'])
def test_preflight_never_contacts_model(error):
    class Guard:
        def check(self,*args): return {'allowed':False,'error':error}
    class Client:
        def request(self,*args,**kwargs): raise AssertionError('No model call allowed')
    payload={'messages':[],'reference_map':{},'format':{}}
    result=Inference(Client(),Guard()).analyze({},payload,Settings())
    assert result['label']=='UNKNOWN' and result['technical_error']==error


def test_sequential_switch_and_external_model():
    class Client:
        current=[]
        calls=[]
        def request(self,method,path,**kwargs):
            if path=='/api/ps': return {'models':[{'name':m} for m in self.current]}
            body=kwargs['json']; self.calls.append(body)
            self.current=[] if body['keep_alive']==0 else [body['model']]
            return {}
    c=Client(); runner=Inference(c,None)
    runner.load(MODELS[0]); runner.load(MODELS[1])
    assert [call['keep_alive'] for call in c.calls]==['5m',0,'5m']
    runner.unload()
    c.current=['outside-model']
    from app.ollama import OllamaError
    with pytest.raises(OllamaError,match='EXTERNAL_MODEL_LOADED'): runner.load(MODELS[0])
    assert c.current==['outside-model']


def test_invalid_response_saved_and_disconnect_blocks_next_model():
    class Guard:
        def check(self,*args): return {'allowed':True,'input_tokens':100}
    class Client:
        broken=False
        def request(self,method,path,**kwargs):
            if path=='/api/ps': return {'models':[]}
            if path=='/api/chat':
                if self.broken:
                    from app.ollama import OllamaError
                    raise OllamaError('disconnected')
                return {'done':True,'message':{'content':'invalid JSON'}}
            return {}
    c=Client(); runner=Inference(c,Guard())
    payload={'messages':[],'format':{},'reference_map':{}}
    r=runner.analyze({'model':MODELS[0]},payload,Settings())
    assert r['label']=='UNKNOWN' and r['raw_output']=='invalid JSON'
    c.broken=True
    runner.analyze({'model':MODELS[0]},payload,Settings())
    assert runner.degraded
    from app.ollama import OllamaError
    with pytest.raises(OllamaError,match='SERVICE_DEGRADED'): runner.load(MODELS[1])
