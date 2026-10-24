"""Validated local inference; the service worker is responsible for serialization."""
import json
import time
from typing import Literal
from pydantic import BaseModel, ConfigDict, field_validator
from .ollama import OllamaError


class Verdict(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    label: Literal['NORMAL','ALERT','UNKNOWN']
    reason: str
    evidence_refs: list[str]

    @field_validator('reason')
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError('Blank reason')
        return value


def validate_output(raw, reference_map):
    def unique_pairs(pairs):
        obj = {}
        for k,v in pairs:
            if k in obj:
                raise ValueError('Duplicate JSON key')
            obj[k] = v
        return obj
    verdict = Verdict.model_validate(json.loads(raw,object_pairs_hook=unique_pairs))
    if any(ref not in reference_map for ref in verdict.evidence_refs):
        raise ValueError('Unknown evidence reference')
    if verdict.label == 'ALERT' and not verdict.evidence_refs:
        raise ValueError('Alert requires evidence')
    result = verdict.model_dump()
    result['evidence_refs'] = [reference_map[r] for r in verdict.evidence_refs]
    return result


class Inference:
    def __init__(self, client, guard):
        self.client, self.guard = client, guard
        self.owned_model = None
        self.degraded = False

    def loaded(self):
        return self.client.request('GET','/api/ps').get('models', [])

    def unload(self):
        if self.owned_model is None:
            return
        model = self.owned_model
        self.client.request('POST','/api/generate', timeout=300,
                            json={'model':model,'stream':False,'keep_alive':0})
        for _ in range(30):
            if not any(m.get('name',m.get('model')) == model for m in self.loaded()):
                self.owned_model = None
                return
            time.sleep(1)
        self.degraded = True
        raise OllamaError('UNLOAD_UNCONFIRMED')

    def load(self, model):
        if self.degraded:
            raise OllamaError('SERVICE_DEGRADED')
        external = [m for m in self.loaded() if m.get('name',m.get('model')) != self.owned_model]
        if external:
            raise OllamaError('EXTERNAL_MODEL_LOADED')
        if self.owned_model and self.owned_model != model:
            self.unload()
        if self.owned_model != model:
            self.owned_model = model
            try:
                self.client.request('POST','/api/generate', timeout=300,
                                    json={'model':model,'stream':False,'keep_alive':'5m'})
            except OllamaError:
                self.degraded = True
                raise

    def analyze(self, metadata, payload, settings):
        started = time.perf_counter()
        preflight = self.guard.check(metadata,payload['messages'],settings)
        base = {'metadata':metadata,'payload':payload,'options':{'temperature':settings.temperature,
                'num_ctx':settings.num_ctx,'num_predict':settings.num_predict},'preflight':preflight,
                'raw_output':None,'response':None,'technical_error':None}
        def failure(code):
            base.update(label='UNKNOWN',reason='Analysis unavailable: '+code,evidence_refs=[],technical_error=code)
        if not preflight['allowed']:
            failure(preflight['error'])
        else:
            try:
                self.load(metadata['model'])
                response = self.client.request('POST','/api/chat',timeout=settings.inference_timeout_seconds,
                    json={'model':metadata['model'],'messages':payload['messages'],'format':payload['format'],
                          'stream':False,'keep_alive':'5m','options':base['options']})
                base['response'] = response
                base['raw_output'] = response.get('message',{}).get('content')
                if response.get('done') is not True or response.get('done_reason') == 'length':
                    raise ValueError('Incomplete response')
                base.update(validate_output(base['raw_output'],payload['reference_map']))
            except OllamaError as exc:
                # A timeout/disconnect may leave inference running. Keep the gate closed.
                self.degraded = True
                failure(str(exc))
            except (ValueError,TypeError,KeyError):
                failure('INVALID_MODEL_OUTPUT')
        base['wall_seconds'] = time.perf_counter()-started
        return base
