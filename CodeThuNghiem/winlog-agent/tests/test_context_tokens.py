import pytest
from app.config import MODELS
from app.context_tokens import TEMPLATES, render
from app.gguf_tokenizer import read_metadata
from app.context_tokens import ContextGuard, implementation_fingerprint
from app.config import Settings
from app.storage import canonical, digest


def test_template_locked_and_no_unsupported_messages():
    messages = [{'role':'system','content':'rules'}, {'role':'user','content':'evidence'}]
    assert render(MODELS[0],messages,TEMPLATES[MODELS[0]]).startswith('<|im_start|>system\nrules')
    assert 'Cutting Knowledge Date' in render(MODELS[1],messages,TEMPLATES[MODELS[1]])
    with pytest.raises(ValueError, match='CONTEXT_UNVERIFIED'):
        render(MODELS[0],messages,'changed')
    with pytest.raises(ValueError, match='CONTEXT_UNVERIFIED'):
        render(MODELS[0],messages + [{'role':'assistant','content':'x'}],TEMPLATES[MODELS[0]])


def test_truncated_gguf_rejected(tmp_path):
    path = tmp_path / 'invalid.gguf'
    path.write_bytes(b'GGUF')
    with pytest.raises(ValueError, match='Truncated'):
        read_metadata(path)


def test_preflight_missing_changed_and_boundaries(tmp_path, monkeypatch):
    meta = dict(model=MODELS[0],digest='test',template_sha256=TEMPLATES[MODELS[0]],ollama_version='test')
    messages = [{'role':'system','content':'rules'},{'role':'user','content':'evidence'}]
    guard = ContextGuard(tmp_path)
    assert guard.check(meta,messages,Settings())['error'] == 'CONTEXT_UNVERIFIED'
    path = tmp_path/'qwen2.5.json'
    path.write_text('{}')
    record = dict(metadata=meta,verified=True,implementation_sha256=implementation_fingerprint(),tokenizer_sha256=digest(path.read_bytes()))
    (tmp_path/'verification.json').write_text(canonical([record]))
    class Counter:
        count = 3328
        def __init__(self, path): pass
        def encode(self, text): return [0]*self.count
    monkeypatch.setattr('app.context_tokens.ByteBPE',Counter)
    assert guard.check(meta,messages,Settings())['allowed']
    Counter.count += 1
    assert guard.check(meta,messages,Settings())['error'] == 'INPUT_TOO_LARGE'
    assert guard.check(dict(meta,digest='changed'),messages,Settings())['error'] == 'CONTEXT_UNVERIFIED'
    path.write_text('changed')
    assert guard.check(meta,messages,Settings())['error'] == 'CONTEXT_UNVERIFIED'
