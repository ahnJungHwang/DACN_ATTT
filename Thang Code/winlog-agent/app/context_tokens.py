"""Exact supported two-message templates, pinned by observed template hashes."""
import json
from pathlib import Path
import regex
from .config import MODELS
from .storage import digest
from .gguf_tokenizer import ByteBPE

TEMPLATES = {
    MODELS[0]: 'eb4402837c7829a690fa845de4d7f3fd842c2adee476d5341da8a46ea9255175',
    MODELS[1]: '966de95ca8a62200913e3f8bfbf84c8494536f1b94b49166851e76644e966396',
}


def render(model, messages, template_sha256):
    if TEMPLATES.get(model) != template_sha256:
        raise ValueError('CONTEXT_UNVERIFIED: template changed')
    if len(messages) != 2 or [m['role'] for m in messages] != ['system','user']:
        raise ValueError('CONTEXT_UNVERIFIED: unsupported conversation')
    system, user = [m['content'] for m in messages]
    if model == MODELS[0]:
        return f'<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{user}<|im_end|>\n<|im_start|>assistant\n'
    return ('<|start_header_id|>system<|end_header_id|>\n\nCutting Knowledge Date: December 2023\n\n'
            + system + '<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n'
            + user + '<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n')


def implementation_fingerprint():
    root = Path(__file__).parent
    return digest((root/'context_tokens.py').read_bytes() + (root/'gguf_tokenizer.py').read_bytes()
                  + regex.__version__.encode())


class ContextGuard:
    def __init__(self, root):
        self.root = Path(root)

    def check(self, metadata, messages, settings):
        try:
            records = json.loads((self.root/'verification.json').read_text(encoding='utf-8'))
            record = next(r for r in records if r['metadata']['model'] == metadata['model'])
            if record.get('implementation_sha256') != implementation_fingerprint() or record.get('verified') is not True:
                raise ValueError('Unverified implementation')
            for field in ('model','digest','template_sha256','ollama_version'):
                if record['metadata'][field] != metadata[field]:
                    raise ValueError('Metadata changed')
            path = self.root/(metadata['model'].split(':')[0]+'.json')
            if digest(path.read_bytes()) != record['tokenizer_sha256']:
                raise ValueError('Tokenizer changed')
            count = len(ByteBPE(path).encode(render(metadata['model'],messages,metadata['template_sha256'])))
        except (OSError, ValueError, KeyError, TypeError, StopIteration):
            return {'allowed':False,'error':'CONTEXT_UNVERIFIED','input_tokens':None}
        allowed = count + settings.num_predict + settings.context_reserve <= settings.num_ctx
        return {'allowed':allowed,'error':None if allowed else 'INPUT_TOO_LARGE','input_tokens':count,
                'output_reserve':settings.num_predict,'safety_reserve':settings.context_reserve,
                'num_ctx':settings.num_ctx}
