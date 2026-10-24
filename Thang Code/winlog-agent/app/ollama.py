"""Local-only metadata adapter. No automatic pull or cloud fallback."""
import httpx
from .config import MODELS
from .storage import digest


class OllamaError(RuntimeError):
    pass


class Ollama:
    def __init__(self, url='http://127.0.0.1:11434', *, transport=None):
        if url != 'http://127.0.0.1:11434':
            raise ValueError('Only the configured local Ollama endpoint is allowed')
        self.client = httpx.Client(base_url=url, timeout=10, trust_env=False,
                                   follow_redirects=False, transport=transport)

    def close(self):
        self.client.close()

    def request(self, method, path, **kwargs):
        try:
            response = self.client.request(method, path, **kwargs)
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                raise ValueError('Expected object')
            return result
        except (httpx.HTTPError, ValueError) as exc:
            raise OllamaError(f'OLLAMA_UNAVAILABLE_OR_INVALID: {type(exc).__name__}') from exc

    def inspect(self, model):
        if model not in MODELS:
            raise ValueError('MODEL_NOT_ALLOWED')
        version = self.request('GET', '/api/version').get('version')
        models = self.request('GET', '/api/tags').get('models', [])
        entry = next((m for m in models if m.get('name') == model or m.get('model') == model), None)
        if entry is None:
            raise OllamaError('MODEL_MISSING: ' + model)
        details = self.request('POST', '/api/show', json={'model': model})
        template = details.get('template')
        model_digest = entry.get('digest')
        if not isinstance(version, str) or not version or not isinstance(template, str) or not template or not isinstance(model_digest, str) or not model_digest:
            raise OllamaError('MODEL_METADATA_MISSING')
        return {'model': model, 'digest': model_digest, 'ollama_version': version,
                'template': template, 'template_sha256': digest(template.encode()),
                'model_info': details.get('model_info', {}), 'parameters': details.get('parameters'),
                'details': details.get('details', {})}
