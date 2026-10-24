import httpx
import pytest
from app.config import MODELS
from app.ollama import Ollama, OllamaError


def test_local_metadata_and_missing_model():
    def handler(request):
        data = {'/api/version': {'version':'test'}, '/api/tags': {'models':[{'name':MODELS[0],'digest':'test-digest'}]},
                '/api/show': {'template':'test template','model_info':{}}}[request.url.path]
        return httpx.Response(200, json=data)
    client = Ollama(transport=httpx.MockTransport(handler))
    assert client.inspect(MODELS[0])['digest'] == 'test-digest'
    with pytest.raises(OllamaError, match='MODEL_MISSING'):
        client.inspect(MODELS[1])
    client.close()


def test_no_external_url_redirect_or_fallback():
    with pytest.raises(ValueError):
        Ollama('https://external.example')
    calls=[]
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={'Location':'https://external.example'})
    client = Ollama(transport=httpx.MockTransport(handler))
    with pytest.raises(OllamaError):
        client.inspect(MODELS[0])
    assert calls == ['http://127.0.0.1:11434/api/version']
    with pytest.raises(ValueError):
        client.inspect('unapproved')
    client.close()


def test_connection_error():
    def handler(request):
        raise httpx.ConnectError('offline')
    client = Ollama(transport=httpx.MockTransport(handler))
    with pytest.raises(OllamaError):
        client.inspect(MODELS[0])
    client.close()
