"""Prepare tokenizer metadata from verified local Ollama blobs; never downloads."""
import argparse
import hashlib
import json
from pathlib import Path
from .config import MODELS
from .gguf_tokenizer import export_tokenizer
from .ollama import Ollama
from .storage import canonical, digest


def file_hash(path):
    sha = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            sha.update(chunk)
    return sha.hexdigest()


def prepare(models_root, output):
    output.mkdir(parents=True, exist_ok=True)
    client = Ollama()
    provenance = []
    for model in MODELS:
        name, tag = model.split(':')
        manifest_path = models_root / 'manifests/registry.ollama.ai/library' / name / tag
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        metadata = client.inspect(model)
        digests = [l['digest'] for l in manifest['layers'] if l['mediaType'] == 'application/vnd.ollama.image.model']
        if len(digests) != 1:
            raise ValueError('Expected one local GGUF model blob')
        blob_digest = digests[0]
        blob = models_root / 'blobs' / blob_digest.replace(':','-')
        actual = file_hash(blob)
        if 'sha256:' + actual != blob_digest:
            raise ValueError('Local model blob hash mismatch')
        tokenizer_sha = export_tokenizer(blob, output / (name + '.json'))
        provenance.append({'model':model,'metadata':metadata,'manifest_path':str(manifest_path),
                           'manifest_sha256':digest(manifest_path.read_bytes()), 'blob_sha256':actual,
                           'tokenizer_sha256':tokenizer_sha, 'source':'local Ollama GGUF',
                           'algorithm_reference':'https://github.com/ggml-org/llama.cpp/blob/master/src/llama-vocab.cpp'})
    client.close()
    (output / 'provenance.json').write_text(canonical(provenance),encoding='utf-8')
    return provenance


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--models-root', type=Path, default=Path.home()/'.ollama/models')
    parser.add_argument('--output', type=Path, default=Path('data/tokenizers'))
    args = parser.parse_args()
    for record in prepare(args.models_root,args.output):
        print(record['model'],record['tokenizer_sha256'])
