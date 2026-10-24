"""Offline byte BPE from local GGUF metadata; no model tensors are loaded."""
import json
from pathlib import Path
import struct
import regex
from .storage import canonical, digest


def read_metadata(path):
    with Path(path).open('rb') as f:
        def unpack(fmt):
            size = struct.calcsize('<' + fmt)
            raw = f.read(size)
            if len(raw) != size:
                raise ValueError('Truncated GGUF')
            return struct.unpack('<' + fmt, raw)[0]
        def string():
            size = unpack('Q')
            if size > 64 * 1024 * 1024:
                raise ValueError('GGUF metadata string too large')
            raw = f.read(size)
            if len(raw) != size:
                raise ValueError('Truncated GGUF string')
            return raw.decode('utf-8')
        def value(kind, depth=0):
            if depth > 2:
                raise ValueError('Nested GGUF array')
            scalar = {0:'B',1:'b',2:'H',3:'h',4:'I',5:'i',6:'f',7:'?',10:'Q',11:'q',12:'d'}
            if kind in scalar:
                return unpack(scalar[kind])
            if kind == 8:
                return string()
            if kind == 9:
                subtype, count = unpack('I'), unpack('Q')
                if count > 1000000:
                    raise ValueError('GGUF metadata array too large')
                return [value(subtype, depth+1) for _ in range(count)]
            raise ValueError('Unsupported GGUF type')
        if f.read(4) != b'GGUF' or unpack('I') not in (2,3):
            raise ValueError('Unsupported GGUF header')
        unpack('Q')  # tensor count: weights are deliberately not read
        count = unpack('Q')
        if count > 10000:
            raise ValueError('Too many metadata fields')
        result = {}
        for _ in range(count):
            key = string()
            result[key] = value(unpack('I'))
        return {k:v for k,v in result.items() if k.startswith('tokenizer.')}


def export_tokenizer(blob, destination):
    metadata = read_metadata(blob)
    text = canonical(metadata)
    Path(destination).write_text(text, encoding='utf-8')
    return digest(text.encode())


class ByteBPE:
    def __init__(self, path):
        self.meta = json.loads(Path(path).read_text(encoding='utf-8'))
        m = self.meta
        if m.get('tokenizer.ggml.model') != 'gpt2' or m.get('tokenizer.ggml.pre') not in ('qwen2','llama-bpe'):
            raise ValueError('Unsupported tokenizer algorithm')
        self.vocab = {text:i for i,text in enumerate(m['tokenizer.ggml.tokens'])}
        self.ranks = {tuple(pair.split(' ')): i for i,pair in enumerate(m['tokenizer.ggml.merges'])}
        types = m['tokenizer.ggml.token_type']
        self.special = {text:i for text,i in self.vocab.items() if types[i] in (3,4)}
        self.special_pattern = regex.compile('(' + '|'.join(regex.escape(t) for t in sorted(self.special,key=len,reverse=True)) + ')')
        numeric = r'\p{N}' if m['tokenizer.ggml.pre'] == 'qwen2' else r'\p{N}{1,3}'
        self.pattern = regex.compile(r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|" + numeric + r'| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+')
        values = list(range(33,127)) + list(range(161,173)) + list(range(174,256))
        chars = values.copy()
        for b in range(256):
            if b not in values:
                values.append(b)
                chars.append(256 + len(chars) - 188)
        self.byte_chars = dict(zip(values, map(chr, chars)))
        self.cache = {}

    def encode(self, text):
        ids = []
        if self.meta.get('tokenizer.ggml.add_bos_token', self.meta['tokenizer.ggml.pre'] == 'llama-bpe'):
            ids.append(self.meta['tokenizer.ggml.bos_token_id'])
        for fragment in self.special_pattern.split(text):
            if fragment in self.special:
                ids.append(self.special[fragment])
                continue
            for piece in self.pattern.findall(fragment):
                if piece not in self.cache:
                    symbols = [self.byte_chars[b] for b in piece.encode('utf-8')]
                    word = ''.join(symbols)
                    if self.meta['tokenizer.ggml.pre'] == 'llama-bpe' and word in self.vocab:
                        symbols = [word]
                    while len(symbols) > 1:
                        best = min(range(len(symbols)-1), key=lambda i: self.ranks.get((symbols[i],symbols[i+1]), float('inf')))
                        if (symbols[best],symbols[best+1]) not in self.ranks:
                            break
                        symbols[best:best+2] = [symbols[best]+symbols[best+1]]
                    self.cache[piece] = [self.vocab[s] for s in symbols]
                ids.extend(self.cache[piece])
        if self.meta.get('tokenizer.ggml.add_eos_token', False):
            ids.append(self.meta['tokenizer.ggml.eos_token_id'])
        return ids
