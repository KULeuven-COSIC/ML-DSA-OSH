"""Read/write test vectors in the line-based hex format used by KAT/ and the testbenches.

Each file holds one value per line (uppercase hex, no prefix); line i of every
file belongs to test vector i. Files are named <Op>_<field>_<44|65|87>.txt.
SigVer_result is a single binary digit: 1 = reject (matches the HW `fail` output),
0 = accept.
"""
import os

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

LEVELS = {44: ML_DSA_44, 65: ML_DSA_65, 87: ML_DSA_87}

FIELDS = {
    'KeyGen': ['seed', 'pk', 'sk'],
    'SigGen': ['sk', 'message', 'mlen', 'ctx', 'ctxlen', 'signature'],
    'SigVer': ['pk', 'message', 'mlen', 'ctx', 'ctxlen', 'signature', 'result'],
}


def _hex(b):
    return b.hex().upper() if b else '0'


def encode(field, value):
    if field in ('mlen', 'ctxlen'):
        return '%X' % value if field == 'mlen' else '%02X' % value
    if field == 'result':
        return '1' if value else '0'
    return _hex(value)


def write(out_dir, op, level, vectors):
    """vectors: list of dicts with the keys in FIELDS[op] (bytes / int / bool)."""
    os.makedirs(out_dir, exist_ok=True)
    for field in FIELDS[op]:
        with open(os.path.join(out_dir, f'{op}_{field}_{level}.txt'), 'w') as f:
            for v in vectors:
                f.write(encode(field, v[field]) + '\n')


def read(in_dir, op, level):
    cols = {}
    for field in FIELDS[op]:
        with open(os.path.join(in_dir, f'{op}_{field}_{level}.txt')) as f:
            cols[field] = [ln.strip() for ln in f if ln.strip()]
    n = len(cols[FIELDS[op][0]])
    out = []
    for i in range(n):
        v = {}
        for field in FIELDS[op]:
            s = cols[field][i]
            if field in ('mlen', 'ctxlen'):
                v[field] = int(s, 16)
            elif field == 'result':
                v[field] = s == '1'
            else:
                v[field] = bytes.fromhex(s if len(s) % 2 == 0 else '0' + s)
        for data, length in (('message', 'mlen'), ('ctx', 'ctxlen')):
            if data in v:  # values are right-aligned; restore exact length
                v[data] = v[data].rjust(v[length], b'\0')[-v[length]:] if v[length] else b''
        out.append(v)
    return out
