#!/usr/bin/env python3
import sys, json, base64, hashlib
from pathlib import Path
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    print("cryptography package required", file=sys.stderr)
    sys.exit(2)

def canonical_payload(att):
    # Remove signature block then canonicalize
    data = {k:v for k,v in att.items() if k != 'signature'}
    return json.dumps(data, sort_keys=True, separators=(',',':')).encode('utf-8')

def verify(path:Path):
    att = json.loads(path.read_text('utf-8'))
    if 'signature' not in att:
        print('Missing signature block', file=sys.stderr)
        return 1
    sigblk = att['signature']
    for f in ('alg','value_b64','pubkey_b64'):
        if f not in sigblk:
            print(f'Missing signature field {f}', file=sys.stderr)
            return 1
    if sigblk['alg'] != 'ed25519':
        print('Unsupported alg', file=sys.stderr)
        return 1
    pub = base64.b64decode(sigblk['pubkey_b64'])
    sig = base64.b64decode(sigblk['value_b64'])
    pk = Ed25519PublicKey.from_public_bytes(pub)
    try:
        pk.verify(sig, canonical_payload(att))
    except Exception:
        print('FAIL: signature invalid', file=sys.stderr)
        return 1
    print('OK: signature valid')
    return 0

if __name__ == '__main__':
    if len(sys.argv)!=2:
        print('usage: carnot-verify.py <attestation.json>', file=sys.stderr)
        sys.exit(2)
    sys.exit(verify(Path(sys.argv[1])))
