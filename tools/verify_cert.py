#!/usr/bin/env python3
import argparse, json, os, sys
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
parser = argparse.ArgumentParser()
parser.add_argument('--cert', required=True)
parser.add_argument('--pubkey', default=os.path.expanduser('~/.securewipe/keys/ed25519_pk.hex'))
args = parser.parse_args()
cert = json.load(open(args.cert))
if 'signature' not in cert or 'hex' not in cert['signature']:
    print('No signature found'); sys.exit(2)
sig = cert['signature']['hex']
payload = dict(cert); del payload['signature']
payload_bytes = json.dumps(payload, separators=(',',':')).encode()
if not os.path.exists(args.pubkey):
    print('Public key missing:', args.pubkey); sys.exit(3)
vk = VerifyKey(open(args.pubkey).read().strip(), encoder=HexEncoder)
try:
    vk.verify(payload_bytes, bytes.fromhex(sig))
    print('Signature valid'); print(json.dumps(payload, indent=2))
except Exception as e:
    print('Verification failed:', e); sys.exit(4)
