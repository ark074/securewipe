#!/usr/bin/env python3
import argparse, os
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
parser = argparse.ArgumentParser()
parser.add_argument('--out-dir', default=os.path.expanduser('~/.securewipe/keys'))
args = parser.parse_args()
os.makedirs(args.out_dir, exist_ok=True)
sk = SigningKey.generate()
vk = sk.verify_key
with open(os.path.join(args.out_dir,'ed25519_sk.hex'),'w') as f: f.write(sk.encode(encoder=HexEncoder).decode())
with open(os.path.join(args.out_dir,'ed25519_pk.hex'),'w') as f: f.write(vk.encode(encoder=HexEncoder).decode())
print('Keys written to', args.out_dir)
