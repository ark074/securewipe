from flask import Flask, request, render_template, jsonify
import json, os
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
app = Flask(__name__)
PUBKEY = os.environ.get('PUBKEY_CONTENT') or os.path.expanduser('~/.securewipe/keys/ed25519_pk.hex')
@app.route('/', methods=['GET','POST'])
def index():
    result = None
    if request.method=='POST':
        f = request.files.get('certificate')
        if not f:
            result = 'No file uploaded'
        else:
            try:
                cert = json.load(f)
                if 'signature' not in cert:
                    result = 'No signature in certificate'
                else:
                    sig = cert['signature']['hex']
                    payload = dict(cert); del payload['signature']
                    payload_bytes = json.dumps(payload, separators=(',',':')).encode()
                    if os.path.exists(PUBKEY):
                        vk = VerifyKey(open(PUBKEY).read().strip(), encoder=HexEncoder)
                    else:
                        vk = VerifyKey(os.environ.get('PUBKEY_CONTENT').strip(), encoder=HexEncoder)
                    vk.verify(payload_bytes, bytes.fromhex(sig))
                    result = 'Signature valid'
            except Exception as e:
                result = 'Verification failed: '+str(e)
    return render_template('index.html', result=result)
@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.json
    try:
        cert = data
        if 'signature' not in cert:
            return jsonify({'valid':False,'reason':'no signature'}),400
        sig = cert['signature']['hex']
        payload = dict(cert); del payload['signature']
        payload_bytes = json.dumps(payload, separators=(',',':')).encode()
        if os.path.exists(PUBKEY):
            vk = VerifyKey(open(PUBKEY).read().strip(), encoder=HexEncoder)
        else:
            vk = VerifyKey(os.environ.get('PUBKEY_CONTENT').strip(), encoder=HexEncoder)
        vk.verify(payload_bytes, bytes.fromhex(sig))
        return jsonify({'valid':True})
    except Exception as e:
        return jsonify({'valid':False,'reason':str(e)}),400
if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000)
