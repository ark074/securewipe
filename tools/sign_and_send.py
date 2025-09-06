#!/usr/bin/env python3
import argparse, json, os, sys, requests
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from reportlab.pdfgen import canvas
parser = argparse.ArgumentParser()
parser.add_argument('--cert', required=True)
parser.add_argument('--email', required=True)
parser.add_argument('--smtp-config', default=os.path.expanduser('~/.securewipe/smtp.json'))
parser.add_argument('--submit-url', default=None)
args = parser.parse_args()
with open(args.cert,'r') as f: cert = json.load(f)
sk_path = os.path.expanduser('~/.securewipe/keys/ed25519_sk.hex')
if not os.path.exists(sk_path):
    print('Signing key not found:', sk_path, file=sys.stderr); sys.exit(2)
with open(sk_path,'r') as f: sk_hex = f.read().strip()
sk = SigningKey(sk_hex, encoder=HexEncoder)
payload = json.dumps(cert, separators=(',',':')).encode()
sig = sk.sign(payload).signature.hex()
cert_signed = dict(cert); cert_signed['signature'] = {'alg':'Ed25519','hex':sig}
out_json = args.cert.replace('.json','-signed.json')
with open(out_json,'w') as f: json.dump(cert_signed,f,indent=2)
# PDF with pyhanko could be used; for simplicity create visual PDF with reportlab
pdf_path = out_json.replace('.json','.pdf')
c = canvas.Canvas(pdf_path)
c.setFont('Helvetica',10)
c.drawString(40,800,'SecureWipe Certificate')
c.drawString(40,780,'ID: '+cert_signed.get('id',''))
c.drawString(40,760,'Device: '+cert_signed.get('device',''))
c.drawString(40,740,'Profile: '+cert_signed.get('profile',''))
c.drawString(40,720,'Method: '+cert_signed.get('method',''))
c.drawString(40,700,'Timestamp: '+str(cert_signed.get('timestamp','')))
c.drawString(40,680,'Hash: '+cert_signed.get('hash','')[:64])
c.showPage(); c.save()
# send email if config present
if os.path.exists(args.smtp_config):
    cfg = json.load(open(args.smtp_config))
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg['Subject'] = f"SecureWipe Certificate {cert_signed.get('id')}"
    msg['From'] = cfg.get('from')
    msg['To'] = args.email
    msg.set_content('Attached: JSON and PDF certificate.')
    with open(out_json,'rb') as f: msg.add_attachment(f.read(), maintype='application', subtype='json', filename=os.path.basename(out_json))
    with open(pdf_path,'rb') as f: msg.add_attachment(f.read(), maintype='application', subtype='pdf', filename=os.path.basename(pdf_path))
    s = smtplib.SMTP(cfg['host'], cfg.get('port',587)); s.starttls(); s.login(cfg['user'], cfg['pass']); s.send_message(msg); s.quit()
    print('Email sent to', args.email)
else:
    print('No SMTP config; created:', out_json, pdf_path)
# optionally submit to verifier
if args.submit_url:
    try:
        resp = requests.post(args.submit_url, json=cert_signed, timeout=10)
        print('Submitted to verifier:', resp.status_code, resp.text)
    except Exception as e:
        print('Submit failed:', e)
