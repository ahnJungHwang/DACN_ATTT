import urllib.request, urllib.error

data = b'{"client_id": "test", "hostname": "TEST", "security_xml": "", "powershell_xml": "", "model": "qwen"}'
req = urllib.request.Request('http://localhost:5678/webhook/windows-log', data=data, headers={'Content-Type': 'application/json'})

try:
    resp = urllib.request.urlopen(req, timeout=15)
    print("PROD WEBHOOK SUCCESS:", resp.getcode(), resp.read().decode())
except urllib.error.HTTPError as e:
    print("PROD HTTPError:", e.code, e.read().decode())
except Exception as e:
    print("PROD Err:", e)

