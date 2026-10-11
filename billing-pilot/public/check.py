"""Verify public TLS, redirects, proxy headers and the actual admin login."""
from pathlib import Path
import http.cookiejar
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BASE = 'https://80.249.131.4/'
context = ssl.create_default_context()
with socket.create_connection(('80.249.131.4', 443), timeout=20) as tcp:
    with context.wrap_socket(tcp, server_hostname='80.249.131.4') as tls:
        cert = tls.getpeercert()
        assert ('IP Address', '80.249.131.4') in cert['subjectAltName']
        certificate = {'expires': cert['notAfter'], 'tls': tls.version(),
                       'issuer': dict(item[0] for item in cert['issuer'])}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


plain = urllib.request.build_opener(NoRedirect())
try:
    plain.open('http://80.249.131.4/admin', timeout=20)
    raise AssertionError('HTTP did not redirect')
except urllib.error.HTTPError as exc:
    assert exc.code == 308 and exc.headers['Location'] == BASE + 'admin'

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                     urllib.request.HTTPSHandler(context=context))
with opener.open(BASE + 'admin/staff/login', timeout=30) as response:
    html = response.read().decode()
    assert response.status == 200 and '127.0.0.1:8088' not in html
assert any(cookie.name == 'fossbilling_csrf' and cookie.secure for cookie in jar)
credentials = json.loads((ROOT / '.secrets/bootstrap.json').read_text())


def request(path, data):
    csrf = next(cookie.value for cookie in jar if cookie.name == 'fossbilling_csrf')
    payload = urllib.parse.urlencode({**data, 'CSRFToken': csrf}).encode()
    req = urllib.request.Request(BASE + path, data=payload,
        headers={'Content-Type': 'application/x-www-form-urlencoded', 'Origin': BASE.rstrip('/')})
    with opener.open(req, timeout=30) as response:
        value = json.loads(response.read())
    assert value.get('error') is None, 'API error: ' + str(value.get('error'))
    return value['result']


admin = request('api/guest/staff/login', {'email': credentials['admin_email'],
                                        'password': credentials['admin_password']})
assert isinstance(admin, dict) and admin['id'] == 1
with opener.open(BASE + 'admin', timeout=30) as response:
    assert response.status == 200 and '/staff/login' not in response.url
    admin_url = response.url
order = request('api/admin/order/get', {'id': 1})
assert order['status'] == 'active'
spoofed = urllib.request.Request(BASE + 'admin/staff/login', headers={
    'Forwarded': 'for=127.0.0.1;host=evil.invalid;proto=http',
    'X-Forwarded-For': '127.0.0.1', 'X-Forwarded-Host': 'evil.invalid',
    'X-Forwarded-Proto': 'http', 'X-Forwarded-Port': '8088',
    'X-Forwarded-Prefix': '/evil'})
with urllib.request.urlopen(spoofed, timeout=30, context=context) as response:
    html = response.read().decode()
    assert response.status == 200
    assert 'evil.invalid' not in html and '127.0.0.1:8088' not in html
for name in ('config.php', 'config.old.php', 'composer.json', '.env'):
    try:
        urllib.request.urlopen(BASE + name, timeout=15, context=context)
        raise AssertionError('Sensitive path exposed: ' + name)
    except urllib.error.HTTPError as exc:
        assert exc.code == 404

proof = {'url': admin_url, 'http_redirect': 308, 'certificate': certificate,
         'admin_id': admin['id'], 'login_http': 200, 'order_id': order['id'],
         'order_status': order['status'], 'secure_csrf_cookie': True,
         'spoofed_headers_ignored': True, 'sensitive_paths': '404'}
path = ROOT / '.state/public-http-login.json'
path.write_text(json.dumps(proof, indent=2, ensure_ascii=False) + '\n')
path.chmod(0o600)
print(json.dumps(proof, indent=2, ensure_ascii=False))
