"""Loopback-only fake native-money endpoint. Never contacts payment providers."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib.request import urlopen

TOKEN = 'test-finance-token-separate-and-at-least-thirty-two-characters'
calls = []
control = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        self.reply(200, {'calls': calls} if self.path == '/state' else {'ok': True})

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if self.path == '/control':
            control.clear()
            control.update(request)
            self.reply(200, {'ok': True})
            return
        if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
            self.reply(401, {'error': 'unauthorized'})
            return
        with urlopen('http://mock:8090/') as response:
            pve = json.load(response)
        calls.append({'request': request, 'pve': pve})
        if control.get('denyCommand') == request['command']:
            self.reply(409, {'error': 'SECRET-denial-body'})
            return
        if control.get('temporary') or control.get('completeOnce') and request['stage'] == 'complete':
            control.pop('completeOnce', None)
            self.reply(503, {'error': 'SECRET-temporary-body'})
            return
        self.reply(200, {'ok': True, 'paidService': request['account'] is not None,
                         'state': 'done' if request['stage'] == 'complete' else 'prepared'})


HTTPServer(('127.0.0.1', 8091), Handler).serve_forever()
