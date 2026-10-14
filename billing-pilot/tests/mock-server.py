"""Real engine with persistent FakePVE. No Proxmox credentials or remote calls."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys

sys.path.insert(0, '/tests')
spec = importlib.util.spec_from_file_location('engine', '/backend/engine.py')
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
from test_engine import FakePVE

config = json.loads(Path('/config.json').read_text())
config['template_marker'] = 'proxmox-pilot:v1:template:demo'
pve = FakePVE(config)
saved = Path('/state/pve.json')
if saved.exists():
    value = json.loads(saved.read_text())
    pve.vms = {int(k): v for k,v in value['vms'].items()}
    pve.states = {int(k): v for k,v in value['states'].items()}
    pve.calls = value['calls']

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        self.reply({'clones': sum(c[0] == 'clone' for c in pve.calls), 'vms': pve.vms, 'states': pve.states})

    def do_POST(self):
        e = engine.Engine(config, '/state/engine', '/state/snippets', pve)
        try:
            size = int(self.headers['Content-Length'])
            engine.require(0 < size <= 8192, 'Request too large')
            result = e.handle(json.loads(self.rfile.read(size)))
            response = {'ok': True, 'result': result}
        except (ValueError, OSError, KeyError) as exc:
            response = {'ok': False, 'error': str(exc), 'code': 'refused' if isinstance(exc, engine.Refused) else 'temporary'}
        finally:
            e.db.close()
            saved.write_text(json.dumps({'vms': pve.vms, 'states': pve.states, 'calls': pve.calls}))
        self.reply(response)

HTTPServer(('0.0.0.0', 8090), Handler).serve_forever()
