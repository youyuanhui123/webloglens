"""Bounded loopback-only HTTP experiments; never serve filesystem content."""

from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from threading import Thread

SCENARIOS = {
    'baseline': ['/', '/help', '/login', '/', '/help', '/login'],
    'mixed': ['/', '/help', '/login', '/.env', '/.git/config', '/admin'],
    'normal-wide': ['/', '/help', '/login', '/about', '/contact'],
}
PUBLIC_ROUTES = {'/', '/help', '/login', '/about', '/contact'}
MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
          'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def run_local_experiment(output_dir, scenario='mixed'):
    """Create a NEW evidence directory; issue real local GETs; close server."""
    if scenario not in SCENARIOS:
        raise ValueError('Unknown experiment scenario')
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    requests = []
    with (output_dir / 'access.log').open('x', encoding='utf-8', newline='\n') as log:
        class LabHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split('?', 1)[0]
                code = 200 if path in PUBLIC_ROUTES else 404
                body = (b'Local lab public test page\n' if code == 200
                        else b'Local lab: no such resource\n')
                self.send_response(code)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_request(self, code='-', size='-'):
                now = datetime.now(timezone.utc)
                stamp = (f'{now.day:02d}/{MONTHS[now.month - 1]}/{now.year:04d}:'
                         f'{now:%H:%M:%S} +0000')
                request = json.dumps(self.requestline, ensure_ascii=True)
                referer = json.dumps(self.headers.get('Referer', '-'), ensure_ascii=True)
                agent = json.dumps(self.headers.get('User-Agent', '-'), ensure_ascii=True)
                # Base send_response logs before body transmission: size is unknown (-).
                log.write(f'{self.client_address[0]} - - [{stamp}] '
                          f'{request} {code} {size} {referer} {agent}\n')
                log.flush()

            def log_message(self, format, *args):
                # Keep stderr quiet; only explicit access logging above is used.
                pass

        with HTTPServer(('127.0.0.1', 0), LabHandler) as server:
            port = server.server_address[1]
            thread = Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
            thread.start()
            try:
                for target in SCENARIOS[scenario]:
                    connection = HTTPConnection('127.0.0.1', port, timeout=5)
                    try:
                        connection.request('GET', target, headers={'User-Agent': 'WebLogLens-LocalLab/1.0'})
                        response = connection.getresponse()
                        body = response.read()
                        requests.append({
                            'target': target, 'status': response.status,
                            'body_bytes': len(body),
                            'received_at_utc': datetime.now(timezone.utc).isoformat(),
                        })
                    finally:
                        connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)
                if thread.is_alive():
                    raise RuntimeError('Experiment server thread failed to stop')
    manifest = {
        'data_kind': 'local-experiment', 'scenario': scenario,
        'server_implementation': 'Python stdlib HTTPServer with custom combined-format logger; NOT Nginx',
        'server_host': '127.0.0.1', 'server_port': port,
        'started_at_utc': started, 'finished_at_utc': datetime.now(timezone.utc).isoformat(),
        'requests': requests,
        'server_closed': True,
        'safety': 'Fixed text responses only; no filesystem serving, authentication or sensitive files.',
    }
    with (output_dir / 'manifest.json').open('x', encoding='utf-8') as file:
        json.dump(manifest, file, ensure_ascii=False, indent=2)
        file.write('\n')
    return manifest
