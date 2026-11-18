"""Controlled Nginx experiment; no real sensitive files, loopback host ports only."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, ProxyHandler, build_opener
import uuid

CONFIG = '''worker_processes 1;
error_log /evidence/error.log notice;
pid /tmp/nginx.pid;
events { worker_connections 128; }
http {
    access_log /evidence/access.log combined;
    server {
        listen 8080;
        default_type text/plain;
        location = /ready { access_log off; return 200 "ready\\n"; }
        location = /.env { return 404 "not present in this lab\\n"; }
        location = /.git/config { return 404 "not present in this lab\\n"; }
        location / { return 200 "fixed local experiment response\\n"; }
    }
}
'''


def prepare_files(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    config = directory / 'nginx.conf'
    config.write_text(CONFIG, encoding='utf-8')
    log = directory / 'access.log'
    log.write_bytes(b'')
    return {'config': config, 'log': log}


SCENARIOS = {
    'baseline': (['/', '/health', '/', '/health', '/', '/health'],
                 {'sensitive_paths': 0, 'windows': 0}),
    'mixed': (['/', '/.env', '/.git/config?download=1', '/login', '/help', '/help'],
              {'sensitive_paths': 2, 'windows': 1}),
    'normal-wide': (['/', '/help', '/docs', '/about', '/contact'],
                    {'sensitive_paths': 0, 'windows': 1}),
}
PROJECT = Path(__file__).resolve().parents[1]


def _save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True), encoding='utf-8')


def _docker(*arguments, check=True):
    completed = subprocess.run(['docker', *arguments], capture_output=True,
                               text=True, encoding='utf-8', errors='replace', timeout=30)
    if check and completed.returncode:
        raise RuntimeError('docker ' + ' '.join(arguments[:2]) + ': ' + completed.stderr)
    return completed


def _events(path):
    if not path.exists():
        return []
    # During startup only complete JSONL lines are available for decoding.
    return [json.loads(line) for line in path.read_bytes().split(b'\n')[:-1] if line]


def _comparable(value):
    if isinstance(value, dict):
        return {k: _comparable(v) for k, v in value.items()
                if k not in ('observed_at', 'line_number')}
    if isinstance(value, list):
        return [_comparable(v) for v in value]
    return value


def _request(opener, base, target):
    sent_at = datetime.now(timezone.utc).isoformat()
    try:
        response = opener.open(Request(base + target,
            headers={'User-Agent': 'WebLogLens-NginxLab/2'}), timeout=2)
    except HTTPError as exc:
        response = exc
    with response:
        return dict(target=target, method='GET', sent_at=sent_at,
                    received_at=datetime.now(timezone.utc).isoformat(),
                    status=response.code, body=response.read(4096).decode('utf-8'))


def _port_released(port):
    # Windows connect timeout may yield WSAEWOULDBLOCK even after removal.
    # Successful exclusive local binding directly verifies the host port is free.
    with socket.socket() as probe:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(('127.0.0.1', port))
        except OSError:
            return False
    return True


def _listeners_for_port(port, text):
    result = []
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == 'TCP':
            if len(fields) != 5:
                raise RuntimeError('Unrecognized Windows netstat TCP row')
            if fields[1].rsplit(':', 1)[-1] == str(port) and fields[3] == 'LISTENING':
                result.append(line.strip())
    return result


def _host_port_check(port):
    released = _port_released(port)
    if os.name != 'nt':
        return dict(port_closed=released, host_port_released=released,
                    port_check='local_bind', port=port)
    probe = subprocess.run(['netstat.exe', '-ano', '-p', 'tcp'],
                           capture_output=True, text=True, errors='replace', timeout=10)
    if probe.returncode:
        raise RuntimeError('Cannot verify host listeners with netstat')
    listeners = _listeners_for_port(port, probe.stdout)
    rows = [line.strip() for line in probe.stdout.splitlines()
            if line.split() and line.split()[0] == 'TCP'
            and line.split()[1].rsplit(':', 1)[-1] == str(port)]
    return dict(port_closed=not listeners, host_port_released=released, port=port,
                port_check='windows_tcp_listener_table', listeners=listeners, local_port_rows=rows)


def _scenario(root, name, image_id, config):
    folder = root / name
    files = prepare_files(folder)
    targets, expected = SCENARIOS[name]
    token = uuid.uuid4().hex
    container = 'webloglens-nginx-' + token[:12]
    watcher = None
    port = None
    requests = []
    cleanup = {}
    result = dict(name=name, expected=expected, request_count=len(targets), verified=False)
    opener = build_opener(ProxyHandler({}))
    try:
        created = _docker('create', '--name', container,
            '--label', 'webloglens.experiment=' + token,
            '--pull=never', '--publish', '127.0.0.1::8080',
            '--mount', f'type=bind,source={folder},target=/evidence',
            '--memory', '128m', '--cpus', '1', '--pids-limit', '64',
            '--security-opt', 'no-new-privileges:true',
            image_id, 'nginx', '-c', '/evidence/nginx.conf', '-g', 'daemon off;')
        result['container_id'] = created.stdout.strip()
        _docker('start', container)
        metadata = json.loads(_docker('inspect', container).stdout)[0]
        _save(folder / 'container.json', metadata)
        bindings = metadata['NetworkSettings']['Ports']['8080/tcp']
        if len(bindings) != 1 or bindings[0]['HostIp'] != '127.0.0.1':
            raise RuntimeError('Experiment port was not restricted to IPv4 loopback')
        port = int(bindings[0]['HostPort'])
        base = 'http://127.0.0.1:' + str(port)
        result['url'] = base
        deadline = time.monotonic() + 10
        while True:
            try:
                ready = _request(opener, base, '/ready')
                if ready['status'] == 200 and ready['body'] == 'ready\n':
                    break
            except (URLError, OSError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('Nginx failed readiness HTTP check')
            time.sleep(0.05)
        version = _docker('exec', container, 'nginx', '-v')
        result['nginx_version'] = (version.stdout + version.stderr).strip()
        checked = _docker('exec', container, 'nginx', '-t', '-c', '/evidence/nginx.conf')
        (folder / 'nginx-config-test.txt').write_text(checked.stdout + checked.stderr, encoding='utf-8')
        # No health request is logged. Start following the empty genuine Nginx log.
        with (folder / 'watch-stdout.jsonl').open('x', encoding='utf-8') as stdout, \
                (folder / 'watch-stderr.txt').open('x', encoding='utf-8') as stderr:
            command = [sys.executable, str(PROJECT / 'watch.py'), str(files['log']),
                '--detect', '--start', 'end', '--config', str(config),
                '--lateness-seconds', '0', '--cooldown-seconds', '60',
                '--interval', '0.02', '--duration', '5',
                '--output', str(folder / 'live.jsonl')]
            _save(folder / 'watch-command.json', command)
            watcher = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + 3
            while not _events(folder / 'live.jsonl'):
                if watcher.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Watcher failed startup; see watch-stderr.txt')
                time.sleep(0.02)
            if _events(folder / 'live.jsonl')[0]['type'] != 'started':
                raise RuntimeError('Watcher startup event missing')
            for target in targets:
                response = _request(opener, base, target)
                requests.append(response)
                expected_status = 404 if target.split('?', 1)[0] in ('/.env', '/.git/config') else 200
                if response['status'] != expected_status:
                    raise RuntimeError('Unexpected Nginx response: ' + target)
            watcher.wait(timeout=12)
            if watcher.returncode:
                raise RuntimeError('Watcher failed; see watch-stderr.txt')
    finally:
        if watcher is not None and watcher.poll() is None:
            watcher.terminate()
            try:
                watcher.wait(timeout=3)
            except subprocess.TimeoutExpired:
                watcher.kill()
                watcher.wait(timeout=3)
        _save(folder / 'requests.json', requests)
        # Only remove the uniquely named container if its ownership label matches.
        inspected = _docker('inspect', container, check=False)
        if inspected.returncode == 0:
            owner = json.loads(inspected.stdout)[0]['Config']['Labels'].get('webloglens.experiment')
            if owner != token:
                raise RuntimeError('Refusing cleanup of container without matching ownership label')
            logs = _docker('logs', container, check=False)
            (folder / 'container-console.txt').write_text(logs.stdout + logs.stderr, encoding='utf-8')
            _docker('rm', '-f', container)
        remaining = _docker('ps', '-a', '--filter', 'name=^/' + container + '$', '--format', '{{.ID}}')
        cleanup['container_removed'] = not remaining.stdout.strip()
        if port is not None:
            with socket.socket() as connection:
                connection.settimeout(1)
                code = connection.connect_ex(('127.0.0.1', port))
            checked = _host_port_check(port)
            deadline = time.monotonic() + 3
            while not checked['port_closed'] and time.monotonic() < deadline:
                time.sleep(0.05)
                checked = _host_port_check(port)
            cleanup.update(checked, connect_code=code)
        result['cleanup'] = cleanup
        _save(folder / 'cleanup.json', cleanup)
    # Nginx is removed: the log is now static for replay and hashing.
    replay = subprocess.run([sys.executable, str(PROJECT / 'watch.py'), str(files['log']),
        '--replay', '--config', str(config), '--lateness-seconds', '0',
        '--cooldown-seconds', '60', '--output', str(folder / 'replay.jsonl')],
        capture_output=True, text=True, encoding='utf-8', timeout=15)
    (folder / 'replay-stderr.txt').write_text(replay.stderr, encoding='utf-8')
    if replay.returncode:
        raise RuntimeError('Replay failed: ' + replay.stderr)
    live = _events(folder / 'live.jsonl')
    replay_events = _events(folder / 'replay.jsonl')
    live_findings = [e for e in live if e['type'] == 'finding']
    replay_findings = [e for e in replay_events if e['type'] == 'finding']
    records = [e for e in live if e['type'] == 'record']
    summary = live[-1]
    analysis = summary['analysis']
    actual = dict(sensitive_paths=analysis.get('path_findings', 0),
                  windows=analysis.get('window_findings', 0))
    matched = _comparable(live_findings) == _comparable(replay_findings)
    errors = [e for e in live if e['type'] in
              ('parse_error', 'decode_error', 'time_error', 'late_record', 'state_limit')]
    result.update(actual=actual, matched_live_replay=matched,
                  log_sha256=hashlib.sha256(files['log'].read_bytes()).hexdigest(),
                  analysis=analysis, input_kind='controlled_real_nginx_http',
                  log_path=name + '/access.log')
    result['verified'] = (actual == expected and matched and not errors
        and summary['type'] == 'summary' and analysis['records'] == len(targets)
        and [e['fields']['target'] for e in records] == targets
        and all(e['fields']['user_agent'] == 'WebLogLens-NginxLab/2' for e in records)
        and cleanup.get('container_removed') and cleanup.get('port_closed'))
    _save(folder / 'verification.json', result)
    if not result['verified']:
        raise RuntimeError('Scenario verification failed: ' + name)
    return result


def run_experiment(directory, image='nginx:alpine'):
    root = Path(directory).resolve()
    # No pulling, installing, global daemon changes or touching other containers.
    _docker('version', '--format', '{{.Server.Version}}')
    metadata = json.loads(_docker('image', 'inspect', image).stdout)[0]
    root.mkdir(parents=True, exist_ok=False)
    _save(root / 'image.json', {key: metadata.get(key) for key in
                              ('Id', 'RepoTags', 'RepoDigests', 'Os', 'Architecture')})
    config = root / 'experiment-config.json'
    _save(config, dict(sensitive_paths=['/.env', '/.git/config'], window_seconds=60, min_paths=5))
    result = dict(image_id=metadata['Id'], image_requested=image, scenarios=[], verified=False)
    try:
        for name in SCENARIOS:
            result['scenarios'].append(_scenario(root, name, metadata['Id'], config))
        result['verified'] = all(item['verified'] for item in result['scenarios'])
    except BaseException as exc:
        result['error'] = str(exc)
        raise
    finally:
        _save(root / 'summary.json', result)
    return result
