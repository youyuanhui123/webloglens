"""Run controlled loopback Nginx experiments using an already local Docker image."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import uuid

from webloglens.nginx_lab import run_experiment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='nginx:alpine', help='local image only; never pulls')
    parser.add_argument('--output', help='new evidence directory; refuses reuse')
    args = parser.parse_args()
    output = Path(args.output) if args.output else (Path(__file__).resolve().parent / 'experiments' /
        ('nginx-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8]))
    result = run_experiment(output, image=args.image)
    print(json.dumps(dict(output=str(output.resolve()), verified=result['verified'],
        image_id=result['image_id'], scenarios=[dict(name=s['name'], actual=s['actual'],
        matched_live_replay=s['matched_live_replay'], cleanup=s['cleanup'])
        for s in result['scenarios']]), indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f'Nginx experiment failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
