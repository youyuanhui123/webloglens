"""Assemble an intact finalized rolling run into one new JSONL, from any cwd."""
import sys
from webloglens.output import main

if __name__ == '__main__':
    try:
        raise SystemExit(main(['assemble', *sys.argv[1:]]))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'assemble failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
