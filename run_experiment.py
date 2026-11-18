"""Bounded loopback experiments with private evidence and sharing views."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys

from webloglens.local_lab import run_local_experiment

if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description='Loopback HTTP experiments; no external targets')
    parser.add_argument('--output-root', type=Path, default=root / 'experiments' /
                        datetime.now(timezone.utc).strftime('local-%Y%m%dT%H%M%S-%fZ'))
    args = parser.parse_args()
    output_root = args.output_root.resolve()
    try:
        output_root.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        parser.error(f'Cannot create NEW evidence directory: {ascii(str(exc))}')
    # Pin experiment settings independently of user-edited default.json.
    config_path = output_root / 'experiment-config.json'
    config_path.write_text(json.dumps({
        'sensitive_paths': ['/.env', '/.git/config'], 'window_seconds': 60, 'min_paths': 5,
    }, indent=2) + '\n', encoding='utf-8')
    results = []
    expected = {'baseline': (0, 0), 'mixed': (2, 1), 'normal-wide': (0, 1)}
    for scenario, (expected_sensitive, expected_behavior) in expected.items():
        directory = output_root / scenario
        manifest = run_local_experiment(directory, scenario=scenario)
        base = [sys.executable, str(root / 'analyze.py'), str(directory / 'access.log'),
                '--data-kind', 'local-experiment', '--config', str(config_path)]
        for name, format, sharing in [
            ('report.json', 'json', False), ('analysis.md', 'markdown', False),
            ('share.json', 'json', True), ('share.md', 'markdown', True),
        ]:
            command = base + ['--format', format, '--output', str(directory / name)]
            if sharing:
                command.append('--redact-share')
            subprocess.run(command, check=True, timeout=30)
        report_path = directory / 'report.json'
        report = json.loads(report_path.read_text(encoding='utf-8'))
        shared = json.loads((directory / 'share.json').read_text(encoding='utf-8'))
        sensitive = sum(f['rule_id'] == 'sensitive-path-exact-v1' for f in report['findings'])
        behavior = len(report['behavior']['findings'])
        with socket.socket() as check:
            check.settimeout(1)
            closed = check.connect_ex(('127.0.0.1', manifest['server_port'])) != 0
        passed = (
            sensitive == expected_sensitive and behavior == expected_behavior
            and report['finding_count'] == len(report['findings']) == sensitive + behavior
            and shared['finding_count'] == report['finding_count']
            and report['parsing']['parsed'] == len(manifest['requests'])
            and report['parsing']['errors'] == 0 and not report['behavior']['time_errors'] and closed
        )
        results.append({
            'scenario': scenario, 'request_count': len(manifest['requests']),
            'sensitive_findings': sensitive, 'behavior_findings': behavior,
            'expected_sensitive_findings': expected_sensitive,
            'expected_behavior_findings': expected_behavior,
            'server_port': manifest['server_port'], 'server_port_closed_verified': closed,
            'access_log_sha256': hashlib.sha256((directory / 'access.log').read_bytes()).hexdigest(),
            'report_path': f'{scenario}/report.json', 'passed': passed,
        })
        print(f'{scenario}: requests={len(manifest["requests"])} sensitive={sensitive} behavior={behavior} passed={passed}')
    summary = {
        'data_kind': 'local-experiment', 'results': results,
        'all_passed': all(item['passed'] for item in results),
        'note': 'normal-wide deliberately demonstrates benign browsing meeting the threshold; not proof of attack.',
    }
    with (output_root / 'summary.json').open('x', encoding='utf-8') as file:
        json.dump(summary, file, ensure_ascii=False, indent=2)
        file.write('\n')
    overview = [
        '# WebLogLens 本地 HTTP 实验验收报告', '',
        '私有实验材料：原始日志、请求清单、精确时间与端口保留。不要直接公开整个目录。', '',
        '服务只监听回环地址并返回固定文本，不读取文件系统；使用 Python HTTPServer 自定义 combined 日志，不是 Nginx。', '',
        '| 场景 | 请求数 | 敏感路径线索 | 行为线索 | 验收 |', '|---|---:|---:|---:|---|',
    ]
    for result in results:
        overview.append(f"| {result['scenario']} | {result['request_count']} | {result['sensitive_findings']} | {result['behavior_findings']} | {'通过' if result['passed'] else '失败'} |")
    overview.extend([
        '', '## 关键结论', '',
        '正常访问五个公开页面也会命中行为阈值，因此线索不等于扫描或入侵成功。没有代表性数据集，不报告准确率或误报率。', '',
        '## 证据说明', '',
        '- access.log：真实服务端日志；manifest.json：客户端实际请求与响应记录。',
        '- report.json、analysis.md：私有完整分析；share.json、share.md：可选分享视图。',
        '- summary.json：结果对照、日志哈希、端口关闭验证；experiment-config.json：本次固定配置。',
        '- 分享版用代号替换 IP/路径，移除原始文本、查询参数和精确时间；计数、关系与行号仍可能关联，须人工复核。', '',
        '## 复现', '', '在项目根目录运行 python run_experiment.py，每次创建新的证据目录。', '',
        f"整体验收：{'通过' if summary['all_passed'] else '失败'}。", '',
    ])
    with (output_root / 'REPORT.md').open('x', encoding='utf-8') as file:
        file.write('\n'.join(overview))
    print(f'Experiment evidence: {output_root}')
    if not summary['all_passed']:
        raise SystemExit(1)
