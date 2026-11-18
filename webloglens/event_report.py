"""Private bounded stage reports from saved JSONL, not a second detector."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from webloglens.behavior import parse_timestamp

EVENTS = frozenset(('started', 'status', 'summary', 'record', 'finding', 'blank',
    'parse_error', 'decode_error', 'line_too_long', 'time_error', 'late_record',
    'state_limit', 'rotated', 'truncated', 'path_missing', 'path_available'))
RULES = frozenset(('sensitive-path-exact-v1', 'multi-path-window-v2'))
DIAGNOSTICS = frozenset(('parse_error', 'decode_error', 'line_too_long', 'time_error',
                        'late_record', 'state_limit', 'rotated', 'truncated', 'path_missing'))
STRUCTURAL = frozenset(('missing_started', 'missing_summary', 'invalid_jsonl',
    'invalid_event', 'unknown_event_type', 'unknown_rule', 'multiple_runs',
    'bad_event_order', 'declared_counts_mismatch', 'declared_analysis_mismatch',
    'oversized_event_line', 'unterminated_jsonl_line', 'source_changed'))


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON key')
        value[key] = item
    return value


def _reject_constant(value):
    raise ValueError('Nonfinite JSON constant')


def _signature(stat):
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def summarize_events(path, max_samples=20, max_event_bytes=2097152,
                     max_sample_bytes=262144):
    for name, value, minimum in [('max_samples', max_samples, 0),
            ('max_event_bytes', max_event_bytes, 1), ('max_sample_bytes', max_sample_bytes, 0)]:
        if type(value) is not int or value < minimum:
            raise ValueError(f'{name} must be an integer >= {minimum}')
    path = Path(path).resolve()
    before = _signature(path.stat())
    counts, rules, statuses = Counter(), Counter(), Counter()
    issues = set()
    samples, diagnostics = [], []
    retained_bytes = 0
    sample_skips = 0
    started = summary = None
    first_kind = last_kind = None
    first_time = last_time = None
    digest = hashlib.sha256()
    physical_lines = total_bytes = 0
    with path.open('rb') as stream:
        while True:
            offset = total_bytes
            line = stream.readline(max_event_bytes + 1)
            if not line:
                break
            physical_lines += 1
            digest.update(line)
            total_bytes += len(line)
            if len(line) > max_event_bytes:
                issues.add('oversized_event_line')
                while not line.endswith(b'\n'):
                    line = stream.readline(max_event_bytes + 1)
                    if not line:
                        break
                    digest.update(line)
                    total_bytes += len(line)
                continue
            if not line.endswith(b'\n'):
                issues.add('unterminated_jsonl_line')
            try:
                event = json.loads(line.decode('utf-8-sig' if offset == 0 else 'utf-8'),
                                   object_pairs_hook=_unique, parse_constant=_reject_constant)
            except (UnicodeDecodeError, ValueError, RecursionError):
                issues.add('invalid_jsonl')
                continue
            if not isinstance(event, dict) or not isinstance(event.get('type'), str):
                issues.add('invalid_event')
                continue
            kind = event['type']
            if kind not in EVENTS:
                counts['unknown'] += 1
                issues.add('unknown_event_type')
                continue
            if first_kind is None:
                first_kind = kind
            if last_kind == 'summary':
                issues.add('bad_event_order')
            last_kind = kind
            counts[kind] += 1
            if kind == 'started':
                started = event
            elif kind == 'summary':
                summary = event
            elif kind == 'record':
                fields = event.get('fields', {})
                if not isinstance(fields, dict):
                    issues.add('invalid_event')
                    continue
                status = fields.get('status')
                if type(status) is int and 0 <= status <= 999:
                    statuses[str(status)] += 1
                else:
                    issues.add('invalid_event')
                if 'time' in fields:
                    try:
                        instant = parse_timestamp(fields['time'])
                        first_time = instant if first_time is None else min(first_time, instant)
                        last_time = instant if last_time is None else max(last_time, instant)
                    except (ValueError, KeyError, OverflowError, AttributeError, TypeError):
                        issues.add('invalid_record_time')
            elif kind == 'finding':
                rule = event.get('rule_id')
                if isinstance(rule, str) and rule in RULES:
                    rules[rule] += 1
                else:
                    rules['unknown'] += 1
                    issues.add('unknown_rule')
            destination = samples if kind == 'finding' else diagnostics if kind in DIAGNOSTICS else None
            if destination is not None and len(destination) < max_samples:
                if retained_bytes + len(line) <= max_sample_bytes:
                    destination.append(dict(event_line=physical_lines, event_offset=offset, event=event))
                    retained_bytes += len(line)
                elif kind == 'finding':
                    sample_skips += 1
    try:
        if _signature(path.stat()) != before:
            issues.add('source_changed')
    except OSError:
        issues.add('source_changed')
    if started is None:
        issues.add('missing_started')
    if summary is None:
        issues.add('missing_summary')
    if counts['started'] > 1 or counts['summary'] > 1:
        issues.add('multiple_runs')
    if first_kind != 'started' or last_kind != 'summary':
        issues.add('bad_event_order')
    if summary is not None:
        declared = summary.get('counts')
        observed = {k: v for k, v in counts.items() if k not in ('started', 'status', 'summary') and v}
        if (not isinstance(declared, dict)
                or any(type(v) is not int or v < 0 for v in declared.values())
                or {k: v for k, v in declared.items() if v} != observed):
            issues.add('declared_counts_mismatch')
        analysis = summary.get('analysis', {})
        if started is not None and started.get('stage') == 'detection' and 'analysis' not in summary:
            issues.add('declared_analysis_mismatch')
        if not isinstance(analysis, dict):
            issues.add('declared_analysis_mismatch')
            analysis = {}
        expected = dict(records=counts['record'],
                        path_findings=rules['sensitive-path-exact-v1'],
                        window_findings=rules['multi-path-window-v2'],
                        late_records=counts['late_record'], time_errors=counts['time_error'],
                        state_limits=counts['state_limit'])
        for key, value in expected.items():
            if key in analysis and (type(analysis[key]) is not int or analysis[key] != value):
                issues.add('declared_analysis_mismatch')
        if 'status_counts' in analysis and analysis['status_counts'] != dict(statuses):
            issues.add('declared_analysis_mismatch')
    for kind, code in [('late_record', 'late_records_excluded'),
                       ('state_limit', 'capacity_limit_excluded'),
                       ('time_error', 'invalid_record_time'),
                       ('parse_error', 'input_format_errors'),
                       ('decode_error', 'input_encoding_errors'),
                       ('line_too_long', 'input_lines_discarded'),
                       ('rotated', 'rotation_requires_review'),
                       ('truncated', 'truncation_requires_review'),
                       ('path_missing', 'source_unavailable_during_run')]:
        if counts[kind]:
            issues.add(code)
    if started is not None and started.get('stage') == 'input-only':
        issues.add('detection_not_enabled')
    if summary and summary.get('pending_bytes', 0):
        issues.add('incomplete_input_tail')
    return dict(schema_version='stream-report-1.0', privacy={'mode': 'private'},
        input=dict(events_file=str(path), sha256=digest.hexdigest(),
                   physical_lines=physical_lines, bytes_read=total_bytes),
        run=dict(started=started, summary=summary),
        observed=dict(counts=dict(counts), rule_counts=dict(rules), status_counts=dict(statuses),
                      first_valid_event_time=first_time.isoformat() if first_time else None,
                      last_valid_event_time=last_time.isoformat() if last_time else None),
        quality=dict(event_stream_complete=not bool(issues & STRUCTURAL),
                     analysis_has_gaps=bool(issues), issues=sorted(issues)),
        finding_samples=samples, diagnostic_samples=diagnostics,
        samples=dict(limit=max_samples, byte_limit=max_sample_bytes, payload_bytes=retained_bytes,
                     retained=len(samples), omitted=counts['finding'] - len(samples),
                     diagnostic_retained=len(diagnostics), oversized_or_budget_skipped=sample_skips))


ISSUE_LABELS = {
    'missing_started': '缺少启动事件，无法确定本次运行起点。',
    'missing_summary': '缺少退出摘要，可能尚在运行、异常中止或事件文件不完整。',
    'invalid_jsonl': '存在无效编码、JSON、重复键或非有限数事件行。',
    'invalid_event': '存在不符合当前事件结构的记录。',
    'unknown_event_type': '存在当前报告器不支持的事件类型。',
    'unknown_rule': '存在当前报告器不支持的规则。',
    'multiple_runs': '出现多个启动或摘要，请按单次运行拆分文件。',
    'bad_event_order': '启动/结束顺序异常，或摘要之后还有事件。',
    'declared_counts_mismatch': '摘要声明的事件计数与实际可读取事件不一致。',
    'declared_analysis_mismatch': '摘要分析计数与实际记录/规则线索不一致。',
    'oversized_event_line': '事件行超过读取上限，已跳过；实际总量可能更多。',
    'unterminated_jsonl_line': '最后事件行没有换行，可能尚未写完。',
    'source_changed': '读取期间源文件发生变化，不能当作静态快照。',
    'late_records_excluded': '存在迟到记录，未进入行为窗口，但仍可能参与路径检测。',
    'capacity_limit_excluded': '检测状态达到容量上限，部分记录未参与行为分析。',
    'invalid_record_time': '存在无效事件时间，时间覆盖及窗口分析有缺口。',
    'input_format_errors': '原日志存在格式错误，部分请求未解析。',
    'input_encoding_errors': '原日志存在编码错误，部分行被跳过。',
    'input_lines_discarded': '原日志超长行已被丢弃。',
    'rotation_requires_review': '发生文件轮转，交接和迟到写入仍有已知风险。',
    'truncation_requires_review': '发生文件截断，需核查日志是否丢失或重复。',
    'source_unavailable_during_run': '运行中源路径曾不可用，需核查采集覆盖。',
    'incomplete_input_tail': '结束时仍有未补全的日志尾部。',
    'detection_not_enabled': '本次仅运行输入模式，未启用检测。',
}


def render_stage_markdown(report):
    counts = report['observed']['counts']
    quality = report['quality']
    sample_info = report['samples']
    lines = ['# WebLogLens 阶段排查报告', '',
        '> 私有报告：含本地路径、来源 IP、参数及原始证据；没有自动脱敏，不可直接公开。', '',
        '本报告汇总事件，不重新执行规则。线索数不是攻击次数，命中不证明攻击成功。', '',
        '## 一、可读取事件概况', '', '| 指标 | 数量 |', '|---|---:|']
    for label, key in [('成功解析请求', 'record'), ('检测线索', 'finding'),
                       ('原日志格式错误', 'parse_error'), ('原日志编码错误', 'decode_error'),
                       ('原日志超长行', 'line_too_long'), ('坏时间', 'time_error'),
                       ('迟到排除', 'late_record'), ('容量超限', 'state_limit')]:
        lines.append(f'| {label} | {int(counts.get(key, 0))} |')
    lines += ['', '计数只基于可读取事件；若存在跳过或损坏，不代表实际总量。', '',
              '## 二、运行质量与分析缺口', '',
              ('事件流结构及计数交叉检查通过；这不是日志覆盖完整或证据真实性保证。'
               if quality['event_stream_complete'] else '事件流不完整或交叉检查失败，实际总量可能未知。'), '',
              ('**分析存在缺口或需复核项，不能凭未命中认定安全。**' if quality['analysis_has_gaps']
               else '未在可读取事件中识别出上述分析缺口；仍不能证明系统安全。'), '']
    for code in quality['issues']:
        lines.append('- ' + ISSUE_LABELS.get(code, '未知质量标记，需人工复核。'))
    def block(value):
        lines.extend('    ' + line for line in json.dumps(value, ensure_ascii=False, indent=2).splitlines())
        lines.append('')
    lines += ['', '### 状态码、规则与事件时间范围', '',
              '时间范围仅描述成功解析记录中的有效事件时间，不证明期间没有日志缺失。', '']
    block({key: report['observed'][key] for key in
           ('status_counts', 'rule_counts', 'first_valid_event_time', 'last_valid_event_time')})
    lines += ['## 三、线索样本与证据定位', '',
              f"保留 {sample_info['retained']} 条，省略 {sample_info['omitted']} 条可读取线索。",
              '这是有界样本，不是完整线索清单；请回查原事件文件。', '']
    for number, sample in enumerate(report['finding_samples'], 1):
        lines += [f'### 线索样本 {number}', '']
        block(sample)
    lines += ['### 质量/输入状态样本', '']
    for sample in report['diagnostic_samples']:
        block(sample)
    lines += ['## 四、来源、配置与运行摘要', '',
              'observed 为报告器重新计数；run.summary 是事件文件中的声明，二者分开保留。', '']
    block(dict(input=report['input'], run=report['run'], samples=sample_info))
    lines += ['## 五、后续排查与边界', '',
              '- 对照原始日志、事件文件字节偏移及行号核查证据；文件哈希不证明来源可信。',
              '- 核对迟到策略、容量限制、日志轮转和采集中断，不把缺口当成正常访问。',
              '- 敏感路径需核对响应内容；HTTP 200 不单独证明泄露。',
              '- 多路径命中可能是正常浏览、监控或共享出口，不自动封禁。',
              '- 本报告只覆盖保存下来的这次运行，不恢复未采集日志，也不是生产准确率评估。', '']
    return '\n'.join(lines)

