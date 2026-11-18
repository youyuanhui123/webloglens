"""Human-readable Markdown with log values confined to indented code blocks."""

import json


def render_markdown(report):
    """Render analyzer data, without claiming exploitation or redaction."""
    source_labels = {
        'synthetic': '合成测试数据', 'local-experiment': '本地实验日志（来源由调用者声明）',
        'authorized': '授权日志（授权与来源由调用者声明）',
        'unspecified': '来源未声明',
    }
    source = report['source']
    label = source_labels.get(source.get('data_kind'), '来源未声明')
    parsing = report['parsing']
    sharing = report.get('privacy', {}).get('mode') == 'share-redacted'
    notice = ('> 分享版：已移除原始日志、查询参数、精确时间和本地路径，IP 与请求路径使用代号。'
              '计数、关系和行号仍保留，不能保证匿名，公开前须人工复核。' if sharing else
              '> 本报告提供排查线索，不证明攻击成功。内容未自动脱敏，公开前须检查路径、IP、参数和原始日志。')
    lines = [
        '# WebLogLens 日志分析报告', '',
        f'数据类型：{label}。工具未独立核验数据来源或授权。', '',
        notice, '',
        '## 一、分析概况', '',
        '| 指标 | 数量 |', '|---|---:|',
    ]
    for title, value in [
        ('总行数', parsing['total_lines']), ('成功解析', parsing['parsed']),
        ('格式错误', parsing['errors']), ('空行', parsing['blank_lines']),
        ('检测线索', report['finding_count']),
    ]:
        lines.append(f'| {title} | {int(value)} |')
    lines.extend(['', '### 输入与数据来源', ''])
    # JSON escapes embedded newlines. Indentation, rather than fences, prevents
    # attacker-supplied backticks/HTML/headings from breaking out of code blocks.
    encoded = json.dumps(source, ensure_ascii=False, indent=2)
    lines.extend('    ' + line for line in encoded.splitlines())
    lines.extend(['', '## 二、访问统计', '',
                  '以下为成功解析记录的计数，不代表独立用户数或风险排名。', ''])
    for title, key in [('状态码', 'status_counts'), ('来源 IP', 'ip_counts'), ('访问路径', 'path_counts')]:
        lines.extend([f'### {title}', ''])
        encoded = json.dumps(report['summary'][key], ensure_ascii=False, indent=2)
        lines.extend('    ' + line for line in encoded.splitlines())
        lines.append('')
    lines.extend(['## 三、检测线索与证据', '',
                  '不同规则可能引用同一请求，线索数不等于独立攻击次数。', ''])
    if not report['findings']:
        lines.extend(['未发现当前规则覆盖的线索；这不等于系统安全或没有攻击。', ''])
    for number, finding in enumerate(report['findings'], start=1):
        lines.extend([f'### 线索 {number}', ''])
        if finding.get('rule_id') == 'sensitive-path-exact-v1':
            lines.extend(['**类型：敏感路径访问。** 请求目标命中精确路径规则；需核对响应内容，不能只看状态码判断泄露。', ''])
        elif finding.get('rule_id') == 'multi-path-window-v1':
            lines.extend(['**类型：短时多路径访问。** 同一来源达到窗口阈值；正常浏览也可能命中，需结合业务背景排查。', ''])
        encoded = json.dumps(finding, ensure_ascii=False, indent=2)
        lines.extend('    ' + line for line in encoded.splitlines())
        lines.append('')
    lines.extend(['## 四、输入质量与检测配置', '',
                  '时间无效的记录仍可参与基础统计，但不参与时间窗口检测。', ''])
    behavior = report.get('behavior', {})
    encoded = json.dumps({
        'effective_configuration': report.get('configuration', {}),
        'parse_errors': report.get('parse_errors', []),
        'behavior_config': behavior.get('config', {}),
        'time_errors': behavior.get('time_errors', []),
    }, ensure_ascii=False, indent=2)
    lines.extend('    ' + line for line in encoded.splitlines())
    lines.extend(['', '## 五、判断边界与后续排查', '',
                  '- HTTP 200 不能单独证明文件泄露；404 也不抹去访问行为。',
                  '- 多路径窗口可能来自正常浏览、监控或代理后的多个用户。',
                  '- 建议核对响应内容、业务基线、代理拓扑及相关日志，不自动封禁来源。',
                  '- 原始日志仍须保留；本报告不是逐字节证据归档，也不是修复完成证明。', '',
                  '### 分析器声明的限制', ''])
    encoded = json.dumps(report.get('limitations', []), ensure_ascii=False, indent=2)
    lines.extend('    ' + line for line in encoded.splitlines())
    return '\n'.join(lines) + '\n'
