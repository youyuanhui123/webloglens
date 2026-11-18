# WebLogLens 1.0.0

基于 Python 标准库的离线 Web 访问日志排查工具。面向个人安全实践：从原始日志到统计、可解释线索、证据回查及 JSON / Markdown 报告。**不是漏洞扫描器、WAF 或生产级入侵检测系统。**

## 已验证结果

第一版在 Windows Python 3.11 / 3.15 下分别通过 34 个自动测试；三组真实本机 HTTP 对照实验全部符合预期。验收输出保存在本地 acceptance/v1.0.0/，不进入分享源码包。具体复验方法和限制见 docs/ACCEPTANCE.md。

## 运行要求

- Python 3.11 或更新版本；当前验收覆盖 3.11 与 3.15。
- 无第三方运行依赖，不需要 pip install，不需要管理员权限。
- 日志：UTF-8（支持 BOM）、固定 combined 格式；只面向小型离线日志，当前会将解析结果保存在内存中。

## 快速开始

在项目目录运行（Windows CMD 与 WSL bash 均可，进入目录命令见 docs/QUICKSTART.md）：

```text
python analyze.py --version
python analyze.py
python analyze.py examples/synthetic_burst.log --data-kind synthetic --format markdown
python run_experiment.py
python -m unittest discover -s tests -v
```

PyCharm：打开整个项目，选择 Python 解释器，右键运行 analyze.py 或 run_experiment.py。原 main.py、read_demo.py、stats_demo.py、detect_demo.py 保留作分步演示。

## 功能

- 批量读取，保留原始行号与文本，区分空行、格式错误和时间错误。
- 请求数、状态码、来源 IP、路径统计。
- 配置化精确路径匹配，输出规则、原因和证据。
- 按来源 IP 分组、UTC 排序的多路径滑动窗口检测。
- JSON / Markdown 导出、拒绝覆盖已有文件。
- 可选 --redact-share 分享视图，严格按允许字段重建报告。
- 一键本地真实 HTTP 实验：正常重复、混合访问、正常多页面三个场景。
- 白名单发布包与逐文件 SHA-256 清单。

## 常用导出

输出目录必须已存在，下面使用已有 docs 目录。再次运行请换文件名。

```text
python analyze.py examples/synthetic_burst.log --data-kind synthetic --output docs/private-report.json
python analyze.py examples/synthetic_burst.log --data-kind synthetic --format markdown --output docs/private-report.md
python analyze.py examples/synthetic_burst.log --data-kind synthetic --redact-share --format markdown --output docs/share-report.md
python analyze.py examples/synthetic_burst.log --config rules/example.json --min-paths 5
```

命令行阈值优先于配置；配置无效时退出，不静默回退。--data-kind 只是调用者声明，工具不能证明数据来源或授权。

## 实验与证据

run_experiment.py 只监听 127.0.0.1 动态端口，发送真实 HTTP 请求并采集日志；服务只返回固定文本，不读取磁盘文件，不访问外部目标。完成后关闭服务并验证端口。每次新建 experiments/local-<UTC>/：

```text
REPORT.md、summary.json、experiment-config.json
baseline/、mixed/、normal-wide/
    access.log、manifest.json
    report.json、analysis.md         # 私有完整报告
    share.json、share.md             # 分享视图
```

服务为 Python HTTPServer 自定义 combined 日志器，**不是 Nginx**。normal-wide 的五个正常页面也会命中多路径规则，这是必须保留的检测边界，不报告虚构准确率。

## 分享与隐私

默认报告不脱敏。分享版移除原始证据、查询串、头部、精确时间和本地路径，IP/请求路径替换为单次导出内的代号，不输出映射表。计数、关系与行号仍可能关联，不能保证匿名；发布前人工复核。详见 docs/PRIVACY.md。

不要公开整个 experiments 目录，也不要把 docs 中的历史私有输出推到公开仓库。build_release.py 使用明确文件白名单，不包含 experiments、缓存、虚拟环境、历史报告或 .env。

## 项目结构

```text
analyze.py                统一分析入口
run_experiment.py         本地端到端实验
build_release.py          源码便携包
webloglens/               解析、读取、统计、规则、窗口、脱敏、报告模块
rules/                    默认和示例配置
examples/                 明确标记的合成日志
tests/                    unittest 回归与真实 HTTP 集成测试
docs/                     当前手册及开发历史
```

## 文档

- docs/QUICKSTART.md：CMD / PyCharm / WSL 的具体运行方式。
- docs/ARCHITECTURE.md：数据流、算法和配置决策。
- docs/PRIVACY.md：分享策略与边界。
- docs/INTERVIEW.md：演示顺序、简历表述、面试问题。
- docs/ACCEPTANCE.md：验收方法与已知限制。
- docs/step*.md、docs/progress.md：开发过程记录，可能描述历史状态，以本 README 为准。

## 第一版边界

仅固定 combined 格式；没有原生 Nginx 配置验证、生产流量准确率评估、实时监控、大文件性能保证、可信代理链解析、通用攻击识别或自动封禁。敏感路径规则不解码或规范化 URL；行为规则每 IP 只输出首个命中窗口。HTTP 状态码不能证明攻击成功。
