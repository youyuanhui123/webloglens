# WebLogLens 2.0.0

基于Python标准库、支持**历史回放与实时跟随**的Web访问日志排查工具。个人安全实践项目，AI辅助开发；用于发现可解释线索和整理证据，**不是WAF、漏洞扫描器、自动封禁平台或入侵成功判定器**。

## 运行要求

- Python 3.11及以上；实机验收覆盖Windows Python 3.11.9和3.15.1，不等于所有平台都已验证。
- 核心入口无需pip安装、管理员权限或Docker。原生Nginx实验额外需要已启动Docker及本地nginx:alpine镜像，不自动拉取。
- 本地UTF-8、固定combined日志。analyze.py批量累积并排序；watch.py采用有限增量状态。两者时间语义不同，不承诺所有输入结果恒等。

## 从解压包直接运行（Windows CMD，项目根）

输出文件须不存在，父目录须存在；下面使用包内examples/docs，不依赖未打包的历史验收文件。

```cmd
python analyze.py --version
python watch.py examples/synthetic_sensitive.log --replay --min-paths 3 --output docs/demo-events.jsonl
python report_events.py docs/demo-events.jsonl --output docs/demo-stage.md
python -m unittest discover -s tests -v
```

回放样例包含5条请求，min-paths=3时得到2条精确路径线索和1条窗口线索。再次演示请换输出名，工具不会覆盖已有结果。默认测试跳过2个Docker集成项，其余测试仍包含真实本地HTTP和watch子进程，需要本机允许回环监听。

PyCharm：打开整个WebLogLens目录，选择解释器，工作目录设项目根。运行watch.py，脚本形参填 `examples/synthetic_sensitive.log --replay --min-paths 3 --output docs/demo-events.jsonl`；再运行report_events.py，形参填 `docs/demo-events.jsonl --output docs/demo-stage.md`。形参中不要重复python或脚本名。

## 入口选择

|入口|用途|
|---|---|
|analyze.py|保留第一版整批分析：UTC全量排序、每IP首个窗口，可选分享视图|
|watch.py --replay|静态日志按文件原顺序回放，隐含开启检测，EOF刷新退出|
|watch.py --detect|持续跟随单文件新完整行，按有限乱序策略增量检测|
|watch.py（无检测参数）|只读取解析，不做规则检测；默认从末尾开始|
|report_events.py|汇总已保存的单次JSONL，不重新检测；仅私有报告|
|run_experiment.py|受控Python HTTPServer实验，保留第一版入口|
|run_nginx_experiment.py|本地原生Nginx三场景，清理本次容器|
|run_baseline.py|受控合成资源及真实watch延迟初始基线|
|build_release.py|明确白名单源码ZIP与逐文件SHA-256清单|

自己的授权日志（CMD）：

```cmd
python watch.py "D:\logs\access.log" --detect --output "D:\logs\events.jsonl"
```

默认只观察启动后的新增完整行；从头观察加 --start beginning。正常Ctrl+C会刷新并写退出摘要，再用report_events.py生成报告。不能把日志中的200响应当作泄露或攻击成功。

## 已实现与边界

- combined解析、原始证据定位、坏行记录、精确路径和多路径窗口规则。
- 增量核心共用实时/回放入口，包含有限乱序、迟到事件、冷却、状态过期和容量限制；容量排除明确留事件。
- 文件轮转、截断、路径缺失、半行、超长行处理；不保证轮转竞争下exactly-once或无损。
- 私有JSONL与JSON/Markdown阶段报告，独立核对观察计数和退出摘要，区分事件流完整与分析缺口。
- 原生Nginx正常/混合/正常多页面反例实验；短时资源与延迟基线。
- 固定combined；不自动URL解码/大小写或路径归一化，不解析可信代理链，不支持远程多机采集、强断点恢复或自动防御。
- 未做生产准确率、高基数压力、多小时稳定性、进程RSS或持续业务轮转无损评估。初始基线不构成生产SLA。

## 隐私与发布范围

watch输出和阶段报告默认含原文、IP、查询串、精确时间与本地路径，**不能直接公开**。只有analyze.py的 --redact-share 支持旧结构分享视图，不能用于新增JSONL/阶段报告。Markdown安全渲染不等于脱敏，旧分享视图也不保证匿名。

源码ZIP只包含明确列出的源码、测试、手册、规则、合成样例与清单；不包含acceptance、experiments、study.md、历史报告、环境或缓存。白名单无法判断用户后来写入样例或规则的秘密，重新发布前仍需检查。旧版WebLogLens-1.0.0-r1.zip保留，第二版另存WebLogLens-2.0.0.zip。

## 文档与复现

- [快速开始](docs/QUICKSTART.md)：CMD/PyCharm和完整演示。
- [架构](docs/ARCHITECTURE.md)、[实时策略](docs/V2-REALTIME.md)：时间/窗口/容量语义。
- [阶段报告](docs/EVENT-REPORT.md)、[隐私](docs/PRIVACY.md)：质量与公开边界。
- [原生Nginx实验](docs/NGINX-LAB.md)、[资源延迟基线](docs/BASELINE.md)。
- [验收](docs/ACCEPTANCE.md)、[项目表达](docs/INTERVIEW.md)。

手册中的acceptance/...引用是开发机历史证据，不在源码ZIP内；按手册命令可生成自己的新实验材料，不应把缺失历史目录当作运行依赖。源码与清单校验一致只证明内容一致，不证明来源可信或通过全面安全审计。
