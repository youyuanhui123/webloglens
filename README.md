# WebLogLens 3.0.0

支持历史回放、实时跟随与来源回查的本地 Web 访问日志排查工具。Python 标准库实现，无需 pip 安装或数据库服务。

个人安全实践项目，AI 辅助开发。定位是**发现可解释线索、保留证据、帮助调查**，不是 WAF、漏洞扫描器、自动封禁平台或入侵成功判定器。

## 第三版增加了什么

- 显式选择 combined 或约定 Nginx JSON；接入前检查格式、坏行和预算。
- JSON 多站点独立窗口、水位、冷却与容量；站点来自 Nginx 配置标签，不信任任意 Host/XFF。
- SQLite 派生索引、条件查询与来源时间线；不重复检测，不把线索引用重复算作请求。
- 可选事件分片、明确保留策略、完整事件拼接及运行健康提示。使用方法见 [运行与留存](docs/V3-RUNTIME.md)。
- 保留第一版批量入口与第二版实时/回放、报告和实验入口。

前两版 ZIP 保持冻结；第三版不覆盖历史包。GitHub 提交和 Release 创建是独立操作，本地打包不代表已经推送。

## 运行要求

Windows 实机验证使用 Python 3.11.9 与 3.15.1；推荐 Python 3.11 及以上。不声称所有平台/中间版本均实测。

核心入口不需要管理员权限、Docker 或第三方 Python 包。本地 Nginx 实验额外需要已启动 Docker 和已有 `nginx:alpine` 镜像，不自动拉取。测试包含本机回环服务和子进程，需要允许回环监听。

## 五分钟演示（Windows CMD，项目根）

所有输出名称须不存在。重复演示请换名，不要覆盖旧证据。

```cmd
python analyze.py --version
python check_input.py examples/synthetic_sites.jsonl --log-format nginx-json
python watch.py examples/synthetic_sites.jsonl --log-format nginx-json --replay --min-paths 2 --output docs/demo-v3-events.jsonl
python report_events.py docs/demo-v3-events.jsonl --output docs/demo-v3-stage.md
python investigate.py import docs/demo-v3-events.jsonl --database docs/demo-v3.sqlite
python investigate.py query docs/demo-v3.sqlite --run-id 1 --site a.local
python investigate.py timeline docs/demo-v3.sqlite --run-id 1 --site a.local --ip 192.0.2.10
```

样例为合成数据：4 条请求、2 个站点，各有一条窗口线索。`a.local`/`b.local` 是样例站点标签，不需要公网域名；指定 `a.local` 时间线有 2 条请求。SQLite 是命令指定位置的本地文件，不用启动数据库服务器。

PyCharm：打开整个项目，选择解释器，工作目录设项目根；运行 `watch.py`，脚本形参填上面命令中 `watch.py` 后的内容，不重复 Python 或脚本名。

## 现场观察（CMD）

```cmd
python watch.py "D:\logs\access.log" --detect --output "D:\logs\events.jsonl"
```

日志和输出父目录须存在，输出文件须不存在。默认从末尾观察新增完整行；从头加 `--start beginning`。约定 JSON 加 `--log-format nginx-json`。Ctrl+C 正常结束会刷新检测并写退出摘要；强杀/断电不保证完整。

不加 `--detect` 的 watch 只读取解析；`--replay` 从头读取静态文件并隐含检测，不能与 duration 同用。实时和回放共用增量核心，不保证与批量全量排序结果恒等。

## 入口与资料

|入口|用途|
|---|---|
|analyze.py|旧 combined 批量分析，全量排序首窗口，可选旧结构分享视图|
|check_input.py|有界接入预检，显式格式|
|watch.py|增量跟随、检测、静态文件原顺序回放及可选留存|
|report_events.py|独立核对单次完整事件流并生成阶段报告，不重跑规则|
|investigate.py|导入 SQLite、条件查询、来源时间线|
|run_experiment.py|回环 HTTPServer 三组受控实验|
|run_nginx_experiment.py|已有本地镜像的原生 Nginx 三场景与清理|
|run_baseline.py|核心资源及实际 watch 短时延迟初始基线|
|build_release.py|显式白名单源码 ZIP 和逐文件哈希清单|

[快速运行](docs/QUICKSTART.md) · [架构](docs/ARCHITECTURE.md) · [验收](docs/ACCEPTANCE.md) · [项目表达](docs/INTERVIEW.md) · [使用边界](docs/PRIVACY.md)

第三版：[JSON 接入](docs/V3-INPUT.md) · [站点隔离](docs/V3-SITES.md) · [调查索引](docs/V3-INDEX.md) · [运行与留存](docs/V3-RUNTIME.md) · [发布说明](docs/RELEASE-3.0.0.md)

历史实现说明：[实时核心](docs/V2-REALTIME.md) · [阶段报告](docs/EVENT-REPORT.md) · [Nginx 实验](docs/NGINX-LAB.md) · [初始基线](docs/BASELINE.md)

## 测试与打包（CMD）

```cmd
python -m unittest discover -s tests -v
python build_release.py
```

默认跳过两个显式 Docker 集成项，其余也含真实子进程和本机 HTTP 实验。启用 Docker 集成：

```cmd
set WEBLOGLENS_NGINX_TEST=1
python -m unittest discover -s tests -v
set WEBLOGLENS_NGINX_TEST=
```

默认包为 `dist/WebLogLens-3.0.0.zip`，拒绝覆盖，包内有 `RELEASE-MANIFEST.json`。不包含真实实验、数据库、私有输出、缓存或学习记录；学习记录是否单独传 Git 由用户决定。发布复验见验收手册。

## 已知边界

- target 原样保留；路径只去查询串，不自动解码、折叠斜杠或判断编码变体等价。
- 200 不证明泄露/登录成功；404 不否认探测访问事实。正常多页面也可能触发窗口，未测生产准确率。
- 迟到、超限等请求可能排除行为分析但仍有统计/精确检测；事件完整不等于分析无缺口。
- 本地日志轮转存在竞态边界，不保证 exactly-once、无损交接或跨进程断点恢复。
- SQLite 是可重建派生物，JSONL/原日志独立留证；查询 run-id 区分实时和回放重复观察。
- 短时实验不证明生产吞吐、长期内存稳定或强断电恢复；详见发布说明中的实测范围。
- 本地使用保留原文，不强制脱敏；准备公开真实日志/数据库时另行检查敏感信息。旧 analyze 分享视图不适用于新事件结构。
