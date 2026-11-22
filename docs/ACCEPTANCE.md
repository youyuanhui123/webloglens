# 验收说明（3.0.0）

## 范围与口径

核心 Python 标准库，无额外数据库服务。实机解释器 Windows Python 3.11.9 与 3.15.1。覆盖批量历史入口、combined/约定 JSON 解析、站点隔离、增量检测、实时追加/回放、阶段报告、SQLite 查询、滚动与保留、健康状态及发布包。

测试包含真实本机 HTTP 和子进程，不能统称纯单元测试。默认跳过两个显式 Docker 集成，启用后应全部实际执行。发布实际测试数量与时长记录在 RELEASE-3.0.0 及开发机 acceptance/v3.0.0-release；不沿用旧版 72/87/98 项作为当前数量。

## 默认复验（Windows CMD，项目根）

```cmd
python analyze.py --version
python -m unittest discover -s tests -v
python check_input.py examples/synthetic_sites.jsonl --log-format nginx-json
python watch.py examples/synthetic_sites.jsonl --log-format nginx-json --replay --min-paths 2 --output docs/check-v3.jsonl
python report_events.py docs/check-v3.jsonl --output docs/check-v3.md
python investigate.py import docs/check-v3.jsonl --database docs/check-v3.sqlite
python investigate.py timeline docs/check-v3.sqlite --run-id 1 --site a.local --ip 192.0.2.10
```

输出名称须不存在。合成样例四条请求、两个站点各一条窗口线索，a.local 时间线两条请求。观察质量而不只看 exit 0。

## Docker 集成

需要运行中的引擎与已有 nginx:alpine 镜像，不拉取，不改已有容器：

```cmd
set WEBLOGLENS_NGINX_TEST=1
python -m unittest discover -s tests -v
set WEBLOGLENS_NGINX_TEST=
```

combined 三场景预期请求 6/6/5、精确路径线索 0/2/0、窗口线索 0/1/1。正常多页面也命中是已知反例，不计算生产准确率。集成还检查中途失败清理，Windows 无监听与 TIME_WAIT 分开看。

第三版开发验收另有真实 Nginx JSON 双站点实验：六条请求、四条线索，首两条分属不同站点不形成跨站窗口。输出分片验收在真实采集后的原始日志回放及持续追加场景上核对完整拼接、报告和索引；主动删除/缺片不得被拼接成完整事件。

## 发布复验

```cmd
python build_release.py --output dist/my-recheck.zip
```

发布前复核白名单文件，ZIP 内仅 WebLogLens/ 下源码、文档、测试、配置和合成示例。RELEASE-MANIFEST.json 的 file_count 不含清单本身，逐文件哈希对应归档字节。不含原始验收数据、数据库、真实日志、学习记录、缓存或环境。

解压到新的中文路径，在非项目 cwd 运行版本、默认分析、JSON 回放、阶段报告、SQLite 导入/时间线、分片/拼接。源码树和解压树对两解释器各跑完整测试，实际记录数量/跳过数。默认套件的两项跳过不能描述为 Docker 通过。

打包后不可继续改包内文件却沿用原验收；有改动要生成新包并重验。旧正式 ZIP 不覆盖。窄 token 特征扫描仅辅助检查，不是全面安全审计或秘密不存在的证明。

## 留存证据

开发机 acceptance/ 保存各版真实输出、失败记录及复验结果，不放进源码 ZIP。包内示例和入口不依赖这些历史绝对路径；新机器自行生成报告和实验数据。study.md 是学习记录，不在发布白名单，是否随 Git 仓库上传单独决定。

## 不声称

测试通过不证明生产准确率、合规、高并发容量、无损轮转、强断电恢复或多小时无泄漏。tracemalloc 不等于 RSS；短时连续运行不等于生产长期验证。WSL 未独立做本次发布验收。本地保留原文，公开真实资料前检查敏感信息即可，不强制新增脱敏系统。
