# 架构与设计（3.0.0）

## 主干数据流

```text
analyze → combined reader/parser → 全量统计/UTC排序首窗口 → 旧结构报告/可选分享

watch/replay → follow新增完整行 → ingest显式格式
                                 ├─ combined → StreamAnalyzer
                                 └─ nginx-json → SiteAnalyzer → 每站点StreamAnalyzer
                                                       ↓
                                         顶层record / finding / 诊断 / summary
                                                       ↓
                                      单JSONL 或 可选分片目录→完整拼接
                                                       ↓
                          ┌────────────────────────────┴─────────────────┐
                    event_report独立核对                            SQLite派生索引
                          ↓                                             ↓
                   JSON/Markdown阶段报告                    条件查询 / 来源时间线
```

analyze 保留第一版批量读取与全量排序，不是恒定内存。watch/replay 增量读取，不每秒重扫全文件；它们使用有限乱序策略，不能冒充全量排序或保证与 analyze 任意输入恒等。

## 输入与来源

combined 和约定 `webloglens-nginx-1` JSON 显式选择，不猜格式。JSON 模板采用 `escape=json`；site 来自受控 Nginx `$server_name`，IP 使用连接来源，不把任意 Host/XFF 当可信身份。额外字段、时间和数值的约束见 V3-INPUT。

follow 有界读取新增字节，完整行才解析，半行等待；超长行有界恢复。路径、运行内 generation、字节 offset 和原文保留；从末尾启动未知物理行号为 null。raw 不是字节级归档，原日志仍需保留。轮转、快速 copytruncate 和旧文件交接竞态不承诺无损或 exactly-once。

## 时间、站点与资源

- target 保留原样，派生路径只去第一个问号后查询，不 URL 解码或折叠。
- 批量行为按 IP 全量 UTC 排序；增量核心采用事件时间小顶堆、水位、有限乱序和冷却，tick 以单调处理时间判断 idle。
- 默认乱序 2 秒、窗口 60 秒、不同路径阈值 5、冷却 60 秒。每核心 max_buffer=512、max_window_records=2048、max_ips=256。
- JSON 每站点独立核心，窗口、水位、冷却、idle 都隔离；默认最多准入 16 个站点，范围 1..128，整个运行首次准入，不静默回收重置。每核心预算乘站点上限才是总预算上界。
- 过迟/坏时间/容量排除仍保留请求统计与精确路径线索，明确留诊断。超站点容量不伪装解析失败。
- 检测 finish 在 EOF/正常退出刷新；不提供跨运行恢复协议。

## 输出与调查

默认配置相对入口定位，显式命令行覆盖已验证配置。started 保存模式/格式/设置，summary 保存计数和检测状态。运行健康与分片协议见 V3-RUNTIME。

阶段报告独立核对顶层事件和退出摘要；finding 的 evidence 不重复算请求。`event_stream_complete` 与 `analysis_has_gaps` 分开。有限结构核对不是来源真实性认证。

SQLite 使用 Python 自带 sqlite3，不需安装或启动数据库服务。完整静态事件先有界暂存、质量核对，再事务导入；显式追加、SHA 去重。runs 保留源哈希与质量，events 保存顶层事件和定位，evidence_links 关联既有线索。实时与回放可以是不同 run，不能据此当成不同真实访问。

query 使用绑定参数和有界返回；timeline 只排序访问事实并关联既有线索，不再跑检测、不推断攻击链。SQLite 文件是可重建派生物，原事件不修改。路径/时间/返回预算与关联限制见 V3-INDEX。

JSON 与 Markdown 基于同一结果；动态值使用安全代码文本显示。显示转义不等于脱敏，本地默认保留原文。

## 验证与不做

实验只用回环固定响应服务；Docker 仅已有本地镜像，不读取真实敏感文件，不请求外站，只清理本次拥有的容器。Windows 无监听与 TIME_WAIT 分开判断。

资源初始基线采用 tracemalloc，不是 RSS；短时延迟只针对精确路径线索。持续运行收尾测试范围见 RELEASE-3.0.0，不冒充生产容量保证。

不做远程多机采集、可信代理链归因、自动封禁、入侵成功判定、强断点恢复、生产准确率承诺。分析入口不联网、不执行日志中的表达式。
