# 第三版·阶段二：站点隔离分析

## 当前范围

JSON检测使用SiteAnalyzer按配置site分区，每个分区复用现有StreamAnalyzer。窗口、IP状态、乱序缓冲/水位、提交时间、冷却与idle时间都独立，而不是只在报告上加site标签。combined继续直接使用旧StreamAnalyzer，不默认推断站点。

```text
Nginx JSON统一记录 → 按site路由（最多max_sites）
                     ├─ a.local → 独立缓冲/水位 → IP窗口/冷却
                     ├─ b.local → 独立缓冲/水位 → IP窗口/冷却
                     └─ 未准入站点 → 请求计数+精确路径+容量诊断
                                      ↓
                        带site的事件 + 全局/各站点摘要
```

本文保留第二阶段站点隔离的设计与历史实测。当前3.0.0还包括SQLite调查索引（V3-INDEX）与输出滚动/健康状态（V3-RUNTIME），整版验收见RELEASE-3.0.0。强恢复未实现；旧正式包不改写，GitHub不自动同步。

## 运行（项目根，Windows CMD）

```cmd
python check_input.py examples/synthetic_sites.jsonl --log-format nginx-json
python watch.py examples/synthetic_sites.jsonl --log-format nginx-json --replay --min-paths 2 --output docs/sites-events.jsonl
python report_events.py docs/sites-events.jsonl --output docs/sites-stage.md
```

合成样例为4条请求、同一IP、两个配置站点；每站点各两条不同路径，得到2条窗口线索，不跨站点凑路径。其中a站点事件时间比b快40秒，b不应因a的水位而被判迟到。样例只是人工对照，不冒充真实流量。输出须不存在，重复运行换名。

PyCharm：运行watch.py，工作目录项目根，脚本形参 `examples/synthetic_sites.jsonl --log-format nginx-json --replay --min-paths 2`。stdout中的finding带site，summary.analysis含各站点快照。

## 站点与时间语义

site来自约定JSON中的配置标识；Nginx模板用$server_name，不把任意Host或XFF当可信站点/客户端身份。不同部署复用相同server_name仍会被视为同站点，需要操作者保证标识唯一。当前不是跨日志来源/跨进程合流；同站点时钟异常仍可能推进该站点水位。

所有站点使用同一份生效规则与阈值，仅状态隔离；尚无每站点独立配置文件。JSON线索、迟到/时间错误、容量事件带顶层site，原evidence内的site与raw保留。combined输出不额外伪造site。不同site的finish/tick按分区处理，输出不承诺全局事件时间排序。

每站点tick根据该分区最后有效到达判断idle；finish刷新所有分区。一个站点的活跃不会阻止另一个站点的idle刷新，未来时间也不会污染另一个站点水位。本站点原有迟到/冷却限制仍保留。

## 容量：不能只分区不设上限

--max-sites默认16，范围1..128；watch只允许JSON模式使用。--max-buffer、--max-window-records、--max-ips在JSON模式改为每站点限制，combined保持原限制语义。生效配置写在started.settings，summary显示capacity_scope与aggregate_upper_bounds。

默认理论状态上限为：16个站点分区，合计8192条乱序缓冲、32768条窗口记录、4096个站点/IP状态对。只是状态数量上限，不是完整进程内存上限；原始行长度、临时输出对象、解释器及JSON序列化仍有成本。

站点按本次运行首次出现准入。分区内过期IP/窗口会清理，但站点槽位及累计计数保留到运行结束，不隐式驱逐/重置旧站点的水位和冷却。超过站点上限的新site：

- 不新增分区/任意site历史映射。
- 顶层record和全局请求/状态码计数仍完整保留。
- 仍做无状态精确路径检测。
- 行为排除输出state_limit，reason=max_sites，并带原证据和site。
- 阶段报告标capacity_limit_excluded；不会误标为格式解析失败。

first-seen策略可能使长期不活跃的已准入站点仍占槽；需按实际配置预设站点上限，或分文件分进程运行。动态回收/允许列表不在本阶段实现。active_ips为各站点活动IP数量之和（站点/IP对），不是全局唯一IP数。sites摘要只包含已准入站点，未准入站点仅累计总计数、不建立无限明细表。

## 预检同步更新

check_input也接受--max-sites。多site本身不再判不就绪，超过设定站点数才提示site_capacity_exceeded。site_count_observed_at_least为有界集合观察的下界，最多保留max_sites+1个内部标识，公开样本最多20项；不能在超限后冒充精确站点总数。readiness仍只针对已读前缀，后续站点与日志质量未验证。

## 实际验证

真实Nginx实验复用acceptance/v3-input/run_nginx_json.py，新增--multi-site：两个server_name写同一JSON日志，同一连接来源交错访问。首两条分别落两个站点，仅各1个路径，等待watch确认读取后留checkpoint，确认没有跨站点虚假窗口；后续各自达到阈值。每轮6条请求、2条精确路径线索、2条窗口线索；每条窗口的证据仅来自对应site，实时与回放一致。实际报告质量无缺口，容器移除、端口无监听。

```cmd
python acceptance/v3-input/run_nginx_json.py acceptance/v3-sites/my-new-run --multi-site
```

需要本地Docker引擎及已有nginx:alpine，不自动拉取、不修改其他容器。开发机证据在acceptance/v3-sites/nginx-python311和nginx-python315，原始材料私有，不随源码包发布。

测试覆盖跨站点不合并、水位/冷却/idle独立、站点数超限仍保留精确匹配、非法站点不计数/不分配、CLI/预检/报告一致。详细完整回归输出见acceptance/v3-sites/。SQLite与来源时间线现已在后续第三阶段实现，见V3-INDEX.md；本阶段历史站点隔离实测数据不改写。
