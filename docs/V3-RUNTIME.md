# 第三版：输出滚动、保留与运行健康

## 默认不变

`--output FILE` 仍生成单个 JSONL，拒绝覆盖。输出目录存在且文件名是新的即可。不加输出选项只写终端。读取/写入失败非零退出；exit 0 不代表没有解析/分析缺口。

## 可选滚动（Windows CMD，项目根）

```cmd
python watch.py examples/synthetic_sites.jsonl --log-format nginx-json --replay --min-paths 2 --output-dir docs/demo-shards --output-max-bytes 4096
python assemble_events.py docs/demo-shards --output docs/demo-complete.jsonl
python report_events.py docs/demo-complete.jsonl --output docs/demo-complete.md
python investigate.py import docs/demo-complete.jsonl --database docs/demo-complete.sqlite
```

`docs/demo-shards` 必须不存在，其父目录必须存在；它属于这一次运行。`--output` 和 `--output-dir` 互斥。滚动必须显式设置正整数 `--output-max-bytes`，单位字节。完整事件不能拆行，因此单条超大事件可以超过此目标，不是严格磁盘配额。

目录结构：

```text
一次运行目录/
├─ manifest.json
├─ part-000001.jsonl
├─ part-000002.jsonl
└─ ...
```

manifest 按顺序记录分片名、大小、SHA-256 和删除标记。正常退出且首 started、末 summary 才置 complete；异常、写入失败和强杀不伪装成完整运行。它不是事务数据库或断电保证，flush 也不是 fsync。

分片不是独立完整运行，不要逐片导入/汇总。`assemble_events.py` 校验正常结束、每片未删除/存在、大小/哈希一致，按顺序拼成**新** JSONL；复制时再核对哈希，失败清理本次部分目标。拒绝覆盖旧文件。完整 JSONL 才供 report_events/investigate 使用。

也可在项目根调用：

```cmd
python -m webloglens.output assemble docs/demo-shards --output docs/demo-complete-2.jsonl
```

从非项目目录调用时优先用 `assemble_events.py` 绝对路径，避免模块搜索路径问题。manifest/哈希不是来源真实性签名，不保证有人修改全部文件后仍能识别。不要接收不可信目录当作可靠证据。

## 保留策略：默认不删除

默认保留所有分片。若只需要最近现场记录、愿意放弃整次完整导出，可显式设置：

```cmd
python watch.py "D:\logs\access.jsonl" --detect --log-format nginx-json --output-dir "D:\logs\session-new" --output-max-bytes 10485760 --output-keep-shards 20
```

仅删除本次独占新目录内、本次 writer 创建并登记的旧分片；不扫描父目录、不按时间清理原始日志，不删除其他会话。manifest 留 deleted 标记。只要实际删过分片，完整拼接就明确失败，不能静默生成“看似完整”的报告/索引。manifest 的 complete 只表示正常结束，不代表没有主动删除，拼接会同时检查 deleted。

保留上限只约束分片数量；manifest 仍保留整个运行的分片元数据且当前会重写，超长期、极小分片时会增长、增加 IO。它不是恒定内存/恒定磁盘服务：按合理大小分片并定期结束会话；生产级分片目录索引/强恢复不在本版范围。

## 健康状态

定期 status 及最终 summary 的 health：

|state|含义|
|---|---|
|waiting|当前轮未读到有效请求，等待新增数据；不是程序卡死|
|healthy|当前轮读到有效请求，尚无已观察运行问题；不是安全判定|
|input_missing|当前日志路径缺失，不能当作正常空闲|
|parse_problem|本次出现过解析、编码、超长行或时间错误|
|capacity_gap|本次出现过容量排除，需检查分析摘要|
|analysis_gap|存在过迟记录等行为分析排除，不能显示成健康|

input_state 单独给 active/waiting/missing。parse_problem、capacity_gap、late_records 与 analysis_gap 是本次运行粘性标志，之后读到正常行不会擦除历史问题；多个问题同时存在时 state 按缺路径→容量→解析→分析缺口优先显示，但布尔标志仍保留。`--status-interval` 控制间隔；回放很快时可能没有周期 status，最终 summary 仍有 health。

健康不是完整质量判定：输入轮转、来源短暂缺失、行为排除与事件完整性仍要看 analysis 和 report quality；等待不表示没有攻击，healthy 不表示网站安全。写盘错误无法靠同一损坏输出可靠记录，CLI 会在 stderr 报错并非零退出，不生成虚假正常摘要。

## 验证口径

专项测试覆盖行边界/超大行、拒覆盖、保留后拼接拒绝、异常未完成、分片篡改、IO失败、缺路径/空闲/解析/容量和单文件兼容。发布验收还包含真实双站点 Nginx 与两解释器受控持续追加，具体时长、请求数和结果见 RELEASE-3.0.0。
