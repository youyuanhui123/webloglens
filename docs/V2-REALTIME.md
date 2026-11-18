# 第二版：实时输入与共享增量检测（2.0.0）

## 当前范围

目标：支持历史回放与实时跟随的 Web 访问日志排查工具。不是 WAF、监控平台或自动封禁系统。已完成：单文件跟随、combined 解析、共享增量统计与两类规则、有限乱序、窗口冷却、状态限制、文件顺序回放、私有 JSONL，以及原生 Nginx 三场景实验与失败清理。第一版 analyze.py 保留原有全量排序/首窗口语义；不把它与新增回放混淆。私有阶段报告及受控合成资源/延迟初始基线亦已完成，分别见 [EVENT-REPORT.md](EVENT-REPORT.md)、[BASELINE.md](BASELINE.md)。初始基线阶段双解释器各71项完整回归通过（两个Docker集成项显式开启），证据在 acceptance/v2-baseline/。2.0.0发布套件为72项，复验方法见ACCEPTANCE.md，开发机发布证据另存acceptance/v2.0.0-release/。旧版ZIP保留。长期运行资源/延迟评估与新增报告分享模式不在本版完成范围。

## 运行（Windows CMD，项目根目录）

输入模式保持兼容，不做规则检测：

```cmd
python watch.py examples/synthetic_sensitive.log --start beginning --duration 2
```

静态文件回放，到 EOF 后刷新缓冲并退出，自动启用检测：

```cmd
python watch.py examples/synthetic_sensitive.log --replay --min-paths 3
python watch.py examples/synthetic_burst.log --replay --lateness-seconds 60
```

持续跟随自己的日志（替换实际路径），Ctrl+C 正常退出：

```cmd
python watch.py "D:\logs\access.log" --detect --start end --output "D:\logs\watch-events.jsonl"
```

PyCharm：运行 watch.py，工作目录设项目根；脚本形参可填 `examples/synthetic_sensitive.log --replay --min-paths 3`，不包含解释器和脚本路径。强制杀进程不保证输出 summary。

--start：watch 默认 end，只观察启动后的新增完整行；replay 固定 beginning，不能与 --duration 或 --start end 组合。回放不是按原始时间间隔重放请求，不发送网络请求，也不全量排序。请使用静态日志副本：文件身份、大小、mtime 或代次发生可检测变化时非零退出，已有输出属于未完成结果；这不是原子快照保证。

--interval：默认 0.2 秒，范围 (0,60]；--status-interval 默认 5 秒，正有限数；--duration 可有限时长退出。输出父目录必须存在，输出文件必须不存在，避免覆盖。显式相对路径相对当前工作目录；默认配置相对脚本目录。

## 数据流

```text
文件新增完整行 / 静态文件顺序回放
                 ↓
         follow.py → parser.py
                 ↓
     record / 坏行 / 输入状态事件
                 ↓ record
        stream.py 增量分析核心
      ├─ 请求与状态码计数
      ├─ 复用精确路径规则（立即）
      └─ UTC 时间 → 乱序缓冲 → 每 IP 滑动窗口 → 冷却
                 ↓
        finding / time_error / late_record / state_limit
                 ↓
        私有 JSONL + 周期 status + 退出 summary
```

--detect 开启检测；--replay 隐含 --detect。支持 --config、--window-seconds、--min-paths；配置先校验，显式命令行阈值再覆盖，started 保存配置来源、覆盖项和最终设置。输入模式不使用检测设置。精确匹配保持大小写敏感、不解码，只去查询串；命中不证明攻击成功。

## 时间与窗口策略

- fields.time 为日志事件时间，转换 UTC；observed_at 是工具输出时间，idle 使用 monotonic 计时，三者不混用。
- --lateness-seconds 默认 2，非负整数。缓冲用最小堆，按事件时间、到达次序排序；时间水位为已接受最大事件时间减乱序预算，达到水位的记录可提交。严格早于水位或已提交时间的记录产生 late_record，不进入行为窗口，但仍计数并执行精确路径检测。
- 新记录不足以推进水位时，经过至少乱序预算的输入空闲时间，tick 刷新尾部缓冲；正常退出也刷新。提前刷新后才到达的旧数据可能被认作迟到。迟到及坏时间不阻止已有缓冲的空闲刷新。
- 窗口是闭区间，按 IP 隔离，用 deque 和 Counter 维护请求与不同路径；同一路径不同参数不重复增加种类。窗口规则 ID 为 multi-path-window-v2，证据带原文和来源定位。
- --cooldown-seconds 默认 60，非负整数；同 IP 窗口命中在冷却期间不重复发 finding，suppressed_windows 统计被抑制的触发次数（不是丢失请求数）；到期仍满足条件可以再次告警。精确路径线索逐条保留，不做冷却。这是冷却抑制，不是完整会话/告警归并。
- 旧窗口随事件时间推进清理；空闲超过 max(window,cooldown)+lateness 时清空活动窗口状态，避免长期保留空闲对象。这意味着长时间采集中断后，即使日志事件时间连续，也不会保留先前状态拼接行为。
- 源日志时间被信任；错误的未来时间可能推进全局水位，使其他记录被标记迟到。尚未实现时钟异常诊断、多流独立水位或跨服务器合流。

## 容量与结果完整性

- --max-buffer 默认 512：等待排序的记录上限。
- --max-window-records 默认 2048：所有 IP 窗口中的记录总上限。
- --max-ips 默认 256：活动 IP 状态上限（包括冷却状态）。均为正整数。
- 超限输出 state_limit，带触发记录和原因，对该记录不继续行为检测；不静默替换旧证据。统计与精确路径检测仍有效。检测有缺口时不得据“未命中”认定安全。
- summary.analysis 包含已解析请求数、状态码计数、精确/窗口命中数、抑制次数（如发生）、迟到/坏时间/超限计数（如发生）、当前缓冲与活动状态大小。counts 包含输入与分析事件分类，不计 started/status/summary。
- 不维护无限增长的历史 IP/路径统计，不在内存保存整份报告。状态按记录数有上限，但不是实测内存预算：单行大小、输出序列化和证据副本都影响内存；JSONL 持续增长，磁盘轮转未实现。终端/磁盘阻塞可能形成背压。没有长期性能或吞吐保证。

## 输入与证据边界

- source + generation + offset（字节）定位；代次仅本次进程有效。从头读取有物理行号，从末尾不扫描历史，初始代次 line_number=null；新代次从第1行开始。对比 live/replay 时不能要求两种启动方式的行号一致。
- 末尾已有半行时，跳过后续残段；每轮读最多 64 KiB，单行上限 256 KiB。超长产生 line_too_long、丢弃至换行；无效 UTF-8 产生 decode_error，继续后续行。原日志仍是证据原件。
- LF/CRLF 支持；无换行尾部等补全，summary 标 pending_bytes。
- 改名/替换时旧句柄读到当时 EOF 再交接，旧尾部残片在 rotated 中注明字节数；交接后旧文件的迟到写入不跟随。路径缺失或 stat/open 间消失时保留旧句柄、返回已读取事件，等待恢复；其他读取/权限错误非零退出。
- 截断依赖长度与读取位置前最多64字节锚点；相同锚点重写、copytruncate 竞争及多次短暂轮转可能漏读/重复，不承诺 exactly-once。
- Windows 使用允许读写/删除共享的只读句柄，不阻止改名。当前 Windows 本机验证不代表所有文件系统；不支持网络文件系统、动态符号链接、多服务器和崩溃恢复。
- **所有事件均为私有输出**：包含 IP、原文、参数、本地路径；不是 v1 分享视图，不能直接公开。输出不能与输入同文件，独占创建拒绝已有文件。

## 验收证据

历史输入层验收在 acceptance/v2-input/，45项为当时记录，不是当前测试总数。

本阶段：tests/test_stream.py 覆盖精确规则、窗口边界、不同路径/来源、冷却、乱序/迟到、坏时间、空闲刷新和状态限额，并用固定随机种子的20组合成语料与 v1 首窗口结果作有限条件下的差分比较。tests/test_stream_cli.py 实际启动子进程验证 live/replay、配置失败和回放中输入截断；保留既有输入层及第一版回归。

acceptance/v2-core/run_smoke.py 可在一个全新输出目录复跑。smoke-02/ 包含真实启动 watch 后追加5条合成日志的原文件、live/replay JSONL 和 verification.json：两种模式均2条路径线索、1条窗口线索。比较排除 observed_at 与 line_number，原文、字节偏移和其他线索字段一致。smoke-01/ 保留首次对比的输出，当时因错误地要求 end/beginning 行号相同而断言失败，不是通过记录。burst-replay.jsonl 为7条乱序样例配置60秒预算的回放，3条路径线索、1条窗口线索。

这些是受控合成输入和真实进程运行，不是原生 Nginx/生产日志采集，也不能用于宣称检测准确率。

最终复验：Python 3.11.9 与 Python 3.15.1 各 56 项通过，实际控制台输出分别保存为 acceptance/v2-core/tests-python311.txt 和 tests-python315.txt。最终源码再次运行真实追加/回放验收通过，最新结果在 smoke-03/verification.json。独立子代理审查因连接失败未完成，不计为通过；本阶段结论仅来自可复跑测试、差分及真实进程验收。

后续原生 Nginx 里程碑已完成：`run_nginx_experiment.py` 实际运行三组回环 HTTP 场景，原生日志实时/回放对照通过，正常与请求失败路径的清理都已验证。当前完整回归在 Python 3.11.9 / 3.15.1 各62项通过（含显式启用的两个 Docker 集成项）；最新证据在 acceptance/v2-nginx/verified-02/，运行与边界见 [NGINX-LAB.md](NGINX-LAB.md)。前述56项及合成输入说明仅属于上一里程碑历史。
