# 资源与延迟基线（受控合成输入）

## 目的与结论边界

run_baseline.py 提供可重复的初始基线，不改 watch.py 和检测核心。所有输入均在本地生成，不连接外部目标、不监听端口、无需 Docker。它不是压力测试、生产容量承诺或长期稳定性验收。

分开测量两条路径：

```text
独立核心子进程：逐条构造日志 → parser → StreamAnalyzer → 丢弃已统计的输出
                          ↓
                 墙钟 / CPU时间 / Python分配峰值

真实watch子进程：空日志 → 等started → 父进程持续追加 → watcher输出finding
                          ↓
                 同一父进程单调时钟配对 → 延迟分布
```

## 复跑（Windows CMD，项目根）

```cmd
python run_baseline.py --output acceptance/v2-baseline/my-run
```

默认核心负载为1000、10000条；实时追加40条，间隔0.05秒，watch轮询也设0.05秒。输出目录必须不存在，拒绝覆盖历史证据。

```cmd
python run_baseline.py --output acceptance/v2-baseline/my-custom-run --sizes 1000 20000 --live-records 60
```

--sizes 为1..1000000的整数列表，每个规模启动新的解释器进程，避免前一规模的堆/缓存干扰；--live-records 最大200。worker单次有180秒上限，失败可能保留诊断目录，不自动删除证据。计数不符、重复线索、子进程异常或超时均失败退出。尚未完成的失败目录不可当作成功结果。

PyCharm：入口 run_baseline.py，工作目录项目根，脚本形参 `--output acceptance/v2-baseline/my-pycharm-run`。需要测试某解释器时选相应解释器，不要把python和文件名再填进脚本形参。

## 测量口径

### 核心耗时与分配

- 单IP、两种精确路径，每10条访问一次 /.env，其余访问 /，均为404；不产生多路径窗口线索。
- 合成事件时间每条递增1秒，与处理机器的真实时间无关。该负载刻意使窗口过期，因此不是“同一秒10000请求”的场景。
- lateness_seconds=0；其余采用StreamAnalyzer默认值（窗口60秒、min_paths=5、冷却60秒、max_buffer=512、max_window_records=2048、max_ips=256）。
- 逐条生成，不预先把整个输入放进列表；成功解析及feed/finish产生的事件只计数、不长期保存。每组结束断言record数、路径线索预期数、容量事件为0。
- wall_seconds 使用perf_counter，cpu_seconds使用process_time，覆盖日志构造、解析、检测及输出计数，不包含子进程启动和CLI逐事件JSON序列化、磁盘/终端输出。
- 测量启用了tracemalloc，因此耗时含追踪开销。records_per_second 仅为这个受追踪核心循环的派生速率，不能当作完整watch吞吐。
- python_current_bytes / python_peak_bytes 是追踪开始后的Python分配，不是RSS、工作集、私有提交或系统总内存；解释器启动、预先导入及部分原生分配不包括在内。
- tracemalloc开始于分析器初始化之后，本组结果用于相同口径对照，不代表完整分析器所有内存成本。final_state保留最后缓冲/IP/窗口大小，不代替运行期间的全状态峰值。

### 实时线索延迟

- 真正运行watch.py --detect，等待started后才写日志，避免默认从末尾启动漏掉起始输入。
- 每条访问 /.env?baseline=N，query用来关联，但不改变精确路径命中；40条来自单IP，故没有窗口线索。
- 父进程记录“准备构造并写入该行之前”的perf_counter，到读线程从watch stdout读到完整finding行的perf_counter之差，单位ms；同一父进程时钟，不混用UTC日志时间。
- 该端到端观测包含日志行构造、写入、轮询、解析/检测、JSON输出、管道与线程调度，不是严格的“完整行可读时刻到检测”的净延迟。writer无用户态缓冲，但不fsync，亦不测断电持久性。
- watch同时flush私有JSONL并输出stdout；stdout由线程持续读取，不是PyCharm/终端渲染速度。保存live-events.jsonl、live-access.log和stderr；JSON中保留逐条延迟及完整summary。
- P50/P95用nearest-rank；只有40个样本，不能推断高并发长尾或SLA。轮询与写入周期接近会形成相位效应，P95可能小于轮询周期，不意味着轮询上限被突破。
- 仅测即时精确路径线索，不包含行为窗口凑齐、乱序容忍或idle flush等待；未测默认0.2秒轮询。

## 本次实际结果

解释器按顺序运行，避免两套基线同时争用本机资源；不是严格隔离机器，后台负载未固定。以下各一次，不给版本优劣结论。

|解释器|核心条数|墙钟秒|CPU秒|Python分配峰值KiB|
|---|---:|---:|---:|---:|
|3.11.9|1000|0.308|0.312|279.3|
|3.11.9|10000|2.811|2.812|279.2|
|3.15.1|1000|0.116|0.109|352.1|
|3.15.1|10000|1.114|1.094|357.1|

各规模最终都仅保留1个IP、61条窗口记录，缓冲0，容量事件0。在这个固定基数/时间递增输入下，没有观察到随历史条数近似线性增长的追踪峰值；不能据此排除其他负载或长期泄漏。

|解释器|写入/对应线索|P50 ms|P95 ms|最大ms|
|---|---|---:|---:|---:|
|3.11.9|40 / 40|13.05|24.94|55.39|
|3.15.1|40 / 40|7.81|13.97|56.08|

原始未舍入结果：acceptance/v2-baseline/python311/baseline.json 和 python315/baseline.json。平台字符串直接由各解释器platform.platform()记录；不同Python可能将同一Windows版本识别为Windows-10或Windows-11，不用它推断换了机器。

## 验收及尚未覆盖

TDD端到端测试先因缺入口失败，实现后通过。两解释器完整回归各71项OK，显式开启两个真实Docker集成项；完整输出在acceptance/v2-baseline/tests-python311.txt、tests-python315.txt。

未覆盖：进程RSS/工作集、CPU百分比、磁盘容量与写放大、高基数IP/路径、真实乱序峰值、网络挂载日志、生产流量、Nginx写缓冲到日志可读的时间、多小时运行、默认轮询与不同负载重复对照。文件轮转边界已有功能测试，但本基线不测持续高负载下的轮转无损性。

基线阶段的71项是历史验收数；2.0.0发布套件为72项，发布复验见ACCEPTANCE.md。旧版ZIP保留；短基线不能写成“长期稳定性已完成”，未做的指标保留为限制。
