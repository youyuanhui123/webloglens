# 第三版·阶段三：SQLite调查索引与来源时间线

## 定位

investigate.py把已经保存的单次事件JSONL导入私有SQLite；不重新检测、不连接远程目标。JSONL仍是原始事件证据，SQLite是可重建的派生索引，不能替代原始日志或证明数据来源可信。

```text
静态JSONL → 有界暂存副本 → 运行质量核对 → SQLite单事务导入
                                      ├─ runs：来源SHA/质量/配置与摘要
                                      ├─ events：顶层事件、查询列、原事件对象
                                      └─ evidence_links：线索与原请求关联
                                                        ↓
                                 条件查询 / 来源访问时间线 / 私有JSON或Markdown
```

本阶段已提供站点/来源/时间/路径/状态/规则筛选、分页、有界返回及线索关联。尚无GUI、自动围绕某条线索计算前后时间范围、输出滚动/保留策略、强断点恢复或完整第三版发布。

## 从包内合成样例演示（Windows CMD，项目根）

先生成新事件，文件及数据库名须不存在，输出父目录须存在：

```cmd
python watch.py examples/synthetic_sites.jsonl --log-format nginx-json --replay --min-paths 2 --output docs/index-events.jsonl
python investigate.py import docs/index-events.jsonl --database docs/private.sqlite
python investigate.py query docs/private.sqlite --run-id 1 --site a.local
python investigate.py query docs/private.sqlite --run-id 1 --kind finding --rule-id multi-path-window-v2
python investigate.py timeline docs/private.sqlite --run-id 1 --site a.local --ip 192.0.2.10 --format markdown --output docs/index-timeline-report.md
```

该合成输入4条请求、2条窗口线索。a.local时间线为2条请求，它们关联同一条窗口线索，不因此变成4条请求或2次独立攻击。重复演示请换文件名，不覆盖旧证据。

PyCharm：入口investigate.py，工作目录项目根。脚本形参分别填 `import docs/index-events.jsonl --database docs/private.sqlite` 或 `timeline docs/private.sqlite --run-id 1 --site a.local --ip 192.0.2.10`；不重复python或脚本名。

## 条件查询

```cmd
python investigate.py query docs/private.sqlite --run-id 1 --site a.local --ip 192.0.2.10 --path /a --status 200
python investigate.py query docs/private.sqlite --start "2026-11-18T02:00:00Z" --end "2026-11-18T02:00:41Z" --limit 2 --offset 0
```

- 默认kind=record，只数顶层请求，不把finding.evidence再次当请求。kind=finding查线索；kind=all可包含启动、摘要及诊断事件。
- path是去首个问号后的精确派生路径，不URL解码、不模糊匹配。原target及查询串完整保留在event.fields；status也不证明访问成功。
- 路径/状态筛选仅适用于kind=record；窗口没有唯一path/status，CLI会拒绝歧义组合，而非默默漏掉窗口。rule-id要求kind=finding或all。
- site/IP为记录中的精确值，不等于已核实站点唯一性或真实操作者。combined缺site时仍为null，不捏造站点。
- start/end为含秒、显式时区的ISO8601，转换为固定格式UTC，边界闭区间。请求按日志事件时间排序；窗口线索以end_time、精确线索以引用请求时间定位，不拿observed_at当请求时间。
- 无法解析的时间存为null并在index.issues明确提示；默认排到最后，时间范围筛选不会包含null，不能据此断言该时段没有活动。
- 同一时刻按run_id/event_line稳定排序。run_id与事件id是本数据库内标识，不保证换一个导入顺序重建后仍相同；来源SHA+物理行号/字节偏移用于回查原事件文件。

## 时间线与关联

时间线必须指定ip，可再指定site/run-id/时间范围。每个items元素仍是一条顶层record，related_findings仅列已有线索的id、规则和站点，避免重复嵌入整份证据。每条最多展示20个关联，related_findings_total为精确关联数，related_findings_has_more标明省略。

关联限定同一run，以日志来源、generation和offset寻找原record；同时核对fields与raw，矛盾则拒绝导入。找不到、缺定位或有多个同定位候选，不随便关联，记录unresolved_evidence_links。空证据、请求/线索缺事件时间也作为独立index.issues保留。

这只是访问事实及已有线索的时间整理，不自动推断攻击链、会话或入侵成功。时间线没有自动扩大时间范围；需依据线索时间自行提供start/end。

## 多次运行与追加

```cmd
python investigate.py import "另一份完整事件.jsonl" --database docs/private.sqlite --append
```

默认数据库独占创建，已有文件拒绝覆盖；append只能针对本工具兼容的现有索引。每份JSONL须对应单次完整运行，不能把多次运行拼成一个文件。按完整事件文件SHA-256拒绝同字节重复导入，不是按真实请求去重：实时和回放的JSONL字节不同，可以各存为独立run，因此跨run统计可能重复观察同一批HTTP请求。调查时建议先指定--run-id。

每次导入事务独立，失败追加不保留半个run；新建失败只清理本次创建的数据库。structural完整性不通过（缺摘要、坏JSON、未知事件/规则、计数冲突等）直接拒绝，不生成一个看似完整的部分索引。事件流完整但含迟到/容量排除等分析缺口可以导入，保留source quality；index.issues另描述关联/时间投影缺口，不将二者混为安全判定。

原始文件复制前后及提交前核对可检测的身份/大小/mtime，副本全字节hash与质量预检一致。该流程不是对抗性原子快照或签名验证；查询不会自动重新读取原JSONL，数据库和原始证据应分别受控保存。

## 预算与存储

- 默认单份源文件最多256MiB（max-source-bytes，上限1GiB），先按已知大小有界复制到临时目录，再做质量预检，避免不断增长的文件让预检读不完。临时副本自动清理，可能占用系统临时盘，需留空间。
- 单事件行默认/最大2MiB；顶层事件默认100000、上限1000000；证据引用默认500000、上限1000000。max-events和max-links超限使本次导入回滚，不截去后半段假装成功。
- SQLite是磁盘索引，append总量没有自动保留/配额；原文和finding引用可能重复占空间。尚未做海量导入、磁盘写放大或长期容量评估。
- 查询limit默认100、范围1..1000；offset为0..1000000。max-payload-bytes默认4MiB、上限16MiB，限制items的序列化payload预算，不是整个进程RSS或最终美化输出文件字节数。
- total为当前筛选条件的精确SQL计数，returned为实际条数，has_more与next_offset基于实际返回条数。下一项放不下时不跳过或截改证据，next_item_exceeds_budget=true；若一项也放不下，next_offset不前进，需要提高预算，不能无限按同一参数翻页。
- 运行质量摘要仅附本页涉及及显式run-id，最多20个；run_summaries_omitted提示更多，quality_scope说明范围。无匹配/小预算返回空，不代表安全或所有run没有缺口。
- 时间线每项关联元数据也计入payload预算；运行摘要、输出缩进和固定头部不在payload预算内，另受条数和源事件上限约束。
- SQL筛选值均为参数，列名和排序固定。查询用mode=ro与query_only，不创建缺失数据库；单次计数与结果页用同一读取事务。不是任意第三方SQLite的安全沙箱，application_id/schema版本检查不是可信签名。
- 5秒连接超时是锁等待上限，不是查询CPU预算。limit限制返回量，不保证COUNT/排序对超大数据库的工作量；目前没有生产级性能承诺。

## 隐私与错误

数据库、JSONL和导出都含原文/IP/查询串/本地路径，当前只有私有模式，无加密、无新增分享视图。Markdown动态值只放代码块，安全显示不等于脱敏。开发工作区.gitignore排除SQLite/sidecar/非白名单JSONL；忽略不等于文件已经脱敏，也不能撤回已上传的数据。

输出文件拒绝覆盖，不能与数据库路径相同。CLI返回0表示操作或报告生成成功，不表示源分析无缺口；stderr会提示质量/索引缺口及payload预算问题。数据库提交成功后，若独立报告输出因磁盘/权限失败，数据库可能已成功建立，需检查后再操作；不承诺数据库与报告两文件的原子事务，也不承诺断电恢复认证。

## 实测材料

acceptance/v3-index/run_verify.py在两套解释器下分别真实调用CLI，导入此前留存的两份原生Nginx双站点事件及一份容量受限回放，读回SQLite核对18条请求、11条线索、3个run；它们包含同一请求的多次观察，不能当作18次独立HTTP请求。过滤a站点404路径得1条；指定run的来源时间线3条请求、2条不同线索，索引关联不会重复计请求。SQL完整性与外键检查通过，重复/缺摘要输入拒绝，原事件字节未变。

这些是对已留存真实实验事件的索引验收，本轮没有重新启动Nginx来冒充新采集；正常回归仍可显式运行既有Docker集成。数据库及报告在acceptance/v3-index/python311、python315，默认私有，不打进源码包。
