# 架构与设计（2.0.0）

## 两条分析路径

```text
批量analyze → reader/parser → 全量统计/精确路径/UTC排序首窗口
                                             ↓
                                 私有报告 / 可选旧结构分享视图
                                             ↓
                                        JSON/Markdown

实时watch / 静态文件原顺序replay → follow/parser → stream增量核心
                                                      ↓
                                              私有JSONL事件
                                                      ↓
                                       event_report独立核对与汇总
                                                      ↓
                                           私有JSON/Markdown
```

analyze保留第一版整批读取与全量排序，不等于恒定内存；watch/replay不反复重扫全文件，不把所有历史记录永久留存。它们复用解析、精确路径及时间解析逻辑，但窗口策略不同，不承诺任意输入结果恒等。

## 输入与来源

固定UTF-8 combined。批量reader兼容BOM，保留物理行号与去换行raw；实时follow有界读取新增字节，半行等待，超长行有界恢复，处理轮转/截断/路径缺失并明确事件。来源定位为路径、运行内generation和字节offset；从末尾启动未知物理行号为null，不能伪造。raw不是字节级归档，原日志仍需保留。轮转竞争、旧文件交接后迟到追加、快速copytruncate仍有限制，不承诺exactly-once。

## 路径

target保留原样，派生路径只去第一个问号后的查询串，不URL解码、转小写或折叠斜杠。/a%2Fb与/a/b不同；编码变体漏报是已知边界。仅面向常见origin-form，不做通用URI规范化。

## 时间和有限状态

- 批量behavior按IP分组，将带时区时间转UTC，全量排序；闭区间窗口，每IP仅保留首个满足阈值的线索。
- stream使用事件时间小顶堆、有限乱序和水位，路径即时匹配，行为按提交顺序更新IP窗口；冷却抑制重叠窗口，状态过期清理。
- 默认乱序2秒、窗口60秒、min_paths=5、冷却60秒；max_buffer=512、max_window_records=2048、max_ips=256。
- 过迟和坏时间仍参与请求统计及精确路径，排除行为窗口并发事件；容量不足也明确排除，不静默当作安全。
- tick按单调处理时间判断idle，空闲flush；finish在EOF/正常结束刷新。有限状态细节见V2-REALTIME.md。

## 配置与输出

默认配置相对入口文件定位，不依赖cwd；显式CLI阈值覆盖所选配置，拒绝非法配置而非回退。默认敏感路径为/.env、/.git/config。

批量schema_version=1.1，阶段报告schema_version=stream-report-1.0；版本号2.0.0不意味着旧报告schema强制变更。watch事件为单次started、记录/诊断/线索、正常退出summary，当前没有跨运行恢复协议。

阶段报告独立计数并核对summary，不重新跑规则、不重复计算finding里的引用证据。有界读取单个事件、有界样本、全输入字节哈希；event_stream_complete与analysis_has_gaps分开。有限交叉核对不等于完整schema验证或可信来源证明。

动态值只放代码文本，拒绝覆盖输出；写盘中断可能留下部分文件，不保证事务或断电可靠。新增报告只私有，旧分享模块只适配批量报告。

## 实验边界

run_experiment建立回环HTTPServer；run_nginx_experiment使用本地已有镜像启动回环Nginx，固定文本响应，不读取真实敏感文件，不访问外部站点。只清理本次容器，Windows清理以无监听和容器移除为准，不把TIME_WAIT当服务残留。

run_baseline分开测核心与真实watch短时延迟，使用Python分配追踪，不是RSS或生产容量测试。详细口径见BASELINE.md。

## 不做

远程多机采集、可信代理链解析、HTTPS还原、自动封禁、攻击成功判定、强断点恢复、生产准确率保证和长期容量承诺。分析入口不联网、不执行日志中的表达式；实验脚本是显式建立回环服务的独立入口。
