# 演示与项目表达（3.0.0）

## 五分钟演示（CMD，项目根）

```cmd
python analyze.py --version
python check_input.py examples/synthetic_sites.jsonl --log-format nginx-json
python watch.py examples/synthetic_sites.jsonl --log-format nginx-json --replay --min-paths 2 --output docs/interview-events.jsonl
python report_events.py docs/interview-events.jsonl --output docs/interview-stage.md
python investigate.py import docs/interview-events.jsonl --database docs/interview.sqlite
python investigate.py timeline docs/interview.sqlite --run-id 1 --site a.local --ip 192.0.2.10
```

输出名必须不存在。先声明为合成样例，核对四条请求、两个站点各一条窗口线索；a.local 时间线两条请求关联同一窗口。数据库不用单独部署。再展示受控真实 Nginx 实验及正常多页面反例，而不是把手写日志说成真实采集。

运行健康、滚动与保留的演示见 V3-RUNTIME。实时观察时说明自己是在排查线索，不是给请求自动贴恶意标签。

## 可如实描述

WebLogLens：支持历史回放、实时跟随与来源回查的本地 Web 日志排查工具（个人实践，AI 辅助开发）。围绕完整行增量读取、有限乱序与容量限制构建可解释检测；按配置站点隔离窗口、水位与冷却，保存事件定位及质量诊断。支持输出留存与来源回查，以 SQLite 作为可重建索引。设计正常、可疑与正常多页面对照实验，核验真实 Nginx 采集、实时/回放、报告及清理；通过回归测试和中文路径解压复验验证交付。

主要由 AI 编码时说“参与设计并复现”，只有自己理解并能复现的部分才说“实现”。不能包装成客户项目、生产安全运营经历、独立原创漏洞发现或高准确率检测系统。测试通过不证明个人已独立掌握。

## 要能解释的取舍

- 为什么不每秒重扫？避免文件越大重复工作越多、线索重复；采用增量读取和有界状态。
- 为什么保留批量入口？历史全量排序与现场有限乱序互补，语义不同。
- 为什么按站点隔离不只改键？水位、冷却和 idle 也会互相污染。
- 为什么需要质量提示？完整保存排除诊断不代表所有请求参与了行为分析。
- 为什么不自动解码路径？保留原始语义，代价是编码变体不自动等价。
- 为什么 200 不证明泄露？没有响应内容与应用上下文；404 也不抹去探测事实。
- 为什么 IP 不是攻击者身份？NAT、代理和共享出口可合并多人。
- 为什么正常多页面也展示？达到阈值只是行为特征，不能只展示命中的可疑样例。
- 为什么 SQLite 不是主卖点？它只负责回查，核心价值是来源可信边界、检测解释和可靠运行。
- 为什么保留原事件？数据库可重建，回放与实时是不同观察，不一定是不同访问。
- 为什么滚动要能完整拼接？只看某片缺 started/summary 会丢上下文；主动删除旧片后不能再声称完整。
- 如何解释资源基线？tracemalloc 非 RSS，短时测试不是生产 SLA，具体实测时长以验收记录为准。

## 局限

本地单文件、显式约定格式；不自动封禁、不判断入侵成功。未证明生产准确率、高负载容量、多小时内存稳定、无损轮转或断电恢复。后续扩展依据实际使用反馈，不继续为简历堆规则、平台和大屏。
