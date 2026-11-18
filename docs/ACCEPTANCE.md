# 第一版验收说明

## 本次真实验收结果

开发工作区 acceptance/v1.0.0/ 已保存实际执行输出：Python 3.11 下 34 个测试通过，Python 3.15 下 34 个测试通过。真实本地实验的 baseline/mixed/normal-wide 均按预期完成，私有 JSON/Markdown 与分享 JSON/Markdown 已实际生成，服务端口关闭验证均通过。便携包另做解压搬迁复验，最终结果见发布交付说明。

## 复核补充

一键实验 summary.json 内的报告引用改为相对路径；回归测试覆盖中文证据目录、不同工作目录、整体移动目录后引用仍有效，以及重复运行不覆盖历史证据。私有报告中的原始来源路径保留为采集时证据元数据，不作为搬迁后的链接使用。

## 验收范围

受控 Windows 环境，Python 3.11 与 Python 3.15；无第三方运行依赖。核心测试包含：解析/错误行、统计与路径聚合、敏感路径规则、UTC 与滑动窗口边界、配置校验与覆盖、分享版字段剔除、JSON/Markdown 导出、文件覆盖保护、本机真实 HTTP、服务关闭及便携包搬迁。

## 复验命令

```text
python --version
python analyze.py --version
python -m unittest discover -s tests -v
python run_experiment.py
python build_release.py --output dist/recheck.zip
```

运行前输出文件须不存在；实验路径自动生成。对每个场景检查 access.log 与 manifest.json 的请求一致，report.json 与 Markdown 的数量一致，share.json 与私有版总数一致，summary.json 的 all_passed 为 true 且端口关闭验证为 true。

便携包可解压到新目录并重复上述测试。包中 RELEASE-MANIFEST.json 记录相对文件 SHA-256，不包含自身哈希；文件数量加上清单本身才是 ZIP 总成员数。

## 实验期望（不是检测准确率）

| 场景 | 请求数 | 敏感路径线索 | 行为线索 |
|---|---:|---:|---:|
| baseline | 6 | 0 | 0 |
| mixed | 6 | 2 | 1 |
| normal-wide | 5 | 0 | 1 |

正常浏览命中行为规则是刻意保留的边界，不是独立恶意标签。三个场景不足以计算代表性的误报率或准确率。

## 发布前检查

- 阅读源码、规则和合成样例，确认未写入真实秘密。
- 只发布白名单生成包，不直接压缩整个工作区。
- 不将私有实验目录或终端中的本地路径截图公开。
- --redact-share 不是完整匿名化保证，分享前人工复核。
- 测试通过不代表生产环境性能、安全性或合规认证。

## 明确尚未覆盖

原生 Nginx 独立部署验证、生产流量效果评估、WSL 独立实机验收、实时采集、可信代理链、大文件容量保证、事务式输出和任意格式日志。第一版不承诺自动判定攻击成功或自动防御。

具体发布验收输出保存在开发工作区的 acceptance/，不将本地私有验收日志打进分享源码包。以实际执行结果为准，不把本文复验方法当作已经运行的证据。
