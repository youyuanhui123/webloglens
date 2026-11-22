# 快速运行（3.0.0）

## 第三版接入与回查（CMD，项目根）

```cmd
python check_input.py examples/synthetic_sites.jsonl --log-format nginx-json
python watch.py examples/synthetic_sites.jsonl --log-format nginx-json --replay --min-paths 2 --output docs/quick-v3.jsonl
python report_events.py docs/quick-v3.jsonl --output docs/quick-v3.md
python investigate.py import docs/quick-v3.jsonl --database docs/quick-v3.sqlite
python investigate.py query docs/quick-v3.sqlite --run-id 1 --site a.local
python investigate.py timeline docs/quick-v3.sqlite --run-id 1 --site a.local --ip 192.0.2.10
```

四条合成请求分属两个站点，各产生一条窗口线索；a.local 的来源时间线有两条请求。站点是配置标签，不需要访问公网域名；SQLite 是指定路径的本地文件，不需安装服务器。输出名称须不存在。

分片、保留、完整拼接和运行健康见 [V3-RUNTIME.md](V3-RUNTIME.md)。下文保留 combined 入门方式，批量 analyze 仍只处理 combined。


## PyCharm

打开解压后含watch.py的整个WebLogLens目录，解释器选择Python3.11或更新版本，工作目录设项目根，无需安装Python第三方包。

1. 右键analyze.py运行，可看到保留的批量分析样例；版本用CMD的 `python analyze.py --version` 查看。
2. 编辑watch运行配置，脚本形参：

```text
examples/synthetic_sensitive.log --replay --min-paths 3 --output docs/demo-events.jsonl
```

3. 运行report_events.py，脚本形参：

```text
docs/demo-events.jsonl --output docs/demo-stage.md
```

4. 打开docs/demo-stage.md，核对5条请求、3条线索、质量标记和证据样本。

形参不重复解释器或脚本名。再次运行换文件名，不覆盖已有报告。输出仍为私有；样例虽然是合成的，实际日志不能照此直接公开。

## Windows CMD

资源管理器打开项目目录，在地址栏输入cmd。若从别处进入，使用 `cd /d "实际项目路径"`。完整最小演示：

```cmd
python --version
python analyze.py --version
python watch.py examples/synthetic_sensitive.log --replay --min-paths 3 --output docs/demo-events.jsonl
python report_events.py docs/demo-events.jsonl --output docs/demo-stage.md
python report_events.py docs/demo-events.jsonl --format json --output docs/demo-stage.json
python -m unittest discover -s tests -v
```

默认测试跳过2个Docker集成；会运行本机HTTP实验与短watch基线，不是纯单元测试。本机需允许回环端口监听。

## 实时观察授权日志

```cmd
python watch.py "D:\logs\access.log" --detect --output "D:\logs\my-events.jsonl"
```

文件与输出父目录须存在，输出文件须不存在。默认从末尾开始；--start beginning可读取已有内容。Ctrl+C正常结束后：

```cmd
python report_events.py "D:\logs\my-events.jsonl" --output "D:\logs\my-stage.md"
```

未加--detect的watch只读取解析，不做检测。正在写入或异常结束的事件文件也能生成质量告警报告；生成成功不等于事件完整或安全。

## 保留的批量入口与分享

```cmd
python analyze.py examples/synthetic_burst.log --data-kind synthetic --format markdown
python analyze.py examples/synthetic_burst.log --data-kind synthetic --redact-share --format markdown --output docs/batch-share.md
```

--redact-share只适配analyze报告，不适用于watch JSONL或新阶段报告。--data-kind只是调用者声明，不证明来源或授权。

## 可选实验和基线

```cmd
python run_experiment.py
python run_baseline.py --output experiments/my-baseline
python run_nginx_experiment.py
```

前两个不需要Docker；run_experiment建立本地固定响应HTTP服务。Nginx实验需要Docker引擎及本地nginx:alpine镜像，不自动拉取、不改已有容器，完成后清理本次临时容器。Nginx实验详细材料见NGINX-LAB.md。

## WSL bash（仅用法示例）

```bash
cd /你的项目路径/WebLogLens
python3 watch.py examples/synthetic_sensitive.log --replay
```

实机覆盖为Windows Python3.11/3.15，不宣称本版已在WSL独立验收。不要在bash中照搬CMD的 /d 或 %PY% 语法。

## 打包

```cmd
python build_release.py
```

默认生成dist/WebLogLens-3.0.0.zip，已有包拒绝覆盖。可用--output指定新文件。包内RELEASE-MANIFEST.json记录相对路径和SHA-256；不包含清单自身哈希，也不含私有实验证据。验收方法见ACCEPTANCE.md。

## 错误与质量

输出父目录须存在、文件须不存在；格式用--format显式选择，不按扩展名猜测。无效参数、配置或文件错误非零退出。退出0只表示流程成功，不保证没有坏行、迟到或容量排除；必须同时查看摘要与quality。
