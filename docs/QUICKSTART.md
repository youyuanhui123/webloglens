# 快速运行

## PyCharm（优先）

1. 解压便携包，用“文件 -> 打开”选择含 analyze.py 的整个 WebLogLens 目录。
2. 设置项目解释器为 Python 3.11 或更新版本；不需要安装第三方包。
3. 右键 analyze.py -> 运行：默认在控制台显示合成样例的 JSON。
4. 右键 run_experiment.py -> 运行：自动产生三组本地真实实验和双格式私有/分享报告。
5. 运行 -> 编辑配置 -> 选择 analyze -> 脚本形参填写：

```text
"examples/synthetic_burst.log" --data-kind synthetic --redact-share --format markdown --output "docs/share-report.md"
```

工作目录设为项目根目录。形参中不重复填 python.exe 或 analyze.py。相对路径按工作目录解释；默认配置和默认样例按脚本位置定位。

## Windows CMD

在资源管理器进入项目目录，在地址栏输入 cmd 打开终端，然后：

```bat
python --version
python analyze.py --version
python run_experiment.py
python -m unittest discover -s tests -v
```

如 python 不是期望的解释器，将 python 替换为 PyCharm 展示的解释器完整路径并加引号。若从其他目录进入，CMD 使用 cd /d "实际项目路径"。不要在 bash 中使用 /d 或 %PY% 语法。

## WSL bash（可选）

```bash
cd /你的项目路径/WebLogLens
python3 --version
python3 analyze.py --version
python3 analyze.py examples/synthetic_burst.log --data-kind synthetic
```

WSL 仅是使用示例，第一版当前实机验收为 Windows Python 3.11/3.15，不宣称已在 WSL 独立验收。

## 自己的授权日志

```text
python analyze.py "日志的绝对路径" --data-kind authorized --format markdown --output "docs/authorized-private.md"
```

必须是本工具支持的 combined 格式及 UTF-8 编码。先看 parsing 的 errors，不能只看退出码。不要把公开网站访问权限当作日志获取或渗透授权。

## 输出与错误

- 0：分析流程完成；不意味着没有坏行或没有风险。
- 1：输入读取/编码或输出写入失败。
- 2：命令行或配置无效。
- 已有输出拒绝覆盖，请更换文件名；输出父目录须存在。
- 一键实验需要本机允许回环端口监听；失败应排查错误，不用合成日志冒充真实结果。
- --format 不根据输出扩展名自动推断。

## 发布源码便携包

```text
python build_release.py
```

默认写入 dist/WebLogLens-1.0.0.zip；已有包拒绝覆盖。可用 --output 指定新位置。包内 RELEASE-MANIFEST.json 记录相对文件名及 SHA-256，不含实验原始证据。解压后不需安装，直接运行。
