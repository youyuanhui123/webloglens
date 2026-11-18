# 原生 Nginx 实时排查实验

## 本阶段做了什么

用现有本地 nginx:alpine Docker 镜像启动临时 Nginx，HTTP 只发布到 127.0.0.1 的动态端口。Nginx 原生 combined access log 直接落入独立宿主证据目录，watch.py --detect 跟随新增日志；停止并移除容器后，对同一份日志进行静态回放，核对线索和证据。这不再是 Python HTTPServer 自定义日志，但仍是受控本机实验，不是生产数据。

```text
本机 HTTP 请求 → Docker Nginx → 原生 access.log（宿主挂载目录）
                                  ↓
                          watch.py --detect
                                  ↓
                         线索 + 私有 live.jsonl
                                  ↓
                  结束 watcher、移除本次实验容器
                                  ↓
                    静态回放 → 对照线索与原始证据
```

## 如何运行

要求：Docker 引擎可用，已经有本地 nginx:alpine 镜像。普通日志分析不依赖 Docker；只有本实验需要。runner 不会自动拉取镜像、安装 Docker 或修改引擎设置，缺少镜像或引擎未启动会明确失败。

Windows CMD，在项目根目录：

```cmd
python run_nginx_experiment.py
```

默认创建项目下 experiments/nginx-<UTC>-<随机后缀>/。指定目录必须不存在：

```cmd
python run_nginx_experiment.py --output acceptance/my-nginx-run
```

--image 可以选择已有本地镜像或镜像 ID；实验先 inspect，后按实际 Id 创建容器，保留 RepoDigests，避免同一运行中标签变化影响复现。默认本机实测 nginx/1.31.8；实际使用版本以该次证据为准。

PyCharm：运行 run_nginx_experiment.py，无需填参数；使用现有解释器。可在脚本形参填 `--output acceptance/my-nginx-run`，工作目录为项目根。请等程序正常结束；IDE 强制终止父进程或关闭 Docker 不能保证 finally 得到执行。

## 三个固定场景

所有服务都只返回固定文本，/.env 与 /.git/config 返回 404，不存在真实敏感文件，不做代理或外部请求。

| 场景 | 请求数 | 敏感路径线索 | 多路径窗口线索 | 用途 |
|---|---:|---:|---:|---|
| baseline | 6 | 0 | 0 | 正常重复访问少量页面 |
| mixed | 6 | 2 | 1 | 敏感路径请求与多页面混合 |
| normal-wide | 5 | 0 | 1 | 正常浏览也会达到多路径阈值 |

阈值固定为 60 秒、5 个不同路径，冷却 60 秒；这组单来源、有序实验明确用 lateness_seconds=0，便于验证新增记录立即进入窗口。默认实时模式的2秒乱序策略已由核心测试覆盖，本实验不冒充跨机乱序验证。配置与 watch 命令均留存，不受用户修改 rules/default.json 影响。

/ready 只做 HTTP 就绪检查并关闭 access_log，避免混入场景统计。等待 watcher 的 started 事件后才发送场景请求，不用固定睡眠猜启动成功。每场景 watcher 最多约5秒；若宿主严重繁忙、请求超过时限，验收会失败，不会补写假日志。

Nginx 看到的连接来源可能是 Docker NAT 网关，本次为 172.17.0.1；不把它当作真实公网客户端身份，不伪造 X-Forwarded-For。

## 证据结构

```text
<本次输出目录>/
  image.json                 实际本地镜像 Id/RepoDigests
  experiment-config.json     固定检测配置
  summary.json               三场景结果与失败信息
  baseline/ mixed/ normal-wide/
    nginx.conf               可复跑的 Nginx 配置
    nginx-config-test.txt    nginx -t 真实输出
    container.json           实际绑定/资源/标签信息（私有）
    access.log error.log     Nginx 原始日志
    requests.json            请求目标、时间、响应状态和固定响应正文
    watch-command.json       实际 watcher 命令
    live.jsonl replay.jsonl  私有实时/回放事件
    watch-stdout.jsonl       真实 watcher 控制台输出
    watch-stderr.txt replay-stderr.txt
    container-console.txt
    cleanup.json             本次容器移除和端口检查
    verification.json        哈希、命中与证据对照结果
```

failed 场景也保留已取得的请求清单、清理结果及顶层 error，不把输出目录覆盖复用为“成功”。log_path 使用相对引用，原始证据里的采集路径仍可能是绝对路径。这些都是私有材料，不能因实验对象是固定文本就公开整个目录。

## 清理和安全范围

每场景使用唯一容器名 webloglens-nginx-<随机串> 和唯一所有权标签。finally 清理前检查标签，只移除本次实验容器；不停止其他容器，不删除镜像/卷，不运行 prune，不停止 Docker Desktop。容器设置内存、CPU 与进程数量上限，但这不是宿主资源性能测试。

正常与请求失败路径均已实际验证：watcher 退出或被终止，本次容器被删除，检查容器列表确认不存在；Windows 使用 netstat TCP 监听表确认该端口没有 LISTENING，保留该端口的相关行作为证据。TIME_WAIT 或 ESTABLISHED 与 LISTENING 不同；连接超时、暂时不能独占重绑不能直接证明服务还在监听。host_port_released 仅为独占重绑的补充诊断，不作为唯一清理判据。非 Windows 采用保守绑定检查，本轮没有 Linux 宿主实验验收。

若强杀程序导致中断，先检查遗留项，不进行批量删除：

```cmd
docker ps -a --filter "name=webloglens-nginx-"
docker inspect 具体容器名
```

确认是本实验遗留且标签匹配后，才针对该名称执行 `docker rm -f 具体容器名`。不要清理其他靶场容器。

## 验收与已知限制

最新保留证据：acceptance/v2-nginx/verified-02/。三组 live/replay 比较排除 observed_at 和启动位置造成的 line_number 差异，原始文本、字节偏移和其他线索字段一致。realtime-confirmation.json 验证线索在 watcher 结束前已输出，不仅是退出时统一计算；这不是端到端延迟基准。

完整回归（包含真实 Nginx 与注入请求失败的清理）在 Windows Python 3.11.9 / 3.15.1 各62项通过。默认测试不要求 Docker，会跳过两个集成项。Windows CMD 显式启用：

```cmd
set WEBLOGLENS_NGINX_TEST=1
python -m unittest discover -s tests -v
set WEBLOGLENS_NGINX_TEST=
```

不宣称生产准确率、海量吞吐、多服务器、客户端真实 IP 归因或长期稳定性。本阶段也没有验证 Nginx 在持续业务流量下的轮转竞争；既有文件轮转/半行测试不等于生产轮转无损保证。私有阶段报告现已提供，见 [EVENT-REPORT.md](EVENT-REPORT.md)；受控初始基线见 [BASELINE.md](BASELINE.md)，2.0.0发布复验见 [ACCEPTANCE.md](ACCEPTANCE.md)。
