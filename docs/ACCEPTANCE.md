# 验收说明（2.0.0）

## 范围

Windows Python3.11.9/3.15.1；核心无Python第三方依赖。测试覆盖批量历史入口、解析/统计/配置/分享、实时跟随边界、增量窗口/迟到/容量、真实追加与回放对照、阶段报告、基线入口和便携包。

套件共72项；默认跳过2个Docker/Nginx集成，启用后须全部实际执行。包含本机HTTP与真实子进程，不应全部称作单元测试。以下是复验方法，实际输出保存在开发机acceptance/，不会进入源码ZIP。

## 默认复验（CMD，项目根）

```cmd
python analyze.py --version
python -m unittest discover -s tests -v
python watch.py examples/synthetic_sensitive.log --replay --min-paths 3 --output docs/check-events.jsonl
python report_events.py docs/check-events.jsonl --output docs/check-stage.md
```

样例5条成功请求、2条精确路径+1条窗口线索；确认quality而不只看退出码。输出文件须不存在；重复运行请换名。

## Docker集成（可选，但不等同默认跳过的结果）

需要引擎运行及本地nginx:alpine镜像；不拉取、不修改已有容器。Windows CMD：

```cmd
set WEBLOGLENS_NGINX_TEST=1
python -m unittest discover -s tests -v
set WEBLOGLENS_NGINX_TEST=
```

正常/混合/正常多页面场景预期请求6/6/5、路径线索0/2/0、窗口线索0/1/1。正常多页面命中并不证明攻击；另有中途请求失败后的清理检查。端口无监听与TIME_WAIT可同时存在。

## 发布包复验

```cmd
python build_release.py --output dist/my-recheck.zip
```

先确认白名单文件没有真实秘密。ZIP成员都在WebLogLens/下，RELEASE-MANIFEST.json列出除清单本身之外的文件及SHA-256；成员数等于file_count+1。私有acceptance/experiments、学习日志、缓存及环境不进入包。

解压到新的中文路径；以非项目cwd运行绝对路径analyze.py --version、默认分析、watch静态样例回放与report_events双格式；然后在解压根对两解释器各跑全套测试。启用Docker时需明确72项均执行；只跑默认套件时明确有2项跳过。打包后不能继续改包内源码而沿用旧包验收，改动必须重建新包再验证。

发布回归本身也在临时中文目录构建并解压包，核对全部文件哈希、拒绝覆盖以及新增实时入口。完整双解释器搬迁验收由开发机单独留证，不递归从测试中再跑全套。

## 历史证据与新的复现

开发机保留acceptance/v1.0.0、v2-input、v2-core、v2-nginx、v2-report、v2-baseline及v2.0.0-release；源码包不携带这些原始证据。NGINX-LAB、EVENT-REPORT和BASELINE手册中引用的历史路径仅为证据位置，不是运行依赖。新机器从包内synthetic样例生成自己的事件和报告，或按实验脚本重新采集，不虚构缺失材料。

## 明确限制

测试不证明生产准确率、合规、全面安全审计或长期稳定性。未验证WSL独立部署、生产高并发、RSS/工作集、多小时泄漏、可信代理归因、强恢复和业务负载下的无损轮转。版本2.0不包含新增报告的公开分享模式；旧analyze分享视图也不保证匿名。
