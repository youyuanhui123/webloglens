# 第三版·阶段一：约定的Nginx JSON接入

> 本文保留输入阶段的历史实测；当前正式版本为3.0.0，整版状态以README和RELEASE-3.0.0为准。

## 当前交付与边界

输入阶段新增ingest.py统一适配、check_input.py有界接入检查、watch.py --log-format nginx-json；combined仍为默认，analyze.py保持旧批量combined语义。site/请求耗时/request_id保留；站点隔离见[V3-SITES.md](V3-SITES.md)，SQLite与时间线见[V3-INDEX.md](V3-INDEX.md)，输出滚动与运行健康见[V3-RUNTIME.md](V3-RUNTIME.md)。强断点恢复未实现。

当时开发版本为3.0.0.dev1；当前已统一3.0.0。dist/WebLogLens-2.0.0.zip保持冻结，历史验收数据不改写。本文不代表已同步或推送GitHub。

```text
combined / 约定Nginx JSON → ingest适配 → 统一fields + 原始raw
                               │                    ↓
                       有界接入检查             watch实时/回放
                               ↓                    ↓
                    样本质量与缺失能力       原有检测核心 → 私有事件 → 阶段报告
```

## 直接运行（Windows CMD，项目根）

下面使用明确人工编写的synthetic样例，不冒充真实Nginx采集：

```cmd
python analyze.py --version
python check_input.py examples/synthetic_nginx.jsonl --log-format nginx-json
python watch.py examples/synthetic_nginx.jsonl --log-format nginx-json --replay --min-paths 3 --output docs/v3-events.jsonl
python report_events.py docs/v3-events.jsonl --output docs/v3-stage.md
```

5条请求、2条精确路径线索、1条窗口线索。输出文件须不存在，父目录须存在；再次运行换名。真实日志与报告仍私有，不因JSON格式改变而自动脱敏。

PyCharm：入口check_input.py，工作目录项目根，脚本形参 `examples/synthetic_nginx.jsonl --log-format nginx-json`。实时观察用watch.py，形参 `"你的日志路径" --log-format nginx-json --detect --output "新的事件文件路径"`；默认从末尾观察新增完整行，Ctrl+C正常结束。

## JSON契约

每个物理行一个JSON对象，schema为webloglens-nginx-1，不自动猜格式、不接受任意自定义JSON。required字段：

|字段|类型与语义|
|---|---|
|schema|固定字符串webloglens-nginx-1|
|time|秒级ISO8601，必须有Z或±HH:MM时区；拒绝小数秒而不是截断|
|ip|有效IPv4/IPv6连接来源地址，不是已验证真实用户身份|
|method|有效HTTP token|
|target|以/开头且无空白/控制字符的原始origin-form请求目标，含查询串|
|protocol|HTTP/1.0、HTTP/1.1、HTTP/2.0或HTTP/3.0|
|status|整数100..599，不接受布尔值或数字字符串|
|body_bytes|非负64位有符号范围内整数|
|site|非空、无空白/控制字符、最多255字符的配置站点标识|
|request_time|非负有限数值，秒，最大1e9；不接受布尔/NaN/Infinity|
|request_id|非空文本，最多256字符；保留关联字段，不保证全局唯一|

referer/user_agent可选，缺少时为null，不冒充已采集到“-”。本契约拒绝重复键、未知字段、错误类型、未约定时间精度和控制字符；异常请求不满足契约时作为坏行，不静默伪造成功记录。畸形HTTP请求可能使Nginx变量为空，因此真实环境仍可能出现解析错误，必须看质量计数。

time转换为旧核心可读的英文月份格式，同时保留event_time_iso；不重写raw、原始target、百分号编码或查询串。combined仍走原parse_line，不因新增格式暗中改变其宽松字段校验。

## Nginx配置方式

examples/nginx-json-format.conf仅含http上下文的log_format，使用escape=json；它不是可直接替换生产nginx.conf的完整配置。实验副本中，将它包含在http{}内，并为目标server配置明确的server_name：

```nginx
http {
    include /实际配置路径/nginx-json-format.conf;
    server {
        listen 8080;
        server_name demo.local;
        access_log /实际日志路径/access.jsonl webloglens_json;
        # 其他业务配置保留
    }
}
```

先在授权副本中校验配置和固定响应实验，再由操作者决定是否应用到真实服务；本轮没有修改用户的业务Nginx配置。日志目录权限/磁盘/轮转需另行管理。日志格式使用$server_name而非客户端可控Host；若多个业务复用相同server_name，它仍不能充当可靠唯一站点ID，需按部署明确设计。$remote_addr也可能是代理地址；不读取或信任X-Forwarded-For。

## 接入检查口径

默认最多1000物理行、4MiB读取、单行64KiB。max-lines上限100000、max-bytes上限64MiB、max-line-bytes上限1MiB。超长行有界跳过，错误样本最多20条；max-sites默认16（1..128），预检内部最多保留max_sites+1个站点标识用于判断超限，site样本最多输出20项。统计parsed/errors/blank和独立time_errors、时间范围、字段可用性、物理行号/字节偏移，不把缺失耗时默认成0。

sample_sha256只覆盖实际读取的前缀，不是全文件哈希；sample_limited=true表示后续未检查。ready_for_detection仅表示已观察样本没有格式/时间/来源变化/站点容量问题，不保证后续日志适配、不保证无攻击。即使输出0退出码也需看readiness，0只表示检查报告生成成功。stat前后核对不是原子快照或对抗性防篡改保证。

不完整EOF尾行即使JSON语法完整，也不判就绪，因为watch要等换行。解析期间文件身份、大小或mtime可检测变化会提示source_changed。无效参数、读取错误、输出冲突非零退出，拒绝覆盖。

## 站点隔离（第二阶段已更新）

第一阶段仅允许单站点的保护已被有界站点隔离取代。JSON --detect/--replay按site各自维护窗口、水位与冷却；多site在上限内不再判错。超过--max-sites时请求仍保留且精确路径继续检查，行为排除归state_limit，不再归parse_error。详情与总资源上限见[V3-SITES.md](V3-SITES.md)。combined没有site字段，操作者仍需保证来源范围。

## 原生Nginx实测

开发机acceptance/v3-input/run_nginx_json.py使用本地已有镜像，只绑定127.0.0.1动态端口，固定文本响应，不读真实敏感文件、不拉取镜像。实际发送6个请求由Nginx写JSON，接入检查/实时/回放/阶段报告核对成功，两套解释器分别运行。每轮为6条成功、2条精确路径+1条窗口线索，无解析缺口；引号和反斜杠User-Agent经escape=json保留，伪造X-Forwarded-For不替换连接IP。

/%2eenv可能被Nginx路由到/.env位置，但日志$request_uri仍编码原样，当前规则不会自动把它当/.env命中；这正是原文/服务端处理语义不同的边界。窗口可能在finish阶段输出；两个路径线索已在watch结束前产生。不宣称行为线索总是即时。

证据：nginx-02、nginx-python315；nginx-01保留首轮验证器失败材料（Windows同一时钟刻度导致finish线索与summary时间相同，错误的严格小于判据已修正为考虑事件顺序，未更改检测核心）。每轮容器移除、端口无监听；TIME_WAIT不是残留服务。

## 后续阶段与整版状态

站点隔离、SQLite查询/来源时间线、输出留存与运行健康已完成。当前3.0.0的发布验收见RELEASE-3.0.0与ACCEPTANCE。GitHub Release需操作者另行创建，打包不等于远端已发布；强断点恢复仍不在本版范围。
