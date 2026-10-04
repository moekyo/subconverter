# 独立评估对照与分期验收（2026-10-03）

本页保留第一轮评估记录。PR #1 后续六项 finding 的修复、当前测试与兼容边界见 [2026-10-04 六项复审修复](PR1_REVIEW_FIXES.md)；后续自动组/容器边界与当前限定见 [第二轮修复](PR1_SECOND_REVIEW_FIXES.md)。

## 决策

继续在 `moekyo/subconverter` 上做选择性增量，不整包合并候选 fork。先修已经支持的协议和显式损失诊断；新协议的成功输出不能代替完整性门槛。

基线为 `37761233af84b2ffc8ef1112da553751a087306b`；参考 fork 为 `asdlokj1qpi233/subconverter@ecb63a9b49c8a269a80578704117b20c3e8a19f9`。用户提供的独立评估全文 1682 行（含原始记录附录）已核对。报告中的“原函数 harness”与本分支编译的生产静态转换库是不同证据；两者都不是 NAS 部署或真实线路握手。

## 已直接复现并修复的旧协议单元

`tests/pro-review-regressions.py` 最初 11 项断言全部失败，修复后通过；追加安全边界测试继续保留。没有通过改写预期去接受旧错误。

| 问题 | 当前处置 | 证据 / 限制 |
| --- | --- | --- |
| SS2022 规范明文 userinfo | 支持 percent 编码的 method/password，并保留传统 Base64 URI | 生产解析器正向与负向测试；不声称所有非标准变体都支持 |
| SS 未知插件剥成裸 SS | 结构化输入与 Clash 输出显式拒绝未建模插件 | 不把缺少插件当成普通 SS 成功 |
| 配置值含 `=` 被拆碎 | 配置键值只拆第一个 `=` | Surge 的 Base64 padding 密码红转绿 |
| SS plugin mux 重复拼接 | 修为单独 `mux` 标志 | 保留已有插件处理，非通用插件导入 |
| 明文混合 URI 被再次 Base64 解码 | 先识别 URI 容器；只解码 Base64 聚合 | raw / Base64 混合旧新协议测试 |
| 单协议 exporter 重复上一条 URI | 每节点重置临时输出；不兼容时告警并跳过 | SS + 不可转 SS 的 SSR 负控 |
| QX AnyTLS 输入空分支 | 完成构造、tls-host、显式 flags 和证书 pin 处理 | 未实现的 QX 选项显式拒绝，非 QX 实机验收 |
| AnyTLS sing-box outbound 错写 users | 改为 password；会话参数与 TLS/detour 映射 | JSON 字段断言；非 sing-box 核心握手验收 |
| AnyTLS URI 默认端口、IPv6、认证解码、溢出 | 严格共享 URI 边界；默认 443；只解码一次 | 保留 literal `+`，拒绝坏 percent、控制字符、歧义 query |
| AnyTLS 客户端指纹 / 证书 pin 混淆 | 独立字段；Mihomo 分别输出；完整 ALPN / session 参数 | 不把 SPKI pin 当成 whole-certificate pin |
| HY2 URI 默认 443 / percent auth / port 范围 | 严格单端口或 hopping 范围，保留 obfs、pin、ALPN | 不支持的目标范围/obfs/pin 明确跳过 |
| HY2 YAML ALPN / UDP 丢失 | 完整列表、明确 false 与缺省分开 | 原 REALITY 测试不再忽略 HY2 UDP 缺失 |
| QX 不支持的 transport 输出成 TCP | 显式拒绝尚未实现的 VMess 非 TCP/WS、Trojan 非 TCP 映射 | 不代表 QX 客户端本身永远不支持这些 transport |
| Clash JSON 被嵌套 version 误识别 | 先识别顶层 proxies/Proxy 数组 | 含 Snell version 的混合 JSON 红转绿 |
| 逐节点状态 / 解析错误 | 循环内状态；YAML 类型错误只隔离该节点并告警 | 仍不等同于完整输入损失 manifest |
| AnyTLS/TUIC `!!TYPE` 字典遗漏 | 补全类型匹配 | 混合组的实际 matcher 测试 |
| HY 数值未初始化 | 成员显式初始化为 0 | 防止未设置字段被作为随机数读出 |

新解码边界同步增加文本输出安全检查：SS、HY2、AnyTLS 中不能被目标文本语法安全表达的逗号、引号、反斜杠或控制字符不会被当成新选项/新行输出。结构化格式保留可表示的秘密字符串；诊断不打印密码或完整 URI。

## 已验证但仍属受限增量

- VLESS 原始 / Base64 URI：TCP、WS、gRPC、H2；URI `type=http` 按 Xray 分享语义映为 Mihomo H2。Host 与 TLS SNI 独立，缺省 TLS SNI 为远端 host，缺省客户端指纹按分享规范处理。
- VLESS 现有 REALITY 字符串保护保留，并补 ALPN、packet-encoding、证书 pin 和 `support-x25519mlkem768` 字段保留。
- TUIC v4 token 与 v5 UUID/password 独立、只向 Mihomo/Clash 导出。typed allowlist 不生成臆测默认值，保留全 ALPN 和明确的 false/0。URI 中 literal `:` 与 `%3A` 不混淆。
- dialer/detour 保留时修正已输出节点的重命名引用；被过滤的 source 节点依赖会递归移除。重复原名引用视为歧义。不存在于输入中的 base group 引用仍保留，由完整配置校验负责。

这些变化不能声称每个输入字段、全部旧客户端、所有 TLS 扩展均已保真。新协议仍须以实际客户端版本和独立完整性验收决定是否采用。

## 不采用候选的实现

- 不引入 group-extra：会与 `!!TYPE` / PROVIDER 等选择器冲突。现有 binder、base-group preservation 和原顶层健康字段保持原契约。
- 不扩大 AND/OR/NOT 规则白名单：当前第二逗号去重签名不适用复杂谓词，须另做语法结构解析。
- 不引入 rule-provider format / MRS：声明 format 不等于解码、展开或跨目标转换；还会改变客户端抓取与缓存边界。
- 不引入 XHTTP、Mieru、泛化 sing-box importer 或目标 fork 的全量 exporter。
- 不采用 short-id 输出文本修补、老 Alpine 配方、构建时重新 clone HEAD 或 push 自动发布。

## 已独立验证的最小 P0 fetch 单元

真实 `webget.cpp`、文件 I/O 和系统 libcurl 8.14.1 的 loopback 对照中，固定基线复现了重试拼接、200截断写坏缓存、认证上下文串缓存、forced cors 直达 gateway 四类问题。修复候选对应 10 项测试及 4 项额外边界均通过：

- 每个 curl attempt 清 body / response headers / cookies；仅最后一次响应进入结果。
- `FetchResult` 分别记录 transport code 与 upstream HTTP status；失败传输的有效 status 为 0，不能因为上游曾回 200 就覆盖好缓存。
- v2 缓存命名空间包含按大小写无关顺序、长度边界编码的 request headers 摘要；旧无认证隔离 cache 不可复用。同一认证上下文仍能正常命中。
- 强制模式只允许实际支持的 HTTP(S)/SOCKS 代理描述符；`cors:`、空值、不支持的 scheme 在 cache hit 与网络访问之前拒绝。
- 普通缓存、现有显式开启的 stale-on-failure、API 模式不自动重试、正常 HTTP proxy 强制覆盖 NO_PROXY 的行为保持。

可复用的 `tests/fetch-loopback.py` 使用生产 fetch/file 实现，唯一服务 stub 是 logger，绑定地址仅 `127.0.0.1`，端口临时分配；不进行 TLS 或真实订阅测试。portable 版本额外检查了非 forced cors 兼容路径。实际镜像中的 libcurl 8.21.0 仍需在发布前复跑。

## P0：当前仍未完成的门槛

以下不是“文件没变所以安全”。独立评估已有原函数局部证据，另有源码复核；本分支在最终完整服务中尚未验收：

1. 强制抓取策略：错误 TOML 容器类型、percent-host 与 libcurl 规范化差异、跨 host redirect、失败 reload 的原子性。
2. HTTP 完整性：本次已修上述重试/截断问题；完整服务 HTTP 边界、原子缓存事务与并发异常仍需追加。
3. 缓存上下文：本次已修 Authorization 隔离；真实 converter build/revision、stale 状态的结构化可见性仍未完成。
4. 每源/每节点/每字段转换清单，以及 admin 在发布前消费清单的门槛。
5. 全部旧协议的 transport/plugin/TLS 细节；日志已经比静默 continue 更可见，但不是端到端完整性证明。

共享的 HTTPS 抓取禁用证书验证问题仍是现有策略债务。本次不偷偷改变生产证书默认策略，也不声称走代理会自动补上 TLS 身份验证。

### 已实施且不要求新 HTTP API 的修复范围

- 每次 curl attempt 清空当前响应 buffer；将 CURLcode 与 HTTPcode 同时用于成功判断；失败不能覆盖上一份好缓存。
- 请求认证/语义相关 headers 进入缓存上下文摘要，不能把秘密明文放入缓存文件名或日志。
- 强制模式明确拒绝 `cors:` 和不支持的代理 scheme；route 容器与条目类型的严格解析留独立配置事务单元。

这些最小修复已由真实 `webget.cpp` + loopback origin/proxy 回归验证，后续配置事务仍需独立测试。默认 TLS 策略、网络出口与已存在的服务接口保持独立评审。

### 需要明确接口 / 消费方设计的单元

建议引入请求内的结构化 conversion report：source ordinal、source 内 node ordinal、protocol、parsed/emitted/filtered/unsupported/invalid/lossy 状态、固定 reason code 和 field paths。不要以名字作为唯一 identity，不在报告写原始 URI、token、密码或私钥。

- 报告应直接从生产 parser/exporter 产生，不在 admin 维护第二套不一致的解析器。
- 普通订阅文本客户端不会可靠显示 warning header，因此“加日志/响应头”不能当作发布门槛。
- 推荐新增显式审计/严格模式后，由 admin 授权地请求、检查并发布同一转换结果；默认订阅响应协议不应未经协调直接变成 JSON envelope。
- 不支持的 QX 子集必须有明确的允许排除策略。未知损失默认不应被视为完整成功，但不能偷偷改变用户当前选择集合。
- converter 源码 revision、构建身份、转换 options、源 bytes 与 policy identity 应共同进入缓存见证；真实 image digest 属于部署/消费方联动，单改 converter 不足。
- 重定向应逐跳规范化并重新核对策略，或明确拒绝跨策略跳转；不能先访问后审查。跨 origin 的认证头转发也需独立负控。

此单元涉及 `proxy-stack` 与 API/发布契约，另行确认后实施；本分支没有修改该仓库、NAS 配置或真实订阅。

## 已运行证据与不作的推断

- 生产 C++ static conversion library：原 REALITY 四组合，混合协议/字段/负控测试；不是抽取函数替代实现。
- 固定官方 Mihomo v1.19.29 配置解析：18 个合成节点，block/flow × full/list。不是认证、TCP/UDP、DNS 或出口 IP 验证。
- 合成 146 节点 / 44426 条有序规则：node 顺序、base/DNP 组、同名覆盖、类型 matcher、已有健康字段、首匹配去重、明确保护图中无 DIRECT、空集 REJECT。此规模不是生产输入完整性的替代 oracle。
- `tolerance` / `evaluate-before-use` 的断言证明 YAML 契约保留，不证明 pinned Mihomo fallback 运行时采用这些字段。
- 旧输出正向差分用于保护既有正常路径；报告指出的旧 bug 单独以正确预期的红测修复。
- ASan/UBSan 可以运行；本云环境的 LeakSanitizer 受 ptrace 限制，不能声称 leak 检查通过。
- 尚未运行完整 converter server、实际 admin finalizer、真实机场冻结重放、QX/Surge/Loon/sing-box 实机导入或服务器连接。


## 最终候选验收摘要

- `protocol-roundtrip.py`：28 组综合测试通过。
- `pro-review-regressions.py`：14 组既存缺陷与新增安全边界测试通过（最初 11 条全红已保留正确预期）。
- `fetch-loopback.py`：15 项可复用真实 fetch/file/libcurl 回归通过；另有独立 baseline/candidate 10+4 项对照。
- 原 REALITY round-trip：block/flow × full/list 四组合通过，三个 short-id 类型样例保留，HY2 UDP 现在正向校验。
- pinned Mihomo v1.19.29：18 个合成节点、四种转换组合配置解析通过。
- 最终生产源改动经独立只读审查；其发现的证书 pin 降级、URI/text 注入、类型异常、端口/默认参数、链依赖与重复身份问题已加入回归并修复。
- TUIC 仍标记 EXPERIMENTAL：未有完整 source-to-final manifest、真实冻结机场样本、admin eligibility/finalizer 对照、真实 v4/v5 服务端认证及 TCP/UDP 测试。分支源码不是镜像发布或生产迁移批准。

剩余架构决定很具体：转换 report/API 与 admin 发布门槛、原子配置 reload、URL 规范化与逐跳 redirect 策略、converter 构建身份进入消费方缓存、结构化 stale provenance，以及另行确认的 HTTPS 证书校验默认策略。它们不会因本次有限回归通过而被记为完成。
