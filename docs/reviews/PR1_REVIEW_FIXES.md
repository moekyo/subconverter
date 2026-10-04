# PR #1 六项复审修复（2026-10-04）

本轮以已发布的 `e624f326c5f8a028d05d88862114f0ff2a75a20f` 为修复起点，核对完整 545 行 PR 独立评估。R1/R3/R4/R6 是旧可用路径的新回归；R2 是新增链保真没有覆盖完整生命周期，R5 是新增 raw 订阅入口的格式隔离不完整。六项均先以固定 base/head 合成对照复现，再修复。PR 继续为 Draft。

| Finding | 修复 | 验收要点 |
| --- | --- | --- |
| R1：Surge append_type 删除合法链节点 | 按原始身份解析依赖，再映射最终输出名；稳定且实际存在的组可作为依赖 | 开启/关闭前缀、引用节点/组均保留 Leaf；完整规则仍指向 Exit，不再因错误删节点进入旧 DIRECT 回退 |
| R2：身份记录晚于拒绝、过滤、改名 | 请求内源记录从 parser intake 开始保留；拒绝/过滤记录不随节点删除；导出决策仅在本次目标内保存 | JSON/YAML、raw/Base64、legacy URI/container，真实 include/exclude、emoji/rename、多源重名、链级联、重复导出与目标切换 |
| R3：SS none 被旧 cipher 表误拒 | 单独恢复已由基线和固定 Mihomo 支持的 none 输入，不扩大旧跨格式 cipher 映射表 | URI、外层 Base64、JSON、YAML 同义输入；未知 cipher 继续拒绝；原始完整输出核心解析 |
| R4：强制裸代理/SYSTEM 失效 | 合法 host:port 按 HTTP 归一化，网络和缓存使用同一已验证描述符 | bare/显式 HTTP/SYSTEM、raw/wrapper、NO_PROXY、等价缓存命中、无效端口/CORS 零网络负控 |
| R5：vnext 子串劫持 raw 入口 | 只按真实 JSON 容器分派；raw URI 先隔离；恢复 SS Android 数组、flow YAML、UTF-8 BOM 兼容 | 备注、host、认证含关键词时 raw/Base64 同义；旧格式正向控制保持 |
| R6：不完整 IPv6 正则 | URI 数字地址改用 inet_pton；完整、压缩和 IPv4-mapped 均支持，超长/非法地址拒绝 | 五种共享 URI 协议、raw/Base64 正负对照；server 输出强制字符串，防止数字外观 IPv6 被 YAML 1.1 当数值 |

## 链身份与失败行为

源记录保留原始名字和链声明，包括已拒绝或已过滤的项。成功解析时，以真实 parser 得到的名字完成记录，兼容旧 Trojan 的 `+` 语义、QX tag 和默认节点名。VMess/SSR/Netch 的编码内名字在协议校验前登记。注释与 Surge 的 direct/reject 策略声明不当作失败代理节点。

对链引用采用请求范围内的严格消歧：同一原名若对应多个源记录，或与实际输出组重名，拒绝该引用。不会拿改名后碰巧相同的另一个节点修补依赖。无链引用的普通重名节点仍沿用既有后缀处理。名字、密码和原始 URI 不进入新增诊断日志。

Clash、Surge、sing-box 只认可当前目标真正保留或生成的组。Clash base groups 仍经既有 wrapper 保留；Surge/sing-box 被移除的 base group 不会冒充存在。对链可达的实际组成员逐层检查，拒绝因过滤变空、缺失或循环的链；显式 DIRECT/REJECT 与无关普通空组的历史策略没有被全局替换。Provider 和其他不透明组的远程成员仍不属于本轮完整性证明。

行为变化是明确的：

- **完整配置**遇到无法保留的链会设置转换失败并返回空结果，避免继续生成因链丢失而回落 DIRECT 的策略。HTTP handler 在上传前检查失败，并返回现有 400 错误形式。此 HTTP 分支已作源码审查，未运行完整服务请求。
- **节点列表**可保留独立有效节点，并拒绝不完整链及其级联依赖；未知外部组不能凭名字猜测存在。日志继续使用固定原因，不输出输入秘密。列表仍不是完整 source/node/field manifest。
- 导出使用目标内的名字/拒绝状态；不会把改名或省略结果写回源图。sing-box 的源副本活到 JSON 序列化完成，避免 StringRef 悬空。

为覆盖真实入口，静态测试库现在编译生产 `filterNodes`、`preprocessNodes` 的非 JS 路径，未复制 helper 实现。相应修正了过滤 erase 的失效迭代器与 emoji 空字符串读取边界。JS 删除路径调用同一过滤状态 helper，但测试模拟的是删除边界，未运行 JS 引擎。

## 可复跑验证

依赖版本沿用 [选择性升级说明](../SELECTIVE_PROTOCOL_UPGRADES.md)。本轮运行 GCC 14.2、yaml-cpp 0.8、libcurl 8.14.1、固定 RapidJSON 与官方 Mihomo v1.19.29。实际镜像 curl 8.21.0 与 Windows 未运行。

```sh
python3 tests/protocol-roundtrip.py
python3 tests/pro-review-regressions.py
python3 tests/reality-roundtrip.py
cmake -S tests -B build/reality-roundtrip -DBUILD_FETCH_TESTS=ON
cmake --build build/reality-roundtrip -j2
python3 tests/fetch-loopback.py --binary build/reality-roundtrip/fetch-contract-driver
python3 tests/chain-regressions.py \
  --driver build/reality-roundtrip/chain-convert \
  --mihomo /path/to/verified/mihomo-v1.19.29-linux-amd64 \
  --artifacts build/chain-evidence
bash tests/modern-mihomo-contract.sh
```

`chain-regressions.py` 要求固定的 Linux amd64 核心 SHA256 `9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577`，不自行下载或运行未知二进制。

最终候选结果：

- 综合协议测试 **28/28**；既存缺陷与本轮输入边界 **21/21**。
- 链回归 **211/211**，其中 **24 次**固定 Mihomo 检查直接读取 converter 的原始完整输出字节，保留组、规则和字符串标签，检查前后校验文件哈希；PyYAML 仅用于断言，不重写核心输入。
- 原 REALITY block/flow × full/list **4 组合**通过；原节点 schema 检查仍为 **18 节点 × 4 组合**，该旧检查会重写测试组/规则，不能与上面的完整输出检查混称。
- 真实 fetch/file/libcurl loopback **18 组**通过。新增包含 8 种 bare/explicit/SYSTEM × raw/wrapper 请求，以及 8 次无效裸代理零请求控制；归一化前先校验，等价地址共享同一认证隔离缓存。
- 合成 **146 节点 / 44,426 有序规则**、已有 group/health-field 契约、源契约脚本通过。规模测试并非真实订阅完整性 oracle。
- **ASan + UBSan** 下重复通过 28、21、211、18 组及单独的策略契约。LeakSanitizer 仍受运行环境 ptrace 限制，明确使用 detect_leaks=0；未声明泄漏检查通过。
- 独立只读审查追加 **26 + 54** 个定点反例/控制，发现的 intake、格式分派、嵌套组与级联问题均修复，无剩余已报告阻塞。

## 保留的边界

这不是生产发布或 NAS 切换验收。未运行完整 HTTP 服务、真实 JS 引擎、真实机场冻结重放、客户端设备导入或服务端握手；Surge/sing-box 检查是生成配置与字段断言。强制代理测试仅绑定 127.0.0.1，无 TLS、SOCKS 服务或外部订阅流量。SYSTEM 测试执行生产 getSystemProxy 的合成 Linux 环境读取，不等于完整配置加载/路由选择或 Windows 验收。

IPv6 zone-qualified/scoped URI 与代理地址没有被建模，当前明确拒绝，不删除 zone 后假造成功。此处替换的是共享 URI/代理地址校验，不宣称旧通用 isIPv6 的所有调用都已升级。

Surge AnyTLS 输入丢证书 pin/underlying-proxy 的基线缺口没有在本轮实现通用修复。其 base/head 对照仍表明输入阶段可能丢字段，因此跨目标输出 pin guard 不代表任意 AnyTLS 输入完整保真。TUIC 仍为 EXPERIMENTAL。

此前的完整转换 report/API、admin 发布门槛、原子配置 reload、URL/redirect 策略、真实构建身份和 stale provenance、HTTPS 验证默认策略仍按 [原评估剩余 P0](PRO_REVIEW_RECONCILIATION.md) 单独处理。
