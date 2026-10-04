# PR #1 第二轮复审修复（2026-10-04）

本轮从 `03f28a80ce2936468af5688ecfde3a573ca0f596` 开始，只修复第二轮完整评估的 F1、C1、F2、H1。F1/F2 是相对 `e624f326` 的回归；C1 是新链保护的覆盖缺口；H1 是新分派扩大旧 schema 假设的可达范围。原六项修复与测试仍保留，PR 继续为 Draft。

## 四项修改

| Finding | 最终行为 | 验证重点 |
| --- | --- | --- |
| F1：合法自动组异常或误空 | 可选 YAML 字段安全读取；按最终输出节点与最终组模型计算本地自动成员，再检查依赖图 | include-all-proxies/include-all、省略/空 proxies、filter/exclude、真实空组与循环、无链请求、同名生成组覆盖 |
| C1：名称异常早于链记录 | 每行先建立匿名 rejected 记录并捕获链声明；合法名称解析后再填身份 | 名称为序列/对象/null/缺失/空串、有链全拒源与其他源合并、full 三目标失败/list 独立节点保留 |
| F2：raw 首个异常行决定整源格式 | 先识别真实容器；纯文本扫描全部候选 URI 行；Base64 解码后重新进行结构分派 | garbage 首中尾、CRLF/注释、URI 内格式关键词、JSON/YAML/INI metadata、零有效节点、文档前导和编码容器 |
| H1：旧 JSON 解析器访问错误形状 | outbounds/settings/vnext/users、stream/ws/tcp/header/request 在访问前检查类型 | 同一负控在 Debug 与 Release 都受控拒绝，不依赖 RapidJSON assert 或链接顺序 |

Clash 名称 null/缺失/空串以前可能生成空名字节点；本轮明确拒绝。名字为合法标量时仍采用已有字符串语义，不把 `[Leaf]` 猜成 `Leaf`。没有明确链声明的坏行不会自动导致全部独立节点失败。

V2Ray JSON 的 users 空数组、首项 null/空对象、缺失/空/非字符串 id 以前可能产生没有可用用户的 VMess 节点；本轮明确拒绝这些畸形输入。合法配置、无 streamSettings、TCP、WS 和既有“只取首个用户”语义有正向控制；不是通用 Xray/sing-box JSON 导入升级。

容器是否成立不再取决于成功节点数。INI 正常节标题和裸 Surge/QX 行、其 `#` / `;` / `//` 前导注释先于 YAML 分类；YAML 序列、显式根 scalar、`---` / `%YAML` / `%TAG` 前导，以及声明但解析失败的容器，不会把内嵌 URI 改当 raw 节点。Base64 解码仅在字节长度严格缩短时重新分派，保留共享 registry，不重复创建成功节点身份。

## 本地自动组的准确范围

图模型只用于校验，保留原 base group 的自动字段与 provider 声明。最终节点集合经过目标省略、过滤、改名、协议前缀、同名后缀；同名生成组按既有 wrapper 语义整体替换 base group。生成组因为无匹配而渲染的历史 DIRECT 回退仍单独标为空，不能被误认为用户显式选择 DIRECT。

- filter 只筛选自动加入的节点；显式 proxies 不被 include filter 删除。反引号分隔多个表达式。
- exclude-filter 与 exclude-type 作用于显式和自动成员；类型按 Mihomo AdapterType.String() 比较，例如 Shadowsocks，而不是 YAML 别名 ss。ASCII 大小写不敏感，`|` 分隔且不擅自 trim。
- 显式缺失引用、纯组循环在排除前检查；不能靠 exclude 把原本无法加载的配置“修成合法”。动态节点与组的循环在最终成员上检查。
- include-all-providers（包括 include-all）以全部已声明 provider 名称替换 use。空 use、缺失 provider、false flag 不冒充有效上游。provider 与组同名时，按客户端兼容 provider 创建条件检查冲突。
- 用户显式 DIRECT/REJECT 及合法的显式 empty-fallback 保留；不把本地零匹配自动补成 DIRECT/COMPATIBLE。无链模板不因本地证明不足而改写字段。

正则引擎有明确边界。Mihomo 使用 regexp2，本项目使用 PCRE2；不能声称任意表达式等义。本轮验证子集包括普通/Unicode 字面量、字符类、锚点、标准量词、分支、普通/非捕获组及正负 lookahead。`(?i)` 仅在表达式和待匹配名字均为 ASCII 时建模。严格允许 `{m}`、`{m,}`、`{m,n}`；禁止 PCRE 扩展的空下限、量词内空格和 possessive 量词。反向引用、lookbehind、Unicode/shorthand 类、引擎指令等不作推测。默认换行固定 LF、不隐式开启 multiline；匹配资源错误/非法 UTF8 不被当作“不匹配”。非 ASCII exclude-type 也不以 ASCII fold 猜测。

超出此证明范围的**链可达组**受控拒绝，并给出脱敏诊断；普通无链输出保留输入字段。需要更广表达式能力时，应增加明确语义与正负控，而不是取消图检查。

## 可复跑测试

沿用现有生产 CMake 静态库与实际 parser/filter/preprocess/exporter，测试仅使用合成数据。Debug 必须明确设置 `-DCMAKE_BUILD_TYPE=Debug`，Release 设置 `Release`；不能把空 CMake cache 类型误认为 Debug，生产子目录默认会用 Release。

```sh
cmake -S tests -B build/reality-roundtrip -DCMAKE_BUILD_TYPE=Release -DBUILD_FETCH_TESTS=ON
cmake --build build/reality-roundtrip -j2
python3 tests/second-review-regressions.py \
  --driver build/reality-roundtrip/protocol-convert \
  --chain-driver build/reality-roundtrip/chain-convert \
  --mihomo /path/to/pinned/mihomo \
  --artifacts build/second-review-evidence
python3 tests/automatic-group-regressions.py \
  --driver build/reality-roundtrip/chain-convert \
  --mihomo /path/to/pinned/mihomo \
  --out build/automatic-group-evidence
cmake -S tests -B build/review2-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/review2-debug -j2
```

对 Debug 运行同一 second-review 脚本，替换两个 driver 路径；自动组脚本也可使用 Debug。Mihomo 工具固定为官方 v1.19.29 Linux amd64，SHA256 `9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577`。完整 stdout 直接传给核心，前后校验哈希；PyYAML 只读断言，不重写组、规则或字符串类型。

最终源码验证：

- 新解析 gate **286/286**（C1/F2/H1），自动组 gate **84/84**，Release、Debug 与 ASan+UBSan 三种构建均通过。
- 原协议 **28/28**、输入边界 **21/21**、链 **211/211**，三种构建均通过。
- 每种构建包含 **60 次**直接使用原始完整输出的固定 Mihomo 检查：原链 24、新解析 5、自动组 31；它们是上述用例的子集，不另加作“独立配置总数”。
- Release 与 sanitizer 的真实抓取 **18 组**通过；REALITY **4 组合**、旧 schema **18 节点 × 4 组合**及源码契约通过。旧 schema suite 会重写组/规则，仍与上面完整字节检查区分。
- **146 合成节点 / 44,426 有序 DOMAIN 规则**及 base/DNP、health 字段、首匹配和既有保护组契约，在三种构建下通过；不是生产冻结订阅重放。
- sanitizer 明确使用 `ASAN_OPTIONS=detect_leaks=0`、`UBSAN_OPTIONS=halt_on_error=1`；没有宣称 LeakSanitizer 或第三方依赖内部也得到完整检查。
- 两路独立只读审查完成；发现的自动组正则/命名、INI/YAML 容器边界已修复并纳入正负控。原始红测、编译配置错误和中间失败没有被抹去或计作通过。

工具链仍为 GCC 14.2、CMake 4.4.3、yaml-cpp 0.8、固定 RapidJSON `24b5e7a8b27f42fa16b96fc70aade9106cf7102f`、PCRE2 10.46、libcurl 8.14.1。实际镜像 libcurl 8.21.0 未运行。Debug/Release 的 schema 行为在同一源码和不同明确优化/断言设置下对照。

## 仍然存在的边界

1. **Surge SSID 组的静态边没有完整登记。** default 和条件分支可能通向空组或构成循环；旧、新源码对照证明这是既有覆盖缺口。本轮没有宣称所有组类型均闭环，Mihomo 已移除 relay 的版本差异也不由本次兼容图模型解决。
2. **Surge 输入链字段尚未完整建模，已确认 SS 与 AnyTLS。** underlying-proxy 在输入时就可能丢失；AnyTLS 还存在证书 pin 的旧缺口。输出 guard 不能恢复已丢字段。
3. **真实 provider 成员未展开。** 声明存在的 provider 可继续兼容输出，局部明确的循环/缺失仍被拒绝；这不证明动态 provider 的完整链安全。registry 也不是完整 source/node/field manifest。
4. 没有运行完整 HTTP/admin 服务、真实 JS、Windows、最终 Docker 镜像、机场冻结重放、原生 QX/Surge/sing-box 导入、握手或生产流量。`-t` 甚至会接受某些 dialer 循环，不能代替图语义或真实连接验收。
5. TUIC 仍为 EXPERIMENTAL。strict TOML/原子 reload、URL/redirect 策略、构建身份、stale provenance、完整发布门槛与 HTTPS 验证默认策略仍按原 P0 分期处理。

本轮不增加协议、rule-provider 格式、候选 group-extra、CI 或部署策略。后续采用仍需独立生产验收。
