# PR #1 第三轮复审修复（2026-10-04）

本轮基于 `32334a19ff01a58e57d8c411c4ba324fa0b8bb95`，修复第三轮完整评估中的 R3-1、R3-2、R3-3。上一轮四个原反例仍关闭；本轮发现说明原来的成功测试没有覆盖所有最终语义。PR 保持 Draft。

## 修复行为与测试判据

### R3-1：最终组合并与图校验使用同一结果

旧 wrapper 与生成组去重都对 YAML sequence 的 iterator handle 调用 `reset`，只改变临时 handle，没有替换实际序列元素。验证 map 却采用最后生成组，导致模型与输出不同。这是旧根因；第二轮自动组支持使原先异常退出的两个输入成功输出错误的自动组。

现在在转换实现中复制 base 组序列，再用真正写回序列的索引赋值整体替换同名组。保留原 base 位置与无关组内容；新增组按出现顺序追加。重复 generated 名称采用最后一个有效生成定义，保留该名称的首个位置；重复 base 名称仍不被当成可修复输入。生成空组的独立标记随最后定义更新，不能把历史 DIRECT 回退当成显式安全成员。

图校验只从已经合并、即将输出的序列构建。公共 wrapper 不再在校验后合并另一份 base。缺失 name 的 base mapping 安全跳过名称读取；这不意味着该畸形组通过客户端配置检查。

新测试直接断言完整组映射，包括 type、members、旧自动字段消失、其余 base 组内容/顺序、Leaf 的依赖和规则保留。覆盖自动空组、自循环、静态 Missing、重复 generated、危险反向覆盖、嵌套组，以及旧/新字段名与 full/list。

固定 Mihomo v1.19.29 除 `-t` 外，还在隔离目录加载 **未经重写的 converter 原始完整输出**，仅通过随机 loopback 控制端口 GET `/proxies`，核对真实组成员与 Selector 类型。原始输入配置关闭全部入站、DNS、TUN、provider、健康探测；合成 SS 地址是 loopback，未发送代理请求。每次检查前后校验输出哈希并回收进程。旧字段名与 provider list 仅做结构检查，不冒充现代核心完整配置。

### R3-2：INI 预分类与实际解析器一致

首个有效语法行改用 INIReader 相同的 LF/CR 行界选择，去除行尾空白（包括 CRLF 的 CR）；节名按首尾方括号识别，不再限制为 ASCII 字母、数字或连字符。带点、非 ASCII、数字开头的节名不会先于真正 INIReader 被错误拒绝。

raw URI 探测与实际消费共用 LF、CR、单行空格分隔规则，修复 Base64 解码后首项垃圾遮蔽其后有效 URI 的 CR/空格边界。单行 `#`、`;`、`//` 注释拥有整行，不能从注释文字的空格 token 中捡出 URI。

JSON/YAML/INI 容器仍优先于 metadata 中看似 URI 的文本，包括容器没有任何有效节点的情况。测试按原字节传入 LF/CRLF/CR、前导注释、零到两层 Base64、raw 垃圾首中尾与容器负控。这里没有认证带任意非标准序言的所有 INI 变体，也没有改变完整 HTTP/admin 的源失败策略。

### R3-3：可空 transport 与访问检查一起修复

`streamSettings`、`tcpSettings`、`wsSettings` 的 null 按 absent 处理；进入对象读取前显式检查 `IsObject()`。未选用的 transport 为 null 不再使合法 VMess 消失；被选用的可空设置也使用已有默认行为。

此语义与 [固定 V2Fly StreamConfig 的可选指针字段及非 nil 构建](https://github.com/v2fly/v2ray-core/blob/1c6e4bbf6cabfcd252ce72da7d5a771f28e128d8/infra/conf/transport_internet.go#L434-L505) 一致。本轮自身未重新下载或运行 V2Fly 二进制，不将第三方报告的官方配置加载结果记作本轮实跑。

其他错误类型仍拒绝；必要的 outbounds/settings/vnext/users/有效首用户 ID 检查保留。嵌套 header/request/headers 的既有严格检查未在此泛化放宽。原 H1 中把三个可空 pointer fixture 判为错误的 oracle 已改为正向，fixture 未删除；新增测试将 null 和 absent 的原始输出逐字节比较，并核对 WS path/Host/Edge/TLS 与用户、端点。

## 复跑方式

沿用 `tests/CMakeLists.txt` 构建的真实生产 parser/filter/preprocess/exporter，分别设置 Release 和显式 Debug：

```sh
cmake -S tests -B build/reality-roundtrip -DCMAKE_BUILD_TYPE=Release -DBUILD_FETCH_TESTS=ON
cmake --build build/reality-roundtrip -j2
python3 tests/third-review-parser-regressions.py \
  --driver build/reality-roundtrip/protocol-convert --out build/r3-parser
python3 tests/group-replacement-regressions.py \
  --driver build/reality-roundtrip/chain-convert --mihomo /path/to/pinned/mihomo \
  --out build/r3-groups
```

对 Debug 构建运行同样的脚本；组脚本的输出目录必须是新目录，以免把上次的核心运行证据覆盖为本次结果。Mihomo 固定官方 v1.19.29 Linux amd64，可执行文件 SHA256 为 `9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577`。测试不自动下载软件，安全条件和断言在 Python `-O` 下仍生效。

## 验证结果与限制

最终同一源码在 Release（`-O3 -DNDEBUG`）、显式 Debug（`-g`、无 `NDEBUG`）与 ASan+UBSan 三种构建通过：

- 新 parser 回归 **151/151**；最终组回归 **88/88**（22 个场景 × 新旧字段 × full/list）。
- 原协议 **28/28**、输入边界 **21/21**、链 **211/211**、第二轮解析 **286/286**、自动组 **84/84**。286 个既有 fixture 中三个可空 pointer oracle 已按上述说明纠正。
- 每种构建有 **72 次**原始完整输出 Mihomo 配置检查：原 60 次加新 12 次；其中新 12 次另检查实际 `/proxies` 成员。三个构建重复的是相同场景，不计作 36 个独立运行场景。全部进程回收，原始输出哈希不变。
- 合成 146 节点、44,426 条平面 DOMAIN 规则的顺序/首匹配、base/DNP、六项健康字段与保护组契约三种构建均通过；本轮另明确断言 SameName 的最终成员是 REJECT。
- Release 与 sanitizer 的真实 libcurl loopback **18 组**通过；Release 的 REALITY 四组合、modern Mihomo 源码契约通过。

独立审查与红测：固定 32334 基线新字段组检查为 **32/44**，其中 12 个错误输出反例；12 个原始完整输出均可通过 `-t`，但 11 个实际成员检查错误，另外一个由完整映射断言抓住。作者 parser 基线 **116/151**，35 个失败保留为红测记录；独立 parser 基线 **131/159**，候选 **159/159**。独审发现的单行注释 token 导入与缺 name 读取风险已修复并保留负控。独审未发现本轮范围内剩余阻断。

工具链沿用 GCC 14.2、CMake 4.4.3、yaml-cpp 0.8、RapidJSON `24b5e7a8b27f42fa16b96fc70aade9106cf7102f`、PCRE2 10.46、libcurl 8.14.1。静态转换库使用 `NO_JS_RUNTIME` / `NO_WEBGET`；fetch 是另一个真实 curl 驱动。ASan 设置 `detect_leaks=0`，未宣称 LeakSanitizer 通过；系统依赖未全部插桩。

所有输入均为合成数据。本轮没有完成真实机场冻结输入、完整 converter HTTP/JS/admin 链、最终镜像或任一协议握手、UDP、真实出口验证。实际组成员观察增加了配置运行证据，但不是线路测试。

TUIC 仍为 EXPERIMENTAL。Surge SSID 图、Surge 输入 underlying-proxy（包括 SS/AnyTLS）及 AnyTLS pin、动态 provider 的真实成员、完整 source/node/field manifest、原子 reload、URL/redirect/TLS 默认策略与 cache provenance 等延期边界继续保留。此次没有更换候选基底或改变生产策略。
