# PLAN：按《在 BoringSSL 的接缝中实现 REALITY》写轻量 diff 的 naive-reality

> 2026-10-05 · Phase 1（PLAN）· 执行落点：`/root/lightweight-reality/`
> 基准：博客 [blog.sam1314.com/posts/c65526af.html](https://blog.sam1314.com/posts/c65526af.html)（2026-07-07，@wangran10）
> 基底：BoringSSL tag `0.20260413.0`（`78f7fbee…`，博客服务端 pin 的版本）；客户端落在 `/root/upstream-naiveproxy`（klzgrad/naiveproxy，Chromium 154，树内 BoringSSL 修订 `ac39ea68…`/CPE 0.20260413.0）
> 引用行号：服务端 patch 全部按 tag `0.20260413.0` 的工作树 `/root/lightweight-reality/boringssl` 核对

---

## 0. 一句话方案

**服务端**：给 BoringSSL 加一个"ServerHello 镜像注入"接缝（博客接缝三）+ 一个 select-certificate 回调里做的 REALITY 认证（接缝一/二），外面套一个最小 C++ 前置进程（L4 `MSG_PEEK` 分流 + 挂起窗口里同步连 mirror 抓 SH）。
**客户端**：naiveproxy 树内，BoringSSL 侧加"CH session_id 注入 + 证书校验接管 + sigalg 窄门控 carve-out"，Chromium net 侧把 naive 配置接进去（全部门控）。
**认证**：完全照 XTLS/REALITY 语义（X25519 → HKDF-SHA256(salt=CH.random[:20], info="REALITY") → AES-256-GCM），证书形态用 **Ed25519 临时证书 + 窄门控 carve-out**（理由见 §3）。

---

## 1. 严格性对照：博客五条 → 本实现的落点

| 博客机制 | 博客章节 | 本实现落点 | 备注 |
|---|---|---|---|
| 接缝一：`SSL_CTX_set_select_certificate_cb` 做认证 | §2 接缝一 | 服务端 app：`RealityAuthCallback()` 传给 `SSL_CTX_set_select_certificate_cb`；认证是**纯函数** `RealityAuthDecide()`（L4 与 TLS 回调共用） | 不动 BoringSSL |
| 接缝二：`ssl_select_cert_retry` 挂起 + 挂起窗口内连 mirror 抓 SH | §2 接缝二、§4.2 | 回调第一次返回 `ssl_select_cert_retry` → `SSL_do_handshake` 得 `SSL_ERROR_PENDING_CERTIFICATE`(12) → 同步 `DialMirrorAndCaptureSH()` → 第二次回调返回 `ssl_select_cert_success` | 用库自带语义，无 patch |
| 接缝三：`reality_serverhello_cb` 注入镜像 SH、只换 key_share 密文 | §2 接缝三 | **BoringSSL patch**：`ssl/tls13_server.cc:1026-1048` 之间插入 hook；`RealityPatchServerHello()` 完成 session_id 回显替换、key_share 密文替换、cipher/random 对齐 | patch 的唯一"深水区" |
| §4.3 组匹配：连 mirror 必须用客户端首个组 | §4.3 | mirror 客户端用 `SSL_set1_supported_groups([client_first_group, X25519])`；服务端 BoringSSL 侧默认 `tls1_get_shared_group`（`ssl/extensions.cc:204-227`，未开 `SSL_OP_CIPHER_SERVER_PREFERENCE` 时**以客户端顺序优先**）本来就是"客户端首个双方都支持的组"，无需改 | 少一处 patch |
| L4 `MSG_PEEK` 透明回落 | §5 | 服务端 app：`recv(fd, buf, MSG_PEEK)` 窥探 CH → 用**只解析**的 BoringSSL 实例跑同一份 `RealityAuthDecide()` → 分流（认证走 REALITY TLS，否则 `splice()` 到 target） | 不动 BoringSSL |
| 不改握手主状态机 / 门控 / 关掉即上游行为 | §6 | 服务端 patch 只在 `do_send_server_hello` 尾部加一段 `if (cb != nullptr)`；客户端 patch 所有改动点都有 `if (!ssl->reality_configured) return …原逻辑…;` | 见 §5 行数账 |

---

## 2. 落点选择

### 2.1 服务端：选 (a) BoringSSL C++ 最小服务端

- **理由 1（严格性）**：接缝一/二/三都只在 BoringSSL 里存在（`select_certificate_cb`、`SSL_ERROR_PENDING_CERTIFICATE`、SH 注入点）。Go 侧 `crypto/tls` 没有这些接缝，走 (b) 就只能实现"L4 peek + `xtls/reality` 服务端"，**镜像 SH 这一半完全落空**，与"严格按博客"冲突。
- **理由 2（可验证性）**：BoringSSL 可以单独编译（cmake+ninja，见 §6），能做出**真跑起来的** PoC；Go 方案只能复用现成库，验证的是别人代码。
- **理由 3（对照价值）**：naivereal 的服务端已经是 Go（`xtls/reality`），再做一条 Go 路线没有新信息；C++ 前置是博客独有的形态。
- **代价（写进报告）**：与 naive 生态（Caddy/Go）语言错位，前置进程要自己桥接 naive 的 h2 CONNECT；这条我在研究报告中已列为"移植成本高"。
- 交付形态：`lightweight-reality-server.patch`（对 BoringSSL）+ `server/` 下的 app 源码（新文件，不是 patch）。

### 2.2 客户端：naiveproxy 树内两层

- **BoringSSL 层**（`src/third_party/boringssl/src/`）：CH session_id 注入、AuthKey 保存、`SSL_reality_verify_certificate()`、`SSL_set1_reality_config()`、`tls12_check_peer_sigalg` 窄门控 carve-out。
- **Chromium net 层**（`src/net/`）：新增 `net/socket/reality_config.{h,cc}`（进程级配置，由 naive 启动时写入）+ `ssl_client_socket_impl.cc` 三处接线（set config / verify 短路 / 门控）+ `naive_config.{h,cc}` 解析配置项 + `naive_proxy_bin.cc` 初始化。
- 为什么用"进程级配置"：naiveproxy 是单用途可执行文件（一个进程一个代理配置），把 REALITY 参数从 `NaiveConfig` 传到 `SSLClientSocketImpl` 的现成管道要动 `ProxyConfig`/`SSLConfig`/`URLRequestContext` 一串（naivereal 的 002 也是这么绕的）。全局 + 门控是**最小 diff** 的做法；报告里标注这是权衡。

---

## 3. 认证方案选择：Ed25519 + 窄门控 carve-out（不用合规 ECDSA 版）

**选 Ed25519，理由三条**：

1. **博客本身就是 Ed25519**：§3 的三层信任表把"Ed25519 CertificateVerify 签名"列为"保留并验证"，把"sigalg 通告检查"列为"放宽"。改成 ECDSA 是博客明确说的"另一种做法"，不是它做的做法；任务书要求"严格按博客"。
2. **服务端→客户端认证依赖 Ed25519 的定长签名**：XTLS/REALITY 用 `HMAC-SHA512(AuthKey, ed25519_pub)`（64 字节）**整体覆写证书签名字段**（`reality-src/handshake_server_tls13.go:150-152`），客户端比对 `certs[0].Signature` 完成对服务端的认证（`/tmp/xray_reality.go:110-112`）。SHA-512 输出 64 字节 = Ed25519 签名长度，换成 ECDSA 的 DER 变长签名这套"覆写"就不成立，得另造服务端认证机制——**比 carve-out 大得多**。
3. **可对照**：naivereal 在同一个函数上做了同样的事（`patches/001-boringssl-reality.patch:478-495`），本实现可与它逐行对照。

**carve-out 的"窄"体现在**：只在 `ssl->reality_configured && sigalg == SSL_SIGN_ED25519` 时放行；**不改 CH 通告列表**（naivereal 注释里的同一考虑：保持 CH 与真站兼容）；不配置 REALITY 时行为与上游逐字节一致。

**代价（写进报告）**：字面违反 RFC 8446 §4.4.3 的准入半句（只在认证成功后的受控两端之间、对外不可观测，博客 §7 同样承认）。合规版留作后续可选项（服务端换成"只签客户端已通告算法"的证书即可去掉这处 carve-out）。

---

## 4. 文件级改动清单

### 4.1 服务端 patch（`lightweight-reality-server.patch`，对 BoringSSL tag 0.20260413.0）

| 文件 | 职责 | 改动 | 预估 |
|---|---|---|---|
| `include/openssl/ssl.h` | 公开 API | `typedef bool (*reality_serverhello_cb)(SSL*, const uint8_t**, size_t*)` + `SSL_CTX_set_reality_serverhello_cb()` 声明 + 文档注释 | +18 |
| `ssl/internal.h` | 配置字段 | `SSL_CONFIG` 加 `reality_serverhello_cb reality_cb = nullptr;`（放在 `select_certificate_cb` 附近） | +6 |
| `ssl/ssl_lib.cc` | setter | `SSL_CTX_set_reality_serverhello_cb` 实现（含 `SSL_CTX` 拷贝时的 cfg 传递：`ssl_create_ssl`/`SSL_CTX`→`SSL` 的 config 复制点已自动带上，无需额外改） | +12 |
| `ssl/tls13_server.cc` | 接缝三 | ① 在 `do_send_server_hello()` 的 `finish_message`（:1026）与 `add_message`（:1048）之间插 `if (ssl->config->reality_serverhello_cb != nullptr && reality_apply_server_hello(hs, &server_hello)) …`；② 新增静态函数 `reality_apply_server_hello()`（解析镜像 SH + session_id/key_share/cipher/random 对齐，失败则回退不注入）；③ 静态辅助 `reality_find_key_share_ext()` | +150 |
| **合计** | | | **≈ +186 / −0**（博客服务端 +210/−45、3 文件；本实现 4 文件、186 行、0 删除——**行数在博客量级内**，文件数 +1 的原因：博客把类型声明算进 internal 头，我们把公开 API 单独放 ssl.h） |

关键实现细节（已核对 tag 源码）：
- 注入点：`ssl/tls13_server.cc:1026`（`finish_message` 产出完整 handshake message，含 4 字节头）之后、`:1048`（`add_message`）之前——此时**主状态机已在 `state13_send_server_hello`**，替换的是"要发出去的字节"，不触碰状态迁移。
- `key_share` 密文来源：`hs->key_share_ciphertext`（在 `resolve_ecdhe_secret()` `:107` 由 `SSLKeyShare::Encap` 生成）——**同组**才能替换（长度必须相等，否则回退）。
- `session_id` 回显：`hs->session_id`（`do_send_server_hello():1017` 用的就是它）。
- cipher 对齐：镜像 SH 的 cipher 若 `SSL_CIPHER_find()` 找得到、且其 hash 与 `hs->transcript` 已初始化的 hash 一致（`:471` `InitHash` 早于本 hook，**不能换 hash 家族**），则采纳并把 `hs->new_cipher` / `hs->new_session->cipher` 一起换掉；否则**把注入字节里的 cipher 字段改回我方 cipher**（保证双方 transcript 一致）。
- random 对齐：注入字节里的 random 换成 `ssl->s3->server_random`（TLS 1.3 key schedule 只看 transcript，但 API/会话一致性要求同步）。
- 安全校验：镜像 SH 必须 **(i)** type=2、**(ii)** 含 `supported_versions` 与 `key_share`、**(iii)** 不含 `pre_shared_key`、**(iv)** key_share 组与 `hs->new_session->group_id` 相同、**(v)** 长度匹配。任一不满足 → **不注入**（用 BoringSSL 自己生成的 SH），保证不会把连接搞挂。

### 4.2 服务端 app（`server/`，新文件，不属 patch）

| 文件 | 职责 | 预估 |
|---|---|---|
| `server/reality_common.h` | REALITY 常量（version 1.0.0、X25519 group 0x001d、偏移 39）、`RealityServerConfig` | ~60 |
| `server/reality_common.cc` | 纯函数：解析 CH（session_id/random/key_share）→ `RealityDeriveAuthKey()`（X25519+HKDF）→ `RealityOpenSessionId()`（AES-256-GCM，AAD=session_id 置零的整条 CH）→ 版本/时间窗/shortId 校验 = `RealityAuthDecide()`；临时 Ed25519 证书生成 + `HMAC-SHA512` 覆写签名字段 | ~260 |
| `server/reality_server.cc` | L4 监听 + `MSG_PEEK` 窥探 CH → 只解析的 BoringSSL 实例跑 `RealityAuthDecide()` → 分流：认证走 REALITY TLS（select-cert 回调 + 挂起 + mirror 抓 SH + 注入），否则 `splice()` 到 target；连接循环用 `poll()` 单线程 | ~420 |
| `server/mirror_client.cc`（或并入上一文件） | 挂起窗口内连 mirror：`SSL_set1_supported_groups([client_first_group, X25519])`、`SSL_set_msg_callback` 抓 SH（校验 type=2 且非 HRR） | ~120 |
| `server/poc_suspend_resume.cc` | 博客 PoC 1 的等价物（挂起原语自测） | ~120 |
| `server/poc_end_to_end.cc` | 博客 PoC 2 的等价物 + **真认证**：内存 BIO 三方（client=打了客户端 patch 的 BoringSSL / reality-server / mirror-server），跑完整 REALITY 握手 + 数据 | ~350 |

### 4.3 客户端 patch（`lightweight-reality-client.patch`，对 `/root/upstream-naiveproxy`）

| 文件 | 职责 | 改动 | 预估 |
|---|---|---|---|
| `src/third_party/boringssl/src/ssl/internal.h` | 状态 | `ssl_st` 加 `reality_configured` / `reality_public_key[32]` / `reality_short_id[8]` / `reality_auth_key[32]` / `reality_auth_key_set` | +10 |
| `src/third_party/boringssl/src/include/openssl/ssl.h` | 公开 API | `SSL_set1_reality_config()`、`SSL_reality_verify_certificate()` 声明 | +14 |
| `src/third_party/boringssl/src/ssl/handshake_client.cc` | 接缝（客户端侧） | 在 `ssl_add_client_hello()`（:219）`add_message` 之前调用 `ssl_reality_patch_client_hello()`；新增静态函数（X25519 私钥来自 `hs->key_shares` + `SerializePrivateKey`、HKDF、AES-GCM 封装 session_id blob） | +95 |
| `src/third_party/boringssl/src/ssl/extensions.cc` | sigalg carve-out | `tls12_check_peer_sigalg()` 里加 `is_reality_ed25519` 放行分支（门控） | +9 / −2 |
| `src/third_party/boringssl/src/ssl/ssl_lib.cc` | API 实现 | `SSL_set1_reality_config()` + `SSL_reality_verify_certificate()`（HMAC-SHA512 比对 leaf 签名域） | +70 |
| `src/net/socket/reality_config.h/.cc` | net 层配置 | 进程级 `SetRealityConfig/GetRealityConfig`（mutex + optional） | +55 |
| `src/net/socket/ssl_client_socket_impl.cc` | 接线 | ① `Connect()` 附近：有配置则 `SSL_set1_reality_config()`；② `VerifyCert()` 开头：REALITY 校验通过则直接 `ssl_verify_ok`（否则走原逻辑）；③ 结果字段最小填充 | +45 |
| `src/net/tools/naive/naive_config.{h,cc}` | 配置解析 | `NaiveConfig` 加 `RealityConfig`（`public_key`/`short_id` hex），JSON 与 CLI 解析 | +45 |
| `src/net/tools/naive/naive_proxy_bin.cc` | 启动接线 | 解析完配置后 `SetRealityConfig(...)` | +12 |
| **合计** | | | **≈ +355 / −2，11 文件（BoringSSL 5 + net 6）** |

**与博客"客户端十余处门控"的对照**：改动点 = 5 处 BoringSSL（CH 注入 / 字段 / 两个 API / carve-out）+ 5 处 net（配置、set、verify、解析、启动）= **10 处**，全部有门控；行数比博客的说法大，是因为博客的"十余处"不含配套的配置解析与 crypto helper（naivereal 是 +737/−8，本实现约为它的一半）。**超量部分在报告里逐处解释。**

---

## 5. "关掉即上游行为"的保证方式

- 服务端：`SSL_CONFIG::reality_serverhello_cb == nullptr` 时，`do_send_server_hello()` 的执行路径与上游**完全一致**（只在 `add_message` 前多一次指针判空）。
- 客户端：`ssl->reality_configured == false` 时：CH 注入函数直接 return；`tls12_check_peer_sigalg` 走原条件；`VerifyCert()` 走原路径；`SetRealityConfig(nullptr)` 后全局回到无配置态。
- 所有新增符号只增不改（除 carve-out 的 2 行条件改写），无删除行。

---

## 6. 验证策略（含 2.4G 内存约束）

| 验证项 | 做法 | 预期 |
|---|---|---|
| BoringSSL 可编译性 | 已起：`cmake -GNinja -DBUILD_TESTING=OFF` + `ninja -j2 ssl crypto`（tag 0.20260413.0，worktree `/root/lightweight-reality/boringssl`，日志 `/tmp/bssl_build.log`） | 407 个目标，`-j2`；**只编库，不编测试、不碰 Chromium**；内存峰值靠 `-j2` + `nice` 控制，若 OOM 降 `-j1` |
| 服务端 patch 语法/链接 | 打完 patch 后 `ninja ssl`（增量） | 编译通过 |
| 博客 PoC 1 等价 | `poc_suspend_resume`：挂起 → 0 字节 → 恢复 → 握手完成 | PASS |
| 博客 PoC 2 等价 + 真认证 | `poc_end_to_end`：镜像 SH 注入 + session_id 认证 + HMAC 证书校验 + 数据 | PASS（若失败，按失败点标注 `[未验证]`） |
| 客户端 patch 可应用 | `git apply --check lightweight-reality-client.patch`（在 `/root/upstream-naiveproxy` 的干净副本上） | 通过（不写原树，副本在 `/root/lightweight-reality/naiveproxy-check`） |
| 客户端 patch 语法 | 把客户端 BoringSSL hunks 应用到同一 BoringSSL worktree 的**第二份副本**编译（可选，若时间允许） | 编译通过 |
| Chromium 全量编译 | **不做**（1.1GB 树、需要完整 Chromium 工具链与 GB 级内存） | 明确标 `[未验证]` |

内存纪律：编译用 `nice -n 10`、`-j2→-j1` 降级；不并行跑多个编译；OOM 则如实记录。

---

## 7. 交付物

1. `/root/lightweight-reality-server.patch`（BoringSSL 服务端三接缝）
2. `/root/lightweight-reality-client.patch`（naiveproxy 客户端）
3. `/root/lightweight-reality/`（工作目录：BoringSSL worktree、`server/` app 与 PoC 源码、构建脚本）
4. `/root/dsh-lightweight-reality-report.md`（逐处改动 + 行数 + 验证状态 + 与博客章节对应表 + `[未验证]` 清单 + 与 naivereal 对照）

## 8. 风险清单

1. **cipher/hash 耦合**：镜像 SH 的 cipher 若跨 hash 家族（SHA-256↔SHA-384）不能采纳 → 已用"同 hash 才采纳，否则改回我方 cipher"兜住。
2. **扩展集污染**：mirror 回显我方 mirror-client 的扩展（如 pre_shared_key）→ 已用"只接受 {supported_versions, key_share}"校验兜住。
3. **HRR**：mirror 回 HelloRetryRequest（也是 type=2）→ mirror 抓取侧校验 HRR random 常量，抓到 HRR 就放弃注入（回退普通 SH）。
4. **编译内存**：见 §6，OOM 则只交付静态分析 + 明确标注。
5. **客户端无法端到端验证**：Chromium 全量编译不可行 → 客户端侧标注 `[未验证]`，只保证 patch 可应用 + BoringSSL 侧可编译。
6. **同步 dial 的偏离**：博客 §5 是 event-driven 异步；本实现 PoC 在挂起窗口内**同步**连 mirror（与博客 PoC 2 的同进程做法一致），报告里标注这是简化，不改变接缝语义。
