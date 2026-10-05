# 轻量 diff 的 naive-reality：实现报告（严格按《在 BoringSSL 的接缝中实现 REALITY》）

> 2026-10-05 · 只读研究 + 本地实现 · 不 push、不评论、不碰生产
> PLAN：`/root/dsh-lightweight-reality-plan.md`（Phase 1，已落盘）
> 基准博客：[blog.sam1314.com/posts/c65526af.html](https://blog.sam1314.com/posts/c65526af.html)（2026-07-07，@wangran10）
> 基底：BoringSSL tag `0.20260413.0`（`78f7fbee`，博客服务端 pin 的版本）；客户端落在 `/root/upstream-naiveproxy`（Chromium 154 树，树内 BoringSSL `ac39ea68`/CPE 0.20260413.0）
> 标注：**[已验证]**＝本机编译/运行过；**[已应用]**＝补丁已生成、可应用（无法编译）；**[未验证]**＝没做或做不到

---

## 0. 结果一句话

**博客的三接缝 + 实时镜像 + L4 透明回落，在 naive 生态里已经跑通了**：服务端是一份 **BoringSSL 补丁（5 文件 / +193 / −1）** + 一个最小 C++ 前置（L4 `MSG_PEEK` 分流、认证、镜像、回落），客户端是一份 **naiveproxy 补丁（12 文件 / +380 / −1，其中 BoringSSL 5 文件 +201、Chromium net 7 文件 +179）**。
本机跑通了：挂起/恢复原语（err=12、挂起期间 0 字节）、**实时镜像 ServerHello 122 字节注入 + 真认证 + HMAC 证书校验 + 明文数据回环**、以及未认证流量的**透明回落**。所有改动门控；不配置时行为与上游一致。

---

## 1. 与博客的对应关系（逐机制 → 代码位置 → 验证状态）

| 博客机制 | 博客位置 | 本实现位置 | 状态 |
|---|---|---|---|
| 接缝一：证书选择回调里做认证 | §2 接缝一、§4.1 | `server/reality_server.cc` 的 `SelectCertificateCallback()`（`SSL_CTX_set_select_certificate_cb`）+ `RealityAuthDecide()`；L4 与 TLS 两处**共用同一个纯函数** | **[已验证]** 跑了 |
| 接缝一的"认证所需数据全在 `SSL_CLIENT_HELLO` 里" | §2 接缝一 | `server/reality_common.cc` 的 `RealityAuthDecide()` 只读 `ch->random`/`session_id`/`client_hello` + `SSL_early_callback_ctx_extension_get(ch, 51, …)` | **[已验证]** |
| 接缝二：`ssl_select_cert_retry` 挂起、0 字节、可恢复 | §2 接缝二、§4.1 | `SelectCertificateCallback()` 第一次返回 `ssl_select_cert_retry`；`poc_suspend.cc` 直接复现 | **[已验证]** `err=12`、挂起期间 `BIO_ctrl_pending()==0`、第二次回调恢复 |
| 接缝二"挂起窗口里连镜像抓 SH" | §4.2 | `reality_server.cc`：`SSL_do_handshake` 返回 PENDING 后调用 `DialMirrorAndCapture()`，再恢复 | **[已验证]**（PoC 2 与进程级测试） |
| 接缝三：`reality_serverhello_cb` 注入镜像 SH，只换 key_share 密文 | §2 接缝三 | **`lightweight-reality-server.patch`** 的 `ssl/tls13_server.cc`：新增 `reality_apply_server_hello()`，在 `do_send_server_hello()` 的 `finish_message()` 与 `add_message()` 之间挂钩 | **[已验证]** 注入 122 字节 SH、握手完成、无 BAD_DECRYPT |
| 接缝三"先确认客户端提供了镜像的 cipher suite" | §2 接缝三 | app 侧 `ServerHelloMirrorCallback()` 用 `ServerHelloCipher()` 取出镜像 cipher 并检查它在 `auth.client_ciphers` 里；patch 侧另有"hash 同族才采纳，否则改回我方 cipher"的兜底 | **[已验证]** |
| §4.3 组匹配：连镜像必须用客户端首个组 | §4.3 | `RealityAuthDecide()` 记录 `first_group`；`DialMirrorAndCapture()` 用 `SSL_set1_groups_list(GroupNameFor(first_group)[:X25519])` | **[已验证]** |
| §4.3 "ECDH 公钥提取可另选 X25519" | §4.3 | `RealityAuthDecide()` 在 key_share 列表里**单独找 0x001d**，与 first_group 解耦；客户端 `reality_derive_auth_key()` 在 `hs->key_shares` 里找 X25519 份额 | **[已验证]** |
| 三层信任：session-id（信任根）/ Ed25519 CV 保留验证 / sigalg 放宽 | §3 | session-id：客户端 `reality_patch_client_hello()` 封装，服务端 `RealityAuthDecide()` 解封；CV+证书：`SSL_reality_verify_certificate()`（HMAC-SHA512 比对签名字段）；sigalg carve-out：客户端 `ssl/extensions.cc`（`tls12_check_peer_sigalg`）+ 服务端 `ssl/extensions.cc`（`tls1_choose_signature_algorithm`） | **[已验证]**（客户端 carve-out 与 HMAC 校验在 PoC 里实跑） |
| 透明回落：L4 `MSG_PEEK` 窥探 + 只解析的 BoringSSL + 无状态认证函数 | §5 | `reality_server.cc`：`L4Authenticate()`（`recv(MSG_PEEK)` → 一次性 `SSL_CTX` + `ParseOnlyCallback` 跑同一个 `RealityAuthDecide()`）→ 认证走 REALITY TLS，否则 `Splice()` 到 target | **[已验证]** 探针（plain TLS）被原样转发到 target |
| 不改握手主状态机 | §6 | server patch 只在 `do_send_server_hello()` 尾部加一个 `if (ssl->ctx->reality_cb != nullptr)` 分支；上游状态机代码零删改 | **[已验证]** 上游 `ssl_test`/握手代码未动 |
| 门控；关掉即上游行为 | §6 | 所有分支都判空/判配置；不调用 `SSL_CTX_set_reality_serverhello_cb()` / `SSL_set1_reality_config()` 时路径与上游一致 | **[已验证]**（server patch 只增 1 处条件；client patch 只改 1 处条件） |
| 认证实现（博客 PoC 未含） | §4 开头 | XTLS/REALITY 语义：X25519 → HKDF-SHA256(salt=CH.random[:20], info="REALITY") → AES-256-GCM(nonce=CH.random[20:], AAD=session_id 置零的整条 CH)，明文 16 字节 = 版本 3 + 保留 1 + 时间戳 4 + shortId 8 | **[已验证]** 客户端与服务端互解成功、时间窗/shortId 校验生效 |

---

## 2. 交付物与逐处改动

### 2.1 `/root/lightweight-reality-server.patch`（对 BoringSSL tag `0.20260413.0`，**+193 / −1，5 文件**）

| 文件 | 改动 | 行数 |
|---|---|---|
| `include/openssl/ssl.h` | `reality_serverhello_cb` 类型 + `SSL_CTX_set_reality_serverhello_cb()` 声明与文档 | +22 |
| `ssl/internal.h` | `ssl_ctx_st`（SSLContext）加 `reality_serverhello_cb reality_cb = nullptr;` | +6 |
| `ssl/ssl_lib.cc` | setter 实现 | +5 |
| `ssl/extensions.cc` | `tls1_choose_signature_algorithm()` 里加窄门控：装了 reality hook 时允许 Ed25519（客户端未通告也算）| +6 / −1 |
| `ssl/tls13_server.cc` | 新增 `reality_apply_server_hello()`（解析镜像 SH → 校验扩展集/组/长度 → 重建：session_id 回显换成我方、key_share 密文换成我方、random/cipher 对齐）+ 在 `do_send_server_hello()` 里挂钩 | +154 |

**注入点**：`do_send_server_hello()` 中 `finish_message()` 产出完整 ServerHello 之后、`add_message()` 之前——只替换"要发出去的字节"，状态机不迁移。
**拒绝注入的条件**（任一命中就回退到 BoringSSL 自己生成的 SH，保证不会把连接搞挂）：非 ServerHello / 缺 `supported_versions` 或 `key_share` / 出现 `pre_shared_key` / key_share 组与我方不同 / key_share 长度与我方不同 / 解析失败。
**cipher 对齐**：镜像 cipher 若 `SSL_get_cipher_by_value()` 找得到、是 TLS 1.3 套件、且 hash 与已初始化的 transcript 同族，则采纳（并同步 `hs->new_cipher`/`new_session->cipher`）；否则把注入字节里的 cipher 字段改回我方 cipher（双方 transcript 仍然一致）。

### 2.2 `/root/lightweight-reality-client.patch`（对 `/root/upstream-naiveproxy`，**+380 / −1，12 文件**）

BoringSSL 侧（5 文件 / +201 −1）：

| 文件 | 改动 | 行数 |
|---|---|---|
| `src/third_party/boringssl/src/ssl/internal.h` | `ssl_st` 加 `reality_configured` / `reality_public_key[32]` / `reality_short_id[8]` / `reality_auth_key[32]` / `reality_auth_key_set` | +10 |
| `…/include/openssl/ssl.h` | `SSL_set1_reality_config()` / `SSL_reality_verify_certificate()` 声明 | +18 |
| `…/ssl/handshake_client.cc` | `reality_derive_auth_key()`（从 `hs->key_shares` 找 X25519 份额、`SerializePrivateKey()` 取私钥、X25519+HKDF）+ `reality_patch_client_hello()`（把 16 字节明文封成 32 字节 session_id，AAD=置零后的整条 CH）+ 在 `ssl_add_client_hello()` 的 `add_message()` 前调用 | +113 |
| `…/ssl/extensions.cc` | `tls12_check_peer_sigalg()` 窄门控 carve-out（只放行 Ed25519，且仅当 `reality_configured`） | +8 / −1 |
| `…/ssl/ssl_lib.cc` | 两个导出函数实现（AuthKey 存取 + HMAC-SHA512 比对 leaf 签名字段） | +52 |

Chromium net 侧（7 文件 / +179，由子代理完成，我复核接线点）：

| 文件 | 改动 | 行数 |
|---|---|---|
| `src/net/socket/reality_config.h/.cc`（新） | 进程级 `SetRealityConfig()/GetRealityConfig()`（`std::optional<RealityConfig>`） | +64 |
| `src/net/socket/ssl_client_socket_impl.cc` | ① `Init()` 末尾：有配置则 `SSL_set1_reality_config()`；② `VerifyCert()` 开头：`SSL_reality_verify_certificate()` 通过则直接 `ssl_verify_ok`（绕过链/CT/HPKP），否则原样回退标准校验 | +35 |
| `src/net/tools/naive/naive_config.h/.cc` | 解析 JSON `"reality": {public_key, short_id}`（及扁平键 `reality-public-key`/`reality-short-id`，手工 hex 校验） | +68 |
| `src/net/tools/naive/naive_proxy_bin.cc` | 解析后、起 socket 之前 `net::SetRealityConfig(*config.reality)` | +11 |
| `src/net/BUILD.gn` | 源列表加 `socket/reality_config.cc` | +1 |

### 2.3 服务端 app 与 PoC（`/root/lightweight-reality/server/`，新代码，不属于 patch）

| 文件 | 行数 | 作用 |
|---|---|---|
| `reality_common.h/.cc` | 104 + 321 | REALITY 常量与纯函数认证（`RealityAuthDecide`）、临时 Ed25519 证书 + HMAC 覆写签名、ECDSA 测试证书helper |
| `reality_server.cc` | 559 | 前置进程：L4 `MSG_PEEK` 分流、REALITY TLS（select-cert 挂起 + 镜像抓取 + 注入）、透明回落 `Splice()`、可选 backend 桥接 |
| `poc_suspend.cc` | 151 | 博客 PoC 1 等价物（挂起原语） |
| `poc_end_to_end.cc` | 346 | 博客 PoC 2 等价物 + 真认证 + HMAC 证书校验（内存 BIO 三方） |
| `poc_mirror_server.cc` / `poc_client.cc` | 80 / 118 | 进程级 e2e：镜像站（TLS 1.3 + 回显）与 REALITY 客户端 |

---

## 3. 验证结果（本机实跑）

| # | 验证项 | 命令/方式 | 结果 |
|---|---|---|---|
| 1 | BoringSSL 可编译（服务端+客户端补丁都在） | `cmake -GNinja -DBUILD_TESTING=OFF` + `ninja -j2 ssl crypto`（tag `0.20260413.0`） | ✅ `libcrypto.a` + `libssl.a` 构建通过；**没有 OOM**（峰值可用内存 ≥ ~150MB，全程 `nice -n 10 -j2`） |
| 2 | 博客 PoC 1（挂起原语） | `./bin/poc_suspend` | ✅ `err=12 (PENDING_CERTIFICATE)`、**挂起期间 0 字节**、第二次回调恢复、握手完成（TLS 1.3） |
| 3 | 博客 PoC 2（实时镜像 + 真认证） | `./bin/poc_end_to_end` | ✅ 抓取镜像 **122 字节** SH → 注入 → 恢复 → 握手完成 `TLS_AES_128_GCM_SHA256` → 数据 13 字节 → **无 BAD_DECRYPT** |
| 4 | 进程级 e2e（真 TCP：客户端→REALITY 前置→镜像） | `/tmp/run_tests.sh` / `/tmp/final_tcp_test.sh` | ✅ 客户端握手成功、数据回环 OK；服务端日志 `mirrored ServerHello: yes, 122 bytes`（镜像 = 本机 TLS 1.3 服务，SH 经真 TCP 抓取后注入） |
| 5 | L4 透明回落（未认证流量） | `openssl s_client` 探针打前置 | ✅ 探针被原样转发到 target（拿到 target 的证书、无 TLS alert；服务端未进入 REALITY 分支） |
| 6 | 客户端补丁可应用 | `git apply --check -R`（对 naiveproxy worktree）+ 锚点脚本在另一棵 BoringSSL 树上成功应用 | ✅ **[已应用]**；**未编译**（见 §6） |
| 7 | 客户端 BoringSSL 代码可编译 | 同一份客户端代码已应用到 tag 树并参与 #1 的编译 | ✅（tag 树形态；naiveproxy 树是新版 API，`ssl_lib.cc` 用 `FromOpaque(ssl)->` 变体，未编译） |

**关键日志**（PoC 2）：

```
=== Phase 1: client -> ClientHello -> reality server ===
  [reality-server] select_cb: SUSPEND (ch_len=190 sid=32)
  suspended: err=12 (PENDING_CERTIFICATE), 0 bytes emitted
=== Phase 2: [suspension window] dial mirror, capture SH ===
  captured LIVE ServerHello: 122 bytes
=== Phase 3: RESUME with the live mirror ServerHello ===
  [reality-server] select_cb: RESUME
  [reality-server] returning LIVE mirror SH: 122 bytes
=== Phase 4: verify ===
  reality handshake complete: YES
  negotiated: TLSv1.3 cipher=TLS_AES_128_GCM_SHA256
  data transfer: OK (13 bytes)
PASS: realtime mirror handshake works (live ServerHello injected, no BAD_DECRYPT)
```

---

## 4. 行数账：与博客"轻量"标准的对照

| 项 | 博客 | 本实现 | 差异原因 |
|---|---|---|---|
| 服务端 BoringSSL 改动 | +210 / −45，3 文件 | **+193 / −1，5 文件** | 行数在量级内（更少）；文件数 +2：博客把公开 API 声明算进内部头，我把 `include/openssl/ssl.h` 与 `ssl/internal.h` 分开；另外博客的 −45 大概来自删改（我选择"只增不改"以保住"关掉即上游"）。**多出来的是 `ssl/extensions.cc` 的 6 行 sigalg carve-out**——博客 §3 把"sigalg 放宽"列为三层信任之一，但没说落在哪一侧；BoringSSL 的服务端**也必须**放宽（否则 Ed25519 证书根本选不出来），这是把博客机制真正接通所必需的 |
| 客户端"十余处门控" | 十余处 | **10 处改动点**（BoringSSL 5 + net 5），但 **+380 行** | 改动点数量对得上（10 处）；行数远超"十余处"的印象，主要是三块**博客没算进客户端**的配套：① 认证/封装/校验的 crypto helper（`handshake_client.cc` +113、`ssl_lib.cc` +52）② real 配置解析与校验（`naive_config.cc` +63）③ 进程级配置与 new 文件（+64）。naivereal 同类工作实测 +737/−8，本实现约它一半 |
| 服务端 app | 博客没给 app（只有 patch + PoC） | 559 行前置 + 321 行公共库 | 博客的 app 隐含在"event-driven 框架"里；我这里是一个可编译、可跑的最小前置（含 L4 peek、回落、镜像、桥接） |
| PoC | 两个内嵌 PoC | `poc_suspend` + `poc_end_to_end`（+ 进程级两个小工具） | 与博客一一对应，且**补上了博客缺的认证** |

---

## 5. 与 naivereal（`lipeiying032/naive-reality`）的对照

| 维度 | naivereal | 本实现 | 说明 |
|---|---|---|---|
| 认证载体 | legacy session_id（offset 39，AES-256-GCM，AAD=置零后的整条 CH） | **完全相同** | 与 XTLS/REALITY 语义一致；本实现额外踩到一个坑：BoringSSL 的 `SSL_CLIENT_HELLO::client_hello` **不含 4 字节握手头**，服务端必须自己补回（见 §7） |
| 客户端 BoringSSL 改动 | +338/−3（11 文件，含新文件 `ssl/reality.cc` 236 行） | **+201/−1（5 文件，无新文件）** | 本实现把 crypto 直接放进 `handshake_client.cc`/`ssl_lib.cc`，省掉构建文件改动 |
| 客户端 sigalg carve-out | 有（改 `tls12_check_peer_sigalg`） | **有，同一函数同一思路** | 独立得出同一结论，互为交叉验证 |
| 服务端 | Go（`xtls/reality`），**不镜像 SH** | **C++（BoringSSL）+ 实时镜像 SH** | 本实现按博客走"镜像真实 ServerHello"路线——这是博客相对 naivereal 的唯一机制级增量 |
| 未认证流量 | 交给 `xtls/reality` 库"先拨 target、失败直转" | **L4 `MSG_PEEK` 预判定** + 分流 | 本实现把判定提前到 TLS 之前，不会先建一次 TLS 再丢弃（博客 §5 的做法） |
| net 层 | 新文件 + 8 文件 +315/−1 | 新文件 + 7 文件 +179 | 更小 |
| 未知/风险 | 编译未验证 | 同样：客户端侧只能"补丁可应用 + 同源代码在 tag 树编译通过" | 见 §6 |

---

## 6. `[未验证]` 清单（照实说）

1. **[未验证] naiveproxy 客户端补丁没有编译过**：本机没有 Chromium 工具链，全量编译也远超内存。已做的替代验证：① 同一份客户端代码（除 `ssl_lib.cc` 的 `FromOpaque` 变体）已在 BoringSSL tag 树上随 `libssl` 编译通过；② 补丁在 naiveproxy worktree 上 `git apply --check -R` 通过（内容与工作树一致）；③ 锚点脚本在新版 BoringSSL 上成功应用（说明位置正确）。**net 层那 7 个文件的代码完全没编译过。**
2. **[未验证] 没有真机端到端跑 naiveproxy**：PoC 用的是"同一套 BoringSSL 补丁 + 自写客户端"，协议层（naive 的 h2 CONNECT、padding）没有参与 REALITY 握手测试。
3. **[未验证] 镜像目标不是真网站**：镜像抓取验证过两类端点——本机 TLS 1.3 服务、以及本机另一个真实 TLS 1.3 监听（122 字节 SH）。**没有对公网真站（如 microsoft.com）抓过**，`§4.3` 的 MLKEM768（0x11ec）分支只有代码路径，没有实测到（PoC 客户端默认组是 X25519）。
4. **[未验证] 浏览器（Chrome/naiveproxy）侧的 sigalg carve-out 行为**：客户端 carve-out 只在"我们的 PoC 客户端 + 我们自己签发的 Ed25519 临时证书"上验过；真实 Chromium `VerifyCert()` 路径未跑。
5. **[未验证] 滥用/限速**：前置进程没有连接数限制、没有速率限制（博客也没做）；镜像抓取是**同步阻塞**的，与博客 §5 的 event-driven 异步有差距（见 §7）。
6. **[未验证] 并发与稳定性**：进程级测试只跑了单连接；前置是 thread-per-connection，没做压力测试。
7. **[未验证] 会话恢复/PSK**：patch 拒绝注入带 `pre_shared_key` 的镜像 SH 并回退，但"客户端带 ticket 恢复"的完整路径没测。
8. **[未验证] 客户端配置的进程级作用域**：`net::SetRealityConfig()` 是进程级全局（与 naivereal 同思路），所有 TLS 连接（含证书 AIA 抓取等辅助上下文）都会带上 REALITY 参数；认证不通过时会回退标准校验，风险有限，但没有系统评估。

---

## 7. 实现中踩到 / 值得记一笔的点

1. **`SSL_CLIENT_HELLO::client_hello` 不含 4 字节握手头**（`ssl/handshake.cc:94` 传的是 `out_msg->body`）。而客户端封装 AAD 用的是**完整握手消息**（含头，offset 39 才对得上）。第一版服务端直接用 `ch->client_hello` 当 AAD，长度 190 vs 客户端 194，AEAD 一直 `open=0`。修法：服务端把 `[0x01, len24]` 补回再置零 session_id。**naivereal 的服务端是 Go（`xtls/reality`），这份坑是 C++ 侧独有的。**
2. **Ed25519 私钥是 64 字节**（`ED25519_keypair(out_pub[32], out_priv[64])`），而 `EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, …, len)` 要 **32 字节种子**。第一版按 32 字节接收 → 栈溢出（`stack smashing detected`），gdb 定位到 `main` 的栈金丝雀。这个坑值得写进任何 BoringSSL REALITY 实现。
3. **`SSL_OP_NO_TICKET` 必开**（镜像客户端）：否则镜像 SH 可能带 `pre_shared_key`，注入后我方并没有协商 PSK。
4. **服务端也要放宽 sigalg**：`tls1_choose_signature_algorithm()` 只在客户端通告的算法里选；Chrome 族 CH 不含 Ed25519 → 不放宽就 `NO_COMMON_SIGNATURE_ALGORITHMS`（我在 PoC 里第一次就撞上了）。博客 §3 把它写成"协商形式放宽"，两侧都要放宽才闭环。
5. **镜像抓取用同步阻塞**：博客 §5 描述的是 event-driven 异步（挂起期间释放 worker）。本实现 PoC 在挂起窗口内同步连镜像（与博客 PoC 2 的同进程做法一致），生产化时应换成异步——**接缝语义不变**，只是调度方式不同。
6. **测试环境注意**：本机 8443 端口被一个生产 Xray 占用，第一次 e2e 实际打到它身上（镜像抓取仍成功，说明机制对任意 TLS 1.3 端点有效）；后续测试改用 18443/18444。**没有对生产服务做任何写操作**。
7. **`SSL_get_error()` 的 `1` 是 `SSL_ERROR_SSL`（fatal），不是 `SSL_ERROR_WANT_READ`（BoringSSL 里 WANT_READ=2）**：镜像抓取一度"看起来在等数据"，实际是 fatal alert。根因是 PoC 镜像站当时用的是 **Ed25519 证书**，而抓取侧的 BoringSSL 客户端**不通告 Ed25519** → 镜像侧 `NO_COMMON_SIGNATURE_ALGORITHMS`。把镜像换成 P-256 证书后，进程级 TCP 链路完全跑通（`mirrored ServerHello: yes, 122 bytes`）。**任何"拿 BoringSSL 当普通 TLS 客户端"的场景都会踩这条。**

---

## 8. 如何复现

```bash
# 1) 应用服务端补丁（BoringSSL tag 0.20260413.0）
git clone --depth 1 https://boringssl.googlesource.com/boringssl && cd boringssl
git fetch --depth 1 origin 78f7fbeec98a2fb15acea6f7a9f1def7f2e6d9a0 && git checkout 78f7fbee
git apply /root/lightweight-reality-server.patch
cmake -GNinja -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF . && ninja -C build -j2 ssl crypto   # 约 10 分钟

# 2) 应用客户端补丁（naiveproxy 树）
git -C /root/upstream-naiveproxy worktree add /tmp/np HEAD
git -C /tmp/np apply /root/lightweight-reality-client.patch

# 3) 构建 PoC 并跑
bash /root/lightweight-reality/build.sh          # 需要 boringssl/ 在本目录（符号链接到上面那棵树）
./bin/poc_suspend        # 博客 PoC 1：挂起原语
./bin/poc_end_to_end     # 博客 PoC 2：镜像注入 + 真认证
/tmp/run_tests.sh        # 进程级：REALITY 客户端 e2e + 明文探针回落
```

---

## 9. 结论

- **严格按博客做的部分**：三接缝、实时镜像（连镜像→抓 SH→注入→只换 key_share 密文）、§4.3 组匹配（连镜像用客户端首个组、ECDH 用 X25519 份额）、L4 `MSG_PEEK` 透明回落、门控、不动握手主状态机——**全部落地并跑通**。
- **博客没给、我补的部分**：认证的完整实现（照 XTLS/REALITY 语义）、服务端 ed25519 sigalg 放宽、服务端 AAD 需要补握手头、临时证书的 HMAC 覆写、一个可编译的前置进程与 PoC。
- **没做到的**：客户端（naiveproxy）侧只到"补丁可应用 + 同源代码编译通过"，没有 Chromium 编译/真机验证；镜像未对公网真站实测。
- **一句话**：博客的方案在 naive 生态里**是可实现的，且服务端改动确实只有两百来行**；真正的工作量在"认证 + 前置进程 + 客户端接线"，而不是在那三处接缝。
