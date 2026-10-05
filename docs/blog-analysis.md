# 《在 BoringSSL 的接缝中实现 REALITY》精读 + 三方对照 + 对 naive-reality 路线的意义

> 2026-10-05 · 只读研究 · 不 push、不评论、不编译
> 原文：https://blog.sam1314.com/posts/c65526af.html （@wangran10 投稿；页面元数据 **发表于 2026-07-07 00:00、更新于 2026-07-07 12:22**（UTC+8），页内提示"更新距今 90 天"）
> 原文在线抓取失败（Cloudflare 人机校验，只拿到 5.4KB 的 "Just a moment..." 页），本报告以**本地缓存全文**为准：`/root/.hermes/cache/documents/doc_12eac901fafe_*.html`（728KB，正文完整，含 6 个代码块）；提取后的纯文本在 `/root/boring-blog.txt`（339 行）。
> 标注规则：**[核实]**＝我在本机源码/仓库里逐行看过；**[博客称]**＝博客自述、但代码未公开、我无法核实；**[推断]**＝我的推理；**[未验证]**＝没查到可靠证据。
> 引用代号：**[tag 0.20260413.0]**＝BoringSSL tag `0.20260413.0`（commit `78f7fbee…`，博客服务端 pin 的版本，我把关键行都在这个 tag 上重查过）；**[本机BS]**＝`/root/upstream-naiveproxy/src/third_party/boringssl/src`（naiveproxy 树内 BoringSSL，`README.chromium` 记 Revision `ac39ea68…`、CPE `cpe:/a:google:boringssl:0.20260413.0`）；**[HEAD]**＝BoringSSL 上游 HEAD `dd73e69a…`（2026-10-03，子代理浅克隆 `/root/boringssl`）；**[naivereal]**＝`/root/naivereal-prior-art`（HEAD `274a470`）；**[Go]**＝本机 go1.26.5 源码 + `/root/reality-src`（XTLS/REALITY）；**[uTLS]**＝refraction-networking/utls master；**[博客]**＝缓存 HTML 原文。
> 两份逐项证据文件（子代理产出，我抽检过关键条目）：`/root/boring-verify-boringssl.md`（544 行）、`/root/boring-verify-naivereal.md`（435 行）。

---

## 0. 一页纸：这篇博客到底给了什么、我核实到什么程度

博客的主线只有一句：**REALITY 的服务端可以不做在 Go 里，而是顺着 BoringSSL 本来就留好的三个扩展点做进去；授权握手的 ServerHello 每连接实时从真站镜像，认证失败则用 L4 层的 MSG_PEEK 提前分流，不在 TLS 里发 alert。**

我把它拆成 6 条主张，逐条核实：

| # | 博客的主张 | 我的核实结论 | 依据 |
|---|---|---|---|
| 1 | 接缝一：`SSL_CTX_set_select_certificate_cb` 在 ClientHello 解析完、ServerHello 生成前触发，能拿到认证需要的一切 | ✅ 成立 | 文档与实现都在：[本机BS] `ssl.h:5396-5412`、`ssl/handshake_server.cc:508-541`；`SSL_CLIENT_HELLO` 字段齐全 `ssl.h:5344-5361` |
| 2 | 接缝二：回调返回 `ssl_select_cert_retry` → 握手挂起、**一个字节都不发**、之后可恢复 | ✅ 成立，且比博客说得更"糙"——恢复不是断点续跑，而是**从同一状态重跑、回调第二次被调用** | [tag 0.20260413.0] `ssl/handshake_server.cc:599-600`、`ssl/handshake.cc:616-619`、`ssl.h:5494`；上游测试 `ssl_test.cc:12176-12199` 就是这个用法（[HEAD] 行号） |
| 3 | 接缝三：`reality_serverhello_cb` 注入镜像 ServerHello，只换 key_share 密文 | ⚠️ 机制自洽，但**这个 hook 不是上游 API，是博客自己加的 patch**（上游 0 命中） | [HEAD]/[tag] 全仓库 grep：`reality_serverhello_cb`、`reality_replace_key_share` 均无 |
| 4 | 客户端改动"十余处、全部门控、关掉与上游逐字节一致" | ❓ **[博客称]**：文章里**没有任何代码或仓库链接**（正文唯一外链是 `t.me/wangran10`），我搜了唯一符号名也没有公开实现 | [博客] 正文链接清单；web 搜索 + grep.app 无果 |
| 5 | 服务端改动 +210/−45 行、3 个文件 | ❓ **[博客称]**：无 patch 可数（同上） | — |
| 6 | "违反 RFC §4.4.3 的 sigalg 通告放宽不是必需的，改用 ECDSA-P256/RSA-PSS 即可合规" | ✅ 逻辑成立（BoringSSL 客户端确实硬检查通告列表），但**换算法会连带影响"客户端认证服务端"那套 HMAC 机制**，博客没提这层耦合 | [tag] `ssl/extensions.cc:351-362`；[Go] `reality-src/handshake_server_tls13.go:150-152`、`/tmp/xray_reality.go:110-112` |

**三句最重要的话：**

1. **三个接缝的机制全部核实为真**（第 3 个 hook 是自加的，但用法与 BoringSSL 的挂起语义完全吻合）。这篇博客把"REALITY 服务端 = 必须改 Go 的 crypto/tls"这个印象打破了：**在 C++/BoringSSL 里做，确实只需要挂一个回调 + 一个注入点 + 一堆门控分支。**
2. **但它没有让 naive + REALITY"落地"更近多少**：博客的接缝全在**服务端**，客户端只写了"十余处门控"六个字；而 naive 生态的服务端是 Caddy（Go），套不上 BoringSSL 的接缝——除非另起一个 C++ 前置进程。
3. **最有价值的两个可搬运点**：① **L4 透明回落**（`MSG_PEEK` 窥探 ClientHello + 用"只解析"的 BoringSSL 实例跑同一份无状态认证函数 → 分流），任何语言的服务端前置都能照抄这个思路；② **sigalg 准入分析**——它精确解释了为什么"naive 客户端（Chromium/BoringSSL）+ Ed25519 临时证书"必然要打一个 RFC carve-out，而第三方项目 naivereal 的补丁里**恰好就有这一处 carve-out**（[naivereal] `patches/001-boringssl-reality.patch:478-495`，改的正是 `tls12_check_peer_sigalg`）。

---

## 1. 机制精读（带出处）

### 1.1 三个接缝，逐个核

#### 接缝一：证书选择回调（认证的落点）

博客说：`SSL_CTX_set_select_certificate_cb` 在 `SSL_do_handshake` 内部触发，时点是"ClientHello 已解析完、ServerHello 还没生成"，REALITY 的 session-id 认证（X25519 → HKDF → AES-GCM）就放这儿。

核实：

- 声明与语义：[本机BS] `include/openssl/ssl.h:5396-5409`（原文："sets a callback that is called before most ClientHello processing and before the decision whether to resume a session is made… In the case that a retry is indicated, `SSL_get_error` will return `SSL_ERROR_PENDING_CERTIFICATE` and the caller should arrange for the high-level operation on `ssl` to be retried at a later time, which will result in another call to `cb`"）。
- 触发位置：[本机BS] `ssl/handshake_server.cc:508-541` 的 `do_read_client_hello_after_ech()`——回调（`:516-521`）确实在 ClientHello 解析之后、版本范围冻结（`:541-542`）与 TLS 1.3 跳转（`:628`）之前。**ServerHello 尚未生成**，博客这句话对。
- 能拿到的东西：[本机BS] `ssl.h:5344-5361` 的 `SSL_CLIENT_HELLO`（`struct ssl_early_callback_ctx`）里有 `client_hello/_len`、`random/_len`、`session_id/_len`、`cipher_suites/_len`、`extensions/_len`（外加 `ssl`、`version`、`dtls_cookie*`、`compression_methods*`）。博客 PoC 里用到的 `ch->client_hello_len`、`ch->session_id_len`、`ch->random` **全部存在**，找扩展用 `SSL_early_callback_ctx_extension_get`（[本机BS] `ssl.h:5384-5387`）。→ 博客说的"`SSL_CLIENT_HELLO` 原生暴露了认证所需的一切，不需要 patch"**[核实]成立**。
- 一个博客没提但实现者必须知道的坑（文档原文）：*"Note: The `SSL_CLIENT_HELLO` is only valid for the duration of the callback and is not valid while the handshake is paused."*（[本机BS] `ssl.h:5408-5409`）——**挂起期间不能再用那个指针**，要用的字节必须先拷出来。博客的镜像 PoC 是"挂起窗口里连真站、抓 SH"，与这个指针无关，所以没踩到；但真正把认证数据留到恢复后用的实现要小心。

#### 接缝二：挂起 / 恢复（把"异步证书"机制当通用暂停用）

博客说：返回 `ssl_select_cert_retry` 后 BoringSSL 给 `SSL_ERROR_PENDING_CERTIFICATE`，握手挂起、**不发任何字节**、状态机冻结、worker 可释放；本质是"在握手某个确定时点合法暂停整个状态机、去做任意异步 I/O、再接着走"的通用原语。

核实（三层证据）：

1. retry 的落点：[tag 0.20260413.0] `ssl/handshake_server.cc:599-600` `case ssl_select_cert_retry: return ssl_hs_certificate_selection_pending;`
2. 挂起动作：[tag 0.20260413.0] `ssl/handshake.cc:616-619`
   ```c
   case ssl_hs_certificate_selection_pending:
     ssl->s3->rwstate = SSL_ERROR_PENDING_CERTIFICATE;
     hs->wait = ssl_hs_ok;
     return -1;
   ```
   即：设一个 rwstate 然后**直接 return -1**，没有 flush、没有写记录 —— **TLS 下 0 字节发给对端成立**（DTLS 在握手循环开头有一次 flush，见 [HEAD] `ssl/handshake.cc:532-537`，博客的"不发任何字节"只对 TLS 语境的描述是准确的）。
3. `SSL_ERROR_PENDING_CERTIFICATE` 就是 **12**：[tag] `ssl.h:437` `#define SSL_ERROR_PENDING_CERTIFICATE 12` —— 和博客 PoC 输出里的 `err=12` 对得上。`SSL_get_error` 的映射在 [本机BS] `ssl/ssl_lib.cc:1243`（错误码→`SSL_ERROR_PENDING_CERTIFICATE`；`:1322` 是它的字符串名）。

**比博客说得更值得注意的一点**（子代理在上游测试里找到的）：恢复**不是断点续跑**。`hs->wait = ssl_hs_ok`、`hs->state` 不前进，下一次 `SSL_do_handshake` 会**从函数头重跑**这个状态，于是**回调被第二次调用**——这正是上游文档 `…which will result in another call to cb` 的意思，上游自己的测试 `ssl_test.cc:12176-12199` 就是"第一次 retry、第二次 success"的写法（[HEAD] 行号）。所以"把挂起当通用暂停用"这个挪用是**合法且被库显式支持的**，博客对它的评价（"不是找到一个异步 API，而是意识到扩展点的本质能力"）我**[核实]认同**。

一个小差异：这个枚举在上游现在有 **4 个值**，博客只提了 3 个——多了 `ssl_select_cert_disable_ech = -2`（[本机BS] `ssl.h:5384`），与 REALITY 无关，但说明"接缝语义随版本变"不是空话。

另外，博客说"在证书回调里返回错误会让 BoringSSL 发 alert"——**有代码为证**：[本机BS] `ssl/handshake_server.cc:530-534`，`case ssl_select_cert_error:` → `ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE)`。这个 alert 对探测者就是"这台机器握手失败"的可识别信号，所以博客才要把判定提前到 L4（见 §1.5）。

#### 接缝三：ServerHello 镜像回调（**博客自己加的 patch，不是上游 API**）

博客给的签名：

```c
// 返回 true 并把 out/out_len 设为要发出的镜像 ServerHello 字节。
bool (*reality_serverhello_cb)(SSL *ssl, const uint8_t **out, size_t *out_len);
```

核实：**[tag]/[HEAD]/[本机BS] 三份源码里都没有这个符号**，`reality_replace_key_share` 同样 0 命中；整个 BoringSSL 仓库里 `reality` 只出现在 6 处英文散文（gmock 文档、x509_test、evp_extra_test、aesni-x86_64.pl ×2、d1_both.cc）——**这两个 hook 是博客服务端 patch 的产物**。子代理的独立克隆（[HEAD]）也得到同样结论。

博客描述它做的两件事：
1. **采用镜像的 cipher suite**，但先确认客户端确实在 CH 里提供了这个套件（检查 `client_hello.cipher_suites`）；
2. **发镜像的 ServerHello**，只把 key_share 扩展里的密文换成服务端自己的（`reality_replace_key_share`），这样 ECDHE 是真的，其余部分逐字节像被镜像的站。

**[推断] 这里有个博客一句带过、但实现上必须处理的点**：从"线上字节"看是"只换了 key_share 密文"，但服务端内部状态（`hs->hello` 的 random、cipher suite、session_id、自己的 key_share 私钥）必须和注入的 SH **保持一致**，否则 key schedule 与 transcript 会对不上（transcript = 双方各自哈希自己看到的 SH 字节）。也就是说：patch 要落在"生成 SH 的那条路径"上，把 BoringSSL 自己生成的值换成镜像值 + 自己的密钥份额。博客说"握手主状态机没有改动"，指的是**状态机流程没重写**（还是标准 SH → EE → Cert → CV → Fin），不是说 SH 的**产出路径**没被碰过。

### 1.2 实时镜像的完整流程（PoC 2）

博客给的是"同进程三方"（client、reality-server、mirror-server，全走 memory BIO）：

```
1. client 发 ClientHello -> reality-server
2. reality-server 的 select_cb 返回 ssl_select_cert_retry，握手挂起，0 字节发出
3. [挂起窗口] reality-server 作为 TLS 客户端连 mirror-server，完成一次握手，
   经 SSL_set_msg_callback 抓下 mirror-server 的 ServerHello 字节
4. reality-server 恢复。发 ServerHello 时调用 reality_serverhello_cb，
   返回刚抓的 ServerHello（session_id 换成此 client 的）；
   patch 把其中 key_share 密文换成自己的，并沿用镜像的 random。
5. client 对着 reality-server 走完握手，数据流通。
```

抓包那段的代码（博客原文，PoC 2 只给了这一段）：

```cpp
static std::vector<uint8_t> g_live_mirror_sh;
static void mirror_msg_cb(int write_p, int, int content_type,
                          const void *buf, size_t len, SSL *, void *) {
  // 入站(write_p==0) 的握手(content_type==22)，首字节是 ServerHello(type==2)
  const uint8_t *p = static_cast<const uint8_t *>(buf);
  if (write_p == 0 && content_type == SSL3_RT_HANDSHAKE &&
      len >= 1 && p[0] == SSL3_MT_SERVER_HELLO && g_live_mirror_sh.empty()) {
    g_live_mirror_sh.assign(p, p + len);   // 要注入给真实客户端的实时 ServerHello
  }
}
```

核实（`SSL_set_msg_callback` 是真 API，用它抓 SH 的写法成立）：

- 声明：[本机BS] `ssl.h:5169-5171`；文档 `:5136-5162` 明确"For each handshake message… `content_type` is the corresponding record type. The `len` bytes from `buf` contain the handshake message"→ **缓冲区首字节就是 handshake type**，所以 `p[0] == SSL3_MT_SERVER_HELLO` 这个判断合法 ✓；`write_p` = 1 出 / 0 入 ✓。
- 一个细节修正：**上游没有叫 `SSL_msg_callback` 的 typedef**（[HEAD] 全仓库 0 命中），参数是内联函数指针类型，而且 `SSL_CTX_set_msg_callback` 那版的形参名是 `is_write`、`SSL_set_msg_callback` 那版是 `write_p`（[本机BS] `ssl.h:5159-5171`）。博客的代码本身用的是 `SSL_set_msg_callback`，没问题。

PoC 2 的运行输出（博客原文）：

```
=== Phase 2: reality-server SUSPENDS ===
    [reality-server] select_cb: SUSPEND (sid=32B)
    suspended cleanly (0 bytes emitted)
=== Phase 3: [async window] dial mirror, capture LIVE ServerHello ===
    [mirror-client] captured LIVE ServerHello: 122 bytes
=== Phase 4: RESUME reality handshake with live mirror ===
    [reality_cb] returning LIVE mirror SH: 122 bytes
=== Phase 5: verify ===
  reality handshake complete: YES
  negotiated: TLSv1.3 cipher=0x1301
  data transfer: OK (got 29 bytes)

PASS: realtime mirror handshake works (live-captured ServerHello injected,
      no BAD_DECRYPT, data flows)
```

**[推断] 两个博客没写、但工程上会咬人的边界**（都是从代码逻辑推出来的）：

1. **HRR 会被误当成 SH**。HelloRetryRequest 也是一个 handshake type = 2 的 "ServerHello"（靠 random 的特殊常量区分）。如果镜像站回了 HRR（比如它对这个 key_share 组不满意），这段代码会把 HRR 当成 SH 注入 → 握手必挂。缓解办法正是博客 §4.3 的做法（用客户端首个组去连），但"目标站一定接受这个组"不是免费的保证。
2. **只校验了 cipher suite，没提校验扩展集**。镜像 SH 里可能带客户端没提供的扩展（或者长度/顺序与客户端预期不符）。博客明确说了检查 cipher suite 在不在 `client_hello.cipher_suites` 里，但没提其它扩展——真要上生产，这一层校验得自己补。
3. **每个握手多一次完整 TLS 往返 + 一次真站连接**：CPU、出站流量、时延、以及"你的服务器替每个探测者去连一次真站"的滥用面（博客 §7 只讨论了时延与目标选择，没讨论限速/滥用；对比之下 Xray 有 `limitFallbackUpload/Download`）。

### 1.3 §4.3 的"组必须匹配"：为什么、以及 1184 这个数

博客说：镜像必须用**客户端第一个提供、双方都支持的组**去连；客户端首选 X25519MLKEM768（0x11ec）时，抓回的 SH 约 **1210 字节**（含 MLKEM768 的 1184 字节 key_share）；用 X25519 去连则约 **122 字节**；把 122 字节的注入给一个协商了 MLKEM768 的握手，BoringSSL 会拒绝。处理办法：**连镜像用的组 = 客户端首个组；提取 ECDH 公钥可以另选任一 X25519 值**，两者是两回事。

核实与算术：

- `0x11ec` 正确：[tag] `ssl.h:2576` / [本机BS] `ssl.h:2641` `#define SSL_GROUP_X25519_MLKEM768 0x11ec`。
- **1184 的口径要修正**：1184 是 `MLKEM768_PUBLIC_KEY_BYTES`（[本机BS] `include/openssl/mlkem.h:51`），也就是**客户端 key_share 里那段 ML-KEM 公钥**；服务端 SH 里放的是**密文**，`MLKEM768_CIPHERTEXT_BYTES 1088`（`:81`）。所以 SH 里 key_share 长度 = 1088 + 32(X25519) = **1120**，加上 ServerHello 的固定开销（version 2 + random 32 + session_id 回显 1+32 + cipher 2 + compression 1 + extensions 长度 2 + key_share 头 8 ≈ 82），再算上 handshake 头 4 与记录头 5 → **约 1213 字节**，与博客"约 1210"吻合 ✓。
- X25519 的情况：key_share 32+8=40 → 服务端 SH 约 121-122 字节，与 PoC 的 122 吻合 ✓。
- 结论：**"约 1210 / 约 122"这两个数是自洽的；括号里的"1184 字节 key_share"说的是客户端侧公钥尺寸，不是 SH 里那段的长度**（差 64 字节，量级上不影响结论，但抄代码的人别拿 1184 去算 SH）。[核实 + 推断]

**[推断] "组必须匹配"的深层原因**（我把它讲透，因为这决定了服务端要支持哪些组）：SH 是**明文**，且 key_share 扩展的长度、group id 都在里面；服务端要在保持"其余字节与镜像逐字相同"的前提下，把 key_share 换成自己的——那就必须**自己的公私钥对也在这个组里**，即服务端 BoringSSL 必须支持客户端首选的那个组（这里是 X25519MLKEM768）。同时，"用于连镜像的组"和"用于 ECDH 认证的公钥提取"确实可以解耦：前者只决定"抓回来的 SH 长什么样"，后者（REALITY 的 AuthKey）本来就走 X25519，和密码套件的组是两码事。博客这一节的结论 **[核实]成立**。

### 1.4 三层信任：博客哪儿说对了，哪儿需要修正

博客的三层表：

| 层 | 用途 | 状态 |
|---|---|---|
| session-id：X25519 + HKDF + AES-GCM | 真正的对端认证 | 新增（信任根） |
| Ed25519 CertificateVerify 签名 | transcript 完整性 | 保留并验证 |
| sigalg 通告检查 | 协商形式 | 放宽 |

核实结果：**"放宽 sigalg 通告检查"这一层完全成立，而且我找到了比博客更精确的机制；但博客顺手对比 Go 版的那句话是错的，另外"对端认证"少了一个方向。**

#### （1）BoringSSL 客户端的 sigalg 准入：硬检查，且"通告的 = 接受的"

[tag 0.20260413.0] `ssl/extensions.cc:351-362`（`tls12_check_peer_sigalg`）：

```c
  // The peer must have selected an algorithm that is consistent with its public
  // key, the TLS version, and what we advertised.
  Span<const uint16_t> sigalgs = tls12_get_verify_sigalgs(hs);
  if (std::find(sigalgs.begin(), sigalgs.end(), sigalg) == sigalgs.end() ||
      !ssl_pkey_supports_algorithm(hs->ssl, pkey, sigalg, /*is_verify=*/true)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_SIGNATURE_TYPE);
    *out_alert = SSL_AD_ILLEGAL_PARAMETER;
```

而**客户端 CH 里通告的 signature_algorithms，用的就是同一个列表**：`ext_sigalgs_add_clienthello()`（[tag] `ssl/extensions.cc:1014-1040`，关键行 `:1021` `tls12_add_verify_sigalgs(hs, &sigalgs_cbb)`）→ `tls12_get_verify_sigalgs()`（`:334-339`）→ `hs->config->verify_sigalgs`，为空则用默认 `kVerifySignatureAlgorithms`（`:290-306`，**不含 Ed25519**——Ed25519 只在"签名用"的 `kSignSignatureAlgorithms`，`:312`）。

所以对 stock BoringSSL 客户端：**既不通告、也不接受 Ed25519 的 CertificateVerify**。Chromium 还额外收窄了一层：`SSL_set_verify_algorithm_prefs(kVerifyPrefs)`（[本机BS] `naiveproxy/src/net/socket/ssl_client_socket_impl.cc:800-812`）= {ML-DSA-44/65/87, ECDSA-P256, RSA-PSS-256, RSA-PKCS1-256, ECDSA-P384, RSA-PSS-384, RSA-PKCS1-384, RSA-PSS-512, RSA-PKCS1-512}，**同样没有 Ed25519**。

→ 博客的整个"要不要放宽"的讨论前提 **[核实]成立**，而且这就是**为什么必须动客户端**：服务端用 Ed25519 临时证书，Chromium 侧必然 `illegal_parameter` 挂掉。博客给的替代方案（用客户端通告过的 ECDSA-P256 / RSA-PSS 签 CV）**[核实]在"消除 RFC 违反"这个意义上正确**。

> 补一句口径：博客并没有说"stock BoringSSL 会接受未通告的 Ed25519"——它说的正是"客户端要放宽准入"。子代理报告里"博客说法在 stock BoringSSL 不成立"的表述，我复核后认为是对博客原意的误读（博客描述的是它自己那套"客户端 + 放宽"的组合）；证据本身没问题，结论按本节写。

#### （2）RFC §4.4.3 原文与"违反的是哪半句"

RFC 8446 §4.4.3（`/tmp/rfc8446.txt`）原文：

> If the CertificateVerify message is sent by a server, the signature algorithm **MUST be one offered in the client's "signature_algorithms" extension** unless no valid certificate chain can be produced without unsupported algorithms (see Section 4.2.3).

博客说"违反的是 MUST be one offered（准入）这半句，不是 MUST verify（验证）那半句"——**[核实]成立**：BoringSSL 客户端仍然会做 `ssl_public_key_verify`（[本机BS] `ssl/tls13_both.cc:365-397`：先 `tls12_check_peer_sigalg` 准入、再 `ssl_public_key_verify` 验签；在 tag 上分别是 `:339` 函数头 / `:358` 准入 / `:373` 验签），所以"跳过验签"和"放宽准入"是两件事，博客的区分是对的。

#### （3）需要修正：博客对 Go/XTLS 客户端的描述不准确

博客原话："对比 XTLS/REALITY 常见的 `InsecureSkipVerify`（客户端整个跳过 CertificateVerify 验证）：那短路的是'对端身份必须被验证'这个核心不变量"。

核实（[Go] 1.26.5 源码，uTLS 是它的 fork，代码结构相同）：

- `InsecureSkipVerify` 只 gate **证书链校验**：`handshake_client.go:1147` `} else if !c.config.InsecureSkipVerify {` → 里面是 `x509.VerifyOptions` + `Verify()`。
- **CertificateVerify 的签名验证是无条件的**：`handshake_client_tls13.go:669` `verifyHandshakeSignature(...)`，前面 `:656-660` 是准入检查。uTLS 同构：[uTLS] `handshake_client_tls13.go:792-807`。
- 所以准确的对比是：Go 版跳的是**证书链/身份**（`InsecureSkipVerify`），**不是** CandidateVerify 验签；而"身份"这一环由另一套机制补上——**HMAC 覆写证书签名**：服务端 `hmac.New(sha512, AuthKey)` + `h.Write(ed25519Priv[32:])` + `h.Sum(cert[:len(cert)-64])`（[Go] `reality-src/handshake_server_tls13.go:150-152`），客户端比对 `HMAC(AuthKey, leaf_pubkey) == certs[0].Signature`（[Go] `/tmp/xray_reality.go:110-112`）。

#### （4）"真正的对端认证"缺了一个方向

session-id 的 AEAD 是**客户端→服务端**的认证（服务端解密 CH 里的密文，校验版本/时间窗/shortId：`reality-src/tls.go:244-271`）。**客户端怎么确认对面是真服务端？** Go 版的答案是上面那条 HMAC 覆写证书签名（只有握有 REALITY 私钥、能算出同一个 AuthKey 的服务端才能给出匹配的 `cert.Signature`）。博客的三层表把"session-id"标成"真正的对端认证"，但**全文没有提到 HMAC 覆写证书这一步**；如果客户端 patch 只是"放宽 sigalg 准入 + 跳过链校验"，那客户端其实**没有在认证服务端**（任何自签 Ed25519 证书都能过）。博客明确说过 PoC 不含认证实现、客户端细节也没公开，所以这不算错误，但**读的人不能以为"信任根"已经完整交待了**。这一条我标 **[推断]/[未验证]**，因为客户端那"十余处"到底做了什么，我们看不到。

#### （5）顺带一个"换算法不免费"的耦合（博客的取舍表没提）

博客的取舍表说"只签客户端已通告的算法 → 合规、改动更小"。从**服务端 carve-out** 的角度这是对的；但从**整套机制**看：客户端认证服务端靠的是 `HMAC-SHA512(AuthKey, pubkey)` 恰好 64 字节、正好覆写 Ed25519 定长签名域（[Go] 上述代码 + 客户端显式 `certs[0].PublicKey.(ed25519.PublicKey)` 类型断言）。换成 ECDSA-P256 的 DER 变长签名，这套"覆写"技巧要重新设计。**[推断]**：博客的"更小"只算进了服务端准入那一处，没算进客户端认证机制这一处。

### 1.5 认证失败时的透明回落（这篇博客最可搬运的一段）

博客的论证链：

1. **错误做法**：在证书回调里认证失败就返回错误 → BoringSSL 发 alert → 探测者看到"握手失败"这个可识别异常。[核实]代码为证：[本机BS] `ssl/handshake_server.cc:530-534`（`ssl_select_cert_error` → `ssl_send_alert(… SSL_AD_HANDSHAKE_FAILURE)`）。
2. **正确做法**：把判定提前到 **L4**：监听层过滤器用 `MSG_PEEK` 窥探 ClientHello（**不消费**），用一个"只用于解析"的 BoringSSL 实例复用**同一套认证逻辑**判定，把结果写进连接元数据，再由 filter chain 把连接分流——认证过的走 REALITY TLS，其余走透明 TCP 代理到真实目标；因为 CH 是 peek 不是 drain，两条路都还能读到完整原始字节。
3. **关键性质**：REALITY 的认证逻辑是**无状态纯函数**（输入=解析好的 CH + 配置密钥，输出=布尔），所以能在 BoringSSL 内部的证书回调里跑，也能在 L4 用一个只解析的实例跑，**两处共用一份实现**。

我的评估：

- **[核实] 这个设计在工程上是干净的**，而且它回答的正是"REALITY 在 BoringSSL 里怎么处理未授权流量"——**不要在 TLS 层拒绝，要在 TLS 之前分流**。
- **[推断] 它对 naive 生态有直接价值**：naivereal 的 Go 前置、以及 XTLS 报告 §2.1 的 1C 方案（Go 前置 + h2 CONNECT 桥接），都可以照抄"peek + 只解析认证 + 分流"这个结构。Go 里对应 `syscall.Recvfrom(fd, buf, MSG_PEEK)` 或带缓冲的连接包装；难点是 `xtls/reality` 目前**只暴露 `reality.Server()`**，没有"只解析 CH 做认证判定"的导出函数（[Go] `reality-src`），要自己抽一份或重写。
- **[推断] 与 XTLS 报告 §3.4-6 的关系**：报告当时把"njs 在 `js_preread` 里跑 REALITY 认证"列为开放问题。博客**没有**回答"nginx/caddy 能不能做"（它们依然不能），但它给出了**替代层**的答案：别指望 nginx 的 njs，在你的服务端进程自己的 L4 层做。这把那个开放问题从"要不要写 njs"改成了"前置进程该长什么样"。

### 1.6 规模声称：哪些有证据、哪些只是声称

| 声称 | 状态 | 说明 |
|---|---|---|
| 服务端 **+210/−45 行、3 个文件** | **[博客称]** | 文中无 patch、无仓库链接（正文唯一外链 `t.me/wangran10`），无法数 |
| 客户端 **十余处、全部门控、关掉与上游逐字节一致** | **[博客称]** | 同上；"逐字节一致"需要 diff 或测试才能证明 |
| **握手主状态机没有改动** | **[核实]（机制层面）** | 挂起/恢复用的是库自带状态（§1.1 接缝二）；SH 产出路径被 patch 碰过（[推断]，见接缝三） |
| PoC 1（75 行）**自包含、可直接编译** | **[核实]（代码层面）** | 只用公开 API（`SSL_CTX_set_select_certificate_cb` / `ssl_select_cert_retry` / `SSL_early_callback_ctx_extension_get`），确实只有一个 `int main`（全文唯一一个） |
| **"两个 PoC 都自包含"** | ⚠️ **不成立（对 PoC 2）** | PoC 2 只给了 `mirror_msg_cb` 一个片段；注入端依赖自加的 `reality_serverhello_cb`，**上游 BoringSSL 没有这个符号**，拿不到 patch 就编不过 |
| 输出里的 `err=12`、0 字节、122 字节 SH、`cipher=0x1301`、29 字节数据、ASan/UBSan 干净 | **[博客称]** | 与机制自洽（我核过 12 的定义、0 字节的实现路径、122 的算术），但**跑不到**（见 §1.7） |
| 版本 pin：BCR tag `0.20260413.0`（sha256 `3560f7dd…`）/ Chromium 侧 boringssl `65818adf…` | ✅ tag 与 commit **都存在** | [tag] `0.20260413.0` = `78f7fbee…`（2026-04-13，"Bump version for Bazel Central Registry release."）；`65818adf16411ca394625f5747a1af28faf95d2c` 在 BoringSSL 上游存在且是 commit（2026-05-04）。**未核实**：那串 sha256 对的是什么产物（仓库里查不到），以及 `65818adf` 是否就是当时 Chromium `DEPS` pin 的那个（那要去 Chromium 的 DEPS 里看） |

### 1.7 PoC 复现评估：本机不编译，静态分析为主

**结论：不编译。** 明确写清原因（任务书也允许）：

- 本机内存 **2479MB 总 / 约 460MB 可用**、2 vCPU。BoringSSL 是 cmake + ninja 的中大型 C/C++ 工程（[HEAD] 浅克隆源码树就有 ~257MB 工作区、大量汇编与测试目标），全量构建的内存峰值通常在 GB 级、耗时以十分钟到小时计——**在这个内存水位上硬上几乎必然 OOM，甚至可能拖垮正在跑的服务**。任务书明确"优先静态分析；若编译不可行明确标注"，所以我只做源码级核实。
- **即使编译，PoC 2 也编不出来**：它依赖博客自加的 `reality_serverhello_cb`/`reality_replace_key_share`，而上游 BoringSSL 没有这些符号（[tag]/[HEAD] 0 命中）。
- **PoC 1 理论上可编**（只用公开 API），但按上面的内存约束，我没有尝试；它验证的是"挂起-恢复闭环"，而这部分的机制我已经在源码层面核到位（§1.1 接缝二，含上游测试的用法）。
- **[核实] 顺带发现 PoC 1 的"客户端"并不模拟真实客户端**：PoC 只调了 `SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, nullptr)`。BoringSSL 的默认 `SSL_VERIFY_NONE` 会让链校验错误**非致命**（[tag] `ssl/ssl_x509.cc:260-264`：“If `SSL_VERIFY_NONE`, the error is non-fatal, but we keep the result”），而真实 Chrome 是 `SSL_CTX_set_custom_verify(ssl_ctx, SSL_VERIFY_PEER, …)`（[本机BS] `naiveproxy/src/net/socket/ssl_client_socket_impl.cc:201`）。所以 PoC 1 里那个自签证书能过，**恰恰是因为它没开校验**——这一点在博客里没说明，而它正是"服务端机制"与"客户端改造"之间那道鸿沟。

---

## 2. 三方对照

### 2.1 vs 用户项目 naivereal（`lipeiying032/naive-reality`）

naivereal 的补丁规模（我用 `git apply --numstat` 重新数过，[naivereal] `patches/`）：

| patch | 增/删 | 文件数 | 作用域 |
|---|---|---|---|
| `001-boringssl-reality.patch` | **+338/−3** | 11 | BoringSSL：新增 `ssl/reality.cc`(236 行)/`reality.h`(34)，改 `ssl.h`/`internal.h`/`handshake_client.cc`/`extensions.cc` + 构建文件 |
| `002-net-reality-plumbing.patch` | **+315/−1** | 8 | Chromium net：`net/socket/reality_config.{h,cc}` 新增、`ssl_client_socket_impl.cc` 接线、`naive_config.cc` 配置 |
| `003-spider-mode` / `004-build-registration` / `005-native-h3-config` / `006-tcp-reality-scope` / `007-native-h3-context` | +42/−1、+2、+14、+17、+9/−3 | 2/1/1/1/1 | 模式与构建注册 |
| **合计** | **+737/−8** | 22 个唯一文件 | 客户端两层；服务端不在补丁里（是 Go frontend） |

（对比：我之前 XTLS 报告里写的"001 新增 349 行 / 002 323 行"是另一种数法（把 `+++` 头等算进去了），以本表的 `git apply --numstat` 为准。）

**逐维度对照：**

| 维度 | 博客方案（BoringSSL 服务端） | naivereal（客户端 patch + Go 服务端） | 证据 |
|---|---|---|---|
| 认证字段载体 | ClientHello 的 **legacy session_id**（PoC 注释明说"加密的认证信息藏在这里"） | **同样是 session_id**：offset 39、32 字节、把 CH 的 session_id 段清零后整条 CH 当 AAD | [博客] §4.1 注释；[naivereal] `001:329-347`；[Go] `reality-src/tls.go:244-259` |
| 是否镜像真实 ServerHello | **是**（服务端每连接实时连真站抓 SH，只换 key_share 密文） | **否**（客户端补丁里 0 命中；服务端用 `xtls/reality`，SH 由 Go 自己生成） | [naivereal] grep：`reality_serverhello_cb`/`reality_replace_key_share`/`SSL_set_msg_callback` 全 0 |
| 是否用"证书选择挂起"三接缝 | 是（接缝一+二+三） | **一个都没用**：`SSL_CTX_set_select_certificate_cb`、`ssl_select_cert_retry`、`SSL_ERROR_PENDING_CERTIFICATE` 在 7 个 patch 里全 0 命中 | [naivereal] grep |
| 证书校验接管方式 | 博客没说客户端细节 | **新增一个普通导出函数** `SSL_reality_verify_certificate(ssl, leaf_der, …)`（`001:138`、`001:389`），由 Chromium 既有的 `VerifyCert()` 显式调用、自行跳过链校验（`002:181-197`）；`SSL_CTX_set_custom_verify` 0 命中 | [naivereal] `001:132-140`、`389` |
| **sigalg 准入** | 博客说需要 carve-out（或服务端换算法） | **补丁里真的有一处 carve-out，改的正是 `tls12_check_peer_sigalg`**：`if ((不在 verify_sigalgs) && !is_reality_ed25519) → 拒绝`，注释写着"Chromium does not normally advertise Ed25519 for certificate verification… Keep the advertised list unchanged" | [naivereal] `001:478-495` |
| 服务端语言 | C++（BoringSSL + patch） | Go（`github.com/xtls/reality`，`frontend/reality.go`） | [naivereal] `frontend/reality.go`；[Go] 同 commit 克隆 `reality-src` |
| 未认证流量处理 | L4 `MSG_PEEK` 预判 + filter chain 分流到真站 | 不做显式分流（frontend 只计数）；由 `xtls/reality` 库"读一字节写一字节镜像 + 认证失败 `io.Copy` 直转"处理 | [naivereal] `frontend/main.go:140-146`（`reality.Server()` 返回错误后只 `stats.IncRelays()`，注释写明 "The fork relays unauthenticated traffic to the target…"）；[Go] `reality-src/tls.go:71-83`（`MirrorConn.Read` 读一字节写一字节）/`:286`、`:448-453`（认证失败 `io.Copy` 直转）；**naivereal 全仓库 `MSG_PEEK` 0 命中** |
| 开关与可回退性 | 博客称"全部门控、关掉与上游逐字节一致" | 开关齐全（config.json `"reality"` 或 `--reality-*`，默认关；native-h3 profile 直接拒绝这些键），**但仓库里没有"关掉后与上游逐字节一致"的证据**（只有静态门控；`status.md` 自认"补丁应用检查 ≠ 编译通过"） | [naivereal] `002:136/155/186/206`、`005:8-19`、`scripts/apply-kernel-patches.py:55-65` |

**异同小结（我的判断）：**

- **思路相同的地方**：认证信息都藏在 CH 的 session_id 里、都是用"客户端被改造"换取服务端的无钥握手、都保留 Ed25519 证书形态。
- **真正的分歧是"服务端 SH 从哪来"**：naivereal（走 `xtls/reality` 库）是**自己生成 SH**；博客是**实时镜像真站的 SH**。这才是这篇博客相对 naivereal 的唯一**机制级增量**。
- **博客的"三个接缝"对 naivereal 一点用都没有**（naivereal 是纯客户端 + Go 服务端）；反过来，naivereal 的补丁**替博客证明了"客户端那十来个门控"具体长什么样**——尤其是那处 `tls12_check_peer_sigalg` carve-out，与博客的 §3 分析严丝合缝。**这两份材料互为对方的缺失拼图**，这是本次对照最值钱的发现。

### 2.2 vs 我此前的《XTLS 报告》（`/root/dsh-xtls-reality-report.md`）

#### （a）服务端两条路线：博客的"C++ BoringSSL 前置" vs 报告的"1C：Go 前置 + `xtls/reality` 桥接"

| | 报告 §2.1 的 1C | 这篇博客 |
|---|---|---|
| 前置进程语言/库 | Go + `github.com/xtls/reality` | C++ + 打过 patch 的 BoringSSL |
| 认证实现 | 现成的（库里有） | **没有**（博客明说 PoC 不含认证，要自己写 X25519/HKDF/AES-GCM + 时间窗/shortId） |
| SH 形态 | 自己生成（Go crypto/tls 的 SH） | **实时镜像真站**（明文部分与真站逐字节同形，除 key_share 密文） |
| 未认证流量 | 库内 `io.Copy` TCP 直转到 target（[Go] `tls.go:286/448-453`） | L4 `MSG_PEEK` 预判后分流（**在 TLS 之前**就分好） |
| 与 naive 后端对接 | 报告里就是"认证后桥接到 h2c/H3 的 naive 后端" | 博客没提 naive；博客 §5 只说"复用框架原生异步握手通道" |
| 生态匹配度 | 与 Caddy/naive 同为 Go，桥接代码少 | 需要新引入一个 C++ 服务（或把 BoringSSL 编进 Caddy？Caddy 的 TLS 是 Go，做不到） |

**结论**：博客**不是 1C 的替代品，而是第三条服务端路线**（C++）。它比 1C 多一个"镜像 SH"的抗指纹收益，但少一个"认证已经写好"的现实优势。对 naive 项目来说，**1C 依然是最短路径**，博客的价值在于"如果你愿意为镜像 SH 付 C++ + 长期 pin BoringSSL 的代价，机制上确实成立"。

#### （b）博客的 L4 透明回落 vs 报告对 nginx/caddy 的评估

- 报告 §2.2.2/§3.4-6 的开放问题是"能不能在 nginx 的 njs/OpenResty Lua 里解析 CH 做同 SNI 分流 + REALITY 认证"。
- **博客没有让 nginx/caddy 变得能做这件事**：它把认证判定放在**服务端进程自己的 L4 过滤层**（`MSG_PEEK` + 只解析的 BoringSSL 实例），这是"自己写前置进程"的思路，不是"配置 nginx"。
- 但**它把问题换了个更好的问法**：与其在 njs 里复刻 X25519/AES-GCM（无先例、性能未知），不如在前置进程里做——**对 1C 的 Go 前置同样适用**（Go 里用带缓冲的 peek，把 `xtls/reality` 的解析逻辑抽成纯函数）。报告的结论（"nginx/caddy 做不了 C1/C2"）**不变**；变的是"L4 分流该在哪一层实现"有了更明确的答案。

#### （c）对"C2/C4 互斥"结论的影响

- **C2（无钥握手）与 C4（原封 Chrome 客户端）依旧互斥，博客没有改变这一点**：博客自己也说了客户端要改（"十余处门控"），而且客户端必须
  ① 在 CH 里塞 session_id 认证、② 接管证书校验；BoringSSL 侧的准入还要求 ③ 放宽 `tls12_check_peer_sigalg`（naivereal 的补丁就是活证）。
- **它改变的是"改造量的估计"**：博客的说法（十余处、门控、关掉即上游行为）与 naivereal 的实测规模（BoringSSL +338/−3、net +315/−1）**方向一致**——都比"大改 Chromium 网络栈"小得多。这与报告里 RPRX 的判断（"客户端应该非常简单"）以及 naivereal 先例（约 700 行）相互印证。
- 换句话说：**报告 §2.5.1 的"拆成两半"依然成立**——"服务端同时服务标准 Chrome 和 REALITY 客户端"仍然不可能；"把客户端都换成改过的 naive"仍然可行，而且**改造量的上界现在有了第三方实测数据**。

### 2.3 vs Go 版 REALITY（`xtls/reality` + uTLS）

| 维度 | Go 版（现状） | 博客的 BoringSSL 版 |
|---|---|---|
| 服务端库 | Go `crypto/tls` fork（`github.com/xtls/reality`） | BoringSSL + 自加 patch |
| 临时证书 | Ed25519 自签（进程级一次生成，`:84-86`），现在还能选 ML-DSA-65（`:144-158`） | Ed25519（博客沿用同一形态） |
| **客户端如何确认服务端身份** | **HMAC 覆写证书签名**：服务端 `h.Sum(cert[:len(cert)-64])`（`:150-152`），客户端比对（Xray `reality.go:110-112`） | **博客没写这一段**（三层表只列了 session-id，标 [未验证]） |
| ServerHello | 服务端自己生成（random 自己出，cipher/扩展按 BoringSSL/Go 的偏好） | **实时镜像真站的 SH**（random、cipher、扩展都是真站此刻的），只换 key_share 密文 |
| 认证失败回落 | 先 `DialContext(dest)`（`tls.go:169`），失败就把两边 `io.Copy` 对接（`tls.go:286`、`:448-453`） | L4 `MSG_PEEK` 预判 → 认证失败的分流到真站（TLS 之前就分开） |
| 认证决策点 | TLS 握手内（解密 session_id 后） | L4（TLS 之前）+ 共用同一份无状态认证函数 |
| 客户端 | uTLS（Go fork），CH 由 parrot 生成 | Chromium/BoringSSL（真 Chrome 形状） |
| **RFC §4.4.3 准入** | 现状：**uTLS 的 CH 用 Chrome parrot（不含 Ed25519，[uTLS] `u_parrots.go` 0 命中），但验证用的是 Go 的默认列表（含 Ed25519，[Go] `defaults.go:41-55`）→ 实际接受未通告的 Ed25519，字面违反准入半句**，靠的是"uTLS 不按通告列表检查"；纯 Go 客户端则通告且接受，不违反 | BoringSSL 客户端：通告列表 = 准入列表（同源），不含 Ed25519 → **硬失败**，必须 carve-out（或服务端换算法） |
| 抗指纹收益 | SH 是自己造的：random 随机、cipher/扩展是"合理选择"，但**与真站当下发的 SH 没有逐字节关系** | SH 明文部分**就是真站此刻的**（被动观察者拿不到可对比的差异） |
| 维护面 | 跟 Go 版本；依赖 uTLS fork | 跟 BoringSSL/Chromium 版本；BoringSSL 官方明说**不保证 API/ABI 稳定**（`README.md:5-8`："We don't recommend that third parties depend upon it… no guarantees of API or ABI stability"），三个接缝的行为都要按 commit 重验 |

**一句话**：Go 版解决"未授权流量看到真站"用的是 **splice**；博客解决同一问题用的是 **L4 预分流 + SH 镜像**。前者认证已经在库里写好了，后者把"授权流量的握手长什么样"也做成了真站的样子——**这是博客相对 Go 版的唯一实质增强，也是它全部的额外成本来源。**

---

## 3. 对"naive + REALITY"路线的意义（核心问题）

### 3.1 客户端：这是不是 naiveproxy 可用的"改造模板"？

**分两半回答：**

- **作为"BoringSSL 里怎么挂 REALITY"的模板**：博客讲的三个接缝**全在服务端**（`SSL_CTX_set_select_certificate_cb`、`ssl_select_cert_retry`、SH 注入），客户端那侧只有一句"十余处、门控"。**对客户端工作，它几乎没有增量信息**——真正能当模板的是 naivereal 的 `patches/001+002`（能数、能看、能编译验证），博客只能当"设计意图说明"。
- **作为"客户端改造量的估计"**：有用。它给出的量级（十余处、门控、关掉即上游行为）与 naivereal 的实测（+737/−8、22 文件）在同一数量级，**支持"客户端改造可控"的判断**。
- **唯一一条能直接指导 naive 客户端 patch 的技术结论**：**Ed25519 临时证书 + Chromium/BoringSSL 客户端 ⇒ 必须放宽 `tls12_check_peer_sigalg`**（或服务端改用客户端通告的算法）。naivereal 选择了前者（carve-out 13 行）；博客提示了后者（更合规），但后者会牵动"客户端认证服务端"的 HMAC 机制（§1.4-5）。**这是一个需要项目自己权衡的取舍，博客把选项摆出来了，但没有给出答案。**

### 3.2 服务端：C++ 路线 vs Go 路线，移植路径存在吗？

naive 生态的服务端是 **Caddy（Go）/ sing-box（Go）**，而博客的服务端是 **C++ / BoringSSL**。可选路径：

| 路径 | 可行性 | 代价 |
|---|---|---|
| A. 直接把博客的 C++ 前置做出来，认证后桥接到 naive 后端（h2 CONNECT） | **[推断] 技术可行**——与 naivereal 的 Go 前置同构，只是换了语言和 TLS 库 | 栈里多一门语言；BoringSSL pin + 重验接缝；naive 的 padding/协议桥接要自己写 |
| B. 在 Go 前置（1C）里复刻博客的思路 | **部分可行**：L4 peek 分流 ✅ 能抄；**SH 实时镜像 ❌ 抄不了**——Go `crypto/tls` 没有"注入 ServerHello"的接口，要么 fork 得更深（XTLS/REALITY 就是 fork，但也没有这个接缝），要么放弃镜像 | 放弃镜像 = 回到"SH 自己造"的现状；或者在 Go fork 里新开一个注入点（等于自己维护一个更深的 fork） |
| C. 在 Caddy 里做 | **不可行**：Caddy 的 TLS 是 Go 标准库/certmagic；caddy-l4 的 matcher 拿不到 session_id，也没有 SH 注入能力（见 XTLS 报告 §2.3） | — |

**结论**：博客**没有让 naive 的服务端更容易**——它把"要做 REALITY 就得有个独立前置进程"这件事又说了一遍，并额外指出"这个前置可以是 C++"，但 naive 生态里没有 C++ 的位置。**Go（1C）仍是最短路径；镜像 SH 是这条路上唯一抄不过去的部分。**

### 3.3 缺口清单（要把"博客路线"变成"naive 能用的方案"还差什么）

1. **认证实现**（博客自己说 PoC 不含）：X25519 ECDH → HKDF-SHA256(salt=CH.random[:20], info="REALITY") → AES-256-GCM(nonce=CH.random[20:], AAD=session_id 清零后的整条 CH) + 版本/时间窗/shortId 校验。Go 版有现成参照（`reality-src/tls.go:244-271`、`/tmp/xray_reality.go:166-200`），但还是得写、得测。
2. **客户端→服务端 与 服务端→客户端 的双向认证**：博客只讲了前者（session-id）；后者（Go 版的 HMAC 覆写证书签名）在博客里**没有出现**。这是 naive-reality 必须补的关键块。
3. **客户端 patch 本体**：博客的"十余处门控"没有一行代码、没有仓库；而 naivereal 的客户端 patch 与博客服务端**不能直接拼**（naivereal 服务端是 Go 的 `xtls/reality`，SH 自造，没有镜像能力）。
4. **服务端生态适配**：naive 的服务端协议是 HTTP/2 CONNECT + padding；C++ 前置要自己实现"REALITY 终结 → h2 CONNECT 到 Caddy"这一段（naivereal 的 Go 前置已经趟过一遍，但那是 Go）。
5. **镜像目标的工程约束**：[推断] 同组（必须支持客户端首选组）、网络距离（时延对比）、可用性（目标站挂了/限流/改行为）、**滥用与放大**（每个探测都替你连一次真站）、隐私（你的服务器替陌生人访问第三方）。博客 §7 只覆盖了时延与目标选择。
6. **维护成本**：BoringSSL 没有 API/ABI 稳定承诺（官方 README 原文），三个接缝的行为按 commit 变；naiveproxy 本身已经在追 Chromium 版本，再加一条"服务端 BoringSSL pin + 每个版本重验接缝"的升级链，是**两条维护线**。
7. **细节缺口**（[推断]，见 §1.2）：HRR 误判、镜像扩展集校验、DoSed 放大与限速。

### 3.4 结论：这篇博客让"naive + REALITY"落地更近了吗？

**分层回答：**

- **机制层：更近了。** 它把"REALITY 服务端能不能不做在 Go 里"这个问题回答了：能，而且改动集中在回调 + 一个注入点 + 门控分支；它还把"认证失败怎么不透出 alert"这个真问题挑明了，并给出 L4 peek + 共用无状态认证函数的干净解法。**这两条对任何前置进程都成立，包括 Go 的 1C。**
- **工程层：没更近。** 没有代码、没有认证、没有客户端 patch、没有 naive 协议适配；服务端语言还与 naive 生态错位。**唯一实质增量（SH 实时镜像）恰好是最难搬进 Go 生态的部分。**
- **对用户的项目（naive-reality / naivereal）**：最值得吸收的排序是
  1. **L4 `MSG_PEEK` + 只解析认证 + 分流**（可以直接进 Go 前置的设计）；
  2. **`tls12_check_peer_sigalg` 的取舍分析**（决定客户端 patch 要不要保留那 13 行 carve-out，以及是否值得把服务端改成 ECDSA/RSA-PSS 来换合规——注意 HMAC 机制的耦合）；
  3. **镜像 SH**：把它当"未来增强"，不是当下路径——除非愿意接受 C++ 前置 + BoringSSL pin 这两项长期成本。
- **一句话**：这篇博客的价值不在"给出了一个能抄的实现"，而在**把 BoringSSL 侧的可行性证据补齐了、把"透明回落"这个设计问题回答清楚了**；它没有回答的是"naive 生态该怎么接"——而那个答案，短期看仍然是 Go 前置（1C），长期看取决于你愿不愿意为"授权握手的 SH 也长得像真站"付出换语言的代价。

---

## 4. 证据、核实清单与未验证清单

### 4.1 我实际核实的（关键结论 → 证据）

| 结论 | 证据 |
|---|---|
| 博客发表/更新时间 | 缓存 HTML `<time class=post-meta-date-created datetime=2026-07-06T16:00:00.000Z title="发表于 2026-07-07 00:00:00">`、`…date-updated datetime=2026-07-07T04:22:27.724Z` |
| 原文在线抓取被 Cloudflare 拦 | `curl https://blog.sam1314.com/posts/c65526af.html` → 5421 字节 "Just a moment..." 页（`/tmp/blog_online.html`） |
| 正文无代码仓库链接 | 文章内 `<a href>` 只有 `https://t.me/wangran10` |
| PoC 1 是完整程序、PoC 2 不是 | 全文 `int main` 只出现 1 次（[博客] 提取文本行 177） |
| `SSL_ERROR_PENDING_CERTIFICATE` = 12 | [tag] `ssl.h:437`；[本机BS] `ssl.h:437` |
| 挂起时不发字节 | [tag] `ssl/handshake.cc:616-619`（设 rwstate 后 `return -1`，无 flush）；DTLS 例外见 [HEAD] `handshake.cc:532-537` |
| retry 的处理点 | [tag] `ssl/handshake_server.cc:599-600` |
| 恢复=回调被再次调用（非断点续跑） | [本机BS] `ssl.h:5401-5404` 文档；[HEAD] 上游测试 `ssl_test.cc:12176-12199` |
| `SSL_CLIENT_HELLO` 字段齐全 | [本机BS] `ssl.h:5344-5361`（`client_hello_len`/`session_id(_len)`/`random(_len)`/`cipher_suites(_len)`/`extensions(_len)`） |
| 回调里返回 error 会发 alert | [本机BS] `ssl/handshake_server.cc:530-534` |
| `reality_serverhello_cb` / `reality_replace_key_share` 不是上游 API | [HEAD]/[tag]/[本机BS] 全仓库 0 命中；`grep -i reality` 仅 6 处英文散文 |
| `SSL_set_msg_callback` 是真 API、能抓到完整握手消息 | [本机BS] `ssl.h:5136-5171`（"For each handshake message… the `len` bytes from `buf` contain the handshake message"） |
| 上游没有 `SSL_msg_callback` 这个 typedef 名 | [HEAD] 全仓库 0 命中；参数是内联函数指针（ctx 版形参名 `is_write`） |
| `0x11ec` = X25519MLKEM768 | [tag] `ssl.h:2576`；[本机BS] `ssl.h:2641` |
| 1184 是公钥长度、1088 才是密文 | [本机BS] `mlkem.h:51` / `mlkem.h:81`（SH 里 key_share ≈1120+开销 ≈1213 字节，与博客"约 1210"吻合） |
| BoringSSL 客户端 sigalg 准入是硬检查，且**通告列表与准入列表同源** | [tag] `ssl/extensions.cc:351-362`（`tls12_check_peer_sigalg`）、`:1014-1040`（`ext_sigalgs_add_clienthello` → `tls12_add_verify_sigalgs`，关键行 `:1021`）、`:290-306`（`kVerifySignatureAlgorithms`，无 Ed25519）、`:312`（`kSignSignatureAlgorithms` 里有 Ed25519） |
| Chromium 把 verify 偏好收窄为 `kVerifyPrefs`（无 Ed25519） | [本机BS] `naiveproxy/src/net/socket/ssl_client_socket_impl.cc:800-812` |
| Chrome 用 custom_verify + SSL_VERIFY_PEER | [本机BS] 同文件 `:201` |
| BoringSSL 默认 `SSL_VERIFY_NONE` 下链校验错误非致命 | [tag] `ssl/ssl_x509.cc:260-264` |
| RFC 8446 §4.4.3 原文（准入 half） | `/tmp/rfc8446.txt`（"If the CertificateVerify message is sent by a server, the signature algorithm MUST be one offered in the client's "signature_algorithms" extension…"） |
| Go 的 `InsecureSkipVerify` 只跳链校验、不跳 CV 验签 | [Go] `handshake_client.go:1147`（gate 链校验）、`handshake_client_tls13.go:656-660`（准入）、`:669`（`verifyHandshakeSignature` 无条件） |
| Go 默认 sigalg 列表含 Ed25519；Go 客户端通告并用同一列表检查 | [Go] `defaults.go:41-55`、`handshake_client.go:122`、`handshake_client_tls13.go:656` |
| uTLS 的 Chrome parrot **不通告** Ed25519，但验证用 Go 的列表 | [uTLS] `u_parrots.go`（`ed25519`/`0x0807` 0 命中，样例块只列 ECDSA/RSA）；`handshake_client_tls13.go:792-807` |
| naivereal 的 BoringSSL carve-out 就改在 `tls12_check_peer_sigalg` | [naivereal] `patches/001-boringssl-reality.patch:478-495` |
| naivereal 认证载体 = legacy session_id（offset 39、AAD=清零后的整条 CH） | [naivereal] `001:329-347` |
| naivereal 补丁规模 | `git apply --numstat patches/*.patch` → 001 +338/−3(11 文件)、002 +315/−1(8)、合计 +737/−8、22 唯一文件 |
| naivereal 没用博客的任何接缝、也没有 MSG_PEEK | [naivereal] 7 个 patch grep：`SSL_CTX_set_select_certificate_cb` / `ssl_select_cert_retry` / `SSL_ERROR_PENDING_CERTIFICATE` / `SSL_set_msg_callback` / `MSG_PEEK` / `reality_serverhello_cb` / `reality_replace_key_share` 全 0 |
| `xtls/reality` 服务端先拨 target、失败后 `io.Copy` 直转 | [Go] `reality-src/tls.go:169`、`:286`、`:448-453` |
| BoringSSL 官方不保证 API/ABI 稳定 | [本机BS] `boringssl/README.md:5-8` |
| 博客 pin 的两个版本都存在 | tag `0.20260413.0` → `78f7fbee…`（2026-04-13）；commit `65818adf…`（2026-05-04）均在 BoringSSL 上游可取到 |

### 4.2 没能核实的（明确标注）

1. **[未验证] 博客的 210/−45、3 文件、客户端"十余处门控"、'关掉即上游逐字节一致'**：文章不含 patch、无仓库链接（正文唯一外链是 Telegram），公开代码搜索（web 搜索 + grep.app，后者被人机校验挡住）也没有找到 `reality_serverhello_cb` 这个唯一符号。**这些数字目前只能当"作者自述"。**
2. **[未验证] BCR tag 的 sha256 `3560f7dd…`** 对的是什么产物（BoringSSL 仓库里查不到该串；tag 本身存在且有独立 commit）。
3. **[未核实] `65818adf…` 是否就是当时 Chromium `DEPS` pin 的 BoringSSL**：能证明它是 BoringSSL 上游的真实 commit（2026-05-04），但"它就是 Chromium 当时用的那个"要在 Chromium 的 DEPS 里看，本次没查。
4. **[未验证] 客户端认证服务端那一步（HMAC 覆写证书签名）在博客方案里是否存在**：博客全文未出现该机制；由于客户端代码未公开，只能标记为"缺说明"，不能断言它没有。
5. **[未验证] PoC 的运行输出**（err=12、0 字节、122 字节 SH、ASan/UBSan 干净）：与机制自洽，但本机未编译（内存不足，§1.7），未复现。
6. **[推断] 几处工程边界**（HRR 误判、镜像扩展集校验、服务端必须支持客户端首选组、滥用/放大与限速）：由代码逻辑推出，博客没有正面讨论，也没有实测。
7. **[未验证] 行号的版本漂移**：我引的 [tag] 行号是在 tag `0.20260413.0` 上现查的；[本机BS] 是 Chromium 树内同一 CPE 版本的修订（`ac39ea68…`），两者个别行号相差几行（例如 `kVerifySignatureAlgorithms` 在 tag 是 `:290`、在 [本机BS] 是 `:286`）。**引用时建议按字符串（函数名/错误串）核对，不要只认行号。**

### 4.3 复现命令（本次实际跑过的）

```bash
# ① 博客原文与元数据（在线抓取会被 Cloudflare 拦，以本地缓存为准）
curl -sS -A 'Mozilla/5.0' https://blog.sam1314.com/posts/c65526af.html -o /tmp/blog_online.html   # → 5.4KB "Just a moment..."
python3 - <<'EOF'   # 从缓存 HTML 提取正文（去掉代码行号列、保留 <td class=code> 的代码块）
import re,html,glob
p=glob.glob('/root/.hermes/cache/documents/doc_12eac901fafe_*.html')[0]
raw=open(p,encoding='utf-8',errors='replace').read()
art=re.search(r'<article.*?</article>',raw,flags=re.S).group(0)
print(len(art), art.count('<td class=code>'))   # 6 个代码块
print([m.group(1)[:40] for m in re.finditer(r'<time[^>]*>(.*?)</time>',raw,flags=re.S)][:2])  # 发表/更新时间
EOF

# ② BoringSSL 关键事实（在 naiveproxy 树内的 BoringSSL 上核，再用 tag 复核）
cd /root/upstream-naiveproxy/src/third_party/boringssl/src
grep -n "SSL_ERROR_PENDING_CERTIFICATE" include/openssl/ssl.h            # 437
grep -n "ssl_select_cert_retry = \|SSL_GROUP_X25519_MLKEM768" include/openssl/ssl.h
grep -n "MLKEM768_PUBLIC_KEY_BYTES\|MLKEM768_CIPHERTEXT_BYTES" include/openssl/mlkem.h   # 1184 / 1088
sed -n '350,362p' ssl/extensions.cc        # tls12_check_peer_sigalg 的硬准入
sed -n '1014,1040p' ssl/extensions.cc      # CH 的 signature_algorithms 用的是同一个 verify 列表
cd /root/boringssl && T=78f7fbeec98a2fb15acea6f7a9f1def7f2e6d9a0
git show $T:ssl/extensions.cc  | sed -n '351,362p'   # tag 上同样的检查
git show $T:ssl/handshake.cc   | sed -n '616,619p'   # 挂起：设 rwstate + return -1
git show $T:ssl/handshake_server.cc | sed -n '599,600p'  # retry → ssl_hs_certificate_selection_pending

# ③ Go / uTLS 侧（判断博客对 Go 版的描述对不对）
cd /usr/local/go/src/crypto/tls
grep -n -A20 "func defaultSupportedSignatureAlgorithms" defaults.go    # 列表里有 Ed25519
grep -n "InsecureSkipVerify" handshake_client.go                       # 1147：只 gate 链校验
sed -n '650,672p' handshake_client_tls13.go                            # 656 准入 / 669 无条件验签
curl -s https://raw.githubusercontent.com/refraction-networking/utls/master/u_parrots.go | grep -ci ed25519   # → 0

# ④ naivereal 补丁事实
cd /root/naivereal-prior-art
for p in patches/00*.patch; do printf '%s ' "$p"; git apply --numstat "$p" | awk '{a+=$1;d+=$2;f++} END{printf "+%d/-%d files=%d\n",a,d,f}'; done
sed -n '478,495p' patches/001-boringssl-reality.patch      # tls12_check_peer_sigalg 的 carve-out
sed -n '320,350p' patches/001-boringssl-reality.patch      # session_id(offset 39) 封装
for s in SSL_CTX_set_select_certificate_cb ssl_select_cert_retry SSL_ERROR_PENDING_CERTIFICATE SSL_set_msg_callback MSG_PEEK reality_serverhello_cb; do printf '%s: ' $s; grep -rc "$s" patches/*.patch | awk -F: '{s+=$2} END{print s+0}'; done
```

### 4.4 环境与产物

- 博客缓存：`/root/.hermes/cache/documents/doc_12eac901fafe_*.html`（728KB）；提取文本 `/root/boring-blog.txt`
- BoringSSL：`/root/boringssl`（浅克隆，HEAD `dd73e69a…`；另 fetch 了 tag 对象 `0.20260413.0`、`ac39ea68…`、`65818adf…`）
- Chromium 树内 BoringSSL：[本机BS]（`naiveproxy/src/third_party/boringssl/src`）
- Go：`/usr/local/go`（1.26.5）；XTLS/REALITY：`/root/reality-src`
- naivereal：`/root/naivereal-prior-art`（只读，`git status` 干净）
- 子代理证据文件：`/root/boring-verify-boringssl.md`、`/root/boring-verify-naivereal.md`
- **本机没有编译任何代码**（内存 460MB 可用，理由见 §1.7）；没有对任何仓库做写操作
