# naivereality

**Lightweight REALITY for the naive ecosystem** — a from-scratch port of the mechanism described in
《在 BoringSSL 的接缝中实现 REALITY》 ([blog.sam1314.com/posts/c65526af.html](https://blog.sam1314.com/posts/c65526af.html), 2026-07-07):

* the **server** lives in BoringSSL behind three seams — the certificate-selection callback (authentication),
  `ssl_select_cert_retry` (suspend/resume) and a mirrored-ServerHello hook — plus a small C++ front end that
  peeks the ClientHello at L4 (`MSG_PEEK`) and transparently forwards anything that fails authentication;
* the **client** is a patch for [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy) (Chromium's BoringSSL +
  `net/`): the REALITY blob is sealed into the ClientHello's `legacy_session_id`, the temporary Ed25519 certificate
  is authenticated with `HMAC-SHA512(AuthKey, pubkey)`, and a narrow sigalg carve-out lets the handshake complete.

This repository is the deliverable of that port; see [`docs/report.md`](docs/report.md) for the full write-up
(including the list of things that are **not** verified) and [`docs/plan.md`](docs/plan.md) for the design plan.

## Status

| Part | State |
|---|---|
| Server BoringSSL patch (`patches/boringssl-reality-server.patch`, +193/−1, 5 files) | **[verified]** builds against BoringSSL tag `0.20260413.0`; PoCs pass |
| Server front end + PoCs (`server/`) | **[verified]** in-process PoCs pass; the TCP smoke test (REALITY handshake + mirror injection + transparent fallback) passes |
| Client patch (`patches/naiveproxy-reality-client.patch`, +380/−1, 12 files) | **[applies]** cleanly to naiveproxy `d6ba2a2e55`; **not built as part of Chromium** |
| Client BoringSSL part (`patches/boringssl-reality-client.patch`) | **[built in CI]** against BoringSSL `ac39ea68…` (the revision vendored in the naiveproxy tree) |
| Full naiveproxy build | **not attempted** — needs a Chromium-scale checkout/toolchain; see [`docs/client-build.md`](docs/client-build.md) |

Everything is gated: without `SSL_CTX_set_reality_serverhello_cb()` / `SSL_set1_reality_config()` the code paths
are the upstream ones. The handshake state machine is not modified.

## Layout

```
patches/
  boringssl-reality-server.patch       # -p1 against BoringSSL tag 0.20260413.0 (server: the three seams)
  naiveproxy-reality-client.patch      # -p1 against naiveproxy d6ba2a2e55 (client: BoringSSL + net/)
  boringssl-reality-client.patch       # -p5 against BoringSSL ac39ea68 (client's BoringSSL part only)
server/
  reality_common.{h,cc}                # REALITY auth (X25519/HKDF/AES-GCM), temp cert + HMAC, test certs
  reality_server.cc                    # front end: L4 MSG_PEEK, REALITY TLS, mirror capture, TCP fallback
  poc_suspend.cc                       # blog PoC 1 equivalent (suspend/resume primitive)
  poc_end_to_end.cc                    # blog PoC 2 equivalent + real authentication (in-process, deterministic)
  poc_mirror_server.cc / poc_client.cc # TCP smoke test peers
  genkey.cc                            # prints an X25519 key pair for the PoCs
  build.sh
tools/apply_client_code.py             # regenerates the client-side BoringSSL changes (used to build the patch)
docs/plan.md, docs/report.md           # implementation plan + report (verification levels, [unverified] list)
docs/blog-analysis.md                  # analysis of the blog + comparison with Go REALITY / naivereal
```

## Build the server (Linux)

```bash
# 1) BoringSSL at the pinned tag + the REALITY server seams
git clone --depth 1 https://boringssl.googlesource.com/boringssl
cd boringssl
git fetch --depth 1 origin 78f7fbeec98a2fb15acea6f7a9f1def7f2e6d9a0
git checkout FETCH_HEAD
git apply ../patches/boringssl-reality-server.patch
cmake -GNinja -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF .
ninja -C build -j"$(nproc)" ssl crypto
cd ..

# 2) front end + PoCs
BSSL_DIR="$PWD/boringssl" bash server/build.sh "$PWD/bin"

# 3) the two blog PoCs (in-process, no network)
./bin/poc_suspend
./bin/poc_end_to_end

# 4) TCP smoke test: REALITY client + unauthenticated probe (transparent fallback)
./bin/genkey > keys.txt
PRIV=$(sed -n 1p keys.txt); PUB=$(sed -n 2p keys.txt); SHORT=0102030405060708
./bin/poc_mirror_server 18443 & sleep 1
./bin/reality_server --listen 127.0.0.1:18444 --target 127.0.0.1:18443 \
    --private-key "$PRIV" --short-id "$SHORT" & sleep 1
./bin/poc_client 18444 "$PUB" "$SHORT" "hello"          # -> handshake ok, echo
printf 'probe\n' | openssl s_client -connect 127.0.0.1:18444 \
    -tls1_3 -quiet -servername probe.test                # -> forwarded to the mirror
```

The front end log should contain `mirrored ServerHello: yes, 122 bytes`.

## Build the client

```bash
git clone https://github.com/klzgrad/naiveproxy
cd naiveproxy && git checkout d6ba2a2e55416294bca1ae87499bfb31d94ccd4d
git apply ../patches/naiveproxy-reality-client.patch
# then build naiveproxy the usual way (Chromium checkout + gn/ninja) — see docs/client-build.md
```

Configuration (naiveproxy `config.json`):

```json
{ "reality": { "public_key": "<64 hex chars>", "short_id": "<up to 16 hex chars>" } }
```

or the flat switches `--reality-public-key` / `--reality-short-id`.

## CI

`.github/workflows/build.yml` (push to `main` + `workflow_dispatch`) has two jobs:

* **server** — BoringSSL at tag `0.20260413.0`, apply the server patch, build `ssl`/`crypto` and the apps,
  run `poc_suspend` + `poc_end_to_end`, then a real-TCP smoke test (REALITY handshake, 122-byte mirror
  ServerHello injection, unauthenticated probe forwarded to the mirror). Artifacts: binaries + logs.
* **client** — checks that the client patch applies to the pinned naiveproxy commit and builds the
  client-side BoringSSL (`ac39ea68…`) into `libssl.a`. A full naiveproxy build is intentionally out of scope
  for a hosted runner.

## Unverified / limitations

Read [`docs/report.md` §6](docs/report.md) before using any of this. The short version: the naiveproxy side has
never been compiled into Chromium or run end-to-end; mirroring has only been exercised against local TLS 1.3
endpoints (never a public third-party site); there is no rate limiting, and the mirror dial in the front end is
synchronous (the blog describes an asynchronous, event-driven arrangement).

## References

* Blog: 《在 BoringSSL 的接缝中实现 REALITY》 — <https://blog.sam1314.com/posts/c65526af.html>
* XTLS/REALITY (Go) — <https://github.com/XTLS/REALITY> · Xray-core client side — `transport/internet/reality/`
* Prior art with the same goal (Go server, no ServerHello mirroring): <https://github.com/lipeiying032/naive-reality>
* Upstreams: [BoringSSL](https://boringssl.googlesource.com/boringssl), [naiveproxy](https://github.com/klzgrad/naiveproxy)

## License

No license file is included yet; the patches apply to BoringSSL and naiveproxy and remain subject to their
respective licenses. Open an issue if you need an explicit license for this repository's own code.
