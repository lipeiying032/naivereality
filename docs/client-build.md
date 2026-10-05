# Building the naiveproxy client with REALITY

The client patch (`patches/naiveproxy-reality-client.patch`) is written against the naiveproxy tree at commit
`d6ba2a2e55416294bca1ae87499bfb31d94ccd4d` (Chromium 154 generation). This document explains why the hosted CI
does **not** build it and what to do instead.

## What CI verifies (and what it does not)

| Check | Where | Status |
|---|---|---|
| The patch applies to the pinned naiveproxy commit | CI job `client` (`git apply --check`) | yes |
| The client's BoringSSL changes compile (`ac39ea6853833c1f18fd23614091d11855e71752`) | CI job `client` (`ninja ssl`) | yes |
| The Chromium `net/` changes compile and link | — | **not verified** |
| The patched client actually connects to a REALITY server | — | **not verified** |

## Why not a full naiveproxy build in CI

naiveproxy is a patched Chromium network stack. Building it means `depot_tools` + `gclient sync` of a full
Chromium checkout (tens of GB) and a `gn`/`ninja` build that takes hours on many cores. GitHub-hosted runners
give ~14 GB of disk on `/` and a 6-hour job limit, so a hosted-runner build is not realistic with the default
image. The failure mode is disk exhaustion during `gclient sync`, not a compile error — which is why CI stays
with "patch applies + BoringSSL compiles".

## Recommended paths

1. **Self-hosted runner** (or a bigger hosted runner) with ≥100 GB free disk, 8+ cores:
   ```bash
   git clone https://github.com/klzgrad/naiveproxy && cd naiveproxy
   git checkout d6ba2a2e55416294bca1ae87499bfb31d94ccd4d
   git apply /path/to/naiveproxy-reality-client.patch
   # follow naiveproxy's own build instructions (depot_tools, gclient sync, gn gen, ninja -C out)
   ```
2. **Local machine with disk**: same steps; the patch touches 12 files
   (5 under `src/third_party/boringssl/src`, 7 under `src/net`). Adding `src/net/socket/reality_config.cc` to
   the build is already included in the patch (`src/net/BUILD.gn`).

## Runtime configuration

`config.json`:

```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://user:pass@example.com",
  "reality": { "public_key": "<64 hex chars>", "short_id": "<up to 16 hex chars>" }
}
```

Flat switches `--reality-public-key` / `--reality-short-id` are also parsed. When no REALITY configuration is
present, the client behaves exactly like upstream naiveproxy.

## How the client pieces fit together

```
naive_config.cc        parse {"reality": {...}} (hex validation, short_id right-padded)
naive_proxy_bin.cc     net::SetRealityConfig(...) before the first socket is created
ssl_client_socket_impl.cc
    Init()             SSL_set1_reality_config(ssl, pubkey, short_id)      [BoringSSL]
    VerifyCert()       SSL_reality_verify_certificate(leaf DER) -> ok      [BoringSSL]
                       (falls through to the standard verification otherwise)

BoringSSL side (patches/boringssl-reality-client.patch):
    ssl/handshake_client.cc   seal version/timestamp/short_id into the ClientHello session id
    ssl/extensions.cc         accept the unadvertised Ed25519 CertificateVerify (narrow carve-out)
    ssl/ssl_lib.cc            SSL_set1_reality_config + SSL_reality_verify_certificate
```

## Known limitations

* REALITY is wired into `SSLClientSocketImpl` (TLS over TCP) only; `quic://` proxies are unaffected and will
  not use REALITY.
* `net::RealityConfig` is process-wide (one proxy per process, matching naiveproxy's model).
* The Ed25519 carve-out means the client accepts a signature algorithm its ClientHello did not advertise —
  see `docs/report.md` §1.4 in `docs/blog-analysis.md` for the RFC trade-off and the compliant alternative.
