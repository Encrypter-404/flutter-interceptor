# 🛡️ Flutter Interceptor

**One-click Android traffic interception for Flutter & native apps** — auto-provisions frida,
unpins TLS across every common stack, bypasses root/VPN & anti-instrumentation, self-recovers
from crashes, and captures decrypted **HTTP + WebSocket** right inside the tool. Now also ships a
**root-free** path: a one-click **reFlutter → Burp** chain that patches, signs and installs the
target APK so you get traffic without a rooted device at all.

<p>
<img alt="license" src="https://img.shields.io/badge/license-MIT-green">
<img alt="python" src="https://img.shields.io/badge/python-3.10%2B-blue">
<img alt="platform" src="https://img.shields.io/badge/platform-Windows-lightgrey">
<img alt="frida" src="https://img.shields.io/badge/frida-17.x-orange">
<img alt="status" src="https://img.shields.io/badge/status-active-brightgreen">
</p>

> ⚠️ **Authorized use only.** This is a security-research / penetration-testing tool. Use it **only**
> on applications and devices you own or are explicitly authorized to test. You are responsible for
> complying with all applicable laws and agreements. The author accepts no liability for misuse.

---

## ✨ Features

| | |
|---|---|
| 🎯 **One-click intercept** | Pick a device, click an app — frida, unpinning, routing all automatic |
| 🔧 **Root-free reFlutter chain** | Build, sign & install a patched APK that sends traffic straight to Burp — **no root needed** |
| 🔓 **Universal TLS unpin** | Flutter BoringSSL, Conscrypt, OkHttp, Cronet, Java TrustManagers/HostnameVerifier |
| 🕵️ **Anti-detection** | Anti-ptrace, keep-alive (blocks self exit/kill/tgkill/raise), frida-artifact hiding |
| 🧱 **Bypasses** | Root detection, VPN detection; QUIC-block + IPv4-force so no traffic escapes |
| ♻️ **Self-recovering** | Adaptive launch ladder: spawn → attach → delayed-attach → stealth, auto-retry on crashes |
| 🧪 **In-tool capture** | Built-in TLS MITM proxy decrypts **HTTP + WebSocket** for *any* stack (auto-installs its CA on rooted devices) |
| 📊 **Compatibility report** | Auto-detects Flutter/ABI, SSL backend, networking libs, RASP framework, hook status + recommended fixes |
| 🧰 **Workbench** | Live request list (filter / pause / copy / export), gzip/br body decoding, traffic meter, scrcpy screen mirror |

## 🧩 Requirements

- **Windows** PC with **Python 3.10+ (x64)** and **Java 17+** (only needed for the reFlutter chain)
- An **Android** device with **USB debugging** enabled
  - **Rooted** is *only* required for the live frida intercept path (in-tool capture + Burp routing)
  - **Not rooted** is fine for the **reFlutter root-free** path (patched-APK install)
- Optional: [Burp Suite](https://portswigger.net/burp) / HTTP Toolkit (only if you prefer an external proxy)

## 🚀 Install & run

```text
1.  setup.bat        ← run once (creates a Python venv + installs frida, pywebview, cryptography)
2.  run.bat          ← launch the tool (GUI + a console showing the live log)
```

- **`setup.bat`** — one-time environment setup (also installs `reflutter` into the venv for the root-free chain).
- **`run.bat`** — start the tool (recommended; shows the engine log).
- **`run_gui_only.bat`** — start the GUI with no console window.

> If the live intercept path can't gain root (no `su` prompt appears), approve the **superuser**
> prompt in your root manager (Magisk / KernelSU → grant *Shell*), then hit **↻**. For a
> **non-rooted** device, skip straight to the **reFlutter chain** below — it needs no `su`.

## 🌐 Getting the requests — three ways

### A) reFlutter chain → Burp (no root needed) — newest
1. In the **Intercept** tab config strip, type the app's package name (or scan & use an app card)
   and click **🔧 Build patched APK**.
2. The tool pulls the APK, disables TLS with [reFlutter](https://github.com/Impact-I/reFlutter),
   re-signs it with `uber-apk-signer`, and installs it on the phone.
3. In Burp, add a proxy listener on `0.0.0.0:8083` and tick **Support invisible proxying**
   (Request Handling tab).
4. For **newer Flutter engines** (the common case now), also set the phone's Wi-Fi **HTTP proxy**
   to `<your-PC-IP>:8083` (or use a no-root VPN like TunProxy). For **older engines** the proxy
   address is baked into the APK, so just launching the app is enough.
5. Launch the patched app → requests appear in Burp's HTTP history.

> Your PC's LAN IP is auto-detected; you can override it in the **Burp IP** box. Patched APKs are
> saved in `patched/`. Because the APK is re-signed, apps that verify their own
> signature/integrity will reject it — those need the live intercept path instead.

### B) In-tool capture (no Burp needed) — easiest
1. Turn on the **Capture proxy** toggle (on by default).
2. Click the app and use it.
3. Open the **Requests** tab — decrypted HTTP + WebSocket appear live (filter / copy / export),
   with gzip/deflate/brotli bodies decoded to readable text.

### C) Your own proxy (Burp / HTTP Toolkit) — rooted device
1. Add an **invisible** listener on `:8080`.
2. Turn off any VPN (it reroutes traffic away from the proxy).
3. Click the app — HTTP shows in Proxy history, WebSocket in **Proxy → WebSockets history**.

## ⚙️ Options (config strip)

`SSL unpinning` · `Root` · `VPN` bypass · `Anti-detection` · `Stealth (experimental)` ·
`Capture proxy` (on by default) · `Auto-recover on crash` · `Spawn / Attach` mode · proxy `port` ·
**Burp IP** (for the reFlutter chain) · **🔧 Build patched APK** (root-free) · **▣ Screen** (scrcpy mirror)

## 🗂️ Project layout

```
flutter_interceptor.py   main app (orchestration, UI backend, adb/frida control)
fi_bundle.js             frida engine — TLS unpin + root/VPN bypass (frida-compiled)
fi_engine.js             native detection + expanded multi-stack SSL unpin + diagnostics
fi_mitm.py               in-tool TLS MITM capture proxy (HTTP + WebSocket)
fi_reflutter.py          one-click root-free reFlutter -> Burp chain (pull/patch/sign/install)
webui/index.html         the UI
adb.exe (+ DLLs)         bundled Android platform tool
tools/                   APKEditor.jar (split merge) + uber-apk-signer.jar (resign)
run.bat / setup.bat      launchers
```

## 🧠 How it works

**Live intercept path (rooted):** provisions a matching **frida-server**, resolves the target app's
uid and sets up transparent routing (**iptables redirect + adb-reverse + route_localnet**, QUIC
blocked, IPv6 forced to v4), then injects the engine to **unpin TLS** and **bypass**
root/VPN/anti-instrumentation. Traffic is captured by the built-in **MITM proxy** (auto-trusted via
an installed CA on rooted devices) or routed to your own proxy. It continuously monitors hook status
and **auto-recovers** on crashes.

**reFlutter path (no root):** pulls the installed APK(s), merges split APKs into one
([APKEditor](https://github.com/REAndroid/APKEditor)), patches `libflutter.so` to disable
certificate verification ([reFlutter](https://github.com/Impact-I/reFlutter)) while baking your
Burp IP into the socket layer (older engines) or leaving routing to a phone-side proxy (newer
engines), re-signs the APK with [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer),
and installs it with `adb install` — no root at any step.

## 🚫 Limitations

- **FLAG_SECURE** bank/login screens appear black in the mirror unless an LSPosed *DisableFlagSecure*
  module is enabled + scoped (an Android protection, not a tool bug).
- A few apps ship **commercial RASP** that detect frida via multiple vectors + self-integrity and
  self-destruct; these can't be intercepted by any runtime tool and need a per-app native patch. The
  Report tab names the detected RASP when this happens.
- **reFlutter signature check** — re-signing changes the app's certificate, so apps that verify their
  own integrity will refuse to run/re-login. Use the live intercept path for those.
- **reFlutter engine support** — engines not yet in reFlutter's hash database report
  "unsupported"; fall back to the on-device frida unpin (which also covers that engine's BoringSSL
  via the byte-pattern + Java unpin already shipped).
- **HTTP/2 & QUIC** — the in-tool MITM proxy is HTTP/1.1; HTTP/2-only and gRPC backends aren't
  fully bridged yet, and QUIC/HTTP-3 traffic is blocked (not captured) so it falls back to TCP.

## 📄 License

[MIT](LICENSE) © **Parth Raval**

---

## 📦 Changelog

### v1.1.0
- **New: root-free reFlutter → Burp chain** — `fi_reflutter.py` pulls, patches, re-signs and
  installs the target APK with no root required. One-click button per app card + a standalone
  "build any package" control; auto-detects your PC's Burp IP.
- **Fixed: intermittent request loss** in the MITM proxy — the upstream reader was recreated on
  every keep-alive request, discarding buffered bytes for the next response.
- **Fixed: non-standard-port APIs** now reach upstream (443 → 8443 fallback) instead of silently
  dialing the wrong port.
- **Fixed: compressed response bodies** (gzip/deflate/brotli) are now decoded to readable text in
  the Requests tab instead of showing as binary gibberish.
- **Better diagnostics** — when `libflutter.so` loads but no unpin pattern matches (newer Flutter
  version), the Report tab now says **"⚠ TLS still PINNED"** instead of failing silently.
- **Capture proxy is now ON by default** (pure-Dart apps depend on it for any visibility).
- Bundled `tools/APKEditor.jar` + `tools/uber-apk-signer.jar` so the chain works out-of-the-box.

### v1.0.0
- Initial release: one-click frida-based intercept, universal TLS unpin, anti-detection,
  self-recovery, in-tool HTTP + WebSocket MITM capture, compatibility report, scrcpy mirror.