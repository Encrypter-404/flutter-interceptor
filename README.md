# 🛡️ Flutter Interceptor

**One-click Android traffic interception for Flutter & native apps** — auto-provisions frida,
unpins TLS across every common stack, bypasses root/VPN & anti-instrumentation, self-recovers
from crashes, and captures decrypted **HTTP + WebSocket** right inside the tool.

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
| 🔓 **Universal TLS unpin** | Flutter BoringSSL, Conscrypt, OkHttp, Cronet, Java TrustManagers/HostnameVerifier |
| 🕵️ **Anti-detection** | Anti-ptrace, keep-alive (blocks self exit/kill/tgkill/raise), frida-artifact hiding |
| 🧱 **Bypasses** | Root detection, VPN detection; QUIC-block + IPv4-force so no traffic escapes |
| ♻️ **Self-recovering** | Adaptive launch ladder: spawn → attach → delayed-attach → stealth, auto-retry on crashes |
| 🧪 **In-tool capture** | Built-in TLS MITM proxy decrypts **HTTP + WebSocket** for *any* stack (auto-installs its CA on rooted devices) |
| 📊 **Compatibility report** | Auto-detects Flutter/ABI, SSL backend, networking libs, RASP framework, hook status + recommended fixes |
| 🧰 **Workbench** | Live request list (filter / pause / pretty-JSON / copy / export), traffic meter, scrcpy screen mirror |

## 🧩 Requirements

- **Windows** PC with **Python 3.10+ (x64)**
- A **rooted Android** device with **USB debugging** enabled (frida-server auto-provisioned)
- Optional: [Burp Suite](https://portswigger.net/burp) / HTTP Toolkit (only if you prefer an external proxy)

## 🚀 Install & run

```text
1.  setup.bat        ← run once (creates a Python venv + installs frida, pywebview, cryptography)
2.  run.bat          ← launch the tool (GUI + a console showing the live log)
```

- **`setup.bat`** — one-time environment setup.
- **`run.bat`** — start the tool (recommended; shows the engine log).
- **`run_gui_only.bat`** — start the GUI with no console window.

> First connection: if root doesn't show, approve the **superuser (su)** prompt on the phone, then hit **↻**.

## 🌐 Getting the requests — two ways

**A) In-tool capture (no Burp needed) — easiest**
1. Turn on the **Capture proxy** toggle.
2. Click the app and use it.
3. Open the **Requests** tab — decrypted HTTP + WebSocket appear live (filter / copy / export).

**B) Your own proxy (Burp / HTTP Toolkit)**
1. Add an **invisible** listener on `:8080`.
2. Turn off any VPN (it reroutes traffic away from the proxy).
3. Click the app — HTTP shows in Proxy history, WebSocket in **Proxy → WebSockets history**.

## ⚙️ Options (config strip)

`SSL unpinning` · `Root` · `VPN` bypass · `Anti-detection` · `Stealth (experimental)` ·
`Capture proxy` · `Auto-recover on crash` · `Spawn / Attach` mode · proxy `port` · **▣ Screen** (scrcpy mirror)

## 🗂️ Project layout

```
flutter_interceptor.py   main app (orchestration, UI backend, adb/frida control)
fi_bundle.js             frida engine — TLS unpin + root/VPN bypass (frida-compiled)
fi_engine.js             native detection + expanded multi-stack SSL unpin + diagnostics
fi_mitm.py               in-tool TLS MITM capture proxy (HTTP + WebSocket)
webui/index.html         the UI
adb.exe (+ DLLs)         bundled Android platform tool
run.bat / setup.bat      launchers
```

## 🧠 How it works

Provisions a matching **frida-server**, resolves the target app's uid and sets up transparent
routing (**iptables redirect + adb-reverse + route_localnet**, QUIC blocked, IPv6 forced to v4),
then injects the engine to **unpin TLS** and **bypass** root/VPN/anti-instrumentation. Traffic can
be captured by the built-in **MITM proxy** (auto-trusted via an installed CA on rooted devices) or
routed to your own proxy. It continuously monitors hook status and **auto-recovers** on crashes.

## 🚫 Limitations

- **FLAG_SECURE** bank/login screens appear black in the mirror unless an LSPosed *DisableFlagSecure*
  module is enabled + scoped (an Android protection, not a tool bug).
- A few apps ship **commercial RASP** that detect frida via multiple vectors + self-integrity and
  self-destruct; these can't be intercepted by any runtime tool and need a per-app native patch. The
  Report tab names the detected RASP when this happens.

## 📄 License

[MIT](LICENSE) © **Parth Raval**
