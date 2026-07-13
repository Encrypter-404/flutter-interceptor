"""
fi_reflutter.py — one-click reFlutter chain (root-free path to Burp).

Pipeline:
  1. Pull the app's APK(s) from the device (adb pull, no root).
  2. If split APKs -> merge into one with APKEditor.jar.
  3. Run reFlutter on it (Burp IP piped via stdin, non-interactive).
       - older Flutter engine (<=58): TLS off + socket redirect to BurpIP:8083 baked in.
       - newer engine (>58): TLS off only; needs a no-root VPN (TunProxy) on the phone for routing.
       - unsupported engine: fails cleanly (caller should fall back to on-device Frida unpin).
  4. ZipAlign + sign release.RE.apk with uber-apk-signer.jar (debug key).
  5. (optional) uninstall original + install patched APK (adb install, no root).

Everything runs in an isolated temp workdir because reFlutter writes release.RE.apk /
libappTmp / release / enginehash.csv into CWD and calls sys.exit() at the end.

This module is self-contained and does NOT import frida/pywebview, so it can be used
standalone or from the GUI.
"""
import os
import re
import sys
import json
import shutil
import subprocess
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = os.path.join(HERE, "adb.exe")
APKEDITOR = os.path.join(HERE, "tools", "APKEditor.jar")
UBERSIGN = os.path.join(HERE, "tools", "uber-apk-signer.jar")
REFLUTTER_EXE = os.path.join(os.path.dirname(sys.executable), "reflutter.exe")


def _log_default(msg):
    print(msg)


def _stream(proc, log, tag, sink):
    """Forward a subprocess's stdout/stderr to log() line by line, and accumulate bytes."""
    try:
        while True:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            if sink is not None:
                try: sink.extend(chunk)
                except Exception: pass
            if log:
                try:
                    for line in chunk.decode("utf-8", "replace").splitlines():
                        log((tag + line) if tag else line)
                except Exception:
                    pass
    finally:
        pass


def _run(cmd, log, cwd=None, stdin_data=None, timeout=None, tag=""):
    if log:
        log("$ " + " ".join('"' + c + '"' if " " in c else c for c in cmd))
    try:
        p = subprocess.Popen(
            cmd, cwd=cwd, shell=False,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if stdin_data is not None else None,
            bufsize=0,
        )
    except FileNotFoundError as e:
        if log: log("[!] command not found: " + cmd[0])
        return -1, b""
    stdin_bytes = stdin_data.encode() if isinstance(stdin_data, str) else stdin_data
    out = bytearray()
    try:
        if stdin_bytes is not None:
            try:
                p.stdin.write(stdin_bytes); p.stdin.close()
            except Exception:
                pass
        th = threading.Thread(target=lambda: _stream(p, log, tag, out), daemon=True)
        th.start()
    except Exception:
        pass
    try:
        rc = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait()
        if log: log("[!] timeout")
        return -2, bytes(out)
    th.join(timeout=2)
    return p.returncode, bytes(out)


_SERIAL = {"serial": None}


def set_serial(serial):
    _SERIAL["serial"] = serial


def _adb(args, log, timeout=None):
    cmd = [ADB] + (["-s", _SERIAL["serial"]] if _SERIAL["serial"] else []) + args
    rc, out = _run(cmd, log, timeout=timeout)
    return rc, out.decode("utf-8", "replace")


def _detect_serial(log):
    rc, out = _run([ADB, "devices"], lambda m: None)
    lines = [l for l in out.decode("utf-8", "replace").splitlines()
             if l.strip() and "\tdevice" in l]
    if not lines:
        return None
    serial = lines[0].split("\t")[0].strip()
    _SERIAL["serial"] = serial
    return serial


def _lan_ip(log):
    """Best-effort LAN IPv4 for Burp. Picks the most likely reachable one."""
    rc, out = _run(["ipconfig"], lambda m: None, timeout=10)
    text = out.decode("utf-8", "replace") if isinstance(out, (bytes, bytearray)) else (out or "")
    ips = re.findall(r"IPv4 Address[.\s]*:\s*([0-9.]+)", text)
    # prefer 192.168.* then 10.* then anything not loopback/virtual
    def rank(ip):
        a = ip.split(".")[0]
        return 0 if ip.startswith("192.168.") else 1 if a == "10" else 2 if a == "172" else 3
    ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("169.254")]
    if not ips:
        return None
    ips.sort(key=rank)
    return ips[0]


def pull_apks(pkg, log, workdir):
    """adb shell pm path + adb pull all split APKs into workdir. Returns list of local apk paths."""
    rc, out = _adb(["shell", "pm", "path", pkg], log)
    if rc != 0:
        log("[!] pm path failed for " + pkg)
        return []
    paths = [l.replace("package:", "").strip() for l in out.splitlines() if l.startswith("package:")]
    if not paths:
        log("[!] no APK paths for " + pkg + " — installed?")
        return []
    local = []
    for i, p in enumerate(paths):
        dst = os.path.join(workdir, "split_%d.apk" % i)
        rc, _ = _adb(["pull", p, dst], log, timeout=180)
        if rc == 0:
            local.append(dst)
        else:
            log("[!] pull failed: " + p)
    return local


def merge_splits(apks, log, workdir):
    """Merge split APKs into a single APK via APKEditor. Returns merged apk path or None."""
    merged = os.path.join(workdir, "merged.apk")
    rc, _ = _run(["java", "-jar", APKEDITOR, "m", "-i", workdir, "-o", merged], log, timeout=600)
    if rc != 0 or not os.path.exists(merged):
        log("[!] APKEditor merge failed")
        return None
    return merged


def reflutter(apk, log, workdir, burp_ip):
    """Run reflutter on apk (cwd=workdir). Returns (release_apk, mode) where mode is 'socket'|'tls'|'unsupported'."""
    if not os.path.exists(REFLUTTER_EXE):
        log("[!] reflutter.exe not found at " + REFLUTTER_EXE)
        return None, "unsupported"
    # reflutter uses input() for Burp IP (older engines). Pipe IP via stdin; newer engines
    # don't read stdin at all, so the extra line is harmlessly ignored.
    stdin_data = (burp_ip + "\n") if burp_ip else "\n"
    rc, out = _run([REFLUTTER_EXE, apk], log, cwd=workdir,
                   stdin_data=stdin_data, timeout=900)
    txt = out.decode("utf-8", "replace") if isinstance(out, (bytes, bytearray)) else (out or "")
    release_apk = os.path.join(workdir, "release.RE.apk")
    if not os.path.exists(release_apk):
        log("[!] release.RE.apk not produced by reFlutter")
        return None, "unsupported"
    # detect which routing mode reflutter used
    if "Configure TunProxy" in txt:
        mode = "tls"          # newer engine: TLS off only, needs TunProxy VPN for routing
    elif "8083" in txt and "Invisible Proxying" in txt:
        mode = "socket"       # older engine: socket redirect baked to BurpIP:8083
    else:
        mode = "socket"       # default assumption
    log("[*] reFlutter routing mode: " + mode)
    return release_apk, mode


def sign(apk, log, final_dir=None):
    """ZipAlign + sign in-place with uber-apk-signer (debug key, --overwrite).
    If final_dir is given, copies the signed APK there as <stem>.patched.apk and returns that path.
    --overwrite and -o are mutually exclusive in uber-apk-signer, so we sign in place then move."""
    rc, out = _run(["java", "-jar", UBERSIGN, "-a", apk, "--overwrite", "--allowResign"],
                   log, timeout=300)
    txt = out.decode("utf-8", "replace") if isinstance(out, (bytes, bytearray)) else (out or "")
    ok = (rc == 0) and ("sign success" in txt or "signature verified" in txt)
    if not ok:
        log("[!] uber-apk-signer did not report success (rc=%d)" % rc)
        return None
    if not final_dir:
        return apk
    os.makedirs(final_dir, exist_ok=True)
    dst = os.path.join(final_dir, os.path.splitext(os.path.basename(apk))[0] + ".patched.apk")
    shutil.copy(apk, dst)
    return dst


def install(apk, pkg, log, replace=True):
    """Uninstall original (ignore failure) then adb install -r the patched APK. No root needed."""
    _adb(["uninstall", pkg], log)   # ignore rc — may fail if data must stay
    rc, out = _adb(["install", "-r", apk], log, timeout=300)
    if rc != 0:
        log("[!] install failed (rc=%d)" % rc)
        log((out or ""))
        return False
    if "Failure" in out:
        log("[!] install reported Failure:\n" + out)
        return False
    log("[+] installed: " + pkg)
    return True


def run_chain(pkg=None, apk=None, burp_host=None, do_install=True, log=None):
    """
    One-click reFlutter -> Burp chain.

    pkg: target package name (pull from device). Either pkg or apk required.
    apk: local APK path (skip pull/merge).
    burp_host: BurpSuite PC IPv4. Auto-detected if None.
    do_install: install the patched APK at the end.
    log: callable(str) for progress.

    Returns dict: {ok, signed_apk, mode, burp_host, notes}
    """
    log = log or _log_default
    if not (pkg or apk):
        return dict(ok=False, error="need pkg or apk")
    if not os.path.exists(APKEDITOR):
        log("[!] missing tools/APKEditor.jar — run setup first")
        return dict(ok=False, error="missing APKEditor")
    if not os.path.exists(UBERSIGN):
        log("[!] missing tools/uber-apk-signer.jar — run setup first")
        return dict(ok=False, error="missing uber-apk-signer")
    if not os.path.exists(REFLUTTER_EXE) or not os.path.exists(os.path.join(os.path.dirname(sys.executable), "reflutter.exe")):
        log("[!] reflutter not installed in this Python env: pip install reflutter")
        return dict(ok=False, error="missing reflutter")

    _detect_serial(log)

    if burp_host is None:
        burp_host = _lan_ip(log)
        if burp_host:
            log("[*] auto-detected Burp PC IP: " + burp_host)
        else:
            log("[!] could not auto-detect LAN IP — pass burp_host explicitly")
            return dict(ok=False, error="no LAN IP")

    workdir = tempfile.mkdtemp(prefix="reflutter_")
    log("[*] workdir: " + workdir)
    result = dict(ok=False, signed_apk=None, mode=None, burp_host=burp_host, notes=[])
    try:
        # 1) obtain a single APK
        if apk:
            single = os.path.join(workdir, "input.apk")
            shutil.copy(apk, single)
        else:
            log("== 1/5 pulling APK(s) for " + pkg + " ==")
            apks = pull_apks(pkg, log, workdir)
            if not apks:
                return dict(ok=False, error="pull failed")
            if len(apks) == 1:
                single = apks[0]
            else:
                log("== merging %d split APKs ==" % len(apks))
                merged = merge_splits(apks, log, workdir)
                if not merged:
                    return dict(ok=False, error="merge failed")
                single = merged

        # 2) reflutter
        log("== 2/5 reFlutter (this can take a few minutes) ==")
        release_apk, mode = reflutter(single, log, workdir, burp_host)
        if not release_apk:
            result["note"] = "unsupported engine — fall back to on-device Frida unpin"
            result["error"] = "reflutter unsupported"
            log("[!] " + result["note"])
            return result
        result["mode"] = mode

        # 3) sign (into a persistent folder so it survives temp cleanup)
        final_dir = os.path.join(HERE, "patched")
        log("== 3/5 signing (uber-apk-signer) ==")
        signed = sign(release_apk, log, final_dir=final_dir)
        if not signed:
            return dict(ok=False, error="sign failed")
        result["signed_apk"] = signed
        log("[+] signed APK: " + signed)

        # 4) routing guidance
        if mode == "socket":
            result["notes"].append(
                "Burp: add a proxy listener on %s:8083 (all interfaces), "
                "enable 'Support invisible proxying' in Request-Handling. "
                "Then install the patched APK — traffic routes there automatically." % burp_host)
        else:
            result["notes"].append(
                "Newer Flutter engine: reFlutter disabled TLS only. Install a no-root "
                "VPN app (e.g. TunProxy / ProxyDroid) on the phone pointing at %s:8083, "
                "or set the device Wi-Fi HTTP proxy to %s:8083. Then install the patched APK." % (burp_host, burp_host))

        # 5) install
        if do_install and pkg:
            log("== 4/5 installing patched APK (no root needed) ==")
            ok = install(signed, pkg, log)
            result["installed"] = ok
        else:
            log("[*] skipping install (signed APK ready at " + signed + ")")

        log("== 5/5 done ==")
        if mode == "socket":
            log("[+] Now open Burp, add the *:8083 invisible listener, and launch the app. "
                "Requests should appear in Burp's HTTP history.")
        else:
            log("[+] Set the phone proxy / start TunProxy to " + burp_host + ":8083, "
                "then launch the app. Requests should appear in Burp.")
        result["ok"] = True
        return result
    except Exception as e:
        log("[!] chain error: " + str(e))
        return dict(ok=False, error=str(e))
    finally:
        # keep the signed apk; clean the rest of the temp dir contents
        try:
            for f in os.listdir(workdir):
                p = os.path.join(workdir, f)
                if os.path.abspath(p) == os.path.abspath(result.get("signed_apk", "")):
                    continue
                if os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    try: os.remove(p)
                    except Exception: pass
        except Exception:
            pass


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="reFlutter one-click chain -> Burp")
    ap.add_argument("pkg", nargs="?", help="package name (pull from device)")
    ap.add_argument("-a", "--apk", help="local APK path instead of package")
    ap.add_argument("-b", "--burp", help="Burp PC IPv4 (auto-detected if omitted)")
    ap.add_argument("--no-install", action="store_true", help="do not install the patched APK")
    ap.add_argument("-s", "--serial", help="adb device serial")
    args = ap.parse_args()
    if args.serial:
        set_serial(args.serial)
    r = run_chain(pkg=args.pkg, apk=args.apk, burp_host=args.burp,
                  do_install=not args.no_install, log=_log_default)
    print("\n---- result ----")
    print(json.dumps({k: v for k, v in r.items() if k != "notes"}, indent=2))
    for n in r.get("notes", []):
        print("  note: " + n)
    sys.exit(0 if r.get("ok") else 1)