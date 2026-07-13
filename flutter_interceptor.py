#!/usr/bin/env python3
"""
Flutter Interceptor (web UI) - HTTP-Toolkit-style interface via pywebview (HTML/CSS/JS frontend)
backed by the frida-17 engine. Universal: auto-provisions a matching frida-server per device,
unpins TLS (Flutter BoringSSL + Java), bypasses root/VPN, routes traffic to your proxy.
Run with a frida-17 Python that has pywebview. Keep fi_bundle.js + webui/ next to this file.
"""
import os, sys, json, time, threading, subprocess, lzma, tempfile, urllib.request, datetime, traceback, logging, socket
import webview
# frida is LAZY-loaded (its native module is ~1s to import) so the window + app list appear fast;
# it's only needed when you actually start intercepting.
frida=None
def load_frida():
    global frida
    if frida is None:
        import frida as _m; frida=_m
    return frida
# silence pywebview's caught internal COM / accessibility-probe noise so the console
# shows only our clean diagnostic log (these are non-fatal and already handled by pywebview)
logging.getLogger('pywebview').setLevel(logging.CRITICAL)

def res(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)
HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
ADB = "adb"   # bundled adb next to this script, else the one on PATH
for c in (res("adb.exe"), os.path.join(HERE,"adb.exe")):
    if os.path.isfile(c): ADB=c; break
SCRCPY = ""   # optional: put a full scrcpy (scrcpy.exe + SDL2.dll + scrcpy-server) beside this script
for c in (res("scrcpy.exe"), os.path.join(HERE,"scrcpy.exe")):
    # require a COMPLETE install (scrcpy.exe + SDL2.dll + scrcpy-server) or it won't launch
    d=os.path.dirname(c)
    if os.path.isfile(c) and os.path.isfile(os.path.join(d,"SDL2.dll")) and os.path.isfile(os.path.join(d,"scrcpy-server")):
        SCRCPY=c; break
SCRCPY_DIR = os.path.dirname(SCRCPY) if SCRCPY else ""
ARCH={"arm64-v8a":"arm64","armeabi-v7a":"arm","x86_64":"x86_64","x86":"x86"}
NW=getattr(subprocess,"CREATE_NO_WINDOW",0)

# ---- terminal + file logging (so crashes are visible) ----
LOGFILE=os.path.join(HERE,"flutter_interceptor.log")
def tlog(m):
    line="[%s] %s"%(datetime.datetime.now().strftime("%H:%M:%S"),m)
    try: print(line,flush=True)
    except Exception:
        # console can't encode a char (cp1252) -> print an ASCII-safe version instead of dropping it
        try: print(line.encode("ascii","replace").decode(),flush=True)
        except Exception: pass
    try:
        with open(LOGFILE,"a",encoding="utf-8") as f: f.write(line+"\n")
    except Exception: pass

def run(a,to=120):
    try: return subprocess.run(a,capture_output=True,text=True,timeout=to,creationflags=NW).stdout
    except Exception as e:
        tlog("[!] cmd failed (%s): %s"%(e," ".join(str(x) for x in a[-4:]))); return "ERR %s"%e
def adb(a,s=None,to=120): return run([ADB]+(["-s",s] if s else [])+a,to)
def sush(c,s=None,to=120): return adb(["shell","su","-c",c],s,to)
def sush_script(script,s=None,to=120):
    """Run a multi-line shell script as root by feeding it to `su -c sh` via stdin.
    Avoids the adb double-parse that mangles ';'/loops in `su -c '<script>'`."""
    a=[ADB]+(["-s",s] if s else [])+["shell","su","-c","sh"]
    try:
        return subprocess.run(a,input=script,capture_output=True,text=True,timeout=to,creationflags=NW).stdout
    except Exception as e:
        tlog("[!] script failed: %s"%e); return "ERR %s"%e

# Universal anti-detection layer — native-only, frida-17 correct APIs (Module.findExportByName
# was REMOVED in frida 17). Every hook individually guarded so it can NEVER break a working app
# or the main bundle. Loaded as a SEPARATE script in the same session BEFORE the bundle.
# Verified to keep hardened apps alive (it catches anti-tamper _exit) without breaking normal apps.
# Defeats: PTRACE_TRACEME self-attach detection, self-termination (exit/abort/kill-self),
# and frida string/proc scans. (Cannot beat SIGSEGV-crash-on-detect packers — those need per-app work.)
ANTIFRIDA_JS = r"""
(function(){
  function expt(name){
    try{ var m=Process.findModuleByName("libc.so"); if(m){ var e=m.findExportByName(name); if(e) return e; } }catch(e){}
    try{ if(Module.findGlobalExportByName) return Module.findGlobalExportByName(name); }catch(e){}
    return null;
  }
  var n=0;
  // 1) anti-ptrace: pretend ptrace always succeeds (defeats PTRACE_TRACEME self-attach detection)
  try{ var p=expt("ptrace");
    if(p){ Interceptor.replace(p, new NativeCallback(function(req,pid,addr,data){ return 0; },'long',['int','int','pointer','pointer'])); n++; }
  }catch(e){}
  // 2) keep-alive: swallow self-termination (this is the DEFENSE working, not an error).
  //    throttled so a chatty anti-tamper loop doesn't flood the log.
  var _blk=0;
  function note(w){ _blk++; if(_blk<=3) send("[*] anti-tamper defense: kept app alive (blocked "+w+")"+(_blk===3?" — further blocks silenced":"")); }
  ["exit","_exit","_Exit"].forEach(function(fn){ try{ var a=expt(fn);
    if(a){ Interceptor.replace(a, new NativeCallback(function(c){ note(fn+"("+c+")"); },'void',['int'])); n++; } }catch(e){} });
  try{ var ab=expt("abort"); if(ab){ Interceptor.replace(ab, new NativeCallback(function(){ note("abort"); },'void',[])); n++; } }catch(e){}
  try{ var k=expt("kill"); if(k){ var kf=new NativeFunction(k,'int',['int','int']); var me=Process.id;
    Interceptor.replace(k, new NativeCallback(function(pid,sig){ if(pid===me||pid===0){ note("kill self sig="+sig); return 0;} return kf(pid,sig); },'int',['int','int'])); n++; }
  }catch(e){}
  try{ var tk=expt("tgkill"); if(tk){ var tkf=new NativeFunction(tk,'int',['int','int','int']); var me2=Process.id;
    Interceptor.replace(tk, new NativeCallback(function(tgid,tid,sig){ if(tgid===me2){ note("tgkill self sig="+sig); return 0;} return tkf(tgid,tid,sig); },'int',['int','int','int'])); n++; }
  }catch(e){}
  // raise(sig): block fatal self-signals (SIGILL/SIGABRT/SIGKILL/SIGSEGV) used as anti-tamper
  try{ var rs=expt("raise"); if(rs){ var rsf=new NativeFunction(rs,'int',['int']);
    Interceptor.replace(rs, new NativeCallback(function(sig){ if([4,6,9,11].indexOf(sig)>=0){ note("raise sig="+sig); return 0;} return rsf(sig); },'int',['int'])); n++; }
  }catch(e){}
  // 3) frida hiding: token searches return not-found; /proc scans drop frida lines
  function rd(pp){ try{ return pp.readCString(); }catch(e){ return null; } }
  var TOK=["frida","gum-js","gum_js","gmain","gdbus","linjector","27042","27043","frida-server","frida-agent","gadget","pool-frida"];
  function hot(s){ if(!s) return false; s=(""+s).toLowerCase(); for(var i=0;i<TOK.length;i++) if(s.indexOf(TOK[i])>=0) return true; return false; }
  ["strstr","strcasestr"].forEach(function(fn){ try{ var a=expt(fn);
    if(a){ Interceptor.attach(a,{ onEnter:function(ar){ this.n=rd(ar[1]); }, onLeave:function(r){ try{ if(this.n&&hot(this.n)) r.replace(ptr(0)); }catch(e){} } }); n++; } }catch(e){} });
  try{ var fg=expt("fgets"); if(fg){ Interceptor.attach(fg,{ onEnter:function(a){ this.b=a[0]; }, onLeave:function(r){ try{ if(!r.isNull()){ var s=rd(this.b); if(s&&hot(s)) this.b.writeUtf8String("\n"); } }catch(e){} } }); n++; } }catch(e){}
  send("[*] universal anti-detection active ("+n+" hooks: anti-ptrace + keep-alive + frida-hide)");
})();
"""

# device-side launcher-icon extractor: for each package, find the best ic_launcher PNG in the
# apk and stream it back as base64 (one adb round-trip for all apps). awk-free (toybox-safe).
ICON_SH = r'''
for p in __PKGS__; do
  paths=$(pm path "$p" 2>/dev/null | cut -d: -f2)
  ent=""; apk=""
  for a in $paths; do
    e=$(unzip -l "$a" 2>/dev/null | grep -oE 'res/[^ ]+\.(webp|png)' | grep -iE 'launcher|appicon|ic_launcher|app_icon|ic_app' | sort -r | head -1)
    [ -n "$e" ] && ent="$e" && apk="$a" && break
  done
  if [ -z "$ent" ]; then for a in $paths; do
      e=$(unzip -l "$a" 2>/dev/null | grep -oE 'res/(mipmap|drawable)[^ ]+\.(webp|png)' | grep -iE 'logo|icon' | sort -r | head -1)
      [ -n "$e" ] && ent="$e" && apk="$a" && break
    done; fi
  if [ -n "$ent" ]; then
    ext=$(echo "$ent" | grep -oiE '\.(webp|png)$' | tr -d '.')
    printf '%s\t%s\t' "$p" "$ext" && unzip -p "$apk" "$ent" 2>/dev/null | base64 | tr -d '\n' && printf '\n'
  fi
done
'''

# Request capture: hook BoringSSL SSL_write/SSL_read (plaintext, before/after TLS) and stream the
# HTTP to the tool's Requests tab. Works where libssl.so is dynamically linked (Conscrypt/Cronet/
# OkHttp+BoringSSL). Pure-Dart static-BoringSSL apps may not expose it — Burp remains the full source.
CAPTURE_JS = r"""
(function(){
  function expt(n){ try{var m=Process.findModuleByName("libssl.so"); if(m){var e=m.findExportByName(n); if(e)return e;}}catch(e){}
    try{ if(Module.findGlobalExportByName) return Module.findGlobalExportByName(n);}catch(e){} return null; }
  function bytes(p,len){ try{ if(len>16384) len=16384; return new Uint8Array(p.readByteArray(len)); }catch(e){ return null; } }
  function ascii(u,n){ var s=""; n=Math.min(n||u.length,u.length); for(var i=0;i<n;i++){ var c=u[i]; s+=(c===9||c===10||c===13||(c>=32&&c<127))?String.fromCharCode(c):""; } return s; }
  function http(s){ return /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \S+ HTTP\/|^HTTP\/1/.test(s); }
  var WS={};  // ssl-ptr -> true once the connection upgraded to WebSocket
  function parseWS(u){   // decode a WebSocket text/binary frame payload (unmasked)
    if(u.length<2) return null;
    var op=u[0]&0x0f; if(!(op===1||op===2||op===0)) return null;      // text/binary/continuation
    var masked=(u[1]&0x80)!==0, len=u[1]&0x7f, off=2;
    if(len===126){ if(u.length<4) return null; len=(u[2]<<8)|u[3]; off=4; }
    else if(len===127) return null;                                   // 64-bit len: skip huge
    var mask=null; if(masked){ if(u.length<off+4) return null; mask=[u[off],u[off+1],u[off+2],u[off+3]]; off+=4; }
    var n=Math.min(len, u.length-off), out="";
    for(var i=0;i<n;i++){ var c=u[off+i]; if(mask) c^=mask[i&3]; out+=(c===9||c===10||(c>=32&&c<127))?String.fromCharCode(c):""; }
    return out;
  }
  function handle(ssl,u,dir){
    if(!u||u.length<2) return;
    var head=ascii(u,600);
    if(http(head)){
      send("FIREQ "+JSON.stringify({dir:dir,data:ascii(u,4096)}));
      if(/upgrade:\s*websocket/i.test(head)||/^HTTP\/1\.1 101/.test(head)) WS[ssl]=true;  // WS handshake
      return;
    }
    if(WS[ssl]){ var t=parseWS(u); if(t&&t.length) send("FIREQ "+JSON.stringify({dir:dir,ws:true,data:t.slice(0,4096)})); }
  }
  var w=expt("SSL_write");
  if(w) Interceptor.attach(w,{ onEnter:function(a){ try{ handle(a[0].toString(), bytes(a[1],a[2].toInt32()), "out"); }catch(e){} } });
  var r=expt("SSL_read");
  if(r) Interceptor.attach(r,{ onEnter:function(a){ this.s=a[0].toString(); this.b=a[1]; }, onLeave:function(ret){ try{ var n=ret.toInt32(); if(n>0) handle(this.s, bytes(this.b,n), "in"); }catch(e){} } });
  send(w||r ? "[*] request + WebSocket capture active (SSL_write/SSL_read)" : "[*] capture: no libssl.so here — use Burp's WebSockets tab for full traffic");
})();
"""

# Native-only Flutter TLS unpin — NO frida-java-bridge (its ART instrumentation is what many RASP
# apps detect). Tiny footprint: scans libflutter.so for BoringSSL ssl_verify_peer_cert and forces OK.
# Used in Stealth mode instead of the full Java+native bundle, to survive harder apps.
NATIVE_UNPIN_JS = r"""
(function(){
  var PAT=[
    {p:"F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",r:0},
    {p:"F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",r:0},
    {p:"FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",r:0},
    {p:"FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9",r:1}
  ];
  var done=false, tries=0;
  function scan(){
    if(done) return; tries++;
    var m=Process.findModuleByName("libflutter.so");
    if(!m){ if(tries<25) setTimeout(scan,800); else send("[!] flutter-native: libflutter.so not found"); return; }
    var end=m.base.add(m.size);
    Process.enumerateRanges('r-x').forEach(function(rg){
      if(done) return;
      if(rg.base.compare(m.base)<0 || rg.base.compare(end)>=0) return;
      PAT.forEach(function(pat){ try{ Memory.scanSync(rg.base,rg.size,pat.p).forEach(function(hit){
        try{ Interceptor.replace(hit.address, new NativeCallback(function(){ return pat.r; },'int',['pointer','int']));
             done=true; send("[+][flutter-native] ssl_verify_peer_cert patched @"+hit.address); }catch(e){} }); }catch(e){} });
    });
    if(!done){ if(tries<25) setTimeout(scan,800); else send("[!] flutter-native: no pattern matched (Dart version?)"); }
    else send("[+] Flutter TLS unpinned (native-only — no Java bridge, stealthy)");
  }
  scan();
})();
"""

class Api:
    def __init__(self):
        self.win=None; self.serial=None; self.uid=None; self.port=8080
        self.session=None; self.dev=None; self.srv=None; self.running=False; self._stopping=False
        self._q=[]; self._qlock=threading.Lock(); self._alive=True
        # auto-recovery state
        self.want_running=False   # user intends interception to stay up
        self.cur_pkg=None; self.opts={}; self.auto_recover=True; self._recovering=False; self._afsc=None
        self._active_ts=0; self._rapid=0   # circuit-breaker for anti-tamper apps that self-kill
        # stealth frida-server (renamed binary + non-standard port) to defeat frida-server detection
        self._stealth_name="memtrackd"; self._stealth_port=47823; self._fdev=None
        self.diag=None; self._strat=0     # diagnostics report + adaptive-launch escalation index
        self._launch_delay=0; self._ensured_stealth=None; self._ssl_hooked=False; self._mitm=None; self._mitm_ca_name=None

    # ---- unified UI dispatch ----
    # ALL UI updates (logs, status, device/app/icon pushes) are queued here and executed by a
    # SINGLE pump thread. pywebview's evaluate_js is NOT safe to call from many threads at once
    # (it deadlocks the GUI thread); funnelling through one thread eliminates that entirely.
    def _push(self,kind,payload):
        with self._qlock: self._q.append((kind,payload))
    def log(self,m):
        tlog(m); self._push("log",m)
    def status(self,state,text):
        self._push("js","fiStatus(%s,%s)"%(json.dumps(state),json.dumps(text)))
    def _ui(self,js):
        self._push("js",js)

    def _handle_req(self,raw):
        """Parse a captured plaintext HTTP/WebSocket blob from the SSL hook -> Requests tab."""
        try: o=json.loads(raw)
        except Exception: return
        data=o.get("data","") or ""
        if o.get("ws"):   # a decoded WebSocket frame payload
            d=o.get("dir")
            obj={"method":"WS"+(" UP" if d=="out" else " DN"),"url":" ".join(data.split())[:160],
                 "first":data[:160],"data":data,"dir":d,"ws":True}
            self._ui("fiReq(%s)"%json.dumps(obj)); return
        first=data.replace("\r","").split("\n",1)[0].strip()[:300]
        method=None; url=first
        if o.get("dir")=="out":
            parts=first.split(" ")
            if len(parts)>=2 and parts[0] in ("GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"):
                method=parts[0]; path=parts[1]; host=""
                for ln in data.replace("\r","").split("\n"):
                    if ln.lower().startswith("host:"): host=ln.split(":",1)[1].strip(); break
                url=(("https://"+host) if host else "")+path
        else:
            method="RESP"
        obj={"method":method,"url":url,"first":first,"data":data[:4000],"dir":o.get("dir")}
        self._ui("fiReq(%s)"%json.dumps(obj))

    # heavy UI pushes (esp. big base64 app icons) are throttled to a few per tick so a burst
    # can't saturate the WebView UI thread and make the window go 'Not Responding' on connect.
    _JS_PER_TICK=3
    def _pump(self):
        while self._alive:
            time.sleep(0.12)
            items=None
            with self._qlock:
                if self._q: items=self._q; self._q=[]
            if not items or not self.win: continue
            logbuf=[]
            def flush():
                if logbuf:
                    for i in range(0,len(logbuf),200):
                        try: self.win.evaluate_js("fiLogBatch(%s)"%json.dumps(logbuf[i:i+200]))
                        except Exception: pass
                    del logbuf[:]
            js_done=0; leftover=[]
            for kind,payload in items:
                if kind=="log":
                    logbuf.append(payload)
                elif js_done < self._JS_PER_TICK:
                    flush();
                    try: self.win.evaluate_js(payload)
                    except Exception: pass
                    js_done+=1
                else:
                    leftover.append((kind,payload))   # spread the rest over later ticks
            flush()
            if leftover:
                with self._qlock: self._q = leftover + self._q

    # ---- device / apps ----
    # async: never blocks the GUI thread (the first `su` on a new phone can hang on the
    # on-device superuser prompt). Results pushed to the UI via fiDevices().
    def refresh_devices(self):
        threading.Thread(target=self._devices,daemon=True).start()
        return {"ok":True}

    def _devices(self):
        out=[]
        try:
            for l in adb(["devices"],to=10).splitlines()[1:]:
                parts=l.split()
                if len(parts)<2: continue
                sn,state=parts[0],parts[1]
                if state=="device":
                    rootout=sush("id",sn,to=12)
                    if "ERR" in rootout and "uid=0" not in rootout:
                        self.log("[*] %s: if no root shows, approve the superuser (su) prompt on the phone, then Refresh"%sn)
                    out.append({"serial":sn,"root":"uid=0" in rootout})
                elif state=="unauthorized":
                    self.log("[!] %s is UNAUTHORIZED — tap 'Allow USB debugging' on the phone (tick 'Always'), then Refresh"%sn)
                elif state=="offline":
                    self.log("[!] %s is OFFLINE — reconnect the cable or toggle USB debugging, then Refresh"%sn)
                else:
                    self.log("[!] %s state=%s — check the cable/USB-debugging"%(sn,state))
        except Exception as e:
            self.log("[!] device list failed: %s"%e)
        self._ui("fiDevices(%s)"%json.dumps(out))

    # ---- screen mirror (scrcpy) ----
    def mirror(self,serial):
        threading.Thread(target=self._mirror,args=(serial,),daemon=True).start()
        return {"ok":True}

    def _mirror(self,serial):
        if not serial:
            self.log("[!] scrcpy: select a device first"); return
        if not SCRCPY or not os.path.isfile(SCRCPY):
            self.log("[!] scrcpy.exe not found next to the tool — screen mirror unavailable"); return
        # make sure the device is actually present before launching
        if serial not in adb(["devices"],to=10):
            self.log("[!] scrcpy: device %s not connected"%serial); return
        try:
            self.log("[*] launching screen mirror (scrcpy) for %s…"%serial)
            env=dict(os.environ); env["ADB"]=ADB   # make scrcpy use OUR adb (same server)
            # Launch scrcpy EXACTLY like a double-click: detached, with its OWN console + window
            # (via cmd `start`). Running it under pythonw with CREATE_NO_WINDOW + piped stdout made
            # SDL render a black screen — a real console/detached launch fixes that.
            title="Flutter Interceptor - %s"%serial
            subprocess.Popen(["cmd","/c","start","", "/D", SCRCPY_DIR or ".", SCRCPY,
                              "-s", serial, "--window-title", title],
                             creationflags=NW, env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            self.log("[+] screen mirror opened — drive the phone in the scrcpy window")
            self.log("[?] if it shows BLACK on a bank/login screen, that app sets FLAG_SECURE (screenshot-protected) — normal; other screens mirror fine")
        except Exception as e:
            self.log("[!] scrcpy launch failed: %s"%e); tlog(traceback.format_exc())

    # device-side scan: runs up to 12 checks IN PARALLEL on the phone (was serial -> much faster),
    # and only opens base.apk + ABI-split apks (skips density/language splits that can't hold .so).
    _SCAN_SH=r'''i=0
for p in $(pm list packages -3 | cut -d: -f2); do
  (
    for a in $(pm path "$p" 2>/dev/null | cut -d: -f2); do
      case "$a" in
        *base.apk|*arm64*|*armeabi*|*armv7*|*x86*)
          unzip -l "$a" 2>/dev/null | grep -q libflutter.so && echo "$p" && break ;;
      esac
    done
  ) &
  i=$((i+1)); [ $((i%12)) -eq 0 ] && wait
done
wait'''

    def scan(self,serial):
        """Kick off the scan on a worker thread so the UI never blocks; results pushed via fiApps()."""
        self.serial=serial
        threading.Thread(target=self._scan,args=(serial,),daemon=True).start()
        return {"ok":True}

    def _scan(self,serial):
        found=[]
        try:
            out=sush_script(self._SCAN_SH,serial)
            for l in out.splitlines():
                pk=l.strip()
                if pk and "." in pk and " " not in pk:
                    found.append({"pkg":pk,"name":pk.split('.')[-1].capitalize()})
            found.sort(key=lambda x:x["pkg"])
        except Exception as e:
            self.log("[!] scan failed: %s"%e)
        self._ui("fiApps(%s)"%json.dumps(found))

    # ---- real app icons (best-effort, async; cards already shown with letter fallback) ----
    def fetch_icons(self,serial,pkgs):
        self.serial=serial
        threading.Thread(target=self._fetch_icons,args=(serial,list(pkgs)),daemon=True).start()
        return {"ok":True}

    def _fetch_icons(self,serial,pkgs):
        safe=[p for p in pkgs if p and all(c.isalnum() or c in "._" for c in p)]
        if not safe: return
        try:
            out=sush_script(ICON_SH.replace("__PKGS__"," ".join(safe)),serial,to=90)
        except Exception as e:
            tlog("[!] icon fetch failed: %s"%e); return
        n=0
        for line in (out or "").splitlines():
            parts=line.split("\t")
            if len(parts)<3: continue
            pk,ext,b64=parts[0].strip(),parts[1].strip().lower(),parts[2].strip()
            if not pk or not b64 or len(b64)>120000: continue   # skip large icons (keep UI pushes light)
            mime="image/webp" if ext=="webp" else "image/png"
            url="data:%s;base64,%s"%(mime,b64)
            self._ui("fiIcon(%s,%s)"%(json.dumps(pk),json.dumps(url))); n+=1
        tlog("[*] loaded %d app icons"%n)

    # ---- interception ----
    # NOTE: this js_api method must return FAST so the GUI thread never blocks.
    # All device I/O (teardown of a prior run, root check, frida, routing) happens in _run.
    def start(self,serial,pkg,ssl,root,vpn,port,mode,antifrida=False,stealth=False,mitmcap=False):
        self.serial=serial; self.port=int(port or 8080)
        self.opts={"ssl":bool(ssl),"root":bool(root),"vpn":bool(vpn),"mode":mode or "spawn",
                   "antifrida":bool(antifrida),"stealth":bool(stealth),"mitmcap":bool(mitmcap),
                   "expunpin":False}
        threading.Thread(target=self._run,args=(pkg,),daemon=True).start()
        return {"ok":True}

    # ---- reFlutter one-click chain (root-free path to Burp) ----
    # Builds a patched, signed, installable APK from the app's installed package on the phone,
    # no root needed. sidesteps the root/frida requirement entirely. see fi_reflutter.py.
    def build_reflutter(self,serial,pkg,burp_host=None,do_install=True):
        self.serial=serial
        threading.Thread(target=self._build_reflutter,args=(serial,pkg,burp_host,bool(do_install)),daemon=True).start()
        return {"ok":True}

    def _build_reflutter(self,serial,pkg,burp_host,do_install):
        try:
            import fi_reflutter
            fi_reflutter.set_serial(serial or None)
            self._ui("fiBuildReflutterView(%s)"%json.dumps(pkg))
            self.log("[*] reFlutter one-click chain -> Burp  (pkg=%s, install=%s)"%(pkg,do_install))
            self.log("[*] This is root-free: pulls the APK, disables TLS via reFlutter, re-signs, installs.")
            r=fi_reflutter.run_chain(pkg=pkg, burp_host=(burp_host or None),
                                     do_install=do_install, log=lambda m: self.log(m))
            self._ui("fiReflutterResult(%s)"%json.dumps(r))
            if r.get("ok"):
                self.log("[+] DONE: patched APK ready.")
                if r.get("mode")=="socket":
                    self.log("    -> add a Burp listener on %s:8083 (all ifaces) + enable "
                             "'Support invisible proxying'. Launch the app -> requests appear."%r.get("burp_host","PC"))
                else:
                    self.log("    -> newer Flutter: set the phone Wi-Fi HTTP proxy (or a no-root VPN) "
                             "to %s:8083, then launch the app."%r.get("burp_host","PC"))
                if r.get("installed") is False:
                    self.log("[!] install did not succeed (%s). The patched APK is saved in ./patched/ — "
                             "you can install it manually, or via the live intercept path."%r.get("install_reason","?"))
            else:
                err = r.get("error") or ""
                self.log("[!] chain did not complete: %s"%(err or r.get("note") or "unknown"))
                if "unsupported" in err:
                    self.log("[*] The app's Flutter engine isn't in reFlutter's hash DB yet.")
                    self.log("[*] FALLBACK: use the on-device Intercept path (pick the app above). The "
                             "bundle's byte-pattern + Java unpin + the new version-independent handshake.cc "
                             "locator cover most builds. Needs root (KernelSU/Magisk -> grant Shell).")
                elif r.get("install_reason")=="signature_protected":
                    self.log("[*] The app rejects the re-signed APK (signature self-check). The root-free "
                             "chain can't help here. Use the on-device Intercept path (needs root).")
        except Exception as e:
            self.log("[!] reFlutter chain error: %s"%e); tlog(traceback.format_exc())

    def _start_mitm(self):
        """Start the in-tool TLS MITM capture proxy on the proxy port (captures ALL apps incl pure-Dart)."""
        try: import fi_mitm
        except Exception as e: self.log("[!] capture proxy unavailable (need 'cryptography' — run setup): %s"%e); return
        try:
            if self._mitm: self._mitm.stop()
        except Exception: pass
        self._mitm=fi_mitm.MitmProxy(self.port, self._mitm_event, os.path.join(HERE,"mitm_ca"), log=self.log, debug=False)
        if self._mitm.start():
            self._install_mitm_ca()   # trust our CA on-device so every TLS stack accepts the MITM cert
            self.log("[*] IN-TOOL CAPTURE PROXY active — decrypted requests appear in the Requests tab (no Burp needed)")
        else:
            self._mitm=None

    def _install_mitm_ca(self):
        """Install the MITM CA into the device system trust store (rooted) so ALL TLS stacks
        (Cronet/Conscrypt/OkHttp/Flutter) accept our cert — the key to universal capture."""
        ca=self._mitm.ca_path() if self._mitm else None
        if not ca or not os.path.isfile(ca): return
        try:
            from cryptography import x509; import hashlib
            c=x509.load_pem_x509_certificate(open(ca,"rb").read())
            name="%08x.0"%int.from_bytes(hashlib.md5(c.subject.public_bytes()).digest()[:4],"little")
        except Exception as e:
            self.log("[!] CA hash calc failed: %s"%e); return
        s=self.serial
        adb(["push",ca,"/data/local/tmp/fi_ca.pem"],s,to=15)
        script=("line=$(ls -Z /system/etc/security/cacerts/*.0 2>/dev/null | head -1); set -- $line; CTX=$1\n"
                "for D in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; do\n"
                "  [ -d \"$D\" ] && cp /data/local/tmp/fi_ca.pem $D/%s 2>/dev/null && chmod 644 $D/%s 2>/dev/null\n"
                "  [ -n \"$CTX\" ] && chcon $CTX $D/%s 2>/dev/null\n"
                "done\n"%(name,name,name))
        sush_script(script,s,to=20)
        self._mitm_ca_name=name
        self.log("[+] MITM CA installed in device trust store (%s) — all TLS stacks now trust the proxy"%name)

    def _mitm_event(self,ev):
        try: self._ui("fiReq(%s)"%json.dumps(ev))
        except Exception: pass

    def ensure_frida(self,s):
        load_frida()   # lazy import (kept out of startup so the UI opens fast)
        hv=frida.__version__; abi=adb(["shell","getprop","ro.product.cpu.abi"],s).strip(); arch=ARCH.get(abi,"arm64")
        canon="frida-server-%s-android-%s"%(hv,arch); cdp="/data/local/tmp/%s"%canon
        # 1) ensure the canonical binary is on the device (download + push if missing)
        if canon not in sush("ls /data/local/tmp 2>/dev/null",s):
            self.log("[*] provisioning %s (arch=%s)…"%(canon,arch))
            local=os.path.join(tempfile.gettempdir(),canon)
            if not os.path.isfile(local):
                try:
                    raw=urllib.request.urlopen("https://github.com/frida/frida/releases/download/%s/%s.xz"%(hv,canon),timeout=120).read()
                    open(local,"wb").write(lzma.decompress(raw)); self.log("[+] downloaded matching frida-server")
                except Exception as e: self.log("[!] fetch frida-server failed: %s"%e); return False
            adb(["push",local,cdp],s)
        sush("chmod 755 %s"%cdp,s)
        # 2) stealth: run a RENAMED copy on a non-standard port so the app can't detect frida-server
        #    by its process name ("frida-server") or default port (27042).
        stealth=bool(self.opts.get("stealth"))
        if stealth:
            name=self._stealth_name; dp="/data/local/tmp/%s"%name; port=self._stealth_port
            csz=(sush("stat -c %%s %s 2>/dev/null"%cdp,s) or "").strip()
            dsz=(sush("stat -c %%s %s 2>/dev/null"%dp,s) or "").strip()
            if dsz!=csz or not csz:   # (re)create the renamed copy via cat> (fresh ctx so chmod works)
                sush("cat %s > %s 2>/dev/null; chmod 755 %s"%(cdp,dp,dp),s)
            launch="%s -l 127.0.0.1:%d"%(dp,port)
            self.log("[*] stealth frida-server: name=%s port=%d (hidden from name/port detection)"%(name,port))
        else:
            dp=cdp; launch=dp
        # 3) kill any prior servers (canonical + stealth) then start ours host-detached (stays root)
        sush("pkill -9 -f frida-server 2>/dev/null; pkill -9 -f %s 2>/dev/null; pkill -9 -f re.frida 2>/dev/null"%self._stealth_name,s); time.sleep(1)
        self.srv=subprocess.Popen([ADB,"-s",s,"shell","su","-c",launch],creationflags=NW,
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL)
        # connect: stealth uses adb-forward + remote device (a custom port can't spawn over USB);
        # non-stealth uses the normal USB device.
        self._fdev=None
        if stealth:
            time.sleep(2); adb(["forward","tcp:%d"%port,"tcp:%d"%port],s)
            try: self._fdev=frida.get_device_manager().add_remote_device("127.0.0.1:%d"%port)
            except Exception as e: tlog("[!] remote device add: %s"%e)
        for _ in range(12):
            time.sleep(1)
            try:
                d=self._fdev or frida.get_usb_device(timeout=4)
                d.enumerate_processes(); self._fdev=d
                self._ensured_stealth=stealth
                self.log("[+] frida-server %s running (root%s)"%(hv," · stealth" if stealth else "")); return True
            except Exception: pass
        self.log("[!] frida-server did not come up"); return False

    def _handle_diag(self,raw):
        """Receive the engine's FIDIAG detection report, enrich it (proxy/traffic/fixes), push to UI."""
        try: d=json.loads(raw)
        except Exception: return
        self.diag=d
        rep=dict(d)
        rep["pkg"]=self.cur_pkg; rep["port"]=self.port
        rep["proxy_listening"]=self._proxy_up()
        hooks=d.get("hooks",[]) or []
        rep["ssl_ok"]=any(h.get("ok") for h in hooks) or self._ssl_hooked
        is_flutter=bool(d.get("flutter"))
        recs=[]
        if d.get("rasp"):
            recs.append("RASP present (%s). If the app crashes: enable Stealth or Attach mode. Hardcore RASP (libts) may be uninterceptable."%", ".join(d["rasp"]))
        if not rep["ssl_ok"] and is_flutter:
            # THE #1 reason for 'no requests': libflutter loaded but no byte-pattern matched its
            # ssl_verify_peer_cert, so TLS stayed PINNED and the MITM handshake is rejected.
            recs.append("⚠ TLS still PINNED: libflutter.so is present but ssl_verify_peer_cert was NOT patched — "
                        "this is almost always why you see ZERO requests. Usually the app's Flutter/Dart version is "
                        "newer than the unpin byte-patterns. Wait ~10s (libflutter can load late); if still unpatched, "
                        "the patterns need updating for this Flutter version (see the engine log for 'no pattern matched').")
        elif not rep["ssl_ok"]:
            recs.append("No SSL hook confirmed yet — libflutter/libssl may load late; wait a few seconds or use Attach mode.")
        if not rep["proxy_listening"]:
            recs.append("No proxy on PC:%d — start Burp with an INVISIBLE listener on :%d."%(self.port,self.port))
        if not d.get("ssl"):
            recs.append("No known SSL backend detected — app may use a custom stack; verify in Burp.")
        recs.append("If traffic stays 0: turn OFF GlobalProtect/VPN and make sure you're using the intercepted app.")
        rep["recommend"]=recs
        self._ui("fiDiag(%s)"%json.dumps(rep))
        self.log("[*] compatibility report ready — see the 'Report' tab (arch=%s, ssl=%s, rasp=%s)"%(
            d.get("arch"), ",".join(d.get("ssl",[]))[:40] or "?", ",".join(d.get("rasp",[])) or "none"))

    # js_api: copy text to the Windows clipboard (for a captured request)
    def copy(self,text):
        try:
            subprocess.run("clip",input=(text or "")[:200000],text=True,creationflags=NW); return {"ok":True}
        except Exception as e:
            return {"ok":False,"err":str(e)}

    # js_api: export all captured requests to a text file next to the tool
    def export_requests(self,items):
        try:
            p=os.path.join(HERE,"captured_requests_%s.txt"%datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
            with open(p,"w",encoding="utf-8") as f:
                for it in (items or []):
                    f.write("### %s %s   [%s]\n"%(it.get("method",""),it.get("url",""),it.get("t","")))
                    f.write((it.get("data","") or "")+"\n\n")
            self.log("[+] exported %d captured items -> %s"%(len(items or []),p))
            return {"ok":True,"path":p,"n":len(items or [])}
        except Exception as e:
            self.log("[!] export failed: %s"%e); return {"ok":False,"err":str(e)}

    def _proxy_up(self):
        """Is a proxy actually listening on PC:port? (catches 'forgot to start Burp')."""
        try:
            c=socket.create_connection(("127.0.0.1",self.port),timeout=1.5); c.close(); return True
        except Exception:
            return False

    def _setup_routing(self,pkg):
        """One-time device prep: resolve uid, adb-reverse, route_localnet, iptables redirect."""
        s=self.serial
        r=(sush("stat -c %%u /data/data/%s 2>/dev/null"%pkg,s) or "").strip().splitlines()
        self.uid=r[0].strip() if r and r[0].strip().isdigit() else None
        if not self.uid: self.log("[!] cannot resolve uid"); return False
        self.log("[*] app uid %s"%self.uid)
        adb(["reverse","tcp:%d"%self.port,"tcp:%d"%self.port],s)
        self.orig_rln=(sush("sysctl -n net.ipv4.conf.all.route_localnet 2>/dev/null",s) or "0").strip() or "0"
        sush("sysctl -w net.ipv4.conf.all.route_localnet=1 2>/dev/null || echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null",s)
        u=self.uid
        # 1) redirect the app's HTTPS/HTTP (+ common alt-TLS 8443) to the PC proxy
        for d in (443,80,8443):
            sush("iptables -t nat -D OUTPUT -p tcp --dport %d -m owner --uid-owner %s -j REDIRECT --to-ports %d 2>/dev/null"%(d,u,self.port),s)
            sush("iptables -t nat -A OUTPUT -p tcp --dport %d -m owner --uid-owner %s -j REDIRECT --to-ports %d"%(d,u,self.port),s)
        # 2) BLOCK QUIC / HTTP-3 (UDP 443/80) so the app falls back to interceptable TCP TLS
        #    (Cronet/Chrome-net apps use QUIC over UDP, which a TCP redirect can't capture)
        for d in (443,80):
            sush("iptables -D OUTPUT -p udp --dport %d -m owner --uid-owner %s -j REJECT 2>/dev/null"%(d,u),s)
            sush("iptables -A OUTPUT -p udp --dport %d -m owner --uid-owner %s -j REJECT"%(d,u),s)
        # 3) FORCE IPv4: reject the app's IPv6 web traffic so happy-eyeballs falls back to v4 (which we capture)
        for proto in ("tcp","udp"):
            for d in (443,80,8443):
                sush("ip6tables -D OUTPUT -p %s --dport %d -m owner --uid-owner %s -j REJECT 2>/dev/null"%(proto,d,u),s)
                sush("ip6tables -A OUTPUT -p %s --dport %d -m owner --uid-owner %s -j REJECT 2>/dev/null"%(proto,d,u),s)
        self.log("[+] routing: reverse :%d + redirect 443/80/8443 + QUIC(UDP) blocked + IPv6 forced to v4 (uid %s)"%(self.port,u))
        return True

    def _traffic_monitor(self):
        """Watch the redirect rule's packet counters. Confirm flow, or print a fix-checklist
        when nothing is reaching the proxy (the classic 'no requests in Burp' problem)."""
        warned=False; flowed=False; last=-1
        while self.running and not self._stopping and self._alive:
            time.sleep(5)
            if not (self.running and self.uid): break
            out=sush("iptables -t nat -nvxL OUTPUT 2>/dev/null",self.serial,to=8) or ""
            pk=by=0
            for line in out.splitlines():
                if ("redir ports %d"%self.port) in line:
                    p=line.split()
                    if len(p)>=2 and p[0].isdigit(): pk+=int(p[0]); by+=int(p[1])
            if pk!=last:
                self._ui("fiTraffic(%d,%d)"%(pk,by)); last=pk
            if pk>0 and not flowed:
                flowed=True
                self.log("[+] traffic IS flowing to PC:%d (%d packets redirected). If you don't see it in Burp → check Burp has an INVISIBLE listener on :%d."%(self.port,pk,self.port))
            if pk==0 and not warned and (time.time()-(self._active_ts or 0))>15:
                warned=True
                self.log("[?] NO TRAFFIC captured yet — fix checklist:")
                self.log("    (1) turn OFF GlobalProtect / any VPN on the phone or PC (it reroutes traffic away from Burp)")
                self.log("    (2) actually USE the app (login / pull-to-refresh) — an idle app sends nothing")
                self.log("    (3) make sure Burp has an INVISIBLE proxy listener on :%d"%self.port)
                self.log("    (4) if still 0, the app may use a VPN/DNS path the redirect can't see — tell me and I'll add a full-tunnel mode")

    def _launch_and_get_pid(self,dev,pkg):
        """Launch the app normally (monkey) and wait for its process — used for attach."""
        s=self.serial
        adb(["shell","monkey","-p",pkg,"-c","android.intent.category.LAUNCHER","1"],s)
        deadline=time.time()+15
        while time.time()<deadline:
            ps=[p for p in dev.enumerate_processes() if pkg in (p.name or "")]
            if ps: return ps[0].pid
            time.sleep(0.5)
        return None

    def _inject(self,pkg,force_spawn=False):
        """(Re)spawn/attach the app and load the patch engine. Reusable for crash recovery."""
        s=self.serial
        dev=self._fdev or frida.get_usb_device(timeout=20)
        self.dev=dev; resume=False
        # stealth (remote-device) can't suspend-spawn reliably; and 'attach' mode is explicit.
        want_attach = self.opts.get("stealth") or (self.opts.get("mode")=="attach" and not force_spawn)
        if want_attach:
            ps=[p for p in dev.enumerate_processes() if pkg in (p.name or "")]
            pid=ps[0].pid if ps else self._launch_and_get_pid(dev,pkg)
            if not pid: self.log("[!] app did not start (for attach)"); return False
            # delayed-attach strategy: let the app pass more of its startup checks before we attach
            if self._launch_delay>0:
                self.log("[*] delayed attach: waiting %ds for app to settle…"%self._launch_delay); time.sleep(self._launch_delay)
            self.log("[*] attaching to pid %d"%pid)
        else:
            adb(["shell","am","force-stop",pkg],s); self.log("[*] spawning %s…"%pkg)
            try:
                pid=dev.spawn([pkg]); resume=True
            except (frida.TimedOutError, frida.TransportError, frida.NotSupportedError) as e:
                # hardened apps reject frida's suspended spawn — launch normally + attach instead
                self.log("[*] spawn failed (%s) — launching normally and attaching"%e)
                pid=self._launch_and_get_pid(dev,pkg)
                if not pid: self.log("[!] app did not start for attach"); return False
                resume=False
        self.session=dev.attach(pid); self.log("[*] target pid %d"%pid)
        self.session.on('detached', self._on_detached)  # detect app close/crash
        optsjs="globalThis.FI_OPTS=%s;\n"%json.dumps({k:self.opts[k] for k in ("ssl","root","vpn")})
        optsjs+="globalThis.FI_EXPERIMENTAL_UNPIN=%s;\n"%("1" if self.opts.get("expunpin") else "0")
        # ROOT-CAUSE guard for the "access violation" noise: wrap Memory.scan(Sync) so a scan that
        # hits an unreadable/guard page just skips that range (returns nothing) instead of throwing.
        # Runs BEFORE the bundle, so the bundle's pattern search no longer surfaces that error,
        # while the real pattern in valid memory is still found and patched.
        optsjs+=("try{var _ss=Memory.scanSync;Memory.scanSync=function(a,s,p){try{return _ss(a,s,p);}catch(e){return [];}};}catch(e){}\n"
                 "try{var _sa=Memory.scan;Memory.scan=function(a,s,p,cb){try{return _sa(a,s,p,cb);}catch(e){try{cb&&cb.onComplete&&cb.onComplete();}catch(_){}}};}catch(e){}\n")
        bjs=res("fi_bundle.js")
        if not os.path.isfile(bjs): bjs=os.path.join(HERE,"fi_bundle.js")
        def onmsg(m,_):
            t=m.get('type')
            if t in('log','send'):
                ps=str(m.get('payload'))
                if ps.startswith("FIREQ "): self._handle_req(ps[6:]); return
                if ps.startswith("FIDIAG "): self._handle_diag(ps[7:]); return
                if ("ssl_verify_peer_cert has been patched" in ps) or ("[+][ssl]" in ps) or \
                   ("unpinning active" in ps) or ("BoringSSL unpinned" in ps) or ("forced OK" in ps):
                    self._ssl_hooked=True
                self.log(ps)
            elif t=='error':
                d=str(m.get('description') or m); dl=d.lower()
                # benign engine noise that varies per device/memory layout — the bundle tries
                # multiple patterns and continues; interception is unaffected. Don't alarm.
                if any(k in dl for k in ("access violation","unable to intercept","invalid argument",
                                          "already watched","cannot read","memory.scan","unable to find")):
                    self.log("[*] (non-fatal engine note) %s — recovered automatically, interception unaffected"%d)
                else:
                    self.log("[!] frida: "+d)
        # opt-in anti-frida layer FIRST (separate, isolated script — can't break the main bundle)
        if self.opts.get("antifrida"):
            try:
                self._afsc=self.session.create_script(ANTIFRIDA_JS); self._afsc.on('message',onmsg); self._afsc.load()
            except Exception as e: self.log("[!] anti-frida load failed (continuing): %s"%e)
        if self.opts.get("stealth"):
            # stealth: native-only unpin (no frida-java-bridge = far smaller footprint for RASP apps)
            self.log("[*] stealth: native-only Flutter unpin (no Java bridge)")
            sc=self.session.create_script(optsjs+NATIVE_UNPIN_JS)
        else:
            sc=self.session.create_script(optsjs+open(bjs,encoding="utf-8").read())
        sc.on('message',onmsg); sc.load()
        # request-capture layer (feeds the Requests tab); isolated so it can't break the bundle.
        # skipped when the in-tool MITM proxy is on (the proxy captures everything, incl. pure-Dart).
        if not self.opts.get("mitmcap"):
            try:
                self._capsc=self.session.create_script(CAPTURE_JS); self._capsc.on('message',onmsg); self._capsc.load()
            except Exception as e: self.log("[!] request-capture load failed (continuing): %s"%e)
        # detection + diagnostics + expanded native SSL unpin (emits FIDIAG compatibility report)
        try:
            ejs=res("fi_engine.js")
            if not os.path.isfile(ejs): ejs=os.path.join(HERE,"fi_engine.js")
            if os.path.isfile(ejs):
                self._ensc=self.session.create_script(open(ejs,encoding="utf-8").read()); self._ensc.on('message',onmsg); self._ensc.load()
        except Exception as e: self.log("[!] engine/diagnostics load failed (continuing): %s"%e)
        if resume: self.dev.resume(pid)
        self.running=True; self._active_ts=time.time()
        self.status("active","INTERCEPTING %s — proxy PC:%d (invisible mode)"%(pkg,self.port))
        self.log("[+] ACTIVE — patches applied; point your proxy (invisible) at PC :%d"%self.port)
        threading.Thread(target=self._traffic_monitor,daemon=True).start()  # watch/diagnose traffic flow
        return True

    def _run(self,pkg):
        s=self.serial
        try:
            # if something's still active (or stuck), tear it down first so we can always (re)start
            if self.running or self.session or self.uid:
                self.log("[*] previous session active — stopping it before restart")
                self._teardown()
            self.want_running=True; self.cur_pkg=pkg; self._rapid=0; self._total_recov=0; self._strat=0; self._ssl_hooked=False
            self.status("starting","Starting %s…"%pkg)
            if "uid=0" not in sush("id",s,to=15):
                self.log("[!] device not rooted (su) — cannot intercept"); return self._reset()
            if not self.ensure_frida(s): return self._reset()
            if not self._setup_routing(pkg): return self._reset()
            if self.opts.get("mitmcap"):
                self._start_mitm()   # tool becomes the proxy
            elif not self._proxy_up():
                self.log("[?] heads-up: nothing is listening on PC:%d yet — start Burp with an INVISIBLE listener on :%d, or requests will be refused."%(self.port,self.port))
            if not self._inject(pkg): return self._reset()
        except Exception as e:
            self.log("[!] failed: %s"%e); tlog(traceback.format_exc()); self._reset()

    def _diagnose(self,reason,dt):
        """Tell the user WHY it crashed and exactly which option to enable for this crash type."""
        st=self.opts.get("stealth"); af=self.opts.get("antifrida"); mode=self.opts.get("mode")
        if reason in ("connection-terminated","device-lost","transport-error","server-terminated"):
            self.log("[?] DIAGNOSIS: the frida-server connection dropped — usually frida-server detection. → Enable 'Stealth (experimental)'. (Auto-recover will reprovision the server.)")
        elif reason=="process-terminated" and dt<5:
            if not st:
                self.log("[?] DIAGNOSIS: app self-terminated %.0fs after launch — anti-tamper/frida-server detection. → Turn ON 'Stealth (experimental)' (keep 'Anti-detection' ON)."%dt)
            elif mode!="attach":
                self.log("[?] DIAGNOSIS: still self-terminating with Stealth ON — try 'Attach' mode: open the app yourself, let it load, then click it. (Spawn-time checks are the hardest.)")
            else:
                self.log("[?] DIAGNOSIS: app escalates to a hard crash (SIGSEGV/SIGKILL) our keep-alive can't block. This app needs a per-app anti-tamper patch — generic options can't beat it.")
        elif reason=="process-terminated":
            self.log("[?] DIAGNOSIS: app ran %.0fs then ended — likely a normal close, a screen change, or a periodic integrity check. Auto-recover will re-open it."%dt)
        else:
            self.log("[?] DIAGNOSIS: ended (%s). Auto-recover will retry; if it loops, enable 'Stealth' or use 'Attach' mode."%reason)
        if not af: self.log("[?] TIP: keep 'Anti-detection' ON — it blocks the self-kill calls (you saw 'kept app alive' above).")

    def _on_detached(self,reason,*a):
        """Frida session ended — app closed, crashed, or we detached."""
        if self._stopping: return            # we triggered it via teardown; already cleaning up
        self.session=None; self.running=False
        dt=time.time()-(self._active_ts or 0)
        self._diagnose(reason,dt)
        if self.want_running and self.auto_recover and not self._recovering:
            # global cap: stop the endless re-open loop for apps that keep self-killing
            self._total_recov = getattr(self,"_total_recov",0)+1
            if self._total_recov > 6:
                self.log("[!] %s has re-spawned %d times — it keeps self-terminating (anti-tamper)."%(self.cur_pkg,self._total_recov))
                self.log("[*] auto-recover STOPPED to avoid endless re-opens. Turn it back on to retry, or this app needs a per-app anti-tamper patch.")
                threading.Thread(target=self._teardown,daemon=True).start()
                return
            # ADAPTIVE LAUNCH LADDER: if the app self-terminates within seconds, escalate the
            # strategy automatically (spawn -> attach -> delayed-attach -> stealth) before giving up.
            self._rapid = self._rapid+1 if dt < 8 else 0
            if self._rapid >= 2:
                if self._escalate():        # advanced to a stronger strategy -> retry with it
                    self._rapid=0
                    self.status("starting","App fought back — escalating launch strategy…")
                    threading.Thread(target=self._recover,args=(reason,),daemon=True).start()
                    return
                # exhausted all strategies
                self.log("[!] %s self-terminates on every launch strategy (spawn/attach/delayed/stealth) — it ships anti-tamper/RASP that beats generic instrumentation."%self.cur_pkg)
                self.log("[*] auto-recover HALTED. This app needs a per-app anti-tamper patch (see the Report tab for the detected RASP).")
                threading.Thread(target=self._teardown,daemon=True).start()
                return
            self.log("[!] app ended (%s, after %.1fs) — AUTO-RECOVER"%(reason,dt))
            self.status("starting","App crashed — auto-recovering…")
            threading.Thread(target=self._recover,args=(reason,),daemon=True).start()
        else:
            self.log("[!] app closed (%s) — stopping & restoring device"%reason)
            threading.Thread(target=self._teardown,daemon=True).start()

    # adaptive launch ladder: each step makes instrumentation harder to detect
    _STRATS=[
        {"name":"spawn",        "mode":"spawn",  "stealth":False, "delay":0},
        {"name":"attach",       "mode":"attach", "stealth":False, "delay":0},
        {"name":"delayed-attach","mode":"attach","stealth":False, "delay":6},
        {"name":"stealth+attach","mode":"attach","stealth":True,  "delay":6},
    ]
    def _escalate(self):
        """Advance to the next launch strategy; return True if one was applied, False if exhausted."""
        if self._strat+1 >= len(self._STRATS): return False
        self._strat+=1
        st=self._STRATS[self._strat]
        self.opts["mode"]=st["mode"]; self.opts["stealth"]=st["stealth"]; self._launch_delay=st["delay"]
        self.log("[*] ADAPTIVE: switching to '%s' launch strategy (mode=%s stealth=%s delay=%ds)"%(st["name"],st["mode"],st["stealth"],st["delay"]))
        return True

    def _frida_ok(self):
        """True only if our frida-server is ACTUALLY running on the device (a dead server can
        still let enumerate() pass while spawn() fails). Checks the stealth name when stealth is on."""
        try:
            pat=self._stealth_name if self.opts.get("stealth") else "frida-server"
            out=sush("pgrep -f %s 2>/dev/null | head -1"%pat,self.serial,to=8) or ""
            if not out.strip().split("\n")[0].strip().isdigit(): return False
            (self._fdev or frida.get_usb_device(timeout=6)).enumerate_processes(); return True
        except Exception:
            return False

    def _recover(self,reason="?"):
        """Self-heal after a crash: keep routing in place, re-spawn + re-inject the patch engine.
        If the frida-server itself died (connection-terminated / 'need Gadget'), reprovision it."""
        if self._recovering: return
        self._recovering=True
        # if the DEVICE itself is gone, don't retry-spam — stop with a clear message
        if reason=="device-lost" or (self.serial and self.serial not in adb(["devices"],to=10)):
            self.log("[!] device disconnected — cannot recover. Reconnect the phone and start again.")
            self._recovering=False; self._teardown(); return
        # a dropped frida connection (vs. just the app process dying) means the server needs reviving
        server_dead = reason in ("connection-terminated","device-lost","server-terminated","transport-error")
        # if the adaptive ladder just switched stealth on/off, the frida-server must be re-provisioned in that mode
        if self.opts.get("stealth")!=self._ensured_stealth: server_dead=True
        try:
            for attempt in range(1,6):
                if self._stopping or not self.want_running: return
                self.log("[*] recovery attempt %d/5 (reason=%s)…"%(attempt,reason))
                self.status("starting","Auto-recovering (attempt %d/5)…"%attempt)
                try:
                    # revive frida-server if it died or is unhealthy (THE fix for the 'need Gadget' error)
                    if server_dead or not self._frida_ok():
                        self.log("[*] frida-server not healthy — reprovisioning")
                        if not self.ensure_frida(self.serial):
                            raise RuntimeError("frida-server reprovision failed")
                        server_dead=False
                    # routing may have been lost if the device rebooted — re-assert it
                    if not self.uid: self._setup_routing(self.cur_pkg)
                    if self._inject(self.cur_pkg, force_spawn=True):
                        self.log("[+] RECOVERED — app re-spawned and patches re-applied"); return
                except frida.NotSupportedError as e:
                    # "need Gadget to attach on jailed Android" => frida-server is gone; force reprovision
                    self.log("[!] frida-server gone (%s) — will reprovision next attempt"%e); server_dead=True
                except Exception as e:
                    self.log("[!] recovery attempt %d failed: %s"%(attempt,e)); tlog(traceback.format_exc())
                # backoff before next try (interruptible)
                for _ in range(int(min(2*attempt,8))*2):
                    if self._stopping or not self.want_running: return
                    time.sleep(0.5)
            self.log("[!] auto-recover gave up after 5 attempts — stopping & restoring device")
            self._recovering=False; self._teardown()
        finally:
            self._recovering=False

    def _reset(self):
        self.status("idle","Not intercepting."); self.running=False; self.want_running=False
        return False

    # js_api: toggle crash auto-recovery from the UI
    def set_auto(self,on):
        self.auto_recover=bool(on)
        self.log("[*] auto-recover on crash: %s"%("ON" if self.auto_recover else "OFF"))
        return {"ok":True}

    # js_api: return immediately, do the teardown on a worker thread so the button can't freeze the UI
    def stop(self):
        self.want_running=False   # cancel any in-flight auto-recovery
        threading.Thread(target=self._teardown,daemon=True).start()
        return {"ok":True}

    def _teardown(self):
        """Full teardown — restore the device to its original state. Reentrancy-safe;
        all device calls use SHORT timeouts so it can never hang the window."""
        if self._stopping: return {"ok":True}
        self._stopping=True
        self.want_running=False   # this is a real stop — don't let recovery fight it
        # reset UI state immediately so 'already running' clears even if teardown is slow
        self.running=False
        self.status("starting","Stopping — restoring device…")
        try:
            if self._mitm: self._mitm.stop(); self._mitm=None   # stop the in-tool capture proxy
        except Exception: pass
        s=self.serial
        try:
            # 1) detach frida (removes all in-app hooks; pinning restored automatically)
            try:
                if self.session: self.session.detach()
            except Exception as e: tlog("[!] detach: %s"%e)
            self.session=None
            if s:
                # 2) remove OUR rules for this uid (redirect + QUIC block + IPv6 force)
                if self.uid:
                    u=self.uid
                    for d in (443,80,8443):
                        sush("iptables -t nat -D OUTPUT -p tcp --dport %d -m owner --uid-owner %s -j REDIRECT --to-ports %d 2>/dev/null"%(d,u,self.port),s,to=10)
                    for d in (443,80):
                        sush("iptables -D OUTPUT -p udp --dport %d -m owner --uid-owner %s -j REJECT 2>/dev/null"%(d,u),s,to=10)
                    for proto in ("tcp","udp"):
                        for d in (443,80,8443):
                            sush("ip6tables -D OUTPUT -p %s --dport %d -m owner --uid-owner %s -j REJECT 2>/dev/null"%(proto,d,u),s,to=10)
                # 3) belt-and-suspenders: delete ANY leftover redirect-to-our-port rules
                for _ in range(8):
                    out=sush("iptables -t nat -S OUTPUT 2>/dev/null",s,to=10)
                    line=next((l for l in out.splitlines() if ("--to-ports %d"%self.port) in l and l.startswith("-A ")), None)
                    if not line: break
                    sush("iptables -t nat -D"+line[2:],s,to=10)
                # 4) clear the adb-reverse tunnel (and the stealth adb-forward, if any)
                adb(["reverse","--remove","tcp:%d"%self.port],s,to=10)
                adb(["forward","--remove","tcp:%d"%self._stealth_port],s,to=10)
                # 5) restore route_localnet to its original value
                if getattr(self,"orig_rln",None) is not None:
                    sush("sysctl -w net.ipv4.conf.all.route_localnet=%s 2>/dev/null"%self.orig_rln,s,to=10)
                # 6) stop the frida-server WE launched
                try:
                    if self.srv: self.srv.terminate()
                except Exception as e: tlog("[!] srv.terminate: %s"%e)
                sush("pkill -9 -f frida-server 2>/dev/null; pkill -9 -f %s 2>/dev/null"%self._stealth_name,s,to=10)
            self.uid=None; self.srv=None
            self.log("[+] stopped — device restored to normal (hooks removed, iptables cleared, reverse removed, route_localnet restored, frida-server stopped)")
            self.status("idle","Stopped — device restored to normal.")
        except Exception as e:
            self.log("[!] stop error: %s"%e); tlog(traceback.format_exc())
            self.status("idle","Stopped (with warnings — see log).")
        finally:
            self._stopping=False
        return {"ok":True}

def main():
    tlog("="*64)
    tlog("Flutter Interceptor starting  (frida loads on first intercept)")
    tlog("ADB: %s"%ADB)
    tlog("log file: %s"%LOGFILE)
    tlog("="*64)
    api=Api()
    html=res(os.path.join("webui","index.html"))
    if not os.path.isfile(html): html=os.path.join(HERE,"webui","index.html")
    win=webview.create_window("Flutter Interceptor", html, js_api=api, width=1120, height=760, min_size=(960,660), background_color="#0f1115")
    api.win=win
    # batched log flusher (keeps a chatty frida script from flooding/freezing the WebView)
    threading.Thread(target=api._pump,daemon=True).start()
    # on window close / abort -> restore the device to normal (bounded by short timeouts)
    def _on_closed():
        tlog("[*] window closed — running teardown")
        api._alive=False
        try: api._teardown()
        except Exception: tlog(traceback.format_exc())
    try: win.events.closed += _on_closed
    except Exception: pass
    try:
        webview.start()
    except Exception:
        tlog("[!] FATAL in webview.start():\n"+traceback.format_exc())
        raise

if __name__=="__main__":
    try:
        main()
    except Exception:
        tlog("[!] FATAL:\n"+traceback.format_exc())
        try: input("\n[crashed — press Enter to close]")  # keep console open on crash
        except Exception: pass
