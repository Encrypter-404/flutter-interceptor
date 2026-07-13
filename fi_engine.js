// fi_engine.js — native detection + diagnostics + expanded SSL unpin (no Java bridge; runs
// alongside the main bundle). Emits a structured FIDIAG report and per-hook status.
(function(){
  var R={arch:Process.arch, platform:Process.platform, flutter:null, ssl:[], net:[], rasp:[], root:[], hooks:[], notes:[]};
  function push(a,v){ if(a.indexOf(v)<0) a.push(v); }
  function gx(n){ try{ if(Module.findGlobalExportByName) return Module.findGlobalExportByName(n); }catch(e){}
    try{ var m=Process.findModuleByName("libssl.so"); if(m){var e=m.findExportByName(n); if(e) return e;} }catch(e){} return null; }

  // ---------- 1) module / library classification (re-run at report time so late-loaded libs appear) ----------
  var engineScanned=false;
  function classify(){
    R.ssl=[]; R.net=[]; R.rasp=[]; R.root=[];   // recompute fresh
    var names=[]; try{ names=Process.enumerateModules().map(function(m){return (m.name||"").toLowerCase();}); }catch(e){}
    function has(re){ return names.some(function(n){return re.test(n);}); }
    if(has(/libflutter\.so/)){ R.flutter=R.flutter||{}; R.flutter.lib="libflutter.so"; }
    if(has(/libapp\.so/)){ R.flutter=R.flutter||{}; R.flutter.dart="libapp.so (Dart AOT)"; }
    if(has(/libssl\.so/)) push(R.ssl,"BoringSSL/OpenSSL (libssl.so)");
    if(has(/libcrypto\.so/)) push(R.ssl,"libcrypto.so");
    if(has(/conscrypt/)) push(R.ssl,"Conscrypt (native)");
    if(has(/libflutter\.so/)) push(R.ssl,"Flutter BoringSSL (static in libflutter)");
    if(has(/cronet/)) push(R.net,"Cronet");
    if(has(/libcurl/)) push(R.net,"libcurl");
    if(has(/okhttp/)) push(R.net,"OkHttp (native)");
    [[/libts\.so/,"libts (commercial RASP)"],[/promon|blueshield|shield/,"Promon SHIELD"],
     [/appdome/,"Appdome"],[/guardsquare|dexguard|ixguard/,"Guardsquare"],[/build38|libtak/,"Build38 T.A.K"],
     [/libtoolchecker/,"RootBeer(native)"],[/libucs-credential/,"signature-check(ucs)"],
     [/tamper|integrity|antifrida|antihook|libdetect/,"anti-tamper lib"]].forEach(function(s){ if(has(s[0])) push(R.rasp,s[1]); });
    if(has(/rootbeer|libtoolchecker/)) push(R.root,"RootBeer");
    // Flutter engine version string (once, after libflutter is present)
    if(!engineScanned){ try{ var mf=Process.findModuleByName("libflutter.so");
      if(mf){ engineScanned=true; R.flutter=R.flutter||{lib:"libflutter.so"};
        Memory.scanSync(mf.base, Math.min(mf.size,0x600000), "46 6c 75 74 74 65 72 20 45 6e 67 69 6e 65").slice(0,1).forEach(function(h){
          try{ var s=h.address.readCString(); if(s) R.flutter.engine=s.substring(0,90); }catch(e){} });
      }
    }catch(e){} }
  }
  classify();

  // ---------- 3) expanded native SSL unpin ----------
  // (a) Flutter static BoringSSL ssl_verify_peer_cert — multi-pattern, multi-ABI
  var PAT={
    arm64:[ {p:"F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",r:0},
            {p:"F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",r:0},
            {p:"FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",r:0},
            {p:"FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9",r:1} ],
    arm:[   {p:"2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8",r:0} ],
    x64:[   {p:"55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? ?? 0? 00 00 4D 85 ?? 74 1? 4D 8B",r:0} ]
  };
  var arch=Process.arch, plist=PAT[arch==="ia32"?"x86":arch]||PAT.arm64;
  var flutterPatched=false, tries=0;
  function unpinFlutter(){
    if(flutterPatched) return;
    tries++;
    var m=Process.findModuleByName("libflutter.so");
    if(!m){ if(tries<25) setTimeout(unpinFlutter,800); else finish("Flutter ssl_verify_peer_cert","libflutter.so not loaded"); return; }
    var end=m.base.add(m.size);
    Process.enumerateRanges('r-x').forEach(function(rg){
      if(flutterPatched) return;
      if(rg.base.compare(m.base)<0||rg.base.compare(end)>=0) return;
      plist.forEach(function(p){ try{ Memory.scanSync(rg.base,rg.size,p.p).forEach(function(hit){
        try{ Interceptor.replace(hit.address,new NativeCallback(function(){return p.r;},'int',['pointer','int']));
             flutterPatched=true; R.hooks.push({name:"Flutter ssl_verify_peer_cert",ok:true,at:hit.address.toString()});
             send("[+][engine] Flutter BoringSSL unpinned @"+hit.address); }catch(e){} }); }catch(e){} });
    });
    if(!flutterPatched){
      if(tries<25){ setTimeout(unpinFlutter,800); return; }
      // STATIC PATTERNS EXHAUSTED. Run the version-independent locator (handshake.cc __FILE__ xref).
      // If it finds OPENSSL_PUT_ERROR sites -> report them in the Report tab (proves it's BoringSSL +
      // locates the verify area). AUTO-PATCHING is gated behind FI_EXPERIMENTAL_UNPIN (set by the
      // orchestrator only when the user explicitly opts in) because patching the wrong handshake.cc
      // function (e.g. ssl_run_handshake) to return 0 would brick the handshake. So: diagnose always,
      // patch only when the flag is set.
      var vi = locateHandshakeCcXrefs(m);
      if(vi && vi.xrefs>0){
        R.notes.push("version-independent: "+vi.xrefs+" OPENSSL_PUT_ERROR(handshake.cc) sites located");
        if(vi.patched>0){
          flutterPatched=true; R.hooks.push({name:"ssl_verify_peer_cert (xref, EXPERIMENTAL)",ok:true,at:"handshake.cc"});
          send("[+][engine] Flutter BoringSSL unpinned via OPENSSL_PUT_ERROR xref (EXPERIMENTAL) — "+vi.patched+" site(s)");
          diag(); return;
        }
        R.notes.push("leave FI_EXPERIMENTAL_UNPIN=1 to auto-patch (can crash the app if it mis-IDs the function)");
      }
      finish("Flutter ssl_verify_peer_cert","no matching pattern (Dart/Flutter version?)"+(vi&&vi.xrefs?(" — "+vi.xrefs+" handshake.cc xrefs found (see Report)"):""));
    }
    else diag();
  }

  // ---------- (a2) version-independent Flutter unpin via OPENSSL_PUT_ERROR __FILE__ string ----------
  // BoringSSL's OPENSSL_PUT_ERROR embeds __FILE__ as a string literal. ssl_verify_peer_cert lives in
  // handshake.cc, so finding "ssl/handshake.cc" + its ADRP xref locates the verify-error area without
  // any per-version byte pattern. Returns {xrefs:N, patched:N}. Patches ONLY when globalThis.
  // FI_EXPERIMENTAL_UNPIN is truthy (orchestrator opt-in) — otherwise this is a pure diagnostic.
  function locateHandshakeCcXrefs(m){
    try{
      var end=m.base.add(m.size);
      var needle="73 73 6c 2f 68 61 6e 64 73 68 61 6b 65 2e 63 63";   // "ssl/handshake.cc"
      var strs=[]; Process.enumerateRanges('r--').forEach(function(rg){
        if(rg.base.compare(m.base)<0||rg.base.compare(end)>=0) return;
        try{ Memory.scanSync(rg.base,rg.size,needle).forEach(function(h){ strs.push(h.address); }); }catch(e){}
      });
      if(!strs.length){ send("[*][engine] handshake.cc string not found (engine may use a different path)"); return {xrefs:0,patched:0}; }
      var want = (globalThis.FI_EXPERIMENTAL_UNPIN) ? true : false;
      var xrefs=0, patched=0;
      Process.enumerateRanges('r-x').forEach(function(rg){
        if(rg.base.compare(m.base)<0||rg.base.compare(end)>=0) return;
        if(patched>=3) return;
        try{
          var buf=Memory.readByteArray(rg.base, Math.min(rg.size, 0x800000)); if(!buf) return;
          var b=new Uint8Array(buf); var len=b.length;
          for(var off=0; off+8<len; off+=4){
            // 32-bit instruction words (little-endian)
            var w=b[off]|(b[off+1]<<8)|(b[off+2]<<16)|((b[off+3]<<24)>>>0);
            var w2=b[off+4]|(b[off+5]<<8)|(b[off+6]<<16)|((b[off+7]<<24)>>>0);
            if((w & 0x9F000000)>>>0 !== 0x90000000) continue;        // ADRP
            var rd=w & 0x1f;
            if((w2 & 0xFF000000)>>>0 !== 0x91000000) continue;       // ADD (imm, 64-bit, shift0)
            if((w2 & 0x1f)!==rd || ((w2>>5)&0x1f)!==rd) continue;   // ADD Rd==Rn==ADRP Rd
            var immlo=(w>>>29)&0x3;
            var immhi=(w>>>5)&0x7ffff;                               // 19 bits
            var imm=((immhi<<2)|immlo); if(imm & (1<<20)) imm=imm-(1<<21);  // sign-extend 21-bit
            var adrpAddr=rg.base.add(off);
            var tgtPage=adrpAddr.and(ptr("0xFFFFFFFFFFFFF000")).add(ptr(imm*0x1000));
            var addImm=(w2>>>10)&0xfff;                              // imm12
            var tgtAddr=tgtPage.add(addImm);
            for(var si=0; si<strs.length; si++){
              if(tgtAddr.equals(strs[si])){ xrefs++;
                if(want){ var p=walkBackToPrologue(rg.base, off);
                  if(p){ try{ Interceptor.replace(p,new NativeCallback(function(){return 0;},'int',['pointer','int']));
                    patched++; send("[+][engine] EXP xref patched @"+p); }catch(e){} } }
                break;
              }
            }
          }
        }catch(e){}
      });
      if(xrefs>0) R.notes.push("handshake.cc: "+xrefs+" OPENSSL_PUT_ERROR xref(s)"+(want?(" — patched "+patched):" (diagnose-only; enable FI_EXPERIMENTAL_UNPIN to patch)"));
      return {xrefs:xrefs, patched:patched};
    }catch(e){ send("[!][engine] version-independent error: "+e); return {xrefs:0,patched:0}; }
  }

  function walkBackToPrologue(rgBase, off){
    try{
      var sz=Math.min(off+0x4000,0x800000); var buf=Memory.readByteArray(rgBase,sz); if(!buf) return null;
      var b=new Uint8Array(buf);
      for(var p=off; p>=8; p-=4){
        var b3=b[p+3],b2=b[p+2],b1=b[p+1];
        // str x30,[sp,#-imm]!  ->  "F? 0F 1C F8"
        if((b3&0xFF)===0xF8 && b2===0x1C && b1===0x0F) return rgBase.add(p);
        // stp x29,x30,[sp,#-imm]! ->  "F? ?? 01 A9" family; commonly "FF 03 01 D1"/"F? 43 01 D1"
        if(b3===0xD1 && (b2&0x03)===0x01 && b1===0xFF) return rgBase.add(p);
      }
      return null;
    }catch(e){ return null; }
  }
  // (b) libssl.so exported verify (covers Conscrypt/Cronet/OkHttp-native/any BoringSSL)
  function hook(name,ret){
    try{ var a=gx(name); if(!a) return false;
      Interceptor.replace(a,new NativeCallback(function(){return ret;},'int',(name==="SSL_get_verify_result")?['pointer']:['pointer','int']));
      R.hooks.push({name:name+" (libssl)",ok:true}); send("[+][engine] "+name+" forced OK (libssl)"); return true;
    }catch(e){ return false; }
  }
  // SSL_get_verify_result -> 0 (X509_V_OK); safest generic native unpin
  hook("SSL_get_verify_result",0);
  // SSL_set_custom_verify / SSL_CTX_set_custom_verify callback replacement (boringssl) — set verify OK
  try{ var scv=gx("SSL_CTX_set_custom_verify")||gx("SSL_set_custom_verify");
    if(scv){ var orig=new NativeFunction(scv,'void',['pointer','int','pointer']);
      Interceptor.replace(scv,new NativeCallback(function(ctx,mode,cb){
        var ok=new NativeCallback(function(){return 0;},'int',['pointer','pointer']);
        orig(ctx,0,ok); R.hooks.push({name:"SSL_CTX_set_custom_verify",ok:true}); },'void',['pointer','int','pointer']));
      send("[+][engine] custom_verify neutralized (BoringSSL)");
    }
  }catch(e){}

  function finish(name,note){ R.hooks.push({name:name,ok:false,note:note}); R.notes.push(note); diag(); }
  function diag(){ try{ classify(); }catch(e){} send("FIDIAG "+JSON.stringify(R)); }

  // report immediately, again after unpin, and a final refreshed report once libs have loaded
  diag();
  unpinFlutter();
  setTimeout(diag, 4000);
  setTimeout(diag, 9000);   // final refreshed report (libflutter + hooks settled)
})();
