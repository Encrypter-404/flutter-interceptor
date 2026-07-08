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
    if(!flutterPatched){ if(tries<25) setTimeout(unpinFlutter,800); else finish("Flutter ssl_verify_peer_cert","no matching pattern (Dart/Flutter version?)"); }
    else diag();
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
