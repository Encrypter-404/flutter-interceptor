"""
fi_mitm.py — lightweight transparent TLS MITM capture proxy for Flutter Interceptor.

Because the frida engine already UNPINS TLS in the app, the app trusts any certificate — so
this proxy can terminate TLS itself (choosing the leaf cert by the ClientHello SNI), read the
plaintext HTTP / WebSocket, forward it upstream so the app keeps working, and hand every
request/response to a callback for the tool's Requests tab.

Works for ANY app (Flutter/Dart, Cronet, OkHttp, native) with no per-version byte patterns.
"""
import os, ssl, socket, threading, datetime, ipaddress

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


# ---------------------------------------------------------------- CA / leaf certs
class CertStore:
    def __init__(self, cadir):
        self.dir = cadir
        os.makedirs(cadir, exist_ok=True)
        self.ca_cert_pem = os.path.join(cadir, "fi_ca.crt")
        self.ca_key_pem = os.path.join(cadir, "fi_ca.key")
        self._leaf = {}           # host -> (certfile, keyfile)
        self._lock = threading.Lock()
        self._ca_cert = None; self._ca_key = None
        self._ensure_ca()

    def _ensure_ca(self):
        if os.path.isfile(self.ca_cert_pem) and os.path.isfile(self.ca_key_pem):
            self._ca_key = serialization.load_pem_private_key(open(self.ca_key_pem, "rb").read(), None)
            self._ca_cert = x509.load_pem_x509_certificate(open(self.ca_cert_pem, "rb").read())
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Flutter Interceptor CA"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FlutterInterceptor")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                        key_encipherment=False, content_commitment=False, data_encipherment=False,
                        key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))
        open(self.ca_key_pem, "wb").write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        open(self.ca_cert_pem, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        self._ca_key, self._ca_cert = key, cert

    def leaf(self, host):
        host = host or "localhost"
        with self._lock:
            if host in self._leaf:
                return self._leaf[host]
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:63])])
            now = datetime.datetime.now(datetime.timezone.utc)
            try: san = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError: san = x509.DNSName(host)
            cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(self._ca_cert.subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=825))
                    .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                    .sign(self._ca_key, hashes.SHA256()))
            cf = os.path.join(self.dir, "leaf_%s.crt" % _safe(host))
            kf = os.path.join(self.dir, "leaf_%s.key" % _safe(host))
            open(cf, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
            open(kf, "wb").write(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            self._leaf[host] = (cf, kf)
            return cf, kf


def _safe(h): return "".join(c if c.isalnum() or c in ".-" else "_" for c in h)[:60]
def _is_ip(h):
    try: ipaddress.ip_address(h); return True
    except Exception: return False


# ---------------------------------------------------------------- HTTP / WS helpers
def _read_headers(rf):
    """Read request/response line + headers. Returns (first_line, header_dict, raw_bytes)."""
    raw = b""; first = b""
    line = rf.readline()
    if not line: return None, None, b""
    first = line.rstrip(b"\r\n"); raw += line
    hdrs = {}
    while True:
        line = rf.readline()
        if not line or line in (b"\r\n", b"\n"): raw += line; break
        raw += line
        if b":" in line:
            k, v = line.split(b":", 1); hdrs[k.strip().lower()] = v.strip()
    return first.decode("latin1"), hdrs, raw


def _read_body(rf, hdrs):
    """Read a message body per Content-Length / chunked. Returns raw bytes (best-effort, capped)."""
    if not hdrs: return b""
    te = hdrs.get(b"transfer-encoding", b"").lower()
    if b"chunked" in te:
        out = b""
        while len(out) < 2_000_000:
            ln = rf.readline();
            if not ln: break
            out += ln
            try: n = int(ln.strip().split(b";")[0], 16)
            except Exception: break
            if n == 0:
                out += rf.readline(); break
            chunk = rf.read(n + 2); out += chunk
        return out
    cl = hdrs.get(b"content-length")
    if cl:
        try: n = min(int(cl), 4_000_000)
        except Exception: n = 0
        return rf.read(n)
    return b""


def _ws_frames(buf):
    """Yield decoded text/binary WebSocket frame payloads from a raw buffer."""
    i = 0; out = []
    while i + 2 <= len(buf):
        b0 = buf[i]; b1 = buf[i + 1]; op = b0 & 0x0f; masked = b1 & 0x80; ln = b1 & 0x7f; off = i + 2
        if ln == 126:
            if off + 2 > len(buf): break
            ln = (buf[off] << 8) | buf[off + 1]; off += 2
        elif ln == 127:
            break
        mask = None
        if masked:
            if off + 4 > len(buf): break
            mask = buf[off:off + 4]; off += 4
        if off + ln > len(buf): break
        payload = bytearray(buf[off:off + ln])
        if mask:
            for k in range(len(payload)): payload[k] ^= mask[k & 3]
        if op in (1, 2, 0):
            out.append(payload.decode("utf-8", "replace"))
        i = off + ln
    return out


# ---------------------------------------------------------------- the proxy
class MitmProxy:
    def __init__(self, port, on_event, cadir, log=lambda m: None, debug=True):
        self.port = int(port); self.on_event = on_event; self.log = log
        self.store = CertStore(cadir) if _HAVE_CRYPTO else None
        self._srv = None; self._alive = False; self._threads = []
        self._debug = debug

    def ca_path(self): return self.store.ca_cert_pem if self.store else None

    def start(self):
        if not _HAVE_CRYPTO:
            self.log("[!] MITM proxy needs the 'cryptography' package — run setup.bat"); return False
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.bind(("127.0.0.1", self.port)); self._srv.listen(128)
        except Exception as e:
            self.log("[!] MITM proxy could not bind :%d — %s (is Burp using it?)" % (self.port, e)); return False
        self._alive = True
        threading.Thread(target=self._accept, daemon=True).start()
        self.log("[+] in-tool capture proxy listening on 127.0.0.1:%d (CA: %s)" % (self.port, self.store.ca_cert_pem))
        return True

    def stop(self):
        self._alive = False
        try:
            if self._srv: self._srv.close()
        except Exception: pass
        self._srv = None

    def _accept(self):
        while self._alive:
            try:
                c, _ = self._srv.accept()
            except Exception:
                break
            t = threading.Thread(target=self._handle, args=(c,), daemon=True); t.start()

    def _handle(self, client):
        try:
            client.settimeout(30)
            peek = client.recv(8, socket.MSG_PEEK)
            if not peek: client.close(); return
            if peek[0] == 0x16:                    # TLS ClientHello
                self._handle_tls(client)
            else:                                  # plain HTTP
                self._handle_plain(client)
        except Exception as e:
            if self._debug: self.log("[mitm] handle err: %s" % e)
            try: client.close()
            except Exception: pass

    # ---- TLS: read SNI, present a matching leaf, MITM to upstream:443 ----
    def _handle_tls(self, client):
        host_box = {}
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        def sni_cb(sslobj, servername, sslctx):
            if servername: host_box["h"] = servername
        ctx.sni_callback = sni_cb
        # temp default cert so the handshake can start; real cert chosen after SNI via a fresh ctx
        # simpler: do a first peek of SNI ourselves, then build ctx with the right cert
        sni = _peek_sni(client)
        host = sni or "localhost"
        if self._debug: self.log("[mitm] conn SNI=%s" % host)
        cf, kf = self.store.leaf(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try: ctx.load_cert_chain(cf, kf)
        except Exception as e: self.log("[!] mitm cert load: %s" % e); client.close(); return
        try: ctx.set_alpn_protocols(["http/1.1"])   # force HTTP/1.1 (our parser); avoids app negotiating h2
        except Exception: pass
        try:
            tls_client = ctx.wrap_socket(client, server_side=True)
        except Exception as e:
            if self._debug: self.log("[mitm] client TLS handshake FAILED for %s: %s" % (host, e))
            client.close(); return
        if self._debug: self.log("[mitm] client TLS OK (%s), dialing upstream…" % host)
        # connect upstream (real server) with TLS, no verify (we're already MITMing)
        try:
            up_raw = socket.create_connection((host, 443), timeout=20)
            uctx = ssl._create_unverified_context()
            try: uctx.set_alpn_protocols(["http/1.1"])
            except Exception: pass
            up = uctx.wrap_socket(up_raw, server_hostname=host if not _is_ip(host) else None)
        except Exception as e:
            if self._debug: self.log("[mitm] upstream %s:443 FAILED: %s" % (host, e))
            try: tls_client.close()
            except Exception: pass
            return
        if self._debug: self.log("[mitm] MITM established %s — relaying" % host)
        self._pump_http(tls_client, up, host, "https")

    def _handle_plain(self, client):
        rf = client.makefile("rb")
        first, hdrs, raw = _read_headers(rf)
        if not first: client.close(); return
        host = (hdrs.get(b"host", b"") or b"").decode("latin1").split(":")[0] or "localhost"
        try:
            up = socket.create_connection((host, 80), timeout=20)
        except Exception:
            client.close(); return
        body = _read_body(rf, hdrs)
        up.sendall(raw + body)
        self._emit("out", first, host, "http", raw + body)
        self._relay_response(up, client, host, "http")
        try: client.close(); up.close()
        except Exception: pass

    # ---- HTTP/1.1 keep-alive pump (also upgrades to WS relay) ----
    def _pump_http(self, client, up, host, scheme):
        try:
            crf = client.makefile("rb")
            while self._alive:
                first, hdrs, raw = _read_headers(crf)
                if not first: break
                body = _read_body(crf, hdrs)
                up.sendall(raw + body)
                self._emit("out", first, host, scheme, raw + body)
                # WebSocket upgrade?
                if hdrs and b"websocket" in hdrs.get(b"upgrade", b"").lower():
                    self._relay_ws(client, up, host); return
                # response
                urf = up.makefile("rb")
                rfirst, rhdrs, rraw = _read_headers(urf)
                if not rfirst: break
                rbody = _read_body(urf, rhdrs)
                client.sendall(rraw + rbody)
                self._emit("in", rfirst, host, scheme, rraw + rbody)
                if rhdrs and b"101" in rfirst.encode() and b"websocket" in rhdrs.get(b"upgrade", b"").lower():
                    self._relay_ws(client, up, host); return
                if (hdrs.get(b"connection", b"").lower() == b"close" or
                        (rhdrs.get(b"connection", b"").lower() == b"close")):
                    break
        except Exception:
            pass
        finally:
            for s in (client, up):
                try: s.close()
                except Exception: pass

    def _relay_response(self, up, client, host, scheme):
        try:
            urf = up.makefile("rb")
            rfirst, rhdrs, rraw = _read_headers(urf)
            if not rfirst: return
            rbody = _read_body(urf, rhdrs)
            client.sendall(rraw + rbody)
            self._emit("in", rfirst, host, scheme, rraw + rbody)
        except Exception:
            pass

    def _relay_ws(self, client, up, host):
        """After the 101 handshake, relay raw frames both ways and capture text/binary payloads."""
        def relay(src, dst, direction):
            try:
                while self._alive:
                    data = src.recv(65536)
                    if not data: break
                    dst.sendall(data)
                    for msg in _ws_frames(data):
                        if msg: self.on_event({"dir": direction, "ws": True, "data": msg[:4096],
                                               "method": "WS UP" if direction == "out" else "WS DN",
                                               "url": " ".join(msg.split())[:160], "host": host})
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try: s.close()
                    except Exception: pass
        threading.Thread(target=relay, args=(client, up, "out"), daemon=True).start()
        relay(up, client, "in")

    def _emit(self, direction, first, host, scheme, raw):
        try:
            text = raw.decode("latin1", "replace")
            method = None; url = first
            if direction == "out":
                p = first.split(" ")
                if len(p) >= 2 and p[0].isalpha():
                    method = p[0]; url = scheme + "://" + host + p[1]
            else:
                method = "RESP"
            self.on_event({"dir": direction, "method": method, "url": url, "first": first,
                           "data": text[:4000], "host": host})
        except Exception:
            pass


# ---- peek the SNI out of a TLS ClientHello without consuming it ----
def _peek_sni(sock):
    try:
        data = b""
        # peek up to 2KB (ClientHello is small); grow the peek until we have the record
        for n in (512, 1500, 4096):
            data = sock.recv(n, socket.MSG_PEEK)
            if len(data) >= 43: break
        if len(data) < 43 or data[0] != 0x16: return None
        # TLS record: skip 5 (record hdr) + handshake header
        p = 5 + 4                      # record(5) + handshake type(1)+len(3)
        p += 2 + 32                    # client version(2) + random(32)
        sid = data[p]; p += 1 + sid    # session id
        cs = int.from_bytes(data[p:p+2], "big"); p += 2 + cs   # cipher suites
        cm = data[p]; p += 1 + cm      # compression
        if p + 2 > len(data): return None
        ext_len = int.from_bytes(data[p:p+2], "big"); p += 2
        end = min(p + ext_len, len(data))
        while p + 4 <= end:
            etype = int.from_bytes(data[p:p+2], "big"); elen = int.from_bytes(data[p+2:p+4], "big"); p += 4
            if etype == 0x00:          # server_name
                # server_name_list(2) + type(1) + name_len(2) + name
                if p + 5 > len(data): return None
                nlen = int.from_bytes(data[p+3:p+5], "big")
                return data[p+5:p+5+nlen].decode("latin1")
            p += elen
        return None
    except Exception:
        return None
