"""
fi_mitm.py — lightweight transparent TLS MITM capture proxy for Flutter Interceptor.

Because the frida engine already UNPINS TLS in the app, the app trusts any certificate — so
this proxy can terminate TLS itself (choosing the leaf cert by the ClientHello SNI), read the
plaintext HTTP / WebSocket, forward it upstream so the app keeps working, and hand every
request/response to a callback for the tool's Requests tab.

Works for ANY app (Flutter/Dart, Cronet, OkHttp, native) with no per-version byte patterns.
"""
import os, ssl, socket, threading, datetime, ipaddress, gzip, zlib, select
try:
    import brotli as _brotli            # optional: pip install brotli — for br-encoded bodies
except Exception:
    _brotli = None

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False

try:
    import h2.connection
    import h2.events
    import h2.config
    import h2.exceptions
    _HAVE_H2 = True
except Exception:
    _HAVE_H2 = False


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


def _decode_display(raw):
    """Split an HTTP message into head + a HUMAN-READABLE body: decompress gzip/deflate/br so the
    Requests tab shows real JSON/text instead of binary gibberish. Best-effort; never raises.
    The bytes actually relayed to the app are untouched — this only affects what we DISPLAY."""
    try:
        i = raw.find(b"\r\n\r\n")
        if i < 0: return raw.decode("latin1", "replace")
        head = raw[:i + 4]; body = raw[i + 4:]
        enc = b""
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-encoding:"):
                enc = line.split(b":", 1)[1].strip().lower(); break
        try:
            if b"gzip" in enc or b"x-gzip" in enc:
                body = gzip.decompress(body)
            elif b"deflate" in enc:
                try: body = zlib.decompress(body)
                except Exception: body = zlib.decompress(body, -zlib.MAX_WBITS)
            elif b"br" in enc and _brotli is not None:
                body = _brotli.decompress(body)
        except Exception:
            pass   # truncated/partial body (we cap reads) — show what we have, undecoded
        return head.decode("latin1", "replace") + body.decode("utf-8", "replace")
    except Exception:
        return raw.decode("latin1", "replace")


def _safe(h): return "".join(c if c.isalnum() or c in ".-" else "_" for c in h)[:60]
def _is_ip(h):
    try: ipaddress.ip_address(h); return True
    except Exception: return False
def _is_closed(s):
    try: return s.fileno() < 0
    except Exception: return True


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
        if not sni:
            # No SNI in the ClientHello: the app connected to a bare IP or used ECH/ESNI. Because the
            # traffic reaches us through an iptables REDIRECT + adb-reverse tunnel, the ORIGINAL
            # destination is already lost, so we can't know where to forward. Report it instead of
            # silently dropping — this is a known blind spot for IP-direct / no-SNI TLS.
            self.log("[!] capture: a TLS connection had NO SNI (bare-IP or ECH) — can't route it; that request won't appear. (rare; most apps use SNI)")
            client.close(); return
        host = sni
        if self._debug: self.log("[mitm] conn SNI=%s" % host)
        cf, kf = self.store.leaf(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try: ctx.load_cert_chain(cf, kf)
        except Exception as e: self.log("[!] mitm cert load: %s" % e); client.close(); return
        # Offer both h2 and http/1.1 so the app can pick. h2 (incl. gRPC) is bridged via the h2 lib;
        # http/1.1 goes through the keep-alive pump. Falls back to http/1.1 only if h2 lib missing.
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"] if _HAVE_H2 else ["http/1.1"])
        except Exception:
            try: ctx.set_alpn_protocols(["http/1.1"])
            except Exception: pass
        try:
            tls_client = ctx.wrap_socket(client, server_side=True)
        except Exception as e:
            if self._debug: self.log("[mitm] client TLS handshake FAILED for %s: %s" % (host, e))
            client.close(); return
        client_alpn = ""
        try: client_alpn = tls_client.selected_alpn_protocol() or ""
        except Exception: pass
        if self._debug: self.log("[mitm] client TLS OK (%s, ALPN=%s), dialing upstream…" % (host, client_alpn or "none"))
        # connect upstream (real server) with TLS, no verify (we're already MITMing).
        # The iptables REDIRECT flattens the original destination PORT, so we don't know if the app
        # dialed 443 or an alt-TLS port. Try the ports the routing redirects (443 then 8443) so
        # non-standard-port APIs (api.host:8443, :8443 gateways) stop silently vanishing.
        up = None
        want_h2 = (client_alpn == "h2" and _HAVE_H2)
        for uport in (443, 8443):
            try:
                up_raw = socket.create_connection((host, uport), timeout=15)
                uctx = ssl._create_unverified_context()
                try: uctx.set_alpn_protocols(["h2", "http/1.1"] if want_h2 else ["http/1.1"])
                except Exception: pass
                up = uctx.wrap_socket(up_raw, server_hostname=host if not _is_ip(host) else None)
                if self._debug and uport != 443: self.log("[mitm] upstream %s reached on alt port %d" % (host, uport))
                break
            except Exception as e:
                if self._debug: self.log("[mitm] upstream %s:%d failed: %s" % (host, uport, e))
                continue
        if up is None:
            self.log("[!] capture: could not reach upstream %s (tried 443, 8443) — request dropped" % host)
            try: tls_client.close()
            except Exception: pass
            return
        up_alpn = ""
        try: up_alpn = up.selected_alpn_protocol() or ""
        except Exception: pass
        if self._debug: self.log("[mitm] MITM established %s (app=%s upstream=%s) — relaying" % (host, client_alpn or "1.1", up_alpn or "1.1"))
        # Route: if BOTH sides negotiated h2, use the h2 bridge (handles HTTP/2 + gRPC w/ trailers).
        # Otherwise fall back to the HTTP/1.1 keep-alive pump (servers that only speak 1.1).
        if want_h2 and up_alpn == "h2":
            self._pump_h2(tls_client, up, host)
        else:
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
            # both readers created ONCE: their read-ahead buffers must persist across keep-alive
            # requests. Re-creating urf each loop discarded bytes it had buffered for the NEXT
            # response, corrupting the 2nd+ request on a reused connection (intermittent loss).
            urf = up.makefile("rb")
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

    # ---- HTTP/2 + gRPC bridge (both sides h2 via the `h2` lib; preserves trailers) ----
    def _pump_h2(self, client_sock, up_sock, host):
        """Bridge an HTTP/2 connection from the app to an HTTP/2 upstream, capturing every stream.
        Handles gRPC (HTTP/2 POST + trailers + protobuf body) transparently because it relays at
        the frame layer. Each app stream is mapped to an upstream stream and relayed both ways."""
        try:
            cfg_s = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
            cfg_c = h2.config.H2Configuration(client_side=True,  header_encoding="utf-8")
            s_conn = h2.connection.H2Connection(config=cfg_s)   # server side: faces the app
            c_conn = h2.connection.H2Connection(config=cfg_c)   # client side: faces upstream
            s_conn.initiate_connection()
            c_conn.initiate_connection()
            client_sock.sendall(s_conn.data_to_send())
            up_sock.sendall(c_conn.data_to_send())
            # stream map: app_stream_id -> upstream_stream_id (and reverse for routing responses)
            fwd = {}     # app_id -> up_id
            rev = {}     # up_id   -> app_id
            client_sock.settimeout(None); up_sock.settimeout(None)
            socks = [client_sock, up_sock]
            while self._alive:
                r, _, _ = select.select(socks, [], [], 1.0)
                if not r:
                    if any(_is_closed(s) for s in socks): break
                    continue
                for s in r:
                    try: data = s.recv(65536)
                    except Exception: data = b""
                    if not data:
                        try: self._h2_close(s_conn, c_conn, client_sock, up_sock, fwd, rev)
                        except Exception: pass
                        return
                    try:
                        if s is client_sock:
                            evs = s_conn.receive_data(data)
                            conn_to_flush, peer_sock = s_conn, client_sock
                            upside = False
                        else:
                            evs = c_conn.receive_data(data)
                            conn_to_flush, peer_sock = c_conn, up_sock
                            upside = True
                        out = conn_to_flush.data_to_send()
                        if out: peer_sock.sendall(out)
                    except h2.exceptions.ProtocolError:
                        break
                    except Exception:
                        break
                    for ev in evs:
                        try:
                            self._h2_handle_event(ev, s_conn, c_conn, client_sock, up_sock, fwd, rev, host, upside)
                        except Exception:
                            if self._debug: self.log("[mitm-h2] event err: %s" % ev)
                # flush any pending frames
                try:
                    for conn, sk in ((s_conn, client_sock), (c_conn, up_sock)):
                        d = conn.data_to_send()
                        if d: sk.sendall(d)
                except Exception:
                    return
        except Exception as e:
            if self._debug: self.log("[mitm-h2] bridge error: %s" % e)
        finally:
            for s in (client_sock, up_sock):
                try: s.close()
                except Exception: pass

    def _h2_handle_event(self, ev, s_conn, c_conn, client_sock, up_sock, fwd, rev, host, upside):
        # upside=False => event came from the APP side (request);  True => from the UPSTREAM side (response)
        if upside:
            # ---- upstream -> app (response / trailers / response-data) ----
            sid = getattr(ev, "stream_id", None)
            appid = rev.get(sid)
            if isinstance(ev, (h2.events.ResponseReceived, h2.events.TrailersReceived)):
                if appid is None: return
                # capture the response headers / trailers so bodyless responses (e.g. gRPC status-only)
                # still appear in the Requests tab
                if isinstance(ev, h2.events.ResponseReceived):
                    status = next((v for k, v in ev.headers if k == ":status"), "")
                    self.on_event({"dir": "in", "method": "RESP", "url": "%s [h2 stream %d]" % (host, appid),
                                   "first": "HTTP/2 %s" % status, "data": "h2 response %s {trailer: grpc} %s" % (status, host),
                                   "host": host})
                s_conn.send_headers(appid, list(ev.headers), end_stream=ev.stream_ended)
            elif isinstance(ev, h2.events.DataReceived):
                if appid is None:
                    c_conn.acknowledge_received_data(ev.flow_controlled_length, sid); return
                if ev.data:
                    self._emit_h2("in", host, appid, None, ev.data[:4_000_000])
                    s_conn.send_data(appid, ev.data[:4_000_000])
                c_conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                if ev.stream_ended: s_conn.end_stream(appid)
            elif isinstance(ev, h2.events.StreamReset):
                if appid is not None:
                    try: s_conn.reset_stream(appid, getattr(ev, "error_code", 0))
                    except Exception: pass
        else:
            # ---- app -> upstream (request headers / data / reset) ----
            sid = getattr(ev, "stream_id", None)
            if isinstance(ev, h2.events.RequestReceived):
                upid = c_conn.get_next_available_stream_id()
                fwd[sid] = upid; rev[upid] = sid
                c_conn.send_headers(upid, list(ev.headers), end_stream=ev.stream_ended)
            elif isinstance(ev, h2.events.DataReceived):
                upid = fwd.get(sid)
                if upid is None:
                    s_conn.acknowledge_received_data(ev.flow_controlled_length, sid); return
                if ev.data:
                    self._emit_h2("out", host, sid, None, ev.data[:4_000_000])
                    c_conn.send_data(upid, ev.data[:4_000_000])
                s_conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                if ev.stream_ended: c_conn.end_stream(upid)
            elif isinstance(ev, h2.events.StreamReset):
                upid = fwd.get(sid)
                if upid is not None:
                    try: c_conn.reset_stream(upid, getattr(ev, "error_code", 0))
                    except Exception: pass
        # settings / window / ping events are handled internally by the h2 connection objects

    def _emit_h2(self, direction, host, stream_id, headers_text, body):
        """Emit an h2 stream chunk to the Requests tab as a readable entry."""
        try:
            # for gRPC, body is protobuf (binary) — show a hex-ish preview, not garbled utf-8
            if body and len(body) > 2 and body[:1] in (b"\x00", b"\x01") and direction == "out":
                text = "gRPC frame (grpc): " + body[:200].hex()
            else:
                text = (headers_text or "") + ("\n" + body.decode("utf-8", "replace") if body else "")
            self.on_event({"dir": direction, "method": "GRPC" if direction == "out" else "RESP",
                           "url": "%s [h2 stream %d]" % (host, stream_id),
                           "first": "%s h2/%d" % (direction, stream_id),
                           "data": text[:4000], "host": host})
        except Exception:
            pass

    def _h2_close(self, s_conn, c_conn, client_sock, up_sock, fwd, rev):
        try:
            for conn, sk in ((s_conn, client_sock), (c_conn, up_sock)):
                d = conn.data_to_send()
                if d: sk.sendall(d)
        except Exception: pass
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
            text = _decode_display(raw)   # decompress gzip/br/deflate so the body is readable
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
