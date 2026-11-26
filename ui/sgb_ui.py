"""
Read-only web UI for the SGB feed. Docker version.

In Docker it runs behind nginx (BEHIND_PROXY=1): HTTPS, IP restriction and password are handled by nginx.
The UI is reachable only from the internal Docker network; the audit log records the real
client IP and user name forwarded by nginx.

It READS the files produced by sgb_sync.py and never modifies them:
  sgb.db (full history), status.json, feeds/*.txt + index.json, sgb_sync.log, sgb_sync.running

Pages:
  /             Status screen + address lookup + last lines of the log
  /?q=address   Lookup: IP, domain, URL or keyword (whole history)
  /api/status   JSON status (for a PRTG/Zabbix HTTP sensor)
  /healthz      Container liveness check
"""
import base64
import datetime as dt
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import sqlite3
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

# --- SETTINGS ---
BASE_DIR = os.environ.get("SGB_BASE_DIR", "/data")
HOST = os.environ.get("UI_HOST", "127.0.0.1")
PORT = int(os.environ.get("UI_PORT", "8080"))
BEHIND_PROXY = os.environ.get("BEHIND_PROXY", "0") == "1"  # behind nginx: access control is done by nginx
ALLOWED_NETS = [n.strip() for n in os.environ.get("UI_ALLOWED", "127.0.0.1/32").split(",") if n.strip()]
UI_USER = os.environ.get("UI_USER", "admin")
UI_PASS = os.environ.get("SGB_UI_PASS", "")   # only when used without the proxy
CERT_FILE = os.environ.get("UI_CERT_FILE", "")
KEY_FILE = os.environ.get("UI_KEY_FILE", "")
ALLOWLIST_FILE = os.environ.get("ALLOWLIST_FILE", "/config/allowlist.txt")
STALE_AFTER_HOURS = float(os.environ.get("STALE_AFTER_HOURS", "2.5"))
SEARCH_LIMIT = 50

DB_FILE = os.path.join(BASE_DIR, "sgb.db")
STATUS_FILE = os.path.join(BASE_DIR, "status.json")
FEED_DIR = os.path.join(BASE_DIR, "feeds")
SYNC_LOG = os.path.join(BASE_DIR, "sgb_sync.log")
RUN_MARKER = os.path.join(BASE_DIR, "sgb_sync.running")
UI_LOG = os.environ.get("UI_LOG_FILE", os.path.join(BASE_DIR, "sgb_ui.log"))  # /data is read-only in Docker

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
KIND_TITLES = {"domain": "Domain", "ip": "IPv4", "ipv6": "IPv6", "url": "URL"}
log = logging.getLogger("sgb_ui")


# --- DATA READING (read-only) ---

def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def db():
    return sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=10)


def load_allowlist():
    if not os.path.exists(ALLOWLIST_FILE):
        return set()
    with open(ALLOWLIST_FILE, encoding="utf-8") as f:
        return {l.split("#")[0].strip().lower().removeprefix("*.").rstrip(".") for l in f} - {""}


def tail(path, lines=40):
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        f.seek(max(0, f.tell() - 64 * 1024))
        return f.read().decode("utf-8", errors="replace").splitlines()[-lines:]


def get_status():
    now = dt.datetime.now()
    s = read_json(STATUS_FILE, {}) or {}
    st = {"ok": False, "message": "", "last_success": s.get("last_success"), "age_hours": None,
          "mode": s.get("mode"), "last_full_scan": s.get("last_full_scan"), "sgb_records": s.get("sgb_records"),
          "feed_counts": s.get("feed_counts", {}), "allowlisted": s.get("allowlisted"),
          "allowlist_count": len(load_allowlist()), "running_since": None,
          "last_result": None, "last_result_level": None}
    if st["last_success"]:
        st["age_hours"] = round((now - dt.datetime.fromisoformat(st["last_success"])).total_seconds() / 3600, 2)
    if os.path.exists(RUN_MARKER):
        with open(RUN_MARKER, encoding="utf-8", errors="replace") as f:
            st["running_since"] = f.read().strip() or "bilinmiyor"
    for line in reversed(tail(SYNC_LOG, 400)):
        if "--- Bitti:" in line:
            st["last_result"] = line
            st["last_result_level"] = "ERROR" if "[ERROR]" in line else "INFO"
            break

    if st["last_success"] is None:
        st["message"] = ("İlk tam tarama sürüyor." if st["running_since"] else "Henüz başarılı bir çalıştırma yok.")
    elif st["age_hours"] > STALE_AFTER_HOURS:
        st["message"] = f"Son başarılı senkronizasyon {st['age_hours']:.1f} saat önce. Feed'ler bayatlıyor."
    elif st["last_result_level"] == "ERROR":
        st["ok"] = True
        st["message"] = "Feed'ler güncel, ancak son çalıştırma hatayla bitti."
    else:
        st["ok"] = True
        st["message"] = "Sistem güncel."
    return st


# --- LOOKUP ---

def classify(raw):
    """Normalizes a query like sgb_sync.classify: ('domain'|'ip'|'ipv6'|'url', value) or None.
    Unlike sgb_sync.classify it does not drop non-public IPs or malformed names, so any input can be looked up."""
    s = (raw or "").strip()
    if not s:
        return None
    try:  # bare IP (including IPv6 without brackets); URL parsing would take it for host:port
        ip = ipaddress.ip_address(s.removeprefix("[").removesuffix("]"))
        return ("ip" if ip.version == 4 else "ipv6"), ip.compressed
    except ValueError:
        pass
    try:
        parts = urlsplit(s if "://" in s else "http://" + s)
        host = parts.hostname
    except ValueError:
        return None
    host = (host or "").rstrip(".").removeprefix("*.")
    path = parts.path if parts.path not in ("", "/") else ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if path:
            return "url", (f"[{ip.compressed}]" if ip.version == 6 else ip.compressed) + path
        return ("ip" if ip.version == 4 else "ipv6"), ip.compressed
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not host:
        return None
    return ("url", host + path) if path else ("domain", host)


def allow_match(kind, value, allow):
    host = value
    if kind == "url":
        host = value.split("/", 1)[0].strip("[]")
    if host in allow:
        return host
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in allow:
            return ".".join(labels[i:])
    return None


def feed_membership(kind, value):
    """Finds which feed files sent to the firewall contain the value, by looking at the files."""
    index = read_json(os.path.join(FEED_DIR, "index.json"), {}) or {}
    needle = b"\n" + value.encode() + b"\n"
    found = []
    for e in index.get("feeds", []):
        if e["kind"] != kind:
            continue
        try:
            with open(os.path.join(FEED_DIR, e["name"]), "rb") as f:
                if needle in b"\n" + f.read():
                    found.append(e["name"])
        except OSError:
            pass
    return found


def sgb_entries(conn, kind, value):
    rows = conn.execute("SELECT id, date, descr, source, criticality, conntype, raw FROM records "
                        "WHERE kind = ? AND value = ? ORDER BY id DESC", (kind, value)).fetchall()
    return [dict(zip(("id", "date", "descr", "source", "criticality", "conntype", "raw"), r)) for r in rows]


def summary(conn, kind, value, allow):
    rows = sgb_entries(conn, kind, value)
    if not rows:
        return None
    dates = [r["date"] for r in rows if r["date"]]
    return {"kind": kind, "value": value, "entries": rows, "first_seen": min(dates) if dates else None,
            "last_seen": max(dates) if dates else None, "allowlisted_by": allow_match(kind, value, allow),
            "feeds": feed_membership(kind, value)}


def like_escape(s):
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search(query):
    res = {"query": query, "normalized": None, "keyword": False, "exact": None, "related": [], "partial": []}
    if not os.path.exists(DB_FILE):
        res["error"] = "Veritabanı henüz oluşmadı (ilk tam tarama sürüyor olabilir)."
        return res
    q = query.strip()
    norm = classify(q)
    keyword = norm is not None and norm[0] == "domain" and "." not in norm[1]
    res["keyword"] = keyword
    allow = load_allowlist()
    try:
        conn = db()
        conn.execute("SELECT 1 FROM records LIMIT 1").fetchone()
    except sqlite3.Error:
        res["error"] = ("Veritabanı şu an okunamıyor. Senkronizasyon servisi yarıda kesildiyse yeniden "
                        "başladığında kendiliğinden düzelir (docker compose logs sync).")
        return res
    try:
        if norm and not keyword:
            kind, value = norm
            res["normalized"] = norm
            res["exact"] = summary(conn, kind, value, allow)
            related = []
            if kind == "domain":
                labels = value.split(".")
                for i in range(1, len(labels) - 1):  # parent domains
                    related.append(("Üst alan adı", "domain", ".".join(labels[i:])))
            if kind == "url":
                host = value.split("/", 1)[0]
                h = classify(host)
                if h:
                    related.append(("URL'nin host'u", h[0], h[1]))
            for label, k, v in related:
                s = summary(conn, k, v, allow)
                if s:
                    res["related"].append((label, s))
            if kind in ("domain", "ip", "ipv6"):  # URL records under this host
                prefix = (f"[{value}]" if kind == "ipv6" else value) + "/"
                for (v,) in conn.execute("SELECT DISTINCT value FROM records WHERE kind = 'url' AND value LIKE ? "
                                         "ESCAPE '\\' LIMIT 20", (like_escape(prefix) + "%",)):
                    res["related"].append(("Bu host altındaki URL", summary(conn, "url", v, allow)))
            needle = value
        else:
            needle = q.lower()
        if len(needle) >= 3:
            rows = conn.execute("SELECT kind, value, MAX(date), COUNT(*) FROM records WHERE value LIKE ? ESCAPE '\\' "
                                "GROUP BY kind, value ORDER BY MAX(date) DESC LIMIT ?",
                                ("%" + like_escape(needle) + "%", SEARCH_LIMIT + 1)).fetchall()
            shown = {res["normalized"]} | {(s["kind"], s["value"]) for _, s in res["related"]}
            res["partial"] = [r for r in rows if (r[0], r[1]) not in shown][:SEARCH_LIMIT]
    finally:
        conn.close()
    return res


# --- HTML ---

CSS = """
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1d2330}
header{background:#1d2330;color:#fff;padding:14px 24px;display:flex;justify-content:space-between;align-items:center;gap:12px}
header h1{font-size:18px;margin:0;font-weight:600}header a{color:#cfd6e4;font-size:14px;margin-left:16px}
main{max-width:1150px;margin:20px auto;padding:0 20px}
.card{background:#fff;border:1px solid #e2e5ea;border-radius:8px;padding:16px 20px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.stat .n{font-size:22px;font-weight:600}.stat .l{color:#5c6475;font-size:13px}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:13px;font-weight:600}
.ok{background:#e3f4e8;color:#17663a}.bad{background:#fde8e8;color:#9b1c1c}.warn{background:#fff4d6;color:#7a5200}
.neutral{background:#eceef2;color:#3b4352}
form{display:flex;gap:8px}input[type=text]{flex:1;padding:9px 12px;border:1px solid #c9ced8;border-radius:6px;font-size:15px}
button{padding:9px 18px;border:0;border-radius:6px;background:#1d2330;color:#fff;font-size:15px;cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eceef2;vertical-align:top}
th{color:#5c6475;font-weight:600}td.n{text-align:right;font-variant-numeric:tabular-nums}
pre{background:#0f131b;color:#d6dbe4;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.45}
.muted{color:#5c6475;font-size:13px}h2{font-size:16px;margin:0 0 12px}h3{font-size:14px;margin:16px 0 8px}
code{background:#eceef2;padding:1px 5px;border-radius:4px;font-size:13px}.wrap{word-break:break-all}
"""


def e(x):
    return html.escape("" if x is None else str(x), quote=True)


def num(n):
    return "-" if n is None else f"{n:,}".replace(",", ".")


def qlink(value):
    return f"<a href='/?q={quote(value, safe='')}'>{e(value)}</a>"


def render_summary(s):
    if s["feeds"]:
        verdict = "<span class='badge bad'>ENGELLİ</span>"
        feeds = "Firewall'a giden feed'ler: " + ", ".join(f"<code>{e(f)}</code>" for f in s["feeds"])
    elif s["allowlisted_by"]:
        verdict = "<span class='badge warn'>SGB listesinde var, allowlist'te</span>"
        feeds = f"<b>{e(s['allowlisted_by'])}</b> allowlist kaydı nedeniyle hiçbir feed'e yazılmıyor."
    else:
        verdict = "<span class='badge neutral'>SGB listesinde var, feed'de yok</span>"
        feeds = "Feed dosyalarında bulunamadı (bir sonraki senkronizasyonda eklenecek olabilir)."
    out = [f"<p>{verdict} <b class='wrap'>{e(s['value'])}</b> <span class='muted'>({KIND_TITLES[s['kind']]})</span></p>",
           f"<p class='muted'>{feeds}<br>SGB listesinde ilk görülme: {e(s['first_seen'])} · son görülme: {e(s['last_seen'])} · "
           f"kayıt sayısı: {len(s['entries'])}</p>",
           "<table><tr><th>Tarih</th><th>Açıklama</th><th>Kaynak</th><th>Kritiklik</th>"
           "<th>Bağlantı türü</th><th>SGB'deki ham değer</th></tr>"]
    for r in s["entries"][:20]:
        out.append(f"<tr><td>{e(r['date'])}</td><td>{e(r['descr'])}</td><td>{e(r['source'])}</td>"
                   f"<td>{e(r['criticality'])}</td><td>{e(r['conntype'])}</td><td class='wrap'>{e(r['raw'])}</td></tr>")
    out.append("</table>")
    if len(s["entries"]) > 20:
        out.append(f"<p class='muted'>… ve {len(s['entries']) - 20} kayıt daha.</p>")
    return "".join(out)


def render_search(res):
    q = res["query"]
    if res.get("error"):
        return f"<div class='card'><h2>Sorgu: {e(q)}</h2><p>{e(res['error'])}</p></div>"
    parts = ["<div class='card'>"]
    if res["keyword"] or res["normalized"] is None:
        parts.append(f"<h2>Kelime araması: {e(q)}</h2>")
        if not res["partial"]:
            parts.append("<p>İçinde bu ifade geçen kayıt yok.</p>")
    else:
        kind, value = res["normalized"]
        parts.append(f"<h2>Sorgu: <span class='wrap'>{e(value)}</span></h2>")
        if res["exact"]:
            parts.append(render_summary(res["exact"]))
        else:
            parts.append(f"<p><span class='badge ok'>SGB kayıtlarında yok</span> "
                         f"Bu {KIND_TITLES[kind]} SGB'nin yayımladığı hiçbir kayıtta geçmiyor.</p>")
        for label, s in res["related"]:
            parts.append(f"<h3>{e(label)}</h3>")
            if label == "Üst alan adı":
                parts.append("<p class='muted'>Alt alan adlarının da engellenip engellenmediği firewall'un "
                             "eşleştirme ayarına (wildcard) bağlıdır.</p>")
            parts.append(render_summary(s))
    if res["partial"]:
        more = f" (ilk {SEARCH_LIMIT})" if len(res["partial"]) >= SEARCH_LIMIT else ""
        parts.append(f"<h3>İçinde “{e(q.strip())}” geçen kayıtlar{more}</h3><table><tr><th>Tür</th><th>Değer</th>"
                     "<th>Son görülme</th><th class='n'>SGB kaydı</th></tr>")
        for kind, value, last, count in res["partial"]:
            parts.append(f"<tr><td>{KIND_TITLES.get(kind, e(kind))}</td><td class='wrap'>{qlink(value)}</td>"
                         f"<td>{e(last)}</td><td class='n'>{count}</td></tr>")
        parts.append("</table>")
    parts.append("</div>")
    return "".join(parts)


def render_page(query=None):
    st = get_status()
    badge = "ok" if st["ok"] and st["last_result_level"] != "ERROR" else ("warn" if st["ok"] else "bad")
    fc = st["feed_counts"] or {}
    info = []
    if st["running_since"]:
        info.append(f"Senkronizasyon şu an çalışıyor ya da önceki çalıştırma yarıda kalmış (başlangıç: {e(st['running_since'])}).")
    if st["last_result"]:
        info.append(e(st["last_result"]))
    if st["last_full_scan"]:
        info.append(f"Son tam tarama: {e(st['last_full_scan'].replace('T', ' '))} · SGB kayıt sayısı: {num(st['sgb_records'])} · "
                    f"allowlist nedeniyle çıkarılan: {num(st['allowlisted'])}")
    last = st["last_success"].replace("T", " ") if st["last_success"] else "-"
    body = [
        f"<header><h1>SGB Engelleme Listesi</h1><div><span class='badge {badge}'>{e(st['message'])}</span>"
        "<a href='/feed/'>Feed listesi</a></div></header><main>",
        "<div class='card grid'>",
        f"<div class='stat'><div class='n'>{num(fc.get('domain'))}</div><div class='l'>Domain</div></div>",
        f"<div class='stat'><div class='n'>{num(fc.get('ip'))}</div><div class='l'>IPv4</div></div>",
        f"<div class='stat'><div class='n'>{num(fc.get('url'))}</div><div class='l'>URL</div></div>",
        f"<div class='stat'><div class='n'>{st['allowlist_count']}</div><div class='l'>Allowlist kaydı</div></div>",
        f"<div class='stat'><div class='n' style='font-size:15px;padding-top:6px'>{e(last)}</div>"
        "<div class='l'>Son başarılı senkronizasyon</div></div>",
        "</div>",
        "<div class='card'>" + "".join(f"<p class='muted'>{i}</p>" for i in info) +
        "<form method='get' action='/'><input type='text' name='q' autofocus "
        "placeholder='IP, domain, URL ya da kelime (ör. evil.com, 1.2.3.4, https://x.evil.com/login, garanti)' "
        f"value='{e(query or '')}'><button type='submit'>Sorgula</button></form></div>",
    ]
    if query:
        body.append(render_search(search(query)))
    body.append("<div class='card'><h2>Senkronizasyon log'u (son 40 satır)</h2><pre>"
                + e("\n".join(tail(SYNC_LOG))) + "</pre></div></main>")
    return ("<!DOCTYPE html><html lang='tr'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>SGB Engelleme Listesi</title><style>{CSS}</style></head><body>"
            + "".join(body) + "</body></html>")


# --- SERVER ---

def client_allowed(addr, nets):
    ip = ipaddress.ip_address(addr)
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return any(ip in n for n in nets)


class Handler(BaseHTTPRequestHandler):
    server_version = "SGB-UI"
    sys_version = ""
    nets = []

    def client(self):
        """'ip (user)' for the audit log. Behind the proxy it uses the headers set by nginx."""
        if BEHIND_PROXY:
            return f"{self.headers.get('X-Real-IP', '?')} ({self.headers.get('X-Remote-User') or '-'})"
        return self.client_address[0]

    def log_message(self, fmt, *args):
        log.info(f"{self.client()} {fmt % args}")

    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        if not UI_PASS:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, _, pw = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        except ValueError:
            return False
        # bytes comparison: works with non-ASCII passwords too; & makes sure both are always evaluated
        return hmac.compare_digest(user.encode(), UI_USER.encode()) & hmac.compare_digest(pw.encode(), UI_PASS.encode())

    def do_GET(self):
        if not BEHIND_PROXY and not client_allowed(self.client_address[0], self.nets):
            log.warning(f"{self.client()} izin verilmeyen ağdan erişim denemesi reddedildi")
            self._send(403, "Erişim reddedildi.", "text/plain; charset=utf-8")
            return
        if not BEHIND_PROXY and not self._authorized():
            log.warning(f"{self.client()} hatalı ya da eksik kimlik bilgisi")
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="SGB", charset="UTF-8"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        url = urlsplit(self.path)
        try:
            if url.path == "/":
                q = (parse_qs(url.query).get("q") or [""])[0][:300]
                if q:
                    log.info(f"{self.client()} sorgu: {q!r}")
                self._send(200, render_page(q), "text/html; charset=utf-8")
            elif url.path == "/healthz":  # container liveness check
                self._send(200, "ok", "text/plain; charset=utf-8")
            elif url.path == "/api/status":
                self._send(200, json.dumps(get_status(), ensure_ascii=False), "application/json; charset=utf-8")
            else:
                self._send(404, "Bulunamadı.", "text/plain; charset=utf-8")
        except Exception:
            log.exception("İstek işlenirken hata")
            self._send(500, "Sunucu hatası, ayrıntı sgb_ui.log dosyasında.", "text/plain; charset=utf-8")


def make_server(host=HOST, port=PORT, allowed=ALLOWED_NETS):
    Handler.nets = [ipaddress.ip_network(n, strict=False) for n in allowed]
    srv = ThreadingHTTPServer((host, port), Handler)
    if CERT_FILE and KEY_FILE:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def main():
    os.makedirs(os.path.dirname(UI_LOG), exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                        handlers=[logging.FileHandler(UI_LOG, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
                        force=True)
    loopback = ipaddress.ip_address(HOST).is_loopback if HOST != "localhost" else True
    if not UI_PASS and not loopback and not BEHIND_PROXY:
        log.error("SGB_UI_PASS tanımlı değil: parolasız arayüz yalnızca 127.0.0.1'de açılabilir. Çıkılıyor.")
        return 1
    tls = bool(CERT_FILE and KEY_FILE)
    if not tls and not loopback and not BEHIND_PROXY:
        log.warning("HTTPS kapalı: parola ağda açık metin gider. Uzaktan erişimde CERT_FILE/KEY_FILE tanımlayın.")
    srv = make_server()
    scheme = "https" if tls else "http"
    if BEHIND_PROXY:
        log.info(f"Arayüz açıldı: {scheme}://{HOST}:{PORT}/ (nginx arkasında; erişim denetimi nginx'te)")
    else:
        log.info(f"Arayüz açıldı: {scheme}://{HOST}:{PORT}/  (izinli ağlar: {', '.join(ALLOWED_NETS)}, "
                 f"kimlik doğrulama: {'açık' if UI_PASS else 'kapalı'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("Arayüz kapatıldı (kullanıcı durdurdu).")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
