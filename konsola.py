"""AdminDesk Konsola — serwer API dla klientów AdminDesk (RustDesk) + panel WWW dla technika.

Klient sam wysyła tu meldunki (adres API = host serwera, port 21114 — common.rs get_api_server):
  POST /api/sysinfo     nazwa komputera, użytkownik, system      -> "SYSINFO_UPDATED"
  POST /api/heartbeat   co 15 s: id, uuid, ver, aktywne sesje   -> {} lub {"sysinfo": 1} (nieznane urządzenie)
  POST /api/audit/conn  początek/koniec połączenia, kto i skąd  -> ""
Panel:  GET /login  formularz (konto „admin”); sesja w ciasteczku, GET /wyloguj
        Pierwsze logowanie hasłem z ADMIN_PASSWORD wymusza ustawienie własnego (GET/POST /haslo, hash PBKDF2 w bazie);
        od tej chwili ADMIN_PASSWORD jest ignorowane. Zmiana hasła: /haslo.
        GET /  lista urządzeń i połączeń
        POST /panel/rozlacz  -> sesje urządzenia trafiają do kolejki; najbliższy heartbeat (co 3 s przy aktywnej sesji)
                                dostaje {"disconnect": [...]} i klient je zamyka (connection.rs: „Closed manually by web console”)

Uruchomienie:  ADMIN_PASSWORD=... python konsola.py [port=21114] [baza=konsola.db]
Tylko biblioteka standardowa Pythona.
"""
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ONLINE_S = 45  # klient wysyła heartbeat co 15 s (sync.rs TIME_HEARTBEAT)
CSRF = secrets.token_urlsafe(24)  # token formularzy panelu; obca strona go nie odczyta (same-origin), restart = odśwież panel
MAX_BODY = 64 * 1024
SESJA_S = 12 * 3600
PBKDF2_ITER = 600_000
HERE = Path(__file__).resolve().parent

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, uuid TEXT, hostname TEXT, username TEXT, os TEXT, version TEXT,
  cpu TEXT, memory TEXT, last_seen REAL, conns TEXT DEFAULT '[]', ip TEXT);
CREATE TABLE IF NOT EXISTS audit (
  ts REAL, device_id TEXT, conn_id INTEGER, action TEXT, ip TEXT,
  peer_id TEXT, peer_name TEXT, type INTEGER, nonce TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS rozlacz (device_id TEXT, conn_id INTEGER, ts REAL);
CREATE TABLE IF NOT EXISTS ustawienia (klucz TEXT PRIMARY KEY, wartosc TEXT);
"""


class Baza:
    def __init__(self, path):
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.executescript(SCHEMA)
        self.lock = threading.Lock()  # shortcut: jedna blokada na całą bazę, wystarczy na setki urządzeń

    def sql(self, q, args=()):
        with self.lock:
            rows = self.con.execute(q, args).fetchall()  # przed commit: RETURNING trzyma otwartą instrukcję
            self.con.commit()
            return rows


def hash_hasla(haslo, sol=None, it=PBKDF2_ITER):
    sol = sol or secrets.token_hex(16)
    return f"pbkdf2_sha256${it}${sol}${hashlib.pbkdf2_hmac('sha256', haslo.encode(), sol.encode(), it).hex()}"


def sprawdz_hash(haslo, zapisany):
    _, it, sol, _ = zapisany.split("$")
    return hmac.compare_digest(hash_hasla(haslo, sol, int(it)), zapisany)


def tekst(v, n=200):
    return str(v)[:n] if v is not None else ""


class Obsluga(BaseHTTPRequestHandler):
    baza: Baza
    haslo: str  # ADMIN_PASSWORD — tylko do pierwszego logowania, dopóki w bazie nie ma własnego hasła
    sesje: dict = {}  # shortcut: sesje w pamięci, restart konsoli = ponowne logowanie; wystarczy dla jednego konta
    server_version = "AdminDeskKonsola"

    def log_message(self, fmt, *args):  # bez zaśmiecania logów co 15 s na urządzenie
        pass

    def odpowiedz(self, kod, tresc, typ="text/plain; charset=utf-8", naglowki=()):
        dane = tresc.encode() if isinstance(tresc, str) else tresc
        self.send_response(kod)
        self.send_header("Content-Type", typ)
        self.send_header("Content-Length", str(len(dane)))
        for k, v in naglowki:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(dane)

    def json_z_ciala(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return None
        try:
            v = json.loads(self.rfile.read(n))
        except ValueError:
            return None
        return v if isinstance(v, dict) and v.get("id") else None

    # ---------------- API klientów ----------------
    def do_POST(self):
        if self.path == "/panel/rozlacz":
            return self.rozlacz()
        if self.path == "/login":
            return self.zaloguj()
        if self.path == "/haslo":
            return self.zmien_haslo()
        v = self.json_z_ciala()
        if v is None:
            return self.odpowiedz(400, "bad request")
        dev, ip, teraz = tekst(v["id"], 32), self.client_address[0], time.time()
        if self.path == "/api/sysinfo":
            self.baza.sql(
                "INSERT INTO devices(id,uuid,hostname,username,os,version,cpu,memory,last_seen,ip) VALUES(?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET uuid=excluded.uuid, hostname=excluded.hostname, username=excluded.username, "
                "os=excluded.os, version=excluded.version, cpu=excluded.cpu, memory=excluded.memory, last_seen=excluded.last_seen, ip=excluded.ip",
                (dev, tekst(v.get("uuid")), tekst(v.get("hostname")), tekst(v.get("username")), tekst(v.get("os")),
                 tekst(v.get("version"), 32), tekst(v.get("cpu")), tekst(v.get("memory"), 32), teraz, ip))
            return self.odpowiedz(200, "SYSINFO_UPDATED")
        if self.path == "/api/heartbeat":
            conns = v.get("conns") if isinstance(v.get("conns"), list) else []
            znane = self.baza.sql("UPDATE devices SET last_seen=?, conns=?, ip=? WHERE id=? RETURNING id",
                                  (teraz, json.dumps(conns[:50]), ip, dev))
            # nieznane urządzenie (np. po czyszczeniu bazy) -> klient wyśle sysinfo ponownie (sync.rs: rsp "sysinfo")
            if not znane:
                return self.odpowiedz(200, '{"sysinfo":1}', "application/json")
            self.baza.sql("DELETE FROM rozlacz WHERE ts < ?", (teraz - 300,))  # zlecenie dla sesji, której już nie ma
            do_zamkniecia = [r[0] for r in self.baza.sql("DELETE FROM rozlacz WHERE device_id=? RETURNING conn_id", (dev,))]
            return self.odpowiedz(200, json.dumps({"disconnect": do_zamkniecia} if do_zamkniecia else {}), "application/json")
        if self.path == "/api/audit/conn":
            peer = v.get("peer") if isinstance(v.get("peer"), list) else [None, None]
            self.baza.sql(
                "INSERT OR IGNORE INTO audit(ts,device_id,conn_id,action,ip,peer_id,peer_name,type,nonce) VALUES(?,?,?,?,?,?,?,?,?)",
                (teraz, dev, int(v.get("conn_id") or 0), tekst(v.get("action"), 16), tekst(v.get("ip"), 64),
                 tekst(peer[0] if peer else None, 32), tekst(peer[1] if len(peer) > 1 else None, 64),
                 v.get("type") if isinstance(v.get("type"), int) else None, tekst(v.get("nonce"), 64) or None))
            return self.odpowiedz(200, "")
        return self.odpowiedz(404, '{"error":"nieobsługiwane w AdminDesk Konsola"}', "application/json")

    # ---------------- panel ----------------
    def do_GET(self):
        if self.path == "/logo-desk.webp":
            return self.odpowiedz(200, (HERE / "logo-desk.webp").read_bytes(), "image/webp", [("Cache-Control", "max-age=86400")])
        if self.path == "/logo.png":
            return self.odpowiedz(200, (HERE / "logo.png").read_bytes(), "image/png", [("Cache-Control", "max-age=86400")])
        if self.path.split("?")[0] == "/login":
            return self.strona(LOGOWANIE.format(blad=BLEDY.get(self.path.partition("?")[2], ""), csrf=CSRF))
        if self.path == "/wyloguj":
            self.sesje.pop(self.ciastko(), None)
            return self.przekieruj("/login", [("Set-Cookie", "ad_sesja=; Path=/; Max-Age=0")])
        s = self.sesja()
        if not s:
            return self.przekieruj("/login")
        if self.path.split("?")[0] == "/haslo":
            return self.strona(HASLO.format(csrf=CSRF, blad=BLEDY.get(self.path.partition("?")[2], ""),
                                            info="Pierwsze logowanie — ustaw własne hasło." if s["zmiana"] else "Zmiana hasła panelu."))
        if s["zmiana"]:
            return self.przekieruj("/haslo")
        if self.path in ("/", "/index.html"):
            return self.strona(self.panel())
        return self.odpowiedz(404, "nie ma")

    def rozlacz(self):
        s = self.sesja()
        if not s or s["zmiana"]:
            return self.przekieruj("/login")
        f = self.formularz()
        if not self.csrf_ok(f):
            return self.odpowiedz(403, "Nieważny formularz — odśwież panel")
        dev = (f.get("id") or [""])[0][:32]
        wiersz = self.baza.sql("SELECT conns FROM devices WHERE id=?", (dev,))
        teraz = time.time()
        for c in json.loads(wiersz[0][0] or "[]") if wiersz else []:
            if isinstance(c, int):
                self.baza.sql("INSERT INTO rozlacz VALUES(?,?,?)", (dev, c, teraz))
        return self.odpowiedz(303, "", naglowki=[("Location", "/")])

    # ---------------- logowanie ----------------
    def strona(self, tresc):
        return self.odpowiedz(200, tresc, "text/html; charset=utf-8", [("Cache-Control", "no-store")])

    def przekieruj(self, gdzie, naglowki=()):
        return self.odpowiedz(303, "", naglowki=[("Location", gdzie), *naglowki])

    def formularz(self):
        n = int(self.headers.get("Content-Length") or 0)
        return parse_qs(self.rfile.read(n).decode(errors="replace")) if 0 < n <= 4096 else {}

    @staticmethod
    def csrf_ok(f):
        return hmac.compare_digest((f.get("t") or [""])[0].encode(), CSRF.encode())

    def ciastko(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c["ad_sesja"].value if "ad_sesja" in c else ""

    def sesja(self):
        s = self.sesje.get(self.ciastko())
        return s if s and s["do"] > time.time() else None

    def nowa_sesja(self, zmiana):
        token = secrets.token_urlsafe(32)
        self.sesje[token] = {"do": time.time() + SESJA_S, "zmiana": zmiana}
        return ("Set-Cookie", f"ad_sesja={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESJA_S}")

    def haslo_ok(self, haslo):
        """-> (poprawne, czy to jeszcze hasło startowe z ADMIN_PASSWORD)"""
        zapisany = self.baza.sql("SELECT wartosc FROM ustawienia WHERE klucz='haslo'")
        if zapisany:
            return sprawdz_hash(haslo, zapisany[0][0]), False
        return bool(self.haslo) and hmac.compare_digest(haslo.encode(), self.haslo.encode()), True

    def zaloguj(self):
        f = self.formularz()
        ok, startowe = self.haslo_ok((f.get("password") or [""])[0])
        if not (self.csrf_ok(f) and (f.get("username") or [""])[0] == "admin" and ok):
            time.sleep(1)  # spowalnia zgadywanie hasła
            return self.przekieruj("/login?blad")
        return self.przekieruj("/haslo" if startowe else "/", [self.nowa_sesja(startowe)])

    def zmien_haslo(self):
        if not self.sesja():
            return self.przekieruj("/login")
        f = self.formularz()
        pole = lambda k: (f.get(k) or [""])[0]
        if not self.csrf_ok(f):
            return self.odpowiedz(403, "Nieważny formularz — odśwież stronę")
        if not self.haslo_ok(pole("stare"))[0]:
            time.sleep(1)
            return self.przekieruj("/haslo?stare")
        if len(pole("nowe")) < 12:
            return self.przekieruj("/haslo?krotkie")
        if pole("nowe") != pole("nowe2"):
            return self.przekieruj("/haslo?rozne")
        if pole("nowe") == pole("stare"):
            return self.przekieruj("/haslo?takie_samo")
        self.baza.sql("INSERT OR REPLACE INTO ustawienia VALUES('haslo', ?)", (hash_hasla(pole("nowe")),))
        self.sesje.clear()  # nowe hasło wylogowuje wszystkie sesje
        return self.przekieruj("/", [self.nowa_sesja(False)])

    @staticmethod
    def przycisk(dev, sesje):
        return (f"<form method=post action=/panel/rozlacz onsubmit=\"return confirm('Rozłączyć aktywne sesje na tym komputerze?')\">"
                f"<b class=sesja>{sesje} aktywna</b> <input type=hidden name=id value=\"{html.escape(dev)}\">"
                f"<input type=hidden name=t value=\"{CSRF}\"><button>Rozłącz</button></form>")

    def panel(self):
        teraz = time.time()
        e = html.escape
        urz = self.baza.sql("SELECT id,hostname,username,os,version,last_seen,conns,ip FROM devices ORDER BY last_seen DESC")
        wiersze = []
        for id_, host, user, os_, ver, seen, conns, ip in urz:
            online = teraz - (seen or 0) < ONLINE_S
            sesje = len(json.loads(conns or "[]")) if online else 0  # offline = lista sesji z ostatniego meldunku jest nieaktualna
            wiersze.append(
                f"<tr><td><span class='kropka {'on' if online else 'off'}'></span>{'online' if online else 'offline'}</td>"
                f"<td class='mono'>{e(id_)}</td><td>{e(host)}</td><td>{e(user)}</td><td>{e(os_)}</td><td>{e(ver)}</td>"
                f"<td>{self.przycisk(id_, sesje) if sesje else '—'}</td>"
                f"<td class='mono'>{e(ip)}</td><td>{e(czas(seen, teraz))}</td></tr>")
        # jedno połączenie = rekordy z tym samym (device_id, conn_id): new (ip) -> auth (peer) -> close
        # shortcut: conn_id zeruje się po restarcie usługi klienta, więc grupujemy też po dniu; wystarczy do podglądu
        pol = self.baza.sql(
            "SELECT a.device_id, d.hostname, MIN(a.ts), MAX(CASE WHEN a.action='close' THEN a.ts END), "
            "MAX(a.peer_id), MAX(a.peer_name), MAX(a.ip) FROM audit a LEFT JOIN devices d ON d.id=a.device_id "
            "GROUP BY a.device_id, a.conn_id, date(a.ts,'unixepoch') ORDER BY MIN(a.ts) DESC LIMIT 100")
        log = [
            f"<tr><td>{e(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start)))}</td><td>{e(host or dev)}"
            f" <span class='mono szary'>{e(dev)}</span></td><td>{e(pname or '')} <span class='mono szary'>{e(pid or '')}</span></td>"
            f"<td class='mono'>{e(ip or '')}</td><td>{e(trwanie(start, koniec, teraz))}</td></tr>"
            for dev, host, start, koniec, pid, pname, ip in pol]
        online = sum(1 for r in urz if teraz - (r[5] or 0) < ONLINE_S)
        return SZABLON.format(
            urzadzenia="".join(wiersze) or "<tr><td colspan=9 class=pusto>Brak urządzeń — klienci zgłoszą się po ustawieniu serwera.</td></tr>",
            polaczenia="".join(log) or "<tr><td colspan=5 class=pusto>Brak połączeń.</td></tr>",
            online=online, wszystkie=len(urz), odswiezono=time.strftime("%H:%M:%S"))


def czas(ts, teraz):
    if not ts:
        return "—"
    s = int(teraz - ts)
    return "teraz" if s < 60 else f"{s // 60} min temu" if s < 3600 else time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def trwanie(start, koniec, teraz):
    if koniec is None:
        return "trwa" if teraz - start < 12 * 3600 else "?"
    m = int(koniec - start) // 60
    return f"{m} min" if m < 120 else f"{m // 60} h {m % 60} min"


SZABLON = """<!doctype html><html lang=pl><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<meta http-equiv=refresh content=15><title>AdminDesk Konsola</title><style>
:root{{--tlo:#f4f5f7;--karta:#fff;--tekst:#1b1f24;--szary:#6b7280;--linia:#e3e6ea;--granat:#212830;--zielony:#2ea043}}
@media(prefers-color-scheme:dark){{:root{{--tlo:#15191e;--karta:#1d232a;--tekst:#e6e8eb;--szary:#9aa3ad;--linia:#2c333b}}}}
body{{margin:0;font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--tlo);color:var(--tekst)}}
header{{background:var(--granat);color:#fff;padding:14px 20px;display:flex;align-items:center;gap:16px}}
header img{{height:44px}} header a.k{{color:#fff;opacity:.85;font-size:13px;border:1px solid #ffffff40;border-radius:6px;padding:4px 10px;text-decoration:none}} header a.k:hover{{opacity:1;background:#ffffff1a}} header .t{{font-size:18px;font-weight:600}} header .s{{opacity:.75;margin-left:auto}}
main{{max-width:1200px;margin:0 auto;padding:16px}} h2{{font-size:16px;margin:22px 0 8px}}
.karta{{background:var(--karta);border:1px solid var(--linia);border-radius:10px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--linia);white-space:nowrap}}
th{{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--szary)}} tr:last-child td{{border-bottom:0}}
.mono{{font-family:ui-monospace,Consolas,monospace}} .szary{{color:var(--szary);font-size:12px}} .pusto{{color:var(--szary);text-align:center;padding:24px}}
.kropka{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}} .on{{background:var(--zielony)}} .off{{background:#8b949e}}
.sesja{{color:#d29922}} form{{margin:0;display:flex;gap:8px;align-items:center}}
button{{font:inherit;font-size:12px;padding:3px 10px;border-radius:6px;border:1px solid #da3633;background:transparent;color:#da3633;cursor:pointer}}
button:hover{{background:#da3633;color:#fff}} footer{{color:var(--szary);font-size:12px;text-align:center;padding:20px}}
</style></head><body><header><img src=/logo.png alt="ADMIN by Karol Wojewski"><span class=t>AdminDesk Konsola</span>
<span class=s>online: {online} / {wszystkie} · odświeżono {odswiezono}</span><a class=k href=/haslo>Zmień hasło</a><a class=k href=/wyloguj>Wyloguj</a></header><main>
<h2>Urządzenia</h2><div class=karta><table><tr><th>Stan</th><th>ID</th><th>Komputer</th><th>Użytkownik</th><th>System</th><th>Wersja</th><th>Sesje</th><th>IP</th><th>Ostatnio</th></tr>{urzadzenia}</table></div>
<h2>Połączenia (ostatnie 100)</h2><div class=karta><table><tr><th>Początek</th><th>Do komputera</th><th>Kto (technik)</th><th>Z IP</th><th>Czas</th></tr>{polaczenia}</table></div>
</main><footer>AdminDesk — A.D.M.I.N (4dmin.pl), by Karol Wojewski · oparte na RustDesk (AGPL-3.0)</footer></body></html>"""


BLEDY = {"blad": "Nieprawidłowe konto lub hasło.", "stare": "Obecne hasło jest nieprawidłowe.",
         "krotkie": "Nowe hasło musi mieć co najmniej 12 znaków.", "rozne": "Nowe hasła nie są takie same.",
         "takie_samo": "Nowe hasło musi być inne niż obecne."}

# wygląd jak logowanie AdminInventory (app.css: loginwrap / logincard / f / btn primary)
STYL = """<style>:root{{color-scheme:dark;--bg:#0c111b;--panel:#141c2a;--line:#2b3a50;--txt:#edf2fb;--muted:#a0aec3}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}}
.loginwrap{{min-height:calc(100vh - 60px);display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at 50% 20%,#192943 0,transparent 70%)}}
.logincard{{background:var(--panel);border:1px solid #34455f;border-radius:18px;padding:30px;width:min(420px,100%);box-shadow:0 24px 60px #0005}}
.loginlogo{{display:block;width:min(300px,100%);height:auto;margin:0 auto 8px}}.nazwa{{text-align:center;color:var(--muted);letter-spacing:.2em;text-transform:uppercase;font-size:12px;margin:0 0 24px}}
.f{{margin-bottom:16px}}.f label{{display:block;font-size:12px;color:var(--muted);margin-bottom:7px}}
.f input{{width:100%;background:#101826;border:1px solid var(--line);border-radius:8px;padding:10px 11px;color:var(--txt);font:inherit;min-height:40px}}
.f input:focus{{border-color:#709fff;outline:none}}
.btn{{width:100%;background:#2563eb;border:1px solid #4c8af4;color:#fff;border-radius:8px;padding:10px 14px;min-height:40px;cursor:pointer;font:inherit;font-weight:600;box-shadow:0 4px 12px #123f852b}}
.btn:hover{{background:#3475e3}}.blad{{background:#321f29;border:1px solid #65404b;color:#ffb5b5;border-radius:8px;padding:9px 11px;margin-bottom:16px}}
.blad:empty{{display:none}}.info{{color:var(--muted);margin:0 0 16px}}a{{color:var(--muted)}}
.app-footer{{margin:28px auto 16px;padding:0 28px;font-size:11px;color:#93a5bc;text-align:center}}
@media(max-width:480px){{.loginwrap{{padding:16px}}.logincard{{padding:24px}}}}</style>"""

STOPKA = "<footer class=app-footer>AdminDesk — A.D.M.I.N (4dmin.pl) · oparte na RustDesk (AGPL-3.0)</footer></body></html>"

LOGOWANIE = """<!doctype html><html lang=pl><head><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>Logowanie — AdminDesk</title>""" + STYL + """</head><body><div class=loginwrap><div class=logincard>
<img class=loginlogo src=/logo-desk.webp alt="ADMIN by Karol Wojewski | DESK"><div class=blad>{blad}</div>
<form method=post action=/login><input type=hidden name=t value="{csrf}">
<div class=f><label>Konto panelu</label><input name=username value=admin autocomplete=username required></div>
<div class=f><label>Hasło</label><input type=password name=password autocomplete=current-password autofocus required></div>
<button class=btn type=submit>Zaloguj</button></form></div></div>""" + STOPKA

HASLO = """<!doctype html><html lang=pl><head><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>Hasło — AdminDesk</title>""" + STYL + """</head><body><div class=loginwrap><div class=logincard>
<img class=loginlogo src=/logo-desk.webp alt="ADMIN by Karol Wojewski | DESK"><p class=info>{info}</p><div class=blad>{blad}</div>
<form method=post action=/haslo><input type=hidden name=t value="{csrf}"><input type=hidden name=username value=admin autocomplete=username>
<div class=f><label>Obecne hasło</label><input type=password name=stare autocomplete=current-password autofocus required></div>
<div class=f><label>Nowe hasło (min. 12 znaków)</label><input type=password name=nowe minlength=12 autocomplete=new-password required></div>
<div class=f><label>Powtórz nowe hasło</label><input type=password name=nowe2 minlength=12 autocomplete=new-password required></div>
<button class=btn type=submit>Zapisz hasło</button></form><p style="text-align:center;margin:16px 0 0"><a href=/wyloguj>Wyloguj</a></p></div></div>""" + STOPKA


def main():
    haslo = os.environ.get("ADMIN_PASSWORD", "")
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 21114
    Obsluga.baza = Baza(sys.argv[2] if len(sys.argv) > 2 else "konsola.db")
    if len(haslo) < 12 and not Obsluga.baza.sql("SELECT 1 FROM ustawienia WHERE klucz='haslo'"):
        sys.exit("Ustaw ADMIN_PASSWORD (min. 12 znaków) — hasło startowe panelu, zmieniane przy pierwszym logowaniu.")
    Obsluga.haslo = haslo
    print(f"AdminDesk Konsola: port {port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Obsluga).serve_forever()


if __name__ == "__main__":
    main()
