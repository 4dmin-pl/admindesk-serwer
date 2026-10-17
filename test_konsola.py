"""Test kontraktu z klientem AdminDesk (kształty JSON jak w src/hbbs_http/sync.rs i src/server/connection.rs).
Uruchom:  python test_konsola.py
"""
import http.client
import json
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import konsola

HASLO = "test-haslo-1234567"


def post(url, v):
    r = urllib.request.urlopen(urllib.request.Request(url, json.dumps(v).encode(), {"Content-Type": "application/json"}))
    return r.read().decode()


def zapytanie(port, metoda, sciezka, pola=None, ciastko=None):
    """Bez podążania za przekierowaniem -> (kod, Location, Set-Cookie, treść)."""
    c = http.client.HTTPConnection("127.0.0.1", port)
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if ciastko:
        h["Cookie"] = ciastko
    c.request(metoda, sciezka, urllib.parse.urlencode(pola) if pola else None, h)
    r = c.getresponse()
    return r.status, r.getheader("Location"), (r.getheader("Set-Cookie") or "").split(";")[0], r.read().decode(errors="replace")


def main():
    konsola.Obsluga.baza = konsola.Baza(os.path.join(tempfile.mkdtemp(), "t.db"))
    konsola.Obsluga.haslo = HASLO
    srv = ThreadingHTTPServer(("127.0.0.1", 0), konsola.Obsluga)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    u = f"http://127.0.0.1:{srv.server_port}"

    # nieznane urządzenie -> konsola prosi o sysinfo
    assert json.loads(post(u + "/api/heartbeat", {"id": "123456789", "uuid": "dXVpZA==", "ver": 1005000, "modified_at": 0})) == {"sysinfo": 1}
    assert post(u + "/api/sysinfo", {"id": "123456789", "uuid": "dXVpZA==", "hostname": "<script>alert(1)</script>KSIEGOWOSC",
                                     "username": "anna", "os": "Windows 11", "cpu": "x", "memory": "16GB", "version": "1.5.0"}) == "SYSINFO_UPDATED"
    odp = json.loads(post(u + "/api/heartbeat", {"id": "123456789", "uuid": "dXVpZA==", "ver": 1005000, "conns": [7], "modified_at": 0}))
    haslo = odp["haslo"]
    assert set(odp) == {"haslo"} and len(haslo) == 12 and not set(haslo) & set("0O1lI"), odp
    # to samo hasło przy kolejnym heartbeacie; obcy uuid z tym samym ID nie dostaje hasła ani nie przejmuje urządzenia
    assert json.loads(post(u + "/api/heartbeat", {"id": "123456789", "uuid": "dXVpZA==", "ver": 1005000, "conns": [7]}))["haslo"] == haslo
    assert "haslo" not in json.loads(post(u + "/api/heartbeat", {"id": "123456789", "uuid": "b2JjeQ==", "ver": 1005000, "conns": [7]}))
    post(u + "/api/sysinfo", {"id": "123456789", "uuid": "b2JjeQ==", "hostname": "KSIEGOWOSC", "username": "x"})
    assert "haslo" not in json.loads(post(u + "/api/heartbeat", {"id": "123456789", "uuid": "b2JjeQ==", "ver": 1005000, "conns": [7]})), "sysinfo z obcym uuid przejęło urządzenie"
    post(u + "/api/sysinfo", {"id": "123456789", "uuid": "dXVpZA==", "hostname": "<script>alert(1)</script>KSIEGOWOSC",
                              "username": "anna", "os": "Windows 11", "cpu": "x", "memory": "16GB", "version": "1.5.0"})
    # połączenie: new (ip) -> auth (kto) -> close; powtórzony nonce nie dubluje wpisu
    for a in ({"action": "new", "ip": "203.0.113.5", "nonce": "n1"}, {"peer": ["987654321", "Karol"], "type": 0, "nonce": "n2"},
              {"peer": ["987654321", "Karol"], "type": 0, "nonce": "n2"}, {"action": "close", "nonce": "n3"}):
        assert post(u + "/api/audit/conn", {"id": "123456789", "uuid": "dXVpZA==", "conn_id": 7, "session_id": 1, **a}) == ""
    assert len(konsola.Obsluga.baza.sql("SELECT * FROM audit")) == 3

    # logowanie: bez sesji -> /login; złe hasło -> błąd; hasło startowe -> wymuszona zmiana
    p, T = srv.server_port, konsola.CSRF
    assert zapytanie(p, "GET", "/")[1] == "/login"
    assert "Konto panelu" in zapytanie(p, "GET", "/login")[3]
    assert zapytanie(p, "POST", "/login", {"username": "admin", "password": "zle", "t": T})[1] == "/login?blad"
    assert zapytanie(p, "POST", "/login", {"username": "admin", "password": HASLO, "t": "obcy"})[1] == "/login?blad"
    kod, gdzie, c1, _ = zapytanie(p, "POST", "/login", {"username": "admin", "password": HASLO, "t": T})
    assert gdzie == "/haslo" and c1.startswith("ad_sesja=")
    assert zapytanie(p, "GET", "/", ciastko=c1)[1] == "/haslo", "hasło startowe musi wymusić zmianę"
    assert "Pierwsze logowanie" in zapytanie(p, "GET", "/haslo", ciastko=c1)[3]
    NOWE = "nowe-haslo-panelu-123"
    assert zapytanie(p, "POST", "/haslo", {"stare": HASLO, "nowe": "krotkie", "nowe2": "krotkie", "t": T}, c1)[1] == "/haslo?krotkie"
    assert zapytanie(p, "POST", "/haslo", {"stare": HASLO, "nowe": NOWE, "nowe2": NOWE + "x", "t": T}, c1)[1] == "/haslo?rozne"
    assert zapytanie(p, "POST", "/haslo", {"stare": "zle", "nowe": NOWE, "nowe2": NOWE, "t": T}, c1)[1] == "/haslo?stare"
    kod, gdzie, c2, _ = zapytanie(p, "POST", "/haslo", {"stare": HASLO, "nowe": NOWE, "nowe2": NOWE, "t": T}, c1)
    assert gdzie == "/" and c2 and c2 != c1
    assert zapytanie(p, "GET", "/", ciastko=c1)[1] == "/login", "zmiana hasła unieważnia stare sesje"
    assert zapytanie(p, "POST", "/login", {"username": "admin", "password": HASLO, "t": T})[1] == "/login?blad", "hasło startowe już nie działa"
    assert konsola.sprawdz_hash(NOWE, konsola.Obsluga.baza.sql("SELECT wartosc FROM ustawienia")[0][0])
    kod, _, _, strona = zapytanie(p, "GET", "/", ciastko=c2)
    assert kod == 200 and "Wyloguj" in strona
    assert "<script>alert(1)" not in strona and "&lt;script&gt;" in strona, "XSS: nazwa komputera nie zescapowana"
    assert "online: 1 / 1" in strona and "1 aktywna" in strona and "Karol" in strona and "203.0.113.5" in strona

    # rozłączanie: przycisk w panelu, CSRF, kolejka -> {"disconnect":[7]} dokładnie raz
    assert "Rozłącz" in strona and T in strona
    assert zapytanie(p, "POST", "/panel/rozlacz", {"id": "123456789", "t": T})[1] == "/login"
    assert zapytanie(p, "POST", "/panel/rozlacz", {"id": "123456789", "t": "obcy"}, c2)[0] == 403
    assert zapytanie(p, "POST", "/panel/rozlacz", {"id": "123456789", "t": T}, c2)[0] == 303
    hb = {"id": "123456789", "uuid": "dXVpZA==", "ver": 1005000, "conns": [7], "modified_at": 0}
    assert json.loads(post(u + "/api/heartbeat", hb)) == {"disconnect": [7], "haslo": haslo}
    assert json.loads(post(u + "/api/heartbeat", hb)) == {"haslo": haslo}

    # przycisk „Połącz” = link do zainstalowanej Konsoli z ID i hasłem; „Nowe hasło” (CSRF) losuje inne
    assert f"admindesk-konsola://connection/new/123456789?password={haslo}" in strona
    assert zapytanie(p, "POST", "/panel/nowe-haslo", {"id": "123456789", "t": "obcy"}, c2)[0] == 403
    assert zapytanie(p, "POST", "/panel/nowe-haslo", {"id": "123456789", "t": T})[1] == "/login"
    assert zapytanie(p, "POST", "/panel/nowe-haslo", {"id": "123456789", "t": T}, c2)[0] == 303
    nowe = json.loads(post(u + "/api/heartbeat", hb))["haslo"]
    assert nowe != haslo and f"password={nowe}" in zapytanie(p, "GET", "/", ciastko=c2)[3]

    # śmieci z sieci -> 400, nie wywrotka
    for zle in (b"nie-json", b"[1,2]", b'{"bez_id":1}'):
        req = urllib.request.Request(u + "/api/heartbeat", zle)
        try:
            urllib.request.urlopen(req)
            raise AssertionError("powinno być 400")
        except urllib.error.HTTPError as e:
            assert e.code == 400
    assert zapytanie(p, "GET", "/logo.png")[0] == 200
    # wylogowanie
    assert zapytanie(p, "GET", "/wyloguj", ciastko=c2)[1] == "/login"
    assert zapytanie(p, "GET", "/", ciastko=c2)[1] == "/login"
    srv.shutdown()
    print("OK: kontrakt sysinfo/heartbeat/audit, hasło per komputer (uuid, Połącz, Nowe hasło), rozłączanie (CSRF), logowanie+pierwsza zmiana hasła+wylogowanie, XSS, błędne dane")


if __name__ == "__main__":
    main()
