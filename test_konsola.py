"""Test kontraktu z klientem AdminDesk (kształty JSON jak w src/hbbs_http/sync.rs i src/server/connection.rs).
Uruchom:  python test_konsola.py
"""
import base64
import http.client
import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import konsola

HASLO = "test-haslo-1234567"


def post(url, v):
    r = urllib.request.urlopen(urllib.request.Request(url, json.dumps(v).encode(), {"Content-Type": "application/json"}))
    return r.read().decode()


def get(url, haslo=None):
    req = urllib.request.Request(url)
    if haslo:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"admin:{haslo}".encode()).decode())
    try:
        r = urllib.request.urlopen(req)
        return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


def formularz(port, pola, haslo=None):
    """POST z panelu bez podążania za przekierowaniem; zwraca kod odpowiedzi."""
    c = http.client.HTTPConnection("127.0.0.1", port)
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if haslo:
        h["Authorization"] = "Basic " + base64.b64encode(f"admin:{haslo}".encode()).decode()
    c.request("POST", "/panel/rozlacz", "&".join(f"{k}={v}" for k, v in pola.items()), h)
    return c.getresponse().status


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
    assert json.loads(post(u + "/api/heartbeat", {"id": "123456789", "uuid": "dXVpZA==", "ver": 1005000, "conns": [7], "modified_at": 0})) == {}
    # połączenie: new (ip) -> auth (kto) -> close; powtórzony nonce nie dubluje wpisu
    for a in ({"action": "new", "ip": "203.0.113.5", "nonce": "n1"}, {"peer": ["987654321", "Karol"], "type": 0, "nonce": "n2"},
              {"peer": ["987654321", "Karol"], "type": 0, "nonce": "n2"}, {"action": "close", "nonce": "n3"}):
        assert post(u + "/api/audit/conn", {"id": "123456789", "uuid": "dXVpZA==", "conn_id": 7, "session_id": 1, **a}) == ""
    assert len(konsola.Obsluga.baza.sql("SELECT * FROM audit")) == 3

    # panel: bez hasła 401, złe hasło 401, dobre 200 i treść zescapowana
    assert get(u + "/")[0] == 401 and get(u + "/", "zle")[0] == 401
    kod, strona = get(u + "/", HASLO)
    assert kod == 200
    assert "<script>alert(1)" not in strona and "&lt;script&gt;" in strona, "XSS: nazwa komputera nie zescapowana"
    assert "online: 1 / 1" in strona and "1 aktywna" in strona and "Karol" in strona and "203.0.113.5" in strona

    # rozłączanie: przycisk w panelu, CSRF, kolejka -> {"disconnect":[7]} dokładnie raz
    assert "Rozłącz" in strona and konsola.CSRF in strona
    p = srv.server_port
    assert formularz(p, {"id": "123456789", "t": konsola.CSRF}) == 401
    assert formularz(p, {"id": "123456789", "t": "obcy-token"}, HASLO) == 403
    assert formularz(p, {"id": "123456789", "t": konsola.CSRF}, HASLO) == 303
    hb = {"id": "123456789", "uuid": "dXVpZA==", "ver": 1005000, "conns": [7], "modified_at": 0}
    assert json.loads(post(u + "/api/heartbeat", hb)) == {"disconnect": [7]}
    assert json.loads(post(u + "/api/heartbeat", hb)) == {}

    # śmieci z sieci -> 400, nie wywrotka
    for zle in (b"nie-json", b"[1,2]", b'{"bez_id":1}'):
        req = urllib.request.Request(u + "/api/heartbeat", zle)
        try:
            urllib.request.urlopen(req)
            raise AssertionError("powinno być 400")
        except urllib.error.HTTPError as e:
            assert e.code == 400
    assert get(u + "/logo.png")[0] == 200
    srv.shutdown()
    print("OK: kontrakt sysinfo/heartbeat/audit, rozłączanie (CSRF), logowanie, XSS, błędne dane")


if __name__ == "__main__":
    main()
