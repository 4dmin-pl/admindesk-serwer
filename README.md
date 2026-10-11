# AdminDesk Serwer — A.D.M.I.N (4dmin.pl)

Serwer dla [AdminDesk](https://github.com/4dmin-pl/admindesk) (pomoc zdalna, oparta na RustDesk):
- **hbbs + hbbr** — oficjalny RustDesk Server OSS 1.1.16 (ID i przekazywanie połączeń),
- **AdminDesk Konsola** — panel WWW: urządzenia online/offline, nazwa komputera, użytkownik, system,
  aktywne sesje i dziennik połączeń (kto, skąd, kiedy, jak długo).

## Instalacja (Linux z publicznym IP: VPS, Proxmox/VM w biurze)
```bash
curl -fsSL https://github.com/4dmin-pl/admindesk-serwer/releases/latest/download/install.sh | sudo bash
# panel przez HTTPS (domena musi wskazywać na serwer, porty 80/443 otwarte):
curl -fsSL https://github.com/4dmin-pl/admindesk-serwer/releases/latest/download/install.sh | sudo DOMENA=pomoc.4dmin.pl bash
```
Instalator: Docker (jeśli brak) → `/opt/admindesk-serwer` → uruchomienie → wypisuje **adres, klucz publiczny i hasło panelu**.
Porty: TCP 21114–21117, UDP 21116 (+ TCP 80/443 z domeną). Ponowne uruchomienie = aktualizacja.

**Nie za CGNAT** (internet komórkowy, część światłowodów): serwer musi przyjmować połączenia z zewnątrz.
Panel można oglądać z dowolnego miejsca (Mac, telefon) — to zwykła strona WWW.

## Jak konsola widzi klientów
Klient AdminDesk sam wysyła meldunki na `http://<serwer>:21114` (adres API wyliczany z adresu serwera):
`/api/sysinfo` (komputer, użytkownik, system), `/api/heartbeat` (co 15 s, aktywne sesje),
`/api/audit/conn` (początek/koniec połączenia, ID i nazwa technika, IP). Konsola zapisuje to w SQLite
(`/opt/admindesk-serwer/konsola/konsola.db`). Nic nie trzeba zmieniać w kliencie poza adresem serwera.

## Rozwój
```bash
python test_konsola.py                                   # test kontraktu z klientem (bez sieci)
ADMIN_PASSWORD=... python konsola.py 21114 konsola.db    # lokalnie
```
Tylko biblioteka standardowa Pythona. Obraz: `ghcr.io/4dmin-pl/admindesk-konsola:1` (amd64/arm64).
Wydanie: tag `vX.Y.Z` → `install.sh` w GitHub Releases.

Licencja: AGPL-3.0-or-later.
