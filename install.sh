#!/usr/bin/env bash
# AdminDesk Serwer — instalator na Linuksa (Debian/Ubuntu, amd64/arm64): hbbs + hbbr (RustDesk Server OSS) + AdminDesk Konsola.
#
#   curl -fsSL https://github.com/4dmin-pl/admindesk-serwer/releases/latest/download/install.sh | sudo bash
#   ... | sudo DOMENA=pomoc.4dmin.pl bash      # + panel przez HTTPS (Caddy, Let's Encrypt; DNS musi wskazywać na serwer)
#
# Ponowne uruchomienie = aktualizacja obrazów; dane i klucz serwera zostają w /opt/admindesk-serwer.
set -euo pipefail

KAT=/opt/admindesk-serwer
OBRAZ_RD=rustdesk/rustdesk-server:1.1.16
OBRAZ_KONSOLA=ghcr.io/4dmin-pl/admindesk-konsola:1
DOMENA="${DOMENA:-}"

[ "$(id -u)" -eq 0 ] || { echo "Uruchom jako root (sudo)."; exit 1; }

if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  echo "== Instaluję Dockera (oficjalny skrypt get.docker.com)"
  curl -fsSL https://get.docker.com | sh
fi

mkdir -p "$KAT/rustdesk" "$KAT/konsola" "$KAT/caddy"
chown 65534 "$KAT/konsola"   # konsola działa jako nobody
cd "$KAT"

if [ ! -s haslo-panelu.txt ]; then
  (umask 077; head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 20 > haslo-panelu.txt)
fi
umask 077
printf 'ADMIN_PASSWORD=%s\n' "$(cat haslo-panelu.txt)" > konsola.env

cat > docker-compose.yml <<EOF
# wygenerowane przez install.sh — zmiany nadpisze kolejne uruchomienie instalatora
services:
  hbbs:
    image: $OBRAZ_RD
    command: hbbs
    volumes: ["./rustdesk:/root"]
    network_mode: host
    restart: unless-stopped
  hbbr:
    image: $OBRAZ_RD
    command: hbbr
    volumes: ["./rustdesk:/root"]
    network_mode: host
    restart: unless-stopped
  konsola:
    image: $OBRAZ_KONSOLA
    env_file: konsola.env
    volumes: ["./konsola:/data"]
    network_mode: host
    restart: unless-stopped
EOF

if [ -n "$DOMENA" ]; then
  printf '%s {\n  reverse_proxy 127.0.0.1:21114\n}\n' "$DOMENA" > caddy/Caddyfile
  cat >> docker-compose.yml <<EOF
  caddy:
    image: caddy:2
    volumes: ["./caddy/Caddyfile:/etc/caddy/Caddyfile:ro", "./caddy/data:/data"]
    network_mode: host
    restart: unless-stopped
EOF
fi

echo "== Pobieram i uruchamiam usługi"
docker compose pull -q
docker compose up -d --remove-orphans

if command -v ufw >/dev/null && ufw status | grep -q active; then
  ufw allow 21114:21117/tcp >/dev/null; ufw allow 21116/udp >/dev/null
  [ -n "$DOMENA" ] && { ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; }
fi

for _ in $(seq 30); do [ -s rustdesk/id_ed25519.pub ] && break; sleep 1; done
[ -s rustdesk/id_ed25519.pub ] || { echo "hbbs nie wygenerował klucza — sprawdź: docker compose logs hbbs"; exit 1; }

IP=$(curl -fsS --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
ADRES="${DOMENA:-$IP}"
cat <<EOF

============================================================
 AdminDesk Serwer działa.

 Adres serwera:   $ADRES
 Klucz publiczny: $(cat rustdesk/id_ed25519.pub)
   -> wpisz oba do src/admindesk.rs (RENDEZVOUS_SERVER, SERVER_KEY) i wydaj nowy AdminDesk

 Panel:  $( [ -n "$DOMENA" ] && echo "https://$DOMENA" || echo "http://$IP:21114  (bez HTTPS — najlepiej przez tunel SSH/VPN)" )
 Login:  admin
 Hasło:  w pliku $KAT/haslo-panelu.txt

 Porty do otwarcia na zaporze/routerze: TCP 21114-21117, UDP 21116$( [ -n "$DOMENA" ] && echo ", TCP 80, 443" )
 Kopia zapasowa: cały katalog $KAT (zwłaszcza rustdesk/id_ed25519 — utrata = przepinanie klientów)
============================================================
EOF
