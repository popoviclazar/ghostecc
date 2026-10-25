#!/bin/bash
# Ghost ECC: lokalni server za testiranje na Macu. Pokreće se iz Terminala, iz foldera projekta.
#
#   bash scripts/dev_local.sh              server + HTTPS na https://localhost:8443 (simulatori)
#   bash scripts/dev_local.sh --tunnel     privremena javna HTTPS adresa (pravi iPhone)
#   bash scripts/dev_local.sh trust        dodaj lokalni sertifikat pokrenutim simulatorima
#   bash scripts/dev_local.sh link "URL"   otvori link pozivnice u izabranom simulatoru
#   bash scripts/dev_local.sh reset        obriši lokalne sandučiće servera
#
# Sve što skripta pravi nalazi se u server/.dev (podaci servera, lokalni sertifikat, logovi).
# Napisano za bash 3.2 koji dolazi uz macOS.

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEV="$ROOT/server/.dev"
DATA="$DEV/data"
CA_DIR="$DEV/caddy"
ROOT_CERT="$CA_DIR/pki/authorities/local/root.crt"
SERVER_PORT="${GHOST_DEV_SERVER_PORT:-8080}"
HTTPS_PORT="${GHOST_DEV_HTTPS_PORT:-8443}"
LOCAL_ORIGIN="https://localhost:$HTTPS_PORT"
UDID_PATTERN='[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'
PIDS=""

say() { printf '%s\n' "$*"; }
fail() { printf '\nGreška: %s\n' "$*" >&2; exit 1; }

show_logs() {
  for log in "$DEV/server.log" "$DEV/caddy.log" "$DEV/tunnel.log"; do
    [ -s "$log" ] || continue
    printf '\n--- posljednje linije: %s ---\n' "${log#$ROOT/}" >&2
    tail -n 15 "$log" >&2
  done
}

need() { # need <komanda> <homebrew paket>
  command -v "$1" >/dev/null 2>&1 && return 0
  command -v brew >/dev/null 2>&1 || fail "nedostaje '$1', a Homebrew nije instaliran. Instaliraj ga po uputstvu sa https://brew.sh pa pokreni skriptu ponovo."
  say "Instaliram $2 preko Homebrew-a…"
  brew install "$2" || fail "instalacija paketa $2 nije uspjela."
  command -v "$1" >/dev/null 2>&1 || fail "'$1' i dalje nije dostupan. Otvori novi prozor Terminala i pokušaj ponovo."
}

need_node() {
  need node node
  major=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null)
  case "$major" in ''|*[!0-9]*) major=0 ;; esac
  [ "$major" -ge 20 ] || fail "potreban je Node.js 20 ili noviji (pokreni: brew upgrade node)."
}

port_in_use() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

check_ports() {
  for port in "$@"; do
    port_in_use "$port" && fail "port $port je zauzet. Možda skripta već radi u drugom prozoru Terminala; zaustavi je sa Ctrl+C."
  done
  return 0
}

booted_simulators() {
  xcrun simctl list devices booted 2>/dev/null | grep -oE "$UDID_PATTERN"
}

trust_simulators() {
  [ -f "$ROOT_CERT" ] || fail "lokalni sertifikat još ne postoji. Prvo pokreni: bash scripts/dev_local.sh"
  if ! command -v xcrun >/dev/null 2>&1; then
    say "xcrun nije dostupan (instaliraj Xcode), pa sertifikat nije dodat simulatorima."
    return 0
  fi
  ids=$(booted_simulators)
  if [ -z "$ids" ]; then
    say "Nijedan simulator nije pokrenut. Pokreni ih, pa u drugom prozoru Terminala: bash scripts/dev_local.sh trust"
    return 0
  fi
  for id in $ids; do
    if xcrun simctl keychain "$id" add-root-cert "$ROOT_CERT" >/dev/null 2>&1; then
      say "  ✓ sertifikat dodat simulatoru $id"
    else
      say "  ✗ dodavanje nije uspjelo za simulator $id"
    fi
  done
  say "Ako je aplikacija već bila otvorena u simulatoru, ugasi je i otvori ponovo."
}

open_link() {
  url="${1:-}"
  case "$url" in ghost-ecc://invite/*) ;; *) fail "navedi link pozivnice u navodnicima, npr: bash scripts/dev_local.sh link \"ghost-ecc://invite/…\"" ;; esac
  command -v xcrun >/dev/null 2>&1 || fail "xcrun nije dostupan; instaliraj Xcode."
  lines=$(xcrun simctl list devices booted 2>/dev/null | grep -E "$UDID_PATTERN")
  [ -n "$lines" ] || fail "nijedan simulator nije pokrenut."
  count=$(printf '%s\n' "$lines" | wc -l | tr -d ' ')
  choice=1
  if [ "$count" -gt 1 ]; then
    say "Pokrenuti simulatori:"
    printf '%s\n' "$lines" | sed -E 's/^[[:space:]]+//' | awk '{ printf "  %d) %s\n", NR, $0 }'
    printf 'Broj simulatora koji PRIHVATA pozivnicu (ne onaj koji ju je napravio): '
    read -r choice
  fi
  case "$choice" in ''|*[!0-9]*) fail "nepoznat izbor." ;; esac
  udid=$(printf '%s\n' "$lines" | sed -n "${choice}p" | grep -oE "$UDID_PATTERN")
  [ -n "$udid" ] || fail "nepoznat izbor."
  xcrun simctl openurl "$udid" "$url" || fail "simulator nije otvorio link. Da li je Ghost ECC instaliran na njemu?"
  say "Link je otvoren u simulatoru $udid. U aplikaciji upiši ime kontakta i dodirni Poveži se."
}

wait_for_health() { # wait_for_health <origin> [cacert] [pokušaji]
  tries=0
  limit="${3:-60}"
  while [ "$tries" -lt "$limit" ]; do
    if [ -n "${2:-}" ]; then
      out=$(curl -fsS --max-time 3 --cacert "$2" "$1/v1/health" 2>/dev/null)
    else
      out=$(curl -fsS --max-time 5 "$1/v1/health" 2>/dev/null)
    fi
    case "$out" in *'"status":"ok"'*) return 0 ;; esac
    for pid in $PIDS; do kill -0 "$pid" 2>/dev/null || return 1; done
    sleep 0.5
    tries=$((tries + 1))
  done
  return 1
}

start_server() { # start_server <origin>
  mkdir -p "$DATA"
  GHOST_ORIGIN="$1" GHOST_LISTEN="127.0.0.1:$SERVER_PORT" GHOST_DATA_DIR="$DATA" GHOST_MAX_MEMORY_MB=256 \
    node "$ROOT/server/src/main.js" >"$DEV/server.log" 2>&1 &
  PIDS="$PIDS $!"
}

cleanup() {
  trap - EXIT
  [ -n "$PIDS" ] || return
  for pid in $PIDS; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  say ""
  say "Zaustavljeno. Lokalni sandučići ostaju u server/.dev/data (bash scripts/dev_local.sh reset ih briše)."
}

keep_running() {
  say "Zaustavljanje: Ctrl+C"
  while :; do
    for pid in $PIDS; do
      if ! kill -0 "$pid" 2>/dev/null; then
        show_logs
        fail "jedan od procesa se neočekivano zaustavio (logovi su iznad)."
      fi
    done
    sleep 2
  done
}

local_mode() {
  need_node
  need caddy caddy
  check_ports "$SERVER_PORT" "$HTTPS_PORT"
  mkdir -p "$DEV" "$CA_DIR"
  # Lokalni CA ostaje u server/.dev i ne dodaje se u povjerenje samog Maca (skip_install_trust);
  # povjerenje dobijaju samo simulatori, preko xcrun simctl.
  cat >"$DEV/Caddyfile" <<EOF
{
	admin off
	skip_install_trust
	auto_https disable_redirects
	storage file_system {
		root "$CA_DIR"
	}
}

https://localhost:$HTTPS_PORT {
	bind 127.0.0.1 [::1]
	tls internal
	reverse_proxy 127.0.0.1:$SERVER_PORT
}
EOF
  trap 'exit 0' INT TERM
  trap cleanup EXIT
  say "Pokrećem Ghost relay server i lokalni HTTPS…"
  start_server "$LOCAL_ORIGIN"
  caddy run --config "$DEV/Caddyfile" --adapter caddyfile >"$DEV/caddy.log" 2>&1 &
  PIDS="$PIDS $!"
  if ! wait_for_health "$LOCAL_ORIGIN" "$ROOT_CERT"; then
    show_logs
    fail "server nije odgovorio preko HTTPS-a."
  fi
  say ""
  say "Server radi i odgovara preko HTTPS-a."
  trust_simulators
  cat <<EOF

────────────────────────────────────────────────────────────
  Adresa za aplikaciju:   $LOCAL_ORIGIN
  U svakom simulatoru:    Zaštita → Veza → unesi adresu iznad
────────────────────────────────────────────────────────────
U drugom prozoru Terminala (Cmd+N, pa ponovo cd u folder projekta):
  novi simulator:         bash scripts/dev_local.sh trust
  pozivnica u simulator:  bash scripts/dev_local.sh link "ghost-ecc://invite/…"
Logovi: server/.dev/server.log i server/.dev/caddy.log
Pravi iPhone ne vidi localhost; za njega koristi: bash scripts/dev_local.sh --tunnel

EOF
  keep_running
}

tunnel_mode() {
  need_node
  need cloudflared cloudflared
  check_ports "$SERVER_PORT"
  mkdir -p "$DEV"
  : >"$DEV/tunnel.log"
  trap 'exit 0' INT TERM
  trap cleanup EXIT
  say "Otvaram privremeni Cloudflare tunel…"
  cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$SERVER_PORT" >"$DEV/tunnel.log" 2>&1 &
  PIDS="$PIDS $!"
  url=""
  tries=0
  while [ -z "$url" ] && [ "$tries" -lt 80 ]; do
    url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$DEV/tunnel.log" 2>/dev/null | head -n 1)
    [ -n "$url" ] && break
    for pid in $PIDS; do kill -0 "$pid" 2>/dev/null || { show_logs; fail "tunel se zaustavio."; }; done
    sleep 0.5
    tries=$((tries + 1))
  done
  [ -n "$url" ] || { show_logs; fail "tunel nije dobio javnu adresu u roku od 40 sekundi."; }
  start_server "$url"
  if wait_for_health "$url" "" 60; then
    say "Server je dostupan sa interneta."
  else
    say "Server radi, ali adresa još nije dostupna sa interneta (DNS ponekad kasni). Provjeri je za minut u Safariju: $url/v1/health"
  fi
  cat <<EOF

────────────────────────────────────────────────────────────
  Adresa za aplikaciju:   $url
  Na iPhone-u i u simulatoru: Zaštita → Veza → unesi adresu iznad
────────────────────────────────────────────────────────────
Adresa se mijenja pri svakom pokretanju tunela; kontakti povezani preko
stare adrese tada se prekidaju, pa za svaku sesiju napravi nove pozivnice.
Samo za probne poruke: Cloudflare vidi metapodatke saobraćaja.
Logovi: server/.dev/server.log i server/.dev/tunnel.log

EOF
  keep_running
}

case "${1:-}" in
  "") local_mode ;;
  --tunnel|tunnel) tunnel_mode ;;
  trust) trust_simulators ;;
  link) open_link "${2:-}" ;;
  reset)
    port_in_use "$SERVER_PORT" && fail "server još radi; zaustavi ga sa Ctrl+C pa pokušaj ponovo."
    rm -rf "$DATA"
    say "Lokalni sandučići su obrisani. U aplikacijama obriši i stare kontakte i pozivnice."
    ;;
  -h|--help|help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) fail "nepoznata komanda '$1'. Pomoć: bash scripts/dev_local.sh help" ;;
esac
