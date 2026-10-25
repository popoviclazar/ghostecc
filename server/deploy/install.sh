#!/bin/bash
# Ghost relay: instalacija na čist Ubuntu Server (26.04 LTS; radi i na 24.04).
#
#   sudo bash deploy/install.sh relay.tvojdomen.com
#
# Šta radi: ažurira sistem, uključuje automatske sigurnosne zakrpe, instalira Node.js i Caddy,
# postavlja Ghost relay kao systemd servis, Caddy sa automatskim HTTPS sertifikatom, firewall
# (samo SSH, 80 i 443) i, uz tvoju potvrdu, SSH prijavu samo ključem.
#
# Ponovno pokretanje sa istim domenom ažurira kod i konfiguraciju; sandučići ostaju.
# Opcije:
#   --apns-key /root/AuthKey_XXXXXXXXXX.p8 --team-id TEAMID   uključuje push notifikacije
#   --topic net.ghostecc.app                                  bundle ID aplikacije (podrazumijevano)
#   --no-ssh-hardening                                        ne mijenja SSH podešavanja

set -euo pipefail

FS="${GHOST_INSTALL_ROOTFS:-}"   # koristi se samo u testovima skripte
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$FS/opt/ghost-relay"
UNIT="$FS/etc/systemd/system/ghost-relay.service"
CADDYFILE="$FS/etc/caddy/Caddyfile"
SSH_DROPIN="$FS/etc/ssh/sshd_config.d/10-ghost-hardening.conf"
APNS_DIR="$FS/etc/ghost-relay"
AUTO_UPGRADES="$FS/etc/apt/apt.conf.d/20auto-upgrades"
export DEBIAN_FRONTEND=noninteractive

step() { printf '\n==> %s\n' "$*"; }
ok() { printf '    ✓ %s\n' "$*"; }
warn() { printf '    ! %s\n' "$*"; }
fail() { printf '\nGreška: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }

DOMAIN=""
HARDEN_SSH=1
APNS_KEY=""
APNS_KEY_ID=""
TEAM_ID=""
TOPIC="net.ghostecc.app"
while [ $# -gt 0 ]; do
  case "$1" in
    --no-ssh-hardening) HARDEN_SSH=0 ;;
    --apns-key) [ $# -ge 2 ] || fail "--apns-key traži putanju do .p8 fajla."; APNS_KEY="$2"; shift ;;
    --apns-key-id) [ $# -ge 2 ] || fail "--apns-key-id traži vrijednost."; APNS_KEY_ID="$2"; shift ;;
    --team-id) [ $# -ge 2 ] || fail "--team-id traži vrijednost."; TEAM_ID="$2"; shift ;;
    --topic) [ $# -ge 2 ] || fail "--topic traži bundle ID."; TOPIC="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) fail "nepoznata opcija $1" ;;
    *) [ -z "$DOMAIN" ] || fail "navedi samo jedan domen."; DOMAIN="$1" ;;
  esac
  shift
done
[ -n "$DOMAIN" ] || { usage; exit 1; }
DOMAIN=$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z')
DOMAIN=${DOMAIN#https://}
DOMAIN=${DOMAIN%/}
[[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || fail "'$DOMAIN' nije ispravan domen (primjer: relay.tvojdomen.com)."
ORIGIN="https://$DOMAIN"
if [ -n "$APNS_KEY" ]; then
  [ -f "$APNS_KEY" ] || fail "ne postoji APNs ključ $APNS_KEY."
  grep -q "BEGIN PRIVATE KEY" "$APNS_KEY" || fail "$APNS_KEY ne izgleda kao Apple .p8 ključ."
  if [ -z "$APNS_KEY_ID" ]; then
    APNS_KEY_ID=$(basename "$APNS_KEY" | sed -nE 's/^AuthKey_([A-Z0-9]{10})\.p8$/\1/p')
    [ -n "$APNS_KEY_ID" ] || fail "ne mogu da pročitam Key ID iz imena fajla; dodaj --apns-key-id XXXXXXXXXX."
  fi
  [[ "$APNS_KEY_ID" =~ ^[A-Z0-9]{10}$ ]] || fail "Key ID mora imati 10 znakova (velika slova i cifre)."
  [[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || fail "uz --apns-key navedi --team-id (10 znakova, Apple Developer → Membership)."
  [[ "$TOPIC" =~ ^[A-Za-z0-9.-]+$ ]] || fail "--topic mora biti bundle ID aplikacije."
fi

# ---------------------------------------------------------------- provjere
[ "$(id -u)" -eq 0 ] || fail "pokreni skriptu kao root ili sa sudo."
for file in src/main.js src/relay.js src/http.js package.json deploy/ghost-relay.service deploy/Caddyfile; do
  [ -f "$SRC/$file" ] || fail "nedostaje $file. Skripta mora ostati u server/deploy, pored server/src."
done
OS_RELEASE="$FS/etc/os-release"; [ -f "$OS_RELEASE" ] || OS_RELEASE=/etc/os-release
# shellcheck disable=SC1090
. "$OS_RELEASE"
[ "${ID:-}" = ubuntu ] || fail "skripta je pisana za Ubuntu Server (pronađeno: ${PRETTY_NAME:-nepoznato})."

step "Ghost relay za $ORIGIN na ${PRETTY_NAME:-Ubuntu}"

step "Provjera DNS zapisa"
dns_ips=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
local_ips=" $(hostname -I 2>/dev/null || true) "
if [ -z "${dns_ips// /}" ]; then
  warn "$DOMAIN još nema A zapis. Dodaj ga u DNS-u domena (tip A, ime relay, vrijednost IP ovog servera)."
  warn "Instalacija se nastavlja; Caddy sam pribavlja sertifikat čim zapis proradi."
else
  match=0
  for ip in $dns_ips; do case "$local_ips" in *" $ip "*) match=1 ;; esac; done
  if [ "$match" -eq 1 ]; then ok "$DOMAIN pokazuje na ovaj server ($dns_ips)"
  else warn "$DOMAIN pokazuje na ${dns_ips}a adrese ovog servera su:$local_ips. Ako je to greška, ispravi A zapis."; fi
fi

# ---------------------------------------------------------------- paketi
step "Ažuriranje sistema (može potrajati nekoliko minuta)"
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade
apt-get -y -q install ca-certificates curl gnupg ufw unattended-upgrades
install -d -m 0755 "$(dirname "$AUTO_UPGRADES")"
cat >"$AUTO_UPGRADES" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
# System logs (e.g. Caddy error messages, which can contain an IP address) are kept at most 7 days.
install -d -m 0755 "$FS/etc/systemd/journald.conf.d"
printf '[Journal]\nMaxRetentionSec=7day\n' >"$FS/etc/systemd/journald.conf.d/ghost-retention.conf"
systemctl restart systemd-journald 2>/dev/null || true
ok "sistem ažuriran, automatske sigurnosne zakrpe uključene, sistemski logovi se čuvaju najviše 7 dana"

step "Node.js"
node_major() { node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0; }
if [ "$(node_major)" -lt 20 ]; then apt-get -y -q install nodejs || true; fi
if [ "$(node_major)" -lt 20 ]; then
  warn "Ubuntu nudi stariju verziju; dodajem zvanični NodeSource repozitorijum (Node 22)."
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" >/etc/apt/sources.list.d/nodesource.list
  apt-get update -q
  apt-get -y -q install nodejs
fi
[ "$(node_major)" -ge 20 ] || fail "Node.js 20 ili noviji nije instaliran."
NODE_BIN=$(command -v node)
ok "Node.js $(node --version) ($NODE_BIN)"

step "Caddy (HTTPS)"
if ! command -v caddy >/dev/null 2>&1; then
  # Zvanični Caddy repozitorijum, po uputstvu sa caddyserver.com.
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt >/etc/apt/sources.list.d/caddy-stable.list
  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -q
  apt-get -y -q install caddy
fi
ok "Caddy $(caddy version 2>/dev/null | awk '{print $1}')"

# ---------------------------------------------------------------- relay
step "Ghost relay servis"
install -d -m 0755 "$APP_DIR/src"
install -m 0644 "$SRC"/src/*.js "$APP_DIR/src/"
install -m 0644 "$SRC/package.json" "$APP_DIR/package.json"
mem_mb=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
relay_mb=$((mem_mb * 35 / 100))
[ "$relay_mb" -gt 1024 ] && relay_mb=1024
[ "$relay_mb" -lt 128 ] && relay_mb=128
max_mb=$((relay_mb + 512))
if [ -n "$APNS_KEY" ]; then
  install -d -m 0700 "$APNS_DIR"
  install -m 0600 "$APNS_KEY" "$APNS_DIR/apns.p8"
  printf 'GHOST_APNS_KEY_ID=%s\nGHOST_APNS_TEAM_ID=%s\nGHOST_APNS_TOPIC=%s\n' "$APNS_KEY_ID" "$TEAM_ID" "$TOPIC" >"$APNS_DIR/apns.env"
  chmod 0600 "$APNS_DIR/apns.env"
fi
PUSH_LINE=""
[ -f "$APNS_DIR/apns.p8" ] && [ -f "$APNS_DIR/apns.env" ] && PUSH_LINE="LoadCredential=apns.p8:/etc/ghost-relay/apns.p8"
install -d -m 0755 "$(dirname "$UNIT")"
sed -e "s#^Environment=GHOST_ORIGIN=.*#Environment=GHOST_ORIGIN=$ORIGIN#" \
    -e "s#^Environment=GHOST_MAX_MEMORY_MB=.*#Environment=GHOST_MAX_MEMORY_MB=$relay_mb#" \
    -e "s#^MemoryMax=.*#MemoryMax=${max_mb}M#" \
    -e "s#^ExecStart=.*#ExecStart=$NODE_BIN /opt/ghost-relay/src/main.js#" \
    -e "/^# Promijeni na svoju/d" \
    "$SRC/deploy/ghost-relay.service" >"$UNIT.tmp"
if [ -n "$PUSH_LINE" ]; then sed -i "/^ExecStart=/a $PUSH_LINE" "$UNIT.tmp"; fi
mv "$UNIT.tmp" "$UNIT"
ok "kod u /opt/ghost-relay, RAM kvota za poruke ${relay_mb} MB (server ima ${mem_mb} MB)"
if [ -n "$PUSH_LINE" ]; then
  ok "push notifikacije uključene za $(grep -oE 'TOPIC=.*' "$APNS_DIR/apns.env" | cut -d= -f2)"
  [ -n "$APNS_KEY" ] && warn "ključ je kopiran u /etc/ghost-relay; original možeš obrisati: rm $APNS_KEY"
else
  warn "push notifikacije nisu podešene (vidi --apns-key u server/README.md)"
fi

install -d -m 0755 "$(dirname "$CADDYFILE")"
if [ -f "$CADDYFILE" ] && ! grep -q "Ghost relay" "$CADDYFILE"; then
  cp "$CADDYFILE" "$CADDYFILE.pre-ghost"
  warn "postojeći Caddyfile je sačuvan kao $CADDYFILE.pre-ghost"
fi
{
  echo "# Ghost relay: napravila deploy/install.sh. Ponovno pokretanje skripte prepisuje ovaj fajl."
  sed "s/relay\.example\.com/$DOMAIN/" "$SRC/deploy/Caddyfile"
} >"$CADDYFILE"
caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 || fail "Caddyfile nije ispravan."
ok "Caddy podešen za $DOMAIN"

# ---------------------------------------------------------------- firewall
step "Firewall"
# Ubuntu pokreće SSH preko socket aktivacije, pa /run/sshd ponekad ne postoji; bez njega sshd -T/-t padaju.
install -d -m 0755 "$FS/run/sshd"
ssh_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u || true)
[ -n "$ssh_ports" ] || ssh_ports=22
for port in $ssh_ports; do ufw allow "$port/tcp" >/dev/null; done
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow 443/udp >/dev/null
ufw --force enable >/dev/null
ok "otvoreni su samo SSH ($(echo $ssh_ports)), 80 i 443"

# ---------------------------------------------------------------- SSH
step "SSH"
if [ "$HARDEN_SSH" -eq 0 ]; then
  warn "preskočeno (--no-ssh-hardening)"
elif [ -f "$SSH_DROPIN" ]; then
  ok "prijava samo ključem je već uključena"
else
  keys=0
  for file in "$FS/root/.ssh/authorized_keys" "$FS"/home/*/.ssh/authorized_keys; do
    [ -f "$file" ] && grep -qE '^(ssh-|ecdsa-|sk-)' "$file" && keys=1
  done
  answer=""
  if [ "$keys" -eq 1 ] && [ -t 0 ]; then
    printf '    Na serveru postoji SSH ključ. Jesi li se SADA prijavio tim ključem, bez lozinke servera? [d/N] '
    read -r answer || answer=""
  fi
  case "$answer" in
    d|D|da|DA|y|Y|yes)
      install -d -m 0755 "$(dirname "$SSH_DROPIN")"
      # 10- se učitava prije cloud-init podešavanja (50-), a kod sshd-a važi prva vrijednost.
      printf '%s\n' "# Ghost relay: prijava samo ključem" "PasswordAuthentication no" "KbdInteractiveAuthentication no" \
        "PermitRootLogin prohibit-password" >"$SSH_DROPIN"
      if check=$(sshd -t 2>&1); then
        systemctl reload ssh 2>/dev/null || systemctl restart ssh
        ok "prijava lozinkom isključena; SSH radi samo sa ključem"
        warn "ne zatvaraj ovaj prozor dok u NOVOM prozoru Terminala ne provjeriš da 'ssh root@IP' radi"
      else
        rm -f "$SSH_DROPIN"
        warn "SSH podešavanje nije prošlo provjeru, pa ništa nije promijenjeno: ${check:-nepoznata greška}"
      fi
      ;;
    *)
      if [ "$keys" -eq 0 ]; then
        warn "nijedan SSH ključ nije pronađen, pa prijavu lozinkom NE isključujem (da se ne zaključaš)."
        warn "Sa Maca pokreni: ssh-copy-id root@IP-servera, pa ponovo pokreni ovu skriptu."
      else
        warn "SSH podešavanja nisu mijenjana. Kad se prijaviš ključem, pokreni skriptu ponovo."
      fi
      ;;
  esac
fi

# ---------------------------------------------------------------- start
step "Pokretanje"
systemctl daemon-reload
systemctl enable ghost-relay >/dev/null 2>&1
systemctl restart ghost-relay
systemctl enable caddy >/dev/null 2>&1
systemctl reload caddy 2>/dev/null || systemctl restart caddy

healthy() { curl -fsS --max-time 5 "$1/v1/health" 2>/dev/null | grep -q '"status":"ok"'; }
local_ok=0
for _ in $(seq 1 30); do healthy http://127.0.0.1:8080 && { local_ok=1; break; }; sleep 0.5; done
[ "$local_ok" -eq 1 ] || { journalctl -u ghost-relay -n 20 --no-pager 2>/dev/null || true; fail "Ghost relay servis se nije pokrenuo (log je iznad)."; }
ok "relay servis radi"

printf '    čekam HTTPS sertifikat i javnu adresu (do 2 minuta)'
public_ok=0
for _ in $(seq 1 40); do
  healthy "$ORIGIN" && { public_ok=1; break; }
  printf '.'
  sleep 3
done
echo

if [ "$public_ok" -eq 1 ]; then
  cat <<EOF

────────────────────────────────────────────────────────────
  Server radi: $ORIGIN
  U aplikaciji: Zaštita → Veza → Podesi svoj server → unesi adresu iznad
────────────────────────────────────────────────────────────
Ažuriranje kasnije: prekopiraj novi server/ folder i ponovo pokreni ovu skriptu.
Stanje servisa: systemctl status ghost-relay   Logovi: journalctl -u ghost-relay
EOF
else
  cat <<EOF

Relay radi lokalno, ali $ORIGIN još nije dostupan sa interneta.
Najčešći uzroci:
  • A zapis za $DOMAIN još ne pokazuje na ovaj server (provjera: getent hosts $DOMAIN)
  • firewall kod provajdera (npr. Hetzner Cloud Firewall) ne propušta portove 80 i 443
Caddy pokušava sam; za par minuta provjeri: curl $ORIGIN/v1/health
Logovi sertifikata: journalctl -u caddy -n 40 --no-pager
EOF
fi
