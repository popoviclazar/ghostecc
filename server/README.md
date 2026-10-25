# Ghost relay server

Relay za Ghost ECC: anonimni jednosmjerni sandučići, samo šifrati, poruke samo u RAM-u. Node.js 20 ili noviji, bez npm zavisnosti.

## Lokalno

```bash
cd server
npm test                          # 14 testova: protokol, sigurnost, limiti, HTTP tok
python3 test/crosscheck.py        # nezavisni klijent (pip install cryptography) protiv pravog procesa
GHOST_ORIGIN=https://relay.example.com GHOST_DATA_DIR=./data node src/main.js
```

## Instalacija na internet server (jedna komanda)

Potrebni su VPS sa Ubuntu Server 26.04 LTS (radi i 24.04) i domen. Dovoljno je 2 vCPU i 2–4 GB RAM-a.

1. **DNS:** u podešavanjima domena (npr. GoDaddy → DNS) dodaj zapis tipa **A**, ime `relay`, vrijednost = IPv4 adresa servera. Ako server ima IPv6, dodaj i **AAAA** zapis.
2. **SSH ključ** (ako ga nisi dodao pri pravljenju servera), na Macu:
   ```bash
   ssh-copy-id root@IP-SERVERA
   ```
3. **Kopiranje servera**, na Macu iz foldera projekta:
   ```bash
   rsync -a --exclude .dev server/ root@IP-SERVERA:/root/ghost-relay-src/
   ```
4. **Instalacija**, na serveru:
   ```bash
   ssh root@IP-SERVERA
   bash /root/ghost-relay-src/deploy/install.sh relay.tvojdomen.com
   ```

Skripta ažurira sistem i uključuje automatske sigurnosne zakrpe, instalira Node.js i Caddy, postavlja relay kao servis sa ograničenjima, pribavlja HTTPS sertifikat, otvara samo SSH, 80 i 443, i na kraju provjerava da je `https://relay.tvojdomen.com/v1/health` dostupan. Prijavu lozinkom isključuje samo ako na serveru postoji SSH ključ i potvrdiš da si se njime prijavio, da se ne bi zaključao. Ako provajder ima svoj firewall (npr. Hetzner Cloud Firewall), u njemu dozvoli portove 22, 80 i 443.

**Ažuriranje:** ponovi korake 3 i 4. Sandučići ostaju, a nedostavljene poruke se pri restartu gube.

Ručna instalacija, korak po korak, odgovara sadržaju `deploy/install.sh`, `deploy/ghost-relay.service` i `deploy/Caddyfile`.

`GHOST_ORIGIN` mora biti tačno ona adresa koju korisnici unose (https, mala slova, bez putanje), jer je dio svakog potpisa; skripta ga postavlja iz domena.

## Push notifikacije

1. Na developer.apple.com → Certificates, Identifiers & Profiles → **Keys** → **+**: upiši ime (npr. „Ghost relay“), označi **Apple Push Notifications service (APNs)**; ako traži okruženje, izaberi **Sandbox & Production**. Sačuvaj i preuzmi `AuthKey_XXXXXXXXXX.p8`. Fajl se može preuzeti **samo jednom**, pa ga sačuvaj na sigurno.
2. Team ID je u Membership details (10 znakova, npr. `AB12CD34EF`).
3. Sa Maca: `scp ~/Downloads/AuthKey_XXXXXXXXXX.p8 root@IP-SERVERA:/root/`
4. Na serveru:
   ```bash
   bash /root/ghost-relay-src/deploy/install.sh relay.tvojdomen.com --apns-key /root/AuthKey_XXXXXXXXXX.p8 --team-id AB12CD34EF
   rm /root/AuthKey_XXXXXXXXXX.p8
   ```
   Key ID se čita iz imena fajla. `--topic` je bundle ID aplikacije i podrazumijevano je `net.ghostecc.app`; ako u Xcode-u promijeniš bundle ID, navedi ga i ovdje.
5. `journalctl -u ghost-relay -n 5` treba da pokaže `push on (net.ghostecc.app)`.

Ključ ostaje u `/etc/ghost-relay` (dozvole 0600) i servisu se predaje kao systemd credential; kasnija pokretanja skripte bez `--apns-key` zadržavaju postojeće podešavanje.

## Održavanje

- Stanje je u `/var/lib/ghost-relay/queues.json`. Ako ga uključiš u bekap, bekapuješ samo ID-eve sandučića i javne ključeve; poruke nikad nisu na disku.
- Logovi (`journalctl -u ghost-relay`) sadrže samo pokretanje i generičke greške.
- Ažuriranje: zamijeni `src/`, pa `sudo systemctl restart ghost-relay`. Nedostavljene poruke se pri restartu gube, veze ostaju.

## Podešavanja (env)

| Promjenljiva | Podrazumijevano | Značenje |
|---|---|---|
| `GHOST_ORIGIN` | obavezno | javna https adresa servera |
| `GHOST_LISTEN` | `127.0.0.1:8080` | lokalna adresa iza Caddy-ja |
| `GHOST_DATA_DIR` | `./data` | direktorijum za `queues.json` |
| `GHOST_TRUST_PROXY` | `0` | `1` kad je ispred Caddy (IP za ograničenje zahtjeva iz X-Forwarded-For) |
| `GHOST_MAX_MEMORY_MB` | `1024` | ukupna RAM kvota za nedostavljene šifrate |
