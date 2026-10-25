# Server

Relay server je u direktorijumu `server/`: Node.js bez ijedne npm zavisnosti, testiran (`npm test`) i provjeren nezavisnim Python klijentom (`python3 test/crosscheck.py`). Uputstvo za instalaciju na Ubuntu Server 26.04 LTS je u `server/README.md`, a protokol u `docs/RELAY-PROTOCOL.md`.

## Šta server čuva

- **Na disku** (`queues.json`, dozvole 0600, atomičan upis): nasumične ID-eve sandučića, javne Ed25519 ključeve sandučića, šifrovane pozivnice dok nisu iskorišćene i dan (ne vrijeme) posljednjeg čitanja radi brisanja napuštenih sandučića.
- **Samo u RAM-u**: šifrate poruka do potvrde ili isteka (najviše 24 h), APNs tokene uređaja, nonce-ove i brojače za ograničenje zahtjeva po IP adresi.
- **Nikad**: Ghost ID-eve, identitetske ključeve, imena, sadržaj, logove zahtjeva sa IP adresama ili ID-evima.

Restart servera briše nedostavljene poruke, ali sandučići i veze ostaju.

## Šta server i dalje vidi

TLS skriva saobraćaj od posmatrača na mreži, ali operater servera vidi IP adresu, vrijeme i veličinu (dopunjenih) paketa, kao i koji sandučići se čitaju zajedno u istom zahtjevu. Ne vidi ko je ko niti povezuje pošiljaočev i primaočev sandučić, osim analizom vremena. Za skrivanje IP adrese korisnik može koristiti VPN ili Tor; ugrađeno onion rutiranje nije dio ove verzije.

## Notifikacije

Dok je aplikacija otvorena, klijent provjerava sandučiće svake 3 sekunde. Kad je zatvorena, server (ako je podešen APNs ključ) šalje Apple-u obavještenje sa fiksnim tekstom „Nova poruka“, bez pošiljaoca, ID-eva i sadržaja, najviše jedno na 15 sekundi po uređaju. Veza između tokena uređaja i sandučića postoji samo u RAM-u. Podešavanje: `server/README.md` → Push notifikacije.
