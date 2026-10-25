# Ghost relay protokol v1

Ovaj dokument je izvor istine za klijent (`Networking/RelayClient.swift`) i server (`server/src/relay.js`). Oba testa koriste isti test vektor na dnu.

## Model

Server ne poznaje naloge, Ghost ID-eve ni identitetske ključeve. Poznaje samo **sandučiće** (queue): jednosmjerne redove sa dva nasumična ID-a od 24 bajta (base64url, 32 znaka).

- `recipientId` zna samo vlasnik sandučića; njime čita, potvrđuje i briše.
- `senderId` zna samo onaj kome je vlasnik dao adresu; njime šalje.
- Vlasnik pravi sandučić sa sopstvenim Ed25519 ključem (`recipientKey`), posebnim za svaki sandučić.
- Prvi pošiljalac koji pošalje važeću, potpisanu poruku sa `senderKey` „zaključava“ sandučić. Nakon toga server prihvata samo potpise tim ključem, a pozivnica na sandučiću se briše.

Za jedan razgovor postoje dva sandučića, po jedan na serveru svakog učesnika. Server vidi samo da je neko upisao u sandučić X i da je neko čitao sandučić Y; veza X↔Y i Ghost ID-evi nisu dio protokola.

## Tok jednokratne pozivnice

1. **Bob (poziva)**: pravi jednokratni libsignal bundle (EC prekey, potpisani prekey, Kyber prekey), šifruje ga AES-GCM ključem `x` od 32 bajta (AAD: `GHOST-INVITE-v1|` + Base64 identitetskog ključa) i pravi sandučić sa tim šifratom kao `invitation`.
2. Link: `ghost-ecc://invite/` + base64url(JSON `{k, q, s, v, x}`), gdje je `s` origin servera, `q` senderId, `k` Bobov identitetski ključ (33 bajta), `x` ključ pozivnice. Server nikad ne vidi `x`.
3. **Alice (prihvata)**: preuzima `GET /v1/invitations/{q}`, otvara bundle ključem `x`, provjerava da se identitet poklapa sa `k`, pokreće libsignal sesiju, pravi sopstveni sandučić i šalje Bobu `hello` (sa svojim senderId) na `q`, uz svoj `senderKey`. Time zaključava Bobov sandučić.
4. **Bob**: prima PreKey poruku, iz nje dobija Alicin identitet, pravi kontakt i šalje `ready` u Alicin sandučić, čime zaključava i njega.
5. Sadržaj (tekst, fotografija) šalje se tek kada korisnik uporedi sigurnosni broj.

## Potpis zahtjeva

Svaki potpisani zahtjev nosi `auth = { timestamp, nonce, signature }`:

- `timestamp`: Unix milisekunde, cijeli broj; server dozvoljava ±120 s.
- `nonce`: 16 nasumičnih bajtova, base64url bez dopune (22 znaka); server odbija ponovljeni nonce 5 minuta.
- `signature`: Ed25519 potpis (64 bajta, standardni Base64) nad UTF-8 tekstom, linije spojene sa `\n`, bez završnog novog reda:

```
GHOST-RELAY-v1
<origin>          https://host[:port], mala slova, bez kose crte na kraju
<op>              create | send | fetch | ack | delete | notify
<queueId>         "-" za create, senderId za send, recipientId za ostalo
<timestamp>
<nonce>
<digest>          SHA-256, mala heksadecimalna slova, nad ulazom ispod
```

Ulaz za `digest`:

| op | ulaz |
|---|---|
| create | `recipientKey` (32 sirova bajta) + `invitation` bajtovi (ako postoji) |
| send | `message` bajtovi + UTF-8 `|<expiresAt>|` + `senderKey` sirovi bajtovi (samo ako je poslat) |
| fetch | prazan niz |
| ack | UTF-8 ID-eva poruka spojenih zarezom |
| delete | prazan niz |
| notify | UTF-8 `<token>|<environment>` (prazan token kad se registracija uklanja) |

Origin u potpisu sprečava da se potpis za jedan server iskoristi na drugom. Kod `clock_skew` greške odgovor sadrži `serverTime`; klijent ispravlja razliku i potpisuje ponovo jednom.

## Push notifikacije (opciono)

`POST /v1/notify` sa `{ token, environment, queues: [{ recipientId, auth }] }` veže APNs token uređaja (heksadecimalno; `null` uklanja vezu) za do 64 sopstvena sandučića, svaki potpisan svojim ključem. `environment` je `sandbox` (build iz Xcode-a) ili `production` (TestFlight, App Store). Kad u sandučić stigne nova poruka, server šalje Apple-u obavještenje fiksnog teksta („Nova poruka“), najviše jedno na 15 sekundi po uređaju, sa `apns-collapse-id`, bez ID-eva i sadržaja. Veza token↔sandučić postoji samo u RAM-u servera; klijent je obnavlja pri svakom povratku u aplikaciju.

## Format poruke u sandučiću

Binarni okvir: bajt `2` (verzija), bajt tipa libsignal poruke (`2` whisper, `3` prekey), zatim šifrat. Bez pošiljaoca, primaoca i ID-a. Unutar šifrata je JSON `PrivatePayload` (verzija 2, vrste `text`, `photo`, `hello`, `ready`), dopunjen do fiksne veličine (1, 4, 16, 64 KB, pa višestruko od 256 KB) da dužina ne otkriva sadržaj.

## Ograničenja servera

Poruka do 6 000 000 bajtova; isti šifrat u istom sandučiću je idempotentan. Rok najviše 24 h od prijema. Do 100 poruka i 24 MB po sandučiću, ukupna RAM kvota podesiva. Fetch: do 64 sandučića, do 50 poruka i ~9 MB po odgovoru, kružno između sandučića. Nezaključan sandučić sa pozivnicom briše se nakon 7 dana, a sandučić koji niko ne čita 60 dana. Na disk se upisuju samo ID-evi sandučića, javni ključevi i šifrovane pozivnice, nikad poruke.

## Test vektor

```
digest("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
message(origin=https://relay.example.com, op=fetch, queueId=Q, timestamp=1700000000000, nonce=N, digest=gore)
= "GHOST-RELAY-v1\nhttps://relay.example.com\nfetch\nQ\n1700000000000\nN\n2cf24dba…9824"
```
