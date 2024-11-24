# Aplikacija za izradu hash-ova može poslužiti za sigurne lozinke

## SHA-256
* Što je? SHA-256 je član obitelji Secure Hash Algorithm (SHA-2), razvijen od strane NSA. Generira fiksnu duljinu hash-a od 256 bita.
* Primjena: Koristi se u kriptografiji, digitalnim potpisima, autentifikaciji podataka i blockchainu (npr. Bitcoin).
* Sigurnost: Vrlo siguran, no ranjiv na brute force ako hashing nije "posoljen".
## SHA-512
* Što je? Sličan SHA-256, ali generira veći hash (512 bita).
* Prednost: Bolje performanse na 64-bitnim sustavima i otporniji na određene napade.
* Primjena: Sigurnosno osjetljive aplikacije koje zahtijevaju veće hasheve.
## Argon2
* Što je? Moderni password hashing algoritam, pobjednik Password Hashing Competitiona 2015.
* Prednost: Otpornost na GPU napade, prilagodljiv po memoriji i vremenu (parametri mogu kontrolirati koliko resursa treba).
* Primjena: Hashiranje lozinki i zaštita od brute force napada.
* Sigurnost: Vrlo siguran; smatra se najboljim za hashiranje lozinki danas.
## bcrypt
* Što je? Password hashing algoritam baziran na Blowfish šifri. Automatski ugrađuje salt u izlaz.
* Prednost: Sporo i prilagodljivo, čime se otežava brute force.
* Primjena: Hashiranje lozinki u aplikacijama.
* Sigurnost: Dobar izbor za lozinke, ali sporiji od Argon2 i manje fleksibilan.
## BLAKE2
* Što je? Brža i sigurnija alternativa SHA-2, razvijena 2012. godine.
* Prednost: Brža od SHA-256/512, podržava personalizaciju i salt.
* Primjena: Kriptografija, verifikacija podataka, hashiranje podataka.
* Sigurnost: Sigurnija i brža od SHA-2, ali manje prihvaćena u industriji.
## Salt + SHA-256
* Što je? Kombinacija randomiziranog salta (nasumični niz bajtova) i SHA-256 algoritma.
* Kako radi: Salt se dodaje podacima prije hashiranja, čime se onemogućavaju napadi putem precomputed Rainbow Tables.
* Primjena: Autentifikacija lozinki i zaštita korisničkih podataka.
* Sigurnost: Ovisno o implementaciji; dodavanje salta značajno povećava sigurnost SHA-256.
## SHA-3-256 i SHA-3-512
* SHA-3 je dio obitelji Secure Hash Algorithm (SHA), no za razliku od SHA-2 (koji koristi konstrukciju Merkle–Damgård), SHA-3 temelji se na 
  potpuno drukčijem algoritmu nazvanom Keccak.

## SHA-3-256
* Što je? Generira 256-bitni hash. Manji je brat SHA-3-512.
* Primjena: Slična SHA-256, ali koristi se kada je potrebna otpornost na specifične napade na konstrukcije SHA-2.
* Sigurnost: Vrlo siguran. SHA-3 nije ranjiv na poznate slabosti Merkle–Damgård konstrukcija.
## SHA-3-512
* Što je? Generira 512-bitni hash. Pogodan za aplikacije koje zahtijevaju još veću sigurnost.
* Primjena: Sigurnosno kritične aplikacije s dugoročnim zahtjevima za integritet.
* Sigurnost: Još otporniji na kolizije i preimage napade.
* Zašto SHA-3?
* SHA-3 nije zamjena za SHA-2, već je alternativa. 
* SHA-2 je još uvijek siguran, ali SHA-3 dodaje dodatni sloj sigurnosti koristeći drukčiju matematičku konstrukciju.

* Za što se koriste hash algoritmi?
1. Provjera integriteta podataka
* Hash algoritmi se koriste kako bi se osiguralo da podaci nisu izmijenjeni tijekom prijenosa ili pohrane.
* Primjer: Digitalni potpisi, preuzimanje datoteka (provjera checksum-a).
2. Hashiranje lozinki
* Algoritmi poput Argon2, bcrypt, SHA-256 (s saltom) koriste se za pohranu lozinki.
* Lozinke se nikad ne pohranjuju u izvornom obliku; hash osigurava da su sigurne i da ih napadači teško probiju.
3. Digitalni potpisi i certifikati
* Algoritmi poput SHA-256 i SHA-3 koriste se u kriptografskim digitalnim potpisima (npr. u SSL/TLS certifikatima).
4. Blockchain
* Blockchain (poput Bitcoina) koristi hash algoritme poput SHA-256 za rudarenje blokova i povezivanje blokova u lanac.
5. Verifikacija podataka
* Hashovi se koriste za brzo uspoređivanje velikih podataka (npr. u bazama podataka).
* Umjesto uspoređivanja cijelog sadržaja, dovoljno je usporediti hash vrijednosti.
6. Generiranje jedinstvenih identifikatora
* Hash funkcije stvaraju jedinstvene identifikatore za podatke, dokumente ili poruke.
7. Kriptografski ključevi
* Hash algoritmi pomažu u generiranju sigurnih ključeva za šifriranje (npr. u kombinaciji s HMAC-om).
* Primjena specifičnih algoritama
* SHA-256 i SHA-512: Provjera integriteta podataka, blockchain, digitalni potpisi.
* SHA-3-256 i SHA-3-512: Slične aplikacije kao SHA-2, ali za dodatnu sigurnost (otpornost na nove napade).
* Argon2 i bcrypt: Isključivo za lozinke (otpornost na brute force i GPU napade).
* BLAKE2: Brza alternativa SHA-2; koristi se za hashiranje podataka u aplikacijama gdje su brzina i sigurnost važni.
* Salt + SHA-256: Osiguranje lozinki uz dodatnu zaštitu od Rainbow Table napada.

## Možete posjetiti moju web stranicu!
###   https://cybersecuritycfdtrading.com.hr/   ###