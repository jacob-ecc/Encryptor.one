# encryptor.one

Ende-zu-Ende-Verschlüsselung im Browser. Man erzeugt einmalig eine Identität, tauscht
Public Keys aus und schickt den Chiffretext danach über einen beliebigen Kanal —
WhatsApp, Signal, E-Mail, SMS, ein Zettel. Der Betreiber des Kanals sieht nur Buchstabensalat.

Kein Server, kein Konto, keine Telemetrie. Nichts verlässt das Gerät.

---

## Aufbau

Statische Dateien, kein Build-Schritt, keine Laufzeit-Abhängigkeiten. Was im Repo liegt,
ist exakt das, was im Browser läuft — das ist bei einer Krypto-Anwendung wichtiger als
jeder Bequemlichkeitsgewinn durch ein Bundling-Werkzeug.

```
index.html                 Struktur, Icon-Sprite, Dialoge
assets/styles.css          Design-Tokens, beide Themes, Animationen
assets/seal.svg            App-Icon
src/boot.js                Theme + Sprache vor dem ersten Frame (kein Flackern)
src/app.js                 Oberfläche, Zustand, Abläufe
src/crypto.js              Krypto-Kern (der Teil, den man prüfen sollte)
src/store.js               IndexedDB-Vault, Einstellungen
src/sigil.js               Siegel-Generator
src/i18n.js                Deutsch / Englisch
src/util.js                Base64, DOM-Fabrik ohne innerHTML, Animationen
sw.js                      Offline-Betrieb
_headers                   Security-Header für Cloudflare Pages
test/crypto.test.mjs       52 Tests gegen den Krypto-Kern (bricht bei Fehlern mit Exit-Code 1 ab)
```

### Lokal starten

```bash
npm run serve      # http://localhost:8080
npm test           # Krypto-Tests, braucht Node 18+
```

Über `file://` läuft die App nicht: ES-Module und die Web Crypto API brauchen einen
Secure Context. `localhost` gilt als sicher, ein simpler HTTP-Server genügt also.

---

## Deployment auf Cloudflare Pages

1. Repo zu GitHub pushen.
2. Cloudflare Dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**.
3. Beim Build-Setup:
   - **Framework preset:** `None`
   - **Build command:** leer lassen
   - **Build output directory:** `/`
4. **Deploy**. Fertig.

`_headers` wird von Pages automatisch ausgewertet und setzt die Security-Header. Nach
dem ersten Deploy unter *Custom domains* die eigene Domain verbinden.

> **Wichtig:** Build command wirklich leer lassen. Die `package.json` existiert nur für
> `npm test` und `npm run serve` — sie ist kein Build-Manifest. Wenn Cloudflare
> versucht, etwas zu bauen, ist die Einstellung falsch.

### Was `_headers` bewirkt

`default-src 'none'` plus `script-src 'self'` heißt: Der Browser lädt ausschließlich
Code von der eigenen Domain. Kein Inline-Script, kein Inline-Style, kein CDN. Deshalb
gibt es im gesamten Projekt kein `innerHTML` und keine `style="..."`-Attribute —
alles läuft über `createElement`/`textContent` und die CSSOM.

`require-trusted-types-for 'script'` plus `trusted-types sw` sperrt alle DOM-Senken, über
die sich Code einschleusen ließe (`innerHTML`, `eval`, Script-URLs). Die einzige erlaubte
Policy heißt `sw` und lässt genau eine URL durch: `/sw.js` für die Service-Worker-Registrierung.
Ohne sie verweigert Chromium die Registrierung — die App wäre dort nicht offline-fähig.

Dieselbe CSP steht zusätzlich als `<meta>`-Tag in `index.html`, als zweite Linie für Hosts,
die `_headers` nicht auswerten. Wer die eine ändert, muss die andere mitziehen.

`connect-src 'self'` erlaubt nur den Service Worker. Die App macht keine Netzwerkanfragen;
sollte je eine auftauchen, blockiert der Browser sie. Das ist die eigentliche Zusicherung
hinter „nichts verlässt das Gerät" — sie hängt nicht davon ab, dass man dem Code glaubt.

---

## Krypto

### Identität

ECDH auf P-256. Der private Schlüssel wird mit AES-256-GCM aus einer Passphrase verpackt
(PBKDF2-SHA-256, 600 000 Runden, 16 Byte Salt) und liegt nur so in IndexedDB. Nach dem
Entsperren existiert er als **nicht-exportierbarer** `CryptoKey`: JavaScript kann damit
rechnen, aber nicht an das Schlüsselmaterial heran — auch nicht bei einem XSS.

Der Public Key liegt dagegen offen im Vault und in der Sicherung. Beim Entsperren prüft
die App deshalb, ob privater und öffentlicher Schlüssel zusammengehören (ECDH mit einem
Probe-Schlüssel gegen beide Hälften). Ohne diese Prüfung ließe sich in einer Sicherung
der Public Key austauschen: Die Passphrase würde weiter passen, und die App würde fortan
einen fremden Schlüssel als eigene Identität weitergeben — samt passendem Fingerabdruck.

`meta` und `data` werden in einer einzigen IndexedDB-Transaktion geschrieben, wo sie
voneinander abhängen (Passphrasen- und Schlüsselwechsel). Ein Absturz dazwischen kann so
keinen Vault hinterlassen, dessen Kontakte mit einem nicht mehr existierenden Schlüssel
versiegelt sind.

Aus der Passphrase werden per HKDF zwei getrennte Schlüssel abgeleitet: einer zum
Verpacken des privaten Schlüssels, einer für die Kontaktdaten. Beides sind
unterschiedliche Aufgaben und bekommen deshalb unterschiedliche Schlüssel.

### Nachrichtenumschlag (`ENC1.`)

Pro Nachricht wird ein ephemeres Schlüsselpaar erzeugt:

```
dh_e = ECDH(eph_priv, empfaenger_pub)     Vorwärtssicherheit senderseitig
dh_s = ECDH(sender_priv, empfaenger_pub)  implizite Absender-Authentizität
k    = HKDF-SHA256(dh_e ‖ dh_s, salt, info)
```

Aus `k` kommen zwei AES-256-GCM-Schlüssel — einer für den Header, einer für den Body.
Beide Aufrufe binden den kompletten vorangehenden Header als AAD, jedes Bit ist also
authentifiziert.

`dh_s` liefert Authentizität ohne Signatur. Das ist Absicht: Eine Signatur wäre ein
Beweis gegenüber Dritten, dass genau diese Person genau diese Nachricht geschrieben hat.
Über ein geteiltes Geheimnis kann der Empfänger den Absender überprüfen, aber niemandem
sonst beweisen — dieselbe Eigenschaft, die Signal anstrebt.

**Sealed Sender:** Die Absenderkennung liegt selbst verschlüsselt im Umschlag. Wer den
Chiffretext abfängt, sieht nicht, von wem er stammt. Nebeneffekt: Der Empfänger muss
beim Entschlüsseln nichts auswählen — es funktioniert einfach.

```
Offset  Länge   Feld
0       2       Magic "E1"
2       1       Flags
3       4       Body-Länge (u32BE)
7       32      Salt
39      65      Ephemeraler Public Key
104     12      IV (Header)
116     81      Absender, verschlüsselt      AAD = bytes[0..116]
197     12      IV (Body)
209     n       Body                          AAD = bytes[0..209]
```

Der Body ist JSON: `{ v, t, m, rk?, p }`. `p` ist Füllung: Die Payload wird auf mindestens
256 Byte und darüber auf die nächste [Padmé](https://lbarman.ch/blog/padme/)-Stufe
aufgefüllt (höchstens 12 % Overhead). Ohne Padding verrät die Chiffretextlänge die
Textlänge aufs Byte — „ja“ und „nein“ wären unterscheidbar. `rk` trägt beim
Schlüsselwechsel den neuen Public Key (siehe unten). Ältere Versionen ignorieren beide
Felder; das Format ist in beide Richtungen kompatibel.

Das Längenfeld macht den Umschlag selbst-begrenzend. Ohne das bricht die Entschlüsselung,
sobald jemand den Block mitsamt umgebendem Chatverlauf kopiert — der häufigste Fall
überhaupt. Es steht in beiden AADs und ist damit authentifiziert.

### Schlüsselwechsel

Unter *Einstellungen → Schlüssel* erzeugt „Schlüssel jetzt wechseln“ ein neues Paar. Der
alte Schlüssel wandert in den Vault-Eintrag `prev`, mit derselben Passphrase verpackt.

Die Kontakte erfahren davon **mit der nächsten Nachricht**, ohne dass jemand etwas tun muss:

```
Absender   = alter Schlüssel        (den kennt und prüft der Empfänger)
Payload.rk = neuer Public Key       (durch dh_s authentifiziert)
```

Nur wer den bisherigen privaten Schlüssel besitzt, kann ein solches Update erzeugen —
es ist dieselbe Authentifizierung wie bei jeder Nachricht.

Nach mehreren Wechseln reicht das nicht: Alice wechselt K1 → K2, Bob übernimmt K2, antwortet
aber nicht. Alice wechselt erneut auf K3 und sendet weiter von K1 aus, weil sie nicht weiß,
dass Bob K2 schon hat. Deshalb beglaubigen **alle** früheren Schlüssel, die Alice noch hat,
den neuen mit (`ra`, je 16 Byte, gebildet wie `dh_s` über ECDH mit dem Empfänger).

Die App des Empfängers übernimmt `rk` automatisch, **aber nur**, wenn genau der Schlüssel,
den sie für den Kontakt gespeichert hat, das Update beglaubigt — als Absender oder per
`ra`. Ein wiedereingespieltes altes Update (Rollback) ändert nichts, ebenso eines von einem
Unbekannten oder von jemandem, der einen schon ausgemusterten Schlüssel erbeutet hat, etwa
aus einer alten Sicherung. Hat der Empfänger die neue Kontaktkarte schon separat
gespeichert, werden beide Einträge zusammengeführt, sofern der zweite ungeprüft ist. Der Prüfstatus („verifiziert“) bleibt erhalten, weil die
Kette vom verifizierten Schlüssel aus beglaubigt ist; Kontaktdetail und Entschlüsseln-
Ansicht zeigen den Wechsel aber sichtbar an. Wer nicht warten will, erzeugt im
Kontaktdetail gezielt eine „Update-Nachricht“.

Pro Kontakt merkt sich die App, welchen ihrer Schlüssel das Gegenüber kennt (`mk`).
Solange das ein früherer ist, gehen Nachrichten von diesem aus und tragen `rk`. Sobald
eine Antwort an den *neuen* Schlüssel eintrifft, ist klar, dass das Update angekommen
ist — ab dann wird normal gesendet. Wechseln beide gleichzeitig, konvergiert das von
selbst.

Beim Entschlüsseln probiert die App erst den aktuellen, dann die früheren Schlüssel. Der
versiegelte Absender-Header dient dabei als Schlüsselerkennung. Nachrichten, die noch an
den alten Schlüssel unterwegs waren, bleiben so lesbar.

Frühere Schlüssel werden nach einer einstellbaren Frist gelöscht (7/30/90 Tage oder nie,
Standard 30). **Erst das Löschen bringt den Sicherheitsgewinn:** Was an einen gelöschten
Schlüssel ging, kann auch jemand, der später Gerät *und* Passphrase erbeutet, nicht mehr
lesen. Das ist keine lückenlose Vorwärtssicherheit wie beim Double Ratchet, begrenzt aber
das Zeitfenster. Zwei Punkte gehören dazu:

- Alte **Sicherungsdateien** enthalten alte Schlüssel. Nach einem Wechsel eine neue
  Sicherung exportieren und die alten löschen.
- Wer das Update bis zum Löschen nicht erhalten hat, muss dich neu hinzufügen und den
  Fingerabdruck erneut vergleichen. Solange noch irgendein früherer Schlüssel existiert,
  sendet die App von diesem aus.

### Fingerabdruck und Siegel

Aus SHA-256 des Public Keys entstehen 100 Bit in Crockford-Base32 (`6C2R-QZE8-…`) und
zusätzlich ein **Siegel**: ein deterministisch generiertes Emblem. Zwei Schlüssel zu
vergleichen, indem man zwanzig Zeichen abliest, macht in der Praxis niemand. Zwei Bilder
zu vergleichen schon.

---

## Was das schützt — und was nicht

**Schützt gegen:** den Messenger-Betreiber, mitlesende Netzwerke, Server-Leaks beim
Anbieter, jemanden mit Zugriff auf das Gerät ohne die Passphrase.

**Schützt nicht gegen:**

- **Kompromittierte Endgeräte.** Ein Keylogger oder Screenshot-Trojaner sieht den
  Klartext, bevor er verschlüsselt wird. Dagegen hilft keine Verschlüsselung.
- **Metadaten.** Dass ihr kommuniziert, wie oft und wie lang die Nachrichten sind,
  bleibt für den Kanal sichtbar.
- **Untergeschobene Schlüssel.** Wenn jemand den Schlüsselaustausch manipuliert, redet
  ihr beide mit dem Angreifer. Deshalb der Fingerabdruck: einmal über einen zweiten
  Kanal vergleichen — Telefon, persönlich, Videoanruf.
- **Einen gestohlenen eigenen Schlüssel (Key Compromise Impersonation).** Die
  Authentifizierung über `dh_s` ist gewollt abstreitbar, und das hat eine Kehrseite:
  `ECDH(A, B) = ECDH(B, A)`. Wer deinen privaten Schlüssel samt Passphrase erbeutet, kann
  dir Nachrichten im Namen jedes Kontakts unterschieben — auch einen Schlüsselwechsel.
  Dagegen hilft nur eine Signatur, und die würde die Abstreitbarkeit kosten. Nach einem
  Geräteverlust: sofort selbst den Schlüssel wechseln und Fingerabdrücke neu vergleichen.
- **Einen kompromittierten Server.** Eine Web-App lädt ihren Code von dem Server, der sie
  ausliefert. Wer den Server, das Cloudflare-Konto oder das GitHub-Repo kontrolliert, kann
  manipulierten Code verteilen. Der Service Worker liefert nach dem ersten Besuch aus dem
  Cache, holt Updates aber regelmäßig nach. Wer das ausschließen muss, betreibt die App
  lokal (`npm run serve`) aus einem geprüften Checkout.
- **Rückwärtige Vorwärtssicherheit.** Der ephemere Schlüssel schützt den *Absender*:
  wird sein Gerät später kompromittiert, bleiben gesendete Nachrichten unlesbar. Für den
  *Empfänger* gilt das nicht — sein Langzeitschlüssel entschlüsselt alles, was er je
  bekommen hat — bis er ihn per Schlüsselwechsel ablöst und der alte gelöscht ist.
  Vollständige Vorwärtssicherheit bräuchte einen Double Ratchet, der Zustand über
  Nachrichten hinweg voraussetzt. Das passt nicht zu einem Werkzeug, das „kopieren,
  einfügen, fertig" sein soll.

Wer gegen einen Angreifer mit Zugriff auf das Endgerät verteidigen muss, braucht Signal,
nicht dieses Werkzeug.

---

## Zur Passphrase

Sie ist optional-fähig gebaut, aber standardmäßig an, und das aus gutem Grund: Ohne sie
liegt der private Schlüssel im Klartext im Browserspeicher — lesbar für jeden mit
Gerätezugriff, für bösartige Erweiterungen und für Forensik-Werkzeuge.

Der Preis: Passphrase vergessen heißt Identität weg. Es gibt keine Wiederherstellung,
weil es niemanden gibt, der wiederherstellen könnte. Dagegen hilft der verschlüsselte
Backup-Export in den Einstellungen — die Sicherung enthält den weiterhin verpackten
Schlüssel und ist ohne Passphrase nutzlos, kann also gefahrlos in eine Cloud.

Die vorgeschlagene Passphrase besteht aus 8 von 130 Wörtern, gleichverteilt gezogen
(Rejection Sampling statt Modulo): rund 56 Bit.

Drei Fehlversuche löschen **nichts**. Stattdessen wächst die Wartezeit exponentiell
(gedeckelt bei zwei Minuten). Automatisches Löschen nach Fehlversuchen klingt nach
Sicherheit, ist aber vor allem ein Weg, sich selbst auszusperren — und ein Angriffsvektor
für jeden, der kurz an ein entsperrtes Gerät kommt. Die Wartezeit ist eine Bremse für
Menschen am Gerät, keine Schutzmaßnahme: Wer den Vault kopiert, rät offline. Dagegen
stehen allein PBKDF2 und die Länge der Passphrase.

Die automatische Sperre zählt nur Tastatur und Zeiger als Aktivität. Die Rückkehr in den
Tab prüft zuerst, ob die Frist abgelaufen ist — mobile Browser frieren Hintergrund-Tabs
ein, der Timer läuft dort nicht.

---

## Lizenz

MIT.
