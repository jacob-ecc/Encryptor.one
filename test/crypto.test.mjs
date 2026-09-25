import {
  createIdentity, unwrapIdentity, rewrapIdentity, deriveVaultKeys,
  encryptMessage, decryptMessage, fingerprint, sealJSON, openJSON,
  encodeContactCard, parseContactInput, randomBytes, randomInt, keyPairMatches, paddedLength,
  CryptoError, KDF_ITERATIONS
} from '../src/crypto.js';
import { b64urlDecode } from '../src/util.js';

let failed = 0;
const ok = (label, cond) => {
  if (!cond) failed++;
  console.log((cond ? '  PASS  ' : '! FAIL  ') + label);
};
const same = (a, b) => !!a && !!b && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const envBytes = (armored) => b64urlDecode(armored.slice(5));

// --- Vault-Schluessel + Identitaet ---
const salt = randomBytes(16);
console.time('PBKDF2 600k');
const A = await deriveVaultKeys('korrektes-pferd-batterie-heftklammer', salt, KDF_ITERATIONS);
console.timeEnd('PBKDF2 600k');
const B = await deriveVaultKeys('anderes-geheimnis-mit-laenge-xy', randomBytes(16));

const alice = await createIdentity(A.wrapKey);
const bob   = await createIdentity(B.wrapKey);
ok('Public Key ist 65 Byte, unkomprimiert', alice.publicKeyRaw.length === 65 && alice.publicKeyRaw[0] === 4);
ok('Privater Schluessel ist NICHT exportierbar', alice.privateKey.extractable === false);

// erneutes Entpacken mit derselben Passphrase
const A2 = await deriveVaultKeys('korrektes-pferd-batterie-heftklammer', salt, KDF_ITERATIONS);
const reopened = await unwrapIdentity(A2.wrapKey, alice.wrapped, alice.iv);
ok('Entpacken mit gleicher Passphrase klappt', !!reopened);

let wrongFailed = false;
try { await unwrapIdentity(B.wrapKey, alice.wrapped, alice.iv); } catch { wrongFailed = true; }
ok('Falsche Passphrase entpackt nicht', wrongFailed);

// --- Nachricht ---
const msg = 'Treffen 19:30 am Nordufer. Umlaute: äöüß — Emoji: 🔐\nZweite Zeile.';
const ct = await encryptMessage({
  text: msg, senderPrivateKey: alice.privateKey,
  senderPublicKeyRaw: alice.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw
});
ok('Chiffretext hat ENC1-Praefix', ct.startsWith('ENC1.'));

const out = await decryptMessage({ armored: ct, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
ok('Klartext identisch', out.text === msg);
ok('Absender wird erkannt', Buffer.compare(Buffer.from(out.senderPublicKeyRaw), Buffer.from(alice.publicKeyRaw)) === 0);
ok('Zeitstempel vorhanden', typeof out.sentAt === 'number');

// Determinismus / Frische
const ct2 = await encryptMessage({
  text: msg, senderPrivateKey: alice.privateKey,
  senderPublicKeyRaw: alice.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw
});
ok('Zwei Chiffrate derselben Nachricht unterscheiden sich', ct !== ct2);

// Sender kann eigene Nachricht NICHT mehr lesen (Vorwaertssicherheit senderseitig)
let senderBlocked = false;
try { await decryptMessage({ armored: ct, privateKey: alice.privateKey, publicKeyRaw: alice.publicKeyRaw }); }
catch (e) { senderBlocked = e.code === 'not_for_you'; }
ok('Sender selbst kann nicht entschluesseln', senderBlocked);

// Dritter kann nicht lesen
const C = await deriveVaultKeys('dritte-partei-passphrase-lang', randomBytes(16));
const eve = await createIdentity(C.wrapKey);
let eveBlocked = false;
try { await decryptMessage({ armored: ct, privateKey: eve.privateKey, publicKeyRaw: eve.publicKeyRaw }); }
catch (e) { eveBlocked = e.code === 'not_for_you'; }
ok('Fremder Schluessel wird abgewiesen', eveBlocked);

// Manipulation im Body
const tamper = (s, at) => {
  const b = Buffer.from(s.slice(5).replace(/-/g,'+').replace(/_/g,'/') + '==', 'base64');
  b[at] ^= 0x01;
  return 'ENC1.' + b.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
};
let bodyTamper = false;
try { await decryptMessage({ armored: tamper(ct, 260), privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw }); }
catch (e) { bodyTamper = e.code === 'tampered'; }
ok('Manipulierter Body faellt auf (AES-GCM Tag)', bodyTamper);

let headTamper = false;
try { await decryptMessage({ armored: tamper(ct, 10), privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw }); }
catch (e) { headTamper = e.code === 'not_for_you' || e.code === 'tampered'; }
ok('Manipulierter Header faellt auf (AAD)', headTamper);

// --- Fingerabdruck ---
const fp = await fingerprint(alice.publicKeyRaw);
const fp2 = await fingerprint(alice.publicKeyRaw);
ok('Fingerabdruck deterministisch, 24 Zeichen mit Trennern', fp.text === fp2.text && fp.text.length === 24);
ok('Fingerabdruck unterscheidet Identitaeten', fp.text !== (await fingerprint(bob.publicKeyRaw)).text);
console.log('        Fingerabdruck Beispiel:', fp.text);

// --- Kontaktkarten ---
const card = encodeContactCard('Käthe Ö’Brien', alice.publicKeyRaw);
const parsed = parseContactInput('Hier mein Schlüssel:\n\n' + card + '\n\nbis später');
ok('Kontaktkarte mit Umlauten ueberlebt Round-Trip', parsed && parsed.name === 'Käthe Ö’Brien' && parsed.publicKeyRaw.length === 65);
ok('Muell wird abgewiesen', parseContactInput('hallo welt') === null);

// Chiffretext mit Umgebungstext / Zeilenumbruechen
const wrapped = 'Alice: schau mal\n' + ct.slice(0, 60) + '\n' + ct.slice(60) + '\nAlice: ok?';
const out2 = await decryptMessage({ armored: wrapped, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
ok('Chiffretext mit Umbruechen und Chat-Text lesbar', out2.text === msg);

// --- Datenblob ---
const rec = await sealJSON(A.dataKey, { contacts: [{ n: 'Bob' }], seen: ['ab'] });
const back = await openJSON(A2.dataKey, rec);
ok('Kontaktdaten ver-/entschluesseln', back.contacts[0].n === 'Bob');

// --- Passphrasenwechsel ---
const D = await deriveVaultKeys('neue-passphrase-die-lang-genug-ist', randomBytes(16));
const re = await rewrapIdentity(A2.wrapKey, alice.wrapped, alice.iv, D.wrapKey);
const afterChange = await unwrapIdentity(D.wrapKey, re.wrapped, re.iv);
const ct3 = await encryptMessage({ text: 'nach dem Wechsel', senderPrivateKey: afterChange,
  senderPublicKeyRaw: alice.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw });
const out3 = await decryptMessage({ armored: ct3, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
ok('Nach Passphrasenwechsel bleibt die Identitaet gueltig', out3.text === 'nach dem Wechsel');

// Groessen
console.log('        Overhead: ' + (ct.length) + ' Zeichen fuer ' + msg.length + ' Zeichen Klartext');

console.log('\n--- Randfaelle ---');
// abgeschnittener Chiffretext
let trunc = false;
try { await decryptMessage({ armored: ct.slice(0, ct.length - 40), privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw }); }
catch (e) { trunc = e.code === 'no_envelope'; }
ok('Abgeschnittener Chiffretext wird sauber gemeldet', trunc);

// Laengenfeld manipuliert
const lenTamper = tamper(ct, 4);
let lt = false;
try { await decryptMessage({ armored: lenTamper, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw }); }
catch (e) { lt = ['no_envelope','not_for_you','tampered'].includes(e.code); }
ok('Manipuliertes Laengenfeld wird abgefangen', lt);

// leer / Muell
for (const [inp, code] of [['', 'empty'], ['nur text ohne alles', 'no_envelope'], ['ENC1.AAAA', 'no_envelope']]) {
  let c = null;
  try { await decryptMessage({ armored: inp, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw }); }
  catch (e) { c = e.code; }
  ok(`Eingabe ${JSON.stringify(inp.slice(0,20))} -> ${c}`, c === code);
}

// Grenzwerte Nachrichtenlaenge
for (const n of [1, 20000]) {
  const long = 'ü'.repeat(n);
  const c = await encryptMessage({ text: long, senderPrivateKey: alice.privateKey,
    senderPublicKeyRaw: alice.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw });
  const o = await decryptMessage({ armored: c, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
  ok(`${n} Zeichen (Umlaut) unveraendert`, o.text === long);
}

// zwei Chiffretexte hintereinander im selben Text -> der erste wird gelesen
const both = ct + ' und noch einer: ' + ct2;
const o1 = await decryptMessage({ armored: both, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
ok('Bei zwei Bloecken wird der erste gelesen', o1.text === msg);

// Nachrichten-ID ist pro Umschlag eindeutig
const idA = Buffer.from((await decryptMessage({armored:ct,privateKey:bob.privateKey,publicKeyRaw:bob.publicKeyRaw})).envelopeId).toString('hex');
const idB = Buffer.from((await decryptMessage({armored:ct2,privateKey:bob.privateKey,publicKeyRaw:bob.publicKeyRaw})).envelopeId).toString('hex');
ok('Umschlag-ID unterscheidet zwei Nachrichten (Dublettenerkennung)', idA !== idB);

// Kontaktkarte direkt hinter dem Link-Fragment
const link = 'https://encryptor.one/#' + encodeContactCard('Bob', bob.publicKeyRaw);
const fromLink = parseContactInput(link.split('#')[1]);
ok('Einladungslink laesst sich lesen', fromLink && fromLink.name === 'Bob');

console.log('\n--- Laengen-Padding ---');
const lens = new Set();
for (const text of ['ja', 'nein', 'x'.repeat(150)]) {
  lens.add((await encryptMessage({ text, senderPrivateKey: alice.privateKey,
    senderPublicKeyRaw: alice.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw })).length);
}
ok('Kurze Nachrichten sind gleich lang ("ja" = "nein" = 150 Zeichen)', lens.size === 1);
ok('Padme: Stufen wachsen monoton, Overhead unter 12 %', (() => {
  let last = 0;
  for (let n = 1; n < 70000; n += 37) {
    const p = paddedLength(n);
    if (p < n || p < last || (n > 256 && (p - n) / n > 0.12)) return false;
    last = p;
  }
  return true;
})());
const padded = await decryptMessage({ armored: ct, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
ok('Padding aendert den Klartext nicht', padded.text === msg);
ok('Body-Laenge liegt auf einer Padding-Stufe', (() => {
  const b = envBytes(ct);
  const bodyLen = ((b[3] << 24) | (b[4] << 16) | (b[5] << 8) | b[6]) >>> 0;
  return paddedLength(bodyLen - 16) === bodyLen - 16;
})());

console.log('\n--- Schluesselpaar-Pruefung ---');
ok('Passendes Paar wird erkannt', await keyPairMatches(alice.privateKey, alice.publicKeyRaw));
ok('Fremder Public Key zum eigenen privaten Schluessel faellt auf', !(await keyPairMatches(alice.privateKey, eve.publicKeyRaw)));
ok('Kaputter Public Key faellt auf', !(await keyPairMatches(alice.privateKey, new Uint8Array(65))));

console.log('\n--- Schluesselwechsel ---');
// Alice wechselt von alice -> alice2. Das Update reist mit dem alten Schluessel als Absender.
const alice2 = await createIdentity(A.wrapKey);
const upd = await encryptMessage({ text: 'neuer Schluessel', senderPrivateKey: alice.privateKey,
  senderPublicKeyRaw: alice.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw, rotateTo: alice2.publicKeyRaw });
const ru = await decryptMessage({ armored: upd, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
ok('Update ist vom alten Schluessel authentifiziert', same(ru.senderPublicKeyRaw, alice.publicKeyRaw));
ok('Empfaenger liest den neuen Schluessel aus', same(ru.rotateTo, alice2.publicKeyRaw));
ok('Normale Nachricht traegt kein Update', out.rotateTo === null);
ok('Update-Nachricht ist so lang wie eine normale kurze Nachricht',
  upd.length === (await encryptMessage({ text: 'neuer Schluessel', senderPrivateKey: alice.privateKey,
    senderPublicKeyRaw: alice.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw })).length);

const selfRot = await encryptMessage({ text: 'x', senderPrivateKey: alice.privateKey,
  senderPublicKeyRaw: alice.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw, rotateTo: alice.publicKeyRaw });
ok('"Wechsel" auf denselben Schluessel wird ignoriert',
  (await decryptMessage({ armored: selfRot, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw })).rotateTo === null);

// Bob schreibt an Alices neuen Schluessel; Alice hat beide im Schluesselbund.
const toNew = await encryptMessage({ text: 'an neu', senderPrivateKey: bob.privateKey,
  senderPublicKeyRaw: bob.publicKeyRaw, recipientPublicKeyRaw: alice2.publicKeyRaw });
const toOld = await encryptMessage({ text: 'an alt', senderPrivateKey: bob.privateKey,
  senderPublicKeyRaw: bob.publicKeyRaw, recipientPublicKeyRaw: alice.publicKeyRaw });
const ring = [
  { privateKey: alice2.privateKey, publicKeyRaw: alice2.publicKeyRaw },
  { privateKey: alice.privateKey, publicKeyRaw: alice.publicKeyRaw }
];
const rn = await decryptMessage({ armored: toNew, keys: ring });
const ro = await decryptMessage({ armored: toOld, keys: ring });
ok('Schluesselbund: Nachricht an neuen Schluessel -> keyIndex 0', rn.text === 'an neu' && rn.keyIndex === 0);
ok('Schluesselbund: Nachricht an alten Schluessel bleibt lesbar -> keyIndex 1', ro.text === 'an alt' && ro.keyIndex === 1);

let gone = null;
try { await decryptMessage({ armored: toOld, keys: ring.slice(0, 1) }); } catch (e) { gone = e.code; }
ok('Nach dem Loeschen des alten Schluessels ist die alte Nachricht unlesbar', gone === 'not_for_you');

// Update-Feld ist authentifiziert: ein Dritter kann Bob keinen Schluessel fuer Alice unterschieben.
const forged = await encryptMessage({ text: 'ich bin alice', senderPrivateKey: eve.privateKey,
  senderPublicKeyRaw: eve.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw, rotateTo: eve.publicKeyRaw });
const rf = await decryptMessage({ armored: forged, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
ok('Fremdes Update traegt Eves Absender, nicht Alices', same(rf.senderPublicKeyRaw, eve.publicKeyRaw));

console.log('\n--- Mehrere Wechsel (Beglaubigung) ---');
// Alice: K1 -> K2 -> K3. Bob hat K2 schon gespeichert, die Nachricht kommt aber noch von K1.
const alice3 = await createIdentity(A.wrapKey);
const k1 = { privateKey: alice.privateKey, publicKeyRaw: alice.publicKeyRaw };
const k2 = { privateKey: alice2.privateKey, publicKeyRaw: alice2.publicKeyRaw };
const dbl = await encryptMessage({ text: 'zwei Wechsel', senderPrivateKey: k1.privateKey,
  senderPublicKeyRaw: k1.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw,
  rotateTo: alice3.publicKeyRaw, endorsers: [k2] });
const rd = await decryptMessage({ armored: dbl, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw });
ok('Absender (K1) beglaubigt implizit', await rd.vouchedBy(k1.publicKeyRaw));
ok('K2 beglaubigt per Tag', await rd.vouchedBy(k2.publicKeyRaw));
ok('Unbeteiligter Schluessel beglaubigt nicht', !(await rd.vouchedBy(eve.publicKeyRaw)));

// Ohne Beglaubigung durch K2 (z. B. altes Update wiedereingespielt) -> Bob mit K2 lehnt ab.
const noTag = await encryptMessage({ text: 'x', senderPrivateKey: k1.privateKey,
  senderPublicKeyRaw: k1.publicKeyRaw, recipientPublicKeyRaw: bob.publicKeyRaw, rotateTo: alice3.publicKeyRaw });
ok('Update nur von K1 reicht nicht, wenn Bob schon K2 hat',
  !(await (await decryptMessage({ armored: noTag, privateKey: bob.privateKey, publicKeyRaw: bob.publicKeyRaw })).vouchedBy(k2.publicKeyRaw)));

ok('Normale Nachricht beglaubigt nichts', !(await out.vouchedBy(alice.publicKeyRaw)));

console.log('\n--- Zufall ---');
const counts = new Array(130).fill(0);
for (let i = 0; i < 130000; i++) counts[randomInt(130)]++;
ok('randomInt(130) bleibt im Bereich und trifft jeden Wert', counts.every((c) => c > 700));

console.log(failed ? `\n${failed} Test(s) fehlgeschlagen.` : '\nAlle Tests bestanden.');
if (failed) process.exitCode = 1;
