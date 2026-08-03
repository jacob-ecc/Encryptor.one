import {
  createIdentity, unwrapIdentity, rewrapIdentity, deriveVaultKeys,
  encryptMessage, decryptMessage, fingerprint, sealJSON, openJSON,
  encodeContactCard, parseContactInput, randomBytes, CryptoError, KDF_ITERATIONS
} from '../src/crypto.js';

const ok = (label, cond) => console.log((cond ? '  PASS  ' : '! FAIL  ') + label);

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
