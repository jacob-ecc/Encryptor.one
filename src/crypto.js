// crypto.js — Krypto-Kern.
//
// Nachrichten-Schema (Envelope v1):
//   Sender erzeugt pro Nachricht ein ephemeres ECDH-Schlüsselpaar.
//     dh_e = ECDH(eph_priv,    empfaenger_pub)
//     dh_s = ECDH(sender_priv, empfaenger_pub)
//   k_hdr  = HKDF-SHA256(dh_e,          salt, "…/hdr"  || eph_pub)
//   k_body = HKDF-SHA256(dh_e || dh_s,  salt, "…/body" || eph_pub || sender_pub || empf_pub)
//
//   dh_e liefert Vorwärtssicherheit auf Senderseite (der ephemere Schlüssel wird
//   verworfen). dh_s authentifiziert den Sender implizit: nur wer den privaten
//   Schlüssel des Senders besitzt, kann k_body bilden — ohne eine übertragbare
//   Signatur zu erzeugen (Abstreitbarkeit, wie bei Signal).
//
//   Der Sender-Public-Key liegt verschlüsselt im Umschlag ("sealed sender"),
//   d. h. wer den Chiffretext abfängt, sieht nicht, von wem er stammt.
//
// Layout (Bytes):
//   0    magic "E1"        2
//   2    flags             1
//   3    body_len (u32BE)  4   -- macht den Umschlag selbst-begrenzend
//   7    salt             32
//   39   eph_pub (raw)    65
//   104  iv0              12
//   116  sealed_sender    81   = AES-GCM(k_hdr, iv0, sender_pub[65]), AAD = bytes[0..116]
//   197  iv1              12
//   209  body        body_len  = AES-GCM(k_body, iv1, payload), AAD = bytes[0..209]
//
// body_len steht in beiden AADs und ist damit authentifiziert. Es erlaubt dem
// Parser, den Block exakt abzuschneiden — nur so ueberlebt ein Chiffretext das
// Einfuegen mitten in einen Chatverlauf.
//
// Payload (JSON, im Body):
//   v   Version (1)
//   t   Zeitstempel des Absenders
//   m   Text
//   rk  optional: neuer Public Key des Absenders (Schluesselwechsel). Authentifiziert
//       durch dh_s mit dem bisherigen Schluessel — nur dessen Besitzer kann ihn setzen.
//   ra  optional: Beglaubigungen von rk durch weitere fruehere Schluessel des Absenders,
//       je 16 Byte: HKDF(ECDH(frueher, empfaenger), salt, "…/endorse" || frueher || rk || empf).
//       Noetig nach mehreren Wechseln: Der Empfaenger kennt vielleicht schon einen
//       neueren Schluessel als den, von dem die Nachricht ausgeht, und uebernimmt ein
//       Update nur, wenn genau dieser es beglaubigt.
//   p   Fuellzeichen. Die Laenge landet auf festen Stufen (mind. 256 Byte, darueber
//       Padme), damit der Chiffretext nicht die exakte Textlaenge verraet.
// Aeltere Versionen ignorieren rk und p, das Format bleibt kompatibel.

import { enc, dec, concat, b64urlEncode, b64urlDecode, wipe, cleanName } from './util.js';

const subtle = globalThis.crypto && globalThis.crypto.subtle;
export const CRYPTO_AVAILABLE = !!(subtle && globalThis.isSecureContext !== false);

const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const MAGIC = Uint8Array.of(0x45, 0x31); // "E1"
const OFF = { len: 3, salt: 7, eph: 39, iv0: 104, sealed: 116, iv1: 197, body: 209 };
const HDR_AAD_LEN = 116;
const FULL_HDR_LEN = 209;
const MAX_BODY = 4_000_000;
const MIN_PAYLOAD = 256;
const HDR_INFO = enc.encode('encryptor.one/v1/hdr');
const BODY_INFO = enc.encode('encryptor.one/v1/body');
const ENDORSE_INFO = enc.encode('encryptor.one/v1/endorse');
const MAX_ENDORSE = 8;

export const KDF_ITERATIONS = 600_000;
export const MSG_PREFIX = 'ENC1.';
export const CARD_PREFIX = 'ENCID1.';

export class CryptoError extends Error {
  constructor(code) { super(code); this.code = code; }
}

/* ---------------- Primitive ---------------- */

async function hkdf(ikm, salt, info, bits = 256) {
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, bits));
}

async function aesKey(raw, usages) {
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, usages);
}

async function ecdh(privateKey, publicKey) {
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256));
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

export function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }

/** Gleichverteilte Zahl in [0, n) — Rejection Sampling statt Modulo, also ohne Bias. */
export function randomInt(n) {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limit);
  return buf[0] % n;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/* ---------------- Schlüssel ---------------- */

export async function importPublicRaw(raw) {
  if (!(raw instanceof Uint8Array) || raw.length !== 65 || raw[0] !== 0x04) {
    throw new CryptoError('bad_key');
  }
  try {
    return await subtle.importKey('raw', raw, ECDH, true, []);
  } catch {
    throw new CryptoError('bad_key');
  }
}

/** Erzeugt eine Identität und verpackt den privaten Schlüssel sofort. */
export async function createIdentity(wrapKey) {
  const kp = await subtle.generateKey(ECDH, true, ['deriveBits']);
  const publicKeyRaw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const iv = randomBytes(12);
  const wrapped = new Uint8Array(await subtle.wrapKey('pkcs8', kp.privateKey, wrapKey, { name: 'AES-GCM', iv }));
  // Ab hier nur noch der nicht-exportierbare Schlüssel im Speicher.
  const privateKey = await unwrapIdentity(wrapKey, wrapped, iv, false);
  return { publicKeyRaw, wrapped, iv, privateKey };
}

export async function unwrapIdentity(wrapKey, wrapped, iv, extractable = false) {
  return subtle.unwrapKey(
    'pkcs8', wrapped, wrapKey, { name: 'AES-GCM', iv },
    ECDH, extractable, ['deriveBits']
  );
}

/**
 * Prueft, ob privater und oeffentlicher Schluessel zusammengehoeren: ein Probe-Schluessel
 * rechnet ECDH einmal mit jeder Haelfte. Der Public Key liegt unverschluesselt im Vault
 * und in der Sicherung — ohne diese Pruefung koennte jemand ihn austauschen, und die App
 * wuerde fortan einen fremden Schluessel als eigene Identitaet weitergeben.
 */
export async function keyPairMatches(privateKey, publicKeyRaw) {
  try {
    const pub = await importPublicRaw(publicKeyRaw);
    const probe = await subtle.generateKey(ECDH, false, ['deriveBits']);
    const a = await ecdh(privateKey, probe.publicKey);
    const b = await ecdh(probe.privateKey, pub);
    const same = equalBytes(a, b);
    wipe(a, b);
    return same;
  } catch {
    return false;
  }
}

export async function rewrapIdentity(oldWrapKey, wrapped, iv, newWrapKey) {
  const priv = await unwrapIdentity(oldWrapKey, wrapped, iv, true);
  const newIv = randomBytes(12);
  const newWrapped = new Uint8Array(await subtle.wrapKey('pkcs8', priv, newWrapKey, { name: 'AES-GCM', iv: newIv }));
  return { wrapped: newWrapped, iv: newIv };
}

/* ---------------- Fingerabdruck ---------------- */

const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford: ohne I, L, O, U

/** 100-Bit-Fingerabdruck als 5×4 Zeichen plus Hash-Bytes für das Siegel. */
export async function fingerprint(publicKeyRaw) {
  const h = await sha256(concat(enc.encode('encryptor.one/fp/v1'), publicKeyRaw));
  let bits = 0, value = 0, out = '';
  for (let i = 0; i < h.length && out.length < 20; i++) {
    value = ((value << 8) | h[i]) >>> 0;
    bits += 8;
    while (bits >= 5 && out.length < 20) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
      value &= (1 << bits) - 1;
    }
  }
  return { text: out.match(/.{1,4}/g).join('-'), hash: h };
}

/* ---------------- Nachrichten ---------------- */

/** Zielgroesse: mindestens MIN_PAYLOAD, darueber Padme (≤ 12 % Overhead, leakt O(log log n) Bit). */
export function paddedLength(n) {
  if (n <= MIN_PAYLOAD) return MIN_PAYLOAD;
  const e = Math.floor(Math.log2(n));
  const s = Math.floor(Math.log2(e)) + 1;
  const mask = (1 << (e - s)) - 1;
  return (n + mask) & ~mask;
}

function encodePayload(obj) {
  const json = JSON.stringify(obj);
  const len = enc.encode(json).length;
  // json endet auf "}" — ersetzt durch ,"p":"<fill>"} kommen 7 Byte plus Fuellung dazu.
  const fill = paddedLength(len + 7) - len - 7;
  return enc.encode(json.slice(0, -1) + ',"p":"' + ' '.repeat(fill) + '"}');
}

/** Beglaubigung: nur Inhaber von `endorser` oder Empfaenger koennen sie bilden (wie dh_s). */
async function endorsementTag(dh, salt, endorserRaw, newKeyRaw, recipientRaw) {
  return hkdf(dh, salt, concat(ENDORSE_INFO, endorserRaw, newKeyRaw, recipientRaw), 128);
}

export async function encryptMessage({
  text, senderPrivateKey, senderPublicKeyRaw, recipientPublicKeyRaw, rotateTo = null, endorsers = []
}) {
  const recipientPub = await importPublicRaw(recipientPublicKeyRaw);

  const eph = await subtle.generateKey(ECDH, true, ['deriveBits']);
  const ephRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));

  const salt = randomBytes(32);
  const iv0 = randomBytes(12);
  const iv1 = randomBytes(12);

  const dhE = await ecdh(eph.privateKey, recipientPub);
  const dhS = await ecdh(senderPrivateKey, recipientPub);

  const body0 = { v: 1, t: Date.now(), m: text };
  if (rotateTo) {
    body0.rk = b64urlEncode(rotateTo);
    const tags = [];
    for (const e of endorsers.slice(0, MAX_ENDORSE)) {
      const dh = await ecdh(e.privateKey, recipientPub);
      tags.push(b64urlEncode(await endorsementTag(dh, salt, e.publicKeyRaw, rotateTo, recipientPublicKeyRaw)));
      wipe(dh);
    }
    if (tags.length) body0.ra = tags;
  }
  const payload = encodePayload(body0);
  const bodyLen = payload.length + 16; // AES-GCM haengt 16 Byte Tag an
  const lenField = Uint8Array.of(
    (bodyLen >>> 24) & 0xff, (bodyLen >>> 16) & 0xff, (bodyLen >>> 8) & 0xff, bodyLen & 0xff
  );

  const head = concat(MAGIC, Uint8Array.of(0), lenField, salt, ephRaw, iv0); // 116
  const kHdrRaw = await hkdf(dhE, salt, concat(HDR_INFO, ephRaw));
  const kHdr = await aesKey(kHdrRaw, ['encrypt']);
  const sealed = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: iv0, additionalData: head, tagLength: 128 }, kHdr, senderPublicKeyRaw
  ));

  const head2 = concat(head, sealed, iv1); // 209
  const kBodyRaw = await hkdf(
    concat(dhE, dhS), salt,
    concat(BODY_INFO, ephRaw, senderPublicKeyRaw, recipientPublicKeyRaw)
  );
  const kBody = await aesKey(kBodyRaw, ['encrypt']);
  const body = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: iv1, additionalData: head2, tagLength: 128 }, kBody, payload
  ));

  wipe(dhE, dhS, kHdrRaw, kBodyRaw, payload);
  return MSG_PREFIX + b64urlEncode(concat(head2, body));
}

/**
 * Entschluesselt mit dem ersten passenden Schluessel aus `keys` (aktueller zuerst,
 * danach fruehere). Der Header dient dabei als Schluesselerkennung: nur beim
 * richtigen Schluessel laesst sich der Absender entsiegeln.
 */
export async function decryptMessage({ armored, keys, privateKey, publicKeyRaw }) {
  const ring = keys || [{ privateKey, publicKeyRaw }];
  const bytes = parseEnvelope(armored);

  const salt = bytes.slice(OFF.salt, OFF.salt + 32);
  const ephRaw = bytes.slice(OFF.eph, OFF.eph + 65);
  const iv0 = bytes.slice(OFF.iv0, OFF.iv0 + 12);
  const sealed = bytes.slice(OFF.sealed, OFF.sealed + 81);
  const iv1 = bytes.slice(OFF.iv1, OFF.iv1 + 12);
  const head = bytes.slice(0, HDR_AAD_LEN);
  const head2 = bytes.slice(0, FULL_HDR_LEN);
  const body = bytes.slice(FULL_HDR_LEN);

  const ephPub = await importPublicRaw(ephRaw);

  let keyIndex = -1, dhE = null, senderPublicKeyRaw = null;
  for (let i = 0; i < ring.length && keyIndex < 0; i++) {
    const dh = await ecdh(ring[i].privateKey, ephPub);
    const kHdrRaw = await hkdf(dh, salt, concat(HDR_INFO, ephRaw));
    const kHdr = await aesKey(kHdrRaw, ['decrypt']);
    wipe(kHdrRaw);
    try {
      senderPublicKeyRaw = new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv: iv0, additionalData: head, tagLength: 128 }, kHdr, sealed
      ));
      keyIndex = i;
      dhE = dh;
    } catch {
      wipe(dh);
    }
  }
  // Passt der Header zu keinem Schluessel, war die Nachricht fuer jemand anderen bestimmt.
  if (keyIndex < 0) throw new CryptoError('not_for_you');
  const me = ring[keyIndex];

  const senderPub = await importPublicRaw(senderPublicKeyRaw);
  const dhS = await ecdh(me.privateKey, senderPub);
  const kBodyRaw = await hkdf(
    concat(dhE, dhS), salt,
    concat(BODY_INFO, ephRaw, senderPublicKeyRaw, me.publicKeyRaw)
  );
  const kBody = await aesKey(kBodyRaw, ['decrypt']);

  let plain;
  try {
    plain = new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: iv1, additionalData: head2, tagLength: 128 }, kBody, body
    ));
  } catch {
    throw new CryptoError('tampered');
  } finally {
    wipe(dhE, dhS, kBodyRaw);
  }

  let payload;
  try { payload = JSON.parse(dec.decode(plain)); } catch { throw new CryptoError('tampered'); }
  wipe(plain);

  const rotateTo = await readRotation(payload.rk, senderPublicKeyRaw);
  const tags = rotateTo && Array.isArray(payload.ra)
    ? payload.ra.slice(0, MAX_ENDORSE).filter((x) => typeof x === 'string' && x.length <= 32)
    : [];

  return {
    text: typeof payload.m === 'string' ? payload.m : '',
    sentAt: Number.isFinite(payload.t) ? payload.t : null,
    senderPublicKeyRaw,
    rotateTo,
    keyIndex,
    envelopeId: (await sha256(bytes)).slice(0, 12),
    /**
     * Hat `endorserRaw` den neuen Schluessel beglaubigt? Der Absender selbst ja (die ganze
     * Nachricht ist mit ihm authentifiziert), jeder andere Schluessel nur mit gueltigem Tag.
     */
    async vouchedBy(endorserRaw) {
      if (!rotateTo) return false;
      if (equalBytes(endorserRaw, senderPublicKeyRaw)) return true;
      if (!tags.length) return false;
      let pub;
      try { pub = await importPublicRaw(endorserRaw); } catch { return false; }
      const dh = await ecdh(me.privateKey, pub);
      const want = await endorsementTag(dh, salt, endorserRaw, rotateTo, me.publicKeyRaw);
      wipe(dh);
      let hit = false;
      for (const t of tags) {
        try { if (equalBytes(b64urlDecode(t), want)) hit = true; } catch { /* kaputter Tag */ }
      }
      return hit;
    }
  };
}

/** Neuer Schluessel aus dem Payload — nur wenn er ein gueltiger Kurvenpunkt ist. */
async function readRotation(rk, senderPublicKeyRaw) {
  if (typeof rk !== 'string' || rk.length > 100) return null;
  try {
    const raw = b64urlDecode(rk);
    await importPublicRaw(raw);
    return equalBytes(raw, senderPublicKeyRaw) ? null : raw;
  } catch {
    return null;
  }
}

/**
 * Holt einen Umschlag aus beliebig eingebettetem Text. Dank des Laengenfeldes
 * wird exakt so viel abgeschnitten, wie zum Umschlag gehoert — was danach im
 * Chat noch steht, stoert nicht.
 */
export function parseEnvelope(input) {
  const compact = String(input || '').replace(/\s+/g, '');
  if (!compact) throw new CryptoError('empty');

  let b64 = null;
  const tagged = /ENC1\.([A-Za-z0-9_\-+/=]{16,})/.exec(compact);
  if (tagged) b64 = tagged[1];
  else if (/^[A-Za-z0-9_\-+/=]{280,}$/.test(compact)) b64 = compact;
  if (!b64) throw new CryptoError('no_envelope');

  let peek;
  try { peek = b64urlDecode(b64.slice(0, 12)); } catch { throw new CryptoError('no_envelope'); }
  if (peek.length < 7) throw new CryptoError('no_envelope');
  if (peek[0] !== MAGIC[0] || peek[1] !== MAGIC[1]) throw new CryptoError('unknown_version');

  const bodyLen = ((peek[3] << 24) | (peek[4] << 16) | (peek[5] << 8) | peek[6]) >>> 0;
  if (bodyLen < 17 || bodyLen > MAX_BODY) throw new CryptoError('no_envelope');

  const total = FULL_HDR_LEN + bodyLen;
  const need = Math.ceil((total * 4) / 3);
  if (b64.length < need) throw new CryptoError('no_envelope');

  let bytes;
  try { bytes = b64urlDecode(b64.slice(0, need)); } catch { throw new CryptoError('no_envelope'); }
  if (bytes.length !== total) throw new CryptoError('no_envelope');
  return bytes;
}

/* ---------------- Kontaktkarten ---------------- */

export function encodeContactCard(name, publicKeyRaw) {
  const json = enc.encode(JSON.stringify({
    n: cleanName(name),
    k: b64urlEncode(publicKeyRaw)
  }));
  const out = new Uint8Array(3 + json.length);
  out[0] = 0x43; // 'C'
  out[1] = (json.length >> 8) & 0xff;
  out[2] = json.length & 0xff;
  out.set(json, 3);
  return CARD_PREFIX + b64urlEncode(out);
}

/** Akzeptiert Kontaktkarte, Einladungslink oder einen nackten Public Key. */
export function parseContactInput(input) {
  const compact = String(input || '').replace(/\s+/g, '');
  if (!compact) return null;

  const card = /ENCID1\.([A-Za-z0-9_\-+/=]{8,})/.exec(compact);
  if (card) {
    try {
      const peek = b64urlDecode(card[1].slice(0, 4));
      if (peek.length < 3 || peek[0] !== 0x43) return null;
      const len = (peek[1] << 8) | peek[2];
      const total = 3 + len;
      const need = Math.ceil((total * 4) / 3);
      if (len < 2 || len > 4096 || card[1].length < need) return null;

      const bytes = b64urlDecode(card[1].slice(0, need));
      if (bytes.length !== total) return null;

      const obj = JSON.parse(dec.decode(bytes.subarray(3)));
      const key = b64urlDecode(obj.k);
      if (key.length !== 65 || key[0] !== 0x04) return null;
      return { name: cleanName(obj.n), publicKeyRaw: key };
    } catch { return null; }
  }

  const bare = /^([A-Za-z0-9_\-+/=]{86,92})$/.exec(compact);
  if (bare) {
    try {
      const key = b64urlDecode(bare[1]);
      if (key.length === 65 && key[0] === 0x04) return { name: '', publicKeyRaw: key };
    } catch { /* ignorieren */ }
  }
  return null;
}

/* ---------------- Vault-Schlüssel ---------------- */

/**
 * Passphrase → PBKDF2-HMAC-SHA256 → HKDF-Split in zwei getrennte Schlüssel:
 * einen zum Verpacken der Identität, einen für Kontakte/Einstellungen.
 */
export async function deriveVaultKeys(passphrase, salt, iterations = KDF_ITERATIONS) {
  const base = await subtle.importKey(
    'raw', enc.encode(String(passphrase).normalize('NFKC')), 'PBKDF2', false, ['deriveBits']
  );
  const master = new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, 256
  ));
  const wrapRaw = await hkdf(master, salt, enc.encode('encryptor.one/vault/wrap/v1'));
  const dataRaw = await hkdf(master, salt, enc.encode('encryptor.one/vault/data/v1'));
  wipe(master);

  const wrapKey = await subtle.importKey('raw', wrapRaw, { name: 'AES-GCM' }, false, ['wrapKey', 'unwrapKey']);
  const dataKey = await subtle.importKey('raw', dataRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  wipe(wrapRaw, dataRaw);
  return { wrapKey, dataKey };
}

export async function sealJSON(dataKey, obj) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, dataKey, enc.encode(JSON.stringify(obj))
  ));
  return { iv, ct };
}

export async function openJSON(dataKey, rec) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, tagLength: 128 }, dataKey, rec.ct);
  return JSON.parse(dec.decode(pt));
}
