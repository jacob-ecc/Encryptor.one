// app.js — Oberfläche und Ablauf.

import {
  $, $$, el, clear, icon, copyText, b64urlEncode, b64urlDecode,
  scrambleTo, formatDateTime, toHex, prefersReducedMotion, cleanName
} from './util.js';
import {
  CRYPTO_AVAILABLE, KDF_ITERATIONS, CryptoError,
  createIdentity, unwrapIdentity, rewrapIdentity, deriveVaultKeys, keyPairMatches,
  sealJSON, openJSON, encryptMessage, decryptMessage, fingerprint,
  encodeContactCard, parseContactInput, importPublicRaw, randomBytes, randomInt, sha256
} from './crypto.js';
import { readMeta, readData, writeData, writeVault, hasVault, destroyVault, prefs } from './store.js';
import { t, setLang, getLang, detectLang, WORDS } from './i18n.js';
import { sigil } from './sigil.js';

const VERSION = '2.1.1';
const MAX_MESSAGE = 20000;
const DAY = 86400000;
const DEFAULT_SETTINGS = { autolock: 15, keepOld: 30 };

const state = {
  publicKeyRaw: null,
  privateKey: null,
  wrapKey: null,
  dataKey: null,
  wrapped: null,
  wrapIv: null,
  prev: [],          // fruehere Schluessel nach einem Wechsel: { publicKeyRaw, privateKey, retiredAt }
  meta: null,
  fp: null,
  contacts: [],
  seen: [],
  settings: { ...DEFAULT_SETTINGS },
  view: 'encrypt',
  pendingCard: null,
  addPrev: null,     // { key, prev } — Absender, der beim Speichern gleich einen Wechsel mitbringt
  lastCipher: '',
  lastActivity: Date.now()
};

/* ================= Start ================= */

async function boot() {
  setLang(detectLang(), { persist: false });
  syncThemeButton();
  wireChrome();
  wireGuide();
  wireEncrypt();
  wireDecrypt();
  wireContacts();
  wireSettings();

  $('#versionLine').textContent = `encryptor.one · v${VERSION}`;
  $('#appVersion').textContent = VERSION;

  if (!CRYPTO_AVAILABLE) {
    showScreen('landing');
    $('#btnCreate').disabled = true;
    toast(t('err.nocrypto'), 'warn', 12000);
    return;
  }

  readInviteFromUrl();

  let vaultExists = false;
  try { vaultExists = await hasVault(); }
  catch { toast(t('err.nostorage'), 'warn', 9000); }

  if (vaultExists) {
    state.meta = await readMeta();
    mountGuide('app');
    showScreen('lock');
    renderLockSeal();
    setTimeout(() => $('#unlockPass').focus(), 220);
  } else {
    mountGuide('landing');
    showScreen('landing');
    renderHeroSeal();
    updateLandingCta(false);
  }

  registerServiceWorker();
  setInterval(autolockTick, 15000);
  for (const evt of ['pointerdown', 'keydown']) {
    document.addEventListener(evt, () => { state.lastActivity = Date.now(); }, { passive: true });
  }
  // Zurueck im Tab zaehlt nicht als Aktivitaet: Mobile Browser frieren Hintergrund-Tabs
  // ein, der Timer lief also nicht. Erst pruefen, ob die Sperrfrist abgelaufen ist.
  document.addEventListener('visibilitychange', () => { if (!document.hidden) autolockTick(); });
  window.addEventListener('pageshow', autolockTick);
}

function readInviteFromUrl() {
  const hash = location.hash.slice(1);
  if (!hash) return;
  let raw = hash;
  try { raw = decodeURIComponent(hash); } catch { /* kaputtes %-Escape: roh versuchen */ }
  const card = parseContactInput(raw);
  if (card) state.pendingCard = card;
  history.replaceState(null, '', location.pathname + location.search);
}

function updateLandingCta(vaultExists) {
  $('#btnCreate').textContent = vaultExists ? t('landing.cta.unlock') : t('landing.cta.create');
}

/* ================= Rahmen: Theme, Sprache, Screens ================= */

function wireChrome() {
  $('#btnTheme').addEventListener('click', () => {
    const order = ['system', 'light', 'dark'];
    const next = order[(order.indexOf(document.documentElement.dataset.themePref || 'system') + 1) % 3];
    applyTheme(next);
  });
  $('#btnLang').addEventListener('click', () => {
    const next = getLang() === 'de' ? 'en' : 'de';
    setLang(next);
    afterLangChange();
  });
  $('#btnSettings').addEventListener('click', () => openDialog('#dlgSettings'));
  $('#importFile').addEventListener('change', importBackup);
  $('#btnRestoreLanding').addEventListener('click', () => $('#importFile').click());
  $('#btnLock').addEventListener('click', lock);

  for (const btn of $$('[data-close]')) {
    btn.addEventListener('click', () => btn.closest('dialog').close());
  }
  for (const dlg of $$('dialog')) {
    dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
  }
  for (const btn of $$('[data-toggle-visibility]')) {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.toggleVisibility);
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      clear(btn);
      btn.appendChild(icon(show ? 'eye-off' : 'eye', 'icon icon-sm'));
    });
  }

  $('#btnCreate').addEventListener('click', () => {
    if (state.meta) { showScreen('lock'); $('#unlockPass').focus(); return; }
    openDialog('#dlgSetup');
    setTimeout(() => $('#setupPass').focus(), 220);
  });
  $('#btnHow').addEventListener('click', () => {
    $('#howto').scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  });

  wireSetup();
  wireUnlock();
}

function applyTheme(pref) {
  const root = document.documentElement;
  root.dataset.themePref = pref;
  const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = pref === 'system' ? (dark ? 'dark' : 'light') : pref;
  prefs.set('theme', pref);
  syncThemeButton();
}

function syncThemeButton() {
  const pref = document.documentElement.dataset.themePref || 'system';
  const name = pref === 'system' ? 'monitor' : pref === 'light' ? 'sun' : 'moon';
  const btn = $('#btnTheme');
  clear(btn);
  btn.appendChild(icon(name));
  $('#btnLang').textContent = getLang().toUpperCase();
  for (const b of $$('#themeSeg button')) b.setAttribute('aria-pressed', String(b.dataset.themeVal === pref));
}

function afterLangChange() {
  $('#btnLang').textContent = getLang().toUpperCase();
  for (const b of $$('#langSeg button')) b.setAttribute('aria-pressed', String(b.dataset.langVal === getLang()));
  renderStepIndices();
  if (state.privateKey) { renderContacts(); renderRecipients(); renderKeyInfo(); }
  updateLandingCta(!!state.meta);
}

function showScreen(name) {
  for (const id of ['landing', 'lock', 'app']) {
    $('#screen-' + id).hidden = id !== name;
  }
  $('#btnLock').hidden = name !== 'app';
  $('#btnSettings').hidden = name !== 'app';
  window.scrollTo({ top: 0 });
}

function setView(name) {
  state.view = name;
  for (const v of ['encrypt', 'decrypt', 'contacts', 'guide']) $('#view-' + v).hidden = v !== name;
  for (const tab of $$('.tab')) tab.classList.toggle('is-active', tab.dataset.view === name);
  window.scrollTo({ top: 0 });
}

function openDialog(sel) {
  const dlg = $(sel);
  if (!dlg.open) dlg.showModal();
  return dlg;
}

/* ================= Identität anlegen ================= */

function wireSetup() {
  const pass = $('#setupPass');
  pass.addEventListener('input', () => renderStrength(pass.value));

  $('#btnSuggestPass').addEventListener('click', async () => {
    const words = [];
    for (let i = 0; i < 8; i++) words.push(WORDS[randomInt(WORDS.length)]);
    const suggestion = words.join('-');
    $('#setupPass').value = suggestion;
    $('#setupPass2').value = suggestion;
    $('#setupPass').type = 'text';
    renderStrength(suggestion);
    $('#btnCopyPass').hidden = false;
  });

  $('#btnCopyPass').addEventListener('click', () => copyAndToast($('#setupPass').value));

  $('#setupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const p1 = $('#setupPass').value;
    const p2 = $('#setupPass2').value;
    const err = $('#setupError');
    err.hidden = true;

    if (p1.length < 12) return showError(err, t('setup.tooweak'));
    if (p1 !== p2) return showError(err, t('setup.nomatch'));

    const btn = $('#setupSubmit');
    await withBusy(btn, t('setup.working'), async () => {
      const salt = randomBytes(16);
      const { wrapKey, dataKey } = await deriveVaultKeys(p1, salt);
      const id = await createIdentity(wrapKey);

      state.wrapKey = wrapKey;
      state.dataKey = dataKey;
      state.privateKey = id.privateKey;
      state.publicKeyRaw = id.publicKeyRaw;
      state.wrapped = id.wrapped;
      state.wrapIv = id.iv;
      state.meta = {
        v: 1, createdAt: Date.now(),
        kdf: { iterations: KDF_ITERATIONS, salt },
        publicKeyRaw: id.publicKeyRaw, wrapped: id.wrapped, iv: id.iv
      };
      state.contacts = [];
      state.seen = [];
      state.prev = [];
      await persistVault();
      $('#dlgSetup').close();
      $('#setupPass').value = $('#setupPass2').value = '';
      await enterApp();
    });
  });
}

function renderStrength(p) {
  const score = passScore(p);
  const bar = $('#passMeter');
  bar.style.width = `${[6, 25, 50, 75, 100][score]}%`;
  bar.dataset.level = String(score);
  $('#passStrength').textContent = `${t('setup.strength')}: ${t('setup.s' + score)}`;
}

function passScore(p) {
  if (!p) return 0;
  if (p.length < 8) return 0;
  if (/^(passwort|password|12345|qwert|abcdef|letmein)/i.test(p)) return 0;
  let classes = 0;
  if (/[a-z]/.test(p)) classes++;
  if (/[A-Z]/.test(p)) classes++;
  if (/[0-9]/.test(p)) classes++;
  if (/[^A-Za-z0-9]/.test(p)) classes++;
  const words = p.trim().split(/[\s\-_.]+/).filter(Boolean).length;
  const effective = p.length + (words > 2 ? words * 2 : 0) + (classes - 1) * 2;
  let score = effective >= 34 ? 4 : effective >= 26 ? 3 : effective >= 18 ? 2 : 1;
  if (p.length < 12) score = Math.min(score, 1);
  return score;
}

/* ================= Entsperren / Sperren ================= */

function wireUnlock() {
  $('#unlockForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#unlockError');
    err.hidden = true;

    const until = Number(prefs.get('lockUntil', 0));
    if (until > Date.now()) {
      return showError(err, t('unlock.wait', { s: Math.ceil((until - Date.now()) / 1000) }));
    }

    const pass = $('#unlockPass').value;
    if (!pass) return;

    await withBusy($('#unlockSubmit'), t('setup.working'), async () => {
      let meta, keys, priv;
      try {
        meta = state.meta || await readMeta();
        keys = await deriveVaultKeys(pass, meta.kdf.salt, meta.kdf.iterations);
        priv = await unwrapIdentity(keys.wrapKey, meta.wrapped, meta.iv);
      } catch {
        const fails = Number(prefs.get('fails', 0)) + 1;
        prefs.set('fails', fails);
        if (fails >= 3) {
          const wait = Math.min(120, 2 ** (fails - 2)) * 1000;
          prefs.set('lockUntil', Date.now() + wait);
        }
        return showError(err, t('unlock.wrong'));
      }

      // Ab hier stimmt die Passphrase. Was jetzt scheitert, ist ein beschaedigter
      // oder manipulierter Vault — das darf nicht als Tippfehler durchgehen.
      prefs.remove('fails');
      prefs.remove('lockUntil');
      try {
        await openVault(meta, keys, priv);
      } catch {
        return showError(err, t('unlock.corrupt'));
      }
      $('#unlockPass').value = '';
      await enterApp();
    });
  });

  $('#btnRestore').addEventListener('click', () => $('#importFile').click());

  $('#btnForgot').addEventListener('click', () => {
    confirmDialog({
      title: t('unlock.forgot'),
      body: t('unlock.forgotBody'),
      okLabel: t('unlock.reset'),
      onOk: async () => { await destroyVault(); location.reload(); }
    });
  });
}

/** Entpackt alle Schluessel, prueft, dass jeder zu seinem Public Key passt, laedt die Daten. */
async function openVault(meta, { wrapKey, dataKey }, privateKey) {
  if (!(await keyPairMatches(privateKey, meta.publicKeyRaw))) throw new Error('integrity');
  const prev = [];
  for (const p of meta.prev || []) {
    const k = await unwrapIdentity(wrapKey, p.wrapped, p.iv);
    if (!(await keyPairMatches(k, p.publicKeyRaw))) throw new Error('integrity');
    prev.push({ publicKeyRaw: p.publicKeyRaw, privateKey: k, retiredAt: p.retiredAt });
  }

  state.meta = meta;
  state.wrapKey = wrapKey;
  state.dataKey = dataKey;
  state.privateKey = privateKey;
  state.publicKeyRaw = meta.publicKeyRaw;
  state.wrapped = meta.wrapped;
  state.wrapIv = meta.iv;
  state.prev = prev;

  await loadData();
  await expireOldKeys();
}

async function enterApp() {
  state.fp = await fingerprint(state.publicKeyRaw);
  mountGuide('app');
  showScreen('app');
  setView('encrypt');
  await renderIdentity();
  $('#autolockSel').value = String(state.settings.autolock);
  $('#keepOldSel').value = String(state.settings.keepOld);
  renderKeyInfo();
  syncThemeButton();
  afterLangChange();

  if (state.pendingCard) {
    const card = state.pendingCard;
    state.pendingCard = null;
    openAddContact(card);
  }
}

function lock() {
  state.privateKey = null;
  state.wrapKey = null;
  state.dataKey = null;
  state.prev = [];
  state.addPrev = null;
  state.contacts = [];
  state.seen = [];
  state.lastCipher = '';
  $('#plainInput').value = '';
  $('#cipherInput').value = '';
  $('#cipherOutput').value = '';
  clear($('#plainOutput'));
  $('#encResult').hidden = true;
  $('#decResult').hidden = true;
  $('#manualKey').value = '';
  $('#backupOut').value = '';
  $('#backupOut').hidden = true;
  $('#decMeta').textContent = '';
  $('#decNotice').hidden = true;
  $('#myFingerprint').textContent = '';
  clear($('#mySeal'));
  clear($('#decSender'));
  // Ohne das blieben Kontaktnamen und Fingerabdrücke nach dem Sperren im DOM stehen.
  renderContacts();
  renderRecipients();
  renderLockSeal();
  showScreen('lock');
  toast(t('toast.locked'));
  setTimeout(() => $('#unlockPass').focus(), 220);
}

function autolockTick() {
  const minutes = Number(state.settings.autolock);
  if (!state.privateKey || !minutes) return;
  if (Date.now() - state.lastActivity > minutes * 60000) lock();
}

/* ================= Daten ================= */

async function loadData() {
  const rec = await readData();
  if (!rec) { state.contacts = []; state.seen = []; return; }
  const data = await openJSON(state.dataKey, rec);
  state.contacts = Array.isArray(data.contacts) ? data.contacts : [];
  state.seen = Array.isArray(data.seen) ? data.seen.slice(-300) : [];
  state.settings = Object.assign({ ...DEFAULT_SETTINGS }, data.settings || {});
}

function sealData(dataKey = state.dataKey) {
  return sealJSON(dataKey, {
    contacts: state.contacts,
    seen: state.seen.slice(-300),
    settings: state.settings
  });
}

async function persistData() {
  await writeData(await sealData());
}

/** meta und data zusammen, in einer Transaktion. */
async function persistVault() {
  await writeVault(state.meta, await sealData());
}

/** Kontakt zu einem Public Key — aktueller Schluessel oder einer, den er vorher hatte. */
function contactByKey(b64) {
  return state.contacts.find((c) => c.k === b64)
    || state.contacts.find((c) => Array.isArray(c.pk) && c.pk.includes(b64))
    || null;
}

async function contactVisual(c) {
  const raw = b64urlDecode(c.k);
  const fp = await fingerprint(raw);
  return { raw, fp };
}

/* ================= Identität rendern ================= */

async function renderIdentity() {
  const seal = $('#mySeal');
  clear(seal);
  seal.appendChild(sigil(state.fp.hash, { size: 68, animate: true, title: t('con.you') }));
  $('#myFingerprint').textContent = state.fp.text;
}

async function renderHeroSeal() {
  const demo = await sha256(randomBytes(32));
  const box = $('#heroSeal');
  clear(box);
  box.appendChild(sigil(demo, { size: 148, animate: true }));
}

async function renderLockSeal() {
  const box = $('#lockSeal');
  clear(box);
  const meta = state.meta || await readMeta();
  const hash = meta ? (await fingerprint(meta.publicKeyRaw)).hash : await sha256(randomBytes(32));
  clear(box);
  box.appendChild(sigil(hash, { size: 84, animate: true }));
}

/* ================= Verschlüsseln ================= */

function wireEncrypt() {
  for (const tab of $$('.tab')) tab.addEventListener('click', () => setView(tab.dataset.view));

  const input = $('#plainInput');
  input.addEventListener('input', () => {
    if (input.value.length > MAX_MESSAGE) input.value = input.value.slice(0, MAX_MESSAGE);
    $('#plainCounter').textContent = String(input.value.length);
  });

  $('#btnEncrypt').addEventListener('click', doEncrypt);
  $('#btnEncAgain').addEventListener('click', () => {
    $('#plainInput').value = '';
    $('#plainCounter').textContent = '0';
    $('#encResult').hidden = true;
    $('#plainInput').focus();
  });
  $('#btnCopyCipher').addEventListener('click', () => copyAndToast(state.lastCipher));
  $('#btnShareCipher').addEventListener('click', () => shareText(state.lastCipher));
  if (navigator.share) $('#btnShareCipher').hidden = false;
}

async function doEncrypt() {
  const err = $('#encError');
  err.hidden = true;
  const text = $('#plainInput').value;
  if (!text.trim()) return showError(err, t('enc.err.text'));

  let recipientRaw = null;
  let recipientName = '';
  let contact = null;
  const sel = $('#recipient').value;
  const manual = $('#manualKey').value.trim();

  if (sel) {
    contact = state.contacts.find((x) => x.id === sel) || null;
    if (contact) { recipientRaw = b64urlDecode(contact.k); recipientName = contact.n; }
  } else if (manual) {
    const parsed = parseContactInput(manual);
    if (!parsed) return showError(err, t('enc.err.key'));
    recipientRaw = parsed.publicKeyRaw;
    recipientName = parsed.name || t('dec.unknown');
  }
  if (!recipientRaw) return showError(err, t('enc.err.recipient'));

  // Kennt der Kontakt noch einen frueheren Schluessel von uns, geht die Nachricht von
  // diesem aus (nur den kann er pruefen) und traegt den aktuellen als Update mit.
  // Nach mehreren Wechseln kennt der Kontakt womoeglich schon einen neueren Schluessel als
  // den, von dem wir senden. Deshalb beglaubigen alle anderen frueheren Schluessel das
  // Update mit — der Kontakt prueft die Beglaubigung desjenigen, den er gespeichert hat.
  let sender = { privateKey: state.privateKey, publicKeyRaw: state.publicKeyRaw };
  let rotateTo = null;
  let endorsers = [];
  const known = contact && contact.mk && state.prev.find((p) => b64urlEncode(p.publicKeyRaw) === contact.mk);
  if (known) {
    sender = known;
    rotateTo = state.publicKeyRaw;
    endorsers = state.prev.filter((p) => p !== known);
  }

  await withBusy($('#btnEncrypt'), null, async () => {
    try {
      await importPublicRaw(recipientRaw);
      const armored = await encryptMessage({
        text,
        senderPrivateKey: sender.privateKey,
        senderPublicKeyRaw: sender.publicKeyRaw,
        recipientPublicKeyRaw: recipientRaw,
        rotateTo,
        endorsers
      });
      state.lastCipher = armored;
      $('#encStatus').textContent = t('enc.done', { name: recipientName }) + (rotateTo ? ' ' + t('rot.included') : '');
      $('#encResult').hidden = false;
      await scrambleTo($('#cipherOutput'), armored, { duration: 620, max: 4000 });
      $('#encResult').scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'nearest' });
    } catch (e) {
      showError(err, e instanceof CryptoError ? t('enc.err.key') : t('err.generic'));
    }
  });
}

/* ================= Entschlüsseln ================= */

function wireDecrypt() {
  $('#btnDecrypt').addEventListener('click', doDecrypt);
  $('#btnDecAgain').addEventListener('click', () => {
    $('#cipherInput').value = '';
    $('#decResult').hidden = true;
    $('#cipherInput').focus();
  });
  $('#btnCopyPlain').addEventListener('click', () => copyAndToast($('#plainOutput').textContent));
}

async function doDecrypt() {
  const err = $('#decError');
  err.hidden = true;
  const armored = $('#cipherInput').value;
  if (!armored.trim()) return showError(err, t('dec.err.empty'));

  await withBusy($('#btnDecrypt'), null, async () => {
    try {
      const res = await decryptMessage({ armored, keys: keyRing() });

      const senderB64 = b64urlEncode(res.senderPublicKeyRaw);
      const known = contactByKey(senderB64);
      let changed = false;
      let rotated = false;

      if (known) {
        // An unseren aktuellen Schluessel geschrieben: der Kontakt hat das Update.
        if (res.keyIndex === 0 && known.mk) { delete known.mk; changed = true; }
        rotated = await applyRotation(known, res);
        changed = changed || rotated;
      }

      const shownKey = rotated ? res.rotateTo : res.senderPublicKeyRaw;
      const senderFp = await fingerprint(shownKey);

      const box = $('#decSender');
      clear(box);
      box.appendChild(sigil(senderFp.hash, { size: 42 }));
      box.appendChild(el('div', { class: 'contact-meta' },
        el('p', { class: 'contact-name', text: known ? known.n : t('dec.unknown') }),
        el('p', { class: 'contact-fp', text: senderFp.text })
      ));
      if (known) {
        box.appendChild(el('span', { class: 'badge ' + (known.v ? 'badge-ok' : 'badge-warn') },
          icon(known.v ? 'check' : 'alert', 'icon icon-sm'),
          t(known.v ? 'con.verified' : 'con.unverified')
        ));
      } else {
        // Bringt die Nachricht einen neuen Schluessel mit, wird gleich dieser gespeichert —
        // er ist es, dessen Fingerabdruck das Gegenueber jetzt in seiner App sieht.
        box.appendChild(el('button', {
          class: 'btn btn-small btn-quiet',
          onclick: () => openAddContact({ name: '', publicKeyRaw: res.rotateTo || res.senderPublicKeyRaw },
            res.rotateTo ? senderB64 : null)
        }, t('dec.addsender')));
      }

      const id = toHex(res.envelopeId);
      const duplicate = state.seen.includes(id);
      if (!duplicate) {
        state.seen.push(id);
        changed = true;
      }
      if (changed) await persistData();
      if (rotated) { renderContacts(); renderRecipients(); }

      const notice = $('#decNotice');
      notice.hidden = !rotated;
      if (rotated) $('#decNoticeText').textContent = t('rot.applied', { name: known.n, fp: senderFp.text });

      const meta = [];
      if (res.sentAt) meta.push(`${t('dec.sentAt')}: ${formatDateTime(res.sentAt, getLang())}`);
      if (duplicate) meta.push(t('dec.dup'));
      if (!known) meta.push(t('dec.unknownHint'));
      if (known && !rotated && known.k !== senderB64) meta.push(t('dec.theirOldKey'));
      if (res.keyIndex > 0) meta.push(t('dec.myOldKey'));
      $('#decMeta').textContent = meta.join(' · ');

      $('#decResult').hidden = false;
      await scrambleTo($('#plainOutput'), res.text, { duration: 560, max: 3000 });
    } catch (e) {
      const code = e instanceof CryptoError ? e.code : 'generic';
      showError(err, t('dec.err.' + code) === 'dec.err.' + code ? t('err.generic') : t('dec.err.' + code));
    }
  });
}

function keyRing() {
  return [
    { privateKey: state.privateKey, publicKeyRaw: state.publicKeyRaw },
    ...state.prev.map((p) => ({ privateKey: p.privateKey, publicKeyRaw: p.publicKeyRaw }))
  ];
}

/**
 * Uebernimmt einen neuen Schluessel des Kontakts — aber nur, wenn genau der Schluessel,
 * den wir fuer ihn gespeichert haben, das Update beglaubigt. Kommt die Nachricht von
 * einem aelteren Schluessel, muss sie eine Beglaubigung des aktuellen mitbringen. So kann
 * weder ein wiedereingespieltes altes Update zurueckrollen, noch jemand, der einen
 * ausgemusterten Schluessel erbeutet hat, den Kontakt umlenken. Der Pruefstatus bleibt
 * erhalten: Die Kette beginnt beim bisherigen, geprueften Schluessel.
 */
async function applyRotation(contact, res) {
  if (!res.rotateTo) return false;
  const next = b64urlEncode(res.rotateTo);
  if (next === contact.k || next === b64urlEncode(state.publicKeyRaw)) return false;
  if ((contact.pk || []).includes(next)) return false; // kein Zurueckrollen
  if (!(await res.vouchedBy(b64urlDecode(contact.k)))) return false;

  // Hat jemand die neue Kontaktkarte schon separat gespeichert, fuehren wir beide
  // Eintraege zusammen. Einen geprueften Eintrag oder einen mit eigener Schluessel-
  // geschichte fassen wir nicht an — da entscheidet der Mensch.
  const dup = state.contacts.find((x) => x !== contact && (x.k === next || (x.pk || []).includes(next)));
  if (dup) {
    if (dup.v || dup.k !== next || (dup.pk || []).length) return false;
    state.contacts = state.contacts.filter((x) => x !== dup);
  }

  contact.pk = [contact.k, ...(contact.pk || [])].slice(0, 8);
  contact.k = next;
  contact.rt = Date.now();
  return true;
}

/* ================= Kontakte ================= */

function wireContacts() {
  $('#btnAddContact').addEventListener('click', () => openAddContact(null));
  $('#btnCopyCard').addEventListener('click', () => copyAndToast(myCard()));
  $('#btnCopyLink').addEventListener('click', () => copyAndToast(myLink()));
  $('#btnShareCard').addEventListener('click', () => shareText(myCard()));
  if (navigator.share) $('#btnShareCard').hidden = false;

  const input = $('#contactInput');
  input.addEventListener('input', () => previewContact(input.value));

  $('#contactForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#contactError');
    err.hidden = true;
    const parsed = parseContactInput($('#contactInput').value);
    if (!parsed) return showError(err, t('con.add.invalid'));

    const b64 = b64urlEncode(parsed.publicKeyRaw);
    if (b64 === b64urlEncode(state.publicKeyRaw)) return showError(err, t('con.add.self'));
    const existing = contactByKey(b64);
    if (existing) return showError(err, t('con.add.exists', { name: existing.n }));

    const name = cleanName($('#contactName').value) || parsed.name || t('dec.unknown');
    const entry = { id: toHex(randomBytes(8)), n: name, k: b64, v: false, t: Date.now() };
    // Stammt der Schluessel aus einem Update, bleibt der alte als Vorgaenger bekannt —
    // sonst erschiene die naechste Nachricht, die noch vom alten kommt, als Fremder.
    if (state.addPrev && state.addPrev.key === b64 && !contactByKey(state.addPrev.prev)) {
      entry.pk = [state.addPrev.prev];
    }
    state.addPrev = null;
    state.contacts.push(entry);
    state.contacts.sort((a, b) => a.n.localeCompare(b.n));
    await persistData();
    renderContacts();
    renderRecipients();
    $('#dlgContact').close();
    toast(t('con.added', { name }));
  });
}

function myCard() { return encodeContactCard(t('con.you'), state.publicKeyRaw); }
function myLink() {
  const base = location.origin && location.origin !== 'null' ? location.origin + location.pathname : 'https://encryptor.one/';
  return base + '#' + encodeContactCard('', state.publicKeyRaw);
}

function openAddContact(card, prevKey = null) {
  state.addPrev = card && prevKey ? { key: b64urlEncode(card.publicKeyRaw), prev: prevKey } : null;
  $('#contactError').hidden = true;
  $('#contactInput').value = card ? encodeContactCard(card.name || '', card.publicKeyRaw) : '';
  $('#contactName').value = card && card.name ? card.name : '';
  previewContact($('#contactInput').value);
  openDialog('#dlgContact');
  setTimeout(() => $(card ? '#contactName' : '#contactInput').focus(), 220);
}

async function previewContact(value) {
  const box = $('#contactPreview');
  const parsed = parseContactInput(value);
  clear(box);
  if (!parsed) { box.hidden = true; return; }
  const fp = await fingerprint(parsed.publicKeyRaw);
  box.appendChild(sigil(fp.hash, { size: 46 }));
  box.appendChild(el('div', { class: 'contact-meta' },
    el('p', { class: 'label-sm', text: t('con.fingerprint') }),
    el('p', { class: 'contact-fp', text: fp.text })
  ));
  box.hidden = false;
  if (parsed.name && !$('#contactName').value) $('#contactName').value = parsed.name;
}

// Der Aufbau ist asynchron (Fingerabdruck je Kontakt). Ohne diesen Zähler können
// zwei überlappende Aufrufe beide leeren und dann beide anhängen — Kontakte doppelt.
let contactsRender = 0;

async function renderContacts() {
  const token = ++contactsRender;
  const rows = [];

  for (const c of state.contacts) {
    const { fp } = await contactVisual(c);
    if (token !== contactsRender) return; // ein neuerer Aufbau hat übernommen
    const row = el('li', {},
      el('button', { class: 'contact-row', type: 'button', onclick: () => openContactDetail(c) },
        sigil(fp.hash, { size: 38 }),
        el('div', { class: 'contact-meta' },
          el('p', { class: 'contact-name', text: c.n }),
          el('p', { class: 'contact-fp', text: fp.text })
        ),
        el('span', { class: 'badge ' + (c.v ? 'badge-ok' : 'badge-warn') },
          icon(c.v ? 'check' : 'alert', 'icon icon-sm'),
          t(c.v ? 'con.verified' : 'con.unverified'))
      )
    );
    rows.push(row);
  }

  if (token !== contactsRender) return;
  const list = $('#contactList');
  clear(list);
  for (const row of rows) list.appendChild(row);
  $('#contactEmpty').hidden = rows.length > 0;
}

function renderRecipients() {
  const sel = $('#recipient');
  const previous = sel.value;
  clear(sel);
  sel.appendChild(el('option', { value: '' }, t('enc.pickNone')));
  for (const c of state.contacts) {
    sel.appendChild(el('option', { value: c.id }, c.n + (c.v ? ' ✓' : '')));
  }
  // Bei genau einem Kontakt gibt es nichts zu wählen — dann gleich vorbelegen.
  const stillThere = state.contacts.some((c) => c.id === previous);
  sel.value = stillThere ? previous : (state.contacts.length === 1 ? state.contacts[0].id : '');
  $('#encNoContacts').hidden = state.contacts.length > 0;
  $('#manualKeyBox').open = state.contacts.length === 0;
}

async function openContactDetail(c) {
  const { raw, fp } = await contactVisual(c);
  $('#detailTitle').textContent = c.n;
  const body = $('#detailBody');
  clear(body);

  body.appendChild(el('div', { class: 'identity' },
    el('div', { class: 'identity-seal' }, sigil(fp.hash, { size: 68, animate: true })),
    el('div', { class: 'identity-body' },
      el('p', { class: 'label-sm', text: t('con.fingerprint') }),
      el('p', { class: 'fingerprint', text: fp.text })
    )
  ));

  if (c.rt) {
    body.appendChild(el('p', { class: 'hint', text: t('rot.contactChanged', { date: formatDateTime(c.rt, getLang()) }) }));
  }
  if (c.mk && state.prev.some((p) => b64urlEncode(p.publicKeyRaw) === c.mk)) {
    body.appendChild(el('p', { class: 'callout callout-info' },
      icon('refresh', 'icon icon-sm'), el('span', { text: t('rot.pending', { name: c.n }) })));
    body.appendChild(el('div', { class: 'btn-row' }, el('button', {
      class: 'btn btn-primary', type: 'button', onclick: () => composeKeyUpdate(c)
    }, icon('refresh'), t('rot.compose'))));
  }

  body.appendChild(el('p', { class: 'label-sm', text: t('con.verify') }));
  body.appendChild(el('p', { class: 'hint', text: t('con.verifyBody') }));

  const verifyBtn = el('button', {
    class: 'btn ' + (c.v ? 'btn-quiet' : 'btn-primary'), type: 'button',
    onclick: async () => {
      c.v = !c.v;
      await persistData();
      renderContacts();
      renderRecipients();
      $('#dlgDetail').close();
    }
  }, icon('check'), t(c.v ? 'con.unverify' : 'con.verifyConfirm'));

  const renameBtn = el('button', {
    class: 'btn btn-quiet', type: 'button',
    onclick: () => {
      const field = el('input', { class: 'input', value: c.n, maxlength: 64 });
      const save = el('button', { class: 'btn btn-primary', type: 'button', onclick: async () => {
        c.n = cleanName(field.value) || c.n;
        state.contacts.sort((a, b) => a.n.localeCompare(b.n));
        await persistData();
        renderContacts();
        renderRecipients();
        $('#dlgDetail').close();
      } }, t('action.save'));
      clear(body);
      body.appendChild(el('div', { class: 'field' },
        el('label', { class: 'label', text: t('con.add.name') }), field));
      body.appendChild(el('div', { class: 'btn-row btn-row-end' }, save));
      field.focus();
    }
  }, icon('pencil'), t('con.rename'));

  const copyCardBtn = el('button', {
    class: 'btn btn-quiet', type: 'button',
    onclick: () => copyAndToast(encodeContactCard(c.n, raw))
  }, icon('copy'), t('con.copyCard'));

  const copyKeyBtn = el('button', {
    class: 'btn btn-quiet', type: 'button',
    onclick: () => copyAndToast(b64urlEncode(raw))
  }, icon('key'), t('con.copyKey'));

  const delBtn = el('button', {
    class: 'btn btn-danger', type: 'button',
    onclick: () => {
      $('#dlgDetail').close();
      confirmDialog({
        title: c.n,
        body: t('con.deleteConfirm', { name: c.n }),
        okLabel: t('action.delete'),
        onOk: async () => {
          state.contacts = state.contacts.filter((x) => x.id !== c.id);
          await persistData();
          renderContacts();
          renderRecipients();
          toast(t('con.deleted'));
        }
      });
    }
  }, icon('trash'), t('action.delete'));

  body.appendChild(el('div', { class: 'btn-row' }, verifyBtn, renameBtn));
  body.appendChild(el('div', { class: 'btn-row' }, copyCardBtn, copyKeyBtn));
  body.appendChild(el('div', { class: 'btn-row' }, delBtn));
  openDialog('#dlgDetail');
}

/** Fuellt den Verschluesseln-Tab mit einer Update-Nachricht an genau diesen Kontakt. */
async function composeKeyUpdate(c) {
  $('#dlgDetail').close();
  setView('encrypt');
  $('#manualKey').value = '';
  $('#recipient').value = c.id;
  $('#plainInput').value = t('rot.message', { fp: state.fp.text });
  $('#plainCounter').textContent = String($('#plainInput').value.length);
  await doEncrypt();
}

/* ================= Schluesselwechsel ================= */

async function rotateKey() {
  const id = await createIdentity(state.wrapKey);
  const now = Date.now();
  const oldB64 = b64urlEncode(state.publicKeyRaw);
  const retired = {
    publicKeyRaw: state.meta.publicKeyRaw, wrapped: state.meta.wrapped, iv: state.meta.iv,
    createdAt: state.meta.createdAt, retiredAt: now
  };
  const meta = Object.assign({}, state.meta, {
    createdAt: now, publicKeyRaw: id.publicKeyRaw, wrapped: id.wrapped, iv: id.iv,
    prev: [retired, ...(state.meta.prev || [])]
  });

  // Jeder Kontakt kennt bis auf Weiteres nur den bisherigen Schluessel. Wer schon auf ein
  // noch aelteres Update wartet, behaelt diesen Stand — den kann er ja pruefen.
  const pending = state.contacts.filter((c) => !c.mk);
  for (const c of pending) c.mk = oldB64;
  try {
    await writeVault(meta, await sealData());
  } catch (e) {
    for (const c of pending) delete c.mk;
    throw e;
  }

  state.meta = meta;
  state.prev = [{ publicKeyRaw: retired.publicKeyRaw, privateKey: state.privateKey, retiredAt: now }, ...state.prev];
  state.privateKey = id.privateKey;
  state.publicKeyRaw = id.publicKeyRaw;
  state.wrapped = id.wrapped;
  state.wrapIv = id.iv;
  state.fp = await fingerprint(id.publicKeyRaw);
  await renderIdentity();
  renderKeyInfo();
}

/** Loescht fruehere Schluessel, deren Aufbewahrungsfrist abgelaufen ist. */
async function expireOldKeys() {
  const days = Number(state.settings.keepOld);
  if (!days || !state.prev.length) return;
  const cutoff = Date.now() - days * DAY;
  const keep = state.prev.filter((p) => p.retiredAt > cutoff);
  if (keep.length !== state.prev.length) await dropOldKeys(keep);
}

async function dropOldKeys(keep = []) {
  const kept = new Set(keep.map((p) => b64urlEncode(p.publicKeyRaw)));
  // Kennt ein Kontakt nur einen Schluessel, der jetzt geloescht wird, senden wir vom
  // aeltesten verbliebenen aus — vielleicht hat er dessen Update ja bekommen. Bleibt
  // keiner, kommt Post vom aktuellen, und der Kontakt muss dich neu hinzufuegen.
  const oldest = keep.length ? b64urlEncode(keep[keep.length - 1].publicKeyRaw) : null;
  for (const c of state.contacts) {
    if (!c.mk || kept.has(c.mk)) continue;
    if (oldest) c.mk = oldest; else delete c.mk;
  }
  state.meta = Object.assign({}, state.meta, {
    prev: (state.meta.prev || []).filter((p) => kept.has(b64urlEncode(p.publicKeyRaw)))
  });
  state.prev = keep;
  await persistVault();
  renderKeyInfo();
}

function renderKeyInfo() {
  if (!state.meta) return;
  const parts = [t('set.keys.since', { date: formatDateTime(state.meta.createdAt, getLang()) })];
  if (state.prev.length) parts.push(t('set.keys.old', { n: state.prev.length }));
  $('#keyInfo').textContent = parts.join(' · ');
  $('#btnDropOld').hidden = state.prev.length === 0;
}

/* ================= Einstellungen, Sicherung ================= */

function wireSettings() {
  for (const b of $$('#themeSeg button')) {
    b.addEventListener('click', () => applyTheme(b.dataset.themeVal));
  }
  for (const b of $$('#langSeg button')) {
    b.addEventListener('click', () => { setLang(b.dataset.langVal); afterLangChange(); });
  }
  $('#autolockSel').addEventListener('change', async (e) => {
    state.settings.autolock = Number(e.target.value);
    await persistData();
  });
  $('#btnLockNow').addEventListener('click', () => { $('#dlgSettings').close(); lock(); });

  $('#keepOldSel').addEventListener('change', async (e) => {
    state.settings.keepOld = Number(e.target.value);
    await persistData();
    await expireOldKeys();
  });
  $('#btnRotate').addEventListener('click', () => {
    $('#dlgSettings').close();
    confirmDialog({
      title: t('rot.confirmTitle'),
      body: t('rot.confirmBody'),
      okLabel: t('rot.confirmOk'),
      onOk: async () => {
        try {
          await rotateKey();
        } catch {
          return toast(t('err.generic'), 'warn');
        }
        renderContacts();
        setView('contacts');
        toast(t('rot.done'), 'ok', 9000);
      }
    });
  });
  $('#btnDropOld').addEventListener('click', () => {
    $('#dlgSettings').close();
    confirmDialog({
      title: t('set.keys.drop'),
      body: t('set.keys.dropConfirm'),
      okLabel: t('set.keys.drop'),
      onOk: async () => { await dropOldKeys([]); toast(t('set.keys.dropped')); }
    });
  });

  $('#btnExport').addEventListener('click', exportBackup);
  $('#btnImport').addEventListener('click', () => $('#importFile').click());

  $('#passForm').addEventListener('submit', changePassphrase);

  $('#btnPurge').addEventListener('click', () => {
    $('#dlgSettings').close();
    confirmDialog({
      title: t('set.danger'),
      body: t('set.purge.confirm'),
      okLabel: t('set.purge'),
      onOk: async () => {
        await destroyVault();
        prefs.remove('fails'); prefs.remove('lockUntil');
        toast(t('toast.purged'));
        setTimeout(() => location.reload(), 500);
      }
    });
  });
}

async function exportBackup() {
  const data = await readData();
  const payload = {
    app: 'encryptor.one', type: 'backup', v: 1, createdAt: Date.now(),
    kdf: { name: 'PBKDF2-SHA256', iterations: state.meta.kdf.iterations, salt: b64urlEncode(state.meta.kdf.salt) },
    identity: {
      publicKey: b64urlEncode(state.meta.publicKeyRaw),
      wrapped: b64urlEncode(state.meta.wrapped),
      iv: b64urlEncode(state.meta.iv),
      createdAt: state.meta.createdAt
    },
    previous: (state.meta.prev || []).map((p) => ({
      publicKey: b64urlEncode(p.publicKeyRaw),
      wrapped: b64urlEncode(p.wrapped),
      iv: b64urlEncode(p.iv),
      createdAt: p.createdAt,
      retiredAt: p.retiredAt
    })),
    data: data ? { iv: b64urlEncode(data.iv), ct: b64urlEncode(data.ct) } : null
  };
  const text = JSON.stringify(payload, null, 2);
  const box = $('#backupOut');
  box.value = text;
  box.hidden = false;

  try {
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: `encryptor-one-backup-${new Date().toISOString().slice(0, 10)}.json` });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  } catch { /* Textfeld bleibt als Rückfallebene */ }
  toast(t('set.backup.done'));
}

async function importBackup(e) {
  const file = e.target.files && e.target.files[0];
  e.target.value = '';
  if (!file) return;

  let payload;
  try { payload = JSON.parse(await file.text()); } catch { return toast(t('set.backup.bad'), 'warn'); }
  if (!payload || payload.app !== 'encryptor.one' || !payload.identity || !payload.kdf) {
    return toast(t('set.backup.bad'), 'warn');
  }

  $('#dlgSettings').close();

  const restore = async () => {
    let meta, data;
    try {
      ({ meta, data } = parseBackup(payload));
    } catch {
      return toast(t('set.backup.bad'), 'warn');
    }

    // Ob Public Key und verpackter Schluessel zusammenpassen, laesst sich erst mit der
    // Passphrase pruefen — das passiert beim naechsten Entsperren (openVault).
    await writeVault(meta, data);
    state.meta = meta;
    state.privateKey = null;
    prefs.remove('fails');
    prefs.remove('lockUntil');
    toast(t('set.backup.imported'));
    setTimeout(() => location.reload(), 900);
  };

  // Ohne bestehende Identität gibt es nichts zu überschreiben — direkt einspielen.
  if (!state.meta && !(await hasVault())) return restore();

  confirmDialog({
    title: t('set.backup.import'),
    body: t('set.backup.overwrite'),
    okLabel: t('set.backup.import'),
    onOk: restore
  });
}

/** Sicherungsdatei → Vault-Datensaetze. Alles, was von aussen kommt, wird geprueft. */
function parseBackup(payload) {
  const bytes = (v, min, max) => {
    const b = b64urlDecode(String(v));
    if (b.length < min || b.length > max) throw new Error('backup');
    return b;
  };
  const key = (rec) => {
    const publicKeyRaw = bytes(rec.publicKey, 65, 65);
    if (publicKeyRaw[0] !== 4) throw new Error('backup');
    return {
      publicKeyRaw,
      wrapped: bytes(rec.wrapped, 48, 1024),
      iv: bytes(rec.iv, 12, 12),
      createdAt: Number(rec.createdAt) || null,
      retiredAt: Number(rec.retiredAt) || null
    };
  };
  // Eine manipulierte Datei soll das Entsperren weder abschwaechen noch einfrieren koennen.
  const iterations = payload.kdf.iterations ?? KDF_ITERATIONS;
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 10_000_000) throw new Error('backup');

  const current = key(payload.identity);
  const prev = (Array.isArray(payload.previous) ? payload.previous : []).slice(0, 32).map(key);
  if (prev.some((p) => !p.retiredAt)) throw new Error('backup');

  const meta = {
    v: 1,
    createdAt: current.createdAt || Number(payload.createdAt) || Date.now(),
    kdf: { iterations, salt: bytes(payload.kdf.salt, 16, 64) },
    publicKeyRaw: current.publicKeyRaw, wrapped: current.wrapped, iv: current.iv,
    prev
  };
  const data = payload.data
    ? { iv: bytes(payload.data.iv, 12, 12), ct: bytes(payload.data.ct, 16, 8_000_000) }
    : null;
  return { meta, data };
}

async function changePassphrase(e) {
  e.preventDefault();
  const err = $('#passError');
  err.hidden = true;
  const oldPass = $('#passOld').value;
  const newPass = $('#passNew').value;
  if (newPass.length < 12) return showError(err, t('setup.tooweak'));

  const btn = e.target.querySelector('button[type="submit"]');
  await withBusy(btn, t('setup.working'), async () => {
    try {
      const oldKeys = await deriveVaultKeys(oldPass, state.meta.kdf.salt, state.meta.kdf.iterations);
      await unwrapIdentity(oldKeys.wrapKey, state.meta.wrapped, state.meta.iv);

      const salt = randomBytes(16);
      const newKeys = await deriveVaultKeys(newPass, salt);
      const rewrapped = await rewrapIdentity(oldKeys.wrapKey, state.meta.wrapped, state.meta.iv, newKeys.wrapKey);
      const prev = [];
      for (const p of state.meta.prev || []) {
        const r = await rewrapIdentity(oldKeys.wrapKey, p.wrapped, p.iv, newKeys.wrapKey);
        prev.push(Object.assign({}, p, { wrapped: r.wrapped, iv: r.iv }));
      }

      const meta = Object.assign({}, state.meta, {
        kdf: { iterations: KDF_ITERATIONS, salt },
        wrapped: rewrapped.wrapped, iv: rewrapped.iv, prev
      });
      await writeVault(meta, await sealData(newKeys.dataKey));
      state.meta = meta;
      state.wrapKey = newKeys.wrapKey;
      state.dataKey = newKeys.dataKey;
      $('#passOld').value = $('#passNew').value = '';
      toast(t('set.pass.done'));
    } catch {
      showError(err, t('set.backup.wrongpass'));
    }
  });
}

/* ================= Anleitung ================= */

let stepIndex = 0;
let stepTimer = null;
let guideVisible = false;

function wireGuide() {
  const dots = $('#stepDots');
  for (let i = 0; i < 5; i++) {
    dots.appendChild(el('button', {
      class: 'dot' + (i === 0 ? ' is-active' : ''), type: 'button',
      'aria-label': `${i + 1}`, onclick: () => { stopAuto(); goToStep(i); }
    }));
  }
  $('#stepPrev').addEventListener('click', () => { stopAuto(); goToStep(stepIndex - 1); });
  $('#stepNext').addEventListener('click', () => { stopAuto(); goToStep(stepIndex + 1); });
  renderStepIndices();

  if ('IntersectionObserver' in window) {
    new IntersectionObserver(
      (entries) => { guideVisible = entries[0].isIntersecting; },
      { threshold: 0.3 }
    ).observe($('#howto'));
  } else {
    guideVisible = true;
  }
  startAuto();
}

function renderStepIndices() {
  for (const node of $$('[data-step-index]')) {
    node.textContent = t('guide.step', { n: node.dataset.stepIndex });
  }
}

function goToStep(i) {
  const steps = $$('.step');
  stepIndex = (i + steps.length) % steps.length;
  steps.forEach((s, n) => s.classList.toggle('is-active', n === stepIndex));
  $$('#stepDots .dot').forEach((d, n) => d.classList.toggle('is-active', n === stepIndex));
}

function startAuto() {
  if (prefersReducedMotion()) return;
  stepTimer = setInterval(() => {
    if (document.hidden || !guideVisible) return;
    goToStep(stepIndex + 1);
  }, 7000);
}
function stopAuto() { if (stepTimer) { clearInterval(stepTimer); stepTimer = null; } }

function mountGuide(where) {
  const howto = $('#howto');
  const sec = $('#securityNote');
  const guideSlot = where === 'app' ? $('#howtoSlotApp') : $('#howtoSlotLanding');
  const secSlot = where === 'app' ? $('#securitySlotApp') : $('#securitySlotLanding');
  guideSlot.appendChild(howto);
  secSlot.appendChild(sec);
}

/* ================= Kleine Helfer ================= */

function showError(node, message) {
  node.textContent = message;
  node.hidden = false;
}

async function withBusy(btn, label, fn) {
  const original = btn.cloneNode(true);
  btn.disabled = true;
  if (label) { clear(btn); btn.appendChild(document.createTextNode(label)); }
  try { await fn(); }
  finally {
    btn.disabled = false;
    if (label) { clear(btn); while (original.firstChild) btn.appendChild(original.firstChild); }
  }
}

async function copyAndToast(text) {
  if (!text) return;
  const ok = await copyText(text);
  toast(ok ? t('toast.copied') : t('toast.copyFailed'), ok ? 'ok' : 'warn');
}

async function shareText(text) {
  if (!navigator.share || !text) return copyAndToast(text);
  try { await navigator.share({ text }); } catch { /* abgebrochen */ }
}

function toast(message, kind = 'ok', ms = 4200, action = null) {
  const box = $('#toasts');
  const node = el('div', { class: 'toast' + (kind === 'warn' ? ' toast-warn' : '') },
    icon(kind === 'warn' ? 'alert' : 'check', 'icon icon-sm'),
    el('span', { text: message })
  );
  if (action) node.appendChild(el('button', { type: 'button', onclick: action.onClick }, action.label));
  box.appendChild(node);
  if (ms) setTimeout(() => node.remove(), ms);
}

function confirmDialog({ title, body, okLabel, onOk }) {
  const dlg = $('#dlgConfirm');
  $('#confirmTitle').textContent = title;
  $('#confirmBody').textContent = body;
  const ok = $('#confirmOk');
  ok.textContent = okLabel;
  const cancel = $('#confirmCancel');

  const cleanup = () => {
    ok.removeEventListener('click', accept);
    cancel.removeEventListener('click', decline);
  };
  const accept = async () => { cleanup(); dlg.close(); await onOk(); };
  const decline = () => { cleanup(); dlg.close(); };

  ok.addEventListener('click', accept);
  cancel.addEventListener('click', decline);
  if (!dlg.open) dlg.showModal();
}

/* ================= Service Worker ================= */

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  if (location.protocol !== 'https:' && location.hostname !== 'localhost') return;
  // Die CSP verlangt Trusted Types. register() ist eine Script-URL-Senke und nimmt ohne
  // Policy keinen String an — die Policy laesst genau eine URL durch, sonst nichts.
  let url = '/sw.js';
  if (window.trustedTypes) {
    url = trustedTypes.createPolicy('sw', {
      createScriptURL: (u) => { if (u !== '/sw.js') throw new TypeError('sw'); return u; }
    }).createScriptURL(url);
  }
  navigator.serviceWorker.register(url).then((reg) => {
    reg.addEventListener('updatefound', () => {
      const sw = reg.installing;
      if (!sw) return;
      sw.addEventListener('statechange', () => {
        if (sw.state === 'installed' && navigator.serviceWorker.controller) {
          // Bleibt stehen: Bis zum Neuladen laeuft die alte Version weiter.
          toast(t('toast.update'), 'warn', 0, {
            label: t('toast.reload'),
            onClick: () => { sw.postMessage({ type: 'SKIP_WAITING' }); location.reload(); }
          });
        }
      });
    });
  }).catch(() => { /* offline nicht verfügbar */ });
}

boot();
