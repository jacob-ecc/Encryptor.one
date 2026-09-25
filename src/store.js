// store.js — IndexedDB-Ablage. Es liegt nichts Unverschlüsseltes im Vault:
// der private Schlüssel ist mit der Passphrase verpackt, Kontakte und
// Einstellungen sind mit einem daraus abgeleiteten, separaten Schlüssel versiegelt.

const DB_NAME = 'encryptor.one';
const DB_VERSION = 1;
const STORE = 'vault';

let dbPromise = null;

function open() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error('db_blocked'));
  });
  return dbPromise;
}

function tx(mode, fn) {
  return open().then((db) => new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const store = t.objectStore(STORE);
    let req;
    try { req = fn(store); } catch (e) { reject(e); return; }
    t.oncomplete = () => resolve(req && 'result' in req ? req.result : undefined);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  }));
}

export const idb = {
  get: (key) => tx('readonly', (s) => s.get(key)),
  set: (key, value) => tx('readwrite', (s) => s.put(value, key)),
  del: (key) => tx('readwrite', (s) => s.delete(key)),
  clear: () => tx('readwrite', (s) => s.clear())
};

/* ---------------- Datensätze ---------------- */
// meta     { v, createdAt, kdf:{iterations, salt:Uint8Array}, publicKeyRaw, wrapped, iv,
//            prev:[{ publicKeyRaw, wrapped, iv, createdAt, retiredAt }] }
// data     { iv:Uint8Array, ct:Uint8Array }  → { contacts:[], seen:[], settings:{} }

export const hasVault = async () => !!(await idb.get('meta'));
export const readMeta = () => idb.get('meta');
export const writeMeta = (meta) => idb.set('meta', meta);
export const readData = () => idb.get('data');
export const writeData = (rec) => idb.set('data', rec);

/**
 * Schreibt meta und data in einer Transaktion. Beim Passphrasen- oder Schluesselwechsel
 * haengen beide voneinander ab: ein Absturz dazwischen darf keinen Vault hinterlassen,
 * dessen Kontakte mit einem Schluessel versiegelt sind, den es nicht mehr gibt.
 */
export const writeVault = (meta, data) => tx('readwrite', (s) => {
  s.put(meta, 'meta');
  return s.put(data, 'data');
});

export async function destroyVault() {
  await idb.clear();
  try {
    const db = await open();
    db.close();
    dbPromise = null;
    await new Promise((resolve) => {
      const req = indexedDB.deleteDatabase(DB_NAME);
      req.onsuccess = req.onerror = req.onblocked = () => resolve();
    });
  } catch { /* schon weg */ }
}

/* ---------------- Nicht-geheime Einstellungen ---------------- */
// Theme und Sprache müssen vor dem ersten Frame verfügbar sein → localStorage.

export const prefs = {
  get(key, fallback = null) {
    try { const v = localStorage.getItem('eo.' + key); return v === null ? fallback : v; }
    catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem('eo.' + key, String(value)); } catch { /* Privatmodus */ }
  },
  remove(key) {
    try { localStorage.removeItem('eo.' + key); } catch { /* egal */ }
  }
};
