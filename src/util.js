// util.js — kleine Helfer. Keine innerHTML-Nutzung (Trusted Types safe).

export const enc = new TextEncoder();
export const dec = new TextDecoder();

const SVG_NS = 'http://www.w3.org/2000/svg';

/* ---------- Bytes ---------- */

export function concat(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function b64encode(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

export function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncode(bytes) {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/=]/g, '');
  while (s.length % 4) s += '=';
  return b64decode(s);
}

export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function wipe(...arrays) {
  for (const a of arrays) { if (a && a.fill) a.fill(0); }
}

/* ---------- DOM ---------- */

export function $(sel, root = document) { return root.querySelector(sel); }
export function $$(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }

/**
 * Element-Fabrik. `style` wird über CSSOM gesetzt, nicht als style-Attribut,
 * damit eine strikte style-src-CSP ohne 'unsafe-inline' funktioniert.
 */
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k === 'style') for (const [p, val] of Object.entries(v)) node.style.setProperty(p, val);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  append(node, children);
  return node;
}

export function svgEl(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'style') { for (const [p, val] of Object.entries(v)) node.style.setProperty(p, val); continue; }
    node.setAttribute(k, String(v));
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const c of children.flat(4)) {
    if (c === null || c === undefined || c === false || c === '') continue;
    node.appendChild(c && c.nodeType ? c : document.createTextNode(String(c)));
  }
}

export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

/** Icon aus dem Inline-Sprite in index.html. */
export function icon(name, cls = 'icon') {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', cls);
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', '#i-' + name);
  svg.appendChild(use);
  return svg;
}

/* ---------- Sonstiges ---------- */

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }
}

export function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

export function prefersReducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

const SCRAMBLE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Schreibt `target` zeichenweise auf `finalText`, wobei noch nicht
 * aufgelöste Positionen als Rauschen erscheinen. Rein visuell.
 */
export function scrambleTo(target, finalText, { duration = 700, max = 900 } = {}) {
  if (prefersReducedMotion() || finalText.length > max) {
    target.value !== undefined ? (target.value = finalText) : (target.textContent = finalText);
    return Promise.resolve();
  }
  const set = (v) => { if (target.value !== undefined) target.value = v; else target.textContent = v; };
  const len = finalText.length;
  const start = performance.now();
  return new Promise((resolve) => {
    function frame(now) {
      const p = Math.min(1, (now - start) / duration);
      const resolved = Math.floor(p * len);
      let out = finalText.slice(0, resolved);
      for (let i = resolved; i < len; i++) {
        const c = finalText[i];
        out += (c === '\n' || c === ' ') ? c : SCRAMBLE_CHARS[(Math.random() * SCRAMBLE_CHARS.length) | 0];
      }
      set(out);
      if (p < 1) requestAnimationFrame(frame);
      else { set(finalText); resolve(); }
    }
    requestAnimationFrame(frame);
  });
}

export function formatDateTime(ts, lang) {
  if (!ts) return '';
  try {
    return new Intl.DateTimeFormat(lang === 'de' ? 'de-DE' : 'en-GB', {
      dateStyle: 'medium', timeStyle: 'short'
    }).format(new Date(ts));
  } catch { return new Date(ts).toISOString(); }
}
