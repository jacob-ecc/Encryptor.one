// boot.js — läuft synchron im <head>, damit Theme und Sprache vor dem ersten
// Frame stehen. Bewusst kein Modul und kein Inline-Script (strikte CSP).
(function () {
  var root = document.documentElement;
  var pref = 'system', lang = null;
  try {
    pref = localStorage.getItem('eo.theme') || 'system';
    lang = localStorage.getItem('eo.lang');
  } catch (e) { /* Speicher gesperrt */ }

  function resolve() {
    var dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = pref === 'system' ? (dark ? 'dark' : 'light') : pref;
  }
  root.dataset.themePref = pref;
  resolve();

  var mq = window.matchMedia('(prefers-color-scheme: dark)');
  var onChange = function () { if (root.dataset.themePref === 'system') resolve(); };
  mq.addEventListener ? mq.addEventListener('change', onChange) : mq.addListener(onChange);

  if (!lang) lang = (navigator.language || 'en').toLowerCase().indexOf('de') === 0 ? 'de' : 'en';
  root.lang = lang;
})();
