/**
 * i18n.js — Lightweight selector-based translation for purvanas.fr
 * French is the HTML source. English is applied via JS overlay.
 * Zero HTML modification needed — translations use CSS selectors.
 *
 * Usage: add at bottom of each page:
 *   <script src="/i18n.js"></script>
 *   <script>
 *   i18n.init({ en: {
 *     '.header p': 'Download videos from any platform',
 *     '#btn-analyze': 'Analyze',
 *     '#url-input': { placeholder: 'Paste a YouTube, Instagram link...' },
 *   }});
 *   </script>
 */
const i18n = (() => {
  let lang = 'fr';
  let trans = {};
  let originals = new Map();

  function detect() {
    const s = localStorage.getItem('lang');
    if (s) return s;
    return (navigator.language || '').startsWith('fr') ? 'fr' : 'en';
  }

  function apply(l) {
    lang = l;
    localStorage.setItem('lang', l);
    document.documentElement.lang = l;

    if (l === 'fr') {
      // Restore French originals
      originals.forEach((orig, sel) => {
        const el = document.querySelector(sel);
        if (!el) return;
        if (orig.t !== undefined) el.textContent = orig.t;
        if (orig.h !== undefined) el.innerHTML = orig.h;
        if (orig.p !== undefined) el.placeholder = orig.p;
        if (orig.ti !== undefined) el.title = orig.ti;
      });
    } else {
      const t = trans[l];
      if (!t) return;
      Object.entries(t).forEach(([sel, val]) => {
        const el = document.querySelector(sel);
        if (!el) return;
        // Save original once
        if (!originals.has(sel)) {
          originals.set(sel, { t: el.textContent, h: el.innerHTML, p: el.placeholder, ti: el.title });
        }
        if (typeof val === 'string') {
          // If contains HTML tags or entities, use innerHTML; otherwise textContent
          if (/<[a-z][\s\S]*>/i.test(val) || /&[#\w]+;/.test(val)) el.innerHTML = val;
          else el.textContent = val;
        } else if (typeof val === 'object') {
          if (val.text) el.textContent = val.text;
          if (val.html) el.innerHTML = val.html;
          if (val.placeholder) el.placeholder = val.placeholder;
          if (val.title) el.title = val.title;
        }
      });
    }
    updateBtn();
  }

  function updateBtn() {
    const b = document.getElementById('lang-toggle');
    if (b) b.textContent = lang === 'fr' ? '🇬🇧 EN' : '🇫🇷 FR';
  }

  function toggle() { apply(lang === 'fr' ? 'en' : 'fr'); }

  function addToggle() {
    const b = document.createElement('button');
    b.id = 'lang-toggle';
    b.onclick = toggle;
    Object.assign(b.style, {
      position: 'fixed', top: '12px', right: '12px', zIndex: '9999',
      background: '#23232b', color: '#fff', border: '1px solid #444',
      borderRadius: '8px', padding: '6px 14px', cursor: 'pointer',
      fontSize: '14px', fontWeight: '600', transition: 'background .2s',
      fontFamily: '-apple-system,sans-serif'
    });
    b.onmouseenter = () => b.style.background = '#333';
    b.onmouseleave = () => b.style.background = '#23232b';
    document.body.appendChild(b);
  }

  // For JS-generated text: i18n.t('French text', 'English text')
  function t(fr, en) { return lang === 'fr' ? fr : (en || fr); }

  function init(t) {
    trans = t;
    lang = detect();
    addToggle();
    if (lang !== 'fr') apply(lang);
    else updateBtn();
  }

  return { init, apply, toggle, t, lang: () => lang };
})();
