// Runs in the main webview, whose origin owns calabi_lang. The bundled tray
// has separate storage. Rust validates the sender against the daemon origin.
(() => {
  if (location.protocol !== 'http:' || location.hostname !== '127.0.0.1') return;
  let sent;
  async function sync() {
    const locale = document.documentElement?.lang || localStorage.getItem('calabi_lang') || 'en';
    if (locale === sent) return;
    try {
      await window.__TAURI_INTERNALS__.invoke('tray_set_locale', { locale });
      sent = locale;
    } catch (_) { /* Startup can precede tray state; the timer retries. */ }
  }
  function start() {
    new MutationObserver(sync).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
    sync();
  }
  if (document.documentElement) start();
  else document.addEventListener('DOMContentLoaded', start, { once: true });
  window.addEventListener('storage', sync);
  setInterval(sync, 1000);
})();
