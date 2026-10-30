// NODE_PATH may point to the local Playwright installation. No daemon required.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const catalog = JSON.parse(fs.readFileSync(path.join(root, 'shell/tray-locales.json'), 'utf8'));
const labels = catalog.en;
const languages = fs.readFileSync(path.join(root, '../client/internal/status/ui/src/i18n/languages.ts'), 'utf8');
const codes = [...languages.matchAll(/code: "([^"]+)"/g)].map(m => m[1]);
assert.deepEqual(Object.keys(catalog).sort(), codes.sort());
for (const code of codes) {
  assert.deepEqual(Object.keys(catalog[code]).sort(), Object.keys(labels).sort(), code);
  assert.ok(Object.values(catalog[code]).every(value => typeof value === 'string' && value.trim()), code);
}

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 288, height: 340 } });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.addInitScript(({ labels }) => {
      window.snapshot = { name: 'eq-cbf1ae3c', org: 'CalabiTeam', ip: '100.64.0.36',
        status: 'Connected', up: true, online: 3, files: true, locale: 'en', labels };
      window.actions = [];
      window.__TAURI_INTERNALS__ = { invoke: async (_, { action }) => {
        if (action === 'snapshot') return window.snapshot;
        window.actions.push(action);
      }};
    }, { labels });
    await page.goto('file:///' + path.join(root, 'shell/tray.html').replaceAll('\\', '/'));
    await page.getByText('Open main window', { exact: true }).waitFor();
    assert.equal(await page.locator('#peers').innerText(), '3 online');
    await page.locator('#copy').click();
    assert.equal(await page.locator('#receipt').innerText(), 'Mesh IP copied');
    for (const locale of [...codes, 'en']) {
      await page.evaluate(({ locale, catalog }) => {
        snapshot.locale = locale;
        snapshot.labels = catalog[locale];
        snapshot.status = catalog[locale]['组网已连接'];
        return update();
      }, { locale, catalog });
      assert.equal(await page.locator('html').getAttribute('lang'), locale);
      assert.equal(await page.locator('[data-action="open"] > span').first().innerText(), catalog[locale]['打开主窗口']);
      const overflow = await page.evaluate(() => [...document.querySelectorAll('.row, .header, .statusline, .copy')]
        .filter(el => el.scrollWidth > el.clientWidth || el.getBoundingClientRect().right > innerWidth).map(el => el.className));
      assert.deepEqual(overflow, [], locale);
      assert.ok(await page.evaluate(() => document.documentElement.scrollHeight <= 340), locale);
      for (const key of ['正在检查连接…', '后台服务不可用', '组网状态暂不可用', '组网已暂停', '组网未开启', '组网连接中']) {
        await page.evaluate(key => {
          snapshot.status = snapshot.labels[key]; snapshot.ip = ''; snapshot.online = null;
          return update();
        }, key);
        assert.ok(await page.evaluate(() => document.documentElement.scrollHeight <= 340), locale + ': ' + key);
        assert.equal(await page.locator('#peers').innerText(), catalog[locale]['状态待确认']);
      }
      await page.evaluate(() => { snapshot.status = snapshot.labels['组网已连接']; snapshot.ip = '100.64.0.36'; snapshot.online = 3; return update(); });
      console.log('Layout OK:', locale);
      if (process.env.TRAY_SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.TRAY_SCREENSHOT_DIR, locale + '.png') });
    }
    if (process.env.TRAY_SCREENSHOT) await page.screenshot({ path: process.env.TRAY_SCREENSHOT });
    for (const status of ['Service unavailable', 'Mesh status unavailable', 'Connecting…']) {
      await page.evaluate(status => { snapshot.status = status; snapshot.ip = ''; snapshot.online = null; snapshot.files = false; return update(); }, status);
      assert.ok(await page.locator('#copy').isDisabled());
      assert.ok(await page.locator('#files').isDisabled());
      assert.equal(await page.locator('#peers').innerText(), 'Unknown');
    }
    // Exercise the real injected bridge against a fake daemon origin, including
    // startup rejection, live switching, and non-daemon navigation.
    const bridge = await browser.newPage();
    await bridge.route('http://127.0.0.1:7400/**', r => r.fulfill({ body: '<html lang="en"><body></body></html>', contentType: 'text/html' }));
    await bridge.addInitScript(() => {
      window.calls = [];
      let first = true;
      window.__TAURI_INTERNALS__ = { invoke: async (cmd, args) => {
        if (first) { first = false; throw Error('Tray not ready'); }
        window.calls.push({ cmd, ...args });
      }};
    });
    await bridge.addInitScript({ path: path.join(root, 'shell/tray-language.js') });
    await bridge.goto('http://127.0.0.1:7400/');
    await bridge.waitForFunction(() => calls.some(c => c.locale === 'en'));
    for (const code of codes) {
      await bridge.evaluate(code => { document.documentElement.lang = code; }, code);
      await bridge.waitForFunction(code => calls.some(c => c.locale === code), code);
    }
    assert.ok((await bridge.evaluate(() => calls)).every(c => c.cmd === 'tray_set_locale'));
    await bridge.goto('about:blank');
    await bridge.waitForTimeout(1100);
    assert.deepEqual(await bridge.evaluate(() => calls), []);
    assert.deepEqual(errors, []);
    console.log('PASS: 10-language switching, compact layout, copy feedback, unavailable states, bridge retry and origin guard.');
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
