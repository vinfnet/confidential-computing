import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { pathToFileURL, fileURLToPath } from 'node:url';
import path from 'node:path';

// Opt in with an existing Playwright module; no browser dependency is installed by this sample.
// PowerShell, from the sample root when Playwright is resolvable:
// $env:UI_PLAYWRIGHT_MODULE = node --input-type=module -e "import { fileURLToPath } from 'node:url'; console.log(fileURLToPath(import.meta.resolve('playwright')))"
// npm run test:browser
// Alternatively set UI_PLAYWRIGHT_MODULE to an absolute module-entry path.
// Optional UI_CHROMIUM_PATH selects an existing Chromium executable; otherwise
// Playwright uses its installed browser. UI_SCREENSHOT_DIR saves project-relative screenshots.
// No module configured is an explicit skip; invalid paths or missing browsers fail.
test('production UI: real browser motion gating, keyboard controls, responsive themes and original logos', {
  skip: !process.env.UI_PLAYWRIGHT_MODULE && 'Set UI_PLAYWRIGHT_MODULE to an existing Playwright module entry point'
}, async () => {
  const { chromium } = await import(pathToFileURL(process.env.UI_PLAYWRIGHT_MODULE).href);
  const root = new URL('../', import.meta.url);
  const model = { authenticated: false, state: 'unavailable', fail: false, leaseMs: 12000 };
  const servers = [];
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.UI_CHROMIUM_PATH ? { executablePath: process.env.UI_CHROMIUM_PATH } : {})
  });
  const start = async (kind) => {
    const server = createServer(async (req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'");
      if (req.url.startsWith('/api/')) {
        res.setHeader('Content-Type', 'application/json');
        if (req.url === '/api/logout') model.authenticated = false;
        if (req.url === '/api/commands' && model.fail) {
          res.writeHead(503).end('{"error":"fixture_unavailable"}');
          return;
        }
        const responses = {
          '/api/session': { authenticated: kind === 'worker' && model.authenticated, user: 'fixture.operator' },
          '/api/config': { workerUrl: '' },
          '/api/health': { ready: false },
          '/api/logout': { authenticated: false },
          '/api/ciphertext': { state: model.state, envelope: { ciphertext: 'deterministic-fixture-ciphertext' } },
          '/api/commands': { state: model.state, plaintext: 'Fictional Tailspin design\n<img src=x onerror=alert(1)>', expiresAt: Date.now() + model.leaseMs }
        };
        res.end(JSON.stringify(responses[req.url] || { error: 'unknown_fixture_endpoint' }));
        return;
      }
      const routes = {
        '/': `${kind}/public/index.html`,
        '/app.js': 'worker/public/app.js',
        '/style.css': 'worker/public/style.css',
        '/dashboard.js': 'tailspin/public/dashboard.js',
        '/session.js': 'tailspin/public/session.js',
        '/styles.css': 'tailspin/public/styles.css',
        '/ui/preferences.js': 'ui/public/preferences.js',
        '/ui/preferences.css': 'ui/public/preferences.css'
      };
      const file = routes[req.url];
      if (!file) { res.writeHead(404).end(); return; }
      try {
        const content = await readFile(new URL(file, root));
        res.setHeader('Content-Type', file.endsWith('.html') ? 'text/html' : file.endsWith('.css') ? 'text/css' : 'text/javascript');
        res.end(content);
      } catch { res.writeHead(500).end(); }
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    servers.push(server);
    return `http://127.0.0.1:${server.address().port}`;
  };
  let screenshotDirectory;
  if (process.env.UI_SCREENSHOT_DIR) {
    screenshotDirectory = path.resolve(fileURLToPath(root), process.env.UI_SCREENSHOT_DIR);
    assert.ok(screenshotDirectory.startsWith(fileURLToPath(root)), 'screenshots stay inside the project');
    await mkdir(screenshotDirectory, { recursive: true });
  }
  const screenshot = async (page, name) => {
    if (screenshotDirectory) await page.screenshot({ path: path.join(screenshotDirectory, `${name}.png`), fullPage: true });
  };
  try {
    const [workerUrl, tailspinUrl] = await Promise.all([start('worker'), start('tailspin')]);
    const page = await browser.newPage({ viewport: { width: 1280, height: 700 }, colorScheme: 'light', reducedMotion: 'no-preference' });
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const motion = () => page.locator('#production-scene').getAttribute('data-motion');
    const waitForMotion = (value) => page.waitForFunction((wanted) =>
      document.getElementById('production-scene').dataset.motion === wanted, value);
    await page.goto(workerUrl);
    await waitForMotion('locked');
    const sceneBox = await page.locator('#production-scene').boundingBox();
    assert.ok(sceneBox.height >= 250 && sceneBox.height <= 320, `desktop scene stays capture-friendly (${sceneBox.height}px)`);
    assert.equal(await page.locator('#scene-toggle').isDisabled(), true);
    await screenshot(page, 'worker-locked-light');
    model.authenticated = true;
    model.state = 'protected';
    await waitForMotion('running');
    const protectedSceneBox = await page.locator('#production-scene').boundingBox();
    assert.ok(protectedSceneBox.height >= 250 && protectedSceneBox.height <= 320, `protected desktop scene stays capture-friendly (${protectedSceneBox.height}px)`);
    assert.equal(await page.locator('#commands img').count(), 0, 'commands are not interpreted as markup');
    assert.match(await page.locator('#commands').textContent(), /<img/);
    const animations = await page.locator('.robot-arm').first().evaluate((element) => element.getAnimations().map((animation) => animation.playState));
    assert.deepEqual(animations, ['running']);
    await page.locator('#scene-toggle').focus();
    await page.keyboard.press('Space');
    assert.equal(await motion(), 'paused');
    await page.waitForTimeout(2100);
    assert.equal(await motion(), 'paused');
    await page.keyboard.press('Enter');
    assert.equal(await motion(), 'running');
    await page.locator('#production-scene').scrollIntoViewIfNeeded();
    await screenshot(page, 'worker-protected-light');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await waitForMotion('paused');
    assert.equal(await page.locator('#scene-toggle').isDisabled(), true);
    assert.equal(await page.locator('.robot-arm').first().evaluate((element) => element.getAnimations().length), 0);
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await waitForMotion('running');
    model.state = 'unavailable';
    await waitForMotion('locked');
    assert.equal(await page.locator('#scene-job').textContent(), 'No authorized design in view');
    model.state = 'protected';
    await waitForMotion('running');
    model.fail = true;
    await waitForMotion('locked');
    model.fail = false;
    model.leaseMs = 700;
    await waitForMotion('running');
    await waitForMotion('locked');
    model.leaseMs = 12000;
    await waitForMotion('running');
    await page.locator('#logout').click();
    await waitForMotion('locked');
    assert.doesNotMatch(await page.locator('#commands').textContent(), /Fictional Tailspin design/);
    for (const [kind, url] of [['worker', workerUrl], ['tailspin', tailspinUrl]]) {
      await page.goto(url);
      await page.locator('.brand-art:visible').first().waitFor({ state: 'visible' });
      for (const theme of ['light', 'dark']) {
        await page.evaluate((value) => document.documentElement.dataset.theme = value, theme);
        for (const [width, height] of [[1440, 1100], [390, 844]]) {
          await page.setViewportSize({ width, height });
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${kind} ${theme} width ${width} has no horizontal overflow`);
          await screenshot(page, `${kind}-${theme}-${width}`);
        }
      }
    }
    assert.deepEqual(errors, [], 'both pages execute without browser errors under a strict CSP');
  } finally {
    await browser.close();
    await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  }
});
