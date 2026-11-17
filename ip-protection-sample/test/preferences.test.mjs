import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { X509Certificate } from 'node:crypto';
import vm from 'node:vm';
import { installDemoUi } from '../ui/server.mjs';
import { ephemeralTls } from '../tailspin/src/server.js';

const require = createRequire(new URL('../tailspin/package.json', import.meta.url));
const express = require('express');
const source = await readFile(new URL('../ui/public/preferences.js', import.meta.url), 'utf8');

function browser({ saved = null, dark = false, storageBlocked = false, certificateStatus = 200 } = {}) {
  const elements = new Map();
  const warnings = [];
  const requests = [];
  let ready;
  let systemChange;
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', attributes: {}, handlers: {},
      setAttribute(name, value) { this.attributes[name] = value; },
      addEventListener(name, callback) { this.handlers[name] = callback; },
      showModal() { this.open = true; }
    });
    return elements.get(id);
  };
  const system = { matches: dark, addEventListener(_name, callback) { systemChange = callback; } };
  const root = { dataset: {} };
  vm.runInNewContext(source, {
    document: {
      documentElement: root, getElementById: element, querySelector: () => element('meta'),
      addEventListener(_name, callback) { ready = callback; },
      createElement: () => element('certificate-dialog'), body: { append() {} }
    },
    matchMedia: () => system,
    localStorage: {
      getItem() { if (storageBlocked) throw new Error('Storage disabled'); return saved; },
      setItem(_key, value) { if (storageBlocked) throw new Error('Storage disabled'); saved = value; }
    },
    console: { warn: (...args) => warnings.push(args) },
    fetch: async (url) => {
      requests.push(url);
      return {
        ok: certificateStatus === 200, status: certificateStatus,
        json: async () => ({ subject: 'CN=Test public CA', fingerprint256: 'AA:BB', validFrom: 'today', validTo: 'tomorrow' })
      };
    }
  });
  assert.equal(root.dataset.theme, saved === 'light' || saved === 'dark' ? saved : dark ? 'dark' : 'light');
  ready();
  return {
    element, root, warnings, requests, saved: () => saved,
    systemChange(dark) { system.matches = dark; systemChange(); }
  };
}

test('theme follows OS before selection, then persists an explicit accessible choice', () => {
  const page = browser();
  assert.equal(page.root.dataset.theme, 'light');
  page.systemChange(true);
  assert.equal(page.root.dataset.theme, 'dark');
  assert.equal(page.element('theme-toggle').attributes['aria-pressed'], 'true');
  page.element('theme-toggle').handlers.click();
  assert.equal(page.root.dataset.theme, 'light');
  assert.equal(page.saved(), 'light');
  assert.equal(page.element('theme-toggle').attributes['aria-label'], 'Switch to dark mode');
  page.systemChange(true);
  assert.equal(page.root.dataset.theme, 'light');
  assert.equal(browser({ saved: page.saved(), dark: true }).root.dataset.theme, 'light');
});

test('stored dark preference overrides a light system and invalid values are ignored', () => {
  assert.equal(browser({ saved: 'dark' }).root.dataset.theme, 'dark');
  assert.equal(browser({ saved: 'invalid' }).root.dataset.theme, 'light');
});

test('blocked storage does not break controls and failure is visible', () => {
  const page = browser({ storageBlocked: true });
  page.element('theme-toggle').handlers.click();
  assert.equal(page.root.dataset.theme, 'dark');
  assert.match(page.element('appearance-status').textContent, /could not save/);
  assert.equal(page.warnings.length, 2);
});

test('certificate button opens manual import guidance and shows public fingerprint only', async () => {
  const page = browser();
  assert.deepEqual(page.requests, []);
  await page.element('certificate-help').handlers.click();
  assert.equal(page.element('certificate-dialog').open, true);
  assert.match(page.element('certificate-dialog').innerHTML, /cannot install trusted certificates automatically/);
  assert.match(page.element('certificate-dialog').innerHTML, /href="\/demo-ca.crt"/);
  assert.match(page.element('certificate-dialog').innerHTML, /button cannot help yet/);
  assert.match(page.element('certificate-info').textContent, /SHA-256: AA:BB/);
  assert.deepEqual(page.requests, ['/ui/certificate.json']);
});

test('certificate metadata failures are visible and never presented as successful import', async () => {
  const page = browser({ certificateStatus: 503 });
  await page.element('certificate-help').handlers.click();
  assert.match(page.element('certificate-info').textContent, /could not be loaded \(HTTP 503\)/);
});

test('public UI routes serve only the selected public certificate and matching metadata', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'tailspin-public-ca-'));
  t.after(() => rm(directory, { recursive: true }));
  const tls = await ephemeralTls({ tailspinUrl: 'https://localhost' });
  const certificatePath = path.join(directory, 'ca.crt');
  await writeFile(certificatePath, tls.cert);
  const app = express();
  installDemoUi(app, { certificatePath });
  app.use((_error, _req, res, _next) => res.status(503).json({ error: 'certificate_unavailable' }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const certificate = await fetch(`${base}/demo-ca.crt`);
  assert.equal(certificate.status, 200);
  assert.match(certificate.headers.get('content-disposition'), /^attachment; filename="?tailspin-demo-ca\.crt"?$/);
  assert.equal(await certificate.text(), tls.cert.toString());
  const metadata = await fetch(`${base}/ui/certificate.json`).then(r => r.json());
  assert.equal(metadata.fingerprint256, new X509Certificate(tls.cert).fingerprint256);
  assert.deepEqual(Object.keys(metadata).sort(), ['fingerprint256', 'subject', 'validFrom', 'validTo']);
  for (const asset of ['preferences.js', 'preferences.css']) {
    assert.equal((await fetch(`${base}/ui/${asset}`)).status, 200);
  }
  assert.equal((await fetch(`${base}/ui/../ca.key`)).status, 404);
  await rm(certificatePath);
  assert.equal((await fetch(`${base}/ui/certificate.json`)).status, 503);
});

test('both pages include shared pre-paint theme script and signed-out certificate control', async () => {
  for (const app of ['tailspin', 'worker']) {
    const html = await readFile(new URL(`../${app}/public/index.html`, import.meta.url), 'utf8');
    assert.match(html, /id="theme-toggle"/);
    assert.match(html, /id="certificate-help"[^>]*aria-haspopup="dialog"/);
    assert.ok(html.indexOf('src="/ui/preferences.js"') < html.indexOf('rel="stylesheet"'));
    assert.match(html, /href="\/ui\/preferences.css"/);
  }
});
