import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../worker/public/app.js', import.meta.url), 'utf8');
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('company identities are original inline marks with explicit hosting and IP ownership roles', async () => {
  const [worker, tailspin, workerCss, tailspinCss] = await Promise.all([
    readFile(new URL('../worker/public/index.html', import.meta.url), 'utf8'),
    readFile(new URL('../tailspin/public/index.html', import.meta.url), 'utf8'),
    readFile(new URL('../worker/public/style.css', import.meta.url), 'utf8'),
    readFile(new URL('../tailspin/public/styles.css', import.meta.url), 'utf8')
  ]);
  for (const html of [worker, tailspin]) {
    assert.match(html, /Hosted by Contoso/);
    assert.match(html, /IP owned by Tailspin Toys/);
    assert.match(html, /<svg[^>]*role="img"[^>]*aria-label="Tailspin Toys pinwheel mark"/);
    assert.doesNotMatch(html, /<img[^>]*src="https?:/);
    const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
    assert.equal(new Set(ids).size, ids.length, 'branding must not introduce duplicate DOM IDs');
  }
  assert.match(worker, /<svg[^>]*role="img"[^>]*aria-label="Contoso industrial mark"/);
  assert.match(worker, /TAILSPIN-AUTHORIZED VIEW/);
  assert.match(worker, /not a host-operator right/);
  assert.match(worker, /Hosting the worker does not authorize Contoso operators to view plaintext/);
  assert.match(worker, /Confidential computing protects data inside the enclave, not data deliberately displayed to an authorized browser/);
  assert.match(tailspin, /class="mobile-brand"[^]*Tailspin Toys/);
  assert.match(workerCss, /--accent:#096574/);
  assert.match(workerCss, /data-theme="dark"[^]*--accent:#77d8df/);
  assert.match(tailspinCss, /--ts-accent:#7040b1/);
  assert.match(tailspinCss, /data-theme="dark"[^]*--ts-accent:#d0adff/);
  assert.match(tailspinCss, /html \.topbar>\.mobile-brand\{display:flex/);
  for (const [name, label] of [['tailspin', 'Tailspin Toys pinwheel mark'], ['contoso', 'Contoso industrial mark']]) {
    const artwork = (await readFile(new URL(`../docs/images/${name}-logo.svg`, import.meta.url), 'utf8')).trim();
    for (const html of [worker, tailspin]) {
      const logos = [...html.matchAll(/<svg\b[^]*?<\/svg>/g)].map(([svg]) => svg).filter((svg) => svg.includes(`aria-label="${label}"`));
      assert.ok(logos.length, `Live ${name} artwork is present`);
      for (const svg of logos) assert.equal(svg, artwork, `Live ${name} logo and documentation artwork must be exact copies`);
    }
  }
  assert.match(worker, /Contoso owns and operates the robots, 3D printers and manufacturing infrastructure/);
  assert.match(tailspin, /Contoso owns and operates the manufacturing infrastructure, robots and 3D printers/);
  assert.match(worker, /Fictional manufacturing animation · not live machinery/);
  assert.match(workerCss, /prefers-reduced-motion:reduce/);
  assert.match(workerCss, /data-motion="running"[^]*animation-play-state:running/);
});

test('company palettes keep normal text, brand labels and buttons at WCAG AA contrast in both themes', async () => {
  const luminance = (hex) => {
    const digits = hex.length === 4 ? [...hex.slice(1)].map((c) => c + c).join('') : hex.slice(1);
    return digits.match(/../g).reduce((sum, channel, index) => {
      const value = Number.parseInt(channel, 16) / 255;
      return sum + (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4) * [0.2126, 0.7152, 0.0722][index];
    }, 0);
  };
  for (const [file, prefix, pairs] of [
    ['worker/public/style.css', '', [['text', 'page'], ['muted', 'surface'], ['accent', 'surface'], ['owner', 'owner-surface'], ['brand-button', 'surface']]],
    ['tailspin/public/styles.css', 'ts-', [['text', 'page'], ['muted', 'surface'], ['accent', 'surface'], ['accent', 'tint']]]
  ]) {
    const css = await readFile(new URL(`../${file}`, import.meta.url), 'utf8');
    const palettes = [...css.matchAll(/\{([^{}]*--(?:ts-)?page:#[^{}]+)\}/g)];
    assert.equal(palettes.length, 2, `${file} defines light and dark palettes`);
    for (const [index, palette] of palettes.entries()) {
      const colors = Object.fromEntries([...palette[1].matchAll(/--([\w-]+):(#[\da-f]+)/gi)].map((match) => [match[1], match[2]]));
      for (const [foreground, background] of pairs) {
        const values = [foreground, background].map((key) => luminance(colors[prefix + key]));
        const contrast = (Math.max(...values) + 0.05) / (Math.min(...values) + 0.05);
        assert.ok(contrast >= 4.5, `${file} theme ${index}: ${foreground}/${background} = ${contrast.toFixed(2)}`);
      }
    }
    assert.match(css, /html:root:root\{[^}]*--ui-accent:var\(/, 'brand tokens override shared controls in both themes');
  }
});

function browser() {
  const elements = new Map();
  const requests = [];
  let interval;
  let scroll;
  let time = Date.now();
  const timers = new Map();
  const listeners = new Map();
  let motionChange;
  const motion = { matches: false, addEventListener(_name, callback) { motionChange = callback; } };
  class BrowserDate extends Date { static now() { return time; } }
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', value: '', hidden: false, scrollTop: 0, scrollHeight: 1200, clientHeight: 450,
      dataset: {}, attributes: {}, setAttribute(name, value) { this.attributes[name] = value; },
      paused: false, matches() { return this.paused; }
    });
    return elements.get(id);
  };
  const document = { hidden: false, getElementById: element, addEventListener(name, callback) { listeners.set(name, callback); } };
  vm.runInNewContext(source, {
    document,
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
    setInterval: (callback, delay) => { if (delay === 2000) interval = callback; else scroll = callback; },
    matchMedia: () => motion,
    setTimeout: (callback, delay) => { const token = {}; timers.set(token, { callback, at: time + delay }); return token; },
    clearTimeout: (token) => timers.delete(token), Date: BrowserDate
  });
  const respond = (url, data, status = 200) => {
    const request = requests.find((entry) => entry.url === url && !entry.done);
    assert.ok(request, `Pending ${url}`);
    request.done = true;
    request.resolve({ ok: status < 400, status, json: async () => data });
  };
  const refresh = () => interval();
  return {
    element, requests, respond, refresh, scroll: () => scroll(), motion,
    setMotion: (value) => { motion.matches = value; motionChange(); },
    setHidden: (value) => { document.hidden = value; listeners.get('visibilitychange')(); },
    reject: (url) => {
      const request = requests.find((entry) => entry.url === url && !entry.done);
      assert.ok(request, `Pending ${url}`);
      request.done = true;
      request.reject(new Error('Network failed'));
    },
    advance: (ms) => {
      time += ms;
      for (const [token, timer] of timers) {
        if (timer.at <= time) { timers.delete(token); timer.callback(); }
      }
    }
  };
}

test('long command panel scrolls, pauses for interaction or reduced motion, and clears on protection loss', async () => {
  const page = browser();
  const plaintext = Array.from({ length: 34 }, (_, index) => `Fictional command ${index + 1}`).join('\n');
  const protectedState = { state: 'protected', envelope: { sequence: 17, ciphertext: 'encrypted' } };
  page.respond('/api/ciphertext', { ...protectedState, envelope: { ...protectedState.envelope, sequence: 18 } });
  page.respond('/api/session', { authenticated: true, user: 'tailspin.operator' });
  await settle();
  page.respond('/api/commands', { state: 'protected', plaintext, expiresAt: Date.now() + 12000 });
  await settle();
  page.advance(1600);
  page.scroll();
  assert.equal(page.element('commands').scrollTop, 3);
  for (const pause of ['interaction', 'motion']) {
    page.element('commands').paused = pause === 'interaction';
    page.motion.matches = pause === 'motion';
    page.scroll();
    assert.equal(page.element('commands').scrollTop, 3);
  }
  page.element('commands').paused = false;
  page.motion.matches = false;
  const refresh = page.refresh();
  page.respond('/api/ciphertext', protectedState);
  page.respond('/api/session', { authenticated: true, user: 'tailspin.operator' });
  await settle();
  page.respond('/api/commands', { state: 'protected', plaintext, expiresAt: Date.now() + 12000 });
  await refresh;
  assert.equal(page.element('commands').scrollTop, 3, 'polling and envelope rotation preserve scroll position');
  page.scroll();
  assert.equal(page.element('commands').scrollTop, 6);
  const locked = page.refresh();
  page.respond('/api/ciphertext', { state: 'locked', envelope: protectedState.envelope });
  page.respond('/api/session', { authenticated: true, user: 'tailspin.operator' });
  await locked;
  assert.doesNotMatch(page.element('commands').textContent, /Fictional command/);
  assert.match(page.element('ciphertext').textContent, /encrypted/);
  page.scroll();
  assert.equal(page.element('commands').scrollTop, 6, 'locked panel does not scroll');
});

for (const logoutStatus of [200, 503]) {
  test(`logout cannot be undone by overlapping session polling (HTTP ${logoutStatus})`, async () => {
    const page = browser();
    page.respond('/api/ciphertext', { state: 'locked', envelope: { ciphertext: 'encrypted' } });
    page.respond('/api/session', { authenticated: true, user: 'tailspin.operator' });
    await settle();
    assert.match(page.element('identity').textContent, /Tailspin operator/);

    const logout = page.element('logout').onclick();
    const refresh = page.refresh();
    page.respond('/api/logout', { authenticated: false, error: 'unavailable' }, logoutStatus);
    await logout;
    page.respond('/api/session', { authenticated: true, user: 'tailspin.operator' });
    page.respond('/api/ciphertext', { state: 'protected', envelope: { ciphertext: 'encrypted' } });
    await refresh;

    assert.equal(page.element('identity').textContent, 'Not signed in');
    assert.equal(page.element('sign-in').hidden, false);
    assert.match(page.element('commands').textContent, /sign-in required/);
    assert.equal(page.requests.filter((entry) => entry.url === '/api/commands').length, 0);
    if (logoutStatus !== 200) assert.match(page.element('error').textContent, /Sign-out failed/);
  });
}

const protectedState = { state: 'protected', envelope: { ciphertext: 'encrypted' } };
async function authorize(page, overrides = {}) {
  page.respond('/api/ciphertext', protectedState);
  page.respond('/api/session', { authenticated: true, user: 'tailspin.operator' });
  await settle();
  page.respond('/api/commands', {
    state: 'protected', plaintext: 'Fictional Tailspin design', expiresAt: Date.now() + 12000, ...overrides
  });
  await settle();
}
function assertLocked(page) {
  assert.equal(page.element('production-scene').dataset.motion, 'locked');
  assert.equal(page.element('scene-toggle').disabled, true);
  assert.equal(page.element('scene-toggle').attributes['aria-pressed'], 'false');
  assert.equal(page.element('scene-job').textContent, 'No authorized design in view');
  assert.doesNotMatch(page.element('commands').textContent, /Fictional Tailspin design/);
}

test('scene gates on protected plaintext, supports manual pause across polls and respects motion preference changes', async () => {
  const page = browser();
  assertLocked(page);
  await authorize(page, { plaintext: '<img src=x onerror=alert(1)>Fictional Tailspin design' });
  assert.equal(page.element('production-scene').dataset.motion, 'running');
  assert.equal(page.element('scene-toggle').textContent, 'Pause animation');
  assert.equal(page.element('scene-toggle').attributes['aria-pressed'], 'true');
  assert.match(page.element('commands').textContent, /^<img/, 'commands remain literal text, never HTML');
  assert.doesNotMatch(page.element('scene-job').textContent, /<img|Fictional Tailspin/);
  page.element('scene-toggle').onclick();
  assert.equal(page.element('production-scene').dataset.motion, 'paused');
  assert.equal(page.element('scene-toggle').textContent, 'Play animation');
  const poll = page.refresh();
  await authorize(page);
  await poll;
  assert.equal(page.element('production-scene').dataset.motion, 'paused', 'polling preserves user pause');
  page.element('scene-toggle').onclick();
  assert.equal(page.element('production-scene').dataset.motion, 'running');
  page.setMotion(true);
  assert.equal(page.element('production-scene').dataset.motion, 'paused');
  assert.equal(page.element('scene-toggle').disabled, true);
  assert.match(page.element('scene-status').textContent, /Reduced motion/);
  page.setMotion(false);
  assert.equal(page.element('production-scene').dataset.motion, 'running');
});

for (const unavailable of [
  { state: 'unavailable' },
  { plaintext: '' },
  { plaintext: '   ' },
  { plaintext: { unexpected: 'object' } },
  { expiresAt: 0 },
  { expiresAt: String(Date.now() + 12000) },
  { expiresAt: null }
]) {
  test(`scene rejects invalid protected payload ${JSON.stringify(unavailable)}`, async () => {
    const page = browser();
    await authorize(page, unavailable);
    assertLocked(page);
  });
}

for (const transition of ['revoked', 'expired lease', 'expired session', 'commands 401', 'commands 503', 'network failure', 'logout']) {
  test(`scene locks and clears design labels on ${transition}`, async () => {
    const page = browser();
    await authorize(page);
    assert.equal(page.element('production-scene').dataset.motion, 'running');
    if (transition === 'expired lease') page.advance(15000);
    else if (transition === 'logout') {
      const logout = page.element('logout').onclick();
      assertLocked(page);
      page.respond('/api/logout', { authenticated: false });
      await logout;
    } else {
      const poll = page.refresh();
      if (transition === 'network failure') {
        page.reject('/api/ciphertext');
        page.respond('/api/session', { authenticated: true });
      } else {
        page.respond('/api/ciphertext', transition === 'revoked' ? { state: 'unavailable', reason: 'Key disabled' } : protectedState);
        page.respond('/api/session', { authenticated: transition !== 'expired session' });
        if (transition.startsWith('commands')) {
          await settle();
          page.respond('/api/commands', { error: 'unavailable' }, Number(transition.slice(-3)));
        }
      }
      await poll;
    }
    assertLocked(page);
  });
}

test('hidden documents clear plaintext and reject in-flight responses, even after becoming visible again', async () => {
  const page = browser();
  await authorize(page);
  const poll = page.refresh();
  page.respond('/api/ciphertext', protectedState);
  page.respond('/api/session', { authenticated: true });
  await settle();
  page.setHidden(true);
  assertLocked(page);
  page.setHidden(false);
  page.respond('/api/commands', { state: 'protected', plaintext: 'Fictional Tailspin design', expiresAt: Date.now() + 12000 });
  await poll;
  assertLocked(page);
  await authorize(page);
  assert.equal(page.element('production-scene').dataset.motion, 'running', 'visibility restore requires a fresh authorized fetch');
});

test('a late successful poll cannot undo a newer locked response', async () => {
  const page = browser();
  page.respond('/api/ciphertext', protectedState);
  page.respond('/api/session', { authenticated: true });
  await settle();
  const next = page.refresh();
  page.respond('/api/ciphertext', { state: 'unavailable' });
  page.respond('/api/session', { authenticated: false });
  await next;
  page.respond('/api/commands', { state: 'protected', plaintext: 'Fictional Tailspin design', expiresAt: Date.now() + 12000 });
  await settle();
  assertLocked(page);
});
