import { chromium, request } from 'playwright';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const timeline = JSON.parse(await readFile(path.join(root, 'src', 'timeline.json'), 'utf8'));
const baseUrl = (process.env.DEMO_BASE_URL || 'https://localhost:9999').replace(/\/$/, '');
const architectureConnectivityIcon = `data:image/svg+xml;base64,${(await readFile(path.join(root, '..', 'app-instance', 'app-src', 'static', 'azure-icons', 'expressroute-circuits.svg'))).toString('base64')}`;
const rehearsal = process.argv.includes('--rehearsal');
const record = process.argv.includes('--record');
if (rehearsal === record) throw new Error('Specify exactly one of --rehearsal or --record.');

const outputDir = path.join(root, 'output');
const screenshotDir = path.join(outputDir, 'screenshots');
await mkdir(screenshotDir, { recursive: true });

const report = {
  mode: rehearsal ? 'rehearsal' : 'record',
  baseUrl,
  startedAt: new Date().toISOString(),
  durationSeconds: timeline.durationSeconds,
  preflight: [],
  actions: [],
  passed: false,
};

const api = await request.newContext({ baseURL: baseUrl, ignoreHTTPSErrors: true });
for (const endpoint of ['/health', '/db/status', '/api/citizenhelp/model', '/media/status', '/security/evidence']) {
  const response = await api.get(endpoint, { timeout: 30_000 });
  report.preflight.push({ endpoint, status: response.status(), ok: response.ok() });
  if (!response.ok()) throw new Error(`Preflight failed for ${endpoint}: HTTP ${response.status()}`);
}
await api.dispose();

const browser = await chromium.launch({ headless: true });
const contextOptions = {
  viewport: timeline.viewport,
  ignoreHTTPSErrors: true,
  colorScheme: 'dark',
  reducedMotion: 'no-preference',
};
if (record) contextOptions.recordVideo = { dir: path.join(outputDir, 'raw'), size: timeline.viewport };
const context = await browser.newContext(contextOptions);
await context.addInitScript(() => localStorage.setItem('citizen-registry-theme', 'dark'));
const page = await context.newPage();
const video = page.video();

page.on('pageerror', error => report.actions.push({ handler: 'pageerror', ok: false, error: error.message }));
page.on('console', message => {
  if (message.type() === 'error') report.actions.push({ handler: 'console', ok: false, error: message.text() });
});

async function installPointer() {
  await page.evaluate(() => {
    if (document.getElementById('demo-pointer')) return;
    const style = document.createElement('style');
    style.textContent = '#demo-pointer{position:fixed;left:0;top:0;width:24px;height:24px;border:3px solid #f0b429;border-radius:50%;background:rgba(240,180,41,.22);box-shadow:0 0 0 5px rgba(15,118,110,.22);z-index:2147483647;pointer-events:none;transform:translate(-50%,-50%);transition:left .28s ease,top .28s ease,transform .12s ease}#demo-pointer.demo-click{transform:translate(-50%,-50%) scale(.62)}';
    document.head.appendChild(style);
    const pointer = document.createElement('div');
    pointer.id = 'demo-pointer';
    document.body.appendChild(pointer);
  });
}

async function goto(route) {
  await page.goto(`${baseUrl}${route}`, { waitUntil: 'domcontentloaded', timeout: 45_000 });
  await installPointer();
  await page.waitForFunction(() => document.fonts?.status === 'loaded', null, { timeout: 15_000 });
}

async function click(selector) {
  const target = page.locator(selector).filter({ visible: true }).first();
  await target.scrollIntoViewIfNeeded();
  const box = await target.boundingBox();
  if (!box) throw new Error(`Visible target has no bounding box: ${selector}`);
  const x = box.x + box.width / 2;
  const y = box.y + box.height / 2;
  await page.evaluate(({ x, y }) => {
    const pointer = document.getElementById('demo-pointer');
    pointer.style.left = `${x}px`;
    pointer.style.top = `${y}px`;
  }, { x, y });
  await page.waitForTimeout(rehearsal ? 20 : 350);
  await target.click();
  await page.evaluate(() => {
    const pointer = document.getElementById('demo-pointer');
    if (!pointer) return;
    pointer.classList.add('demo-click');
    setTimeout(() => pointer.classList.remove('demo-click'), 180);
  });
}

async function waitForImage(selector) {
  await page.locator(selector).waitFor({ state: 'visible', timeout: 30_000 });
  await page.waitForFunction(imageSelector => {
    const image = document.querySelector(imageSelector);
    return image?.complete && image.naturalWidth > 0 && image.naturalHeight > 0;
  }, selector, { timeout: 30_000 });
}

async function ask(questionText) {
  const assistantsBefore = await page.locator('.message.assistant').count();
  await page.locator('#question').fill(questionText);
  await click('#ask');
  await page.waitForFunction(count => {
    const complete = document.querySelector('#status')?.textContent === 'Complete';
    return complete && document.querySelectorAll('.message.assistant').length > count;
  }, assistantsBefore, { timeout: 210_000 });
}

async function applyArchitectureRecordingOverride() {
  await page.evaluate(icon => {
    const root = document.querySelector('[data-architecture-diagram]');
    if (!root) throw new Error('Architecture diagram is unavailable.');
    const connectivity = root.querySelector('[data-architecture-node="connectivity"], [data-architecture-node="bastion"]');
    if (!connectivity) throw new Error('Architecture connectivity node is unavailable.');
    connectivity.dataset.architectureNode = 'connectivity';
    connectivity.querySelector('image')?.setAttribute('href', icon);
    const title = connectivity.querySelector('.architecture-node-title');
    const detail = connectivity.querySelector('.architecture-node-detail');
    if (title) title.textContent = 'ExpressRoute / VPN';
    if (detail) detail.textContent = 'Private connectivity';

    const browserPath = root.querySelector('[data-connection="browser-connectivity"], [data-connection="browser-bastion"]');
    const appPath = root.querySelector('[data-connection="connectivity-app"], [data-connection="bastion-app"]');
    if (browserPath) browserPath.dataset.connection = 'browser-connectivity';
    if (appPath) appPath.dataset.connection = 'connectivity-app';

    for (const label of root.querySelectorAll('.architecture-connection-labels text')) {
      if (label.textContent.trim() === 'HTTPS tunnel') label.textContent = 'Customer network';
      if (label.textContent.trim() === 'mTLS') label.textContent = 'Private IP · mTLS';
    }
    const description = root.querySelector('#architecture-description');
    if (description) description.textContent = 'An end-user browser reaches an Application Confidential VM through private ExpressRoute or site-to-site VPN connectivity and mutual TLS. The application communicates with a separate SQL Confidential VM over private VNet peering and TLS, with an NVIDIA H100 local to the application.';
  }, architectureConnectivityIcon);
}

const handlers = {
  async openingArchitecture() {
    await goto('/architecture');
    await applyArchitectureRecordingOverride();
    const diagram = page.locator('[data-architecture-diagram]');
    await diagram.waitFor({ state: 'visible' });
    await page.waitForFunction(async () => {
      const images = [...document.querySelectorAll('.architecture-svg image')];
      if (!images.length || images.some(image => image.getBoundingClientRect().width === 0)) return false;
      const results = await Promise.all(images.map(image => fetch(image.href.baseVal).then(response => response.ok).catch(() => false)));
      return results.every(Boolean);
    }, null, { timeout: 30_000 });
    const architectureCheck = await diagram.evaluate(root => {
      const requiredNodes = ['browser', 'connectivity', 'app', 'gpu', 'database', 'attestation', 'hsm', 'policy'];
      const requiredConnections = ['browser-connectivity', 'connectivity-app', 'app-gpu-local', 'app-database', 'app-attestation', 'app-hsm-private-link', 'database-hsm-private-link'];
      const text = root.textContent || '';
      return {
        nodes: requiredNodes.every(name => root.querySelector(`[data-architecture-node="${name}"]`)),
        connections: requiredConnections.every(name => root.querySelector(`[data-connection="${name}"]`)),
        privateConnectivity: text.includes('ExpressRoute / VPN') && text.includes('Private connectivity') && !text.includes('Azure Bastion'),
        policyCapability: text.includes('NOT ASSIGNED BY THIS SAMPLE') && text.includes('Allowed locations'),
        legible: root.getBoundingClientRect().width > 900 && root.getBoundingClientRect().height > 500,
      };
    });
    if (!Object.values(architectureCheck).every(Boolean)) {
      throw new Error(`Architecture overview is incomplete: ${JSON.stringify(architectureCheck)}`);
    }
  },
  async opening() {
    await goto('/citizens');
    await page.locator('header h1').waitFor({ state: 'visible' });
    await page.locator('.security-info').scrollIntoViewIfNeeded();
    await page.waitForFunction(() => !document.querySelector('#cpu-attestation-label')?.textContent.includes('CHECKING'), null, { timeout: 30_000 });
  },
  async showRegistry() {
    await page.locator('.citizens-section').scrollIntoViewIfNeeded();
    await page.locator('button.portrait-button[data-citizen-id]').first().waitFor({ state: 'visible' });
  },
  async openPassport() {
    await click('button.portrait-button[data-citizen-id]');
    await page.locator('#credential-dialog[open]').waitFor({ state: 'visible' });
    await waitForImage('#credential-image');
    const title = await page.locator('#credential-title').textContent();
    if (!title?.includes('fictional credential')) throw new Error('Credential dialog is not clearly marked fictional.');
  },
  async closePassport() {
    await click('#close-credential');
    await page.locator('#credential-dialog').waitFor({ state: 'hidden' });
  },
  async openHistory() {
    await click('button.history-citizen');
    await page.locator('#history-dialog[open]').waitFor({ state: 'visible' });
    await page.locator('#employment-history tr').first().waitFor({ state: 'visible', timeout: 30_000 });
  },
  async closeHistory() {
    await click('#close-history');
  },
  async openSecurityEvidence() {
    await goto('/citizens');
    await click('label[for="cpu-attestation-toggle"]');
    await page.locator('#cpu-attestation-evidence').scrollIntoViewIfNeeded();
  },
  async showGpuEvidence() {
    await click('label[for="gpu-attestation-toggle"]');
    await page.locator('#gpu-attestation-evidence').scrollIntoViewIfNeeded();
  },
  async showEncryptionEvidence() {
    await click('label[for="encryption-toggle"]');
    await page.locator('#encryption-evidence').scrollIntoViewIfNeeded();
  },
  async openCitizenHelp() {
    await goto('/citizenhelp');
    await page.locator('#status').filter({ hasText: 'Ready' }).waitFor({ state: 'visible' });
  },
  async askAverageAge() {
    await ask('What is the average age of all citizens?');
  },
  async askSalaryBands() {
    await ask('Calculate the average salary by age band and gender.');
  },
  async showBoundary() {
    const diagram = page.locator('[data-infrastructure-diagram]');
    await diagram.scrollIntoViewIfNeeded();
    const pathCheck = await diagram.evaluate(root => {
      root.infrastructureDiagram.setState('response');
      return {
        gpuApp: root.querySelector('[data-path="gpu-app"]')?.classList.contains('is-active') === true,
        appBrowser: root.querySelector('[data-path="app-browser"]')?.classList.contains('is-active') === true,
        appActive: root.querySelector('[data-node="app"]')?.classList.contains('is-active') === true,
        directPathPresent: root.querySelector('[data-path="gpu-browser"], [data-path="gpu-browser-cctv"]') !== null,
      };
    });
    if (!pathCheck.gpuApp || !pathCheck.appBrowser || !pathCheck.appActive || pathCheck.directPathPresent) {
      throw new Error(`Infrastructure response path is invalid: ${JSON.stringify(pathCheck)}`);
    }
    await click('[data-diagram-replay]');
  },
  async closingFrame() {
    await page.locator('main h1').scrollIntoViewIfNeeded();
  },
};

const start = performance.now();
let failed = null;
try {
  for (const action of timeline.actions) {
    if (record) {
      const waitMilliseconds = action.at * 1000 - (performance.now() - start);
      if (waitMilliseconds > 0) await page.waitForTimeout(waitMilliseconds);
      const lateness = (performance.now() - start) / 1000 - action.at;
      if (lateness > 2) throw new Error(`${action.handler} missed its cue by ${lateness.toFixed(2)} seconds.`);
    }
    const actionStart = performance.now();
    await handlers[action.handler]();
    const entry = { handler: action.handler, scheduledAt: action.at, elapsedSeconds: Number(((performance.now() - start) / 1000).toFixed(3)), durationSeconds: Number(((performance.now() - actionStart) / 1000).toFixed(3)), ok: true };
    report.actions.push(entry);
    if (action.checkpoint) await page.screenshot({ path: path.join(screenshotDir, `${action.checkpoint}.png`), fullPage: false });
  }
  if (record) {
    const remaining = timeline.durationSeconds * 1000 - (performance.now() - start);
    if (remaining < 0) throw new Error(`Recording exceeded ${timeline.durationSeconds} seconds.`);
    await page.waitForTimeout(remaining);
  }
  report.passed = true;
} catch (error) {
  failed = error;
  report.error = error.message;
  await page.screenshot({ path: path.join(screenshotDir, 'failure.png'), fullPage: false }).catch(() => {});
} finally {
  report.finishedAt = new Date().toISOString();
  await context.close();
  if (record && video) await copyFile(await video.path(), path.join(outputDir, 'browser.webm'));
  await browser.close();
  await writeFile(path.join(outputDir, 'run-manifest.json'), `${JSON.stringify(report, null, 2)}\n`);
}

if (failed) throw failed;
console.log(`${rehearsal ? 'Rehearsal' : 'Recording'} passed with ${report.actions.length} actions.`);