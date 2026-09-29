import { chromium, request } from 'playwright';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const timeline = JSON.parse(await readFile(path.join(root, 'src', 'timeline.json'), 'utf8'));
const baseUrl = (process.env.DEMO_BASE_URL || 'https://localhost:9999').replace(/\/$/, '');
const iconRoot = path.join(root, '..', 'app-instance', 'app-src', 'static', 'azure-icons');
const iconData = async name => `data:image/svg+xml;base64,${(await readFile(path.join(iconRoot, name))).toString('base64')}`;
const architectureIcons = {
  attestation: await iconData('azure-attestation.svg'),
  browser: await iconData('browser.svg'),
  gpu: await iconData('pcie-card.svg'),
  hsm: await iconData('dedicated-hsm.svg'),
  privateLink: await iconData('private-link.svg'),
  storage: await iconData('storage-accounts.svg'),
  vm: await iconData('virtual-machine.svg'),
};
const architectureConnectivityIcon = await iconData('expressroute-circuits.svg');
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
for (const endpoint of ['/health', '/media/status', '/security/evidence', '/cctv/status', '/cctv/technical-details']) {
  const response = await api.get(endpoint, { timeout: 30_000 });
  report.preflight.push({ endpoint, status: response.status(), ok: response.ok() });
  if (!response.ok()) throw new Error(`Preflight failed for ${endpoint}: HTTP ${response.status()}`);
}
const statusResponse = await api.get('/cctv/status', { timeout: 30_000 });
const status = await statusResponse.json();
if (!['processing', 'running', 'completed'].includes(status.state) || status.confidential_gpu?.verified !== true) {
  throw new Error(`CCTV is not backed by a verified confidential GPU: ${JSON.stringify(status)}`);
}
const sourceResponse = await api.get('/cctv/video', { headers: { Range: 'bytes=0-1023' }, timeout: 30_000 });
report.preflight.push({ endpoint: '/cctv/video', status: sourceResponse.status(), ok: sourceResponse.status() === 206 });
if (sourceResponse.status() !== 206 || (await sourceResponse.body()).length !== 1024) {
  throw new Error('CCTV source range preflight failed.');
}
const playlistResponse = await api.get('/cctv/processed/index.m3u8', { timeout: 30_000 });
const playlist = await playlistResponse.text();
report.preflight.push({ endpoint: '/cctv/processed/index.m3u8', status: playlistResponse.status(), ok: playlistResponse.ok() && playlist.startsWith('#EXTM3U') });
if (!playlistResponse.ok() || !playlist.startsWith('#EXTM3U')) throw new Error('Anonymized HLS playlist preflight failed.');
const segment = playlist.split(/\r?\n/).findLast(line => /^segment-\d+\.ts$/.test(line));
if (!segment) throw new Error('Anonymized HLS playlist contains no media segment.');
const segmentResponse = await api.get(`/cctv/processed/${segment}`, { timeout: 30_000 });
report.preflight.push({ endpoint: `/cctv/processed/${segment}`, status: segmentResponse.status(), ok: segmentResponse.ok() });
if (!segmentResponse.ok() || !(await segmentResponse.body()).length) throw new Error('Anonymized HLS segment preflight failed.');
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
let comparisonStart = null;

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

async function showCctvArchitecture(focus = 'all') {
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root{--ink:#eff6ff;--muted:#a8bdd0;--panel:#112536;--line:#3d8bfd;--teal:#2dd4bf;--green:#55d187;--gold:#f5c451;--edge:#315169}
  *{box-sizing:border-box} body{margin:0;min-height:100vh;color:var(--ink);font-family:"Aptos Display","Segoe UI",sans-serif;background-color:#07131d;background-image:linear-gradient(rgba(55,96,124,.12) 1px,transparent 1px),linear-gradient(90deg,rgba(55,96,124,.12) 1px,transparent 1px);background-size:40px 40px;letter-spacing:0}
  main{height:1080px;padding:48px 66px 36px;display:flex;flex-direction:column;gap:26px}.kicker{margin:0;color:#65dacb;font-size:18px;font-weight:700;text-transform:uppercase}.title-row{display:flex;align-items:end;justify-content:space-between;gap:40px}h1{margin:5px 0 0;font-family:Georgia,"Times New Roman",serif;font-size:53px;font-weight:600;letter-spacing:0}.lede{max-width:610px;margin:0;color:var(--muted);font-size:22px;line-height:1.4}
  .diagram{position:relative;flex:1;border:1px solid var(--edge);background:rgba(7,19,29,.92);padding:34px 34px 28px;overflow:hidden}.control-row{display:grid;grid-template-columns:1fr 1fr;gap:28px;width:780px;margin:0 auto 48px}.control{height:130px}.flow-row{display:grid;grid-template-columns:230px 150px 260px 150px 500px 150px 230px;align-items:center;justify-content:center}.node,.control,.tee{border:1px solid var(--edge);background:var(--panel);transition:border-color .3s,box-shadow .3s,opacity .3s}.node,.control{padding:20px;display:flex;align-items:center;gap:16px}.node{height:165px;flex-direction:column;justify-content:center;text-align:center}.node img,.control img{width:62px;height:62px}.node strong,.control strong{font-size:21px}.node span,.control span{display:block;color:var(--muted);font-size:16px;line-height:1.3;margin-top:5px}.camera-mark{position:relative;width:76px;height:48px;border:5px solid #66b5ff;border-radius:5px}.camera-mark:before{content:"";position:absolute;width:22px;height:22px;border:5px solid #66b5ff;border-radius:50%;left:22px;top:8px}.camera-mark:after{content:"";position:absolute;width:18px;height:30px;background:#66b5ff;clip-path:polygon(0 20%,100% 0,100% 100%,0 80%);right:-22px;top:8px}
  .tee{height:255px;padding:18px;border-color:#3d6683}.tee-title{text-align:center;font-size:18px;font-weight:700;color:#9ed3ff;margin-bottom:16px}.tee-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.tee .node{height:175px;background:#0c1c29}.tee .node img{width:58px;height:58px}.arrow{text-align:center;color:var(--muted);font-size:15px;font-weight:600}.arrow .shaft{height:3px;background:var(--line);position:relative;margin-bottom:10px}.arrow .shaft:after{content:"";position:absolute;right:-1px;top:-6px;border-left:12px solid var(--line);border-top:7px solid transparent;border-bottom:7px solid transparent}.arrow.output .shaft{background:var(--green)}.arrow.output .shaft:after{border-left-color:var(--green)}
  .evidence,.key-path{position:absolute;top:164px;width:2px;height:48px}.evidence{left:50%;border-left:3px dashed var(--teal)}.key-path{left:68%;background:var(--green)}.connector-label{position:absolute;left:13px;top:5px;width:160px;font-size:15px;font-weight:700;white-space:nowrap}.evidence .connector-label{color:var(--teal)}.key-path .connector-label{color:var(--green)}
  .trust-note{margin:28px auto 0;max-width:1110px;border-left:4px solid var(--teal);padding:12px 18px;color:#d8e8f4;font-size:18px;line-height:1.45;background:#0c1c29}.legend{display:flex;gap:30px;justify-content:center;color:var(--muted);font-size:15px;margin-top:20px}.sample{display:inline-block;width:46px;height:3px;background:var(--line);vertical-align:middle;margin-right:8px}.sample.dashed{height:0;background:none;border-top:3px dashed var(--teal)}.sample.green{background:var(--green)}
  body.raw-focus [data-node]:not([data-node="camera"]):not([data-node="storage"]):not([data-node="hsm"]){opacity:.38}body.raw-focus [data-node="camera"],body.raw-focus [data-node="storage"],body.raw-focus [data-node="hsm"]{border-color:var(--gold);box-shadow:0 0 0 3px rgba(245,196,81,.22)}body.output-focus [data-node]:not([data-node="vm"]):not([data-node="gpu"]):not([data-node="reviewer"]):not([data-node="attestation"]){opacity:.38}body.output-focus [data-node="vm"],body.output-focus [data-node="gpu"],body.output-focus [data-node="reviewer"],body.output-focus [data-node="attestation"]{border-color:var(--green);box-shadow:0 0 0 3px rgba(85,209,135,.2)}
</style></head><body class="${focus === 'all' ? '' : `${focus}-focus`}"><main>
  <div class="title-row"><div><p class="kicker">Republic of Contoso · one simulated camera</p><h1>Privacy-preserving CCTV analytics</h1></div><p class="lede">Retain original evidence. Verify the confidential runtime. Release a separate anonymized stream for routine review.</p></div>
  <section class="diagram" data-cctv-architecture>
    <div class="control-row">
      <div class="control" data-node="attestation"><img src="${architectureIcons.attestation}" alt=""><div><strong>Azure Attestation</strong><span>CPU, GPU and current-boot evidence</span></div></div>
      <div class="control" data-node="hsm"><img src="${architectureIcons.hsm}" alt=""><div><strong>Customer-controlled Managed HSM</strong><span>Storage CMK and release policy</span></div></div>
    </div>
    <div class="evidence"><span class="connector-label">Attestation evidence</span></div><div class="key-path"><span class="connector-label">Customer key control</span></div>
    <div class="flow-row">
      <div class="node" data-node="camera"><div class="camera-mark" aria-hidden="true"></div><div><strong>CCTV camera 01</strong><span>Simulated video source</span></div></div>
      <div class="arrow"><div class="shaft"></div>Original footage</div>
      <div class="node" data-node="storage"><img src="${architectureIcons.storage}" alt=""><div><strong>Private DVR storage</strong><span>Unmodified evidence · CMK</span></div></div>
      <div class="arrow"><div class="shaft"></div><img src="${architectureIcons.privateLink}" alt="" width="25" height="25"><br>Private Link</div>
      <div class="tee" data-node="tee"><div class="tee-title">Hardware-protected trusted execution environment</div><div class="tee-grid"><div class="node" data-node="vm"><img src="${architectureIcons.vm}" alt=""><div><strong>Application CVM</strong><span>Decode · track · blur · HLS</span></div></div><div class="node" data-node="gpu"><img src="${architectureIcons.gpu}" alt=""><div><strong>Confidential H100</strong><span>GPU face detection · CC ON</span></div></div></div></div>
      <div class="arrow output"><div class="shaft"></div>Anonymized HLS only</div>
      <div class="node" data-node="reviewer"><img src="${architectureIcons.browser}" alt=""><div><strong>Routine reviewer</strong><span>People not identifiable in demonstrated output</span></div></div>
    </div>
    <p class="trust-note"><strong>Data in use:</strong> plaintext frames are confined to the verified CVM-GPU processing boundary. Missing or invalid evidence stops processing; raw footage is never used as a playback fallback.</p>
    <div class="legend"><span><i class="sample"></i>Protected data path</span><span><i class="sample dashed"></i>Attestation evidence</span><span><i class="sample green"></i>Anonymized output / key control</span></div>
  </section>
</main></body></html>`;
  await page.setContent(html, { waitUntil: 'load' });
  const diagram = page.locator('[data-cctv-architecture]');
  await diagram.waitFor({ state: 'visible' });
  const architectureCheck = await diagram.evaluate(rootElement => {
    const teeTitleBounds = rootElement.querySelector('.tee-title').getBoundingClientRect();
    const connectorLabels = [...rootElement.querySelectorAll('.connector-label')];
    return {
      nodes: ['camera', 'storage', 'attestation', 'hsm', 'vm', 'gpu', 'reviewer'].every(name => rootElement.querySelector(`[data-node="${name}"]`)),
      icons: [...rootElement.querySelectorAll('img')].every(image => image.complete && image.naturalWidth > 0),
      legible: rootElement.getBoundingClientRect().width > 1600 && rootElement.getBoundingClientRect().height > 700,
      connectorLabelsClear: connectorLabels.every(label => label.getBoundingClientRect().bottom <= teeTitleBounds.top - 8),
    };
  });
  if (!Object.values(architectureCheck).every(Boolean)) throw new Error(`CCTV architecture is incomplete: ${JSON.stringify(architectureCheck)}`);
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
  async openingCctvArchitecture() {
    await showCctvArchitecture('all');
  },
  async showRawEvidencePath() {
    await page.evaluate(() => {
      document.body.classList.remove('output-focus');
      document.body.classList.add('raw-focus');
    });
    const focusCheck = await page.locator('[data-cctv-architecture]').evaluate(rootElement => ({
      camera: rootElement.querySelector('[data-node="camera"]') !== null,
      storage: rootElement.querySelector('[data-node="storage"]') !== null,
      hsm: rootElement.querySelector('[data-node="hsm"]') !== null,
      unchanged: rootElement.textContent.includes('Unmodified evidence'),
    }));
    if (!Object.values(focusCheck).every(Boolean)) throw new Error(`Raw evidence path is incomplete: ${JSON.stringify(focusCheck)}`);
  },
  async openCctv() {
    await goto('/cctv');
    await page.addStyleTag({ content: `
      nav{display:none!important} body{padding:0!important} main{max-width:1880px!important;padding:24px 42px!important}
      main>p.eyebrow,main>h1,main>h1+p{margin-top:3px!important;margin-bottom:6px!important}
      .actions{margin:10px 0!important}.viewer{gap:12px!important;padding-top:12px!important}
      .status-strip{gap:10px!important}.metric{min-height:72px!important;padding:12px!important}
      .streams{gap:16px!important}.video-frame video{max-height:430px!important}.caption{font-size:13px!important;line-height:1.25!important}
      .infrastructure-panel,.debug-open{display:none!important}
    ` });
    await page.locator('#open-viewer').waitFor({ state: 'visible' });
    const statusResponse = await page.request.get(`${baseUrl}/cctv/status`);
    const liveStatus = await statusResponse.json();
    if (!['processing', 'running', 'completed'].includes(liveStatus.state) || liveStatus.confidential_gpu?.verified !== true) {
      throw new Error(`Live CCTV status is not ready: ${JSON.stringify(liveStatus)}`);
    }
  },
  async startComparison() {
    await click('#open-viewer');
    await page.locator('#viewer.is-visible').waitFor({ state: 'visible' });
    await page.waitForFunction(() => {
      const source = document.querySelector('#source-video');
      return source && Number.isFinite(source.duration) && source.duration > 20;
    }, null, { timeout: 30_000 });
    await page.evaluate(() => {
      const processed = document.querySelector('#processed-video');
      if (!processed.src && typeof attachProcessedStream === 'function') attachProcessedStream();
    });
    await page.waitForFunction(() => {
      const processed = document.querySelector('#processed-video');
      return processed && Number.isFinite(processed.duration) && processed.duration > 20;
    }, null, { timeout: 45_000 });
    comparisonStart = await page.evaluate(async () => {
      const source = document.querySelector('#source-video');
      const processed = document.querySelector('#processed-video');
      source.currentTime = 3;
      processed.currentTime = 3;
      await Promise.all([source.play(), processed.play()]);
      return { source: source.currentTime, processed: processed.currentTime };
    });
    await page.waitForFunction(() => {
      const source = document.querySelector('#source-video');
      const processed = document.querySelector('#processed-video');
      return source.currentTime > 3.5 && processed.currentTime > 3.5 && !source.paused && !processed.paused;
    }, null, { timeout: 20_000 });
    await page.locator('.streams').scrollIntoViewIfNeeded();
  },
  async showLiveMetrics() {
    await page.waitForFunction(start => {
      const source = document.querySelector('#source-video');
      const processed = document.querySelector('#processed-video');
      return source.currentTime - start.source >= 2 && processed.currentTime - start.processed >= 2;
    }, comparisonStart, { timeout: 15_000 });
    const playback = await page.evaluate(start => {
      const source = document.querySelector('#source-video');
      const processed = document.querySelector('#processed-video');
      return {
        source: source.currentTime,
        processed: processed.currentTime,
        sourceAdvanced: source.currentTime - start.source,
        processedAdvanced: processed.currentTime - start.processed,
        drift: Math.abs(source.currentTime - processed.currentTime),
        gpu: document.querySelector('#gpu-state')?.textContent || '',
        faces: Number(document.querySelector('#face-count')?.textContent),
        attribution: document.querySelector('.caption')?.textContent.includes('CC BY-SA 4.0') === true,
      };
    }, comparisonStart);
    if (playback.sourceAdvanced < 2 || playback.processedAdvanced < 2 || playback.drift > 3
        || !playback.gpu.includes('Verified') || !Number.isFinite(playback.faces) || playback.faces < 1 || !playback.attribution) {
      throw new Error(`CCTV playback evidence is incomplete: ${JSON.stringify(playback)}`);
    }
    await page.locator('#viewer').scrollIntoViewIfNeeded();
  },
  async showTechnicalDetails() {
    if (!await page.locator('#technical-details-toggle').isChecked()) await click('label[for="technical-details-toggle"]');
    await page.locator('#technical-details:not([hidden])').waitFor({ state: 'visible' });
    await page.waitForFunction(() => {
      const text = document.querySelector('#technical-details')?.textContent || '';
      return text.includes('Blob Private Link only') && text.includes('Azure Managed HSM') && !text.includes('Loading');
    }, null, { timeout: 30_000 });
    await page.locator('#technical-details').scrollIntoViewIfNeeded();
  },
  async closingFrame() {
    await showCctvArchitecture('output');
  },
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
  async legacyRegistryClosingFrame() {
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