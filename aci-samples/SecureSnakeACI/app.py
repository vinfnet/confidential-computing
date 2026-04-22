import base64
import json
import os
import stat
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

RUNTIME = os.getenv('SECURE_SNAKE_RUNTIME', 'Azure Confidential ACI')
POLICY_BOUND = os.getenv('SECURE_SNAKE_POLICY_BOUND', 'false').lower() == 'true'
POLICY_MODE = os.getenv('SECURE_SNAKE_POLICY_MODE', 'confcom-generated')
IMAGE_DIGEST = os.getenv('SECURE_SNAKE_IMAGE_DIGEST', '')
MAA_ENDPOINT = os.getenv('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
HARDENING = os.getenv('SECURE_SNAKE_HARDENING_SUMMARY', 'digest-pinned; confcom; stdio-disabled')
LOG_FILES = {
    'skr': '/var/log/supervisor/skr.log',
    'skr_error': '/var/log/supervisor/skr_error.log',
    'flask': '/var/log/supervisor/flask.log',
    'flask_error': '/var/log/supervisor/flask_error.log',
    'supervisord': '/var/log/supervisor/supervisord.log'
}


def read_log_files(max_lines: int = 80) -> dict:
    logs = {}
    for name, path in LOG_FILES.items():
        try:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8', errors='replace') as handle:
                    lines = handle.readlines()
                logs[name] = ''.join(lines[-max_lines:]) if lines else '(empty)'
            else:
                logs[name] = f'(file not found: {path})'
        except Exception as exc:
            logs[name] = f'(error reading file: {exc})'
    return logs


def short_value(value: str) -> str:
    if not value:
        return 'not-set'
    if len(value) <= 28:
        return value
    return f"{value[:16]}...{value[-10:]}"


def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return {}
        payload = parts[1] + '=' * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode('utf-8')).decode('utf-8')
        return json.loads(decoded)
    except Exception:
        return {}


def validate_maa_endpoint(raw: str) -> str:
    endpoint = (raw or MAA_ENDPOINT).strip()
    endpoint = endpoint.replace('https://', '').replace('http://', '').split('/')[0]
    if not endpoint.endswith('.attest.azure.net'):
        raise ValueError('maa_endpoint must be an Azure Attestation endpoint (*.attest.azure.net)')
    return endpoint


def check_sev_guest_device() -> dict:
    result = {
        'available': False,
        'device_path': None,
        'device_info': None,
        'explanation': 'No AMD SEV-SNP guest device detected.'
    }

    for device in ('/dev/sev-guest', '/dev/sev', '/dev/sev0'):
        if os.path.exists(device):
            result['available'] = True
            result['device_path'] = device
            try:
                details = os.stat(device)
                result['device_info'] = {
                    'mode': oct(details.st_mode),
                    'type': 'character device' if stat.S_ISCHR(details.st_mode) else 'other',
                    'readable': os.access(device, os.R_OK)
                }
            except Exception as exc:
                result['device_info'] = {'error': str(exc)}
            result['explanation'] = f'AMD SEV-SNP guest device is present at {device}.'
            break

    if not result['available']:
        try:
            result['dev_listing'] = [d for d in os.listdir('/dev') if 'sev' in d.lower() or 'sgx' in d.lower() or 'tpm' in d.lower()]
        except Exception:
            result['dev_listing'] = []

    return result


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    if request.path.startswith('/attest') or request.path.startswith('/api/security'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    return response


GAME_HTML = r'''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Secure Snake ACI</title>
  <style>
    :root {
      --bg: #07111f;
      --panel: rgba(8, 18, 31, 0.86);
      --line: rgba(255,255,255,0.12);
      --accent: #6fffb0;
      --accent2: #63c7ff;
      --warn: #ffd166;
      --danger: #ff6b6b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      color: #eef6ff;
      background:
        radial-gradient(circle at top, rgba(68, 117, 255, 0.22), transparent 38%),
        linear-gradient(180deg, #07111f 0%, #0f1f36 100%);
      min-height: 100vh;
    }
    .topbar {
      display:flex; justify-content:space-between; align-items:center;
      padding: 14px 18px; border-bottom:1px solid rgba(255,255,255,.08);
      background: rgba(2, 8, 15, 0.55);
      position: sticky; top: 0;
      backdrop-filter: blur(6px);
    }
    .nav a {
      color:#eef6ff; text-decoration:none; margin-left:10px; padding:8px 12px;
      border:1px solid rgba(255,255,255,.12); border-radius:10px;
    }
    .nav a:hover { border-color: var(--accent2); }
    .layout {
      display: grid;
      grid-template-columns: 320px 1fr 320px;
      gap: 16px;
      padding: 16px;
      min-height: calc(100vh - 64px);
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      box-shadow: 0 12px 30px rgba(0,0,0,0.28);
      backdrop-filter: blur(4px);
    }
    .panel h1, .panel h2, .panel h3 { margin: 0 0 10px 0; }
    .panel p { margin: 6px 0; font-size: 14px; line-height: 1.4; }
    .stat {
      display: flex; justify-content: space-between; gap: 12px;
      padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.08);
      font-size: 14px;
    }
    .value { color: var(--accent); font-weight: bold; text-align: right; word-break: break-word; }
    .center { display:flex; align-items:center; justify-content:center; }
    .game-shell {
      width: min(92vw, 760px);
      background: rgba(3, 9, 18, 0.74);
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,0.12);
      padding: 16px;
      box-shadow: 0 18px 50px rgba(0,0,0,0.35);
    }
    canvas {
      width: 100%; max-width: 700px; aspect-ratio: 1 / 1; display: block; margin: 0 auto;
      background: linear-gradient(180deg, #0b1b31, #08121f);
      border: 1px solid rgba(255,255,255,0.12); border-radius: 12px;
    }
    .status { margin-top: 12px; padding: 10px 12px; border-radius: 10px; background: rgba(255,255,255,0.06); font-weight: bold; color: var(--warn); }
    .good { color: var(--accent); }
    .bad { color: var(--danger); }
    .pill {
      display:inline-block; margin-top:8px; padding:6px 10px; border-radius:999px;
      background: rgba(111,255,176,.12); border:1px solid rgba(111,255,176,.35);
      color: var(--accent); font-size: 12px; font-weight: bold;
    }
    .modal-backdrop {
      position: fixed;
      inset: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(3, 8, 15, 0.72);
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.35s ease;
      z-index: 20;
    }
    .modal-backdrop.show { opacity: 1; pointer-events: auto; }
    .attest-modal {
      width: min(92vw, 520px);
      background: rgba(8, 18, 31, 0.96);
      border: 1px solid rgba(99, 199, 255, 0.35);
      border-radius: 16px;
      padding: 18px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.42);
    }
    .attest-modal h3 { margin: 0 0 10px 0; }
    .attest-modal p { margin: 8px 0; line-height: 1.45; }
    .progress-track {
      width: 100%;
      height: 12px;
      background: rgba(255,255,255,0.08);
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid rgba(255,255,255,0.10);
      margin: 12px 0 10px;
    }
    .progress-bar {
      width: 0%;
      height: 100%;
      background: linear-gradient(90deg, var(--accent2), var(--accent));
      transition: width 0.25s ease;
    }
    .modal-note { color: #9fd8ff; font-size: 13px; }
    .modal-success { color: var(--accent); }
    .modal-error { color: var(--warn); }
    @media (max-width: 1100px) {
      .layout { grid-template-columns: 1fr; }
      .center { order: -1; }
    }
  </style>
</head>
<body>
  <div class="topbar">
    <strong>Secure Snake on Confidential ACI</strong>
    <div class="nav">
      <a href="/">Game</a>
      <a href="/attestation">Attestation</a>
    </div>
  </div>

  <div class="layout">
    <section class="panel">
      <h1>🐍 Secure Snake</h1>
      <p>Running inside <strong>{{ runtime }}</strong></p>
      <p>This app is intentionally trivial so the confidential-computing security model is the star of the show.</p>
      <div class="stat"><span>Policy bound</span><span class="value">{{ policy_bound }}</span></div>
      <div class="stat"><span>Policy mode</span><span class="value">{{ policy_mode }}</span></div>
      <div class="stat"><span>Image digest</span><span class="value">{{ image_digest }}</span></div>
      <div class="stat"><span>MAA endpoint</span><span class="value">{{ maa_endpoint }}</span></div>
      <div class="stat"><span>Score</span><span class="value" id="score">0</span></div>
      <div class="stat"><span>Best</span><span class="value" id="best">0</span></div>
      <div class="stat"><span>Length</span><span class="value" id="length">3</span></div>
      <div class="stat"><span>Speed</span><span class="value" id="speed">1</span></div>
      <div class="status" id="status">Press an arrow key or WASD to begin.</div>
    </section>

    <main class="center">
      <div class="game-shell">
        <canvas id="game" width="700" height="700"></canvas>
      </div>
    </main>

    <aside class="panel">
      <h2>Security posture</h2>
      <p><strong>Interactive shell access is blocked</strong> by the confcom-generated CCE policy.</p>
      <p><strong>Tampering changes the policy hash</strong>, which breaks attestation for the deployed workload identity.</p>
      <p><strong>Exact image is pinned by digest</strong>, so the deployment is bound to one immutable image version.</p>
      <span class="pill">{{ hardening }}</span>
      <h3 style="margin-top:16px;">Controls</h3>
      <p>W / A / S / D or Arrow Keys</p>
      <p>Space = pause, R = restart</p>
      <p style="margin-top:16px;"><a href="/attestation" style="color:#63c7ff;">Open the attestation page →</a></p>
    </aside>
  </div>

  <div class="modal-backdrop" id="attestationModal" aria-hidden="true">
    <div class="attest-modal" role="dialog" aria-modal="true" aria-labelledby="attestationTitle">
      <h3 id="attestationTitle">Integrity verification in progress</h3>
      <p id="attestationMessage">Attestation check is being performed to protect game integrity.</p>
      <div class="progress-track" aria-hidden="true">
        <div class="progress-bar" id="attestationProgress"></div>
      </div>
      <p class="modal-note" id="attestationNote">Requesting evidence from the confidential container...</p>
    </div>
  </div>

  <script>
    const canvas = document.getElementById('game');
    const ctx = canvas.getContext('2d');
    const grid = 25;
    const tiles = canvas.width / grid;

    let snake;
    let direction;
    let queuedDirection;
    let food;
    let score;
    let best = Number(localStorage.getItem('secureSnakeBest') || '0');
    let gameOver;
    let paused;
    let speedLevel;
    let lastStep = 0;
    let stepDelay = 120;
    let attestationCheckActive = false;
    let attestationTimer = null;
    let highScoreVerifiedThisRun = false;

    function setAttestationProgress(value) {
      document.getElementById('attestationProgress').style.width = `${Math.max(0, Math.min(100, value))}%`;
    }

    function showAttestationModal(title, message, note, noteClass = 'modal-note') {
      document.getElementById('attestationTitle').textContent = title;
      document.getElementById('attestationMessage').textContent = message;
      const noteEl = document.getElementById('attestationNote');
      noteEl.textContent = note;
      noteEl.className = noteClass;
      document.getElementById('attestationModal').classList.add('show');
    }

    function hideAttestationModal() {
      document.getElementById('attestationModal').classList.remove('show');
      setAttestationProgress(0);
    }

    async function verifyHighScoreAttestation() {
      if (attestationCheckActive || gameOver) return;

      attestationCheckActive = true;
      paused = true;
      let progress = 10;
      setAttestationProgress(progress);
      showAttestationModal(
        'Integrity verification in progress',
        'Attestation check is being performed to protect game integrity.',
        'Verifying that the running game is still protected by Azure Confidential Computing...'
      );
      updateHud('New high score detected. Validating workload integrity...', '');

      attestationTimer = setInterval(() => {
        progress = Math.min(progress + (progress < 70 ? 11 : 4), 92);
        setAttestationProgress(progress);
      }, 180);

      try {
        const response = await fetch('/attest/maa', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            maa_endpoint: '{{ maa_endpoint }}',
            runtime_data: JSON.stringify({
              event: 'high-score-check',
              score,
              best,
              snake_length: snake.length,
              checked_at: new Date().toISOString()
            })
          })
        });

        const result = await response.json();
        clearInterval(attestationTimer);
        setAttestationProgress(100);

        if (response.ok && result.status === 'success') {
          highScoreVerifiedThisRun = true;
          showAttestationModal(
            'Integrity verified',
            'Game data is protected by Azure Confidential Computing.',
            'Attestation succeeded. Resuming play...',
            'modal-note modal-success'
          );
          updateHud('High score verified. Resume play.', 'good');
          setTimeout(() => {
            hideAttestationModal();
            attestationCheckActive = false;
            paused = false;
          }, 1500);
          return;
        }

        throw new Error(result.message || 'Attestation did not succeed.');
      } catch (error) {
        clearInterval(attestationTimer);
        showAttestationModal(
          'Attestation warning',
          'Integrity verification could not be completed right now.',
          'The game will continue, but you should review the attestation page for details.',
          'modal-note modal-error'
        );
        updateHud('Attestation check could not be confirmed. Continuing play.', 'bad');
        setTimeout(() => {
          hideAttestationModal();
          attestationCheckActive = false;
          paused = false;
        }, 1900);
      }
    }

    function updateHud(message, cls='') {
      document.getElementById('score').textContent = score;
      document.getElementById('best').textContent = best;
      document.getElementById('length').textContent = snake.length;
      document.getElementById('speed').textContent = speedLevel;
      const status = document.getElementById('status');
      status.textContent = message;
      status.className = 'status ' + cls;
    }

    function resetGame() {
      snake = [{x: 8, y: 14}, {x: 7, y: 14}, {x: 6, y: 14}];
      direction = {x: 1, y: 0};
      queuedDirection = {x: 1, y: 0};
      food = spawnFood();
      score = 0;
      gameOver = false;
      paused = false;
      speedLevel = 1;
      stepDelay = 120;
      highScoreVerifiedThisRun = false;
      attestationCheckActive = false;
      clearInterval(attestationTimer);
      hideAttestationModal();
      updateHud('Press an arrow key or WASD to begin.');
    }

    function spawnFood() {
      while (true) {
        const point = { x: Math.floor(Math.random() * tiles), y: Math.floor(Math.random() * tiles) };
        if (!snake || !snake.some(s => s.x === point.x && s.y === point.y)) return point;
      }
    }

    function reverseOfCurrent(next) { return next.x === -direction.x && next.y === -direction.y; }

    window.addEventListener('keydown', (e) => {
      const key = e.key.toLowerCase();
      if (attestationCheckActive) {
        e.preventDefault();
        return;
      }
      if (key === ' ') {
        e.preventDefault();
        if (!gameOver) {
          paused = !paused;
          updateHud(paused ? 'Paused. Press Space to continue.' : 'Back in motion.', paused ? '' : 'good');
        }
        return;
      }
      if (key === 'r') { resetGame(); return; }

      const map = {
        arrowup: {x: 0, y: -1}, w: {x: 0, y: -1},
        arrowdown: {x: 0, y: 1}, s: {x: 0, y: 1},
        arrowleft: {x: -1, y: 0}, a: {x: -1, y: 0},
        arrowright: {x: 1, y: 0}, d: {x: 1, y: 0}
      };

      if (map[key]) {
        e.preventDefault();
        const next = map[key];
        if (!reverseOfCurrent(next) || snake.length === 1) {
          queuedDirection = next;
          if (score === 0 && snake.length === 3 && !gameOver) updateHud('Snake is moving. Stay sharp.', 'good');
        }
      }
    });

    function stepGame() {
      if (gameOver || paused) return;
      direction = queuedDirection;
      const head = {x: snake[0].x + direction.x, y: snake[0].y + direction.y};
      if (head.x < 0 || head.y < 0 || head.x >= tiles || head.y >= tiles || snake.some(s => s.x === head.x && s.y === head.y)) {
        gameOver = true;
        updateHud('Game over. Press R to restart.', 'bad');
        return;
      }
      snake.unshift(head);
      if (head.x === food.x && head.y === food.y) {
        score += 10;
        const previousBest = best;
        best = Math.max(best, score);
        localStorage.setItem('secureSnakeBest', String(best));
        const shouldVerifyHighScore = best > previousBest && !highScoreVerifiedThisRun;
        if (shouldVerifyHighScore) {
          verifyHighScoreAttestation();
        }
        food = spawnFood();
        speedLevel = 1 + Math.floor(score / 50);
        stepDelay = Math.max(60, 120 - Math.floor(score / 20) * 6);
        if (!shouldVerifyHighScore) {
          updateHud('Nice catch. Keep going.', 'good');
        }
      } else {
        snake.pop();
      }
    }

    function drawCell(x, y, color, glow = false) {
      const px = x * grid;
      const py = y * grid;
      if (glow) { ctx.shadowBlur = 18; ctx.shadowColor = color; }
      ctx.fillStyle = color;
      ctx.fillRect(px + 2, py + 2, grid - 4, grid - 4);
      ctx.shadowBlur = 0;
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (let y = 0; y < tiles; y++) {
        for (let x = 0; x < tiles; x++) {
          ctx.fillStyle = (x + y) % 2 === 0 ? '#0a1729' : '#0c1b31';
          ctx.fillRect(x * grid, y * grid, grid, grid);
        }
      }
      drawCell(food.x, food.y, '#ffd166', true);
      snake.forEach((part, index) => drawCell(part.x, part.y, index === 0 ? '#6fffb0' : '#36d98a', index === 0));
      if (paused && !gameOver) {
        ctx.fillStyle = 'rgba(7,17,31,0.72)'; ctx.fillRect(120, 280, 460, 90);
        ctx.fillStyle = '#eef6ff'; ctx.font = 'bold 28px Arial'; ctx.fillText('Paused', 300, 325);
      }
      if (gameOver) {
        ctx.fillStyle = 'rgba(7,17,31,0.76)'; ctx.fillRect(90, 255, 520, 120);
        ctx.strokeStyle = '#ff6b6b'; ctx.lineWidth = 2; ctx.strokeRect(90, 255, 520, 120);
        ctx.fillStyle = '#eef6ff'; ctx.font = 'bold 28px Arial'; ctx.fillText('Snake crashed', 240, 302);
        ctx.font = '16px Arial'; ctx.fillText('Press R to try again', 258, 336);
      }
    }

    function loop(timestamp) {
      if (!lastStep) lastStep = timestamp;
      if (timestamp - lastStep >= stepDelay) { stepGame(); lastStep = timestamp; }
      draw();
      requestAnimationFrame(loop);
    }

    resetGame();
    requestAnimationFrame(loop);
  </script>
</body>
</html>
'''


ATTESTATION_HTML = r'''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Secure Snake Attestation</title>
  <style>
    body { margin:0; font-family:Arial,sans-serif; color:#eef6ff; background:linear-gradient(180deg,#07111f 0%,#0f1f36 100%); }
    .topbar { display:flex; justify-content:space-between; align-items:center; padding:14px 18px; border-bottom:1px solid rgba(255,255,255,.08); background:rgba(2,8,15,.55); }
    .nav a { color:#eef6ff; text-decoration:none; margin-left:10px; padding:8px 12px; border:1px solid rgba(255,255,255,.12); border-radius:10px; }
    .wrap { padding:16px; display:grid; grid-template-columns:320px 1fr; gap:16px; }
    .panel { background:rgba(8,18,31,.86); border:1px solid rgba(255,255,255,.12); border-radius:14px; padding:14px; }
    .stat { display:flex; justify-content:space-between; gap:12px; padding:8px 0; border-bottom:1px solid rgba(255,255,255,.08); font-size:14px; }
    .value { color:#6fffb0; font-weight:bold; text-align:right; word-break:break-word; }
    .controls { display:flex; flex-wrap:wrap; gap:10px; margin:12px 0; }
    button { cursor:pointer; border:0; border-radius:10px; padding:10px 14px; background:#163459; color:#eef6ff; font-weight:bold; }
    button:hover { background:#1f4d82; }
    input { width:100%; padding:10px; border-radius:10px; border:1px solid rgba(255,255,255,.12); background:#08121f; color:#eef6ff; }
    pre { white-space:pre-wrap; word-break:break-word; background:#04101c; padding:12px; border-radius:10px; border:1px solid rgba(255,255,255,.08); max-height:460px; overflow:auto; }
    .hint { color:#9fd8ff; font-size:13px; }
    .claim-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(240px, 1fr)); gap:12px; margin-top:12px; }
    .claim-card { background:#04101c; border:1px solid rgba(255,255,255,.08); border-radius:12px; padding:12px; }
    .claim-card h4 { margin:0 0 6px 0; color:#6fffb0; }
    .claim-name { font-family:Consolas, monospace; color:#9fd8ff; font-size:12px; margin-bottom:8px; }
    .claim-card p { margin:6px 0; font-size:13px; line-height:1.45; }
    .claim-current-value { color:#ffd166; font-weight:bold; }
    .claim-detail-label { color:#c8dcf4; }
    .claim-detail-text { color:#9fb4cc; }
    .claim-card code { color:#ffd166; }
    @media (max-width: 1000px) { .wrap { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <div class="topbar">
    <strong>Container Attestation</strong>
    <div class="nav">
      <a href="/">Game</a>
      <a href="/attestation">Attestation</a>
    </div>
  </div>

  <div class="wrap">
    <section class="panel">
      <h2>Runtime summary</h2>
      <div class="stat"><span>Runtime</span><span class="value">{{ runtime }}</span></div>
      <div class="stat"><span>Policy mode</span><span class="value">{{ policy_mode }}</span></div>
      <div class="stat"><span>Image digest</span><span class="value">{{ image_digest }}</span></div>
      <div class="stat"><span>MAA endpoint</span><span class="value">{{ maa_endpoint }}</span></div>
      <div class="stat"><span>SEV device</span><span class="value">{{ sev_device }}</span></div>
      <p class="hint">This page requests attestation from inside the running container and displays the returned evidence and claims.</p>
      <p class="hint"><strong>Hardening:</strong> {{ hardening }}</p>
    </section>

    <section class="panel">
      <h2>Live attestation actions</h2>
      <label for="maa">MAA endpoint</label>
      <input id="maa" value="{{ maa_endpoint }}" />
      <div class="controls">
        <button onclick="checkSidecar()">Check attestation service</button>
        <button onclick="requestToken()">Request MAA token</button>
        <button onclick="requestRaw()">Get raw report</button>
      </div>
      <h3>Status / output</h3>
      <pre id="output">Use the buttons above to query attestation from the live confidential container.</pre>

      <h3 style="margin-top:16px;">What each claim means</h3>
      <p class="hint">These claim explanations describe how the token proves freshness, issuer trust, and confidential workload integrity.</p>
      <div id="claim-guide" class="claim-grid"></div>
    </section>
  </div>

  <script>
    async function callJson(url, method = 'GET', body = null) {
      const options = { method, headers: { 'Content-Type': 'application/json' } };
      if (body) options.body = JSON.stringify(body);
      const response = await fetch(url, options);
      const data = await response.json();
      return { ok: response.ok, status: response.status, data };
    }

    function show(data) {
      document.getElementById('output').textContent = JSON.stringify(data, null, 2);
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function renderClaimGuide(claimGuide) {
      const host = document.getElementById('claim-guide');
      if (!Array.isArray(claimGuide) || claimGuide.length === 0) {
        host.innerHTML = '<div class="claim-card"><h4>No claims yet</h4><p>Request an attestation token to populate this guide with live values from the running confidential container.</p></div>';
        return;
      }

      host.innerHTML = claimGuide.map((item) => `
        <article class="claim-card">
          <h4>${escapeHtml(item.label)}</h4>
          <div class="claim-name">${escapeHtml(item.name)}</div>
          <p><strong>Current value:</strong> <span class="claim-current-value">${escapeHtml(item.value)}</span></p>
          <p><strong class="claim-detail-label">What it means:</strong> <span class="claim-detail-text">${escapeHtml(item.meaning)}</span></p>
          <p><strong class="claim-detail-label">Why it matters:</strong> <span class="claim-detail-text">${escapeHtml(item.why_it_matters)}</span></p>
        </article>
      `).join('');
    }

    const claimGuideTemplate = {{ claim_guide|tojson }};

    function formatClaimValue(name, value) {
      if (value === null || value === undefined || value === '') {
        return 'Not returned in the current token.';
      }
      if (name === 'iat' || name === 'nbf' || name === 'exp') {
        const asNumber = Number(value);
        if (!Number.isNaN(asNumber)) {
          return new Date(asNumber * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
        }
      }
      if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
      }
      if (typeof value === 'object') {
        return JSON.stringify(value, null, 2);
      }
      return String(value);
    }

    function buildClaimGuideFromClaims(claims) {
      const sourceClaims = claims && typeof claims === 'object' ? claims : {};
      const knownClaimNames = new Set(claimGuideTemplate.map((item) => item.name));

      const guide = claimGuideTemplate.map((item) => ({
        ...item,
        value: formatClaimValue(item.name, sourceClaims[item.name])
      }));

      Object.keys(sourceClaims)
        .sort()
        .forEach((name) => {
          if (knownClaimNames.has(name)) {
            return;
          }
          guide.push({
            name,
            label: 'Additional signed claim',
            value: formatClaimValue(name, sourceClaims[name]),
            meaning: 'This is another field returned inside the signed attestation token payload.',
            why_it_matters: 'Even when this sample does not interpret it directly, downstream verifiers can still use it to enforce workload-specific trust policies.'
          });
        });

      return guide;
    }

    async function checkSidecar() {
      show({ status: 'checking' });
      const result = await callJson('/sidecar/status');
      show(result.data);
    }

    async function requestToken() {
      show({ status: 'requesting-token' });
      const maa = document.getElementById('maa').value;
      const result = await callJson('/attest/maa', 'POST', { maa_endpoint: maa, runtime_data: 'secure-snake-demo' });
      show(result.data);
      renderClaimGuide(buildClaimGuideFromClaims(result.data.claims || {}));
    }

    async function requestRaw() {
      show({ status: 'requesting-raw-report' });
      const result = await callJson('/attest/raw', 'POST', { runtime_data: 'secure-snake-demo' });
      show(result.data);
    }

    renderClaimGuide(claimGuideTemplate);
  </script>
</body>
</html>
'''


@app.get('/')
def root():
    return render_template_string(
        GAME_HTML,
        runtime=RUNTIME,
        policy_bound='yes' if POLICY_BOUND else 'no',
        policy_mode=POLICY_MODE,
        image_digest=short_value(IMAGE_DIGEST),
        maa_endpoint=MAA_ENDPOINT,
        hardening=HARDENING
    )


@app.get('/attestation')
def attestation_page():
    sev = check_sev_guest_device()
    return render_template_string(
        ATTESTATION_HTML,
        runtime=RUNTIME,
        policy_mode=POLICY_MODE,
        image_digest=short_value(IMAGE_DIGEST),
        maa_endpoint=MAA_ENDPOINT,
        sev_device=sev.get('device_path') or 'not-detected',
        hardening=HARDENING,
        claim_guide=build_claim_guide()
    )


@app.get('/health')
def health():
    return jsonify({
        'status': 'ok',
        'app': 'secure-snake',
        'runtime': 'azure-confidential-aci',
        'policy_bound': POLICY_BOUND,
        'image_digest_pinned': bool(IMAGE_DIGEST),
        'maa_endpoint': MAA_ENDPOINT
    })


@app.get('/api/scenario')
def scenario():
    return jsonify({
        'title': 'Browser Snake on Azure Confidential ACI',
        'objective': 'Collect food, grow the snake, and avoid collisions.',
        'controls': ['WASD or Arrow Keys', 'Space pause', 'R restart'],
        'confidential_compute': True,
        'security': {
            'policy_bound': POLICY_BOUND,
            'policy_mode': POLICY_MODE,
            'image_digest': IMAGE_DIGEST or None,
            'maa_endpoint': MAA_ENDPOINT,
            'hardening': HARDENING
        }
    })


@app.get('/api/security')
def api_security():
    return jsonify({
        'runtime': RUNTIME,
        'policy_bound': POLICY_BOUND,
        'policy_mode': POLICY_MODE,
        'image_digest': IMAGE_DIGEST or None,
        'maa_endpoint': MAA_ENDPOINT,
        'hardening': HARDENING,
        'sev_device': check_sev_guest_device()
    })


@app.get('/sidecar/status')
def sidecar_status():
    try:
        response = requests.get('http://localhost:8080/status', timeout=5)
        return jsonify({
            'status': 'available',
            'sidecar_status_code': response.status_code,
            'sidecar_response': response.text[:400],
            'sev_device': check_sev_guest_device()
        })
    except Exception as exc:
        return jsonify({
            'status': 'unavailable',
            'message': str(exc),
            'sev_device': check_sev_guest_device(),
            'logs': read_log_files()
        }), 503


@app.post('/attest/maa')
def attest_maa():
    try:
        data = request.get_json(silent=True) or {}
        maa_endpoint = validate_maa_endpoint(data.get('maa_endpoint', MAA_ENDPOINT))
        runtime_data = encode_runtime_data(data.get('runtime_data', 'secure-snake-demo'))

        response = requests.post(
            'http://localhost:8080/attest/maa',
            json={'maa_endpoint': maa_endpoint, 'runtime_data': runtime_data},
            timeout=30
        )

        if response.status_code != 200:
            return jsonify({
                'status': 'error',
                'message': f'Attestation failed with status {response.status_code}',
                'maa_endpoint': maa_endpoint,
                'runtime_data_preview': runtime_data[:120],
                'sidecar_response': response.text[:1600],
                'sev_device': check_sev_guest_device(),
                'logs': read_log_files()
            }), response.status_code

        token = response.text
        claims = decode_jwt_payload(token)
        interesting = {
            'x-ms-attestation-type': claims.get('x-ms-attestation-type'),
            'x-ms-sevsnpvm-hostdata': claims.get('x-ms-sevsnpvm-hostdata'),
            'x-ms-sevsnpvm-is-debuggable': claims.get('x-ms-sevsnpvm-is-debuggable'),
            'iss': claims.get('iss'),
            'iat': claims.get('iat'),
            'nbf': claims.get('nbf'),
            'exp': claims.get('exp')
        }

        return jsonify({
            'status': 'success',
            'maa_endpoint': maa_endpoint,
            'attestation_token': token,
            'claims': claims,
            'interesting_claims': interesting,
            'security_summary': {
                'policy_bound': POLICY_BOUND,
                'image_digest_pinned': bool(IMAGE_DIGEST),
                'hostdata_present': bool(claims.get('x-ms-sevsnpvm-hostdata'))
            }
        })
    except Exception as exc:
        return jsonify({'status': 'error', 'message': str(exc), 'logs': read_log_files()}), 500


@app.post('/attest/raw')
def attest_raw():
    try:
        data = request.get_json(silent=True) or {}
        runtime_data = encode_runtime_data(data.get('runtime_data', 'secure-snake-demo'))
        response = requests.post(
            'http://localhost:8080/attest/raw',
            json={'runtime_data': runtime_data},
            timeout=30
        )

        if response.status_code != 200:
            return jsonify({
                'status': 'error',
                'message': f'Raw attestation failed with status {response.status_code}',
                'runtime_data_preview': runtime_data[:120],
                'sidecar_response': response.text[:1600],
                'sev_device': check_sev_guest_device(),
                'logs': read_log_files()
            }), response.status_code

        return jsonify({
            'status': 'success',
            'attestation_report': response.text
        })
    except Exception as exc:
        return jsonify({'status': 'error', 'message': str(exc), 'logs': read_log_files()}), 500


def encode_runtime_data(value: str) -> str:
    payload_json = None

    if isinstance(value, str):
        raw = value.strip()
        if raw.startswith('{') and raw.endswith('}'):
            try:
                json.loads(raw)
                payload_json = raw
            except Exception:
                payload_json = None

    if payload_json is None:
        payload_json = json.dumps(
            {
                'nonce': value or 'secure-snake-demo',
                'sample': 'secure-snake-aci'
            },
            separators=(',', ':')
        )

    return base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')


def build_claim_guide(claims: dict | None = None) -> list[dict]:
    claims = claims or {}
    docs = {
        'x-ms-attestation-type': {
            'label': 'Attestation type',
            'meaning': 'Identifies the attestation flow that Microsoft Azure Attestation used when it evaluated evidence from the confidential container.',
            'why_it_matters': 'This helps confirm that the token came from a hardware-backed attestation path rather than from an ordinary application response.'
        },
        'x-ms-sevsnpvm-hostdata': {
            'label': 'SEV-SNP host data',
            'meaning': 'Contains measurement-related host data tied to the confidential workload launch context and policy material.',
            'why_it_matters': 'A verifier can compare this value with an expected measurement to detect drift or tampering in the approved workload configuration.'
        },
        'x-ms-sevsnpvm-is-debuggable': {
            'label': 'Debuggable flag',
            'meaning': 'Shows whether the underlying confidential guest was launched in a debuggable mode.',
            'why_it_matters': 'For strong integrity guarantees, this should normally be false so the workload cannot be inspected or altered through debug capabilities.'
        },
        'iss': {
            'label': 'Issuer',
            'meaning': 'The authority that issued the signed attestation token.',
            'why_it_matters': 'This lets you verify the token was minted by the expected Microsoft Azure Attestation endpoint.'
        },
        'iat': {
            'label': 'Issued at',
            'meaning': 'The UTC timestamp when the token was created.',
            'why_it_matters': 'This proves the evidence was evaluated recently and helps prevent replaying stale tokens.'
        },
        'nbf': {
            'label': 'Not before',
            'meaning': 'The earliest UTC time at which the token should be accepted.',
            'why_it_matters': 'This prevents the token from being treated as valid before its intended trust window begins.'
        },
        'exp': {
            'label': 'Expires at',
            'meaning': 'The UTC timestamp when the token is no longer valid.',
            'why_it_matters': 'Short-lived tokens reduce replay risk and encourage fresh attestation checks for sensitive operations.'
        }
    }

    ordered_names = [
        'x-ms-attestation-type',
        'x-ms-sevsnpvm-hostdata',
        'x-ms-sevsnpvm-is-debuggable',
        'iss',
        'iat',
        'nbf',
        'exp'
    ]

    guide = []
    for name in ordered_names:
        item = docs[name]
        guide.append({
            'name': name,
            'label': item['label'],
            'value': format_claim_value(name, claims.get(name)),
            'meaning': item['meaning'],
            'why_it_matters': item['why_it_matters']
        })

    for name in sorted(claims.keys()):
        if name in docs:
            continue
        guide.append({
            'name': name,
            'label': 'Additional signed claim',
            'value': format_claim_value(name, claims.get(name)),
            'meaning': 'This is another field returned inside the signed attestation token payload.',
            'why_it_matters': 'Even when this sample does not interpret it directly, downstream verifiers can still use it to enforce workload-specific trust policies.'
        })

    return guide


def format_claim_value(name: str, value):
    if value in (None, ''):
        return 'Not returned in the current token.'
    if name in {'iat', 'nbf', 'exp'}:
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            return str(value)
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2)
    return str(value)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
