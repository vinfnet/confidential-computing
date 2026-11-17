const el = (id) => document.getElementById(id);
let signedIn = false;
let sessionSuppressed = false;
let signOutError = '';
let authEpoch = 0;
let leaseTimer;
let commandScrollTop = 0;
let plaintextVisible = false;
let plaintextExpiresAt = 0;
let refreshId = 0;
let animationPaused = false;
let scrollResumeAt = Date.now() + 1500;
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
function renderScene() {
  const available = plaintextVisible && signedIn && !document.hidden && plaintextExpiresAt > Date.now();
  const running = available && !animationPaused && !reducedMotion.matches;
  el('production-scene').dataset.motion = available ? (running ? 'running' : 'paused') : 'locked';
  el('scene-toggle').disabled = !available || reducedMotion.matches;
  el('scene-toggle').textContent = running ? 'Pause animation' : 'Play animation';
  el('scene-toggle').setAttribute('aria-pressed', String(running));
  el('scene-status').textContent = !available ? 'Locked · animation unavailable'
    : reducedMotion.matches ? 'Reduced motion · illustration paused'
      : running ? 'Illustration playing · not live machinery' : 'Illustration paused';
  el('scene-job').textContent = available ? 'Tailspin design available to authorized viewer' : 'No authorized design in view';
}
el('scene-toggle').onclick = () => {
  if (plaintextExpiresAt <= Date.now()) hidePlaintext();
  animationPaused = !animationPaused;
  renderScene();
};
reducedMotion.addEventListener('change', renderScene);
function hidePlaintext(message = 'Plaintext is no longer available.') {
  if (plaintextVisible) commandScrollTop = el('commands').scrollTop;
  plaintextVisible = false;
  plaintextExpiresAt = 0;
  el('commands').textContent = message;
  clearTimeout(leaseTimer);
  renderScene();
}
function scrollCommands() {
  const commands = el('commands');
  if (!plaintextVisible || document.hidden || reducedMotion.matches ||
      commands.matches(':hover, :focus-within') || Date.now() < scrollResumeAt) return;
  const bottom = commands.scrollHeight - commands.clientHeight;
  if (bottom <= 0) return;
  if (commands.scrollTop >= bottom - 1) {
    commands.scrollTop = 0;
    scrollResumeAt = Date.now() + 1500;
  } else {
    commands.scrollTop = Math.min(bottom, commands.scrollTop + 3);
    if (commands.scrollTop >= bottom - 1) scrollResumeAt = Date.now() + 2000;
  }
}
function showSession(data) {
  signedIn = !sessionSuppressed && data.authenticated === true;
  el('identity').textContent = signedIn ? `Tailspin operator: ${data.user}` : 'Not signed in';
  el('sign-in').hidden = signedIn;
  el('logout').hidden = !signedIn;
  if (!signedIn) hidePlaintext('Plaintext is not available. Tailspin sign-in required.');
}
async function post(route, body) {
  const response = await fetch(route, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed: HTTP ${response.status}`);
  return data;
}
el('login-form').onsubmit = async (event) => {
  event.preventDefault();
  const epoch = ++authEpoch;
  el('login').disabled = true;
  try {
    const data = await post('/api/login', { username: el('username').value, password: el('password').value });
    if (epoch !== authEpoch) return;
    sessionSuppressed = false;
    signOutError = '';
    showSession(data);
    el('error').textContent = '';
    await refresh();
  } catch (error) { el('error').textContent = error.message; }
  finally { el('password').value = ''; el('login').disabled = false; }
};
el('logout').onclick = async () => {
  ++authEpoch;
  sessionSuppressed = true;
  signOutError = '';
  showSession({ authenticated: false });
  try { await post('/api/logout', {}); el('error').textContent = ''; }
  catch (error) {
    signOutError = `Sign-out failed: ${error.message}. Plaintext stays hidden until you sign in again.`;
    el('error').textContent = signOutError;
  }
};
async function refresh() {
  const id = ++refreshId;
  if (document.hidden) { hidePlaintext(); return; }
  const epoch = authEpoch;
  const current = () => epoch === authEpoch && id === refreshId && !document.hidden;
  try {
    const [response, sessionResponse] = await Promise.all([
      fetch('/api/ciphertext', { cache: 'no-store' }),
      fetch('/api/session', { cache: 'no-store', credentials: 'same-origin' })
    ]);
    if (!response.ok || !sessionResponse.ok) throw new Error(`Worker returned HTTP ${!response.ok ? response.status : sessionResponse.status}`);
    const [state, session] = await Promise.all([response.json(), sessionResponse.json()]);
    if (!current()) return;
    const expired = signedIn && !session.authenticated;
    showSession(session);
    el('status').textContent = state.state === 'protected' ? 'Protected - fresh key release succeeded' : 'Locked - plaintext unavailable';
    el('status').className = state.state === 'protected' ? 'protected' : 'unavailable';
    el('reason').textContent = state.reason || 'Decryption occurs inside this confidential container.';
    el('last').textContent = state.lastSuccess || 'Never';
    el('lease').textContent = state.expiresAt ? new Date(state.expiresAt).toLocaleTimeString() : 'None';
    el('ciphertext').textContent = JSON.stringify(state.envelope, null, 2);
    if (state.state !== 'protected') hidePlaintext();
    if (signedIn && state.state === 'protected') {
      const secured = await fetch('/api/commands', { credentials: 'same-origin', cache: 'no-store' });
      if (!current()) return;
      if (!secured.ok) {
        if (secured.status === 401) showSession({ authenticated: false });
        throw new Error(`Tailspin authorization rejected: HTTP ${secured.status}`);
      }
      const data = await secured.json();
      if (!current()) return;
      if (signedIn && data.state === 'protected' && typeof data.plaintext === 'string' &&
          data.plaintext.trim() && Number.isFinite(data.expiresAt) && data.expiresAt > Date.now()) {
        clearTimeout(leaseTimer);
        if (plaintextVisible) commandScrollTop = el('commands').scrollTop;
        el('commands').textContent = data.plaintext;
        el('commands').scrollTop = commandScrollTop;
        plaintextVisible = true;
        plaintextExpiresAt = data.expiresAt;
        renderScene();
        leaseTimer = setTimeout(hidePlaintext, data.expiresAt - Date.now());
      } else hidePlaintext();
    }
    el('error').textContent = signOutError || (expired ? 'Your operator session expired. Sign in again.' : '');
  } catch (error) {
    if (!current()) return;
    hidePlaintext();
    el('status').textContent = 'Disconnected - plaintext hidden';
    el('error').textContent = error.message;
  }
}
document.addEventListener('visibilitychange', () => {
  ++refreshId; // Invalidate responses begun before the visibility boundary.
  if (document.hidden) hidePlaintext(); else refresh();
});
renderScene();
refresh();
setInterval(refresh, 2000);
setInterval(scrollCommands, 100);
