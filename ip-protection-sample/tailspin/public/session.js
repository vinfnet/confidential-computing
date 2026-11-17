export class OperatorSession {
  constructor({ fetchImpl = globalThis.fetch.bind(globalThis), onChange = () => {}, onExpired = () => {} } = {}) {
    this.fetch = fetchImpl;
    this.onChange = onChange;
    this.onExpired = onExpired;
    this.user = null;
    this.generation = 0;
    this.requests = new Set();
  }

  clear() {
    this.generation++;
    this.user = null;
    for (const controller of this.requests) controller.abort();
    this.requests.clear();
    this.onChange(null);
  }

  async request(url, options = {}, requireSession = true) {
    if (requireSession && !this.user) throw new Error('Sign in with your operator username and password.');
    const generation = this.generation;
    const controller = new AbortController();
    this.requests.add(controller);
    try {
      const response = await this.fetch(url, {
        ...options, credentials: 'same-origin', cache: 'no-store',
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(25000)])
      });
      const body = await response.json();
      if (generation !== this.generation) throw new Error('Session changed; response discarded.');
      if (response.status === 401 && requireSession) {
        this.clear();
        this.onExpired();
        throw new Error('Your operator session expired. Sign in again.');
      }
      if (!response.ok) {
        const code = typeof body.error === 'string' && /^[a-z0-9_]+$/.test(body.error) ? body.error : 'request_failed';
        throw new Error(`${code} (HTTP ${response.status})`);
      }
      return body;
    } finally { this.requests.delete(controller); }
  }

  async restore() {
    const generation = this.generation;
    const session = await this.request('/api/session', {}, false);
    if (generation !== this.generation) throw new Error('Session changed; response discarded.');
    if ((session.authenticated !== true && session.authenticated !== false) ||
        (session.authenticated && (typeof session.user !== 'string' || !session.user))) {
      throw new Error('Invalid session response.');
    }
    this.user = session.authenticated ? session.user : null;
    this.onChange(this.user);
  }

  async login(username, password) {
    const generation = this.generation;
    await this.request('/api/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password })
    }, false);
    if (generation !== this.generation) throw new Error('Session changed; response discarded.');
    await this.restore();
    if (!this.user) throw new Error('Sign-in did not establish an operator session.');
  }

  async logout() {
    this.clear();
    await this.request('/api/logout', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
    }, false);
  }
}
