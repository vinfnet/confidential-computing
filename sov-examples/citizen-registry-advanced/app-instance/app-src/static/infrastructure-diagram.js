(() => {
  const diagramStates = {
    idle: { text: 'Idle', nodes: { browser: 'Ready', app: 'Waiting', database: 'Protected', hsm: 'Available', gpu: 'CC ON · attested' }, paths: [] },
    request: { text: 'Request moving', nodes: { browser: 'Question sent', app: 'Validating', database: 'Protected', hsm: 'Available', gpu: 'CC ON · attested' }, paths: ['browser-app'] },
    database: { text: 'Retrieving records', nodes: { browser: 'Waiting', app: 'Querying', database: 'Reading records', hsm: 'Available', gpu: 'CC ON · attested' }, paths: ['browser-app', 'app-db'] },
    'hsm-evidence': { text: 'Checking key evidence', nodes: { browser: 'Waiting', app: 'Reading evidence', database: 'Protected', hsm: 'Key evidence', gpu: 'CC ON · attested' }, paths: ['app-hsm'] },
    'gpu-processing': { text: 'Confidential GPU processing', nodes: { browser: 'Waiting', app: 'Bounded context', database: 'Protected', hsm: 'Available', gpu: 'H100 · inference' }, paths: ['app-gpu'] },
    response: { text: 'Response returning', nodes: { browser: 'Answer received', app: 'Returning answer', database: 'Protected', hsm: 'Available', gpu: 'H100 · complete' }, paths: ['gpu-browser'] },
    'cctv-processing': { text: 'CCTV anonymization', nodes: { browser: 'Monitoring', app: 'Streaming HLS', database: 'Protected', hsm: 'Key evidence', gpu: 'Anonymizing faces' }, paths: ['browser-source', 'source-app', 'app-gpu-cctv', 'gpu-browser-cctv'] },
    unavailable: { text: 'Unavailable', nodes: { browser: 'Unavailable', app: 'Unavailable', database: 'Unknown', hsm: 'Unknown', gpu: 'Unavailable' }, paths: [] },
  };

  class InfrastructureDiagram {
    constructor(root) {
      this.root = root;
      this.state = 'idle';
      this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      this.stateElement = root.querySelector('[data-diagram-state]');
      this.replayButton = root.querySelector('[data-diagram-replay]');
      this.nodes = Object.fromEntries([...root.querySelectorAll('[data-node]')].map(node => [node.dataset.node, node]));
      this.paths = Object.fromEntries([...root.querySelectorAll('[data-path]')].map(path => [path.dataset.path, path]));
      this.pulses = [...root.querySelectorAll('[data-pulse-for]')];
      this.root.dataset.flow = root.dataset.flow || 'citizen-help';
      this.lastPaths = [];
      this.replayTimer = null;
      this.setState('idle');
      this.lastPaths = ['browser-app'];
      if (this.replayButton) this.replayButton.disabled = false;
      this.replayButton?.addEventListener('click', () => this.replay());
    }

    setState(state, labels = {}) {
      const next = diagramStates[state] || diagramStates.idle;
      this.state = state;
      this.root.dataset.state = state;
      this.stateElement.textContent = labels.state || next.text;
      this.lastPaths = [...next.paths];
      if (this.replayButton) this.replayButton.disabled = !this.lastPaths.length || Boolean(this.replayTimer);
      Object.entries(next.nodes).forEach(([name, text]) => {
        const node = this.nodes[name];
        if (node) node.querySelector(`[data-label="${name}"]`).textContent = labels[name] || text;
      });
      Object.values(this.nodes).forEach(node => node.classList.remove('is-active', 'is-complete', 'is-unavailable'));
      next.paths.forEach(pathName => {
        const path = this.paths[pathName];
        if (path) path.classList.add('is-active');
      });
      next.paths.forEach(pathName => {
        const endpointNames = pathName.split('-').filter(name => this.nodes[name]);
        endpointNames.forEach(name => this.nodes[name].classList.add('is-active'));
      });
      if (state === 'response' || state === 'cctv-processing') this.nodes.gpu?.classList.add('is-complete');
      if (state === 'unavailable') Object.values(this.nodes).forEach(node => node.classList.add('is-unavailable'));
      this.paths && Object.values(this.paths).forEach(path => { if (!next.paths.includes(path.dataset.path)) path.classList.remove('is-active'); });
      this.pulses.forEach(pulse => {
        pulse.classList.toggle('is-active', !this.reducedMotion && next.paths.includes(pulse.dataset.pulseFor));
      });
    }

    replay() {
      if (this.reducedMotion || !this.lastPaths.length || this.replayTimer) return;
      const replayPaths = [...this.lastPaths];
      Object.values(this.paths).forEach(path => path.classList.remove('is-active'));
      Object.values(this.nodes).forEach(node => node.classList.remove('is-active'));
      replayPaths.forEach(pathName => {
        const path = this.paths[pathName];
        if (path) path.classList.add('is-active');
        pathName.split('-').filter(name => this.nodes[name]).forEach(name => this.nodes[name].classList.add('is-active'));
      });
      this.pulses.forEach(pulse => pulse.classList.toggle('is-active', replayPaths.includes(pulse.dataset.pulseFor)));
      this.root.dataset.replay = 'true';
      this.replayButton.disabled = true;
      this.replayButton.textContent = 'Replaying...';
      this.root.classList.remove('is-replaying');
      void this.root.offsetWidth;
      this.root.classList.add('is-replaying');
      const motions = this.pulses
        .filter(pulse => replayPaths.includes(pulse.dataset.pulseFor))
        .map(pulse => {
          const current = pulse.querySelector('animateMotion');
          const replacement = current.cloneNode(true);
          replacement.setAttribute('dur', '6.25s');
          replacement.setAttribute('repeatCount', '1');
          current.replaceWith(replacement);
          try {
            replacement.beginElement();
          } catch {
            // The CSS replay still provides a visible directional replay.
          }
          return { pulse, motion: replacement };
        });
      this.replayTimer = window.setTimeout(() => {
        motions.forEach(({ pulse, motion }) => {
          const replacement = motion.cloneNode(true);
          replacement.setAttribute('dur', '1.25s');
          replacement.setAttribute('repeatCount', 'indefinite');
          motion.replaceWith(replacement);
          try { replacement.beginElement(); } catch { /* CSS animation remains active. */ }
        });
        this.root.classList.remove('is-replaying');
        this.setState(this.state);
        delete this.root.dataset.replay;
        this.replayButton.disabled = false;
        this.replayButton.textContent = 'Replay path';
        this.replayTimer = null;
      }, 6250);
    }
  }

  window.InfrastructureDiagram = InfrastructureDiagram;
  document.querySelectorAll('[data-infrastructure-diagram]').forEach(root => { root.infrastructureDiagram = new InfrastructureDiagram(root); });
})();
