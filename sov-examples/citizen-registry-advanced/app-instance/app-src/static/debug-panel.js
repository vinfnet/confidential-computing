(() => {
  const init = panel => {
    const button = document.querySelector(`[data-debug-open="${panel.dataset.debugId}"]`);
    const close = panel.querySelector('[data-debug-close]');
    const pause = panel.querySelector('[data-debug-pause]');
    const refresh = panel.querySelector('[data-debug-refresh]');
    const level = panel.querySelector('[data-debug-level]');
    const metrics = panel.querySelector('[data-debug-metrics]');
    const log = panel.querySelector('[data-debug-log]');
    let timer;
    let paused = false;
    const render = async () => {
      try {
        const telemetry = await (await fetch('/api/debug/telemetry', { cache: 'no-store' })).json();
        const c = telemetry.components || {};
        metrics.replaceChildren(...Object.entries({
          'Database': `${c.database?.status || 'unknown'} · ${c.database?.record_count ?? '-'} records`,
          'GPU': `${c.gpu?.status || 'unknown'} · ${c.gpu?.model || '-'}`,
          'CC mode': c.gpu?.confidential_compute || 'unknown',
          'Media': `${c.media?.state || 'unknown'} · ${c.media?.percent ?? 0}%`,
          'CCTV': `${c.cctv?.state || 'unknown'} · ${c.cctv?.processing_fps ?? '-'} fps`,
        }).flatMap(([name, value]) => { const dt = document.createElement('dt'); dt.textContent = name; const dd = document.createElement('dd'); dd.textContent = value; return [dt, dd]; }));
        const logs = await (await fetch(`/api/debug/logs?level=${level.value}&limit=100`, { cache: 'no-store' })).json();
        log.textContent = logs.logs?.map(item => `${item.timestamp} ${item.level} ${item.component}: ${item.message}`).join('\n') || 'No sanitized activity events.';
        log.scrollTop = log.scrollHeight;
      } catch { log.textContent = 'Diagnostics unavailable.'; }
    };
    const schedule = () => { window.clearInterval(timer); if (!paused) timer = window.setInterval(render, 3000); };
    button?.addEventListener('click', () => { panel.hidden = false; render(); schedule(); });
    close.addEventListener('click', () => { panel.hidden = true; window.clearInterval(timer); });
    pause.addEventListener('click', () => { paused = !paused; pause.textContent = paused ? 'Resume' : 'Pause'; schedule(); });
    refresh.addEventListener('click', render);
    level.addEventListener('change', render);
  };
  document.querySelectorAll('[data-debug-panel]').forEach(init);
})();
