(() => {
  const key = 'tailspin-demo-theme';
  const system = matchMedia('(prefers-color-scheme: dark)');
  let preference;
  try { preference = localStorage.getItem(key); }
  catch (error) { console.warn('Theme preference could not be read; using system appearance.', error); }
  let theme = ['light', 'dark'].includes(preference) ? preference : system.matches ? 'dark' : 'light';
  const apply = () => { document.documentElement.dataset.theme = theme; };
  apply();
  document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('theme-toggle');
    const status = document.getElementById('appearance-status');
    const label = () => {
      toggle.textContent = theme === 'dark' ? 'Light mode' : 'Dark mode';
      toggle.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`);
      toggle.setAttribute('aria-pressed', String(theme === 'dark'));
      document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#111b2d' : '#f4f6fa');
    };
    label();
    toggle.addEventListener('click', () => {
      theme = theme === 'dark' ? 'light' : 'dark';
      preference = theme;
      apply();
      label();
      try { localStorage.setItem(key, theme); status.textContent = ''; }
      catch (error) {
        console.warn('Theme preference could not be saved.', error);
        status.textContent = 'Appearance changed for this page, but the browser could not save your preference.';
      }
    });
    system.addEventListener('change', () => {
      if (['light', 'dark'].includes(preference)) return;
      theme = system.matches ? 'dark' : 'light';
      apply();
      label();
    });
    const dialog = document.createElement('dialog');
    dialog.id = 'certificate-dialog';
    dialog.setAttribute('aria-labelledby', 'certificate-title');
    dialog.innerHTML = `
      <h2 id="certificate-title">Import the Tailspin demo certificate</h2>
      <p>Websites cannot install trusted certificates automatically. Download the public demo CA, review it, then import it manually.</p>
      <p><a class="certificate-download" href="/demo-ca.crt" download="tailspin-demo-ca.crt">Download public CA certificate (.crt)</a></p>
      <p id="certificate-info" role="status">Loading certificate details...</p>
      <ol>
        <li>Compare the SHA-256 fingerprint below with the local demo CA supplied by the demo owner, using an independent trusted channel.</li>
        <li>For Edge/Chrome on Windows: open browser Settings, search for <strong>Manage certificates</strong>, and open the certificate manager. Import the reviewed CA into <strong>Trusted Root Certification Authorities</strong> for the current user. This can affect other applications using that Windows trust store, not just this site or browser profile. Prefer a disposable test account or VM.</li>
        <li>For Firefox: Settings &gt; Privacy &amp; Security &gt; Certificates &gt; View Certificates &gt; Authorities &gt; Import. Review the CA before enabling website trust.</li>
        <li>Restart the browser if needed and reopen both demo URLs. Remove this demo CA when finished.</li>
      </ol>
      <p>If a certificate warning prevents this page from loading, this button cannot help yet. Obtain <code>demo-ca.crt</code> from the local deployment or the demo owner and import it first. Do not disable TLS verification.</p>
      <p>This download contains only the public CA certificate, never a private key. Trusting a CA authorizes certificates it signs; only trust it in your isolated demo environment.</p>
      <form method="dialog"><button class="button" type="submit">Close</button></form>`;
    document.body.append(dialog);
    document.getElementById('certificate-help').addEventListener('click', async () => {
      dialog.showModal();
      const info = document.getElementById('certificate-info');
      try {
        const response = await fetch('/ui/certificate.json', { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const certificate = await response.json();
        info.textContent = `${certificate.subject}\nSHA-256: ${certificate.fingerprint256}\nValid: ${certificate.validFrom} to ${certificate.validTo}`;
      } catch (error) {
        info.textContent = `Certificate details could not be loaded (${error.message}). Verify the downloaded certificate independently before importing it.`;
      }
    });
  });
})();
