import { readFile } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const publicPath = fileURLToPath(new URL('./public/', import.meta.url));
const defaultCertificate = fileURLToPath(new URL('../.generated/certs/demo-ca.crt', import.meta.url));

export function installDemoUi(app, {
  certificatePath = process.env.NODE_EXTRA_CA_CERTS || defaultCertificate
} = {}) {
  app.get('/ui/preferences.js', (_req, res) => res.sendFile('preferences.js', { root: publicPath }));
  app.get('/ui/preferences.css', (_req, res) => res.sendFile('preferences.css', { root: publicPath }));
  app.get('/demo-ca.crt', (_req, res) => {
    res.type('application/x-x509-ca-cert');
    res.download(certificatePath, 'tailspin-demo-ca.crt');
  });
  app.get('/ui/certificate.json', async (_req, res, next) => {
    try {
      const certificate = new X509Certificate(await readFile(certificatePath));
      res.json({
        subject: certificate.subject, fingerprint256: certificate.fingerprint256,
        validFrom: certificate.validFrom, validTo: certificate.validTo
      });
    } catch (error) { next(error); }
  });
}
