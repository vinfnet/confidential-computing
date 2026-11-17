import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { generate } from 'selfsigned';
import { promisify } from 'node:util';
import { ephemeralTls, tlsOptions } from '../src/server.js';

test('production never falls back to ephemeral TLS; incomplete or malformed material is rejected', async () => {
  await assert.rejects(tlsOptions({ tailspinUrl: 'https://tailspin.example' }), /Production TLS material/);
  await assert.rejects(tlsOptions({ tlsKeyB64: 'a' }), /Both TLS values/);
  await assert.rejects(tlsOptions({ tlsKeyB64: '%%%', tlsCertB64: '%%%' }), /TLS encoding/);
  await assert.rejects(tlsOptions({
    tailspinUrl: 'https://tailspin.example',
    tlsKeyB64: Buffer.from('not a private key').toString('base64'),
    tlsCertB64: Buffer.from('not a certificate').toString('base64')
  }), /Invalid TLS material/);
});

test('real ephemeral HTTPS certificate serves TLS and validates its own SAN', async (t) => {
  const options = await ephemeralTls({ tailspinUrl: 'https://tailspin.example' });
  const supplied = await tlsOptions({
    tailspinUrl: 'https://tailspin.example',
    tlsKeyB64: options.key.toString('base64'), tlsCertB64: options.cert.toString('base64')
  });
  assert.deepEqual(supplied, options);
  await assert.rejects(tlsOptions({
    tailspinUrl: 'https://wrong.example',
    tlsKeyB64: options.key.toString('base64'), tlsCertB64: options.cert.toString('base64')
  }), /Invalid TLS material/);
  const certificate = new X509Certificate(options.cert);
  assert.equal(certificate.checkHost('tailspin.example'), 'tailspin.example');
  assert.equal(certificate.checkHost('localhost'), 'localhost');
  assert.equal(certificate.checkIP('127.0.0.1'), '127.0.0.1');
  assert.equal(certificate.issuer, certificate.subject);
  assert.ok(certificate.verify(certificate.publicKey));
  assert.equal(certificate.ca, false);
  assert.equal(options.minVersion, 'TLSv1.2');
  const server = https.createServer(options, (_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end('{"ready":true}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await new Promise((resolve, reject) => {
    const request = https.get({
      hostname: '127.0.0.1', port: server.address().port, ca: options.cert
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    request.on('error', reject);
  });
  assert.deepEqual(response, { status: 200, body: '{"ready":true}' });
});

test('development TLS generation needs no filesystem write permission', async () => {
  const moduleUrl = new URL('../src/server.js', import.meta.url).href;
  const { stdout } = await promisify(execFile)(process.execPath, [
    '--experimental-permission', '--allow-fs-read=*', '--input-type=module', '-e',
    `import { ephemeralTls } from ${JSON.stringify(moduleUrl)};
     const result = await ephemeralTls({ tailspinUrl: 'https://tailspin.example' });
     if (!result.key.length || !result.cert.length) process.exit(1);
     console.log('generated-without-writes');`
  ], { timeout: 30000, windowsHide: true });
  assert.equal(stdout.trim(), 'generated-without-writes');
});

test('deployment-supplied CA-signed TLS is verifiable by another HTTPS client without bypass', async (t) => {
  const authority = await generate([{ name: 'commonName', value: 'Tailspin Test Demo CA' }], {
    keySize: 2048, algorithm: 'sha256', extensions: [
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }
    ]
  });
  const certificate = await generate([{ name: 'commonName', value: 'tailspin.example' }], {
    keySize: 2048, algorithm: 'sha256',
    ca: { key: authority.private, cert: authority.cert },
    extensions: [
      { name: 'basicConstraints', cA: false, critical: true },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames: [
        { type: 2, value: 'tailspin.example' }, { type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }
      ] }
    ]
  });
  const leaf = Buffer.from(certificate.cert);
  const key = Buffer.from(certificate.private);
  const ca = Buffer.from(authority.cert);
  const options = await tlsOptions({
    tailspinUrl: 'https://tailspin.example',
    tlsKeyB64: key.toString('base64'), tlsCertB64: leaf.toString('base64')
  });
  const server = https.createServer(options, (_req, res) => res.end('verified HTTPS'));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const body = await new Promise((resolve, reject) => {
    https.get({
      hostname: '127.0.0.1', port: server.address().port, ca,
      servername: 'tailspin.example', rejectUnauthorized: true
    }, (response) => {
      assert.equal(response.socket.authorized, true);
      let text = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => resolve(text));
    }).on('error', reject);
  });
  assert.equal(body, 'verified HTTPS');
});
