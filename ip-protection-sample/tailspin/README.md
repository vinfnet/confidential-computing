# Tailspin Toys confidential control room

Node 22 ESM application. `npm ci`, `npm test`, `npm start`. No build step,
CDN, Entra registration, client secret, storage account, or Azure deployment is needed to run
the tests. The parent-provided `../auth/operator.mjs` is required for password/session
integration tests and production. Production also needs the confidential-container deployment,
managed identity, release sidecar, approved worker template and Key Vault keys.

## Trust and demonstration boundaries

Tailspin is the **trusted command source**: this process creates fictional toy
airplane instructions in memory before encrypting them. This is not a claim that
plaintext never exists at the author. Neither plaintext commands nor DEKs are
returned by any API, rendered by the UI, or logged. A new random 256-bit DEK
encrypts each generation with AES-256-GCM and is zeroed in a `finally` block,
alongside the command buffer. JavaScript and crypto runtimes cannot guarantee
erasure of internal copies or immutable strings.

The worker's **public** versioned Key Vault RSA key wraps the DEK locally with
RSA-OAEP/SHA-256. Tailspin never requests the worker private JWK. Only the worker
TEE should release that key under the exact externally generated CCE policy.

Tailspin separately releases `SELF_KEY_NAME` through the local sidecar at startup
and every 10 seconds. Only a recent successful release permits sensitive routes;
stale requests synchronously retry and fail closed. The RSA private JWK is
validated and discarded, never cached or used to decrypt worker instructions.
This is a **real sidecar key-release gate**, not an invented attestation check.
MAA and Key Vault enforce the external release policy. A failed gate does not
silently fall back to plaintext HTTP or bypass authentication. The public UI,
minimal health endpoint and authenticated historical dashboard remain accessible
during release failure or refresh; command generation, challenge issuance,
telemetry acceptance and lifecycle actions remain blocked. Read-only access is
not represented as successful key release.

Cycle latency is measured by the worker, process uptime is worker-reported
elapsed process time (floored to integer seconds), and completed cycles are the
worker's actual completed demo-cycle counter. **Only defect rate is synthetic**.
These are **signature-verified worker reports, not independently proven
measurements or evidence of physical manufacturing**. The commands themselves
remain fictional demonstration instructions. Dashboard HTTP receipt timestamps
and stale-heartbeat state are real. Protected sample percentage is
the proportion of received, attested samples reporting `protected` in the last
hour, **not wall-clock uptime or an SLA**. Before any real samples, availability
and heartbeat are unknown. Missing heartbeats do not prove compromise.

Telemetry and security history are bounded to 500 entries each, in memory only.
A process restart loses history. `GET /api/dashboard` exposes per-field
`metricProvenance` (`latencyMs: "worker-reported-measured"`,
`uptimeSeconds: "worker-reported-process"`,
`completedCycles: "worker-reported-count"`, `state: "worker-reported"`,
`defectRate: "synthetic"`) and a `metricAssurance` explanation, rather than a
blanket synthetic-performance flag. No security tokens, key material, upstream
response bodies, or command plaintext are logged to stdio. This initial demo is
not a durable audit system. A production system also needs trusted TLS,
ingress rate limiting, durable auditing, monitoring and incident procedures.

## Configuration

| Environment variable | Meaning |
|---|---|
| `AZURE_CLIENT_ID` | Required user-assigned managed identity client UUID; used with `ManagedIdentityCredential`, never a developer credential fallback |
| `OPERATOR_USERNAME` | Required operator username; no default production credentials |
| `OPERATOR_PASSWORD_HASH` | Required password hash in the format validated by the parent-owned shared auth module; supply securely, never a plaintext password |
| `TAILSPIN_URL` | Required public HTTPS origin, no path, query or fragment |
| `WORKER_URL` | Required Contoso worker HTTPS origin |
| `VAULT_URL` | Required Key Vault HTTPS origin |
| `MAA_ENDPOINT` | Required Microsoft Azure Attestation HTTPS origin; trailing slash normalized away |
| `WORKER_POLICY_HASH` | Required 64-character lowercase/uppercase hex CCE-policy hostdata SHA-256; compared exactly after configuration normalization |
| `WORKER_KEY_NAME` | Defaults to `contoso-robot` |
| `SELF_KEY_NAME` | Defaults to `tailspin-control`; must differ from worker key |
| `WORKER_RESOURCE_ID` | Full ARM container-group ID; required for deploy/restart, fixed server-side |
| `WORKER_TEMPLATE_PATH` | Approved container-group PUT body supplied by parent **after** generating policy; defaults to `/app/deploy/worker.json` |
| `WORKER_API_VERSION` | Defaults to `2023-05-01` |
| `TLS_KEY_B64` | Required outside explicit development/test HTTP: base64-encoded PEM private key supplied as ARM secure environment data |
| `TLS_CERT_B64` | Base64-encoded PEM certificate/chain; must match private key, hostname and current validity |
| `NODE_ENV` | Only `development` permits absent TLS material and ephemeral self-signed HTTPS |
| `NODE_EXTRA_CA_CERTS` | Parent sets `/app/certs/demo-ca.crt` to trust its public demo CA for cross-service HTTPS |
| `TEST_HTTP` | Only literal `1` enables HTTP, bound exclusively to `127.0.0.1:8443`; otherwise HTTPS on `0.0.0.0:8443` |

Deployment HTTPS uses the per-application demo-CA-signed certificate and key
provided by `TLS_KEY_B64` and `TLS_CERT_B64`; missing, incomplete, malformed,
mismatched, expired or wrong-host material prevents production startup. Never
commit private keys. The parent copies only the **public** CA into the image and
sets `NODE_EXTRA_CA_CERTS` before Node starts so the worker can verify HTTPS to
Tailspin; no certificate verification bypass is implemented.

For development only, set `NODE_ENV=development` to allow a new self-signed RSA
certificate per process start, with no external executable required.
Development certificates are generated entirely in memory using `selfsigned`
(RSA-3072/SHA-256, one-day validity). No key, certificate or scratch directory
is written, so a non-root process needs no application-directory write access.
The TLS tests likewise generate their test CA and server certificate in memory.
Production still requires the supplied TLS material; no trust store is modified.

Browser users must explicitly import the deployment's public demo CA into their
own **CurrentUser** trusted certificate store before password sign-in. The app
does not modify machine or user trust stores. Do not use `TEST_HTTP=1` or
`NODE_ENV=development` in an Azure deployment.

## Operator password sessions

The parent owns `../auth/operator.mjs`, imported by the server as
`../../auth/operator.mjs`. The image places it at `/auth/operator.mjs` while
Tailspin runs under `/app/src`. Do not copy a second auth implementation into
Tailspin. `start()` constructs `createOperatorAuth` with `OPERATOR_USERNAME`,
`OPERATOR_PASSWORD_HASH`, the exact Tailspin origin and a sanitized security-event
callback. `createApp` installs it immediately after `express.json` and uses its
`requireOperator` middleware for the dashboard and every management action.
The injected `authenticate` dependency exists only for isolated route tests;
production never selects bearer/Entra authentication.

The public login form submits real credentials over trusted HTTPS:

- `POST /api/login`, JSON `{username,password}`, exact `Origin: <TAILSPIN_URL>`.
- `GET /api/session` returns `{authenticated:boolean,user?:string}`.
- `POST /api/logout`, JSON `{}`, exact Tailspin Origin, invalidates the session.

Shared auth verifies the configured hash, rate-limits attempts and creates
random, in-memory sessions expiring after 30 minutes. Its
`__Host-tailspin-session` cookie is `Secure; HttpOnly; SameSite=Strict; Path=/`
with no Domain. Sessions disappear on process restart. Deploy only behind
trusted HTTPS; explicit test HTTP does not make browser Secure cookies usable
over an ordinary HTTP origin. Tests transport the cookie explicitly.
Provision the verifier with the shared module's `hashPassword` helper: a salted
`scrypt$<32 hex salt>$<128 hex derived key>` string. It requires a password of
16–1024 characters; generate/provision it externally and keep credentials out of
source, images, URLs and logs. A missing or malformed verifier prevents startup.

The browser sends same-origin cookies, never stores a token/password in web
storage, and clears the password input after submission. Logout immediately
clears protected tables, charts, cards and action state, aborts pending requests
and invalidates their generation before contacting the logout endpoint. Late
dashboard/action responses cannot restore a signed-out view. A 401 clears the
view and explicitly requests reauthentication. Failed server logout is shown as
unconfirmed and can be retried; aborting a request cannot cancel an Azure action
already accepted by the server. No MSAL/CDN or Entra interactive flow remains.
Managed identity remains the only credential used for Key Vault and ARM.

## HTTP contracts

All responses have `Cache-Control: no-store`; no CORS allow-origin is emitted.
`GET /api/config` is public and returns only `{tailspinUrl,workerUrl}`;
no username, password hash or credentials are exposed. `GET /api/health` is public and
returns only `{ready:boolean}`, HTTP 200 or 503.

### Encrypted command retrieval

`GET /api/envelope` is public, but release-gated. It returns **only**:

```json
{
  "algorithm": "A256GCM",
  "keyId": "https://<vault>/keys/contoso-robot/<version>",
  "wrappedKey": "<standard base64 RSA-OAEP/SHA256 wrapped 32-byte DEK>",
  "iv": "<standard base64 12-byte IV>",
  "tag": "<standard base64 16-byte GCM authentication tag>",
  "ciphertext": "<standard base64>",
  "aad": "<standard base64 UTF-8 bytes>",
  "sequence": 1,
  "issuedAt": "<ISO8601 UTC>"
}
```

AAD bytes are UTF-8 `JSON.stringify({sequence,issuedAt,keyId})` in that property
order. Use decoded AAD **unchanged** during GCM decryption. Envelopes are cached
for 30 seconds; sequence increases per generation within one process and resets
on restart. Do not treat sequence alone as a globally durable replay counter.

### Verified telemetry

1. `GET /api/challenge` returns `{nonce,expiresAt}`. Nonce is 32 random bytes,
   base64url, valid for 60 seconds. At most 2,000 outstanding nonces; saturation
   returns 429. No operator sign-in is required for worker telemetry.
2. The worker gets a fresh MAA token binding its ephemeral RSA **public** JWK in
   `x-ms-runtime.keys` (array, 1–4 keys, 2048–8192 bits, exponent 65537).
3. Worker signs an RS256 JWT with that runtime private key:

```json
{
  "nonce": "<challenge nonce>",
  "metrics": {
    "state": "protected",
    "latencyMs": 42.5,
    "uptimeSeconds": 120,
    "completedCycles": 300,
    "defectRate": 0.01
  },
  "iat": 1800000000,
  "exp": 1800000060
}
```

4. `POST /api/telemetry`, `Content-Type: application/json`, body
   `{attestationToken:"<MAA JWT>",proof:"<RS256 JWT>"}` returns HTTP 202
   `{status:"accepted"}` only after verification and atomic nonce consumption.

MAA JWKS is `${MAA_ENDPOINT}/certs` (the provider's official signing-key endpoint).
Issuer is exactly normalized `MAA_ENDPOINT`; **no audience is assumed**.
Required MAA claims:

| Claim | Required value |
|---|---|
| `x-ms-compliance-status` | `azure-compliant-uvm` |
| `x-ms-sevsnpvm-is-debuggable` | boolean `false` or string `"false"` |
| `x-ms-sevsnpvm-hostdata` | exact configured policy hash |
| `x-ms-attestation-type` | `sevsnpvm` |
| `x-ms-runtime.keys` | bound public RSA JWK array, no private members |

MAA `iat` must be at most 90 seconds old and its signed `exp` must be unexpired;
MAA controls that token's lifetime, so a longer service-issued expiry is not
mistaken for fresh evidence. Proof `iat` age and lifetime are at most 60 seconds. Both must be unexpired;
future issuance allows at most 5 seconds clock skew. Synchronize clocks. Metrics
have exactly the five shown properties; state is `protected` or `unavailable`;
latency is 0–3,600,000 ms; uptime is an integer 0–315,360,000 seconds; cycles an
integer 0–1e12; defect rate is a fraction 0–1. Non-finite values, strings, unknown
properties, arbitrary commands and secrets are rejected. No raw tokens or
claims are stored in the dashboard history.
Rejected evidence records contain only allowlisted failure identifiers (for
example `attestation_policy_mismatch`, `invalid_proof` or
`nonce_expired_or_replayed`). Raw token text and exception messages are never
copied into events, and failed verification never creates a verified event,
heartbeat or metric record.

### Sidecar hostnames

The loopback key-release request is:

```json
{
  "maa_endpoint": "<provider>.attest.azure.net",
  "akv_endpoint": "<vault>.vault.azure.net",
  "kid": "tailspin-control"
}
```

Both endpoint values are **hostnames, without `https://`**; the sidecar source
constructs `https://%s/attest/...` and `https://%s/keys/.../release`.
`MAA_ENDPOINT` and `VAULT_URL` remain HTTPS origins in app configuration; hostname
conversion applies only to the loopback sidecar request. Verification/JWKS calls
continue to use the full HTTPS MAA origin.
The release response must be a complete private RSA JWK, either top-level or
under `key`. Both object JWKs and the sidecar's `{key:"<JSON JWK string>"}` form
are accepted (including a top-level JSON JWK string). Malformed strings fail
closed with a sanitized error. The validated private JWK is immediately discarded.

### Management

`POST /api/actions/deploy`, `/restart`, `/revoke` require a valid operator
session cookie, **exact** `Origin: <TAILSPIN_URL>`, JSON content type and body `{}`.
User input cannot supply a template, resource target, token, or key name.

- Deploy reads the server's approved JSON file, checks `properties.sku: "Confidential"` and
  nonempty `properties.confidentialComputeProperties.ccePolicy`, then PUTs the
  **exact file body** to the configured ARM resource. It does not generate or
  alter policy. Trust/integrity of the mounted approved template is external.
  `properties.sku: "Standard"` and top-level-only `sku` are rejected.
  The parent supplies the actual resource PUT body, stripping ARM template
  wrapper fields such as `type`, `name` and `apiVersion` before mounting it.
- Restart POSTs the configured container group's `/restart`.
- Revoke enumerates **all key versions**, disables every version not already
  explicitly disabled, and invalidates the envelope cache before and after the
  attempt. Partial errors return failure, not success. Already released keys
  **cannot be recalled**; restart the worker and observe heartbeat behavior.
- Management uses only managed identity's ARM token or KeyClient data-plane
  authorization. Grant least-privilege rights on this demo worker and vault.

Successful requests return **HTTP 202**, with
`{status:"accepted",operation,upstreamStatus}` for ARM or
`{status:"accepted",operation:"revoke",disabledVersions,detail}` for key disable.
ARM acceptance is **not provisioning success**; completion must be checked in
Azure. Error responses include only safe error identifiers and sanitized HTTP
status codes, never upstream response text or Azure operation URLs.
The dashboard optionally reads public key enabled status every 30 seconds.
It does not poll ARM provisioning state or long-running operation URLs.

## Verification

`npm test` uses `node:test` and DI. Tests exercise actual RSA/AES encryption and
tamper rejection, real attestation JWT signatures, password/cookie sessions,
MAA claims/freshness/runtime-key possession, replay and bounded challenges,
metric validation, release-gate expiry/failure, all-version revocation,
approved-template/exact ARM bodies, security headers, logout/expiry and
HTTP route behavior. Azure dependencies are injected; tests do not deploy.
The parent's transport-key bootstrap may import `src/server.js`, populate
`TLS_KEY_B64`/`TLS_CERT_B64`, then explicitly call its exported `start()`.
Importing the module alone does not start the listener or load configuration.

References:

- https://learn.microsoft.com/en-us/azure/attestation/claim-sets
- https://learn.microsoft.com/en-us/azure/attestation/basic-concepts
- https://learn.microsoft.com/en-us/azure/container-instances/confidential-containers-attestation-concepts
- https://learn.microsoft.com/en-us/javascript/api/@azure/keyvault-keys/keyclient
- https://github.com/microsoft/confidential-sidecar-containers/blob/main/pkg/common/maa.go
- https://github.com/microsoft/confidential-sidecar-containers/blob/main/pkg/common/akv.go
