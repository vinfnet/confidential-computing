# Citizen Registry Demo Video

This package records and renders the exact three-minute-thirty-second sovereignty demo at 1920x1080 and 30 fps. It opens on the logical architecture overview, then uses a clean Playwright Chromium context, Azure Speech `en-GB-RyanNeural` narration, WebVTT captions, and FFmpeg H.264/AAC composition.

The Data Sovereignty sequence clicks a citizen portrait, waits for the simulated passport image that is visibly marked as a fictional credential, holds it, closes it, and continues to employment and tax history. The Citizen Help sequence shows the guarded query flow through the Application CVM, Database CVM, confidential H100, and back through the Application CVM to the browser.

## Prerequisites

- The Bastion tunnel and live application are available at `https://localhost:9999`.
- Node.js, npm, FFmpeg, and ffprobe are on `PATH`.
- Azure CLI is signed in to the target tenant and the identity has `Cognitive Services Speech User` on the Speech account.
- Local authentication is disabled on the Speech account; no keys are used or stored.

## Generate

From this directory:

```powershell
.\Create-DemoVideo.ps1 `
	-SpeechResourceId '/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<speech-account-name>' `
	-SpeechEndpoint 'https://<speech-account-name>.cognitiveservices.azure.com/' `
	-TenantId '<tenant-id>'
```

The command installs pinned dependencies, rehearses all live interactions, synthesizes narration, records exactly 210 seconds, renders the MP4, and runs the media quality gate.

Useful focused commands:

```powershell
npm run analyze
npm run rehearse
npm run narrate
npm run record
npm run render
npm run verify
```

Set `DEMO_BASE_URL` to use another local tunnel endpoint. Generated media, screenshots, manifests, traces, and local Speech configuration are under `output/` and are ignored by Git.

## Outputs

- `output/citizen-registry-sovereignty-demo.mp4`: presentation and upload copy.
- `output/citizen-registry-sovereignty-demo-master.mp4`: archival master with English soft captions.
- `output/captions.vtt`: caption sidecar.
- `output/narration.wav`: 48 kHz narration timeline.
- `output/run-manifest.json`: sanitized action and endpoint checks.
- `output/screenshots/`: section and failure checkpoints.