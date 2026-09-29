# Confidential CCTV Demo Video

This independent package records and renders a two-minute privacy-preserving CCTV demonstration at 1920x1080 and 30 fps. It shows a one-camera Azure architecture, unchanged raw evidence in private storage, confidential H100 face detection, synchronized source and anonymized playback, live processing evidence, and the separate reviewer output.

The browser recording uses the deployed Republic of Contoso sample. The source footage is a CC BY-SA 4.0 London Marathon extract credited in the application. The camera context is simulated. The privacy-gap, verifiable-trust, controlled-disclosure, and output-minimization framing is based on `The Privacy Gap in Conventional Video Analytics`.

## Prerequisites

- The Bastion tunnel and live application are available at `https://localhost:9999`.
- The CCTV worker reports `processing`, `running`, or `completed`, with verified current-boot H100 evidence.
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

The command installs pinned dependencies, rehearses all live interactions, synthesizes narration, records exactly 120 seconds, renders the MP4, and runs the media quality gate.

Useful focused commands:

```powershell
npm run analyze
npm run rehearse
npm run narrate
npm run record
npm run render
npm run verify
```

Set `DEMO_BASE_URL` to use another local tunnel endpoint. Generated media, screenshots, manifests, and narration clips are under `output/` and are ignored by Git.

## Outputs

- `output/confidential-cctv-anonymization-demo.mp4`: presentation and upload copy.
- `output/confidential-cctv-anonymization-demo-master.mp4`: archival master with English soft captions.
- `output/captions.vtt`: caption sidecar.
- `output/narration.wav`: 48 kHz narration timeline.
- `output/run-manifest.json`: sanitized action and endpoint checks.
- `output/screenshots/`: section and failure checkpoints.

## Privacy Boundary

The original source remains separate from the anonymized output. GPU-accelerated MTCNN face detection runs on the attested H100. FFmpeg decoding and encoding, temporal tracking, and Gaussian blur run inside the AMD SEV-SNP-protected Application Confidential VM. Routine reviewers receive the resulting HLS output through that CVM.

The demo describes the output as de-identified for routine review. It does not claim legal certification or immunity from every possible re-identification technique.