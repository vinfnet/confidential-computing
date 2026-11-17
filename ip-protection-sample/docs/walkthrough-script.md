# Outsourced manufacturing, protected IP

**Length:** 58 seconds (55.12 seconds of narration, followed by a closing hold). **Voice:** Azure AI Speech,
`en-US-AvaMultilingualNeural` (AI-generated narration). Natural-paced English,
with no voice impersonation or background music.

## Narration

> Tailspin Toys owns the toy-line designs and manufacturing instructions:
> its intellectual property. Contoso is the subcontractor, operating
> the robots, printers, and infrastructure.
> Tailspin sends encrypted instructions. Encryption in use protects them
> in confidential-container memory while approved code processes them.
> Attestation checks the runtime. Secure key release makes Tailspin's keys
> available only to the approved identity and exact measured container policy.
> Contoso engineers operate the infrastructure, but cannot open a shell
> into this protected workload.
> Now Tailspin revokes command-key access. The key is disabled.
> Further key release fails. When the app detects this, plaintext commands
> disappear and the fictional line locks. Ciphertext and status remain available.
> Tailspin owns the IP and controls permission to process it.

## Visual direction

| Time | Picture and message |
|---|---|
| 00:00.000-00:06.274 | The toy-line designs and manufacturing IP belong to Tailspin Toys. |
| 00:06.274-00:11.850 | Contoso owns and operates the machines. Not Tailspin's IP. |
| 00:11.850-00:20.469 | Protected during processing. Not just at rest or in transit. |
| 00:20.469-00:30.082 | Hosting the container does not entitle Contoso engineers to its keys. |
| 00:30.082-00:36.265 | Contoso engineers manage infrastructure, not the protected guest shell. |
| 00:36.265-00:39.274 | Now Tailspin selects Revoke key access. |
| 00:39.274-00:43.064 | KEY ACCESS REVOKED. The command key is DISABLED. |
| 00:43.064-00:46.264 | Plaintext commands are gone. Only ciphertext remains. |
| 00:46.264-00:48.338 | No command plaintext. The fictional production line locks. |
| 00:48.338-00:51.467 | The service stays reachable. Tailspin's commands stay locked. |
| 00:51.467-00:58.000 | Tailspin Toys owns the toy-line IP and controls permission to process it. |

The video uses full-HD framing with normal browser zoom and a dedicated
450-pixel-high commands panel, scrolling at approximately 60 pixels/second.
It combines edited real app captures with an explicitly labeled
recorded-evidence replay. The factory animation and robot commands are
fictional; no machinery is connected. A Tailspin-authorized browser can
receive plaintext; this is not a Contoso host-administrator view.
Revocation banners are editorial labels over verified footage, not mock app
controls. Routine fail-closed refresh pauses are shortened in the motion edit.
Deployment-specific key URIs are permanently covered by opaque pixel redactions,
not blurred or replaced with fictional endpoints. Evidence also withholds
deployment names, operation identifiers and exact policy fingerprints; matching
redacted labels are not deployable SHA-256 values. Recorded security states,
responses, timings, commands and ciphertext are otherwise unchanged.

Both organizations are simulated in one tenant. This demonstrates measured
runtime enforcement and fail-closed key access, not absolute isolation from
privileged tenant/subscription or Tailspin policy administrators. Revocation
cannot recall already released keys or promise perfect memory erasure. The
worker clears plaintext after a failed release or expired 12-second lease;
there is no instantaneous-revocation or hard-erasure guarantee.

Original key states are restored administratively after capture, outside the
story; no product Restore button is implied.

[Watch the narrated video](media/ip-protection-walkthrough.mp4) |
[WebVTT captions](media/ip-protection-walkthrough.vtt)
