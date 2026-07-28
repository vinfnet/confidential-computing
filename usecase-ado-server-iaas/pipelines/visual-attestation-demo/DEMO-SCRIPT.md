# 3‑Minute Demo Script — Contoso ships to the cloud and keeps control of its IP

**Scenario:** Contoso wants developers to ship application changes to the cloud
continuously, while keeping control of its intellectual property end to end. The
source, the build system, and the running workloads should stay within a
boundary Contoso owns and can verify.

The demo covers that path: a **private Azure DevOps Server** with no public
internet exposure drives a pipeline that builds and deploys onto **Azure
confidential computing**. The point of the demo is the **control and evidence**
Contoso gets — hardware‑backed proof of exactly what is running and where, and
keys that are released only against that proof.

---

## How to read this script

- **DO** = what you show on screen.
- **SAY** = read aloud, word for word.
- Total spoken time ≈ **3 minutes**.
- **Set up first:** deploy the Confidential version (and, if you want the
  optional contrast in section 5, the Standard version) *before* you present, so
  you narrate against finished results and nothing hangs on a live build.

---

## 1. The problem — 0:00 to 0:30

**DO:** Title slide, or the Contoso Azure DevOps project home page.

**SAY:**
> "Contoso's developers ship application changes to the cloud regularly. The code
> and the data are core IP, so Contoso doesn't want to hand them to a public
> service it doesn't control, or run them on infrastructure where the platform
> operator could see inside.
>
> The requirement is two things together: continuous delivery, and control of the
> IP end to end. Here's how that's set up."

---

## 2. The private pipeline — 0:30 to 1:10

**DO:** Show the Azure DevOps Server project, then open `azure-pipelines.yml`.
Point out the `confidential-build-pool`.

**SAY:**
> "This runs on Contoso's own Azure DevOps Server. It has no public IP, so
> developers reach it privately and the source stays inside Contoso's network.
>
> When a developer pushes a change, the pipeline builds the container and deploys
> it. The build itself runs on confidential agents — inside enclaves — so the
> code is protected while it's being built, not just at rest.
>
> The pipeline targets Azure confidential computing. Let's look at the evidence
> that gives Contoso."

---

## 3. The evidence confidential computing produces — 1:10 to 2:00

**DO:** Open the app deployed to **Confidential** (SEV‑SNP) ACI. Click
**Attest** and show the returned token / claims.

**SAY:**
> "This is the app running on Azure confidential computing. When it attests, it
> produces a hardware‑signed report — here are the claims.
>
> The token is signed by the AMD hardware root of trust. It confirms the workload
> is running inside a genuine SEV‑SNP enclave, with secure boot, and it includes a
> measurement of exactly this container. At deploy time the pipeline generates an
> enforcement policy — a CCE policy — directly from the image it just built, and
> the hardware enforces it at launch.
>
> That policy is what makes the report trustworthy end to end. Suppose someone
> tampered with a build runner, edited a pipeline or deployment config file, added
> a sidecar, mounted an extra volume, or swapped the image — any of that changes
> the measurement, so it no longer matches the policy and the enclave won't start,
> or won't attest to the value Contoso expects. The container that runs can only
> be the one Contoso built; it can't be substituted or quietly modified.
>
> That's the shift: instead of trusting the runners, the config, and the
> infrastructure operator, Contoso has cryptographic evidence of exactly what's
> running, on every run."

---

## 4. Evidence becomes control — keys follow the proof — 2:00 to 2:35

**DO:** Show the Secure Key Release idea — the sibling
[`secretapp-helloworld`](../secretapp-helloworld/README.md) example, or a simple
"key vault → attestation → key" slide.

**SAY:**
> "That evidence isn't just for auditing — it's what gates access to the data.
> Contoso's keys sit in a vault with a release policy tied to the attestation. The
> vault checks the report and only releases the key when the measurement and the
> environment match what Contoso approved.
>
> So Contoso decides, in policy, the exact conditions under which its IP can be
> unlocked — and the hardware and the vault enforce that decision. The control
> sits with Contoso, not with the operator of the infrastructure."

---

## 5. The baseline for contrast — 2:35 to 2:50

**DO:** Briefly show the same app deployed to **Standard** ACI. Click **Attest**
— no token.

**SAY:**
> "For contrast, the same app on ordinary hardware can't produce that report, so
> the vault has nothing to verify and the key stays sealed. Same code — but
> without the evidence, no access to the data."

---

## 6. Close — 2:50 to 3:00

**DO:** Back to the title or an architecture diagram.

**SAY:**
> "A private pipeline, a confidential build, and hardware‑backed evidence tied to
> key release. Contoso ships continuously, and gets verifiable proof and policy
> control over its IP on every run — from source to running workload."

---

## Quick reference — what the audience should remember

| | Azure confidential computing | Ordinary hardware (baseline) |
| --- | --- | --- |
| Evidence of what's running and where | **Hardware‑signed report** (SEV‑SNP, secure boot, image measurement) | None available |
| Tampering with runners, config, or image | **Detected** — measurement changes, enclave won't launch or attest | Not detectable |
| Who sets the conditions for unlocking data | **Contoso**, via key‑release policy | — |
| Result | Verifiable run; keys released against proof | No report, so keys stay sealed |

**The one‑liner:** Confidential computing gives Contoso **evidence and control** —
hardware‑backed proof of the workload and its environment, with keys released
only on Contoso's terms, from private source through confidential build to a
verifiable running workload.

## Presenter tips

- The demo's centre of gravity is **section 3 (the attestation evidence)** and
  **section 4 (evidence gating key release)** — spend your time there.
- Section 5 (ordinary hardware) is a quick contrast, not the point; keep it to a
  few seconds.
- Tight on time? Show the Confidential attestation claims and the key‑release
  policy; the Standard baseline is optional.
- Keep both apps deployed and open in tabs beforehand so nothing waits on a build.
