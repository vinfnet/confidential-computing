# 3‑Minute Demo Script — Contoso ships to the cloud and keeps control of its IP

**Scenario:** Contoso wants developers to ship application changes to the cloud
continuously, while keeping control of its intellectual property end to end. The
source, the build system, and the running workloads should stay within a
boundary Contoso owns and can verify.

The demo covers that path: a **private Azure DevOps Server** with no public
internet exposure drives a pipeline that builds and deploys onto **confidential
computing** hardware. The workload will not run on infrastructure that cannot
prove it is genuine confidential hardware.

---

## How to read this script

- **DO** = what you show on screen.
- **SAY** = read aloud, word for word.
- Total spoken time ≈ **3 minutes**.
- **Set up first:** deploy both versions (Standard and Confidential) *before*
  you present, so you narrate against finished results and nothing hangs on a
  live build.

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
> Note this one parameter: the SKU switch, Standard or Confidential. That selects
> ordinary cloud hardware or confidential hardware. We'll run both."

---

## 3. Ordinary hardware fails — 1:10 to 1:50

**DO:** Show the app that was deployed to **Standard** ACI. Open its URL. Click
**Attest**.

**SAY:**
> "First the ordinary path: the app deployed to Standard hardware, with no
> confidential guarantees. It starts and the page loads. Now it tries to prove
> where it's running."

**DO:** The **Attest** button returns an error — no token.

**SAY:**
> "It can't. Ordinary hardware can't produce a hardware attestation, so Azure
> Attestation won't issue a token. The app runs, but it can't prove it's running
> in a trusted environment. That's the behaviour we want to rely on."

---

## 4. Confidential hardware succeeds — 1:50 to 2:30

**DO:** Switch to the app deployed to **Confidential** (SEV‑SNP) ACI. Click
**Attest**, and show the returned token / claims.

**SAY:**
> "Same app, this time on Confidential hardware. At deploy time the pipeline
> fingerprints the container and pins a policy for exactly what's allowed to run,
> so the image can't be substituted.
>
> This time attestation succeeds. The token is signed by the AMD hardware root of
> trust and confirms genuine confidential hardware running this specific workload.
> It's a cryptographic check rather than a configuration setting."

---

## 5. Why this keeps Contoso in control — 2:30 to 2:55

**DO:** Show the Secure Key Release idea — the sibling
[`secretapp-helloworld`](../secretapp-helloworld/README.md) example, or a simple
"key vault → attestation → key" slide.

**SAY:**
> "This is what connects it to the data. Contoso's keys sit in a vault that only
> releases them when attestation succeeds. On ordinary hardware there's no token,
> so no key is released and the app has nothing to work with. On confidential
> hardware the token is issued, the key is released, and the app runs.
>
> Enforcement is in the hardware and the vault, not in pipeline configuration, so
> the IP can only run where its environment can be verified."

---

## 6. Close — 2:55 to 3:00

**DO:** Back to the title or an architecture diagram.

**SAY:**
> "A private pipeline, a confidential build, and attestation‑gated secrets.
> Contoso ships continuously and keeps control of its IP from source to running
> workload."

---

## Quick reference — what the audience should remember

| | Standard hardware | Confidential hardware |
| --- | --- | --- |
| Can it prove where it runs? | **No** | **Yes** (SEV‑SNP token) |
| Does it get the keys to the data? | **No** | **Yes** |
| Result | App is **inert** | App runs **with** its data |

**The one‑liner:** *No attestation, no key, no run.* Enforcement lives in the
hardware and the vault — from private source, through confidential build, to a
workload that only runs on a verifiable environment.

## Presenter tips

- Tight on time? Skip straight from section 2 to the two finished apps — the
  Standard failure and the Confidential success are the only two things you must
  show.
- The line that lands the message is in section 5: **no token → no key → the app
  is inert.**
- Keep both apps deployed and open in tabs beforehand so nothing waits on a build.
