# 3‑Minute Demo Script — Contoso ships to the cloud, and keeps its IP

**The story:** Contoso wants its developers to ship application changes to the
cloud continuously — but Contoso must keep **full control of its intellectual
property**, end to end. Their source, their build system, and their running
workloads must never leave a boundary they own and can prove.

This demo shows how they do it: a **private Azure DevOps Server** (no public
internet exposure) drives a pipeline that builds and deploys onto **confidential
computing** hardware — and the workload simply **won't run** anywhere that can't
prove it's genuine confidential infrastructure.

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
> "Contoso wants to move fast — developers pushing app changes to the cloud every
> day. But Contoso's code and data *are* the business. They can't hand that IP to
> a public service they don't control, and they can't risk it running on
> infrastructure where someone else could see inside.
>
> So they need two things at once: **continuous delivery**, and **end‑to‑end
> control of their IP**. Let's see how they get both."

---

## 2. The private pipeline — 0:30 to 1:10

**DO:** Show the Azure DevOps Server project, then open `azure-pipelines.yml`.
Point out the `confidential-build-pool`.

**SAY:**
> "Everything you're looking at lives on Contoso's **own** Azure DevOps Server.
> It has **no public IP** — developers reach it privately. The source never
> leaves Contoso's network.
>
> When a developer pushes a change, this pipeline builds the container and
> deploys it — and it runs on Contoso's **confidential build agents**, which are
> themselves running inside secure enclaves. So the code is protected not just at
> rest, but **while it's being built**.
>
> One line to notice: this **SKU** switch — Standard or Confidential. That's the
> difference between ordinary cloud hardware and confidential hardware. Let's try
> both and see what happens."

---

## 3. Ordinary hardware fails — 1:10 to 1:50

**DO:** Show the app that was deployed to **Standard** ACI. Open its URL. Click
**Attest**.

**SAY:**
> "First, the ordinary path. Here's the app deployed to **Standard** hardware —
> regular cloud, no confidential guarantees. It starts, the page loads… now watch
> when it tries to prove where it's running."

**DO:** The **Attest** button returns an error — no token.

**SAY:**
> "It can't. On ordinary hardware there's no way to produce a hardware
> attestation, so Azure Attestation refuses to vouch for it. The app is running,
> but it **can't prove it's trustworthy** — and that failure is the whole point."

---

## 4. Confidential hardware succeeds — 1:50 to 2:30

**DO:** Switch to the app deployed to **Confidential** (SEV‑SNP) ACI. Click
**Attest**, and show the returned token / claims.

**SAY:**
> "Now the exact same app, deployed to **Confidential** hardware. During deploy,
> the pipeline fingerprints the container and locks in a policy for exactly what's
> allowed to run — so nothing can be swapped in behind Contoso's back.
>
> And this time, **Attest succeeds**. Here's a live token, signed by the AMD
> hardware root of trust, proving genuine confidential hardware running *exactly*
> this workload. That's Contoso's proof — cryptographic, not a checkbox."

---

## 5. Why this keeps Contoso in control — 2:30 to 2:55

**DO:** Show the Secure Key Release idea — the sibling
[`secretapp-helloworld`](../secretapp-helloworld/README.md) example, or a simple
"key vault → attestation → key" slide.

**SAY:**
> "Here's what ties it together. Contoso's secrets — the keys to its data — sit in
> a vault that only releases them **when attestation succeeds**. So on ordinary
> hardware: no proof, no token, **no key**, and the app is inert. On confidential
> hardware: proof, token, key — it just works.
>
> Nobody has to remember to tick a box. The **hardware** enforces it. Contoso's IP
> can only ever run where Contoso can prove it's safe."

---

## 6. Close — 2:55 to 3:00

**DO:** Back to the title or an architecture diagram.

**SAY:**
> "Private pipeline, confidential build, attestation‑gated secrets. Contoso ships
> every day — and keeps full control of its IP, end to end."

---

## Quick reference — what the audience should remember

| | Standard hardware | Confidential hardware |
| --- | --- | --- |
| Can it prove where it runs? | **No** | **Yes** (SEV‑SNP token) |
| Does it get the keys to the data? | **No** | **Yes** |
| Result | App is **inert** | App runs **with** its data |

**The one‑liner:** *No proof → no key → nothing runs.* Contoso's IP is protected
by the hardware itself — from private source, through confidential build, to a
workload that can only run on infrastructure it trusts.

## Presenter tips

- Tight on time? Skip straight from section 2 to the two finished apps — the
  Standard failure and the Confidential success are the only two things you must
  show.
- The line that lands the message is in section 5: **no token → no key → the app
  is inert.**
- Keep both apps deployed and open in tabs beforehand so nothing waits on a build.
