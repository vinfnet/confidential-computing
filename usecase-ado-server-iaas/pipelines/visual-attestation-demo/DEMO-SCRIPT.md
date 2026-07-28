# 3‑Minute Demo Script — "You can't deploy this to the wrong hardware"

A narration guide for the Visual Attestation demo. It shows a CI/CD pipeline in
which an application **cannot** obtain the secrets it needs unless it proves —
via AMD SEV‑SNP attestation — that it is running on genuine confidential
hardware. Deploy it to ordinary infrastructure and it is inert.

**Format:** the left column is what you *do* on screen; the right column is what
you *say*. Total spoken time ≈ 3:00. The spoken lines are written to be read
aloud verbatim.

> **Before you start:** deploy **both** apps (Standard and Confidential) ahead of
> time and narrate against finished results, so nothing hangs on a live build.
> The single most important sentence to land is at **[2:20]**: *no token → no
> key → the app is inert.* That is the "prevents deployment to non‑confidential
> infrastructure" claim.

---

## [0:00–0:25] — The problem

**On screen:** Title slide, or the Azure DevOps project home.

> "Confidential computing only protects your data if your workload actually lands
> on confidential hardware. So the real question isn't *'can I run this in a
> TEE?'* — it's *'what stops someone from accidentally, or deliberately,
> deploying it to ordinary infrastructure instead?'* This demo shows a CI/CD
> pipeline where that mistake is **impossible** — the app simply can't get the
> secrets it needs unless it proves it's running inside a genuine AMD SEV‑SNP
> enclave."

---

## [0:25–0:55] — The setup

**On screen:** Open `azure-pipelines.yml`; point at the `aciSku` parameter and
the `confidential-build-pool`.

> "Everything here runs inside a self‑hosted Azure DevOps Server — no public IP —
> on **confidential build agents** that are themselves running in enclaves. A
> developer just does a `git push`. The pipeline builds the container
> server‑side with `az acr build`, then deploys it to Azure Container Instances.
> Notice this one parameter: **SKU** — Standard, or Confidential. That's the
> toggle we're going to test."

---

## [0:55–1:35] — The wrong hardware (Standard deploy)

**On screen:** Queue the pipeline with `aciSku = Standard`. Open the resulting
App URL. Click **Attest**.

> "First, let's deploy to **Standard** ACI — ordinary, non‑confidential hardware.
> The container starts fine, the web UI comes up… but watch what happens when the
> app tries to attest."

**On screen:** The Attest button returns an error / no token.

> "It fails. There's no `/dev/sev-guest` device, so there's no SEV‑SNP report to
> produce. The app cannot prove where it's running — and because it can't prove
> it, Microsoft Azure Attestation will **not** issue it a token. On its own
> that's just a failed button… but that failed attestation is the hook the whole
> security model hangs on."

---

## [1:35–2:20] — The enforcement (Confidential deploy)

**On screen:** Queue again with `aciSku = Confidential`. While it runs, point at
the `acipolicygen` step in the log.

> "Now the same app, same image, deployed to **Confidential** ACI. One extra
> thing happens at deploy time: `confcom acipolicygen` measures every layer of
> the image and produces a **CCE policy** — a cryptographic fingerprint of
> exactly what's allowed to run. That policy is injected into the container group
> and enforced by the hardware. Change the image, change the policy — no match,
> no boot."

**On screen:** Open the Confidential app's URL, click **Attest**, show the
returned JWT claims.

> "And now Attest **succeeds** — here's a live SEV‑SNP token from Azure
> Attestation, signed by AMD's hardware root of trust, confirming genuine
> confidential hardware, secure boot, and the exact measurement of this
> workload."

---

## [2:20–2:55] — Why it *prevents* the mistake (the key point)

**On screen:** Show the secure‑key‑release concept — the sibling
[`secretapp-helloworld`](../secretapp-helloworld/README.md) example, or a Key
Vault Secure Key Release policy slide.

> "Here's the part that makes it *prevention*, not just a demo. In the real
> pattern, the app's secrets live in a key vault behind a **Secure Key Release
> policy** bound to that attestation. The key is released **only** when the token
> proves a valid enclave with the expected measurement. So deploy to Standard
> hardware — attestation fails — no token — **no key** — the app is inert.
> There's no config flag to flip, no reviewer to remember: the *hardware and the
> key vault* enforce it. You physically cannot run this workload with its data
> anywhere except confidential infrastructure."

---

## [2:55–3:00] — Close

**On screen:** Back to title / architecture diagram.

> "Attestation‑gated secrets turn a best‑practice into a guarantee. Wrong
> hardware, no keys, full stop."

---

## Narrator notes

- If you have less than 3 minutes, cut the Standard **build** wait by
  pre‑running it and just switching tabs to the finished Standard app at
  **[0:55]**.
- The most important beat is **[2:20]**: *no token → no key → app is inert.*
- Have both apps deployed **before** you start; narrate against finished results
  so nothing hangs on a live build.

## What the audience should take away

| Deploy target | Attestation | Token from MAA | Secret released | Result |
| --- | --- | --- | --- | --- |
| **Standard ACI** (no TEE) | Fails — no `/dev/sev-guest` | No | No | App runs but is **inert** — no data |
| **Confidential ACI** (SEV‑SNP) | Succeeds — CCE policy enforced | Yes | Yes | App runs **with** its secrets |

The enforcement lives in the **hardware and the key vault**, not in pipeline
configuration — so deploying to the wrong infrastructure fails safe by design.
