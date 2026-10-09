# Citizen Registry Sovereignty Demo Script

**Length:** 3 minutes 30 seconds

**Audience:** Microsoft sovereignty, confidential computing, Azure security, and public-sector stakeholders

**Demo:** Republic of Contoso Citizen Registry Advanced

## 0:00-1:00 | Architecture Opening

**Show:** Open the Architecture page and hold on the full logical diagram.

**Say:**

> This is the Republic of Contoso citizen registry on Azure Confidential Computing. We begin with its trust boundaries, showing where processing and operational control reside.
>
> A Confidential VM uses a hardware-backed trusted execution environment, or TEE, like a locked safe. Plaintext data is handled only inside the safe; outside it, only encrypted data is visible.
>
> Browser traffic reaches the Application Confidential VM, or CVM, through private ExpressRoute or VPN connectivity. An H100 Confidential GPU is attached.
>
> SQL Server runs in a separate Database CVM, connected through private VNet peering and TLS.
>
> Managed HSM provides keys over Private Link, while Azure Attestation validates runtime evidence.
>
> Azure Policy restricts deployment to two approved regions. Everything outside republic-managed CVMs is treated as untrusted.

## 1:00-1:28 | Data Processing Confidentiality

**Show:** Open the registry table and click a citizen's portrait to show the simulated passport image, clearly marked as a fictional credential. Close it, then open that citizen's Employment and Tax History dialog.

**Say:**

> First, data sovereignty. This simulated passport and the citizen's employment and tax history are visible to the application.
>
> SQL Server holds sensitive health, tax, and employment data inside the Database CVM. The application retrieves only the records needed for each operation.
>
> Encryption protects data at rest and in transit, while Azure Confidential Computing protects it in use.

## 1:28-2:04 | Operational Confidentiality

**Show:** Expand the security evidence panel. Point to CPU attestation, GPU attestation, mTLS, Managed HSM, and the infrastructure diagram.

**Say:**

> Next, operational sovereignty shows what is running and whether protected components are in the expected state.
>
> Azure Attestation validates current boot evidence from the Application CVM. The H100 GPU is independently attested in confidential-computing mode. These checks fail closed if required evidence is missing or invalid.
>
> Managed HSM protects customer-managed keys and releases them through policy only when the calling application demonstrates valid attestation.
>
> Private Link and mutual TLS keep service access controlled and private.

## 2:04-3:01 | Using AI in Confidential Applications

**Show:** Open Citizen Help and ask:

> What is the average age of all citizens?

Then ask:

> Calculate the average salary by age band and gender, format output as a table.

**Say:**

> Now consider an AI-enabled application with end-to-end confidential-computing protection. Citizen Help runs an open-weight Qwen model on the attested H100 GPU, without calling a public AI endpoint or sending citizen data to an external service.
>
> A question arrives in ordinary language. The model produces a constrained query plan, not SQL. The Application CVM checks every operation and field against an allowlist.
>
> Only then does the application build a read-only query for the Database CVM. The model has no credentials and cannot modify the registry.
>
> Bounded results return through the Application CVM to the H100 for explanation, then a sanitized answer returns to the browser.
>
> One answer uses dates of birth; the other combines age band, gender, and salary history. Both are grounded in protected data, not model guesses.

## 3:01-3:20 | Demonstrate the Boundary

**Show:** Open the infrastructure diagram and optionally open Debug diagnostics.

**Say:**

> The boundary is clear: browser to Application CVM, application to SQL, bounded context to the H100, and back through the Application CVM. Only sanitized states are exposed, never prompts, SQL, credentials, keys, or citizen records.

## 3:20-3:30 | Close

**Say:**

> Protected data, attested operations, and confidential AI, with every boundary made explicit. That is sovereignty by design.

## Presenter Notes

- Keep all questions within the fictional Contoso dataset.
- Use the live security evidence only as evidence of the deployed demo state; do not claim it is a full legal or regulatory certification.
- If the H100 is still loading, use the registry and security evidence first, then ask Citizen Help after the model reports ready.
- Do not display raw SQL, prompts, credentials, tokens, HSM key material, or unredacted logs.
- The sovereignty framing used here is explanatory: data sovereignty, operational sovereignty, and digital/technology sovereignty. Map the wording to the specific Microsoft sovereignty framework being presented to the audience.
