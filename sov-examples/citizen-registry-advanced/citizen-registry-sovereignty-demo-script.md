# Citizen Registry Sovereignty Demo Script

**Length:** 3 minutes 30 seconds

**Audience:** Microsoft sovereignty, confidential computing, Azure security, and public-sector stakeholders

**Demo:** Republic of Norland Citizen Registry Advanced

## 0:00-0:40 | Architecture Opening

**Show:** Open the Architecture page and hold on the full logical diagram.

**Say:**

> This is the Republic of Norland citizen registry on Azure Confidential Computing. We begin with its trust boundaries.
>
> Browser traffic reaches the Application Confidential VM through private ExpressRoute or site-to-site VPN connectivity. The H100 is local to that tier. SQL runs in a separate Database Confidential VM over private VNet peering and TLS. Managed HSM uses Private Link, while Azure Attestation supplies runtime evidence.
>
> The deployment spans two approved regions. Azure Policy can deny new resources elsewhere; that is a governance option, not a policy assignment made by this sample.

## 0:40-1:10 | Data Sovereignty

**Show:** Open the registry table and click a citizen's portrait to show the simulated passport image, clearly marked as a fictional credential. Close it, then open that citizen's Employment and Tax History dialog.

**Say:**

> First, data sovereignty. This simulated credential and the citizen's employment and tax history are visible to the application, but remain in the protected database tier.
>
> SQL Server holds citizen, health, company, employment, salary, and tax data inside its dedicated Confidential VM. The application retrieves only the records needed for each operation.
>
> The H100 has no direct database connection and never receives SQL credentials.

## 1:10-1:55 | Operational Sovereignty

**Show:** Expand the security evidence panel. Point to CPU attestation, GPU attestation, mTLS, Managed HSM, and the infrastructure diagram.

**Say:**

> Next, operational sovereignty shows what is running and whether protected components are in the expected state.
>
> The Application CVM is protected by AMD SEV-SNP, with evidence from its current boot. The H100 is independently attested in production confidential-computing mode. These runtime checks fail closed if required evidence is missing or invalid.
>
> Managed HSM protects customer-managed keys and key-release policy. It holds no citizen records and is reached through Private Link.
>
> Mutual TLS protects service boundaries, while access follows controlled private paths.

## 1:55-3:00 | Digital and Technology Sovereignty

**Show:** Open Citizen Help and ask:

> What is the average age of all citizens?

Then ask:

> Calculate the average salary by age band and gender.

**Say:**

> Now for digital and technology sovereignty. Citizen Help runs an open-weight Qwen model on the attested H100. It neither calls a public AI endpoint nor sends registry data to an external service.
>
> A question arrives as ordinary language. The model produces a constrained, structured query plan, not SQL. The Application CVM checks every requested table, field, operation, join, and limit against an allowlist.
>
> Only then does the application build parameterized, read-only SQL for SQL Server in the Database CVM. The query runs there; the model has no credentials and cannot modify the registry.
>
> Bounded results return through the Application CVM to the H100 for explanation. The sanitized answer returns through the Application CVM to the browser.
>
> One answer uses stored dates of birth. The other combines age band, gender, and salary history. Both are grounded in protected data, not a model guess.

## 3:00-3:20 | Demonstrate the Boundary

**Show:** Open the infrastructure diagram and optionally open Debug diagnostics.

**Say:**

> The live flow traces that boundary: browser to Application CVM, application to SQL, bounded context to the H100, then the answer back through the Application CVM. It exposes only sanitized states, never prompts, SQL, credentials, keys, or citizen records.

## 3:20-3:30 | Close

**Say:**

> Protected data, attested operations, and confidential AI, with every boundary made explicit. That is sovereignty by design.

## Presenter Notes

- Keep all questions within the fictional Norland dataset.
- Use the live security evidence only as evidence of the deployed demo state; do not claim it is a full legal or regulatory certification.
- If the H100 is still loading, use the registry and security evidence first, then ask Citizen Help after the model reports ready.
- Do not display raw SQL, prompts, credentials, tokens, HSM key material, or unredacted logs.
- The sovereignty framing used here is explanatory: data sovereignty, operational sovereignty, and digital/technology sovereignty. Map the wording to the specific Microsoft sovereignty framework being presented to the audience.
