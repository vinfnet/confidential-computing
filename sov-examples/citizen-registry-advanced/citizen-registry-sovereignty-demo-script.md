# Citizen Registry Sovereignty Demo Script

**Length:** 3 minutes  
**Audience:** Microsoft sovereignty, confidential computing, Azure security, and public-sector stakeholders  
**Demo:** Republic of Norland Citizen Registry Advanced

## 0:00-0:20 | Opening

**Show:** Citizen Registry home page and the security status strip.

**Say:**

> This is a fictional Republic of Norland citizen registry running on Azure Confidential Computing. In three minutes, I will show how the design supports three sovereignty goals: data sovereignty, operational sovereignty, and digital sovereignty.
>
> Everything in the registry is fictional. The security evidence is real deployment evidence from the confidential workload.

## 0:20-1:00 | Data Sovereignty

**Show:** Open the registry table, then open a citizen's Health or Employment and Tax History dialog. Point to the Data Explorer tab if available.

**Say:**

> First, data sovereignty. The registry data is stored in SQL Server running inside a separate Azure Confidential VM. The database contains the citizen records, health fixtures, company catalog, employment history, and annual salary and tax history.
>
> The Data Explorer is read-only. It shows the database structure and bounded previews, but it does not provide arbitrary SQL editing or mutation.
>
> The application and database communicate over private networking. The H100 assistant does not connect directly to SQL and never receives database credentials.
>
> This gives us a clear data boundary: the records remain in the protected SQL CVM, and the application retrieves only the data needed for a specific question.

## 1:00-1:45 | Operational Sovereignty

**Show:** Expand the security evidence panel. Point to CPU attestation, GPU attestation, mTLS, Managed HSM, and the infrastructure diagram.

**Say:**

> Second, operational sovereignty. We can verify what is running and where it is running.
>
> The application CVM is protected by AMD SEV-SNP and current-boot CPU evidence. The NVIDIA H100 is in production confidential-computing mode and is independently attested. If those checks fail, the protected services fail closed.
>
> The Managed HSM protects customer-managed encryption keys and secure key-release policy. It is not a database and it does not store the citizen records. It supplies key-management evidence and encryption controls through private connectivity.
>
> Mutual TLS protects the application boundary. Operational access is through controlled private access paths, not an open public application endpoint.

## 1:45-2:35 | Digital and Technology Sovereignty

**Show:** Open Citizen Help and ask:

> What is the average age of all citizens?

Then ask:

> Calculate the average salary by age band and gender.

**Say:**

> Third, digital and technology sovereignty. Citizen Help runs locally on the attested H100 using an open-weight Qwen model. The model is not calling a public AI endpoint, sending records to an external API, or using an external tool.
>
> The model proposes what information it needs as a structured query plan. The application CVM validates that plan against the approved schema, converts it to parameterized read-only SQL, and executes it inside the protected environment.
>
> The H100 then receives the exact bounded result and explains it. It does not execute SQL itself, and it cannot modify the registry.
>
> Here, the first answer is calculated from all stored dates of birth. The second combines date of birth, gender, and annual salary history. The answer comes from the data, not from the model guessing.

## 2:35-2:55 | Demonstrate the Boundary

**Show:** Open the infrastructure diagram and optionally open Debug diagnostics.

**Say:**

> The infrastructure diagram makes the flow visible: browser to application CVM, application to SQL for retrieval, application to the H100 for confidential inference, and the answer returning to the browser.
>
> The debug panel is intentionally sanitized. It shows service state, attestation state, database availability, and processing activity, but never exposes prompts, raw SQL, credentials, keys, or citizen records.

## 2:55-3:00 | Close

**Say:**

> The result is a sovereign-by-design demo: data stays in the protected SQL boundary, operations are attested and controlled, and AI inference uses an open-weight model inside the confidential H100 boundary. The application controls the data path, while the model provides flexible analysis without becoming the database administrator.

## Presenter Notes

- Keep all questions within the fictional Norland dataset.
- Use the live security evidence only as evidence of the deployed demo state; do not claim it is a full legal or regulatory certification.
- If the H100 is still loading, use the security evidence and Data Explorer first, then ask Citizen Help after the model reports ready.
- Do not display raw SQL, prompts, credentials, tokens, HSM key material, or unredacted logs.
- The sovereignty framing used here is explanatory: data sovereignty, operational sovereignty, and digital/technology sovereignty. Map the wording to the specific Microsoft sovereignty framework being presented to the audience.
