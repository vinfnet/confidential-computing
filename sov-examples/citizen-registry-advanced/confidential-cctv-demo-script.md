# Confidential CCTV Anonymization Demo Script

**Length:** 2 minutes

**Audience:** Security, privacy, public-sector, and video-analytics stakeholders

**Demo:** Republic of Contoso Confidential CCTV

## 0:00-0:25 | The Privacy Gap

**Show:** Open the one-camera architecture and hold on the complete raw and anonymized paths.

**Say:**

> Conventional video analytics has a privacy gap. Encryption protects footage at rest and in transit, but AI must still use decrypted frames.
>
> Organizations may need original video as evidence, while routine reviewers should not identify everyone in view. This design protects that moment. One simulated camera retains its original recording in private DVR storage and creates a separate anonymized stream for review.

## 0:25-0:45 | Preserve Raw Evidence

**Show:** Emphasize the camera-to-DVR path, Managed HSM key control, Private Link, and the distinct review output.

**Say:**

> The raw recording remains unchanged in private, zone-redundant Blob Storage. A customer-managed key in Managed HSM protects storage encryption, public and shared-key access are disabled, and the application reads through Private Link with managed identity.
>
> That retained original remains available to appropriately authorized evidence and analysis workflows.

## 0:45-1:10 | Anonymization Inside Confidential Computing

**Show:** Open Confidential CCTV, start the comparison, and show the attested H100 status.

**Say:**

> Processing starts after verifying current-boot evidence, H100 identity, and confidential-computing mode. Face detection runs on the H100. Decoding, tracking, blurring, and HLS encoding stay inside the AMD SEV-SNP Confidential VM.
>
> Together, CPU and GPU protect data in use. Invalid evidence fails closed; raw footage never substitutes for unavailable anonymized video.

## 1:10-1:45 | Anonymous Review

**Show:** Play the synchronized source and anonymized views. Hold on a dense crowd section, then show live face and GPU metrics and expand technical details.

**Say:**

> Here, the left pane is the retained source and the right pane is the separate anonymized output. Faces are detected in batches, blurred, and tracked briefly between frames to reduce visible gaps. Reviewers receive the resulting HLS video through the Application Confidential VM.
>
> The live status reports the attested H100, processing state, frame count, and detected faces. Storage details expose the security design without exposing credentials, keys, or biometric identity data.

## 1:45-2:00 | Keep Evidence, Minimize Exposure

**Show:** Return to the architecture with the anonymized reviewer path emphasized.

**Say:**

> Preserve original footage for controlled evidentiary use, while providing de-identified video for ordinary review.
>
> That moves privacy from “trust us” toward verifiable trust: isolate the computation, attest the runtime, and disclose only what the reviewer needs.

## Presenter Notes

- The camera context is simulated; the sample is a CC BY-SA 4.0 London Marathon extract credited in the application.
- Describe the demonstrated output as de-identified or anonymized for routine review, not as a universal guarantee against every possible re-identification method.
- Do not claim legal or regulatory certification.
- Do not display credentials, access tokens, private keys, raw attestation tokens, or unredacted diagnostics.
- The privacy-gap, verifiable-trust, controlled-disclosure, and output-minimization framing is based on `The Privacy Gap in Conventional Video Analytics`.
- The article's editor note describes CCTV as a proposed extension; this recording demonstrates the extension now implemented in the current sample.