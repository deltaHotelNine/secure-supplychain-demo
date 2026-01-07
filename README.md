
# Secure Supply Chain Demo

This repository demonstrates a simple secure software supply chain: build -> SBOM -> vulnerability scan -> push -> sign -> enforce. It is a hands-on demo using GitHub Actions, Cosign, Syft, Grype, and Kyverno (Kind cluster).

See the full, step-by-step instructions in the walkthrough: `walkthrough.md`.

Quick links:

- Workflow: `.github/workflows/supplychain.yml`
- Kyverno policies: `policies/require-signed.yaml`, `policies/disallow-latest.yaml`

Follow `walkthrough.md` for the full guided demo (creating keys, configuring GitHub Actions, installing Kyverno in Kind, and testing admission policies).

Security note: Do NOT commit `cosign.key` (private key). Store private keys and passwords in your CI secrets or a vault.
