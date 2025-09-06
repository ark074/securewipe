# Deployment & Hardening Guide (SecureWipe)

## Overview
This document outlines deployment steps for the SecureWipe agent (Linux & Windows) and the cloud verifier. It also lists the hardening checklist required before running real wipes.

## Quick flow
1. Deploy verifier to cloud (Render or VM) and secure it with TLS + client certs.
2. Install agent on each on-prem host (Linux systemd unit or Windows service).
3. Configure mTLS client certs (signed by your CA) and configure agent `config.yaml`.
4. Provision signing keys in Vault/TPM and configure agent to use them.
5. Test end-to-end using loopback images (Linux) or VHDX (Windows).

## Hardening checklist (required before production)
- Use Vault/HSM for signing keys; do not store private keys in plaintext.
- Enable operator authentication and RBAC on UI and API.
- Keep audit logs off-host in S3 (versioned).
- Review and test NVMe/ATA commands in a lab before use on production hardware.
- Implement two-operator approval for bulk or irreversible operations (optional but recommended).
