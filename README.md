# SecureWipe — Production Package (Linux + Windows)

This package contains a production-oriented scaffold for SecureWipe with **Linux and Windows agent artifacts**, a cloud verifier service, signing tools, and deployment instructions.
**DO NOT** run wipe operations on production disks until you have reviewed the hardening checklist and tested thoroughly with loopback images/VHDs.

Folders:
- backend/           Rust actix-web backend (agent core + API)
- agent/linux/       systemd unit, install scripts, config templates (Linux agent)
- agent/windows/     PowerShell service wrapper + installer (Windows agent)
- verifier/          Flask verifier (cloud) + Dockerfile
- tools/             Python tools: keygen, sign_and_send, verify
- deploy/            Render and VM deployment guides, mTLS, Vault instructions
- scripts/           helper scripts (create loopback images, create VHDX)
- LICENSE

Read `deploy/README.md` for step-by-step deployment and hardening checklist.
