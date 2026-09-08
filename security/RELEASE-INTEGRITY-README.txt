GARP 2.5.1 – RELEASE INTEGRITY PROCEDURE
Application: generator 7.1.24

Source candidate and deployment artifact are separate. Do not sign source ZIP as if it were deployment integrity.

PREP ceremony after a clean build
1. npm ci from exact package-lock.json in a clean workspace.
2. npm test / qa:p5:ci, including GARP selftest, SBOM drift check, deployment leak scan and SW security freeze.
3. freeze source revision/source ZIP SHA-256 and deployment package SHA-256.
4. generate build provenance for the exact deployment artifact.
5. generate security evidence manifest.
6. create release-integrity.json over the exact dist directory using schema v2/artifactDigest.
7. create a disposable Ed25519 keypair ONLY for RI-PREP verification; do not commit/copy private key to candidate.
8. create trust-root containing only the disposable public key; sign detached manifest; verify signature/integrity/registry/provenance/evidence.
9. mutate artifact/manifest/provenance/evidence/key/registry in disposable copies and confirm relevant negative controls fail closed.
10. delete disposable private key and prep temp directory.

SCHOOL/LIVE ceremony
- use organization-approved release signer, never PREP disposable key;
- school profile of release-gate requires deploy, manifest, signature, trust root, registry, artifact, provenance, evidence dir/manifest and authoritative SW critical list;
- Integrity Service/app-guard must verify before protected runtime, including anti-rollback/mixed-version/revoked-key policy;
- actual live status may be GREEN only after independent verification of deployed bytes and server behavior.

Current status in this source migration
RI tooling: PRESENT + round-3 selftest PASS 51/51.
Independent round-2 audit: exact npm-ci RI-PREP PASS, deterministic rebuild PASS, unified PREP gate GREEN.
Current round-3 source-only corrective delta: exact RI-PREP revalidation pending because local npm registry DNS is unavailable; surrogate local builds are not official RI evidence.
RI-LIVE: NOT TESTED.
