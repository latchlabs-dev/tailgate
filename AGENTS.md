# Reusable component instructions

- This independent repository contains reusable Tailgate components. Use placeholder domains (`example.com`), documentation IP ranges, and fictitious identities in examples. Company inventories, hostnames, addresses, policy rosters and deployment scripts belong in the separate deployment repository.
- Never commit secrets, generated keys, database state, certificate state or raw runtime logs.
- Python tooling supports Python 3.9+ and uses only the standard library. Use pnpm if JavaScript tooling becomes necessary. Preserve the global seven-day package release-age policies.
- Lock upstream versions, publication times, artifact SHA-256 values and source provenance. Verify artifacts before execution. Do not silently follow latest versions or download an unpinned Go toolchain.
- Keep policy explicitly deny-all until intentional grants are supplied. Validate listeners, identities, names and topology before rendering deployable output.
- Run unit/security checks and the documented isolated integration test after material component changes. Never use a live network's state or migrate a client for these tests.
- Deliver all intended files committed, with a clean working tree and exact revision. Local commits do not publish a remote or deploy a service.
