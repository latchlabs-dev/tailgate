# Development and local validation

[Overview](../README.md) · [Documentation index](README.md)

Run commands from the `tailgate-core` repository. Python tooling requires Python 3.9+ and the standard library. Git is needed for source receipts. Go builds require the exact toolchain in `versions.lock.json`; build scripts disable automatic toolchain downloads and use locked module inputs. No JavaScript package installation is needed for the bundled web assets.

## Validate and render

```sh
python3 -m unittest discover -s tests -v
python3 tools/tailgate.py validate examples/pilot.json
python3 tools/tailgate.py validate examples/company.json
python3 tools/tailgate.py validate examples/partitioned.json
python3 tools/tailgate.py render examples/pilot.json --output build/pilot
python3 tools/tailgate.py render examples/company.json --output build/company
```

The examples cover embedded relay, standalone relays and partitioned address pools. Output directories must be empty or absent. Rendering emits configuration, explicit policy, Nginx/systemd definitions and input/version receipts; it neither installs services nor supplies credentials. The [input contract](../schemas/README.md) explains draft mode and database-policy initialization.

## Obtain verified artifacts

Choose the actual target architecture. This example prepares the Linux ARM64 integration fixtures:

```sh
python3 tools/tailgate.py fetch headscale --platform linux_arm64 --output .cache/linux_arm64
python3 tools/tailgate.py fetch lego --platform linux_arm64 --output .cache/linux_arm64
python3 tools/tailgate.py fetch tailscale --platform linux_arm64 --output .cache/linux_arm64
python3 tools/tailgate.py build-derper --platform linux_arm64 --output .cache/linux_arm64
python3 tools/build-admin.py --platform linux_arm64 --output .cache/linux_arm64/tailgate-admin
```

Fetching enforces locked SHA-256 values and a minimum seven-day upstream release age before executable extraction. Build receipts record binary hashes and dependency sums. See [provenance](provenance.md); do not bypass age settings when an artifact is too new.

## Choose the check that matches the change

| Check | What it establishes | Prerequisites |
| --- | --- | --- |
| Python unit suite above | Renderer/tooling contracts and regressions | Python |
| Native controller smoke | Pinned Headscale accepts fixture configuration/policy | Matching native Headscale binary |
| Official-client integration | Disposable allowed/denied traffic, DNS and relay scenarios | Docker with Linux ARM64 execution, OpenSSL, locked artifacts |
| Admin smoke | Private adapter and controller interaction | Matching native admin and Headscale binaries |
| Docker review lab | Interactive console and containment checks | Prepared Linux ARM64 artifacts and Docker |
| Gateway integration | Two isolated networks, bridge identity and policy behavior | Gateway-specific build/lab prerequisites |

On an ARM64 Mac, prepare and run native smoke checks separately from the Linux artifacts:

```sh
python3 tools/tailgate.py fetch headscale --platform darwin_arm64 --output .cache/darwin_arm64
python3 tools/smoke.py --headscale .cache/darwin_arm64/headscale
python3 tools/build-admin.py --platform darwin_arm64 --output .cache/darwin_arm64/tailgate-admin
python3 tools/admin-smoke.py --headscale .cache/darwin_arm64/headscale --admin .cache/darwin_arm64/tailgate-admin
```

Use matching native Linux artifacts on Linux. Run the disposable integration fixtures with:

```sh
python3 tools/integration.py --artifacts .cache/linux_arm64
python3 tools/integration.py --artifacts .cache/linux_arm64 --example partitioned
```

These tests create their own identities and networks and clean up their own resources. Never point a lab at production state. The digest-pinned proxy image is a test fixture. For interactive inspection use the [Docker lab](docker-lab.md); for the gateway use its [build and validation guide](../components/gateway/README.md).

## Preview the interface

After the native admin build:

```sh
.cache/darwin_arm64/tailgate-admin --demo
```

Open `http://127.0.0.1:18100`. Demo identities are fictitious and edits reset on restart. See [administration](../components/admin/README.md) for connected mode, Google authentication, approval semantics and security tests, and [public site](../components/public-site/README.md) for public-page generation.

## Delivering a change

Keep examples generic and never add company identities, secrets or runtime state. Validate material component changes with unit/security checks and the relevant isolated integration. Record exactly which evidence was collected. A local commit is source delivery; a deployment repository must separately select and qualify that revision before it reaches a live service.
