# Input contract, version 1

[Overview](../README.md) · [Documentation index](../docs/README.md)

`tools/tailgate.py validate` is the executable contract. Examples cover embedded-relay pilot and standalone-relay company topology. Inputs use JSON; duplicate keys are rejected.

Required fields: `schema_version: 1`, `controller`, `identity`, `certificates`, `relay`, `policy`, `services` (empty permitted). Controller contains lowercase FQDNs `hostname`, `device_domain`, `application_domain`, private loopback `listen` and `metrics`, and optional advertised `public_ipv4`. Google identity contains `client_id`, `allowed_domains`, `allowed_users`; at least one filter is required. Domain and user filters intersect when both exist. `certificates` names lego's `dns_provider` and the ACME contact `email`; provider credentials are external.

Optional `controller.prefixes` specifies canonical `v4` and `v6` CIDRs and an optional `allocation` (`sequential`, the default, or `random`). Both address families must be supported subsets of `100.64.0.0/10` and `fd7a:115c:a1e0::/48`, with at least four addresses each. Application addresses must belong to the selected IPv4 pool. Omitting this object preserves the original full ranges. See `examples/partitioned.json`. Rendering allocation ranges does not renumber existing nodes or reserve them in another network; deployment must separately verify both networks' assignments and allocation policies, back up state, rehearse renumbering and update address-based listeners and records.

Policy must contain an explicit `grants` list. The upstream Headscale policy validator is still authoritative for user/tag/group semantics. No automatic team access or default grant is synthesized. Empty `grants` is deny-all. Services contain a private application FQDN, enrolled IPv4 `address`, host-local HTTP `backend`, and lowercase `audience`. Service registration creates DNS and proxy configuration, not a grant. Add and qualify the matching grant separately. Services at the same IP:443 must share an audience; app authentication for finer distinctions requires a separately reviewed adapter.

Optional `policy_storage` selects `file` (default) or `database` for the approval UI. Database mode still emits `policy.json` as the explicit initializer; the deployment must initialize and verify it using the pinned Headscale offline CLI before starting any listener. An unset database policy is not deny-all. After activation, the UI's durable ledger and policy database are authoritative together; rerendering the initializer must never reset approved runtime access.

`relay.mode` is `embedded` or `standalone`. Standalone nodes require unique `region_id`, `code`, `hostname` and `ipv4`. IPv6 relay advertisement is deliberately disabled until individually qualified. No public relay map is included. Controller and relay certificates are DNS-01 files managed separately from Headscale.

`--draft` permits missing client ID, admission filters and certificate contact/provider for planning previews. It substitutes an impossible example-domain admission identity when no filter exists. Draft output is marked in `manifest.json` and **must never activate**. Deploy tooling rerenders strict input and refuses drafts.

The contract intentionally limits this first version: no subnet routes, arbitrary TXT/SRV DNS, cross-host plaintext backends, shared-audience authorization inference, or public app listeners. Extend it with evidence-backed checks when a concrete need appears.
