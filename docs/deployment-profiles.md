# aiueos Deployment Profiles

Status: proposed baseline
Date: 2026-07-01

aiueos is a containment architecture. A deployment profile states which
additional claims a deployment is allowed to make beyond Phase-0 containment.

## Profile Summary

| Profile | Intended use | Allowed claim |
|---|---|---|
| `research` | local experiments, demos, early integration | capability containment only |
| `sensitive-local` | single-tenant local systems with sensitive data | containment plus host hardening and encrypted audit/data |
| `regulated` | systems needing auditable governance and crypto boundaries | containment plus evidence, key lifecycle, SBOM/SLSA, provider policy |
| `high-assurance` | future verified/sensitive deployments | blocked until formal and side-channel evidence exists |

## `research`

Required:

- deny-by-default manifest policy;
- Wasm fuel and memory limits;
- append-only audit enabled;
- clear non-claim of FIPS, side-channel resistance, and formal verification.

Not claimed:

- side-channel resistance;
- FIPS validation;
- hard real-time scheduling;
- production key lifecycle;
- release evidence packet completeness.

## `sensitive-local`

Required:

- all `research` controls;
- no untrusted co-tenant execution on the host;
- encrypted audit logs or encrypted audit storage;
- no deterministic `random()` for secrets, keys, nonces, or tokens;
- explicit operator review of granted `:network`, `:secrets`, and
  `:persistent-write` capabilities.

Not claimed:

- FIPS validation unless `regulated` provider evidence is also present;
- side-channel resistance against privileged local attackers.

## `regulated`

Required:

- all `sensitive-local` controls;
- key lifecycle register with active/retired/revoked/compromised states;
- signer expiry and revocation checks;
- SBOM and SLSA/in-toto provenance for release artifacts;
- package/component verification evidence;
- monitoring and incident-response exercise evidence;
- FIPS provider policy when a FIPS claim is made.

Not claimed:

- FIPS validation without named module certificate and boundary evidence;
- production PQC migration without hybrid envelope evidence.

## `high-assurance`

Blocked until evidence exists for:

- side-channel threat model and mitigations;
- formal verification or equivalent high-assurance argument for the broker and
  host ABI;
- hardened TCB boundary;
- reproducible, signed, independently verified release pipeline;
- PQ/hybrid key wrapping for long-retention private data.

No release should use this profile today.

## Release Note Requirement

Every release note or deployment report must name one profile and list the
non-claims that remain true for that profile. If the profile is omitted, the
deployment defaults to `research`.

