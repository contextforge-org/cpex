---
title: "Capstone"
weight: 12
---

# Capstone: the three-backend agent

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This needs the IdP.

**Goal:** assemble everything into the full scenario from the [Overview]({{< relref "/docs/overview" >}}): one agent, three backends, three callers, one policy. See identity, permission, delegation, redaction, information flow, and audit compose.

## The scenario

One policy ([`policies/capstone.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/capstone.yaml)) defines three routes:

- `get_compensation` (HR): authorize by role, mint a scoped downstream token, taint the session as having read secret data, audit, and redact fields by permission on the way out.
- `search_repos` (repos): hand the decision to CEL: engineers read internal only, security reads any.
- `send_email` (email): refuse if the session already touched secret data, and audit every attempt.

## Run it

```bash
cargo run -p cpex-tutorial --example capstone
```

Two behaviors carry the whole idea.

**Same request, different result.**

```
▸ alice (hr, view_ssn) → get_compensation
  ✓ ALLOWED  { ... "ssn":"521-38-7710" ... }

▸ dana (hr, no view_ssn) → get_compensation (SSN redacted)
  ✓ ALLOWED  { ... "ssn":"[REDACTED]" ... }

▸ evan (engineer) → get_compensation (denied, not HR)
  ✗ DENIED   [...] access denied
```

**Information follows the session.**

```
▸ dana, fresh session → send_email (allowed: nothing read yet)
  ✓ ALLOWED  {"sent":true, ...}

▸ dana, same session as her HR read → send_email (write-down blocked)
  ✗ DENIED   [session_tainted] write-down blocked: this session read secret data
```

The application code treated every call the same. Identity, permission, and session history produced every outcome. That is the whole point of CPEX: behavior lives in policy, at the boundary, not in the app.

If you skipped module 6, run the variant that drops delegation:

```bash
cargo run -p cpex-tutorial --example capstone -- --no-delegation
```

## Compare to the shipped policy

This is the same policy the README and Overview describe. Read [`capstone.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/capstone.yaml) top to bottom: every step is one you built in an earlier module. Nothing new was introduced to assemble the whole.

## Where to go next

- [Patterns]({{< relref "/docs/patterns" >}}): layered enforcement, shadow rollout, defense in depth.
- [Deployment]({{< relref "/docs/deployment" >}}): where to run the enforcement point (gateway, sidecar, in-process).
- [Builtins]({{< relref "/docs/builtins" >}}): the full bundled plugin and PDP set.
- [Go bindings](https://github.com/contextforge-org/cpex/tree/main/go/cpex): drive CPEX from Go over the FFI.
- Write and contribute a plugin: you already did the hard part in [module 9]({{< relref "09-custom-plugin" >}}).
