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

`get_compensation` is the densest route, and it runs each control you built in order:

```yaml
- tool: get_compensation
  authentication: [keycloak]                 # module 2: resolve the caller from a JWT
  authorization:
    pre_invocation:
      - "require(role.hr)"                     # module 1/2: gate by role
      - "delegate(workday-oauth, target: workday-api, audience: workday-api)"  # module 6
      - "taint(secret, session)"               # module 7: mark the session
      - "run(audit-log)"                       # module 4: record the attempt
  result:
    ssn: "str | redact(!perm.view_ssn)"        # module 3: shape the output per permission
    salary: "int | redact(!role.hr)"
```

The one control the Overview did not show is `delegate(...)`: before the backend call, CPEX exchanges the caller's token for a fresh one scoped to the `workday-api` audience (RFC 8693, [module 6]({{< relref "06-delegation" >}})), so the backend never receives the caller's original credential. Everything else on this route you have already seen on its own; the capstone just runs them together, in sequence, on one operation.

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

The application code treated every call the same. Identity, permission, and session history produced every outcome: behavior lives in policy, not in the application.

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
