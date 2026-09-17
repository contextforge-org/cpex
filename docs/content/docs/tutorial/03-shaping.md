---
title: "Shaping data"
weight: 4
---

# Module 3: Shaping data

> You are in the [CPEX tutorial]({{< relref "_index" >}}). Runs without the IdP (redaction fires for anonymous callers). The full contrast needs it.

**Goal:** return a different view of the same backend record per caller, by transforming the result on the way out with redact and mask, gated by permission.

## The problem

An HR analyst with clearance should see an employee's SSN. One without should get the record with the SSN removed. Not a different endpoint, not a second query: the same call with a field stripped. The backend returns the full record, so policy must shape it before it leaves the boundary.

## Build it

The route allows the call, then a `result:` field pipeline transforms the response. From [`policies/m03.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m03.yaml):

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation: []
    result:
      ssn: "str | redact(!perm.view_ssn)"
      salary: "int | redact(!role.hr)"
      employee_id: "str | mask(4)"
```

Each entry reads `<field>: "<type> | <op>(<when>)"`. The op runs only when its predicate holds. `redact(!perm.view_ssn)` means redact when the caller does not have `view_ssn`. `mask(4)` always keeps the last four characters. This runs in the Post phase, after the backend returns and before the caller sees the response.

## Run it

Without a token, no permissions are set, so both redactions fire:

```bash
cargo run -p cpex-tutorial --example m03_shaping
```

```
▸ anonymous → get_compensation (result pipeline redacts ssn + salary, masks id)
  ✓ ALLOWED  {"employee_id":"**1001","name":"Alice Okafor","title":"Staff Engineer","salary":"[REDACTED]","ssn":"[REDACTED]"}
```

The call is allowed, so the record still comes back, but `ssn` and `salary` are redacted and `employee_id` is masked. The backend returned all of it. Policy shaped it.

{{< asciinema cast="https://asciinema.org/a/FJscsrCUbnazbPSl.cast" poster="npt:0:03" >}}

## Try it

1. Redact another field. In `examples/tutorial/policies/m03.yaml`, add a line under `result:` such as `name: "str | redact(!perm.view_ssn)"`, then re-run. Expect: `name` now comes back `[REDACTED]` too. The pipeline transforms exactly the fields you name.
2. See the full record with identity. The default run is anonymous, so every redaction fires (no caller has `view_ssn`). To see the per-permission contrast, give the route an identity, the same way module 2 does. This is a two-file change:
   - In `examples/tutorial/policies/m03.yaml`, add the `keycloak` identity plugin and reference it from the route. Copy the top-level `plugins:` block and the `authentication:` line from `policies/m02.yaml` (module 3's policy has no identity plugin on its own, which is why minting a token alone changes nothing).
   - In `examples/tutorial/examples/m03_shaping.rs`, add `use cpex_tutorial::idp;` near the other imports and replace `let caller = Caller::anonymous();` with:
     ```rust
     let caller = match idp::mint_token("alice", "alice").await {
         Ok(t) => Caller::with_token(t),
         Err(e) => { eprintln!("{e}"); std::process::exit(1); }
     };
     ```
   - Start the IdP and re-run. Expect: alice (`view_ssn`) now sees the full `ssn` and `salary`, with `employee_id` still masked. Swap `"alice"` for `"dana"` and `ssn` is redacted again (she lacks `view_ssn`) while `salary` stays visible. Same policy, different caller. This is the contrast the [capstone]({{< relref "capstone" >}}) runs end to end.
3. Change the mask width. Set `employee_id: "str | mask(2)"` and re-run. Expect: only the last two characters survive.

## Checkpoint

{{< details "Was the call allowed or denied?" >}}
Allowed. Redaction is not denial. The operation runs and returns, and the result pipeline transforms specific fields on the way out. Denial (module 1) stops the call entirely.
{{< /details >}}

{{< details "Where does the redaction happen, before or after the backend?" >}}
After. The `result:` pipeline runs in the Post phase, on the backend's response. The backend always returns the full record, and the boundary decides what leaves.
{{< /details >}}

## Go deeper

- [APL: field pipelines]({{< relref "/docs/apl" >}}) and [Effects]({{< relref "/docs/apl/effects" >}}).

## Next

[Module 4: Effects & sequencing]({{< relref "04-effects" >}}): compose multiple effects in order, add auditing, and write your own denial codes.
