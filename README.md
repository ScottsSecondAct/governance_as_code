# Governance as Code
![AI Assisted](https://img.shields.io/badge/AI%20Assisted-Claude-blue?logo=anthropic)

A self-contained C++17 library demonstrating **policy enforcement** and **compliance checking** as first-class code constructs — with structured audit trails, JSON serialization for SIEM integration, and zero external dependencies.

## Why This Project

Most access control systems hide their logic behind configuration files, spreadsheets, or UI-driven rule builders. These approaches share a common failure mode: policies become opaque, unversioned, and untestable. Engineers stop trusting them, auditors can't trace decisions, and security gaps hide in the space between rules.

Governance as Code inverts this. Policies and compliance rules are expressed as typed C++ functions, registered in an engine, and evaluated against a structured request context. They live in source control, they can be unit-tested, and every evaluation produces a structured trace that explains exactly which policy fired and why — the full ordered list of outcomes, not just the winning one.

This project was built as a hands-on exploration of how governance concepts — deny-wins semantics, audit trails, compliance frameworks — map to concrete engineering primitives. AI assistance (Anthropic's Claude) was used throughout as a collaborator for type design, evaluation semantics, and JSON output architecture. Every design decision was reviewed, understood, and intentional.

## The Policy Model

A `Policy` is a named function from a `RequestContext` to an optional `PolicyDecision`. Returning `std::nullopt` means the policy **abstains** — it doesn't apply to this request. Returning `Allow` or `Deny` produces a decision with a policy name and human-readable reason.

```cpp
governance::Policy require_mfa_for_confidential() {
    return {
        "RequireMFAForConfidential",
        "1.0",
        "security-team",
        "Deny access to confidential resources when MFA has not been verified.",
        [](const governance::RequestContext& ctx) -> std::optional<governance::PolicyDecision> {
            if (ctx.resource.classification == "confidential" && !ctx.mfa_verified) {
                return governance::PolicyDecision{
                    governance::Effect::Deny,
                    "RequireMFAForConfidential",
                    "MFA required for confidential resources."
                };
            }
            return std::nullopt; // abstain: not my concern, let other policies decide
        }
    };
}

engine.register_policy(require_mfa_for_confidential());
```

### Resolution Strategy (Fail-Closed)

The engine uses a **deny-wins, fail-closed** strategy:

1. **First `Deny` wins** — evaluation stops immediately; remaining policies are not consulted.
2. **First `Allow` sticks** — if no `Deny` appears after all policies are checked, the first `Allow` is returned.
3. **Default: `Deny`** — if no policy produces a decision, access is denied. Abstaining is never silently promoted to access.

```cpp
auto engine = governance::default_policy_engine();

governance::RequestContext ctx {
    { "bob@corp.io", "engineer", "Backend" },     // principal
    { "prod-db", "database", "restricted", {} },  // resource
    { "write" },                                   // action
    "production",                                  // environment
    false                                          // mfa_verified
};

auto result = engine.evaluate(ctx);
// result.decision.effect      == Effect::Deny
// result.decision.policy_name == "MFARequiredForRestricted"
// result.decision.reason      == "MFA required to access restricted resources."
```

### Evaluation Traces

Every call to `evaluate()` returns an `EvaluationResult` containing the final decision and a full `EvaluationTrace` — a complete, ordered record of every policy consulted during that evaluation:

```cpp
auto result = engine.evaluate(ctx);

for (const auto& step : result.trace.steps) {
    // step.policy_name — which policy was evaluated
    // step.outcome     — Allow, Deny, or Abstain
    // step.reason      — human-readable explanation (empty on Abstain)
}

std::cout << "Evaluated : " << result.trace.evaluated_count() << "\n";
std::cout << "Abstained : " << result.trace.abstain_count()   << "\n";
```

Trace for an engineer attempting a write in production:

```
[Abstain] AdminFullAccess
[Abstain] MFARequiredForRestricted
[Deny   ] ProductionImmutability -- Write/delete operations require admin role in production.
```

The Deny short-circuits evaluation. Policies registered after `ProductionImmutability` never appear in the trace — the trace reflects the actual execution path, not a hypothetical full pass.

## Architecture

```
  RequestContext
  (principal, resource, action,
   environment, mfa_verified)
        │
        ▼
 ┌─────────────────┐   Iterates registered policies in order. Records
 │  PolicyEngine   │   each step (Allow / Deny / Abstain) into the
 │  evaluate()     │   trace. Short-circuits and returns on first Deny.
 │                 │   Default deny if no policy grants access.
 └────────┬────────┘
          │ EvaluationResult
          ├── PolicyDecision   (effect, policy_name, reason)
          └── EvaluationTrace
                  ├── context   (RequestContext snapshot)
                  └── steps[]   (PolicyStep per policy consulted)

  Resource
  (id, type, classification, tags)
        │
        ▼
 ┌─────────────────┐   Evaluates every registered rule regardless of
 │ ComplianceCheck- │   prior results — all violations are captured,
 │ er evaluate()   │   not just the first. Non-short-circuiting by
 │                 │   design: audits want the full picture.
 └────────┬────────┘
          │ ComplianceReport
          ├── resource_id
          ├── compliant()
          └── violations[]   (one entry per failed rule)

  EvaluationResult / ComplianceReport
        │
        ▼
 ┌─────────────────┐   Header-only, zero-dependency JSON serialization.
 │  json.hpp       │   to_json() overloads for PolicyDecision,
 │  to_json()      │   PolicyStep, EvaluationResult, ComplianceReport.
 └─────────────────┘
          │ std::string (valid JSON)
          ▼
    SIEM / log pipeline
```

## Technical Highlights

### Type Design

The core types in `types.hpp` are plain aggregates with no inheritance:

| Type | Fields |
|---|---|
| `Principal` | `id`, `role`, `department` |
| `Resource` | `id`, `type`, `classification`, `tags` (`unordered_map`) |
| `Action` | `verb` (`"read"`, `"write"`, `"delete"`, `"execute"`) |
| `RequestContext` | `principal`, `resource`, `action`, `environment`, `mfa_verified` |
| `PolicyDecision` | `effect` (`Allow`/`Deny`), `policy_name`, `reason` |

`PolicyFn` is a `std::function<std::optional<PolicyDecision>(const RequestContext&)>`. The `std::optional` return type encodes the abstain-or-decide distinction directly in the type system — there is no sentinel value, no separate enum, no ambiguity.

### Deny-Wins Evaluation Loop

The evaluation loop in `PolicyEngine::evaluate()` builds the trace as it iterates and moves it into the return value:

```cpp
for (const auto& policy : policies_) {
    auto decision = policy.evaluate(ctx);
    if (!decision) {
        trace.steps.push_back({ policy.name, StepOutcome::Abstain, "" });
        continue;
    }
    if (decision->effect == Effect::Deny) {
        trace.steps.push_back({ policy.name, StepOutcome::Deny, decision->reason });
        return { *decision, std::move(trace) };   // short-circuit; move, not copy
    }
    trace.steps.push_back({ policy.name, StepOutcome::Allow, decision->reason });
    if (!first_allow) first_allow = decision;
}
```

`EvaluationTrace::context` stores a snapshot of the `RequestContext` at evaluation time. This decouples the audit record from the caller's object lifetime — the trace is self-contained and safe to log asynchronously.

### Compliance vs. Access Control Semantics

`ComplianceChecker` is intentionally **non-short-circuiting**. Unlike `PolicyEngine` (which stops on first Deny), `ComplianceChecker` evaluates every rule and accumulates all violations. This reflects the semantics of an audit: the goal is a complete picture, not a fast exit.

```cpp
auto checker = governance::default_compliance_checker();
auto report  = checker.evaluate(rogue_db);

// report.compliant()   → false
// report.violations    → [
//   "[RequiresOwnerTag] Resource must have an 'owner' tag.",
//   "[DatabasesMustBeRestricted] Database resources must be classified as ..."
// ]
```

### JSON Serialization

`include/governance/json.hpp` is header-only and uses only `<sstream>`. Four `to_json()` overloads live in `namespace governance`:

```cpp
to_json(const PolicyDecision&)    // { "effect", "policy_name", "reason" }
to_json(const PolicyStep&)        // compact single-line: { "policy", "outcome", "reason" }
to_json(const EvaluationResult&)  // nested: decision + trace context + steps[]
to_json(const ComplianceReport&)  // { "resource_id", "compliant", "violations[]" }
```

Example output:

```json
{
  "decision": {
    "effect": "Allow",
    "policy_name": "AdminFullAccess",
    "reason": "Admin role has unrestricted access."
  },
  "trace": {
    "principal": "alice@corp.io",
    "resource": "db-patient-records",
    "action": "read",
    "environment": "production",
    "steps": [
      { "policy": "AdminFullAccess", "outcome": "Allow", "reason": "Admin role has unrestricted access." },
      { "policy": "MFARequiredForRestricted", "outcome": "Abstain", "reason": "" },
      { "policy": "ProductionImmutability", "outcome": "Abstain", "reason": "" },
      { "policy": "AnalystReadOnly", "outcome": "Abstain", "reason": "" },
      { "policy": "EngineerAccess", "outcome": "Abstain", "reason": "" }
    ]
  }
}
```

Private helpers in `namespace governance::json_detail` handle string escaping (`escape()`, `quoted()`) and enum-to-string conversion (`effect_str()`, `outcome_str()`). The `outcome_str()` switch covers all three `StepOutcome` values plus a default case to satisfy `-Wreturn-type` under `-Werror`.

### Policy Metadata

Every `Policy` and `ComplianceRule` carries version, author, and description fields alongside its logic — enabling policy registries, changelogs, and tooling that can inspect what is registered without invoking it:

```cpp
struct Policy {
    std::string name;
    std::string version;      // "1.0"
    std::string author;       // "governance-team"
    std::string description;  // human-readable summary
    PolicyFn    evaluate;
};
```

### Zero External Dependencies

Every header uses only the C++17 standard library: `<functional>`, `<optional>`, `<vector>`, `<string>`, `<unordered_map>`, `<sstream>`, `<ostream>`. No Boost, no JSON library, no test framework. Custom assertion macros (`ASSERT_EQ`, `ASSERT_TRUE`) integrate with CTest via stdout regex matching.

## Built-in Policies

| Policy | Role | Condition | Effect |
|---|---|---|---|
| `AdminFullAccess` | `admin` | always | `Allow` |
| `MFARequiredForRestricted` | any | `restricted` resource + no MFA | `Deny` |
| `ProductionImmutability` | non-admin | `write`/`delete` in production | `Deny` |
| `AnalystReadOnly` | `analyst` | non-read verb, or `confidential`/`restricted` resource | `Deny`/`Allow` |
| `EngineerAccess` | `engineer` | dev/staging (any verb), production (read only) | `Allow` |

Registration order matters. `MFARequiredForRestricted` fires before `AnalystReadOnly` and `EngineerAccess`, so a request to a restricted resource without MFA is denied regardless of role — the deny-wins rule is enforced by ordering, not by special-casing.

## Built-in Compliance Rules

| Rule | Description |
|---|---|
| `RequiresOwnerTag` | Every resource must have an `owner` tag |
| `SecretsNotPublic` | Resources of type `secret` must not be classified `public` |
| `DatabasesMustBeRestricted` | Databases must be `restricted` or `confidential` |
| `NoUnclassifiedResources` | Every resource must have a non-empty classification |

## Build

### Prerequisites

- CMake ≥ 3.16
- C++17 compiler: GCC 7+, Clang 5+, or MSVC 2017+

No other dependencies. No package manager required.

### Quick Start

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

./build/governance_demo
```

### Other Configurations

```bash
# Debug build
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build

# Skip tests
cmake -B build -DBUILD_TESTS=OFF && cmake --build build
```

All compiler warnings are treated as errors (`-Wall -Wextra -Wpedantic -Werror` on GCC/Clang; `/W4 /WX` on MSVC).

## Running Tests

```bash
cmake -B build && cmake --build build
ctest --test-dir build --output-on-failure

# Full output from individual test binaries
./build/tests/test_policy_engine
./build/tests/test_compliance
```

Expected:

```
=== Policy Engine Tests ===
...
--- Results: 24 passed, 0 failed ---

=== Compliance Checker Tests ===
...
--- Results: 21 passed, 0 failed ---
```

## Development Process & AI Collaboration

This project was built incrementally with AI assistance as a design accelerator:

- **Type design**: Claude helped reason through the `PolicyFn` / `std::optional` approach — specifically why returning `std::nullopt` (abstain) is cleaner than a three-valued enum, and why `EvaluationTrace` should store a context snapshot rather than a reference to the caller's object.
- **Evaluation semantics**: Edge cases in fail-closed evaluation were worked through together — what happens when the engine has no registered policies? When a Deny fires mid-trace? Should the winning Allow be the first or the last? (First, to preserve registration-order semantics.)
- **Architecture split**: The deliberate difference between `PolicyEngine` (short-circuits on Deny) and `ComplianceChecker` (exhaustive) came from a design conversation about access control vs. auditing semantics. They look similar on the surface but have opposite goals.
- **JSON output**: The zero-dependency constraint ruled out external libraries. Claude helped design the `json_detail` private namespace pattern and caught the `-Wreturn-type` issue in `outcome_str()` under `-Werror` before it became a build failure.

The AI accelerated iteration; every design decision was made and understood by hand.

## Skills Demonstrated

- **Systems programming**: C++17 with `std::function`, `std::optional`, move semantics, and value-type design
- **API design**: Composable, zero-overhead abstractions using lambdas and plain structs — no virtual dispatch, no mandatory heap allocation
- **Type system usage**: Encoding semantics (`std::optional<PolicyDecision>` for abstain vs. decide) in types rather than sentinel values or out-parameters
- **Security engineering**: Fail-closed evaluation, deny-wins semantics, audit trail design, exhaustive compliance reporting
- **Zero-dependency implementation**: Complete feature set (evaluation, tracing, JSON output) with only the C++17 standard library
- **Build systems**: CMake with multi-target library, executable, and test configurations; compiler warnings as errors
- **Testing**: Custom assertion macros integrated with CTest; suites covering normal paths, edge cases (empty engine, default deny, multiple violations), and new trace/JSON APIs

## Roadmap

- [x] Deny-wins, fail-closed policy engine
- [x] Compliance checker with exhaustive violation accumulation
- [x] Five built-in policies covering common access control patterns
- [x] Four built-in compliance rules (ownership, classification, database restrictions)
- [x] Structured `EvaluationTrace` with per-step `Allow`/`Deny`/`Abstain` outcomes
- [x] Policy and rule metadata (version, author, description)
- [x] Header-only JSON serialization for SIEM/logging integration
- [ ] Logical policy combinators (`all_of`, `any_of`, `none_of`)
- [ ] Named compliance rule bundles (e.g., `PCI-DSS`, `SOC2`)
- [ ] Runtime policy loading from YAML/JSON configuration files
- [ ] C API for embedding in non-C++ applications

## License

MIT
