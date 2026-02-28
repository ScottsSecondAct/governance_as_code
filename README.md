# Governance as Code

![AI Assisted](https://img.shields.io/badge/AI%20Assisted-Claude-blue?logo=anthropic)

A self-contained C++17 project demonstrating **Governance as Code** patterns: policy rules, access control evaluation, and compliance checking expressed as first-class code constructs rather than manual spreadsheet-driven processes.

---

## Concepts

| Concept | Description |
|---|---|
| **Policy Engine** | Evaluates named policies against a request context; fail-closed by default |
| **PolicyDecision** | `Allow` or `Deny`, with the responsible policy name and a human-readable reason |
| **ComplianceChecker** | Evaluates resource metadata against named compliance rules |
| **ComplianceReport** | Lists all rule violations found on a resource |

The engine uses a **deny-wins, fail-closed** resolution strategy:

1. If any policy returns `Deny` → access is denied immediately.
2. If at least one policy returns `Allow` and none return `Deny` → access is granted.
3. If no policy matches → access is denied (default-deny).

---

## Built-in Policies

| Policy | Description |
|---|---|
| `AdminFullAccess` | Admins bypass all restrictions |
| `MFARequiredForRestricted` | Deny access to `restricted` resources without MFA |
| `ProductionImmutability` | Non-admins cannot `write` or `delete` in production |
| `AnalystReadOnly` | Analysts can only `read` non-sensitive resources |
| `EngineerAccess` | Engineers have full dev/staging access; read-only in production |

## Built-in Compliance Rules

| Rule | Description |
|---|---|
| `RequiresOwnerTag` | Every resource must have an `owner` tag |
| `SecretsNotPublic` | Resources of type `secret` must not be `public` |
| `DatabasesMustBeRestricted` | Databases must be `restricted` or `confidential` |
| `NoUnclassifiedResources` | Every resource must have a non-empty classification |

---

## Building

### Prerequisites

- CMake ≥ 3.16
- A C++17-capable compiler (GCC 7+, Clang 5+, MSVC 2017+)

### Quick start

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/governance_demo
```

### Debug build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### Skip tests

```bash
cmake -B build -DBUILD_TESTS=OFF
cmake --build build
```

---

## Running Tests

```bash
# Build (tests are enabled by default)
cmake -B build
cmake --build build

# Run all tests
ctest --test-dir build --output-on-failure

# Or run test binaries directly for full output
./build/tests/test_policy_engine
./build/tests/test_compliance
```

Expected output:

```
=== Policy Engine Tests ===

[AdminFullAccess]
  [PASS] admin delete restricted in prod -> Allow
  [PASS] policy name
...
--- Results: 20 passed, 0 failed ---

=== Compliance Checker Tests ===

[CompliantResources]
  [PASS] restricted database with owner tag -> compliant
...
--- Results: 20 passed, 0 failed ---
```

---

## Extending the Engine

### Add a custom policy

```cpp
#include "governance/policy_engine.hpp"

governance::Policy require_department_tag() {
    return {
        "RequireDepartmentTag",
        [](const governance::RequestContext& ctx) -> std::optional<governance::PolicyDecision> {
            if (ctx.resource.tags.count("department") == 0) {
                return governance::PolicyDecision{
                    governance::Effect::Deny,
                    "RequireDepartmentTag",
                    "Resource must be tagged with a department before access is granted."
                };
            }
            return std::nullopt; // abstain; let other policies decide
        }
    };
}

// Register it
engine.register_policy(require_department_tag());
```

### Add a custom compliance rule

```cpp
#include "governance/compliance.hpp"

checker.add_rule({
    "MustHaveRegionTag",
    "Resource must specify a 'region' tag.",
    [](const governance::Resource& r) {
        return r.tags.count("region") > 0;
    }
});
```

---

## Design Notes

- **No external dependencies.** The library uses only the C++17 standard library.
- **`std::function` + `std::optional`** make policies and rules easy to express as lambdas without inheritance hierarchies.
- **Separation of concerns:** `governance` is a static library; `governance_demo` and the test binaries link against it independently.
- **Fail-closed by default:** absence of a matching policy always results in `Deny`, never silent `Allow`.
