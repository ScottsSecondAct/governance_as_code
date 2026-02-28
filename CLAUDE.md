# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Governance as Code is a self-contained C++17 library demonstrating policy enforcement and compliance checking as first-class code constructs. It has no external dependencies (C++17 standard library only).

## Build and Test Commands

**Prerequisites:** CMake ≥ 3.16, C++17 compiler (GCC 7+, Clang 5+, MSVC 2017+)

```bash
# Configure and build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Run individual test binaries
./build/tests/test_policy_engine
./build/tests/test_compliance

# Run the demo
./build/governance_demo

# Debug build
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build

# Build without tests
cmake -B build -DBUILD_TESTS=OFF
```

All compiler warnings are treated as errors (`-Wall -Wextra -Wpedantic -Werror` on GCC/Clang; `/W4 /WX` on MSVC).

## Architecture

**Core design:** A static `governance` library exposes two independent subsystems consumed by the demo and tests.

### Policy Engine (`include/governance/policy_engine.hpp`, `src/policy_engine.cpp`)

- `PolicyFn` = `std::function<std::optional<PolicyDecision>(const RequestContext&)>`
- Policies return `Allow`, `Deny`, or `nullopt` (abstain)
- Evaluation strategy: **first Deny wins, fail-closed** — if no policy allows, the default is Deny
- `PolicyEngine::evaluate()` iterates registered policies in order; stops immediately on Deny

### Compliance Checker (`include/governance/compliance.hpp`, `src/compliance.cpp`)

- `ComplianceRule` pairs a name/description with a check function over `Resource`
- `ComplianceChecker::check()` returns a `ComplianceReport` listing all violations for a resource

### Types (`include/governance/types.hpp`)

All data structures: `Principal` (id, role, department), `Resource` (id, type, classification, tags), `Action` (verb), `RequestContext` (principal + resource + action + environment + mfa_verified), `PolicyDecision` (Effect::Allow/Deny + policy_name + reason).

### Tests

Tests use custom assertion macros (`ASSERT_EQ`, `ASSERT_TRUE`) with no external test framework. CTest uses regex patterns to detect pass/fail from stdout.

## Key Design Constraints

- **Deny-wins, fail-closed:** A missing or non-matching policy never grants access.
- **Ordered policy evaluation:** Policy registration order matters — first Deny short-circuits remaining evaluation.
- **Zero external dependencies:** Everything uses C++17 stdlib only (`<functional>`, `<optional>`, `<vector>`, `<string>`, `<unordered_map>`).
- **Not accepting contributions:** Project is in early development; see CONTRIBUTING.md.

## Notes

- The `.github/workflows/release.yml` workflow is for a Rust/Cargo project and does not apply to this C++ codebase.
- SECURITY.md contains a reference to "terminal pager `some`" that is leftover from a different project and should be ignored.
