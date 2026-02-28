#pragma once

#include "governance/types.hpp"
#include <functional>
#include <optional>
#include <ostream>
#include <vector>
#include <string>

namespace governance {

// A Policy is a named rule. Given a context, returns a decision or abstains.
using PolicyFn = std::function<std::optional<PolicyDecision>(const RequestContext&)>;

struct Policy {
    std::string name;
    std::string version;      // e.g. "1.0"
    std::string author;       // e.g. "governance-team"
    std::string description;
    PolicyFn    evaluate;
};

// ── Trace types ───────────────────────────────────────────────────────────────

enum class StepOutcome { Allow, Deny, Abstain };

inline std::ostream& operator<<(std::ostream& os, StepOutcome o) {
    switch (o) {
        case StepOutcome::Allow:   return os << "Allow";
        case StepOutcome::Deny:    return os << "Deny";
        case StepOutcome::Abstain: return os << "Abstain";
        default:                   return os << "Unknown";
    }
}

struct PolicyStep {
    std::string policy_name;
    StepOutcome outcome;
    std::string reason;   // empty when Abstain
};

struct EvaluationTrace {
    RequestContext          context;
    std::vector<PolicyStep> steps;

    std::size_t evaluated_count() const {
        std::size_t count = 0;
        for (const auto& s : steps)
            if (s.outcome != StepOutcome::Abstain) ++count;
        return count;
    }
    std::size_t abstain_count() const { return steps.size() - evaluated_count(); }
};

struct EvaluationResult {
    PolicyDecision  decision;
    EvaluationTrace trace;
};

/**
 * PolicyEngine
 *
 * Evaluates an ordered list of policies against a RequestContext.
 *
 * Resolution strategy (fail-closed):
 *   1. First explicit Deny wins immediately.
 *   2. If at least one Allow and no Deny, access is granted.
 *   3. Default: Deny if no policy explicitly allows.
 */
class PolicyEngine {
public:
    void register_policy(Policy policy);

    EvaluationResult evaluate(const RequestContext& ctx) const;

    std::size_t policy_count() const { return policies_.size(); }

private:
    std::vector<Policy> policies_;
};

// ── Built-in policies ────────────────────────────────────────────────────────

/// Admins bypass all restrictions.
Policy admin_full_access();

/// Deny access to "restricted" resources when MFA has not been verified.
Policy mfa_required_for_restricted();

/// Non-admins cannot write or delete in production.
Policy production_immutability();

/// Analysts are limited to read-only access on non-sensitive resources.
Policy analyst_read_only();

/// Engineers have full access in dev/staging, read-only in production.
Policy engineer_access();

/// Returns a PolicyEngine pre-loaded with all built-in policies in recommended evaluation order.
PolicyEngine default_policy_engine();

} // namespace governance
