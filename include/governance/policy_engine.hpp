#pragma once

#include "governance/types.hpp"
#include <functional>
#include <optional>
#include <vector>
#include <string>

namespace governance {

// A Policy is a named rule. Given a context, returns a decision or abstains.
using PolicyFn = std::function<std::optional<PolicyDecision>(const RequestContext&)>;

struct Policy {
    std::string name;
    PolicyFn    evaluate;
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

    PolicyDecision evaluate(const RequestContext& ctx) const;

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
