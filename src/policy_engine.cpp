#include "governance/policy_engine.hpp"

namespace governance {

// ── PolicyEngine ─────────────────────────────────────────────────────────────

void PolicyEngine::register_policy(Policy policy) {
    policies_.push_back(std::move(policy));
}

PolicyDecision PolicyEngine::evaluate(const RequestContext& ctx) const {
    std::optional<PolicyDecision> first_allow;

    for (const auto& policy : policies_) {
        auto decision = policy.evaluate(ctx);
        if (!decision) continue; // abstain

        if (decision->effect == Effect::Deny) {
            return *decision; // Deny wins immediately
        }
        if (!first_allow) {
            first_allow = decision;
        }
    }

    if (first_allow) return *first_allow;

    return { Effect::Deny, "default", "No policy explicitly granted access." };
}

// ── Built-in policies ─────────────────────────────────────────────────────────

Policy admin_full_access() {
    return {
        "AdminFullAccess",
        [](const RequestContext& ctx) -> std::optional<PolicyDecision> {
            if (ctx.principal.role == "admin") {
                return PolicyDecision{ Effect::Allow, "AdminFullAccess",
                    "Admin role has unrestricted access." };
            }
            return std::nullopt;
        }
    };
}

Policy mfa_required_for_restricted() {
    return {
        "MFARequiredForRestricted",
        [](const RequestContext& ctx) -> std::optional<PolicyDecision> {
            if (ctx.resource.classification == "restricted" && !ctx.mfa_verified) {
                return PolicyDecision{ Effect::Deny, "MFARequiredForRestricted",
                    "MFA required to access restricted resources." };
            }
            return std::nullopt;
        }
    };
}

Policy production_immutability() {
    return {
        "ProductionImmutability",
        [](const RequestContext& ctx) -> std::optional<PolicyDecision> {
            if (ctx.environment == "production" &&
                ctx.principal.role != "admin" &&
                (ctx.action.verb == "write" || ctx.action.verb == "delete")) {
                return PolicyDecision{ Effect::Deny, "ProductionImmutability",
                    "Write/delete operations require admin role in production." };
            }
            return std::nullopt;
        }
    };
}

Policy analyst_read_only() {
    return {
        "AnalystReadOnly",
        [](const RequestContext& ctx) -> std::optional<PolicyDecision> {
            if (ctx.principal.role != "analyst") return std::nullopt;

            if (ctx.action.verb != "read") {
                return PolicyDecision{ Effect::Deny, "AnalystReadOnly",
                    "Analysts are limited to read-only access." };
            }
            if (ctx.resource.classification == "restricted" ||
                ctx.resource.classification == "confidential") {
                return PolicyDecision{ Effect::Deny, "AnalystReadOnly",
                    "Analysts cannot access confidential or restricted data." };
            }
            return PolicyDecision{ Effect::Allow, "AnalystReadOnly",
                "Analyst read access on non-sensitive resource allowed." };
        }
    };
}

Policy engineer_access() {
    return {
        "EngineerAccess",
        [](const RequestContext& ctx) -> std::optional<PolicyDecision> {
            if (ctx.principal.role != "engineer") return std::nullopt;

            // Defer restricted resources to other policies (e.g. MFA check)
            if (ctx.resource.classification == "restricted") return std::nullopt;

            if (ctx.environment == "dev" || ctx.environment == "staging") {
                return PolicyDecision{ Effect::Allow, "EngineerAccess",
                    "Engineers have full access in non-production environments." };
            }
            if (ctx.environment == "production" && ctx.action.verb == "read") {
                return PolicyDecision{ Effect::Allow, "EngineerAccess",
                    "Engineers can read production resources." };
            }
            return std::nullopt;
        }
    };
}

} // namespace governance
