#include "governance/policy_engine.hpp"

namespace governance {

// ── PolicyEngine ─────────────────────────────────────────────────────────────

void PolicyEngine::register_policy(Policy policy) {
    policies_.push_back(std::move(policy));
}

EvaluationResult PolicyEngine::evaluate(const RequestContext& ctx) const {
    EvaluationTrace trace;
    trace.context = ctx;
    std::optional<PolicyDecision> first_allow;

    for (const auto& policy : policies_) {
        auto decision = policy.evaluate(ctx);
        if (!decision) {
            trace.steps.push_back({ policy.name, StepOutcome::Abstain, "" });
            continue;
        }

        if (decision->effect == Effect::Deny) {
            trace.steps.push_back({ policy.name, StepOutcome::Deny, decision->reason });
            return { *decision, std::move(trace) };
        }

        trace.steps.push_back({ policy.name, StepOutcome::Allow, decision->reason });
        if (!first_allow) {
            first_allow = decision;
        }
    }

    if (first_allow) return { *first_allow, std::move(trace) };

    PolicyDecision default_deny { Effect::Deny, "default", "No policy explicitly granted access." };
    return { default_deny, std::move(trace) };
}

// ── Built-in policies ─────────────────────────────────────────────────────────

Policy admin_full_access() {
    return {
        "AdminFullAccess",
        "1.0",
        "governance-team",
        "Grants unrestricted access to all principals with the admin role.",
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
        "1.0",
        "governance-team",
        "Denies access to restricted resources when MFA has not been verified.",
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
        "1.0",
        "governance-team",
        "Prevents non-admin principals from writing or deleting in production.",
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
        "1.0",
        "governance-team",
        "Restricts analysts to read-only access on non-sensitive resources.",
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
        "1.0",
        "governance-team",
        "Grants engineers full access in dev/staging and read-only in production.",
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

PolicyEngine default_policy_engine() {
    PolicyEngine engine;
    engine.register_policy(admin_full_access());
    engine.register_policy(mfa_required_for_restricted());
    engine.register_policy(production_immutability());
    engine.register_policy(analyst_read_only());
    engine.register_policy(engineer_access());
    return engine;
}

} // namespace governance
