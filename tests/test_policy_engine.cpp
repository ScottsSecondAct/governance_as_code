#include "governance/policy_engine.hpp"
#include "governance/json.hpp"

#include <cassert>
#include <iostream>
#include <string>

using namespace governance;

// ── Helpers ──────────────────────────────────────────────────────────────────

static PolicyEngine make_default_engine() {
    return default_policy_engine();
}

static Resource make_resource(const std::string& id,
                               const std::string& type,
                               const std::string& classification,
                               std::unordered_map<std::string, std::string> tags = {}) {
    return { id, type, classification, std::move(tags) };
}

static int passed = 0;
static int failed = 0;

#define ASSERT_EQ(label, expected, actual)                                  \
    do {                                                                    \
        if ((expected) == (actual)) {                                       \
            std::cout << "  [PASS] " << label << "\n";                     \
            ++passed;                                                       \
        } else {                                                            \
            std::cout << "  [FAIL] " << label                              \
                      << "  (expected=" << (expected)                      \
                      << " got=" << (actual) << ")\n";                     \
            ++failed;                                                       \
        }                                                                   \
    } while (0)

#define ASSERT_TRUE(label, expr)                                            \
    do {                                                                    \
        if ((expr)) {                                                       \
            std::cout << "  [PASS] " << label << "\n";                     \
            ++passed;                                                       \
        } else {                                                            \
            std::cout << "  [FAIL] " << label << "\n";                     \
            ++failed;                                                       \
        }                                                                   \
    } while (0)

// ── Test suites ───────────────────────────────────────────────────────────────

void test_admin_full_access() {
    std::cout << "\n[AdminFullAccess]\n";
    auto engine = make_default_engine();
    auto restricted = make_resource("r1", "database", "restricted");

    // Admin with MFA can do anything
    RequestContext ctx;
    ctx.principal = { "alice", "admin", "IT" };
    ctx.resource  = restricted;
    ctx.action    = { "delete" };
    ctx.environment = "production";
    ctx.mfa_verified = true;

    auto d = engine.evaluate(ctx);
    ASSERT_EQ("admin delete restricted in prod -> Allow",
              Effect::Allow, d.decision.effect);
    ASSERT_EQ("policy name", std::string("AdminFullAccess"), d.decision.policy_name);
}

void test_mfa_required_for_restricted() {
    std::cout << "\n[MFARequiredForRestricted]\n";
    auto engine = make_default_engine();
    auto restricted = make_resource("r1", "database", "restricted");

    RequestContext ctx;
    ctx.principal    = { "bob", "engineer", "Backend" };
    ctx.resource     = restricted;
    ctx.action       = { "read" };
    ctx.environment  = "staging";
    ctx.mfa_verified = false;

    auto d = engine.evaluate(ctx);
    ASSERT_EQ("engineer read restricted without MFA -> Deny",
              Effect::Deny, d.decision.effect);
    ASSERT_EQ("policy name", std::string("MFARequiredForRestricted"), d.decision.policy_name);
}

void test_production_immutability() {
    std::cout << "\n[ProductionImmutability]\n";
    auto engine = make_default_engine();
    auto resource = make_resource("api", "compute", "confidential");

    RequestContext ctx;
    ctx.principal    = { "bob", "engineer", "Backend" };
    ctx.resource     = resource;
    ctx.environment  = "production";
    ctx.mfa_verified = false;

    // Write in production -> Deny
    ctx.action = { "write" };
    auto d = engine.evaluate(ctx);
    ASSERT_EQ("engineer write prod -> Deny", Effect::Deny, d.decision.effect);
    ASSERT_EQ("policy name", std::string("ProductionImmutability"), d.decision.policy_name);

    // Delete in production -> Deny
    ctx.action = { "delete" };
    d = engine.evaluate(ctx);
    ASSERT_EQ("engineer delete prod -> Deny", Effect::Deny, d.decision.effect);

    // Read in production -> Allow (falls through to EngineerAccess)
    ctx.action = { "read" };
    d = engine.evaluate(ctx);
    ASSERT_EQ("engineer read prod -> Allow", Effect::Allow, d.decision.effect);

    // Write in staging -> Allow
    ctx.environment = "staging";
    ctx.action = { "write" };
    d = engine.evaluate(ctx);
    ASSERT_EQ("engineer write staging -> Allow", Effect::Allow, d.decision.effect);
}

void test_analyst_read_only() {
    std::cout << "\n[AnalystReadOnly]\n";
    auto engine = make_default_engine();
    auto public_res      = make_resource("docs", "storage",  "public",
                                         {{"owner", "mktg"}});
    auto confidential    = make_resource("db",   "database", "confidential",
                                         {{"owner", "bi"}});
    auto restricted      = make_resource("vault","database", "restricted",
                                         {{"owner", "sec"}});

    Principal analyst = { "carol", "analyst", "DataSci" };

    RequestContext ctx;
    ctx.principal    = analyst;
    ctx.mfa_verified = false;
    ctx.environment  = "dev";

    // Read public -> Allow
    ctx.resource = public_res;
    ctx.action   = { "read" };
    ASSERT_EQ("analyst read public -> Allow",
              Effect::Allow, engine.evaluate(ctx).decision.effect);

    // Write public -> Deny
    ctx.action = { "write" };
    ASSERT_EQ("analyst write public -> Deny",
              Effect::Deny, engine.evaluate(ctx).decision.effect);

    // Read confidential -> Deny
    ctx.resource = confidential;
    ctx.action   = { "read" };
    ASSERT_EQ("analyst read confidential -> Deny",
              Effect::Deny, engine.evaluate(ctx).decision.effect);

    // Read restricted (no MFA) -> Deny via MFA policy
    ctx.resource     = restricted;
    ctx.mfa_verified = false;
    ASSERT_EQ("analyst read restricted no-MFA -> Deny",
              Effect::Deny, engine.evaluate(ctx).decision.effect);
}

void test_engineer_access() {
    std::cout << "\n[EngineerAccess]\n";
    auto engine  = make_default_engine();
    auto resource = make_resource("svc", "compute", "internal",
                                  {{"owner", "platform"}});

    Principal engineer = { "bob", "engineer", "Backend" };

    RequestContext ctx;
    ctx.principal    = engineer;
    ctx.resource     = resource;
    ctx.mfa_verified = false;

    ctx.environment = "dev";
    ctx.action = { "write" };
    ASSERT_EQ("engineer write dev -> Allow",
              Effect::Allow, engine.evaluate(ctx).decision.effect);

    ctx.environment = "staging";
    ASSERT_EQ("engineer write staging -> Allow",
              Effect::Allow, engine.evaluate(ctx).decision.effect);

    ctx.environment = "production";
    ctx.action = { "read" };
    ASSERT_EQ("engineer read prod -> Allow",
              Effect::Allow, engine.evaluate(ctx).decision.effect);

    ctx.action = { "write" };
    ASSERT_EQ("engineer write prod -> Deny",
              Effect::Deny, engine.evaluate(ctx).decision.effect);
}

void test_guest_default_deny() {
    std::cout << "\n[DefaultDeny]\n";
    auto engine   = make_default_engine();
    auto resource = make_resource("docs", "storage", "public", {{"owner", "x"}});

    RequestContext ctx;
    ctx.principal    = { "dave", "guest", "Consulting" };
    ctx.resource     = resource;
    ctx.action       = { "read" };
    ctx.environment  = "dev";
    ctx.mfa_verified = false;

    auto d = engine.evaluate(ctx);
    ASSERT_EQ("guest read public -> Deny (no matching policy)",
              Effect::Deny, d.decision.effect);
    ASSERT_EQ("policy name", std::string("default"), d.decision.policy_name);
}

void test_empty_engine_denies() {
    std::cout << "\n[EmptyEngine]\n";
    PolicyEngine engine; // no policies registered
    Resource resource = make_resource("r", "storage", "public");
    RequestContext ctx;
    ctx.principal   = { "alice", "admin", "IT" };
    ctx.resource    = resource;
    ctx.action      = { "read" };
    ctx.environment = "dev";

    auto d = engine.evaluate(ctx);
    ASSERT_EQ("empty engine always denies", Effect::Deny, d.decision.effect);
}

void test_policy_count() {
    std::cout << "\n[PolicyCount]\n";
    auto engine = make_default_engine();
    ASSERT_EQ("default engine has 5 policies",
              static_cast<std::size_t>(5), engine.policy_count());
}

void test_evaluation_trace() {
    std::cout << "\n[EvaluationTrace]\n";

    // Custom 2-policy engine: first abstains, second allows
    PolicyEngine engine;
    engine.register_policy({
        "AlwaysAbstain", "1.0", "test", "Always abstains.",
        [](const RequestContext&) -> std::optional<PolicyDecision> {
            return std::nullopt;
        }
    });
    engine.register_policy({
        "AlwaysAllow", "1.0", "test", "Always allows.",
        [](const RequestContext&) -> std::optional<PolicyDecision> {
            return PolicyDecision{ Effect::Allow, "AlwaysAllow", "Always allowed." };
        }
    });

    RequestContext ctx;
    ctx.principal   = { "bob", "engineer", "Backend" };
    ctx.resource    = { "r1", "storage", "public", {} };
    ctx.action      = { "read" };
    ctx.environment = "dev";

    auto result = engine.evaluate(ctx);
    ASSERT_EQ("decision is Allow", Effect::Allow, result.decision.effect);
    ASSERT_EQ("trace has 2 steps", static_cast<std::size_t>(2), result.trace.steps.size());
    ASSERT_EQ("first step abstains", StepOutcome::Abstain, result.trace.steps[0].outcome);
    ASSERT_EQ("second step allows",  StepOutcome::Allow,   result.trace.steps[1].outcome);
    ASSERT_EQ("evaluated_count == 1", static_cast<std::size_t>(1), result.trace.evaluated_count());
    ASSERT_EQ("abstain_count == 1",   static_cast<std::size_t>(1), result.trace.abstain_count());

    // Single-policy deny engine -> trace has 1 step
    PolicyEngine deny_engine;
    deny_engine.register_policy({
        "AlwaysDeny", "1.0", "test", "Always denies.",
        [](const RequestContext&) -> std::optional<PolicyDecision> {
            return PolicyDecision{ Effect::Deny, "AlwaysDeny", "Always denied." };
        }
    });

    auto deny_result = deny_engine.evaluate(ctx);
    ASSERT_EQ("deny trace has 1 step",    static_cast<std::size_t>(1), deny_result.trace.steps.size());
    ASSERT_EQ("deny evaluated_count == 1", static_cast<std::size_t>(1), deny_result.trace.evaluated_count());
    ASSERT_EQ("deny abstain_count == 0",   static_cast<std::size_t>(0), deny_result.trace.abstain_count());
}

void test_trace_context_preserved() {
    std::cout << "\n[TraceContextPreserved]\n";
    auto engine = make_default_engine();

    RequestContext ctx;
    ctx.principal    = { "alice@corp.io", "admin", "IT" };
    ctx.resource     = { "db-patient-records", "database", "restricted", {} };
    ctx.action       = { "read" };
    ctx.environment  = "production";
    ctx.mfa_verified = true;

    auto result = engine.evaluate(ctx);
    ASSERT_EQ("trace preserves principal id",
              std::string("alice@corp.io"), result.trace.context.principal.id);
    ASSERT_EQ("trace preserves resource id",
              std::string("db-patient-records"), result.trace.context.resource.id);
    ASSERT_EQ("trace preserves action",
              std::string("read"), result.trace.context.action.verb);
    ASSERT_EQ("trace preserves environment",
              std::string("production"), result.trace.context.environment);
}

void test_json_policy_decision() {
    std::cout << "\n[JsonPolicyDecision]\n";
    PolicyDecision d { Effect::Allow, "TestPolicy", "Test reason." };
    auto json = to_json(d);
    ASSERT_TRUE("json contains effect",      json.find("\"Allow\"")       != std::string::npos);
    ASSERT_TRUE("json contains policy_name", json.find("\"TestPolicy\"")  != std::string::npos);
    ASSERT_TRUE("json contains reason",      json.find("\"Test reason.\"") != std::string::npos);
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== Policy Engine Tests ===\n";

    test_admin_full_access();
    test_mfa_required_for_restricted();
    test_production_immutability();
    test_analyst_read_only();
    test_engineer_access();
    test_guest_default_deny();
    test_empty_engine_denies();
    test_policy_count();
    test_evaluation_trace();
    test_trace_context_preserved();
    test_json_policy_decision();

    std::cout << "\n--- Results: "
              << passed << " passed, " << failed << " failed ---\n";
    return failed == 0 ? 0 : 1;
}
