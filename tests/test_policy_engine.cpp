#include "governance/policy_engine.hpp"

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
              Effect::Allow, d.effect);
    ASSERT_EQ("policy name", std::string("AdminFullAccess"), d.policy_name);
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
              Effect::Deny, d.effect);
    ASSERT_EQ("policy name", std::string("MFARequiredForRestricted"), d.policy_name);
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
    ASSERT_EQ("engineer write prod -> Deny", Effect::Deny, d.effect);
    ASSERT_EQ("policy name", std::string("ProductionImmutability"), d.policy_name);

    // Delete in production -> Deny
    ctx.action = { "delete" };
    d = engine.evaluate(ctx);
    ASSERT_EQ("engineer delete prod -> Deny", Effect::Deny, d.effect);

    // Read in production -> Allow (falls through to EngineerAccess)
    ctx.action = { "read" };
    d = engine.evaluate(ctx);
    ASSERT_EQ("engineer read prod -> Allow", Effect::Allow, d.effect);

    // Write in staging -> Allow
    ctx.environment = "staging";
    ctx.action = { "write" };
    d = engine.evaluate(ctx);
    ASSERT_EQ("engineer write staging -> Allow", Effect::Allow, d.effect);
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
              Effect::Allow, engine.evaluate(ctx).effect);

    // Write public -> Deny
    ctx.action = { "write" };
    ASSERT_EQ("analyst write public -> Deny",
              Effect::Deny, engine.evaluate(ctx).effect);

    // Read confidential -> Deny
    ctx.resource = confidential;
    ctx.action   = { "read" };
    ASSERT_EQ("analyst read confidential -> Deny",
              Effect::Deny, engine.evaluate(ctx).effect);

    // Read restricted (no MFA) -> Deny via MFA policy
    ctx.resource     = restricted;
    ctx.mfa_verified = false;
    ASSERT_EQ("analyst read restricted no-MFA -> Deny",
              Effect::Deny, engine.evaluate(ctx).effect);
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
              Effect::Allow, engine.evaluate(ctx).effect);

    ctx.environment = "staging";
    ASSERT_EQ("engineer write staging -> Allow",
              Effect::Allow, engine.evaluate(ctx).effect);

    ctx.environment = "production";
    ctx.action = { "read" };
    ASSERT_EQ("engineer read prod -> Allow",
              Effect::Allow, engine.evaluate(ctx).effect);

    ctx.action = { "write" };
    ASSERT_EQ("engineer write prod -> Deny",
              Effect::Deny, engine.evaluate(ctx).effect);
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
              Effect::Deny, d.effect);
    ASSERT_EQ("policy name", std::string("default"), d.policy_name);
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
    ASSERT_EQ("empty engine always denies", Effect::Deny, d.effect);
}

void test_policy_count() {
    std::cout << "\n[PolicyCount]\n";
    auto engine = make_default_engine();
    ASSERT_EQ("default engine has 5 policies",
              static_cast<std::size_t>(5), engine.policy_count());
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

    std::cout << "\n--- Results: "
              << passed << " passed, " << failed << " failed ---\n";
    return failed == 0 ? 0 : 1;
}
