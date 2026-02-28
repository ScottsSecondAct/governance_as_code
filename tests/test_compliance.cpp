#include "governance/compliance.hpp"
#include "governance/json.hpp"

#include <iostream>
#include <string>

using namespace governance;

static int passed = 0;
static int failed = 0;

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

// ── Suites ────────────────────────────────────────────────────────────────────

void test_compliant_resources() {
    std::cout << "\n[CompliantResources]\n";
    auto checker = default_compliance_checker();

    Resource r {
        "db-patient-records", "database", "restricted",
        { {"owner", "health-team"} }
    };
    auto report = checker.evaluate(r);
    ASSERT_TRUE("restricted database with owner tag -> compliant",
                report.compliant());
    ASSERT_EQ("zero violations", static_cast<std::size_t>(0),
              report.violations.size());
    ASSERT_EQ("resource id preserved", std::string("db-patient-records"),
              report.resource_id);
}

void test_missing_owner_tag() {
    std::cout << "\n[MissingOwnerTag]\n";
    auto checker = default_compliance_checker();

    Resource r { "db-no-owner", "storage", "internal", {} };
    auto report = checker.evaluate(r);
    ASSERT_TRUE("missing owner tag -> non-compliant", !report.compliant());

    bool found = false;
    for (const auto& v : report.violations)
        if (v.find("RequiresOwnerTag") != std::string::npos) found = true;
    ASSERT_TRUE("RequiresOwnerTag violation present", found);
}

void test_secret_classified_public() {
    std::cout << "\n[SecretNotPublic]\n";
    auto checker = default_compliance_checker();

    Resource r { "secret-api-key", "secret", "public", {{"owner", "devops"}} };
    auto report = checker.evaluate(r);
    ASSERT_TRUE("public secret -> non-compliant", !report.compliant());

    bool found = false;
    for (const auto& v : report.violations)
        if (v.find("SecretsNotPublic") != std::string::npos) found = true;
    ASSERT_TRUE("SecretsNotPublic violation present", found);

    // Non-secret public resource is fine
    Resource r2 { "docs", "storage", "public", {{"owner", "mktg"}} };
    auto report2 = checker.evaluate(r2);
    ASSERT_TRUE("public storage -> compliant", report2.compliant());
}

void test_database_must_be_restricted() {
    std::cout << "\n[DatabasesMustBeRestricted]\n";
    auto checker = default_compliance_checker();

    Resource compliant { "db-ok", "database", "restricted",  {{"owner","t"}} };
    Resource also_ok   { "db-c",  "database", "confidential",{{"owner","t"}} };
    Resource violating { "db-bad","database", "public",      {{"owner","t"}} };

    ASSERT_TRUE("restricted db -> compliant",
                checker.evaluate(compliant).compliant());
    ASSERT_TRUE("confidential db -> compliant",
                checker.evaluate(also_ok).compliant());
    ASSERT_TRUE("public db -> non-compliant",
                !checker.evaluate(violating).compliant());
}

void test_no_unclassified_resources() {
    std::cout << "\n[NoUnclassifiedResources]\n";
    auto checker = default_compliance_checker();

    Resource r { "mystery-box", "storage", "", {{"owner", "unknown"}} };
    auto report = checker.evaluate(r);
    ASSERT_TRUE("empty classification -> non-compliant", !report.compliant());

    bool found = false;
    for (const auto& v : report.violations)
        if (v.find("NoUnclassifiedResources") != std::string::npos) found = true;
    ASSERT_TRUE("NoUnclassifiedResources violation present", found);
}

void test_multiple_violations() {
    std::cout << "\n[MultipleViolations]\n";
    auto checker = default_compliance_checker();

    // Missing owner, database but public, unclassified is not an issue (it IS classified as public)
    Resource rogue { "db-legacy", "database", "public", {} };
    auto report = checker.evaluate(rogue);
    ASSERT_TRUE("rogue db -> non-compliant", !report.compliant());
    ASSERT_EQ("two violations (RequiresOwnerTag + DatabasesMustBeRestricted)",
              static_cast<std::size_t>(2), report.violations.size());
}

void test_custom_rule() {
    std::cout << "\n[CustomRule]\n";
    ComplianceChecker checker;
    checker.add_rule({
        "MustHaveRegionTag",
        "1.0",
        "governance-team",
        "Resource must specify a 'region' tag.",
        [](const Resource& r) { return r.tags.count("region") > 0; }
    });

    Resource with_region    { "svc", "compute", "internal", {{"region","us-east-1"}} };
    Resource without_region { "svc", "compute", "internal", {} };

    ASSERT_TRUE("resource with region tag -> compliant",
                checker.evaluate(with_region).compliant());
    ASSERT_TRUE("resource without region tag -> non-compliant",
                !checker.evaluate(without_region).compliant());
}

void test_rule_count() {
    std::cout << "\n[RuleCount]\n";
    auto checker = default_compliance_checker();
    ASSERT_EQ("default checker has 4 rules",
              static_cast<std::size_t>(4), checker.rule_count());
}

void test_json_compliance_report() {
    std::cout << "\n[JsonComplianceReport]\n";
    auto checker = default_compliance_checker();
    Resource rogue { "db-legacy", "database", "public", {} };
    auto report = checker.evaluate(rogue);
    auto json = to_json(report);
    ASSERT_TRUE("json contains resource_id", json.find("\"db-legacy\"")   != std::string::npos);
    ASSERT_TRUE("json contains compliant false", json.find("false")        != std::string::npos);
    ASSERT_TRUE("json contains violations key",  json.find("violations")   != std::string::npos);
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== Compliance Checker Tests ===\n";

    test_compliant_resources();
    test_missing_owner_tag();
    test_secret_classified_public();
    test_database_must_be_restricted();
    test_no_unclassified_resources();
    test_multiple_violations();
    test_custom_rule();
    test_rule_count();
    test_json_compliance_report();

    std::cout << "\n--- Results: "
              << passed << " passed, " << failed << " failed ---\n";
    return failed == 0 ? 0 : 1;
}
