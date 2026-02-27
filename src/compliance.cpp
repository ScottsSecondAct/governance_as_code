#include "governance/compliance.hpp"

namespace governance {

// ── ComplianceChecker ─────────────────────────────────────────────────────────

void ComplianceChecker::add_rule(ComplianceRule rule) {
    rules_.push_back(std::move(rule));
}

ComplianceReport ComplianceChecker::evaluate(const Resource& resource) const {
    ComplianceReport report;
    report.resource_id = resource.id;

    for (const auto& rule : rules_) {
        if (!rule.check(resource)) {
            report.violations.push_back("[" + rule.name + "] " + rule.description);
        }
    }
    return report;
}

// ── Default rules ─────────────────────────────────────────────────────────────

ComplianceChecker default_compliance_checker() {
    ComplianceChecker checker;

    checker.add_rule({
        "RequiresOwnerTag",
        "Resource must have an 'owner' tag.",
        [](const Resource& r) {
            return r.tags.count("owner") > 0;
        }
    });

    checker.add_rule({
        "SecretsNotPublic",
        "Resources of type 'secret' must not be classified as 'public'.",
        [](const Resource& r) {
            return !(r.type == "secret" && r.classification == "public");
        }
    });

    checker.add_rule({
        "DatabasesMustBeRestricted",
        "Database resources must be classified as 'restricted' or 'confidential'.",
        [](const Resource& r) {
            if (r.type != "database") return true;
            return r.classification == "restricted" ||
                   r.classification == "confidential";
        }
    });

    checker.add_rule({
        "NoUnclassifiedResources",
        "Every resource must have a non-empty classification.",
        [](const Resource& r) {
            return !r.classification.empty();
        }
    });

    return checker;
}

} // namespace governance
