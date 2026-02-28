#pragma once

#include "governance/types.hpp"
#include <functional>
#include <vector>
#include <string>

namespace governance {

struct ComplianceRule {
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    std::function<bool(const Resource&)> check;
};

struct ComplianceReport {
    std::string              resource_id;
    std::vector<std::string> violations;

    bool compliant() const { return violations.empty(); }
};

/**
 * ComplianceChecker
 *
 * Evaluates a Resource against a set of named ComplianceRules and
 * produces a ComplianceReport listing any violations.
 */
class ComplianceChecker {
public:
    void add_rule(ComplianceRule rule);

    ComplianceReport evaluate(const Resource& resource) const;

    std::size_t rule_count() const { return rules_.size(); }

private:
    std::vector<ComplianceRule> rules_;
};

// ── Built-in compliance rules ─────────────────────────────────────────────

/// Returns a ComplianceChecker pre-loaded with standard governance rules.
ComplianceChecker default_compliance_checker();

} // namespace governance
