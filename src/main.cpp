#include "governance/policy_engine.hpp"
#include "governance/compliance.hpp"

#include <iostream>
#include <string>
#include <vector>

using namespace governance;

static std::string effect_str(Effect e) {
    return e == Effect::Allow ? "[ALLOW]" : "[DENY] ";
}

static void print_decision(const RequestContext& ctx, const PolicyDecision& d) {
    std::cout << "\n  Principal : " << ctx.principal.id
              << " [" << ctx.principal.role << "]\n"
              << "  Resource  : " << ctx.resource.id
              << " (" << ctx.resource.classification << ")\n"
              << "  Action    : " << ctx.action.verb
              << " @ " << ctx.environment
              << (ctx.mfa_verified ? " [MFA]" : "") << "\n"
              << "  Decision  : " << effect_str(d.effect)
              << " <- " << d.policy_name << "\n"
              << "  Reason    : " << d.reason << "\n";
}

static void separator(const std::string& title) {
    std::cout << "\n" << std::string(55, '-') << "\n"
              << "  " << title << "\n"
              << std::string(55, '-') << "\n";
}

int main() {
    // ── Build Policy Engine ──────────────────────────────────────────────────
    auto engine = default_policy_engine();

    // ── Define Resources ─────────────────────────────────────────────────────
    Resource patient_db {
        "db-patient-records", "database", "restricted",
        { {"owner", "health-team"}, {"region", "us-west-2"} }
    };
    Resource public_docs {
        "storage-public-docs", "storage", "public",
        { {"owner", "marketing"} }
    };
    Resource prod_api {
        "compute-prod-api", "compute", "confidential",
        { {"env", "production"}, {"owner", "platform-team"} }
    };

    // ── Define Principals ────────────────────────────────────────────────────
    Principal alice { "alice@corp.io", "admin",    "IT"         };
    Principal bob   { "bob@corp.io",   "engineer", "Backend"    };
    Principal carol { "carol@corp.io", "analyst",  "DataSci"    };
    Principal dave  { "dave@corp.io",  "guest",    "Consulting" };

    // ── Access Control Scenarios ─────────────────────────────────────────────
    separator("ACCESS CONTROL EVALUATION");

    std::vector<RequestContext> scenarios = {
        { alice, patient_db,  {"read"},   "production", true  },
        { bob,   prod_api,    {"write"},  "production", false },
        { bob,   prod_api,    {"read"},   "production", false },
        { bob,   prod_api,    {"write"},  "staging",    false },
        { carol, public_docs, {"read"},   "dev",        false },
        { carol, patient_db,  {"read"},   "production", true  },
        { dave,  public_docs, {"read"},   "dev",        false },
        { bob,   patient_db,  {"read"},   "staging",    false },
        { bob,   patient_db,  {"read"},   "staging",    true  },
    };

    for (const auto& ctx : scenarios) {
        print_decision(ctx, engine.evaluate(ctx));
    }

    // ── Compliance Checks ────────────────────────────────────────────────────
    separator("COMPLIANCE CHECKS");

    auto checker = default_compliance_checker();

    Resource rogue_db {
        "db-legacy-public", "database", "public",
        { /* missing owner tag */ }
    };

    for (const auto* res : { &patient_db, &public_docs, &rogue_db }) {
        auto report = checker.evaluate(*res);
        std::cout << "\n  Resource : " << report.resource_id << "\n";
        if (report.compliant()) {
            std::cout << "  Status   : Compliant\n";
        } else {
            std::cout << "  Status   : Non-Compliant ("
                      << report.violations.size() << " violation(s))\n";
            for (const auto& v : report.violations)
                std::cout << "             -> " << v << "\n";
        }
    }

    std::cout << "\n" << std::string(55, '-') << "\n"
              << "  Governance evaluation complete.\n"
              << std::string(55, '-') << "\n\n";
    return 0;
}
