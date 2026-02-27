#pragma once

#include <ostream>
#include <string>
#include <unordered_map>

namespace governance {

enum class Effect { Allow, Deny };

struct Principal {
    std::string id;
    std::string role;           // "admin", "engineer", "analyst", "guest"
    std::string department;
};

struct Resource {
    std::string id;
    std::string type;           // "database", "storage", "compute", "secret"
    std::string classification; // "public", "internal", "confidential", "restricted"
    std::unordered_map<std::string, std::string> tags;
};

struct Action {
    std::string verb;           // "read", "write", "delete", "execute"
};

struct RequestContext {
    Principal   principal;
    Resource    resource;
    Action      action;
    std::string environment;    // "production", "staging", "dev"
    bool        mfa_verified = false;
};

struct PolicyDecision {
    Effect      effect;
    std::string policy_name;
    std::string reason;
};

inline std::ostream& operator<<(std::ostream& os, Effect e) {
    return os << (e == Effect::Allow ? "Allow" : "Deny");
}

} // namespace governance
