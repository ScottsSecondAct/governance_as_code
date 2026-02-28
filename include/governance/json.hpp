#pragma once

#include "governance/policy_engine.hpp"
#include "governance/compliance.hpp"

#include <sstream>
#include <string>

namespace governance {

namespace json_detail {

inline std::string escape(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:   result += c;      break;
        }
    }
    return result;
}

inline std::string quoted(const std::string& s) {
    return "\"" + escape(s) + "\"";
}

inline std::string effect_str(Effect e) {
    return e == Effect::Allow ? "Allow" : "Deny";
}

inline std::string outcome_str(StepOutcome o) {
    switch (o) {
        case StepOutcome::Allow:   return "Allow";
        case StepOutcome::Deny:    return "Deny";
        case StepOutcome::Abstain: return "Abstain";
        default:                   return "Unknown";
    }
}

} // namespace json_detail

inline std::string to_json(const PolicyDecision& d) {
    std::ostringstream os;
    os << "{\n"
       << "  \"effect\": "      << json_detail::quoted(json_detail::effect_str(d.effect)) << ",\n"
       << "  \"policy_name\": " << json_detail::quoted(d.policy_name) << ",\n"
       << "  \"reason\": "      << json_detail::quoted(d.reason) << "\n"
       << "}";
    return os.str();
}

inline std::string to_json(const PolicyStep& step) {
    std::ostringstream os;
    os << "{ \"policy\": "  << json_detail::quoted(step.policy_name)
       << ", \"outcome\": " << json_detail::quoted(json_detail::outcome_str(step.outcome))
       << ", \"reason\": "  << json_detail::quoted(step.reason)
       << " }";
    return os.str();
}

inline std::string to_json(const EvaluationResult& result) {
    std::ostringstream os;
    const auto& d = result.decision;
    const auto& t = result.trace;
    os << "{\n"
       << "  \"decision\": {\n"
       << "    \"effect\": "      << json_detail::quoted(json_detail::effect_str(d.effect)) << ",\n"
       << "    \"policy_name\": " << json_detail::quoted(d.policy_name) << ",\n"
       << "    \"reason\": "      << json_detail::quoted(d.reason) << "\n"
       << "  },\n"
       << "  \"trace\": {\n"
       << "    \"principal\": "   << json_detail::quoted(t.context.principal.id) << ",\n"
       << "    \"resource\": "    << json_detail::quoted(t.context.resource.id) << ",\n"
       << "    \"action\": "      << json_detail::quoted(t.context.action.verb) << ",\n"
       << "    \"environment\": " << json_detail::quoted(t.context.environment) << ",\n"
       << "    \"steps\": [";
    for (std::size_t i = 0; i < t.steps.size(); ++i) {
        os << "\n      " << to_json(t.steps[i]);
        if (i + 1 < t.steps.size()) os << ",";
    }
    os << "\n    ]\n"
       << "  }\n"
       << "}";
    return os.str();
}

inline std::string to_json(const ComplianceReport& report) {
    std::ostringstream os;
    os << "{\n"
       << "  \"resource_id\": " << json_detail::quoted(report.resource_id) << ",\n"
       << "  \"compliant\": "   << (report.compliant() ? "true" : "false") << ",\n"
       << "  \"violations\": [";
    for (std::size_t i = 0; i < report.violations.size(); ++i) {
        os << "\n    " << json_detail::quoted(report.violations[i]);
        if (i + 1 < report.violations.size()) os << ",";
    }
    os << "\n  ]\n"
       << "}";
    return os.str();
}

} // namespace governance
