cmake_minimum_required(VERSION 3.16)

# ── Test: policy engine ────────────────────────────────────────────────────────
add_executable(test_policy_engine test_policy_engine.cpp)
target_link_libraries(test_policy_engine PRIVATE governance)

add_test(
    NAME PolicyEngineTests
    COMMAND test_policy_engine
)
set_tests_properties(PolicyEngineTests PROPERTIES
    PASS_REGULAR_EXPRESSION "0 failed"
    FAIL_REGULAR_EXPRESSION "[1-9][0-9]* failed"
)

# ── Test: compliance checker ───────────────────────────────────────────────────
add_executable(test_compliance test_compliance.cpp)
target_link_libraries(test_compliance PRIVATE governance)

add_test(
    NAME ComplianceCheckerTests
    COMMAND test_compliance
)
set_tests_properties(ComplianceCheckerTests PROPERTIES
    PASS_REGULAR_EXPRESSION "0 failed"
    FAIL_REGULAR_EXPRESSION "[1-9][0-9]* failed"
)
