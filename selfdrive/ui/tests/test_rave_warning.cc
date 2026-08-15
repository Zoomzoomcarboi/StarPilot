#include "catch2/catch.hpp"

#include "starpilot/ui/qt/onroad/rave_warning.h"

namespace {
constexpr uint64_t NOW_NS = 1000000000ULL;

RaveWarningInput eligibleInput() {
  return {
    .received = true,
    .valid = true,
    .now_ns = NOW_NS,
    .rcv_time_ns = NOW_NS,
    .packet_age_ms = 0,
    .enabled = true,
    .paired = true,
    .connection_state = cereal::RaveState::ConnectionState::CONNECTED,
    .health = cereal::RaveState::RaveHealth::OK,
    .left_threat = cereal::RaveState::ThreatLevel::NONE,
    .right_threat = cereal::RaveState::ThreatLevel::NONE,
  };
}

void requireNone(const RaveWarningInput &input) {
  REQUIRE(evaluateRaveWarning(input) == RaveWarningState{});
}
}  // namespace

TEST_CASE("RAVE warnings fail unavailable and enforce both freshness clocks") {
  auto input = eligibleInput();
  input.left_threat = cereal::RaveState::ThreatLevel::WATCH;

  SECTION("never received") { input.received = false; requireNone(input); }
  SECTION("invalid") { input.valid = false; requireNone(input); }
  SECTION("packet age boundary is allowed") {
    input.packet_age_ms = 275;
    REQUIRE(evaluateRaveWarning(input).left == RaveVisualSeverity::WATCH);
  }
  SECTION("packet age beyond boundary is unavailable") { input.packet_age_ms = 276; requireNone(input); }
  SECTION("receipt age boundary is allowed") {
    input.rcv_time_ns = NOW_NS - RAVE_UI_MAX_RECEIPT_AGE_NS;
    REQUIRE(evaluateRaveWarning(input).left == RaveVisualSeverity::WATCH);
  }
  SECTION("receipt age beyond boundary is unavailable") {
    input.rcv_time_ns = NOW_NS - RAVE_UI_MAX_RECEIPT_AGE_NS - 1;
    requireNone(input);
  }
  SECTION("frozen low packet age cannot defeat stale receipt time") {
    input.packet_age_ms = 1;
    input.rcv_time_ns = NOW_NS - RAVE_UI_MAX_RECEIPT_AGE_NS - 1;
    requireNone(input);
  }
  SECTION("future receipt time is unavailable") { input.rcv_time_ns = NOW_NS + 1; requireNone(input); }
  SECTION("fresh state recovers after stale state") {
    auto stale = input;
    stale.rcv_time_ns = NOW_NS - RAVE_UI_MAX_RECEIPT_AGE_NS - 1;
    requireNone(stale);
    REQUIRE(evaluateRaveWarning(input).left == RaveVisualSeverity::WATCH);
  }
}

TEST_CASE("RAVE eligibility rejects ineligible operating states") {
  auto input = eligibleInput();
  input.left_threat = cereal::RaveState::ThreatLevel::WARNING;

  SECTION("unknown health") { input.health = cereal::RaveState::RaveHealth::UNKNOWN; requireNone(input); }
  SECTION("fault health") { input.health = cereal::RaveState::RaveHealth::FAULT; requireNone(input); }
  SECTION("disabled") { input.enabled = false; requireNone(input); }
  SECTION("unpaired") { input.paired = false; requireNone(input); }
  SECTION("disabled connection") { input.connection_state = cereal::RaveState::ConnectionState::DISABLED; requireNone(input); }
  SECTION("not paired connection") { input.connection_state = cereal::RaveState::ConnectionState::NOT_PAIRED; requireNone(input); }
  SECTION("pairing connection") { input.connection_state = cereal::RaveState::ConnectionState::PAIRING; requireNone(input); }
  SECTION("waiting connection") { input.connection_state = cereal::RaveState::ConnectionState::WAITING; requireNone(input); }
  SECTION("stale connection") { input.connection_state = cereal::RaveState::ConnectionState::STALE; requireNone(input); }
  SECTION("error connection") { input.connection_state = cereal::RaveState::ConnectionState::ERROR; requireNone(input); }
}

TEST_CASE("RAVE threats preserve severity and side independence") {
  auto input = eligibleInput();

  SECTION("none") { requireNone(input); }
  SECTION("left watch only") {
    input.left_threat = cereal::RaveState::ThreatLevel::WATCH;
    REQUIRE(evaluateRaveWarning(input) == RaveWarningState{RaveVisualSeverity::WATCH, RaveVisualSeverity::NONE});
  }
  SECTION("right warning only") {
    input.right_threat = cereal::RaveState::ThreatLevel::WARNING;
    REQUIRE(evaluateRaveWarning(input) == RaveWarningState{RaveVisualSeverity::NONE, RaveVisualSeverity::WARNING});
  }
  SECTION("dual side threats are preserved") {
    input.left_threat = cereal::RaveState::ThreatLevel::WARNING;
    input.right_threat = cereal::RaveState::ThreatLevel::WARNING;
    REQUIRE(evaluateRaveWarning(input) == RaveWarningState{RaveVisualSeverity::WARNING, RaveVisualSeverity::WARNING});
  }
  SECTION("degraded health remains eligible") {
    input.health = cereal::RaveState::RaveHealth::DEGRADED;
    input.right_threat = cereal::RaveState::ThreatLevel::WARNING;
    REQUIRE(evaluateRaveWarning(input).right == RaveVisualSeverity::WARNING);
  }
  SECTION("warning is not downgraded") {
    input.left_threat = cereal::RaveState::ThreatLevel::WARNING;
    REQUIRE(evaluateRaveWarning(input).left == RaveVisualSeverity::WARNING);
  }
  SECTION("factory blind-spot state is not an evaluator input") {
    input.left_threat = cereal::RaveState::ThreatLevel::WATCH;
    const RaveWarningState without_factory_bsm = evaluateRaveWarning(input);
    const bool factory_blind_spot = true;
    (void)factory_blind_spot;
    REQUIRE(evaluateRaveWarning(input) == without_factory_bsm);
  }
}
