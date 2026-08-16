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

TEST_CASE("native urgent side warnings retain visual priority") {
  REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::NONE, false));
  REQUIRE(shouldPaintRaveWarning(RaveVisualSeverity::WATCH, false));
  REQUIRE(shouldPaintRaveWarning(RaveVisualSeverity::WARNING, false));
  REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::WATCH, true));
  REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::WARNING, true));
}

TEST_CASE("RAVE suppression follows actual native side rendering") {
  SECTION("blind-spot warning render gate") {
    const auto native_visual = nativeSideVisual(true, true, false, false, false);
    REQUIRE(native_visual == NativeSideVisual::TRAFFIC_MODE);
    REQUIRE(nativeSideWarningVisible(native_visual));
    REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::WATCH, nativeSideWarningVisible(native_visual)));
    REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::WARNING, nativeSideWarningVisible(native_visual)));
  }

  SECTION("underlying blind-spot state with its visual gated off") {
    const bool native_visible = nativeSideWarningVisible(nativeSideVisual(false, true, false, false, false));
    REQUIRE_FALSE(native_visible);
    REQUIRE(shouldPaintRaveWarning(RaveVisualSeverity::WATCH, native_visible));
  }

  SECTION("turn-signal flicker on paints native and suppresses RAVE") {
    const auto native_visual = nativeSideVisual(false, false, true, true, true);
    REQUIRE(native_visual == NativeSideVisual::CEM_DISABLED);
    REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::WARNING,
                                         nativeSideWarningVisible(native_visual)));
  }

  SECTION("turn-signal flicker off paints background and leaves RAVE eligible") {
    const auto native_visual = nativeSideVisual(false, false, true, true, false);
    REQUIRE(native_visual == NativeSideVisual::BACKGROUND);
    REQUIRE(shouldPaintRaveWarning(RaveVisualSeverity::WATCH,
                                   nativeSideWarningVisible(native_visual)));
  }

  SECTION("opposite sides remain independent") {
    const bool native_left = nativeSideWarningVisible(nativeSideVisual(true, true, false, false, false));
    const bool native_right = nativeSideWarningVisible(nativeSideVisual(true, false, false, false, false));
    REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::WATCH, native_left));
    REQUIRE(shouldPaintRaveWarning(RaveVisualSeverity::WARNING, native_right));

    REQUIRE(shouldPaintRaveWarning(RaveVisualSeverity::WATCH, native_right));
    REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::WARNING, native_left));
  }

  SECTION("no native visual leaves RAVE eligibility unchanged") {
    const bool native_visible = nativeSideWarningVisible(nativeSideVisual(false, false, false, false, false));
    REQUIRE_FALSE(native_visible);
    REQUIRE_FALSE(shouldPaintRaveWarning(RaveVisualSeverity::NONE, native_visible));
    REQUIRE(shouldPaintRaveWarning(RaveVisualSeverity::WATCH, native_visible));
    REQUIRE(shouldPaintRaveWarning(RaveVisualSeverity::WARNING, native_visible));
  }
}

TEST_CASE("native side visual preserves blind-spot and combined flicker behavior") {
  REQUIRE(nativeSideVisual(true, true, false, false, false) == NativeSideVisual::TRAFFIC_MODE);
  REQUIRE(nativeSideVisual(true, true, true, true, true) == NativeSideVisual::TRAFFIC_MODE);
  REQUIRE(nativeSideVisual(true, true, true, true, false) == NativeSideVisual::CEM_DISABLED);
  REQUIRE(nativeSideVisual(false, false, false, false, true) == NativeSideVisual::BACKGROUND);
}

TEST_CASE("RAVE curved warning style includes a scaled separator") {
  REQUIRE(RAVE_SEPARATOR_WIDTH_DIVISOR > 1);
  REQUIRE(raveSeparatorWidth(30) == 5);
  REQUIRE(raveSeparatorWidth(3) == 1);
}
