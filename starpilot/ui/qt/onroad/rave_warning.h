#pragma once

#include <algorithm>
#include <cstdint>

#include "cereal/gen/cpp/custom.capnp.h"

constexpr uint64_t RAVE_UI_MAX_RECEIPT_AGE_NS = 275000000ULL;
constexpr uint16_t RAVE_MAX_PACKET_AGE_MS = 275;

enum class RaveVisualSeverity : uint8_t {
  NONE,
  WATCH,
  WARNING,
};

enum class NativeSideVisual : uint8_t {
  BACKGROUND,
  TRAFFIC_MODE,
  CEM_DISABLED,
};

constexpr int RAVE_SEPARATOR_WIDTH_DIVISOR = 6;

struct RaveWarningState {
  RaveVisualSeverity left = RaveVisualSeverity::NONE;
  RaveVisualSeverity right = RaveVisualSeverity::NONE;

  bool operator==(const RaveWarningState &other) const {
    return left == other.left && right == other.right;
  }
  bool operator!=(const RaveWarningState &other) const { return !(*this == other); }
};

struct RaveWarningInput {
  bool received;
  bool valid;
  uint64_t now_ns;
  uint64_t rcv_time_ns;
  uint16_t packet_age_ms;
  bool enabled;
  bool paired;
  cereal::RaveState::ConnectionState connection_state;
  cereal::RaveState::RaveHealth health;
  cereal::RaveState::ThreatLevel left_threat;
  cereal::RaveState::ThreatLevel right_threat;
};

inline RaveVisualSeverity raveVisualSeverity(cereal::RaveState::ThreatLevel threat) {
  switch (threat) {
    case cereal::RaveState::ThreatLevel::WATCH:
      return RaveVisualSeverity::WATCH;
    case cereal::RaveState::ThreatLevel::WARNING:
      return RaveVisualSeverity::WARNING;
    case cereal::RaveState::ThreatLevel::NONE:
    default:
      return RaveVisualSeverity::NONE;
  }
}

inline bool shouldPaintRaveWarning(RaveVisualSeverity severity, bool native_urgent) {
  return severity != RaveVisualSeverity::NONE && !native_urgent;
}

inline NativeSideVisual nativeSideVisual(bool show_blindspot, bool blindspot,
                                         bool show_signal, bool turn_signal,
                                         bool flicker_active) {
  if (turn_signal && show_signal) {
    if (blindspot) {
      return flicker_active ? NativeSideVisual::TRAFFIC_MODE : NativeSideVisual::CEM_DISABLED;
    }
    return flicker_active ? NativeSideVisual::CEM_DISABLED : NativeSideVisual::BACKGROUND;
  }
  return blindspot && show_blindspot ? NativeSideVisual::TRAFFIC_MODE : NativeSideVisual::BACKGROUND;
}

inline bool nativeSideWarningVisible(NativeSideVisual visual) {
  return visual != NativeSideVisual::BACKGROUND;
}

inline int raveSeparatorWidth(int scaled_border_width) {
  return std::max(1, scaled_border_width / RAVE_SEPARATOR_WIDTH_DIVISOR);
}

inline RaveWarningState evaluateRaveWarning(const RaveWarningInput &input) {
  const bool clock_valid = input.now_ns >= input.rcv_time_ns;
  const bool receipt_fresh = clock_valid &&
                             input.now_ns - input.rcv_time_ns <= RAVE_UI_MAX_RECEIPT_AGE_NS;
  const bool health_eligible = input.health == cereal::RaveState::RaveHealth::OK ||
                               input.health == cereal::RaveState::RaveHealth::DEGRADED;

  if (!input.received || !input.valid || !receipt_fresh ||
      input.packet_age_ms > RAVE_MAX_PACKET_AGE_MS || !input.enabled || !input.paired ||
      input.connection_state != cereal::RaveState::ConnectionState::CONNECTED || !health_eligible) {
    return {};
  }

  return {raveVisualSeverity(input.left_threat), raveVisualSeverity(input.right_threat)};
}
