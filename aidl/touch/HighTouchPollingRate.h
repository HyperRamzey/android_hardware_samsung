/*
 * SPDX-FileCopyrightText: 2025 The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <aidl/vendor/lineage/touch/BnHighTouchPollingRate.h>
#include <samsung_touch.h>
#include <fstream>

namespace aidl {
namespace vendor {
namespace lineage {
namespace touch {

class HighTouchPollingRate : public BnHighTouchPollingRate {
  public:
    HighTouchPollingRate() = default;

    bool isSupported();

    ndk::ScopedAStatus getEnabled(bool* _aidl_return) override;
    ndk::ScopedAStatus setEnabled(bool enabled) override;

  private:
    // Re-read the command list on demand instead of caching it in the
    // constructor. This HAL starts at early-init, long before the ist40xx
    // driver publishes /sys/class/sec/tsp/cmd_list, so a constructor-cached
    // capability could never become true on a slow boot - and setEnabled()
    // would then have written a malformed ",1" to the command node.
    void probe();

    std::string mHtprCmd;
};

}  // namespace touch
}  // namespace lineage
}  // namespace vendor
}  // namespace aidl
