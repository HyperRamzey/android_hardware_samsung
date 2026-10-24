/*
 * SPDX-FileCopyrightText: 2025 The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fstream>

#include "HighTouchPollingRate.h"

namespace aidl {
namespace vendor {
namespace lineage {
namespace touch {

// Re-scan the command list on every call rather than trusting a value captured
// in the constructor: this service starts at early-init, before the ist40xx
// driver has necessarily published /sys/class/sec/tsp/cmd_list.
void HighTouchPollingRate::probe() {
    mHtprCmd.clear();

    std::ifstream file(TSP_CMD_LIST_NODE);
    if (!file.is_open()) return;

    std::string line;
    while (getline(file, line)) {
        if (!line.compare("set_game_mode") || !line.compare("set_scan_rate")) {
            mHtprCmd = line;
            break;
        }
    }
}

bool HighTouchPollingRate::isSupported() {
    probe();
    return !mHtprCmd.empty();
}

ndk::ScopedAStatus HighTouchPollingRate::getEnabled(bool* _aidl_return) {
    probe();
    *_aidl_return = false;

    if (mHtprCmd.empty()) return ndk::ScopedAStatus::ok();

    std::ifstream file(TSP_CMD_RESULT_NODE);
    if (file.is_open()) {
        std::string line;
        getline(file, line);
        *_aidl_return = !line.compare(mHtprCmd + ",1:OK");
        file.close();
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus HighTouchPollingRate::setEnabled(bool enabled) {
    probe();
    // Nothing to drive on this panel - never emit a malformed ",1".
    if (mHtprCmd.empty()) return ndk::ScopedAStatus::ok();

    std::ofstream file(TSP_CMD_NODE);
    file << (mHtprCmd + ",") << (enabled ? "1" : "0");

    return ndk::ScopedAStatus::ok();
}

}  // namespace touch
}  // namespace lineage
}  // namespace vendor
}  // namespace aidl
