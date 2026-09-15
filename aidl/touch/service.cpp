/*
 * SPDX-FileCopyrightText: 2025 The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "vendor.lineage.touch-service.samsung"

#include <unistd.h>

#include "GloveMode.h"
#include "HighTouchPollingRate.h"
#include "KeyDisabler.h"
#include "StylusMode.h"
#include "TouchscreenGesture.h"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

using aidl::vendor::lineage::touch::GloveMode;
using aidl::vendor::lineage::touch::HighTouchPollingRate;
using aidl::vendor::lineage::touch::KeyDisabler;
using aidl::vendor::lineage::touch::StylusMode;
using aidl::vendor::lineage::touch::TouchscreenGesture;

// A30s: the ist40xx touchscreen driver sometimes hasn't published its sysfs
// nodes (/sys/class/sec/tsp/*, sec_touchkey, sec_epen) when this HAL starts,
// so every isSupported() probe fails and nothing gets registered. Since the
// instances are VINTF-declared, system_server waits for them forever and boot
// hangs. Retry the probe instead of deciding once: break as soon as the
// driver proves itself (anything registered, nothing left pending); otherwise
// keep retrying, bounded, then fall through to the old idle behavior.
static constexpr int kMaxProbeAttempts = 120;
static constexpr unsigned int kProbeRetryDelaySec = 5;

// Attempts registration when supported; sets pendingFlag if the feature is
// supported but still unregistered afterwards (i.e. worth another round).
#define TRY_REGISTER(obj, Type, regFlag, pendingFlag)                       \
    do {                                                                    \
        if (!(regFlag) && (obj)->isSupported()) {                            \
            const std::string instance =                                    \
                    std::string(Type::descriptor) + "/default";              \
            if (AServiceManager_addService((obj)->asBinder().get(),         \
                                           instance.c_str()) ==             \
                STATUS_OK) {                                                \
                (regFlag) = true;                                           \
            } else {                                                        \
                LOG(ERROR) << "Failed to add service " << instance          \
                           << " - will retry";                              \
            }                                                               \
        }                                                                   \
        if (!(regFlag) && (obj)->isSupported()) (pendingFlag) = true;       \
    } while (0)

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    std::shared_ptr<GloveMode> gm = ndk::SharedRefBase::make<GloveMode>();
    std::shared_ptr<HighTouchPollingRate> htpr = ndk::SharedRefBase::make<HighTouchPollingRate>();
    std::shared_ptr<KeyDisabler> kd = ndk::SharedRefBase::make<KeyDisabler>();
    std::shared_ptr<StylusMode> sm = ndk::SharedRefBase::make<StylusMode>();
    std::shared_ptr<TouchscreenGesture> tg = ndk::SharedRefBase::make<TouchscreenGesture>();

    bool gm_reg = false, htpr_reg = false, kd_reg = false;
    bool sm_reg = false, tg_reg = false;

    for (int attempt = 0; attempt < kMaxProbeAttempts; ++attempt) {
        bool pending = false;

        TRY_REGISTER(gm, GloveMode, gm_reg, pending);
        TRY_REGISTER(htpr, HighTouchPollingRate, htpr_reg, pending);
        TRY_REGISTER(kd, KeyDisabler, kd_reg, pending);
        TRY_REGISTER(sm, StylusMode, sm_reg, pending);
        TRY_REGISTER(tg, TouchscreenGesture, tg_reg, pending);

        const bool anyRegistered = gm_reg || htpr_reg || kd_reg || sm_reg || tg_reg;
        if (anyRegistered && !pending) {
            if (attempt > 0) {
                LOG(INFO) << "All supported touch interfaces registered after "
                          << attempt << " retries";
            }
            break;
        }
        LOG(WARNING) << "Touch sysfs nodes not ready or registration pending "
                        "(attempt "
                     << attempt << "), retrying";
        sleep(kProbeRetryDelaySec);
    }

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
