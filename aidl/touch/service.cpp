/*
 * SPDX-FileCopyrightText: 2025 The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "vendor.lineage.touch-service.samsung"

#include <sys/stat.h>
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

// All five instances are declared in /vendor/etc/vintf/manifest.xml and required
// by /product/etc/vintf/compatibility_matrix.lineage.xml, so this HAL must
// ALWAYS provide them.
//
// A declared AIDL service that never registers is fatal to the framework:
// ServiceManager.waitForDeclaredService() blocks with no timeout waiting for it.
// system_server reached that from
//     InputMethodManagerService.systemRunning()        (BOOT_PHASE_ACTIVITY_MANAGER_READY)
//       -> InputMethodManagerService.updateTouchSensitivity()
//       -> LineageHardwareManager.isSupported()
// while already holding ImfLock, so the 60 s watchdog killed system_server, init
// restarted it, and it deadlocked in the same place every time: an endless
// restart loop showing bootanimation forever.
//
// The previous version of this file tried to paper over that with a bounded
// probe (120 attempts x 5 s = 10 minutes). That cannot work: the watchdog fires
// at 60 s, long before the probe gives up, and after the loop the old code called
// ABinderProcess_joinThreadPool() without ever registering anything, so the
// service stayed missing no matter what. It also named the wrong driver in its
// comment - the A30s uses ist40xx (CONFIG_TOUCHSCREEN_IST4050), whose sysfs group
// /sys/class/sec/tsp/* is only published once the TSP probe finishes, which can be
// minutes after early-init on a cold or heavily loaded boot. That timing is why
// this only ever reproduced intermittently.
//
// Registration is therefore unconditional, and real capability is reported through
// the binder methods: every implementation here already reads its sysfs node per
// call and reports "off" when it is absent, so nothing depends on the service
// being missing.
static constexpr unsigned int kPermissionRetryDelaySec = 5;
static constexpr unsigned int kPermissionRetryAttempts = 24;

// vendor.lineage.touch-service.samsung runs as uid system, but the ist40xx driver
// creates /sys/class/sec/tsp/cmd root-owned. The init .rc chowned it at
// early-init, which is *before* the driver publishes the node, so on a slow boot
// the chown silently failed and setEnabled() could not write the node even once
// the driver appeared. Re-apply it here once the node shows up instead of
// trusting a one-shot early-init window.
static void ensureCommandNodeWritable() {
    struct stat st {};
    if (stat(TSP_CMD_NODE, &st) != 0) return;

    if ((st.st_uid == 0) || ((st.st_mode & 0664) != 0664)) {
        if (chown(TSP_CMD_NODE, 1000 /* AID_SYSTEM */, 1002 /* AID_RADIO */) == 0) {
            chmod(TSP_CMD_NODE, 0664);
            LOG(INFO) << "Applied system:radio 0664 to " << TSP_CMD_NODE;
        }
    }
}

// The class must be named explicitly: `descriptor` is a static member inherited
// from the Bn<> base, so it cannot be reached through the deduced shared_ptr type.
template <typename T>
static bool registerService(const std::shared_ptr<T>& obj) {
    const std::string instance = std::string(T::descriptor) + "/default";
    if (AServiceManager_addService(obj->asBinder().get(), instance.c_str()) == STATUS_OK) {
        LOG(INFO) << "Registered " << instance;
        return true;
    }
    LOG(WARNING) << "Did not register " << instance
                 << " (not declared in the VINTF manifest - expected for some)";
    return false;
}

int main() {
    // NOTE: do NOT call ABinderProcess_setThreadPoolMaxThreadCount(0) here.
    //
    // That call was in the original file and is a second, independent deadlock.
    // Setting the max to 0 spawns *no* binder worker threads, so the process
    // cannot service any incoming transaction. Verified on device: this HAL ran
    // with "Threads: 1" (just main) while a healthy NDK HAL - the fingerprint
    // service - runs with 2. The consequence is that a client making a
    // *synchronous* call blocks forever in IPCThreadState::transact, and
    // system_server does exactly that from
    //     InputMethodManagerService.updateTouchSensitivity()
    //       -> LineageHardwareManager.set(...)
    //       -> vendor.lineage.touch.IGloveMode$Stub$Proxy.setEnabled()
    // again while holding ImfLock, so the 60 s watchdog restarted it in a loop
    // again. The default (15 threads) is what a registered AIDL service needs.
    //
    // Leaving the default also means the pool must be started explicitly before
    // the main thread goes off to sleep below, otherwise a client that calls in
    // during the permission-retry window would find no thread to answer it.

    std::shared_ptr<GloveMode> gm = ndk::SharedRefBase::make<GloveMode>();
    std::shared_ptr<HighTouchPollingRate> htpr = ndk::SharedRefBase::make<HighTouchPollingRate>();
    std::shared_ptr<KeyDisabler> kd = ndk::SharedRefBase::make<KeyDisabler>();
    std::shared_ptr<StylusMode> sm = ndk::SharedRefBase::make<StylusMode>();
    std::shared_ptr<TouchscreenGesture> tg = ndk::SharedRefBase::make<TouchscreenGesture>();

    // VINTF-declared: these must exist even if the touch driver is not up yet.
    registerService<GloveMode>(gm);
    registerService<HighTouchPollingRate>(htpr);
    registerService<KeyDisabler>(kd);
    registerService<StylusMode>(sm);
    registerService<TouchscreenGesture>(tg);

    // Answer callers from here on; the loop below must not starve the pool.
    ABinderProcess_startThreadPool();

    for (unsigned int i = 0; i < kPermissionRetryAttempts; ++i) {
        ensureCommandNodeWritable();
        if (::access(TSP_CMD_NODE, W_OK) == 0) break;
        sleep(kPermissionRetryDelaySec);
    }

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
