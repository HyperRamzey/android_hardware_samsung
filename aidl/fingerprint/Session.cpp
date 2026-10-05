/*
 * Copyright (C) 2024-2026 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Session.h"
#include "CancellationSignal.h"
#include "Legacy2Aidl.h"
#include "VendorConstants.h"

#include <fingerprint.sysprop.h>

#include <android-base/logging.h>

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <string.h>
#include <unistd.h>
#include <thread>

using namespace ::android::fingerprint::samsung;
using namespace ::std::chrono_literals;

namespace aidl {
namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {

void onClientDeath(void* cookie) {
    LOG(INFO) << "FingerprintService has died";
    Session* session = static_cast<Session*>(cookie);
    if (session && !session->isClosed()) {
        session->close();
    }
}

Session::Session(LegacyHAL hal, int userId, std::shared_ptr<ISessionCallback> cb,
                 LockoutTracker lockoutTracker)
    : mHal(hal), mLockoutTracker(lockoutTracker), mUserId(userId), mCb(cb) {
    mDeathRecipient = AIBinder_DeathRecipient_new(onClientDeath);

    char filename[64];
    snprintf(filename, sizeof(filename), FINGERPRINT_DATA_DIR, userId);
    mHal.ss_fingerprint_set_active_group(userId, filename);
}

ndk::ScopedAStatus Session::generateChallenge() {
    LOG(INFO) << "generateChallenge";

    uint64_t challenge = mHal.ss_fingerprint_pre_enroll();
    mCb->onChallengeGenerated(challenge);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::revokeChallenge(int64_t challenge) {
    LOG(INFO) << "revokeChallenge";

    mHal.ss_fingerprint_post_enroll();
    mCb->onChallengeRevoked(challenge);

    return ndk::ScopedAStatus::ok();
}

namespace {

// The node is a sysfs attribute of the DECON platform device itself, created by
// decon_create_fingerprint_illum() via device_create_file(decon->dev, ...), so it
// lands directly under the platform device's kobject. Verified on the device:
//
//     /sys/devices/platform/14860000.decon_f/fingerprint_illum
//
// The previous pattern had two problems and matched nothing: it looked for a
// "decon0" directory, which does not exist on this board (the node is named
// 14860000.decon_f), and it added an extra path level, so it was asking for
// platform/<x>/decon0/fingerprint_illum rather than platform/<x>/fingerprint_illum.
// Either mistake alone is fatal to a glob.
const char kFingerprintIllumGlob[] =
        "/sys/devices/platform/*/fingerprint_illum";
std::string gFingerprintIllumPath;

// The knob only ARMS the mask path. The LEVEL is a separate attribute,
// /sys/class/lcd/panel/mask_brightness (lcd->mask_brightness), and its default is
// 255. A71 commit 877ef30d9d16 documents 255 as breaking fingerprint enrollment
// and 337 as the working value, and the panel log names the level directly:
//     lcd panel: dsim_panel_mask_brightness: current(1) to mask(255)
// Leaving the default in place is what made the trustlet reject every captured
// frame with BAD_QUALITY 39 even though the mask layer was correctly engaged.
constexpr const char kMaskBrightnessPath[] = "/sys/class/lcd/panel/mask_brightness";
constexpr int kFingerprintIllumValue = 337;

static void setMaskBrightness(int value) {
    int fd = open(kMaskBrightnessPath, O_WRONLY);
    if (fd < 0) {
        LOG(ERROR) << "fingerprint illum level: open failed: " << strerror(errno);
        return;
    }
    char buf[8];
    int n = snprintf(buf, sizeof(buf), "%d", value);
    if (write(fd, buf, n) != n) {
        LOG(ERROR) << "fingerprint illum level: write failed: " << strerror(errno);
    }
    close(fd);
}

void setFingerprintIllum(bool on) {
    // Level first, then arm. Reversing this engages the mask at the 255 default
    // for one frame.
    if (on) setMaskBrightness(kFingerprintIllumValue);

    if (gFingerprintIllumPath.empty()) {
        glob_t paths;
        if (glob(kFingerprintIllumGlob, 0, nullptr, &paths) == 0 && paths.gl_pathc > 0) {
            gFingerprintIllumPath = paths.gl_pathv[0];
        }
        globfree(&paths);
        LOG(INFO) << "fingerprint illum node: "
                  << (gFingerprintIllumPath.empty() ? std::string("NOT FOUND")
                                                    : gFingerprintIllumPath);
    }

    if (gFingerprintIllumPath.empty()) {
        // Say why, once, rather than every call. A bare "NOT FOUND" on every
        // attempt is what made this look like a missing kernel node.
        LOG(ERROR) << "fingerprint illum: " << kFingerprintIllumGlob
                   << " matched nothing; panel illumination is not being driven";
        return;
    }

    int fd = open(gFingerprintIllumPath.c_str(), O_WRONLY);
    if (fd < 0) {
        LOG(ERROR) << "fingerprint illum: open failed: " << strerror(errno);
        return;
    }

    const char value = on ? '1' : '0';
    if (write(fd, &value, 1) != 1) {
        LOG(ERROR) << "fingerprint illum: write failed: " << strerror(errno);
    }
    close(fd);
    LOG(INFO) << "fingerprint illum: " << (on ? "enabled" : "disabled");
}

}  // namespace

ndk::ScopedAStatus Session::enroll(const HardwareAuthToken& hat,
                                   std::shared_ptr<ICancellationSignal>* out) {
    LOG(INFO) << "enroll";
    setFingerprintIllum(true);

    if (FingerprintHalProperties::force_calibrate().value_or(false)) {
        mCaptureReady = false;

        // a30s ET715 is an OPTICAL under-display sensor (ro.vendor.fingerprint.type
        // = udfps_optical), but FORCE_CBGE is the CAPACITIVE enrollment path. Sending
        // the capacitive request to an optical sensor leaves the trustlet unconfigured:
        // its own frame counter stays at "nd cnt : 0" and every poll answers BAuth
        // BAD_QUALITY 39, so enrollment never completes.
        //
        // SEM_REQUEST_OPTICAL_CALIBRATION (0x3F8) is what the optical path needs. It has
        // been defined in VendorConstants.h since the tree was created and was never
        // referenced anywhere. Keep FORCE_CBGE for genuinely capacitive sensors - the
        // a30s is the only optical board on this tree, so this is a type gate rather
        // than a board check.
        const std::string typeProp = FingerprintHalProperties::type().value_or("");
        if (typeProp == "udfps_optical") {
            LOG(INFO) << "optical sensor: requesting SEM_REQUEST_OPTICAL_CALIBRATION";
            mHal.request(SEM_REQUEST_OPTICAL_CALIBRATION, 1);
        } else {
            mHal.request(SEM_REQUEST_FORCE_CBGE, 1);
        }
    }

    hw_auth_token_t authToken{};
    translate(hat, authToken);

    // NOTE (a30s ET715): timeoutSec must be non-zero; 60 s matches the AOSP
    // framework enroll budget a51 passes through.
    //
    // CORRECTION 2026-09-30: the earlier comment here claimed the vendor lib
    // skips Trustlet cmd 49 *when timeoutSec is 0*. That is FALSE. libbauthtzcommon
    // hard-skips opcode 49 unconditionally (cmp w8,#0x31 / b.ne at +0x60d8), zeroes
    // the opcode and returns 0. No argument influences it, and it is present on
    // stock too. Do not re-chase this as a timeout problem.
    // What DOES block enroll is the auth-token challenge (TA code 61 on mismatch).
    int32_t error = mHal.ss_fingerprint_enroll(&authToken, mUserId, 60 /* timeoutSec */);
    if (error) {
        LOG(ERROR) << "ss_fingerprint_enroll failed: " << error;
        setFingerprintIllum(false);
        mCb->onError(Error::UNABLE_TO_PROCESS, error);
    }

    // NOTE (a30s ET715): do NOT block here waiting for CAPTURE_READY. The old
    // while(!mCaptureReady) loop held this binder thread forever with no timeout,
    // wedging the framework scheduler (and making enroll uncancellable) whenever
    // calibration did not complete. Stock OneUI instead swallows early touches
    // until its enroll animation finishes (giving CBGE a finger-off window); we
    // reproduce that below by gating TOUCH_EVENT forwarding on mCaptureReady.
    // Progress callbacks arrive via notify() on HAL worker threads regardless.

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticate(int64_t operationId,
                                         std::shared_ptr<ICancellationSignal>* out) {
    LOG(INFO) << "authenticate";
    setFingerprintIllum(true);

    int32_t error = mHal.ss_fingerprint_authenticate(operationId, mUserId);
    if (error) {
        LOG(ERROR) << "ss_fingerprint_authenticate failed: " << error;
        setFingerprintIllum(false);
        mCb->onError(Error::UNABLE_TO_PROCESS, error);
    }

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::detectInteraction(std::shared_ptr<ICancellationSignal>* out) {
    LOG(INFO) << "detectInteraction";

    LOG(DEBUG) << "Detect interaction is not supported";
    mCb->onError(Error::UNABLE_TO_PROCESS, 0 /* vendorCode */);

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enumerateEnrollments() {
    LOG(INFO) << "enumerateEnrollments";

    if (mHal.ss_fingerprint_enumerate) {
        int32_t error = mHal.ss_fingerprint_enumerate();
        if (error) {
            LOG(ERROR) << "ss_fingerprint_enumerate failed: " << error;
        }
    } else {
        std::vector<int> enrollments;
        char filename[64];
        snprintf(filename, sizeof(filename), FINGERPRINT_DATA_DIR, mUserId);

        DIR* directory = opendir(filename);
        if (directory) {
            struct dirent* entry;
            while ((entry = readdir(directory))) {
                int uid, fid;
                if (sscanf(entry->d_name, "User_%d_%dtmpl.dat", &uid, &fid)) {
                    if (uid == mUserId) {
                        enrollments.push_back(fid);
                    }
                }
            }
            closedir(directory);
        } else {
            LOG(WARNING) << "Failed to open " << filename;
        }

        mCb->onEnrollmentsEnumerated(enrollments);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::removeEnrollments(const std::vector<int32_t>& enrollmentIds) {
    LOG(INFO) << "removeEnrollments, size: " << enrollmentIds.size();

    for (int32_t enrollment : enrollmentIds) {
        int32_t error = mHal.ss_fingerprint_remove(mUserId, enrollment);
        if (error) {
            LOG(ERROR) << "ss_fingerprint_remove failed: " << error;
        }
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::getAuthenticatorId() {
    LOG(INFO) << "getAuthenticatorId";

    mCb->onAuthenticatorIdRetrieved(mHal.ss_fingerprint_get_auth_id());

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::invalidateAuthenticatorId() {
    LOG(INFO) << "invalidateAuthenticatorId";

    mCb->onAuthenticatorIdInvalidated(mHal.ss_fingerprint_get_auth_id());

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::resetLockout(const HardwareAuthToken& /*hat*/) {
    LOG(INFO) << "resetLockout";

    clearLockout(true);
    mIsLockoutTimerAborted = true;

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::close() {
    LOG(INFO) << "close";
    mClosed = true;
    mCb->onSessionClosed();
    AIBinder_DeathRecipient_delete(mDeathRecipient);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerDown(int32_t /*pointerId*/, int32_t /*x*/, int32_t /*y*/,
                                          float /*minor*/, float /*major*/) {
    LOG(INFO) << "onPointerDown";

    // a30s ET715: while force_calibrate calibration is pending (!mCaptureReady),
    // swallow the touch like stock OneUI does during its enroll animation: forwarding
    // TOUCH_EVENT mid-calibration poisons the background reference and every frame
    // is then rejected (BAuth BAD_QUALITY 39 for the whole session).
    if (FingerprintHalProperties::force_calibrate().value_or(false) && !mCaptureReady) {
        LOG(INFO) << "onPointerDown swallowed (calibration pending)";
        return ndk::ScopedAStatus::ok();
    }

    if (FingerprintHalProperties::request_touch_event().value_or(false)) {
        mHal.request(SEM_REQUEST_TOUCH_EVENT, 2);
    }
    checkSensorLockout();
    mCb->onAcquired(AcquiredInfo::START, 0);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUp(int32_t /*pointerId*/) {
    LOG(INFO) << "onPointerUp";

    if (FingerprintHalProperties::force_calibrate().value_or(false) && !mCaptureReady) {
        return ndk::ScopedAStatus::ok();
    }

    if (FingerprintHalProperties::request_touch_event().value_or(false)) {
        mHal.request(SEM_REQUEST_TOUCH_EVENT, 1);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onUiReady() {
    LOG(INFO) << "onUiReady";

    // TODO: stub

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticateWithContext(int64_t operationId,
                                                    const OperationContext& /*context*/,
                                                    std::shared_ptr<ICancellationSignal>* out) {
    return authenticate(operationId, out);
}

ndk::ScopedAStatus Session::enrollWithContext(const HardwareAuthToken& hat,
                                              const OperationContext& /*context*/,
                                              std::shared_ptr<ICancellationSignal>* out) {
    return enroll(hat, out);
}

ndk::ScopedAStatus Session::detectInteractionWithContext(
        const OperationContext& /*context*/, std::shared_ptr<ICancellationSignal>* out) {
    return detectInteraction(out);
}

ndk::ScopedAStatus Session::onPointerDownWithContext(const PointerContext& context) {
    int screenOffPressDelayMs = FingerprintHalProperties::screen_off_press_delay().value_or(0);

    if (screenOffPressDelayMs > 0) {
        if (context.isAod && mDisplayState == DisplayState::NO_UI) {
            std::this_thread::sleep_for(std::chrono::milliseconds(screenOffPressDelayMs));
        }
    }

    return onPointerDown(context.pointerId, context.x, context.y, context.minor, context.major);
}

ndk::ScopedAStatus Session::onPointerUpWithContext(const PointerContext& context) {
    return onPointerUp(context.pointerId);
}

ndk::ScopedAStatus Session::onContextChanged(const OperationContext& context) {
    mDisplayState = context.displayState;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerCancelWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::setIgnoreDisplayTouches(bool /*shouldIgnore*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::cancel() {
    int32_t ret = mHal.ss_fingerprint_cancel();
    setFingerprintIllum(false);

    if (ret == 0) {
        mCb->onError(Error::CANCELED, 0 /* vendorCode */);

        return ndk::ScopedAStatus::ok();
    } else {
        return ndk::ScopedAStatus::fromServiceSpecificError(ret);
    }
}

binder_status_t Session::linkToDeath(AIBinder* binder) {
    return AIBinder_linkToDeath(binder, mDeathRecipient, this);
}

bool Session::isClosed() {
    return mClosed;
}

// Translate from errors returned by traditional HAL (see fingerprint.h) to
// AIDL-compliant Error
Error Session::VendorErrorFilter(int32_t error, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (error) {
        case FINGERPRINT_ERROR_HW_UNAVAILABLE:
            return Error::HW_UNAVAILABLE;
        case FINGERPRINT_ERROR_UNABLE_TO_PROCESS:
            return Error::UNABLE_TO_PROCESS;
        case FINGERPRINT_ERROR_TIMEOUT:
            return Error::TIMEOUT;
        case FINGERPRINT_ERROR_NO_SPACE:
            return Error::NO_SPACE;
        case FINGERPRINT_ERROR_CANCELED:
            return Error::CANCELED;
        case FINGERPRINT_ERROR_UNABLE_TO_REMOVE:
            return Error::UNABLE_TO_REMOVE;
        case FINGERPRINT_ERROR_LOCKOUT: {
            *vendorCode = FINGERPRINT_ERROR_LOCKOUT;
            return Error::VENDOR;
        }
        default:
            if (error >= FINGERPRINT_ERROR_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = error - FINGERPRINT_ERROR_VENDOR_BASE;
                return Error::VENDOR;
            }
    }
    LOG(ERROR) << "Unknown error from fingerprint vendor library: " << error;
    return Error::UNABLE_TO_PROCESS;
}

// Translate acquired messages returned by traditional HAL (see fingerprint.h)
// to AIDL-compliant AcquiredInfo
AcquiredInfo Session::VendorAcquiredFilter(int32_t info, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (info) {
        case FINGERPRINT_ACQUIRED_GOOD:
            return AcquiredInfo::GOOD;
        case FINGERPRINT_ACQUIRED_PARTIAL:
            return AcquiredInfo::PARTIAL;
        case FINGERPRINT_ACQUIRED_INSUFFICIENT:
            return AcquiredInfo::INSUFFICIENT;
        case FINGERPRINT_ACQUIRED_IMAGER_DIRTY:
            return AcquiredInfo::SENSOR_DIRTY;
        case FINGERPRINT_ACQUIRED_TOO_SLOW:
            return AcquiredInfo::TOO_SLOW;
        case FINGERPRINT_ACQUIRED_TOO_FAST:
            return AcquiredInfo::TOO_FAST;
        default:
            if (info >= FINGERPRINT_ACQUIRED_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = info - FINGERPRINT_ACQUIRED_VENDOR_BASE;
                return AcquiredInfo::VENDOR;
            }
    }
    LOG(ERROR) << "Unknown acquiredmsg from fingerprint vendor library: " << info;
    return AcquiredInfo::INSUFFICIENT;
}

bool Session::checkSensorLockout() {
    LockoutMode lockoutMode = mLockoutTracker.getMode();
    if (lockoutMode == LockoutMode::PERMANENT) {
        LOG(ERROR) << "Fail: lockout permanent";
        mCb->onLockoutPermanent();
        mIsLockoutTimerAborted = true;
        return true;
    } else if (lockoutMode == LockoutMode::TIMED) {
        int64_t timeLeft = mLockoutTracker.getLockoutTimeLeft();
        LOG(ERROR) << "Fail: lockout timed " << timeLeft;
        mCb->onLockoutTimed(timeLeft);
        if (!mIsLockoutTimerStarted) startLockoutTimer(timeLeft);
        return true;
    }
    return false;
}

void Session::clearLockout(bool clearAttemptCounter) {
    mLockoutTracker.reset(clearAttemptCounter);
    mCb->onLockoutCleared();
}

void Session::startLockoutTimer(int64_t timeout) {
    mIsLockoutTimerAborted = false;
    std::function<void()> action = std::bind(&Session::lockoutTimerExpired, this);
    std::thread([timeout, action]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        action();
    }).detach();

    mIsLockoutTimerStarted = true;
}

void Session::lockoutTimerExpired() {
    if (!mIsLockoutTimerAborted) {
        clearLockout(false);
    }

    mIsLockoutTimerStarted = false;
    mIsLockoutTimerAborted = false;
}

void Session::notify(const fingerprint_msg_t* msg) {
    switch (msg->type) {
        case FINGERPRINT_ERROR: {
            int32_t vendorCode = 0;
            Error result = VendorErrorFilter(msg->data.error, &vendorCode);
            LOG(DEBUG) << "onError(" << static_cast<int>(result) << ")";
            mCb->onError(result, vendorCode);
        } break;
        case FINGERPRINT_ACQUIRED: {
            int32_t vendorCode = 0;
            AcquiredInfo result =
                    VendorAcquiredFilter(msg->data.acquired.acquired_info, &vendorCode);
            LOG(DEBUG) << "onAcquired(" << static_cast<int>(result) << ")";
            mCb->onAcquired(result, vendorCode);
        } break;
        case FINGERPRINT_TEMPLATE_ENROLLING:
            if (FingerprintHalProperties::uses_percentage_samples().value_or(false)) {
                const_cast<fingerprint_msg_t*>(msg)->data.enroll.samples_remaining =
                        100 - msg->data.enroll.samples_remaining;
            }
            if (FingerprintHalProperties::cancel_on_enroll_completion().value_or(false)) {
                if (msg->data.enroll.samples_remaining == 0) {
                    setFingerprintIllum(false);
                    mHal.ss_fingerprint_cancel();
                }
            }
            LOG(DEBUG) << "onEnrollResult(fid=" << msg->data.enroll.finger.fid
                       << ", gid=" << msg->data.enroll.finger.gid
                       << ", rem=" << msg->data.enroll.samples_remaining << ")";
            mCb->onEnrollmentProgress(msg->data.enroll.finger.fid,
                                      msg->data.enroll.samples_remaining);
            break;
        case FINGERPRINT_TEMPLATE_REMOVED: {
            LOG(DEBUG) << "onRemove(fid=" << msg->data.removed.finger.fid
                       << ", gid=" << msg->data.removed.finger.gid
                       << ", rem=" << msg->data.removed.remaining_templates << ")";
            std::vector<int> enrollments;
            enrollments.push_back(msg->data.removed.finger.fid);
            mCb->onEnrollmentsRemoved(enrollments);
        } break;
        case FINGERPRINT_AUTHENTICATED: {
            LOG(DEBUG) << "onAuthenticated(fid=" << msg->data.authenticated.finger.fid
                       << ", gid=" << msg->data.authenticated.finger.gid << ")";
            if (msg->data.authenticated.finger.fid != 0) {
                setFingerprintIllum(false);
                const hw_auth_token_t hat = msg->data.authenticated.hat;
                HardwareAuthToken authToken;
                translate(hat, authToken);

                mCb->onAuthenticationSucceeded(msg->data.authenticated.finger.fid, authToken);
                mLockoutTracker.reset(true);
            } else {
                mCb->onAuthenticationFailed();
                mLockoutTracker.addFailedAttempt();
                checkSensorLockout();
            }
        } break;
        case FINGERPRINT_TEMPLATE_ENUMERATING: {
            LOG(DEBUG) << "onEnumerate(fid=" << msg->data.enumerated.finger.fid
                       << ", gid=" << msg->data.enumerated.finger.gid
                       << ", rem=" << msg->data.enumerated.remaining_templates << ")";
            static std::vector<int> enrollments;
            enrollments.push_back(msg->data.enumerated.finger.fid);
            if (msg->data.enumerated.remaining_templates == 0) {
                mCb->onEnrollmentsEnumerated(enrollments);
                enrollments.clear();
            }
        } break;
    }
}

void Session::onCaptureReady() {
    mCaptureReady = true;
}

}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
