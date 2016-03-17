/**
 * Copyright (c) 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "Netd"

#include <vector>

#include <android-base/stringprintf.h>
#include <cutils/log.h>
#include <utils/Errors.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include "android/net/BnNetd.h"

#include "Controllers.h"
#include "NetdConstants.h"
#include "NetdNativeService.h"

using android::base::StringPrintf;

namespace android {
namespace net {

namespace {

const char CONNECTIVITY_INTERNAL[] = "android.permission.CONNECTIVITY_INTERNAL";

binder::Status checkPermission(const char *permission) {
    pid_t pid;
    uid_t uid;

    if (checkCallingPermission(String16(permission), (int32_t *) &pid, (int32_t *) &uid)) {
        return binder::Status::ok();
    } else {
        auto err = StringPrintf("UID %d / PID %d lacks permission %s", uid, pid, permission);
        return binder::Status::fromExceptionCode(binder::Status::EX_SECURITY, String8(err.c_str()));
    }
}

#define ENFORCE_PERMISSION(permission) {                    \
    binder::Status status = checkPermission((permission));  \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

#define NETD_LOCKING_RPC(permission, lock)                  \
    ENFORCE_PERMISSION(permission);                         \
    android::RWLock::AutoWLock _lock(lock);

#define NETD_BIG_LOCK_RPC(permission) NETD_LOCKING_RPC((permission), gBigNetdLock)

}  // namespace


status_t NetdNativeService::start() {
    IPCThreadState::self()->disableBackgroundScheduling(true);
    status_t ret = BinderService<NetdNativeService>::publish();
    if (ret != android::OK) {
        return ret;
    }
    sp<ProcessState> ps(ProcessState::self());
    ps->startThreadPool();
    ps->giveThreadPoolName();
    return android::OK;
}

binder::Status NetdNativeService::isAlive(bool *alive) {
    NETD_BIG_LOCK_RPC(CONNECTIVITY_INTERNAL);

    *alive = true;
    return binder::Status::ok();
}

binder::Status NetdNativeService::firewallReplaceUidChain(const android::String16& chainName,
        bool isWhitelist, const std::vector<int32_t>& uids, bool *ret) {
    NETD_LOCKING_RPC(CONNECTIVITY_INTERNAL, gCtls->firewallCtrl.lock);

    android::String8 name = android::String8(chainName);
    int err = gCtls->firewallCtrl.replaceUidChain(name.string(), isWhitelist, uids);
    *ret = (err == 0);
    return binder::Status::ok();

}
}  // namespace net
}  // namespace android
