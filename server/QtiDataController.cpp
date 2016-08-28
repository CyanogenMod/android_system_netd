/*
   Copyright (c) 2015-16, The Linux Foundation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#include <sys/wait.h>
#include <cutils/log.h>
#include <dlfcn.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>

#include "QtiDataController.h"
#include "NetdConstants.h"


void *_libDataHandle = NULL;
void (*_initDataController) () = NULL;
int (*_blockAllData) () = NULL;
int (*_unblockAllData) () = NULL;
unsigned (*_checkAppInWhitelist) (SocketClient *cli) = NULL;

void *_libCsmDataHandle = NULL;
void (*_initCsmDataCtl) () = NULL;
bool (*_enableMms)(char *uids) = NULL;
bool (*_enableData)(char *uids) = NULL;

void initDataControllerLibrary() {
    if (!_libDataHandle) {
        _libDataHandle = dlopen("libdatactrl.so", RTLD_NOW);
        if (_libDataHandle) {
            *(void **)&_initDataController =
                    dlsym(_libDataHandle, "initDataController");
            *(void **)&_blockAllData =
                    dlsym(_libDataHandle, "blockAllData");
            *(void **)&_unblockAllData =
                    dlsym(_libDataHandle, "unblockAllData");
            *(void **)&_checkAppInWhitelist =
                    dlsym(_libDataHandle, "checkAppInWhitelist");
            ALOGI("Successfully loaded %s", "Zero Balance libdatacontroller");
        } else {
            ALOGE("Failed to open libdatactrl, "
                    "some features may not be present.");
        }
    }

    /**csm data*/
    if (!_libCsmDataHandle) {
        _libCsmDataHandle = dlopen("libcsm_data.so", RTLD_NOW);
        if (_libCsmDataHandle) {
            *(void **)&_initCsmDataCtl =
                    dlsym(_libCsmDataHandle, "initCsmDataCtl");
            *(void **)&_enableMms =
                    dlsym(_libCsmDataHandle, "enableMms");
            *(void **)&_enableData =
                    dlsym(_libCsmDataHandle, "enableData");
            ALOGI("Successfully loaded %s", "libCsmDataHandle");
        } else {
            ALOGE("Failed to open libcsm_data, "
                    "some features may not be present.");
        }
    }
}


void initializeDataControllerLib() {
    initDataControllerLibrary();
    if (_initDataController) _initDataController();
    if (_initCsmDataCtl) _initCsmDataCtl();
}

int blockAllData() {
    if (_blockAllData) return _blockAllData();
    return -1;
}

int unblockAllData() {
    if (_unblockAllData) return _unblockAllData();
    return -1;
}

unsigned checkAppInWhitelist(SocketClient *cli) {
    if (_checkAppInWhitelist) return _checkAppInWhitelist(cli);
    return 0;
}

bool enableMms(char *uids) {
    if (_enableMms) return _enableMms(uids);
    return -1;
}

bool enableData(char *uids) {
    if (_enableData) return _enableData(uids);
    return -1;
}
