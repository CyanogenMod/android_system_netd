/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _NAT_CONTROLLER_H
#define _NAT_CONTROLLER_H

#include <linux/in.h>

#include <utils/List.h>

class NatController {

public:
    NatController();
    virtual ~NatController();

    int enableNat(const char *intIface, const char *extIface);
    int disableNat(const char *intIface, const char *extIface);

private:
    int natCount;

    int setDefaults();
    int runIptablesCmd(const char *cmd);
    bool interfaceExists(const char *iface);
    int doNatCommands(const char *intIface, const char *extIface, bool add);
};

#endif
