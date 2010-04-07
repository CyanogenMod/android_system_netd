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

#ifndef _THROTTLE_CONTROLLER_H
#define _THROTTLE_CONTROLLER_H

class ThrottleController {
public:
    static int setInterfaceThrottle(const char *iface, int rxKbps, int txKbps);
    static int getInterfaceRxThrottle(const char *iface, int *rx);
    static int getInterfaceTxThrottle(const char *iface, int *tx);

private:
    static int runTcCmd(const char *cmd);
    static void reset(const char *iface);
};

#endif
