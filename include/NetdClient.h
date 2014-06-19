/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef NETD_INCLUDE_NETD_CLIENT_H
#define NETD_INCLUDE_NETD_CLIENT_H

#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

bool setNetworkForSocket(unsigned netId, int socketFd);

unsigned getNetworkForProcess(void);
bool setNetworkForProcess(unsigned netId);

bool setNetworkForResolv(unsigned netId);

bool protectFromVpn(int socketFd);

__END_DECLS

#endif  // NETD_INCLUDE_NETD_CLIENT_H
