/*
 * Copyright (C) 2012 The Android Open Source Project
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

// #define LOG_NDEBUG 0

/*
 * MODUS OPERANDI
 * --------------
 *
 * IPTABLES command sequence:
 *
 * iptables -F
 *
 * iptables -t nat -F idletimer_PREROUTING
 * iptables -t nat -F idletimer_POSTROUTING
 *
 *
 * iptables -t nat -N idletimer_PREROUTING
 * iptables -t nat -N idletimer_POSTROUTING
 *
 * iptables -t nat -D PREROUTING -j idletimer_PREROUTING
 * iptables -t nat -D POSTROUTING -j idletimer_POSTROUTING
 *
 *
 * iptables -t nat -I PREROUTING -j idletimer_PREROUTING
 * iptables -t nat -I POSTROUTING -j idletimer_POSTROUTING
 *
 * # For notifications to work the lable name must match the name of a valid interface.
 * # If the label name does match an interface, the rules will be a no-op.
 *
 * iptables -t nat -A idletimer_PREROUTING -i rmnet0 -j IDLETIMER  --timeout 5 --label test-chain --send_nl_msg 1
 * iptables -t nat -A idletimer_POSTROUTING -o rmnet0 -j IDLETIMER  --timeout 5 --label test-chain --send_nl_msg 1
 *
 * iptables -nxvL -t nat
 *
 * =================
 *
 * ndc command sequence
 * ------------------
 * ndc idletimer enable
 * ndc idletimer add <iface> <timeout>
 * ndc idletimer remove <iface> <timeout>
 *
 * Monitor effect on the iptables chains after each step using:
 *     iptables -nxvL -t nat
 *
 * Remember that the timeout value has to be same at the time of the
 * removal.
 *
 * Note that currently if the name of the iface is incorrect, iptables
 * will setup rules without checking if it is the name of a valid
 * interface (although no notifications will ever be received).  It is
 * the responsibility of code in Java land to ensure that the interface name
 * is correct. The benefit of this, is that idletimers can be setup on
 * interfaces than come and go.
 *
 * A remove should be called for each add command issued during cleanup, as duplicate
 * entries of the rule may exist and will all have to removed.
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <cutils/properties.h>

#define LOG_TAG "IdletimerController"
#include <cutils/log.h>

#include "IdletimerController.h"
#include "NetdConstants.h"

extern "C" int system_nosh(const char *command);

IdletimerController::IdletimerController() {
}

IdletimerController::~IdletimerController() {
}
/* return 0 or non-zero */
int IdletimerController::runIpxtablesCmd(const char *cmd) {
    char *buffer;
    size_t len = strnlen(cmd, 255);
    int res;

    if (len == 255) {
        ALOGE("command too long");
        return -1;
    }

    asprintf(&buffer, "%s %s", IPTABLES_PATH, cmd);
    res = system_nosh(buffer);
    ALOGV("%s #%d", buffer, res);
    free(buffer);

    return res;
}

bool IdletimerController::setupIptablesHooks() {
    runIpxtablesCmd("-t nat -D PREROUTING -j idletimer_nat_PREROUTING");
    runIpxtablesCmd("-t nat -F idletimer_nat_PREROUTING");
    runIpxtablesCmd("-t nat -N idletimer_nat_PREROUTING");

    runIpxtablesCmd("-t nat -D POSTROUTING -j idletimer_nat_POSTROUTING");
    runIpxtablesCmd("-t nat -F idletimer_nat_POSTROUTING");
    runIpxtablesCmd("-t nat -N idletimer_nat_POSTROUTING");

    if (runIpxtablesCmd("-t nat -I PREROUTING -j idletimer_nat_PREROUTING")
        || runIpxtablesCmd("-t nat -I POSTROUTING -j idletimer_nat_POSTROUTING")) {
        return false;
    }
    return true;
}

int IdletimerController::setDefaults() {
  if (runIpxtablesCmd("-t nat -F idletimer_nat_PREROUTING")
      || runIpxtablesCmd("-t nat -F idletimer_nat_POSTROUTING") )
      return -1;
  return 0;
}

int IdletimerController::enableIdletimerControl() {
    int res = setDefaults();
    return res;
}

int IdletimerController::disableIdletimerControl() {
    int res = setDefaults();
    return res;
}

int IdletimerController::modifyInterfaceIdletimer(IptOp op, const char *iface,
                                                  uint32_t timeout) {
  int res;
  char *buffer;
  asprintf(&buffer, "-t nat -%c idletimer_nat_PREROUTING -i %s -j IDLETIMER"
           " --timeout %u --label %s --send_nl_msg 1",
           (op == IptOpAdd) ? 'A' : 'D', iface, timeout, iface);
  res = runIpxtablesCmd(buffer);
  free(buffer);

  asprintf(&buffer, "-t nat -%c idletimer_nat_POSTROUTING -o %s -j IDLETIMER"
           " --timeout %u --label %s --send_nl_msg 1",
           (op == IptOpAdd) ? 'A' : 'D', iface, timeout, iface);
  res |= runIpxtablesCmd(buffer);
  free(buffer);

  return res;
}

int IdletimerController::addInterfaceIdletimer(const char *iface, uint32_t timeout) {
  return modifyInterfaceIdletimer(IptOpAdd, iface, timeout);
}

int IdletimerController::removeInterfaceIdletimer(const char *iface, uint32_t timeout) {
  return modifyInterfaceIdletimer(IptOpDelete, iface, timeout);
}
