/*
 * Copyright (C) 2011 The Android Open Source Project
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
#ifndef _BANDWIDTH_CONTROLLER_H
#define _BANDWIDTH_CONTROLLER_H

#include <list>
#include <string>

class BandwidthController {
public:
	BandwidthController();
	int enableBandwidthControl(void);
	int disableBandwidthControl(void);
	int setInterfaceQuota(const char *iface, int64_t bytes);

protected:
	int runCommands(const char *commands[], int numCommands,
			bool allowFailure = false);
	int removeQuota(const char *iface);
	std::list<std::string /*ifaceName*/> ifaceRules;

private:
	static const char *cleanupCommands[];
	static const char *setupCommands[];
	static const char *basicAccountingCommands[];
	static const int MAX_CMD_LEN;
	static const int MAX_IFACENAME_LEN;
	static const int MAX_CMD_ARGS;
	static const char IPTABLES_PATH[];

	static int runIptablesCmd(const char *cmd);
};

#endif
