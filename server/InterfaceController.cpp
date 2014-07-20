/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dirent.h>

#define LOG_TAG "InterfaceController"
#include <cutils/log.h>

#include "InterfaceController.h"
#include "RouteController.h"

const char ipv6_proc_path[] = "/proc/sys/net/ipv6/conf";

const char sys_net_path[] = "/sys/class/net";

InterfaceController::InterfaceController() {
	// Initial IPv6 settings.
	// By default, accept_ra is set to 1 (accept RAs unless forwarding is on) on all interfaces.
	// This causes RAs to work or not work based on whether forwarding is on, and causes routes
	// learned from RAs to go away when forwarding is turned on. Make this behaviour predictable
	// by always setting accept_ra to 2.
	setAcceptRA("2");

	setAcceptRARouteTable(-RouteController::ROUTE_TABLE_OFFSET_FROM_INDEX);
}

InterfaceController::~InterfaceController() {
}

int InterfaceController::writeIPv6ProcPath(const char *interface, const char *setting, const char *value) {
	char *path;
	if (!isIfaceName(interface)) {
		errno = ENOENT;
		return -1;
	}
	asprintf(&path, "%s/%s/%s", ipv6_proc_path, interface, setting);
	int success = writeFile(path, value, strlen(value));
	free(path);
	return success;
}

int InterfaceController::setEnableIPv6(const char *interface, const int on) {
	// When disable_ipv6 changes from 1 to 0, the kernel starts autoconf.
	// When disable_ipv6 changes from 0 to 1, the kernel clears all autoconf
	// addresses and routes and disables IPv6 on the interface.
	const char *disable_ipv6 = on ? "0" : "1";
	return writeIPv6ProcPath(interface, "disable_ipv6", disable_ipv6);
}

int InterfaceController::setIPv6PrivacyExtensions(const char *interface, const int on) {
	// 0: disable IPv6 privacy addresses
	// 0: enable IPv6 privacy addresses and prefer them over non-privacy ones.
	return writeIPv6ProcPath(interface, "use_tempaddr", on ? "2" : "0");
}

int InterfaceController::isInterfaceName(const char *name) {
	return strcmp(name, ".") &&
		strcmp(name, "..") &&
		strcmp(name, "default") &&
		strcmp(name, "all");
}

void InterfaceController::setOnAllInterfaces(const char* filename, const char* value) {
	// Set the default value, which is used by any interfaces that are created in the future.
	writeIPv6ProcPath("default", filename, value);

	// Set the value on all the interfaces that currently exist.
	DIR* dir = opendir(ipv6_proc_path);
	if (!dir) {
		ALOGE("Can't list %s: %s", ipv6_proc_path, strerror(errno));
		return;
	}
	dirent* d;
	while ((d = readdir(dir))) {
		if (d->d_type == DT_DIR && isInterfaceName(d->d_name)) {
			writeIPv6ProcPath(d->d_name, filename, value);
		}
	}
	closedir(dir);
}

void InterfaceController::setAcceptRA(const char *value) {
	setOnAllInterfaces("accept_ra", value);
}

// |tableOrOffset| is interpreted as:
//     If == 0: default. Routes go into RT6_TABLE_MAIN.
//     If > 0: user set. Routes go into the specified table.
//     If < 0: automatic. The absolute value is intepreted as an offset and added to the interface
//             ID to get the table. If it's set to -1000, routes from interface ID 5 will go into
//             table 1005, etc.
void InterfaceController::setAcceptRARouteTable(int tableOrOffset) {
	char* value;
	asprintf(&value, "%d", tableOrOffset);
	setOnAllInterfaces("accept_ra_rt_table", value);
	free(value);
}

int InterfaceController::setMtu(const char *interface, const char *mtu)
{
	char *path;
	if (!isIfaceName(interface)) {
		errno = ENOENT;
		return -1;
	}
	asprintf(&path, "%s/%s/mtu", sys_net_path, interface);
	int success = writeFile(path, mtu, strlen(mtu));
	free(path);
	return success;
}
