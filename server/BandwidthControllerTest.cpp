/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * BandwidthControllerTest.cpp - unit tests for BandwidthController.cpp
 */

#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <gtest/gtest.h>

#include <android-base/strings.h>

#include "BandwidthController.h"
#include "IptablesBaseTest.h"

class BandwidthControllerTest : public IptablesBaseTest {
public:
    BandwidthControllerTest() {
        BandwidthController::execFunction = fake_android_fork_exec;
        BandwidthController::popenFunction = fake_popen;
        BandwidthController::iptablesRestoreFunction = fakeExecIptablesRestore;
    }
    BandwidthController mBw;

    void addPopenContents(std::string contents) {
        sPopenContents.push_back(contents);
    }
};

TEST_F(BandwidthControllerTest, TestSetupIptablesHooks) {
    mBw.setupIptablesHooks();
    std::vector<std::string> expected = {
        "*filter\n"
        ":bw_INPUT -\n"
        ":bw_OUTPUT -\n"
        ":bw_FORWARD -\n"
        ":bw_happy_box -\n"
        ":bw_penalty_box -\n"
        ":bw_data_saver -\n"
        ":bw_costly_shared -\n"
        "COMMIT\n"
        "*raw\n"
        ":bw_raw_PREROUTING -\n"
        "COMMIT\n"
        "*mangle\n"
        ":bw_mangle_POSTROUTING -\n"
        "COMMIT\n\x04"
    };
    expectIptablesRestoreCommands(expected);
}

TEST_F(BandwidthControllerTest, TestEnableBandwidthControl) {
    mBw.enableBandwidthControl(false);
    std::string expectedFlush =
        "*filter\n"
        ":bw_INPUT -\n"
        ":bw_OUTPUT -\n"
        ":bw_FORWARD -\n"
        ":bw_happy_box -\n"
        ":bw_penalty_box -\n"
        ":bw_data_saver -\n"
        ":bw_costly_shared -\n"
        "COMMIT\n"
        "*raw\n"
        ":bw_raw_PREROUTING -\n"
        "COMMIT\n"
        "*mangle\n"
        ":bw_mangle_POSTROUTING -\n"
        "COMMIT\n\x04";
     std::string expectedAccounting =
        "*filter\n"
        "-A bw_INPUT -m owner --socket-exists\n"
        "-A bw_OUTPUT -m owner --socket-exists\n"
        "-A bw_costly_shared --jump bw_penalty_box\n"
        "-A bw_penalty_box --jump bw_happy_box\n"
        "-A bw_happy_box --jump bw_data_saver\n"
        "-A bw_data_saver -j RETURN\n"
        "-I bw_happy_box -m owner --uid-owner 0-9999 --jump RETURN\n"
        "COMMIT\n"
        "*raw\n"
        "-A bw_raw_PREROUTING -m owner --socket-exists\n"
        "COMMIT\n"
        "*mangle\n"
        "-A bw_mangle_POSTROUTING -m owner --socket-exists\n"
        "COMMIT\n\x04";

    expectIptablesRestoreCommands({ expectedFlush, expectedAccounting });
}

TEST_F(BandwidthControllerTest, TestDisableBandwidthControl) {
    mBw.disableBandwidthControl();
    const std::string expected =
        "*filter\n"
        ":bw_INPUT -\n"
        ":bw_OUTPUT -\n"
        ":bw_FORWARD -\n"
        ":bw_happy_box -\n"
        ":bw_penalty_box -\n"
        ":bw_data_saver -\n"
        ":bw_costly_shared -\n"
        "COMMIT\n"
        "*raw\n"
        ":bw_raw_PREROUTING -\n"
        "COMMIT\n"
        "*mangle\n"
        ":bw_mangle_POSTROUTING -\n"
        "COMMIT\n\x04";
    expectIptablesRestoreCommands({ expected });
}

TEST_F(BandwidthControllerTest, TestEnableDataSaver) {
    mBw.enableDataSaver(true);
    std::vector<std::string> expected = {
        "-R bw_data_saver 1 --jump REJECT",
    };
    expectIptablesCommands(expected);

    mBw.enableDataSaver(false);
    expected = {
        "-R bw_data_saver 1 --jump RETURN",
    };
    expectIptablesCommands(expected);
}

std::string kIPv4TetherCounters = android::base::Join(std::vector<std::string> {
    "Chain natctrl_tether_counters (4 references)",
    "    pkts      bytes target     prot opt in     out     source               destination",
    "      26     2373 RETURN     all  --  wlan0  rmnet0  0.0.0.0/0            0.0.0.0/0",
    "      27     2002 RETURN     all  --  rmnet0 wlan0   0.0.0.0/0            0.0.0.0/0",
    "    1040   107471 RETURN     all  --  bt-pan rmnet0  0.0.0.0/0            0.0.0.0/0",
    "    1450  1708806 RETURN     all  --  rmnet0 bt-pan  0.0.0.0/0            0.0.0.0/0",
}, '\n');

std::string readSocketClientResponse(int fd) {
    char buf[32768];
    ssize_t bytesRead = read(fd, buf, sizeof(buf));
    if (bytesRead < 0) {
        return "";
    }
    for (int i = 0; i < bytesRead; i++) {
        if (buf[i] == '\0') buf[i] = '\n';
    }
    return std::string(buf, bytesRead);
}

TEST_F(BandwidthControllerTest, TestGetTetherStats) {
    int socketPair[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, socketPair));
    ASSERT_EQ(0, fcntl(socketPair[0], F_SETFL, O_NONBLOCK | fcntl(socketPair[0], F_GETFL)));
    ASSERT_EQ(0, fcntl(socketPair[1], F_SETFL, O_NONBLOCK | fcntl(socketPair[1], F_GETFL)));
    SocketClient cli(socketPair[0], false);

    std::string err;
    BandwidthController::TetherStats filter;
    addPopenContents(kIPv4TetherCounters);
    std::string expected =
            "114 wlan0 rmnet0 2373 26 2002 27\n"
            "114 bt-pan rmnet0 107471 1040 1708806 1450\n"
            "200 Tethering stats list completed\n";
    mBw.getTetherStats(&cli, filter, err);
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));

    addPopenContents(kIPv4TetherCounters);
    filter = BandwidthController::TetherStats("bt-pan", "rmnet0", -1, -1, -1, -1);
    expected = "221 bt-pan rmnet0 107471 1040 1708806 1450\n";
    mBw.getTetherStats(&cli, filter, err);
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));


    addPopenContents(kIPv4TetherCounters);
    filter = BandwidthController::TetherStats("rmnet0", "wlan0", -1, -1, -1, -1);
    expected = "221 rmnet0 wlan0 2002 27 2373 26\n";
    mBw.getTetherStats(&cli, filter, err);
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));

    addPopenContents(kIPv4TetherCounters);
    filter = BandwidthController::TetherStats("rmnet0", "foo0", -1, -1, -1, -1);
    expected = "200 Tethering stats list completed\n";
    mBw.getTetherStats(&cli, filter, err);
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));
}
