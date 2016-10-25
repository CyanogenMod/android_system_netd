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

    void addPopenContents(std::string contents1, std::string contents2) {
        sPopenContents.push_back(contents1);
        sPopenContents.push_back(contents2);
    }

    void clearPopenContents() {
        sPopenContents.clear();
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

std::string kIPv6TetherCounters = android::base::Join(std::vector<std::string> {
    "Chain natctrl_tether_counters (2 references)",
    "    pkts      bytes target     prot opt in     out     source               destination",
    "   10000 10000000 RETURN     all      wlan0  rmnet0  ::/0                 ::/0",
    "   20000 20000000 RETURN     all      rmnet0 wlan0   ::/0                 ::/0",
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

void expectNoSocketClientResponse(int fd) {
    char buf[64];
    EXPECT_EQ(-1, read(fd, buf, sizeof(buf)));
}

TEST_F(BandwidthControllerTest, TestGetTetherStats) {
    int socketPair[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, socketPair));
    ASSERT_EQ(0, fcntl(socketPair[0], F_SETFL, O_NONBLOCK | fcntl(socketPair[0], F_GETFL)));
    ASSERT_EQ(0, fcntl(socketPair[1], F_SETFL, O_NONBLOCK | fcntl(socketPair[1], F_GETFL)));
    SocketClient cli(socketPair[0], false);

    std::string err;
    BandwidthController::TetherStats filter;

    // If no filter is specified, both IPv4 and IPv6 counters must have at least one interface pair.
    addPopenContents(kIPv4TetherCounters, "");
    ASSERT_EQ(-1, mBw.getTetherStats(&cli, filter, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearPopenContents();

    addPopenContents("", kIPv6TetherCounters);
    ASSERT_EQ(-1, mBw.getTetherStats(&cli, filter, err));
    clearPopenContents();

    // IPv4 and IPv6 counters are properly added together.
    addPopenContents(kIPv4TetherCounters, kIPv6TetherCounters);
    filter = BandwidthController::TetherStats();
    std::string expected =
            "114 wlan0 rmnet0 10002373 10026 20002002 20027\n"
            "114 bt-pan rmnet0 107471 1040 1708806 1450\n"
            "200 Tethering stats list completed\n";
    ASSERT_EQ(0, mBw.getTetherStats(&cli, filter, err));
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));
    expectNoSocketClientResponse(socketPair[1]);
    clearPopenContents();

    // Test filtering.
    addPopenContents(kIPv4TetherCounters, kIPv6TetherCounters);
    filter = BandwidthController::TetherStats("bt-pan", "rmnet0", -1, -1, -1, -1);
    expected = "221 bt-pan rmnet0 107471 1040 1708806 1450\n";
    ASSERT_EQ(0, mBw.getTetherStats(&cli, filter, err));
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));
    expectNoSocketClientResponse(socketPair[1]);
    clearPopenContents();

    addPopenContents(kIPv4TetherCounters, kIPv6TetherCounters);
    filter = BandwidthController::TetherStats("wlan0", "rmnet0", -1, -1, -1, -1);
    expected = "221 wlan0 rmnet0 10002373 10026 20002002 20027\n";
    ASSERT_EQ(0, mBw.getTetherStats(&cli, filter, err));
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));
    clearPopenContents();

    // Select nonexistent interfaces.
    addPopenContents(kIPv4TetherCounters, kIPv6TetherCounters);
    filter = BandwidthController::TetherStats("rmnet0", "foo0", -1, -1, -1, -1);
    expected = "200 Tethering stats list completed\n";
    ASSERT_EQ(0, mBw.getTetherStats(&cli, filter, err));
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));
    clearPopenContents();

    // No stats with a filter: no error.
    addPopenContents("", "");
    ASSERT_EQ(0, mBw.getTetherStats(&cli, filter, err));
    ASSERT_EQ("200 Tethering stats list completed\n", readSocketClientResponse(socketPair[1]));
    clearPopenContents();

    addPopenContents("foo", "foo");
    ASSERT_EQ(0, mBw.getTetherStats(&cli, filter, err));
    ASSERT_EQ("200 Tethering stats list completed\n", readSocketClientResponse(socketPair[1]));
    clearPopenContents();

    // No stats and empty filter: error.
    filter = BandwidthController::TetherStats();
    addPopenContents("", kIPv6TetherCounters);
    ASSERT_EQ(-1, mBw.getTetherStats(&cli, filter, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearPopenContents();

    addPopenContents(kIPv4TetherCounters, "");
    ASSERT_EQ(-1, mBw.getTetherStats(&cli, filter, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearPopenContents();

    // Include only one pair of interfaces and things are fine.
    std::vector<std::string> counterLines = android::base::Split(kIPv4TetherCounters, "\n");
    std::vector<std::string> brokenCounterLines = counterLines;
    counterLines.resize(4);
    std::string counters = android::base::Join(counterLines, "\n") + "\n";
    addPopenContents(counters, counters);
    expected =
            "114 wlan0 rmnet0 4746 52 4004 54\n"
            "200 Tethering stats list completed\n";
    ASSERT_EQ(0, mBw.getTetherStats(&cli, filter, err));
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));
    clearPopenContents();

    // But if interfaces aren't paired, it's always an error.
    counterLines.resize(3);
    counters = android::base::Join(counterLines, "\n") + "\n";
    addPopenContents(counters, counters);
    ASSERT_EQ(-1, mBw.getTetherStats(&cli, filter, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearPopenContents();

    // popen() failing is always an error.
    addPopenContents(kIPv4TetherCounters);
    ASSERT_EQ(-1, mBw.getTetherStats(&cli, filter, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearPopenContents();
    addPopenContents(kIPv6TetherCounters);
    ASSERT_EQ(-1, mBw.getTetherStats(&cli, filter, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearPopenContents();
}
