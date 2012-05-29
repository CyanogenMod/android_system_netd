/*
 * Copyright (C) 2008 The Android Open Source Project
 * Copyright 2001-2010 Texas Instruments, Inc. - http://www.ti.com/
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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>
#include <cutils/properties.h>

#include <hardware_legacy/power.h>

#include "SoftapControllerTI.h"

SoftapController::SoftapController() {
    mHostapdStarted = false;
    mApMode = false;
}

SoftapController::~SoftapController() {
}

int SoftapController::startDriver(char *iface) {
    LOGD("softAp startDriver called");
    return 0;
}

int SoftapController::stopDriver(char *iface) {
    LOGD("softAp stopDriver called");
    return 0;
}

int SoftapController::initNl() {
    int err;

    nl_soc = nl_socket_alloc();
    if (!nl_soc) {
        LOGE("Failed to allocate netlink socket.");
        return -ENOMEM;
    }

    if (genl_connect(nl_soc)) {
        LOGE("Failed to connect to generic netlink.");
        err = -ENOLINK;
        goto out_handle_destroy;
    }

    genl_ctrl_alloc_cache(nl_soc, &nl_cache);
    if (!nl_cache) {
        LOGE("Failed to allocate generic netlink cache.");
        err = -ENOMEM;
        goto out_handle_destroy;
    }

    nl80211 = genl_ctrl_search_by_name(nl_cache, "nl80211");
    if (!nl80211) {
        LOGE("nl80211 not found.");
        err = -ENOENT;
        goto out_cache_free;
    }

    return 0;

out_cache_free:
    nl_cache_free(nl_cache);
out_handle_destroy:
    nl_socket_free(nl_soc);
    return err;
}

void SoftapController::deinitNl() {
    genl_family_put(nl80211);
    nl_cache_free(nl_cache);
    nl_socket_free(nl_soc);
}

int SoftapController::executeNlCmd(const char *iface, enum nl80211_iftype type,
				   uint8_t cmd) {
    struct nl_cb *cb;
    struct nl_msg *msg;
    int devidx = 0;
    int err;
    bool add_interface = (cmd == NL80211_CMD_NEW_INTERFACE);

    if (add_interface) {
        devidx = phyLookup();
    } else {
        devidx = if_nametoindex(iface);
        if (devidx == 0) {
            LOGE("failed to translate ifname to idx");
            return -errno;
        }
    }

    msg = nlmsg_alloc();
    if (!msg) {
        LOGE("failed to allocate netlink message");
        return 2;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        LOGE("failed to allocate netlink callbacks");
        err = 2;
        goto out_free_msg;
    }

    genlmsg_put(msg, 0, 0, genl_family_get_id(nl80211), 0, 0, cmd, 0);

    if (add_interface) {
        NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
    } else {
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
    }

    if (add_interface) {
        NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, iface);
        NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, type);
    }

    err = nl_send_auto_complete(nl_soc, msg);
    if (err < 0)
        goto out;

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, NlErrorHandler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, NlFinishHandler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, NlAckHandler, &err);

    while (err > 0)
        nl_recvmsgs(nl_soc, cb);
out:
    nl_cb_put(cb);
out_free_msg:
    nlmsg_free(msg);
    return err;
nla_put_failure:
    LOGW("building message failed");
    return 2;
}

int SoftapController::NlErrorHandler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
    int *ret = (int *)arg;
    *ret = err->error;
    return NL_STOP;
}

int SoftapController::NlFinishHandler(struct nl_msg *msg, void *arg)
{
     int *ret = (int *)arg;
     *ret = 0;
     return NL_SKIP;
}

int SoftapController::NlAckHandler(struct nl_msg *msg, void *arg)
{
    int *ret = (int *)arg;
    *ret = 0;
    return NL_STOP;
}


// ignore the "." and ".." entries
static int dir_filter(const struct dirent *name)
{
    if (0 == strcmp("..", name->d_name) ||
        0 == strcmp(".", name->d_name))
            return 0;

    return 1;
}

// lookup the only active phy
int SoftapController::phyLookup()
{
    char buf[200];
    int fd, pos;
    struct dirent **namelist;
    int n, i;

    n = scandir("/sys/class/ieee80211", &namelist, dir_filter,
                (int (*)(const dirent**, const dirent**))alphasort);
    if (n != 1) {
        LOGE("unexpected - found %d phys in /sys/class/ieee80211", n);
        for (i = 0; i < n; i++)
            free(namelist[i]);
        free(namelist);
        return -1;
    }

    snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index",
             namelist[0]->d_name);
    free(namelist[0]);
    free(namelist);

    fd = open(buf, O_RDONLY);
    if (fd < 0)
        return -1;
    pos = read(fd, buf, sizeof(buf) - 1);
    if (pos < 0) {
        close(fd);
        return -1;
    }
    buf[pos] = '\0';
    close(fd);
    return atoi(buf);
}

int SoftapController::switchInterface(bool apMode) {

    int ret;

    if (mApMode == apMode) {
        LOGD("skipping interface switch. apMode: %d", apMode);
        return 0;
    }

    ret = initNl();
    if (ret != 0)
        return ret;

    if (apMode) {
        ret = executeNlCmd(AP_INTERFACE,
                                NL80211_IFTYPE_AP,
                                NL80211_CMD_NEW_INTERFACE);
        if (ret != 0) {
            LOGE("could not add AP interface: %d", ret);
            goto cleanup;
        }
    } else {
        ret = executeNlCmd(AP_INTERFACE,
                                NL80211_IFTYPE_AP,
                                NL80211_CMD_DEL_INTERFACE);
        if (ret != 0) {
            LOGE("could not remove STA interface: %d", ret);
            goto cleanup;
        }
    }

    LOGD("switched interface. apMode: %d", apMode);
    mApMode = apMode;

cleanup:
    deinitNl();
    return ret;
}

int SoftapController::startHostapd() {
    int i;
    char svc_property[100];

    if(mHostapdStarted) {
        LOGE("hostapd is started");
        return 0;
    }

    if (property_set("ctl.start", HOSTAPD_SERVICE_NAME) < 0) {
        LOGE("Failed to start hostapd");
        return -1;
    }

    for(i=0; i < HOSTAPD_START_MAX_RETRIES; i++) {
        usleep(HOSTAPD_START_DELAY_US);
        if (property_get(HOSTAPD_STATE_PROP, svc_property, "no_such_prop") <= 0)
            continue;
        else if (strcmp(svc_property,"running") != 0)
            continue;
       else
           break;
    }

    if (strcmp(svc_property,"running") != 0) {
        LOGE("failed to start hostapd. state: %s", svc_property);
        return -1;
    }

    // give hostapd some more time to actuallly start (connect to driver)
    sleep(2);
    LOGD("hostapd started OK");
    mHostapdStarted = true;

    return 0;
}

int SoftapController::stopHostapd() {

    if (property_set("ctl.stop", HOSTAPD_SERVICE_NAME) < 0) {
        LOGE("Failed to stop hostapd service");
    }

    usleep(HOSTAPD_STOP_DELAY_US);
    LOGD("hostapd successfully stopped");
    mHostapdStarted = false;
    return 0;
}

int SoftapController::startSoftap() {
    // don't do anything here - setSoftap is always called
    return 0;
}

int SoftapController::stopSoftap() {

    if (!mHostapdStarted) {
        LOGE("Softap is stopped");
        return 0;
    }

    stopHostapd();
    switchInterface(false);
    release_wake_lock(AP_WAKE_LOCK);
    return 0;
}

// note: this is valid after setSoftap is called
bool SoftapController::isSoftapStarted() {
    LOGD("returning isSoftapStarted: %d", mHostapdStarted);
    return mHostapdStarted;
}

int SoftapController::clientsSoftap(char **retbuf)
{
	return 0;
}

static struct nla_policy link_bss_policy[NL80211_BSS_MAX + 1];

int SoftapController::linkDumpCbHandler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	int *sta_freq = (int *)arg;

	// bah - cpp doesn't support C99 named initializers. do it manually
	memset(&link_bss_policy, 0, sizeof(link_bss_policy));
	link_bss_policy[NL80211_BSS_TSF].type = NLA_U64;
	link_bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
	//link_bss_policy[NL80211_BSS_BSSID] = { };
	link_bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
	link_bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
	//link_bss_policy[NL80211_BSS_INFORMATION_ELEMENTS] = { };
	link_bss_policy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
	link_bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
	link_bss_policy[NL80211_BSS_STATUS].type = NLA_U32;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_BSS]) {
		LOGD("bss info missing!");
		return NL_SKIP;
	}
	if (nla_parse_nested(bss, NL80211_BSS_MAX,
			     tb[NL80211_ATTR_BSS],
			     link_bss_policy)) {
		LOGD("failed to parse nested attributes!");
		return NL_SKIP;
	}

	if (!bss[NL80211_BSS_BSSID])
		return NL_SKIP;

	if (!bss[NL80211_BSS_STATUS])
		return NL_SKIP;

	switch (nla_get_u32(bss[NL80211_BSS_STATUS])) {
	case NL80211_BSS_STATUS_ASSOCIATED:
		break;
	case NL80211_BSS_STATUS_AUTHENTICATED:
	case NL80211_BSS_STATUS_IBSS_JOINED:
	default:
		return NL_SKIP;
	}

	/* only in the assoc case do we want more info from station get */
	if (bss[NL80211_BSS_FREQUENCY]) {
		*sta_freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
		LOGD("sta freq: %d", *sta_freq);
	}

	return NL_SKIP;
}

int SoftapController::executeScanLinkCmd(const char *iface, int *iface_freq)
{
    struct nl_cb *cb;
    struct nl_msg *msg;
    int devidx = 0;
    int err;

    // initialize to non-valid freq
    *iface_freq = 0;

    devidx = if_nametoindex(iface);
    if (devidx == 0) {
        LOGE("failed to translate ifname to idx");
        return -errno;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        LOGE("failed to allocate netlink message");
        return 2;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        LOGE("failed to allocate netlink callbacks");
        err = 2;
        goto out_free_msg;
    }

    genlmsg_put(msg, 0, 0, genl_family_get_id(nl80211), 0,
                NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

    // iface_freq will be filled out by the callback
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, linkDumpCbHandler, iface_freq);

    err = nl_send_auto_complete(nl_soc, msg);
    if (err < 0)
        goto out;

    err = 1;
    nl_cb_err(cb, NL_CB_CUSTOM, NlErrorHandler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, NlFinishHandler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, NlAckHandler, &err);

    while (err > 0)
        nl_recvmsgs(nl_soc, cb);

out:
    nl_cb_put(cb);
out_free_msg:
    nlmsg_free(msg);
    return err;
nla_put_failure:
    LOGW("building message failed");
    return 2;
}

// a channel value of 0 indicates "no-channel"
int SoftapController::getStaChanAndMode(int *chan, int *is_g_mode)
{
    int ret, sta_freq = -1;

    *chan = 0;

    ret = initNl();
    if (ret != 0)
        return ret;

    ret = executeScanLinkCmd(STA_INTERFACE, &sta_freq);
    if (ret != 0)
        goto out;

    // if we got 0, the STA is probably not connected
    if (sta_freq != 0 && sta_freq != -1) {
        if (sta_freq >= 2412 && sta_freq <= 2472) {
            *is_g_mode = 1;
            *chan = (sta_freq - 2407) / 5;
        } else if ((sta_freq >= 5180 && sta_freq <= 5240) ||
	           (sta_freq >= 5745 && sta_freq <= 5825)) {
            *is_g_mode = 0;
            *chan = (sta_freq - 5000) / 5;
	} else {
            LOGE("frequency %d not supported by SoftApControllerTI", sta_freq);
	    *chan = 0;
	}
    }

out:
    deinitNl();
    return ret;
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - softap interface
 *      argv[4] - SSID
 *	argv[5] - Security
 *	argv[6] - Key
 *	argv[7] - Channel
 *	argv[8] - Preamble
 *	argv[9] - Max SCB
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
    int ret = 0;
    char buf[1024];
    int sta_chan, is_g_mode;


    LOGD("%s - %s - %s - %s - %s - %s",argv[2],argv[3],argv[4],argv[5],argv[6],argv[7]);

    if (argc < 4) {
        LOGE("Softap set - missing arguments");
        return -1;
    }

    FILE* fp = fopen(HOSTAPD_CONF_TEMPLATE_FILE, "r");
    if (!fp) {
       LOGE("Softap set - hostapd template file read failed");
       return -1;
    }

    FILE* fp2 = fopen(HOSTAPD_CONF_FILE, "w");
    if (!fp2) {
       LOGE("Softap set - hostapd.conf file read failed");
       fclose(fp);
       return -1;
    }
    while (fgets(buf, sizeof(buf), fp)) {
        if((strncmp(buf, "ssid=",5) == 0) ||
           (strncmp(buf, "wpa=",4) == 0) ||
           (strncmp(buf, "wpa_passphrase=",15) == 0) ||
           (strncmp(buf, "wpa_key_mgmt=",12) == 0) ||
           (strncmp(buf, "wpa_pairwise=",12) == 0) ||
           (strncmp(buf, "rsn_pairwise=",12) == 0) ||
           (strncmp(buf, "interface=",10) == 0)) {
           continue;
        }
        fputs(buf,fp2);
    }

    // Update interface
    sprintf(buf, "interface=%s\n", AP_INTERFACE);
    fputs(buf, fp2);

    // Update SSID
    sprintf(buf, "ssid=%s\n",argv[4]);
    fputs(buf, fp2);

    // Update security
    if(strncmp(argv[5],"wpa2-psk",8) == 0) {
        sprintf(buf, "wpa=2\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\n"
                  "wpa_pairwise=CCMP\nrsn_pairwise=CCMP\n", argv[6]);
        fputs(buf, fp2);
    }

    if(strncmp(argv[5],"wpa-psk",7) == 0) {
        sprintf(buf, "wpa=1\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\n"
                  "wpa_pairwise=TKIP\nrsn_pairwise=TKIP\n", argv[6]);
        fputs(buf, fp2);
    }

    // Choose the correct channel - based on the current channel of the STA
    if (getStaChanAndMode(&sta_chan, &is_g_mode) != 0 || sta_chan == 0) {
        /* default to channel 11 on G */
        sta_chan = 11;
        is_g_mode = 1;
    }

    LOGD("AP starting on channel %d g_mode: %d", sta_chan, is_g_mode);
    sprintf(buf, "hw_mode=%s\nchannel=%d\n", is_g_mode ? "g" : "a", sta_chan);
    fputs(buf, fp2);

    fclose(fp);
    fclose(fp2);

    // we take the wakelock here because the stop/start is lengthy
    acquire_wake_lock(PARTIAL_WAKE_LOCK, AP_WAKE_LOCK);

    // switch interface to wlan1
    ret = switchInterface(true);
    if (ret != 0)
        goto fail_switch;

    // restart hostapd to update configuration
    ret = stopHostapd();
    if (ret != 0)
        goto fail;

    ret = startHostapd();
    if (ret != 0)
        goto fail;

    LOGD("hostapd set - Ok");
    return 0;

fail:
    switchInterface(false);
fail_switch:
    release_wake_lock(AP_WAKE_LOCK);
    LOGD("hostapd set - failed. AP is off.");

    return ret;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    return 0;
}
