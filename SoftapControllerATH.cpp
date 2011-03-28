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
/*
 */

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

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

#include "SoftapController.h"

extern "C" int delete_module(const char *, unsigned int);
extern "C" int init_module(void * , unsigned int, const char *);
extern "C" void *load_file(const char *fn, unsigned *_sz);

extern "C" int ifc_init();
extern "C" int ifc_up(const char *name);

#include "private/android_filesystem_config.h"
#include "cutils/properties.h"
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#endif

#include <sys/_system_properties.h>
#include "hostapd/hostapd_cli.h"
#include "wpa_ctrl.h"

static const char IFACE_DIR[]           = "/data/misc/wifi/hostapd";
static const char HOSTAPD_NAME[]     = "hostapd";
static const char HOSTAPD_CONFIG_TEMPLATE[]= "/system/etc/wifi/hostapd.conf";
static const char HOSTAPD_CONFIG_FILE[]    = "/data/misc/wifi/hostapd.conf";
static const char HOSTAPD_PROP_NAME[]      = "init.svc.hostapd";

#define WIFI_DEFAULT_BI         100         /* in TU */
#define WIFI_DEFAULT_DTIM       1           /* in beacon */
#define WIFI_DEFAULT_CHANNEL    6
#define WIFI_DEFAULT_MAX_STA    8
#define WIFI_DEFAULT_PREAMBLE   0

static struct wpa_ctrl *ctrl_conn;
static char iface[PROPERTY_VALUE_MAX];
int mProfileValid;

/* rfkill support borrowed from bluetooth */
static int rfkill_id = -1;
static char *rfkill_state_path = NULL;


static int init_rfkill() {
    char path[64];
    char buf[16];
    int fd;
    int sz;
    int id;
    for (id = 0; ; id++) {
        snprintf(path, sizeof(path), "/sys/class/rfkill/rfkill%d/type", id);
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            LOGW("open(%s) failed: %s (%d)\n", path, strerror(errno), errno);
            return -1;
        }
        sz = read(fd, &buf, sizeof(buf));
        close(fd);
        if (sz >= 4 && memcmp(buf, "wlan", 4) == 0) {
            rfkill_id = id;
            break;
        }
    }

    asprintf(&rfkill_state_path, "/sys/class/rfkill/rfkill%d/state", rfkill_id);
    return 0;
}

static int check_wifi_power() {
    int sz;
    int fd = -1;
    int ret = -1;
    char buffer;

    if (rfkill_id == -1) {
        if (init_rfkill()) goto out;
    }

    fd = open(rfkill_state_path, O_RDONLY);
    if (fd < 0) {
        LOGE("open(%s) failed: %s (%d)", rfkill_state_path, strerror(errno),
                errno);
        goto out;
    }
    sz = read(fd, &buffer, 1);
    if (sz != 1) {
        LOGE("read(%s) failed: %s (%d)", rfkill_state_path, strerror(errno),
                errno);
        goto out;
    }

    switch (buffer) {
        case '1':
            ret = 1;
            break;
        case '0':
            ret = 0;
            break;
    }

out:
    if (fd >= 0) close(fd);
    return ret;
}

static int set_wifi_power(int on) {
    int sz;
    int fd = -1;
    int ret = -1;
    const char buffer = (on ? '1' : '0');

    if (rfkill_id == -1) {
        if (init_rfkill()) goto out;
    }

    if (check_wifi_power() == on) {
	return 0;
    }

    fd = open(rfkill_state_path, O_WRONLY);
    if (fd < 0) {
        LOGE("open(%s) for write failed: %s (%d)", rfkill_state_path,
                strerror(errno), errno);
        goto out;
    }
    /* Give it a few seconds before changing state */
    sleep(3);
    sz = write(fd, &buffer, 1);
    if (sz < 0) {
        LOGE("write(%s) failed: %s (%d)", rfkill_state_path, strerror(errno),
                errno);
        goto out;
    }
    ret = 0;

out:
    if (fd >= 0) close(fd);
    return ret;
}

/* end rfkill support */

int ensure_config_file_exists()
{
    char buf[2048];
    int srcfd, destfd;
    int nread;

    if (access(HOSTAPD_CONFIG_FILE, R_OK|W_OK) == 0) {
        return 0;
    } else if (errno != ENOENT) {
        LOGE("Cannot access \"%s\": %s", HOSTAPD_CONFIG_FILE, strerror(errno));
        return -1;
    }

    srcfd = open(HOSTAPD_CONFIG_TEMPLATE, O_RDONLY);
    if (srcfd < 0) {
        LOGE("Cannot open \"%s\": %s", HOSTAPD_CONFIG_TEMPLATE, strerror(errno));
        return -1;
    }

    destfd = open(HOSTAPD_CONFIG_FILE, O_CREAT|O_WRONLY, 0660);
    if (destfd < 0) {
        close(srcfd);
        LOGE("Cannot create \"%s\": %s", HOSTAPD_CONFIG_FILE, strerror(errno));
        return -1;
    }

    while ((nread = read(srcfd, buf, sizeof(buf))) != 0) {
        if (nread < 0) {
            LOGE("Error reading \"%s\": %s", HOSTAPD_CONFIG_TEMPLATE, strerror(errno));
            close(srcfd);
            close(destfd);
            unlink(HOSTAPD_CONFIG_FILE);
            return -1;
        }
        write(destfd, buf, nread);
    }

    close(destfd);
    close(srcfd);

    if (chown(HOSTAPD_CONFIG_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        LOGE("Error changing group ownership of %s to %d: %s",
             HOSTAPD_CONFIG_FILE, AID_WIFI, strerror(errno));
        unlink(HOSTAPD_CONFIG_FILE);
        return -1;
    }

    return 0;
}

int wifi_start_hostapd()
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 300; /* wait at most 30 seconds for completion */
    char mac_buff[15] = {'\0'};
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
    const prop_info *pi;
    unsigned serial = 0;
#endif

    /* Check whether already running */
    if (property_get(HOSTAPD_PROP_NAME, supp_status, NULL)
            && strcmp(supp_status, "running") == 0) {
        return 0;
    }


    /* Clear out any stale socket files that might be left over. */
    wpa_ctrl_cleanup();

#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
    /*
     * Get a reference to the status property, so we can distinguish
     * the case where it goes stopped => running => stopped (i.e.,
     * it start up, but fails right away) from the case in which
     * it starts in the stopped state and never manages to start
     * running at all.
     */
    pi = __system_property_find(HOSTAPD_PROP_NAME);
    if (pi != NULL) {
        serial = pi->serial;
    }
#endif
    property_set("ctl.start", HOSTAPD_NAME);
    sched_yield();

    while (count-- > 0) {
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
        if (pi == NULL) {
            pi = __system_property_find(HOSTAPD_PROP_NAME);
        }
        if (pi != NULL) {
            __system_property_read(pi, NULL, supp_status);
            if (strcmp(supp_status, "running") == 0) {
                return 0;
            } else if (pi->serial != serial &&
                    strcmp(supp_status, "stopped") == 0) {
                return -1;
            }
        }
#endif
        usleep(100000);
    }
    return -1;
}

int wifi_stop_hostapd()
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 50; /* wait at most 5 seconds for completion */

    /* Check whether hostapd already stopped */
    if (property_get(HOSTAPD_PROP_NAME, supp_status, NULL)
        && strcmp(supp_status, "stopped") == 0) {
        return 0;
    }

    property_set("ctl.stop", HOSTAPD_NAME);
    sched_yield();

    while (count-- > 0) {
        if (property_get(HOSTAPD_PROP_NAME, supp_status, NULL)) {
            if (strcmp(supp_status, "stopped") == 0)
                return 0;
        }
        usleep(100000);
    }
    return -1;
}

int wifi_connect_to_hostapd()
{
    char ifname[256];
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};

    /* Make sure hostapd is running */
    if (!property_get(HOSTAPD_PROP_NAME, supp_status, NULL)
            || strcmp(supp_status, "running") != 0) {
        LOGE("Supplicant not running, cannot connect");
        return -1;
    }

    strcpy(iface, "athap0");
    snprintf(ifname, sizeof(ifname), "%s/%s", IFACE_DIR, iface);
    LOGD("ifname = %s\n", ifname);

    { /* check iface file is ready */
	    int cnt = 160; /* 8 seconds (160*50)*/
	    sched_yield();
	    while ( access(ifname, F_OK|W_OK)!=0 && cnt-- > 0) {
		    usleep(50000);
	    }      
	    if (access(ifname, F_OK|W_OK)==0) {
		    snprintf(ifname, sizeof(ifname), "%s/%s", IFACE_DIR, iface);
		    LOGD("ifname %s is ready to read/write cnt=%d\n", ifname, cnt);
	    } else {
		    strlcpy(ifname, iface, sizeof(ifname));
		    LOGD("ifname %s is not ready, cnt=%d\n", ifname, cnt);
	    }
    }


    ctrl_conn = wpa_ctrl_open(ifname);
    if (ctrl_conn == NULL) {
        LOGE("Unable to open connection to hostapd on \"%s\": %s",
             ifname, strerror(errno));
        return -1;
    }
    if (wpa_ctrl_attach(ctrl_conn) != 0) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
        return -1;
    }
    return 0;
}

void wifi_close_hostapd_connection()
{
    if (ctrl_conn != NULL) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
    }
}

int wifi_load_profile(bool started)
{
    if ((started) && (mProfileValid)) {
        if (ctrl_conn == NULL) {
            return -1;
        }
    }
    return 0;
}

static int insmod(const char *filename, const char *args)
{
	void *module;
	unsigned int size;
	int ret;

	module = load_file(filename, &size);
	if (!module)
		return -1;

	ret = init_module(module, size, args);

	free(module);

	return ret;
}

static int rmmod(const char *modname)
{
	int ret = -1;
	int maxtry = 10;

	while (maxtry-- > 0) {
		ret = delete_module(modname, O_NONBLOCK | O_EXCL);
		if (ret < 0 && errno == EAGAIN)
			usleep(500000);
		else
			break;
	}

	if (ret != 0)
		LOGD("Unable to unload driver module \"%s\": %s\n",
				modname, strerror(errno));
	return ret;
}

SoftapController::SoftapController() {
    mPid = 0;
    mSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mSock < 0)
        LOGE("Failed to open socket");
    memset(mIface, 0, sizeof(mIface));
    mProfileValid = 0;
    ctrl_conn = NULL;
}

SoftapController::~SoftapController() {
    if (mSock >= 0)
        close(mSock);
}

int SoftapController::getPrivFuncNum(char *iface, const char *fname) {
    struct iwreq wrq;
    struct iw_priv_args *priv_ptr;
    int i, ret;

    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.pointer = mBuf;
    wrq.u.data.length = sizeof(mBuf) / sizeof(struct iw_priv_args);
    wrq.u.data.flags = 0;
    if ((ret = ioctl(mSock, SIOCGIWPRIV, &wrq)) < 0) {
        LOGE("SIOCGIPRIV failed: %d", ret);
        return ret;
    }
    priv_ptr = (struct iw_priv_args *)wrq.u.data.pointer;
    for(i=0;(i < wrq.u.data.length);i++) {
        if (strcmp(priv_ptr[i].name, fname) == 0)
            return priv_ptr[i].cmd;
    }
    return -1;
}

int SoftapController::startDriver(char *iface) {
	struct iwreq wrq;
	int fnum, ret;

	if (mSock < 0) {
		LOGE("Softap driver start - failed to open socket");
		return -1;
	}
	if (!iface || (iface[0] == '\0')) {
		LOGD("Softap driver start - wrong interface");
		iface = mIface;
	}


#ifdef WIFI_MODULE_PATH
	ret = insmod(WIFI_MODULE_PATH, "ifname=athap0");
	usleep(1000000);
#else
	set_wifi_power(0);
	{
		int fd = -1;
		char buffer;

		fd = open("/sys/module/ar6000/parameters/ifname", O_RDWR);
		if (fd < 0) {
			LOGE("failed to open interface name");
			ret = -1;
		}
		if (read(fd, &buffer, 1) != 1) {
			LOGE("failed to get interface name");
			ret = -1;
		}
		if (buffer != 'a' && write(fd, "athap0", 6) > 0) {
			LOGD("interface renamed for AP mode");
			usleep(500000); /* Give it a while after a name change... */
			ret = set_wifi_power(1);
		} else if (buffer == 'a') {
			LOGD("interface already named for AP mode");
			ret = 0;
		} else {
			LOGE("failed to change interface name - %c",buffer);
			ret = -2;
		}
		close(fd);
	}
#endif

	if (ret) {
		return -1;
	} 

	/* Before starting the daemon, make sure its config file exists */
	ret =ensure_config_file_exists();
	if (ret < 0) {
		LOGE("Softap driver start - configuration file missing");
		return -1;
	}
	/* Indicate interface down */

	LOGD("Softap driver start: %d", ret);
	return ret;
}

int SoftapController::stopDriver(char *iface) {
	struct iwreq wrq;
	int fnum, ret;

	LOGE("softapcontroller->stopDriver");
	if (mSock < 0) {
		LOGE("Softap driver stop - failed to open socket");
		return -1;
	}
	if (!iface || (iface[0] == '\0')) {
		LOGD("Softap driver stop - wrong interface");
		iface = mIface;
	}
	ret = 0;
#ifdef WIFI_MODULE_PATH
	ret = rmmod("ar6000");
#else
	ret = set_wifi_power(0);
	if (!ret) {
		int fd = -1;
		char buffer;

		fd = open("/sys/module/ar6000/parameters/ifname", O_RDWR);
		if (fd < 0) {
			LOGE("failed to open interface name");
			ret = -1;
		}
		if (read(fd, &buffer, 1) != 1) {
			LOGE("failed to get interface name");
			ret = -1;
		}
		if (buffer != 'w' && write(fd, "wlan0", 5) > 0) {
			LOGD("interface renamed for STA mode");
			usleep(500000); /* Give it a while after a name change... */
			ret = 0;
		} else if (buffer == 'w') {
			LOGD("interface already named for STA mode");
			ret = 0;
		} else {
			LOGE("failed to change interface name - %c",buffer);
			ret = -2;
		}
		close(fd);
	}
#endif

	LOGD("Softap driver stop: %d", ret);
	return ret;
}

int SoftapController::startSoftap() {
    struct iwreq wrq;
    pid_t pid = 1;
    int fnum, ret = 0;

    if (mPid) {
        LOGE("Softap already started");
        return 0;
    }
    if (mSock < 0) {
        LOGE("Softap startap - failed to open socket");
        return -1;
    }
#if 0
   if ((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -1;
    }
#endif
    /* system("iwpriv wl0.1 AP_BSS_START"); */
    if (!pid) {
        /* start hostapd */
        return ret;
    } else {

        ifc_init();
        ifc_up("athap0");
        sleep(1); /* Give the driver time to settle... */

        ret = wifi_start_hostapd();
        if (ret < 0) {
            LOGE("Softap startap - starting hostapd fails");
	    stopDriver("athap0");
            return -1;
        }

        sched_yield();
	usleep(100000);

        ret = wifi_connect_to_hostapd();
        if (ret < 0) {
            LOGE("Softap startap - connect to hostapd fails");
            return -1;
        }

        /* Indicate interface up */

        ret = wifi_load_profile(true);
        if (ret < 0) {
            LOGE("Softap startap - load new configuration fails");
            return -1;
        }
        if (ret) {
            LOGE("Softap startap - failed: %d", ret);
        }
        else {
           mPid = pid;
           LOGD("Softap startap - Ok");
           usleep(AP_BSS_START_DELAY);
        }
    }
    return ret;

}

int SoftapController::stopSoftap() {
    struct iwreq wrq;
    int fnum, ret;

    if (mPid == 0) {
        LOGE("Softap already stopped");
        return 0;
    }
    if (mSock < 0) {
        LOGE("Softap stopap - failed to open socket");
        return -1;
    }
    wifi_close_hostapd_connection();
    ret = wifi_stop_hostapd();
    mPid = 0;
    LOGD("Softap service stopped: %d", ret);

#ifndef WIFI_MODULE_PATH
    set_wifi_power(0);
    {
        int fd = -1;
        char buffer;

        fd = open("/sys/module/ar6000/parameters/ifname", O_RDWR);
        if (fd < 0) {
            LOGE("failed to open interface name");
            ret = -1;
        }
        if (read(fd, &buffer, 1) != 1) {
            LOGE("failed to get interface name");
            ret = -1;
        }
        if (buffer != 'w' && write(fd, "wlan0", 5) > 0) {
            LOGD("interface renamed for STA mode");
            usleep(500000); /* Give it a while after a name change... */
            ret = 0;
        } else if (buffer == 'w') {
            LOGD("interface already named for STA mode");
            ret = 0;
        } else {
            LOGE("failed to change interface name - %c",buffer);
            ret = -2;
        }
        close(fd);
    }
#endif
    usleep(AP_BSS_STOP_DELAY);
    return ret;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0 ? true : false);
}

int SoftapController::addParam(int pos, const char *cmd, const char *arg)
{
    if (pos < 0)
        return pos;
    if ((unsigned)(pos + strlen(cmd) + strlen(arg) + 1) >= sizeof(mBuf)) {
        LOGE("Command line is too big");
        return -1;
    }
    pos += sprintf(&mBuf[pos], "%s=%s,", cmd, arg);
    return pos;
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
    unsigned char psk[SHA256_DIGEST_LENGTH];
    char psk_str[2*SHA256_DIGEST_LENGTH+1];
    struct iwreq wrq;
    int fnum, ret, i = 0;
    char *ssid;
    int fd;
    char buf[80];
    int len;
    if (mSock < 0) {
        LOGE("Softap set - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        LOGE("Softap set - missing arguments");
        return -1;
    }
    ret = 0;

    fd = open(HOSTAPD_CONFIG_FILE, O_CREAT|O_WRONLY|O_TRUNC, 0660);
    if (fd < 0) {
        LOGE("Cannot create \"%s\": %s", HOSTAPD_CONFIG_FILE, strerror(errno));
        return -1;
    }
    
    len = snprintf(buf, sizeof(buf), "interface=athap0\n");
    write(fd, buf, len);
    len = snprintf(buf, sizeof(buf), "ctrl_interface=%s\n",IFACE_DIR);
    write(fd, buf, len);
    if (argc > 4) {
        len = snprintf(buf, sizeof(buf), "ssid=%s\n",argv[4]);
    } else {
        len = snprintf(buf, sizeof(buf), "ssid=AndroidAP\n");
    }
    /* set open auth */
    write(fd, buf, len);
    len = snprintf(buf, sizeof(buf), "auth_algs=1\n");
    write(fd, buf, len);
    len = snprintf(buf, sizeof(buf), "max_num_sta=%d\n",WIFI_DEFAULT_MAX_STA);
    write(fd, buf, len);
    len = snprintf(buf, sizeof(buf), "beacon_int=%d\n",WIFI_DEFAULT_BI);
    write(fd, buf, len);
    len = snprintf(buf, sizeof(buf), "dtim_period=%d\n",WIFI_DEFAULT_DTIM);
    write(fd, buf, len);
    if (argc > 5) {
        if (strncmp(argv[5], "wpa2-psk", 8) == 0) {
            len = snprintf(buf, sizeof(buf), "wpa=2\n");
            write(fd, buf, len);
            len = snprintf(buf, sizeof(buf), "wpa_key_mgmt=WPA-PSK\n");
            write(fd, buf, len);
            len = snprintf(buf, sizeof(buf), "wpa_pairwise=CCMP\n");
            write(fd, buf, len);
            if (argc > 6) {
                len = snprintf(buf, sizeof(buf), "wpa_passphrase=%s\n",argv[6]);
                write(fd, buf, len);
            } else {
                len = snprintf(buf, sizeof(buf), "wpa_passphrase=12345678\n");
                write(fd, buf, len);
            }
        }
    }
    if (argc > 7) {
        len = snprintf(buf, sizeof(buf), "channel_num=%s\n",argv[7]);
        write(fd, buf, len);
    } else {
        len = snprintf(buf, sizeof(buf), "channel_num=%d\n",WIFI_DEFAULT_CHANNEL);
        write(fd, buf, len);
    }
    /*if (argc > 8) {
        len = snprintf(buf, sizeof(buf), "preamble=%s\n",argv[8]);
        write(fd, buf, len);
    } else {
        len = snprintf(buf, sizeof(buf), "preamble=%d\n",WIFI_DEFAULT_PREAMBLE);
        write(fd, buf, len);
    }*/
    mProfileValid = 1;

    close(fd);

    ret = wifi_load_profile(isSoftapStarted());
    if (ret < 0) {
        LOGE("Softap set - load new configuration fails");
        return -1;
    }
    if (ret) {
        LOGE("Softap set - failed: %d", ret);
    }
    else {
        LOGD("Softap set - Ok");
        usleep(AP_SET_CFG_DELAY);
    }
    return ret;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    struct iwreq wrq;
    int fnum, ret, i = 0;
    char *iface;

    if (mSock < 0) {
        LOGE("Softap fwrealod - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        LOGE("Softap fwreload - missing arguments");
        return -1;
    }
    ret = 0;
    LOGD("Softap fwReload - Ok");
    return ret;
}
