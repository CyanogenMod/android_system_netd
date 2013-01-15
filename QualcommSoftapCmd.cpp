/*
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
 * Not a Contribution.
 *
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


#include <stdlib.h>
#include <string.h>

#define LOG_TAG "QualcommSoftapCmd"
#include <cutils/log.h>

#include "CommandListener.h"
#include "ResponseCode.h"

#include "qsap_api.h"

CommandListener::QualcommSoftapCmd::QualcommSoftapCmd() :
  SoftapCmd::SoftapCmd() {
}

int CommandListener::QualcommSoftapCmd::runCommand(SocketClient *cli,
                                        int argc, char **argv) {
    int rc = 0, flag = 0;
    char *retbuf = NULL;

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Softap Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "qccmd")) {
#define MAX_CMD_SIZE 256
        char qccmdbuf[MAX_CMD_SIZE], *pcmdbuf;
        int len = MAX_CMD_SIZE, i=2, ret;

        if ( argc < 4 ) {
            cli->sendMsg(ResponseCode::OperationFailed, "failure: invalid arguments", true);
            return 0;
        }

        argc -= 2;
        pcmdbuf = qccmdbuf;
#ifdef QCOM_SAP_STA_CONCURRENCY
        //SAP STA Concurrency Customization
        // Cmd Format Example "set sap_sta_concurrency=6" where 6 is STA Mode channel
        if (!strncmp(argv[3], "sap_sta_concurrency=",20) && !strcmp(argv[2], "set")) {
            //Extract STA Mode channel number from cmd
            int sta_channel = atoi(&argv[3][20]);
            int sap_channel;
            //Get SAP Mode channel from SoftAP SDK
            ret = snprintf(pcmdbuf, len, " get channel");
            len = MAX_CMD_SIZE;
            //Send cmd to SoftAP SDK
            qsap_hostd_exec_cmd(qccmdbuf, qccmdbuf, (u32*)&len);
            cli->sendMsg(qccmdbuf);

            sap_channel = atoi(&qccmdbuf[16]);
            ALOGD("SAP STA Concurrency GET CHANNEL Rsp %s STA Channel %d SAP Channel %d",qccmdbuf,sta_channel,sap_channel);

            //StopSoftAP and exitAP if channels are different
            if(sta_channel != sap_channel) {
                rc = sSoftapCtrl->stopSoftap();
                if (!rc) {
                    cli->sendMsg(ResponseCode::CommandOkay, "Softap operation succeeded", false);
                } else {
                    cli->sendMsg(ResponseCode::OperationFailed, "Softap operation failed", true);
                }
                //Send exitAP cmd to SoftAP SDK
                len = MAX_CMD_SIZE;
                ret = snprintf(pcmdbuf, len, " set reset_ap=5");
                qsap_hostd_exec_cmd(qccmdbuf, qccmdbuf, (u32*)&len);
                cli->sendMsg(qccmdbuf);
                ALOGD("SAP STA Concurrency result for exitAP %s",qccmdbuf);
            }

            return 0;
        }
        // Cmd Format Example "set sta_assoc_complete_ind"
        else if (!strcmp(argv[3], "sta_assoc_complete_ind") && !strcmp(argv[2], "set")) {
            //StartSoftAP and initAP if SoftAP is down
            if(!sSoftapCtrl->isSoftapStarted()) {
                //Send initAP cmd to SoftAP SDK
                len = MAX_CMD_SIZE;
                ret = snprintf(pcmdbuf, len, " set reset_ap=4");
                //Send cmd to SoftAP SDK
                qsap_hostd_exec_cmd(qccmdbuf, qccmdbuf, (u32*)&len);
                cli->sendMsg(qccmdbuf);
                ALOGD("SAP STA Concurrency result for initAP %s",qccmdbuf);

                rc = sSoftapCtrl->startSoftap();
                if (!rc) {
                    cli->sendMsg(ResponseCode::CommandOkay, "Softap operation succeeded", false);
                } else {
                    cli->sendMsg(ResponseCode::OperationFailed, "Softap operation failed", true);
                }
            }
            return 0;
        } //SAP STA Concurrency Customization Ends
        else
#endif //QCOM_SAP_STA_CONCURRENCY
        {

            while(argc--) {
                ret = snprintf(pcmdbuf, len, " %s", argv[i]);
                if ( ret == len ) {
                    /* Error case */
                    /* TODO: Command too long send the error message */
                    *pcmdbuf = '\0';
                    break;
                }
                pcmdbuf += ret;
                len -= ret;
                i++;
            }

            len = MAX_CMD_SIZE;
            qsap_hostd_exec_cmd(qccmdbuf, qccmdbuf, (u32*)&len);
            cli->sendMsg(ResponseCode::CommandOkay, qccmdbuf, false);
            return 0;
        }
    } else if (!strcmp(argv[1], "set")) {
        /* override processing of the "softap set" command.  The
           default class will install a hostapd.conf which contains
           just the settings supported by the Android framework, and
           will do this every time Soft AP is enabled.  This will
           destroy the hostapd.conf used to store the settings used by
           the Qualcomm SoftAP SDK */
        ALOGD("Got softap set command we are overriding");
        rc = qsapsetSoftap(argc, argv);
    } else {
        /* all other commands will be handed off to the native handler */
        ALOGD("Got softap %s command we are passing on", argv[1]);
        return SoftapCmd::runCommand(cli, argc, argv);
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Softap operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Softap operation failed", true);
    }

    return 0;
}
