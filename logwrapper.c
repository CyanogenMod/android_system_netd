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

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "private/android_filesystem_config.h"
#include "cutils/log.h"

#include <logwrap/logwrap.h>

/*
 * The following is based off of bionic/libc/unistd/system.c with
 *  modifications to avoid calling /system/bin/sh -c
 */
int system_nosh(const char *command)
{
    char buffer[255];
    char *argp[32];
    char *next = buffer;
    char *tmp;
    int i = 0;
    int rc;
    int status;

    if (!command)           /* just checking... */
        return(1);

    /*
     * The command to argp splitting is from code that was
     * reverted in Change: 11b4e9b2
     */
    if (strnlen(command, sizeof(buffer) - 1) == sizeof(buffer) - 1) {
        ALOGE("command line too long while processing: %s", command);
        errno = E2BIG;
        return -1;
    }
    strcpy(buffer, command); // Command len is already checked.
    while ((tmp = strsep(&next, " "))) {
        argp[i++] = tmp;
        if (i == 32) {
            ALOGE("argument overflow while processing: %s", command);
            errno = E2BIG;
            return -1;
        }
    }
    argp[i] = NULL;

    rc = android_fork_execvp(i, argp, &status, false, false);
    if (rc)
        return rc;
    if (!WIFEXITED(status))
        return -ECHILD;
    return WEXITSTATUS(status);
}
