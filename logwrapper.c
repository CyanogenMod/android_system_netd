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

int fork_and_execve(const char*, char*[]);

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

    return fork_and_execve(argp[0], argp);
}

extern char **environ;
int fork_and_execve(const char* filename, char* argv[]) {
    pid_t pid;
    sig_t intsave, quitsave;
    sigset_t mask, omask;
    int pstat;

    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &omask);
    switch (pid = vfork()) {
    case -1:                        /* error */
        sigprocmask(SIG_SETMASK, &omask, NULL);
        return(-1);
    case 0:                                 /* child */
        sigprocmask(SIG_SETMASK, &omask, NULL);
        execve(filename, argv, environ);
        _exit(127);
    }

    intsave = (sig_t)  bsd_signal(SIGINT, SIG_IGN);
    quitsave = (sig_t) bsd_signal(SIGQUIT, SIG_IGN);
    pid = waitpid(pid, (int *)&pstat, 0);
    sigprocmask(SIG_SETMASK, &omask, NULL);
    (void)bsd_signal(SIGINT, intsave);
    (void)bsd_signal(SIGQUIT, quitsave);
    return (pid == -1 ? -1 : pstat);
}
