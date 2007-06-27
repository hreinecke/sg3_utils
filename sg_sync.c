/*
 * Copyright (c) 2004-2005 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command SYNCHRONIZE CACHE to the given SCSI
 * device. This command is defined for SCSI "direct access" devices
 * (e.g. disks)
 */

static char * version_str = "1.03 20050808";


#define ME "sg_sync: "


static struct option long_options[] = {
        {"count", 1, 0, 'c'},
        {"group", 1, 0, 'g'},
        {"help", 0, 0, 'h'},
        {"immed", 0, 0, 'i'},
        {"lba", 1, 0, 'l'},
        {"sync-nv", 0, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_sync    [--count=<n>] [--group=<n>] [--help] [-immed]"
          " [--lba=<n>]\n"
          "                  [--sync-nv] [--verbose] [--version]"
          " <scsi_device>\n"
          "  where: --count=<n>|-c <n>  number of blocks to sync (def: 0 "
          "which implies\n"
          "                             rest of device)\n"
          "         --group=<n>|-g <n>  set group number (def: 0)\n"
          "         --help|-h           print out usage message\n"
          "         --immed|-i          command returns immediately when set "
          "else wait\n"
          "                             for 'sync' to complete\n"
          "         --lba=<n>|-l <n>    logical block address to start sync "
          "operation\n"
          "                             from (def: 0)\n"
          "         --sync-nv|-s        synchronize to non-volatile storage "
          "(if distinct\n"
          "                             from medium)\n"
          "         --verbose|-v        increase verbosity\n"
          "         --version|-V        print version string and exit\n\n"
          "Performs a SYNCHRONIZE CACHE SCSI command\n"
          );

}


int main(int argc, char * argv[])
{
    int sg_fd, res, c;
    long long count = 0;
    int group = 0;
    long long lba = 0;
    int immed = 0;
    int sync_nv = 0;
    int verbose = 0;
    char device_name[256];
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "c:g:hil:svV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            count = sg_get_llnum(optarg);
            if (count < 0) {
                fprintf(stderr, "bad argument to '--count'\n");
                return 1;
            }
            break;
        case 'g':
            group = sg_get_num(optarg);
            if ((group < 0) || (group > 31)) {
                fprintf(stderr, "bad argument to '--group'\n");
                return 1;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            immed = 1;
            break;
        case 'l':
            lba = sg_get_llnum(optarg);
            if (lba < 0) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return 1;
            }
            break;
        case 's':
            sync_nv = 1;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if ('\0' == device_name[0]) {
            strncpy(device_name, argv[optind], sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }

    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", device_name);
        perror("");
        return 1;
    }

    res = sg_ll_sync_cache_10(sg_fd, sync_nv, immed, group,
                              (unsigned int)lba, (unsigned int)count,
                              1, verbose);
    if (0 == res)
        ret = 0;
    else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Synchronize cache command not supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "bad field in Synchronize cache command\n");
    else
        fprintf(stderr, "Synchronize cache failed\n");

    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}
