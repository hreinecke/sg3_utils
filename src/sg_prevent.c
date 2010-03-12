/*
 * Copyright (c) 2004-2010 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 * This program issues the SCSI PREVENT ALLOW MEDIUM REMOVAL command to the
 * given SCSI device.
 */

static char * version_str = "1.06 20070919";

#define ME "sg_prevent: "


static struct option long_options[] = {
        {"allow", 0, 0, 'a'},
        {"help", 0, 0, 'h'},
        {"prevent", 1, 0, 'p'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_prevent [--allow] [--help] [--prevent=PC] [--verbose] "
          "[--version]\n"
          "                  DEVICE\n"
          "  where:\n"
          "    --allow|-a            allow media removal\n"
          "    --help|-h             print usage message then exit\n"
          "    --prevent=PC|-p PC    prevent code value (def: 1 -> "
          "prevent)\n"
          "                            0 -> allow, 1 -> prevent\n"
          "                            2 -> persistent allow, 3 -> "
          "persistent prevent\n"
          "    --verbose|-v          increase verbosity\n"
          "    --version|-V          print version string and exit\n\n"
          "Performs a SCSI PREVENT ALLOW MEDIUM REMOVAL command\n"
          );

}

int main(int argc, char * argv[])
{
    int sg_fd, res, c;
    int allow = 0;
    int prevent = -1;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ahp:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            allow = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'p':
           prevent = sg_get_num(optarg);
           if ((prevent < 0) || (prevent > 3)) {
                fprintf(stderr, "bad argument to '--prevent'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (allow && (prevent >= 0)) {
        fprintf(stderr, "can't give both '--allow' and '--prevent='\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (allow)
        prevent = 0;
    else if (prevent < 0)
        prevent = 1;    /* default is to prevent, as utility name suggests */

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    res = sg_ll_prevent_allow(sg_fd, prevent, 1, verbose);
    ret = res;
    if (0 == res)
        ;
    else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "Device not ready\n");
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "Unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "Aborted command\n");
    else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Prevent allow medium removal command not "
                "supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "Prevent allow medium removal, bad field in "
                "command\n");
    else
        fprintf(stderr, "Prevent allow medium removal command failed\n");

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
