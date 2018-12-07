/*
 * Copyright (c) 2004-2018 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 * This program issues the SCSI PREVENT ALLOW MEDIUM REMOVAL command to the
 * given SCSI device.
 */

static const char * version_str = "1.12 20180627";

#define ME "sg_prevent: "


static struct option long_options[] = {
    {"allow", no_argument, 0, 'a'},
    {"help", no_argument, 0, 'h'},
    {"prevent", required_argument, 0, 'p'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
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
            "Performs a SCSI PREVENT ALLOW MEDIUM REMOVAL command\n");

}

int
main(int argc, char * argv[])
{
    bool allow = false;
    bool verbose_given = false;
    bool version_given = false;
    int sg_fd, res, c;
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
            allow = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'p':
           prevent = sg_get_num(optarg);
           if ((prevent < 0) || (prevent > 3)) {
                pr2serr("bad argument to '--prevent'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
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
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        verbose_given = false;
        version_given = false;
        verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr(ME "version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (allow && (prevent >= 0)) {
        pr2serr("can't give both '--allow' and '--prevent='\n");
        usage();
        return SG_LIB_CONTRADICT;
    }
    if (allow)
        prevent = 0;
    else if (prevent < 0)
        prevent = 1;    /* default is to prevent, as utility name suggests */

    sg_fd = sg_cmds_open_device(device_name, false /* rw */, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }
    res = sg_ll_prevent_allow(sg_fd, prevent, true, verbose);
    ret = res;
    if (res) {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Prevent allow medium removal: %s\n", b);
    }
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            ret = sg_convert_errno(-res);
    }
fini:
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_prevent failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
