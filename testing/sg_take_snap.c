/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 2021 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is experimental. It allows the SG_CTL_FLAGM_SNAP_DEV
 * variant of ioctl(SG_SET_GET_EXTENDED) to be called. This assumes
 * a Linux sg driver whose version number > 4.00.30 .
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_LINUX_SG_V4_HDR
/* Kernel uapi header contain __user decorations on user space pointers
 * to indicate they are unsafe in the kernel space. However glibc takes
 * all those __user decorations out from headers in /usr/include/linux .
 * So to stop compile errors when directly importing include/uapi/scsi/sg.h
 * undef __user before doing that include. */
#define __user

/* Want to block the original sg.h header from also being included. That
 * causes lots of multiple definition errors. This will only work if this
 * header is included _before_ the original sg.h header.  */
#define _SCSI_GENERIC_H         /* original kernel header guard */
#define _SCSI_SG_H              /* glibc header guard */

#include "uapi_sg.h"    /* local copy of include/uapi/scsi/sg.h */

#else
#define __user
#endif  /* end of: ifndef HAVE_LINUX_SG_V4_HDR */

#include "sg_lib.h"
#include "sg_pr2serr.h"


#define ME "sg_take_snap: "

static const char * version_str = "1.01 20210403";

#define SG_TAKE_MAX_DEVS 16

static const char *dev_arr[SG_TAKE_MAX_DEVS];
static int next_vacant_dev_idx = 0;

static struct option long_options[] = {
        {"clear", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage(void)
{
    pr2serr("Usage: sg_take_snap [--clear] [--help] [--verbose] [--version] "
            "DEVICE*\n"
            "  where:\n"
            "    --clear|-c      set 'clear_first' flag; otherwise appends\n"
            "    --help|-h       print usage information then exit\n"
            "    --verbose|-v    increase the level of verbosity\n"
            "    --version|-V    print version number then exit\n\n"
            "Use ioctl(SG_SET_GET_EXTENDED(SG_CTL_FLAGM_SNAP_DEV)) to take "
            "snap .\nThe output is placed in /sys/kernel/debug/scsi_generic/"
            "snapped and needs\nroot permissions to read. Requires a Linux "
            "sg driver version > 4.00.30 .\nOne or more DEVICEs can be "
            "given. Note: sending the ioctl to do this\ncreates some "
            "'noise' in the output\n"
           );
}


int main(int argc, char * argv[])
{
    bool clear_first = false;
    int c, k, sg_fd, res;
    int ret = 0;
    int verbose = 0;
    const char * device_name = NULL;
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "chvV", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            clear_first = true;
            break;
        case 'h':
            usage();
            return 0;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (optind < argc) {
        for (; optind < argc; ++optind) {
            if (next_vacant_dev_idx < SG_TAKE_MAX_DEVS) {
                dev_arr[next_vacant_dev_idx] = argv[optind];
                ++next_vacant_dev_idx;
            } else if (next_vacant_dev_idx == SG_TAKE_MAX_DEVS) {
                pr2serr("Maximum of %d DEVICEs on command line\n",
                        next_vacant_dev_idx);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            } else {
                pr2serr("something is wrong ...\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        }
    }
    if (NULL == dev_arr[0]) {
        pr2serr("Need at least one DEVICE name. Use '--help' to see "
                "usage.\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    for (k = 0; k < next_vacant_dev_idx; ++k) {
        device_name = dev_arr[k];
        sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
        if (sg_fd < 0) {
            int err = errno;

            ret = sg_convert_errno(err);
            pr2serr(ME "open error: %s: ", device_name);
            perror("");
            sg_fd = -1;
            goto fini;
        }
        if (0 == k) {
            int t;

            res = ioctl(sg_fd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30000)) {
                pr2serr("sg driver prior to 3.0.00\n");
                ret = SG_LIB_FILE_ERROR;
                goto fini;
            }
            if (verbose) {
                pr2serr("sg driver version: %d.%02d.%02d\n",
                        t / 10000, (t % 10000) / 100, t % 100);
            }
            if (t < 40000) {
                pr2serr("Warning: sg driver prior to 4.0.00\n");
                ret = SG_LIB_FILE_ERROR;
                goto fini;
            } else if (t < 40045) {
                pr2serr("Warning: sg driver prior to 4.0.45\n");
                ret = SG_LIB_FILE_ERROR;
                goto fini;
            }
        }

        seip = &sei;
        memset(seip, 0, sizeof(*seip));
        seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
        seip->sei_rd_mask |= SG_SEIM_CTL_FLAGS;
        seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_SNAP_DEV;
        if (clear_first)    /* ... else 0 (due to memset) --> append */
            seip->ctl_flags |= SG_CTL_FLAGM_SNAP_DEV;
        if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
            pr2serr("ioctl(SG_SET_GET_EXTENDED(SG_CTL_FLAGM_SNAP_DEV)), %s "
                    "failed errno=%d %s\n", device_name, errno,
                    strerror(errno));
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
        if (verbose)
            pr2serr("ioctl(%s, SG_SET_GET_EXTENDED(SG_CTL_FLAGM_SNAP_DEV)) "
                    "ok\n", device_name);
        res = close(sg_fd);
        sg_fd = -1;
        if (res < 0) {
            pr2serr("close errno=%d on %s\n", errno, device_name);
            ret = res;
            goto fini;
        }
    }

fini:
    if (sg_fd >= 0) {
        res = close(sg_fd);
        if (res < 0) {
            res = sg_convert_errno(errno);
            perror(ME "close error");
            if (0 == ret)
                ret = res;
        }
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
