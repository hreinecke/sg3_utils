/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 1999-2018 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program send either device, bus or host resets to device,
 * or bus or host associated with the given sg device. This is a Linux
 * only utility (perhaps Android as well).
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
#include "sg_io_linux.h"


#define ME "sg_reset: "

static const char * version_str = "0.66 20180515";

#ifndef SG_SCSI_RESET
#define SG_SCSI_RESET 0x2284
#endif

#ifndef SG_SCSI_RESET_NOTHING
#define SG_SCSI_RESET_NOTHING 0
#define SG_SCSI_RESET_DEVICE 1
#define SG_SCSI_RESET_BUS 2
#define SG_SCSI_RESET_HOST 3
#endif

#ifndef SG_SCSI_RESET_TARGET
#define SG_SCSI_RESET_TARGET 4
#endif

#ifndef SG_SCSI_RESET_NO_ESCALATE
#define SG_SCSI_RESET_NO_ESCALATE 0x100
#endif

static struct option long_options[] = {
        {"bus", no_argument, 0, 'b'},
        {"device", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'z'},
        {"host", no_argument, 0, 'H'},
        {"no-esc", no_argument, 0, 'N'},
        {"no_esc", no_argument, 0, 'N'},
        {"no-escalate", no_argument, 0, 'N'},
        {"target", no_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

#if defined(__GNUC__) || defined(__clang__)
static int pr2serr(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
static int pr2serr(const char * fmt, ...);
#endif


static int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

static void
usage(int compat_mode)
{
    pr2serr("Usage: sg_reset [--bus] [--device] [--help] [--host] [--no-esc] "
            "[--no-escalate] [--target]\n"
            "                [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --bus|-b        SCSI bus reset (SPI concept), might be all "
            "targets\n"
            "    --device|-d     device (logical unit) reset\n");
    if (compat_mode) {
        pr2serr("    --help|-z       print usage information then exit\n"
                "    --host|-h|-H    host (bus adapter: HBA) reset\n");
    } else {
        pr2serr("    --help|-h       print usage information then exit\n"
                "    --host|-H       host (bus adapter: HBA) reset\n");
    }
    pr2serr("    --no-esc|-N     overrides default action and only does "
            "reset requested\n"
            "    --no-escalate   The same as --no-esc|-N"
            "    --target|-t     target reset. The target holds the DEVICE "
            "and perhaps\n"
            "                    other LUs\n"
            "    --verbose|-v    increase the level of verbosity\n"
            "    --version|-V    print version number then exit\n\n"
            "Use SG_SCSI_RESET ioctl to send a reset to the "
            "host/bus/target/device\nalong the DEVICE path. The DEVICE "
            "itself is known as a logical unit (LU)\nin SCSI terminology.\n"
            "Be warned: if the '-N' option is not given then if '-d' "
            "fails then a\ntarget reset ('-t') is instigated. And it "
            "'-t' fails then a bus reset\n('-b') is instigated. And if "
            "'-b' fails then a host reset ('h') is\ninstigated. It is "
            "recommended to use '-N' to stop the reset escalation.\n"
           );
}


int main(int argc, char * argv[])
{
    bool do_device_reset = false;
    bool do_bus_reset = false;
    bool do_host_reset = false;
    bool no_escalate = false;
    bool do_target_reset = false;
    int c, sg_fd, res, k, hold_errno;
    int verbose = 0;
    char * device_name = NULL;
    char * cp = NULL;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (NULL == cp)
        cp = getenv("SG_RESET_OLD_OPTS");

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "bdhHNtvVz", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            do_bus_reset = true;
            break;
        case 'd':
            do_device_reset = true;
            break;
        case 'h':
            if (cp) {
                do_host_reset = true;
                break;
            } else {
                usage(!!cp);
                return 0;
            }
        case 'H':
            do_host_reset = true;
            break;
        case 'N':
            no_escalate = true;
            break;
        case 't':
            do_target_reset = true;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
        case 'z':
            usage(!!cp);
            return 0;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage(!!cp);
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
            usage(!!cp);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (NULL == device_name) {
        pr2serr("Missing DEVICE name. Use '--help' to see usage.\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if (cp && (0 == verbose))
        ++verbose;      // older behaviour was more verbose

    if (((int)do_device_reset + (int)do_target_reset + (int)do_bus_reset +
         (int)do_host_reset) > 1) {
        pr2serr("Can only request one type of reset per invocation\n");
        return 1;
    }

    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: ", device_name);
        perror("");
        return 1;
    }

    k = SG_SCSI_RESET_NOTHING;
    if (do_device_reset) {
        if (verbose)
            printf(ME "starting device reset\n");
        k = SG_SCSI_RESET_DEVICE;
    }
    else if (do_target_reset) {
        if (verbose)
            printf(ME "starting target reset\n");
        k = SG_SCSI_RESET_TARGET;
    }
    else if (do_bus_reset) {
        if (verbose)
            printf(ME "starting bus reset\n");
        k = SG_SCSI_RESET_BUS;
    }
    else if (do_host_reset) {
        if (verbose)
            printf(ME "starting host reset\n");
        k = SG_SCSI_RESET_HOST;
    }
    if (no_escalate)
        k += SG_SCSI_RESET_NO_ESCALATE;
    if (verbose > 2)
        pr2serr("    third argument to ioctl(SG_SCSI_RESET) is 0x%x\n", k);

    res = ioctl(sg_fd, SG_SCSI_RESET, &k);
    if (res < 0) {
        hold_errno = errno;
        switch (errno) {
        case EBUSY:
            pr2serr(ME "BUSY, may be resetting now\n");
            break;
        case ENODEV:
            pr2serr(ME "'no device' error, may be temporary while device is "
                    "resetting\n");
            break;
        case EAGAIN:
            pr2serr(ME "try again later, may be resetting now\n");
            break;
        case EIO:
            pr2serr(ME "reset (for value=0x%x) may not be available\n", k);
            break;
        case EPERM:
        case EACCES:
            pr2serr(ME "reset requires CAP_SYS_ADMIN (root) permission\n");
            break;
        case EINVAL:
            pr2serr(ME "SG_SCSI_RESET not supported (for value=0x%x)\n", k);
#if defined(__GNUC__)
#if (__GNUC__ >= 7)
            __attribute__((fallthrough));
            /* FALL THROUGH */
#endif
#endif
        default:
            perror(ME "SG_SCSI_RESET failed");
            break;
        }
        if (verbose > 1)
            pr2serr(ME "ioctl(SG_SCSI_RESET) returned %d, errno=%d\n", res,
                    hold_errno);
        close(sg_fd);
        return 1;
    }

    if (no_escalate)
        k -= SG_SCSI_RESET_NO_ESCALATE;
    if (verbose) {
        if (SG_SCSI_RESET_NOTHING == k)
            printf(ME "did nothing, device is normal mode\n");
        else if (SG_SCSI_RESET_DEVICE == k)
            printf(ME "completed device %sreset\n", (no_escalate ?
                    "" : "(or target or bus or host) "));
        else if (SG_SCSI_RESET_TARGET == k)
            printf(ME "completed target %sreset\n", (no_escalate ?
                    "" : "(or bus or host) "));
        else if (SG_SCSI_RESET_BUS == k)
            printf(ME "completed bus %sreset\n", (no_escalate ?
                    "" : "(or host) "));
        else if (SG_SCSI_RESET_HOST == k)
            printf(ME "completed host reset\n");
    }

    if (close(sg_fd) < 0) {
        perror(ME "close error");
        return 1;
    }
    return 0;
}
