/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 1999-2013 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * This program send either device, bus or host resets to device,
 * or bus or host associated with the given sg device.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

static char * version_str = "0.58 20130220";

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
        {"no-escalate", no_argument, 0, 'N'},
        {"target", no_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage(int compat_mode)
{
    fprintf(stderr, "Usage: "
            "sg_reset [--bus] [--device] [--help] [--host] [--no-esc] "
            "[--target]\n"
            "                [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --bus|-b        SCSI bus reset (SPI concept), might be all "
            "targets\n"
            "    --device|-d     device (logical unit) reset\n");
    if (compat_mode) {
        fprintf(stderr,
                "    --help|-z       print usage information then exit\n"
                "    --host|-h|-H    host (bus adapter: HBA) reset\n");
    } else {
        fprintf(stderr,
                "    --help|-h       print usage information then exit\n"
                "    --host|-H       host (bus adapter: HBA) reset\n");
    }
    fprintf(stderr,
            "    --no-esc|-N     overrides default action and only does "
            "reset requested\n"
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
    int c, sg_fd, res, k;
    int do_device_reset = 0;
    int do_bus_reset = 0;
    int do_host_reset = 0;
    int no_escalate = 0;
    int do_target_reset = 0;
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
            ++do_bus_reset;
            break;
        case 'd':
            ++do_device_reset;
            break;
        case 'h':
            if (cp) {
                ++do_host_reset;
                break;
            } else {
                usage(!!cp);
                return 0;
            }
        case 'H':
            ++do_host_reset;
            break;
        case 'N':
            ++no_escalate;
            break;
        case 't':
            ++do_target_reset;
            break;

        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        case 'z':
            usage(!!cp);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
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
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage(!!cp);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (NULL == device_name) {
        fprintf(stderr, "Missing DEVICE name. Use '--help' to see usage.\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if (cp && (0 == verbose))
        ++verbose;      // older behaviour was more verbose

    if ((!!do_device_reset + !!do_target_reset + !!do_bus_reset +
         !!do_host_reset) > 1) {
        fprintf(stderr, "Can only request one type of reset per "
                "invocation\n");
        return 1;
    }

    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", device_name);
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

    res = ioctl(sg_fd, SG_SCSI_RESET, &k);
    if (res < 0) {
        if (EBUSY == errno)
            fprintf(stderr, ME "BUSY, may be resetting now\n");
        else if (EIO == errno)
            fprintf(stderr, ME "reset (for value=0x%x) may not be "
                    "available\n", k);
        else if (EACCES == errno)
            fprintf(stderr, ME "reset requires CAP_SYS_ADMIN (root) "
                   "permission\n");
        else if (EINVAL == errno)
            fprintf(stderr, ME "SG_SCSI_RESET not supported (for "
                    "value=0x%x)\n", k);
        else
            perror(ME "SG_SCSI_RESET failed");
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
