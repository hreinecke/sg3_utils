#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_io_linux.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 1999-2009 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * This program send either device, bus or host resets to device,
 * or bus or host associated with the given sg device.
 */

#define ME "sg_reset: "

static char * version_str = "0.56 20090615";

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


int main(int argc, char * argv[])
{
    int sg_fd, res, k;
    int do_device_reset = 0;
    int do_bus_reset = 0;
    int do_host_reset = 0;
    int do_target_reset = 0;
    char * file_name = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-d", argv[k]))
            do_device_reset = 1;
        else if (0 == strcmp("-b", argv[k]))
            do_bus_reset = 1;
        else if (0 == strcmp("-h", argv[k]))
            do_host_reset = 1;
        else if (0 == strcmp("-t", argv[k]))
            do_target_reset = 1;
        else if (0 == strcmp("-V", argv[k])) {
            fprintf(stderr, "Version string: %s\n", version_str);
            exit(0);
        } else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        } else
            file_name = argv[k];
    }
    if (0 == file_name) {
        printf(
        "Usage: sg_reset  [-b] [-d] [-h] [-t] [-V] DEVICE\n");
        printf("  where: -b       attempt a SCSI bus reset\n");
        printf("         -d       attempt a SCSI device reset\n");
        printf("         -h       attempt a host adapter reset\n");
        printf("         -t       attempt a SCSI target reset\n");
        printf("         -V       print version string then exit\n\n");
        printf("   {if no switch given then check if reset underway}\n");
        printf("To reset use '-d' first, if that is unsuccessful, "
               "then use '-b', then '-h'\n");
        return 1;
    }

    sg_fd = open(file_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", file_name);
        perror("");
        return 1;
    }

    k = SG_SCSI_RESET_NOTHING;
    if (do_device_reset) {
        printf(ME "starting device reset\n");
        k = SG_SCSI_RESET_DEVICE;
    }
    else if (do_target_reset) {
        printf(ME "starting target reset\n");
        k = SG_SCSI_RESET_TARGET;
    }
    else if (do_bus_reset) {
        printf(ME "starting bus reset\n");
        k = SG_SCSI_RESET_BUS;
    }
    else if (do_host_reset) {
        printf(ME "starting host reset\n");
        k = SG_SCSI_RESET_HOST;
    }

    res = ioctl(sg_fd, SG_SCSI_RESET, &k);
    if (res < 0) {
        if (EBUSY == errno)
            printf(ME "BUSY, may be resetting now\n");
        else if (EIO == errno)
            printf(ME "requested type of reset may not be available\n");
        else if (EACCES == errno)
            printf(ME "reset requires CAP_SYS_ADMIN (root) "
                   "permission\n");
        else if (EINVAL == errno)
            printf(ME "SG_SCSI_RESET not supported\n");
        else if (EIO == errno)
            printf(ME "scsi_reset_provider() call failed\n");
        else
            perror(ME "SG_SCSI_RESET failed");
        return 1;
    }
    if (SG_SCSI_RESET_NOTHING == k)
        printf(ME "did nothing, device is normal mode\n");
    else if (SG_SCSI_RESET_DEVICE == k)
        printf(ME "completed device reset\n");
    else if (SG_SCSI_RESET_TARGET == k)
        printf(ME "completed target reset\n");
    else if (SG_SCSI_RESET_BUS == k)
        printf(ME "completed bus reset\n");
    else if (SG_SCSI_RESET_HOST == k)
        printf(ME "completed host reset\n");

    if (close(sg_fd) < 0) {
        perror(ME "close error");
        return 1;
    }
    return 0;
}
