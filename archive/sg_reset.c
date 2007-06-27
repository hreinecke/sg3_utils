#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/../scsi/sg.h>  /* cope with silly includes */

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program send either device, bus or host resets to device,
   or bus or host associated with the given sg device.

   Version 0.02 (20000105)
*/

#ifndef SG_SCSI_RESET
#define SG_SCSI_RESET 0x2284
#endif

#ifndef SG_SCSI_RESET_NOTHING
#define SG_SCSI_RESET_NOTHING 0
#define SG_SCSI_RESET_DEVICE 1
#define SG_SCSI_RESET_BUS 2
#define SG_SCSI_RESET_HOST 3
#endif



int main(int argc, char * argv[])
{
    int sg_fd, res, k, j;
    int do_device_reset = 0;
    int do_bus_reset = 0;
    int do_host_reset = 0;
    int do_wait = 0;
    char * file_name = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-d", argv[k]))
            do_device_reset = 1;
        else if (0 == strcmp("-b", argv[k]))
            do_bus_reset = 1;
        else if (0 == strcmp("-h", argv[k]))
            do_host_reset = 1;
        else if (0 == strcmp("-w", argv[k]))
            do_wait = 1;
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else
            file_name = argv[k];
    }
    if (0 == file_name) {
        printf(
        "Usage: 'sg_reset [-d] [-b] [-h] [-w] <generic_device>'\n");
        printf("  where: -d       attempt a scsi device reset\n");
        printf("         -b       attempt a scsi bus reset\n");
        printf("         -h       attempt a host adapter reset\n");
        printf("         -w       wait for one of the resets to complete\n");
        printf("   {if no switch given then check if reset underway}\n");
        return 1;
    }

    sg_fd = open(file_name, O_RDWR);
    if (sg_fd < 0) {
        perror("sg_reset: open error");
        return 1;
    }
    /* Don't worry, being very careful not to write to a none-sg file ... */
    k = SG_SCSI_RESET_NOTHING;
    if (do_device_reset)
        k = SG_SCSI_RESET_DEVICE;
    else if (do_bus_reset)
        k = SG_SCSI_RESET_BUS;
    else if (do_host_reset)
        k = SG_SCSI_RESET_HOST;

    res = ioctl(sg_fd, SG_SCSI_RESET, &k);
    if (res < 0) {
        if (EBUSY == errno)
            printf("sg_reset: BUSY, may be resetting now\n");
        else if (EIO == errno)
            printf("sg_reset: requested type of reset may not be available\n");
        else if (EACCES == errno)
            printf("sg_reset: to do a reset needs root permission\n");
        else
            printf("sg_reset: SG_SCSI_RESET not supported\n");
        return 1;
    }
    if (SG_SCSI_RESET_NOTHING == k)
        printf("sg_reset: did nothing, device is normal mode\n");
    else {
        if (SG_SCSI_RESET_DEVICE == k)
            printf("sg_reset: started device reset\n");
        else if (SG_SCSI_RESET_BUS == k)
            printf("sg_reset: started bus reset\n");
        else if (SG_SCSI_RESET_HOST == k)
            printf("sg_reset: started host reset\n");

        if (do_wait) {
            printf("waiting for the reset to complete...\n");
            j = 0;
            k = SG_SCSI_RESET_NOTHING;
            do {
                if (0 != j)
                    sleep(1);
                res = ioctl(sg_fd, SG_SCSI_RESET, &k);
                ++j;
            } while ((res < 0) && (EBUSY == errno));
            printf("  ... reset seemingly completed\n");
        }
    }

    if (close(sg_fd) < 0) {
        perror("sg_reset: close error");
        return 1;
    }
    return 0;
}
