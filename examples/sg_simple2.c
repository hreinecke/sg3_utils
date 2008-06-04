#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_linux_inc.h"

/* This is a simple program executing a SCSI INQUIRY command and a
   TEST UNIT READY command using the SCSI generic (sg) driver.
   There is another variant of this program called "sg_simple1"
   which includes the sg_lib.h header and logic and so has more
   advanced error processing.
   This version demonstrates the "sg3" interface.
   In the lk 2.6 series devices nodes such as /dev/sda also support
   the SG_IO ioctl.

*  Copyright (C) 1999-2007 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   Invocation: sg_simple2 [-x] <scsi_device>

   Version 03.58 (20070312)

6 byte INQUIRY command:
[0x12][   |lu][pg cde][res   ][al len][cntrl ]

6 byte TEST UNIT READY command:
[0x00][   |lu][res   ][res   ][res   ][res   ]

*/

#define INQ_REPLY_LEN 96        /* logic assumes >= sizeof(inqCmdBlk) */
#define INQ_CMD_LEN 6
#define TUR_CMD_LEN 6

#define EBUFF_SZ 256


int main(int argc, char * argv[])
{
    int sg_fd, k;
    unsigned char inqCmdBlk [INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    unsigned char turCmdBlk [TUR_CMD_LEN] =
                                {0x00, 0, 0, 0, 0, 0};
    unsigned char inqBuff[INQ_REPLY_LEN];
    sg_io_hdr_t io_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char sense_buffer[32];
    int do_extra = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-x", argv[k], 2))
            do_extra = 1;
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            printf("too many arguments\n");
            file_name = 0;
            break;
        }
    }
    if (0 == file_name) {
        printf("Usage: 'sg_simple2 [-x] <sg_device>'\n");
        return 1;
    }

    /* N.B. An access mode of O_RDWR is required for some SCSI commands */
    if ((sg_fd = open(file_name, O_RDONLY)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
		 "sg_simple2: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Just to be safe, check we have a new sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        printf("sg_simple2: %s doesn't seem to be an new sg device\n",
               file_name);
        close(sg_fd);
        return 1;
    }

    /* Prepare INQUIRY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    /* io_hdr.iovec_count = 0; */  /* memset takes care of this */
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = INQ_REPLY_LEN;
    io_hdr.dxferp = inqBuff;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_simple2: Inquiry SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }

    /* now for the error processing */
    if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        if (io_hdr.sb_len_wr > 0) {
            printf("INQUIRY sense data: ");
            for (k = 0; k < io_hdr.sb_len_wr; ++k) {
                if ((k > 0) && (0 == (k % 10)))
                    printf("\n  ");
                printf("0x%02x ", sense_buffer[k]);
            }
            printf("\n");
        }
        if (io_hdr.masked_status)
            printf("INQUIRY SCSI status=0x%x\n", io_hdr.status);
        if (io_hdr.host_status)
            printf("INQUIRY host_status=0x%x\n", io_hdr.host_status);
        if (io_hdr.driver_status)
            printf("INQUIRY driver_status=0x%x\n", io_hdr.driver_status);
    }
    else {  /* output result if it is available */
        char * p = (char *)inqBuff;
        int f = (int)*(p + 7);
        printf("Some of the INQUIRY command's results:\n");
        printf("    %.8s  %.16s  %.4s  ", p + 8, p + 16, p + 32);
        printf("[wide=%d sync=%d cmdque=%d sftre=%d]\n",
               !!(f & 0x20), !!(f & 0x10), !!(f & 2), !!(f & 1));
    }
    /* Extra info, not necessary to look at */
    if (do_extra)
        printf("INQUIRY duration=%u millisecs, resid=%d, msg_status=%d\n",
               io_hdr.duration, io_hdr.resid, (int)io_hdr.msg_status);

    /* Prepare TEST UNIT READY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(turCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.cmdp = turCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_simple2: Test Unit Ready SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }

    /* now for the error processing */
    if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        if (io_hdr.sb_len_wr > 0) {
            printf("TEST UNIT READY sense data: ");
            for (k = 0; k < io_hdr.sb_len_wr; ++k) {
                if ((k > 0) && (0 == (k % 10)))
                    printf("\n  ");
                printf("0x%02x ", sense_buffer[k]);
            }
            printf("\n");
        }
        else if (io_hdr.masked_status)
            printf("TEST UNIT READY SCSI status=0x%x\n", io_hdr.status);
        else if (io_hdr.host_status)
            printf("TEST UNIT READY host_status=0x%x\n", io_hdr.host_status);
        else if (io_hdr.driver_status)
            printf("TEST UNIT READY driver_status=0x%x\n",
                   io_hdr.driver_status);
        else
            printf("TEST UNIT READY unexpected error\n");
        printf("Test Unit Ready failed so unit may _not_ be ready!\n");
    }
    else
        printf("Test Unit Ready successful so unit is ready!\n");
    /* Extra info, not necessary to look at */
    if (do_extra)
        printf("TEST UNIT READY duration=%u millisecs, resid=%d, msg_status=%d\n",
               io_hdr.duration, io_hdr.resid, (int)io_hdr.msg_status);

    close(sg_fd);
    return 0;
}
