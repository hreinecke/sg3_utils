/*
 * Copyright (C) 2003-2018 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This is a simple program that tests the O_EXCL flag in sg while
 * executing a SCSI INQUIRY command and a
 * TEST UNIT READY command using the SCSI generic (sg) driver
 *
 * Invocation: sg_excl [-x] <sg_device>
 *
 * Version 3.62 (20181227)
 *
 * 6 byte INQUIRY command:
 * [0x12][   |lu][pg cde][res   ][al len][cntrl ]
 *
 * 6 byte TEST UNIT READY command:
 * [0x00][   |lu][res   ][res   ][res   ][res   ]
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_lib.h"
#include "sg_io_linux.h"


#define INQ_REPLY_LEN 96
#define INQ_CMD_LEN 6
#define TUR_CMD_LEN 6

#define EBUFF_SZ 256

#define ME "sg_excl: "

int main(int argc, char * argv[])
{
    int sg_fd, k, ok /*, sg_fd2 */;
    uint8_t inq_cdb [INQ_CMD_LEN] = {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    uint8_t tur_cdb [TUR_CMD_LEN] = {0x00, 0, 0, 0, 0, 0};
    uint8_t inqBuff[INQ_REPLY_LEN];
    sg_io_hdr_t io_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    uint8_t sense_buffer[32];
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
        printf("Usage: 'sg_excl [-x] <sg_device>'\n");
        return 1;
    }

    /* N.B. An access mode of O_RDWR is required for some SCSI commands */
    if ((sg_fd = open(file_name, O_RDWR | O_EXCL | O_NONBLOCK)) < 0) {
        snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Just to be safe, check we have a new sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        printf(ME "%s doesn't seem to be an new sg device\n",
               file_name);
        close(sg_fd);
        return 1;
    }
#if 0
    if ((sg_fd2 = open(file_name, O_RDWR | O_EXCL)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 ME "error opening file: %s a second time", file_name);
        perror(ebuff);
        return 1;
    } else {
        printf(ME "second open of %s in violation of O_EXCL\n", file_name);
        close(sg_fd2);
    }
#endif

    /* Prepare INQUIRY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inq_cdb);
    /* io_hdr.iovec_count = 0; */  /* memset takes care of this */
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = INQ_REPLY_LEN;
    io_hdr.dxferp = inqBuff;
    io_hdr.cmdp = inq_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror(ME "Inquiry SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }

    /* now for the error processing */
    ok = 0;
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        ok = 1;
        break;
    case SG_LIB_CAT_RECOVERED:
        printf("Recovered error on INQUIRY, continuing\n");
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("INQUIRY command error", &io_hdr, 1);
        break;
    }

    if (ok) { /* output result if it is available */
        char * p = (char *)inqBuff;
        int f = (int)*(p + 7);
        printf("Some of the INQUIRY command's results:\n");
        printf("    %.8s  %.16s  %.4s  ", p + 8, p + 16, p + 32);
        printf("[wide=%d sync=%d cmdque=%d sftre=%d]\n",
               !!(f & 0x20), !!(f & 0x10), !!(f & 2), !!(f & 1));
        /* Extra info, not necessary to look at */
        if (do_extra)
            printf("INQUIRY duration=%u millisecs, resid=%d, msg_status=%d\n",
                   io_hdr.duration, io_hdr.resid, (int)io_hdr.msg_status);
    }


    /* Prepare TEST UNIT READY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(tur_cdb);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.cmdp = tur_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror(ME "Test Unit Ready SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }

    /* now for the error processing */
    ok = 0;
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        ok = 1;
        break;
    case SG_LIB_CAT_RECOVERED:
        printf("Recovered error on Test Unit Ready, continuing\n");
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("Test Unit Ready command error", &io_hdr, 1);
        break;
    }

    if (ok)
        printf("Test Unit Ready successful so unit is ready!\n");
    else
        printf("Test Unit Ready failed so unit may _not_ be ready!\n");

    if (do_extra)
        printf("TEST UNIT READY duration=%u millisecs, resid=%d, "
               "msg_status=%d\n", io_hdr.duration, io_hdr.resid,
                (int)io_hdr.msg_status);

    printf("Wait for 60 seconds with O_EXCL help on %s\n", file_name);
    sleep(60);
    close(sg_fd);
    return 0;
}
