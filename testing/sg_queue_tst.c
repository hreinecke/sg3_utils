/*
 * Copyright (C) 2010-2019 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *
 * This program was used to test SCSI mid level queue ordering.
 * The default behaviour is to "queue at head" which is useful for
 * error processing but not for streaming READ and WRITE commands.
 *
 * Invocation: sg_queue_tst [-l=Q_LEN] [-t] <sg_device>
 *      -t      queue at tail
 *
 * Version 0.96 (20190128)
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

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
#include "sg_io_linux.h"
#include "sg_linux_inc.h"



#define INQ_REPLY_LEN 96
#define INQ_CMD_LEN 6
#define SDIAG_CMD_LEN 6
#define SENSE_BUFFER_LEN 96

#define EBUFF_SZ 256

#ifndef SG_FLAG_Q_AT_TAIL
#define SG_FLAG_Q_AT_TAIL 0x10
#endif

#ifndef SG_FLAG_Q_AT_HEAD
#define SG_FLAG_Q_AT_HEAD 0x20
#endif

#define DEF_Q_LEN 16    /* max in sg v3 and earlier */
#define MAX_Q_LEN 256

static void
set_nanosecs(int sg_fd)
{
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

    seip = &sei;
    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
    seip->sei_rd_mask |= SG_SEIM_CTL_FLAGS; /* this or previous optional */
    seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_TIME_IN_NS;
    seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;

    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        fprintf(stderr, "ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n",
                errno, strerror(errno));
    }
}


int main(int argc, char * argv[])
{
    bool q_at_tail = false;
    bool dur_in_nanosecs = false;
    int sg_fd, k, ok;
    uint8_t inq_cdb[INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    uint8_t sdiag_cdb[SDIAG_CMD_LEN] =
                                {0x1d, 0x10 /* PF */, 0, 0, 0, 0};
    uint8_t inqBuff[MAX_Q_LEN][INQ_REPLY_LEN];
    sg_io_hdr_t io_hdr[MAX_Q_LEN];
    sg_io_hdr_t rio_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    uint8_t sense_buffer[MAX_Q_LEN][SENSE_BUFFER_LEN];
    int q_len = DEF_Q_LEN;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-n", argv[k], 2))
            dur_in_nanosecs = true;
        else if (0 == memcmp("-t", argv[k], 2))
            q_at_tail = true;
        else if (0 == memcmp("-l=", argv[k], 3)) {
            q_len = atoi(argv[k] + 3);
            if ((q_len > 511) || (q_len < 1)) {
                printf("Expect -l= to take a number (q length) between 1 "
                       "and 511\n");
                file_name = 0;
                break;
            }

        } else if (*argv[k] == '-') {
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
        printf("Usage: 'sg_queue_tst [-l=Q_LEN] [-n] [-t] <sg_device>'\n"
               "where:\n"
               "      -l=Q_LEN    queue length, between 1 and 511 "
               "(def: 16)\n"
               "      -n    duration in nanosecs (def: milliseconds)\n"
               "      -t    queue_at_tail (def: q_at_head)\n");
        return 1;
    }

    /* An access mode of O_RDWR is required for write()/read() interface */
    if ((sg_fd = open(file_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg_queue_tst: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    if (dur_in_nanosecs)
        set_nanosecs(sg_fd);

    for (k = 0; k < q_len; ++k) {
        /* Prepare INQUIRY command */
        memset(&io_hdr[k], 0, sizeof(sg_io_hdr_t));
        io_hdr[k].interface_id = 'S';
        /* io_hdr[k].iovec_count = 0; */  /* memset takes care of this */
        io_hdr[k].mx_sb_len = (uint8_t)sizeof(sense_buffer);
        if (0 == (k % 3)) {
            io_hdr[k].cmd_len = sizeof(sdiag_cdb);
            io_hdr[k].cmdp = sdiag_cdb;
            io_hdr[k].dxfer_direction = SG_DXFER_NONE;
        } else {
            io_hdr[k].cmd_len = sizeof(inq_cdb);
            io_hdr[k].cmdp = inq_cdb;
            io_hdr[k].dxfer_direction = SG_DXFER_FROM_DEV;
            io_hdr[k].dxfer_len = INQ_REPLY_LEN;
            io_hdr[k].dxferp = inqBuff[k];
        }
        io_hdr[k].sbp = sense_buffer[k];
        io_hdr[k].mx_sb_len = SENSE_BUFFER_LEN;
        io_hdr[k].timeout = 20000;     /* 20000 millisecs == 20 seconds */
        io_hdr[k].pack_id = k;
        /* default is to queue at head (in SCSI mid level) */
        if (q_at_tail)
            io_hdr[k].flags |= SG_FLAG_Q_AT_TAIL;
        else
            io_hdr[k].flags |= SG_FLAG_Q_AT_HEAD;
        /* io_hdr[k].usr_ptr = NULL; */

        if (write(sg_fd, &io_hdr[k], sizeof(sg_io_hdr_t)) < 0) {
            perror("sg_queue_tst: sg write error");
            close(sg_fd);
            return 1;
        }
    }
    /* sleep(3); */
    for (k = 0; k < q_len; ++k) {
        memset(&rio_hdr, 0, sizeof(sg_io_hdr_t));
        rio_hdr.interface_id = 'S';
        if (read(sg_fd, &rio_hdr, sizeof(sg_io_hdr_t)) < 0) {
            perror("sg_queue_tst: sg read error");
            close(sg_fd);
            return 1;
        }
        /* now for the error processing */
        ok = 0;
        switch (sg_err_category3(&rio_hdr)) {
        case SG_LIB_CAT_CLEAN:
            ok = 1;
            break;
        case SG_LIB_CAT_RECOVERED:
            printf("Recovered error, continuing\n");
            ok = 1;
            break;
        default: /* won't bother decoding other categories */
            sg_chk_n_print3("command error", &rio_hdr, 1);
            break;
        }

        if (ok) { /* output result if it is available */
            /* if (0 == rio_hdr.pack_id) */
            if (0 == (rio_hdr.pack_id % 3))
                printf("SEND DIAGNOSTIC %d duration=%u %s\n", rio_hdr.pack_id,
                       rio_hdr.duration, (dur_in_nanosecs ? "ns" : "ms"));
            else
                printf("INQUIRY %d duration=%u %s\n", rio_hdr.pack_id,
                       rio_hdr.duration, (dur_in_nanosecs ? "ns" : "ms"));
        }
    }

    close(sg_fd);
    return 0;
}
