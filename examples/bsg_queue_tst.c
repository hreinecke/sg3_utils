#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* If the following fails the Linux kernel is probably too old */
#include <linux/bsg.h>


#include "sg_lib.h"
#include "sg_io_linux.h"
#include "sg_linux_inc.h"

/* This program was used to test SCSI mid level queue ordering.
   The default behaviour is to "queue at head" which is useful for
   error processing but not for streaming READ and WRITE commands.

*  Copyright (C) 2010 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   Invocation: bsg_queue_tst [-t] <bsg_device>
        -t      queue at tail

   Version 0.90 (20100324)

*/

#define INQ_REPLY_LEN 96
#define INQ_CMD_LEN 6
#define SDIAG_CMD_LEN 6
#define SENSE_BUFFER_LEN 96

#define EBUFF_SZ 256

#ifndef BSG_FLAG_Q_AT_TAIL
#define BSG_FLAG_Q_AT_TAIL 0x10
#endif

#ifndef BSG_FLAG_Q_AT_HEAD
#define BSG_FLAG_Q_AT_HEAD 0x20
#endif


int main(int argc, char * argv[])
{
    int bsg_fd, k, ok;
    unsigned char inqCmdBlk[INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    unsigned char sdiagCmdBlk[SDIAG_CMD_LEN] =
                                {0x1d, 0, 0, 0, 0, 0};
    unsigned char inqBuff[16][INQ_REPLY_LEN];
    struct sg_io_v4 io_hdr[16];
    struct sg_io_v4 rio_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char sense_buffer[16][SENSE_BUFFER_LEN];
    int q_at_tail = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-t", argv[k], 2))
            ++q_at_tail;
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
        printf("Usage: 'bsg_queue_tst [-t] <bsg_device>'\n"
               "where:\n      -t   queue_at_tail (def: q_at_head)\n");
        return 1;
    }

    /* An access mode of O_RDWR is required for write()/read() interface */
    if ((bsg_fd = open(file_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "bsg_queue_tst: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }

    for (k = 0; k < 16; ++k) {
        /* Prepare INQUIRY command */
        memset(&io_hdr[k], 0, sizeof(struct sg_io_v4));
        io_hdr[k].guard = 'Q';
        /* io_hdr[k].iovec_count = 0; */  /* memset takes care of this */
        if (0 == (k % 3)) {
            io_hdr[k].request_len = sizeof(sdiagCmdBlk);
            io_hdr[k].request = (uint64_t)(long)sdiagCmdBlk;
        } else {
            io_hdr[k].request_len = sizeof(inqCmdBlk);
            io_hdr[k].request = (uint64_t)(long)inqCmdBlk;
            io_hdr[k].din_xfer_len = INQ_REPLY_LEN;
            io_hdr[k].din_xferp = (uint64_t)(long)inqBuff[k];
        }
        io_hdr[k].response = (uint64_t)(long)sense_buffer[k];
        io_hdr[k].max_response_len = SENSE_BUFFER_LEN;
        io_hdr[k].timeout = 20000;     /* 20000 millisecs == 20 seconds */
        io_hdr[k].usr_ptr = k;
        /* default is to queue at head (in SCSI mid level) */
        if (q_at_tail)
            io_hdr[k].flags |= BSG_FLAG_Q_AT_TAIL;
        else
            io_hdr[k].flags |= BSG_FLAG_Q_AT_HEAD;

        if (write(bsg_fd, &io_hdr[k], sizeof(struct sg_io_v4)) < 0) {
            perror("bsg_queue_tst: bsg write error");
            close(bsg_fd);
            return 1;
        }
    }
    /* sleep(3); */
    for (k = 0; k < 16; ++k) {
        memset(&rio_hdr, 0, sizeof(struct sg_io_v4));
        rio_hdr.guard = 'Q';
        if (read(bsg_fd, &rio_hdr, sizeof(struct sg_io_v4)) < 0) {
            perror("bsg_queue_tst: bsg read error");
            close(bsg_fd);
            return 1;
        }
        /* now for the error processing */
        ok = 0;
        if (0 == rio_hdr.device_status)
            ok = 1;
        else {
            switch (sg_err_category_sense((unsigned char *)(long)rio_hdr.response,
                    rio_hdr.response_len)) {
            case SG_LIB_CAT_CLEAN:
                ok = 1;
                break;
            case SG_LIB_CAT_RECOVERED:
                printf("Recovered error, continuing\n");
                ok = 1;
                break;
            default: /* won't bother decoding other categories */
                sg_print_sense("command error",
                               (unsigned char *)(long)rio_hdr.response,
                               rio_hdr.response_len, 1);
                break;
            }
        }

        if (ok) { /* output result if it is available */
            /* if (0 == rio_hdr.pack_id) */
            if (0 == (rio_hdr.usr_ptr % 3))
                printf("SEND DIAGNOSTIC %d duration=%u\n", (int)rio_hdr.usr_ptr,
                       rio_hdr.duration);
            else
                printf("INQUIRY %d duration=%u\n", (int)rio_hdr.usr_ptr,
                       rio_hdr.duration);
        }
    }

    close(bsg_fd);
    return 0;
}
