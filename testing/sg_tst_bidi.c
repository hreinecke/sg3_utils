/*
 *  Copyright (C) 2019 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Invocation: See usage() function below.
 *
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
#include "sg_pr2serr.h"
#include "sg_unaligned.h"

/* This program tests bidirectional (bidi) SCSI command support in version 4.0
 * and later of the Linux sg driver. The SBC-3 command XDWRITEREAD(10) that
 is implemented by the scsi_debug driver is used.  */


static const char * version_str = "Version: 1.06  20191021";

#define INQ_REPLY_LEN 96
#define INQ_CMD_OP 0x12
#define INQ_CMD_LEN 6
#define SENSE_BUFFER_LEN 96
#define XDWRITEREAD_10_OP 0x53
#define XDWRITEREAD_10_LEN 10

#define EBUFF_SZ 256

#ifndef SG_FLAG_Q_AT_TAIL
#define SG_FLAG_Q_AT_TAIL 0x10
#endif

#ifndef SG_FLAG_Q_AT_HEAD
#define SG_FLAG_Q_AT_HEAD 0x20
#endif

#define DEF_Q_LEN 16    /* max in sg v3 and earlier */
#define MAX_Q_LEN 256

#define DEF_RESERVE_BUFF_SZ (256 * 1024)


static bool q_at_tail = false;
static int q_len = DEF_Q_LEN;
static int sleep_secs = 0;
static int reserve_buff_sz = DEF_RESERVE_BUFF_SZ;
static int verbose = 0;


static void
usage(void)
{
    printf("Usage: sg_tst_bidi [-b=LB_SZ] [-d=DIO_BLKS] [-D] [-h] -l=LBA [-N] "
           "[-q=Q_LEN]\n"
           "                   [-Q] [-r=SZ] [-R=RC] [-s=SEC] [-t] [-v] [-V] "
           "[-w]\n"
           "                   <sg_or_bsg_device>\n"
           " where:\n"
           "      -b=LB_SZ    logical block size (def: 512 bytes)\n"
           "      -d=DIO_BLKS    data in and out length (unit: logical "
           "blocks; def: 1)\n"
           "      -D    do direct IO (def: indirect which is also "
           "fallback)\n"
           "      -h    help: print usage message then exit\n"
           "      -l=LBA    logical block address (LDA) of first modded "
           "block\n"
           "      -N    durations in nanoseconds (def: milliseconds)\n"
           "      -q=Q_LEN    queue length, between 1 and 511 (def: 16). "
           " Calls\n"
           "                  ioctl(SG_IO) when -q=1 else SG_IOSUBMIT "
           "(async)\n"
           "      -Q    quiet, suppress usual output\n"
           "      -r=SZ     reserve buffer size in KB (def: 256 --> 256 "
           "KB)\n"
           "      -R=RC     repetition count (def: 0)\n"
           "      -s=SEC    sleep between writes and reads (def: 0)\n"
           "      -t    queue_at_tail (def: q_at_head)\n"
           "      -v    increase verbosity of output\n"
           "      -V    print version string then exit\n"
           "      -w    sets DISABLE WRITE bit on cdb to 0 (def: 1)\n\n"
           "Warning: this test utility writes to location LBA and Q_LEN "
           "following\nblocks using the XDWRITEREAD(10) SBC-3 command. "
           "When -q=1 does\nioctl(SG_IO) and that is only case when a "
           "bsg device can be given.\n");
}

static int
ext_ioctl(int sg_fd, bool nanosecs)
{
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

    seip = &sei;
    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_RESERVED_SIZE;
    seip->reserved_sz = reserve_buff_sz;
    seip->sei_rd_mask |= SG_SEIM_RESERVED_SIZE;
    seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
    seip->sei_rd_mask |= SG_SEIM_CTL_FLAGS; /* this or previous optional */
    seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_TIME_IN_NS;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_TIME_IN_NS;
    if (nanosecs)
        seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;
    else
        seip->ctl_flags &= ~SG_CTL_FLAGM_TIME_IN_NS;

    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool done;
    bool direct_io = false;
    bool lba_given = false;
    bool nanosecs = false;
    bool quiet = false;
    bool disable_write = true;
    int k, j, ok, ver_num, pack_id, num_waiting, din_len;
    int dout_len, cat;
    int ret = 0;
    int rep_count = 0;
    int sg_fd = -1;
    int lb_sz = 512;
    int dio_blks = 1;
    int dirio_count = 0;
    int64_t lba = 0;
    uint8_t inq_cdb[INQ_CMD_LEN] = {INQ_CMD_OP, 0, 0, 0, INQ_REPLY_LEN, 0};
    uint8_t xdwrrd10_cdb[XDWRITEREAD_10_LEN] =
                        {XDWRITEREAD_10_OP, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
    uint8_t inqBuff[MAX_Q_LEN][INQ_REPLY_LEN];
    struct sg_io_v4 io_v4[MAX_Q_LEN];
    struct sg_io_v4 rio_v4;
    struct sg_io_v4 * io_v4p;
    char * file_name = 0;
    uint8_t * dinp;
    uint8_t * free_dinp = NULL;
    uint8_t * doutp;
    uint8_t * free_doutp = NULL;
    char ebuff[EBUFF_SZ];
    uint8_t sense_buffer[MAX_Q_LEN][SENSE_BUFFER_LEN];

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-b=", argv[k], 3)) {
            lb_sz = atoi(argv[k] + 3);
            if (lb_sz < 512 || (0 != (lb_sz % 512))) {
                printf("Expect -b=LB_SZ be 512 or higher and a power of 2\n");
                file_name = 0;
                break;
            }
        } else if (0 == memcmp("-d=", argv[k], 3)) {
            dio_blks = atoi(argv[k] + 3);
            if ((dio_blks < 1) || (dio_blks > 0xffff)) {
                fprintf(stderr, "Expect -d=DIO_BLKS to be 1 or greater and "
                        "less than 65536\n");
                file_name = 0;
                break;
            }
        } else if (0 == memcmp("-D", argv[k], 2))
            direct_io = true;
        else if (0 == memcmp("-h", argv[k], 2)) {
            file_name = 0;
            break;
        } else if (0 == memcmp("-l=", argv[k], 3)) {
            if (lba_given) {
                pr2serr("can only give -l=LBA option once\n");
                file_name = 0;
                break;
            }
            lba = sg_get_llnum(argv[k] + 3);
            if ((lba < 0) || (lba > 0xffffffff)) {
                pr2serr("Expect -l= argument (LBA) to be non-negative and "
                        "fit in 32 bits\n");
                return -1;
            }
            lba_given = true;
        } else if (0 == memcmp("-N", argv[k], 2))
            nanosecs = true;
        else if (0 == memcmp("-q=", argv[k], 3)) {
            q_len = atoi(argv[k] + 3);
            if ((q_len > 511) || (q_len < 1)) {
                printf("Expect -q= to take a number (q length) between 1 "
                       "and 511\n");
                file_name = 0;
                break;
            }
        } else if (0 == memcmp("-Q", argv[k], 2))
            quiet = true;
        else if (0 == memcmp("-r=", argv[k], 3)) {
            reserve_buff_sz = atoi(argv[k] + 3);
            if (reserve_buff_sz < 0) {
                printf("Expect -r= to take a number 0 or higher\n");
                file_name = 0;
                break;
            }
        } else if (0 == memcmp("-R=", argv[k], 3)) {
            rep_count = atoi(argv[k] + 3);
            if (rep_count < 0) {
                printf("Expect -R= to take a number 0 or higher\n");
                file_name = 0;
                break;
            }
        } else if (0 == memcmp("-s=", argv[k], 3)) {
            sleep_secs = atoi(argv[k] + 3);
            if (sleep_secs < 0) {
                printf("Expect -s= to take a number 0 or higher\n");
                file_name = 0;
                break;
            }
        } else if (0 == memcmp("-t", argv[k], 2))
            q_at_tail = true;
        else if (0 == memcmp("-vvvvv", argv[k], 5))
            verbose += 5;
        else if (0 == memcmp("-vvvv", argv[k], 5))
            verbose += 4;
        else if (0 == memcmp("-vvv", argv[k], 4))
            verbose += 3;
        else if (0 == memcmp("-vv", argv[k], 3))
            verbose += 2;
        else if (0 == memcmp("-v", argv[k], 2))
            verbose += 1;
        else if (0 == memcmp("-V", argv[k], 2)) {
            printf("%s\n", version_str);
            return 0;
        } else if (0 == memcmp("-w", argv[k], 2))
            disable_write = false;
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
        printf("No filename (sg device) given\n\n");
        usage();
        return 1;
    }
    if (! lba_given) {
        pr2serr("Needs the -l=LBA 'option' to be given, hex numbers "
                "prefixed by '0x';\nor with a trailing 'h'\n");
        ret = 1;
        goto out;
    }
    din_len = lb_sz * dio_blks;
    dout_len = lb_sz * dio_blks;
    dinp = sg_memalign(din_len * q_len, 0, &free_dinp, false);
    if (NULL == dinp) {
        fprintf(stderr, "Unable to allocate %d byte for din buffer\n",
                din_len * q_len);
        ret = 1;
        goto out;
    }
    doutp = sg_memalign(dout_len * q_len, 0, &free_doutp, false);
    if (NULL == doutp) {
        fprintf(stderr, "Unable to allocate %d byte for dout buffer\n",
                dout_len * q_len);
        ret = 1;
        goto out;
    }

    /* An access mode of O_RDWR is required for write()/read() interface */
    if ((sg_fd = open(file_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    if (verbose)
        fprintf(stderr, "opened given file: %s successfully, fd=%d\n",
                file_name, sg_fd);

    if (ioctl(sg_fd, SG_GET_VERSION_NUM, &ver_num) < 0) {
        pr2serr("ioctl(SG_GET_VERSION_NUM) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
    if (! quiet)
        printf("Linux sg driver version: %d\n", ver_num);
    if ((q_len > 1) && ext_ioctl(sg_fd, nanosecs))
        goto out;


    if (1 == q_len) {   /* do sync ioct(SG_IO) */
        io_v4p = &io_v4[k];
rep_sg_io:
        memset(io_v4p, 0, sizeof(*io_v4p));
        io_v4p->guard = 'Q';
        if (direct_io)
            io_v4p->flags |= SG_FLAG_DIRECT_IO;
        if (disable_write)
            xdwrrd10_cdb[2] |= 0x4;
        sg_put_unaligned_be16(dio_blks, xdwrrd10_cdb + 7);
        sg_put_unaligned_be32(lba, xdwrrd10_cdb + 2);
        if (verbose > 2) {
            pr2serr("    %s cdb: ", "XDWRITE(10)");
            for (j = 0; j < XDWRITEREAD_10_LEN; ++j)
                pr2serr("%02x ", xdwrrd10_cdb[j]);
            pr2serr("\n");
        }
        io_v4p->request_len = XDWRITEREAD_10_LEN;
        io_v4p->request = (uint64_t)(uintptr_t)xdwrrd10_cdb;
        io_v4p->din_xfer_len = din_len;
        io_v4p->din_xferp = (uint64_t)(uintptr_t)(dinp + (k * din_len));
        io_v4p->dout_xfer_len = dout_len;
        io_v4p->dout_xferp = (uint64_t)(uintptr_t)(doutp + (k * dout_len));
        io_v4p->response = (uint64_t)(uintptr_t)sense_buffer[k];
        io_v4p->max_response_len = SENSE_BUFFER_LEN;
        io_v4p->timeout = 20000;     /* 20000 millisecs == 20 seconds */
        io_v4p->request_extra = 99;  /* so pack_id doesn't start at 0 */
        /* default is to queue at head (in SCSI mid level) */
        if (q_at_tail)
            io_v4p->flags |= SG_FLAG_Q_AT_TAIL;
        else
            io_v4p->flags |= SG_FLAG_Q_AT_HEAD;
        /* io_v4p->usr_ptr = NULL; */

        if (ioctl(sg_fd, SG_IO, io_v4p) < 0) {
            pr2serr("sg ioctl(SG_IO) errno=%d [%s]\n", errno,
                    strerror(errno));
            close(sg_fd);
            return 1;
        }
        /* now for the error processing */
        ok = 0;
        rio_v4 = *io_v4p;
        cat = sg_err_category_new(rio_v4.device_status,
                                  rio_v4.transport_status,
                                  rio_v4.driver_status,
                          (const uint8_t *)(unsigned long)rio_v4.response,
                                  rio_v4.response_len);
        switch (cat) {
        case SG_LIB_CAT_CLEAN:
            ok = 1;
            break;
        case SG_LIB_CAT_RECOVERED:
            printf("Recovered error, continuing\n");
            ok = 1;
            break;
        default: /* won't bother decoding other categories */
            sg_linux_sense_print(NULL, rio_v4.device_status,
                                 rio_v4.transport_status,
                                 rio_v4.driver_status,
                         (const uint8_t *)(unsigned long)rio_v4.response,
                                 rio_v4.response_len, true);
            break;
        }
        if ((rio_v4.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO)
            ++dirio_count;
        if (verbose > 3) {
            pr2serr(">> din_resid=%d, dout_resid=%d, info=0x%x\n",
                    rio_v4.din_resid, rio_v4.dout_resid, rio_v4.info);
            if (rio_v4.response_len > 0) {
                pr2serr("sense buffer: ");
                hex2stderr(sense_buffer[k], rio_v4.response_len, -1);
            }
        }
        if ((! quiet) && ok)  /* output result if it is available */
            printf("XDWRITEREAD(10) using ioctl(SG_IO) duration=%u\n",
                   rio_v4.duration);
        if (rep_count-- > 0)
            goto rep_sg_io;
        goto out;
    }

rep_async:
    if (! quiet)
        printf("start write() calls\n");
    for (k = 0; k < q_len; ++k) {
        io_v4p = &io_v4[k];
        memset(io_v4p, 0, sizeof(*io_v4p));
        io_v4p->guard = 'Q';
        if (direct_io)
            io_v4p->flags |= SG_FLAG_DIRECT_IO;
        /* io_v4p->iovec_count = 0; */  /* memset takes care of this */
        if (0 != (k % 64)) {
            if (disable_write)
                xdwrrd10_cdb[2] |= 0x4;
            sg_put_unaligned_be16(dio_blks, xdwrrd10_cdb + 7);
            sg_put_unaligned_be32(lba, xdwrrd10_cdb + 2);
            if (verbose > 2) {
                pr2serr("    %s cdb: ", "XDWRITE(10)");
                for (j = 0; j < XDWRITEREAD_10_LEN; ++j)
                    pr2serr("%02x ", xdwrrd10_cdb[j]);
                pr2serr("\n");
            }
            io_v4p->request_len = XDWRITEREAD_10_LEN;
            io_v4p->request = (uint64_t)(uintptr_t)xdwrrd10_cdb;
            io_v4p->din_xfer_len = din_len;
            io_v4p->din_xferp = (uint64_t)(uintptr_t)(dinp + (k * din_len));
            io_v4p->dout_xfer_len = dout_len;
            io_v4p->dout_xferp = (uint64_t)(uintptr_t)(doutp + (k * dout_len));
        } else {
            if (verbose > 2) {
                pr2serr("    %s cdb: ", "INQUIRY");
                for (j = 0; j < INQ_CMD_LEN; ++j)
                    pr2serr("%02x ", inq_cdb[j]);
                pr2serr("\n");
            }
            io_v4p->request_len = sizeof(inq_cdb);
            io_v4p->request = (uint64_t)(uintptr_t)inq_cdb;
            io_v4p->din_xfer_len = INQ_REPLY_LEN;
            io_v4p->din_xferp = (uint64_t)(uintptr_t)inqBuff[k];
        }
        io_v4p->response = (uint64_t)(uintptr_t)sense_buffer[k];
        io_v4p->max_response_len = SENSE_BUFFER_LEN;
        io_v4p->timeout = 20000;     /* 20000 millisecs == 20 seconds */
        io_v4p->request_extra = k + 3;  /* so pack_id doesn't start at 0 */
        /* default is to queue at head (in SCSI mid level) */
        if (q_at_tail)
            io_v4p->flags |= SG_FLAG_Q_AT_TAIL;
        else
            io_v4p->flags |= SG_FLAG_Q_AT_HEAD;
        /* io_v4p->usr_ptr = NULL; */

        if (ioctl(sg_fd, SG_IOSUBMIT, io_v4p) < 0) {
            pr2serr("sg ioctl(SG_IOSUBMIT) errno=%d [%s]\n", errno,
                    strerror(errno));
            close(sg_fd);
            return 1;
        }
    }

#if 0
    {
        struct sg_scsi_id ssi;

        memset(&ssi, 0, sizeof(ssi));
        if (ioctl(sg_fd, SG_GET_SCSI_ID, &ssi) < 0)
            pr2serr("ioctl(SG_GET_SCSI_ID) failed, errno=%d %s\n",
                    errno, strerror(errno));
        else {
            printf("host_no: %d\n", ssi.host_no);
            printf("  channel: %d\n", ssi.channel);
            printf("  scsi_id: %d\n", ssi.scsi_id);
            printf("  lun: %d\n", ssi.lun);
            printf("  pdt: %d\n", ssi.scsi_type);
            printf("  h_cmd_per_lun: %d\n", ssi.h_cmd_per_lun);
            printf("  d_queue_depth: %d\n", ssi.d_queue_depth);
        }
    }
#endif
    if (ioctl(sg_fd, SG_GET_PACK_ID, &pack_id) < 0)
        pr2serr("ioctl(SG_GET_PACK_ID) failed, errno=%d %s\n",
                errno, strerror(errno));
    else if (! quiet)
        printf("first available pack_id: %d\n", pack_id);
    if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0)
        pr2serr("ioctl(SG_GET_NUM_WAITING) failed, errno=%d %s\n",
                errno, strerror(errno));
    else if (! quiet)
        printf("num_waiting: %d\n", num_waiting);

    if (sleep_secs > 0)
        sleep(sleep_secs);

    if (ioctl(sg_fd, SG_GET_PACK_ID, &pack_id) < 0)
        pr2serr("ioctl(SG_GET_PACK_ID) failed, errno=%d %s\n",
                errno, strerror(errno));
    else if (! quiet)
        printf("first available pack_id: %d\n", pack_id);
    if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0)
        pr2serr("ioctl(SG_GET_NUM_WAITING) failed, errno=%d %s\n",
                errno, strerror(errno));
    else if (! quiet)
        printf("num_waiting: %d\n", num_waiting);

    if (! quiet)
        printf("\nstart read() calls\n");
    for (k = 0, done = false; k < q_len; ++k) {
        if ((! done) && (k == q_len / 2)) {
            done = true;
            if (! quiet)
                printf("\n>>> half way through read\n");
            if (ioctl(sg_fd, SG_GET_PACK_ID, &pack_id) < 0)
                pr2serr("ioctl(SG_GET_PACK_ID) failed, errno=%d %s\n",
                        errno, strerror(errno));
            else if (! quiet)
                printf("first available pack_id: %d\n", pack_id);
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0)
                pr2serr("ioctl(SG_GET_NUM_WAITING) failed, errno=%d %s\n",
                        errno, strerror(errno));
            else if (! quiet)
                printf("num_waiting: %d\n", num_waiting);
        }
        memset(&rio_v4, 0, sizeof(struct sg_io_v4));
        rio_v4.guard = 'Q';
        if (ioctl(sg_fd, SG_IORECEIVE, &rio_v4) < 0) {
            perror("sg ioctl(SG_IORECEIVE) error");
            close(sg_fd);
            return 1;
        }
        /* now for the error processing */
        ok = 0;
        cat = sg_err_category_new(rio_v4.device_status,
                                  rio_v4.transport_status,
                                  rio_v4.driver_status,
                          (const uint8_t *)(unsigned long)rio_v4.response,
                                  rio_v4.response_len);
        switch (cat) {
        case SG_LIB_CAT_CLEAN:
            ok = 1;
            break;
        case SG_LIB_CAT_RECOVERED:
            printf("Recovered error, continuing\n");
            ok = 1;
            break;
        default: /* won't bother decoding other categories */
            sg_linux_sense_print(NULL, rio_v4.device_status,
                                 rio_v4.transport_status,
                                 rio_v4.driver_status,
                         (const uint8_t *)(unsigned long)rio_v4.response,
                                 rio_v4.response_len, true);
            break;
        }
        if ((rio_v4.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO)
            ++dirio_count;
        if (verbose > 3) {
            pr2serr(">> din_resid=%d, dout_resid=%d, info=0x%x\n",
                    rio_v4.din_resid, rio_v4.dout_resid, rio_v4.info);
            if (rio_v4.response_len > 0) {
                pr2serr("sense buffer: ");
                hex2stderr(sense_buffer[k], rio_v4.response_len, -1);
            }
        }
        if ((! quiet) && ok) { /* output result if it is available */
            if (0 != ((rio_v4.request_extra - 3) % 64))
                printf("XDWRITEREAD(10) %d duration=%u\n",
                       rio_v4.request_extra, rio_v4.duration);
            else
                printf("INQUIRY %d duration=%u\n",
                       rio_v4.request_extra,
                       rio_v4.duration);
        }
    }
    if (direct_io && (dirio_count < q_len)) {
        pr2serr("Direct IO requested %d times, done %d times\nMaybe need "
                "'echo 1 > /proc/scsi/sg/allow_dio'\n", q_len, dirio_count);
    }
    if (rep_count-- > 0)
        goto rep_async;
    ret = 0;

out:
    if (sg_fd >= 0)
        close(sg_fd);
    if (free_dinp)
        free(free_dinp);
    if (free_doutp)
        free(free_doutp);
    return ret;
}
