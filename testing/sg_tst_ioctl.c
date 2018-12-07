/*
 *  Copyright (C) 2018 D. Gilbert
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

#include "sg_lib.h"
#include "sg_io_linux.h"
#include "sg_linux_inc.h"
#include "sg_pr2serr.h"

/* This program tests ioctl() calls added and modified in version 3.9 and
 * later of the Linux sg driver.  */


static const char * version_str = "Version: 0.98  20181207";

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

#define DEF_RESERVE_BUFF_SZ (256 * 1024)


static void
usage(void)
{
    printf("Usage: 'sg_tst_ioctl [-h] [-l=Q_LEN] [-o] [-r=SZ] [-s=SEC] "
           "[-t]\n"
           "       [-v] [-V] [-w] <sg_device>'\n"
           " where:\n"
           "      -h      help: print usage message then exit\n"
           "      -l=Q_LEN    queue length, between 1 and 511 (def: 16)\n"
           "      -o      ioctls only, then exit\n"
           "      -r=SZ     reserve buffer size in KB (def: 256 --> 256 "
           "KB)\n"
           "      -s=SEC    sleep between writes and reads (def: 0)\n"
           "      -t    queue_at_tail (def: q_at_head)\n"
           "      -v    increase verbosity of output\n"
           "      -V    print version string then exit\n"
           "      -w    write (submit) only then exit\n");
}


int
main(int argc, char * argv[])
{
    bool done;
    bool q_at_tail = false;
    bool ioctl_only = false;
    bool write_only = false;
    int sg_fd, k, ok, ver_num, pack_id, num_waiting, access_count;
    int sg_fd2 = -1;
    uint8_t inq_cdb[INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    uint8_t sdiag_cdb[SDIAG_CMD_LEN] =
                                {0x1d, 0, 0, 0, 0, 0};
    uint8_t inqBuff[MAX_Q_LEN][INQ_REPLY_LEN];
    sg_io_hdr_t io_hdr[MAX_Q_LEN];
    sg_io_hdr_t rio_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    uint8_t sense_buffer[MAX_Q_LEN][SENSE_BUFFER_LEN];
    int q_len = DEF_Q_LEN;
    int sleep_secs = 0;
    int reserve_buff_sz = DEF_RESERVE_BUFF_SZ;
    int verbose = 0;
    uint32_t cflags;
    struct sg_extended_info sei;
    struct sg_extended_info * seip;
    const char * second_fname = "/dev/sg2";
    struct sg_scsi_id ssi;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-t", argv[k], 2))
            q_at_tail = true;
        else if (0 == memcmp("-h", argv[k], 2)) {
            file_name = 0;
            break;
        } else if (0 == memcmp("-l=", argv[k], 3)) {
            q_len = atoi(argv[k] + 3);
            if ((q_len > 511) || (q_len < 1)) {
                printf("Expect -l= to take a number (q length) between 1 "
                       "and 511\n");
                file_name = 0;
                break;
            }
        } else if (0 == memcmp("-o", argv[k], 2))
            ioctl_only = true;
        else if (0 == memcmp("-r=", argv[k], 3)) {
            reserve_buff_sz = atoi(argv[k] + 3);
            if (reserve_buff_sz < 0) {
                printf("Expect -r= to take a number 0 or higher\n");
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
        } else if (0 == memcmp("-vvvv", argv[k], 5))
            verbose += 4;
        else if (0 == memcmp("-vvv", argv[k], 4))
            verbose += 3;
        else if (0 == memcmp("-vv", argv[k], 3))
            verbose += 2;
        else if (0 == memcmp("-v", argv[k], 2))
            verbose += 1;
        else if (0 == memcmp("-V", argv[k], 2)) {
            printf("%s\n", version_str);
            file_name = 0;
            break;
        } else if (0 == memcmp("-w", argv[k], 2))
            write_only = true;
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
        usage();
        return 1;
    }

    /* An access mode of O_RDWR is required for write()/read() interface */
    if ((sg_fd = open(file_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg_queue_tst: error opening file: %s", file_name);
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
    printf("Linux sg driver version: %d\n", ver_num);

    if ((sg_fd2 = open(second_fname, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "%s: error opening file: %s", __func__, second_fname);
        perror(ebuff);
        return 1;
    }
    if (verbose)
        fprintf(stderr, "opened second file: %s successfully, fd=%d\n",
                second_fname, sg_fd2);

    seip = &sei;
    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_RESERVED_SIZE;
    seip->reserved_sz = reserve_buff_sz;
    seip->sgat_elem_sz = 64 * 1024;;
    seip->valid_rd_mask |= SG_SEIM_RESERVED_SIZE;
    seip->valid_rd_mask |= SG_SEIM_RQ_REM_THRESH;
    seip->valid_rd_mask |= SG_SEIM_TOT_FD_THRESH;
    seip->valid_wr_mask |= SG_SEIM_CTL_FLAGS;
    seip->valid_rd_mask |= SG_SEIM_CTL_FLAGS; /* this or previous optional */
    seip->valid_rd_mask |= SG_SEIM_MINOR_INDEX;
    seip->valid_wr_mask |= SG_SEIM_SGAT_ELEM_SZ;
    seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_TIME_IN_NS;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_TIME_IN_NS;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_OTHER_OPENS;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_ORPHANS;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_Q_TAIL;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_UNSHARE;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_MASTER_FINI;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_MASTER_ERR;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_CHECK_FOR_MORE;
    seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;

    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
#if 1
    printf("SG_SET_GET_EXTENDED ioctl ok\n");
    if (SG_SEIM_RESERVED_SIZE & seip->valid_rd_mask)
        printf("  reserved size: %u\n", seip->reserved_sz);
    if (SG_SEIM_MINOR_INDEX & seip->valid_rd_mask)
        printf("  minor index: %u\n", seip->minor_index);
    if (SG_SEIM_RQ_REM_THRESH & seip->valid_rd_mask)
        printf("  rq_rem_sgat_thresh: %u\n", seip->rq_rem_sgat_thresh);
    if (SG_SEIM_TOT_FD_THRESH & seip->valid_rd_mask)
        printf("  tot_fd_thresh: %u\n", seip->tot_fd_thresh);
    if ((SG_SEIM_CTL_FLAGS & seip->valid_rd_mask) ||
         (SG_SEIM_CTL_FLAGS & seip->valid_wr_mask)) {
        cflags = seip->ctl_flags;
        if (SG_CTL_FLAGM_TIME_IN_NS & seip->ctl_flags_rd_mask)
            printf("  TIME_IN_NS: %s\n",
                   (SG_CTL_FLAGM_TIME_IN_NS & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_OTHER_OPENS & seip->ctl_flags_rd_mask)
            printf("  OTHER_OPENS: %s\n",
                   (SG_CTL_FLAGM_OTHER_OPENS & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_ORPHANS & seip->ctl_flags_rd_mask)
            printf("  ORPHANS: %s\n",
                   (SG_CTL_FLAGM_ORPHANS & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_Q_TAIL & seip->ctl_flags_rd_mask)
            printf("  Q_TAIL: %s\n",
                   (SG_CTL_FLAGM_Q_TAIL & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_UNSHARE & seip->ctl_flags_rd_mask)
            printf("  UNSHARE: %s\n",
                   (SG_CTL_FLAGM_UNSHARE & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_MASTER_FINI & seip->ctl_flags_rd_mask)
            printf("  MASTER_FINI: %s\n",
                   (SG_CTL_FLAGM_MASTER_FINI & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_MASTER_ERR & seip->ctl_flags_rd_mask)
            printf("  MASTER_ERR: %s\n",
                   (SG_CTL_FLAGM_MASTER_ERR & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_CHECK_FOR_MORE & seip->ctl_flags_rd_mask)
            printf("  CHECK_FOR_MORE: %s\n",
                   (SG_CTL_FLAGM_CHECK_FOR_MORE & cflags) ? "true" : "false");
    }
    if (SG_SEIM_MINOR_INDEX & seip->valid_rd_mask)
        printf("  minor_index: %u\n", seip->minor_index);
    printf("\n");
#endif

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_INT_MASK;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
    printf("SG_SET_GET_EXTENDED ioctl ok\n");
    printf("  read_value[SG_SEIRV_INT_MASK]= %u\n", seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_VERS_NUM;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
    printf("  read_value[SG_SEIRV_VERS_NUM]= %u\n", seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_FL_RQS;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
    printf("  read_value[SG_SEIRV_FL_RQS]= %u\n", seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_DEV_FL_RQS;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
    printf("  read_value[SG_SEIRV_DEV_FL_RQS]= %u\n", seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_TRC_SZ;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
    printf("  read_value[SG_SEIRV_TRC_SZ]= %u\n", seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_TRC_MAX_SZ;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
    printf("  read_value[SG_SEIRV_TRC_MAX_SZ]= %u\n", seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_SHARE_FD;
    seip->valid_rd_mask |= SG_SEIM_SHARE_FD;
#if 1
    seip->share_fd = sg_fd2;
#else
    seip->share_fd = sg_fd;
#endif
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0)
        pr2serr("ioctl(SG_SET_GET_EXTENDED) shared_fd=%d, failed errno=%d "
                "%s\n", sg_fd2, errno, strerror(errno));
    printf("  read back shared_fd= %u\n", seip->share_fd);

    // printf("SG_IOSUBMIT value=0x%lx\n", SG_IOSUBMIT);
    // printf("SG_IORECEIVE value=0x%lx\n", SG_IORECEIVE);
    if (ioctl(sg_fd, SG_GET_TRANSFORM, NULL) < 0)
        pr2serr("ioctl(SG_GET_TRANSFORM) fail expected, errno=%d %s\n",
                errno, strerror(errno));
    else
        printf("SG_GET_TRANSFORM okay (does nothing)\n");
    if (ioctl(sg_fd, SG_SET_TRANSFORM, NULL) < 0)
        pr2serr("ioctl(SG_SET_TRANSFORM) fail expected, errno=%d %s\n",
                errno, strerror(errno));
    else
        printf("SG_SET_TRANSFORM okay (does nothing)\n");
    printf("\n");

    if (ioctl_only)
        goto out;

    printf("start write() calls\n");
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
        io_hdr[k].pack_id = k + 3;      /* so pack_id doesn't start at 0 */
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
    if (ioctl(sg_fd, SG_GET_PACK_ID, &pack_id) < 0)
        pr2serr("ioctl(SG_GET_PACK_ID) failed, errno=%d %s\n",
                errno, strerror(errno));
    else
        printf("first available pack_id: %d\n", pack_id);
    if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0)
        pr2serr("ioctl(SG_GET_NUM_WAITING) failed, errno=%d %s\n",
                errno, strerror(errno));
    else
        printf("num_waiting: %d\n", num_waiting);

    sleep(sleep_secs);

    if (write_only)
        goto out;

    if (ioctl(sg_fd, SG_GET_PACK_ID, &pack_id) < 0)
        pr2serr("ioctl(SG_GET_PACK_ID) failed, errno=%d %s\n",
                errno, strerror(errno));
    else
        printf("first available pack_id: %d\n", pack_id);
    if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0)
        pr2serr("ioctl(SG_GET_NUM_WAITING) failed, errno=%d %s\n",
                errno, strerror(errno));
    else
        printf("num_waiting: %d\n", num_waiting);

    printf("\nstart read() calls\n");
    for (k = 0, done = false; k < q_len; ++k) {
        if ((! done) && (k == q_len / 2)) {
            done = true;
            printf("\n>>> half way through read\n");
            if (ioctl(sg_fd, SG_GET_PACK_ID, &pack_id) < 0)
                pr2serr("ioctl(SG_GET_PACK_ID) failed, errno=%d %s\n",
                        errno, strerror(errno));
            else
                printf("first available pack_id: %d\n", pack_id);
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0)
                pr2serr("ioctl(SG_GET_NUM_WAITING) failed, errno=%d %s\n",
                        errno, strerror(errno));
            else
                printf("num_waiting: %d\n", num_waiting);
            if (ioctl(sg_fd, SG_GET_ACCESS_COUNT, &access_count) < 0)
                pr2serr("ioctl(SG_GET_ACCESS_COUNT) failed, errno=%d %s\n",
                        errno, strerror(errno));
            else
                printf("access_count: %d\n", access_count);
        }
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
            if (0 == (rio_hdr.pack_id % 3))
                printf("SEND DIAGNOSTIC %d duration=%u\n", rio_hdr.pack_id,
                       rio_hdr.duration);
            else
                printf("INQUIRY %d duration=%u\n", rio_hdr.pack_id,
                       rio_hdr.duration);
        }
    }

out:
    close(sg_fd);
    if (sg_fd2 >= 0)
        close(sg_fd2);
    return 0;
}
