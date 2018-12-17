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

#include <sys/socket.h> /* For passing fd_s via Unix sockets */

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


static const char * version_str = "Version: 1.01  20181216";

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

static bool is_parent = false;
static bool do_fork = false;
static bool ioctl_only = false;
static bool q_at_tail = false;
static bool write_only = false;

static int childs_pid = 0;
static int q_len = DEF_Q_LEN;
static int sleep_secs = 0;
static int reserve_buff_sz = DEF_RESERVE_BUFF_SZ;
static int verbose = 0;

static const char * relative_cp = NULL;


static void
usage(void)
{
    printf("Usage: 'sg_tst_ioctl [-f] [-h] [-l=Q_LEN] [-o] [-r=SZ] [-s=SEC] "
           "[-t]\n"
           "       [-v] [-V] [-w] <sg_device> [<sg_device2>]'\n"
           " where:\n"
           "      -f      fork and test share between processes\n"
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

/* This function taken from Keith Parkard's blog dated 2101205 */
static ssize_t
sock_fd_write(int sock, const void *buf, ssize_t buflen, int fd)
{
    ssize_t     size;
    struct msghdr   msg;
    struct iovec    iov;
    union {
        struct cmsghdr  cmsghdr;
        char        control[CMSG_SPACE(sizeof (int))];
    } cmsgu;
    struct cmsghdr  *cmsg;

    iov.iov_base = (void *)buf; /* OS shouldn't write back in this */
    iov.iov_len = buflen;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (fd != -1) {
        msg.msg_control = cmsgu.control;
        msg.msg_controllen = sizeof(cmsgu.control);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof (int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        printf ("passing fd %d\n", fd);
        *((int *) CMSG_DATA(cmsg)) = fd;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        printf ("not passing fd\n");
    }

    size = sendmsg(sock, &msg, 0);

    if (size < 0)
        perror ("sendmsg");
    return size;
}

/* This function taken from Keith Parkard's blog dated 2101205 */
static ssize_t
sock_fd_read(int sock, void *buf, ssize_t bufsize, int *fd)
{
    ssize_t     size;

    if (fd) {
        struct msghdr   msg;
        struct iovec    iov;
        union {
            struct cmsghdr  cmsghdr;
            char        control[CMSG_SPACE(sizeof (int))];
        } cmsgu;
        struct cmsghdr  *cmsg;

        iov.iov_base = buf;
        iov.iov_len = bufsize;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgu.control;
        msg.msg_controllen = sizeof(cmsgu.control);
        size = recvmsg (sock, &msg, 0);
        if (size < 0) {
            perror ("recvmsg");
            exit(1);
        }
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
            if (cmsg->cmsg_level != SOL_SOCKET) {
                fprintf (stderr, "invalid cmsg_level %d\n",
                     cmsg->cmsg_level);
                exit(1);
            }
            if (cmsg->cmsg_type != SCM_RIGHTS) {
                fprintf (stderr, "invalid cmsg_type %d\n",
                     cmsg->cmsg_type);
                exit(1);
            }

            *fd = *((int *) CMSG_DATA(cmsg));
            printf ("received fd %d\n", *fd);
        } else
            *fd = -1;
    } else {
        size = read (sock, buf, bufsize);
        if (size < 0) {
            perror("read");
            exit(1);
        }
    }
    return size;
}

static int
tst_ioctl(const char * fnp, int sg_fd, const char * fn2p, int sg_fd2,
          int sock, const char * cp)
{
    uint32_t cflags;
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

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
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_IS_SHARE;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_IS_MASTER;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_UNSHARE;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_MASTER_FINI;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_MASTER_ERR;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_CHECK_FOR_MORE;
    seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;

    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
#if 1
    printf("%sSG_SET_GET_EXTENDED ioctl ok\n", cp);
    if (SG_SEIM_RESERVED_SIZE & seip->valid_rd_mask)
        printf("  %sreserved size: %u\n", cp, seip->reserved_sz);
    if (SG_SEIM_MINOR_INDEX & seip->valid_rd_mask)
        printf("  %sminor index: %u\n", cp, seip->minor_index);
    if (SG_SEIM_RQ_REM_THRESH & seip->valid_rd_mask)
        printf("  %srq_rem_sgat_thresh: %u\n", cp, seip->rq_rem_sgat_thresh);
    if (SG_SEIM_TOT_FD_THRESH & seip->valid_rd_mask)
        printf("  %stot_fd_thresh: %u\n", cp, seip->tot_fd_thresh);
    if ((SG_SEIM_CTL_FLAGS & seip->valid_rd_mask) ||
         (SG_SEIM_CTL_FLAGS & seip->valid_wr_mask)) {
        cflags = seip->ctl_flags;
        if (SG_CTL_FLAGM_TIME_IN_NS & seip->ctl_flags_rd_mask)
            printf("  %sTIME_IN_NS: %s\n", cp,
                   (SG_CTL_FLAGM_TIME_IN_NS & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_OTHER_OPENS & seip->ctl_flags_rd_mask)
            printf("  %sOTHER_OPENS: %s\n", cp,
                   (SG_CTL_FLAGM_OTHER_OPENS & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_ORPHANS & seip->ctl_flags_rd_mask)
            printf("  %sORPHANS: %s\n", cp,
                   (SG_CTL_FLAGM_ORPHANS & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_Q_TAIL & seip->ctl_flags_rd_mask)
            printf("  %sQ_TAIL: %s\n", cp,
                   (SG_CTL_FLAGM_Q_TAIL & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_IS_SHARE & seip->ctl_flags_rd_mask)
            printf("  %sIS_SHARE: %s\n", cp,
                   (SG_CTL_FLAGM_IS_SHARE & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_IS_MASTER & seip->ctl_flags_rd_mask)
            printf("  %sIS_MASTER: %s\n", cp,
                   (SG_CTL_FLAGM_IS_MASTER & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_UNSHARE & seip->ctl_flags_rd_mask)
            printf("  %sUNSHARE: %s\n", cp,
                   (SG_CTL_FLAGM_UNSHARE & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_MASTER_FINI & seip->ctl_flags_rd_mask)
            printf("  %sMASTER_FINI: %s\n", cp,
                   (SG_CTL_FLAGM_MASTER_FINI & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_MASTER_ERR & seip->ctl_flags_rd_mask)
            printf("  %sMASTER_ERR: %s\n", cp,
                   (SG_CTL_FLAGM_MASTER_ERR & cflags) ? "true" : "false");
        if (SG_CTL_FLAGM_CHECK_FOR_MORE & seip->ctl_flags_rd_mask)
            printf("  %sCHECK_FOR_MORE: %s\n", cp,
                   (SG_CTL_FLAGM_CHECK_FOR_MORE & cflags) ? "true" : "false");
    }
    if (SG_SEIM_MINOR_INDEX & seip->valid_rd_mask)
        printf("  %sminor_index: %u\n", cp, seip->minor_index);
    printf("\n");
#endif

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_INT_MASK;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_INT_MASK]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_BOOL_MASK;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_BOOL_MASK]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_VERS_NUM;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_VERS_NUM]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_FL_RQS;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_FL_RQS]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_DEV_FL_RQS;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_DEV_FL_RQS]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_TRC_SZ;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_TRC_SZ]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_READ_VAL;
    seip->valid_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_TRC_MAX_SZ;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_TRC_MAX_SZ]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->valid_wr_mask |= SG_SEIM_SHARE_FD;
    seip->valid_rd_mask |= SG_SEIM_SHARE_FD;
#if 1
    seip->share_fd = sg_fd2;
#else
    seip->share_fd = sg_fd;
#endif
    if (do_fork && is_parent)
        goto bypass_share;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("%sioctl(SG_SET_GET_EXTENDED) shared_fd=%d, failed errno=%d "
                "%s\n", cp, sg_fd2, errno, strerror(errno));
    }
    printf("  %sshare successful, read back shared_fd= %d\n", cp,
           (int)seip->share_fd);
bypass_share:

    // printf("SG_IOSUBMIT value=0x%lx\n", SG_IOSUBMIT);
    // printf("SG_IORECEIVE value=0x%lx\n", SG_IORECEIVE);
    if (ioctl(sg_fd, SG_GET_TRANSFORM, NULL) < 0)
        pr2serr("ioctl(SG_GET_TRANSFORM) fail expected, errno=%d %s\n",
                errno, strerror(errno));
    else
        printf("%sSG_GET_TRANSFORM okay (does nothing)\n", cp);
    if (ioctl(sg_fd, SG_SET_TRANSFORM, NULL) < 0)
        pr2serr("ioctl(SG_SET_TRANSFORM) fail expected, errno=%d %s\n",
                errno, strerror(errno));
    else
        printf("%sSG_SET_TRANSFORM okay (does nothing)\n", cp);
    printf("\n");

    /* test sending a sg file descriptor between 2 processes using UNIX
     * sockets */
    if (do_fork && is_parent && fnp && (sock >= 0)) { /* master/READ side */
        int res;
        int fd_ma = open(fnp, O_RDWR);

        if (fd_ma < 0) {
            pr2serr("%s: opening %s failed: %s\n", __func__, fnp,
                    strerror(errno));
            return 1;
        }
        res = sock_fd_write(sock, "boo", 4, fd_ma);
        if (res < 0)
            pr2serr("%s: sock_fd_write() failed\n", __func__);
        else
            printf("%s: sock_fd_write() returned: %d\n", __func__, res);
    } else if (do_fork && !is_parent && fn2p && (sock >= 0)) {
        int res, fd_ma;
        /* int fd_sl = open(fn2p, O_RDWR); not needed */
        uint8_t b[32];

        fd_ma = -1;
        res = sock_fd_read(sock, b, sizeof(b), &fd_ma);
        if (res < 0)
            pr2serr("%s: sock_fd_read() failed\n", __func__);
        else
            printf("%s: sock_fd_read() returned: %d, fd_ma=%d\n", __func__,
                   res, fd_ma);
	/* yes it works! */
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool done;
    int sg_fd, k, ok, ver_num, pack_id, num_waiting, access_count;
    int sg_fd2 = -1;
    int sock = -1;
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
    const char * second_fname = NULL;
    const char * cp;
    struct sg_scsi_id ssi;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-f", argv[k], 2))
            do_fork = true;
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
        } else if (0 == memcmp("-t", argv[k], 2))
            q_at_tail = true;
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
        else if (NULL == second_fname)
            second_fname = argv[k];
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
    printf("Linux sg driver version: %d\n", ver_num);

    if (second_fname) {
        if ((sg_fd2 = open(second_fname, O_RDWR)) < 0) {
            snprintf(ebuff, EBUFF_SZ,
                     "%s: error opening file: %s", __func__, second_fname);
            perror(ebuff);
            return 1;
        }
        if (verbose)
            fprintf(stderr, "opened second file: %s successfully, fd=%d\n",
                    second_fname, sg_fd2);
    }

    if (do_fork) {
        int pid;
        int sv[2];

        if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0) {
            perror("socketpair");
            exit(1);
        }
        printf("socketpair: sv[0]=%d, sv[1]=%d sg_fd=%d\n", sv[0], sv[1],
               sg_fd);
        pid = fork();
        if (pid < 0) {
            perror("fork() failed");
            goto out;
        } else if (0 == pid) {
            relative_cp = "child ";
            is_parent = false;
            close(sv[0]);
            sock = sv[1];
        } else {
            relative_cp = "parent ";
            is_parent = true;
            childs_pid = pid;
            close(sv[1]);
            sock = sv[0];
        }
    }

    cp = do_fork ? relative_cp : "";
    if (tst_ioctl(file_name, sg_fd, second_fname, sg_fd2, sock, cp))
        goto out;
    if (ioctl_only)
        goto out;

    if (do_fork && !is_parent)
        return 0;

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
            pr2serr("%ssg write errno=%d [%s]\n", cp, errno, strerror(errno));
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

    if (do_fork)
        printf("\n\nFollowing starting with get_pack_id are all CHILD\n");
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
            perror("sg read error");
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
