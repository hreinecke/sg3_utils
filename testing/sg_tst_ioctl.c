/*
 *  Copyright (C) 2018-2019 D. Gilbert
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
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#include <sys/socket.h> /* For passing fd_s via Unix sockets */

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

/* This program tests ioctl() calls added and modified in version 4.0 and
 * later of the Linux sg driver.  */


static const char * version_str = "Version: 1.14  20191116";

#define INQ_REPLY_LEN 128
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
#define MAX_Q_LEN 512

#define DEF_RESERVE_BUFF_SZ (256 * 1024)

static bool create_time = false;
static bool is_parent = false;
static bool do_fork = false;
static bool ioctl_only = false;
static bool more_async = false;
static bool no_duration = false;
static bool q_at_tail = false;
static bool write_only = false;
static bool mrq_immed = false;  /* if set, also sets mrq_iosubmit */
static bool mrq_half_immed = false;
static bool mrq_iosubmit = false;
static bool show_size_value = false;
static bool do_v3_only = false;

static int childs_pid = 0;
static int sg_drv_ver_num = 0;
static int q_len = DEF_Q_LEN;
static int sleep_secs = 0;
static int reserve_buff_sz = DEF_RESERVE_BUFF_SZ;
static int num_mrqs = 0;
static int num_sgnw = 0;
static int verbose = 0;

static const char * relative_cp = NULL;
static char * file_name = NULL;


static void
usage(void)
{
    printf("Usage: sg_tst_ioctl [-3] [-c] [-f] [-h] [-l=Q_LEN] "
           "[-m=MRQS[,I|S]]\n"
           "                    [-M] [-n] [-o] [-r=SZ] [-s=SEC] [-S] [-t] "
           "[-T=NUM]\n"
           "                    [-v] [-V] [-w] <sg_device> [<sg_device2>]\n"
           " where:\n"
           "      -c      timestamp when sg driver created <sg_device>\n"
           "      -f      fork and test share between processes\n"
           "      -h      help: print usage message then exit\n"
           "      -l=Q_LEN    queue length, between 1 and 511 (def: 16)\n"
           "      -m=MRQS[,I|S]    test multi-req, MRQS number to do; if "
           "the letter\n"
           "                     'I' is appended after a comma, then do "
           "IMMED mrq;\n"
           "                     'i' IMMED on submission, non-IMMED on "
           "receive;\n"
           "                     'S' is appended, then use "
           "ioctl(SG_IOSUBMIT)\n"
           "      -M      set 'more async' flag\n"
           "      -n      do not calculate per command duration (def: do)\n"
           "      -o      ioctls only, then exit\n"
           "      -r=SZ     reserve buffer size in KB (def: 256 --> 256 "
           "KB)\n"
           "      -s=SEC    sleep between writes and reads (def: 0)\n"
           "      -S        size of interface structures plus ioctl "
           "values\n"
           "      -t    queue_at_tail (def: q_at_head)\n"
           "      -T=NUM    time overhead of NUM invocations of\n"
           "                ioctl(SG_GET_NUM_WAITING); then exit\n"
           "      -v    increase verbosity of output\n"
           "      -V    print version string then exit\n"
           "      -w    write (submit) only then exit\n");
}

static void
timespec_add(const struct timespec *lhs_p, const struct timespec *rhs_p,
              struct timespec *res_p)
{
    if ((lhs_p->tv_nsec + rhs_p->tv_nsec) > 1000000000L) {
        res_p->tv_sec = lhs_p->tv_sec + rhs_p->tv_sec + 1;
        res_p->tv_nsec = lhs_p->tv_nsec + rhs_p->tv_nsec - 1000000000L;
    } else {
        res_p->tv_sec = lhs_p->tv_sec + rhs_p->tv_sec;
        res_p->tv_nsec = lhs_p->tv_nsec + rhs_p->tv_nsec;
    }
}

static void
timespec_diff(const struct timespec *lhs_p, const struct timespec *rhs_p,
              struct timespec *res_p)
{
    if ((lhs_p->tv_nsec - rhs_p->tv_nsec) < 0) {
        res_p->tv_sec = lhs_p->tv_sec - rhs_p->tv_sec - 1;
        res_p->tv_nsec = lhs_p->tv_nsec - rhs_p->tv_nsec + 1000000000L;
    } else {
        res_p->tv_sec = lhs_p->tv_sec - rhs_p->tv_sec;
        res_p->tv_nsec = lhs_p->tv_nsec - rhs_p->tv_nsec;
    }
}

/* Returns 0 on success. */
int timespec2str(char *buf, uint len, struct timespec *ts)
{
    int ret;
    struct tm t;

    tzset();
    if (localtime_r(&(ts->tv_sec), &t) == NULL)
        return 1;

    ret = strftime(buf, len, "%F %T", &t);
    if (ret == 0)
        return 2;
    len -= ret - 1;

    ret = snprintf(&buf[strlen(buf)], len, ".%09ld", ts->tv_nsec);
    if (ret >= (int)len)
        return 3;
    return 0;
}

/* This function taken from Keith Parkard's blog dated 20121005 */
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

static void
set_more_async(int fd, bool more_asy, bool no_dur)
{
    if (sg_drv_ver_num > 40030) {
        struct sg_extended_info sei;
        struct sg_extended_info * seip;

        seip = &sei;
        memset(seip, 0, sizeof(*seip));
        seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
        seip->sei_rd_mask |= SG_SEIM_CTL_FLAGS;
        if (more_asy) {
           seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_MORE_ASYNC;
           seip->ctl_flags = SG_CTL_FLAGM_MORE_ASYNC;
        }
        if (no_dur) {
            seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_NO_DURATION;
            seip->ctl_flags = SG_CTL_FLAGM_NO_DURATION;
        }
        if (ioctl(fd, SG_SET_GET_EXTENDED, seip) < 0) {
            pr2serr("ioctl(SG_SET_GET_EXTENDED, MORE_ASYNC(|NO_DUR)) failed, "
                    "errno=%d %s\n", errno, strerror(errno));
            return;
        }
    } else
        pr2serr("sg driver too old for ioctl(SG_SET_GET_EXTENDED)\n");
}

static void
pr_create_dev_time(int sg_fd, const char * dev_name)
{
    uint32_t u;
    uint64_t l;
    struct sg_extended_info sei;
    struct sg_extended_info * seip;
    struct timespec time_up, realtime, boottime, createtime, tmp;
    char b[64];

    seip = &sei;
        memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_DEV_TS_LOWER;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("%s: ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n",
                __func__, errno, strerror(errno));
        return;
    }
    u = seip->read_value;
    seip->read_value = SG_SEIRV_DEV_TS_UPPER;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("%s: ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n",
                __func__, errno, strerror(errno));
        return;
    }
    l = seip->read_value;
    l <<= 32;
    l |= u;
    time_up.tv_sec = l / 1000000000UL;
    time_up.tv_nsec = l % 1000000000UL;
    /* printf("create time nanoseconds=%" PRIu64 "\n", l); */
    if (clock_gettime(CLOCK_REALTIME, &realtime) < 0) {
        pr2serr("%s: clock_gettime(CLOCK_REALTIME) failed, errno=%d %s\n",
                __func__, errno, strerror(errno));
        return;
    }
    if (clock_gettime(CLOCK_BOOTTIME, &boottime) < 0) {
        pr2serr("%s: clock_gettime(CLOCK_REALTIME) failed, errno=%d %s\n",
                __func__, errno, strerror(errno));
        return;
    }
    timespec_diff(&realtime, &boottime, &tmp);
    timespec_add(&tmp, &time_up, &createtime);
#if 0
    printf("real time: %ld,%ld\n", realtime.tv_sec, realtime.tv_nsec);
    printf("boot time: %ld,%ld\n", boottime.tv_sec, boottime.tv_nsec);
    printf("time up: %ld,%ld\n", time_up.tv_sec, time_up.tv_nsec);
    printf("create time: %ld,%ld\n", createtime.tv_sec, createtime.tv_nsec);
#endif
    timespec2str(b, sizeof(b), &createtime);
    printf("Create time of %s was %s\n", dev_name, b);
}

static int
tst_extended_ioctl(const char * fnp, int sg_fd, const char * fn2p, int sg_fd2,
                   int sock, const char * cp)
{
    uint32_t cflags;
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

    seip = &sei;
    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_RESERVED_SIZE;
    seip->reserved_sz = reserve_buff_sz;
    seip->sgat_elem_sz = 64 * 1024;
    seip->sei_rd_mask |= SG_SEIM_RESERVED_SIZE;
    seip->sei_rd_mask |= SG_SEIM_TOT_FD_THRESH;
    seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
    seip->sei_rd_mask |= SG_SEIM_CTL_FLAGS; /* this or previous optional */
    seip->sei_rd_mask |= SG_SEIM_MINOR_INDEX;
    seip->sei_wr_mask |= SG_SEIM_SGAT_ELEM_SZ;
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
    seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_NO_DURATION;
    seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_NO_DURATION;
    seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;
    seip->ctl_flags |= SG_CTL_FLAGM_NO_DURATION;

    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
#if 1
    printf("%sSG_SET_GET_EXTENDED ioctl ok\n", cp);
    if (SG_SEIM_RESERVED_SIZE & seip->sei_rd_mask)
        printf("  %sreserved size: %u\n", cp, seip->reserved_sz);
    if (SG_SEIM_MINOR_INDEX & seip->sei_rd_mask)
        printf("  %sminor index: %u\n", cp, seip->minor_index);
    if (SG_SEIM_TOT_FD_THRESH & seip->sei_rd_mask)
        printf("  %stot_fd_thresh: %u\n", cp, seip->tot_fd_thresh);
    if ((SG_SEIM_CTL_FLAGS & seip->sei_rd_mask) ||
         (SG_SEIM_CTL_FLAGS & seip->sei_wr_mask)) {
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
        if (SG_CTL_FLAGM_NO_DURATION & seip->ctl_flags_rd_mask)
            printf("  %sNO_DURATION: %s\n", cp,
                   (SG_CTL_FLAGM_NO_DURATION & cflags) ? "true" : "false");
    }
    if (SG_SEIM_MINOR_INDEX & seip->sei_rd_mask)
        printf("  %sminor_index: %u\n", cp, seip->minor_index);
    printf("\n");
#endif

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_INT_MASK;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_INT_MASK]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_BOOL_MASK;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_BOOL_MASK]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_VERS_NUM;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_VERS_NUM]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_INACT_RQS;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_INACT_RQS]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_DEV_INACT_RQS;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_DEV_INACT_RQS]= %u\n", cp,
           seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_SUBMITTED;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_SUBMITTED]= %u\n", cp, seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_DEV_SUBMITTED;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr("ioctl(SG_SET_GET_EXTENDED) failed, errno=%d %s\n", errno,
                strerror(errno));
        return 1;
    }
    printf("  %sread_value[SG_SEIRV_DEV_SUBMITTED]= %u\n", cp,
           seip->read_value);

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_SHARE_FD;
    seip->sei_rd_mask |= SG_SEIM_SHARE_FD;
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
    printf("  %sshare successful, read back previous shared_fd= %d\n", cp,
           (int)seip->share_fd);
bypass_share:

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

static int
do_mrqs(int sg_fd, int sg_fd2, int mrqs)
{
    bool both = (sg_fd2 >= 0);
    int k, j, arr_v4_sz, good;
    int res = 0;
    struct sg_io_v4 * arr_v4;
    struct sg_io_v4 * h4p;
    struct sg_io_v4 * mrq_h4p;
    struct sg_io_v4 mrq_h4;
    uint8_t sense_buffer[SENSE_BUFFER_LEN];
    uint8_t inq_cdb[INQ_CMD_LEN] =      /* Device Id VPD page */
                                {0x12, 0x1, 0x83, 0, INQ_REPLY_LEN, 0};
    uint8_t sdiag_cdb[SDIAG_CMD_LEN] =
                                {0x1d, 0x10 /* PF */, 0, 0, 0, 0};
    uint8_t inqBuff[INQ_REPLY_LEN];

    if (both) {
        struct sg_extended_info sei;
        struct sg_extended_info * seip;

        seip = &sei;
        memset(seip, 0, sizeof(*seip));
        seip->sei_wr_mask |= SG_SEIM_SHARE_FD;
        seip->sei_rd_mask |= SG_SEIM_SHARE_FD;
        seip->share_fd = sg_fd;         /* master */
        if (ioctl(sg_fd2, SG_SET_GET_EXTENDED, seip) < 0) {
            res = errno;
            pr2serr("ioctl(sg_fd2, SG_SET_GET_EXTENDED) shared_fd, "
                    "failed errno=%d %s\n", res, strerror(res));
            return res;
        }
    }
    memset(inqBuff, 0, sizeof(inqBuff));
    mrq_h4p = &mrq_h4;
    memset(mrq_h4p, 0, sizeof(*mrq_h4p));
    mrq_h4p->guard = 'Q';
    mrq_h4p->flags = SGV4_FLAG_MULTIPLE_REQS;
    if (mrq_immed)
        mrq_h4p->flags |= SGV4_FLAG_IMMED;
    arr_v4 = calloc(mrqs, sizeof(struct sg_io_v4));
    if (NULL == arr_v4) {
        res = ENOMEM;
        goto fini;
    }
    arr_v4_sz = mrqs * sizeof(struct sg_io_v4);

    for (k = 0; k < mrqs; ++k) {
        h4p = arr_v4 + k;

        h4p->guard = 'Q';
        /* ->protocol and ->subprotocol are already zero */
        /* io_hdr[k].iovec_count = 0; */  /* memset takes care of this */
        if (0 == (k % 2)) {
            h4p->request_len = sizeof(sdiag_cdb);
            h4p->request = (uint64_t)(uintptr_t)sdiag_cdb;
            /* all din and dout fields are zero */
        } else {
            h4p->request_len = sizeof(inq_cdb);
            h4p->request = (uint64_t)(uintptr_t)inq_cdb;
            h4p->din_xfer_len = INQ_REPLY_LEN;
            h4p->din_xferp = (uint64_t)(uintptr_t)inqBuff;
            if (both)
                h4p->flags |= SGV4_FLAG_DO_ON_OTHER;
        }
        h4p->response = (uint64_t)(uintptr_t)sense_buffer;
        h4p->max_response_len = sizeof(sense_buffer);
        h4p->timeout = 20000;     /* 20000 millisecs == 20 seconds */
        h4p->request_extra = k + 3;      /* so pack_id doesn't start at 0 */
        /* default is to queue at head (in SCSI mid level) */
        if (q_at_tail)
            h4p->flags |= SG_FLAG_Q_AT_TAIL;
        else
            h4p->flags |= SG_FLAG_Q_AT_HEAD;
    }
    mrq_h4p->dout_xferp = (uint64_t)(uintptr_t)arr_v4;
    mrq_h4p->dout_xfer_len = arr_v4_sz;
    mrq_h4p->din_xferp = mrq_h4p->dout_xferp;
    mrq_h4p->din_xfer_len = mrq_h4p->dout_xfer_len;
    if (ioctl(sg_fd, (mrq_iosubmit ? SG_IOSUBMIT : SG_IO), mrq_h4p) < 0) {
        res = errno;
        pr2serr("ioctl(SG_IO%s, mrq) failed, errno=%d %s\n",
                (mrq_iosubmit ? "SUBMIT" : ""), res, strerror(res));
        goto fini;
    }
    if ((mrq_h4p->dout_resid > 0) || ((int)mrq_h4p->info < mrqs))
        pr2serr("ioctl(SG_IO%s, mrq) dout_resid=%d, info=%d\n\n",
                (mrq_iosubmit ? "SUBMIT" : ""), mrq_h4p->dout_resid,
                mrq_h4p->info);

    good = 0;
    j = 0;
    if (mrq_immed) {
receive_more:
        if (mrq_half_immed)
            mrq_h4p->flags = SGV4_FLAG_MULTIPLE_REQS; // zap SGV4_FLAG_IMMED
        if (ioctl(sg_fd, SG_IORECEIVE, mrq_h4p) < 0) {
            res = errno;
            pr2serr("ioctl(SG_IORECEIVE, mrq) failed, errno=%d %s\n",
                    res, strerror(res));
            goto fini;
        }
        if ((mrq_h4p->din_resid > 0) || ((int)mrq_h4p->info < mrqs))
            pr2serr("ioctl(SG_IORECEIVE, mrq) din_resid=%d, info=%d\n",
                    mrq_h4p->din_resid, mrq_h4p->info);
    }

    for (k = 0; k < (int)mrq_h4p->info; ++k, ++j) {
        h4p = arr_v4 + k;
        if (! (h4p->driver_status || h4p->transport_status ||
               h4p->device_status)) {
            if (h4p->info & SG_INFO_MRQ_FINI)
                ++good;
        }
        if ((! (h4p->info & SG_INFO_MRQ_FINI)) && (verbose > 1))
            pr2serr("%s: k=%d: SG_INFO_MRQ_FINI not set on response\n",
                    __func__, k);
    }
    if (mrq_immed && (j < mrqs))
        goto receive_more;

    if (good > 0) {
        printf("Final INQUIRY response:\n");
        hex2stdout(inqBuff, INQ_REPLY_LEN, 0);
    }
    printf("Good responses: %d, bad responses: %d\n", good, mrqs - good);
    if (mrq_h4p->driver_status != 0)
        printf("Master mrq object: driver_status=%d\n",
               mrq_h4p->driver_status);
    h4p = arr_v4 + mrqs - 1;
    if (h4p->driver_status != 0)
        printf("Last mrq object: driver_status=%d\n", h4p->driver_status);

fini:
    if (arr_v4)
        free(arr_v4);
    return res;
}


int
main(int argc, char * argv[])
{
    bool done;
    bool nw_given = false;
    int sg_fd, k, ok, pack_id, num_waiting;
    int res = 0;
    int sg_fd2 = -1;
    int sock = -1;
    uint8_t inq_cdb[INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    uint8_t sdiag_cdb[SDIAG_CMD_LEN] =
                                {0x1d, 0x10 /* PF */, 0, 0, 0, 0};
    uint8_t inqBuff[MAX_Q_LEN][INQ_REPLY_LEN];
    sg_io_hdr_t io_hdr[MAX_Q_LEN];
    sg_io_hdr_t rio_hdr;
    char ebuff[EBUFF_SZ];
    uint8_t sense_buffer[MAX_Q_LEN][SENSE_BUFFER_LEN];
    const char * second_fname = NULL;
    const char * cp;
    struct sg_scsi_id ssi;


    if (sizeof(struct sg_extended_info) != 96)
        pr2serr("Warning <<<< sizeof(struct sg_extended_info)=%zu not 96\n",
                sizeof(struct sg_extended_info));
    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-3", argv[k], 2))
            do_v3_only = true;
        else if (0 == memcmp("-c", argv[k], 2))
            create_time = true;
        else if (0 == memcmp("-f", argv[k], 2))
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
        } else if (0 == memcmp("-m=", argv[k], 3)) {
            num_mrqs = sg_get_num(argv[k] + 3);
            if (num_mrqs < 1) {
                printf("Expect -m= to take a number greater than 0\n");
                file_name = 0;
                break;
            }
            if ((cp = strchr(argv[k] + 3, ','))) {
                mrq_iosubmit = true;
                if (cp[1] == 'I')
                    mrq_immed = true;
                else if (cp[1] == 'i') {
                    mrq_immed = true;
                    mrq_half_immed = true;
                } else if (toupper(cp[1]) == 'S')
                    ;
                else {
                    printf("-m= option expects 'A' or 'a' as a suffix, "
                           "after comma\n");
                    file_name = 0;
                    break;
                }
            }
        } else if (0 == memcmp("-M", argv[k], 2))
            more_async = true;
        else if (0 == memcmp("-n", argv[k], 2))
            no_duration = true;
        else if (0 == memcmp("-o", argv[k], 2))
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
        } else if (0 == memcmp("-S", argv[k], 2))
            show_size_value = true;
        else if (0 == memcmp("-t", argv[k], 2))
            q_at_tail = true;
        else if (0 == memcmp("-T=", argv[k], 3)) {
            num_sgnw = sg_get_num(argv[k] + 3);
            if (num_sgnw < 0) {
                printf("Expect -T= to take a number >= 0\n");
                file_name = 0;
                break;
            }
            nw_given = true;
        } else if (0 == memcmp("-vvvvvvv", argv[k], 8))
            verbose += 7;
        else if (0 == memcmp("-vvvvvv", argv[k], 7))
            verbose += 6;
        else if (0 == memcmp("-vvvvv", argv[k], 6))
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
    if (show_size_value) {
        struct utsname unam;

        printf("Size in bytes:\n");
        printf("\t%zu\tsizeof(struct sg_header) Version 2 interface "
               "structure\n", sizeof(struct sg_header));
        printf("\t%zu\tsizeof(struct sg_io_hdr) Version 3 interface "
               "structure\n", sizeof(struct sg_io_hdr));
        printf("\t%zu\tsizeof(struct sg_io_v4) Version 4 interface "
               "structure\n", sizeof(struct sg_io_v4));
        printf("\t%zu\tsizeof(struct sg_iovec) scatter gather element\n",
               sizeof(struct sg_iovec));
        printf("\t%zu\tsizeof(struct sg_scsi_id) topological device id\n",
               sizeof(struct sg_scsi_id));
        printf("\t%zu\tsizeof(struct sg_req_info) request information\n",
               sizeof(struct sg_req_info));
        printf("\t%zu\tsizeof(struct sg_extended_info) for "
               "SG_SET_GET_EXTENDED\n",
               sizeof(struct sg_extended_info));
        printf("\nioctl values (i.e. second argument to ioctl()):\n");
        printf("\t0x%lx\t\tvalue of SG_GET_NUM_WAITING ioctl\n",
               (unsigned long)SG_GET_NUM_WAITING);
        printf("\t0x%lx\t\tvalue of SG_IO ioctl\n",
               (unsigned long)SG_IO);
        printf("\t0x%lx\tvalue of SG_IOABORT ioctl\n",
               (unsigned long)SG_IOABORT);
        printf("\t0x%lx\tvalue of SG_IORECEIVE ioctl\n",
               (unsigned long)SG_IORECEIVE);
        printf("\t0x%lx\tvalue of SG_IORECEIVE_V3 ioctl\n",
               (unsigned long)SG_IORECEIVE_V3);
        printf("\t0x%lx\tvalue of SG_IOSUBMIT ioctl\n",
               (unsigned long)SG_IOSUBMIT);
        printf("\t0x%lx\tvalue of SG_IOSUBMIT_V3 ioctl\n",
               (unsigned long)SG_IOSUBMIT_V3);
        printf("\t0x%lx\tvalue of SG_SET_GET_EXTENDED ioctl\n",
               (unsigned long)SG_SET_GET_EXTENDED);
        printf("\n\t0x%x\t\tbase value of most SG_* ioctls\n",
               SG_IOCTL_MAGIC_NUM);
        printf("\nsizeof(void *) [a pointer] on this machine: %u bytes\n",
               (unsigned)sizeof(void *));
        if (0 == uname(&unam))
            printf("Machine name: %s\n", unam.machine);

        return 0;
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

    if (ioctl(sg_fd, SG_GET_VERSION_NUM, &sg_drv_ver_num) < 0) {
        pr2serr("ioctl(SG_GET_VERSION_NUM) failed, errno=%d %s\n", errno,
                strerror(errno));
        goto out;
    }
    printf("Linux sg driver version: %d\n", sg_drv_ver_num);

    if (create_time && (sg_drv_ver_num > 40030)) {
        pr_create_dev_time(sg_fd, file_name);
        goto out;
    }

    if (nw_given) {             /* time ioctl(SG_GET_NUM_WAITING) */
        int nw, sum_nw;
        struct timespec start_tm, fin_tm, res_tm;

        printf("Timing %d calls to ioctl(SG_GET_NUM_WAITING)\n", num_sgnw);
        if (0 != clock_gettime(CLOCK_MONOTONIC, &start_tm)) {
                res = errno;
                perror("start clock_gettime() failed:");
                goto out;
        }
        for (k = 0, sum_nw = 0; k < num_sgnw; ++k, sum_nw += nw) {
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &nw) < 0) {
                res = errno;
                fprintf(stderr, "%d: ioctl(SG_GET_NUM_WAITING) failed "
                        "errno=%d\n", k, res);
                goto out;
            }
        }
        if (0 != clock_gettime(CLOCK_MONOTONIC, &fin_tm)) {
            res = errno;
            perror("finish clock_gettime() failed:");
            goto out;
        }
        res_tm.tv_sec = fin_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_nsec = fin_tm.tv_nsec - start_tm.tv_nsec;
        if (res_tm.tv_nsec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_nsec += 1000000000;
        }
        if (verbose) {
            if (verbose > 1)
                printf("sum of num_waiting_s=%d\n", sum_nw);
            printf("elapsed time (nanosecond precision): %d.%09d secs\n",
                   (int)res_tm.tv_sec, (int)res_tm.tv_nsec);
        } else
            printf("elapsed time: %d.%06d secs\n", (int)res_tm.tv_sec,
                   (int)(res_tm.tv_nsec / 1000));
        if (num_sgnw >= 100) {
            double m = (double)res_tm.tv_sec +
                       ((double)res_tm.tv_nsec / 1000000000.0);

            if (m > 0.000001)
                printf("Calls per second: %.2f\n", (double)num_sgnw / m);
        }

        res = 0;
        goto out;
    }
    if ((more_async || no_duration) && !do_v3_only)
        set_more_async(sg_fd, more_async, no_duration);

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
        if (more_async && !do_v3_only)
            set_more_async(sg_fd2, more_async, no_duration);
    }

    if ((num_mrqs > 0) && !do_v3_only) {
        res = do_mrqs(sg_fd, sg_fd2, num_mrqs);
        goto out;
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
    if (! do_v3_only) {
        if (tst_extended_ioctl(file_name, sg_fd, second_fname, sg_fd2, sock,
                               cp))
            goto out;
    }
    if (ioctl_only)
        goto out;

    if (do_fork && !is_parent)
        return 0;

    printf("start write() calls [submits]\n");
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
        printf("  SCSI 8 byte LUN: ");
        hex2stdout(ssi.scsi_lun, 8, -1);
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

    printf("\nstart read() calls [io receive]\n");
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
    return res;
}
