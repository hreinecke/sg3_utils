/* A utility program for copying files. Specialised for "files" that
 * represent devices that understand the SCSI command set.
 *
 * Copyright (C) 1999 - 2020 D. Gilbert and P. Allworth
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is a specialisation of the Unix "dd" command in which
 * one or both of the given files is a scsi generic device or a raw
 * device. A logical block size ('bs') is assumed to be 512 if not given.
 * This program complains if 'ibs' or 'obs' are given with some other value
 * than 'bs'. If 'if' is not given or 'if=-' then stdin is assumed. If
 * 'of' is not given or 'of=-' then stdout assumed.
 *
 * A non-standard argument "bpt" (blocks per transfer) is added to control
 * the maximum number of blocks in each transfer. The default value is 128.
 * For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16 KiB
 * in this case) are transferred to or from the sg device in a single SCSI
 * command.
 *
 * This version is designed for the linux kernel 2.4, 2.6, 3 and 4 series.
 *
 * sgp_dd is a Posix threads specialization of the sg_dd utility. Both
 * sgp_dd and sg_dd only perform special tasks when one or both of the given
 * devices belong to the Linux sg driver
 */

#define _XOPEN_SOURCE 600
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#ifndef major
#include <sys/types.h>
#endif
#include <sys/time.h>
#include <linux/major.h>        /* for MEM_MAJOR, SCSI_GENERIC_MAJOR, etc */
#include <linux/fs.h>           /* for BLKSSZGET and friends */

#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 201112L
#ifndef __STDC_NO_ATOMICS__

#define HAVE_C11_ATOMICS
#include <stdatomic.h>

#endif
#endif
#endif

#ifndef HAVE_C11_ATOMICS
#warning "Don't have C11 Atomics, using mutex with pack_id"
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"


static const char * version_str = "5.75 20200219";

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_BLOCKS_PER_2048TRANSFER 32
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16


#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define SGP_READ10 0x28
#define SGP_WRITE10 0x2a
#define DEF_NUM_THREADS 4
#define MAX_NUM_THREADS 1024  /* was SG_MAX_QUEUE (16) but no longer applies */

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikely value */
#endif

#define FT_OTHER 1              /* filetype other than one of the following */
#define FT_SG 2                 /* filetype is sg char device */
#define FT_RAW 4                /* filetype is raw char device */
#define FT_DEV_NULL 8           /* either "/dev/null" or "." as filename */
#define FT_ST 16                /* filetype is st char device (tape) */
#define FT_BLOCK 32             /* filetype is a block device */
#define FT_ERROR 64             /* couldn't "stat" file */

#define DEV_NULL_MINOR_NUM 3

#define EBUFF_SZ 768

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif

#define STR_SZ 1024
#define INOUTF_SZ 512


struct flags_t {
    bool append;
    bool coe;
    bool dio;
    bool direct;
    bool dpo;
    bool dsync;
    bool excl;
    bool fua;
    bool mmap;
};

typedef struct request_collection
{       /* one instance visible to all threads */
    int infd;
    int64_t skip;
    int in_type;
    int cdbsz_in;
    struct flags_t in_flags;
    int64_t in_blk;                 /* -\ next block address to read */
    int64_t in_count;               /*  | blocks remaining for next read */
    int64_t in_rem_count;           /*  | count of remaining in blocks */
    int in_partial;                   /*  | */
    bool in_stop;                     /*  | */
    pthread_mutex_t in_mutex;         /* -/ */
    int outfd;
    int64_t seek;
    int out_type;
    int cdbsz_out;
    struct flags_t out_flags;
    int64_t out_blk;                /* -\ next block address to write */
    int64_t out_count;              /*  | blocks remaining for next write */
    int64_t out_rem_count;          /*  | count of remaining out blocks */
    int out_partial;                  /*  | */
    bool out_stop;                    /*  | */
    pthread_mutex_t out_mutex;        /*  | */
    pthread_cond_t out_sync_cv;       /* -/ hold writes until "in order" */
    int bs;
    int bpt;
    int num_threads;
    int dio_incomplete_count;   /* -\ */
    int sum_of_resids;          /*  | */
    pthread_mutex_t aux_mutex;  /* -/ (also serializes some printf()s */
    bool mmap_active;
    int debug;
    int dry_run;
} Rq_coll;

typedef struct thread_arg
{       /* pointer to this argument passed to thread */
    int id;
    Rq_coll * clp;
} Thread_arg;

typedef struct request_element
{       /* one instance per worker thread */
    bool wr;
    int infd;
    int outfd;
    int64_t blk;
    int num_blks;
    uint8_t * buffp;
    uint8_t * alloc_bp;
    struct sg_io_hdr io_hdr;
    uint8_t cmd[MAX_SCSI_CDBSZ];
    uint8_t sb[SENSE_BUFF_LEN];
    int bs;
    int dio_incomplete_count;
    int resid;
    int cdbsz_in;
    int cdbsz_out;
    struct flags_t in_flags;
    struct flags_t out_flags;
    int debug;
    uint32_t pack_id;
} Rq_elem;

static sigset_t signal_set;
static pthread_t sig_listen_thread_id;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

static void sg_in_operation(Rq_coll * clp, Rq_elem * rep);
static void sg_out_operation(Rq_coll * clp, Rq_elem * rep);
static bool normal_in_operation(Rq_coll * clp, Rq_elem * rep, int blocks);
static void normal_out_operation(Rq_coll * clp, Rq_elem * rep, int blocks);
static int sg_start_io(Rq_elem * rep);
static int sg_finish_io(bool wr, Rq_elem * rep, pthread_mutex_t * a_mutp);

#ifdef HAVE_C11_ATOMICS

/* Assume initialized to 0, but want to start at 1, hence adding 1 in macro */
static atomic_uint ascending_val;

#define GET_NEXT_PACK_ID(_v) (atomic_fetch_add(&ascending_val, _v) + (_v))

#else

static pthread_mutex_t av_mut = PTHREAD_MUTEX_INITIALIZER;
static int ascending_val = 1;

#define GET_NEXT_PACK_ID(_v)                            \
    ( { int _r;                                         \
    do {                                                \
        pthread_mutex_lock(&av_mut);                    \
        _r = ascending_val;                             \
        ascending_val += _v;                            \
        pthread_mutex_lock(&av_mut);                    \
    } while (0) ; _r; } )

#endif

#define STRERR_BUFF_LEN 128

static pthread_mutex_t strerr_mut = PTHREAD_MUTEX_INITIALIZER;

static pthread_t threads[MAX_NUM_THREADS];
static Thread_arg thr_arg_a[MAX_NUM_THREADS];

static bool shutting_down = false;
static bool do_sync = false;
static bool do_time = false;
static Rq_coll rcoll;
static struct timeval start_tm;
static int64_t dd_count = -1;
static int exit_status = 0;
static char infn[INOUTF_SZ];
static char outfn[INOUTF_SZ];

static const char * my_name = "sgp_dd: ";


static void
calc_duration_throughput(int contin)
{
    struct timeval end_tm, res_tm;
    double a, b;

    gettimeofday(&end_tm, NULL);
    res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
    res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
    if (res_tm.tv_usec < 0) {
        --res_tm.tv_sec;
        res_tm.tv_usec += 1000000;
    }
    a = res_tm.tv_sec;
    a += (0.000001 * res_tm.tv_usec);
    b = (double)rcoll.bs * (dd_count - rcoll.out_rem_count);
    pr2serr("time to transfer data %s %d.%06d secs",
            (contin ? "so far" : "was"), (int)res_tm.tv_sec,
            (int)res_tm.tv_usec);
    if ((a > 0.00001) && (b > 511))
        pr2serr(", %.2f MB/sec\n", b / (a * 1000000.0));
    else
        pr2serr("\n");
}

static void
print_stats(const char * str)
{
    int64_t infull, outfull;

    if (0 != rcoll.out_rem_count)
        pr2serr("  remaining block count=%" PRId64 "\n",
                rcoll.out_rem_count);
    infull = dd_count - rcoll.in_rem_count;
    pr2serr("%s%" PRId64 "+%d records in\n", str,
            infull - rcoll.in_partial, rcoll.in_partial);

    outfull = dd_count - rcoll.out_rem_count;
    pr2serr("%s%" PRId64 "+%d records out\n", str,
            outfull - rcoll.out_partial, rcoll.out_partial);
}

static void
interrupt_handler(int sig)
{
    struct sigaction sigact;

    sigact.sa_handler = SIG_DFL;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(sig, &sigact, NULL);
    pr2serr("Interrupted by signal,");
    if (do_time)
        calc_duration_throughput(0);
    print_stats("");
    kill(getpid (), sig);
}

static void
siginfo_handler(int sig)
{
    if (sig) { ; }      /* unused, dummy to suppress warning */
    pr2serr("Progress report, continuing ...\n");
    if (do_time)
        calc_duration_throughput(1);
    print_stats("  ");
}

static void
install_handler(int sig_num, void (*sig_handler) (int sig))
{
    struct sigaction sigact;
    sigaction (sig_num, NULL, &sigact);
    if (sigact.sa_handler != SIG_IGN)
    {
        sigact.sa_handler = sig_handler;
        sigemptyset (&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction (sig_num, &sigact, NULL);
    }
}

#ifdef SG_LIB_ANDROID
static void
thread_exit_handler(int sig)
{
    pthread_exit(0);
}
#endif

/* Make safe_strerror() thread safe */
static char *
tsafe_strerror(int code, char * ebp)
{
    char * cp;

    pthread_mutex_lock(&strerr_mut);
    cp = safe_strerror(code);
    strncpy(ebp, cp, STRERR_BUFF_LEN);
    pthread_mutex_unlock(&strerr_mut);

    ebp[STRERR_BUFF_LEN - 1] = '\0';
    return ebp;
}


/* Following macro from D.R. Butenhof's POSIX threads book:
 * ISBN 0-201-63392-2 . [Highly recommended book.] Changed __FILE__
 * to __func__ */
#define err_exit(code,text) do { \
    char strerr_buff[STRERR_BUFF_LEN]; \
    pr2serr("%s at \"%s\":%d: %s\n", \
        text, __func__, __LINE__, tsafe_strerror(code, strerr_buff)); \
    exit(1); \
    } while (0)


static int
dd_filetype(const char * filename)
{
    struct stat st;
    size_t len = strlen(filename);

    if ((1 == len) && ('.' == filename[0]))
        return FT_DEV_NULL;
    if (stat(filename, &st) < 0)
        return FT_ERROR;
    if (S_ISCHR(st.st_mode)) {
        if ((MEM_MAJOR == major(st.st_rdev)) &&
            (DEV_NULL_MINOR_NUM == minor(st.st_rdev)))
            return FT_DEV_NULL;
        if (RAW_MAJOR == major(st.st_rdev))
            return FT_RAW;
        if (SCSI_GENERIC_MAJOR == major(st.st_rdev))
            return FT_SG;
        if (SCSI_TAPE_MAJOR == major(st.st_rdev))
            return FT_ST;
    } else if (S_ISBLK(st.st_mode))
        return FT_BLOCK;
    return FT_OTHER;
}

static void
usage()
{
    pr2serr("Usage: sgp_dd  [bs=BS] [count=COUNT] [ibs=BS] [if=IFILE]"
            " [iflag=FLAGS]\n"
            "               [obs=BS] [of=OFILE] [oflag=FLAGS] "
            "[seek=SEEK] [skip=SKIP]\n"
            "               [--help] [--version]\n\n");
    pr2serr("               [bpt=BPT] [cdbsz=6|10|12|16] [coe=0|1] "
            "[deb=VERB] [dio=0|1]\n"
            "               [fua=0|1|2|3] [sync=0|1] [thr=THR] "
            "[time=0|1] [verbose=VERB]\n"
            "               [--dry-run] [--verbose]\n"
            "  where:\n"
            "    bpt         is blocks_per_transfer (default is 128)\n"
            "    bs          must be device logical block size (default "
            "512)\n"
            "    cdbsz       size of SCSI READ or WRITE cdb (default is 10)\n"
            "    coe         continue on error, 0->exit (def), "
            "1->zero + continue\n"
            "    count       number of blocks to copy (def: device size)\n"
            "    deb         for debug, 0->none (def), > 0->varying degrees "
            "of debug\n");
    pr2serr("    dio         is direct IO, 1->attempt, 0->indirect IO (def)\n"
            "    fua         force unit access: 0->don't(def), 1->OFILE, "
            "2->IFILE,\n"
            "                3->OFILE+IFILE\n"
            "    if          file or device to read from (def: stdin)\n"
            "    iflag       comma separated list from: [coe,dio,direct,dpo,"
            "dsync,excl,\n"
            "                fua,mmap,null]\n"
            "    of          file or device to write to (def: stdout), "
            "OFILE of '.'\n"
            "                treated as /dev/null\n"
            "    oflag       comma separated list from: [append,coe,dio,"
            "direct,dpo,\n"
            "                dsync,excl,fua,mmap,null]\n"
            "    seek        block position to start writing to OFILE\n"
            "    skip        block position to start reading from IFILE\n"
            "    sync        0->no sync(def), 1->SYNCHRONIZE CACHE on OFILE "
            "after copy\n"
            "    thr         is number of threads, must be > 0, default 4, "
            "max 1024\n"
            "    time        0->no timing(def), 1->time plus calculate "
            "throughput\n"
            "    verbose     same as 'deb=VERB': increase verbosity\n"
            "    --dry-run|-d    prepare but bypass copy/read\n"
            "    --help|-h      output this usage message then exit\n"
            "    --verbose|-v   increase verbosity of utility\n"
            "    --version|-V   output version string then exit\n"
            "Copy from IFILE to OFILE, similar to dd command\n"
            "specialized for SCSI devices, uses multiple POSIX threads\n");
}

static void
guarded_stop_in(Rq_coll * clp)
{
    pthread_mutex_lock(&clp->in_mutex);
    clp->in_stop = true;
    pthread_mutex_unlock(&clp->in_mutex);
}

static void
guarded_stop_out(Rq_coll * clp)
{
    pthread_mutex_lock(&clp->out_mutex);
    clp->out_stop = true;
    pthread_mutex_unlock(&clp->out_mutex);
}

static void
guarded_stop_both(Rq_coll * clp)
{
    guarded_stop_in(clp);
    guarded_stop_out(clp);
}

static int
sgp_mem_mmap(int fd, int res_sz, uint8_t ** mmpp)
{
    int t;

    if (ioctl(fd, SG_GET_RESERVED_SIZE, &t) < 0) {
        perror("SG_GET_RESERVED_SIZE error");
        return -1;
    }
    if (t < (int)sg_get_page_size())
        t = sg_get_page_size();
    if (res_sz > t) {
        if (ioctl(fd, SG_SET_RESERVED_SIZE, &res_sz) < 0) {
            perror("SG_SET_RESERVED_SIZE error");
            return -1;
        }
    }
    *mmpp = (uint8_t *)mmap(NULL, res_sz,
                            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (MAP_FAILED == *mmpp) {
        perror("mmap() failed");
        return -1;
    }
    return 0;
}

/* Return of 0 -> success, see sg_ll_read_capacity*() otherwise */
static int
scsi_read_capacity(int sg_fd, int64_t * num_sect, int * sect_sz)
{
    int res;
    uint8_t rcBuff[RCAP16_REPLY_LEN];

    res = sg_ll_readcap_10(sg_fd, 0, 0, rcBuff, READ_CAP_REPLY_LEN, false, 0);
    if (0 != res)
        return res;

    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3])) {

        res = sg_ll_readcap_16(sg_fd, 0, 0, rcBuff, RCAP16_REPLY_LEN, false,
                               0);
        if (0 != res)
            return res;
        *num_sect = sg_get_unaligned_be64(rcBuff + 0) + 1;
        *sect_sz = sg_get_unaligned_be32(rcBuff + 8);
    } else {
        /* take care not to sign extend values > 0x7fffffff */
        *num_sect = (int64_t)sg_get_unaligned_be32(rcBuff + 0) + 1;
        *sect_sz = sg_get_unaligned_be32(rcBuff + 4);
    }
    return 0;
}

/* Return of 0 -> success, -1 -> failure. BLKGETSIZE64, BLKGETSIZE and */
/* BLKSSZGET macros problematic (from <linux/fs.h> or <sys/mount.h>). */
static int
read_blkdev_capacity(int sg_fd, int64_t * num_sect, int * sect_sz)
{
#ifdef BLKSSZGET
    if ((ioctl(sg_fd, BLKSSZGET, sect_sz) < 0) && (*sect_sz > 0)) {
        perror("BLKSSZGET ioctl error");
        return -1;
    } else {
 #ifdef BLKGETSIZE64
        uint64_t ull;

        if (ioctl(sg_fd, BLKGETSIZE64, &ull) < 0) {

            perror("BLKGETSIZE64 ioctl error");
            return -1;
        }
        *num_sect = ((int64_t)ull / (int64_t)*sect_sz);
 #else
        unsigned long ul;

        if (ioctl(sg_fd, BLKGETSIZE, &ul) < 0) {
            perror("BLKGETSIZE ioctl error");
            return -1;
        }
        *num_sect = (int64_t)ul;
 #endif
    }
    return 0;
#else
    *num_sect = 0;
    *sect_sz = 0;
    return -1;
#endif
}

static void *
sig_listen_thread(void * v_clp)
{
    Rq_coll * clp = (Rq_coll *)v_clp;
    int sig_number;

    while (1) {
        sigwait(&signal_set, &sig_number);
        if (shutting_down)
            break;
        if (SIGINT == sig_number) {
            pr2serr("%sinterrupted by SIGINT\n", my_name);
            guarded_stop_both(clp);
            pthread_cond_broadcast(&clp->out_sync_cv);
        }
    }
    return NULL;
}

static void
cleanup_in(void * v_clp)
{
    Rq_coll * clp = (Rq_coll *)v_clp;

    pr2serr("thread cancelled while in mutex held\n");
    clp->in_stop = true;
    pthread_mutex_unlock(&clp->in_mutex);
    guarded_stop_out(clp);
    pthread_cond_broadcast(&clp->out_sync_cv);
}

static void
cleanup_out(void * v_clp)
{
    Rq_coll * clp = (Rq_coll *)v_clp;

    pr2serr("thread cancelled while out mutex held\n");
    clp->out_stop = true;
    pthread_mutex_unlock(&clp->out_mutex);
    guarded_stop_in(clp);
    pthread_cond_broadcast(&clp->out_sync_cv);
}

static int
sg_prepare(int fd, int bs, int bpt)
{
    int res, t;

    res = ioctl(fd, SG_GET_VERSION_NUM, &t);
    if ((res < 0) || (t < 30000)) {
        pr2serr("%ssg driver prior to 3.x.y\n", my_name);
        return 1;
    }
    t = bs * bpt;
    res = ioctl(fd, SG_SET_RESERVED_SIZE, &t);
    if (res < 0)
        perror("sgp_dd: SG_SET_RESERVED_SIZE error");
    t = 1;
    res = ioctl(fd, SG_SET_FORCE_PACK_ID, &t);
    if (res < 0)
        perror("sgp_dd: SG_SET_FORCE_PACK_ID error");
    return 0;
}

static int
sg_in_open(const char * fnp, struct flags_t * flagp, int bs, int bpt)
{
    int flags = O_RDWR;
    int fd, err;
    char ebuff[800];

    if (flagp->direct)
        flags |= O_DIRECT;
    if (flagp->excl)
        flags |= O_EXCL;
    if (flagp->dsync)
        flags |= O_SYNC;

    if ((fd = open(fnp, flags)) < 0) {
        err = errno;
        snprintf(ebuff, EBUFF_SZ, "%scould not open %s for sg "
                 "reading", my_name, fnp);
        perror(ebuff);
        return -sg_convert_errno(err);
    }
    if (sg_prepare(fd, bs, bpt))
        return -SG_LIB_FILE_ERROR;
    return fd;
}

static int
sg_out_open(const char * fnp, struct flags_t * flagp, int bs, int bpt)
{
    int flags = O_RDWR;
    int fd, err;
    char ebuff[800];

    if (flagp->direct)
        flags |= O_DIRECT;
    if (flagp->excl)
        flags |= O_EXCL;
    if (flagp->dsync)
        flags |= O_SYNC;

    if ((fd = open(fnp, flags)) < 0) {
        err = errno;
        snprintf(ebuff, EBUFF_SZ, "%scould not open %s for sg "
                 "writing", my_name, fnp);
        perror(ebuff);
        return -sg_convert_errno(err);
    }
    if (sg_prepare(fd, bs, bpt))
        return -SG_LIB_FILE_ERROR;
    return fd;
}

static void *
read_write_thread(void * v_tap)
{
    Thread_arg * tap;
    Rq_coll * clp;
    Rq_elem rel;
    Rq_elem * rep = &rel;
    int sz;
    volatile bool stop_after_write = false;
    int64_t seek_skip;
    int blocks, status, id;

    tap = (Thread_arg *)v_tap;
    id = tap->id;
    clp = tap->clp;
    sz = clp->bpt * clp->bs;
    seek_skip =  clp->seek - clp->skip;
    memset(rep, 0, sizeof(Rq_elem));
    /* Following clp members are constant during lifetime of thread */
    rep->bs = clp->bs;
    if ((clp->num_threads > 1) && clp->mmap_active) {
        /* sg devices need separate file descriptor */
        if (clp->in_flags.mmap && (FT_SG == clp->in_type)) {
            rep->infd = sg_in_open(infn, &clp->in_flags, clp->bs, clp->bpt);
            if (rep->infd < 0) err_exit(-rep->infd, "error opening infn");
        } else
            rep->infd = clp->infd;
        if (clp->out_flags.mmap && (FT_SG == clp->out_type)) {
            rep->outfd = sg_out_open(outfn, &clp->out_flags, clp->bs,
                                     clp->bpt);
            if (rep->outfd < 0) err_exit(-rep->outfd, "error opening outfn");

        } else
            rep->outfd = clp->outfd;
    } else {
        rep->infd = clp->infd;
        rep->outfd = clp->outfd;
    }
    rep->debug = clp->debug;
    rep->cdbsz_in = clp->cdbsz_in;
    rep->cdbsz_out = clp->cdbsz_out;
    rep->in_flags = clp->in_flags;
    rep->out_flags = clp->out_flags;
    if (clp->mmap_active) {
        int fd = clp->in_flags.mmap ? rep->infd : rep->outfd;

pr2serr("%s: id=%d, fd=%d calling sgp_mem_mmap()\n", __func__, id, fd);
        status = sgp_mem_mmap(fd, sz, &rep->buffp);
        if (status) err_exit(status, "sgp_mem_mmap() failed");
    } else {
        rep->buffp = sg_memalign(sz, 0 /* page align */, &rep->alloc_bp,
                                 false);
        if (NULL == rep->buffp)
            err_exit(ENOMEM, "out of memory creating user buffers\n");
    }

    while(1) {
        status = pthread_mutex_lock(&clp->in_mutex);
        if (0 != status) err_exit(status, "lock in_mutex");
        if (clp->in_stop || (clp->in_count <= 0)) {
            /* no more to do, exit loop then thread */
            status = pthread_mutex_unlock(&clp->in_mutex);
            if (0 != status) err_exit(status, "unlock in_mutex");
            break;
        }
        blocks = (clp->in_count > clp->bpt) ? clp->bpt : clp->in_count;
        rep->wr = false;
        rep->blk = clp->in_blk;
        rep->num_blks = blocks;
        clp->in_blk += blocks;
        clp->in_count -= blocks;

        pthread_cleanup_push(cleanup_in, (void *)clp);
        if (FT_SG == clp->in_type)
            sg_in_operation(clp, rep); /* lets go of in_mutex mid operation */
        else {
            stop_after_write = normal_in_operation(clp, rep, blocks);
            status = pthread_mutex_unlock(&clp->in_mutex);
            if (0 != status) err_exit(status, "unlock in_mutex");
        }
        pthread_cleanup_pop(0);

        status = pthread_mutex_lock(&clp->out_mutex);
        if (0 != status) err_exit(status, "lock out_mutex");
        if (FT_DEV_NULL != clp->out_type) {
            while ((! clp->out_stop) &&
                   ((rep->blk + seek_skip) != clp->out_blk)) {
                /* if write would be out of sequence then wait */
                pthread_cleanup_push(cleanup_out, (void *)clp);
                status = pthread_cond_wait(&clp->out_sync_cv, &clp->out_mutex);
                if (0 != status) err_exit(status, "cond out_sync_cv");
                pthread_cleanup_pop(0);
            }
        }

        if (clp->out_stop || (clp->out_count <= 0)) {
            if (! clp->out_stop)
                clp->out_stop = true;
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
            break;
        }
        if (stop_after_write)
            clp->out_stop = true;
        rep->wr = true;
        rep->blk = clp->out_blk;
        clp->out_blk += blocks;
        clp->out_count -= blocks;

        if (0 == rep->num_blks) {
            clp->out_stop = true;
            stop_after_write = true;
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
            break;      /* read nothing so leave loop */
        }

        pthread_cleanup_push(cleanup_out, (void *)clp);
        if (FT_SG == clp->out_type)
            sg_out_operation(clp, rep); /* releases out_mutex mid operation */
        else if (FT_DEV_NULL == clp->out_type) {
            /* skip actual write operation */
            clp->out_rem_count -= blocks;
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
        }
        else {
            normal_out_operation(clp, rep, blocks);
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
        }
        pthread_cleanup_pop(0);

        if (stop_after_write)
            break;
        pthread_cond_broadcast(&clp->out_sync_cv);
    } /* end of while loop */
    if (rep->alloc_bp)
        free(rep->alloc_bp);
    status = pthread_mutex_lock(&clp->in_mutex);
    if (0 != status) err_exit(status, "lock in_mutex");
    if (! clp->in_stop)
        clp->in_stop = true;  /* flag other workers to stop */
    status = pthread_mutex_unlock(&clp->in_mutex);
    if (0 != status) err_exit(status, "unlock in_mutex");
    pthread_cond_broadcast(&clp->out_sync_cv);
    return stop_after_write ? NULL : clp;
}

static bool
normal_in_operation(Rq_coll * clp, Rq_elem * rep, int blocks)
{
    bool stop_after_write = false;
    int res;
    char strerr_buff[STRERR_BUFF_LEN];

    /* enters holding in_mutex */
    while (((res = read(rep->infd, rep->buffp, blocks * clp->bs)) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno)))
        ;
    if (res < 0) {
        if (clp->in_flags.coe) {
            memset(rep->buffp, 0, rep->num_blks * rep->bs);
            pr2serr(">> substituted zeros for in blk=%" PRId64 " for %d "
                    "bytes, %s\n", rep->blk,
                    rep->num_blks * rep->bs,
                    tsafe_strerror(errno, strerr_buff));
            res = rep->num_blks * clp->bs;
        }
        else {
            pr2serr("error in normal read, %s\n",
                    tsafe_strerror(errno, strerr_buff));
            clp->in_stop = true;
            guarded_stop_out(clp);
            return 1;
        }
    }
    if (res < blocks * clp->bs) {
        int o_blocks = blocks;
        stop_after_write = true;
        blocks = res / clp->bs;
        if ((res % clp->bs) > 0) {
            blocks++;
            clp->in_partial++;
        }
        /* Reverse out + re-apply blocks on clp */
        clp->in_blk -= o_blocks;
        clp->in_count += o_blocks;
        rep->num_blks = blocks;
        clp->in_blk += blocks;
        clp->in_count -= blocks;
    }
    clp->in_rem_count -= blocks;
    return stop_after_write;
}

static void
normal_out_operation(Rq_coll * clp, Rq_elem * rep, int blocks)
{
    int res;
    char strerr_buff[STRERR_BUFF_LEN];

    /* enters holding out_mutex */
    while (((res = write(rep->outfd, rep->buffp, rep->num_blks * clp->bs))
            < 0) && ((EINTR == errno) || (EAGAIN == errno)))
        ;
    if (res < 0) {
        if (clp->out_flags.coe) {
            pr2serr(">> ignored error for out blk=%" PRId64 " for %d bytes, "
                    "%s\n", rep->blk, rep->num_blks * rep->bs,
                    tsafe_strerror(errno, strerr_buff));
            res = rep->num_blks * clp->bs;
        }
        else {
            pr2serr("error normal write, %s\n",
                    tsafe_strerror(errno, strerr_buff));
            guarded_stop_in(clp);
            clp->out_stop = true;
            return;
        }
    }
    if (res < blocks * clp->bs) {
        blocks = res / clp->bs;
        if ((res % clp->bs) > 0) {
            blocks++;
            clp->out_partial++;
        }
        rep->num_blks = blocks;
    }
    clp->out_rem_count -= blocks;
}

static int
sg_build_scsi_cdb(uint8_t * cdbp, int cdb_sz, unsigned int blocks,
                  int64_t start_block, bool write_true, bool fua, bool dpo)
{
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};
    int sz_ind;

    memset(cdbp, 0, cdb_sz);
    if (dpo)
        cdbp[1] |= 0x10;
    if (fua)
        cdbp[1] |= 0x8;
    switch (cdb_sz) {
    case 6:
        sz_ind = 0;
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        sg_put_unaligned_be24(0x1fffff & start_block, cdbp + 1);
        cdbp[4] = (256 == blocks) ? 0 : (uint8_t)blocks;
        if (blocks > 256) {
            pr2serr("%sfor 6 byte commands, maximum number of blocks is "
                    "256\n", my_name);
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            pr2serr("%sfor 6 byte commands, can't address blocks beyond "
                    "%d\n", my_name, 0x1fffff);
            return 1;
        }
        if (dpo || fua) {
            pr2serr("%sfor 6 byte commands, neither dpo nor fua bits "
                    "supported\n", my_name);
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        sg_put_unaligned_be32((uint32_t)start_block, cdbp + 2);
        sg_put_unaligned_be16((uint16_t)blocks, cdbp + 7);
        if (blocks & (~0xffff)) {
            pr2serr("%sfor 10 byte commands, maximum number of blocks is "
                    "%d\n", my_name, 0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        sg_put_unaligned_be32((uint32_t)start_block, cdbp + 2);
        sg_put_unaligned_be32((uint32_t)blocks, cdbp + 6);
        break;
    case 16:
        sz_ind = 3;
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        sg_put_unaligned_be64((uint64_t)start_block, cdbp + 2);
        sg_put_unaligned_be32((uint32_t)blocks, cdbp + 10);
        break;
    default:
        pr2serr("%sexpected cdb size of 6, 10, 12, or 16 but got %d\n",
                my_name, cdb_sz);
        return 1;
    }
    return 0;
}

static void
sg_in_operation(Rq_coll * clp, Rq_elem * rep)
{
    int res;
    int status;

    /* enters holding in_mutex */
    while (1) {
        res = sg_start_io(rep);
        if (1 == res)
            err_exit(ENOMEM, "sg starting in command");
        else if (res < 0) {
            pr2serr("%sinputting to sg failed, blk=%" PRId64 "\n", my_name,
                    rep->blk);
            status = pthread_mutex_unlock(&clp->in_mutex);
            if (0 != status) err_exit(status, "unlock in_mutex");
            guarded_stop_both(clp);
            return;
        }
        /* Now release in mutex to let other reads run in parallel */
        status = pthread_mutex_unlock(&clp->in_mutex);
        if (0 != status) err_exit(status, "unlock in_mutex");

        res = sg_finish_io(rep->wr, rep, &clp->aux_mutex);
        switch (res) {
        case SG_LIB_CAT_ABORTED_COMMAND:
        case SG_LIB_CAT_UNIT_ATTENTION:
            /* try again with same addr, count info */
            /* now re-acquire in mutex for balance */
            /* N.B. This re-read could now be out of read sequence */
            status = pthread_mutex_lock(&clp->in_mutex);
            if (0 != status) err_exit(status, "lock in_mutex");
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            if (0 == clp->in_flags.coe) {
                pr2serr("error finishing sg in command (medium)\n");
                if (exit_status <= 0)
                    exit_status = res;
                guarded_stop_both(clp);
                return;
            } else {
                memset(rep->buffp, 0, rep->num_blks * rep->bs);
                pr2serr(">> substituted zeros for in blk=%" PRId64 " for %d "
                        "bytes\n", rep->blk, rep->num_blks * rep->bs);
            }
#if defined(__GNUC__)
#if (__GNUC__ >= 7)
            __attribute__((fallthrough));
            /* FALL THROUGH */
#endif
#endif
        case 0:
            if (rep->dio_incomplete_count || rep->resid) {
                status = pthread_mutex_lock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "lock aux_mutex");
                clp->dio_incomplete_count += rep->dio_incomplete_count;
                clp->sum_of_resids += rep->resid;
                status = pthread_mutex_unlock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "unlock aux_mutex");
            }
            status = pthread_mutex_lock(&clp->in_mutex);
            if (0 != status) err_exit(status, "lock in_mutex");
            clp->in_rem_count -= rep->num_blks;
            status = pthread_mutex_unlock(&clp->in_mutex);
            if (0 != status) err_exit(status, "unlock in_mutex");
            return;
        default:
            pr2serr("error finishing sg in command (%d)\n", res);
            if (exit_status <= 0)
                exit_status = res;
            guarded_stop_both(clp);
            return;
        }
    }
}

static void
sg_out_operation(Rq_coll * clp, Rq_elem * rep)
{
    int res;
    int status;

    /* enters holding out_mutex */
    while (1) {
        res = sg_start_io(rep);
        if (1 == res)
            err_exit(ENOMEM, "sg starting out command");
        else if (res < 0) {
            pr2serr("%soutputting from sg failed, blk=%" PRId64 "\n",
                    my_name, rep->blk);
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
            guarded_stop_both(clp);
            return;
        }
        /* Now release in mutex to let other reads run in parallel */
        status = pthread_mutex_unlock(&clp->out_mutex);
        if (0 != status) err_exit(status, "unlock out_mutex");

        res = sg_finish_io(rep->wr, rep, &clp->aux_mutex);
        switch (res) {
        case SG_LIB_CAT_ABORTED_COMMAND:
        case SG_LIB_CAT_UNIT_ATTENTION:
            /* try again with same addr, count info */
            /* now re-acquire out mutex for balance */
            /* N.B. This re-write could now be out of write sequence */
            status = pthread_mutex_lock(&clp->out_mutex);
            if (0 != status) err_exit(status, "lock out_mutex");
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            if (0 == clp->out_flags.coe) {
                pr2serr("error finishing sg out command (medium)\n");
                if (exit_status <= 0)
                    exit_status = res;
                guarded_stop_both(clp);
                return;
            } else
                pr2serr(">> ignored error for out blk=%" PRId64 " for %d "
                        "bytes\n", rep->blk, rep->num_blks * rep->bs);
#if defined(__GNUC__)
#if (__GNUC__ >= 7)
            __attribute__((fallthrough));
            /* FALL THROUGH */
#endif
#endif
        case 0:
            if (rep->dio_incomplete_count || rep->resid) {
                status = pthread_mutex_lock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "lock aux_mutex");
                clp->dio_incomplete_count += rep->dio_incomplete_count;
                clp->sum_of_resids += rep->resid;
                status = pthread_mutex_unlock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "unlock aux_mutex");
            }
            status = pthread_mutex_lock(&clp->out_mutex);
            if (0 != status) err_exit(status, "lock out_mutex");
            clp->out_rem_count -= rep->num_blks;
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
            return;
        default:
            pr2serr("error finishing sg out command (%d)\n", res);
            if (exit_status <= 0)
                exit_status = res;
            guarded_stop_both(clp);
            return;
        }
    }
}

static int
sg_start_io(Rq_elem * rep)
{
    struct sg_io_hdr * hp = &rep->io_hdr;
    bool fua = rep->wr ? rep->out_flags.fua : rep->in_flags.fua;
    bool dpo = rep->wr ? rep->out_flags.dpo : rep->in_flags.dpo;
    bool dio = rep->wr ? rep->out_flags.dio : rep->in_flags.dio;
    bool mmap = rep->wr ? rep->out_flags.mmap : rep->in_flags.mmap;
    int cdbsz = rep->wr ? rep->cdbsz_out : rep->cdbsz_in;
    int res;

    if (sg_build_scsi_cdb(rep->cmd, cdbsz, rep->num_blks, rep->blk,
                          rep->wr, fua, dpo)) {
        pr2serr("%sbad cdb build, start_blk=%" PRId64 ", blocks=%d\n",
                my_name, rep->blk, rep->num_blks);
        return -1;
    }
    memset(hp, 0, sizeof(struct sg_io_hdr));
    hp->interface_id = 'S';
    hp->cmd_len = cdbsz;
    hp->cmdp = rep->cmd;
    hp->dxfer_direction = rep->wr ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    hp->dxfer_len = rep->bs * rep->num_blks;
    hp->dxferp = mmap ? NULL : rep->buffp;
    hp->mx_sb_len = sizeof(rep->sb);
    hp->sbp = rep->sb;
    hp->timeout = DEF_TIMEOUT;
    hp->usr_ptr = rep;
    rep->pack_id = GET_NEXT_PACK_ID(1);
    hp->pack_id = (int)rep->pack_id;
    if (dio)
        hp->flags |= SG_FLAG_DIRECT_IO;
    if (mmap)
        hp->flags |= SG_FLAG_MMAP_IO;
    if (rep->debug > 8) {
        pr2serr("sg_start_io: SCSI %s, blk=%" PRId64 " num_blks=%d\n",
               rep->wr ? "WRITE" : "READ", rep->blk, rep->num_blks);
        sg_print_command(hp->cmdp);
    }

    while (((res = write(rep->wr ? rep->outfd : rep->infd, hp,
                         sizeof(struct sg_io_hdr))) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("starting io on sg device, error");
        return -1;
    }
    return 0;
}

/* 0 -> successful, SG_LIB_CAT_UNIT_ATTENTION or SG_LIB_CAT_ABORTED_COMMAND
   -> try again, SG_LIB_CAT_NOT_READY, SG_LIB_CAT_MEDIUM_HARD,
   -1 other errors */
static int
sg_finish_io(bool wr, Rq_elem * rep, pthread_mutex_t * a_mutp)
{
    int res, status;
    struct sg_io_hdr io_hdr;
    struct sg_io_hdr * hp;
#if 0
    static int testing = 0;     /* thread dubious! */
#endif

    memset(&io_hdr, 0 , sizeof(struct sg_io_hdr));
    /* FORCE_PACK_ID active set only read packet with matching pack_id */
    io_hdr.interface_id = 'S';
    io_hdr.dxfer_direction = wr ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    io_hdr.pack_id = (int)rep->pack_id;

    while (((res = read(wr ? rep->outfd : rep->infd, &io_hdr,
                        sizeof(struct sg_io_hdr))) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    if (res < 0) {
        perror("finishing io on sg device, error");
        return -1;
    }
    if (rep != (Rq_elem *)io_hdr.usr_ptr)
        err_exit(0, "sg_finish_io: bad usr_ptr, request-response mismatch\n");
    memcpy(&rep->io_hdr, &io_hdr, sizeof(struct sg_io_hdr));
    hp = &rep->io_hdr;

    res = sg_err_category3(hp);
    switch (res) {
        case SG_LIB_CAT_CLEAN:
            break;
        case SG_LIB_CAT_RECOVERED:
            sg_chk_n_print3((wr ? "writing continuing":
                                       "reading continuing"), hp, false);
            break;
        case SG_LIB_CAT_ABORTED_COMMAND:
        case SG_LIB_CAT_UNIT_ATTENTION:
            if (rep->debug > 8)
                sg_chk_n_print3((wr ? "writing": "reading"), hp, false);
            return res;
        case SG_LIB_CAT_NOT_READY:
        default:
            {
                char ebuff[EBUFF_SZ];

                snprintf(ebuff, EBUFF_SZ, "%s blk=%" PRId64,
                         wr ? "writing": "reading", rep->blk);
                status = pthread_mutex_lock(a_mutp);
                if (0 != status) err_exit(status, "lock aux_mutex");
                sg_chk_n_print3(ebuff, hp, false);
                status = pthread_mutex_unlock(a_mutp);
                if (0 != status) err_exit(status, "unlock aux_mutex");
                return res;
            }
    }
#if 0
    if (0 == (++testing % 100)) return -1;
#endif
    if ((wr ? rep->out_flags.dio : rep->in_flags.dio) &&
        ((hp->info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        rep->dio_incomplete_count = 1; /* count dios done as indirect IO */
    else
        rep->dio_incomplete_count = 0;
    rep->resid = hp->resid;
    if (rep->debug > 8)
        pr2serr("sg_finish_io: completed %s\n", wr ? "WRITE" : "READ");
    return 0;
}

static int
process_flags(const char * arg, struct flags_t * fp)
{
    char buff[256];
    char * cp;
    char * np;

    strncpy(buff, arg, sizeof(buff));
    buff[sizeof(buff) - 1] = '\0';
    if ('\0' == buff[0]) {
        pr2serr("no flag found\n");
        return 1;
    }
    cp = buff;
    do {
        np = strchr(cp, ',');
        if (np)
            *np++ = '\0';
        if (0 == strcmp(cp, "append"))
            fp->append = true;
        else if (0 == strcmp(cp, "coe"))
            fp->coe = true;
        else if (0 == strcmp(cp, "dio"))
            fp->dio = true;
        else if (0 == strcmp(cp, "direct"))
            fp->direct = true;
        else if (0 == strcmp(cp, "dpo"))
            fp->dpo = true;
        else if (0 == strcmp(cp, "dsync"))
            fp->dsync = true;
        else if (0 == strcmp(cp, "excl"))
            fp->excl = true;
        else if (0 == strcmp(cp, "fua"))
            fp->fua = true;
        else if (0 == strcmp(cp, "mmap"))
            fp->mmap = true;
        else if (0 == strcmp(cp, "null"))
            ;
        else {
            pr2serr("unrecognised flag: %s\n", cp);
            return 1;
        }
        cp = np;
    } while (cp);
    return 0;
}

/* Returns the number of times 'ch' is found in string 's' given the
 * string's length. */
static int
num_chs_in_str(const char * s, int slen, int ch)
{
    int res = 0;

    while (--slen >= 0) {
        if (ch == s[slen])
            ++res;
    }
    return res;
}


int
main(int argc, char * argv[])
{
    bool verbose_given = false;
    bool version_given = false;
    int64_t skip = 0;
    int64_t seek = 0;
    int ibs = 0;
    int obs = 0;
    int bpt_given = 0;
    int cdbsz_given = 0;
    char str[STR_SZ];
    char * key;
    char * buf;
    int res, k, err, keylen;
    int64_t in_num_sect = 0;
    int64_t out_num_sect = 0;
    int in_sect_sz, out_sect_sz, status, n, flags;
    void * vp;
    Rq_coll * clp = &rcoll;
    char ebuff[EBUFF_SZ];
#if SG_LIB_ANDROID
    struct sigaction actions;

    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = thread_exit_handler;
    sigaction(SIGUSR1, &actions, NULL);
#endif
    memset(clp, 0, sizeof(*clp));
    clp->num_threads = DEF_NUM_THREADS;
    clp->bpt = DEF_BLOCKS_PER_TRANSFER;
    clp->in_type = FT_OTHER;
    clp->out_type = FT_OTHER;
    clp->cdbsz_in = DEF_SCSI_CDBSZ;
    clp->cdbsz_out = DEF_SCSI_CDBSZ;
    infn[0] = '\0';
    outfn[0] = '\0';

    for (k = 1; k < argc; k++) {
        if (argv[k]) {
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
        }
        else
            continue;
        for (key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        keylen = strlen(key);
        if (0 == strcmp(key,"bpt")) {
            clp->bpt = sg_get_num(buf);
            if (-1 == clp->bpt) {
                pr2serr("%sbad argument to 'bpt='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
            bpt_given = 1;
        } else if (0 == strcmp(key,"bs")) {
            clp->bs = sg_get_num(buf);
            if (-1 == clp->bs) {
                pr2serr("%sbad argument to 'bs='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"cdbsz")) {
            clp->cdbsz_in = sg_get_num(buf);
            clp->cdbsz_out = clp->cdbsz_in;
            cdbsz_given = 1;
        } else if (0 == strcmp(key,"coe")) {
            clp->in_flags.coe = !! sg_get_num(buf);
            clp->out_flags.coe = clp->in_flags.coe;
        } else if (0 == strcmp(key,"count")) {
            if (0 != strcmp("-1", buf)) {
                dd_count = sg_get_llnum(buf);
                if (-1LL == dd_count) {
                    pr2serr("%sbad argument to 'count='\n", my_name);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }   /* treat 'count=-1' as calculate count (same as not given) */
        } else if ((0 == strncmp(key,"deb", 3)) ||
                   (0 == strncmp(key,"verb", 4)))
            clp->debug = sg_get_num(buf);
        else if (0 == strcmp(key,"dio")) {
            clp->in_flags.dio = !! sg_get_num(buf);
            clp->out_flags.dio = clp->in_flags.dio;
        } else if (0 == strcmp(key,"fua")) {
            n = sg_get_num(buf);
            if (n & 1)
                clp->out_flags.fua = true;
            if (n & 2)
                clp->in_flags.fua = true;
        } else if (0 == strcmp(key,"ibs")) {
            ibs = sg_get_num(buf);
            if (-1 == ibs) {
                pr2serr("%sbad argument to 'ibs='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"if") == 0) {
            if ('\0' != infn[0]) {
                pr2serr("Second 'if=' argument??\n");
                return SG_LIB_SYNTAX_ERROR;
            } else {
                memcpy(infn, buf, INOUTF_SZ);
                infn[INOUTF_SZ - 1] = '\0';
            }
        } else if (0 == strcmp(key, "iflag")) {
            if (process_flags(buf, &clp->in_flags)) {
                pr2serr("%sbad argument to 'iflag='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"obs")) {
            obs = sg_get_num(buf);
            if (-1 == obs) {
                pr2serr("%sbad argument to 'obs='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"of") == 0) {
            if ('\0' != outfn[0]) {
                pr2serr("Second 'of=' argument??\n");
                return SG_LIB_SYNTAX_ERROR;
            } else {
                memcpy(outfn, buf, INOUTF_SZ);
                outfn[INOUTF_SZ - 1] = '\0';
            }
        } else if (0 == strcmp(key, "oflag")) {
            if (process_flags(buf, &clp->out_flags)) {
                pr2serr("%sbad argument to 'oflag='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"seek")) {
            seek = sg_get_llnum(buf);
            if (-1LL == seek) {
                pr2serr("%sbad argument to 'seek='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"skip")) {
            skip = sg_get_llnum(buf);
            if (-1LL == skip) {
                pr2serr("%sbad argument to 'skip='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"sync"))
            do_sync = !! sg_get_num(buf);
        else if (0 == strcmp(key,"thr"))
            clp->num_threads = sg_get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = !! sg_get_num(buf);
        else if ((keylen > 1) && ('-' == key[0]) && ('-' != key[1])) {
            res = 0;
            n = num_chs_in_str(key + 1, keylen - 1, 'd');
            clp->dry_run += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'h');
            if (n > 0) {
                usage();
                return 0;
            }
            n = num_chs_in_str(key + 1, keylen - 1, 'v');
            if (n > 0)
                verbose_given = true;
            clp->debug += n;   /* -v  ---> --verbose */
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'V');
            if (n > 0)
                version_given = true;
            res += n;

            if (res < (keylen - 1)) {
                pr2serr("Unrecognised short option in '%s', try '--help'\n",
                        key);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if ((0 == strncmp(key, "--dry-run", 9)) ||
                   (0 == strncmp(key, "--dry_run", 9)))
            ++clp->dry_run;
        else if ((0 == strncmp(key, "--help", 6)) ||
                   (0 == strcmp(key, "-?"))) {
            usage();
            return 0;
        } else if (0 == strncmp(key, "--verb", 6)) {
            verbose_given = true;
            ++clp->debug;      /* --verbose */
        } else if (0 == strncmp(key, "--vers", 6))
            version_given = true;
        else {
            pr2serr("Unrecognized option '%s'\n", key);
            pr2serr("For more information use '--help'\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }

#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        verbose_given = false;
        version_given = false;
        clp->debug = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        clp->debug = 2;
    } else
        pr2serr("keep verbose=%d\n", clp->debug);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr("%s%s\n", my_name, version_str);
        return 0;
    }

    if (clp->bs <= 0) {
        clp->bs = DEF_BLOCK_SIZE;
        pr2serr("Assume default 'bs' ((logical) block size) of %d bytes\n",
                clp->bs);
    }
    if ((ibs && (ibs != clp->bs)) || (obs && (obs != clp->bs))) {
        pr2serr("If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((skip < 0) || (seek < 0)) {
        pr2serr("skip and seek cannot be negative\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (clp->out_flags.append && (seek > 0)) {
        pr2serr("Can't use both append and seek switches\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (clp->bpt < 1) {
        pr2serr("bpt must be greater than 0\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (clp->in_flags.mmap && clp->out_flags.mmap) {
        pr2serr("can only use mmap flag in iflag= or oflag=, not both\n");
        return SG_LIB_SYNTAX_ERROR;
    } else if (clp->in_flags.mmap || clp->out_flags.mmap)
        clp->mmap_active = true;
    /* defaulting transfer size to 128*2048 for CD/DVDs is too large
       for the block layer in lk 2.6 and results in an EIO on the
       SG_IO ioctl. So reduce it in that case. */
    if ((clp->bs >= 2048) && (0 == bpt_given))
        clp->bpt = DEF_BLOCKS_PER_2048TRANSFER;
    if ((clp->num_threads < 1) || (clp->num_threads > MAX_NUM_THREADS)) {
        pr2serr("too few or too many threads requested\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (clp->debug)
        pr2serr("%sif=%s skip=%" PRId64 " of=%s seek=%" PRId64 " count=%"
                PRId64 "\n", my_name, infn, skip, outfn, seek, dd_count);

    install_handler(SIGINT, interrupt_handler);
    install_handler(SIGQUIT, interrupt_handler);
    install_handler(SIGPIPE, interrupt_handler);
    install_handler(SIGUSR1, siginfo_handler);

    clp->infd = STDIN_FILENO;
    clp->outfd = STDOUT_FILENO;
    if (infn[0] && ('-' != infn[0])) {
        clp->in_type = dd_filetype(infn);

        if (FT_ERROR == clp->in_type) {
            pr2serr("%sunable to access %s\n", my_name, infn);
            return SG_LIB_FILE_ERROR;
        } else if (FT_ST == clp->in_type) {
            pr2serr("%sunable to use scsi tape device %s\n", my_name, infn);
            return SG_LIB_FILE_ERROR;
        } else if (FT_SG == clp->in_type) {
            clp->infd = sg_in_open(infn, &clp->in_flags, clp->bs, clp->bpt);
            if (clp->infd < 0)
                return -clp->infd;
        }
        else {
            flags = O_RDONLY;
            if (clp->in_flags.direct)
                flags |= O_DIRECT;
            if (clp->in_flags.excl)
                flags |= O_EXCL;
            if (clp->in_flags.dsync)
                flags |= O_SYNC;

            if ((clp->infd = open(infn, flags)) < 0) {
                err = errno;
                snprintf(ebuff, EBUFF_SZ, "%scould not open %s for reading",
                         my_name, infn);
                perror(ebuff);
                return sg_convert_errno(err);
            }
            else if (skip > 0) {
                off64_t offset = skip;

                offset *= clp->bs;       /* could exceed 32 bits here! */
                if (lseek64(clp->infd, offset, SEEK_SET) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, "%scouldn't skip to required "
                             "position on %s", my_name, infn);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
            }
        }
    }
    if (outfn[0] && ('-' != outfn[0])) {
        clp->out_type = dd_filetype(outfn);

        if (FT_ST == clp->out_type) {
            pr2serr("%sunable to use scsi tape device %s\n", my_name, outfn);
            return SG_LIB_FILE_ERROR;
        } else if (FT_SG == clp->out_type) {
            clp->outfd = sg_out_open(outfn, &clp->out_flags, clp->bs,
                                     clp->bpt);
            if (clp->outfd < 0)
                return -clp->outfd;
        } else if (FT_DEV_NULL == clp->out_type)
            clp->outfd = -1; /* don't bother opening */
        else {
            if (FT_RAW != clp->out_type) {
                flags = O_WRONLY | O_CREAT;
                if (clp->out_flags.direct)
                    flags |= O_DIRECT;
                if (clp->out_flags.excl)
                    flags |= O_EXCL;
                if (clp->out_flags.dsync)
                    flags |= O_SYNC;
                if (clp->out_flags.append)
                    flags |= O_APPEND;

                if ((clp->outfd = open(outfn, flags, 0666)) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, "%scould not open %s for "
                             "writing", my_name, outfn);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
            }
            else {      /* raw output file */
                if ((clp->outfd = open(outfn, O_WRONLY)) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, "%scould not open %s for raw "
                             "writing", my_name, outfn);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
            }
            if (seek > 0) {
                off64_t offset = seek;

                offset *= clp->bs;       /* could exceed 32 bits here! */
                if (lseek64(clp->outfd, offset, SEEK_SET) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, "%scouldn't seek to required "
                             "position on %s", my_name, outfn);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
            }
        }
    }
    if ((STDIN_FILENO == clp->infd) && (STDOUT_FILENO == clp->outfd)) {
        pr2serr("Won't default both IFILE to stdin _and_ OFILE to stdout\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (dd_count < 0) {
        in_num_sect = -1;
        if (FT_SG == clp->in_type) {
            res = scsi_read_capacity(clp->infd, &in_num_sect, &in_sect_sz);
            if (2 == res) {
                pr2serr("Unit attention, media changed(in), continuing\n");
                res = scsi_read_capacity(clp->infd, &in_num_sect,
                                         &in_sect_sz);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    pr2serr("read capacity not supported on %s\n", infn);
                else if (res == SG_LIB_CAT_NOT_READY)
                    pr2serr("read capacity failed, %s not ready\n", infn);
                else
                    pr2serr("Unable to read capacity on %s\n", infn);
                in_num_sect = -1;
            }
        } else if (FT_BLOCK == clp->in_type) {
            if (0 != read_blkdev_capacity(clp->infd, &in_num_sect,
                                          &in_sect_sz)) {
                pr2serr("Unable to read block capacity on %s\n", infn);
                in_num_sect = -1;
            }
            if (clp->bs != in_sect_sz) {
                pr2serr("logical block size on %s confusion; bs=%d, from "
                        "device=%d\n", infn, clp->bs, in_sect_sz);
                in_num_sect = -1;
            }
        }
        if (in_num_sect > skip)
            in_num_sect -= skip;

        out_num_sect = -1;
        if (FT_SG == clp->out_type) {
            res = scsi_read_capacity(clp->outfd, &out_num_sect, &out_sect_sz);
            if (2 == res) {
                pr2serr("Unit attention, media changed(out), continuing\n");
                res = scsi_read_capacity(clp->outfd, &out_num_sect,
                                         &out_sect_sz);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    pr2serr("read capacity not supported on %s\n", outfn);
                else if (res == SG_LIB_CAT_NOT_READY)
                    pr2serr("read capacity failed, %s not ready\n", outfn);
                else
                    pr2serr("Unable to read capacity on %s\n", outfn);
                out_num_sect = -1;
            }
        } else if (FT_BLOCK == clp->out_type) {
            if (0 != read_blkdev_capacity(clp->outfd, &out_num_sect,
                                          &out_sect_sz)) {
                pr2serr("Unable to read block capacity on %s\n", outfn);
                out_num_sect = -1;
            }
            if (clp->bs != out_sect_sz) {
                pr2serr("logical block size on %s confusion: bs=%d, from "
                        "device=%d\n", outfn, clp->bs, out_sect_sz);
                out_num_sect = -1;
            }
        }
        if (out_num_sect > seek)
            out_num_sect -= seek;

        if (in_num_sect > 0) {
            if (out_num_sect > 0)
                dd_count = (in_num_sect > out_num_sect) ? out_num_sect :
                                                          in_num_sect;
            else
                dd_count = in_num_sect;
        }
        else
            dd_count = out_num_sect;
    }
    if (clp->debug > 1)
        pr2serr("Start of loop, count=%" PRId64 ", in_num_sect=%" PRId64
                ", out_num_sect=%" PRId64 "\n", dd_count, in_num_sect,
                out_num_sect);
    if (dd_count < 0) {
        pr2serr("Couldn't calculate count, please give one\n");
        return SG_LIB_CAT_OTHER;
    }
    if (! cdbsz_given) {
        if ((FT_SG == clp->in_type) && (MAX_SCSI_CDBSZ != clp->cdbsz_in) &&
            (((dd_count + skip) > UINT_MAX) || (clp->bpt > USHRT_MAX))) {
            pr2serr("Note: SCSI command size increased to 16 bytes (for "
                    "'if')\n");
            clp->cdbsz_in = MAX_SCSI_CDBSZ;
        }
        if ((FT_SG == clp->out_type) && (MAX_SCSI_CDBSZ != clp->cdbsz_out) &&
            (((dd_count + seek) > UINT_MAX) || (clp->bpt > USHRT_MAX))) {
            pr2serr("Note: SCSI command size increased to 16 bytes (for "
                    "'of')\n");
            clp->cdbsz_out = MAX_SCSI_CDBSZ;
        }
    }

    clp->in_count = dd_count;
    clp->in_rem_count = dd_count;
    clp->skip = skip;
    clp->in_blk = skip;
    clp->out_count = dd_count;
    clp->out_rem_count = dd_count;
    clp->seek = seek;
    clp->out_blk = seek;
    status = pthread_mutex_init(&clp->in_mutex, NULL);
    if (0 != status) err_exit(status, "init in_mutex");
    status = pthread_mutex_init(&clp->out_mutex, NULL);
    if (0 != status) err_exit(status, "init out_mutex");
    status = pthread_mutex_init(&clp->aux_mutex, NULL);
    if (0 != status) err_exit(status, "init aux_mutex");
    status = pthread_cond_init(&clp->out_sync_cv, NULL);
    if (0 != status) err_exit(status, "init out_sync_cv");

    if (clp->dry_run > 0) {
        pr2serr("Due to --dry-run option, bypass copy/read\n");
        goto fini;
    }
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    status = pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
    if (0 != status) err_exit(status, "pthread_sigmask");
    status = pthread_create(&sig_listen_thread_id, NULL,
                            sig_listen_thread, (void *)clp);
    if (0 != status) err_exit(status, "pthread_create, sig...");

    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }

/* vvvvvvvvvvv  Start worker threads  vvvvvvvvvvvvvvvvvvvvvvvv */
    if ((clp->out_rem_count > 0) && (clp->num_threads > 0)) {
        /* Run 1 work thread to shake down infant retryable stuff */
        status = pthread_mutex_lock(&clp->out_mutex);
        if (0 != status) err_exit(status, "lock out_mutex");
        thr_arg_a[0].id = 0;
        thr_arg_a[0].clp = clp;
        status = pthread_create(&threads[0], NULL, read_write_thread,
                                (void *)(thr_arg_a + 0));
        if (0 != status) err_exit(status, "pthread_create");
        if (clp->debug)
            pr2serr("Starting worker thread k=0\n");

        /* wait for any broadcast */
        pthread_cleanup_push(cleanup_out, (void *)clp);
        status = pthread_cond_wait(&clp->out_sync_cv, &clp->out_mutex);
        if (0 != status) err_exit(status, "cond out_sync_cv");
        pthread_cleanup_pop(0);
        status = pthread_mutex_unlock(&clp->out_mutex);
        if (0 != status) err_exit(status, "unlock out_mutex");

        /* now start the rest of the threads */
        for (k = 1; k < clp->num_threads; ++k) {

            thr_arg_a[k].id = k;
            thr_arg_a[k].clp = clp;
            status = pthread_create(&threads[k], NULL, read_write_thread,
                                    (void *)(thr_arg_a + k));
            if (0 != status) err_exit(status, "pthread_create");
            if (clp->debug > 2)
                pr2serr("Starting worker thread k=%d\n", k);
        }

        /* now wait for worker threads to finish */
        for (k = 0; k < clp->num_threads; ++k) {
            status = pthread_join(threads[k], &vp);
            if (0 != status) err_exit(status, "pthread_join");
            if (clp->debug > 2)
                pr2serr("Worker thread k=%d terminated\n", k);
        }
    }   /* started worker threads and here after they have all exited */

    if (do_time && (start_tm.tv_sec || start_tm.tv_usec))
        calc_duration_throughput(0);

    if (do_sync) {
        if (FT_SG == clp->out_type) {
            pr2serr(">> Synchronizing cache on %s\n", outfn);
            res = sg_ll_sync_cache_10(clp->outfd, 0, 0, 0, 0, 0, false, 0);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                pr2serr("Unit attention(out), continuing\n");
                res = sg_ll_sync_cache_10(clp->outfd, 0, 0, 0, 0, 0, false,
                                          0);
            }
            if (0 != res)
                pr2serr("Unable to synchronize cache\n");
        }
    }

#if 0
#if SG_LIB_ANDROID
    /* Android doesn't have pthread_cancel() so use pthread_kill() instead.
     * Also there is no need to link with -lpthread in Android */
    status = pthread_kill(sig_listen_thread_id, SIGUSR1);
    if (0 != status) err_exit(status, "pthread_kill");
#else
    status = pthread_cancel(sig_listen_thread_id);
    if (0 != status) err_exit(status, "pthread_cancel");
#endif
#endif  /* 0, because always do pthread_kill() next */

    shutting_down = true;
    status = pthread_kill(sig_listen_thread_id, SIGINT);
    if (0 != status) err_exit(status, "pthread_kill");
    /* valgrind says the above _kill() leaks; web says it needs a following
     * _join() to clear heap taken by associated _create() */

fini:
    if (STDIN_FILENO != clp->infd)
        close(clp->infd);
    if ((STDOUT_FILENO != clp->outfd) && (FT_DEV_NULL != clp->out_type))
        close(clp->outfd);
    res = exit_status;
    if ((0 != clp->out_count) && (0 == clp->dry_run)) {
        pr2serr(">>>> Some error occurred, remaining blocks=%" PRId64 "\n",
                clp->out_count);
        if (0 == res)
            res = SG_LIB_CAT_OTHER;
    }
    print_stats("");
    if (clp->dio_incomplete_count) {
        int fd;
        char c;

        pr2serr(">> Direct IO requested but incomplete %d times\n",
                clp->dio_incomplete_count);
        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    pr2serr(">>> %s set to '0' but should be set to '1' for "
                            "direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    }
    if (clp->sum_of_resids)
        pr2serr(">> Non-zero sum of residual counts=%d\n",
               clp->sum_of_resids);
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}
