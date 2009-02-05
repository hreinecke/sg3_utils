#define _XOPEN_SOURCE 500
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <linux/major.h>
#include <linux/fs.h>   /* <sys/mount.h> */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_io_linux.h"

/* A utility program for copying files. Specialised for "files" that
*  represent devices that understand the SCSI command set.
*
*  Copyright (C) 1999 - 2007 D. Gilbert and P. Allworth
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program is a specialisation of the Unix "dd" command in which
   one or both of the given files is a scsi generic device or a raw
   device. A block size ('bs') is assumed to be 512 if not given. This
   program complains if 'ibs' or 'obs' are given with some other value
   than 'bs'. If 'if' is not given or 'if=-' then stdin is assumed. If
   'of' is not given or 'of=-' then stdout assumed.

   A non-standard argument "bpt" (blocks per transfer) is added to control
   the maximum number of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16 KiB
   in this case) are transferred to or from the sg device in a single SCSI
   command.

   This version is designed for the linux kernel 2.4 and 2.6 series.

*/

static char * version_str = "5.40 20090205";

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_BLOCKS_PER_2048TRANSFER 32
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define ME "sgp_dd: "

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

#ifndef SERVICE_ACTION_IN
#define SERVICE_ACTION_IN     0x9e
#endif
#ifndef SAI_READ_CAPACITY_16
#define SAI_READ_CAPACITY_16  0x10
#endif

#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define SGP_READ10 0x28
#define SGP_WRITE10 0x2a
#define DEF_NUM_THREADS 4
#define MAX_NUM_THREADS SG_MAX_QUEUE

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

#define EBUFF_SZ 512

struct flags_t {
    int append;
    int coe;
    int dio;
    int direct;
    int dpo;
    int dsync;
    int excl;
    int fua;
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
    int in_stop;                      /*  | */
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
    int out_stop;                     /*  | */
    pthread_mutex_t out_mutex;        /*  | */
    pthread_cond_t out_sync_cv;       /* -/ hold writes until "in order" */
    int bs;
    int bpt;
    int dio_incomplete;         /* -\ */
    int sum_of_resids;          /*  | */
    pthread_mutex_t aux_mutex;  /* -/ (also serializes some printf()s */
    int debug;
} Rq_coll;

typedef struct request_element
{       /* one instance per worker thread */
    int infd;
    int outfd;
    int wr;
    int64_t blk;
    int num_blks;
    unsigned char * buffp;
    unsigned char * alloc_bp;
    struct sg_io_hdr io_hdr;
    unsigned char cmd[MAX_SCSI_CDBSZ];
    unsigned char sb[SENSE_BUFF_LEN];
    int bs;
    int dio_incomplete;
    int resid;
    int cdbsz_in;
    int cdbsz_out;
    struct flags_t in_flags;
    struct flags_t out_flags;
    int debug;
} Rq_elem;

static sigset_t signal_set;
static pthread_t sig_listen_thread_id;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

static void sg_in_operation(Rq_coll * clp, Rq_elem * rep);
static void sg_out_operation(Rq_coll * clp, Rq_elem * rep);
static int normal_in_operation(Rq_coll * clp, Rq_elem * rep, int blocks);
static void normal_out_operation(Rq_coll * clp, Rq_elem * rep, int blocks);
static int sg_start_io(Rq_elem * rep);
static int sg_finish_io(int wr, Rq_elem * rep, pthread_mutex_t * a_mutp);

#define STRERR_BUFF_LEN 128

static pthread_mutex_t strerr_mut = PTHREAD_MUTEX_INITIALIZER;

static int do_time = 0;
static Rq_coll rcoll;
static struct timeval start_tm;
static int64_t dd_count = -1;
static int num_threads = DEF_NUM_THREADS;
static int do_sync = 0;
static int exit_status = 0;


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
    fprintf(stderr, "time to transfer data %s %d.%06d secs",
            (contin ? "so far" : "was"), (int)res_tm.tv_sec,
            (int)res_tm.tv_usec);
    if ((a > 0.00001) && (b > 511))
        fprintf(stderr, ", %.2f MB/sec\n", b / (a * 1000000.0));
    else
        fprintf(stderr, "\n");
}

static void
print_stats(const char * str)
{
    int64_t infull, outfull;

    if (0 != rcoll.out_rem_count)
        fprintf(stderr, "  remaining block count=%"PRId64"\n",
                rcoll.out_rem_count);
    infull = dd_count - rcoll.in_rem_count;
    fprintf(stderr, "%s%"PRId64"+%d records in\n", str, infull - rcoll.in_partial,
            rcoll.in_partial);

    outfull = dd_count - rcoll.out_rem_count;
    fprintf(stderr, "%s%"PRId64"+%d records out\n", str,
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
    fprintf(stderr, "Interrupted by signal,");
    if (do_time)
        calc_duration_throughput(0);
    print_stats("");
    kill(getpid (), sig);
}

static void
siginfo_handler(int sig)
{
    sig = sig;  /* dummy to stop -W warning messages */
    fprintf(stderr, "Progress report, continuing ...\n");
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
   ISBN 0-201-63392-2 . [Highly recommended book.] */
#define err_exit(code,text) do { \
    char strerr_buff[STRERR_BUFF_LEN]; \
    fprintf(stderr, "%s at \"%s\":%d: %s\n", \
        text, __FILE__, __LINE__, tsafe_strerror(code, strerr_buff)); \
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
   fprintf(stderr, "Usage: "
           "sgp_dd  [bs=BS] [count=COUNT] [ibs=BS] [if=IFILE]"
           " [iflag=FLAGS]\n"
           "               [obs=BS] [of=OFILE] [oflag=FLAGS] "
           "[seek=SEEK] [skip=SKIP]\n"
           "               [--help] [--version]\n\n");
    fprintf(stderr,
           "               [bpt=BPT] [cdbsz=6|10|12|16] [coe=0|1] "
           "[deb=VERB] [dio=0|1]\n"
           "               [fua=0|1|2|3] [sync=0|1] [thr=THR] "
           "[time=0|1] [verbose=VERB]\n"
           "  where:\n"
           "    bpt         is blocks_per_transfer (default is 128)\n"
           "    bs          must be device block size (default 512)\n"
           "    cdbsz       size of SCSI READ or WRITE cdb (default is 10)\n"
           "    coe         continue on error, 0->exit (def), "
           "1->zero + continue\n"
           "    count       number of blocks to copy (def: device size)\n"
           "    deb         for debug, 0->none (def), > 0->varying degrees of "
           "debug\n");
    fprintf(stderr,
           "    dio         is direct IO, 1->attempt, 0->indirect IO (def)\n"
           "    fua         force unit access: 0->don't(def), 1->OFILE, "
           "2->IFILE,\n"
           "                3->OFILE+IFILE\n"
           "    if          file or device to read from (def: stdin)\n"
           "    iflag       comma separated list from: [coe,dio,direct,dpo,"
           "dsync,excl,\n"
           "                fua, null]\n"
           "    of          file or device to write to (def: stdout), "
           "OFILE of '.'\n"
           "                treated as /dev/null\n"
           "    oflag       comma separated list from: [append,coe,dio,direct,"
           "dpo,dsync,\n"
           "                excl,fua,null]\n"
           "    sync        0->no sync(def), 1->SYNCHRONIZE CACHE on OFILE "
           "after copy\n"
           "    thr         is number of threads, must be > 0, default 4, "
           "max 16\n"
           "    time        0->no timing(def), 1->time plus calculate "
           "throughput\n"
           "    verbose     same as 'deb=VERB': increase verbosity\n"
           "    --help      output this usage message then exit\n"
           "    --version   output version string then exit\n"
           "Copy from IFILE to OFILE, similar to dd command\n"
           "specialized for SCSI devices, uses multiple POSIX threads\n");
}

static void
guarded_stop_in(Rq_coll * clp)
{
    pthread_mutex_lock(&clp->in_mutex);
    clp->in_stop = 1;
    pthread_mutex_unlock(&clp->in_mutex);
}

static void
guarded_stop_out(Rq_coll * clp)
{
    pthread_mutex_lock(&clp->out_mutex);
    clp->out_stop = 1;
    pthread_mutex_unlock(&clp->out_mutex);
}

static void
guarded_stop_both(Rq_coll * clp)
{
    guarded_stop_in(clp);
    guarded_stop_out(clp);
}

/* Return of 0 -> success, see sg_ll_read_capacity*() otherwise */
static int
scsi_read_capacity(int sg_fd, int64_t * num_sect, int * sect_sz)
{
    int k, res;
    unsigned int ui;
    unsigned char rcBuff[RCAP16_REPLY_LEN];

    res = sg_ll_readcap_10(sg_fd, 0, 0, rcBuff, READ_CAP_REPLY_LEN, 0, 0);
    if (0 != res)
        return res;

    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3])) {
        int64_t ls;

        res = sg_ll_readcap_16(sg_fd, 0, 0, rcBuff, RCAP16_REPLY_LEN, 0, 0);
        if (0 != res)
            return res;
        for (k = 0, ls = 0; k < 8; ++k) {
            ls <<= 8;
            ls |= rcBuff[k];
        }
        *num_sect = ls + 1;
        *sect_sz = (rcBuff[8] << 24) | (rcBuff[9] << 16) |
                   (rcBuff[10] << 8) | rcBuff[11];
    } else {
        ui = ((rcBuff[0] << 24) | (rcBuff[1] << 16) | (rcBuff[2] << 8) |
              rcBuff[3]);
        /* take care not to sign extend values > 0x7fffffff */
        *num_sect = (int64_t)ui + 1;
        *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
                   (rcBuff[6] << 8) | rcBuff[7];
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
        if (SIGINT == sig_number) {
            fprintf(stderr, ME "interrupted by SIGINT\n");
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

    fprintf(stderr, "thread cancelled while in mutex held\n");
    clp->in_stop = 1;
    pthread_mutex_unlock(&clp->in_mutex);
    guarded_stop_out(clp);
    pthread_cond_broadcast(&clp->out_sync_cv);
}

static void
cleanup_out(void * v_clp)
{
    Rq_coll * clp = (Rq_coll *)v_clp;

    fprintf(stderr, "thread cancelled while out mutex held\n");
    clp->out_stop = 1;
    pthread_mutex_unlock(&clp->out_mutex);
    guarded_stop_in(clp);
    pthread_cond_broadcast(&clp->out_sync_cv);
}

static void *
read_write_thread(void * v_clp)
{
    Rq_coll * clp;
    Rq_elem rel;
    Rq_elem * rep = &rel;
    size_t psz = 0;
    int sz;
    volatile int stop_after_write = 0;
    int64_t seek_skip;
    int blocks, status;

    clp = (Rq_coll *)v_clp;
    sz = clp->bpt * clp->bs;
    seek_skip =  clp->seek - clp->skip;
    memset(rep, 0, sizeof(Rq_elem));
    psz = getpagesize();
    if (NULL == (rep->alloc_bp = (unsigned char *)malloc(sz + psz)))
        err_exit(ENOMEM, "out of memory creating user buffers\n");
    rep->buffp = (unsigned char *)(((unsigned long)rep->alloc_bp + psz - 1) &
                                   (~(psz - 1)));
    /* Follow clp members are constant during lifetime of thread */
    rep->bs = clp->bs;
    rep->infd = clp->infd;
    rep->outfd = clp->outfd;
    rep->debug = clp->debug;
    rep->cdbsz_in = clp->cdbsz_in;
    rep->cdbsz_out = clp->cdbsz_out;
    rep->in_flags = clp->in_flags;
    rep->out_flags = clp->out_flags;

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
        rep->wr = 0;
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
                clp->out_stop = 1;
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
            break;
        }
        if (stop_after_write)
            clp->out_stop = 1;
        rep->wr = 1;
        rep->blk = clp->out_blk;
        clp->out_blk += blocks;
        clp->out_count -= blocks;

        if (0 == rep->num_blks) {
            clp->out_stop = 1;
            stop_after_write = 1;
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
    if (rep->alloc_bp) free(rep->alloc_bp);
    status = pthread_mutex_lock(&clp->in_mutex);
    if (0 != status) err_exit(status, "lock in_mutex");
    if (! clp->in_stop)
        clp->in_stop = 1;  /* flag other workers to stop */
    status = pthread_mutex_unlock(&clp->in_mutex);
    if (0 != status) err_exit(status, "unlock in_mutex");
    pthread_cond_broadcast(&clp->out_sync_cv);
    return stop_after_write ? NULL : clp;
}

static int
normal_in_operation(Rq_coll * clp, Rq_elem * rep, int blocks)
{
    int res;
    int stop_after_write = 0;
    char strerr_buff[STRERR_BUFF_LEN];

    /* enters holding in_mutex */
    while (((res = read(clp->infd, rep->buffp,
                        blocks * clp->bs)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (clp->in_flags.coe) {
            memset(rep->buffp, 0, rep->num_blks * rep->bs);
            fprintf(stderr, ">> substituted zeros for in blk=%"PRId64" for "
                    "%d bytes, %s\n", rep->blk,
                    rep->num_blks * rep->bs,
                    tsafe_strerror(errno, strerr_buff));
            res = rep->num_blks * clp->bs;
        }
        else {
            fprintf(stderr, "error in normal read, %s\n",
                    tsafe_strerror(errno, strerr_buff));
            clp->in_stop = 1;
            guarded_stop_out(clp);
            return 1;
        }
    }
    if (res < blocks * clp->bs) {
        int o_blocks = blocks;
        stop_after_write = 1;
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
    while (((res = write(clp->outfd, rep->buffp,
                 rep->num_blks * clp->bs)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (clp->out_flags.coe) {
            fprintf(stderr, ">> ignored error for out blk=%"PRId64" for "
                    "%d bytes, %s\n", rep->blk,
                    rep->num_blks * rep->bs,
                    tsafe_strerror(errno, strerr_buff));
            res = rep->num_blks * clp->bs;
        }
        else {
            fprintf(stderr, "error normal write, %s\n",
                    tsafe_strerror(errno, strerr_buff));
            guarded_stop_in(clp);
            clp->out_stop = 1;
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
sg_build_scsi_cdb(unsigned char * cdbp, int cdb_sz, unsigned int blocks,
                  int64_t start_block, int write_true, int fua, int dpo)
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
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[1] = (unsigned char)((start_block >> 16) & 0x1f);
        cdbp[2] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[3] = (unsigned char)(start_block & 0xff);
        cdbp[4] = (256 == blocks) ? 0 : (unsigned char)blocks;
        if (blocks > 256) {
            fprintf(stderr, ME "for 6 byte commands, maximum number of "
                            "blocks is 256\n");
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            fprintf(stderr, ME "for 6 byte commands, can't address blocks"
                            " beyond %d\n", 0x1fffff);
            return 1;
        }
        if (dpo || fua) {
            fprintf(stderr, ME "for 6 byte commands, neither dpo nor fua"
                            " bits supported\n");
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[8] = (unsigned char)(blocks & 0xff);
        if (blocks & (~0xffff)) {
            fprintf(stderr, ME "for 10 byte commands, maximum number of "
                            "blocks is %d\n", 0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[6] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[8] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[9] = (unsigned char)(blocks & 0xff);
        break;
    case 16:
        sz_ind = 3;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 56) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 48) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 40) & 0xff);
        cdbp[5] = (unsigned char)((start_block >> 32) & 0xff);
        cdbp[6] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[7] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[8] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[9] = (unsigned char)(start_block & 0xff);
        cdbp[10] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[11] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[12] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[13] = (unsigned char)(blocks & 0xff);
        break;
    default:
        fprintf(stderr, ME "expected cdb size of 6, 10, 12, or 16 but got"
                        " %d\n", cdb_sz);
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
            fprintf(stderr, ME "inputting to sg failed, blk=%"PRId64"\n",
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
                fprintf(stderr, "error finishing sg in command (medium)\n");
                if (exit_status <= 0)
                    exit_status = res;
                guarded_stop_both(clp);
                return;
            } else {
                memset(rep->buffp, 0, rep->num_blks * rep->bs);
                fprintf(stderr, ">> substituted zeros for in blk=%"PRId64" for "
                        "%d bytes\n", rep->blk, rep->num_blks * rep->bs);
            }
            /* fall through */
        case 0:
            if (rep->dio_incomplete || rep->resid) {
                status = pthread_mutex_lock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "lock aux_mutex");
                clp->dio_incomplete += rep->dio_incomplete;
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
            fprintf(stderr, "error finishing sg in command (%d)\n", res);
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
            fprintf(stderr, ME "outputting from sg failed, blk=%"PRId64"\n",
                    rep->blk);
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
                fprintf(stderr, "error finishing sg out command (medium)\n");
                if (exit_status <= 0)
                    exit_status = res;
                guarded_stop_both(clp);
                return;
            } else
                fprintf(stderr, ">> ignored error for out blk=%"PRId64" for "
                        "%d bytes\n", rep->blk, rep->num_blks * rep->bs);
            /* fall through */
        case 0:
            if (rep->dio_incomplete || rep->resid) {
                status = pthread_mutex_lock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "lock aux_mutex");
                clp->dio_incomplete += rep->dio_incomplete;
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
            fprintf(stderr, "error finishing sg out command (%d)\n", res);
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
    int fua = rep->wr ? rep->out_flags.fua : rep->in_flags.fua;
    int dpo = rep->wr ? rep->out_flags.dpo : rep->in_flags.dpo;
    int dio = rep->wr ? rep->out_flags.dio : rep->in_flags.dio;
    int cdbsz = rep->wr ? rep->cdbsz_out : rep->cdbsz_in;
    int res;

    if (sg_build_scsi_cdb(rep->cmd, cdbsz, rep->num_blks, rep->blk,
                          rep->wr, fua, dpo)) {
        fprintf(stderr, ME "bad cdb build, start_blk=%"PRId64", blocks=%d\n",
                rep->blk, rep->num_blks);
        return -1;
    }
    memset(hp, 0, sizeof(struct sg_io_hdr));
    hp->interface_id = 'S';
    hp->cmd_len = cdbsz;
    hp->cmdp = rep->cmd;
    hp->dxfer_direction = rep->wr ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    hp->dxfer_len = rep->bs * rep->num_blks;
    hp->dxferp = rep->buffp;
    hp->mx_sb_len = sizeof(rep->sb);
    hp->sbp = rep->sb;
    hp->timeout = DEF_TIMEOUT;
    hp->usr_ptr = rep;
    hp->pack_id = (int)rep->blk;
    if (dio)
        hp->flags |= SG_FLAG_DIRECT_IO;
    if (rep->debug > 8) {
        fprintf(stderr, "sg_start_io: SCSI %s, blk=%"PRId64" num_blks=%d\n",
               rep->wr ? "WRITE" : "READ", rep->blk, rep->num_blks);
        sg_print_command(hp->cmdp);
    }

    while (((res = write(rep->wr ? rep->outfd : rep->infd, hp,
                         sizeof(struct sg_io_hdr))) < 0) && (EINTR == errno))
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
sg_finish_io(int wr, Rq_elem * rep, pthread_mutex_t * a_mutp)
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
    io_hdr.pack_id = (int)rep->blk;

    while (((res = read(wr ? rep->outfd : rep->infd, &io_hdr,
                        sizeof(struct sg_io_hdr))) < 0) && (EINTR == errno))
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
                                       "reading continuing"), hp, 0);
            break;
        case SG_LIB_CAT_ABORTED_COMMAND:
        case SG_LIB_CAT_UNIT_ATTENTION:
            if (rep->debug > 8)
                sg_chk_n_print3((wr ? "writing": "reading"), hp, 0);
            return res;
        case SG_LIB_CAT_NOT_READY:
        default:
            {
                char ebuff[EBUFF_SZ];

                snprintf(ebuff, EBUFF_SZ, "%s blk=%"PRId64,
                         wr ? "writing": "reading", rep->blk);
                status = pthread_mutex_lock(a_mutp);
                if (0 != status) err_exit(status, "lock aux_mutex");
                sg_chk_n_print3(ebuff, hp, 0);
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
        rep->dio_incomplete = 1; /* count dios done as indirect IO */
    else
        rep->dio_incomplete = 0;
    rep->resid = hp->resid;
    if (rep->debug > 8)
        fprintf(stderr, "sg_finish_io: completed %s\n", wr ? "WRITE" : "READ");
    return 0;
}

static int
sg_prepare(int fd, int bs, int bpt)
{
    int res, t;

    res = ioctl(fd, SG_GET_VERSION_NUM, &t);
    if ((res < 0) || (t < 30000)) {
        fprintf(stderr, ME "sg driver prior to 3.x.y\n");
        return 1;
    }
    res = 0;
    t = bs * bpt;
    res = ioctl(fd, SG_SET_RESERVED_SIZE, &t);
    if (res < 0)
        perror(ME "SG_SET_RESERVED_SIZE error");
    t = 1;
    res = ioctl(fd, SG_SET_FORCE_PACK_ID, &t);
    if (res < 0)
        perror(ME "SG_SET_FORCE_PACK_ID error");
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
        fprintf(stderr, "no flag found\n");
        return 1;
    }
    cp = buff;
    do {
        np = strchr(cp, ',');
        if (np)
            *np++ = '\0';
        if (0 == strcmp(cp, "append"))
            fp->append = 1;
        else if (0 == strcmp(cp, "coe"))
            fp->coe = 1;
        else if (0 == strcmp(cp, "dio"))
            fp->dio = 1;
        else if (0 == strcmp(cp, "direct"))
            fp->direct = 1;
        else if (0 == strcmp(cp, "dpo"))
            fp->dpo = 1;
        else if (0 == strcmp(cp, "dsync"))
            fp->dsync = 1;
        else if (0 == strcmp(cp, "excl"))
            fp->excl = 1;
        else if (0 == strcmp(cp, "fua"))
            fp->fua = 1;
        else if (0 == strcmp(cp, "null"))
            ;
        else {
            fprintf(stderr, "unrecognised flag: %s\n", cp);
            return 1;
        }
        cp = np;
    } while (cp);
    return 0;
}


#define STR_SZ 1024
#define INOUTF_SZ 512


int
main(int argc, char * argv[])
{
    int64_t skip = 0;
    int64_t seek = 0;
    int ibs = 0;
    int obs = 0;
    int bpt_given = 0;
    int cdbsz_given = 0;
    char str[STR_SZ];
    char * key;
    char * buf;
    char inf[INOUTF_SZ];
    char outf[INOUTF_SZ];
    int res, k;
    int64_t in_num_sect = 0;
    int64_t out_num_sect = 0;
    pthread_t threads[MAX_NUM_THREADS];
    int in_sect_sz, out_sect_sz, status, n, flags;
    void * vp;
    char ebuff[EBUFF_SZ];

    memset(&rcoll, 0, sizeof(Rq_coll));
    rcoll.bpt = DEF_BLOCKS_PER_TRANSFER;
    rcoll.in_type = FT_OTHER;
    rcoll.out_type = FT_OTHER;
    rcoll.cdbsz_in = DEF_SCSI_CDBSZ;
    rcoll.cdbsz_out = DEF_SCSI_CDBSZ;
    inf[0] = '\0';
    outf[0] = '\0';

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
        if (0 == strcmp(key,"bpt")) {
            rcoll.bpt = sg_get_num(buf);
            if (-1 == rcoll.bpt) {
                fprintf(stderr, ME "bad argument to 'bpt='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            bpt_given = 1;
        } else if (0 == strcmp(key,"bs")) {
            rcoll.bs = sg_get_num(buf);
            if (-1 == rcoll.bs) {
                fprintf(stderr, ME "bad argument to 'bs='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"cdbsz")) {
            rcoll.cdbsz_in = sg_get_num(buf);
            rcoll.cdbsz_out = rcoll.cdbsz_in;
            cdbsz_given = 1;
        } else if (0 == strcmp(key,"coe")) {
            rcoll.in_flags.coe = sg_get_num(buf);
            rcoll.out_flags.coe = rcoll.in_flags.coe;
        } else if (0 == strcmp(key,"count")) {
            if (0 != strcmp("-1", buf)) {
                dd_count = sg_get_llnum(buf);
                if (-1LL == dd_count) {
                    fprintf(stderr, ME "bad argument to 'count='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            }   /* treat 'count=-1' as calculate count (same as not given) */
        } else if ((0 == strncmp(key,"deb", 3)) ||
                   (0 == strncmp(key,"verb", 4)))
            rcoll.debug = sg_get_num(buf);
        else if (0 == strcmp(key,"dio")) {
            rcoll.in_flags.dio = sg_get_num(buf);
            rcoll.out_flags.dio = rcoll.in_flags.dio;
        } else if (0 == strcmp(key,"fua")) {
            n = sg_get_num(buf);
            if (n & 1)
                rcoll.out_flags.fua = 1;
            if (n & 2)
                rcoll.in_flags.fua = 1;
        } else if (0 == strcmp(key,"ibs")) {
            ibs = sg_get_num(buf);
            if (-1 == ibs) {
                fprintf(stderr, ME "bad argument to 'ibs='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"if") == 0) {
            if ('\0' != inf[0]) {
                fprintf(stderr, "Second 'if=' argument??\n");
                return SG_LIB_SYNTAX_ERROR;
            } else
                strncpy(inf, buf, INOUTF_SZ);
        } else if (0 == strcmp(key, "iflag")) {
            if (process_flags(buf, &rcoll.in_flags)) {
                fprintf(stderr, ME "bad argument to 'iflag='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"obs")) {
            obs = sg_get_num(buf);
            if (-1 == obs) {
                fprintf(stderr, ME "bad argument to 'obs='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"of") == 0) {
            if ('\0' != outf[0]) {
                fprintf(stderr, "Second 'of=' argument??\n");
                return SG_LIB_SYNTAX_ERROR;
            } else
                strncpy(outf, buf, INOUTF_SZ);
        } else if (0 == strcmp(key, "oflag")) {
            if (process_flags(buf, &rcoll.out_flags)) {
                fprintf(stderr, ME "bad argument to 'oflag='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"seek")) {
            seek = sg_get_llnum(buf);
            if (-1LL == seek) {
                fprintf(stderr, ME "bad argument to 'seek='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"skip")) {
            skip = sg_get_llnum(buf);
            if (-1LL == skip) {
                fprintf(stderr, ME "bad argument to 'skip='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"sync"))
            do_sync = sg_get_num(buf);
        else if (0 == strcmp(key,"thr"))
            num_threads = sg_get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = sg_get_num(buf);
        else if ((0 == strncmp(key, "--help", 7)) ||
                 (0 == strcmp(key, "-?"))) {
            usage();
            return 0;
        } else if ((0 == strncmp(key, "--vers", 6)) ||
                   (0 == strcmp(key, "-V"))) {
            fprintf(stderr, ME ": %s\n",
                    version_str);
            return 0;
        }
        else {
            fprintf(stderr, "Unrecognized option '%s'\n", key);
            fprintf(stderr, "For more information use '--help'\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (rcoll.bs <= 0) {
        rcoll.bs = DEF_BLOCK_SIZE;
        fprintf(stderr, "Assume default 'bs' (block size) of %d bytes\n",
                rcoll.bs);
    }
    if ((ibs && (ibs != rcoll.bs)) || (obs && (obs != rcoll.bs))) {
        fprintf(stderr, "If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((skip < 0) || (seek < 0)) {
        fprintf(stderr, "skip and seek cannot be negative\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((rcoll.out_flags.append > 0) && (seek > 0)) {
        fprintf(stderr, "Can't use both append and seek switches\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (rcoll.bpt < 1) {
        fprintf(stderr, "bpt must be greater than 0\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    /* defaulting transfer size to 128*2048 for CD/DVDs is too large
       for the block layer in lk 2.6 and results in an EIO on the
       SG_IO ioctl. So reduce it in that case. */
    if ((rcoll.bs >= 2048) && (0 == bpt_given))
        rcoll.bpt = DEF_BLOCKS_PER_2048TRANSFER;
    if ((num_threads < 1) || (num_threads > MAX_NUM_THREADS)) {
        fprintf(stderr, "too few or too many threads requested\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (rcoll.debug)
        fprintf(stderr, ME "if=%s skip=%"PRId64" of=%s seek=%"PRId64" count=%"PRId64"\n",
               inf, skip, outf, seek, dd_count);

    install_handler(SIGINT, interrupt_handler);
    install_handler(SIGQUIT, interrupt_handler);
    install_handler(SIGPIPE, interrupt_handler);
    install_handler(SIGUSR1, siginfo_handler);

    rcoll.infd = STDIN_FILENO;
    rcoll.outfd = STDOUT_FILENO;
    if (inf[0] && ('-' != inf[0])) {
        rcoll.in_type = dd_filetype(inf);

        if (FT_ERROR == rcoll.in_type) {
            fprintf(stderr, ME "unable to access %s\n", inf);
            return SG_LIB_FILE_ERROR;
        } else if (FT_ST == rcoll.in_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", inf);
            return SG_LIB_FILE_ERROR;
        } else if (FT_SG == rcoll.in_type) {
            flags = O_RDWR;
            if (rcoll.in_flags.direct)
                flags |= O_DIRECT;
            if (rcoll.in_flags.excl)
                flags |= O_EXCL;
            if (rcoll.in_flags.dsync)
                flags |= O_SYNC;

            if ((rcoll.infd = open(inf, flags)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for sg reading", inf);
                perror(ebuff);
                return SG_LIB_FILE_ERROR;
            }
            if (sg_prepare(rcoll.infd, rcoll.bs, rcoll.bpt))
                return SG_LIB_FILE_ERROR;
        }
        else {
            flags = O_RDONLY;
            if (rcoll.in_flags.direct)
                flags |= O_DIRECT;
            if (rcoll.in_flags.excl)
                flags |= O_EXCL;
            if (rcoll.in_flags.dsync)
                flags |= O_SYNC;

            if ((rcoll.infd = open(inf, flags)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", inf);
                perror(ebuff);
                return SG_LIB_FILE_ERROR;
            }
            else if (skip > 0) {
                off64_t offset = skip;

                offset *= rcoll.bs;       /* could exceed 32 here! */
                if (lseek64(rcoll.infd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                        ME "couldn't skip to required position on %s", inf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
            }
        }
    }
    if (outf[0] && ('-' != outf[0])) {
        rcoll.out_type = dd_filetype(outf);

        if (FT_ST == rcoll.out_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", outf);
            return SG_LIB_FILE_ERROR;
        }
        else if (FT_SG == rcoll.out_type) {
            flags = O_RDWR;
            if (rcoll.out_flags.direct)
                flags |= O_DIRECT;
            if (rcoll.out_flags.excl)
                flags |= O_EXCL;
            if (rcoll.out_flags.dsync)
                flags |= O_SYNC;

            if ((rcoll.outfd = open(outf, flags)) < 0) {
                snprintf(ebuff,  EBUFF_SZ,
                         ME "could not open %s for sg writing", outf);
                perror(ebuff);
                return SG_LIB_FILE_ERROR;
            }

            if (sg_prepare(rcoll.outfd, rcoll.bs, rcoll.bpt))
                return SG_LIB_FILE_ERROR;
        }
        else if (FT_DEV_NULL == rcoll.out_type)
            rcoll.outfd = -1; /* don't bother opening */
        else {
            if (FT_RAW != rcoll.out_type) {
                flags = O_WRONLY | O_CREAT;
                if (rcoll.out_flags.direct)
                    flags |= O_DIRECT;
                if (rcoll.out_flags.excl)
                    flags |= O_EXCL;
                if (rcoll.out_flags.dsync)
                    flags |= O_SYNC;
                if (rcoll.out_flags.append)
                    flags |= O_APPEND;

                if ((rcoll.outfd = open(outf, flags, 0666)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for writing", outf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
            }
            else {      /* raw output file */
                if ((rcoll.outfd = open(outf, O_WRONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for raw writing", outf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
            }
            if (seek > 0) {
                off64_t offset = seek;

                offset *= rcoll.bs;       /* could exceed 32 bits here! */
                if (lseek64(rcoll.outfd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                        ME "couldn't seek to required position on %s", outf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
            }
        }
    }
    if ((STDIN_FILENO == rcoll.infd) && (STDOUT_FILENO == rcoll.outfd)) {
        fprintf(stderr, "Won't default both IFILE to stdin _and_ OFILE to "
                "stdout\n");
        fprintf(stderr, "For more information use '--help'\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (dd_count < 0) {
        in_num_sect = -1;
        if (FT_SG == rcoll.in_type) {
            res = scsi_read_capacity(rcoll.infd, &in_num_sect, &in_sect_sz);
            if (2 == res) {
                fprintf(stderr,
                        "Unit attention, media changed(in), continuing\n");
                res = scsi_read_capacity(rcoll.infd, &in_num_sect,
                                         &in_sect_sz);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    fprintf(stderr, "read capacity not supported on %s\n",
                            inf);
                else if (res == SG_LIB_CAT_NOT_READY)
                    fprintf(stderr, "read capacity failed, %s not ready\n",
                            inf);
                else
                    fprintf(stderr, "Unable to read capacity on %s\n", inf);
                in_num_sect = -1;
            }
        } else if (FT_BLOCK == rcoll.in_type) {
            if (0 != read_blkdev_capacity(rcoll.infd, &in_num_sect,
                                          &in_sect_sz)) {
                fprintf(stderr, "Unable to read block capacity on %s\n", inf);
                in_num_sect = -1;
            }
            if (rcoll.bs != in_sect_sz) {
                fprintf(stderr, "block size on %s confusion; bs=%d, from "
                        "device=%d\n", inf, rcoll.bs, in_sect_sz);
                in_num_sect = -1;
            }
        }
        if (in_num_sect > skip)
            in_num_sect -= skip;

        out_num_sect = -1;
        if (FT_SG == rcoll.out_type) {
            res = scsi_read_capacity(rcoll.outfd, &out_num_sect, &out_sect_sz);
            if (2 == res) {
                fprintf(stderr,
                        "Unit attention, media changed(out), continuing\n");
                res = scsi_read_capacity(rcoll.outfd, &out_num_sect,
                                         &out_sect_sz);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    fprintf(stderr, "read capacity not supported on %s\n",
                            outf);
                else if (res == SG_LIB_CAT_NOT_READY)
                    fprintf(stderr, "read capacity failed, %s not ready\n",
                            outf);
                else
                    fprintf(stderr, "Unable to read capacity on %s\n", outf);
                out_num_sect = -1;
            }
        } else if (FT_BLOCK == rcoll.out_type) {
            if (0 != read_blkdev_capacity(rcoll.outfd, &out_num_sect,
                                          &out_sect_sz)) {
                fprintf(stderr, "Unable to read block capacity on %s\n",
                        outf);
                out_num_sect = -1;
            }
            if (rcoll.bs != out_sect_sz) {
                fprintf(stderr, "block size on %s confusion: bs=%d, from "
                        "device=%d\n", outf, rcoll.bs, out_sect_sz);
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
    if (rcoll.debug > 1)
        fprintf(stderr, "Start of loop, count=%"PRId64", in_num_sect=%"PRId64", "
                "out_num_sect=%"PRId64"\n", dd_count, in_num_sect, out_num_sect);
    if (dd_count < 0) {
        fprintf(stderr, "Couldn't calculate count, please give one\n");
        return SG_LIB_CAT_OTHER;
    }
    if (! cdbsz_given) {
        if ((FT_SG == rcoll.in_type) && (MAX_SCSI_CDBSZ != rcoll.cdbsz_in) &&
            (((dd_count + skip) > UINT_MAX) || (rcoll.bpt > USHRT_MAX))) {
            fprintf(stderr, "Note: SCSI command size increased to 16 bytes "
                    "(for 'if')\n");
            rcoll.cdbsz_in = MAX_SCSI_CDBSZ;
        }
        if ((FT_SG == rcoll.out_type) && (MAX_SCSI_CDBSZ != rcoll.cdbsz_out) &&
            (((dd_count + seek) > UINT_MAX) || (rcoll.bpt > USHRT_MAX))) {
            fprintf(stderr, "Note: SCSI command size increased to 16 bytes "
                    "(for 'of')\n");
            rcoll.cdbsz_out = MAX_SCSI_CDBSZ;
        }
    }

    rcoll.in_count = dd_count;
    rcoll.in_rem_count = dd_count;
    rcoll.skip = skip;
    rcoll.in_blk = skip;
    rcoll.out_count = dd_count;
    rcoll.out_rem_count = dd_count;
    rcoll.seek = seek;
    rcoll.out_blk = seek;
    status = pthread_mutex_init(&rcoll.in_mutex, NULL);
    if (0 != status) err_exit(status, "init in_mutex");
    status = pthread_mutex_init(&rcoll.out_mutex, NULL);
    if (0 != status) err_exit(status, "init out_mutex");
    status = pthread_mutex_init(&rcoll.aux_mutex, NULL);
    if (0 != status) err_exit(status, "init aux_mutex");
    status = pthread_cond_init(&rcoll.out_sync_cv, NULL);
    if (0 != status) err_exit(status, "init out_sync_cv");

    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    status = pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
    if (0 != status) err_exit(status, "pthread_sigmask");
    status = pthread_create(&sig_listen_thread_id, NULL,
                            sig_listen_thread, (void *)&rcoll);
    if (0 != status) err_exit(status, "pthread_create, sig...");

    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }

/* vvvvvvvvvvv  Start worker threads  vvvvvvvvvvvvvvvvvvvvvvvv */
    if ((rcoll.out_rem_count > 0) && (num_threads > 0)) {
        /* Run 1 work thread to shake down infant retryable stuff */
        status = pthread_mutex_lock(&rcoll.out_mutex);
        if (0 != status) err_exit(status, "lock out_mutex");
        status = pthread_create(&threads[0], NULL, read_write_thread,
                                (void *)&rcoll);
        if (0 != status) err_exit(status, "pthread_create");
        if (rcoll.debug)
            fprintf(stderr, "Starting worker thread k=0\n");

        /* wait for any broadcast */
        pthread_cleanup_push(cleanup_out, (void *)&rcoll);
        status = pthread_cond_wait(&rcoll.out_sync_cv, &rcoll.out_mutex);
        if (0 != status) err_exit(status, "cond out_sync_cv");
        pthread_cleanup_pop(0);
        status = pthread_mutex_unlock(&rcoll.out_mutex);
        if (0 != status) err_exit(status, "unlock out_mutex");

        /* now start the rest of the threads */
        for (k = 1; k < num_threads; ++k) {
            status = pthread_create(&threads[k], NULL, read_write_thread,
                                    (void *)&rcoll);
            if (0 != status) err_exit(status, "pthread_create");
            if (rcoll.debug)
                fprintf(stderr, "Starting worker thread k=%d\n", k);
        }

        /* now wait for worker threads to finish */
        for (k = 0; k < num_threads; ++k) {
            status = pthread_join(threads[k], &vp);
            if (0 != status) err_exit(status, "pthread_join");
            if (rcoll.debug)
                fprintf(stderr, "Worker thread k=%d terminated\n", k);
        }
    }

    if ((do_time) && (start_tm.tv_sec || start_tm.tv_usec))
        calc_duration_throughput(0);

    if (do_sync) {
        if (FT_SG == rcoll.out_type) {
            fprintf(stderr, ">> Synchronizing cache on %s\n", outf);
            res = sg_ll_sync_cache_10(rcoll.outfd, 0, 0, 0, 0, 0, 0, 0);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                fprintf(stderr,
                        "Unit attention(out), continuing\n");
                res = sg_ll_sync_cache_10(rcoll.outfd, 0, 0, 0, 0, 0, 0, 0);
            }
            if (0 != res)
                fprintf(stderr, "Unable to synchronize cache\n");
        }
    }

    status = pthread_cancel(sig_listen_thread_id);
    if (0 != status) err_exit(status, "pthread_cancel");
    if (STDIN_FILENO != rcoll.infd)
        close(rcoll.infd);
    if ((STDOUT_FILENO != rcoll.outfd) && (FT_DEV_NULL != rcoll.out_type))
        close(rcoll.outfd);
    res = exit_status;
    if (0 != rcoll.out_count) {
        fprintf(stderr, ">>>> Some error occurred, remaining blocks=%"PRId64"\n",
               rcoll.out_count);
        if (0 == res)
            res = SG_LIB_CAT_OTHER;
    }
    print_stats("");
    if (rcoll.dio_incomplete) {
        int fd;
        char c;

        fprintf(stderr, ">> Direct IO requested but incomplete %d times\n",
                rcoll.dio_incomplete);
        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    fprintf(stderr, ">>> %s set to '0' but should be set "
                            "to '1' for direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    }
    if (rcoll.sum_of_resids)
        fprintf(stderr, ">> Non-zero sum of residual counts=%d\n",
               rcoll.sum_of_resids);
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}
