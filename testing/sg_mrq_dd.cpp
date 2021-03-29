/*
 * A utility program for copying files. Specialised for "files" that
 * represent devices that understand the SCSI command set.
 *
 * Copyright (C) 2018-2021 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is a specialisation of the Unix "dd" command in which
 * one or both of the given files is a scsi generic device.
 * A logical block size ('bs') is assumed to be 512 if not given. This
 * program complains if 'ibs' or 'obs' are given with some other value
 * than 'bs'. If 'if' is not given or 'if=-' then stdin is assumed. If
 * 'of' is not given or 'of=-' then stdout assumed.
 *
 * A non-standard argument "bpt" (blocks per transfer) is added to control
 * the maximum number of blocks in each transfer. The default value is 128.
 * For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16 KiB
 * in this case) are transferred to or from the sg device in a single SCSI
 * command.
 *
 * This version is designed for the linux kernel 4 and 5 series.
 *
 * sg_mrq_dd uses C++ threads and MRQ (multiple requests (in one invocation))
 * facilities in the sg version 4 driver to do "dd" type copies and verifies.
 *
 */

static const char * version_str = "1.23 20210328";

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
#include <poll.h>
#include <limits.h>
// #include <pthread.h>
#include <signal.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#ifndef major
#include <sys/types.h>
#endif
#include <sys/time.h>
#include <linux/major.h>        /* for MEM_MAJOR, SCSI_GENERIC_MAJOR, etc */
#include <linux/fs.h>           /* for BLKSSZGET and friends */
#include <sys/mman.h>           /* for mmap() system call */

#include <vector>
#include <array>
#include <atomic>       // C++ header replacing <stdatomic.h>
#include <random>
#include <thread>       // needed for std::this_thread::yield()
#include <mutex>
#include <condition_variable>
#include <chrono>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_GETRANDOM
#include <sys/random.h>         /* for getrandom() system call */
#endif

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

// C++ local header
#include "sg_scat_gath.h"

// C headers associated with sg3_utils library
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"


using namespace std;

// #ifdef __GNUC__
// #ifndef  __clang__
// #pragma GCC diagnostic ignored "-Wclobbered"
// #endif
// #endif


#ifndef SGV4_FLAG_HIPRI
#define SGV4_FLAG_HIPRI 0x800
#endif

#define MAX_SGL_NUM_VAL (INT32_MAX - 1)  /* should reduce for testing */
// #define MAX_SGL_NUM_VAL 7  /* should reduce for testing */
#if MAX_SGL_NUM_VAL > INT32_MAX
#error "MAX_SGL_NUM_VAL cannot exceed 2^31 - 1"
#endif

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_BLOCKS_PER_2048TRANSFER 32
#define DEF_SCSI_CDB_SZ 10
#define MAX_SCSI_CDB_SZ 16      /* could be 32 */
#define PACK_ID_TID_MULTIPLIER (0x1000000)      /* 16,777,216 */

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define SGP_READ10 0x28
#define SGP_PRE_FETCH10 0x34
#define SGP_PRE_FETCH16 0x90
#define SGP_VERIFY10 0x2f
#define SGP_WRITE10 0x2a
#define DEF_NUM_THREADS 4
#define MAX_NUM_THREADS 1024 /* was SG_MAX_QUEUE with v3 driver */
#define DEF_MRQ_NUM 16
#define DEF_STALL_THRESH 4

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikely value */
#endif

#define FT_OTHER 1              /* filetype other than one of the following */
#define FT_SG 2                 /* filetype is sg char device */
#define FT_RAW 4                /* filetype is raw char device */
#define FT_DEV_NULL 8           /* either "/dev/null" or "." as filename */
#define FT_ST 16                /* filetype is st char device (tape) */
#define FT_BLOCK 32             /* filetype is a block device */
#define FT_FIFO 64              /* fifo (named or unnamed pipe (stdout)) */
#define FT_RANDOM_0_FF 128      /* iflag=00, iflag=ff and iflag=random
                                   override if=IFILE */
#define FT_ERROR 256            /* couldn't "stat" file */

#define DEV_NULL_MINOR_NUM 3

#define EBUFF_SZ 768

#define PROC_SCSI_SG_VERSION "/proc/scsi/sg/version"
#define SYS_SCSI_SG_VERSION "/sys/module/sg/version"


struct flags_t {
    bool append;
    bool coe;
    bool dio;
    bool direct;
    bool dpo;
    bool dsync;
    bool excl;
    bool ff;
    bool fua;
    bool hipri;
    bool masync;        /* more async sg v4 driver fd flag */
    bool no_dur;
    bool nocreat;
    bool order;
    bool qhead;
    bool qtail;
    bool random;
    bool serial;
    bool wq_excl;
    bool zero;
    int cdl;            /* command duration limits, 0 --> no cdl */
    int mmap;
};

typedef pair<int64_t, int> get_next_res;
typedef array<uint8_t, MAX_SCSI_CDB_SZ> cdb_arr_t;

/* There is one instance of this structure and it is at file scope so it is
 * initialized to zero. The design of this copy multi-threaded copy algorithm
 * attempts to have no locks on the fast path. Contention in gcoll.get_next()
 * is resolved by the loser repeating its operation. Statistics and error
 * information is held in each thread until it shuts down and contention
 * can occur at that point. */
struct global_collection        /* one instance visible to all threads */
{
    /* get_next() is the pivotal function for multi-threaded safety. It can
     * be safely called from all threads with the desired number of blocks
     * (typically mrq*bpt) and this function returns a pair. The first pair
     * value is the starting count value/index [0..dd_count) and the second
     * pair value is the number of blocks to copy. If desired_num_blks is
     * negative this flags an error has occurred. If the second value in the
     * returned pair is 0 then the calling thread should shutdown; a
     * negative value indicates an error has occurred (e.g. in another
     * thread) and the calling thread should shutdown. */
    get_next_res get_next(int desired_num_blks);
    atomic<int64_t> next_count_pos;

    int infd;
    int64_t dd_count;
    int in_type;
    int cdbsz_in;
    int help;
    struct flags_t in_flags;
    atomic<int64_t> in_rem_count;     /*  | count of remaining in blocks */
    atomic<int> in_partial;           /*  | */
    off_t in_st_size;                 /* Only for FT_OTHER (regular) file */
    int mrq_num;                      /* if user gives 0, set this to 1 */
    int outfd;
    int out_type;
    int cdbsz_out;
    struct flags_t out_flags;
    atomic<int64_t> out_rem_count;    /*  | count of remaining out blocks */
    atomic<int> out_partial;          /*  | */
    off_t out_st_size;                /* Only for FT_OTHER (regular) file */
    condition_variable infant_cv;     /* after thread:0 does first segment */
    mutex infant_mut;
    int bs;
    int bpt;
    int cmd_timeout;            /* in milliseconds */
    int elem_sz;
    int outregfd;
    int outreg_type;
    off_t outreg_st_size;
    atomic<int> dio_incomplete_count;
    atomic<int> sum_of_resids;
    atomic<int> reason_res;
    atomic<int> most_recent_pack_id;
    int verbose;
    int dry_run;
    bool mrq_eq_0;              /* true when user gives mrq=0 */
    bool processed;
    bool cdbsz_given;
    bool cdl_given;
    bool count_given;
    bool ese;
    bool flexible;
    bool mrq_hipri;
    bool ofile_given;
    bool unit_nanosec;          /* default duration unit is millisecond */
    bool no_waitq;              /* if set use polling for response instead */
    bool verify;                /* don't copy, verify like Unix: cmp */
    bool prefetch;              /* for verify: do PF(b),RD(a),V(b)_a_data */
    const char * infp;
    const char * outfp;
    class scat_gath_list i_sgl;
    class scat_gath_list o_sgl;
};

typedef struct request_element
{       /* one instance per worker thread */
    struct global_collection *clp;
    bool has_share;
    bool both_sg;
    bool same_sg;
    bool only_in_sg;
    bool only_out_sg;
    bool stop_after_write;
    bool stop_now;
    int id;
    int infd;
    int outfd;
    int outregfd;
    uint8_t * buffp;
    uint8_t * alloc_bp;
    struct sg_io_v4 io_hdr4[2];
    uint8_t cmd[MAX_SCSI_CDB_SZ];
    uint8_t sb[SENSE_BUFF_LEN];
    int dio_incomplete_count;
    int mmap_active;
    int rd_p_id;
    int rep_count;
    int rq_id;
    int mmap_len;
    int mrq_id;
    int mrq_index;
    int mrq_pack_id_off;
    int64_t in_follow_on;
    int64_t out_follow_on;
    int64_t in_local_count;
    int64_t out_local_count;
    int64_t in_rem_count;
    int64_t out_rem_count;
    int in_local_partial;
    int out_local_partial;
    int in_resid_bytes;
    long seed;
    struct drand48_data drand; /* opaque, used by srand48_r and mrand48_r */
} Rq_elem;

/* Additional parameters for sg_start_io() and sg_finish_io() */
struct sg_io_extra {
    bool prefetch;
    bool dout_is_split;
    int hpv4_ind;
    int blk_offset;
    int blks;
};

#define MONO_MRQ_ID_INIT 0x10000



/* Use this class to wrap C++11 <random> features to produce uniform random
 * unsigned ints in the range [lo, hi] (inclusive) given a_seed */
class Rand_uint {
public:
    Rand_uint(unsigned int lo, unsigned int hi, unsigned int a_seed)
        : uid(lo, hi), dre(a_seed) { }
    /* uid ctor takes inclusive range when integral type */

    unsigned int get() { return uid(dre); }

private:
    uniform_int_distribution<unsigned int> uid;
    default_random_engine dre;
};

static atomic<int> num_ebusy(0);
static atomic<int> num_start_eagain(0);
static atomic<int> num_fin_eagain(0);
static atomic<int> num_miscompare(0);
static atomic<bool> vb_first_time(true);

static sigset_t signal_set;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

static int sg_in_open(struct global_collection *clp, const char *inf,
                      uint8_t **mmpp, int *mmap_len, bool move_data);
static int sg_out_open(struct global_collection *clp, const char *outf,
                       uint8_t **mmpp, int *mmap_len, bool move_data);
static int do_both_sg_segment(Rq_elem * rep, scat_gath_iter & i_sg_it,
                              scat_gath_iter & o_sg_it, int seg_blks,
                              vector<cdb_arr_t> & a_cdb,
                              vector<struct sg_io_v4> & a_v4);
static int do_both_sg_segment_mrq0(Rq_elem * rep, scat_gath_iter & i_sg_it,
                                   scat_gath_iter & o_sg_it, int seg_blks);
static int do_normal_sg_segment(Rq_elem * rep, scat_gath_iter & i_sg_it,
                                scat_gath_iter & o_sg_it, int seg_blks,
                                vector<cdb_arr_t> & a_cdb,
                                vector<struct sg_io_v4> & a_v4);
static int do_normal_normal_segment(Rq_elem * rep, scat_gath_iter & i_sg_it,
                                    scat_gath_iter & o_sg_it, int seg_blks);

#define STRERR_BUFF_LEN 128

static mutex strerr_mut;

static bool have_sg_version = false;
static int sg_version = 0;
static bool sg_version_ge_40045 = false;
static atomic<bool> shutting_down{false};
static bool do_sync = false;
static int do_time = 1;
static struct global_collection gcoll;
static struct timeval start_tm;
static int num_threads = DEF_NUM_THREADS;
static bool after1 = false;

static const char * my_name = "sg_mrq_dd: ";

// static const char * mrq_blk_s = "mrq: ordinary blocking";
static const char * mrq_svb_s = "mrq: shared variable blocking (svb)";
static const char * mrq_ob_s = "mrq: ordered blocking";
static const char * mrq_vb_s = "mrq: variable blocking";


#ifdef __GNUC__
static int pr2serr_lk(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
static int pr2serr_lk(const char * fmt, ...);
#endif


static int
pr2serr_lk(const char * fmt, ...)
{
    int n;
    va_list args;
    lock_guard<mutex> lk(strerr_mut);

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

static void
lk_print_command_len(const char *prefix, uint8_t * cmdp, int len, bool lock)
{
    if (lock) {
        lock_guard<mutex> lk(strerr_mut);

        if (prefix && *prefix)
            fputs(prefix, stderr);
        sg_print_command_len(cmdp, len);
    } else {
        if (prefix && *prefix)
            fputs(prefix, stderr);
        sg_print_command_len(cmdp, len);
    }
}

static void
lk_chk_n_print4(const char * leadin, const struct sg_io_v4 * h4p,
                bool raw_sinfo)
{
    lock_guard<mutex> lk(strerr_mut);

    if (h4p->usr_ptr) {
        const cdb_arr_t * cdbp = (const cdb_arr_t *)h4p->usr_ptr;

        pr2serr("Failed cdb: ");
        sg_print_command(cdbp->data());
    } else
        pr2serr("cdb: <null>\n");
    sg_linux_sense_print(leadin, h4p->device_status, h4p->transport_status,
                         h4p->driver_status, (const uint8_t *)h4p->response,
                         h4p->response_len, raw_sinfo);
}

static void
hex2stderr_lk(const uint8_t * b_str, int len, int no_ascii)
{
    lock_guard<mutex> lk(strerr_mut);

    hex2stderr(b_str, len, no_ascii);
}

static int
system_wrapper(const char * cmd)
{
    int res;

    res = system(cmd);
    if (WIFSIGNALED(res) &&
        (WTERMSIG(res) == SIGINT || WTERMSIG(res) == SIGQUIT))
        raise(WTERMSIG(res));
    return WEXITSTATUS(res);
}

/* Flags decoded into abbreviations for those that are set, separated by
 * '|' . */
static char *
sg_flags_str(int flags, int b_len, char * b)
{
    int n = 0;

    if ((b_len < 1) || (! b))
        return b;
    b[0] = '\0';
    if (SG_FLAG_DIRECT_IO & flags) {            /* 0x1 */
        n += sg_scnpr(b + n, b_len - n, "DIO|");
        if (n >= b_len)
            goto fini;
    }
    if (SG_FLAG_MMAP_IO & flags) {              /* 0x4 */
        n += sg_scnpr(b + n, b_len - n, "MMAP|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_YIELD_TAG & flags) {          /* 0x8 */
        n += sg_scnpr(b + n, b_len - n, "YTAG|");
        if (n >= b_len)
            goto fini;
    }
    if (SG_FLAG_Q_AT_TAIL & flags) {            /* 0x10 */
        n += sg_scnpr(b + n, b_len - n, "QTAI|");
        if (n >= b_len)
            goto fini;
    }
    if (SG_FLAG_Q_AT_HEAD & flags) {            /* 0x20 */
        n += sg_scnpr(b + n, b_len - n, "QHEA|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_NO_WAITQ & flags) {           /* 0x40 */
        n += sg_scnpr(b + n, b_len - n, "NO_WTQ|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_DOUT_OFFSET & flags) {        /* 0x80 */
        n += sg_scnpr(b + n, b_len - n, "DOFF|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_COMPLETE_B4 & flags) {        /* 0x100 */
        n += sg_scnpr(b + n, b_len - n, "CPL_B4|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_SIGNAL & flags) {       /* 0x200 */
        n += sg_scnpr(b + n, b_len - n, "SIGNAL|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_IMMED & flags) {              /* 0x400 */
        n += sg_scnpr(b + n, b_len - n, "IMM|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_STOP_IF & flags) {            /* 0x800 */
        n += sg_scnpr(b + n, b_len - n, "STOPIF|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_DEV_SCOPE & flags) {          /* 0x1000 */
        n += sg_scnpr(b + n, b_len - n, "DEV_SC|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_SHARE & flags) {              /* 0x2000 */
        n += sg_scnpr(b + n, b_len - n, "SHARE|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_DO_ON_OTHER & flags) {        /* 0x4000 */
        n += sg_scnpr(b + n, b_len - n, "DO_OTH|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_KEEP_SHARE & flags) {        /* 0x8000 */
        n += sg_scnpr(b + n, b_len - n, "KEEP_SH|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_NO_DXFER & flags) {          /* 0x10000 */
        n += sg_scnpr(b + n, b_len - n, "NDXFER|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_MULTIPLE_REQS & flags) {     /* 0x20000 */
        n += sg_scnpr(b + n, b_len - n, "MRQS|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_EVENTFD & flags) {           /* 0x40000 */
        n += sg_scnpr(b + n, b_len - n, "EVFD|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_ORDERED_WR & flags) {        /* 0x80000 */
        n += sg_scnpr(b + n, b_len - n, "OWR|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_REC_ORDER & flags) {         /* 0x100000 */
        n += sg_scnpr(b + n, b_len - n, "RECO|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_HIPRI & flags) {             /* 0x200000 */
        n += sg_scnpr(b + n, b_len - n, "HIPRI|");
        if (n >= b_len)
            goto fini;
    }
fini:
    if (n < b_len) {    /* trim trailing '\' */
        if ('|' == b[n - 1])
            b[n - 1] = '\0';
    } else if ('|' == b[b_len - 1])
        b[b_len - 1] = '\0';
    return b;
}

/* Info field decoded into abbreviations for those bits that are set,
 * separated by '|' . */
static char *
sg_info_str(int info, int b_len, char * b)
{
    int n = 0;

    if ((b_len < 1) || (! b))
        return b;
    b[0] = '\0';
    if (SG_INFO_CHECK & info) {               /* 0x1 */
        n += sg_scnpr(b + n, b_len - n, "CHK|");
        if (n >= b_len)
            goto fini;
    }
    if (SG_INFO_DIRECT_IO & info) {           /* 0x2 */
        n += sg_scnpr(b + n, b_len - n, "DIO|");
        if (n >= b_len)
            goto fini;
    }
    if (SG_INFO_MIXED_IO & info) {            /* 0x4 */
        n += sg_scnpr(b + n, b_len - n, "MIO|");
        if (n >= b_len)
            goto fini;
    }
    if (SG_INFO_DEVICE_DETACHING & info) {    /* 0x8 */
        n += sg_scnpr(b + n, b_len - n, "DETA|");
        if (n >= b_len)
            goto fini;
    }
    if (SG_INFO_ABORTED & info) {             /* 0x10 */
        n += sg_scnpr(b + n, b_len - n, "ABRT|");
        if (n >= b_len)
            goto fini;
    }
    if (SG_INFO_MRQ_FINI & info) {            /* 0x20 */
        n += sg_scnpr(b + n, b_len - n, "MRQF|");
        if (n >= b_len)
            goto fini;
    }
fini:
    if (n < b_len) {    /* trim trailing '\' */
        if ('|' == b[n - 1])
            b[n - 1] = '\0';
    } else if ('|' == b[b_len - 1])
        b[b_len - 1] = '\0';
    return b;
}

static void
v4hdr_out_lk(const char * leadin, const sg_io_v4 * h4p, int id, bool chk_info)
{
    lock_guard<mutex> lk(strerr_mut);
    char b[80];

    if (leadin)
        pr2serr("%s [id=%d]:\n", leadin, id);
    if (('Q' != h4p->guard) || (0 != h4p->protocol) ||
        (0 != h4p->subprotocol))
        pr2serr("  <<<sg_io_v4 _NOT_ properly set>>>\n");
    pr2serr("  pointers: cdb=%s  sense=%s  din=%p  dout=%p\n",
            (h4p->request ? "y" : "NULL"), (h4p->response ? "y" : "NULL"),
            (void *)h4p->din_xferp, (void *)h4p->dout_xferp);
    pr2serr("  lengths: cdb=%u  sense=%u  din=%u  dout=%u\n",
            h4p->request_len, h4p->max_response_len, h4p->din_xfer_len,
             h4p->dout_xfer_len);
    pr2serr("  flags=0x%x  request_extra{pack_id}=%d\n",
            h4p->flags, h4p->request_extra);
    pr2serr("  flags set: %s\n", sg_flags_str(h4p->flags, sizeof(b), b));
    pr2serr(" %s OUT:\n", leadin);
    pr2serr("  response_len=%d driver/transport/device_status="
            "0x%x/0x%x/0x%x\n", h4p->response_len, h4p->driver_status,
            h4p->transport_status, h4p->device_status);
    pr2serr("  info=0x%x  din_resid=%u  dout_resid=%u  spare_out=%u  "
            "dur=%u\n",
            h4p->info, h4p->din_resid, h4p->dout_resid, h4p->spare_out,
            h4p->duration);
    if (chk_info && (SG_INFO_CHECK & h4p->info))
        pr2serr("  >>>> info: %s\n", sg_info_str(h4p->info, sizeof(b), b));
}

static void
fetch_sg_version(void)
{
    FILE * fp;
    char b[96];

    have_sg_version = false;
    sg_version = 0;
    fp = fopen(PROC_SCSI_SG_VERSION, "r");
    if (fp && fgets(b, sizeof(b) - 1, fp)) {
        if (1 == sscanf(b, "%d", &sg_version))
            have_sg_version = !!sg_version;
    } else {
        int j, k, l;

        if (fp)
            fclose(fp);
        fp = fopen(SYS_SCSI_SG_VERSION, "r");
        if (fp && fgets(b, sizeof(b) - 1, fp)) {
            if (3 == sscanf(b, "%d.%d.%d", &j, &k, &l)) {
                sg_version = (j * 10000) + (k * 100) + l;
                have_sg_version = !!sg_version;
            }
        }
        if (NULL == fp)
                pr2serr("The sg driver may not be loaded\n");
    }
    if (fp)
        fclose(fp);
}

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
    b = (double)gcoll.bs * (gcoll.dd_count - gcoll.out_rem_count.load());
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

    if (0 != gcoll.out_rem_count.load())
        pr2serr("  remaining block count=%" PRId64 "\n",
                gcoll.out_rem_count.load());
    infull = gcoll.dd_count - gcoll.in_rem_count.load();
    pr2serr("%s%" PRId64 "+%d records in\n", str,
            infull, gcoll.in_partial.load());

    if (gcoll.out_type == FT_DEV_NULL)
        pr2serr("%s0+0 records out\n", str);
    else {
        outfull = gcoll.dd_count - gcoll.out_rem_count.load();
        pr2serr("%s%" PRId64 "+%d records %s\n", str,
                outfull, gcoll.out_partial.load(),
                (gcoll.verify ? "verified" : "out"));
    }
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
    if (do_time > 0)
        calc_duration_throughput(0);
    print_stats("");
    kill(getpid (), sig);
}

static void
siginfo_handler(int sig)
{
    if (sig) { ; }      /* unused, dummy to suppress warning */
    pr2serr("Progress report, continuing ...\n");
    if (do_time > 0)
        calc_duration_throughput(1);
    print_stats("  ");
}

static void
siginfo2_handler(int sig)
{
    if (sig) { ; }      /* unused, dummy to suppress warning */
    pr2serr("Progress report, continuing ...\n");
    if (do_time > 0)
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
    lock_guard<mutex> lk(strerr_mut);
    char * cp;

    cp = safe_strerror(code);
    strncpy(ebp, cp, STRERR_BUFF_LEN);
    ebp[STRERR_BUFF_LEN - 1] = '\0';
    return ebp;
}


static int
dd_filetype(const char * filename, off_t & st_size)
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
    else if (S_ISFIFO(st.st_mode))
        return FT_FIFO;
    st_size = st.st_size;
    return FT_OTHER;
}

static void
usage(int pg_num)
{
    if (pg_num > 3)
        goto page4;
    else if (pg_num > 2)
        goto page3;
    else if (pg_num > 1)
        goto page2;

    pr2serr("Usage: sg_mrq_dd  [bs=BS] [conv=CONV] [count=COUNT] [ibs=BS] "
            "[if=IFILE]\n"
            "                  [iflag=FLAGS] [obs=BS] [of=OFILE] "
            "[oflag=FLAGS]\n"
            "                  [seek=SEEK] [skip=SKIP] [--help] [--verify] "
            "[--version]\n\n");
    pr2serr("                  [bpt=BPT] [cdbsz=6|10|12|16] [cdl=CDL] "
            "[dio=0|1]\n"
            "                  [elemsz_kb=EKB] [ese=0|1] [fua=0|1|2|3] "
            "[hipri=NRQS]\n"
            "                  [mrq=NRQS] [no_waitq=0|1] [ofreg=OFREG] "
            "[sync=0|1]\n"
            "                  [thr=THR] [time=0|1|2[,TO]] [verbose=VERB] "
            "[--dry-run]\n"
            "                  [--pre-fetch] [--verbose] [--version]\n\n"
            "  where: operands have the form name=value and are pecular to "
            "'dd'\n"
            "         style commands, and options start with one or "
            "two hyphens;\n"
            "         the main operands and options (shown in first group "
            "above) are:\n"
            "    bs          must be device logical block size (default "
            "512)\n"
            "    conv        comma separated list from: [nocreat,noerror,"
            "notrunc,\n"
            "                null,sync]\n"
            "    count       number of blocks to copy (def: device size)\n"
            "    if          file or device to read from (def: stdin)\n"
            "    iflag       comma separated list from: [coe,dio,"
            "direct,dpo,\n"
            "                dsync,excl,fua,masync,mmap,nodur,\n"
            "                null,order,qtail,serial,wq_excl]\n"
            "    of          file or device to write to (def: /dev/null "
            "N.B. different\n"
            "                from dd it defaults to stdout). If 'of=.' "
            "uses /dev/null\n"
            "    oflag       comma separated list from: [append,nocreat,\n"
            "                <<list from iflag>>]\n"
            "    seek        block position to start writing to OFILE\n"
            "    skip        block position to start reading from IFILE\n"
            "    --help|-h      output this usage message then exit\n"
            "    --verify|-x    do a verify (compare) operation [def: do a "
            "copy]\n"
            "    --version|-V   output version string then exit\n\n"
            "Copy IFILE to OFILE, similar to dd command. This utility is "
            "specialized for\nSCSI devices and uses the 'multiple requests' "
            "(mrq) in a single invocation\nfacility in version 4 of the sg "
            "driver unless mrq=0. Usually one or both\nIFILE and OFILE will "
            "be sg devices. With the --verify option it does a\n"
            "verify/compare operation instead of a copy. This utility is "
            "Linux specific.\nUse '-hh', '-hhh' or '-hhhh' for more "
            "information.\n"
           );
    return;
page2:
    pr2serr("Syntax:  sg_mrq_dd [operands] [options]\n\n"
            "         the lesser used operands and option are:\n\n"
            "    bpt         is blocks_per_transfer (default is 128)\n"
            "    cdbsz       size of SCSI READ, WRITE or VERIFY cdb_s "
            "(default is 10)\n"
            "    cdl         command duration limits value 0 to 7 (def: "
            "0 (no cdl))\n"
            "    dio         is direct IO, 1->attempt, 0->indirect IO (def)\n"
            "    elemsz_kb=EKB    scatter gather list element size in "
            "kibibytes;\n"
            "                     must be power of two, >= page_size "
            "(typically 4)\n"
            "    ese=0|1     exit on secondary error when 1, else continue\n"
            "    fua         force unit access: 0->don't(def), 1->OFILE, "
            "2->IFILE,\n"
            "                3->OFILE+IFILE\n"
            "    ibs         IFILE logical block size, cannot differ from "
            "obs or bs\n"
            "    hipri       similar to mrq=NRQS operand but also sets "
            "hipri flag\n"
            "    mrq         NRQS is number of cmds placed in each sg "
            "ioctl\n"
            "                (def: 16). Does not set mrq hipri flag.\n"
            "                if mrq=0 does one-by-one, blocking "
            "ioctl(SG_IO)s\n"
            "    no_waitq=0|1    poll for completion when 1; def: 0 (use "
            "wait queue)\n"
            "    obs         OFILE logical block size, cannot differ from "
            "ibs or bs\n"
            "    ofreg       OFREG is regular file or pipe to send what is "
            "read from\n"
            "                IFILE in the first half of each shared element\n"
            "    sync        0->no sync(def), 1->SYNCHRONIZE CACHE on OFILE "
            "after copy\n"
            "    thr         is number of threads, must be > 0, default 4, "
            "max 1024\n"
            "    time        0->no timing; 1/2->millisec/nanosec precision "
            "(def: 1);\n"
            "                TO is command timeout in seconds (def: 60)\n"
            "    verbose     increase verbosity (def: VERB=0)\n"
            "    --dry-run|-d     prepare but bypass copy/read\n"
            "    --prefetch|-p    with verify: do pre-fetch first\n"
            "    --verbose|-v     increase verbosity of utility\n\n"
            "Use '-hhh' or '-hhhh' for more information about flags.\n"
           );
    return;
page3:
    pr2serr("Syntax:  sg_mrq_dd [operands] [options]\n\n"
            "  where: 'iflag=<arg>' and 'oflag=<arg>' arguments are listed "
            "below:\n\n"
            "    00          use all zeros instead of if=IFILE (only in "
            "iflag)\n"
            "    append      append output to OFILE (assumes OFILE is "
            "regular file)\n"
            "    coe         continue of error (reading, fills with zeros)\n"
            "    dio         sets the SG_FLAG_DIRECT_IO in sg requests\n"
            "    direct      sets the O_DIRECT flag on open()\n"
            "    dpo         sets the DPO (disable page out) in SCSI READs "
            "and WRITEs\n"
            "    dsync       sets the O_SYNC flag on open()\n"
            "    excl        sets the O_EXCL flag on open()\n"
            "    ff          use all 0xff bytes instead of if=IFILE (only in "
            "iflag)\n"
            "    fua         sets the FUA (force unit access) in SCSI READs "
            "and WRITEs\n"
            "    hipri       set HIPRI flag and use blk_poll() for "
            "completions\n"
            "    masync      set 'more async' flag on this sg device\n"
            "    mmap        setup mmap IO on IFILE or OFILE\n"
            "    mmap,mmap    when used twice, doesn't call munmap()\n"
            "    nocreat     will fail rather than create OFILE\n"
            "    nodur       turns off command duration calculations\n"
            "    order       require write ordering on sg->sg copy; only "
            "for oflag\n"
            "    qhead       queue new request at head of block queue\n"
            "    qtail       queue new request at tail of block queue (def: "
            "q at head)\n"
            "    random      use random data instead of if=IFILE (only in "
            "iflag)\n"
            "    serial      serialize sg command execution (def: overlap)\n"
            "    wq_excl     set SG_CTL_FLAGM_EXCL_WAITQ on this sg fd\n"
            "\n"
            "Copies IFILE to OFILE (and to OFILE2 if given). If IFILE and "
            "OFILE are sg\ndevices 'shared' mode is selected. "
            "When sharing, the data stays in a\nsingle "
            "in-kernel buffer which is copied (or mmap-ed) to the user "
            "space\nif the 'ofreg=OFREG' is given. Use '-hhhh' for more "
            "information.\n"
           );
    return;
page4:
    pr2serr("pack_id:\n"
            "These are ascending integers, starting at 1, associated with "
            "each issued\nSCSI command. When both IFILE and OFILE are sg "
            "devices, then the READ in\neach read-write pair is issued an "
            "even pack_id and its WRITE pair is\ngiven the pack_id one "
            "higher (i.e. an odd number). This enables a\n'cat '"
            "/proc/scsi/sg/debug' user to see that progress is being "
            "made.\n\n");
    pr2serr("Debugging:\n"
            "Apart from using one or more '--verbose' options which gets a "
            "bit noisy\n'cat /proc/scsi/sg/debug' can give a good overview "
            "of what is happening.\nThat does a sg driver object tree "
            "traversal that does minimal locking\nto make sure that each "
            "traversal is 'safe'. So it is important to note\nthe whole "
            "tree is not locked. This means for fast devices the overall\n"
            "tree state may change while the traversal is occurring. For "
            "example,\nit has been observed that both the read- and write- "
            "sides of a request\nshare show they are in 'active' state "
            "which should not be possible.\nIt occurs because the read-side "
            "probably jumped out of active state and\nthe write-side "
            "request entered it while some other nodes were being "
            "printed.\n\n");
    pr2serr("Busy state:\n"
            "Busy state (abbreviated to 'bsy' in the /proc/scsi/sg/debug "
            "output)\nis entered during request setup and completion. It "
            "is intended to be\na temporary state. It should not block "
            "but does sometimes (e.g. in\nblock_get_request()). Even so "
            "that blockage should be short and if not\nthere is a "
            "problem.\n\n");
    pr2serr("--verify :\n"
            "For comparing IFILE with OFILE. Does repeated sequences of: "
            "READ(ifile)\nand uses data returned to send to VERIFY(ofile, "
            "BYTCHK=1). So the OFILE\ndevice/disk is doing the actual "
            "comparison. Stops on first miscompare\nunless oflag=coe is "
            "given\n\n");
    pr2serr("--prefetch :\n"
            "Used with --verify option. Prepends a PRE-FETCH(ofile, IMMED) "
            "to verify\nsequence. This should speed the trailing VERIFY by "
            "making sure that\nthe data it needs for the comparison is "
            "already in its cache.\n");
    return;
}


get_next_res
global_collection::get_next(int desired_num_blks)
{
    int64_t expected, desired;

    if (desired_num_blks <= 0) {
        if (desired_num_blks < 0) {
            if (next_count_pos.load() >= 0)     /* flag error detection */
                next_count_pos.store(desired_num_blks);
        }
        return make_pair(next_count_pos.load(), 0);
    }

    expected = next_count_pos.load();
    do {        /* allowed to race with other threads */
        if (expected < 0)
            return make_pair(0, (int)expected);
        else if (expected >= dd_count)
            return make_pair(expected, 0);      /* clean finish */
        desired = expected + desired_num_blks;
        if (desired > dd_count)
            desired = dd_count;
    } while (! next_count_pos.compare_exchange_strong(expected, desired));
    return make_pair(expected, desired - expected);
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

/* Has an infinite loop doing a timed wait for any signals in sig_set. After
 * each timeout (300 ms) checks if the most_recent_pack_id atomic integer
 * has changed. If not after another two timeouts announces a stall has
 * been detected. If shutting down atomic is true breaks out of loop and
 * shuts down this thread. Other than that, this thread is normally cancelled
 * by the main thread, after other threads have exited. */
static void
sig_listen_thread(struct global_collection * clp)
{
    bool stall_reported = false;
    int stall_count = 0;
    int prev_pack_id = 0;
    int sig_number, pack_id;
    struct timespec ts;
    struct timespec * tsp = &ts;

    tsp->tv_sec = 0;
    tsp->tv_nsec = 300 * 1000 * 1000;   /* 300 ms */
    while (1) {
        sig_number = sigtimedwait(&signal_set, NULL, tsp);
        if (shutting_down)
            break;
        if (sig_number < 0) {
                int err = errno;

                if (EAGAIN == err) { /* timeout */
                    pack_id = clp->most_recent_pack_id.load();
                    if (pack_id == prev_pack_id) {
                        ++stall_count;
                        if (0 == (stall_count % DEF_STALL_THRESH)) {
                            if (! stall_reported) {
                                stall_reported = true;
                                pr2serr_lk("%s: stall at pack_id=%d "
                                           "detected\n", __func__, pack_id);
                        }
                        pr2serr_lk("%s: stall at pack_id=%d, dump sg/debug\n",
                                   __func__, pack_id);
                        system_wrapper("/usr/bin/cat /proc/scsi/sg/debug\n");
                    }
                } else {
                    stall_count = 0;
                    prev_pack_id = pack_id;
                }
            } else
                pr2serr_lk("%s: sigtimedwait() errno=%d\n", __func__, err);
        }
        if (SIGINT == sig_number) {
            pr2serr_lk("%sinterrupted by SIGINT\n", my_name);
            clp->next_count_pos.store(-1);
            shutting_down.store(true);
        }
    }
    if (clp->verbose > 1)
        pr2serr_lk("%s: exiting\n", __func__);
}

static bool
sg_share_prepare(int write_side_fd, int read_side_fd, int id, bool vb_b)
{
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

    seip = &sei;
    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_SHARE_FD;
    seip->sei_rd_mask |= SG_SEIM_SHARE_FD;
    seip->share_fd = read_side_fd;
    if (ioctl(write_side_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr_lk("tid=%d: ioctl(EXTENDED(shared_fd=%d), failed "
                   "errno=%d %s\n", id, read_side_fd, errno,
                   strerror(errno));
        return false;
    }
    if (vb_b)
        pr2serr_lk("%s: tid=%d: ioctl(EXTENDED(shared_fd)) ok, "
                   "read_side_fd=%d, write_side_fd=%d\n", __func__, id,
                   read_side_fd, write_side_fd);
    return true;
}

static void
sg_take_snap(int sg_fd, int id, bool vb_b)
{
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

    seip = &sei;
    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
    seip->sei_rd_mask |= SG_SEIM_CTL_FLAGS;
    seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_SNAP_DEV;
    seip->ctl_flags &= SG_CTL_FLAGM_SNAP_DEV;   /* 0 --> don't append */
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
        pr2serr_lk("tid=%d: ioctl(EXTENDED(SNAP_DEV), failed errno=%d %s\n",
                   id,  errno, strerror(errno));
        return;
    }
    if (vb_b)
        pr2serr_lk("tid=%d: ioctl(SNAP_DEV) ok\n", id);
}

// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
/* Each thread's "main" function */
static void
read_write_thread(struct global_collection * clp, int id, bool singleton)
{
    Rq_elem rel;
    Rq_elem * rep = &rel;
    int n, sz, fd, vb, err, seg_blks;
    int res = 0;
    int num_sg = 0;
    bool own_infd = false;
    bool in_is_sg, in_mmap, out_is_sg, out_mmap;
    bool own_outfd = false;
    bool only_one_sg = false;
    class scat_gath_iter i_sg_it(clp->i_sgl);
    class scat_gath_iter o_sg_it(clp->o_sgl);
    vector<cdb_arr_t> a_cdb;
    vector<struct sg_io_v4> a_v4;

    vb = clp->verbose;
    sz = clp->mrq_num * clp->bpt * clp->bs;
    in_is_sg = (FT_SG == clp->in_type);
    in_mmap = (in_is_sg && (clp->in_flags.mmap > 0));
    out_is_sg = (FT_SG == clp->out_type);
    out_mmap = (out_is_sg && (clp->out_flags.mmap > 0));
    memset(rep, 0, sizeof(Rq_elem));
    rep->clp = clp;
    rep->id = id;

    if (in_is_sg && out_is_sg)
        rep->both_sg = true;
    else if (in_is_sg || out_is_sg) {
        only_one_sg = true;
        if (in_is_sg)
            rep->only_in_sg = true;
        else
            rep->only_out_sg = true;
    }

    if (vb > 2)
        pr2serr_lk("%d <-- Starting worker thread\n", id);
    if (! (rep->both_sg || in_mmap)) {
        rep->buffp = sg_memalign(sz, 0 /* page align */, &rep->alloc_bp,
                                 false);
        if (NULL == rep->buffp) {
            pr2serr_lk("Failed to allocate %d bytes, exiting\n", sz);
            return;
        }
    }
    rep->infd = clp->infd;
    rep->outfd = clp->outfd;
    rep->outregfd = clp->outregfd;
    rep->rep_count = 0;
    rep->in_follow_on = -1;
    rep->out_follow_on = -1;

    if (rep->infd == rep->outfd) {
        if (in_is_sg)
            rep->same_sg = true;
    }
    if (clp->in_flags.random) {
#ifdef HAVE_GETRANDOM
        ssize_t ssz = getrandom(&rep->seed, sizeof(rep->seed), GRND_NONBLOCK);

        if (ssz < (ssize_t)sizeof(rep->seed)) {
            pr2serr_lk("[%d] %s: getrandom() failed, ret=%d\n", id, __func__,
                       (int)ssz);
            rep->seed = (long)time(NULL);
        }
#else
        rep->seed = (long)time(NULL);    /* use seconds since epoch as proxy */
#endif
        if (vb > 1)
            pr2serr_lk("[%d] %s: seed=%ld\n", id, __func__, rep->seed);
        srand48_r(rep->seed, &rep->drand);
    }

    if (in_is_sg && clp->infp) {
        fd = sg_in_open(clp, clp->infp, (in_mmap ? &rep->buffp : NULL),
                        (in_mmap ? &rep->mmap_len : NULL), true);
        if (fd < 0)
            goto fini;
        rep->infd = fd;
        rep->mmap_active = in_mmap ? clp->in_flags.mmap : 0;
        if (in_mmap && (vb > 4))
            pr2serr_lk("[%d] %s: mmap buffp=%p\n", id, __func__, rep->buffp);
        own_infd = true;
        ++num_sg;
        if (vb > 2)
            pr2serr_lk("[%d]: opened local sg IFILE\n", id);
    }
    if (out_is_sg && clp->outfp) {
        fd = sg_out_open(clp, clp->outfp, (out_mmap ? &rep->buffp : NULL),
                         (out_mmap ? &rep->mmap_len : NULL), true);
        if (fd < 0)
            goto fini;
        rep->outfd = fd;
        if (! rep->mmap_active)
            rep->mmap_active = out_mmap ? clp->out_flags.mmap : 0;
        if (out_mmap && (vb > 4))
            pr2serr_lk("[%d]: mmap buffp=%p\n", id, rep->buffp);
        own_outfd = true;
        ++num_sg;
        if (vb > 2)
            pr2serr_lk("[%d]: opened local sg OFILE\n", id);
    }
    if (vb > 2) {
        if (in_is_sg && (! own_infd))
            pr2serr_lk("[%d]: using global sg IFILE, fd=%d\n", id, rep->infd);
        if (out_is_sg && (! own_outfd))
            pr2serr_lk("[%d]: using global sg OFILE, fd=%d\n", id, rep->outfd);
    }
    if (rep->both_sg)
        rep->has_share = sg_share_prepare(rep->outfd, rep->infd, id, vb > 9);
    if (vb > 9)
        pr2serr_lk("[%d]: has_share=%s\n", id,
                   (rep->has_share ? "true" : "false"));
    // share_and_ofreg = (rep->has_share && (rep->outregfd >= 0));

    /* vvvvvvvvvvvvvv  Main segment copy loop  vvvvvvvvvvvvvvvvvvvvvvv */
    while (! shutting_down) {
        get_next_res gnr = clp->get_next(clp->mrq_num * clp->bpt);

        seg_blks = gnr.second;
        if (seg_blks <= 0) {
            if (seg_blks < 0)
                res = -seg_blks;
            break;
        }
        if (! i_sg_it.set_by_blk_idx(gnr.first)) {
            lock_guard<mutex> lk(strerr_mut);

            pr2serr_lk("[%d]: input set_by_blk_idx() failed\n", id);
            i_sg_it.dbg_print("input after set_by_blk_idx", false, vb > 5);
            res = 2;
            break;
        }
        if (! o_sg_it.set_by_blk_idx(gnr.first)) {
            pr2serr_lk("[%d]: output set_by_blk_idx() failed\n", id);
            res = 3;
            break;
        }
        if (rep->both_sg) {
            uint32_t nn = (2 * clp->mrq_num) + 4;

            if (a_cdb.capacity() < nn)
                a_cdb.reserve(nn);
            if (a_v4.capacity() < nn)
                a_v4.reserve(nn);
            if (clp->mrq_eq_0)
                res = do_both_sg_segment_mrq0(rep, i_sg_it, o_sg_it,
                                              seg_blks);
            else
                res = do_both_sg_segment(rep, i_sg_it, o_sg_it, seg_blks,
                                         a_cdb, a_v4);
            if (res < 0)
                break;
        } else if (only_one_sg) {
            uint32_t nn = clp->mrq_num + 4;

            if (a_cdb.capacity() < nn)
                a_cdb.reserve(nn);
            if (a_v4.capacity() < nn)
                a_v4.reserve(nn);
            res = do_normal_sg_segment(rep, i_sg_it, o_sg_it, seg_blks, a_cdb,
                                       a_v4);
            if (res < 0)
                break;
        } else {
            res = do_normal_normal_segment(rep, i_sg_it, o_sg_it, seg_blks);
            if (res < 0)
                break;
        }
        if (singleton) {
            {
                lock_guard<mutex> lk(clp->infant_mut);

                clp->processed = true;
            }   /* this unlocks lk */
            clp->infant_cv.notify_one();
            singleton = false;
        }
        if (rep->stop_after_write || rep->stop_now) {
            shutting_down = true;
            break;
        }
    }   /* ^^^^^^^^^^ end of main while loop which copies segments ^^^^^^ */

    if (shutting_down)
        goto fini;
    if (singleton) {
        {
            lock_guard<mutex> lk(clp->infant_mut);

            clp->processed = true;
        }   /* this unlocks lk */
        clp->infant_cv.notify_one();
        singleton = false;
    }
    if (res < 0) {
        if (seg_blks >= 0)
            clp->get_next(-1);  /* flag error to main */
        pr2serr_lk("%s: t=%d: aborting, res=%d\n", __func__, rep->id, res);
    }

fini:

    if ((1 == rep->mmap_active) && (rep->mmap_len > 0)) {
        if (munmap(rep->buffp, rep->mmap_len) < 0) {
            err = errno;
            char bb[64];

            pr2serr_lk("thread=%d: munmap() failed: %s\n", rep->id,
                       tsafe_strerror(err, bb));
        }
        if (vb > 4)
            pr2serr_lk("thread=%d: munmap(%p, %d)\n", rep->id, rep->buffp,
                       rep->mmap_len);
        rep->mmap_active = 0;
    }

    if (own_infd && (rep->infd >= 0)) {
        if (vb && in_is_sg) {
            if (ioctl(rep->infd, SG_GET_NUM_WAITING, &n) >= 0) {
                if (n > 0)
                    pr2serr_lk("%s: tid=%d: num_waiting=%d prior close(in)\n",
                               __func__, rep->id, n);
            } else {
                err = errno;
                pr2serr_lk("%s: [%d] ioctl(SG_GET_NUM_WAITING) errno=%d: "
                           "%s\n", __func__, rep->id, err, strerror(err));
            }
        }
        close(rep->infd);
    }
    if (own_outfd && (rep->outfd >= 0)) {
        if (vb && out_is_sg) {
            if (ioctl(rep->outfd, SG_GET_NUM_WAITING, &n) >= 0) {
                if (n > 0)
                    pr2serr_lk("%s: tid=%d: num_waiting=%d prior "
                               "close(out)\n", __func__, rep->id, n);
            } else {
                err = errno;
                pr2serr_lk("%s: [%d] ioctl(SG_GET_NUM_WAITING) errno=%d: "
                           "%s\n", __func__, rep->id, err, strerror(err));
            }
        }
        close(rep->outfd);
    }
    /* pass stats back to read-side */
    clp->in_rem_count -= rep->in_local_count;
    clp->out_rem_count -= rep->out_local_count;
    clp->in_partial += rep->in_local_partial;
    clp->out_partial += rep->out_local_partial;
    clp->sum_of_resids += rep->in_resid_bytes;
    if (rep->alloc_bp)
        free(rep->alloc_bp);
}

/* N.B. Returns 'blocks' is successful, lesser positive number if there was
 * a short read, or an error code which is negative. */
static int
normal_in_rd(Rq_elem * rep, int64_t lba, int blocks, int d_boff)
{
    struct global_collection * clp = rep->clp;
    int res, err;
    int id = rep->id;
    uint8_t * bp;
    char strerr_buff[STRERR_BUFF_LEN];

    if (clp->verbose > 4)
        pr2serr_lk("[%d] %s: lba=%" PRIu64 ", blocks=%d, d_boff=%d\n", id,
                   __func__, lba, blocks, d_boff);
    if (FT_RANDOM_0_FF == clp->in_type) {
        int k, j;
        const int jbump = sizeof(uint32_t);
        long rn;
        uint8_t * bp;

        if (clp->in_flags.zero)
            memset(rep->buffp + d_boff, 0, blocks * clp->bs);
        else if (clp->in_flags.ff)
            memset(rep->buffp + d_boff, 0xff, blocks * clp->bs);
        else {
            bp = rep->buffp + d_boff;
            for (k = 0; k < blocks; ++k, bp += clp->bs) {
                for (j = 0; j < clp->bs; j += jbump) {
                   /* mrand48 takes uniformly from [-2^31, 2^31) */
                    mrand48_r(&rep->drand, &rn);
                    *((uint32_t *)(bp + j)) = (uint32_t)rn;
                }
            }
        }
        return blocks;
    }

    if (clp->in_type != FT_FIFO) {
        int64_t pos = lba * clp->bs;

        if (rep->in_follow_on != pos) {
            if (lseek64(rep->infd, pos, SEEK_SET) < 0) {
                err = errno;
                pr2serr_lk("[%d] %s: >> lseek64(%" PRId64 "): %s\n", id,
                           __func__, pos, safe_strerror(err));
                return -err;
            }
            rep->in_follow_on = pos;
        }
    }
    bp = rep->buffp + d_boff;
    while (((res = read(clp->infd, bp, blocks * clp->bs)) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno)))
        std::this_thread::yield();/* another thread may be able to progress */
    if (res < 0) {
        err = errno;
        if (clp->in_flags.coe) {
            memset(bp, 0, blocks * clp->bs);
            pr2serr_lk("[%d] %s : >> substituted zeros for in blk=%" PRId64
                      " for %d bytes, %s\n", id, __func__, lba,
                       blocks * clp->bs,
                       tsafe_strerror(err, strerr_buff));
            res = blocks * clp->bs;
        } else {
            pr2serr_lk("[%d] %s: error in normal read, %s\n", id, __func__,
                       tsafe_strerror(err, strerr_buff));
            return -err;
        }
    }
    rep->in_follow_on += res;
    if (res < blocks * clp->bs) {
        blocks = res / clp->bs;
        if ((res % clp->bs) > 0) {
            rep->in_local_partial++;
            rep->in_resid_bytes = res % clp->bs;
        }
    }
    return blocks;
}

/* N.B. Returns 'blocks' is successful, lesser positive number if there was
 * a short write, or an error code which is negative. */
static int
normal_out_wr(Rq_elem * rep, int64_t lba, int blocks, int d_boff)
{
    int res, err;
    int id = rep->id;
    struct global_collection * clp = rep->clp;
    uint8_t * bp = rep->buffp + d_boff;
    char strerr_buff[STRERR_BUFF_LEN];

    if (clp->verbose > 4)
        pr2serr_lk("[%d] %s: lba=%" PRIu64 ", blocks=%d, d_boff=%d\n", id,
                    __func__, lba, blocks, d_boff);

    if (clp->in_type != FT_FIFO) {
        int64_t pos = lba * clp->bs;

        if (rep->out_follow_on != pos) {
            if (lseek64(rep->outfd, pos, SEEK_SET) < 0) {
                err = errno;
                pr2serr_lk("[%d] %s: >> lseek64(%" PRId64 "): %s\n", id,
                           __func__, pos, safe_strerror(err));
                return -err;
            }
            rep->out_follow_on = pos;
        }
    }
    while (((res = write(clp->outfd, bp, blocks * clp->bs))
            < 0) && ((EINTR == errno) || (EAGAIN == errno)))
        std::this_thread::yield();/* another thread may be able to progress */
    if (res < 0) {
        err = errno;
        if (clp->out_flags.coe) {
            pr2serr_lk("[%d] %s: >> ignored error for out lba=%" PRId64
                       " for %d bytes, %s\n", id, __func__, lba,
                       blocks * clp->bs, tsafe_strerror(err, strerr_buff));
            res = blocks * clp->bs;
        }
        else {
            pr2serr_lk("[%d] %s: error normal write, %s\n", id, __func__,
                       tsafe_strerror(err, strerr_buff));
            return -err;
        }
    }
    rep->out_follow_on += res;
    if (res < blocks * clp->bs) {
        blocks = res / clp->bs;
        if ((res % clp->bs) > 0) {
            blocks++;
            rep->out_local_partial++;
        }
    }
    return blocks;
}

static int
extra_out_wr(Rq_elem * rep, int num_bytes, int d_boff)
{
    int res, err;
    int id = rep->id;
    struct global_collection * clp = rep->clp;
    uint8_t * bp = rep->buffp + d_boff;
    char strerr_buff[STRERR_BUFF_LEN];

    if (clp->verbose > 4)
        pr2serr_lk("[%d] %s: num_bytes=%d, d_boff=%d\n", id, __func__,
                   num_bytes, d_boff);

    while (((res = write(clp->outfd, bp, num_bytes))
            < 0) && ((EINTR == errno) || (EAGAIN == errno)))
        std::this_thread::yield();/* another thread may be able to progress */
    if (res < 0) {
        err = errno;
        pr2serr_lk("[%d] %s: error normal write, %s\n", id, __func__,
                   tsafe_strerror(err, strerr_buff));
        return -err;
    }
    if (res > 0)
        rep->out_local_partial++;
    return res;
}

static int
sg_build_scsi_cdb(uint8_t * cdbp, int cdb_sz, unsigned int blocks,
                  int64_t start_block, bool ver_true, bool write_true,
                  bool fua, bool dpo, int cdl)
{
    bool normal_rw = true;
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int ve_opcode[] = {0xff /* no VER(6) */, 0x2f, 0xaf, 0x8f};
    int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};
    int sz_ind;

    memset(cdbp, 0, cdb_sz);
    if (ver_true) {     /* only support VERIFY(10) */
        if (cdb_sz < 10) {
            pr2serr_lk("%s only support VERIFY(10)\n", my_name);
            return 1;
        }
        cdb_sz = 10;
        fua = false;
        cdbp[1] |= 0x2; /* BYTCHK=1 --> sending dout for comparison */
        cdbp[0] = ve_opcode[1];
        normal_rw = false;
    }
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
            pr2serr_lk("%sfor 6 byte commands, maximum number of blocks is "
                       "256\n", my_name);
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            pr2serr_lk("%sfor 6 byte commands, can't address blocks beyond "
                       "%d\n", my_name, 0x1fffff);
            return 1;
        }
        if (dpo || fua) {
            pr2serr_lk("%sfor 6 byte commands, neither dpo nor fua bits "
                       "supported\n", my_name);
            return 1;
        }
        break;
    case 10:
        if (! ver_true) {
            sz_ind = 1;
            cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                             rd_opcode[sz_ind]);
        }
        sg_put_unaligned_be32((uint32_t)start_block, cdbp + 2);
        sg_put_unaligned_be16((uint16_t)blocks, cdbp + 7);
        if (blocks & (~0xffff)) {
            pr2serr_lk("%sfor 10 byte commands, maximum number of blocks is "
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
        if (normal_rw && (cdl > 0)) {
            if (cdl & 0x4)
                cdbp[1] |= 0x1;
            if (cdl & 0x3)
                cdbp[14] |= ((cdl & 0x3) << 6);
        }
        break;
    default:
        pr2serr_lk("%sexpected cdb size of 6, 10, 12, or 16 but got %d\n",
                   my_name, cdb_sz);
        return 1;
    }
    return 0;
}

static int
process_mrq_response(Rq_elem * rep, const struct sg_io_v4 * ctl_v4p,
                     const struct sg_io_v4 * a_v4p, int num_mrq,
                     uint32_t & good_inblks, uint32_t & good_outblks,
                     bool & last_err_on_in)
{
    struct global_collection * clp = rep->clp;
    bool ok, all_good;
    bool sb_in_co = !!(ctl_v4p->response);
    int id = rep->id;
    int resid = ctl_v4p->din_resid;
    int sres = ctl_v4p->spare_out;
    int n_subm = num_mrq - ctl_v4p->dout_resid;
    int n_cmpl = ctl_v4p->info;
    int n_good = 0;
    int hole_count = 0;
    int cat = 0;
    int vb = clp->verbose;
    int k, j, f1, slen, sstatus;
    char b[160];

    good_inblks = 0;
    good_outblks = 0;
    if (vb > 2)
        pr2serr_lk("[thread_id=%d] %s: num_mrq=%d, n_subm=%d, n_cmpl=%d\n",
                   id, __func__, num_mrq, n_subm, n_cmpl);
    if (n_subm < 0) {
        pr2serr_lk("[%d] co.dout_resid(%d) > num_mrq(%d)\n", id,
                   ctl_v4p->dout_resid, num_mrq);
        return -1;
    }
    if (n_cmpl != (num_mrq - resid))
        pr2serr_lk("[%d] co.info(%d) != (num_mrq(%d) - co.din_resid(%d))\n"
                   "will use co.info\n", id, n_cmpl, num_mrq, resid);
    if (n_cmpl > n_subm) {
        pr2serr_lk("[%d] n_cmpl(%d) > n_subm(%d), use n_subm for both\n",
                   id, n_cmpl, n_subm);
        n_cmpl = n_subm;
    }
    if (sres) {
        pr2serr_lk("[%d] secondary error: %s [%d], info=0x%x\n", id,
                   strerror(sres), sres, ctl_v4p->info);
        if (E2BIG == sres) {
            sg_take_snap(rep->infd, id, true);
            sg_take_snap(rep->outfd, id, true);
        }
    }
    /* Check if those submitted have finished or not. N.B. If there has been
     * an error then there may be "holes" (i.e. info=0x0) in the array due
     * to completions being out-of-order. */
    for (k = 0, j = 0; ((k < num_mrq) && (j < n_subm));
         ++k, j += f1, ++a_v4p) {
        slen = a_v4p->response_len;
        if (! (SG_INFO_MRQ_FINI & a_v4p->info))
            ++hole_count;
        ok = true;
        f1 = !!(a_v4p->info);   /* want to skip n_subm count if info is 0x0 */
        if (SG_INFO_CHECK & a_v4p->info) {
            ok = false;
            pr2serr_lk("[%d] a_v4[%d]: SG_INFO_CHECK set [%s]\n", id, k,
                       sg_info_str(a_v4p->info, sizeof(b), b));
        }
        sstatus = a_v4p->device_status;
        if ((sstatus && (SAM_STAT_CONDITION_MET != sstatus)) ||
            a_v4p->transport_status || a_v4p->driver_status) {
            ok = false;
            last_err_on_in = ! (a_v4p->flags & SGV4_FLAG_DO_ON_OTHER);
            if (SAM_STAT_CHECK_CONDITION != a_v4p->device_status) {
                pr2serr_lk("[%d] a_v4[%d]:\n", id, k);
                if (vb)
                    lk_chk_n_print4("  >>", a_v4p, vb > 4);
            }
        }
        if (slen > 0) {
            struct sg_scsi_sense_hdr ssh;
            const uint8_t *sbp = (const uint8_t *)
                        (sb_in_co ? ctl_v4p->response : a_v4p->response);

            if (sg_scsi_normalize_sense(sbp, slen, &ssh) &&
                (ssh.response_code >= 0x70)) {
                if (ssh.response_code & 0x1) {
                    ok = true;
                    last_err_on_in = false;
                } else
                    cat = sg_err_category_sense(sbp, slen);
                if (SPC_SK_MISCOMPARE == ssh.sense_key)
                    ++num_miscompare;

                pr2serr_lk("[%d] a_v4[%d]:\n", id, k);
                if (vb)
                    lk_chk_n_print4("  >>", a_v4p, vb > 4);
            }
        } else if (! ok)
            cat = SG_LIB_CAT_OTHER;
        if (ok && f1) {
            ++n_good;
            if (a_v4p->dout_xfer_len >= (uint32_t)clp->bs)
                good_outblks += (a_v4p->dout_xfer_len - a_v4p->dout_resid) /
                                clp->bs;
            if (a_v4p->din_xfer_len >= (uint32_t)clp->bs)
                good_inblks += (a_v4p->din_xfer_len - a_v4p->din_resid) /
                               clp->bs;
        }
        if (! ok) {
            if ((a_v4p->dout_xfer_len > 0) || (! clp->in_flags.coe))
                rep->stop_after_write = true;
        }
    }   /* end of request array scan loop */
    if ((n_subm == num_mrq) || (vb < 3))
        goto fini;
    if (vb)
        pr2serr_lk("[%d] checking response array _beyond_ number of "
                   "submissions [%d] to num_mrq:\n", id, k);
    for (all_good = true; k < num_mrq; ++k, ++a_v4p) {
        if (SG_INFO_MRQ_FINI & a_v4p->info) {
            pr2serr_lk("[%d] a_v4[%d]: unexpected SG_INFO_MRQ_FINI set [%s]\n",
                       id, k, sg_info_str(a_v4p->info, sizeof(b), b));
            all_good = false;
        }
        if (a_v4p->device_status || a_v4p->transport_status ||
            a_v4p->driver_status) {
            pr2serr_lk("[%d] a_v4[%d]:\n", id, k);
            lk_chk_n_print4("    ", a_v4p, vb > 4);
            all_good = false;
        }
    }
    if (all_good)
        pr2serr_lk("    ... all good\n");
fini:
    if (cat > 0)
        clp->reason_res.store(cat);
    return n_good;
}

/* Returns number of blocks successfully processed or a negative error
 * number. */
static int
sg_half_segment_mrq0(Rq_elem * rep, scat_gath_iter & sg_it, bool is_wr,
                     int seg_blks, uint8_t *dp)
{
    int k, res, fd, pack_id_base, id, rflags;
    int num, kk, lin_blks, cdbsz, err;
    uint32_t q_blks = 0;
    struct global_collection * clp = rep->clp;
    cdb_arr_t t_cdb = {};
    struct sg_io_v4 t_v4;
    struct sg_io_v4 * t_v4p = &t_v4;
    struct flags_t * flagsp = is_wr ? &clp->out_flags : &clp->in_flags;
    int vb = clp->verbose;

    id = rep->id;
    pack_id_base = id * PACK_ID_TID_MULTIPLIER;
    rflags = 0;
    fd = is_wr ? rep->outfd : rep->infd;
    if (flagsp->mmap && (rep->outregfd >= 0))
        rflags |= SGV4_FLAG_MMAP_IO;
    if (flagsp->dio)
        rflags |= SGV4_FLAG_DIRECT_IO;
    if (flagsp->qhead)
        rflags |= SGV4_FLAG_Q_AT_HEAD;
    if (flagsp->qtail)
        rflags |= SGV4_FLAG_Q_AT_TAIL;
    if (clp->no_waitq)
        rflags |= SGV4_FLAG_NO_WAITQ;
    if (flagsp->hipri)
        rflags |= SGV4_FLAG_HIPRI;

    for (k = 0, num = 0; seg_blks > 0; ++k, seg_blks -= num) {
        kk = min<int>(seg_blks, clp->bpt);
        lin_blks = sg_it.linear_for_n_blks(kk);
        num = lin_blks;
        if (num <= 0) {
            res = 0;
            pr2serr_lk("[%d] %s: unexpected num=%d\n", id, __func__, num);
            break;
        }

        /* First build the command/request for the read-side */
        cdbsz = is_wr ? clp->cdbsz_out : clp->cdbsz_in;
        res = sg_build_scsi_cdb(t_cdb.data(), cdbsz, num, sg_it.current_lba(),
                                false, is_wr, flagsp->fua, flagsp->dpo,
                                flagsp->cdl);
        if (res) {
            pr2serr_lk("[%d] %s: sg_build_scsi_cdb() failed\n", id, __func__);
            break;
        } else if (vb > 3)
            lk_print_command_len("cdb: ", t_cdb.data(), cdbsz, true);

        memset(t_v4p, 0, sizeof(*t_v4p));
        t_v4p->guard = 'Q';
        t_v4p->request = (uint64_t)t_cdb.data();
        t_v4p->usr_ptr = t_v4p->request;
        t_v4p->response = (uint64_t)rep->sb;
        t_v4p->max_response_len = sizeof(rep->sb);
        t_v4p->flags = rflags;
        t_v4p->request_len = cdbsz;
        if (is_wr) {
            t_v4p->dout_xfer_len = num * clp->bs;
            t_v4p->dout_xferp = (uint64_t)(dp + (q_blks * clp->bs));
        } else {
            t_v4p->din_xfer_len = num * clp->bs;
            t_v4p->din_xferp = (uint64_t)(dp + (q_blks * clp->bs));
        }
        t_v4p->timeout = clp->cmd_timeout;
        t_v4p->request_extra = pack_id_base + ++rep->mrq_pack_id_off;
        clp->most_recent_pack_id.store(t_v4p->request_extra);
mrq0_again:
        res = ioctl(fd, SG_IO, t_v4p);
        err = errno;
        if (vb > 5)
            v4hdr_out_lk("sg_half_segment_mrq0: >> after ioctl(SG_IO)",
                         t_v4p, id, false);
        if (res < 0) {
            if (E2BIG == err)
                sg_take_snap(fd, id, true);
            else if (EBUSY == err) {
                ++num_ebusy;
                std::this_thread::yield();/* so other threads can progress */
                goto mrq0_again;
            }
            pr2serr_lk("[%d] %s: ioctl(SG_IO)-->%d, errno=%d: %s\n", id,
                       __func__, res, err, strerror(err));
            return -err;
        }
        if (t_v4p->device_status || t_v4p->transport_status ||
            t_v4p->driver_status) {
            rep->stop_now = true;
            pr2serr_lk("[%d] t_v4[%d]:\n", id, k);
            lk_chk_n_print4("    ", t_v4p, vb > 4);
            return q_blks;
        }
        q_blks += num;
        sg_it.add_blks(num);
    }
    return q_blks;
}

/* Returns number of blocks successfully processed or a negative error
 * number. */
static int
sg_half_segment(Rq_elem * rep, scat_gath_iter & sg_it, bool is_wr,
                int seg_blks, uint8_t *dp, vector<cdb_arr_t> & a_cdb,
                vector<struct sg_io_v4> & a_v4)
{
    int num_mrq, k, res, fd, mrq_pack_id_base, id, b_len, rflags;
    int num, kk, lin_blks, cdbsz, num_good, err;
    int o_seg_blks = seg_blks;
    uint32_t in_fin_blks, out_fin_blks;
    uint32_t mrq_q_blks = 0;
    uint32_t in_mrq_q_blks = 0;
    uint32_t out_mrq_q_blks = 0;
    const int max_cdb_sz = MAX_SCSI_CDB_SZ;
    struct sg_io_v4 * a_v4p;
    struct sg_io_v4 ctl_v4;     /* MRQ control object */
    struct global_collection * clp = rep->clp;
    const char * iosub_str = "SG_IOSUBMIT(variable blocking)";
    char b[80];
    cdb_arr_t t_cdb = {};
    struct sg_io_v4 t_v4;
    struct sg_io_v4 * t_v4p = &t_v4;
    struct flags_t * flagsp = is_wr ? &clp->out_flags : &clp->in_flags;
    bool serial = flagsp->serial;
    bool err_on_in = false;
    int vb = clp->verbose;

    id = rep->id;
    b_len = sizeof(b);
    if (serial)
        iosub_str = "SG_IO(ordered blocking)";

    a_cdb.clear();
    a_v4.clear();
    mrq_pack_id_base = id * PACK_ID_TID_MULTIPLIER;

    rflags = 0;
    if (flagsp->mmap && (rep->outregfd >= 0))
        rflags |= SGV4_FLAG_MMAP_IO;
    if (flagsp->dio)
        rflags |= SGV4_FLAG_DIRECT_IO;
    if (flagsp->qhead)
        rflags |= SGV4_FLAG_Q_AT_HEAD;
    if (flagsp->qtail)
        rflags |= SGV4_FLAG_Q_AT_TAIL;
    if (clp->no_waitq)
        rflags |= SGV4_FLAG_NO_WAITQ;
    if (flagsp->hipri)
        rflags |= SGV4_FLAG_HIPRI;

    for (k = 0, num = 0; seg_blks > 0; ++k, seg_blks -= num) {
        kk = min<int>(seg_blks, clp->bpt);
        lin_blks = sg_it.linear_for_n_blks(kk);
        num = lin_blks;
        if (num <= 0) {
            res = 0;
            pr2serr_lk("[%d] %s: unexpected num=%d\n", id, __func__, num);
            break;
        }

        /* First build the command/request for the read-side */
        cdbsz = is_wr ? clp->cdbsz_out : clp->cdbsz_in;
        res = sg_build_scsi_cdb(t_cdb.data(), cdbsz, num, sg_it.current_lba(),
                                false, is_wr, flagsp->fua, flagsp->dpo,
                                flagsp->cdl);
        if (res) {
            pr2serr_lk("[%d] %s: sg_build_scsi_cdb() failed\n", id, __func__);
            break;
        } else if (vb > 3)
            lk_print_command_len("cdb: ", t_cdb.data(), cdbsz, true);
        a_cdb.push_back(t_cdb);

        memset(t_v4p, 0, sizeof(*t_v4p));
        t_v4p->guard = 'Q';
        t_v4p->flags = rflags;
        t_v4p->request_len = cdbsz;
        t_v4p->response = (uint64_t)rep->sb;
        t_v4p->max_response_len = sizeof(rep->sb);
        t_v4p->flags = rflags;
        t_v4p->usr_ptr = (uint64_t)&a_cdb[a_cdb.size() - 1];
        if (is_wr) {
            t_v4p->dout_xfer_len = num * clp->bs;
            t_v4p->dout_xferp = (uint64_t)(dp + (mrq_q_blks * clp->bs));
        } else {
            t_v4p->din_xfer_len = num * clp->bs;
            t_v4p->din_xferp = (uint64_t)(dp + (mrq_q_blks * clp->bs));
        }
        t_v4p->timeout = clp->cmd_timeout;
        mrq_q_blks += num;
        t_v4p->request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;
        clp->most_recent_pack_id.store(t_v4p->request_extra);
        a_v4.push_back(t_v4);

        sg_it.add_blks(num);
    }

    if (rep->only_in_sg)
        fd = rep->infd;
    else if (rep->only_out_sg)
        fd = rep->outfd;
    else {
        pr2serr_lk("[%d] %s: why am I here? No sg devices\n", id, __func__);
        return -EINVAL;
    }
    num_mrq = a_v4.size();
    a_v4p = a_v4.data();
    res = 0;
    memset(&ctl_v4, 0, sizeof(ctl_v4));
    ctl_v4.guard = 'Q';
    ctl_v4.request_len = a_cdb.size() * max_cdb_sz;
    ctl_v4.request = (uint64_t)a_cdb.data();
    ctl_v4.max_response_len = sizeof(rep->sb);
    ctl_v4.response = (uint64_t)rep->sb;
    ctl_v4.flags = SGV4_FLAG_MULTIPLE_REQS;
    if (! flagsp->coe)
        ctl_v4.flags |= SGV4_FLAG_STOP_IF;
    if (clp->mrq_hipri)
        ctl_v4.flags |= SGV4_FLAG_HIPRI;
    ctl_v4.dout_xferp = (uint64_t)a_v4.data();        /* request array */
    ctl_v4.dout_xfer_len = a_v4.size() * sizeof(struct sg_io_v4);
    ctl_v4.din_xferp = (uint64_t)a_v4.data();         /* response array */
    ctl_v4.din_xfer_len = a_v4.size() * sizeof(struct sg_io_v4);
    if (false /* allow_mrq_abort */) {
        ctl_v4.request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;
        clp->most_recent_pack_id.store(ctl_v4.request_extra);
    }

    if (vb && vb_first_time.load()) {
        pr2serr_lk("First controlling object output by ioctl(%s), flags: "
                   "%s\n", iosub_str, sg_flags_str(ctl_v4.flags, b_len, b));
        vb_first_time.store(false);
    } else if (vb > 4) {
        pr2serr_lk("[%d] %s: >> Control object _before_ ioctl(%s):\n", id,
                   __func__, iosub_str);
    }
    if (vb > 4) {
        if (vb > 5)
            hex2stderr_lk((const uint8_t *)&ctl_v4, sizeof(ctl_v4), 1);
        v4hdr_out_lk(">> Control object before", &ctl_v4, id, false);
    }

try_again:
    if (!after1 && (vb > 1)) {
        after1 = true;
        pr2serr_lk("%s: %s\n", __func__, serial ? mrq_ob_s : mrq_vb_s);
    }
    if (serial)
        res = ioctl(fd, SG_IO, &ctl_v4);
    else
        res = ioctl(fd, SG_IOSUBMIT, &ctl_v4);  /* overlapping commands */
    if (res < 0) {
        err = errno;
        if (E2BIG == err)
            sg_take_snap(fd, id, true);
        else if (EBUSY == err) {
            ++num_ebusy;
            std::this_thread::yield();/* allow another thread to progress */
            goto try_again;
        }
        pr2serr_lk("[%d] %s: ioctl(%s, %s)-->%d, errno=%d: %s\n", id,
                   __func__, iosub_str, sg_flags_str(ctl_v4.flags, b_len, b),
                   res, err, strerror(err));
        return -err;
    }
    if (vb > 4) {
        pr2serr_lk("%s: >> Control object after ioctl(%s) seg_blks=%d:\n",
                   __func__, iosub_str, o_seg_blks);
        if (vb > 5)
            hex2stderr_lk((const uint8_t *)&ctl_v4, sizeof(ctl_v4), 1);
        v4hdr_out_lk(">> Control object after", &ctl_v4, id, false);
        if (vb > 5) {
            for (k = 0; k < num_mrq; ++k) {
                if ((vb > 6) || a_v4p[k].info) {
                    snprintf(b, b_len, "a_v4[%d/%d]", k, num_mrq);
                    v4hdr_out_lk(b, (a_v4p + k), id, true);
                }
            }
        }
    }
    num_good = process_mrq_response(rep, &ctl_v4, a_v4p, num_mrq, in_fin_blks,
                                    out_fin_blks, err_on_in);
    if (is_wr)
        out_mrq_q_blks = mrq_q_blks;
    else
        in_mrq_q_blks = mrq_q_blks;
    if (vb > 2)
        pr2serr_lk("%s: >>> seg_blks=%d, num_good=%d, in_q/fin blks=%u/%u;  "
                   "out_q/fin blks=%u/%u\n", __func__, o_seg_blks, num_good,
                   in_mrq_q_blks, in_fin_blks, out_mrq_q_blks, out_fin_blks);

    if (clp->ese) {
        int sres = ctl_v4.spare_out;

        if (sres != 0) {
            clp->reason_res.store(sg_convert_errno(sres));
            pr2serr_lk("Exit due to secondary error [%d]\n", sres);
            return -sres;
        }
    }
    if (num_good < 0)
        return -ENODATA;
    else {
        if (num_good < num_mrq) {
            int resid_blks = in_mrq_q_blks - in_fin_blks;

            if (resid_blks > 0) {
                rep->in_rem_count += resid_blks;
                rep->stop_after_write = ! (err_on_in && clp->in_flags.coe);
            }

            resid_blks = out_mrq_q_blks - out_fin_blks;
            if (resid_blks > 0) {
                rep->out_rem_count += resid_blks;
                rep->stop_after_write = ! (! err_on_in && clp->out_flags.coe);
            }
        }
    }
    return is_wr ? out_fin_blks : in_fin_blks;
}

/* Returns number of blocks successfully processed or a negative error
 * number. */
static int
do_normal_normal_segment(Rq_elem * rep, scat_gath_iter & i_sg_it,
                         scat_gath_iter & o_sg_it, int seg_blks)
{
    int k, kk, res, id, num, d_off;
    int o_seg_blks = seg_blks;
    uint32_t in_fin_blks = 0;
    uint32_t out_fin_blks = 0;
    struct global_collection * clp = rep->clp;

    id = rep->id;
    d_off = 0;
    for (k = 0; seg_blks > 0; ++k, seg_blks -= num, d_off += num) {
        kk = min<int>(seg_blks, clp->bpt);
        num = i_sg_it.linear_for_n_blks(kk);
        res = normal_in_rd(rep, i_sg_it.current_lba(), num,
                           d_off * clp->bs);
        if (res < 0) {
            pr2serr_lk("[%d] %s: normal in failed d_off=%d, err=%d\n",
                       id, __func__, d_off, -res);
            break;
        }
        i_sg_it.add_blks(res);
        if (res < num) {
            d_off += res;
            rep->stop_after_write = true;
            break;
        }
    }
    seg_blks = d_off;
    in_fin_blks = seg_blks;

    if (FT_DEV_NULL == clp->out_type)
        goto fini;
    d_off = 0;
    for (k = 0; seg_blks > 0; ++k, seg_blks -= num, d_off += num) {
        kk = min<int>(seg_blks, clp->bpt);
        num = o_sg_it.linear_for_n_blks(kk);
        res = normal_out_wr(rep, o_sg_it.current_lba(), num,
                            d_off * clp->bs);
        if (res < num) {
            if (res < 0) {
                pr2serr_lk("[%d] %s: normal out failed d_off=%d, err=%d\n",
                           id, __func__, d_off, -res);
                break;
            }
        }
        o_sg_it.add_blks(res);
        if (res < num) {
            d_off += res;
            rep->stop_after_write = true;
            break;
        }
    }
    if (rep->in_resid_bytes > 0) {
        res = extra_out_wr(rep, rep->in_resid_bytes, d_off * clp->bs);
        if (res < 0)
            pr2serr_lk("[%d] %s: extr out failed d_off=%d, err=%d\n", id,
                       __func__, d_off, -res);
        rep->in_resid_bytes = 0;
    }
    seg_blks = d_off;
    out_fin_blks = seg_blks;

fini:
    rep->in_local_count += in_fin_blks;
    rep->out_local_count += out_fin_blks;

    if ((in_fin_blks + out_fin_blks) < (uint32_t)o_seg_blks) {
        int resid_blks = o_seg_blks - in_fin_blks;

        if (resid_blks > 0)
            rep->in_rem_count += resid_blks;
        resid_blks = o_seg_blks - out_fin_blks;
        if (resid_blks > 0)
            rep->out_rem_count += resid_blks;
    }
    return res < 0 ? res : (min<int>(in_fin_blks, out_fin_blks));
}

/* Returns number of blocks successfully processed or a negative error
 * number. */
static int
do_normal_sg_segment(Rq_elem * rep, scat_gath_iter & i_sg_it,
                     scat_gath_iter & o_sg_it, int seg_blks,
                     vector<cdb_arr_t> & a_cdb,
                     vector<struct sg_io_v4> & a_v4)
{
    bool in_is_normal = ! rep->only_in_sg;
    int k, kk, res, id, num, d_off;
    int o_seg_blks = seg_blks;
    uint32_t in_fin_blks = 0;
    uint32_t out_fin_blks = 0;
    struct global_collection * clp = rep->clp;

    id = rep->id;
    a_cdb.clear();
    a_v4.clear();

    if (in_is_normal) {   /* in: normal --> out : sg */
        d_off = 0;
        for (k = 0; seg_blks > 0; ++k, seg_blks -= num, d_off += num) {
            kk = min<int>(seg_blks, clp->bpt);
            num = i_sg_it.linear_for_n_blks(kk);
            res = normal_in_rd(rep, i_sg_it.current_lba(), num,
                               d_off * clp->bs);
            if (res < 0) {
                pr2serr_lk("[%d] %s: normal in failed d_off=%d, err=%d\n",
                           id, __func__, d_off, -res);
                break;
            }
            i_sg_it.add_blks(res);
            if (res < num) {
                d_off += res;
                rep->stop_after_write = true;
                break;
            }
        }
        seg_blks = d_off;
        in_fin_blks = seg_blks;

        if (rep->in_resid_bytes > 0) {
            ++seg_blks;
            rep->in_resid_bytes = 0;
        }
        if (clp->mrq_eq_0)
            res = sg_half_segment_mrq0(rep, o_sg_it, true /* is_wr */,
                                      seg_blks, rep->buffp);
        else
            res = sg_half_segment(rep, o_sg_it, true /* is_wr */, seg_blks,
                                  rep->buffp, a_cdb, a_v4);
        if (res < seg_blks) {
            if (res < 0) {
                pr2serr_lk("[%d] %s: sg out failed d_off=%d, err=%d\n",
                           id, __func__, d_off, -res);
                goto fini;
            }
            rep->stop_after_write = true;
        }
        seg_blks = res;
        out_fin_blks = seg_blks;

    } else {      /* in: sg --> out: normal */
        if (clp->mrq_eq_0)
            res = sg_half_segment_mrq0(rep, i_sg_it, false, seg_blks,
                                       rep->buffp);
        else
            res = sg_half_segment(rep, i_sg_it, false, seg_blks, rep->buffp,
                                  a_cdb, a_v4);
        if (res < seg_blks) {
            if (res < 0) {
                pr2serr_lk("[%d] %s: sg in failed, err=%d\n", id, __func__,
                           -res);
                goto fini;
            }
            rep->stop_after_write = true;
        }
        seg_blks = res;
        in_fin_blks = seg_blks;

        if (FT_DEV_NULL == clp->out_type) {
            out_fin_blks = seg_blks;/* so finish logic doesn't suspect ... */
            goto bypass;
        }
        d_off = 0;
        for (k = 0; seg_blks > 0; ++k, seg_blks -= num, d_off += num) {
            kk = min<int>(seg_blks, clp->bpt);
            num = o_sg_it.linear_for_n_blks(kk);
            res = normal_out_wr(rep, o_sg_it.current_lba(), num,
                                d_off * clp->bs);
            if (res < num) {
                if (res < 0) {
                    pr2serr_lk("[%d] %s: normal out failed d_off=%d, err=%d\n",
                               id, __func__, d_off, -res);
                    break;
                }
            }
            o_sg_it.add_blks(res);
            if (res < num) {
                d_off += res;
                rep->stop_after_write = true;
                break;
            }
        }
        seg_blks = d_off;
        out_fin_blks = seg_blks;
    }
bypass:
    rep->in_local_count += in_fin_blks;
    rep->out_local_count += out_fin_blks;

    if ((in_fin_blks + out_fin_blks) < (uint32_t)o_seg_blks) {
        int resid_blks = o_seg_blks - in_fin_blks;

        if (resid_blks > 0)
            rep->in_rem_count += resid_blks;
        resid_blks = o_seg_blks - out_fin_blks;
        if (resid_blks > 0)
            rep->out_rem_count += resid_blks;
    }
fini:
    return res < 0 ? res : (min<int>(in_fin_blks, out_fin_blks));
}

/* This function sets up a multiple request (mrq) transaction and sends it
 * to the pass-through. Returns number of blocks processed (==seg_blks for
 * all good) or a negative error number. */
static int
do_both_sg_segment_mrq0(Rq_elem * rep, scat_gath_iter & i_sg_it,
                        scat_gath_iter & o_sg_it, int seg_blks)
{
    int k, kk, res, pack_id_base, id, iflags, oflags;
    int num, i_lin_blks, o_lin_blks, cdbsz, err;
    uint32_t in_fin_blks = 0;
    uint32_t out_fin_blks = 0;
    struct global_collection * clp = rep->clp;
    int vb = clp->verbose;
    cdb_arr_t t_cdb = {};
    struct sg_io_v4 t_v4;
    struct sg_io_v4 * t_v4p = &t_v4;
    struct flags_t * iflagsp = &clp->in_flags;
    struct flags_t * oflagsp = &clp->out_flags;
    const char * const a_ioctl_s = "do_both_sg_segment_mrq0: after "
                                   "ioctl(SG_IO)";

    id = rep->id;
    pack_id_base = id * PACK_ID_TID_MULTIPLIER;

    iflags = SGV4_FLAG_SHARE;
    if (iflagsp->mmap && (rep->outregfd >= 0))
        iflags |= SGV4_FLAG_MMAP_IO;
    else
        iflags |= SGV4_FLAG_NO_DXFER;
    if (iflagsp->dio)
        iflags |= SGV4_FLAG_DIRECT_IO;
    if (iflagsp->qhead)
        iflags |= SGV4_FLAG_Q_AT_HEAD;
    if (iflagsp->qtail)
        iflags |= SGV4_FLAG_Q_AT_TAIL;
    if (clp->no_waitq)
        iflags |= SGV4_FLAG_NO_WAITQ;
    if (iflagsp->hipri)
        iflags |= SGV4_FLAG_HIPRI;

    oflags = SGV4_FLAG_SHARE | SGV4_FLAG_NO_DXFER;
    if (oflagsp->dio)
        oflags |= SGV4_FLAG_DIRECT_IO;
    if (oflagsp->qhead)
        oflags |= SGV4_FLAG_Q_AT_HEAD;
    if (oflagsp->qtail)
        oflags |= SGV4_FLAG_Q_AT_TAIL;
    if (clp->no_waitq)
        oflags |= SGV4_FLAG_NO_WAITQ;
    if (oflagsp->hipri)
        oflags |= SGV4_FLAG_HIPRI;

    for (k = 0; seg_blks > 0; ++k, seg_blks -= num) {
        kk = min<int>(seg_blks, clp->bpt);
        i_lin_blks = i_sg_it.linear_for_n_blks(kk);
        o_lin_blks = o_sg_it.linear_for_n_blks(kk);
        num = min<int>(i_lin_blks, o_lin_blks);
        if (num <= 0) {
            res = 0;
            pr2serr_lk("[%d] %s: min(i_lin_blks=%d o_lin_blks=%d) < 1\n", id,
                       __func__, i_lin_blks, o_lin_blks);
            break;
        }

        /* First build the command/request for the read-side*/
        cdbsz = clp->cdbsz_in;
        res = sg_build_scsi_cdb(t_cdb.data(), cdbsz, num,
                                i_sg_it.current_lba(), false, false,
                                iflagsp->fua, iflagsp->dpo, iflagsp->cdl);
        if (res) {
            pr2serr_lk("%s: t=%d: input sg_build_scsi_cdb() failed\n",
                       __func__, id);
            break;
        } else if (vb > 3)
            lk_print_command_len("input cdb: ", t_cdb.data(), cdbsz, true);

        memset(t_v4p, 0, sizeof(*t_v4p));
        t_v4p->guard = 'Q';
        t_v4p->request = (uint64_t)t_cdb.data();
        t_v4p->usr_ptr = t_v4p->request;
        t_v4p->response = (uint64_t)rep->sb;
        t_v4p->max_response_len = sizeof(rep->sb);
        t_v4p->flags = iflags;
        t_v4p->request_len = cdbsz;
        t_v4p->din_xfer_len = num * clp->bs;
        t_v4p->timeout = clp->cmd_timeout;
        t_v4p->request_extra = pack_id_base + ++rep->mrq_pack_id_off;
        clp->most_recent_pack_id.store(t_v4p->request_extra);
mrq0_again:
        res = ioctl(rep->infd, SG_IO, t_v4p);
        err = errno;
        if (vb > 5)
            v4hdr_out_lk(a_ioctl_s, t_v4p, id, false);
        if (res < 0) {
            if (E2BIG == err)
                sg_take_snap(rep->infd, id, true);
            else if (EBUSY == err) {
                ++num_ebusy;
                std::this_thread::yield();/* so other threads can progress */
                goto mrq0_again;
            }
            pr2serr_lk("[%d] %s: ioctl(SG_IO, read-side)-->%d, errno=%d: "
                       "%s\n", id, __func__, res, err, strerror(err));
            return -err;
        }
        if (t_v4p->device_status || t_v4p->transport_status ||
            t_v4p->driver_status) {
            rep->stop_now = true;
            pr2serr_lk("[%d] t_v4[%d]:\n", id, k);
            lk_chk_n_print4("    ", t_v4p, vb > 4);
            return min<int>(in_fin_blks, out_fin_blks);
        }
        rep->in_local_count += num;
        in_fin_blks += num;

        /* Now build the command/request for write-side (WRITE or VERIFY) */
        cdbsz = clp->cdbsz_out;
        res = sg_build_scsi_cdb(t_cdb.data(), cdbsz, num,
                                o_sg_it.current_lba(), clp->verify, true,
                                oflagsp->fua, oflagsp->dpo, oflagsp->cdl);
        if (res) {
            pr2serr_lk("%s: t=%d: output sg_build_scsi_cdb() failed\n",
                       __func__, id);
            break;
        } else if (vb > 3)
            lk_print_command_len("output cdb: ", t_cdb.data(), cdbsz, true);

        memset(t_v4p, 0, sizeof(*t_v4p));
        t_v4p->guard = 'Q';
        t_v4p->request = (uint64_t)t_cdb.data();
        t_v4p->usr_ptr = t_v4p->request;
        t_v4p->response = (uint64_t)rep->sb;
        t_v4p->max_response_len = sizeof(rep->sb);
        t_v4p->flags = oflags;
        t_v4p->request_len = cdbsz;
        t_v4p->dout_xfer_len = num * clp->bs;
        t_v4p->timeout = clp->cmd_timeout;
        t_v4p->request_extra = pack_id_base + ++rep->mrq_pack_id_off;
        clp->most_recent_pack_id.store(t_v4p->request_extra);
mrq0_again2:
        res = ioctl(rep->outfd, SG_IO, t_v4p);
        err = errno;
        if (vb > 5)
            v4hdr_out_lk(a_ioctl_s, t_v4p, id, false);
        if (res < 0) {
            if (E2BIG == err)
                sg_take_snap(rep->outfd, id, true);
            else if (EBUSY == err) {
                ++num_ebusy;
                std::this_thread::yield();/* so other threads can progress */
                goto mrq0_again2;
            }
            pr2serr_lk("[%d] %s: ioctl(SG_IO, write-side)-->%d, errno=%d: "
                       "%s\n", id, __func__, res, err, strerror(err));
            return -err;
        }
        if (t_v4p->device_status || t_v4p->transport_status ||
            t_v4p->driver_status) {
            rep->stop_now = true;
            pr2serr_lk("[%d] t_v4[%d]:\n", id, k);
            lk_chk_n_print4("    ", t_v4p, vb > 4);
            return min<int>(in_fin_blks, out_fin_blks);
        }
        rep->out_local_count += num;
        out_fin_blks += num;

        i_sg_it.add_blks(num);
        o_sg_it.add_blks(num);
    }
    return min<int>(in_fin_blks, out_fin_blks);
}

/* This function sets up a multiple request (mrq) transaction and sends it
 * to the pass-through. Returns number of blocks processed (==seg_blks for
 * all good) or a negative error number. */
static int
do_both_sg_segment(Rq_elem * rep, scat_gath_iter & i_sg_it,
                   scat_gath_iter & o_sg_it, int seg_blks,
                   vector<cdb_arr_t> & a_cdb,
                   vector<struct sg_io_v4> & a_v4)
{
    bool err_on_in = false;
    int num_mrq, k, res, fd, mrq_pack_id_base, id, b_len, iflags, oflags;
    int num, kk, i_lin_blks, o_lin_blks, cdbsz, num_good, err;
    int o_seg_blks = seg_blks;
    uint32_t in_fin_blks, out_fin_blks;
    uint32_t in_mrq_q_blks = 0;
    uint32_t out_mrq_q_blks = 0;
    const int max_cdb_sz = MAX_SCSI_CDB_SZ;
    struct sg_io_v4 * a_v4p;
    struct sg_io_v4 ctl_v4;     /* MRQ control object */
    struct global_collection * clp = rep->clp;
    const char * iosub_str = "SG_IOSUBMIT(svb)";
    char b[80];
    cdb_arr_t t_cdb = {};
    struct sg_io_v4 t_v4;
    struct sg_io_v4 * t_v4p = &t_v4;
    struct flags_t * iflagsp = &clp->in_flags;
    struct flags_t * oflagsp = &clp->out_flags;
    int vb = clp->verbose;

    id = rep->id;
    b_len = sizeof(b);

    a_cdb.clear();
    a_v4.clear();
    mrq_pack_id_base = id * PACK_ID_TID_MULTIPLIER;

    iflags = SGV4_FLAG_SHARE;
    if (iflagsp->mmap && (rep->outregfd >= 0))
        iflags |= SGV4_FLAG_MMAP_IO;
    else
        iflags |= SGV4_FLAG_NO_DXFER;
    if (iflagsp->dio)
        iflags |= SGV4_FLAG_DIRECT_IO;
    if (iflagsp->qhead)
        iflags |= SGV4_FLAG_Q_AT_HEAD;
    if (iflagsp->qtail)
        iflags |= SGV4_FLAG_Q_AT_TAIL;
    if (clp->no_waitq)
        iflags |= SGV4_FLAG_NO_WAITQ;
    if (iflagsp->hipri)
        iflags |= SGV4_FLAG_HIPRI;

    oflags = SGV4_FLAG_SHARE | SGV4_FLAG_NO_DXFER;
    if (oflagsp->dio)
        oflags |= SGV4_FLAG_DIRECT_IO;
    if (oflagsp->qhead)
        oflags |= SGV4_FLAG_Q_AT_HEAD;
    if (oflagsp->qtail)
        oflags |= SGV4_FLAG_Q_AT_TAIL;
    if (clp->no_waitq)
        oflags |= SGV4_FLAG_NO_WAITQ;
    if (oflagsp->hipri)
        oflags |= SGV4_FLAG_HIPRI;
    oflags |= SGV4_FLAG_DO_ON_OTHER;

    for (k = 0; seg_blks > 0; ++k, seg_blks -= num) {
        kk = min<int>(seg_blks, clp->bpt);
        i_lin_blks = i_sg_it.linear_for_n_blks(kk);
        o_lin_blks = o_sg_it.linear_for_n_blks(kk);
        num = min<int>(i_lin_blks, o_lin_blks);
        if (num <= 0) {
            res = 0;
            pr2serr_lk("[%d] %s: min(i_lin_blks=%d o_lin_blks=%d) < 1\n", id,
                       __func__, i_lin_blks, o_lin_blks);
            break;
        }

        /* First build the command/request for the read-side*/
        cdbsz = clp->cdbsz_in;
        res = sg_build_scsi_cdb(t_cdb.data(), cdbsz, num,
                                i_sg_it.current_lba(), false, false,
                                iflagsp->fua, iflagsp->dpo, iflagsp->cdl);
        if (res) {
            pr2serr_lk("%s: t=%d: input sg_build_scsi_cdb() failed\n",
                       __func__, id);
            break;
        } else if (vb > 3)
            lk_print_command_len("input cdb: ", t_cdb.data(), cdbsz, true);
        a_cdb.push_back(t_cdb);

        memset(t_v4p, 0, sizeof(*t_v4p));
        t_v4p->guard = 'Q';
        t_v4p->flags = iflags;
        t_v4p->request_len = cdbsz;
        t_v4p->response = (uint64_t)rep->sb;
        t_v4p->max_response_len = sizeof(rep->sb);
        t_v4p->usr_ptr = (uint64_t)&a_cdb[a_cdb.size() - 1];
        t_v4p->din_xfer_len = num * clp->bs;
        t_v4p->timeout = clp->cmd_timeout;
        in_mrq_q_blks += num;
        t_v4p->request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;
        clp->most_recent_pack_id.store(t_v4p->request_extra);
        a_v4.push_back(t_v4);

        /* Now build the command/request for write-side (WRITE or VERIFY) */
        cdbsz = clp->cdbsz_out;
        res = sg_build_scsi_cdb(t_cdb.data(), cdbsz, num,
                                o_sg_it.current_lba(), clp->verify, true,
                                oflagsp->fua, oflagsp->dpo, oflagsp->cdl);
        if (res) {
            pr2serr_lk("%s: t=%d: output sg_build_scsi_cdb() failed\n",
                       __func__, id);
            break;
        } else if (vb > 3)
            lk_print_command_len("output cdb: ", t_cdb.data(), cdbsz, true);
        a_cdb.push_back(t_cdb);
        memset(t_v4p, 0, sizeof(*t_v4p));
        t_v4p->guard = 'Q';
        t_v4p->flags = oflags;
        t_v4p->request_len = cdbsz;
        t_v4p->response = (uint64_t)rep->sb;
        t_v4p->max_response_len = sizeof(rep->sb);
        t_v4p->usr_ptr = (uint64_t)&a_cdb[a_cdb.size() - 1];
        t_v4p->dout_xfer_len = num * clp->bs;
        t_v4p->timeout = clp->cmd_timeout;
        out_mrq_q_blks += num;
        t_v4p->request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;
        clp->most_recent_pack_id.store(t_v4p->request_extra);
        a_v4.push_back(t_v4);

        i_sg_it.add_blks(num);
        o_sg_it.add_blks(num);
    }

    if (vb > 6) {
        pr2serr_lk("%s: t=%d: a_v4 array contents:\n", __func__, id);
        hex2stderr_lk((const uint8_t *)a_v4.data(),
                      a_v4.size() * sizeof(struct sg_io_v4), 1);
    }
    if (rep->both_sg || rep->same_sg)
        fd = rep->infd;         /* assume share to rep->outfd */
    else {
        pr2serr_lk("[%d] %s: why am I here? Want 2 sg devices\n", id,
                   __func__);
        res = -1;
        goto fini;
    }
    num_mrq = a_v4.size();
    a_v4p = a_v4.data();
    res = 0;
    memset(&ctl_v4, 0, sizeof(ctl_v4));
    ctl_v4.guard = 'Q';
    ctl_v4.request_len = a_cdb.size() * max_cdb_sz;
    ctl_v4.request = (uint64_t)a_cdb.data();
    ctl_v4.max_response_len = sizeof(rep->sb);
    ctl_v4.response = (uint64_t)rep->sb;
    ctl_v4.flags = SGV4_FLAG_MULTIPLE_REQS | SGV4_FLAG_SHARE;
    if (! (iflagsp->coe || oflagsp->coe))
        ctl_v4.flags |= SGV4_FLAG_STOP_IF;
    if ((! clp->verify) && clp->out_flags.order)
        ctl_v4.flags |= SGV4_FLAG_ORDERED_WR;
    if (clp->mrq_hipri)
        ctl_v4.flags |= SGV4_FLAG_HIPRI;
    ctl_v4.dout_xferp = (uint64_t)a_v4.data();        /* request array */
    ctl_v4.dout_xfer_len = a_v4.size() * sizeof(struct sg_io_v4);
    ctl_v4.din_xferp = (uint64_t)a_v4.data();         /* response array */
    ctl_v4.din_xfer_len = a_v4.size() * sizeof(struct sg_io_v4);
    if (false /* allow_mrq_abort */) {
        ctl_v4.request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;
        clp->most_recent_pack_id.store(ctl_v4.request_extra);
    }

    if (vb && vb_first_time.load()) {
        pr2serr_lk("First controlling object output by ioctl(%s), flags: "
                   "%s\n", iosub_str, sg_flags_str(ctl_v4.flags, b_len, b));
        vb_first_time.store(false);
    } else if (vb > 4)
        pr2serr_lk("%s: >> Control object _before_ ioctl(%s):\n", __func__,
                   iosub_str);
    if (vb > 4) {
        if (vb > 5)
            hex2stderr_lk((const uint8_t *)&ctl_v4, sizeof(ctl_v4), 1);
        v4hdr_out_lk(">> Control object before", &ctl_v4, id, false);
    }

try_again:
    if (!after1 && (vb > 1)) {
        after1 = true;
        pr2serr_lk("%s: %s\n", __func__, mrq_svb_s);
    }
    res = ioctl(fd, SG_IOSUBMIT, &ctl_v4);
    if (res < 0) {
        err = errno;
        if (E2BIG == err)
                sg_take_snap(fd, id, true);
        else if (EBUSY == err) {
            ++num_ebusy;
            std::this_thread::yield();/* allow another thread to progress */
            goto try_again;
        }
        pr2serr_lk("%s: ioctl(%s, %s)-->%d, errno=%d: %s\n", __func__,
                   iosub_str, sg_flags_str(ctl_v4.flags, b_len, b), res, err,
                   strerror(err));
        res = -err;
        goto fini;
    }
    if (vb > 4) {
        pr2serr_lk("%s: >> Control object after ioctl(%s) seg_blks=%d:\n",
                   __func__, iosub_str, o_seg_blks);
        if (vb > 5)
            hex2stderr_lk((const uint8_t *)&ctl_v4, sizeof(ctl_v4), 1);
        v4hdr_out_lk(">> Control object after", &ctl_v4, id, false);
        if (vb > 5) {
            for (k = 0; k < num_mrq; ++k) {
                if ((vb > 6) || a_v4p[k].info) {
                    snprintf(b, b_len, "a_v4[%d/%d]", k, num_mrq);
                    v4hdr_out_lk(b, (a_v4p + k), id, true);
                }
            }
        }
    }
    num_good = process_mrq_response(rep, &ctl_v4, a_v4p, num_mrq, in_fin_blks,
                                    out_fin_blks, err_on_in);
    if (vb > 2)
        pr2serr_lk("%s: >>> seg_blks=%d, num_good=%d, in_q/fin blks=%u/%u;  "
                   "out_q/fin blks=%u/%u\n", __func__, o_seg_blks, num_good,
                   in_mrq_q_blks, in_fin_blks, out_mrq_q_blks, out_fin_blks);

    if (clp->ese) {
        int sres = ctl_v4.spare_out;

        if (sres != 0) {
            clp->reason_res.store(sg_convert_errno(sres));
            pr2serr_lk("Exit due to secondary error [%d]\n", sres);
            return -sres;
        }
    }
    if (num_good < 0)
        res = -ENODATA;
    else {
        rep->in_local_count += in_fin_blks;
        rep->out_local_count += out_fin_blks;

        if (num_good < num_mrq) {       /* reduced number completed */
            int resid_blks = in_mrq_q_blks - in_fin_blks;

            if (resid_blks > 0) {
                rep->in_rem_count += resid_blks;
                rep->stop_after_write = ! (err_on_in && clp->in_flags.coe);
            }

            resid_blks = out_mrq_q_blks - out_fin_blks;
            if (resid_blks > 0) {
                rep->out_rem_count += resid_blks;
                rep->stop_after_write = ! ((! err_on_in) &&
                                           clp->out_flags.coe);
            }
        }
    }
fini:
    return res < 0 ? res : (min<int>(in_fin_blks, out_fin_blks));
}

#if 0
/* Returns number found and (partially) processed. 'num' is the number of
 * completions to wait for when > 0. When 'num' is zero check all inflight
 * request on 'fd' and return quickly if none completed (i.e. don't wait)
 * If error return negative errno and if no request inflight or waiting
 * then return -9999 . */
static int
sg_blk_poll(int fd, int num)
{
    int res;
    struct sg_extended_info sei;
    struct sg_extended_info * seip = &sei;

    memset(seip, 0, sizeof(*seip));
    seip->sei_rd_mask |= SG_SEIM_BLK_POLL;
    seip->sei_wr_mask |= SG_SEIM_BLK_POLL;
    seip->num = (num < 0) ? 0 : num;
    res = ioctl(fd, SG_SET_GET_EXTENDED, seip);
    if (res < 0) {
        pr2serr_lk("%s: SG_SET_GET_EXTENDED(BLK_POLL) error: %s\n",
                   __func__, strerror(errno));
        return res;
    }
    return (seip->num == -1) ? -9999 : seip->num;
}
#endif

/* Returns reserved_buffer_size/mmap_size if success, else 0 for failure */
static int
sg_prepare_resbuf(int fd, struct global_collection *clp, bool is_in,
                  uint8_t **mmpp)
{
    static bool done = false;
    bool no_dur = is_in ? clp->in_flags.no_dur : clp->out_flags.no_dur;
    bool masync = is_in ? clp->in_flags.masync : clp->out_flags.masync;
    bool wq_excl = is_in ? clp->in_flags.wq_excl : clp->out_flags.wq_excl;
    int elem_sz = clp->elem_sz;
    int res, t, num, err;
    uint8_t *mmp;
    struct sg_extended_info sei;
    struct sg_extended_info * seip = &sei;

    res = ioctl(fd, SG_GET_VERSION_NUM, &t);
    if ((res < 0) || (t < 40000)) {
        if (ioctl(fd, SG_GET_RESERVED_SIZE, &num) < 0) {
            perror("SG_GET_RESERVED_SIZE ioctl failed");
            return 0;
        }
        if (! done) {
            done = true;
            pr2serr_lk("%ssg driver prior to 4.0.00, reduced functionality\n",
                       my_name);
        }
        goto bypass;
    }
    if (elem_sz >= 4096) {
        memset(seip, 0, sizeof(*seip));
        seip->sei_rd_mask |= SG_SEIM_SGAT_ELEM_SZ;
        res = ioctl(fd, SG_SET_GET_EXTENDED, seip);
        if (res < 0)
            pr2serr_lk("sg_mrq_dd: %s: SG_SET_GET_EXTENDED(SGAT_ELEM_SZ) rd "
                       "error: %s\n", __func__, strerror(errno));
        if (elem_sz != (int)seip->sgat_elem_sz) {
            memset(seip, 0, sizeof(*seip));
            seip->sei_wr_mask |= SG_SEIM_SGAT_ELEM_SZ;
            seip->sgat_elem_sz = elem_sz;
            res = ioctl(fd, SG_SET_GET_EXTENDED, seip);
            if (res < 0)
                pr2serr_lk("sg_mrq_dd: %s: SG_SET_GET_EXTENDED(SGAT_ELEM_SZ) "
                           "wr error: %s\n", __func__, strerror(errno));
        }
    }
    if (no_dur || masync) {
        memset(seip, 0, sizeof(*seip));
        seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
        if (no_dur) {
            seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_NO_DURATION;
            seip->ctl_flags |= SG_CTL_FLAGM_NO_DURATION;
        }
        if (masync) {
            seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_MORE_ASYNC;
            seip->ctl_flags |= SG_CTL_FLAGM_MORE_ASYNC;
        }
        if (wq_excl) {
            seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_EXCL_WAITQ;
            seip->ctl_flags |= SG_CTL_FLAGM_EXCL_WAITQ;
        }
        res = ioctl(fd, SG_SET_GET_EXTENDED, seip);
        if (res < 0)
            pr2serr_lk("sg_mrq_dd: %s: SG_SET_GET_EXTENDED(NO_DURATION) "
                       "error: %s\n", __func__, strerror(errno));
    }
bypass:
    num = clp->bs * clp->bpt;
    res = ioctl(fd, SG_SET_RESERVED_SIZE, &num);
    if (res < 0) {
        perror("sg_mrq_dd: SG_SET_RESERVED_SIZE error");
        return 0;
    } else {
        int nn;

        res = ioctl(fd, SG_GET_RESERVED_SIZE, &nn);
        if (res < 0) {
            perror("sg_mrq_dd: SG_GET_RESERVED_SIZE error");
            return 0;
        }
        if (nn < num) {
            pr2serr_lk("%s: SG_GET_RESERVED_SIZE shows size truncated, "
                       "wanted %d got %d\n", __func__, num, nn);
            return 0;
        }
        if (mmpp) {
            mmp = (uint8_t *)mmap(NULL, num, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, fd, 0);
            if (MAP_FAILED == mmp) {
                err = errno;
                pr2serr_lk("sg_mrq_dd: %s: sz=%d, fd=%d, mmap() failed: %s\n",
                           __func__, num, fd, strerror(err));
                return 0;
            }
            *mmpp = mmp;
        }
    }
    t = 1;
    res = ioctl(fd, SG_SET_FORCE_PACK_ID, &t);
    if (res < 0)
        perror("sg_mrq_dd: SG_SET_FORCE_PACK_ID error");
    if (clp->unit_nanosec) {
        memset(seip, 0, sizeof(*seip));
        seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
        seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_TIME_IN_NS;
        seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;
        if (ioctl(fd, SG_SET_GET_EXTENDED, seip) < 0) {
            res = -1;
            pr2serr_lk("ioctl(EXTENDED(TIME_IN_NS)) failed, errno=%d %s\n",
                       errno, strerror(errno));
        }
    }
    if (clp->no_waitq) {
        memset(seip, 0, sizeof(*seip));
        seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
        seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_NO_WAIT_POLL;
        seip->ctl_flags |= SG_CTL_FLAGM_NO_WAIT_POLL;
        if (ioctl(fd, SG_SET_GET_EXTENDED, seip) < 0) {
            res = -1;
            pr2serr_lk("ioctl(EXTENDED(NO_WAIT_POLL)) failed, errno=%d %s\n",
                       errno, strerror(errno));
        }
    }
    if (clp->verbose) {
        t = 1;
        /* more info in /proc/scsi/sg/debug */
        res = ioctl(fd, SG_SET_DEBUG, &t);
        if (res < 0)
            perror("sg_mrq_dd: SG_SET_DEBUG error");
    }
    return (res < 0) ? 0 : num;
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

/* Returns the number of times either 'ch1' or 'ch2' is found in
 * string 's' given the string's length. */
int
num_either_ch_in_str(const char * s, int slen, int ch1, int ch2)
{
    int k;
    int res = 0;

    while (--slen >= 0) {
        k = s[slen];
        if ((ch1 == k) || (ch2 == k))
            ++res;
    }
    return res;
}

/* Allocates and then populates a scatter gether list (array) and returns
 * it via *sgl_pp. Return of 0 is okay, else error number (in which case
 * NULL is written to *sgl_pp) . */
static int
skip_seek(struct global_collection *clp, const char * key, const char * buf,
          bool is_skip, bool ignore_verbose)
{
    bool def_hex = false;
    int len;
    int vb = clp->verbose;  /* needs to appear before skip/seek= on cl */
    int64_t ll;
    const char * cp;
    class scat_gath_list & either_list = is_skip ? clp->i_sgl : clp->o_sgl;

    if (ignore_verbose)
        vb = 0;
    len = (int)strlen(buf);
    if ((('-' == buf[0]) && (1 == len)) || ((len > 1) && ('@' == buf[0])) ||
        ((len > 2) && ('H' == toupper(buf[0])) && ('@' == buf[1]))) {
        if ('H' == toupper(buf[0])) {
            cp = buf + 2;
            def_hex = true;
        } else if ('-' == buf[0])
            cp = buf;
        else
            cp = buf + 1;
        if (! either_list.load_from_file(cp, def_hex, clp->flexible, true)) {
            pr2serr("bad argument to '%s=' [err=%d]\n", key,
                    either_list.m_errno);
            return SG_LIB_SYNTAX_ERROR;
        }
    } else if (num_either_ch_in_str(buf, len, ',', ' ') > 0) {
        if (! either_list.load_from_cli(buf, vb > 0)) {
            pr2serr("bad command line argument to '%s='\n", key);
            return SG_LIB_SYNTAX_ERROR;
        }
    } else {    /* single number on command line (e.g. skip=1234) */
        ll = sg_get_llnum(buf);
        if (-1LL == ll) {
            pr2serr("bad argument to '%s='\n", key);
            return SG_LIB_SYNTAX_ERROR;
        }
        either_list.append_1or(0, ll);
        if (vb > 1)
            pr2serr("%s: singleton, half a degenerate sgl element\n", key);
    }

    either_list.sum_scan(key, vb > 3 /* bool show_sgl */, vb > 1);
    return 0;
}

static bool
process_flags(const char * arg, struct flags_t * fp)
{
    char buff[256];
    char * cp;
    char * np;

    strncpy(buff, arg, sizeof(buff));
    buff[sizeof(buff) - 1] = '\0';
    if ('\0' == buff[0]) {
        pr2serr("no flag found\n");
        return false;
    }
    cp = buff;
    do {
        np = strchr(cp, ',');
        if (np)
            *np++ = '\0';
        if (0 == strcmp(cp, "00"))
            fp->zero = true;
        else if (0 == strcmp(cp, "append"))
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
        else if (0 == strcmp(cp, "ff"))
            fp->ff = true;
        else if (0 == strcmp(cp, "fua"))
            fp->fua = true;
        else if (0 == strcmp(cp, "hipri"))
            fp->hipri = true;
        else if (0 == strcmp(cp, "masync"))
            fp->masync = true;
        else if (0 == strcmp(cp, "mmap"))
            ++fp->mmap;         /* mmap > 1 stops munmap() being called */
        else if (0 == strcmp(cp, "nodur"))
            fp->no_dur = true;
        else if (0 == strcmp(cp, "no_dur"))
            fp->no_dur = true;
        else if (0 == strcmp(cp, "no_dur"))
            fp->no_dur = true;
        else if (0 == strcmp(cp, "noxfer"))
            ;           /* accept but ignore */
        else if (0 == strcmp(cp, "null"))
            ;
        else if (0 == strcmp(cp, "ordered"))
            fp->order = true;
        else if (0 == strcmp(cp, "order"))
            fp->order = true;
        else if (0 == strcmp(cp, "qhead"))
            fp->qhead = true;
        else if (0 == strcmp(cp, "qtail"))
            fp->qtail = true;
        else if (0 == strcmp(cp, "random"))
            fp->random = true;
        else if (0 == strcmp(cp, "serial"))
            fp->serial = true;
        else if (0 == strcmp(cp, "swait"))
            ;           /* accept but ignore */
        else if (0 == strcmp(cp, "wq_excl"))
            fp->wq_excl = true;
        else {
            pr2serr("unrecognised flag: %s\n", cp);
            return false;
        }
        cp = np;
    } while (cp);
    return true;
}

static int
sg_in_open(struct global_collection *clp, const char *inf, uint8_t **mmpp,
           int * mmap_lenp, bool move_data)
{
    int fd, err, n;
    int flags = O_RDWR;
    char ebuff[EBUFF_SZ];

    if (clp->in_flags.direct)
        flags |= O_DIRECT;
    if (clp->in_flags.excl)
        flags |= O_EXCL;
    if (clp->in_flags.dsync)
        flags |= O_SYNC;

    if ((fd = open(inf, flags)) < 0) {
        err = errno;
        snprintf(ebuff, EBUFF_SZ, "%s: could not open %s for sg reading",
                 __func__, inf);
        perror(ebuff);
        return -sg_convert_errno(err);
    }
    if (move_data) {
        n = sg_prepare_resbuf(fd, clp, true, mmpp);
        if (n <= 0)
            return -SG_LIB_FILE_ERROR;
    } else
        n = 0;
    if (mmap_lenp)
        *mmap_lenp = n;
    return fd;
}

static int
sg_out_open(struct global_collection *clp, const char *outf, uint8_t **mmpp,
            int * mmap_lenp, bool move_data)
{
    int fd, err, n;
    int flags = O_RDWR;
    char ebuff[EBUFF_SZ];

    if (clp->out_flags.direct)
        flags |= O_DIRECT;
    if (clp->out_flags.excl)
        flags |= O_EXCL;
    if (clp->out_flags.dsync)
        flags |= O_SYNC;

    if ((fd = open(outf, flags)) < 0) {
        err = errno;
        snprintf(ebuff,  EBUFF_SZ, "%s: could not open %s for sg %s",
                 __func__, outf, (clp->verify ? "verifying" : "writing"));
        perror(ebuff);
        return -sg_convert_errno(err);
    }
    if (move_data) {
        n = sg_prepare_resbuf(fd, clp, false, mmpp);
        if (n <= 0)
            return -SG_LIB_FILE_ERROR;
    } else
        n = 0;
    if (mmap_lenp)
        *mmap_lenp = n;
    return fd;
}

/* Process arguments given to 'conv=" option. Returns 0 on success,
 * 1 on error. */
static int
process_conv(const char * arg, struct flags_t * ifp, struct flags_t * ofp)
{
    char buff[256];
    char * cp;
    char * np;

    strncpy(buff, arg, sizeof(buff));
    buff[sizeof(buff) - 1] = '\0';
    if ('\0' == buff[0]) {
        pr2serr("no conversions found\n");
        return 1;
    }
    cp = buff;
    do {
        np = strchr(cp, ',');
        if (np)
            *np++ = '\0';
        if (0 == strcmp(cp, "nocreat"))
            ofp->nocreat = true;
        else if (0 == strcmp(cp, "noerror"))
            ifp->coe = true;         /* will still fail on write error */
        else if (0 == strcmp(cp, "notrunc"))
            ;         /* this is the default action of sg_dd so ignore */
        else if (0 == strcmp(cp, "null"))
            ;
        else if (0 == strcmp(cp, "sync"))
            ;   /* dd(susv4): pad errored block(s) with zeros but sg_dd does
                 * that by default. Typical dd use: 'conv=noerror,sync' */
        else {
            pr2serr("unrecognised flag: %s\n", cp);
            return 1;
        }
        cp = np;
    } while (cp);
    return 0;
}

#define STR_SZ 1024
#define INOUTF_SZ 512

static int
parse_cmdline_sanity(int argc, char * argv[], struct global_collection * clp,
                     char * inf, char * outf, char * outregf)
{
    bool contra = false;
    bool verbose_given = false;
    bool version_given = false;
    bool verify_given = false;
    bool bpt_given = false;
    int ibs = 0;
    int obs = 0;
    int k, keylen, n, res;
    char str[STR_SZ];
    char * key;
    char * buf;
    char * skip_buf = NULL;
    char * seek_buf = NULL;
    const char * cp;
    const char * ccp;

    for (k = 1; k < argc; k++) {
        if (argv[k]) {
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
        } else
            continue;

        for (key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        keylen = strlen(key);
        if (0 == strcmp(key, "bpt")) {
            clp->bpt = sg_get_num(buf);
            if (-1 == clp->bpt) {
                pr2serr("%sbad argument to 'bpt='\n", my_name);
                goto syn_err;
            }
            bpt_given = true;
        } else if (0 == strcmp(key, "bs")) {
            clp->bs = sg_get_num(buf);
            if (-1 == clp->bs) {
                pr2serr("%sbad argument to 'bs='\n", my_name);
                goto syn_err;
            }
        } else if (0 == strcmp(key, "cdbsz")) {
            ccp = strchr(buf, ',');
            n = sg_get_num(buf);
            if ((n < 0) || (n > 32)) {
                pr2serr("%s: bad argument to 'cdbsz=', expect 6, 10, 12 or "
                        "16\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
            clp->cdbsz_in = n;
            if (ccp) {
                n = sg_get_num(ccp + 1);
                if ((n < 0) || (n > 32)) {
                    pr2serr("%s: bad second argument to 'cdbsz=', expect 6, "
                            "10, 12 or 16\n", my_name);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            clp->cdbsz_out = n;
            clp->cdbsz_given = true;
        } else if (0 == strcmp(key, "cdl")) {
            ccp = strchr(buf, ',');
            n = sg_get_num(buf);
            if ((n < 0) || (n > 7)) {
                pr2serr("%s: bad argument to 'cdl=', expect 0 to 7\n",
                         my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
            clp->in_flags.cdl = n;
            if (ccp) {
                n = sg_get_num(ccp + 1);
                if ((n < 0) || (n > 7)) {
                    pr2serr("%s: bad second argument to 'cdl=', expect 0 "
                            "to 7\n", my_name);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            clp->out_flags.cdl = n;
            clp->cdl_given = true;
        } else if (0 == strcmp(key, "coe")) {
            /* not documented, for compat with sgh_dd */
            clp->in_flags.coe = !! sg_get_num(buf);
            clp->out_flags.coe = clp->in_flags.coe;
        } else if (0 == strcmp(key, "conv")) {
            if (process_conv(buf, &clp->in_flags, &clp->out_flags)) {
                pr2serr("%s: bad argument to 'conv='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "count")) {
            if (clp->count_given) {
                pr2serr("second 'count=' argument detected, only one "
                        "please\n");
                contra = true;
                goto syn_err;
            }
            if (0 != strcmp("-1", buf)) {
                clp->dd_count = sg_get_llnum(buf);
                if (-1LL == clp->dd_count) {
                    pr2serr("%sbad argument to 'count='\n", my_name);
                    goto syn_err;
                }
            }   /* treat 'count=-1' as calculate count (same as not given) */
            clp->count_given = true;
        } else if (0 == strcmp(key, "dio")) {
            clp->in_flags.dio = !! sg_get_num(buf);
            clp->out_flags.dio = clp->in_flags.dio;
        } else if (0 == strcmp(key, "elemsz_kb")) {
            n = sg_get_num(buf);
            if (n < 1) {
                pr2serr("elemsz_kb=EKB wants an integer > 0\n");
                goto syn_err;
            }
            if (n & (n - 1)) {
                pr2serr("elemsz_kb=EKB wants EKB to be power of 2\n");
                goto syn_err;
            }
            clp->elem_sz = n * 1024;
        } else if (0 == strcmp(key, "ese")) {
            n = sg_get_num(buf);
            if (n < 0) {
                pr2serr("ese= wants 0 (default) or 1\n");
                goto syn_err;
            }
            clp->ese = !!n;
        } else if (0 == strcmp(key, "fua")) {
            n = sg_get_num(buf);
            if (n & 1)
                clp->out_flags.fua = true;
            if (n & 2)
                clp->in_flags.fua = true;
        } else if (0 == strcmp(key, "ibs")) {
            ibs = sg_get_num(buf);
            if (-1 == ibs) {
                pr2serr("%sbad argument to 'ibs='\n", my_name);
                goto syn_err;
            }
        } else if (0 == strcmp(key, "if")) {
            if ('\0' != inf[0]) {
                pr2serr("Second 'if=' argument??\n");
                goto syn_err;
            } else {
                memcpy(inf, buf, INOUTF_SZ);
                inf[INOUTF_SZ - 1] = '\0';      /* noisy compiler */
            }
        } else if (0 == strcmp(key, "iflag")) {
            if (! process_flags(buf, &clp->in_flags)) {
                pr2serr("%sbad argument to 'iflag='\n", my_name);
                goto syn_err;
            }
        } else if ((0 == strcmp(key, "hipri")) ||
                   (0 == strcmp(key, "mrq"))) {
            if (isdigit(buf[0]))
                cp = buf;
            else {
                pr2serr("%sonly mrq=NRQS or hipri=NRQS which is a number "
                        "allowed here\n", my_name);
                goto syn_err;
            }
            clp->mrq_num = sg_get_num(cp);
            if (clp->mrq_num < 0) {
                pr2serr("%sbad argument to 'mrq='\n", my_name);
                goto syn_err;
            }
            if (0 == clp->mrq_num) {
                clp->mrq_eq_0 = true;
                clp->mrq_num = 1;
                pr2serr("note: send single, non-mrq commands\n");
            }
            if ('h' == key[0])
                clp->mrq_hipri = true;
        } else if ((0 == strcmp(key, "no_waitq")) ||
                   (0 == strcmp(key, "no-waitq"))) {
            n = sg_get_num(buf);
            if (-1 == n) {
                pr2serr("%sbad argument to 'no_waitq=', expect 0 or 1\n",
                        my_name);
                goto syn_err;
            }
            clp->no_waitq = !!n;
        } else if (0 == strcmp(key, "obs")) {
            obs = sg_get_num(buf);
            if (-1 == obs) {
                pr2serr("%sbad argument to 'obs='\n", my_name);
                goto syn_err;
            }
        } else if (strcmp(key, "ofreg") == 0) {
            if ('\0' != outregf[0]) {
                pr2serr("Second OFREG argument??\n");
                contra = true;
                goto syn_err;
            } else {
                memcpy(outregf, buf, INOUTF_SZ);
                outregf[INOUTF_SZ - 1] = '\0';  /* noisy compiler */
            }
        } else if (strcmp(key, "of") == 0) {
            if ('\0' != outf[0]) {
                pr2serr("Second 'of=' argument??\n");
                goto syn_err;
            } else {
                memcpy(outf, buf, INOUTF_SZ);
                outf[INOUTF_SZ - 1] = '\0';     /* noisy compiler */
            }
        } else if (0 == strcmp(key, "oflag")) {
            if (! process_flags(buf, &clp->out_flags)) {
                pr2serr("%sbad argument to 'oflag='\n", my_name);
                goto syn_err;
            }
        } else if (0 == strcmp(key, "seek")) {
            n = strlen(buf);
            if (n < 1) {
                pr2serr("%sneed argument to 'seek='\n", my_name);
                goto syn_err;
            }
            seek_buf = (char *)calloc(n + 16, 1);
            memcpy(seek_buf, buf, n + 1);
        } else if (0 == strcmp(key, "skip")) {
            n = strlen(buf);
            if (n < 1) {
                pr2serr("%sneed argument to 'skip='\n", my_name);
                goto syn_err;
            }
            skip_buf = (char *)calloc(n + 16, 1);
            memcpy(skip_buf, buf, n + 1);
        } else if (0 == strcmp(key, "sync"))
            do_sync = !! sg_get_num(buf);
        else if (0 == strcmp(key, "thr"))
            num_threads = sg_get_num(buf);
        else if (0 == strcmp(key, "time")) {
            ccp = strchr(buf, ',');
            do_time = sg_get_num(buf);
            if (do_time < 0) {
                pr2serr("%sbad argument to 'time=0|1|2'\n", my_name);
                goto syn_err;
            }
            if (ccp) {
                n = sg_get_num(ccp + 1);
                if (n < 0) {
                    pr2serr("%sbad argument to 'time=0|1|2,TO'\n", my_name);
                    goto syn_err;
                }
                clp->cmd_timeout = n ? (n * 1000) : DEF_TIMEOUT;
            }
        } else if (0 == strncmp(key, "verb", 4))
            clp->verbose = sg_get_num(buf);
        else if ((keylen > 1) && ('-' == key[0]) && ('-' != key[1])) {
            res = 0;
            n = num_chs_in_str(key + 1, keylen - 1, 'd');
            clp->dry_run += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'h');
            clp->help += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'p');
            if (n > 0)
                clp->prefetch = true;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'v');
            if (n > 0)
                verbose_given = true;
            clp->verbose += n;   /* -v  ---> --verbose */
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'V');
            if (n > 0)
                version_given = true;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'x');
            if (n > 0)
                verify_given = true;
            res += n;

            if (res < (keylen - 1)) {
                pr2serr("Unrecognised short option in '%s', try '--help'\n",
                        key);
                goto syn_err;
            }
        } else if ((0 == strncmp(key, "--dry-run", 9)) ||
                   (0 == strncmp(key, "--dry_run", 9)))
            ++clp->dry_run;
        else if ((0 == strncmp(key, "--help", 6)) ||
                   (0 == strcmp(key, "-?")))
            ++clp->help;
        else if ((0 == strncmp(key, "--prefetch", 10)) ||
                 (0 == strncmp(key, "--pre-fetch", 11)))
            clp->prefetch = true;
        else if (0 == strncmp(key, "--verb", 6)) {
            verbose_given = true;
            ++clp->verbose;      /* --verbose */
        } else if (0 == strncmp(key, "--veri", 6))
            verify_given = true;
        else if (0 == strncmp(key, "--vers", 6))
            version_given = true;
        else {
            pr2serr("Unrecognized option '%s'\n", key);
            pr2serr("For more information use '--help'\n");
            goto syn_err;
        }
    }   /* end of parsing for loop */

    if (skip_buf) {
        res = skip_seek(clp, "skip", skip_buf, true /* skip */, false);
        free(skip_buf);
        skip_buf = NULL;
        if (res) {
            pr2serr("%sbad argument to 'seek='\n", my_name);
            goto syn_err;
        }
    }
    if (seek_buf) {
        res = skip_seek(clp, "seek", seek_buf, false /* skip */, false);
        free(seek_buf);
        seek_buf = NULL;
        if (res) {
            pr2serr("%sbad argument to 'seek='\n", my_name);
            goto syn_err;
        }
    }
    /* heap usage should be all freed up now */

#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        verbose_given = false;
        version_given = false;
        clp->verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        clp->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", clp->verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr("%s%s\n", my_name, version_str);
        return SG_LIB_OK_FALSE;
    }
    if (clp->help > 0) {
        usage(clp->help);
        return SG_LIB_OK_FALSE;
    }
    if (clp->bs <= 0) {
        clp->bs = DEF_BLOCK_SIZE;
        pr2serr("Assume default 'bs' ((logical) block size) of %d bytes\n",
                clp->bs);
    }
    if (verify_given) {
        pr2serr("Doing verify/cmp rather than copy\n");
        clp->verify = true;
    }
    if ((ibs && (ibs != clp->bs)) || (obs && (obs != clp->bs))) {
        pr2serr("If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage(0);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (clp->out_flags.append) {
        if ((clp->o_sgl.lowest_lba > 0) ||
            (clp->o_sgl.linearity != SGL_LINEAR)) {
            pr2serr("Can't use both append and seek switches\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (verify_given) {
            pr2serr("Can't use both append and verify switches\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (clp->bpt < 1) {
        pr2serr("bpt must be greater than 0\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (clp->in_flags.mmap && clp->out_flags.mmap) {
        pr2serr("mmap flag on both IFILE and OFILE doesn't work\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    /* defaulting transfer size to 128*2048 for CD/DVDs is too large
     * for the block layer in lk 2.6 and results in an EIO on the
     * SG_IO ioctl. So reduce it in that case. */
    if ((clp->bs >= 2048) && (! bpt_given))
        clp->bpt = DEF_BLOCKS_PER_2048TRANSFER;
    if (clp->in_flags.order && (! clp->out_flags.order))
        pr2serr("Warning iflag=order is ignored, use with oflag=\n");
    if ((num_threads < 1) || (num_threads > MAX_NUM_THREADS)) {
        pr2serr("too few or too many threads requested\n");
        usage(1);
        return SG_LIB_SYNTAX_ERROR;
    }
    clp->unit_nanosec = (do_time > 1) || !!getenv("SG3_UTILS_LINUX_NANO");
    return 0;

syn_err:
    if (seek_buf)
        free(seek_buf);
    if (skip_buf)
        free(skip_buf);
    return contra ? SG_LIB_CONTRADICT : SG_LIB_SYNTAX_ERROR;
}

static int
calc_count(struct global_collection * clp, const char * inf,
           int64_t & in_num_sect, const char * outf, int64_t & out_num_sect)
{
    int in_sect_sz, out_sect_sz, res;

    if (clp->dd_count < 0) {
        in_num_sect = -1;
        out_num_sect = -1;
    }
    if (FT_SG == clp->in_type) {
        res = scsi_read_capacity(clp->infd, &in_num_sect, &in_sect_sz);
        if (2 == res) {
            pr2serr("Unit attention, media changed(in), continuing\n");
            res = scsi_read_capacity(clp->infd, &in_num_sect,
                                     &in_sect_sz);
        }
        if (0 != res) {
            if (res == SG_LIB_CAT_INVALID_OP)
                pr2serr("read capacity not supported on %s\n", inf);
            else if (res == SG_LIB_CAT_NOT_READY)
                pr2serr("read capacity failed, %s not ready\n", inf);
            else
                pr2serr("Unable to read capacity on %s\n", inf);
            return SG_LIB_FILE_ERROR;
        } else if (clp->bs != in_sect_sz) {
            pr2serr(">> warning: logical block size on %s confusion: "
                    "bs=%d, device claims=%d\n", clp->infp, clp->bs,
                    in_sect_sz);
            return SG_LIB_FILE_ERROR;
        }
    }
    if (FT_SG == clp->out_type) {
        res = scsi_read_capacity(clp->outfd, &out_num_sect, &out_sect_sz);
        if (2 == res) {
            pr2serr("Unit attention, media changed(out), continuing\n");
            res = scsi_read_capacity(clp->outfd, &out_num_sect,
                                     &out_sect_sz);
        }
        if (0 != res) {
            if (res == SG_LIB_CAT_INVALID_OP)
                pr2serr("read capacity not supported on %s\n", outf);
            else if (res == SG_LIB_CAT_NOT_READY)
                pr2serr("read capacity failed, %s not ready\n", outf);
            else
                pr2serr("Unable to read capacity on %s\n", outf);
            out_num_sect = -1;
            return SG_LIB_FILE_ERROR;
        } else if (clp->bs != out_sect_sz) {
            pr2serr(">> warning: logical block size on %s confusion: "
                    "bs=%d, device claims=%d\n", clp->outfp, clp->bs,
                    out_sect_sz);
            return SG_LIB_FILE_ERROR;
        }
    }

    if (clp->dd_count < 0) {
        if (FT_SG == clp->in_type)
            ;
        else if (FT_BLOCK == clp->in_type) {
            if (0 != read_blkdev_capacity(clp->infd, &in_num_sect,
                                          &in_sect_sz)) {
                pr2serr("Unable to read block capacity on %s\n", inf);
                in_num_sect = -1;
            }
            if (clp->bs != in_sect_sz) {
                pr2serr("logical block size on %s confusion; bs=%d, from "
                        "device=%d\n", inf, clp->bs, in_sect_sz);
                in_num_sect = -1;
            }
        }

        if (FT_SG == clp->out_type)
            ;
        else if (FT_BLOCK == clp->out_type) {
            if (0 != read_blkdev_capacity(clp->outfd, &out_num_sect,
                                          &out_sect_sz)) {
                pr2serr("Unable to read block capacity on %s\n", outf);
                out_num_sect = -1;
            }
            if (clp->bs != out_sect_sz) {
                pr2serr("logical block size on %s confusion: bs=%d, from "
                        "device=%d\n", outf, clp->bs, out_sect_sz);
                out_num_sect = -1;
            }
        }
    }
    return 0;
}

static int
do_count_work(struct global_collection * clp, const char * inf,
              int64_t & in_num_sect, const char * outf,
              int64_t & out_num_sect)
{
    int res;
    class scat_gath_list * isglp = &clp->i_sgl;
    class scat_gath_list * osglp = &clp->o_sgl;

    res = calc_count(clp, inf, in_num_sect, outf, out_num_sect);
    if (res)
        return res;

    if ((-1 == in_num_sect) && (FT_OTHER == clp->in_type)) {
        in_num_sect = clp->in_st_size / clp->bs;
        if (clp->in_st_size % clp->bs) {
            ++in_num_sect;
            pr2serr("Warning: the file size of %s is not a multiple of BS "
                    "[%d]\n", inf, clp->bs);
        }
    }
    if ((in_num_sect > 0) && (isglp->high_lba_p1 > in_num_sect)) {
        pr2serr("%shighest LBA [0x%" PRIx64 "] exceeds input length: %"
                PRIx64 " blocks\n", my_name, isglp->high_lba_p1 - 1,
                in_num_sect);
        return SG_LIB_CAT_OTHER;
    }
    if ((out_num_sect > 0) && (osglp->high_lba_p1 > out_num_sect)) {
        pr2serr("%shighest LBA [0x%" PRIx64 "] exceeds output length: %"
                PRIx64 " blocks\n", my_name, osglp->high_lba_p1 - 1,
                out_num_sect);
        return SG_LIB_CAT_OTHER;
    }

    if (isglp->sum_hard || osglp->sum_hard) {
        int64_t ccount;

        if (isglp->sum_hard && osglp->sum_hard) {
            if (isglp->sum != osglp->sum) {
                pr2serr("%stwo hard sgl_s, sum of blocks differ: in=%" PRId64
                        ", out=%" PRId64 "\n", my_name , isglp->sum,
                        osglp->sum);
                return SG_LIB_CAT_OTHER;
            }
            ccount = isglp->sum;
        } else if (isglp->sum_hard) {
            if (osglp->sum > isglp->sum) {
                pr2serr("%soutput sgl already too many blocks [%" PRId64
                        "]\n", my_name, osglp->sum);
                return SG_LIB_CAT_OTHER;
            }
            if (osglp->linearity != SGL_NON_MONOTONIC)
                osglp->append_1or(isglp->sum - osglp->sum);
            else {
                pr2serr("%soutput sgl non-montonic: can't extend\n",
                        my_name);
                return SG_LIB_CAT_OTHER;
            }
            ccount = isglp->sum;
        } else {        /* only osglp hard */
            if (isglp->sum > osglp->sum) {
                pr2serr("%sinput sgl already too many blocks [%" PRId64
                        "]\n", my_name, isglp->sum);
                return SG_LIB_CAT_OTHER;
            }
            if (isglp->linearity != SGL_NON_MONOTONIC)
                isglp->append_1or(osglp->sum - isglp->sum);
            else {
                pr2serr("%sinput sgl non-monotonic: can't extend\n",
                        my_name);
                return SG_LIB_CAT_OTHER;
            }
            ccount = osglp->sum;
        }
        if (SG_COUNT_INDEFINITE == clp->dd_count)
            clp->dd_count = ccount;
        else if (ccount != clp->dd_count) {
            pr2serr("%scount=COUNT disagrees with scatter gather list "
                    "length [%" PRId64 "]\n", my_name, ccount);
            return SG_LIB_CAT_OTHER;
        }
    } else if (clp->dd_count != 0) { /* and both input and output are soft */
        if (clp->dd_count > 0) {
            if (isglp->sum > clp->dd_count) {
                pr2serr("%sskip sgl sum [%" PRId64 "] exceeds COUNT\n",
                        my_name, isglp->sum);
                return SG_LIB_CAT_OTHER;
            }
            if (osglp->sum > clp->dd_count) {
                pr2serr("%sseek sgl sum [%" PRId64 "] exceeds COUNT\n",
                        my_name, osglp->sum);
                return SG_LIB_CAT_OTHER;
            }
            goto fini;
        }

        /* clp->dd_count == SG_COUNT_INDEFINITE */
        int64_t iposs = INT64_MAX;
        int64_t oposs = INT64_MAX;

        if (in_num_sect > 0)
            iposs = in_num_sect + isglp->sum - isglp->high_lba_p1;
        if (out_num_sect > 0)
            oposs = out_num_sect + osglp->sum - osglp->high_lba_p1;
        clp->dd_count = iposs < oposs ? iposs : oposs;
        if (INT64_MAX == clp->dd_count) {
            pr2serr("%scan't deduce count=COUNT, please supply one\n",
                    my_name);
            return SG_LIB_CAT_OTHER;
        }
        if (isglp->sum > clp->dd_count) {
            pr2serr("%sdeduced COUNT [%" PRId64 "] exceeds skip sgl sum\n",
                    my_name, clp->dd_count);
            return SG_LIB_CAT_OTHER;
        }
        if (osglp->sum > clp->dd_count) {
            pr2serr("%sdeduced COUNT [%" PRId64 "] exceeds seek sgl sum\n",
                    my_name, clp->dd_count);
            return SG_LIB_CAT_OTHER;
        }
    }
    if (clp->dd_count == 0)
        return 0;
fini:
    if (clp->dd_count > isglp->sum)
        isglp->append_1or(clp->dd_count - isglp->sum);
    if (clp->dd_count > osglp->sum)
        osglp->append_1or(clp->dd_count - osglp->sum);
    return 0;
}


int
main(int argc, char * argv[])
{
    bool fail_after_cli = false;
    char inf[INOUTF_SZ];
    char outf[INOUTF_SZ];
    char outregf[INOUTF_SZ];
    int res, k, err, flags;
    int64_t in_num_sect = -1;
    int64_t out_num_sect = -1;
    const char * ccp = NULL;
    const char * cc2p;
    struct global_collection * clp = &gcoll;
    thread sig_listen_thr;
    vector<thread> work_thr;
    vector<thread> listen_thr;
    char ebuff[EBUFF_SZ];
#if 0   /* SG_LIB_ANDROID */
    struct sigaction actions;

    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = thread_exit_handler;
    sigaction(SIGUSR1, &actions, NULL);
    sigaction(SIGUSR2, &actions, NULL);
#endif
    /* memset(clp, 0, sizeof(*clp)); */
    clp->dd_count = SG_COUNT_INDEFINITE;
    clp->bpt = DEF_BLOCKS_PER_TRANSFER;
    clp->cmd_timeout = DEF_TIMEOUT;
    clp->in_type = FT_FIFO;
    /* change dd's default: if of=OFILE not given, assume /dev/null */
    clp->out_type = FT_DEV_NULL;
    clp->cdbsz_in = DEF_SCSI_CDB_SZ;
    clp->cdbsz_out = DEF_SCSI_CDB_SZ;
    clp->mrq_num = DEF_MRQ_NUM;
    inf[0] = '\0';
    outf[0] = '\0';
    outregf[0] = '\0';
    fetch_sg_version();
    if (sg_version >= 40045)
        sg_version_ge_40045 = true;
    else {
        pr2serr(">>> %srequires an sg driver version of 4.0.45 or later\n\n",
                my_name);
        fail_after_cli = true;
    }

    res = parse_cmdline_sanity(argc, argv, clp, inf, outf, outregf);
    if (SG_LIB_OK_FALSE == res)
        return 0;
    if (res)
        return res;
    if (fail_after_cli) {
        pr2serr("%scommand line parsing was okay but sg driver is too old\n",
                my_name);
        return SG_LIB_SYNTAX_ERROR;
    }

    install_handler(SIGINT, interrupt_handler);
    install_handler(SIGQUIT, interrupt_handler);
    install_handler(SIGPIPE, interrupt_handler);
    install_handler(SIGUSR1, siginfo_handler);
    install_handler(SIGUSR2, siginfo2_handler);

    clp->infd = STDIN_FILENO;
    clp->outfd = STDOUT_FILENO;
    if (clp->in_flags.ff) {
        ccp = "<0xff bytes>";
        cc2p = "ff";
    } else if (clp->in_flags.random) {
        ccp = "<random>";
        cc2p = "random";
    } else if (clp->in_flags.zero) {
        ccp = "<zero bytes>";
        cc2p = "00";
    }
    if (ccp) {
        if (inf[0]) {
            pr2serr("%siflag=%s and if=%s contradict\n", my_name, cc2p, inf);
            return SG_LIB_CONTRADICT;
        }
        clp->in_type = FT_RANDOM_0_FF;
        clp->infp = ccp;
        clp->infd = -1;
    } else if (inf[0] && ('-' != inf[0])) {
        clp->in_type = dd_filetype(inf, clp->in_st_size);

        if (FT_ERROR == clp->in_type) {
            pr2serr("%sunable to access %s\n", my_name, inf);
            return SG_LIB_FILE_ERROR;
        } else if (FT_ST == clp->in_type) {
            pr2serr("%sunable to use scsi tape device %s\n", my_name, inf);
            return SG_LIB_FILE_ERROR;
        } else if (FT_SG == clp->in_type) {
            clp->infd = sg_in_open(clp, inf, NULL, NULL, false);
            if (clp->infd < 0)
                return -clp->infd;
        } else {
            flags = O_RDONLY;
            if (clp->in_flags.direct)
                flags |= O_DIRECT;
            if (clp->in_flags.excl)
                flags |= O_EXCL;
            if (clp->in_flags.dsync)
                flags |= O_SYNC;

            if ((clp->infd = open(inf, flags)) < 0) {
                err = errno;
                snprintf(ebuff, EBUFF_SZ, "%scould not open %s for reading",
                         my_name, inf);
                perror(ebuff);
                return sg_convert_errno(err);
            }
        }
        clp->infp = inf;
    }
    if (clp->cdl_given && (! clp->cdbsz_given)) {
        bool changed = false;

        if ((clp->cdbsz_in < 16) && (clp->in_flags.cdl > 0)) {
            clp->cdbsz_in = 16;
            changed = true;
        }
        if ((clp->cdbsz_out < 16) && (! clp->verify) &&
            (clp->out_flags.cdl > 0)) {
            clp->cdbsz_out = 16;
            changed = true;
        }
        if (changed)
            pr2serr(">> increasing cdbsz to 16 due to cdl > 0\n");
    }
    if (outf[0]) {
        clp->ofile_given = true;
        if (('-' == outf[0]))
            clp->out_type = FT_FIFO;
        else
            clp->out_type = dd_filetype(outf, clp->out_st_size);

        if ((FT_SG != clp->out_type) && clp->verify) {
            pr2serr("%s --verify only supported by sg OFILEs\n", my_name);
            return SG_LIB_FILE_ERROR;
        }
        if (FT_FIFO == clp->out_type)
            ;
        else if (FT_ST == clp->out_type) {
            pr2serr("%sunable to use scsi tape device %s\n", my_name, outf);
            return SG_LIB_FILE_ERROR;
        } else if (FT_SG == clp->out_type) {
            clp->outfd = sg_out_open(clp, outf, NULL, NULL, false);
            if (clp->outfd < 0)
                return -clp->outfd;
        } else if (FT_DEV_NULL == clp->out_type)
            clp->outfd = -1; /* don't bother opening */
        else {
            if (FT_RAW != clp->out_type) {
                flags = O_WRONLY;
                if (! clp->out_flags.nocreat)
                    flags |= O_CREAT;
                if (clp->out_flags.direct)
                    flags |= O_DIRECT;
                if (clp->out_flags.excl)
                    flags |= O_EXCL;
                if (clp->out_flags.dsync)
                    flags |= O_SYNC;
                if (clp->out_flags.append)
                    flags |= O_APPEND;

                if ((clp->outfd = open(outf, flags, 0666)) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, "%scould not open %s for "
                             "writing", my_name, outf);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
            }
            else {      /* raw output file */
                if ((clp->outfd = open(outf, O_WRONLY)) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, "%scould not open %s for raw "
                             "writing", my_name, outf);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
            }
        }
        clp->outfp = outf;
    }
    if (clp->verify && (clp->out_type == FT_DEV_NULL)) {
        pr2serr("Can't do verify when OFILE not given\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((FT_SG == clp->in_type) && (FT_SG == clp->out_type)) {
        if (clp->in_flags.serial || clp->out_flags.serial)
            pr2serr("serial flag ignored when both IFILE and OFILE are sg "
                    "devices\n");
    } else if (clp->in_flags.order)
        pr2serr("Warning: oflag=order only active on sg->sg copies\n");

    if (outregf[0]) {
        int ftyp = dd_filetype(outregf, clp->outreg_st_size);

        clp->outreg_type = ftyp;
        if (! ((FT_OTHER == ftyp) || (FT_ERROR == ftyp) ||
               (FT_DEV_NULL == ftyp))) {
            pr2serr("File: %s can only be regular file or pipe (or "
                    "/dev/null)\n", outregf);
            return SG_LIB_SYNTAX_ERROR;
        }
        if ((clp->outregfd = open(outregf, O_WRONLY | O_CREAT, 0666)) < 0) {
            err = errno;
            snprintf(ebuff, EBUFF_SZ, "could not open %s for writing",
                     outregf);
            perror(ebuff);
            return sg_convert_errno(err);
        }
        if (clp->verbose > 1)
            pr2serr("ofreg=%s opened okay, fd=%d\n", outregf, clp->outregfd);
        if (FT_ERROR == ftyp)
            clp->outreg_type = FT_OTHER;        /* regular file created */
    } else
        clp->outregfd = -1;

    if ((STDIN_FILENO == clp->infd) && (STDOUT_FILENO == clp->outfd)) {
        pr2serr("Won't default both IFILE to stdin _and_ OFILE to "
                "/dev/null\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((clp->in_type == FT_FIFO) && (! clp->i_sgl.is_pipe_suitable())) {
        pr2serr("The skip= argument is not suitable for a pipe\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((clp->out_type == FT_FIFO) && (! clp->o_sgl.is_pipe_suitable())) {
        pr2serr("The seek= argument is not suitable for a pipe\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    res = do_count_work(clp, inf, in_num_sect, outf, out_num_sect);
    if (res)
        return res;

    if (clp->verbose > 2)
        pr2serr("Start of loop, count=%" PRId64 ", in_num_sect=%" PRId64
                ", out_num_sect=%" PRId64 "\n", clp->dd_count, in_num_sect,
                out_num_sect);
    if (clp->dd_count < 0) {
        pr2serr("Couldn't calculate count, please give one\n");
        return SG_LIB_CAT_OTHER;
    }
    if (! clp->cdbsz_given) {
        if ((FT_SG == clp->in_type) && (MAX_SCSI_CDB_SZ != clp->cdbsz_in) &&
            ((clp->i_sgl.high_lba_p1 > UINT_MAX) || (clp->bpt > USHRT_MAX))) {
            pr2serr("Note: SCSI command size increased to 16 bytes (for "
                    "'if')\n");
            clp->cdbsz_in = MAX_SCSI_CDB_SZ;
        }
        if ((FT_SG == clp->out_type) && (MAX_SCSI_CDB_SZ != clp->cdbsz_out) &&
            ((clp->o_sgl.high_lba_p1 > UINT_MAX) || (clp->bpt > USHRT_MAX))) {
            pr2serr("Note: SCSI command size increased to 16 bytes (for "
                    "'of')\n");
            clp->cdbsz_out = MAX_SCSI_CDB_SZ;
        }
    }

    clp->in_rem_count = clp->dd_count;
    clp->out_rem_count = clp->dd_count;

    if (clp->dry_run > 0) {
        pr2serr("Due to --dry-run option, bypass copy/read\n");
        goto fini;
    }
    if (! clp->ofile_given)
        pr2serr("of=OFILE not given so only read from IFILE, to output to "
                "stdout use 'of=-'\n");

    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);

    res = sigprocmask(SIG_BLOCK, &signal_set, NULL);
    if (res < 0) {
        pr2serr("sigprocmask failed: %s\n", safe_strerror(errno));
        goto fini;
    }

    listen_thr.emplace_back(sig_listen_thread, clp);

    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }

/* vvvvvvvvvvv  Start worker threads  vvvvvvvvvvvvvvvvvvvvvvvv */
    if (num_threads > 0) {
        /* launch "infant" thread to catch early mortality, if any */
        work_thr.emplace_back(read_write_thread, clp, 0, true);
        {
            unique_lock<mutex> lk(clp->infant_mut);
            clp->infant_cv.wait(lk, []{ return gcoll.processed; });
        }
        if (clp->next_count_pos.load() < 0) {
            /* infant thread error-ed out, join with it */
            for (auto & t : work_thr) {
                if (t.joinable())
                    t.join();
            }
            goto jump;
        }

        /* now start the rest of the threads */
        for (k = 1; k < num_threads; ++k)
            work_thr.emplace_back(read_write_thread, clp, k, false);

        /* now wait for worker threads to finish */
        for (auto & t : work_thr) {
            if (t.joinable())
                t.join();
        }
    }   /* started worker threads and hereafter they have all exited */
jump:
    if (do_time && (start_tm.tv_sec || start_tm.tv_usec))
        calc_duration_throughput(0);

    if (do_sync) {
        if (FT_SG == clp->out_type) {
            pr2serr_lk(">> Synchronizing cache on %s\n", outf);
            res = sg_ll_sync_cache_10(clp->outfd, 0, 0, 0, 0, 0, false, 0);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                pr2serr_lk("Unit attention(out), continuing\n");
                res = sg_ll_sync_cache_10(clp->outfd, 0, 0, 0, 0, 0, false,
                                          0);
            }
            if (0 != res)
                pr2serr_lk("Unable to synchronize cache\n");
        }
    }

    shutting_down = true;
    for (auto & t : listen_thr) {
        if (t.joinable()) {
            t.detach();
            t.~thread();        /* kill listening thread */
        }
    }

fini:

    if ((STDIN_FILENO != clp->infd) && (clp->infd >= 0))
        close(clp->infd);
    if ((STDOUT_FILENO != clp->outfd) && (FT_DEV_NULL != clp->out_type) &&
        (clp->outfd >= 0))
        close(clp->outfd);
    if ((clp->outregfd >= 0) && (STDOUT_FILENO != clp->outregfd) &&
        (FT_DEV_NULL != clp->outreg_type))
        close(clp->outregfd);
    print_stats("");
    if (clp->dio_incomplete_count.load()) {
        int fd;
        char c;

        pr2serr(">> Direct IO requested but incomplete %d times\n",
                clp->dio_incomplete_count.load());
        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    pr2serr(">>> %s set to '0' but should be set to '1' for "
                            "direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    }
    if (clp->sum_of_resids.load())
        pr2serr(">> Non-zero sum of residual counts=%d\n",
               clp->sum_of_resids.load());
    if (clp->verbose && (num_start_eagain > 0))
        pr2serr("Number of start EAGAINs: %d\n", num_start_eagain.load());
    if (clp->verbose && (num_fin_eagain > 0))
        pr2serr("Number of finish EAGAINs: %d\n", num_fin_eagain.load());
    if (clp->verbose && (num_ebusy > 0))
        pr2serr("Number of EBUSYs: %d\n", num_ebusy.load());
    if (clp->verbose && (num_miscompare > 0))
        pr2serr("Number of miscompare%s: %d\n",
                (num_miscompare > 1) ? "s" : "", num_miscompare.load());
    if (clp->verify && (SG_LIB_CAT_MISCOMPARE == res))
        pr2serr("Verify/compare failed due to miscompare\n");
    if (0 == res)
        res = clp->reason_res.load();
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}
