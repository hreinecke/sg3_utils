/*
 * A utility program for copying files. Specialised for "files" that
 * represent devices that understand the SCSI command set.
 *
 * Copyright (C) 2018-2020 D. Gilbert
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
 * sgp_dd is a Posix threads specialization of the sg_dd utility. Both
 * sgp_dd and sg_dd only perform special tasks when one or both of the given
 * devices belong to the Linux sg driver.
 *
 * sgh_dd further extends sgp_dd to use the experimental kernel buffer
 * sharing feature added in 3.9.02 .
 * N.B. This utility was previously called sgs_dd but there was already an
 * archived version of a dd variant called sgs_dd so this utility name was
 * renamed [20181221]
 */

static const char * version_str = "1.03 20200716";

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
#include <sys/random.h>         /* for getrandom() system call */

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
#include "sg_cmds_basic.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"


using namespace std;

#ifdef __GNUC__
#ifndef  __clang__
#pragma GCC diagnostic ignored "-Wclobbered"
#endif
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
#define MAX_SCSI_CDB_SZ 16
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

#define SG_SGL_MAX_ELEMENTS 16384

#define SG_COUNT_INDEFINITE (-1)
#define SG_LBA_INVALID SG_COUNT_INDEFINITE

/* Sizing matches largest SCSI READ and WRITE commands plus those of Unix
 * read(2)s and write(2)s. User can give larger than 31 bit 'num's but they
 * are split into several consecutive elements. */
struct scat_gath_elem {
    uint64_t lba;       /* of start block */
    uint32_t num;       /* number of blocks from and including start block */

    void make_bad() { lba = UINT64_MAX; num = UINT32_MAX; }
    bool is_bad() const { return (lba == UINT64_MAX && num == UINT32_MAX); }
};

/* Consider "linearity" as a scatter gather list property. Elements of this
 * of from the strongest form to the weakest. */
enum sgl_linearity_e {
    SGL_LINEAR = 0,     /* empty list and 0,0 considered linear */
    SGL_MONOTONIC,      /* since not linear, implies holes */
    SGL_MONO_OVERLAP,   /* monotonic but same LBA in two or more elements */
    SGL_NON_MONOTONIC   /* weakest */
};


/* Holds one scatter gather list and its associated metadata */
class scat_gath_list {
public:
    scat_gath_list() : linearity(SGL_LINEAR), sum_hard(false), m_errno(0),
        high_lba_p1(0), lowest_lba(0), sum(0) { }

    scat_gath_list(const scat_gath_list &) = default;
    scat_gath_list & operator=(const scat_gath_list &) = default;
    ~scat_gath_list() = default;

    bool empty() const;
    bool empty_or_00() const;
    int num_elems() const;
    int64_t get_lowest_lba(bool ignore_degen, bool always_last) const;
    int64_t get_low_lba_from_linear() const;
    bool is_pipe_suitable() const;

    friend bool sgls_eq_off(const scat_gath_list &left, int l_e_ind,
                            int l_blk_off,
                            const scat_gath_list &right, int r_e_ind,
                            int r_blk_off, bool allow_partial);

    bool load_from_cli(const char * cl_p, bool b_vb);
    bool load_from_file(const char * file_name, bool def_hex, bool flexible,
                        bool b_vb);
    int append_1or(int64_t extra_blks, int64_t start_lba);
    int append_1or(int64_t extra_blks);

    void dbg_print(bool skip_meta, const char * id_str, bool to_stdout,
                   bool show_sgl, bool lock = true) const;

    /* calculates and sets following bool-s and int64_t-s */
    void sum_scan(const char * id_str, bool show_sgl, bool b_verbose);

    void set_weaker_linearity(enum sgl_linearity_e lin);
    enum sgl_linearity_e linearity;
    const char * linearity_as_str() const;

    bool sum_hard;      /* 'num' in last element of 'sgl' is > 0 */
    int m_errno;        /* OS failure errno */
    int64_t high_lba_p1;  /* highest LBA plus 1, next write from and above */
    int64_t lowest_lba; /* initialized to 0 */
    int64_t sum;        /* of all 'num' elements in 'sgl' */

    friend int diff_between_iters(const struct scat_gath_iter & left,
                                  const struct scat_gath_iter & right);

private:
    friend class scat_gath_iter;

    bool file2sgl_helper(FILE * fp, const char * fnp, bool def_hex,
                         bool flexible, bool b_vb);

    vector<scat_gath_elem> sgl;  /* an array on heap [0..num_elems()) */
};


class scat_gath_iter {
public:
    scat_gath_iter(const scat_gath_list & my_scat_gath_list);
    scat_gath_iter(const scat_gath_iter & src) = default;
    scat_gath_iter&  operator=(const scat_gath_iter&) = delete;
    ~scat_gath_iter() = default;

    int64_t current_lba() const;
    int64_t current_lba_rem_num(int & rem_num) const;
    struct scat_gath_elem current_elem() const;
    bool at_end() const;
    bool is_sgl_linear() const; /* the whole list */
    int linear_for_n_blks(int max_n) const;

    bool set_by_blk_idx(int64_t _blk_idx);
    /* add/sub blocks return true if they reach EOL, else false */
    bool add_blks(uint64_t blk_count);
    bool sub_blks(uint64_t blk_count);

    void dbg_print(const char * id_str, bool to_stdout, int verbose) const;

    friend int diff_between_iters(const struct scat_gath_iter & left,
                                  const struct scat_gath_iter & right);

    friend bool sgls_eq_from_iters(const struct scat_gath_iter & left,
                                   const struct scat_gath_iter & right,
                                   bool allow_partial);

private:
    const scat_gath_list &sglist;

    /* dual representation: either it_el_ind,it_blk_off or blk_idx */
    int it_el_ind;      /* refers to sge==sglist[it_el_ind] */
    int it_blk_off;     /* refers to LBA==(sge.lba + it_blk_off) */
    int64_t blk_idx;    /* in range: [0 .. sglist.sum) */
    bool extend_last;
};


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
    bool masync;        /* more async sg v4 driver fd flag */
    bool no_dur;
    bool order;
    bool qhead;
    bool qtail;
    bool random;
    bool serial;
    bool wq_excl;
    bool zero;
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
    int mrq_num;                      /* Number of multi-reqs for sg v4 */
    int outfd;
    int out_type;
    int cdbsz_out;
    struct flags_t out_flags;
    atomic<int64_t> out_rem_count;    /*  | count of remaining out blocks */
    atomic<int> out_partial;          /*  | */
    off_t out_st_size;                /* Only for FT_OTHER (regular) file */
    condition_variable infant_cv;     /* after thread:0 does first segment */
    mutex infant_mut;
    bool processed;
    int bs;
    int bpt;
    int outregfd;
    int outreg_type;
    off_t outreg_st_size;
    atomic<int> dio_incomplete_count;
    atomic<int> sum_of_resids;
    int verbose;
    int dry_run;
    bool cdbsz_given;
    bool count_given;
    bool flexible;
    bool ofile_given;
    bool unit_nanosec;          /* default duration unit is millisecond */
    bool mrq_cmds;              /* mrq=<NRQS>,C  given */
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
    int resid;
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

// typedef vector< pair<int, struct sg_io_v4> > mrq_arr_t;
typedef array<uint8_t, 32> big_cdb;     /* allow up to a 32 byte cdb */
typedef pair< vector<struct sg_io_v4>, vector<big_cdb> >   mrq_arr_t;


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

static atomic<long int> pos_index(0);

static atomic<int> num_ebusy(0);
static atomic<int> num_start_eagain(0);
static atomic<int> num_fin_eagain(0);
#if 0
static atomic<long> num_waiting_calls(0);
#endif

static sigset_t signal_set;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

static int sg_in_open(struct global_collection *clp, const char *inf,
                      uint8_t **mmpp, int *mmap_len);
static int sg_out_open(struct global_collection *clp, const char *outf,
                       uint8_t **mmpp, int *mmap_len);
static int do_both_sg_segment(Rq_elem * rep, scat_gath_iter & i_sg_it,
                              scat_gath_iter & o_sg_it, int seg_blks,
                              vector<cdb_arr_t> & a_cdb,
                              vector<struct sg_io_v4> & a_v4);
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
static bool sg_version_ge_40030 = false;
static atomic<bool> shutting_down = false;
static bool do_sync = false;
static int do_time = 1;
static struct global_collection gcoll;
static struct timeval start_tm;
static int num_threads = DEF_NUM_THREADS;
static int exit_status = 0;
static bool after1 = false;

static mutex rand_lba_mutex;

static const char * my_name = "sg_mrq_dd: ";

// static const char * mrq_blk_s = "mrq: ordinary blocking";
static const char * mrq_svb_s = "mrq: shared variable blocking (svb)";
static const char * mrq_ob_s = "mrq: ordered blocking";
static const char * mrq_vb_s = "mrq: variable blocking";


#ifdef __GNUC__
static int pr2serr_lk(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#if 0
static void pr_errno_lk(int e_no, const char * fmt, ...)
        __attribute__ ((format (printf, 2, 3)));
#endif
#else
static int pr2serr_lk(const char * fmt, ...);
#if 0
static void pr_errno_lk(int e_no, const char * fmt, ...);
#endif
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

#if 0   // not used yet
static void
pr_errno_lk(int e_no, const char * fmt, ...)
{
    char b[180];
    va_list args;
    lock_guard<mutex> lk(strerr_mut);

    va_start(args, fmt);
    vsnprintf(b, sizeof(b), fmt, args);
    fprintf(stderr, "%s: %s\n", b, strerror(e_no));
    va_end(args);
}
#endif

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
        n += sg_scnpr(b + n, b_len - n, "NWTQ|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_DOUT_OFFSET & flags) {        /* 0x80 */
        n += sg_scnpr(b + n, b_len - n, "DOFF|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_COMPLETE_B4 & flags) {        /* 0x100 */
        n += sg_scnpr(b + n, b_len - n, "NWTQ|");
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
    if (SGV4_FLAG_EVENTFD & flags) {          /* 0x40000 */
        n += sg_scnpr(b + n, b_len - n, "EVFD|");
        if (n >= b_len)
            goto fini;
    }
    if (SGV4_FLAG_ORDERED_WR & flags) {      /* 0x80000 */
        n += sg_scnpr(b + n, b_len - n, "OWR|");
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

    outfull = gcoll.dd_count - gcoll.out_rem_count.load();
    pr2serr("%s%" PRId64 "+%d records %s\n", str,
            outfull, gcoll.out_partial.load(),
            (gcoll.verify ? "verified" : "out"));
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

#if 0   /* SG_LIB_ANDROID */
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
    lock_guard<mutex> lk(strerr_mut);
    char * cp;

    cp = safe_strerror(code);
    strncpy(ebp, cp, STRERR_BUFF_LEN);
    ebp[STRERR_BUFF_LEN - 1] = '\0';
    return ebp;
}


/* Following macro from D.R. Butenhof's POSIX threads book:
 * ISBN 0-201-63392-2 . Changed __FILE__ to __func__ */
#define err_exit(code,text) do { \
    char strerr_buff[STRERR_BUFF_LEN]; \
    pr2serr("%s at \"%s\":%d: %s\n", \
        text, __func__, __LINE__, tsafe_strerror(code, strerr_buff)); \
    exit(1); \
    } while (0)


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

    pr2serr("Usage: sg_mrq_dd  [bs=BS] [count=COUNT] [ibs=BS] [if=IFILE]"
            " [iflag=FLAGS]\n"
            "                  [obs=BS] [of=OFILE] [oflag=FLAGS] "
            "[seek=SEEK]\n"
            "                  [skip=SKIP] [--help] [--version]\n\n");
    pr2serr("                  [bpt=BPT] [cdbsz=6|10|12|16] [dio=0|1] "
            "[fua=0|1|2|3]\n"
            "                  [mrq=MRQ] [ofreg=OFREG] [sync=0|1] [thr=THR] "
            "[time=0|1]\n"
            "                  [verbose=VERB] [--dry-run] [--verbose] "
            "[--verify]\n"
            "                  [--version]\n\n"
            "  where the main options (shown in first group above) are:\n"
            "    bs          must be device logical block size (default "
            "512)\n"
            "    count       number of blocks to copy (def: device size)\n"
            "    if          file or device to read from (def: stdin)\n"
            "    iflag       comma separated list from: [coe,dio,"
            "direct,dpo,\n"
            "                dsync,excl,fua,masync,mmap,nodur,\n"
            "                null,order,qtail,serial,wq_excl]\n"
            "    mrq         number of cmds placed in each sg call "
            "(def: 16)\n"
            "    of          file or device to write to (def: /dev/null "
            "N.B. different\n"
            "                from dd it defaults to stdout). If 'of=.' "
            "uses /dev/null\n"
            "    oflag       comma separated list from: [append,<<list from "
            "iflag>>]\n"
            "    seek        block position to start writing to OFILE\n"
            "    skip        block position to start reading from IFILE\n"
            "    --help|-h      output this usage message then exit\n"
            "    --prefetch|-p    with verify: do pre-fetch first\n"
            "    --verify|-x    do a verify (compare) operation [def: do a "
            "copy]\n"
            "    --version|-V   output version string then exit\n\n"
            "Copy IFILE to OFILE, similar to dd command. This utility is "
            "specialized for\nSCSI devices and uses the 'multiple requests' "
            "(mrq) in a single invocation\nfacility in version 4 of the sg "
            "driver. Usually one or both IFILE and\nOFILE will be sg "
            "devices. With the --verify option it does a\n"
            "verify/compare operation instead of a copy. This utility is "
            "Linux\n specific. Use '-hh', '-hhh' or '-hhhh' for more "
            "information.\n"
           );
    return;
page2:
    pr2serr("Syntax:  sgh_dd [operands] [options]\n\n"
            "  where: operands have the form name=value and are pecular to "
            "'dd'\n"
            "         style commands, and options start with one or "
            "two hyphens;\n"
            "         the lesser used operands and option are:\n\n"
            "    bpt         is blocks_per_transfer (default is 128)\n"
            "    cdbsz       size of SCSI READ, WRITE or VERIFY cdb_s "
            "(default is 10)\n"
            "    dio         is direct IO, 1->attempt, 0->indirect IO (def)\n"
            "    fua         force unit access: 0->don't(def), 1->OFILE, "
            "2->IFILE,\n"
            "                3->OFILE+IFILE\n"
            "    ofreg       OFREG is regular file or pipe to send what is "
            "read from\n"
            "                IFILE in the first half of each shared element\n"
            "    sync        0->no sync(def), 1->SYNCHRONIZE CACHE on OFILE "
            "after copy\n"
            "    thr         is number of threads, must be > 0, default 4, "
            "max 1024\n"
            "    time        0->no timing, 1->calc throughput(def), "
            "2->nanosec precision\n"
            "    verbose     increase verbosity (def: VERB=0)\n"
            "    --dry-run|-d    prepare but bypass copy/read\n"
            "    --verbose|-v   increase verbosity of utility\n\n"
            "Use '-hhh' or '-hhhh' for more information about flags.\n"
           );
    return;
page3:
    pr2serr("Syntax:  sgh_dd [operands] [options]\n\n"
            "  where: 'iflag=<arg>' and 'oflag=<arg>' arguments are listed "
            "below:\n\n"
            "    00          use all zeros instead of if=IFILE (only in "
            "iflags)\n"
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
            "iflags)\n"
            "    fua         sets the FUA (force unit access) in SCSI READs "
            "and WRITEs\n"
            "    masync      set 'more async' flag on this sg device\n"
            "    mmap        setup mmap IO on IFILE or OFILE\n"
            "    mmap,mmap    when used twice, doesn't call munmap()\n"
            "    mrq_svb     if mrq and sg->sg copy, do shared_variable_"
            "blocking\n"
            "    nodur       turns off command duration calculations\n"
            "    order       require write ordering on sg->sg copy; only "
            "for oflag\n"
            "    qhead       queue new request at head of block queue\n"
            "    qtail       queue new request at tail of block queue (def: "
            "q at head)\n"
            "    random      use random data instead of if=IFILE (only in "
            "iflags)\n"
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
            "comparison. Stops on first miscompare.\n\n");
    pr2serr("--prefetch :\n"
            "Used with --verify option. Prepends a PRE-FETCH(ofile, IMMED) "
            "to verify\nsequence. This should speed the trailing VERIFY by "
            "making sure that\nthe data it needs for the comparison is "
            "already in its cache.\n");
    return;
}


bool
scat_gath_list::empty() const
{
    return sgl.empty();
}

bool
scat_gath_list::empty_or_00() const
{
    if (sgl.empty())
        return true;
    return ((sgl.size() == 1) && (sgl[0].lba == 0) && (sgl[0].num == 0));
}

int
scat_gath_list::num_elems() const
{
    return sgl.size();
}


/* Read numbers (up to 64 bits in size) from command line (comma (or
 * (single) space **) separated list). Assumed decimal unless prefixed
 * by '0x', '0X' or contains trailing 'h' or 'H' (which indicate hex).
 * Returns 0 if ok, or 1 if error. Assumed to be LBA (64 bit) and
 * number_of_block (32 bit) pairs. ** Space on command line needs to
 * be escaped, otherwise it is an operand/option separator. */
bool
scat_gath_list::load_from_cli(const char * cl_p, bool b_vb)
{
    bool split, full_pair;
    int in_len, k, j;
    const int max_nbs = MAX_SGL_NUM_VAL;
    int64_t ll, large_num;
    uint64_t prev_lba;
    char * cp;
    char * c2p;
    const char * lcp;
    struct scat_gath_elem sge;

    if (NULL == cl_p) {
        pr2serr("%s: bad arguments\n", __func__);
        goto err_out;
    }
    lcp = cl_p;
    in_len = strlen(cl_p);
    if ('-' == cl_p[0]) {        /* read from stdin */
        pr2serr("%s: logic error: no stdin here\n", __func__);
        goto err_out;
    } else {        /* list of numbers (default decimal) on command line */
        k = strspn(cl_p, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP, ");
        if (in_len != k) {
            if (b_vb)
                pr2serr("%s: error at pos %d\n", __func__, k + 1);
            goto err_out;
        }
        j = 0;
        full_pair = true;
        for (k = 0, split = false; ; ++k) {
            if (split) {
                /* splitting given elem with large number_of_blocks into
                 * multiple elems within array being built */
                ++j;
                sge.lba = prev_lba + (uint64_t)max_nbs;
                if (large_num > max_nbs) {
                    sge.num = (uint32_t)max_nbs;
                    prev_lba = sge.lba;
                    large_num -= max_nbs;
                    sgl.push_back(sge);
                } else {
                    sge.num = (uint32_t)large_num;
                    split = false;
                    if (b_vb)
                        pr2serr("%s: split large sg elem into %d element%s\n",
                                __func__, j, (j == 1 ? "" : "s"));
                    sgl.push_back(sge);
                    goto check_for_next;
                }
                continue;
            }
            full_pair = false;
            ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                sge.lba = (uint64_t)ll;
                cp = (char *)strchr(lcp, ',');
                c2p = (char *)strchr(lcp, ' ');
                if (NULL == cp) {
                    cp = c2p;
                    if (NULL == cp)
                        break;
                }
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                if (b_vb)
                    pr2serr("%s: error at pos %d\n", __func__,
                            (int)(lcp - cl_p + 1));
                goto err_out;
            }
            ll = sg_get_llnum(lcp);
            if (ll >= 0) {
                full_pair = true;
                if (ll > max_nbs) {
                    sge.num = (uint32_t)max_nbs;
                    prev_lba = sge.lba;
                    large_num = ll - max_nbs;
                    split = true;
                    j = 1;
                    continue;
                }
                sge.num = (uint32_t)ll;
            } else {    /* bad or negative number as number_of_blocks */
                if (b_vb)
                    pr2serr("%s: bad number at pos %d\n", __func__,
                            (int)(lcp - cl_p + 1));
                goto err_out;
            }
            sgl.push_back(sge);
check_for_next:
            cp = (char *)strchr(lcp, ',');
            c2p = (char *)strchr(lcp, ' ');
            if (NULL == cp) {
                cp = c2p;
                if (NULL == cp)
                    break;
            }
            if (c2p && (c2p < cp))
                cp = c2p;
            lcp = cp + 1;
        }       /* end of for loop over items in operand */
        /* other than first pair, expect even number of items */
        if ((k > 0) && (! full_pair)) {
            if (b_vb)
                pr2serr("%s:  expected even number of items: "
                        "LBA0,NUM0,LBA1,NUM1...\n", __func__);
            goto err_out;
        }
    }
    return true;
err_out:
    if (0 == m_errno)
        m_errno = SG_LIB_SYNTAX_ERROR;
    return false;
}

bool
scat_gath_list::file2sgl_helper(FILE * fp, const char * fnp, bool def_hex,
                                bool flexible, bool b_vb)
{
    bool bit0;
    bool pre_addr1 = true;
    bool pre_hex_seen = false;
    int in_len, k, j, m, ind;
    const int max_nbs = MAX_SGL_NUM_VAL;
    int off = 0;
    int64_t ll;
    uint64_t ull, prev_lba;
    char * lcp;
    struct scat_gath_elem sge;
    char line[1024];

    for (j = 0 ; ; ++j) {
        if (NULL == fgets(line, sizeof(line), fp))
            break;
        // could improve with carry_over logic if sizeof(line) too small
        in_len = strlen(line);
        if (in_len > 0) {
            if ('\n' == line[in_len - 1]) {
                --in_len;
                line[in_len] = '\0';
            } else {
                m_errno = SG_LIB_SYNTAX_ERROR;
                if (b_vb)
                    pr2serr("%s: %s: line too long, max %d bytes\n",
                            __func__, fnp, (int)(sizeof(line) - 1));
                goto err_out;
            }
        }
        if (in_len < 1)
            continue;
        lcp = line;
        m = strspn(lcp, " \t");
        if (m == in_len)
            continue;
        lcp += m;
        in_len -= m;
        if ('#' == *lcp)
            continue;
        if (pre_addr1 || pre_hex_seen) {
            /* Accept lines with leading 'HEX' and ignore as long as there
             * is one _before_ any LBA,NUM lines in the file. This allows
             * HEX marked sgls to be concaternated together. */
            if (('H' == toupper(lcp[0])) && ('E' == toupper(lcp[1])) &&
                ('X' == toupper(lcp[2]))) {
                pre_hex_seen = true;
                if (def_hex)
                    continue; /* bypass 'HEX' marker line if expecting hex */
                else {
                    if (flexible) {
                        def_hex = true; /* okay, switch to hex parse */
                        continue;
                    } else {
                        pr2serr("%s: %s: 'hex' string detected on line %d, "
                                "expecting decimal\n", __func__, fnp, j + 1);
                        m_errno = EINVAL;
                        goto err_out;
                    }
                }
            }
        }
        k = strspn(lcp, "0123456789aAbBcCdDeEfFhHxXbBdDiIkKmMgGtTpP, \t");
        if ((k < in_len) && ('#' != lcp[k])) {
            m_errno = EINVAL;
            if (b_vb)
                pr2serr("%s: %s: syntax error at line %d, pos %d\n",
                        __func__, fnp, j + 1, m + k + 1);
            goto err_out;
        }
        for (k = 0; k < 256; ++k) {
            /* limit parseable items on one line to 256 */
            if (def_hex) {      /* don't accept negatives or multipliers */
                if (1 == sscanf(lcp, "%" SCNx64, &ull))
                    ll = (int64_t)ull;
                else
                    ll = -1;    /* use (2**64 - 1) as error flag */
            } else
                ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                ind = ((off + k) >> 1);
                bit0 = !! (0x1 & (off + k));
                if (ind >= SG_SGL_MAX_ELEMENTS) {
                    m_errno = EINVAL;
                    if (b_vb)
                        pr2serr("%s: %s: array length exceeded\n", __func__,
                                fnp);
                    goto err_out;
                }
                if (bit0) {     /* bit0 set when decoding a NUM */
                    if (ll < 0) {
                        m_errno = EINVAL;
                        if (b_vb)
                            pr2serr("%s: %s: bad number in line %d, at pos "
                                    "%d\n", __func__, fnp, j + 1,
                                    (int)(lcp - line + 1));
                        goto err_out;
                    }
                    if (ll > max_nbs) {
                        int h = 1;

                        /* split up this elem into multiple, smaller elems */
                        do {
                            sge.num = (uint32_t)max_nbs;
                            prev_lba = sge.lba;
                            sgl.push_back(sge);
                            sge.lba = prev_lba + (uint64_t)max_nbs;
                            ++h;
                            off += 2;
                            ll -= max_nbs;
                        } while (ll > max_nbs);
                        if (b_vb)
                            pr2serr("%s: split large sg elem into %d "
                                    "elements\n", __func__, h);
                    }
                    sge.num = (uint32_t)ll;
                    sgl.push_back(sge);
                } else {        /* bit0 clear when decoding a LBA */
                    if (pre_addr1)
                        pre_addr1 = false;
                    sge.lba = (uint64_t)ll;
                }
            } else {    /* failed to decode number on line */
                if ('#' == *lcp) { /* numbers before #, rest of line comment */
                    --k;
                    break;      /* goes to next line */
                }
                m_errno = EINVAL;
                if (b_vb)
                    pr2serr("%s: %s: error in line %d, at pos %d\n",
                            __func__, fnp, j + 1, (int)(lcp - line + 1));
                goto err_out;
            }
            lcp = strpbrk(lcp, " ,\t#");
            if ((NULL == lcp) || ('#' == *lcp))
                break;
            lcp += strspn(lcp, " ,\t");
            if ('\0' == *lcp)
                break;
        }       /* <<< end of for(k < 256) loop */
        off += (k + 1);
    }   /* <<< end of for loop, one iteration per line */
    /* allow one items, but not higher odd number of items */
    if ((off > 1) && (0x1 & off)) {
        m_errno = EINVAL;
        if (b_vb)
            pr2serr("%s: %s: expect even number of items: "
                    "LBA0,NUM0,LBA1,NUM1...\n", __func__, fnp);
        goto err_out;
    }
    clearerr(fp);    /* even EOF on first pass needs this before rescan */
    return true;
err_out:
    clearerr(fp);
    return false;
}

/* Read numbers from filename (or stdin), line by line (comma (or (single)
 * space) separated list); places starting_LBA,number_of_block pairs in an
 * array of scat_gath_elem elements pointed to by the returned value. If
 * this fails NULL is returned and an error number is written to errp (if it
 * is non-NULL). Assumed decimal (and may have suffix multipliers) when
 * def_hex==false; if a number is prefixed by '0x', '0X' or contains trailing
 * 'h' or 'H' that denotes a hex number. When def_hex==true all numbers are
 * assumed to be hex (ignored '0x' prefixes and 'h' suffixes) and multiplers
 * are not permitted. Heap allocates an array just big enough to hold all
 * elements if the file is countable. Pipes and stdin are not considered
 * countable. In the non-countable case an array of MAX_FIXED_SGL_ELEMS
 * elements is pre-allocated; if it is exceeded sg_convert_errno(EDOM) is
 * placed in *errp (if it is non-NULL). One of the first actions is to write
 * 0 to *errp (if it is non-NULL) so the caller does not need to zero it
 * before calling. */
bool
scat_gath_list::load_from_file(const char * file_name, bool def_hex,
                               bool flexible, bool b_vb)
{
    bool have_stdin;
    bool have_err = false;
    FILE * fp;
    const char * fnp;

    have_stdin = ((1 == strlen(file_name)) && ('-' == file_name[0]));
    if (have_stdin) {
        fp = stdin;
        fnp = "<stdin>";
    } else {
        fnp = file_name;
        fp = fopen(fnp, "r");
        if (NULL == fp) {
            m_errno = errno;
            if (b_vb)
                pr2serr("%s: opening %s: %s\n", __func__, fnp,
                        safe_strerror(m_errno));
            return false;
        }
    }
    if (! file2sgl_helper(fp, fnp, def_hex, flexible, b_vb))
        have_err = true;
    if (! have_stdin)
        fclose(fp);
    return have_err ? false : true;
}

const char *
scat_gath_list::linearity_as_str() const
{
    switch (linearity) {
    case SGL_LINEAR:
        return "linear";
    case SGL_MONOTONIC:
        return "monotonic";
    case SGL_MONO_OVERLAP:
        return "monotonic, overlapping";
    case SGL_NON_MONOTONIC:
        return "non-monotonic";
    default:
        return "unknown";
    }
}

void
scat_gath_list::set_weaker_linearity(enum sgl_linearity_e lin)
{
    int i_lin = (int)lin;

    if (i_lin > (int)linearity)
        linearity = lin;
}

/* id_str may be NULL (if so replace by "unknown"), present to enhance verbose
 * output. */
void
scat_gath_list::dbg_print(bool skip_meta, const char * id_str, bool to_stdout,
                          bool show_sgl, bool lock) const
{
    int k;
    if (lock)
        strerr_mut.lock();
    int num = sgl.size();
    const char * caller = id_str ? id_str : "unknown";
    FILE * fp = to_stdout ? stdout : stderr;

    if (! skip_meta) {
        fprintf(fp, "%s: elems=%d, sgl %spresent, linearity=%s\n",
                caller, num, (sgl.empty() ? "not " : ""),
                linearity_as_str());
        fprintf(fp, "  sum=%" PRId64 ", sum_hard=%s lowest=0x%" PRIx64
                ", high_lba_p1=", sum, (sum_hard ? "true" : "false"),
                lowest_lba);
        fprintf(fp, "0x%" PRIx64 "\n", high_lba_p1);
    }
    fprintf(fp, "  >> %s scatter gather list (%d element%s):\n", caller, num,
            (num == 1 ? "" : "s"));
    if (show_sgl) {
        for (k = 0; k < num; ++k) {
            const struct scat_gath_elem & sge = sgl[k];

            fprintf(fp, "    lba: 0x%" PRIx64 ", number: 0x%" PRIx32,
                    sge.lba, sge.num);
            if (sge.lba > 0)
                fprintf(fp, " [next lba: 0x%" PRIx64 "]", sge.lba + sge.num);
            fprintf(fp, "\n");
        }
    }
    if (lock)
        strerr_mut.unlock();
}

/* Assumes sgl array (vector) is setup. The other fields in this object are
 * set by analyzing sgl in a single pass. The fields that are set are:
 * fragmented, lowest_lba, high_lba_p1, monotonic, overlapping, sum and
 * sum_hard. Degenerate elements (i.e. those with 0 blocks) are ignored apart
 * from when one is last which makes sum_hard false and its LBA becomes
 * high_lba_p1 if it is the highest in the list. An empty sgl is equivalent
 * to a 1 element list with [0, 0], so sum_hard==false, monit==true,
 * fragmented==false and overlapping==false . id_str may be NULL, present
 * to enhance verbose output. */
void
scat_gath_list::sum_scan(const char * id_str, bool show_sgl, bool b_vb)
{
    bool degen = false;
    bool first = true;
    bool regular = true;        /* no overlapping segments detected */
    int k;
    int elems = sgl.size();
    uint32_t prev_num, t_num;
    uint64_t prev_lba, t_lba, low, high, end;

    sum = 0;
    for (k = 0, low = 0, high = 0; k < elems; ++k) {
        const struct scat_gath_elem & sge = sgl[k];

        degen = false;
        t_num = sge.num;
        if (0 == t_num) {
            degen = true;
            if (! first)
                continue;       /* ignore degen element that not first */
        }
        if (first) {
            low = sge.lba;
            sum = t_num;
            high = sge.lba + sge.num;
            first = false;
        } else {
            t_lba = sge.lba;
            if ((prev_lba + prev_num) != t_lba)
                set_weaker_linearity(SGL_MONOTONIC);
            sum += t_num;
            end = t_lba + t_num;
            if (end > high)
                high = end;     /* high is one plus highest LBA */
            if (prev_lba < t_lba)
                ;
            else if (prev_lba == t_lba) {
                if (prev_num > 0) {
                    set_weaker_linearity(SGL_MONO_OVERLAP);
                    break;
                }
            } else {
                low = t_lba;
                set_weaker_linearity(SGL_NON_MONOTONIC);
                break;
            }
            if (regular) {
                if ((prev_lba + prev_num) > t_lba)
                    regular = false;
            }
        }
        prev_lba = sge.lba;
        prev_num = sge.num;
    }           /* end of for loop while still elements and monot true */

    if (k < elems) {    /* only here if above breaks are taken */
        prev_lba = t_lba;
        ++k;
        for ( ; k < elems; ++k) {
            const struct scat_gath_elem & sge = sgl[k];

            degen = false;
            t_lba = sge.lba;
            t_num = sge.num;
            if (0 == t_num) {
                degen = true;
                continue;
            }
            sum += t_num;
            end = t_lba + t_num;
            if (end > high)
                high = end;
            if (prev_lba > t_lba) {
                if (t_lba < low)
                    low = t_lba;
            }
            prev_lba = t_lba;
        }
    } else
        if (! regular)
            set_weaker_linearity(SGL_MONO_OVERLAP);

    lowest_lba = low;
    if (degen && (elems > 0)) { /* last element always impacts high_lba_p1 */
        t_lba = sgl[elems - 1].lba;
        high_lba_p1 = (t_lba > high) ? t_lba : high;
    } else
        high_lba_p1 = high;
    sum_hard = (elems > 0) ? ! degen : false;
    if (b_vb)
        dbg_print(false, id_str, false, show_sgl);
}

/* Usually will append (or add to start if empty) sge unless 'extra_blks'
 * exceeds MAX_SGL_NUM_VAL. In that case multiple sge_s are added with
 * sge.num = MAX_SGL_NUM_VAL or less (for final sge) until extra_blks is
 * exhausted. Returns new size of scatter gather list. */
int
scat_gath_list::append_1or(int64_t extra_blks, int64_t start_lba)
{
    int o_num = sgl.size();
    const int max_nbs = MAX_SGL_NUM_VAL;
    int64_t cnt = 0;
    struct scat_gath_elem sge;

    if ((extra_blks <= 0) || (start_lba < 0))
        return o_num;       /* nothing to do */
    if ((o_num > 0) && (! sum_hard)) {
        sge = sgl[o_num - 1];   /* assume sge.num==0 */
        if (sge.lba == (uint64_t)start_lba) {
            if (extra_blks <= max_nbs)
                sge.num = extra_blks;
            else
                sge.num = max_nbs;
            sgl[o_num - 1] = sge;
            cnt = sge.num;
            sum += cnt;
            sum_hard = true;
            if (cnt <= extra_blks) {
                high_lba_p1 = sge.lba + cnt;
                return o_num;
            }
        }
    } else if (0 == o_num)
        lowest_lba = start_lba;

    for ( ; cnt < extra_blks; cnt += max_nbs) {
        sge.lba = start_lba + cnt;
        if ((extra_blks - cnt) <= max_nbs)
            sge.num = extra_blks - cnt;
        else
            sge.num = max_nbs;
        sgl.push_back(sge);
        sum += sge.num;
    }           /* always loops at least once */
    sum_hard = true;
    high_lba_p1 = sge.lba + sge.num;
    return sgl.size();
}

int
scat_gath_list::append_1or(int64_t extra_blks)
{
    int o_num = sgl.size();
    if (o_num < 1)
        return append_1or(extra_blks, 0);

    struct scat_gath_elem sge = sgl[o_num - 1];
    return append_1or(extra_blks, sge.lba + sge.num);
}

bool
sgls_eq_off(const scat_gath_list & left, int l_e_ind, int l_blk_off,
            const scat_gath_list & right, int r_e_ind, int r_blk_off,
            bool allow_partial)
{
    int lrem, rrem;
    int lelems = left.sgl.size();
    int relems = right.sgl.size();

    while ((l_e_ind < lelems) && (r_e_ind < relems)) {
        if ((left.sgl[l_e_ind].lba + l_blk_off) !=
            (right.sgl[r_e_ind].lba + r_blk_off))
            return false;
        lrem = left.sgl[l_e_ind].num - l_blk_off;
        rrem = right.sgl[r_e_ind].num - r_blk_off;
        if (lrem == rrem) {
            ++l_e_ind;
            l_blk_off = 0;
            ++r_e_ind;
            r_blk_off = 0;
        } else if (lrem < rrem) {
            ++l_e_ind;
            l_blk_off = 0;
            r_blk_off += lrem;
        } else {
            ++r_e_ind;
            r_blk_off = 0;
            l_blk_off += rrem;
        }
    }
    if ((l_e_ind >= lelems) && (r_e_ind >= relems))
        return true;
    return allow_partial;
}

/* If bad arguments returns -1, otherwise returns the lowest LBA in *sglp .
 * If no elements considered returns 0. If ignore_degen is true than
 * ignores all elements with sge.num zero unless always_last is also
 * true in which case the last element is always considered. */
int64_t
scat_gath_list::get_lowest_lba(bool ignore_degen, bool always_last) const
{
    int k;
    const int num_elems = sgl.size();
    bool some = (num_elems > 0);
    int64_t res = INT64_MAX;

    for (k = 0; k < num_elems; ++k) {
        if ((0 == sgl[k].num) && ignore_degen)
            continue;
        if ((int64_t)sgl[k].lba < res)
            res = sgl[k].lba;
    }
    if (always_last && some) {
        if ((int64_t)sgl[k - 1].lba < res)
            res = sgl[k - 1].lba;
    }
    return (INT64_MAX == res) ? 0 : res;
}

/* Returns >= 0 if sgl can be simplified to a single LBA. So an empty sgl
 * will return 0; a one element sgl will return its LBA. A multiple element
 * sgl only returns the first element's LBA (that is not degenerate) if the
 * sgl is monotonic and not fragmented. In the extreme case takes last
 * element's LBA if all prior elements are degenerate. Else returns -1 .
 * Assumes sgl_sum_scan() has been called. */
int64_t
scat_gath_list::get_low_lba_from_linear() const
{
    const int num_elems = sgl.size();
    int k;

    if (num_elems <= 1)
        return (1 == num_elems) ? sgl[0].lba : 0;
    else {
        if (linearity == SGL_LINEAR) {
            for (k = 0; k < (num_elems - 1); ++k) {
                if (sgl[k].num > 0)
                    return sgl[k].lba;
            }
            /* take last element's LBA if all earlier are degenerate */
            return sgl[k].lba;
        } else
            return -1;
    }
}

bool
scat_gath_list::is_pipe_suitable() const
{
    return (lowest_lba == 0) && (linearity == SGL_LINEAR);
}

scat_gath_iter::scat_gath_iter(const scat_gath_list & parent)
    : sglist(parent), it_el_ind(0), it_blk_off(0), blk_idx(0)
{
    int elems = sglist.num_elems();

    if (elems > 0)
        extend_last = (0 == sglist.sgl[elems - 1].num);
}

bool
scat_gath_iter::set_by_blk_idx(int64_t _blk_idx)
{
    bool first;
    int k;
    const int elems = sglist.sgl.size();
    const int last_ind = elems - 1;
    uint32_t num;
    int64_t bc = _blk_idx;

    if (bc < 0)
        return false;

    if (bc == blk_idx)
        return true;
    else if (bc > blk_idx) {
        k = it_el_ind;
        bc -= blk_idx;
    } else
        k = 0;
    for (first = true; k < elems; ++k, first = false) {
        num = ((k == last_ind) && extend_last) ? MAX_SGL_NUM_VAL :
                                                 sglist.sgl[k].num;
        if (first) {
            if ((int64_t)(num - it_blk_off) < bc)
                bc -= (num - it_blk_off);
            else {
                it_blk_off = bc + it_blk_off;
                break;
            }
        } else {
            if ((int64_t)num < bc)
                bc -= num;
            else {
                it_blk_off = (uint32_t)bc;
                break;
            }
        }
    }
    it_el_ind = k;
    blk_idx = _blk_idx;

    if (k < elems)
        return true;
    else if ((k == elems) && (0 == it_blk_off))
        return true;    /* EOL */
    else
        return false;
}

/* Given a blk_count, the iterator (*iter_p) is moved toward the EOL.
 * Returns true unless blk_count takes iterator two or more past the last
 * element. So if blk_count takes the iterator to the EOL, this function
 * returns true. Takes into account iterator's extend_last flag. */
bool
scat_gath_iter::add_blks(uint64_t blk_count)
{
    bool first;
    int k;
    const int elems = sglist.sgl.size();
    const int last_ind = elems - 1;
    uint32_t num;
    uint64_t bc = blk_count;

    if (0 == bc)
        return true;
    for (first = true, k = it_el_ind; k < elems; ++k, first = false) {
        num = ((k == last_ind) && extend_last) ? MAX_SGL_NUM_VAL :
                                                 sglist.sgl[k].num;
        if (first) {
            if ((uint64_t)(num - it_blk_off) < bc)
                bc -= (num - it_blk_off);
            else {
                it_blk_off = bc + it_blk_off;
                break;
            }
        } else {
            if ((uint64_t)num < bc)
                bc -= num;
            else {
                it_blk_off = (uint32_t)bc;
                break;
            }
        }
    }
    it_el_ind = k;
    blk_idx += blk_count;

    if (k < elems)
        return true;
    else if ((k == elems) && (0 == it_blk_off))
        return true;    /* EOL */
    else
        return false;
}

/* Move the iterator from its current position (which may be to EOL) towards
 * the start of the sgl (i.e. backwards) for blk_count blocks. Returns true
 * if iterator is valid after the move, else returns false. N.B. if false is
 * returned, then the iterator is invalid and may need to set it to a valid
 * value. */
bool
scat_gath_iter::sub_blks(uint64_t blk_count)
{
    bool first;
    int k = it_el_ind;
    uint64_t bc = 0;
    const uint64_t orig_blk_count = blk_count;

    if (0 == blk_count)
        return true;
    for (first = true; k >= 0; --k) {
        if (first) {
            if (blk_count > (uint64_t)it_blk_off)
                blk_count -= it_blk_off;
            else {
                it_blk_off -= blk_count;
                break;
            }
            first = false;
        } else {
            uint32_t off = sglist.sgl[k].num;

            bc = blk_count;
            if (bc > (uint64_t)off)
                blk_count -= off;
            else {
                bc = off - bc;
                break;
            }
        }
    }
    if (k < 0) {
        blk_idx = 0;
        return false;           /* bad situation */
    }
    if ((int64_t)orig_blk_count <= blk_idx)
        blk_idx -= orig_blk_count;
    else
        blk_idx = 0;
    it_el_ind = k;
    if (! first)
        it_blk_off = (uint32_t)bc;
    return true;
}

/* Returns LBA referred to by iterator if valid or returns SG_LBA_INVALID
 * (-1) if at end or invalid. */
int64_t
scat_gath_iter::current_lba() const
{
    const int elems = sglist.sgl.size();
    int64_t res = SG_LBA_INVALID; /* for at end or invalid (-1) */

    if (it_el_ind < elems) {
        struct scat_gath_elem sge = sglist.sgl[it_el_ind];

        if ((uint32_t)it_blk_off < sge.num)
            return sge.lba + it_blk_off;
        else if (((uint32_t)it_blk_off == sge.num) &&
                 ((it_el_ind + 1) < elems)) {
            class scat_gath_iter iter(*this);

            ++iter.it_el_ind;
            iter.it_blk_off = 0;
            /* worst case recursion will stop at end of sgl */
            return iter.current_lba();
        }
    }
    return res;
}

int64_t
scat_gath_iter::current_lba_rem_num(int & rem_num) const
{
    const int elems = sglist.sgl.size();
    int64_t res = SG_LBA_INVALID; /* for at end or invalid (-1) */

    if (it_el_ind < elems) {
        struct scat_gath_elem sge = sglist.sgl[it_el_ind];

        if ((uint32_t)it_blk_off < sge.num) {
            rem_num = sge.num - it_blk_off;
            return sge.lba + it_blk_off;
        } else if (((uint32_t)it_blk_off == sge.num) &&
                 ((it_el_ind + 1) < elems)) {
            class scat_gath_iter iter(*this);

            ++iter.it_el_ind;
            iter.it_blk_off = 0;
            /* worst case recursion will stop at end of sgl */
            return iter.current_lba_rem_num(rem_num);
        }
    }
    rem_num = -1;
    return res;
}

struct scat_gath_elem
scat_gath_iter::current_elem() const
{
    const int elems = sglist.sgl.size();
    struct scat_gath_elem sge;

    sge.make_bad();
    if (it_el_ind < elems)
        return sglist.sgl[it_el_ind];
    return sge;
}

/* Returns true of no sgl or sgl is at the end [elems, 0], otherwise it
 * returns false. */
bool
scat_gath_iter::at_end() const
{
    const int elems = sglist.sgl.size();

    return ((0 == elems) || ((it_el_ind == elems) && (0 == it_blk_off)));
}

/* Returns true if associated iterator is monotonic (increasing) and not
 * fragmented. Empty sgl and single element degenerate considered linear.
 * Assumes sgl_sum_scan() has been called on sgl. */
bool
scat_gath_iter::is_sgl_linear() const
{
    return sglist.linearity == SGL_LINEAR;
}

int
scat_gath_iter::linear_for_n_blks(int max_n) const
{
    int k, rem;
    const int elems = sglist.sgl.size();
    uint64_t prev_lba;
    struct scat_gath_elem sge;

    if (at_end() || (max_n <= 0))
        return 0;
    sge = sglist.sgl[it_el_ind];
    rem = (int)sge.num - it_blk_off;
    if (max_n <= rem)
        return max_n;
    prev_lba = sge.lba + sge.num;
    for (k = it_el_ind + 1; k < elems; ++k) {
        sge = sglist.sgl[k];
        if (sge.lba != prev_lba)
            return rem;
        rem += sge.num;
        if (max_n <= rem)
            return max_n;
        prev_lba = sge.lba + sge.num;
    }
    return rem;
}

/* id_str may be NULL (if so replace by "unknown"), present to enhance verbose
 * output. */
void
scat_gath_iter::dbg_print(const char * id_str, bool to_stdout,
                          int verbose) const
{
    const char * caller = id_str ? id_str : "unknown";
    FILE * fp = to_stdout ? stdout : stderr;
    lock_guard<mutex> lk(strerr_mut);

    fprintf(fp, "%s: it_el_ind=%d, it_blk_off=%d, blk_idx=%" PRId64 "\n",
            caller, it_el_ind, it_blk_off, blk_idx);
    fprintf(fp, "  extend_last=%d\n", extend_last);
    if (verbose)
        sglist.dbg_print(false, " iterator's", to_stdout, verbose > 1, false);
}

/* Calculates difference between iterators, logically: res <-- lhs - rhs
 * Checks that lhsp and rhsp have same underlying sgl, if not returns
 * INT_MIN. Assumes iterators close enough for result to lie in range
 * from (-INT_MAX) to INT_MAX (inclusive). */
int
diff_between_iters(const struct scat_gath_iter & left,
                   const struct scat_gath_iter & right)
{
    int res, k, r_e_ind, l_e_ind;

    if (&left.sglist != &right.sglist) {
        pr2serr("%s: bad args\n", __func__);
        return INT_MIN;
    }
    r_e_ind = right.it_el_ind;
    l_e_ind = left.it_el_ind;
    if (l_e_ind < r_e_ind) { /* so difference will be negative */
        res = diff_between_iters(right, left);        /* cheat */
        if (INT_MIN == res)
            return res;
        return -res;
    } else if (l_e_ind == r_e_ind)
        return (int)left.it_blk_off - (int)right.it_blk_off;
    /* (l_e_ind > r_e_ind) so (lhs > rhs) */
    res = (int)right.sglist.sgl[r_e_ind].num - right.it_blk_off;
    for (k = 1; (r_e_ind + k) < l_e_ind; ++k) {
        // pr2serr("%s: k=%d, res=%d, num=%d\n", __func__, k, res,
        //         (int)right.sglist.sgl[r_e_ind + k].num);
        res += (int)right.sglist.sgl[r_e_ind + k].num;
    }
    res += left.it_blk_off;
    // pr2serr("%s: at exit res=%d\n", __func__, res);
    return res;
}

/* Compares from the current iterator positions of left and left until
 * the shorter list is exhausted. Returns false on the first inequality.
 * If no inequality and both remaining lists are same length then returns
 * true. If no inequality but remaining lists differ in length then returns
 * allow_partial. */
bool
sgls_eq_from_iters(const struct scat_gath_iter & left,
                   const struct scat_gath_iter & right,
                   bool allow_partial)
{
    return sgls_eq_off(left.sglist, left.it_el_ind, left.it_blk_off,
                       right.sglist, right.it_el_ind, right.it_blk_off,
                       allow_partial);
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

static void
sig_listen_thread(struct global_collection * clp)
{
    int sig_number;

    while (1) {
        sigwait(&signal_set, &sig_number);
        if (shutting_down)
            break;
        if (SIGINT == sig_number) {
            pr2serr_lk("%sinterrupted by SIGINT\n", my_name);
            clp->next_count_pos.store(-1);
        }
    }
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

static inline uint8_t *
get_buffp(Rq_elem * rep)
{
    return rep->buffp;
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
    // volatile bool stop_after_write = false;
    bool own_infd = false;
    bool in_is_sg, in_mmap, out_is_sg, out_mmap;
    bool own_outfd = false;
    bool only_one_sg = false;
    // bool share_and_ofreg;
    class scat_gath_iter i_sg_it(clp->i_sgl);
    class scat_gath_iter o_sg_it(clp->o_sgl);
    vector<cdb_arr_t> a_cdb;
    vector<struct sg_io_v4> a_v4;
    // mrq_arr_t deferred_arr;  /* MRQ deferred array (vector) */

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
    if (! rep->both_sg) {
        rep->buffp = sg_memalign(sz, 0 /* page align */, &rep->alloc_bp,
                                 false);
        if (NULL == rep->buffp)
            err_exit(ENOMEM, "out of memory creating user buffers\n");
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
        ssize_t ssz;

        ssz = getrandom(&rep->seed, sizeof(rep->seed), 0);
        if (ssz < (ssize_t)sizeof(rep->seed))
            pr2serr_lk("[%d] %s: getrandom() failed, ret=%d\n", id, __func__,
                       (int)ssz);
        if (vb > 1)
            pr2serr_lk("[%d] %s: seed=%ld\n", id, __func__, rep->seed);
        srand48_r(rep->seed, &rep->drand);
    }

    if (in_is_sg && clp->infp) {
        fd = sg_in_open(clp, clp->infp, (in_mmap ? &rep->buffp : NULL),
                        (in_mmap ? &rep->mmap_len : NULL));
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
                         (out_mmap ? &rep->mmap_len : NULL));
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
    while (1) {
        get_next_res gnr = clp->get_next(clp->mrq_num * clp->bpt);

        seg_blks = gnr.second;
        if (seg_blks <= 0) {
            if (seg_blks < 0)
                res = -seg_blks;
            break;
        }
        if (! i_sg_it.set_by_blk_idx(gnr.first)) {
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
            res = do_both_sg_segment(rep, i_sg_it, o_sg_it, seg_blks, a_cdb,
                                     a_v4);
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
        if (rep->stop_after_write)
            break;
    }   /* ^^^^^^^^^^ end of main while loop which copies segments ^^^^^^ */
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

#if 0
    if ((rep->mmap_active == 0) && rep->alloc_bp)
        free(rep->alloc_bp);
    if ((1 == rep->mmap_active) && (rep->mmap_len > 0)) {
        if (munmap(rep->buffp, rep->mmap_len) < 0) {
            int err = errno;
            char bb[64];

            pr2serr_lk("thread=%d: munmap() failed: %s\n", rep->id,
                       tsafe_strerror(err, bb));
        }
        if (vb > 4)
            pr2serr_lk("thread=%d: munmap(%p, %d)\n", rep->id, rep->buffp,
                       rep->mmap_len);
        rep->mmap_active = 0;
    }
#endif

    if (own_infd && (rep->infd >= 0)) {
        if (vb && in_is_sg) {
#if 0
            ++num_waiting_calls;
#endif
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
#if 0
            ++num_waiting_calls;
#endif
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
                  bool fua, bool dpo)
{
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
    int vb = clp->verbose;
    int k, j, f1, slen, sstatus, blen;
    char b[80];

    blen = sizeof(b);
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
                char b[256];

                if (ssh.response_code & 0x1) {
                    ok = true;
                    last_err_on_in = false;
                }
                if (vb) {
                    sg_get_sense_str("  ", sbp, slen, false, blen, b);
                    pr2serr_lk("[%d] a_v4[%d]:\n%s\n", id, k, b);
                }
            }
        }
        if (ok && f1) {
            ++n_good;
            if (a_v4p->dout_xfer_len >= (uint32_t)clp->bs) {
                if (a_v4p->dout_resid)
                    good_outblks +=
                         (a_v4p->dout_xfer_len - a_v4p->dout_resid) / clp->bs;
                else    /* avoid division in common case of resid==0 */
                    good_outblks += (uint32_t)a_v4p->usr_ptr;
            }
            if (a_v4p->din_xfer_len >= (uint32_t)clp->bs) {
                if (a_v4p->din_resid)
                    good_inblks += (a_v4p->din_xfer_len - a_v4p->din_resid) /
                                   clp->bs;
                else
                    good_inblks += (uint32_t)a_v4p->usr_ptr;
            }
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
    return n_good;
}

/* Returns number of blocks successfully processed or a negative error
 * number. */
static int
sg_half_segment(Rq_elem * rep, scat_gath_iter & sg_it, bool is_wr,
                   int seg_blks, uint8_t *dp,
                   vector<cdb_arr_t> & a_cdb,
                   vector<struct sg_io_v4> & a_v4)
{
    int num_mrq, k, res, fd, mrq_pack_id_base, id, b_len, rflags;
    int num, kk, lin_blks, cdbsz, num_good;
    int o_seg_blks = seg_blks;
    uint32_t in_fin_blks, out_fin_blks;
    uint32_t mrq_q_blks = 0;
    uint32_t in_mrq_q_blks = 0;
    uint32_t out_mrq_q_blks = 0;
    const int max_cdb_sz = MAX_SCSI_CDB_SZ;
    struct sg_io_v4 * a_v4p;
    struct sg_io_v4 ctl_v4;     /* MRQ control object */
    struct global_collection * clp = rep->clp;
    const char * iosub_str = "SUBMIT(variable blocking)";
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
        iosub_str = "(ordered blocking)";

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

    for (k = 0; seg_blks > 0; ++k, seg_blks -= num) {
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
                                false, is_wr, flagsp->fua, flagsp->dpo);
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
        if (is_wr) {
            t_v4p->dout_xfer_len = num * clp->bs;
            t_v4p->dout_xferp = (uint64_t)(dp + (mrq_q_blks * clp->bs));
        } else {
            t_v4p->din_xfer_len = num * clp->bs;
            t_v4p->din_xferp = (uint64_t)(dp + (mrq_q_blks * clp->bs));
        }
        t_v4p->timeout = DEF_TIMEOUT;
        t_v4p->usr_ptr = num;           /* pass number blocks requested */
        mrq_q_blks += num;
        t_v4p->request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;
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
    ctl_v4.dout_xferp = (uint64_t)a_v4.data();        /* request array */
    ctl_v4.dout_xfer_len = a_v4.size() * sizeof(struct sg_io_v4);
    ctl_v4.din_xferp = (uint64_t)a_v4.data();         /* response array */
    ctl_v4.din_xfer_len = a_v4.size() * sizeof(struct sg_io_v4);
    if (false /* allow_mrq_abort */)
        ctl_v4.request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;

    if (vb > 4) {
        pr2serr_lk("[%d] %s: >> Control object _before_ ioctl(SG_IO%s):\n",
                   id, __func__, iosub_str);
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
        int err = errno;

        if (E2BIG == err)
                sg_take_snap(fd, id, true);
        else if (EBUSY == err) {
            ++num_ebusy;
            std::this_thread::yield();/* allow another thread to progress */
            goto try_again;
        }
        pr2serr_lk("[%d] %s: ioctl(SG_IO%s, %s)-->%d, errno=%d: %s\n", id,
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

        if (FT_DEV_NULL == clp->out_type)
            goto bypass;
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
do_both_sg_segment(Rq_elem * rep, scat_gath_iter & i_sg_it,
                   scat_gath_iter & o_sg_it, int seg_blks,
                   vector<cdb_arr_t> & a_cdb,
                   vector<struct sg_io_v4> & a_v4)
{
    bool err_on_in = false;
    int num_mrq, k, res, fd, mrq_pack_id_base, id, b_len, iflags, oflags;
    int num, kk, i_lin_blks, o_lin_blks, cdbsz, num_good;
    int o_seg_blks = seg_blks;
    uint32_t in_fin_blks, out_fin_blks;
    uint32_t in_mrq_q_blks = 0;
    uint32_t out_mrq_q_blks = 0;
    const int max_cdb_sz = MAX_SCSI_CDB_SZ;
    struct sg_io_v4 * a_v4p;
    struct sg_io_v4 ctl_v4;     /* MRQ control object */
    struct global_collection * clp = rep->clp;
    const char * iosub_str = "SUBMIT(svb)";
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

    oflags = SGV4_FLAG_SHARE | SGV4_FLAG_NO_DXFER;
    if (oflagsp->dio)
        oflags |= SGV4_FLAG_DIRECT_IO;
    if (oflagsp->qhead)
        oflags |= SGV4_FLAG_Q_AT_HEAD;
    if (oflagsp->qtail)
        oflags |= SGV4_FLAG_Q_AT_TAIL;
    oflags |= SGV4_FLAG_DO_ON_OTHER;

    for (k = 0; seg_blks > 0; ++k, seg_blks -= num) {
        kk = min<int>(seg_blks, clp->bpt);
        i_lin_blks = i_sg_it.linear_for_n_blks(kk);
        o_lin_blks = o_sg_it.linear_for_n_blks(kk);
        num = min<int>(i_lin_blks, o_lin_blks);
        if (num <= 0) {
            res = 0;
            pr2serr_lk("[%d] %s: unexpected num=%d\n", id, __func__, num);
            break;
        }

        /* First build the command/request for the read-side*/
        cdbsz = clp->cdbsz_in;
        res = sg_build_scsi_cdb(t_cdb.data(), cdbsz, num,
                                i_sg_it.current_lba(), false, false,
                                iflagsp->fua, iflagsp->dpo);
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
        t_v4p->din_xfer_len = num * clp->bs;
        t_v4p->timeout = DEF_TIMEOUT;
        t_v4p->usr_ptr = num;           /* pass number blocks requested */
        in_mrq_q_blks += num;
        t_v4p->request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;
        a_v4.push_back(t_v4);

        /* Now build the command/request for write-side (WRITE or VERIFY) */
        cdbsz = clp->cdbsz_out;
        res = sg_build_scsi_cdb(t_cdb.data(), cdbsz, num,
                                o_sg_it.current_lba(), clp->verify, true,
                                oflagsp->fua, oflagsp->dpo);
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
        t_v4p->dout_xfer_len = num * clp->bs;
        t_v4p->timeout = DEF_TIMEOUT;
        t_v4p->usr_ptr = num;           /* pass number blocks requested */
        out_mrq_q_blks += num;
        t_v4p->request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;
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
    else if (rep->only_in_sg)
        fd = rep->infd;
    else if (rep->only_out_sg)
        fd = rep->outfd;
    else {
        pr2serr_lk("[%d] %s: why am I here? No sg devices\n", id, __func__);
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
    ctl_v4.dout_xferp = (uint64_t)a_v4.data();        /* request array */
    ctl_v4.dout_xfer_len = a_v4.size() * sizeof(struct sg_io_v4);
    ctl_v4.din_xferp = (uint64_t)a_v4.data();         /* response array */
    ctl_v4.din_xfer_len = a_v4.size() * sizeof(struct sg_io_v4);
    if (false /* allow_mrq_abort */)
        ctl_v4.request_extra = mrq_pack_id_base + ++rep->mrq_pack_id_off;

    if (vb > 4) {
        pr2serr_lk("%s: >> Control object _before_ ioctl(SG_IO%s):\n",
                   __func__, iosub_str);
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
        int err = errno;

        if (E2BIG == err)
                sg_take_snap(fd, id, true);
        else if (EBUSY == err) {
            ++num_ebusy;
            std::this_thread::yield();/* allow another thread to progress */
            goto try_again;
        }
        pr2serr_lk("%s: ioctl(SG_IO%s, %s)-->%d, errno=%d: %s\n", __func__,
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
                rep->stop_after_write = ! (! err_on_in && clp->out_flags.coe);
            }
        }
    }
fini:
    return res < 0 ? res : (min<int>(in_fin_blks, out_fin_blks));
}

/* Returns reserved_buffer_size/mmap_size if success, else 0 for failure */
static int
sg_prepare_resbuf(int fd, int bs, int bpt, bool unit_nano, bool no_dur,
                  bool masync, bool wq_excl, uint8_t **mmpp)
{
    static bool done = false;
    int res, t, num;
    uint8_t *mmp;
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

    seip = &sei;
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
            pr2serr_lk("sgh_dd: %s: SG_SET_GET_EXTENDED(NO_DURATION) "
                       "error: %s\n", __func__, strerror(errno));
    }
bypass:
    num = bs * bpt;
    res = ioctl(fd, SG_SET_RESERVED_SIZE, &num);
    if (res < 0) {
        perror("sgh_dd: SG_SET_RESERVED_SIZE error");
        return 0;
    } else {
        int nn;

        res = ioctl(fd, SG_GET_RESERVED_SIZE, &nn);
        if (res < 0) {
            perror("sgh_dd: SG_GET_RESERVED_SIZE error");
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
                int err = errno;

                pr2serr_lk("sgh_dd: %s: sz=%d, fd=%d, mmap() failed: %s\n",
                           __func__, num, fd, strerror(err));
                return 0;
            }
            *mmpp = mmp;
        }
    }
    t = 1;
    res = ioctl(fd, SG_SET_FORCE_PACK_ID, &t);
    if (res < 0)
        perror("sgh_dd: SG_SET_FORCE_PACK_ID error");
    if (unit_nano) {
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
#if 0
    t = 1;
    res = ioctl(fd, SG_SET_DEBUG, &t);  /* more info in /proc/scsi/sg/debug */
    if (res < 0)
        perror("sgh_dd: SG_SET_DEBUG error");
#endif
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
    int len, err;
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
            return err ? err : SG_LIB_SYNTAX_ERROR;
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
#if 0
    if (vb > 3) {
        pr2serr("%s: scatter gathet list:\n", is_skip ? ("skip" : "seek"));
        either_list.dbg_print(false, is_skip ? ("skip" : "seek"), false,
                   bool show_sgl)
#endif
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
        else if (0 == strcmp(cp, "masync"))
            fp->masync = true;
        else if (0 == strcmp(cp, "mmap"))
            ++fp->mmap;         /* mmap > 1 stops munmap() being called */
        else if (0 == strcmp(cp, "nodur"))
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
           int * mmap_lenp)
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
    n = sg_prepare_resbuf(fd, clp->bs, clp->bpt, clp->unit_nanosec,
                          clp->in_flags.no_dur, clp->in_flags.masync,
                          clp->in_flags.wq_excl, mmpp);
    if (n <= 0)
        return -SG_LIB_FILE_ERROR;
    if (mmap_lenp)
        *mmap_lenp = n;
    return fd;
}

static int
sg_out_open(struct global_collection *clp, const char *outf, uint8_t **mmpp,
            int * mmap_lenp)
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
    n = sg_prepare_resbuf(fd, clp->bs, clp->bpt, clp->unit_nanosec,
                          clp->out_flags.no_dur, clp->out_flags.masync,
                          clp->out_flags.wq_excl, mmpp);
    if (n <= 0)
        return -SG_LIB_FILE_ERROR;
    if (mmap_lenp)
        *mmap_lenp = n;
    return fd;
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
            clp->cdbsz_in = sg_get_num(buf);
            clp->cdbsz_out = clp->cdbsz_in;
            clp->cdbsz_given = true;
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
        } else if (0 == strcmp(key, "mrq")) {
            if (isdigit(buf[0]))
                cp = buf;
            else {
                pr2serr("%sonly mrq=NRQS which is a number allowed here\n",
                        my_name);
                goto syn_err;
            }
            clp->mrq_num = sg_get_num(cp);
            if (clp->mrq_num < 0) {
                pr2serr("%sbad argument to 'mrq='\n", my_name);
                goto syn_err;
            }
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
        else if (0 == strcmp(key, "time"))
            do_time = sg_get_num(buf);
        else if (0 == strncmp(key, "verb", 4))
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
#if 0
    if (clp->out_flags.mmap) {
        pr2serr("oflag=mmap needs either noshare=1\n");
        return SG_LIB_SYNTAX_ERROR;
    }
#endif
    /* defaulting transfer size to 128*2048 for CD/DVDs is too large
     * for the block layer in lk 2.6 and results in an EIO on the
     * SG_IO ioctl. So reduce it in that case. */
    if ((clp->bs >= 2048) && (! bpt_given))
        clp->bpt = DEF_BLOCKS_PER_2048TRANSFER;
    if (clp->in_flags.order)
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
    if (sg_version >= 40030)
        sg_version_ge_40030 = true;
    else {
        pr2serr(">>> %srequires an sg driver version of 4.0.30 or later\n\n",
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
            clp->infd = sg_in_open(clp, inf, NULL, NULL);
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
            clp->outfd = sg_out_open(clp, outf, NULL, NULL);
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

    if ((FT_SG == clp->in_type ) && (FT_SG == clp->out_type)) {
        ;
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
    res = exit_status;
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
#if 0
    if (clp->verbose > 1) {
        pr2serr("Number of SG_GET_NUM_WAITING calls=%ld\n",
                num_waiting_calls.load());
    }
#endif
    if (clp->verify && (SG_LIB_CAT_MISCOMPARE == res))
        pr2serr("Verify/compare failed due to miscompare\n");
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}
