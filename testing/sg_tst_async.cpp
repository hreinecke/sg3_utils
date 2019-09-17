/*
 * Copyright (c) 2014-2019 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <iostream>
#include <vector>
#include <map>
#include <list>
#include <system_error>
#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>
#include <random>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>       /* getrusage */


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
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pt.h"
#include "sg_cmds.h"

static const char * version_str = "1.40 20190917";
static const char * util_name = "sg_tst_async";

/* This is a test program for checking the async usage of the Linux sg
 * driver. Each thread opens 1 file descriptor to the next sg device (1
 * or more can be given on the command line) and then starts up to
 * num_per_thread commands or more while checking with the poll command (or
 * ioctl(SG_GET_NUM_WAITING) ) for the completion of those commands. Each
 * command has a unique "pack_id" which is a sequence starting at 1.
 * Either TEST UNIT UNIT, READ(16) or WRITE(16) commands are issued.
 *
 * This is C++ code with some things from C++11 (e.g. threads) and was
 * only just able to compile (when some things were reverted) with gcc/g++
 * version 4.7.3 found in Ubuntu 13.04 . C++11 "feature complete" support
 * was not available until g++ version 4.8.1 . It should build okay on
 * recent distributions.
 *
 * The build uses various object files from the <sg3_utils>/lib directory
 * which is assumed to be a sibling of this examples directory. Those
 * object files in the lib directory can be built with:
 *   cd <sg3_utils_package_root> ; ./configure ; cd lib; make
 *   cd ../testing
 *   make sg_tst_async
 *
 * Currently this utility is Linux only and uses the sg driver. The bsg
 * driver is known to be broken (it doesn't match responses to the
 * correct file descriptor that requested them). Around Linux kernel 4.15
 * the async capability of the bsg driver was removed. So this test code
 * no longer appiles to the bsg driver.
 *
 * BEWARE: >>> This utility will modify a logical block (default LBA 1000)
 * on the given device _when_ the '-W' option is given.
 *
 */

using namespace std;
using namespace std::chrono;

#define DEF_NUM_PER_THREAD 1000
#define DEF_NUM_THREADS 4
#define DEF_WAIT_MS 10          /* 0: yield or no wait */
#define DEF_NANOSEC_WAIT 25000  /* 25 microsecs */
#define DEF_TIMEOUT_MS 20000    /* 20 seconds */
#define DEF_LB_SZ 512
#define DEF_BLOCKING 0
#define DEF_DIRECT false        /* true: direct_io */
#define DEF_MMAP_IO false       /* true: mmap-ed IO with sg */
#define DEF_NO_XFER 0
#define DEF_LBA 1000

#define MAX_Q_PER_FD 16383      /* sg driver per file descriptor limit */
#define MAX_CONSEC_NOMEMS 4     /* was 16 */
#define URANDOM_DEV "/dev/urandom"

#ifndef SG_FLAG_Q_AT_TAIL
#define SG_FLAG_Q_AT_TAIL 0x10
#endif
#ifndef SG_FLAG_Q_AT_HEAD
#define SG_FLAG_Q_AT_HEAD 0x20
#endif


#define DEF_PT_TIMEOUT 60       /* 60 seconds */

#define EBUFF_SZ 256

static mutex console_mutex;
static mutex rand_lba_mutex;
static atomic<int> async_starts(0);
static atomic<int> sync_starts(0);
static atomic<int> async_finishes(0);
static atomic<int> start_ebusy_count(0);
static atomic<int> start_e2big_count(0);
static atomic<int> start_eagain_count(0);
static atomic<int> fin_eagain_count(0);
static atomic<int> fin_ebusy_count(0);
static atomic<int> start_edom_count(0);
static atomic<int> enomem_count(0);
static atomic<int> uniq_pack_id(1);
// static atomic<int> generic_errs(0);

static int page_size = 4096;   /* rough guess, will ask sysconf() */

enum command2execute {SCSI_TUR, SCSI_READ16, SCSI_WRITE16};
/* Linux Block layer queue disciplines: */
enum blkLQDiscipline {BLQ_DEFAULT, BLQ_AT_HEAD, BLQ_AT_TAIL};
/* Queue disciplines of this utility. When both completions and
 * queuing a new command are both possible: */
enum myQDiscipline {MYQD_LOW,   /* favour completions over new cmds */
                    MYQD_MEDIUM,
                    MYQD_HIGH}; /* favour new cmds over completions */

struct opts_t {
    vector<const char *> dev_names;
    vector<int> blk_szs;
    bool block;
    bool cmd_time;
    bool direct;
    bool excl;
    bool generic_sync;
    bool masync;
    bool mmap_io;
    bool no_waitq;
    bool no_xfer;
    bool pack_id_force;
    bool sg_vn_ge_40000;
    bool sg_vn_ge_40030;
    bool submit;
    bool verbose_given;
    bool v3;
    bool v3_given;
    bool v4;
    bool v4_given;
    bool version_given;
    int maxq_per_thread;
    int num_per_thread;
    uint64_t lba;
    unsigned int hi_lba;        /* last one, inclusive range */
    vector<unsigned int> hi_lbas; /* only used when hi_lba=-1 */
    int lb_sz;
    int num_lbs;
    int ovn;            /* override number for submission */
    int stats;
    int verbose;
    int wait_ms;
    command2execute c2e;
    blkLQDiscipline blqd;       /* --qat= 0|1 -> at_head|at_tail */
    myQDiscipline myqd;         /* --qfav= value (def: 2 --> MYQD_HIGH) */
};

static struct opts_t a_opts;    /* Expect zero fill on simple types */

static int pr_rusage(int id);

#if 0
class Rand_uint {
public:
    Rand_uint(unsigned int lo, unsigned int hi) : p{lo, hi} {}
    unsigned int operator()() const { return r(); }
private:
    uniform_int_distribution<unsigned int>::param_type p;
    auto r = bind(uniform_int_distribution<unsigned int>{p},
                  default_random_engine());
    /* compiler thinks auto should be a static, bs again? */
};
#endif

#if 0
class Rand_uint {
public:
    Rand_uint(unsigned int lo, unsigned int hi, unsigned int my_seed)
        : r(bind(uniform_int_distribution<unsigned int>{lo, hi},
                 default_random_engine())) { r.seed(myseed); }
    unsigned int operator()() const { return r(); }
private:
    function<unsigned int()> r;
};
#endif

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

static struct option long_options[] = {
        {"v3", no_argument, 0, '3'},
        {"v4", no_argument, 0, '4'},
        {"more-async", no_argument, 0, 'a'},
        {"more_async", no_argument, 0, 'a'},
        {"masync", no_argument, 0, 'a'},
        {"cmd-time", no_argument, 0, 'c'},
        {"cmd_time", no_argument, 0, 'c'},
        {"direct", no_argument, 0, 'd'},
        {"excl", no_argument, 0, 'e'},
        {"force", no_argument, 0, 'f'},
        {"generic-sync", no_argument, 0, 'g'},
        {"generic_sync", no_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"lba", required_argument, 0, 'l'},
        {"lbsz", required_argument, 0, 'L'},
        {"maxqpt", required_argument, 0, 'M'},
        {"mmap-io", no_argument, 0, 'm'},
        {"mmap_io", no_argument, 0, 'm'},
        {"numpt", required_argument, 0, 'n'},
        {"num-pt", required_argument, 0, 'n'},
        {"num_pt", required_argument, 0, 'n'},
        {"nowaitq", no_argument, 0, 'z'},
        {"no_waitq", no_argument, 0, 'z'},
        {"no-waitq", no_argument, 0, 'z'},
        {"noxfer", no_argument, 0, 'N'},
        {"override", required_argument, 0, 'O'},
        {"pack-id", no_argument, 0, 'p'},
        {"pack_id", no_argument, 0, 'p'},
        {"qat", required_argument, 0, 'q'},
        {"qfav", required_argument, 0, 'Q'},
        {"read", no_argument, 0, 'R'},
        {"stats", no_argument, 0, 'S'},
        {"submit", no_argument, 0, 'u'},
        {"szlb", required_argument, 0, 's'},
        {"tnum", required_argument, 0, 't'},
        {"tur", no_argument, 0, 'T'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wait", required_argument, 0, 'w'},
        {"write", no_argument, 0, 'W'},
        {0, 0, 0, 0},
};


static void
usage(void)
{
    printf("Usage: %s [--cmd-time] [--direct] [--excl] [--force]\n"
           "                    [--generic-sync] [--help] [--lba=LBA+] "
           "[--lbsz=LBSZ]\n"
           "                    [--masync] [--maxqpt=QPT] [--mmap-io] "
           "[--no-waitq]\n"
           "                    [--noxfer] [--numpt=NPT] [--override=OVN] "
           "[--pack-id]\n"
           "                    [--qat=AT] [-qfav=FAV] [--read] [--stats] "
           "[--submit]\n"
           "                    [--szlb=LB[,NLBS]] [--tnum=NT] [--tur] "
           "[--v3] [--v4]\n"
           "                    [--verbose] [--version] [--wait=MS] "
           "[--write]\n"
           "                    <sg_disk_device>*\n",
           util_name);
    printf("  where\n");
    printf("    --cmd-time|-c    calculate per command average time (ns)\n");
    printf("    --direct|-d     do direct_io (def: indirect)\n");
    printf("    --excl|-e       do wait_exclusive calls\n");
    printf("    --force|-f      force: any sg device (def: only scsi_debug "
           "owned)\n");
    printf("                    WARNING: <lba> written to if '-W' given\n");
    printf("    --generic-sync|-g    use generic synchronous SG_IO ioctl "
           "instead\n");
    printf("                       of Linux sg driver assuming /dev/sg* "
           "(def)\n");
    printf("    --help|-h       print this usage message then exit\n");
    printf("    --lba=LBA|-l LBA    logical block to access (def: %u)\n",
           DEF_LBA);
    printf("    --lba=LBA,HI_LBA|-l LBA,HI_LBA    logical block range "
           "(inclusive)\n"
           "                          if hi_lba=-1 assume last block on "
           "device\n");
    printf("    --lbsz=LBSZ|-L LBSZ    logical block size in bytes (def: "
           "512)\n"
           "                           should be power of 2 (0 --> 512)\n");
    printf("    --masync|-a     set 'more async' flag on devices\n");
    printf("    --maxqpt=QPT|-M QPT    maximum commands queued per thread "
           "(def:%d)\n", MAX_Q_PER_FD);
    printf("    --mmap-io|-m    mmap-ed IO (1 cmd outstanding per thread)\n");
    printf("    --no-waitq|-z    set SGV4_FLAG_NO_WAITQ, bypass poll() if "
           "requested\n");
    printf("    --noxfer|-N          no data xfer (def: xfer on READ and "
           "WRITE)\n");
    printf("    --numpt=NPT|-n NPT    number of commands per thread "
           "(def: %d)\n", DEF_NUM_PER_THREAD);
    printf("    --override OVN|-O OVN    override FAV=2 when OVN queue "
           "depth\n"
           "                             reached (def: 0 -> no override)\n");
    printf("    --pack-id|-p    set FORCE_PACK_ID, pack-id input to "
           "read/finish\n");
    printf("    --qat=AT|-q AT       AT=0: q_at_head; AT=1: q_at_tail (def: "
           "(drv): head)\n");
    printf("    --qfav=FAV|-Q FAV    FAV=0: favour completions (smaller q),\n"
           "                         FAV=1: medium,\n"
           "                         FAV=2: favour submissions (larger q, "
           "default)\n");
    printf("    --read|-R       do READs (def: TUR)\n");
    printf("    --stats|-S      show more statistics on completion\n");
    printf("    --submit|-u     use SG_IOSUBMIT+SG_IORECEIVE instead of "
           "write+read\n");
    printf("    --szlb=LB[,NLBS]|    LB is logical block size (def: 512)\n");
    printf("         -s LB[,NLBS]    NLBS is number of logical blocks (def: "
           "1)\n");
    printf("    --tnum=NT|-t NT    number of threads (def: %d)\n",
           DEF_NUM_THREADS);
    printf("    --tur|-T        do TEST UNIT READYs (default is TURs)\n");
    printf("    --v3|-3         use sg v3 interface (def: v3 if driver < "
           "3.9)\n");
    printf("    --v4|-4         use sg v4 interface (def if v4 driver). Sets "
           "--submit\n");
    printf("    --verbose|-v    increase verbosity\n");
    printf("    --version|-V    print version number then exit\n");
    printf("    --wait=MS|-w MS    >0: poll(<wait_ms>); =0: poll(0); (def: "
           "%d)\n", DEF_WAIT_MS);
    printf("    --write|-W      do WRITEs (def: TUR)\n\n");
    printf("Multiple threads send READ(16), WRITE(16) or TEST UNIT READY "
           "(TUR) SCSI\ncommands. There can be 1 or more <sg_disk_device>s "
           "and each thread takes\nthe next in a round robin fashion. "
           "Each thread queues up to NT commands.\nOne block is transferred "
           "by each READ and WRITE; zeros are written. If a\nlogical block "
           "range is given, a uniform distribution generates a pseudo\n"
           "random sequence of LBAs. Set environment variable\n"
           "SG3_UTILS_LINUX_NANO to get command timings in nanoseconds\n");
}

#ifdef __GNUC__
static int pr2serr_lk(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
static void pr_errno_lk(int e_no, const char * fmt, ...)
        __attribute__ ((format (printf, 2, 3)));
#else
static int pr2serr_lk(const char * fmt, ...);
static void pr_errno_lk(int e_no, const char * fmt, ...);
#endif


static int
pr2serr_lk(const char * fmt, ...)
{
    int n;
    va_list args;
    lock_guard<mutex> lg(console_mutex);

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

static void
pr_errno_lk(int e_no, const char * fmt, ...)
{
    char b[160];
    va_list args;
    lock_guard<mutex> lg(console_mutex);

    va_start(args, fmt);
    vsnprintf(b, sizeof(b), fmt, args);
    fprintf(stderr, "%s: %s\n", b, strerror(e_no));
    va_end(args);
}

static unsigned int
get_urandom_uint(void)
{
    unsigned int res = 0;
    int n;
    uint8_t b[sizeof(unsigned int)];
    lock_guard<mutex> lg(rand_lba_mutex);

    int fd = open(URANDOM_DEV, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, b, sizeof(unsigned int));
        if (sizeof(unsigned int) == n)
            memcpy(&res, b, sizeof(unsigned int));
        close(fd);
    }
    return res;
}

#define TUR_CMD_LEN 6
#define READ16_CMD_LEN 16
#define READ16_REPLY_LEN 4096
#define WRITE16_REPLY_LEN 4096
#define WRITE16_CMD_LEN 16

/* Returns 0 if command injected okay, return -1 for error and 2 for
 * not done due to queue data size limit struck. */
static int
start_sg3_cmd(int sg_fd, command2execute cmd2exe, int pack_id, uint64_t lba,
              uint8_t * lbp, int xfer_bytes, int flags, bool submit,
              unsigned int & enomem, unsigned int & eagains,
              unsigned int & ebusy, unsigned int & e2big, unsigned int & edom)
{
    struct sg_io_hdr pt;
    struct sg_io_v4 p4t;
    uint8_t turCmdBlk[TUR_CMD_LEN] = {0, 0, 0, 0, 0, 0};
    uint8_t r16CmdBlk[READ16_CMD_LEN] =
                {0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    uint8_t w16CmdBlk[WRITE16_CMD_LEN] =
                {0x8a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    uint8_t sense_buffer[64];
    const char * np = NULL;
    struct sg_io_hdr * ptp;

    if (submit) {       /* nest a v3 interface inside a store for v4 */
        memset(&p4t, 0, sizeof(p4t));
        ptp = (struct sg_io_hdr *)&p4t; /* p4t is larger than pt */
    } else {
        ptp = &pt;
        memset(ptp, 0, sizeof(*ptp));
    }
    switch (cmd2exe) {
    case SCSI_TUR:
        np = "TEST UNIT READY";
        ptp->cmdp = turCmdBlk;
        ptp->cmd_len = sizeof(turCmdBlk);
        ptp->dxfer_direction = SG_DXFER_NONE;
        break;
    case SCSI_READ16:
        np = "READ(16)";
        if (lba > 0xffffffff)
            sg_put_unaligned_be32(lba >> 32, &r16CmdBlk[2]);
        sg_put_unaligned_be32(lba & 0xffffffff, &r16CmdBlk[6]);
        ptp->cmdp = r16CmdBlk;
        ptp->cmd_len = sizeof(r16CmdBlk);
        ptp->dxfer_direction = SG_DXFER_FROM_DEV;
        ptp->dxferp = lbp;
        ptp->dxfer_len = xfer_bytes;
        break;
    case SCSI_WRITE16:
        np = "WRITE(16)";
        if (lba > 0xffffffff)
            sg_put_unaligned_be32(lba >> 32, &w16CmdBlk[2]);
        sg_put_unaligned_be32(lba & 0xffffffff, &w16CmdBlk[6]);
        ptp->cmdp = w16CmdBlk;
        ptp->cmd_len = sizeof(w16CmdBlk);
        ptp->dxfer_direction = SG_DXFER_TO_DEV;
        ptp->dxferp = lbp;
        ptp->dxfer_len = xfer_bytes;
        break;
    }
    ptp->interface_id = 'S';
    ptp->mx_sb_len = sizeof(sense_buffer);
    ptp->sbp = sense_buffer;      /* ignored .... */
    ptp->timeout = DEF_TIMEOUT_MS;
    ptp->pack_id = pack_id;
    ptp->flags = flags;

    for (int k = 0;
         (submit ? ioctl(sg_fd, SG_IOSUBMIT_V3, ptp) :
                   write(sg_fd, ptp, sizeof(*ptp)) < 0);
         ++k) {
        if ((ENOMEM == errno) && (k < MAX_CONSEC_NOMEMS)) {
            ++enomem;
            this_thread::yield();
            continue;
        } else if (EAGAIN == errno) {
            ++eagains;
            this_thread::yield();
            continue;
        } else if (EBUSY == errno) {
            ++ebusy;
            this_thread::yield();
            continue;
        } else if (E2BIG == errno) {
            ++e2big;
            return 2;
        } else if (EDOM == errno)
            ++edom;
        else if (ENOMEM == errno)
            pr_rusage(-1);
        pr_errno_lk(errno, "%s: %s, pack_id=%d", __func__, np, pack_id);
        return -1;
    }
    return 0;
}

static int
finish_sg3_cmd(int sg_fd, command2execute cmd2exe, int & pack_id,
               bool receive, int wait_ms, unsigned int & enomem,
               unsigned int & eagains, unsigned int & ebusys,
               unsigned int & nanosecs)
{
    bool ok;
    int res, k;
    uint8_t sense_buffer[64];
    const char * np = NULL;
    struct sg_io_hdr pt;
    struct sg_io_hdr * ptp;
    struct sg_io_v4 p4t;

    if (receive) {      /* nest a v3 interface inside a store for v4 */
        memset(&p4t, 0, sizeof(p4t));
        ptp = (struct sg_io_hdr *)&p4t; /* p4t is larger than pt */
    } else {
        ptp = &pt;
        memset(ptp, 0, sizeof(*ptp));
    }
    switch (cmd2exe) {
    case SCSI_TUR:
        np = "TEST UNIT READY";
        ptp->dxfer_direction = SG_DXFER_NONE;
        break;
    case SCSI_READ16:
        np = "READ(16)";
        ptp->dxfer_direction = SG_DXFER_FROM_DEV;
        break;
    case SCSI_WRITE16:
        np = "WRITE(16)";
        ptp->dxfer_direction = SG_DXFER_TO_DEV;
        break;
    }
    ptp->interface_id = 'S';
    ptp->mx_sb_len = sizeof(sense_buffer);
    ptp->sbp = sense_buffer;
    ptp->timeout = DEF_TIMEOUT_MS;
    /* if SG_SET_FORCE_PACK_ID, then need to set ptp->dxfer_direction */
    ptp->pack_id = pack_id;

    k = 0;
    while ((((res = receive ? ioctl(sg_fd, SG_IORECEIVE_V3, ptp) :
                              read(sg_fd, ptp, sizeof(*ptp)))) < 0) &&
           ((EAGAIN == errno) || (EBUSY == errno) || (ENOMEM == errno))) {
        if (ENOMEM == errno)
            ++enomem;
        else if (EAGAIN == errno)
            ++eagains;
        else
            ++ebusys;
        ++k;
        if (k > 10000) {
            pr2serr_lk("%s: sg_fd=%d: after %d EAGAINs, unable to find "
                       "pack_id=%d\n", __func__, sg_fd, k, pack_id);
            return -1;      /* crash out */
        }
        if (wait_ms > 0)
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();
        else if (-2 == wait_ms)
            sleep(0);                   // process yield ??
    }
    if (res < 0) {
        if (ENOMEM == errno)
            pr_rusage(-1);
        pr_errno_lk(errno, "%s: %s", __func__, np);
        return -1;
    }
    /* now for the error processing */
    pack_id = ptp->pack_id;
    ok = false;
    switch (sg_err_category3(ptp)) {
    case SG_LIB_CAT_CLEAN:
        ok = true;
        break;
    case SG_LIB_CAT_RECOVERED:
        pr2serr_lk("%s: Recovered error on %s, continuing\n", __func__, np);
        ok = true;
        break;
    default: /* won't bother decoding other categories */
        {
            lock_guard<mutex> lg(console_mutex);
            sg_chk_n_print3(np, ptp, 1);
        }
        break;
    }
    if (ok)
        nanosecs = ptp->duration;
    return ok ? 0 : -1;
}

/* Returns 0 if command injected okay, return -1 for error and 2 for
 * not done due to queue data size limit struck. */
static int
start_sg4_cmd(int sg_fd, command2execute cmd2exe, int pack_id, uint64_t lba,
              uint8_t * lbp, int xfer_bytes, int flags, bool submit,
              unsigned int & enomem, unsigned int & eagains,
              unsigned int & ebusy, unsigned int & e2big, unsigned int & edom)
{
    struct sg_io_v4 p4t;
    uint8_t turCmdBlk[TUR_CMD_LEN] = {0, 0, 0, 0, 0, 0};
    uint8_t r16CmdBlk[READ16_CMD_LEN] =
                {0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    uint8_t w16CmdBlk[WRITE16_CMD_LEN] =
                {0x8a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    uint8_t sense_buffer[64];
    const char * np = NULL;
    struct sg_io_v4 * ptp;

    if (! submit) {
        pr2serr_lk("%s: logic error, submit must be true, isn't\n", __func__);
        return -1;
    }
    ptp = &p4t;
    memset(ptp, 0, sizeof(*ptp));
    switch (cmd2exe) {
    case SCSI_TUR:
        np = "TEST UNIT READY";
        ptp->request = (uint64_t)turCmdBlk;
        ptp->request_len = sizeof(turCmdBlk);
        break;
    case SCSI_READ16:
        np = "READ(16)";
        if (lba > 0xffffffff)
            sg_put_unaligned_be32(lba >> 32, &r16CmdBlk[2]);
        sg_put_unaligned_be32(lba & 0xffffffff, &r16CmdBlk[6]);
        ptp->request = (uint64_t)r16CmdBlk;
        ptp->request_len = sizeof(r16CmdBlk);
        ptp->din_xferp = (uint64_t)lbp;
        ptp->din_xfer_len = xfer_bytes;
        break;
    case SCSI_WRITE16:
        np = "WRITE(16)";
        if (lba > 0xffffffff)
            sg_put_unaligned_be32(lba >> 32, &w16CmdBlk[2]);
        sg_put_unaligned_be32(lba & 0xffffffff, &w16CmdBlk[6]);
        ptp->request = (uint64_t)w16CmdBlk;
        ptp->request_len = sizeof(w16CmdBlk);
        ptp->dout_xferp = (uint64_t)lbp;
        ptp->dout_xfer_len = xfer_bytes;
        break;
    }
    ptp->guard = 'Q';
    ptp->max_response_len = sizeof(sense_buffer);
    ptp->response = (uint64_t)sense_buffer;      /* ignored .... */
    ptp->timeout = DEF_TIMEOUT_MS;
    ptp->request_extra = pack_id;
    ptp->flags = flags;

    for (int k = 0; ioctl(sg_fd, SG_IOSUBMIT, ptp) < 0; ++k) {
        if ((ENOMEM == errno) && (k < MAX_CONSEC_NOMEMS)) {
            ++enomem;
            this_thread::yield();
            continue;
        } else if (EAGAIN == errno) {
            ++eagains;
            this_thread::yield();
            continue;
        } else if (EBUSY == errno) {
            ++ebusy;
            this_thread::yield();
            continue;
        } else if (E2BIG == errno) {
            ++e2big;
            return 2;
        } else if (EDOM == errno)
            ++edom;
        else if (ENOMEM == errno)
            pr_rusage(-1);
        pr_errno_lk(errno, "%s: %s, pack_id=%d", __func__, np, pack_id);
        return -1;
    }
    return 0;
}

static int
finish_sg4_cmd(int sg_fd, command2execute cmd2exe, int & pack_id,
               bool receive, int wait_ms, unsigned int & enomem,
               unsigned int & eagains, unsigned int & ebusys,
               unsigned int & nanosecs)
{
    bool ok;
    int res, k;
    uint8_t sense_buffer[64];
    const char * np = NULL;
    struct sg_io_v4 * ptp;
    struct sg_io_v4 p4t;

    if (! receive) {
        pr2serr_lk("%s: logic error, receive must be true, isn't\n",
                   __func__);
        return -1;
    }
    ptp = &p4t;
    memset(ptp, 0, sizeof(*ptp));
    switch (cmd2exe) {
    case SCSI_TUR:
        np = "TEST UNIT READY";
        break;
    case SCSI_READ16:
        np = "READ(16)";
        break;
    case SCSI_WRITE16:
        np = "WRITE(16)";
        break;
    }
    ptp->guard = 'Q';
    ptp->max_response_len = sizeof(sense_buffer);
    ptp->response = (uint64_t)sense_buffer;
    ptp->timeout = DEF_TIMEOUT_MS;
    /* if SG_SET_FORCE_PACK_ID, then need to set ptp->dxfer_direction */
    ptp->request_extra = pack_id;

    k = 0;
    while ((((res = ioctl(sg_fd, SG_IORECEIVE, ptp))) < 0) &&
           ((EAGAIN == errno) || (EBUSY == errno))) {
        if (EAGAIN == errno)
            ++eagains;
        else
            ++ebusys;
        ++k;
        if (k > 10000) {
            pr2serr_lk("%s: sg_fd=%d: after %d EAGAINs, unable to find "
                       "pack_id=%d\n", __func__, sg_fd, k, pack_id);
            return -1;      /* crash out */
        }
        if (wait_ms > 0)
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();
        else if (-2 == wait_ms)
            sleep(0);                   // process yield ??
    }
    if (res < 0) {
        if (ENOMEM == errno) {
            ++enomem;
            pr_rusage(-1);
        }
        pr_errno_lk(errno, "%s: %s", __func__, np);
        return -1;
    }
    /* now for the error processing */
    pack_id = ptp->request_extra;
    ok = false;
    res = sg_err_category_new(ptp->device_status, ptp->transport_status,
                              ptp->driver_status,
                              (const uint8_t *)ptp->response,
                              ptp->response_len);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
        ok = true;
        break;
    case SG_LIB_CAT_RECOVERED:
        pr2serr_lk("%s: Recovered error on %s, continuing\n", __func__, np);
        ok = true;
        break;
    default: /* won't bother decoding other categories */
        {
            lock_guard<mutex> lg(console_mutex);

            sg_linux_sense_print(np, ptp->device_status,
                                 ptp->transport_status,
                                 ptp->driver_status,
                                 (const uint8_t *)ptp->response,
                                 ptp->response_len, true);
        }
        break;
    }
    if (ok)
        nanosecs = ptp->duration;
    return ok ? 0 : -1;
}

static int
num_submitted(int sg_fd)
{
    uint32_t num_subm_wait = 0;
    struct sg_extended_info sei;
    struct sg_extended_info *seip = &sei;
    const char * err = NULL;

    memset(seip, 0, sizeof(*seip));
    seip->sei_wr_mask |= SG_SEIM_READ_VAL;
    seip->sei_rd_mask |= SG_SEIM_READ_VAL;
    seip->read_value = SG_SEIRV_SUBMITTED;
    if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0)
        err = "ioctl(SG_SET_GET_EXTENDED) failed\n";
    else
        num_subm_wait = seip->read_value;
    if (err)
        pr2serr_lk("%s: %s, errno=%d\n", __func__, err, errno);
    return err ? -1 : (int)num_subm_wait;
}

static int
pr_rusage(int id)
{
    int res;
    struct rusage ru;

    res = getrusage(RUSAGE_SELF /* RUSAGE_THREAD */, &ru);
    if (res < 0) {
        pr2serr_lk("%d->id: %s: getrusage() failed, errno=%d\n", id,
                   __func__, errno);
        return res;
    }
    pr2serr_lk("%d->id: maxrss=%ldKB  nvcsw=%ld nivcsw=%ld  majflt=%ld\n", id,
               ru.ru_maxrss, ru.ru_nvcsw, ru.ru_nivcsw, ru.ru_majflt);
    return 0;
}

static void
work_sync_thread(int id, const char * dev_name, unsigned int /* hi_lba */,
                 struct opts_t * op)
{
    bool is_rw = (SCSI_TUR != op->c2e);
    int k, sg_fd, err, rs, n, sense_cat, ret;
    int vb = op->verbose;
    int num_errs = 0;
    int thr_sync_starts = 0;
    struct sg_pt_base * ptp = NULL;
    uint8_t cdb[6];
    uint8_t sense_b[32];
    char b[120];

    if (is_rw) {
        pr2serr_lk("id=%d: only support TUR here for now\n", id);
        goto err_out;
    }
    if (op->no_waitq)
        pr2serr_lk("id=%d: ignoring --no-waitq option\n", id);
    if (op->verbose)
        pr2serr_lk("id=%d: using libsgutils generic sync passthrough\n", id);

    if ((sg_fd = sg_cmds_open_device(dev_name, false /* ro */, vb)) < 0) {
        pr2serr_lk("id=%d: error opening file: %s: %s\n", id, dev_name,
                   safe_strerror(-sg_fd));
        if (ENOMEM == -sg_fd)
            pr_rusage(id);
        goto err_out;
    }
    if (vb > 2)
        pr2serr_lk(">>>> id=%d: open(%s) --> fd=%d\n", id, dev_name, sg_fd);

    ptp = construct_scsi_pt_obj_with_fd(sg_fd, vb);
    err = 0;
    if ((NULL == ptp) || ((err = get_scsi_pt_os_err(ptp)))) {
        ret = sg_convert_errno(err ? err : ENOMEM);
        sg_exit2str(ret, true, sizeof(b), b);
        pr2serr_lk("id=%d: construct_scsi_pt_obj_with_fd: %s\n", id, b);
        goto err_out;
    }
    for (k = 0; k < op->num_per_thread; ++k) {
        /* Might get Unit Attention on first invocation */
        memset(cdb, 0, sizeof(cdb));    /* TUR's cdb is 6 zeros */
        set_scsi_pt_cdb(ptp, cdb, sizeof(cdb));
        set_scsi_pt_sense(ptp, sense_b, sizeof(sense_b));
        set_scsi_pt_packet_id(ptp, uniq_pack_id.fetch_add(1));
        ++thr_sync_starts;
        rs = do_scsi_pt(ptp, -1, DEF_PT_TIMEOUT, vb);
        n = sg_cmds_process_resp(ptp, "Test unit ready", rs,
                                 (0 == k), vb, &sense_cat);
        if (-1 == n) {
            ret = sg_convert_errno(get_scsi_pt_os_err(ptp));
            sg_exit2str(ret, true, sizeof(b), b);
            pr2serr_lk("id=%d: do_scsi_pt: %s\n", id, b);
            goto err_out;
        } else if (-2 == n) {
            switch (sense_cat) {
            case SG_LIB_CAT_RECOVERED:
            case SG_LIB_CAT_NO_SENSE:
                break;
            case SG_LIB_CAT_NOT_READY:
                ++num_errs;
                if (1 ==  op->num_per_thread) {
                    pr2serr_lk("id=%d: device not ready\n", id);
                }
                break;
            case SG_LIB_CAT_UNIT_ATTENTION:
                ++num_errs;
                if (vb)
                    pr2serr_lk("Ignoring Unit attention (sense key)\n");
                break;
            default:
                ++num_errs;
                if (1 == op->num_per_thread) {
                    sg_get_category_sense_str(sense_cat, sizeof(b), b, vb);
                    pr2serr_lk("%s\n", b);
                    goto err_out;
                }
                break;
            }
        }
        clear_scsi_pt_obj(ptp);
    }
err_out:
    if (ptp)
        destruct_scsi_pt_obj(ptp);
    if (num_errs > 0)
        pr2serr_lk("id=%d: number of errors: %d\n", id, num_errs);
    sync_starts += thr_sync_starts;
}

static void
work_thread(int id, struct opts_t * op)
{
    bool is_rw = (SCSI_TUR != op->c2e);
    bool need_finish, repeat;
    bool once = false;
    bool once1000 = false;
    bool once_2000 = false;
    bool once_4000 = false;
    bool once5000 = false;
    bool once_6000 = false;
    bool once_7000 = false;
    bool once10_000 = false;
    bool once20_000 = false;
    int open_flags = O_RDWR;
    int thr_async_starts = 0;
    int thr_async_finishes = 0;
    int thr_ovn_force_read = 0;
    int vb = op->verbose;
    int k, n, res, sg_fd, num_outstanding, do_inc, npt, pack_id, sg_flags;
    int num_waiting_read, num_to_read, sz, ern, encore_pack_id, ask, j, m, o;
    int prev_pack_id, blk_sz;
    unsigned int thr_enomem_count = 0;
    unsigned int thr_start_eagain_count = 0;
    unsigned int thr_start_ebusy_count = 0;
    unsigned int thr_start_e2big_count = 0;
    unsigned int thr_fin_eagain_count = 0;
    unsigned int thr_fin_ebusy_count = 0;
    unsigned int thr_start_edom_count = 0;
    unsigned int seed = 0;
    int needed_sz = op->lb_sz * op->num_lbs;
    unsigned int nanosecs;
    unsigned int hi_lba;
    uint64_t lba;
    uint64_t sum_nanosecs = 0;
    uint8_t * lbp;
    uint8_t * free_lbp = NULL;
    uint8_t * wrkMmap = NULL;
    const char * dev_name;
    const char * err = NULL;
    Rand_uint * ruip = NULL;
    char ebuff[EBUFF_SZ];
    struct pollfd  pfd[1];
    list<pair<uint8_t *, uint8_t *> > free_lst;   /* of aligned lb buffers */
    map<int, pair<uint8_t *, uint8_t *> > pi2buff;/* pack_id -> lb buffer */
    map<int, uint64_t> pi_2_lba;            /* pack_id -> LBA */
    pair<uint8_t *, uint8_t *> encore_lbps;

    /* device name and hi_lba may depend on id */
    n = op->dev_names.size();
    dev_name = op->dev_names[id % n];
    if (op->blk_szs.size() >= (unsigned)n)
        blk_sz = op->blk_szs[id % n];
    else
        blk_sz = DEF_LB_SZ;
    if ((UINT_MAX == op->hi_lba) && (n == (int)op->hi_lbas.size()))
        hi_lba = op->hi_lbas[id % n];
    else
        hi_lba = op->hi_lba;

    if (vb) {
        if ((vb > 1) && hi_lba)
            pr2serr_lk("Enter work_t_id=%d using %s\n"
                       "    LBA range: 0x%x to 0x%x (inclusive)\n",
                       id, dev_name, (unsigned int)op->lba, hi_lba);
        else
            pr2serr_lk("Enter work_t_id=%d using %s\n", id, dev_name);
    }
    if (op->generic_sync) {
        work_sync_thread(id, dev_name, hi_lba, op);
        return;
    }
    if (! op->block)
        open_flags |= O_NONBLOCK;

    sg_fd = open(dev_name, open_flags);
    if (sg_fd < 0) {
        pr_errno_lk(errno, "%s: id=%d, error opening file: %s", __func__, id,
                    dev_name);
        if (ENOMEM == -sg_fd)
            pr_rusage(id);
        return;
    }
    if (vb > 2)
        pr2serr_lk(">>>> id=%d: open(%s) --> fd=%d\n", id, dev_name, sg_fd);
    if (op->pack_id_force) {
        k = 1;
        if (ioctl(sg_fd, SG_SET_FORCE_PACK_ID, &k) < 0)
            pr2serr_lk("ioctl(SG_SET_FORCE_PACK_ID) failed, errno=%d %s\n",
                       errno, strerror(errno));
    }
    if (op->sg_vn_ge_40000) {
        if (ioctl(sg_fd, SG_GET_RESERVED_SIZE, &k) >= 0) {
            if (needed_sz > k)
                ioctl(sg_fd, SG_SET_RESERVED_SIZE, &needed_sz);
        }
        if (op->sg_vn_ge_40030 && (op->cmd_time || op->masync)) {
            struct sg_extended_info sei;
            struct sg_extended_info * seip;

            seip = &sei;
            memset(seip, 0, sizeof(*seip));
            seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
            seip->sei_rd_mask |= SG_SEIM_CTL_FLAGS;
            if (op->cmd_time) {
                seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_TIME_IN_NS;
                seip->ctl_flags_rd_mask |= SG_CTL_FLAGM_TIME_IN_NS;
                seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;
            }
            if (op->masync) {
                seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_MORE_ASYNC;
                seip->ctl_flags |= SG_CTL_FLAGM_MORE_ASYNC;
            }
            if (op->excl) {
                seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_EXCL_WAITQ;
                seip->ctl_flags |= SG_CTL_FLAGM_EXCL_WAITQ;
            }
            if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0) {
                pr2serr_lk("ioctl(EXTENDED(TIME_IN_NS)) failed, errno=%d %s\n",
                           errno, strerror(errno));
            }
            if (op->cmd_time &&
                (! (SG_CTL_FLAGM_TIME_IN_NS & seip->ctl_flags))) {
                memset(seip, 0, sizeof(*seip));
                seip->sei_rd_mask |= SG_SEIM_CTL_FLAGS;
                seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
                seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_TIME_IN_NS;
                seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;
                if (ioctl(sg_fd, SG_SET_GET_EXTENDED, seip) < 0)
                    pr2serr_lk("ioctl(EXTENDED(TIME_IN_NS)) failed, "
                               "errno=%d %s\n", errno, strerror(errno));
                else if (vb > 1)
                    pr2serr_lk("t_id: %d: set TIME_IN_NS flag\n", id);
            }
        }
    }
    if (is_rw && op->mmap_io) {

        if (ioctl(sg_fd, SG_GET_RESERVED_SIZE, &sz) < 0) {
            pr2serr_lk("t_id=%d: ioctl(SG_GET_RESERVED_SIZE) errno=%d\n",
                       id, errno);
            return;
        }
        if (sz < needed_sz) {
            sz = needed_sz;
            if (ioctl(sg_fd, SG_SET_RESERVED_SIZE, &sz) < 0) {
                pr2serr_lk("t_id=%d: ioctl(SG_SET_RESERVED_SIZE) errno=%d\n",
                           id, errno);
                return;
            }
            if (ioctl(sg_fd, SG_GET_RESERVED_SIZE, &sz) < 0) {
                pr2serr_lk("t_id=%d: ioctl(SG_GET_RESERVED_SIZE) errno=%d\n",
                           id, errno);
                return;
            }
            if (sz < needed_sz) {
                pr2serr_lk("t_id=%d: unable to grow reserve buffer to %d "
                           "bytes\n", id, needed_sz);
                return;
            }
        }
        wrkMmap = (uint8_t *)mmap(NULL, needed_sz, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, sg_fd, 0);
        if (MAP_FAILED == wrkMmap) {
            ern = errno;
            pr2serr_lk("t_id=%d: mmap() failed, errno=%d\n", id, ern);
            return;
        }
    }
    pfd[0].fd = sg_fd;
    pfd[0].events = POLLIN;
    if (is_rw && hi_lba) {
        seed = get_urandom_uint();
        if (vb > 1)
            pr2serr_lk("  id=%d, /dev/urandom seed=0x%x\n", id, seed);
        ruip = new Rand_uint((unsigned int)op->lba, hi_lba, seed);
    }

    sg_flags = 0;
    if (BLQ_AT_TAIL == op->blqd)
        sg_flags |= SG_FLAG_Q_AT_TAIL;
    else if (BLQ_AT_HEAD == op->blqd)
        sg_flags |= SG_FLAG_Q_AT_HEAD;
    if (op->direct)
        sg_flags |= SG_FLAG_DIRECT_IO;
    if (op->mmap_io)
        sg_flags |= SG_FLAG_MMAP_IO;
    if (op->no_xfer)
        sg_flags |= SG_FLAG_NO_DXFER;
    if (op->no_waitq)
        sg_flags |= SGV4_FLAG_NO_WAITQ;
    if (vb > 1)
        pr2serr_lk("  id=%d, sg_flags=0x%x, %s cmds\n", id, sg_flags,
                   ((SCSI_TUR == op->c2e) ? "TUR":
                    ((SCSI_READ16 == op->c2e) ? "READ" : "WRITE")));

    npt = op->num_per_thread;
    need_finish = false;
    lba = 0;
    pack_id = 0;
    prev_pack_id = 0;
    encore_pack_id = 0;
    do_inc = 0;
    /* main loop, continues until num_per_thread exhausted and there are
     * no more outstanding responses */
    for (k = 0, m = 0, o=0, num_outstanding = 0; (k < npt) || num_outstanding;
         k = do_inc ? k + 1 : k, ++o) {
        if (do_inc)
            m = 0;
        else {
            ++m;
            if (m > 100) {
                if (vb)
                    pr2serr_lk("%d->id: no main loop inc =%d times\n", id, m);
                m = 0;
            }
        }
        if (vb && (! once1000) && (num_outstanding >= 1000)) {
            int num_waiting;
            int num_subm = (op->sg_vn_ge_40030) ? num_submitted(sg_fd) :
                                                  pi2buff.size();

            once1000 = true;
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0) {
                err = "ioctl(SG_GET_NUM_WAITING) failed";
                break;
            }
            pr2serr_lk("%d->id: once 1000: k=%d, submitted=%d waiting=%d; "
                       "pi2buff.sz=%u\n", id, k, num_subm, num_waiting,
                       (uint32_t)pi2buff.size());
            pr_rusage(id);
        }
        if (vb && ! once5000 && num_outstanding >= 5000) {
            int num_waiting;
            int num_subm = (op->sg_vn_ge_40030) ? num_submitted(sg_fd) :
                                                  pi2buff.size();

            once5000 = true;
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0) {
                err = "ioctl(SG_GET_NUM_WAITING) failed";
                break;
            }
            pr2serr_lk("%d->id: once 5000: k=%d, submitted=%d waiting=%d\n",
                       id, k, num_subm, num_waiting);
            pr_rusage(id);
        }
        if (vb && ! once_7000 && num_outstanding >= 7000) {
            int num_waiting;
            int num_subm = (op->sg_vn_ge_40030) ? num_submitted(sg_fd) :
                                                  pi2buff.size();

            once_7000 = true;
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0) {
                err = "ioctl(SG_GET_NUM_WAITING) failed";
                break;
            }
            pr2serr_lk("%d->id: once 7000: k=%d, submitted=%d waiting=%d\n",
                       id, k, num_subm, num_waiting);
            pr_rusage(id);
        }
        if (vb && ! once10_000 && num_outstanding >= 10000) {
            int num_waiting;
            int num_subm = (op->sg_vn_ge_40030) ? num_submitted(sg_fd) :
                                                  pi2buff.size();

            once10_000 = true;
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0) {
                err = "ioctl(SG_GET_NUM_WAITING) failed";
                break;
            }
            pr2serr_lk("%d->id: once 10^4: k=%d, submitted=%d waiting=%d\n",
                       id, k, num_subm, num_waiting);
            pr_rusage(id);
        }
        if (vb && ! once20_000 && num_outstanding >= 20000) {
            int num_waiting;
            int num_subm = (op->sg_vn_ge_40030) ? num_submitted(sg_fd) :
                                                  pi2buff.size();

            once20_000 = true;
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting) < 0) {
                err = "ioctl(SG_GET_NUM_WAITING) failed";
                break;
            }
            pr2serr_lk("%d->id: once 20000: k=%d, submitted=%d waiting=%d\n",
                       id, k, num_subm, num_waiting);
            pr_rusage(id);
        }
        do_inc = 0;
        if ((num_outstanding < op->maxq_per_thread) && (k < npt)) {
            do_inc = 1;
            if (need_finish) {
                pack_id = encore_pack_id;
                need_finish = false;
                repeat = true;
            } else {
                prev_pack_id = pack_id;
                pack_id = uniq_pack_id.fetch_add(1);
                repeat = false;
            }
            if (is_rw) {    /* get new lb buffer or one from free list */
                if (free_lst.empty()) {
                    lbp = sg_memalign(op->lb_sz * op->num_lbs, 0, &free_lbp,
                                      false);
                    if (NULL == lbp) {
                        err = "out of memory";
                        break;
                    }
                } else if (! repeat) {
                    lbp = free_lst.back().first;
                    free_lbp = free_lst.back().second;
                    free_lst.pop_back();
                } else {
                    lbp = encore_lbps.first;
                    free_lbp = encore_lbps.second;
                    if (vb && !once && free_lst.size() > 1000) {
                        once = true;
                        pr2serr_lk("%d->id: free_lst.size() over 1000\n", id);
                    }
                    if (vb && !once_2000 && free_lst.size() > 2000) {
                        once_2000 = true;
                        pr2serr_lk("%d->id: free_lst.size() over 2000\n", id);
                    }
                    if (vb && !once_6000 && free_lst.size() > 6000) {
                        once_2000 = true;
                        pr2serr_lk("%d->id: free_lst.size() over 6000\n", id);
                    }
                }
            } else
                lbp = NULL;
            if (is_rw) {
                if (ruip) {
                    if (! repeat) {
                        lba = ruip->get();  /* fetch a random LBA */
                        if (vb > 3)
                            pr2serr_lk("  id=%d: start IO at lba=0x%" PRIx64
                                       "\n", id, lba);
                    }
                } else
                    lba = op->lba;
            } else
                lba = 0;
            if (vb > 4)
                pr2serr_lk("t_id=%d: starting pack_id=%d\n", id, pack_id);
            res = (op->v4) ?
                start_sg4_cmd(sg_fd, op->c2e, pack_id, lba, lbp,
                              blk_sz * op->num_lbs, sg_flags, op->submit,
                              thr_enomem_count, thr_start_eagain_count,
                              thr_start_ebusy_count, thr_start_e2big_count,
                              thr_start_edom_count)  :
                start_sg3_cmd(sg_fd, op->c2e, pack_id, lba, lbp,
                              blk_sz * op->num_lbs, sg_flags, op->submit,
                              thr_enomem_count, thr_start_eagain_count,
                              thr_start_ebusy_count, thr_start_e2big_count,
                              thr_start_edom_count);
            if (res) {
                if (res > 1) { /* here if E2BIG, start not done, try finish */
                    do_inc = 0;
                    need_finish = true;
                    encore_pack_id = pack_id;
                    pack_id = prev_pack_id;
                    encore_lbps = make_pair(lbp, free_lbp);
                    if (vb > 2)
                        pr2serr_lk("t_id=%d: E2BIG hit, prev_pack_id=%d, "
                                   "encore_pack_id=%d\n", id, prev_pack_id,
                                   encore_pack_id);
                } else {
                    err = "start_sg3_cmd()";
                    break;
                }
            } else {    /* no error */
                ++thr_async_starts;
                ++num_outstanding;
                pi2buff[pack_id] = make_pair(lbp, free_lbp);
                if (ruip)
                    pi_2_lba[pack_id] = lba;
            }
            if (vb && !once && (pi2buff.size() > 1000)) {
                once = true;
                pr2serr_lk("%d->id: pi2buff.size() over 1000 (b)\n", id);
            }
            if (vb && !once_2000 && free_lst.size() > 2000) {
                once_2000 = true;
                pr2serr_lk("%d->id: free_lst.size() over 2000 (b)\n", id);
            }
            if (vb && !once_6000 && free_lst.size() > 6000) {
                once_2000 = true;
                pr2serr_lk("%d->id: free_lst.size() over 6000 (b)\n", id);
            }
        }
        num_to_read = 0;
        if (need_finish) {
            num_waiting_read = 0;
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting_read) < 0) {
                err = "ioctl(SG_GET_NUM_WAITING) failed";
                break;
            } else if (vb > 3)
                pr2serr_lk("t_id=%d: num_waiting_read=%d\n", id,
                           num_waiting_read);
            if (num_waiting_read > 0)
                num_to_read = num_waiting_read;
            else {
                struct timespec tspec = {0, 100000 /* 100 usecs */};

                nanosleep(&tspec, NULL);
                if (vb > 3)
                    pr2serr_lk("t_id=%d: E2BIG, 100 usecs sleep\n", id);
                // err = "strange, E2BIG but nothing to read";
                // break;
            }
        } else if ((num_outstanding >= op->maxq_per_thread) || (k >= npt)) {
            /* full queue or finished injecting */
            num_waiting_read = 0;
            if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting_read) < 0) {
                err = "ioctl(SG_GET_NUM_WAITING) failed";
                break;
            }
            if (1 == num_waiting_read)
                num_to_read = num_waiting_read;
            else if (num_waiting_read > 0) {
                if (k >= npt)
                    num_to_read = num_waiting_read;
                else {
                    switch (op->myqd) {
                    case MYQD_LOW:
                        num_to_read = num_waiting_read;
                        break;
                    case MYQD_MEDIUM:
                        num_to_read = num_waiting_read / 2;
                        break;
                    case MYQD_HIGH:
                    default:
                        if (op->ovn > 0) {
                            if (op->sg_vn_ge_40030) {
                                int num_subm = num_submitted(sg_fd);

                                if (num_subm > op->ovn) {
                                    num_to_read = num_waiting_read > 0 ?
                                                    num_waiting_read : 1;
                                    break;
                                }
                            } else {
                                if (num_waiting_read > (op->ovn / 2)) {
                                    num_to_read = num_waiting_read / 2;
                                    break;
                                }
                            }
                        }
                        num_to_read = 1;
                        break;
                    }
                }
            } else {    /* nothing waiting to be read */
                if (op->sg_vn_ge_40030) {
                    int val = num_submitted(sg_fd);

                    if (0 == val) {
                        err = "nothing submitted now ??";
                        break;
                    } else if (val < 0) {
                        err = "num_submitted failed";
                        break;
                    }
                }
                n = (op->wait_ms > 0) ? op->wait_ms : 0;
                if ((n > 0) && (! op->no_waitq)) {
                    for (j = 0; (j < 1000000) &&
                         (0 == (res = poll(pfd, 1, n)));
                         ++j)
                        ;
                    if (j >= 1000000) {
                        err = "poll() looped 1 million times";
                        break;
                    }
                    if (res < 0) {
                        err = "poll(wait_ms) failed";
                        break;
                    }
                } else {
                    struct timespec ts;

                    ts.tv_sec = 0;
                    ts.tv_nsec = DEF_NANOSEC_WAIT;
                    if (nanosleep(&ts, NULL) < 0) {
                        err = "nanosleep() failed";
                        break;
                    }
                }
            }
        } else {        /* not full, not finished injecting */
            if (MYQD_HIGH == op->myqd) {
                num_to_read = 0;
                if (op->ovn) {
                    if (op->sg_vn_ge_40030) {
                        int num_subm = num_submitted(sg_fd);

                        if (num_subm > op->ovn)
                            num_to_read = num_waiting_read > 0 ?
                                            num_waiting_read : 1;
                    } else {
                        num_waiting_read = 0;
                        if (ioctl(sg_fd, SG_GET_NUM_WAITING,
                                  &num_waiting_read) < 0) {
                            err = "ioctl(SG_GET_NUM_WAITING) failed";
                            break;
                        }
                        if (num_waiting_read > (op->ovn / 2))
                            num_to_read = num_waiting_read / 2;
                    }
                }
            } else {
                num_waiting_read = 0;
                if (ioctl(sg_fd, SG_GET_NUM_WAITING, &num_waiting_read) < 0) {
                    err = "ioctl(SG_GET_NUM_WAITING) failed";
                    break;
                }
                if (num_waiting_read > 0)
                    num_to_read = num_waiting_read /
                                  ((MYQD_LOW == op->myqd) ? 1 : 2);
                else
                    num_to_read = 0;
            }
        }

        if (vb && !once_4000 && (num_to_read > 4000)) {
            once_4000 = true;
            pr2serr_lk("%d->id: num_to_read=%d\n", id, num_to_read);
        }
        while (num_to_read > 0) {
            --num_to_read;
            if (op->pack_id_force) {
                j = pi2buff.size();
                if (j > 0)
                    pack_id = pi2buff.begin()->first;
                else
                    pack_id = -1;
            } else
                pack_id = -1;
            ask = pack_id;
            res = (op->v4) ?
                    finish_sg4_cmd(sg_fd, op->c2e, pack_id, op->submit,
                                   op->wait_ms, thr_enomem_count,
                                   thr_fin_eagain_count, thr_fin_ebusy_count,
                                   nanosecs)           :
                    finish_sg3_cmd(sg_fd, op->c2e, pack_id, op->submit,
                                   op->wait_ms, thr_enomem_count,
                                   thr_fin_eagain_count, thr_fin_ebusy_count,
                                   nanosecs);
            if (res) {
                err = "finish_sg3_cmd()";
                if (ruip && (pack_id > 0)) {
                    auto q = pi_2_lba.find(pack_id);

                    if (q != pi_2_lba.end()) {
                        snprintf(ebuff, sizeof(ebuff), "%s: lba=0x%" PRIx64 ,
                                 err, q->second);
                        err = ebuff;
                    }
                }
                break;
            }
            if (op->cmd_time && op->sg_vn_ge_40030)
                sum_nanosecs += nanosecs;
            ++thr_async_finishes;
            --num_outstanding;
            if (vb > 4)
                pr2serr_lk("t_id=%d: finishing pack_id ask=%d, got=%d, "
                           "outstanding=%d\n", id, ask, pack_id,
                           num_outstanding);
            auto p = pi2buff.find(pack_id);

            if (p == pi2buff.end()) {
                snprintf(ebuff, sizeof(ebuff), "pack_id=%d from "
                         "finish_sg3_cmd() not found\n", pack_id);
                if (! err)
                    err = ebuff;
            } else {
                lbp = p->second.first;
                free_lbp = p->second.second;
                pi2buff.erase(p);
                if (lbp)
                    free_lst.push_front(make_pair(lbp, free_lbp));
            }
            if (ruip && (pack_id > 0)) {
                auto q = pi_2_lba.find(pack_id);

                if (q != pi_2_lba.end()) {
                    if (vb > 3)
                        pr2serr_lk("    id=%d: finish IO at lba=0x%" PRIx64
                                   "\n", id, q->second);
                    pi_2_lba.erase(q);
                }
            }
            if (err)
                break;
        }       /* end of while loop counting down num_to_read */
        if (err)
            break;
    }           /* end of for loop over npt (number per thread) */
    if (vb)
        pr2serr_lk("%d->id: leaving main thread loop; k=%d, o=%d\n", id, k,
                   o);
    close(sg_fd);       // sg driver will handle any commands "in flight"
    if (ruip)
        delete ruip;

    if (err || (k < npt)) {
        if (k < npt)
            pr2serr_lk("t_id=%d FAILed at iteration %d%s%s\n", id, k,
                       (err ? ", Reason: " : ""), (err ? err : ""));
        else
            pr2serr_lk("t_id=%d FAILed on last%s%s\n", id,
                       (err ? ", Reason: " : ""), (err ? err : ""));
    }
    n = pi2buff.size();
    if (n > 0)
        pr2serr_lk("t_id=%d Still %d elements in pi2buff map on "
                   "exit\n", id, n);
    for (k = 0; ! free_lst.empty(); ++k) {
        lbp = free_lst.back().first;
        free_lbp = free_lst.back().second;
        free_lst.back().second = NULL;
        free_lst.pop_back();
        if (vb > 6)
            pr2serr_lk("t_id=%d freeing %p (free_ %p)\n", id, lbp, free_lbp);
        if (free_lbp) {
            free(free_lbp);
            free_lbp = NULL;
        }
    }
    if ((vb > 2) && (k > 0))
        pr2serr_lk("%d->id: Maximum number of READ/WRITEs queued: %d\n",
                   id, k);
    if (vb && (thr_ovn_force_read > 0))
        pr2serr_lk("%d->id: Number of ovn (override number) forced reads: "
                   "%d\n", id, thr_ovn_force_read);
    async_starts += thr_async_starts;
    async_finishes += thr_async_finishes;
    start_eagain_count += thr_start_eagain_count;
    start_ebusy_count += thr_start_ebusy_count;
    start_e2big_count += thr_start_e2big_count;
    fin_eagain_count += thr_fin_eagain_count;
    fin_ebusy_count += thr_fin_ebusy_count;
    enomem_count += thr_enomem_count;
    start_edom_count += thr_start_edom_count;
    if (op->cmd_time && op->sg_vn_ge_40030 && (npt > 0)) {
        pr2serr_lk("t_id=%d average nanosecs per cmd: %" PRId64
                   "\n", id, sum_nanosecs / npt);
    }
}

#define INQ_REPLY_LEN 96
#define INQ_CMD_LEN 6

/* Send INQUIRY and fetches response. If okay puts PRODUCT ID field
 * in b (up to m_blen bytes). Does not use O_EXCL flag. Returns 0 on success,
 * else -1 . */
static int
do_inquiry_prod_id(const char * dev_name, int block, int & sg_ver_num,
                   char * b, int b_mlen)
{
    int sg_fd, ok, ret;
    struct sg_io_hdr pt;
    uint8_t inqCmdBlk [INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    uint8_t inqBuff[INQ_REPLY_LEN];
    uint8_t sense_buffer[64];
    int open_flags = O_RDWR;    /* O_EXCL | O_RDONLY fails with EPERM */

    if (! block)
        open_flags |= O_NONBLOCK;
    sg_fd = open(dev_name, open_flags);
    if (sg_fd < 0) {
        pr_errno_lk(errno, "%s: error opening file: %s", __func__, dev_name);
        return -1;
    }
    if (ioctl(sg_fd, SG_GET_VERSION_NUM, &sg_ver_num) < 0)
        sg_ver_num = 0;
    /* Prepare INQUIRY command */
    memset(&pt, 0, sizeof(pt));
    pt.interface_id = 'S';
    pt.cmd_len = sizeof(inqCmdBlk);
    /* pt.iovec_count = 0; */  /* memset takes care of this */
    pt.mx_sb_len = sizeof(sense_buffer);
    pt.dxfer_direction = SG_DXFER_FROM_DEV;
    pt.dxfer_len = INQ_REPLY_LEN;
    pt.dxferp = inqBuff;
    pt.cmdp = inqCmdBlk;
    pt.sbp = sense_buffer;
    pt.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* pt.flags = 0; */     /* take defaults: indirect IO, etc */
    /* pt.pack_id = 0; */
    /* pt.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &pt) < 0) {
        pr_errno_lk(errno, "%s: Inquiry SG_IO ioctl error", __func__);
        close(sg_fd);
        return -1;
    }

    /* now for the error processing */
    ok = 0;
    switch (sg_err_category3(&pt)) {
    case SG_LIB_CAT_CLEAN:
        ok = 1;
        break;
    case SG_LIB_CAT_RECOVERED:
        pr2serr_lk("Recovered error on INQUIRY, continuing\n");
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        {
            lock_guard<mutex> lg(console_mutex);
            sg_chk_n_print3("INQUIRY command error", &pt, 1);
        }
        break;
    }
    if (ok) {
        /* Good, so fetch Product ID from response, copy to 'b' */
        if (b_mlen > 0) {
            if (b_mlen > 16) {
                memcpy(b, inqBuff + 16, 16);
                b[16] = '\0';
            } else {
                memcpy(b, inqBuff + 16, b_mlen - 1);
                b[b_mlen - 1] = '\0';
            }
        }
        ret = 0;
    } else
        ret = -1;

    close(sg_fd);
    return ret;
}

/* Only allow ranges up to 2**32-1 upper limit, so READ CAPACITY(10)
 * sufficient. Return of 0 -> success, -1 -> failure, 2 -> try again */
static int
do_read_capacity(const char * dev_name, int block, unsigned int * last_lba,
                 unsigned int * blk_sz)
{
    int res, sg_fd;
    uint8_t rcCmdBlk [10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t rcBuff[64];
    uint8_t sense_b[64];
    sg_io_hdr_t io_hdr;
    int open_flags = O_RDWR;    /* O_EXCL | O_RDONLY fails with EPERM */

    if (! block)
        open_flags |= O_NONBLOCK;
    sg_fd = open(dev_name, open_flags);
    if (sg_fd < 0) {
        pr_errno_lk(errno, "%s: error opening file: %s", __func__, dev_name);
        return -1;
    }
    /* Prepare READ CAPACITY(10) command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = sizeof(rcBuff);
    io_hdr.dxferp = rcBuff;
    io_hdr.cmdp = rcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        pr_errno_lk(errno, "%s (SG_IO) error", __func__);
        close(sg_fd);
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    if (SG_LIB_CAT_UNIT_ATTENTION == res) {
        lock_guard<mutex> lg(console_mutex);
        sg_chk_n_print3("read capacity", &io_hdr, 1);
        close(sg_fd);
        return 2; /* probably have another go ... */
    } else if (SG_LIB_CAT_CLEAN != res) {
        lock_guard<mutex> lg(console_mutex);
        sg_chk_n_print3("read capacity", &io_hdr, 1);
        close(sg_fd);
        return -1;
    }
    *last_lba = sg_get_unaligned_be32(&rcBuff[0]);
    *blk_sz = sg_get_unaligned_be32(&rcBuff[4]);
    close(sg_fd);
    return 0;
}


int
main(int argc, char * argv[])
{
    bool maxq_per_thread_given = false;
    int k, n, c, res;
    int force = 0;
    int64_t ll;
    int num_threads = DEF_NUM_THREADS;
    char b[128];
    struct timespec start_tm, end_tm;
    struct opts_t * op;
    const char * cp;
    const char * dev_name;

    op = &a_opts;
#if 0
    memset(op, 0, sizeof(*op));         // C++ doesn't like this
#endif
    op->direct = DEF_DIRECT;
    op->lba = DEF_LBA;
    op->hi_lba = 0;
    op->lb_sz = DEF_LB_SZ;
    op->maxq_per_thread = MAX_Q_PER_FD;
    op->mmap_io = DEF_MMAP_IO;
    op->num_per_thread = DEF_NUM_PER_THREAD;
    op->num_lbs = 1;
    op->no_xfer = !! DEF_NO_XFER;
    op->verbose = 0;
    op->wait_ms = DEF_WAIT_MS;
    op->c2e = SCSI_TUR;
    op->blqd = BLQ_DEFAULT;
    op->block = !! DEF_BLOCKING;
    op->myqd = MYQD_HIGH;
    page_size = sysconf(_SC_PAGESIZE);

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv,
                        "34acdefghl:L:mM:n:NO:pq:Q:Rs:St:TuvVw:Wz",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case '3':
            op->v3 = true;
            op->v3_given = true;
            op->v4 = false;     /* if '-4 -3' take latter */
            op->v4_given = false;
            break;
        case '4':
            op->v4 = true;
            op->v4_given = true;
            op->v3 = false;
            op->v3_given = false;
            break;
        case 'a':
            op->masync = true;
            break;
        case 'c':
            op->cmd_time = true;
            break;
        case 'd':
            op->direct = true;
            break;
        case 'e':
            op->excl = true;
            break;
        case 'f':
            force = true;
            break;
        case 'g':
            op->generic_sync = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            if (isdigit(*optarg)) {
                ll = sg_get_llnum(optarg);
                if (-1 == ll) {
                    pr2serr_lk("could not decode lba\n");
                    return 1;
                } else
                    op->lba = (uint64_t)ll;
                cp = strchr(optarg, ',');
                if (cp) {
                    if (0 == strcmp("-1", cp + 1))
                        op->hi_lba = UINT_MAX;
                    else {
                        ll = sg_get_llnum(cp + 1);
                        if ((-1 == ll) || (ll > UINT_MAX)) {
                            pr2serr_lk("could not decode hi_lba, or > "
                                       "UINT_MAX\n");
                            return 1;
                        } else
                            op->hi_lba = (unsigned int)ll;
                    }
                }
            } else {
                pr2serr_lk("--lba= expects a number\n");
                return 1;
            }
            break;
        case 'L':
            op->lb_sz = sg_get_num(optarg);
            if (op->lb_sz < 0) {
                pr2serr_lk("--lbsz= expects power of 2\n");
                return 1;
            }
            if (0 == op->lb_sz)
                op->lb_sz = DEF_LB_SZ;
            break;
        case 'm':
            op->mmap_io = true;
            break;
        case 'M':
            if (isdigit(*optarg)) {
                n = atoi(optarg);
                if ((n < 1) || (n > MAX_Q_PER_FD)) {
                    pr2serr_lk("-M expects a value from 1 to %d\n",
                               MAX_Q_PER_FD);
                    return 1;
                }
                maxq_per_thread_given = true;
                op->maxq_per_thread = n;
            } else {
                pr2serr_lk("--maxqpt= expects a number\n");
                return 1;
            }
            break;
        case 'n':
            if (isdigit(*optarg))
                op->num_per_thread = sg_get_num(optarg);
            else {
                pr2serr_lk("--numpt= expects a number\n");
                return 1;
            }
            break;
        case 'N':
            op->no_xfer = true;
            break;
        case 'O':
            if (isdigit(*optarg))
                op->ovn = sg_get_num(optarg);
            else {
                pr2serr_lk("--override= expects a number\n");
                return 1;
            }
            if (op->ovn < 0) {
                pr2serr_lk("--override= bad number\n");
                return 1;
            }
            break;
        case 'p':
            op->pack_id_force = true;
            break;
        case 'q':
            if (isdigit(*optarg)) {
                n = atoi(optarg);
                if (0 == n)
                    op->blqd = BLQ_AT_HEAD;
                else if (1 == n)
                    op->blqd = BLQ_AT_TAIL;
            } else {
                pr2serr_lk("--qat= expects a number: 0 or 1\n");
                return 1;
            }
            break;
        case 'Q':
            if (isdigit(*optarg)) {
                n = atoi(optarg);
                if (0 == n)
                    op->myqd = MYQD_LOW;
                else if (1 == n)
                    op->myqd = MYQD_MEDIUM;
                else if (2 == n)
                    op->myqd = MYQD_HIGH;
            } else {
                pr2serr_lk("--qfav= expects a number: 0, 1 or 2\n");
                return 1;
            }
            break;
        case 'R':
            op->c2e = SCSI_READ16;
            break;
        case 's':
            if (isdigit(*optarg)) {
                op->lb_sz = atoi(optarg);
                if (op->lb_sz < 256) {
                    cerr << "Strange lb_sz, using 256" << endl;
                    op->lb_sz = 256;
                }
            } else {
                pr2serr_lk("--szlb= expects a number\n");
                return 1;
            }
            if ((cp = strchr(optarg, ','))) {
                n = sg_get_num(cp + 1);
                if (n < 1) {
                    pr2serr_lk("could not decode 2nd part of "
                               "--szlb=LBS,NLBS\n");
                    return 1;
                }
                op->num_lbs = n;
            }
            break;
        case 'S':
            ++op->stats;
            break;
        case 't':
            if (isdigit(*optarg))
                num_threads = atoi(optarg);
            else {
                pr2serr_lk("--tnum= expects a number\n");
                return 1;
            }
            break;
        case 'T':
            op->c2e = SCSI_TUR;
            break;
        case 'u':
            op->submit = true;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'w':
            if ((isdigit(*optarg) || ('-' == *optarg))) {
                if ('-' == *optarg)
                    op->wait_ms = - atoi(optarg + 1);
                else
                    op->wait_ms = atoi(optarg);
            } else {
                pr2serr_lk("--wait= expects a number\n");
                return 1;
            }
            break;
        case 'W':
            op->c2e = SCSI_WRITE16;
            break;
        case 'z':
            op->no_waitq = true;
            break;
        default:
            pr2serr_lk("unrecognised option code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if (optind < argc) {
            for (; optind < argc; ++optind)
                op->dev_names.push_back(argv[optind]);
        }
    }
#ifdef DEBUG
    pr2serr_lk("In DEBUG mode, ");
    if (op->verbose_given && op->version_given) {
        pr2serr_lk("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->verbose = 0;
    } else if (! op->verbose_given) {
        pr2serr_lk("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr_lk("keep verbose=%d\n", op->verbose);
#else
    if (op->verbose_given && op->version_given)
        pr2serr_lk("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr2serr_lk("version: %s\n", version_str);
        return 0;
    }
    if (op->mmap_io) {
        if (maxq_per_thread_given && (op->maxq_per_thread > 1)) {
            pr2serr_lk("With mmap_io selected, QPT cannot exceed 1\n");
            return 1;
        } else if (op->direct) {
            pr2serr_lk("direct IO and mmap-ed IO cannot both be selected\n");
            return 1;
        } else if (op->generic_sync) {
            pr2serr_lk("--generic-sync and and mmap-ed IO are compatible\n");
            return 1;
        } else
            op->maxq_per_thread = 1;
    }
    if (! op->cmd_time && getenv("SG3_UTILS_LINUX_NANO")) {
        op->cmd_time = true;
        if (op->verbose)
            fprintf(stderr, "setting nanosecond timing due to environment "
                    "variable: SG3_UTILS_LINUX_NANO\n");
    }
    if (0 == op->dev_names.size()) {
        fprintf(stderr, "No sg_disk_device-s given\n\n");
        usage();
        return 1;
    }
    if (op->hi_lba && (op->lba > op->hi_lba)) {
        cerr << "lba,hi_lba range is illegal" << endl;
        return 1;
    }
    if (op->v4) {
        if (! op->submit) {
            op->submit = true;
            if (op->verbose > 1)
                cerr << "when --v4 is given, --submit will be set" << endl;
        }
    }

    try {
        int sg_ver_num;
        unsigned int last_lba;
        unsigned int blk_sz;
        struct stat a_stat;

        for (k = 0; k < (int)op->dev_names.size(); ++k) {
            dev_name = op->dev_names[k];
            if (stat(dev_name, &a_stat) < 0) {
                snprintf(b, sizeof(b), "could not stat() %s", dev_name);
                perror(b);
                return 1;
            }
            if (! S_ISCHR(a_stat.st_mode)) {
                pr2serr_lk("%s should be a sg device which is a char "
                           "device. %s\n", dev_name, dev_name);
                pr2serr_lk("is not a char device and damage could be done "
                           "if it is a BLOCK\ndevice, exiting ...\n");
                return 1;
            }
            res = do_inquiry_prod_id(dev_name, op->block, sg_ver_num,
                                     b, sizeof(b));
            if (! force) {
                if (res) {
                    pr2serr_lk("INQUIRY failed on %s\n", dev_name);
                    return 1;
                }
                // For safety, since <lba> written to, only permit scsi_debug
                // devices. Bypass this with '-f' option.
                if (0 != memcmp("scsi_debug", b, 10)) {
                    pr2serr_lk("Since this utility may write to LBAs, "
                               "only devices with the\n"
                               "product ID 'scsi_debug' accepted. Use '-f' "
                               "to override.\n");
                    return 2;
                }
            }
            if (sg_ver_num < 30000) {
                pr2serr_lk("%s either not sg device or too old\n", dev_name);
                return 2;
            } else if (sg_ver_num >= 40030) {
                op->sg_vn_ge_40030 = true;
                op->sg_vn_ge_40000 = true;
                if (! (op->v3_given || op->v4_given)) {
                    op->v4 = true;
                    op->v3 = false;
                    op->submit = true;
                }
            } else if (sg_ver_num >= 40000) {
                op->sg_vn_ge_40030 = false;
                op->sg_vn_ge_40000 = true;
                if (! (op->v3_given || op->v4_given)) {
                    op->v4 = true;
                    op->v3 = false;
                    op->submit = true;
                }
            } else {
                if (! (op->v3_given || op->v4_given)) {
                    op->v4 = false;
                    op->v3 = true;
                    op->submit = false;
                }
            }

            if ((SCSI_WRITE16 == op->c2e) || (SCSI_READ16 == op->c2e)) {
                res = do_read_capacity(dev_name, op->block, &last_lba,
                                       &blk_sz);
                if (2 == res)
                    res = do_read_capacity(dev_name, op->block, &last_lba,
                                           &blk_sz);
                if (res) {
                    pr2serr_lk("READ CAPACITY(10) failed on %s\n", dev_name);
                    return 1;
                }
                if (blk_sz != (unsigned int)op->lb_sz) {
                    pr2serr_lk(">>> Logical block size (%d) of %s\n"
                               "    differs from command line option (or "
                               "default)\n", blk_sz, dev_name);
                   pr2serr_lk("... continue anyway\n");
                }
                op->blk_szs.push_back(blk_sz);
                if (UINT_MAX == op->hi_lba)
                    op->hi_lbas.push_back(last_lba);
            }
        }

        start_tm.tv_sec = 0;
        start_tm.tv_nsec = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &start_tm) < 0)
            perror("clock_gettime failed");

        vector<thread *> vt;

        /* start multi-threaded section */
        for (k = 0; k < num_threads; ++k) {
            thread * tp = new thread {work_thread, k, op};
            vt.push_back(tp);
        }

        // g++ 4.7.3 didn't like range-for loop here
        for (k = 0; k < (int)vt.size(); ++k)
            vt[k]->join();
        /* end multi-threaded section, just this main thread left */

        for (k = 0; k < (int)vt.size(); ++k)
            delete vt[k];

        n = uniq_pack_id.load() - 1;
        if (((n > 0) || op->generic_sync) &&
            (0 == clock_gettime(CLOCK_MONOTONIC, &end_tm))) {
            struct timespec res_tm;
            double a, b;

            if (op->generic_sync)
                n = op->num_per_thread * num_threads;
            res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
            res_tm.tv_nsec = end_tm.tv_nsec - start_tm.tv_nsec;
            if (res_tm.tv_nsec < 0) {
                --res_tm.tv_sec;
                res_tm.tv_nsec += 1000000000;
            }
            a = res_tm.tv_sec;
            a += (0.000001 * (res_tm.tv_nsec / 1000));
            b = (double)n;
            if (a > 0.000001) {
                printf("Time to complete %d commands was %d.%06d seconds\n",
                       n, (int)res_tm.tv_sec, (int)(res_tm.tv_nsec / 1000));
                printf("Implies %.0f IOPS\n", (b / a));
            }
        }

        if (op->verbose || op->stats) {
            cout << "Number of sync_starts: " << sync_starts.load() << endl;
            cout << "Number of async_starts: " << async_starts.load() << endl;
            cout << "Number of async_finishes: " << async_finishes.load() <<
                    endl;
            cout << "Last pack_id: " << n << endl;
        }
        n = start_ebusy_count.load();
        if (op->verbose || op->stats || (n > 0))
            cout << "Number of start EBUSYs: " << n << endl;
        n = fin_ebusy_count.load();
        if (op->verbose || op->stats || (n > 0))
            cout << "Number of finish EBUSYs: " << n << endl;
        n = start_eagain_count.load();
        if (op->verbose || op->stats || (n > 0))
            cout << "Number of start EAGAINs: " << n << endl;
        n = fin_eagain_count.load();
        if (op->verbose || op->stats || (n > 0))
            cout << "Number of finish EAGAINs: " << n << endl;
        n = start_e2big_count.load();
        if (op->verbose || op->stats || (n > 0))
            cout << "Number of E2BIGs: " << n << endl;
        n = start_edom_count.load();
        if (op->verbose || op->stats || (n > 0))
            cout << "Number of EDOMs: " << n << endl;
        n = enomem_count.load();
        if (op->verbose || op->stats || (n > 0))
            cout << "Number of ENOMEMs: " << n << endl;
    }
    catch(system_error& e)  {
        cerr << "got a system_error exception: " << e.what() << '\n';
        auto ec = e.code();
        cerr << "category: " << ec.category().name() << '\n';
        cerr << "value: " << ec.value() << '\n';
        cerr << "message: " << ec.message() << '\n';
        cerr << "\nNote: if g++ may need '-pthread' or similar in "
                "compile/link line" << '\n';
    }
    catch(...) {
        cerr << "got another exception: " << '\n';
    }
    return 0;
}
