/*
 * Copyright (c) 2014-2018 Douglas Gilbert.
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pt.h"
#include "sg_cmds.h"

static const char * version_str = "1.12 20180319";
static const char * util_name = "sg_tst_async";

/* This is a test program for checking the async usage of the Linux sg
 * driver. Each thread opens 1 file descriptor to the next sg device (1
 * or more can be given on the command line) and then starts up to 16
 * commands while checking with the poll command (or
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
 *   cd ../examples
 * Then to build sg_tst_async concatenate the next 3 lines:
 *   g++ -Wall -std=c++11 -pthread -I ../include ../lib/sg_lib.o
 *     ../lib/sg_lib_data.o ../lib/sg_io_linux.o -o sg_tst_async
 *     sg_tst_async.cpp
 * or use the C++ Makefile in that directory:
 *   make -f Makefile.cplus sg_tst_async
 *
 * Currently this utility is Linux only and uses the sg driver. The bsg
 * driver is known to be broken (it doesn't match responses to the
 * correct file descriptor that requested them) so this utility won't
 * be extended to bsg until that is fixed.
 *
 * BEWARE: >>> This utility will modify a logical block (default LBA 1000)
 * on the given device when the '-W' option is given.
 *
 */

using namespace std;
using namespace std::chrono;

#define DEF_NUM_PER_THREAD 1000
#define DEF_NUM_THREADS 4
#define DEF_WAIT_MS 10          /* 0: yield or no wait */
#define DEF_TIMEOUT_MS 20000    /* 20 seconds */
#define DEF_LB_SZ 512
#define DEF_BLOCKING 0
#define DEF_DIRECT 0            /* 1: direct_io [future maybe 2: mmap IO] */
#define DEF_NO_XFER 0
#define DEF_LBA 1000

#define MAX_Q_PER_FD 16     /* sg driver per file descriptor limit */
#define MAX_CONSEC_NOMEMS 16
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
static atomic<int> ebusy_count(0);
static atomic<int> start_eagain_count(0);
static atomic<int> fin_eagain_count(0);
static atomic<int> uniq_pack_id(1);
static atomic<int> generic_errs(0);

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
    int direct;
    int maxq_per_thread;
    int num_per_thread;
    bool block;
    bool generic_pt;
    uint64_t lba;
    unsigned int hi_lba;        /* last one, inclusive range */
    vector<unsigned int> hi_lbas; /* only used when hi_lba=-1 */
    int lb_sz;
    bool no_xfer;
    int stats;
    int verbose;
    int wait_ms;
    command2execute c2e;
    blkLQDiscipline blqd;
    myQDiscipline myqd;
};

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
        {"direct", no_argument, 0, 'd'},
        {"force", no_argument, 0, 'f'},
        {"generic-pt", no_argument, 0, 'g'},
        {"generic_pt", no_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"lba", required_argument, 0, 'l'},
        {"maxqpt", required_argument, 0, 'M'},
        {"numpt", required_argument, 0, 'n'},
        {"noxfer", no_argument, 0, 'N'},
        {"qat", required_argument, 0, 'q'},
        {"qfav", required_argument, 0, 'Q'},
        {"read", no_argument, 0, 'R'},
        {"szlb", required_argument, 0, 's'},
        {"stats", no_argument, 0, 'S'},
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
    printf("Usage: %s [--direct] [--force] [--generic-pt] [--help]\n"
           "                    [--lba=LBA+] [--maxqpt=QPT] [--numpt=NPT] "
           "[--noxfer]\n"
           "                    [--qat=AT] [-qfav=FAV] [--read] [--szlb=LB] "
           "[--stats]\n"
           "                    [--tnum=NT] [--tur] [--verbose] [--version] "
           "[--wait=MS]\n"
           "                    [--write] <sg_disk_device>*\n",
           util_name);
    printf("  where\n");
    printf("    --direct|-d     do direct_io (def: indirect)\n");
    printf("    --force|-f      force: any sg device (def: only scsi_debug "
           "owned)\n");
    printf("                    WARNING: <lba> written to if '-W' given\n");
    printf("    --generic-pt|-g    use generic passthru in sg3_utils "
           "instead\n");
    printf("                       of Linux sg driver and SG_IO ioctl "
           "(def)\n");
    printf("    --help|-h       print this usage message then exit\n");
    printf("    --lba=LBA|-l LBA    logical block to access (def: %u)\n",
           DEF_LBA);
    printf("    --lba=LBA,HI_LBA|-l LBA,HI_LBA    logical block range "
           "(inclusive)\n"
           "                          if hi_lba=-1 assume last block on "
           "device\n");
    printf("    --maxqpt=QPT|-M QPT    maximum commands queued per thread "
           "(def:%d)\n", MAX_Q_PER_FD);
    printf("    --numpt=NPT|-n NPT    number of commands per thread "
           "(def: %d)\n", DEF_NUM_PER_THREAD);
    printf("    --noxfer|-N             no data xfer (def: xfer on READ and "
           "WRITE)\n");
    printf("    --qat=AT|-q AT       AT=0: q_at_head; AT=1: q_at_tail\n");
    printf("    --qfav=FAV|-Q FAV    FAV=0: favour completions (smaller q),\n"
           "                         FAV=1: medium,\n"
           "                         FAV=2: favour submissions (larger q, "
           "default)\n");
    printf("    --read|-R       do READs (def: TUR)\n");
    printf("    --szlb=LB|-s LB    logical block size (def: 512)\n");
    printf("    --stats|-S      show more statistics on completion\n");
    printf("    --tnum=NT|-t NT    number of threads (def: %d)\n",
           DEF_NUM_THREADS);
    printf("    --tur|-T        do TEST UNIT READYs (default is TURs)\n");
    printf("    --verbose|-v    increase verbosity\n");
    printf("    --version|-V    print version number then exit\n");
    printf("    --wait=MS|-w MS    >0: poll(<wait_ms>); =0: poll(0); (def: "
           "%d)\n", DEF_WAIT_MS);
    printf("    --write|-W      do WRITEs (def: TUR)\n\n");
    printf("Multiple threads send READ(16), WRITE(16) or TEST UNIT READY "
           "(TUR) SCSI\ncommands. There can be 1 or more <sg_disk_device>s "
           "and each thread takes\nthe next in a round robin fashion. "
           "Each thread queues up to 16 commands.\nOne block is transferred "
           "by each READ and WRITE; zeros are written. If a\nlogical block "
           "range is given, a uniform distribution generates a pseudo\n"
           "random sequence of LBAs.\n");
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
#define READ16_REPLY_LEN 512
#define READ16_CMD_LEN 16
#define WRITE16_REPLY_LEN 512
#define WRITE16_CMD_LEN 16

/* Returns 0 if command injected okay, else -1 */
static int
start_sg3_cmd(int sg_fd, command2execute cmd2exe, int pack_id, uint64_t lba,
              uint8_t * lbp, int xfer_bytes, int flags,
              unsigned int & eagains)
{
    struct sg_io_hdr pt;
    uint8_t turCmdBlk[TUR_CMD_LEN] = {0, 0, 0, 0, 0, 0};
    uint8_t r16CmdBlk[READ16_CMD_LEN] =
                {0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    uint8_t w16CmdBlk[WRITE16_CMD_LEN] =
                {0x8a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    uint8_t sense_buffer[64];
    const char * np = NULL;

    memset(&pt, 0, sizeof(pt));
    switch (cmd2exe) {
    case SCSI_TUR:
        np = "TEST UNIT READY";
        pt.cmdp = turCmdBlk;
        pt.cmd_len = sizeof(turCmdBlk);
        pt.dxfer_direction = SG_DXFER_NONE;
        break;
    case SCSI_READ16:
        np = "READ(16)";
        if (lba > 0xffffffff)
            sg_put_unaligned_be32(lba >> 32, &r16CmdBlk[2]);
        sg_put_unaligned_be32(lba & 0xffffffff, &r16CmdBlk[6]);
        pt.cmdp = r16CmdBlk;
        pt.cmd_len = sizeof(r16CmdBlk);
        pt.dxfer_direction = SG_DXFER_FROM_DEV;
        pt.dxferp = lbp;
        pt.dxfer_len = xfer_bytes;
        break;
    case SCSI_WRITE16:
        np = "WRITE(16)";
        if (lba > 0xffffffff)
            sg_put_unaligned_be32(lba >> 32, &w16CmdBlk[2]);
        sg_put_unaligned_be32(lba & 0xffffffff, &w16CmdBlk[6]);
        pt.cmdp = w16CmdBlk;
        pt.cmd_len = sizeof(w16CmdBlk);
        pt.dxfer_direction = SG_DXFER_TO_DEV;
        pt.dxferp = lbp;
        pt.dxfer_len = xfer_bytes;
        break;
    }
    pt.interface_id = 'S';
    pt.mx_sb_len = sizeof(sense_buffer);
    pt.sbp = sense_buffer;      /* ignored .... */
    pt.timeout = DEF_TIMEOUT_MS;
    pt.pack_id = pack_id;
    pt.flags = flags;

    for (int k = 0; write(sg_fd, &pt, sizeof(pt)) < 0; ++k) {
        if ((ENOMEM == errno) && (k < MAX_CONSEC_NOMEMS)) {
            this_thread::yield();
            continue;
        }
        if (EAGAIN == errno) {
            ++eagains;
            this_thread::yield();
            continue;
        }
        pr_errno_lk(errno, "%s: %s, pack_id=%d", __func__, np, pack_id);
        return -1;
    }
    return 0;
}

static int
finish_sg3_cmd(int sg_fd, command2execute cmd2exe, int & pack_id, int wait_ms,
               unsigned int & eagains)
{
    int ok, res;
    struct sg_io_hdr pt;
    uint8_t sense_buffer[64];
    const char * np = NULL;

    memset(&pt, 0, sizeof(pt));
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
    pt.interface_id = 'S';
    pt.mx_sb_len = sizeof(sense_buffer);
    pt.sbp = sense_buffer;
    pt.timeout = DEF_TIMEOUT_MS;
    pt.pack_id = 0;

    while (((res = read(sg_fd, &pt, sizeof(pt))) < 0) &&
           (EAGAIN == errno)) {
        ++eagains;
        if (wait_ms > 0)
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();
        else if (-2 == wait_ms)
            sleep(0);                   // process yield ??
    }
    if (res < 0) {
        pr_errno_lk(errno, "%s: %s", __func__, np);
        return -1;
    }
    /* now for the error processing */
    pack_id = pt.pack_id;
    ok = 0;
    switch (sg_err_category3(&pt)) {
    case SG_LIB_CAT_CLEAN:
        ok = 1;
        break;
    case SG_LIB_CAT_RECOVERED:
        pr2serr_lk("%s: Recovered error on %s, continuing\n", __func__, np);
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        {
            lock_guard<mutex> lg(console_mutex);
            sg_chk_n_print3(np, &pt, 1);
        }
        break;
    }
    return ok ? 0 : -1;
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
    struct sg_pt_base * pbp = NULL;
    uint8_t cdb[6];
    uint8_t sense_b[32];
    char b[120];

    if (is_rw) {
        pr2serr_lk("id=%d: only support TUR here for now\n", id);
        goto err_out;
    }
    if ((sg_fd = sg_cmds_open_device(dev_name, false /* ro */, vb)) < 0) {
        pr2serr_lk("id=%d: error opening file: %s: %s\n", id, dev_name,
                   safe_strerror(-sg_fd));
        goto err_out;
    }

    pbp = construct_scsi_pt_obj_with_fd(sg_fd, vb);
    err = 0;
    if ((NULL == pbp) || ((err = get_scsi_pt_os_err(pbp)))) {
        ret = sg_convert_errno(err ? err : ENOMEM);
        sg_exit2str(ret, true, sizeof(b), b);
        pr2serr_lk("id=%d: construct_scsi_pt_obj_with_fd: %s\n", id, b);
        goto err_out;
    }
    for (k = 0; k < op->num_per_thread; ++k) {
        /* Might get Unit Attention on first invocation */
        memset(cdb, 0, sizeof(cdb));    /* TUR's cdb is 6 zeros */
        set_scsi_pt_cdb(pbp, cdb, sizeof(cdb));
        set_scsi_pt_sense(pbp, sense_b, sizeof(sense_b));
        ++thr_sync_starts;
        rs = do_scsi_pt(pbp, -1, DEF_PT_TIMEOUT, vb);
        n = sg_cmds_process_resp(pbp, "Test unit ready", rs,
                                 SG_NO_DATA_IN, sense_b,
                                 (0 == k), vb, &sense_cat);
        if (-1 == n) {
            ret = sg_convert_errno(get_scsi_pt_os_err(pbp));
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
        clear_scsi_pt_obj(pbp);
    }
err_out:
    if (pbp)
        destruct_scsi_pt_obj(pbp);
    if (num_errs > 0)
        pr2serr_lk("id=%d: number of errors: %d\n", id, num_errs);
    sync_starts += thr_sync_starts;
}

static void
work_thread(int id, struct opts_t * op)
{
    int thr_async_starts = 0;
    int thr_async_finishes = 0;
    int vb = op->verbose;
    unsigned int thr_start_eagain_count = 0;
    unsigned int thr_fin_eagain_count = 0;
    unsigned int seed = 0;
    unsigned int hi_lba;
    int k, n, res, sg_fd, num_outstanding, do_inc, npt, pack_id, sg_flags;
    int num_waiting_read, num_to_read;
    int open_flags = O_RDWR;
    bool is_rw = (SCSI_TUR != op->c2e);
    char ebuff[EBUFF_SZ];
    uint64_t lba;
    uint8_t * lbp;
    uint8_t * free_lbp = NULL;
    const char * dev_name;
    const char * err = NULL;
    Rand_uint * ruip = NULL;
    struct pollfd  pfd[1];
    list<pair<uint8_t *, uint8_t *> > free_lst;   /* of aligned lb buffers */
    map<int, uint8_t *> pi_2_buff;    /* pack_id -> lb buffer */
    map<int, uint64_t> pi_2_lba;            /* pack_id -> LBA */

    /* device name and hi_lba may depend on id */
    n = op->dev_names.size();
    dev_name = op->dev_names[id % n];
    if ((UINT_MAX == op->hi_lba) && (n == (int)op->hi_lbas.size()))
        hi_lba = op->hi_lbas[id % n];
    else
        hi_lba = op->hi_lba;

    if (vb) {
        if ((vb > 1) && hi_lba)
            pr2serr_lk("Enter work_thread id=%d using %s\n"
                       "    LBA range: 0x%x to 0x%x (inclusive)\n",
                       id, dev_name, (unsigned int)op->lba, hi_lba);
        else
            pr2serr_lk("Enter work_thread id=%d using %s\n", id, dev_name);
    }
    if (op->generic_pt) {
        work_sync_thread(id, dev_name, hi_lba, op);
        return;
    }
    if (! op->block)
        open_flags |= O_NONBLOCK;

    sg_fd = open(dev_name, open_flags);
    if (sg_fd < 0) {
        pr_errno_lk(errno, "%s: id=%d, error opening file: %s", __func__, id,
                    dev_name);
        return;
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
    if (op->no_xfer)
        sg_flags |= SG_FLAG_NO_DXFER;
    if (vb > 1)
        pr2serr_lk("  id=%d, sg_flags=0x%x, %s cmds\n", id, sg_flags,
                   ((SCSI_TUR == op->c2e) ? "TUR":
                    ((SCSI_READ16 == op->c2e) ? "READ" : "WRITE")));

    npt = op->num_per_thread;
    /* main loop, continues until num_per_thread exhausted and there are
     * no more outstanding responses */
    for (k = 0, num_outstanding = 0; (k < npt) || num_outstanding;
         k = do_inc ? k + 1 : k) {
        do_inc = 0;
        if ((num_outstanding < op->maxq_per_thread) && (k < npt)) {
            do_inc = 1;
            pack_id = uniq_pack_id.fetch_add(1);
            if (is_rw) {    /* get new lb buffer or one from free list */
                if (free_lst.empty()) {
                    lbp = sg_memalign(op->lb_sz, 0, &free_lbp, vb);
                    if (NULL == lbp) {
                        err = "out of memory";
                        break;
                    }
                } else {
                    lbp = free_lst.back().first;
                    free_lst.pop_back();
                }
            } else
                lbp = NULL;
            if (is_rw) {
                if (ruip) {
                    lba = ruip->get();  /* fetch a random LBA */
                    if (vb > 3)
                        pr2serr_lk("  id=%d: start IO at lba=0x%" PRIx64 "\n",
                                   id, lba);
                } else
                    lba = op->lba;
            } else
                lba = 0;
            if (start_sg3_cmd(sg_fd, op->c2e, pack_id, lba, lbp, op->lb_sz,
                              sg_flags, thr_start_eagain_count)) {
                err = "start_sg3_cmd()";
                break;
            }
            ++thr_async_starts;
            ++num_outstanding;
            pi_2_buff[pack_id] = lbp;
            if (ruip)
                pi_2_lba[pack_id] = lba;
        }
        num_to_read = 0;
        if ((num_outstanding >= op->maxq_per_thread) || (k >= npt)) {
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
                        num_to_read = 1;
                        break;
                    }
                }
            } else {    /* nothing waiting to be read */
                n = (op->wait_ms > 0) ? op->wait_ms : 0;
                while (0 == (res = poll(pfd, 1, n))) {
                    if (res < 0) {
                        err = "poll(wait_ms) failed";
                        break;
                    }
                }
                if (err)
                    break;
            }
        } else {        /* not full, not finished injecting */
            if (MYQD_HIGH == op->myqd)
                num_to_read = 0;
            else {
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

        while (num_to_read-- > 0) {
            if (finish_sg3_cmd(sg_fd, op->c2e, pack_id, op->wait_ms,
                               thr_fin_eagain_count)) {
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
            ++thr_async_finishes;
            --num_outstanding;
            auto p = pi_2_buff.find(pack_id);

            if (p == pi_2_buff.end()) {
                snprintf(ebuff, sizeof(ebuff), "pack_id=%d from "
                         "finish_sg3_cmd() not found\n", pack_id);
                if (! err)
                    err = ebuff;
            } else {
                lbp = p->second;
                pi_2_buff.erase(p);
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
        }
        if (err)
            break;
    }
    close(sg_fd);       // sg driver will handle any commands "in flight"
    if (ruip)
        delete ruip;

    if (err || (k < npt)) {
        if (k < npt)
            pr2serr_lk("thread id=%d FAILed at iteration %d%s%s\n", id, k,
                       (err ? ", Reason: " : ""), (err ? err : ""));
        else
            pr2serr_lk("thread id=%d FAILed on last%s%s\n", id,
                       (err ? ", Reason: " : ""), (err ? err : ""));
    }
    n = pi_2_buff.size();
    if (n > 0)
        pr2serr_lk("thread id=%d Still %d elements in pi_2_buff map on "
                   "exit\n", id, n);
    for (k = 0; ! free_lst.empty(); ++k) {
        lbp = free_lst.back().first;
        free_lbp = free_lst.back().second;
        free_lst.pop_back();
        if (free_lbp)
            free(free_lbp);
    }
    if ((vb > 2) && (k > 0))
        pr2serr_lk("thread id=%d Maximum number of READ/WRITEs queued: %d\n",
                   id, k);
    async_starts += thr_async_starts;
    async_finishes += thr_async_finishes;
    start_eagain_count += thr_start_eagain_count;
    fin_eagain_count += thr_fin_eagain_count;
}

#define INQ_REPLY_LEN 96
#define INQ_CMD_LEN 6

/* Send INQUIRY and fetches response. If okay puts PRODUCT ID field
 * in b (up to m_blen bytes). Does not use O_EXCL flag. Returns 0 on success,
 * else -1 . */
static int
do_inquiry_prod_id(const char * dev_name, int block, char * b, int b_mlen)
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
    int k, n, c, res;
    int force = 0;
    int64_t ll;
    int num_threads = DEF_NUM_THREADS;
    char b[128];
    struct timespec start_tm, end_tm;
    struct opts_t opts;
    struct opts_t * op;
    const char * cp;
    const char * dev_name;

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->direct = DEF_DIRECT;
    op->lba = DEF_LBA;
    op->hi_lba = 0;
    op->lb_sz = DEF_LB_SZ;
    op->maxq_per_thread = MAX_Q_PER_FD;
    op->num_per_thread = DEF_NUM_PER_THREAD;
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

        c = getopt_long(argc, argv, "dfghl:M:n:Nq:Q:Rs:St:TvVw:W",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            op->direct = 1;
            break;
        case 'f':
            force = true;
            break;
        case 'g':
            op->generic_pt = true;
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
        case 'M':
            if (isdigit(*optarg)) {
                n = atoi(optarg);
                if ((n < 1) || (n > MAX_Q_PER_FD)) {
                    pr2serr_lk("-M expects a value from 1 to %d\n",
                               MAX_Q_PER_FD);
                    return 1;
                }
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
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            pr2serr_lk("version: %s\n", version_str);
            return 0;
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

    if (0 == op->dev_names.size()) {
        fprintf(stderr, "No sg_disk_device-s given\n\n");
        usage();
        return 1;
    }
    if (op->hi_lba && (op->lba > op->hi_lba)) {
        cerr << "lba,hi_lba range is illegal" << endl;
        return 1;
    }

    try {
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
            if (! force) {
                res = do_inquiry_prod_id(dev_name, op->block, b, sizeof(b));
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
            if (UINT_MAX == op->hi_lba) {
                unsigned int last_lba;
                unsigned int blk_sz;

                res = do_read_capacity(dev_name, op->block, &last_lba,
                                       &blk_sz);
                if (2 == res)
                    res = do_read_capacity(dev_name, op->block, &last_lba,
                                           &blk_sz);
                if (res) {
                    pr2serr_lk("READ CAPACITY(10) failed on %s\n", dev_name);
                    return 1;
                }
                op->hi_lbas.push_back(last_lba);
                if (blk_sz != (unsigned int)op->lb_sz)
                    pr2serr_lk(">>> warning: Logical block size (%d) of %s\n"
                               "    differs from command line option (or "
                               "default)\n", blk_sz, dev_name);
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
        if (((n > 0) || op->generic_pt) &&
            (0 == clock_gettime(CLOCK_MONOTONIC, &end_tm))) {
            struct timespec res_tm;
            double a, b;

            if (op->generic_pt)
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
            cout << "Number of EBUSYs: " << ebusy_count.load() << endl;
            cout << "Number of start EAGAINs: " << start_eagain_count.load()
                 << endl;
            cout << "Number of finish EAGAINs: " << fin_eagain_count.load()
                 << endl;
        }
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
