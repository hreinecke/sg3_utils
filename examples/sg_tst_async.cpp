/*
 * Copyright (c) 2014 Douglas Gilbert.
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

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_lib.h"
#include "sg_io_linux.h"

static const char * version_str = "1.00 20140710";
static const char * util_name = "sg_tst_async";

/* This is a test program for checking the async usage of the Linux sg
 * driver. Each thread opens 1 file descriptor to the sg device and then
 * starts up to 16 commands while checking with the poll command for
 * the completion of those commands. Each command has a unique "pack_id"
 * which is a sequence starting at 1. Either TEST UNIT UNIT, READ(16)
 * or WRITE(16) commands are issued.
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
 *   cd <sg3_utils> ; ./configure ; cd lib; make
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
 * be extended to bsg until that if fixed.
 *
 * BEWARE: this utility will modify a logical block (default LBA 1000) on the
 * given device when the '-W' option is given.
 *
 */

using namespace std;
using namespace std::chrono;

#define DEF_NUM_PER_THREAD 1000
#define DEF_NUM_THREADS 4
#define DEF_WAIT_MS 10          /* 0: yield; -1: don't wait; -2: sleep(0) */
#define DEF_TIMEOUT_MS 20000    /* 20 seconds */
#define DEF_LB_SZ 512
#define DEF_BLOCKING 0
#define DEF_DIRECT 0
#define DEF_NO_XFER 0

#define Q_PER_FD 16

#ifndef SG_FLAG_Q_AT_TAIL
#define SG_FLAG_Q_AT_TAIL 0x10
#endif
#ifndef SG_FLAG_Q_AT_HEAD
#define SG_FLAG_Q_AT_HEAD 0x20
#endif


#define DEF_LBA 1000

#define EBUFF_SZ 256

static mutex console_mutex;
static atomic<int> async_starts(0);
static atomic<int> async_finishes(0);
static atomic<int> ebusy_count(0);
static atomic<int> eagain_count(0);
static atomic<int> uniq_pack_id(1);

static int page_size = 4096;   /* rough guess, will ask sysconf() */

enum command2execute {SCSI_TUR, SCSI_READ16, SCSI_WRITE16};
enum blkQDiscipline {BQ_DEFAULT, BQ_AT_HEAD, BQ_AT_TAIL};

struct opts_t {
    const char * dev_name;
    bool direct;
    int num_per_thread;
    bool block;
    uint64_t lba;
    int lb_sz;
    bool no_xfer;
    int verbose;
    int wait_ms;
    command2execute c2e;
    blkQDiscipline bqd;
};


static void
usage(void)
{
    printf("Usage: %s [-d] [-f] [-h] [-l <lba>] [-n <n_per_thr>] [-N]\n"
           "                    [-q 0|1] [-R] [-s <lb_sz>] [-t <num_thrs>] "
           "[-T]\n"
           "                    [-v] [-V] [-w <wait_ms>] [-W] "
           "<sg_disk_device>\n",
           util_name);
    printf("  where\n");
    printf("    -d                do direct_io (def: indirect)\n");
    printf("    -f                force: any sg device (def: only scsi_debug "
           "owned)\n");
    printf("                      WARNING: <lba> written to if '-W' given\n");
    printf("    -h                print this usage message then exit\n");
    printf("    -l <lba>          logical block to access (def: %u)\n",
           DEF_LBA);
    printf("    -n <n_per_thr>    number of commands per thread "
           "(def: %d)\n", DEF_NUM_PER_THREAD);
    printf("    -N                no data xfer (def: xfer on READ and "
           "WRITE)\n");
    printf("    -q 0|1            0: blk q_at_head; 1: q_at_tail\n");
    printf("    -s <lb_sz>        logical block size (def: 512)\n");
    printf("    -R                do READs (def: TUR)\n");
    printf("    -t <num_thrs>     number of threads (def: %d)\n",
           DEF_NUM_THREADS);
    printf("    -T                do TEST UNIT READYs (default is TURs)\n");
    printf("    -v                increase verbosity\n");
    printf("    -V                print version number then exit\n");
    printf("    -w <wait_ms>      >0: poll(<wait_ms>); =0: poll(0); (def: "
           "%d)\n", DEF_WAIT_MS);
    printf("    -W                do WRITEs (def: TUR)\n\n");
    printf("Multiple threads do READ(16), WRITE(16) or TEST UNIT READY "
           "(TUR) SCSI\ncommands. Each thread has its own file descriptor "
           "and queues up to\n16 commands. One block is transferred by "
           "each READ and WRITE; zeros\nare written.\n");
}


#define TUR_CMD_LEN 6
#define READ16_REPLY_LEN 512
#define READ16_CMD_LEN 16
#define WRITE16_REPLY_LEN 512
#define WRITE16_CMD_LEN 16

/* Returns 0 if command injected okay, else -1 */
static int
start_sg3_cmd(int sg_fd, command2execute cmd2exe, int pack_id, uint64_t lba,
              unsigned char * lbp, int xfer_bytes, int flags)
{
    struct sg_io_hdr pt;
    unsigned char turCmdBlk[TUR_CMD_LEN] = {0, 0, 0, 0, 0, 0};
    unsigned char r16CmdBlk[READ16_CMD_LEN] =
                {0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    unsigned char w16CmdBlk[WRITE16_CMD_LEN] =
                {0x8a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    unsigned char sense_buffer[64];
    const char * np;

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
        if (lba > 0xffffffff) {
            r16CmdBlk[2] = (lba >> 56) & 0xff;
            r16CmdBlk[3] = (lba >> 48) & 0xff;
            r16CmdBlk[4] = (lba >> 40) & 0xff;
            r16CmdBlk[5] = (lba >> 32) & 0xff;
        }
        r16CmdBlk[6] = (lba >> 24) & 0xff;
        r16CmdBlk[7] = (lba >> 16) & 0xff;
        r16CmdBlk[8] = (lba >> 8) & 0xff;
        r16CmdBlk[9] = lba & 0xff;
        pt.cmdp = r16CmdBlk;
        pt.cmd_len = sizeof(r16CmdBlk);
        pt.dxfer_direction = SG_DXFER_FROM_DEV;
        pt.dxferp = lbp;
        pt.dxfer_len = xfer_bytes;
        break;
    case SCSI_WRITE16:
        np = "WRITE(16)";
        if (lba > 0xffffffff) {
            w16CmdBlk[2] = (lba >> 56) & 0xff;
            w16CmdBlk[3] = (lba >> 48) & 0xff;
            w16CmdBlk[4] = (lba >> 40) & 0xff;
            w16CmdBlk[5] = (lba >> 32) & 0xff;
        }
        w16CmdBlk[6] = (lba >> 24) & 0xff;
        w16CmdBlk[7] = (lba >> 16) & 0xff;
        w16CmdBlk[8] = (lba >> 8) & 0xff;
        w16CmdBlk[9] = lba & 0xff;
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

    if (write(sg_fd, &pt, sizeof(pt)) < 0) {
        console_mutex.lock();
        cerr << __func__ << ": " << np << " pack_id=" << pack_id;
        perror(" write(sg)");
        console_mutex.unlock();
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
    unsigned char sense_buffer[64];
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
        console_mutex.lock();
        perror("do_rd_inc_wr_twice: read(sg, READ_16)");
        console_mutex.unlock();
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
        console_mutex.lock();
        fprintf(stderr, "%s: Recovered error on %s, continuing\n",
                __func__, np);
        console_mutex.unlock();
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        console_mutex.lock();
        sg_chk_n_print3(np, &pt, 1);
        console_mutex.unlock();
        break;
    }
    return ok ? 0 : -1;
}

/* Should have page alignment if direct_io chosen */
static unsigned char *
get_aligned_heap(int bytes_at_least)
{
    int n;
    void * wp;

    if (bytes_at_least < page_size)
        n = page_size;
    else
        n = bytes_at_least;
#if 1
    int err = posix_memalign(&wp, page_size, n);
    if (err) {
        console_mutex.lock();
        fprintf(stderr, "posix_memalign: error [%d] out of memory?\n", err);
        console_mutex.unlock();
        return NULL;
    }
    memset(wp, 0, n);
    return (unsigned char *)wp;
#else
    if (n == page_size) {
        wp = calloc(page_size, 1);
        memset(wp, 0, n);
        return (unsigned char *)wp;
    } else {
        console_mutex.lock();
        fprintf(stderr, "get_aligned_heap: too fiddly to align, choose "
                "smaller lb_sz\n");
        console_mutex.unlock();
        return NULL;
    }
#endif
}

static void
work_thread(int id, struct opts_t * op)
{
    int thr_async_starts = 0;
    int thr_async_finishes = 0;
    unsigned int thr_eagain_count = 0;
    int k, res, sg_fd, num_outstanding, do_inc, num, pack_id, sg_flags;
    int open_flags = O_RDWR;
    char ebuff[EBUFF_SZ];
    unsigned char * lbp;
    const char * err = NULL;
    struct pollfd  pfd;
    list<unsigned char *> free_lst;
    map<int, unsigned char *> pi_map;

    if (op->verbose) {
        console_mutex.lock();
        cerr << "Enter work_thread id=" << id << endl;
        console_mutex.unlock();
    }
    if (! op->block)
        open_flags |= O_NONBLOCK;

    sg_fd = open(op->dev_name, open_flags);
    if (sg_fd < 0) {
        snprintf(ebuff, EBUFF_SZ, "%s: id=%d, error opening file: %s",
                 __func__, id, op->dev_name);
        console_mutex.lock();
        perror(ebuff);
        console_mutex.unlock();
        return;
    }
    pfd.fd = sg_fd;
    pfd.events = POLLIN;
    sg_flags = 0;
    if (BQ_AT_TAIL == op->bqd)
        sg_flags |= SG_FLAG_Q_AT_TAIL;
    else if (BQ_AT_HEAD == op->bqd)
        sg_flags |= SG_FLAG_Q_AT_HEAD;
    if (op->direct)
        sg_flags |= SG_FLAG_DIRECT_IO;
    if (op->no_xfer)
        sg_flags |= SG_FLAG_NO_DXFER;
    if (op->verbose > 1) {
        console_mutex.lock();
        fprintf(stderr, "sg_flags=0x%x, %s cmd\n", sg_flags,
                ((SCSI_TUR != op->c2e) ? "TUR": "IO"));
        console_mutex.unlock();
    }

    num = op->num_per_thread;
    for (k = 0, num_outstanding = 0; (k < num) || num_outstanding;
         k = do_inc ? k + 1 : k) {
        do_inc = 0;
        if ((num_outstanding < Q_PER_FD) && (k < num)) {
            do_inc = 1;
            pack_id = uniq_pack_id.fetch_add(1);
            if (SCSI_TUR != op->c2e) {
                if (free_lst.empty()) {
                    lbp = get_aligned_heap(op->lb_sz);
                    if (NULL == lbp) {
                        err = "out of memory";
                        break;
                    }
                } else {
                    lbp = free_lst.back();
                    free_lst.pop_back();
                }
            } else
                lbp = NULL;
            if (start_sg3_cmd(sg_fd, op->c2e, pack_id, op->lba, lbp,
                              op->lb_sz, sg_flags)) {
                err = "start_sg3_cmd() failed";
                break;
            }
            ++thr_async_starts;
            ++num_outstanding;
            pi_map[pack_id] = lbp;
            /* check if any responses, don't wait */
            res = poll(&pfd, 1, 0);
            if (res < 0) {
                err = "poll(0) failed";
                break;
            }
        } else {
            /* check if any responses, wait as requested */
            res = poll(&pfd, 1, ((op->wait_ms > 0) ? op->wait_ms : 0));
            if (res < 0) {
                err = "poll(wait_ms) failed";
                break;
            }
        }
        if (0 == res)
            continue;
        while (res-- > 0) {
            if (finish_sg3_cmd(sg_fd, op->c2e, pack_id, op->wait_ms,
                               thr_eagain_count)) {
                err = "finish_sg3_cmd() failed";
                break;
            }
            ++thr_async_finishes;
            --num_outstanding;
            auto p = pi_map.find(pack_id);

            if (p == pi_map.end()) {
                snprintf(ebuff, sizeof(ebuff), "pack_id=%d from "
                         "finish_sg3_cmd() not found\n", pack_id);
                err = ebuff;
                break;
            } else {
                lbp = p->second;
                pi_map.erase(p);
                if (lbp)
                    free_lst.push_front(lbp);
            }
        }
    }
    close(sg_fd);
    if (err || (k < num) || (op->verbose > 0)) {
        console_mutex.lock();
        if (k < num) {
            cerr << "thread id=" << id << " FAILed at iteration: " << k;
            if (err)
                cerr << " Reason: " << err << endl;
            else
                cerr << endl;
        } else {
            if (err)
                cerr << "thread id=" << id << " FAILed on last, " <<
                        "Reason: " << err << endl;
            else
                cerr << "thread id=" << id << " normal exit" << '\n';
        }
        console_mutex.unlock();
    }
    k = pi_map.size();
    if (k > 0) {
        console_mutex.lock();
            cerr << "thread id=" << id << " Still " << k << " elements " <<
                    "in pack_id map on exit" << endl;
        console_mutex.unlock();
    }
    while (! free_lst.empty()) {
        lbp = free_lst.back();
        free_lst.pop_back();
        if (lbp)
            free(lbp);
    }
    async_starts += thr_async_starts;
    async_finishes += thr_async_finishes;
    eagain_count += thr_eagain_count;
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
    unsigned char inqCmdBlk [INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    unsigned char inqBuff[INQ_REPLY_LEN];
    unsigned char sense_buffer[64];
    char ebuff[EBUFF_SZ];
    int open_flags = O_RDWR;    /* O_EXCL | O_RDONLY fails with EPERM */

    if (! block)
        open_flags |= O_NONBLOCK;
    sg_fd = open(dev_name, open_flags);
    if (sg_fd < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "do_inquiry_prod_id: error opening file: %s", dev_name);
        perror(ebuff);
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
        perror("do_inquiry_prod_id: Inquiry SG_IO ioctl error");
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
        fprintf(stderr, "Recovered error on INQUIRY, continuing\n");
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("INQUIRY command error", &pt, 1);
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


int
main(int argc, char * argv[])
{
    int k, n, res;
    int force = 0;
    int64_t ll;
    unsigned int inq_ebusy_count = 0;
    int num_threads = DEF_NUM_THREADS;
    char b[64];
    struct timespec start_tm, end_tm;
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    op->dev_name = NULL;
    op->direct = !! DEF_DIRECT;
    op->lba = DEF_LBA;
    op->lb_sz = DEF_LB_SZ;;
    op->num_per_thread = DEF_NUM_PER_THREAD;
    op->no_xfer = !! DEF_NO_XFER;
    op->verbose = 0;
    op->wait_ms = DEF_WAIT_MS;
    op->c2e = SCSI_TUR;
    op->bqd = BQ_DEFAULT;
    op->block = !! DEF_BLOCKING;
    page_size = sysconf(_SC_PAGESIZE);

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-d", argv[k], 2))
            op->direct = true;
        else if (0 == memcmp("-f", argv[k], 2))
            ++force;
        else if (0 == memcmp("-h", argv[k], 2)) {
            usage();
            return 0;
        } else if (0 == memcmp("-l", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k])) {
                ll = sg_get_llnum(argv[k]);
                if (-1 == ll) {
                    fprintf(stderr, "could not decode lba\n");
                    return 1;
                } else
                    op->lba = (uint64_t)ll;
            } else
                break;
        } else if (0 == memcmp("-n", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k]))
                op->num_per_thread = atoi(argv[k]);
            else
                break;
        } else if (0 == memcmp("-N", argv[k], 2))
            op->no_xfer = true;
        else if (0 == memcmp("-q", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k])) {
                n = atoi(argv[k]);
                if (0 == n)
                    op->bqd = BQ_AT_HEAD;
                else if (1 == n)
                    op->bqd = BQ_AT_TAIL;
            }
        } else if (0 == memcmp("-R", argv[k], 2))
            op->c2e = SCSI_READ16;
        else if (0 == memcmp("-s", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k])) {
                op->lb_sz = atoi(argv[k]);
                if (op->lb_sz < 256) {
                    cerr << "Strange lb_sz, using 256" << endl;
                    op->lb_sz = 256;
                }
            } else
                break;
        } else if (0 == memcmp("-t", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k]))
                num_threads = atoi(argv[k]);
            else
                break;
        } else if (0 == memcmp("-T", argv[k], 2))
            op->c2e = SCSI_TUR;
        else if (0 == memcmp("-vvvv", argv[k], 5))
            op->verbose += 4;
        else if (0 == memcmp("-vvv", argv[k], 4))
            op->verbose += 3;
        else if (0 == memcmp("-vv", argv[k], 3))
            op->verbose += 2;
        else if (0 == memcmp("-v", argv[k], 2))
            ++op->verbose;
        else if (0 == memcmp("-V", argv[k], 2)) {
            printf("%s version: %s\n", util_name, version_str);
            return 0;
        } else if (0 == memcmp("-w", argv[k], 2)) {
            ++k;
            if ((k < argc) && (isdigit(*argv[k]) || ('-' == *argv[k]))) {
                if ('-' == *argv[k])
                    op->wait_ms = - atoi(argv[k] + 1);
                else
                    op->wait_ms = atoi(argv[k]);
            } else
                break;
        } else if (0 == memcmp("-W", argv[k], 2))
            op->c2e = SCSI_WRITE16;
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            op->dev_name = NULL;
            break;
        }
        else if (! op->dev_name)
            op->dev_name = argv[k];
        else {
            printf("too many arguments\n");
            op->dev_name = NULL;
            break;
        }
    }
    if (0 == op->dev_name) {
        usage();
        return 1;
    }
    try {
        struct stat a_stat;

        if (stat(op->dev_name, &a_stat) < 0) {
            perror("stat() on dev_name failed");
            return 1;
        }
        if (! S_ISCHR(a_stat.st_mode)) {
            fprintf(stderr, "%s should be a sg device which is a char "
                    "device. %s\n", op->dev_name, op->dev_name);
            fprintf(stderr, "is not a char device and damage could be done "
                    "if it is a BLOCK\ndevice, exiting ...\n");
            return 1;
        }
        if (! force) {
            res = do_inquiry_prod_id(op->dev_name, op->block, b, sizeof(b));
            if (res) {
                fprintf(stderr, "INQUIRY failed on %s\n", op->dev_name);
                return 1;
            }
            // For safety, since <lba> written to, only permit scsi_debug
            // devices. Bypass this with '-f' option.
            if (0 != memcmp("scsi_debug", b, 10)) {
                fprintf(stderr, "Since this utility writes to LBA 0x%" PRIx64
                        ", only devices with scsi_debug\n"
                        "product ID accepted\n", op->lba);
                return 2;
            }
            ebusy_count += inq_ebusy_count;
        }
        start_tm.tv_sec = 0;
        start_tm.tv_nsec = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &start_tm) < 0)
            perror("clock_gettime failed");

        vector<thread *> vt;

        for (k = 0; k < num_threads; ++k) {
            thread * tp = new thread {work_thread, k, op};
            vt.push_back(tp);
        }

        // g++ 4.7.3 didn't like range-for loop here
        for (k = 0; k < (int)vt.size(); ++k)
            vt[k]->join();

        for (k = 0; k < (int)vt.size(); ++k)
            delete vt[k];

        n = uniq_pack_id.load() - 1;
        if ((n > 0) && (0 == clock_gettime(CLOCK_MONOTONIC, &end_tm))) {
            struct timespec res_tm;
            double a, b;

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
                cout << "Implies " << (b / a) << " IOPS" << endl;
            }
        }

        if (op->verbose) {
            cout << "Number of async_starts: " << async_starts.load() << endl;
            cout << "Number of async_finishes: " << async_finishes.load() <<
                    endl;
            cout << "Last pack_id: " << n << endl;
            cout << "Number of EBUSYs: " << ebusy_count.load() << endl;
            cout << "Number of EAGAINs: " << eagain_count.load() << endl;
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
