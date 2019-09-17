/*
 * Copyright (c) 2013-2019 Douglas Gilbert.
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
#include <system_error>
#include <thread>
#include <mutex>
#include <chrono>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_unaligned.h"

static const char * version_str = "1.10 20190917";
static const char * util_name = "sg_tst_excl3";

/* This is a test program for checking O_EXCL on open() works. It uses
 * multiple threads and can be run as multiple processes and attempts
 * to "break" O_EXCL. The strategy is to open a device O_EXCL|O_NONBLOCK
 * and do a double increment on a LB then close it from a single thread.
 * the remaining threads open that device O_NONBLOCK and do a read and
 * note if the number is odd. Assuming the count starts as an even
 * (typically 0) then it should remain even. Odd instances
 * are counted and reported at the end of the program, after all threads
 * have completed.
 *
 * This is C++ code with some things from C++11 (e.g. threads) and was
 * only just able to compile (when some things were reverted) with gcc/g++
 * version 4.7.3 found in Ubuntu 13.04 . C++11 "feature complete" support
 * was not available until g++ version 4.8.1 and that is found in Fedora
 * 19 and Ubuntu 13.10 .
 *
 * The build uses various object files from the <sg3_utils>/lib directory
 * which is assumed to be a sibling of this examples directory. Those
 * object files in the lib directory can be built with:
 *   cd <sg3_utils> ; ./configure ; cd lib; make
 * Then:
 *   cd ../testing
 *   make sg_tst_excl3
 *
 * BEWARE: this utility modifies a logical block (default LBA 1000) on the
 * given device.
 *
 */

using namespace std;
using namespace std::chrono;

#define DEF_NUM_PER_THREAD 200
#define DEF_NUM_THREADS 4
#define DEF_WAIT_MS 0          /* 0: yield; -1: don't wait; -2: sleep(0) */

#define DEF_LBA 1000

#define EBUFF_SZ 256


static mutex odd_count_mutex;
static mutex console_mutex;
static unsigned int odd_count;
static unsigned int ebusy_count;


static void
usage(void)
{
    printf("Usage: %s [-b] [-f] [-h] [-l <lba>] [-n <n_per_thr>]\n"
           "                    [-R] [-t <num_thrs>] [-V] [-w <wait_ms>] "
           "[-x]\n"
           "                    <disk_device>\n", util_name);
    printf("  where\n");
    printf("    -b                block on open (def: O_NONBLOCK)\n");
    printf("    -f                force: any SCSI disk (def: only "
           "scsi_debug)\n");
    printf("                      WARNING: <lba> written to\n");
    printf("    -h                print this usage message then exit\n");
    printf("    -l <lba>          logical block to increment (def: %u)\n",
           DEF_LBA);
    printf("    -n <n_per_thr>    number of loops per thread "
           "(def: %d)\n", DEF_NUM_PER_THREAD);
    printf("    -R                all readers; so first thread (id=0) "
           "just reads\n");
    printf("    -t <num_thrs>     number of threads (def: %d)\n",
           DEF_NUM_THREADS);
    printf("    -V                print version number then exit\n");
    printf("    -w <wait_ms>      >0: sleep_for(<wait_ms>); =0: "
           "yield(); -1: no\n"
           "                      wait; -2: sleep(0)  (def: %d)\n",
           DEF_WAIT_MS);
    printf("    -x                don't use O_EXCL on first thread "
           "(def: use\n"
           "                      O_EXCL on first thread)\n\n");
    printf("Test O_EXCL open flag with pass-through drivers. First thread "
           "(id=0) does\nopen/close cycle with the O_EXCL flag then does a "
           "double increment on\nlba (using its first 4 bytes). Remaining "
           "theads read (without\nO_EXCL flag on open) and check the "
           "value is even.\n");
}

/* Assumed a lock (mutex) held when pt_err() is called */
static int
pt_err(int res)
{
    if (res < 0)
        fprintf(stderr, "  pass through os error: %s\n", safe_strerror(-res));
    else if (SCSI_PT_DO_BAD_PARAMS == res)
        fprintf(stderr, "  bad pass through setup\n");
    else if (SCSI_PT_DO_TIMEOUT == res)
        fprintf(stderr, "  pass through timeout\n");
    else
        fprintf(stderr, "  do_scsi_pt error=%d\n", res);
    return -1;
}

/* Assumed a lock (mutex) held when pt_cat_no_good() is called */
static int
pt_cat_no_good(int cat, struct sg_pt_base * ptp, const unsigned char * sbp)
{
    int slen;
    char b[256];
    const int bl = (int)sizeof(b);

    switch (cat) {
    case SCSI_PT_RESULT_STATUS: /* other than GOOD and CHECK CONDITION */
        sg_get_scsi_status_str(get_scsi_pt_status_response(ptp), bl, b);
        fprintf(stderr, "  scsi status: %s\n", b);
        break;
    case SCSI_PT_RESULT_SENSE:
        slen = get_scsi_pt_sense_len(ptp);
        sg_get_sense_str("", sbp, slen, 1, bl, b);
        fprintf(stderr, "%s", b);
        break;
    case SCSI_PT_RESULT_TRANSPORT_ERR:
        get_scsi_pt_transport_err_str(ptp, bl, b);
        fprintf(stderr, "  transport: %s", b);
        break;
    case SCSI_PT_RESULT_OS_ERR:
        get_scsi_pt_os_err_str(ptp, bl, b);
        fprintf(stderr, "  os: %s", b);
        break;
    default:
        fprintf(stderr, "  unknown pt result category (%d)\n", cat);
        break;
    }
    return -1;
}

#define READ16_REPLY_LEN 512
#define READ16_CMD_LEN 16
#define WRITE16_REPLY_LEN 512
#define WRITE16_CMD_LEN 16

/* Opens dev_name and spins if busy (i.e. gets EBUSY), sleeping for
 * wait_ms milliseconds if wait_ms is positive. Reads lba and treats the
 * first 4 bytes as an int (SCSI endian), increments it and writes it back.
 * Repeats so that happens twice. Then closes dev_name. If an error occurs
 * returns -1 else returns 0 if first int read is even otherwise returns 1. */
static int
do_rd_inc_wr_twice(const char * dev_name, int read_only, unsigned int lba,
                   int block, int excl, int wait_ms, unsigned int & ebusys)
{
    int k, sg_fd, res, cat;
    int odd = 0;
    unsigned int u = 0;
    struct sg_pt_base * ptp = NULL;
    unsigned char r16CmdBlk [READ16_CMD_LEN] =
                {0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    unsigned char w16CmdBlk [WRITE16_CMD_LEN] =
                {0x8a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    unsigned char sense_buffer[64];
    unsigned char lb[READ16_REPLY_LEN];
    char ebuff[EBUFF_SZ];
    int open_flags = O_RDWR;

    sg_put_unaligned_be64(lba, r16CmdBlk + 2);
    sg_put_unaligned_be64(lba, w16CmdBlk + 2);
    if (! block)
        open_flags |= O_NONBLOCK;
    if (excl)
        open_flags |= O_EXCL;

    while (((sg_fd = scsi_pt_open_flags(dev_name, open_flags, 0)) < 0) &&
           (-EBUSY == sg_fd)) {
        ++ebusys;
        if (wait_ms > 0)
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();       // thread yield
        else if (-2 == wait_ms)
            sleep(0);                   // process yield ??
    }
    if (sg_fd < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "do_rd_inc_wr_twice: error opening file: %s", dev_name);
        {
            lock_guard<mutex> lg(console_mutex);

            perror(ebuff);
        }
        return -1;
    }

    ptp = construct_scsi_pt_obj();
    for (k = 0; k < 2; ++k) {
        /* Prepare READ_16 command */
        clear_scsi_pt_obj(ptp);
        set_scsi_pt_cdb(ptp, r16CmdBlk, sizeof(r16CmdBlk));
        set_scsi_pt_sense(ptp, sense_buffer, sizeof(sense_buffer));
        set_scsi_pt_data_in(ptp, lb, READ16_REPLY_LEN);
        res = do_scsi_pt(ptp, sg_fd, 20 /* secs timeout */, 1);
        if (res) {
            {
                lock_guard<mutex> lg(console_mutex);

                fprintf(stderr, "READ_16 do_scsi_pt() submission error\n");
                res = pt_err(res);
            }
            goto err;
        }
        cat = get_scsi_pt_result_category(ptp);
        if (SCSI_PT_RESULT_GOOD != cat) {
            {
                lock_guard<mutex> lg(console_mutex);

                fprintf(stderr, "READ_16 do_scsi_pt() category problem\n");
                res = pt_cat_no_good(cat, ptp, sense_buffer);
            }
            goto err;
        }

        u = sg_get_unaligned_be32(lb);
        // Assuming u starts test as even (probably 0), expect it to stay even
        if (0 == k)
            odd = (1 == (u % 2));

        if (wait_ms > 0)       /* allow daylight for bad things ... */
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();       // thread yield
        else if (-2 == wait_ms)
            sleep(0);                   // process yield ??

        if (read_only)
            break;
        ++u;
        sg_put_unaligned_be32(u, lb);

        /* Prepare WRITE_16 command */
        clear_scsi_pt_obj(ptp);
        set_scsi_pt_cdb(ptp, w16CmdBlk, sizeof(w16CmdBlk));
        set_scsi_pt_sense(ptp, sense_buffer, sizeof(sense_buffer));
        set_scsi_pt_data_out(ptp, lb, WRITE16_REPLY_LEN);
        res = do_scsi_pt(ptp, sg_fd, 20 /* secs timeout */, 1);
        if (res) {
            {
                lock_guard<mutex> lg(console_mutex);

                fprintf(stderr, "WRITE_16 do_scsi_pt() submission error\n");
                res = pt_err(res);
            }
            goto err;
        }
        cat = get_scsi_pt_result_category(ptp);
        if (SCSI_PT_RESULT_GOOD != cat) {
            {
                lock_guard<mutex> lg(console_mutex);

                fprintf(stderr, "WRITE_16 do_scsi_pt() category problem\n");
                res = pt_cat_no_good(cat, ptp, sense_buffer);
            }
            goto err;
        }
    }
err:
    if (ptp)
        destruct_scsi_pt_obj(ptp);
    scsi_pt_close_device(sg_fd);
    return odd;
}


#define INQ_REPLY_LEN 96
#define INQ_CMD_LEN 6

/* Send INQUIRY and fetches response. If okay puts PRODUCT ID field
 * in b (up to m_blen bytes). Does not use O_EXCL flag. Returns 0 on success,
 * else -1 . */
static int
do_inquiry_prod_id(const char * dev_name, int block, int wait_ms,
                   unsigned int & ebusys, char * b, int b_mlen)
{
    int sg_fd, res, cat;
    struct sg_pt_base * ptp = NULL;
    unsigned char inqCmdBlk [INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    unsigned char inqBuff[INQ_REPLY_LEN];
    unsigned char sense_buffer[64];
    char ebuff[EBUFF_SZ];
    int open_flags = O_RDWR;    /* since O_EXCL | O_RDONLY gives EPERM */

    if (! block)
        open_flags |= O_NONBLOCK;
    while (((sg_fd = scsi_pt_open_flags(dev_name, open_flags, 0)) < 0) &&
           (-EBUSY == sg_fd)) {
        ++ebusys;
        if (wait_ms > 0)
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();       // thread yield
        else if (-2 == wait_ms)
            sleep(0);                   // process yield ??
    }
    if (sg_fd < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "do_inquiry_prod_id: error opening file: %s", dev_name);
        perror(ebuff);
        return -1;
    }
    /* Prepare INQUIRY command */
    ptp = construct_scsi_pt_obj();
    clear_scsi_pt_obj(ptp);
    set_scsi_pt_cdb(ptp, inqCmdBlk, sizeof(inqCmdBlk));
    set_scsi_pt_sense(ptp, sense_buffer, sizeof(sense_buffer));
    set_scsi_pt_data_in(ptp, inqBuff, INQ_REPLY_LEN);
    res = do_scsi_pt(ptp, sg_fd, 20 /* secs timeout */, 1);
    if (res) {
        fprintf(stderr, "INQUIRY do_scsi_pt() submission error\n");
        res = pt_err(res);
        goto err;
    }
    cat = get_scsi_pt_result_category(ptp);
    if (SCSI_PT_RESULT_GOOD != cat) {
        fprintf(stderr, "INQUIRY do_scsi_pt() category problem\n");
        res = pt_cat_no_good(cat, ptp, sense_buffer);
        goto err;
    }

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
err:
    if (ptp)
        destruct_scsi_pt_obj(ptp);
    close(sg_fd);
    return res;
}

static void
work_thread(const char * dev_name, unsigned int lba, int id, int block,
            int excl, bool all_readers, int num, int wait_ms)
{
    unsigned int thr_odd_count = 0;
    unsigned int thr_ebusy_count = 0;
    int k, res;
    int reader = ((id > 0) || (all_readers));

    {
        lock_guard<mutex> lg(console_mutex);

        cerr << "Enter work_thread id=" << id << " excl=" << excl << " block="
             << block << " reader=" << reader << endl;
    }
    for (k = 0; k < num; ++k) {
        res = do_rd_inc_wr_twice(dev_name, reader, lba, block, excl,
                                 wait_ms, thr_ebusy_count);
        if (res < 0)
            break;
        if (res)
            ++thr_odd_count;
    }
    {
        lock_guard<mutex> lg(console_mutex);

        if (k < num)
            cerr << "thread id=" << id << " FAILed at iteration: " << k
                 << '\n';
        else
            cerr << "thread id=" << id << " normal exit" << '\n';
    }

    {
        lock_guard<mutex> lg(odd_count_mutex);

        odd_count += thr_odd_count;
        ebusy_count += thr_ebusy_count;
    }
}


int
main(int argc, char * argv[])
{
    int k, res;
    int block = 0;
    int force = 0;
    unsigned int lba = DEF_LBA;
    int num_per_thread = DEF_NUM_PER_THREAD;
    bool all_readers = false;
    int num_threads = DEF_NUM_THREADS;
    int wait_ms = DEF_WAIT_MS;
    int exclude_o_excl = 0;
    char * dev_name = NULL;
    char b[64];

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-b", argv[k], 2))
            ++block;
        else if (0 == memcmp("-f", argv[k], 2))
            ++force;
        else if (0 == memcmp("-h", argv[k], 2)) {
            usage();
            return 0;
        } else if (0 == memcmp("-l", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k]))
                lba = (unsigned int)atoi(argv[k]);
            else
                break;
        } else if (0 == memcmp("-n", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k]))
                num_per_thread = atoi(argv[k]);
            else
                break;
        } else if (0 == memcmp("-t", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k]))
                num_threads = atoi(argv[k]);
            else
                break;
        } else if (0 == memcmp("-R", argv[k], 2))
            all_readers = true;
        else if (0 == memcmp("-V", argv[k], 2)) {
            printf("%s version: %s\n", util_name, version_str);
            return 0;
        } else if (0 == memcmp("-w", argv[k], 2)) {
            ++k;
            if ((k < argc) && (isdigit(*argv[k]) || ('-' == *argv[k]))) {
                if ('-' == *argv[k])
                    wait_ms = - atoi(argv[k] + 1);
                else
                    wait_ms = atoi(argv[k]);
            } else
                break;
        } else if (0 == memcmp("-x", argv[k], 2))
            ++exclude_o_excl;
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            dev_name = NULL;
            break;
        }
        else if (! dev_name)
            dev_name = argv[k];
        else {
            printf("too many arguments\n");
            dev_name = 0;
            break;
        }
    }
    if (0 == dev_name) {
        usage();
        return 1;
    }
    try {

        if (! force) {
            res = do_inquiry_prod_id(dev_name, block, wait_ms, ebusy_count,
                                     b, sizeof(b));
            if (res) {
                fprintf(stderr, "INQUIRY failed on %s\n", dev_name);
                return 1;
            }
            // For safety, since <lba> written to, only permit scsi_debug
            // devices. Bypass this with '-f' option.
            if (0 != memcmp("scsi_debug", b, 10)) {
                fprintf(stderr, "Since this utility writes to LBA %d, only "
                        "devices with scsi_debug\nproduct ID accepted.\n",
                        lba);
                return 2;
            }
        }

        vector<thread *> vt;

        for (k = 0; k < num_threads; ++k) {
            int excl = ((0 == k) && (! exclude_o_excl)) ? 1 : 0;

            thread * tp = new thread {work_thread, dev_name, lba, k, block,
                                      excl, all_readers, num_per_thread,
                                      wait_ms};
            vt.push_back(tp);
        }

        for (k = 0; k < (int)vt.size(); ++k)
            vt[k]->join();

        for (k = 0; k < (int)vt.size(); ++k)
            delete vt[k];

        cout << "Expecting odd count of 0, got " << odd_count << endl;
        cout << "Number of EBUSYs: " << ebusy_count << endl;

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
