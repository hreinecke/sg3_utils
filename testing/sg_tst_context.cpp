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

static const char * version_str = "1.05 20190917";
static const char * util_name = "sg_tst_context";

/* This is a test program for checking that file handles keep their
 * context properly when sent (synchronous) SCSI pass-through commands.
 * A disk device is assumed and even-numbered threads send TEST UNIT
 * READY commands while odd-numbered threads send alternating START STOP
 * UNIT commands (i.e. start then stop then start, etc). The point is to
 * check the results to make sure that they don't get the other command's
 * response. For example a START STOP UNIT command should not see a "not
 * ready" sense key.
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
 *   make sg_tst_context
 *
 */

using namespace std;
using namespace std::chrono;

#define DEF_NUM_PER_THREAD 200
#define DEF_NUM_THREADS 2

#define EBUFF_SZ 256


static mutex count_mutex;
static mutex console_mutex;
static unsigned int even_notreadys;
static unsigned int odd_notreadys;
static unsigned int ebusy_count;
static int verbose;


static void
usage(void)
{
    printf("Usage: %s [-e] [-h] [-n <n_per_thr>] [-N] [-R] [-s]\n"
           "                      [-t <num_thrs>] [-v] [-V] <disk_device>\n",
           util_name);
    printf("  where\n");
    printf("    -e                use O_EXCL on open (def: don't)\n");
    printf("    -h                print this usage message then exit\n");
    printf("    -n <n_per_thr>    number of loops per thread "
           "(def: %d)\n", DEF_NUM_PER_THREAD);
    printf("    -N                use O_NONBLOCK on open (def: don't)\n");
    printf("    -R                make sure device in ready (started) "
           "state after\n"
           "                      test (do extra iteration if "
           "necessary)\n");
    printf("    -s                share an open file handle (def: one "
           "per thread)\n");
    printf("    -t <num_thrs>     number of threads (def: %d)\n",
           DEF_NUM_THREADS);
    printf("    -v                increase verbosity\n");
    printf("    -V                print version number then exit\n\n");
    printf("Test if file handles keep context through to their responses. "
           "Sends\nTEST UNIT READY commands on even threads (origin 0) and "
           "START STOP\nUNIT commands on odd threads. Expect NOT READY "
           "sense keys only\nfrom the even threads (i.e from TUR)\n");
}

static int
pt_err(int res)
{
    if (res < 0)
        fprintf(stderr, "  pass through OS error: %s\n", safe_strerror(-res));
    else if (SCSI_PT_DO_BAD_PARAMS == res)
        fprintf(stderr, "  bad pass through setup\n");
    else if (SCSI_PT_DO_TIMEOUT == res)
        fprintf(stderr, "  pass through timeout\n");
    else
        fprintf(stderr, "  do_scsi_pt error=%d\n", res);
    return (res < 0) ? res : -EPERM /* -1 */;
}

static int
pt_cat_no_good(int cat, struct sg_pt_base * ptp, const unsigned char * sbp)
{
    int slen;
    char b[256];
    const int bl = (int)sizeof(b);
    const char * cp = NULL;

    b[0] = '\0';
    switch (cat) {
    case SCSI_PT_RESULT_STATUS: /* other than GOOD and CHECK CONDITION */
        sg_get_scsi_status_str(get_scsi_pt_status_response(ptp), bl, b);
        cp = "  scsi status: %s\n";
        break;
    case SCSI_PT_RESULT_SENSE:
        slen = get_scsi_pt_sense_len(ptp);
        sg_get_sense_str("", sbp, slen, 1, bl, b);
        cp = "%s\n";
        break;
    case SCSI_PT_RESULT_TRANSPORT_ERR:
        get_scsi_pt_transport_err_str(ptp, bl, b);
        cp = "  transport: %s\n";
        break;
    case SCSI_PT_RESULT_OS_ERR:
        get_scsi_pt_os_err_str(ptp, bl, b);
        cp = "  os: %s\n";
        break;
    default:
        cp = "  unknown pt result category (%d)\n";
        break;
    }
    if (cp) {
        lock_guard<mutex> lg(console_mutex);

        fprintf(stderr, cp, b);
    }
    return -EIO /* -5 */;
}

#define TUR_CMD_LEN 6
#define SSU_CMD_LEN 6
#define NOT_READY SG_LIB_CAT_NOT_READY

/* Returns 0 for good, 1024 for a sense key of NOT_READY, or a negative
 * errno */
static int
do_tur(struct sg_pt_base * ptp, int id)
{
    int slen, res, cat;
    unsigned char turCmdBlk [TUR_CMD_LEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    unsigned char sense_buffer[64];

    clear_scsi_pt_obj(ptp);
    set_scsi_pt_cdb(ptp, turCmdBlk, sizeof(turCmdBlk));
    set_scsi_pt_sense(ptp, sense_buffer, sizeof(sense_buffer));
    res = do_scsi_pt(ptp, -1, 20 /* secs timeout */, verbose);
    if (res) {
        {
            lock_guard<mutex> lg(console_mutex);

            fprintf(stderr, "TEST UNIT READY do_scsi_pt() submission error, "
                    "id=%d\n", id);
        }
        res = pt_err(res);
        goto err;
    }
    cat = get_scsi_pt_result_category(ptp);
    if (SCSI_PT_RESULT_GOOD != cat) {
        slen = get_scsi_pt_sense_len(ptp);
        if ((SCSI_PT_RESULT_SENSE == cat) &&
            (NOT_READY == sg_err_category_sense(sense_buffer, slen))) {
            res = 1024;
            goto err;
        }
        {
            lock_guard<mutex> lg(console_mutex);

            fprintf(stderr, "TEST UNIT READY do_scsi_pt() category problem, "
                    "id=%d\n", id);
        }
        res = pt_cat_no_good(cat, ptp, sense_buffer);
        goto err;
    }
    res = 0;
err:
    return res;
}

/* Returns 0 for good, 1024 for a sense key of NOT_READY, or a negative
 * errno */
static int
do_ssu(struct sg_pt_base * ptp, int id, bool start)
{
    int slen, res, cat;
    unsigned char ssuCmdBlk [SSU_CMD_LEN] = {0x1b, 0x0, 0x0, 0x0, 0x0, 0x0};
    unsigned char sense_buffer[64];

    if (start)
        ssuCmdBlk[4] |= 0x1;
    clear_scsi_pt_obj(ptp);
    set_scsi_pt_cdb(ptp, ssuCmdBlk, sizeof(ssuCmdBlk));
    set_scsi_pt_sense(ptp, sense_buffer, sizeof(sense_buffer));
    res = do_scsi_pt(ptp, -1, 40 /* secs timeout */, verbose);
    if (res) {
        {
            lock_guard<mutex> lg(console_mutex);

            fprintf(stderr, "START STOP UNIT do_scsi_pt() submission error, "
                    "id=%d\n", id);
        }
        res = pt_err(res);
        goto err;
    }
    cat = get_scsi_pt_result_category(ptp);
    if (SCSI_PT_RESULT_GOOD != cat) {
        slen = get_scsi_pt_sense_len(ptp);
        if ((SCSI_PT_RESULT_SENSE == cat) &&
            (NOT_READY == sg_err_category_sense(sense_buffer, slen))) {
            res = 1024;
            goto err;
        }
        {
            lock_guard<mutex> lg(console_mutex);

            fprintf(stderr, "START STOP UNIT do_scsi_pt() category problem, "
                    "id=%d\n", id);
        }
        res = pt_cat_no_good(cat, ptp, sense_buffer);
        goto err;
    }
    res = 0;
err:
    return res;
}

static void
work_thread(const char * dev_name, int id, int num, bool share,
            int pt_fd, int nonblock, int oexcl, bool ready_after)
{
    bool started = true;
    int k;
    int res = 0;
    unsigned int thr_even_notreadys = 0;
    unsigned int thr_odd_notreadys = 0;
    unsigned int thr_ebusy_count = 0;
    struct sg_pt_base * ptp = NULL;
    char ebuff[EBUFF_SZ];

    {
        lock_guard<mutex> lg(console_mutex);

        cerr << "Enter work_thread id=" << id << " num=" << num << " share="
             << share << endl;
    }
    if (! share) {      /* ignore passed ptp, make this thread's own */
        int oflags = O_RDWR;

        if (nonblock)
            oflags |= O_NONBLOCK;
        if (oexcl)
            oflags |= O_EXCL;
        while (((pt_fd = scsi_pt_open_flags(dev_name, oflags, verbose)) < 0)
               && (-EBUSY == pt_fd)) {
            ++thr_ebusy_count;
            this_thread::yield();       // give other threads a chance
        }
        if (pt_fd < 0) {
            snprintf(ebuff, EBUFF_SZ, "work_thread id=%d: error opening: %s",
                     id, dev_name);
            perror(ebuff);
            return;
        }
        if (thr_ebusy_count) {
            lock_guard<mutex> lg(count_mutex);

            ebusy_count += thr_ebusy_count;
        }
    }
    /* The instance of 'struct sg_pt_base' is local to this thread but the
     * pt_fd it contains may be shared, depending on the 'share' boolean. */
    ptp = construct_scsi_pt_obj_with_fd(pt_fd, verbose);
    if (NULL == ptp) {
        fprintf(stderr, "work_thread id=%d: "
                "construct_scsi_pt_obj_with_fd() failed, memory?\n", id);
        return;
    }
    for (k = 0; k < num; ++k) {
        if (0 == (id % 2)) {
            /* Even thread ids do TEST UNIT READYs */
            res = do_tur(ptp, id);
            if (1024 == res) {
                ++thr_even_notreadys;
                res = 0;
            }
        } else {
            /* Odd thread ids do START STOP UNITs, alternating between
             * starts and stops */
            started = (0 == (k % 2));
            res = do_ssu(ptp, id, started);
            if (1024 == res) {
                ++thr_odd_notreadys;
                res = 0;
            }
        }
        if (res)
            break;
        if (ready_after && (! started))
            do_ssu(ptp, id, true);
    }
    if (ptp)
        destruct_scsi_pt_obj(ptp);
    if ((! share) && (pt_fd >= 0))
        close(pt_fd);

    {
        lock_guard<mutex> lg(count_mutex);

        even_notreadys += thr_even_notreadys;
        odd_notreadys += thr_odd_notreadys;
    }

    {
        lock_guard<mutex> lg(console_mutex);

        if (k < num)
            cerr << "thread id=" << id << " FAILed at iteration: " << k
                 << "  [negated errno: " << res << " <"
                 <<  safe_strerror(-res) << ">]" << endl;
        else
            cerr << "thread id=" << id << " normal exit" << '\n';
    }
}


int
main(int argc, char * argv[])
{
    int k;
    int pt_fd = -1;
    int oexcl = 0;
    int nonblock = 0;
    int num_per_thread = DEF_NUM_PER_THREAD;
    bool ready_after = false;
    bool share = false;
    int num_threads = DEF_NUM_THREADS;
    char * dev_name = NULL;
    char ebuff[EBUFF_SZ];

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-e", argv[k], 2))
            ++oexcl;
        else if (0 == memcmp("-h", argv[k], 2)) {
            usage();
            return 0;
        } else if (0 == memcmp("-n", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k])) {
                num_per_thread = sg_get_num(argv[k]);
                if (num_per_thread<= 0) {
                    fprintf(stderr, "want positive integer for number "
                            "per thread\n");
                    return 1;
                }
            } else
                break;
        } else if (0 == memcmp("-N", argv[k], 2))
            ++nonblock;
        else if (0 == memcmp("-R", argv[k], 2))
            ready_after = true;
        else if (0 == memcmp("-s", argv[k], 2))
            share = true;
        else if (0 == memcmp("-t", argv[k], 2)) {
            ++k;
            if ((k < argc) && isdigit(*argv[k]))
                num_threads = atoi(argv[k]);
            else
                break;
        } else if (0 == memcmp("-v", argv[k], 2))
            ++verbose;
        else if (0 == memcmp("-V", argv[k], 2)) {
            printf("%s version: %s\n", util_name, version_str);
            return 0;
        } else if (*argv[k] == '-') {
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
        if (share) {
            int oflags = O_RDWR;

            if (nonblock)
                oflags |= O_NONBLOCK;
            if (oexcl)
                oflags |= O_EXCL;
            while (((pt_fd = scsi_pt_open_flags(dev_name, oflags, verbose))
                    < 0) && (-EBUSY == pt_fd)) {
                ++ebusy_count;
                sleep(0);                   // process yield ??
            }
            if (pt_fd < 0) {
                snprintf(ebuff, EBUFF_SZ, "main: error opening: %s",
                         dev_name);
                perror(ebuff);
                return 1;
            }
            /* Tried calling construct_scsi_pt_obj_with_fd() here but that
             * doesn't work since 'struct sg_pt_base' objects aren't
             * thread-safe without user space intervention (e.g. mutexes). */
        }

        vector<thread *> vt;

        for (k = 0; k < num_threads; ++k) {
            thread * tp = new thread {work_thread, dev_name, k,
                                      num_per_thread, share, pt_fd, nonblock,
                                      oexcl, ready_after};
            vt.push_back(tp);
        }

        for (k = 0; k < (int)vt.size(); ++k)
            vt[k]->join();

        for (k = 0; k < (int)vt.size(); ++k)
            delete vt[k];

        if (share)
            scsi_pt_close_device(pt_fd);

        cout << "Expected not_readys on TEST UNIT READY: " << even_notreadys
             << endl;
        cout << "UNEXPECTED not_readys on START STOP UNIT: "
             << odd_notreadys << endl;
        if (ebusy_count)
            cout << "Number of EBUSYs (on open): " << ebusy_count << endl;

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
    if (pt_fd >= 0)
        close(pt_fd);
    return 0;
}
