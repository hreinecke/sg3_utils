/*
 * Copyright (c) 2013-2014 Douglas Gilbert.
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
#include "sg_io_linux.h"

static const char * version_str = "1.09 20140828";
static const char * util_name = "sg_tst_excl";

/* This is a test program for checking O_EXCL on open() works. It uses
 * multiple threads and can be run as multiple processes and attempts
 * to "break" O_EXCL. The strategy is to open a device O_EXCL|O_NONBLOCK
 * and do a double increment on a LB then close it. Prior to the first
 * increment, the value is checked for even or odd. Assuming the count
 * starts as an even (typically 0) then it should remain even. Odd instances
 * are counted and reported at the end of the program, after all threads
 * have completed.
 *
 * This is C++ code with some things from C++11 (e.g. threads) and was
 * only just able to compile (when some things were reverted) with gcc/g++
 * version 4.7.3 found in Ubuntu 13.04 . C++11 "feature complete" support
 * was not available until g++ version 4.8.1 and that is only currently
 * found in Fedora 19 .
 *
 * The build uses various object files from the <sg3_utils>/lib directory
 * which is assumed to be a sibling of this examples directory. Those
 * object files in the lib directory can be built with:
 *   cd <sg3_utils> ; ./configure ; cd lib; make
 * Then to build sg_tst_excl concatenate the next 3 lines:
 *   g++ -Wall -std=c++11 -pthread -I ../include ../lib/sg_lib.o
 *     ../lib/sg_lib_data.o ../lib/sg_io_linux.o -o sg_tst_excl
 *     sg_tst_excl.cpp
 * or use the C++ Makefile in that directory:
 *   make -f Makefile.cplus sg_tst_excl
 *
 * Currently this utility is Linux only and assumes the SG_IO v3 interface
 * which is supported by sg and block devices (but not bsg devices which
 * require the SG_IO v4 interface). This restriction is relaxed in the
 * sg_tst_excl2 variant of this utility.
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
static unsigned int eagain_count;


static void
usage(void)
{
    printf("Usage: %s [-b] [-f] [-h] [-l <lba>] [-n <n_per_thr>] "
           "[-t <num_thrs>]\n"
           "                   [-V] [-w <wait_ms>] [-x] [-xx] "
           "<sg_disk_device>\n", util_name);
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
    printf("    -t <num_thrs>     number of threads (def: %d)\n",
           DEF_NUM_THREADS);
    printf("    -V                print version number then exit\n");
    printf("    -w <wait_ms>      >0: sleep_for(<wait_ms>); =0: "
           "yield(); -1: no\n"
           "                      wait; -2: sleep(0)  (def: %d)\n",
           DEF_WAIT_MS);
    printf("    -x                don't use O_EXCL on first thread "
           "(def: use\n"
           "                      O_EXCL on all threads)\n"
           "    -xx               don't use O_EXCL on any thread\n\n");
    printf("Test O_EXCL open flag with Linux sg driver. Each open/close "
           "cycle with the\nO_EXCL flag does a double increment on "
           "lba (using its first 4 bytes).\nEach increment uses a READ_16, "
           "READ_16, increment, WRITE_16 cycle. The two\nREAD_16s are "
           "launched asynchronously. Note that '-xx' will run test\n"
           "without any O_EXCL flags.\n");
}


#define READ16_REPLY_LEN 512
#define READ16_CMD_LEN 16
#define WRITE16_REPLY_LEN 512
#define WRITE16_CMD_LEN 16

/* Opens dev_name and spins if busy (i.e. gets EBUSY), sleeping for
 * wait_ms milliseconds if wait_ms is positive.
 * Reads lba (twice) and treats the first 4 bytes as an int (SCSI endian),
 * increments it and writes it back. Repeats so that happens twice. Then
 * closes dev_name. If an error occurs returns -1 else returns 0 if
 * first int read from lba is even otherwise returns 1. */
static int
do_rd_inc_wr_twice(const char * dev_name, unsigned int lba, int block,
                   int excl, int wait_ms, int id, unsigned int & ebusy,
                   unsigned int & eagains)
{
    int k, sg_fd, ok, res;
    int odd = 0;
    unsigned int u = 0;
    struct sg_io_hdr pt, pt2;
    unsigned char r16CmdBlk [READ16_CMD_LEN] =
                {0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    unsigned char w16CmdBlk [WRITE16_CMD_LEN] =
                {0x8a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    unsigned char sense_buffer[64];
    unsigned char lb[READ16_REPLY_LEN];
    char ebuff[EBUFF_SZ];
    int open_flags = O_RDWR;

    r16CmdBlk[6] = w16CmdBlk[6] = (lba >> 24) & 0xff;
    r16CmdBlk[7] = w16CmdBlk[7] = (lba >> 16) & 0xff;
    r16CmdBlk[8] = w16CmdBlk[8] = (lba >> 8) & 0xff;
    r16CmdBlk[9] = w16CmdBlk[9] = lba & 0xff;
    if (! block)
        open_flags |= O_NONBLOCK;
    if (excl)
        open_flags |= O_EXCL;

    while (((sg_fd = open(dev_name, open_flags)) < 0) &&
           (EBUSY == errno)) {
        ++ebusy;
        if (wait_ms > 0)
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();
        else if (-2 == wait_ms)
            sleep(0);                   // process yield ??
    }
    if (sg_fd < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "do_rd_inc_wr_twice: error opening file: %s", dev_name);
        perror(ebuff);
        return -1;
    }

    for (k = 0; k < 2; ++k) {
        /* Prepare READ_16 command */
        memset(&pt, 0, sizeof(pt));
        pt.interface_id = 'S';
        pt.cmd_len = sizeof(r16CmdBlk);
        pt.mx_sb_len = sizeof(sense_buffer);
        pt.dxfer_direction = SG_DXFER_FROM_DEV;
        pt.dxfer_len = READ16_REPLY_LEN;
        pt.dxferp = lb;
        pt.cmdp = r16CmdBlk;
        pt.sbp = sense_buffer;
        pt.timeout = 20000;     /* 20000 millisecs == 20 seconds */
        pt.pack_id = id;

        // queue up two READ_16s to same LBA
        if (write(sg_fd, &pt, sizeof(pt)) < 0) {
            {
                lock_guard<mutex> lg(console_mutex);

                perror("do_rd_inc_wr_twice: write(sg, READ_16)");
            }
            close(sg_fd);
            return -1;
        }
        pt2 = pt;
        if (write(sg_fd, &pt2, sizeof(pt2)) < 0) {
            {
                lock_guard<mutex> lg(console_mutex);

                perror("do_rd_inc_wr_twice: write(sg, READ_16) 2");
            }
            close(sg_fd);
            return -1;
        }

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
            {
                lock_guard<mutex> lg(console_mutex);

                perror("do_rd_inc_wr_twice: read(sg, READ_16)");
            }
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
            {
                lock_guard<mutex> lg(console_mutex);

                fprintf(stderr, "Recovered error on READ_16, continuing\n");
            }
            ok = 1;
            break;
        default: /* won't bother decoding other categories */
            {
                lock_guard<mutex> lg(console_mutex);

                sg_chk_n_print3("READ_16 command error", &pt, 1);
            }
            break;
        }
        if (ok) {
            while (((res = read(sg_fd, &pt2, sizeof(pt2))) < 0) &&
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
                {
                    lock_guard<mutex> lg(console_mutex);

                    perror("do_rd_inc_wr_twice: read(sg, READ_16) 2");
                }
                close(sg_fd);
                return -1;
            }
            pt = pt2;
            /* now for the error processing */
            ok = 0;
            switch (sg_err_category3(&pt)) {
            case SG_LIB_CAT_CLEAN:
                ok = 1;
                break;
            case SG_LIB_CAT_RECOVERED:
                {
                    lock_guard<mutex> lg(console_mutex);

                    fprintf(stderr, "Recovered error on READ_16, continuing "
                            "2\n");
                }
                ok = 1;
                break;
            default: /* won't bother decoding other categories */
                {
                    lock_guard<mutex> lg(console_mutex);

                    sg_chk_n_print3("READ_16 command error 2", &pt, 1);
                }
                break;
            }
        }
        if (! ok) {
            close(sg_fd);
            return -1;
        }

        u = (lb[0] << 24) + (lb[1] << 16) + (lb[2] << 8) + lb[3];
        if (0 == k)
            odd = (1 == (u % 2));
        ++u;
        lb[0] = (u >> 24) & 0xff;
        lb[1] = (u >> 16) & 0xff;
        lb[2] = (u >> 8) & 0xff;
        lb[3] = u & 0xff;

        if (wait_ms > 0)       /* allow daylight for bad things ... */
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();
        else if (-2 == wait_ms)
            sleep(0);                   // process yield ??

        /* Prepare WRITE_16 command */
        memset(&pt, 0, sizeof(pt));
        pt.interface_id = 'S';
        pt.cmd_len = sizeof(w16CmdBlk);
        pt.mx_sb_len = sizeof(sense_buffer);
        pt.dxfer_direction = SG_DXFER_TO_DEV;
        pt.dxfer_len = WRITE16_REPLY_LEN;
        pt.dxferp = lb;
        pt.cmdp = w16CmdBlk;
        pt.sbp = sense_buffer;
        pt.timeout = 20000;     /* 20000 millisecs == 20 seconds */
        pt.pack_id = id;

        if (ioctl(sg_fd, SG_IO, &pt) < 0) {
            {
                lock_guard<mutex> lg(console_mutex);

                perror("do_rd_inc_wr_twice: WRITE_16 SG_IO ioctl error");
            }
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
            {
                lock_guard<mutex> lg(console_mutex);

                fprintf(stderr, "Recovered error on WRITE_16, continuing\n");
            }
            ok = 1;
            break;
        default: /* won't bother decoding other categories */
            {
                lock_guard<mutex> lg(console_mutex);

                sg_chk_n_print3("WRITE_16 command error", &pt, 1);
            }
            break;
        }
        if (! ok) {
            close(sg_fd);
            return -1;
        }
    }
    close(sg_fd);
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
    while (((sg_fd = open(dev_name, open_flags)) < 0) &&
           (EBUSY == errno)) {
        ++ebusys;
        if (wait_ms > 0)
            this_thread::sleep_for(milliseconds{wait_ms});
        else if (0 == wait_ms)
            this_thread::yield();
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

static void
work_thread(const char * dev_name, unsigned int lba, int id, int block,
            int excl, int num, int wait_ms)
{
    unsigned int thr_odd_count = 0;
    unsigned int thr_ebusy_count = 0;
    unsigned int thr_eagain_count = 0;
    int k, res;

    {
        lock_guard<mutex> lg(console_mutex);

        cerr << "Enter work_thread id=" << id << " excl=" << excl << " block="
             << block << endl;
    }
    for (k = 0; k < num; ++k) {
        res = do_rd_inc_wr_twice(dev_name, lba, block, excl, wait_ms, k,
                                 thr_ebusy_count, thr_eagain_count);
        if (res < 0)
            break;
        if (res)
            ++thr_odd_count;
    }
    {
        lock_guard<mutex> lg(console_mutex);

        if (k < num)
            cerr << "thread id=" << id << " FAILed at iteration: " << k <<
                    '\n';
        else
            cerr << "thread id=" << id << " normal exit" << '\n';
    }
    {
        lock_guard<mutex> lg(odd_count_mutex);

        odd_count += thr_odd_count;
        ebusy_count += thr_ebusy_count;
        eagain_count += thr_eagain_count;
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
    int num_threads = DEF_NUM_THREADS;
    int wait_ms = DEF_WAIT_MS;
    int no_o_excl = 0;
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
        } else if (0 == memcmp("-V", argv[k], 2)) {
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
        } else if (0 == memcmp("-xxx", argv[k], 4))
            no_o_excl += 3;
        else if (0 == memcmp("-xx", argv[k], 3))
            no_o_excl += 2;
        else if (0 == memcmp("-x", argv[k], 2))
            ++no_o_excl;
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
        struct stat a_stat;

        if (stat(dev_name, &a_stat) < 0) {
            perror("stat() on dev_name failed");
            return 1;
        }
        if (! S_ISCHR(a_stat.st_mode)) {
            fprintf(stderr, "%s should be a sg device which is a char "
                    "device. %s\n", dev_name, dev_name);
            fprintf(stderr, "is not a char device and damage could be done "
                    "if it is a BLOCK\ndevice, exiting ...\n");
            return 1;
        }
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
            int excl = 1;

            if (no_o_excl > 1)
                excl = 0;
            else if ((0 == k) && (1 == no_o_excl))
                excl = 0;

            thread * tp = new thread {work_thread, dev_name, lba, k, block,
                                      excl, num_per_thread, wait_ms};
            vt.push_back(tp);
        }

        // g++ 4.7.3 didn't like range-for loop here
        for (k = 0; k < (int)vt.size(); ++k)
            vt[k]->join();

        for (k = 0; k < (int)vt.size(); ++k)
            delete vt[k];

        if (no_o_excl)
            cout << "Odd count: " << odd_count << endl;
        else
            cout << "Expecting odd count of 0, got " << odd_count << endl;
        cout << "Number of EBUSYs: " << ebusy_count << endl;
        cout << "Number of EAGAINs: " << eagain_count << endl;

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
