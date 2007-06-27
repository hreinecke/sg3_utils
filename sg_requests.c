/*
 * Copyright (c) 2004-2006 Douglas Gilbert.
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
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/time.h>

#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command REQUEST SENSE to the given SCSI device. 
 */

static char * version_str = "1.11 20060315";

#define REQUEST_SENSE_BUFF_LEN 252

#define ME "sg_requests: "


static struct option long_options[] = {
        {"desc", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"num", 1, 0, 'n'},
        {"time", 0, 0, 't'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_requests [--desc] [--help] [--num=<n>] [--time] [--verbose] "
          "[--version]\n"
          "                   <scsi_device>\n"
          "  where: --desc|-d          set flag for descriptor sense "
          "format\n"
          "         --help|-h          print out usage message\n"
          "         --num=<n>|-n <n>   number of REQUEST SENSE commands "
          "to send (def: 1)\n"
          "         --time|-t          time the transfer, calculate commands "
          "per second\n"
          "         --verbose|-v       increase verbosity\n"
          "         --version|-V       print version string and exit\n\n"
          "Perform a REQUEST SENSE SCSI command\n"
          );

}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, resp_len, k;
    unsigned char requestSenseBuff[REQUEST_SENSE_BUFF_LEN];
    int desc = 0;
    int num_rs = 1;
    int do_time = 0;
    int verbose = 0;
    char device_name[256];
    int ret = 1;
    struct timeval start_tm, end_tm;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dhn:tvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            desc = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'n':
           num_rs = sg_get_num(optarg);
           if (num_rs < 1) {
                fprintf(stderr, "bad argument to '--num'\n");
                return 1;
            }
            break;
        case 't':
            do_time = 1;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if ('\0' == device_name[0]) {
            strncpy(device_name, argv[optind], sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }

    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    sg_fd = sg_cmds_open_device(device_name, 1 /* ro */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return 1;
    }

    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }

    for (k = 0; k < num_rs; ++k) {
        memset(requestSenseBuff, 0x0, sizeof(requestSenseBuff));
        res = sg_ll_request_sense(sg_fd, desc, requestSenseBuff,
                                  sizeof(requestSenseBuff), 1, verbose);
        if (0 == res) {
            if (1 == num_rs) {
                resp_len = requestSenseBuff[7] + 8;
                fprintf(stderr, "Decode response as sense data:\n");
                sg_print_sense(NULL, requestSenseBuff, resp_len, 0);
                if (verbose) {
                    fprintf(stderr, "\nOutput response in hex\n");
                    dStrHex((const char *)requestSenseBuff, resp_len, 1);
                }
            }
            ret = 0;
            continue;
        } else if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "Request Sense command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in Request Sense cdb\n");
        else {
            fprintf(stderr, "Request Sense command failed\n");
            if (0 == verbose)
                fprintf(stderr, "    try the '-v' option for "
                        "more information\n");
        }
        break;
    }
    if ((do_time) && (start_tm.tv_sec || start_tm.tv_usec)) {
        struct timeval res_tm;
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
        b = (double)num_rs;
        printf("time to perform commands was %d.%06d secs",
               (int)res_tm.tv_sec, (int)res_tm.tv_usec);
        if (a > 0.00001)
            printf("; %.2f operations/sec\n", b / a);
        else
            printf("\n");
    }
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, ME "close error: %s\n", safe_strerror(-res));
        return 1;
    }
    return ret;
}
