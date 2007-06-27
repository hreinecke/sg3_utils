/*
 * Copyright (c) 2004-2007 Douglas Gilbert.
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
#include "sg_cmds_basic.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command REQUEST SENSE to the given SCSI device. 
 */

static char * version_str = "1.17 20070127";

#define REQUEST_SENSE_BUFF_LEN 252

#define ME "sg_requests: "


static struct option long_options[] = {
        {"desc", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"num", 1, 0, 'n'},
        {"raw", 0, 0, 'r'},
        {"status", 0, 0, 's'},
        {"time", 0, 0, 't'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_requests [--desc] [--help] [--hex] [--num=NUM] [--raw]\n"
          "                   [--status] [--time] [--verbose] [--version] "
          "DEVICE\n"
          "  where:\n"
          "     --desc|-d         set flag for descriptor sense "
          "format\n"
          "     --help|-h         print out usage message\n"
          "     --hex|-H          output in hexadecimal\n"
          "     --num=NUM|-n NUM  number of REQUEST SENSE commands "
          "to send (def: 1)\n"
          "     --raw|-r          output in binary (to stdout)\n"
          "     --status|-s       set exit status from parameter data "
          "(def: only set\n"
          "                       exit status from autosense)\n"
          "     --time|-t         time the transfer, calculate commands "
          "per second\n"
          "     --verbose|-v      increase verbosity\n"
          "     --version|-V      print version string and exit\n\n"
          "Performs a SCSI REQUEST SENSE command\n"
          );

}

static void dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, resp_len, k;
    unsigned char requestSenseBuff[REQUEST_SENSE_BUFF_LEN];
    int desc = 0;
    int num_rs = 1;
    int do_hex = 0;
    int do_raw = 0;
    int do_status = 0;
    int do_time = 0;
    int verbose = 0;
    char device_name[256];
    int ret = 0;
#ifndef SG3_UTILS_MINGW
    struct timeval start_tm, end_tm;
#endif

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dhHn:rstvV", long_options,
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
        case 'H':
            ++do_hex;
            break;
        case 'n':
           num_rs = sg_get_num(optarg);
           if (num_rs < 1) {
                fprintf(stderr, "bad argument to '--num'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            ++do_raw;
            break;
        case 's':
            do_status = 1;
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
            return SG_LIB_SYNTAX_ERROR;
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
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, 1 /* ro */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

#ifndef SG3_UTILS_MINGW
    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }
#endif

    requestSenseBuff[0] = '\0';
    requestSenseBuff[7] = '\0';
    for (k = 0; k < num_rs; ++k) {
        memset(requestSenseBuff, 0x0, sizeof(requestSenseBuff));
        res = sg_ll_request_sense(sg_fd, desc, requestSenseBuff,
                                  sizeof(requestSenseBuff), 1, verbose);
        ret = res;
        if (0 == res) {
            resp_len = requestSenseBuff[7] + 8;
            if (do_raw)
                dStrRaw((const char *)requestSenseBuff, resp_len);
            else if (do_hex)
                dStrHex((const char *)requestSenseBuff, resp_len, 1);
            else if (1 == num_rs) {
                fprintf(stderr, "Decode parameter data as sense data:\n");
                sg_print_sense(NULL, requestSenseBuff, resp_len, 0);
                if (verbose) {
                    fprintf(stderr, "\nParameter data in hex\n");
                    dStrHex((const char *)requestSenseBuff, resp_len, 1);
                }
            }
            continue;
        } else if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "Request Sense command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in Request Sense cdb\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "Request Sense, aborted command\n");
        else {
            fprintf(stderr, "Request Sense command unexpectedly failed\n");
            if (0 == verbose)
                fprintf(stderr, "    try the '-v' option for "
                        "more information\n");
        }
        break;
    }
    if ((0 == ret) && do_status) {
        resp_len = requestSenseBuff[7] + 8;
        ret = sg_err_category_sense(requestSenseBuff, resp_len);
        if (SG_LIB_CAT_NO_SENSE == ret) {
            struct sg_scsi_sense_hdr ssh;

            if (sg_scsi_normalize_sense(requestSenseBuff, resp_len, &ssh)) {
                if ((0 == ssh.asc) && (0 == ssh.ascq))
                    ret = 0;
            }
        }
    }
#ifndef SG3_UTILS_MINGW
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
#endif
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
