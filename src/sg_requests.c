/*
 * Copyright (c) 2004-2018 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <sys/time.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pr2serr.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command REQUEST SENSE to the given SCSI device.
 */

static const char * version_str = "1.29 20171008";

#define MAX_REQS_RESP_LEN 255
#define DEF_REQS_RESP_LEN 252

/* Not all environments support the Unix sleep() */
#if defined(MSC_VER) || defined(__MINGW32__)
#define HAVE_MS_SLEEP
#endif
#ifdef HAVE_MS_SLEEP
#include <windows.h>
#define sleep_for(seconds)    Sleep( (seconds) * 1000)
#else
#define sleep_for(seconds)    sleep(seconds)
#endif

#define ME "sg_requests: "


static struct option long_options[] = {
        {"desc", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"maxlen", required_argument, 0, 'm'},
        {"num", required_argument, 0, 'n'},
        {"number", required_argument, 0, 'n'},
        {"progress", no_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"status", no_argument, 0, 's'},
        {"time", no_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_requests [--desc] [--help] [--hex] [--maxlen=LEN] "
            "[--num=NUM]\n"
            "                   [--number=NUM] [--progress] [--raw] "
            "[--status]\n"
            "                   [--time] [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --desc|-d         set flag for descriptor sense "
            "format\n"
            "    --help|-h         print out usage message\n"
            "    --hex|-H          output in hexadecimal\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> 252 bytes)\n"
            "    --num=NUM|-n NUM  number of REQUEST SENSE commands "
            "to send (def: 1)\n"
            "    --number=NUM      same action as '--num=NUM'\n"
            "    --progress|-p     output a progress indication (percentage) "
            "if available\n"
            "    --raw|-r          output in binary (to stdout)\n"
            "    --status|-s       set exit status from parameter data "
            "(def: only set\n"
            "                       exit status from autosense)\n"
            "    --time|-t         time the transfer, calculate commands "
            "per second\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Performs a SCSI REQUEST SENSE command\n"
            );

}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

int
main(int argc, char * argv[])
{
    int sg_fd, res, c, resp_len, k, progress;
    unsigned char requestSenseBuff[MAX_REQS_RESP_LEN + 1];
    bool desc = false;
    bool do_progress = false;
    bool do_raw = false;
    bool do_status = false;
    int num_rs = 1;
    int do_hex = 0;
    int maxlen = 0;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;
    char b[80];
#ifndef SG_LIB_MINGW
    bool do_time = false;
    struct timeval start_tm, end_tm;
#endif

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dhHm:n:prstvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            desc = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MAX_REQS_RESP_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_REQS_RESP_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'n':
           num_rs = sg_get_num(optarg);
           if (num_rs < 1) {
                pr2serr("bad argument to '--num'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            do_progress = true;
            break;
        case 'r':
            do_raw = true;
            break;
        case 's':
            do_status = true;
            break;
        case 't':
#ifndef SG_LIB_MINGW
            do_time = true;
#endif
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (0 == maxlen)
        maxlen = DEF_REQS_RESP_LEN;
    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, true /* ro */, verbose);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (do_progress) {
        for (k = 0; k < num_rs; ++k) {
            if (k > 0)
                sleep_for(30);
            memset(requestSenseBuff, 0x0, sizeof(requestSenseBuff));
            res = sg_ll_request_sense(sg_fd, desc, requestSenseBuff, maxlen,
                                      true, verbose);
            if (res) {
                ret = res;
                if (SG_LIB_CAT_INVALID_OP == res)
                    pr2serr("Request Sense command not supported\n");
                else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                    pr2serr("bad field in Request Sense cdb\n");
                else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                    pr2serr("Request Sense, aborted command\n");
                else {
                    sg_get_category_sense_str(res, sizeof(b), b, verbose);
                    pr2serr("Request Sense command: %s\n", b);
                }
                break;
            }
            /* "Additional sense length" same in descriptor and fixed */
            resp_len = requestSenseBuff[7] + 8;
            if (verbose > 1) {
                pr2serr("Parameter data in hex\n");
                hex2stderr(requestSenseBuff, resp_len, 1);
            }
            progress = -1;
            sg_get_sense_progress_fld(requestSenseBuff, resp_len,
                                      &progress);
            if (progress < 0) {
                ret = res;
                if (verbose > 1)
                     pr2serr("No progress indication found, iteration %d\n",
                             k + 1);
                /* N.B. exits first time there isn't a progress indication */
                break;
            } else
                printf("Progress indication: %d.%02d%% done\n",
                       (progress * 100) / 65536,
                       ((progress * 100) % 65536) / 656);
        }
        goto finish;
    }

#ifndef SG_LIB_MINGW
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
        res = sg_ll_request_sense(sg_fd, desc, requestSenseBuff, maxlen,
                                  true, verbose);
        ret = res;
        if (0 == res) {
            resp_len = requestSenseBuff[7] + 8;
            if (do_raw)
                dStrRaw(requestSenseBuff, resp_len);
            else if (do_hex)
                hex2stdout(requestSenseBuff, resp_len, 1);
            else if (1 == num_rs) {
                pr2serr("Decode parameter data as sense data:\n");
                sg_print_sense(NULL, requestSenseBuff, resp_len, 0);
                if (verbose > 1) {
                    pr2serr("\nParameter data in hex\n");
                    hex2stderr(requestSenseBuff, resp_len, 1);
                }
            }
            continue;
        } else if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr("Request Sense command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            pr2serr("bad field in Request Sense cdb\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            pr2serr("Request Sense, aborted command\n");
        else {
            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("Request Sense command: %s\n", b);
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
#ifndef SG_LIB_MINGW
    if (do_time && (start_tm.tv_sec || start_tm.tv_usec)) {
        struct timeval res_tm;
        double den, num;

        gettimeofday(&end_tm, NULL);
        res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
        if (res_tm.tv_usec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        den = res_tm.tv_sec;
        den += (0.000001 * res_tm.tv_usec);
        num = (double)num_rs;
        printf("time to perform commands was %d.%06d secs",
               (int)res_tm.tv_sec, (int)res_tm.tv_usec);
        if (den > 0.00001)
            printf("; %.2f operations/sec\n", num / den);
        else
            printf("\n");
    }
#endif

finish:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
