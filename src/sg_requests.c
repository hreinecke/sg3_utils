/*
 * Copyright (c) 2004-2019 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/time.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pr2serr.h"
#include "sg_pt.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command REQUEST SENSE to the given SCSI device.
 */

static const char * version_str = "1.34 20190706";

#define MAX_REQS_RESP_LEN 255
#define DEF_REQS_RESP_LEN 252

#define SENSE_BUFF_LEN 96       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT 60       /* 60 seconds */

#define REQUEST_SENSE_CMD 0x3
#define REQUEST_SENSE_CMDLEN 6

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
        {"error", no_argument, 0, 'e'},
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
    pr2serr("Usage: sg_requests [--desc] [--error] [--help] [--hex] "
            "[--maxlen=LEN]\n"
            "                   [--num=NUM] [--number=NUM] [--progress] "
            "[--raw]\n"
            "                   [--status] [--time] [--verbose] "
            "[--version] DEVICE\n"
            "  where:\n"
            "    --desc|-d         set flag for descriptor sense "
            "format\n"
            "    --error|-e        change opcode to 0xff; to measure "
            "overhead\n"
            "                      twice: skip ioctl call\n"
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
    int c, n, resp_len, k, progress, rs, sense_cat;
    int do_error = 0;
    int err = 0;
    int num_errs = 0;
    int sg_fd = -1;
    int res = 0;
    uint8_t requestSenseBuff[MAX_REQS_RESP_LEN + 1];
    bool desc = false;
    bool do_progress = false;
    bool do_raw = false;
    bool do_status = false;
    bool verbose_given = false;
    bool version_given = false;
    int num_rs = 1;
    int do_hex = 0;
    int maxlen = 0;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;
    struct sg_pt_base * ptvp = NULL;
    char b[80];
    uint8_t rs_cdb[REQUEST_SENSE_CMDLEN] =
        {REQUEST_SENSE_CMD, 0, 0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
#ifndef SG_LIB_MINGW
    bool do_time = false;
    struct timeval start_tm, end_tm;
#endif

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dehHm:n:prstvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            desc = true;
            break;
        case 'e':
            ++do_error;
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
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
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
#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        verbose_given = false;
        version_given = false;
        verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr(ME "version: %s\n", version_str);
        return 0;
    }

    if (0 == maxlen)
        maxlen = DEF_REQS_RESP_LEN;
    if (NULL == device_name) {
        pr2serr("Missing device name!\n\n");
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
        if (verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto finish;
    }
    ptvp = construct_scsi_pt_obj_with_fd(sg_fd, verbose);
    if ((NULL == ptvp) || ((err = get_scsi_pt_os_err(ptvp)))) {
        pr2serr("%s: unable to construct pt object\n", __func__);
        ret = sg_convert_errno(err ? err : ENOMEM);
        goto finish;
    }
    if (do_error)
        rs_cdb[0] = 0xff;
    if (desc)
        rs_cdb[1] |= 0x1;
    rs_cdb[4] = maxlen;
    if (do_progress) {
        for (k = 0; k < num_rs; ++k) {
            if (k > 0)
                sleep_for(30);
            set_scsi_pt_cdb(ptvp, rs_cdb, sizeof(rs_cdb));
            set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
            memset(requestSenseBuff, 0x0, sizeof(requestSenseBuff));
            set_scsi_pt_data_in(ptvp, requestSenseBuff,
                                sizeof(requestSenseBuff));
            set_scsi_pt_packet_id(ptvp, k + 1);
            if (do_error > 1) {
                ++num_errs;
                n = 0;
            } else {
                rs = do_scsi_pt(ptvp, -1, DEF_PT_TIMEOUT, verbose);
                n = sg_cmds_process_resp(ptvp, "Request sense", rs, (0 == k),
                                         verbose, &sense_cat);
            }
            if (-1 == n) {
                ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
                goto finish;
            } else if (-2 == n) {
                switch (sense_cat) {
                case SG_LIB_CAT_RECOVERED:
                case SG_LIB_CAT_NO_SENSE:
                    break;
                case SG_LIB_CAT_NOT_READY:
                    ++num_errs;
                    if (1 ==  num_rs) {
                        ret = sense_cat;
                        printf("device not ready\n");
                    }
                    break;
                case SG_LIB_CAT_UNIT_ATTENTION:
                    ++num_errs;
                    if (verbose) {
                        pr2serr("Ignoring Unit attention (sense key)\n");
                    }
                    break;
                default:
                    ++num_errs;
                    if (1 == num_rs) {
                        ret = sense_cat;
                        sg_get_category_sense_str(sense_cat, sizeof(b), b,
                                                  verbose);
                        printf("%s\n", b);
                        break; // return k;
                    }
                    break;
                }
            }
            clear_scsi_pt_obj(ptvp);
            if (ret)
                goto finish;

#if 0
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
#endif
            /* "Additional sense length" same in descriptor and fixed */
            resp_len = requestSenseBuff[7] + 8;
            if (verbose > 1) {
                pr2serr("Parameter data in hex\n");
                hex2stderr(requestSenseBuff, resp_len, 1);
            }
            progress = -1;
            sg_get_sense_progress_fld(requestSenseBuff, resp_len, &progress);
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
        set_scsi_pt_cdb(ptvp, rs_cdb, sizeof(rs_cdb));
        set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
        memset(requestSenseBuff, 0x0, sizeof(requestSenseBuff));
        set_scsi_pt_data_in(ptvp, requestSenseBuff,
                            sizeof(requestSenseBuff));
        set_scsi_pt_packet_id(ptvp, k + 1);
        if (do_error > 1) {
            ++num_errs;
            n = 0;
        } else {
            rs = do_scsi_pt(ptvp, -1, DEF_PT_TIMEOUT, verbose);
            n = sg_cmds_process_resp(ptvp, "Request sense", rs, (0 == k),
                                     verbose, &sense_cat);
        }
        if (-1 == n) {
            ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
            goto finish;
        } else if (-2 == n) {
            switch (sense_cat) {
            case SG_LIB_CAT_RECOVERED:
            case SG_LIB_CAT_NO_SENSE:
                break;
            case SG_LIB_CAT_NOT_READY:
                ++num_errs;
                if (1 ==  num_rs) {
                    ret = sense_cat;
                    printf("device not ready\n");
                }
                break;
            case SG_LIB_CAT_UNIT_ATTENTION:
                ++num_errs;
                if (verbose) {
                    pr2serr("Ignoring Unit attention (sense key)\n");
                }
                break;
            default:
                ++num_errs;
                if (1 == num_rs) {
                    ret = sense_cat;
                    sg_get_category_sense_str(sense_cat, sizeof(b), b,
                                              verbose);
                    printf("%s\n", b);
                    break; // return k;
                }
                break;
            }
        }
        clear_scsi_pt_obj(ptvp);
        if (ret)
            goto finish;

        // res = sg_ll_request_sense(sg_fd, desc, requestSenseBuff, maxlen,
                                  // true, verbose);
        // ret = res;
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
#if 0
            continue;
        else if (SG_LIB_CAT_INVALID_OP == res)
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
#endif
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
    if (num_errs > 0)
        printf("Number of errors detected: %d\n", num_errs);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_requests failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
