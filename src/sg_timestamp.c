/*
 * Copyright (c) 2015-2019 Douglas Gilbert.
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
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues a SCSI REPORT TIMESTAMP and SET TIMESTAMP commands
 * to the given SCSI device. Based on spc5r07.pdf .
 */

static const char * version_str = "1.14 20191220";

#define REP_TIMESTAMP_CMDLEN 12
#define SET_TIMESTAMP_CMDLEN 12
#define REP_TIMESTAMP_SA 0xf
#define SET_TIMESTAMP_SA 0xf

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

uint8_t d_buff[256];

/* example Report timestamp parameter data */
/* uint8_t test[12] = {0, 0xa, 2, 0, 0x1, 0x51, 0x5b, 0xe2, 0xc1, 0x30,
 *                     0, 0}; */


static struct option long_options[] = {
        {"elapsed", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"milliseconds", required_argument, 0, 'm'},
        {"no_timestamp", no_argument, 0, 'N'},
        {"no-timestamp", no_argument, 0, 'N'},
        {"origin", no_argument, 0, 'o'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"seconds", required_argument, 0, 's'},
        {"srep", no_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

/* Indexed by 'timestamp origin' field value */
static const char * ts_origin_arr[] = {
    "initialized to zero at power on or by hard reset",
    "reserved [0x1]",
    "initialized by SET TIMESTAMP command",
    "initialized by other method",
    "reserved [0x4]",
    "reserved [0x5]",
    "reserved [0x6]",
    "reserved [0x7]",
};


static void
usage(int num)
{
    if (num > 1)
        goto page2;

    pr2serr("Usage: "
            "sg_timestamp  [--elapsed] [--help] [--hex] [--milliseconds=MS]\n"
            "                     [--no-timestamp] [--origin] [--raw] "
            "[--readonly]\n"
            "                     [--seconds=SECS] [--srep] [--verbose] "
            "[--version]\n"
            "                     DEVICE\n"
           );
    pr2serr("  where:\n"
            "    --elapsed|-e       show time as '<n> days hh:mm:ss.xxx' "
            "where\n"
            "                       '.xxx' is the remainder milliseconds. "
            "Don't show\n"
            "                       '<n> days' if <n> is 0 (unless '-e' "
            "given twice)\n"
            "    --help|-h          print out usage message, use twice for "
            "examples\n"
            "    --hex|-H           output response in ASCII hexadecimal\n"
            "    --milliseconds=MS|-m MS    set timestamp to MS "
            "milliseconds since\n"
            "                               1970-01-01 00:00:00 UTC\n"
            "    --no-timestamp|-N    suppress output of timestamp\n"
            "    --origin|-o        show Report timestamp origin "
            "(def: don't)\n"
            "                       used twice outputs value of field\n"
            "                       0: power up or hard reset; 2: SET "
            "TIMESTAMP\n"
            "    --raw|-r           output Report timestamp response to "
            "stdout in\n"
            "                       binary\n"
            "    --readonly|-R      open DEVICE read only (def: "
            "read/write)\n"
            "    --seconds=SECS|-s SECS    set timestamp to SECS "
            "seconds since\n"
            "                            1970-01-01 00:00:00 UTC\n"
            "    --srep|-S          output Report timestamp in seconds "
            "(def:\n"
            "                       milliseconds)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
          );
    pr2serr("Performs a SCSI REPORT TIMESTAMP or SET TIMESTAMP command. "
            "The timestamp\nis SET if either the --milliseconds=MS or "
            "--seconds=SECS option is given,\notherwise the existing "
            "timestamp is reported in milliseconds. The\nDEVICE stores "
            "the timestamp as the number of milliseconds since power up\n"
            "(or reset) or since 1970-01-01 00:00:00 UTC which also "
            "happens to\nbe the time 'epoch'of Unix machines.\n\n"
            "Use '-hh' (the '-h' option twice) for examples.\n"
#if 0
 "The 'date +%%s' command in "
            "Unix returns the number of\nseconds since the epoch. To "
            "convert a reported timestamp (in seconds since\nthe epoch) "
            "to a more readable form use "
            "'date --date=@<secs_since_epoch>' .\n"
#endif
           );
    return;
page2:
    pr2serr("sg_timestamp examples:\n"
            "It is possible that the target device containing a SCSI "
            "Logical Unit (LU)\nhas a battery (or supercapacitor) to "
            "keep its RTC (real time clock)\nticking during a power "
            "outage. More likely it doesn't and its RTC is\ncleared to "
            "zero after a power cycle or hard reset.\n\n"
            "Either way REPORT TIMESTAMP returns a 48 bit counter value "
            "whose unit is\na millisecond. A heuristic to determine if a "
            "date or elapsed time is\nbeing returned is to choose a date "
            "like 1 January 2000 which is 30 years\nafter the Unix epoch "
            "(946,684,800,000 milliseconds) and values less than\nthat are "
            "elapsed times and greater are timestamps. Observing the "
            "TIMESTAMP\nORIGIN field of REPORT TIMESTAMP is a better "
            "method:\n\n"
           );
    pr2serr(" $ sg_timestamp -o -N /dev/sg1\n"
            "Device clock initialized to zero at power on or by hard "
            "reset\n"
            " $ sg_timestamp -oo -N /dev/sg1\n"
            "0\n\n"
            " $ sg_timestamp /dev/sg1\n"
            "3984499\n"
            " $ sg_timestamp --elapsed /dev/sg1\n"
            "01:06:28.802\n\n"
            "The last output indicates an elapsed time of 1 hour, 6 minutes "
            "and 28.802\nseconds. Next set the clock to the current time:\n\n"
            " $ sg_timestamp --seconds=`date +%%s` /dev/sg1\n\n"
            " $ sg_timestamp -o -N /dev/sg1\n"
            "Device clock initialized by SET TIMESTAMP command\n\n"
            "Now show that as an elapsed time:\n\n"
            " $ sg_timestamp -e /dev/sg1\n"
            "17652 days 20:53:22.545\n\n"
            "That is over 48 years worth of days. Lets try again as a "
            "data-time\nstamp in UTC:\n\n"
            " $ date -u -R --date=@`sg_timestamp -S /dev/sg1`\n"
            "Tue, 01 May 2018 20:56:38 +0000\n"
           );
}

/* Invokes a SCSI REPORT TIMESTAMP command.  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_rep_timestamp(int sg_fd, void * resp, int mx_resp_len, int * residp,
                    bool noisy, int verbose)
{
    int k, ret, res, sense_cat;
    uint8_t rt_cdb[REP_TIMESTAMP_CMDLEN] =
          {SG_MAINTENANCE_IN, REP_TIMESTAMP_SA, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32((uint32_t)mx_resp_len, rt_cdb + 6);
    if (verbose) {
        char b[128];

        pr2serr("    Report timestamp cdb: %s\n",
                sg_get_command_str(rt_cdb, REP_TIMESTAMP_CMDLEN, false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rt_cdb, sizeof(rt_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "report timestamp", res, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;
    k = get_scsi_pt_resid(ptvp);
    if (residp)
        *residp = k;
    if ((verbose > 2) && ((mx_resp_len - k) > 0)) {
        pr2serr("Parameter data returned:\n");
        hex2stderr((const uint8_t *)resp, mx_resp_len - k,
                   ((verbose > 3) ? -1 : 1));
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}


/* Invokes the SET TIMESTAMP command.  Return of 0 -> success, various
 * SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_set_timestamp(int sg_fd, void * paramp, int param_len, bool noisy,
                    int verbose)
{
    int ret, res, sense_cat;
    uint8_t st_cdb[SET_TIMESTAMP_CMDLEN] =
          {SG_MAINTENANCE_OUT, SET_TIMESTAMP_SA, 0, 0,  0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32(param_len, st_cdb + 6);
    if (verbose) {
        char b[128];

        pr2serr("    Set timestamp cdb: %s\n",
                sg_get_command_str(st_cdb, SET_TIMESTAMP_CMDLEN, false,
                                   sizeof(b), b));
        if ((verbose > 1) && paramp && param_len) {
            pr2serr("    set timestamp parameter list:\n");
            hex2stderr((const uint8_t *)paramp, param_len, -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, st_cdb, sizeof(st_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (uint8_t *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "set timestamp", res, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;
    destruct_scsi_pt_obj(ptvp);
    return ret;
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
    bool do_srep = false;
    bool do_raw = false;
    bool no_timestamp = false;
    bool readonly = false;
    bool secs_given = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c;
    int sg_fd = 1;
    int elapsed = 0;
    int do_origin = 0;
    int do_help = 0;
    int do_hex = 0;
    int do_set = 0;
    int ret = 0;
    int verbose = 0;
    uint64_t secs = 0;
    uint64_t msecs = 0;
    int64_t ll;
    const char * device_name = NULL;
    const char * cmd_name;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ehHm:NorRs:SvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'e':
            ++elapsed;
            break;
        case 'h':
        case '?':
            ++do_help;
            break;
        case 'H':
            ++do_hex;
            break;
        case 'm':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--milliseconds=MS'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            msecs = (uint64_t)ll;
            ++do_set;
            break;
        case 'N':
            no_timestamp = true;
            break;
        case 'o':
            ++do_origin;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            readonly = true;
            break;
        case 's':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--seconds=SECS'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            secs = (uint64_t)ll;
            ++do_set;
            secs_given = true;
            break;
        case 'S':
            do_srep = true;
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
            usage(1);
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
            usage(1);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (do_help) {
        usage(do_help);
        return 0;
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
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (do_set > 1) {
        pr2serr("either --milliseconds=MS or --seconds=SECS may be given, "
                "not both\n");
        usage(1);
        return SG_LIB_CONTRADICT;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n\n");
        usage(1);
        return SG_LIB_SYNTAX_ERROR;
    }

    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    memset(d_buff, 0, 12);
    if (do_set) {
        cmd_name = "Set timestamp";
        sg_put_unaligned_be48(secs_given ? (secs * 1000) : msecs, d_buff + 4);
        res = sg_ll_set_timestamp(sg_fd, d_buff, 12, true, verbose);
    } else {
        cmd_name = "Report timestamp";
        res = sg_ll_rep_timestamp(sg_fd, d_buff, 12, NULL, true, verbose);
        if (0 == res) {
            if (do_raw)
                dStrRaw(d_buff, 12);
            else if (do_hex)
                hex2stderr(d_buff, 12, 1);
            else {
                int len = sg_get_unaligned_be16(d_buff + 0);

                if (len < 8)
                    pr2serr("timestamp parameter data length too short, "
                            "expect >= 10, got %d\n", len + 2);
                else {
                    if (do_origin) {
                        if (1 == do_origin)
                            printf("Device clock %s\n",
                                   ts_origin_arr[0x7 & d_buff[2]]);
                        else if (2 == do_origin)
                            printf("%d\n", 0x7 & d_buff[2]);
                        else
                            printf("TIMESTAMP_ORIGIN=%d\n", 0x7 & d_buff[2]);
                    }
                    if (! no_timestamp) {
                        msecs = sg_get_unaligned_be48(d_buff + 4);
                        if (elapsed) {
                            int days = (int)(msecs / 1000 / 60 / 60 / 24);
                            int hours = (int)(msecs / 1000 / 60 / 60 % 24);
                            int mins = (int)(msecs / 1000 / 60 % 60);
                            int secs_in_min =(int)( msecs / 1000 % 60);
                            int rem_msecs = (int)(msecs % 1000);

                            if ((elapsed > 1) || (days > 0))
                                printf("%d day%s ", days,
                                       ((1 == days) ? "" : "s"));
                            printf("%02d:%02d:%02d.%03d\n", hours, mins,
                                   secs_in_min, rem_msecs);
                        } else
                            printf("%" PRIu64 "\n", do_srep ?
                                                    (msecs / 1000) : msecs);
                    }
                }
            }
        }
    }
    ret = res;
    if (res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr("%s command not supported\n", cmd_name);
        else {
            char b[80];

            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("%s command: %s\n", cmd_name, b);
        }
    }

fini:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_timestamp failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
