/*
 * Copyright (c) 2015-2018 Douglas Gilbert.
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

static const char * version_str = "1.05 20180118";

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
        {"help", no_argument, 0, 'h'},
        {"milliseconds", required_argument, 0, 'm'},
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
usage()
{
    pr2serr("Usage: "
            "sg_timestamp  [--help] [--milliseconds=MS] [--origin] [--raw]\n"
            "                     [--readonly] [--seconds=SEC] [--srep] "
            "[--verbose]\n"
            "                     [--version] DEVICE\n");
    pr2serr("  where:\n"
            "    --help|-h          print out usage message\n"
            "    --milliseconds=MS|-m MS    set timestamp to MS "
            "milliseconds since\n"
            "                               1970-01-01 00:00:00 UTC\n"
            "    --origin|-o        show Report timestamp origin "
            "(def: don't)\n"
            "    --raw|-r           output Report timestamp response to "
            "stdout in\n"
            "                       binary\n"
            "    --readonly|-R      open DEVICE read only (def: "
            "read/write)\n"
            "    --seconds=SEC|-s SEC    set timestamp to SEC "
            "seconds since\n"
            "                            1970-01-01 00:00:00 UTC\n"
            "    --srep|-S          output Report timestamp in seconds "
            "(def:\n"
            "                       milliseconds)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI REPORT TIMESTAMP or SET TIMESTAMP command. "
            "The timestamp\nis SET if either the --milliseconds=MS or "
            "--seconds=SEC option is given,\notherwise the existing "
            "timestamp is reported. The DEVICE stores the\ntimestamp as "
            "the number of milliseconds since power up (or reset) or\n"
            "since 1970-01-01 00:00:00 UTC which also happens to be the "
            "time 'epoch'\nof Unix machines. The 'date +%%s' command in "
            "Unix returns the number of\nseconds since the epoch. To "
            "convert a reported timestamp (in seconds since\nthe epoch) "
            "to a more readable form use "
            "'date --date='@<secs_since_epoch>' .\n");
}

/* Invokes a SCSI REPORT TIMESTAMP command.  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_rep_timestamp(int sg_fd, void * resp, int mx_resp_len, int * residp,
                    bool noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rt_cdb[REP_TIMESTAMP_CMDLEN] =
          {SG_MAINTENANCE_IN, REP_TIMESTAMP_SA, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32((uint32_t)mx_resp_len, rt_cdb + 6);
    if (verbose) {
        pr2serr("    Report timestamp cdb: ");
        for (k = 0; k < REP_TIMESTAMP_CMDLEN; ++k)
            pr2serr("%02x ", rt_cdb[k]);
        pr2serr("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rt_cdb, sizeof(rt_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "report timestamp", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
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
        hex2stderr(resp, mx_resp_len - k, ((verbose > 3) ? -1 : 1));
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
    int k, ret, res, sense_cat;
    unsigned char st_cdb[SET_TIMESTAMP_CMDLEN] =
          {SG_MAINTENANCE_OUT, SET_TIMESTAMP_SA, 0, 0,  0, 0, 0, 0,
           0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32(param_len, st_cdb + 6);
    if (verbose) {
        pr2serr("    Set timestamp cdb: ");
        for (k = 0; k < SET_TIMESTAMP_CMDLEN; ++k)
            pr2serr("%02x ", st_cdb[k]);
        pr2serr("\n");
        if ((verbose > 1) && paramp && param_len) {
            pr2serr("    set timestamp parameter list:\n");
            hex2stderr(paramp, param_len, -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, st_cdb, sizeof(st_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "set timestamp", res, SG_NO_DATA_IN,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
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
    bool do_origin = false;
    bool do_srep = false;
    bool do_raw = false;
    bool readonly = false;
    bool secs_given = false;
    int sg_fd, res, c;
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

        c = getopt_long(argc, argv, "hm:orRs:SvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'm':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--milliseconds=MS'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            msecs = (uint64_t)ll;
            ++do_set;
            break;
        case 'o':
            do_origin = true;
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
                pr2serr("bad argument to '--seconds=SEC'\n");
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
            ++verbose;
            break;
        case 'V':
            pr2serr("version: %s\n", version_str);
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

    if (do_set > 1) {
        pr2serr("either --milliseconds=MS or --seconds=SEC may be given, "
                "not both\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
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
            else {
                int len = sg_get_unaligned_be16(d_buff + 0);
                if (len < 8)
                    pr2serr("timestamp parameter data length too short, "
                            "expect >= 10, got %d\n", len + 2);
                else {
                    if (do_origin)
                        printf("Device clock %s\n",
                               ts_origin_arr[0x7 & d_buff[2]]);
                    msecs = sg_get_unaligned_be48(d_buff + 4);
                    printf("%" PRIu64 "\n", do_srep ? (msecs / 1000) : msecs);
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

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
