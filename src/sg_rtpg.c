/*
 * Copyright (c) 2004-2018 Christophe Varoqui and Douglas Gilbert.
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
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command REPORT TARGET PORT GROUPS
 * to the given SCSI device.
 */

static const char * version_str = "1.27 20180628";

#define REPORT_TGT_GRP_BUFF_LEN 1024

#define TPGS_STATE_OPTIMIZED 0x0
#define TPGS_STATE_NONOPTIMIZED 0x1
#define TPGS_STATE_STANDBY 0x2
#define TPGS_STATE_UNAVAILABLE 0x3
#define TPGS_STATE_LB_DEPENDENT 0x4
#define TPGS_STATE_OFFLINE 0xe          /* SPC-4 rev 9 */
#define TPGS_STATE_TRANSITIONING 0xf

#define STATUS_CODE_NOSTATUS 0x0
#define STATUS_CODE_CHANGED_BY_SET 0x1
#define STATUS_CODE_CHANGED_BY_IMPLICIT 0x2

static struct option long_options[] = {
        {"decode", no_argument, 0, 'd'},
        {"extended", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_rtpg   [--decode] [--extended] [--help] [--hex] "
            "[--raw] [--readonly]\n"
            "                 [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --decode|-d        decode status and asym. access state\n"
            "    --extended|-e      use extended header parameter data "
            "format\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           print out response in hex\n"
            "    --raw|-r           output response in binary to stdout\n"
            "    --readonly|-R      open DEVICE read-only (def: read-write)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI REPORT TARGET PORT GROUPS command\n");

}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

static void
decode_status(const int st)
{
    switch (st) {
    case STATUS_CODE_NOSTATUS:
        printf(" (no status available)");
        break;
    case STATUS_CODE_CHANGED_BY_SET:
        printf(" (target port asym. state changed by SET TARGET PORT "
               "GROUPS command)");
        break;
    case STATUS_CODE_CHANGED_BY_IMPLICIT:
        printf(" (target port asym. state changed by implicit lu "
               "behaviour)");
        break;
    default:
        printf(" (unknown status code)");
        break;
    }
}

static void
decode_tpgs_state(const int st)
{
    switch (st) {
    case TPGS_STATE_OPTIMIZED:
        printf(" (active/optimized)");
        break;
    case TPGS_STATE_NONOPTIMIZED:
        printf(" (active/non optimized)");
        break;
    case TPGS_STATE_STANDBY:
        printf(" (standby)");
        break;
    case TPGS_STATE_UNAVAILABLE:
        printf(" (unavailable)");
        break;
    case TPGS_STATE_LB_DEPENDENT:
        printf(" (logical block dependent)");
        break;
    case TPGS_STATE_OFFLINE:
        printf(" (offline)");
        break;
    case TPGS_STATE_TRANSITIONING:
        printf(" (transitioning between states)");
        break;
    default:
        printf(" (unknown)");
        break;
    }
}

int
main(int argc, char * argv[])
{
    bool decode = false;
    bool hex = false;
    bool raw = false;
    bool o_readonly = false;
    bool extended = false;
    bool verbose_given = false;
    bool version_given = false;
    int k, j, off, res, c, report_len, tgt_port_count;
    int sg_fd = -1;
    int ret = 0;
    int verbose = 0;
    uint8_t reportTgtGrpBuff[REPORT_TGT_GRP_BUFF_LEN];
    uint8_t * bp;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dehHrRvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            decode = true;
            break;
        case 'e':
             extended = true;
             break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            hex = true;
            break;
        case 'r':
            raw = true;
            break;
        case 'R':
            o_readonly = true;
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
        pr2serr("Version: %s\n", version_str);
        return 0;
    }
    if (NULL == device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto err_out;
    }

    memset(reportTgtGrpBuff, 0x0, sizeof(reportTgtGrpBuff));
    /* trunc = 0; */

    res = sg_ll_report_tgt_prt_grp2(sg_fd, reportTgtGrpBuff,
                                    sizeof(reportTgtGrpBuff),
                                    extended, true, verbose);
    ret = res;
    if (0 == res) {
        report_len = sg_get_unaligned_be32(reportTgtGrpBuff + 0) + 4;
        if (report_len > (int)sizeof(reportTgtGrpBuff)) {
            /* trunc = 1; */
            pr2serr("  <<report too long for internal buffer, output "
                    "truncated\n");
            report_len = (int)sizeof(reportTgtGrpBuff);
        }
        if (raw) {
            dStrRaw(reportTgtGrpBuff, report_len);
            goto err_out;
        }
        if (verbose)
            printf("Report list length = %d\n", report_len);
        if (hex) {
            if (verbose)
                printf("\nOutput response in hex:\n");
            hex2stdout(reportTgtGrpBuff, report_len, 1);
            goto err_out;
        }
        printf("Report target port groups:\n");
        bp = reportTgtGrpBuff + 4;
        if (extended) {
             if (0x10 != (bp[0] & 0x70)) {
                  pr2serr("   <<invalid extended header format\n");
                  goto err_out;
             }
             printf("  Implicit transition time: %d\n", bp[1]);
             bp += 4;
        }
        for (k = bp - reportTgtGrpBuff; k < report_len;
             k += off, bp += off) {

            printf("  target port group id : 0x%x , Pref=%d, Rtpg_fmt=%d\n",
                   sg_get_unaligned_be16(bp + 2), !!(bp[0] & 0x80),
                   (bp[0] >> 4) & 0x07);
            printf("    target port group asymmetric access state : ");
            printf("0x%02x", bp[0] & 0x0f);
            if (decode)
                decode_tpgs_state(bp[0] & 0x0f);
            printf("\n");

            printf("    T_SUP : %d, ", !!(bp[1] & 0x80));
            printf("O_SUP : %d, ", !!(bp[1] & 0x40));
            printf("LBD_SUP : %d, ", !!(bp[1] & 0x10));
            printf("U_SUP : %d, ", !!(bp[1] & 0x08));
            printf("S_SUP : %d, ", !!(bp[1] & 0x04));
            printf("AN_SUP : %d, ", !!(bp[1] & 0x02));
            printf("AO_SUP : %d\n", !!(bp[1] & 0x01));

            printf("    status code : ");
            printf("0x%02x", bp[5]);
            if (decode)
                decode_status(bp[5]);
            printf("\n");

            printf("    vendor unique status : ");
            printf("0x%02x\n", bp[6]);

            printf("    target port count : ");
            tgt_port_count = bp[7];
            printf("%02x\n", tgt_port_count);

            for (j = 0; j < tgt_port_count * 4; j += 4) {
                if (0 == j)
                    printf("    Relative target port ids:\n");
                printf("      0x%02x\n",
                       sg_get_unaligned_be16(bp + 8 + j + 2));
            }
            off = 8 + j;
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("Report Target Port Groups command not supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        pr2serr("bad field in Report Target Port Groups cdb including "
                "unsupported service action\n");
    else {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Report Target Port Groups: %s\n", b);
    }

err_out:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_rtpg failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
