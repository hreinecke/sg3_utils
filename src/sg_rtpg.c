/*
 * Copyright (c) 2004-2015 Christophe Varoqui and Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

static const char * version_str = "1.20 20151219";

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
        {"decode", 0, 0, 'd'},
        {"extended", 0, 0, 'e'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"raw", 0, 0, 'r'},
        {"readonly", 0, 0, 'R'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
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

static void dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

static void decode_status(const int st)
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

static void decode_tpgs_state(const int st)
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

int main(int argc, char * argv[])
{
    int sg_fd, k, j, off, res, c, report_len, tgt_port_count;
    unsigned char reportTgtGrpBuff[REPORT_TGT_GRP_BUFF_LEN];
    unsigned char * ucp;
    int decode = 0;
    int hex = 0;
    int raw = 0;
    int o_readonly = 0;
    int verbose = 0;
    int extended = 0;
    const char * device_name = NULL;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dehHrRvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            decode = 1;
            break;
        case 'e':
             extended = 1;
             break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            hex = 1;
            break;
        case 'r':
            raw = 1;
            break;
        case 'R':
            ++o_readonly;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr("Version: %s\n", version_str);
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

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
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
        pr2serr("open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    memset(reportTgtGrpBuff, 0x0, sizeof(reportTgtGrpBuff));
    /* trunc = 0; */

    res = sg_ll_report_tgt_prt_grp2(sg_fd, reportTgtGrpBuff,
                                    sizeof(reportTgtGrpBuff),
                                    extended, 1, verbose);
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
            dStrRaw((const char *)reportTgtGrpBuff, report_len);
            goto err_out;
        }
        if (verbose)
            printf("Report list length = %d\n", report_len);
        if (hex) {
            if (verbose)
                printf("\nOutput response in hex:\n");
            dStrHex((const char *)reportTgtGrpBuff, report_len, 1);
            goto err_out;
        }
        printf("Report target port groups:\n");
        ucp = reportTgtGrpBuff + 4;
        if (extended) {
             if (0x10 != (ucp[0] & 0x70)) {
                  pr2serr("   <<invalid extended header format\n");
                  goto err_out;
             }
             printf("  Implicit transition time: %d\n", ucp[1]);
             ucp += 4;
        }
        for (k = ucp - reportTgtGrpBuff; k < report_len;
             k += off, ucp += off) {

            printf("  target port group id : 0x%x , Pref=%d, Rtpg_fmt=%d\n",
                   sg_get_unaligned_be16(ucp + 2), !!(ucp[0] & 0x80),
                   (ucp[0] >> 4) & 0x07);
            printf("    target port group asymmetric access state : ");
            printf("0x%02x", ucp[0] & 0x0f);
            if (decode)
                decode_tpgs_state(ucp[0] & 0x0f);
            printf("\n");

            printf("    T_SUP : %d, ", !!(ucp[1] & 0x80));
            printf("O_SUP : %d, ", !!(ucp[1] & 0x40));
            printf("LBD_SUP : %d, ", !!(ucp[1] & 0x10));
            printf("U_SUP : %d, ", !!(ucp[1] & 0x08));
            printf("S_SUP : %d, ", !!(ucp[1] & 0x04));
            printf("AN_SUP : %d, ", !!(ucp[1] & 0x02));
            printf("AO_SUP : %d\n", !!(ucp[1] & 0x01));

            printf("    status code : ");
            printf("0x%02x", ucp[5]);
            if (decode)
                decode_status(ucp[5]);
            printf("\n");

            printf("    vendor unique status : ");
            printf("0x%02x\n", ucp[6]);

            printf("    target port count : ");
            tgt_port_count = ucp[7];
            printf("%02x\n", tgt_port_count);

            for (j = 0; j < tgt_port_count * 4; j += 4) {
                if (0 == j)
                    printf("    Relative target port ids:\n");
                printf("      0x%02x\n",
                       sg_get_unaligned_be16(ucp + 8 + j + 2));
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
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
