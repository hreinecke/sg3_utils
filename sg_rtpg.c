/*
 * Copyright (c) 2004-2005 Christophe Varoqui and Douglas Gilbert.
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
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command REPORT TARGET PORT GROUPS
 * to the given SCSI device.
 */

static char * version_str = "1.03 20050309";

#define REPORT_TGT_GRP_BUFF_LEN 1024

#define ME "sg_rtpg: "

#define TPGS_STATE_OPTIMIZED 0x0
#define TPGS_STATE_NONOPTIMIZED 0x1
#define TPGS_STATE_STANDBY 0x2
#define TPGS_STATE_UNAVAILABLE 0x3
#define TPGS_STATE_TRANSITIONING 0xf

#define STATUS_CODE_NOSTATUS 0x0
#define STATUS_CODE_CHANGED_BY_SET 0x1
#define STATUS_CODE_CHANGED_BY_IMPLICIT 0x2

/* <<<<<<<<<<<<<<< start of test code */
/* #define TEST_CODE */

#ifdef TEST_CODE

#warning "<<<< TEST_CODE response compiled in >>>>"

unsigned char dummy_resp[32] = {
        0, 0, 0, 28,

        0x80, 0x3, 0, 1, 0, 2, 0, 2,
        0, 0, 0, 1,
        0, 0, 0, 2,

        0x1, 0x3, 0, 2, 0, 0, 0, 1,
        0, 0, 0, 3,
};

#endif
/* <<<<<<<<<<<<<<< end of test code */

static struct option long_options[] = {
        {"decode", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_rtpg   [--decode] [--help] [--hex] [--verbose] [--version]\n"
          "                   <scsi_device>\n"
          "  where: --decode|-d        decode status and asym. access state\n"
          "         --help|-h          print out usage message\n"
          "         --hex|-H           print out response in hex\n"
          "         --verbose|-v       increase verbosity\n"
          "         --version|-V       print version string and exit\n"
          );

}

static void decode_status(const int st)
{
    switch (st) {
    case STATUS_CODE_NOSTATUS:
        printf(" (no status available)");
        break;
    case STATUS_CODE_CHANGED_BY_SET:
        printf(" (status changed by SET TARGET PORT GROUPS)");
        break;
    case STATUS_CODE_CHANGED_BY_IMPLICIT:
        printf(" (status changed by implicit TPGS behaviour)");
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
    int sg_fd, k, j, off, res, c, report_len, tgt_port_count, trunc;
    unsigned char reportTgtGrpBuff[REPORT_TGT_GRP_BUFF_LEN];
    unsigned char * ucp;
    int decode = 0;
    int hex = 0;
    int verbose = 0;
    char device_name[256];
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dhHvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            decode = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            hex = 1;
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
    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", device_name);
        perror("");
        return 1;
    }

    memset(reportTgtGrpBuff, 0x0, sizeof(reportTgtGrpBuff));
    trunc = 0;

#ifndef TEST_CODE
    res = sg_ll_report_tgt_prt_grp(sg_fd, reportTgtGrpBuff,
                            sizeof(reportTgtGrpBuff), 1, verbose);
#else
    memcpy(reportTgtGrpBuff, dummy_resp, sizeof(dummy_resp));
    res = 0;
#endif
    if (0 == res) {
        report_len = (reportTgtGrpBuff[0] << 24) +
                     (reportTgtGrpBuff[1] << 16) + 
                     (reportTgtGrpBuff[2] << 8) +
                     reportTgtGrpBuff[3] + 4;
        printf("Report list length = %d\n", report_len);
        if (report_len > (int)sizeof(reportTgtGrpBuff)) {
            trunc = 1;
            printf("  <<report too long for internal buffer,"
                  " output truncated\n");
        }
        if (hex) {
            fprintf(stderr, "\nOutput response in hex\n");
            dStrHex((const char *)reportTgtGrpBuff,
                    (trunc ? (int)sizeof(reportTgtGrpBuff) : report_len), 1);
            ret = 0;
            goto err_out;
        }
        printf("Report target port groups:\n");
        for (k = 4, ucp = reportTgtGrpBuff + 4; k < report_len;
             k += off, ucp += off) {

            printf("  target port group id : 0x%x , Pref=%d\n",
                   (ucp[2] << 8) + ucp[3], !!(ucp[0] & 0x80));
            printf("    target port group assymetric access state : ");
            printf("0x%02x", ucp[0] & 0x0f);
            if (decode)
                decode_tpgs_state(ucp[0] & 0x0f);
            printf("\n");

            printf("    U_SUP : %d, ", !!(ucp[1] & 0x08));
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
                       (ucp[8 + j + 2] << 8) + ucp[8 + j + 3]);
            }
            off = 8 + j;
        }
        ret = 0;
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Report Target Port Groups command not supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "bad field in Report Target Port Groups cdb\n");

err_out:
    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}
