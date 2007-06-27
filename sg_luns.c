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

#include "sg_lib.h"
#include "sg_cmds_basic.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command REPORT LUNS to the given SCSI device. 
 */

static char * version_str = "1.08 20061015";

#define REPORT_LUNS_BUFF_LEN 1024

#define ME "sg_luns: "


static struct option long_options[] = {
        {"decode", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"raw", 0, 0, 'r'},
        {"select", 1, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_luns    [--decode] [--help] [--hex] [--raw] [--select=<n>]\n"
          "                  [--verbose] [--version] <scsi_device>\n"
          "  where:\n"
          "    --decode|-d        decode all luns into parts\n"
          "    --help|-h          print out usage message\n"
          "    --hex|-H           output in hexadecimal\n"
          "    --raw|-r           output in binary\n"
          "    --select=<n>|-s <n>  select report <n> (def: 0)\n"
          "                          0 -> luns apart from 'well "
          "known' lus\n"
          "                          1 -> only 'well known' "
          "logical unit numbers\n"
          "                          2 -> all luns\n"
          "    --verbose|-v       increase verbosity\n"
          "    --version|-V       print version string and exit\n\n"
          "Performs a REPORT LUNS SCSI command\n"
          );

}

/* Decoded according to SAM-4 rev 4. Note that one draft: BCC rev 0,
 * defines its own "bridge addressing method" in place of the SAM-3
 * "logical addressing method".  */ 
static void decode_lun(const char * leadin, unsigned char * lunp)
{
    int k, j, x, a_method, bus_id, target, lun, len, e_a_method, next_level;
    unsigned char not_spec[8] = {0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff};
    char l_leadin[128];
    unsigned long long ull;

    if (0 == memcmp(lunp, not_spec, sizeof(not_spec))) {
        printf("%sLogical unit not specified\n", leadin);
        return;
    }
    memset(l_leadin, 0, sizeof(l_leadin));
    for (k = 0; k < 4; ++k, lunp += 2) {
        next_level = 0;
        strncpy(l_leadin, leadin, sizeof(l_leadin) - 3);
        if (k > 0) {
            printf("%s>>%s level addressing:\n", l_leadin,
                   ((1 == k) ? "Second" : ((2 == k) ? "Third" : "Fourth")));
            strcat(l_leadin, "  ");
        }
        a_method = (lunp[0] >> 6) & 0x3;
        switch (a_method) {
        case 0:         /* peripheral device addressing method */
            bus_id = lunp[0] & 0x3f;
            if (0 == bus_id)
                printf("%sPeripheral device addressing: lun=%d\n",
                       l_leadin, lunp[1]);
            else {
                printf("%sPeripheral device addressing: bus_id=%d, "
                       "target=%d\n", l_leadin, bus_id, lunp[1]);
                next_level = 1;
            }
            break;
        case 1:         /* flat space addressing method */
            lun = ((lunp[0] & 0x3f) << 8) + lunp[1];
            printf("%sFlat space addressing: lun=%d\n", l_leadin, lun);
            break;
        case 2:         /* logical unit addressing method */
            target = (lunp[0] & 0x3f);
            bus_id = (lunp[1] >> 5) & 0x7;
            lun = lunp[1] & 0x1f;
            printf("%sLogical unit addressing: bus_id=%d, target=%d, "
                   "lun=%d\n", l_leadin, bus_id, target, lun);
            break;
        case 3:         /* extended logical unit addressing method */
            len = (lunp[0] & 0x30) >> 4;
            e_a_method = lunp[0] & 0xf;
            x = lunp[1];
            if ((0 == len) && (1 == e_a_method)) {
                switch (x) {
                case 1:
                    printf("%sREPORT LUNS well known logical unit\n",
                           l_leadin);
                    break;
                case 2:
                    printf("%sACCESS CONTROLS well known logical unit\n",
                           l_leadin);
                    break;
                case 3:
                    printf("%sTARGET LOG PAGES well known logical unit\n",
                           l_leadin);
                    break;
                case 4:
                    printf("%sSECURITY PROTOCOL well known logical unit\n",
                           l_leadin);
                    break;
                default:
                    printf("%swell known logical unit %d\n", l_leadin, x);
                    break;
                }
            } else if ((1 == len) && (2 == e_a_method)) {
                x = (lunp[1] << 16) + (lunp[2] << 8) + lunp[3];
                printf("%sExtended flat space logical unit addressing: "
                       "value=0x%x\n", l_leadin, x);
            } else if ((3 == len) && (0xf == e_a_method))
                printf("%sLogical unit _not_ specified addressing\n",
                       l_leadin);
            else {
                if (len < 2) {
                    if (1 == len)
                        x = (lunp[1] << 16) + (lunp[2] << 8) + lunp[3];
                    printf("%sExtended logical unit addressing: length=%d, "
                           "e.a. method=%d, value=0x%x\n", l_leadin, len,
                           e_a_method, x);
                } else {
                    ull = 0;
                    x = (2 == len) ? 5 : 7;
                    for (j = 0; j < x; ++j) {
                        if (j > 0)
                            ull <<= 8;
                        ull |= lunp[1 + j];
                    }
                    printf("%sExtended logical unit addressing: length=%d, "
                           "e. a. method=%d, value=0x%llx\n", l_leadin, len,
                           e_a_method, ull);
                }
            }
            break;
        default:
            printf("%s<<decode_lun: faulty logic>>\n", l_leadin);
            break;
        }
        if (next_level)
            continue;
        if ((2 == a_method) && (k < 3) && (lunp[2] || lunp[3]))
            printf("%s<<unexpected data at next level, continue>>\n",
                   l_leadin);
        break;
    }
}

static void dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

int main(int argc, char * argv[])
{
    int sg_fd, k, m, off, res, c, list_len, luns, trunc;
    unsigned char reportLunsBuff[REPORT_LUNS_BUFF_LEN];
    int decode = 0;
    int do_hex = 0;
    int do_raw = 0;
    int select_rep = 0;
    int verbose = 0;
    char device_name[256];
    int ret = 0;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dhHrs:vV", long_options,
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
            ++do_hex;
            break;
        case 'r':
            ++do_raw;
            break;
        case 's':
           if ((1 != sscanf(optarg, "%d", &select_rep)) ||
               (select_rep < 0) || (select_rep > 255)) {
                fprintf(stderr, "bad argument to '--select'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
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
    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    memset(reportLunsBuff, 0x0, sizeof(reportLunsBuff));
    trunc = 0;

    res = sg_ll_report_luns(sg_fd, select_rep, reportLunsBuff,
                            sizeof(reportLunsBuff), 1, verbose);
    ret = res;
    if (0 == res) {
        list_len = (reportLunsBuff[0] << 24) + (reportLunsBuff[1] << 16) +
                   (reportLunsBuff[2] << 8) + reportLunsBuff[3];
        if (do_raw) {
            dStrRaw((const char *)reportLunsBuff, list_len + 4);
            goto the_end;
        }
        if (do_hex) {
            dStrHex((const char *)reportLunsBuff, list_len + 4, 1);
            goto the_end;
        }
        luns = (list_len / 8);
        printf("Lun list length = %d which imples %d lun entr%s\n",
               list_len, luns, ((1 == luns) ? "y" : "ies"));
        if ((list_len + 8) > (int)sizeof(reportLunsBuff)) {
            luns = ((sizeof(reportLunsBuff) - 8) / 8);
            trunc = 1;
            printf("  <<too many luns for internal buffer, will show %d "
                   "luns>>\n", luns);
        }
        if (verbose) {
            fprintf(stderr, "\nOutput response in hex\n");
            dStrHex((const char *)reportLunsBuff,
                    (trunc ? (int)sizeof(reportLunsBuff) : list_len + 8), 1);
        }
        for (k = 0, off = 8; k < luns; ++k) {
            if (0 == k)
                printf("Report luns [select_report=%d]:\n", select_rep);
            printf("    ");
            for (m = 0; m < 8; ++m, ++off)
                printf("%02x", reportLunsBuff[off]);
            printf("\n");
            if (decode)
                decode_lun("      ", reportLunsBuff + off - 8);
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Report Luns command not supported (support "
                "mandatory in SPC-3)\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "Report Luns, aborted command\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "Report Luns command has bad field in cdb\n");
    else {
        fprintf(stderr, "Report Luns command failed\n");
        if (0 == verbose)
            fprintf(stderr, "    try '-v' option for more information\n");
    }

the_end:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
