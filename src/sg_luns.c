/*
 * Copyright (c) 2004-2014 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI REPORT LUNS command to the given SCSI device
 * and decodes the response.
 */

static const char * version_str = "1.25 20140508";

#define MAX_RLUNS_BUFF_LEN (1024 * 1024)
#define DEF_RLUNS_BUFF_LEN (1024 * 8)



static struct option long_options[] = {
        {"decode", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
#ifdef SG_LIB_LINUX
        {"linux", no_argument, 0, 'l'},
#endif
        {"maxlen", required_argument, 0, 'm'},
        {"quiet", no_argument, 0, 'q'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"select", required_argument, 0, 's'},
        {"test", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
#ifdef SG_LIB_LINUX
    fprintf(stderr, "Usage: "
            "sg_luns    [--decode] [--help] [--hex] [--linux] "
            "[--maxlen=LEN]\n"
            "                  [--quiet] [--raw] [--readonly] "
            "[--select=SR]\n"
            "                  [--verbose] [--version] DEVICE\n");
#else
    fprintf(stderr, "Usage: "
            "sg_luns    [--decode] [--help] [--hex] [--maxlen=LEN] "
            "[--quiet]\n"
            "                  [--raw] [--readonly] [--select=SR] "
            "[--verbose]\n"
            "                  [--version] DEVICE\n");
#endif
    fprintf(stderr,
            "     or\n"
            "       sg_luns    --test=ALUN [--hex] [--verbose]\n"
            "  where:\n"
            "    --decode|-d        decode all luns into component parts\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           output response in hexadecimal; used "
            "twice\n"
            "                       shows decoded values in hex\n");
#ifdef SG_LIB_LINUX
    fprintf(stderr,
            "    --linux|-l         show Linux integer lun after T10 "
            "representation\n");
#endif
    fprintf(stderr,
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n"
            "    --quiet|-q         output only ASCII hex lun values\n"
            "    --raw|-r           output response in binary\n"
            "    --readonly|-R      open DEVICE read-only (def: "
            "read-write)\n"
            "    --select=SR|-s SR    select report SR (def: 0)\n"
            "                          0 -> luns apart from 'well "
            "known' lus\n"
            "                          1 -> only 'well known' "
            "logical unit numbers\n"
            "                          2 -> all luns\n"
            "                          spc4r36 added 0x10, 0x11 and 0x12\n"
            "    --test=ALUN|-t ALUN    decode ALUN and ignore most other "
            "options\n"
            "                           and DEVICE (apart from '-H')\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI REPORT LUNS command. When the --test=ALUN "
            "option is\ngiven, decodes ALUN rather than sending a "
            "REPORT LUNS command.\n", DEF_RLUNS_BUFF_LEN );
}

/* Decoded according to SAM-5 rev 10. Note that one draft: BCC rev 0,
 * defines its own "bridge addressing method" in place of the SAM-3
 * "logical addressing method".  */
static void
decode_lun(const char * leadin, const unsigned char * lunp, int do_hex,
           int verbose)
{
    int k, j, x, a_method, bus_id, target, lun, len_fld, e_a_method;
    int next_level;
    unsigned char not_spec[8] = {0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff};
    char l_leadin[128];
    char b[256];
    uint64_t ull;

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
            snprintf(b, sizeof(b), "%sPeripheral device addressing: ",
                     l_leadin);
            if ((0 == bus_id) && (0 == verbose)) {
                if (do_hex)
                    printf("%slun=0x%02x\n", b, lunp[1]);
                else
                    printf("%slun=%d\n", b, lunp[1]);
            } else {
                if (do_hex)
                    printf("%sbus_id=0x%02x, %s=0x%02x\n", b, bus_id,
                           (bus_id ? "target" : "lun"), lunp[1]);
                else
                    printf("%sbus_id=%d, %s=%d\n", b, bus_id,
                           (bus_id ? "target" : "lun"), lunp[1]);
            }
            if (bus_id)
                next_level = 1;
            break;
        case 1:         /* flat space addressing method */
            lun = ((lunp[0] & 0x3f) << 8) + lunp[1];
            if (do_hex)
                printf("%sFlat space addressing: lun=0x%04x\n", l_leadin,
                       lun);
            else
                printf("%sFlat space addressing: lun=%d\n", l_leadin, lun);
            break;
        case 2:         /* logical unit addressing method */
            target = (lunp[0] & 0x3f);
            bus_id = (lunp[1] >> 5) & 0x7;
            lun = lunp[1] & 0x1f;
            if (do_hex)
                printf("%sLogical unit addressing: bus_id=0x%x, "
                       "target=0x%02x, lun=0x%02x\n", l_leadin, bus_id,
                       target, lun);
            else
                printf("%sLogical unit addressing: bus_id=%d, target=%d, "
                       "lun=%d\n", l_leadin, bus_id, target, lun);
            break;
        case 3:         /* extended logical unit + flat space addressing */
            len_fld = (lunp[0] & 0x30) >> 4;
            e_a_method = lunp[0] & 0xf;
            x = lunp[1];
            if ((0 == len_fld) && (1 == e_a_method)) {
                snprintf(b, sizeof(b), "well known logical unit");
                switch (x) {
                case 1:
                    printf("%sREPORT LUNS %s\n", l_leadin, b);
                    break;
                case 2:
                    printf("%sACCESS CONTROLS %s\n", l_leadin, b);
                    break;
                case 3:
                    printf("%sTARGET LOG PAGES %s\n", l_leadin, b);
                    break;
                case 4:
                    printf("%sSECURITY PROTOCOL %s\n", l_leadin, b);
                    break;
                default:
                    if (do_hex)
                        printf("%s%s 0x%02x\n", l_leadin, b, x);
                    else
                        printf("%s%s %d\n", l_leadin, b, x);
                    break;
                }
            } else if ((1 == len_fld) && (2 == e_a_method)) {
                x = (lunp[1] << 16) + (lunp[2] << 8) + lunp[3];
                if (do_hex)
                    printf("%sExtended flat space addressing: lun=0x%06x\n",
                           l_leadin, x);
                else
                    printf("%sExtended flat space addressing: lun=%d\n",
                           l_leadin, x);
            } else if ((2 == len_fld) && (2 == e_a_method)) {
                ull = 0;
                for (j = 0; j < 5; ++j) {
                    if (j > 0)
                        ull <<= 8;
                    ull |= lunp[1 + j];
                }
                if (do_hex)
                    printf("%sLong extended flat space addressing: "
                           "lun=010x%" PRIx64 "\n", l_leadin, ull);
                else
                    printf("%sLong extended flat space  addressing: "
                           "lun=%" PRIu64 "\n", l_leadin, ull);
            } else if ((3 == len_fld) && (0xf == e_a_method))
                printf("%sLogical unit _not_ specified addressing\n",
                       l_leadin);
            else {
                if (len_fld < 2) {
                    if (1 == len_fld)
                        x = (lunp[1] << 16) + (lunp[2] << 8) + lunp[3];
                    if (do_hex)
                        printf("%sExtended logical unit addressing: "
                               "length=%d, e.a. method=%d, value=0x%06x\n",
                               l_leadin, len_fld, e_a_method, x);
                    else
                        printf("%sExtended logical unit addressing: "
                               "length=%d, e.a. method=%d, value=%d\n",
                               l_leadin, len_fld, e_a_method, x);
                } else {
                    ull = 0;
                    x = (2 == len_fld) ? 5 : 7;
                    for (j = 0; j < x; ++j) {
                        if (j > 0)
                            ull <<= 8;
                        ull |= lunp[1 + j];
                    }
                    if (do_hex) {
                        printf("%sExtended logical unit addressing: "
                               "length=%d, e. a. method=%d, ", l_leadin,
                               len_fld, e_a_method);
                        if (5 == len_fld)
                                printf("value=0x%010" PRIx64 "\n", ull);
                        else
                                printf("value=0x%014" PRIx64 "\n", ull);
                    } else
                        printf("%sExtended logical unit addressing: "
                               "length=%d, e. a. method=%d, value=%" PRIu64
                               "\n", l_leadin, len_fld, e_a_method, ull);
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

#ifdef SG_LIB_LINUX
static void
linux2t10_lun(uint64_t linux_lun, unsigned char t10_lun[])
{
    int k;
    unsigned int u;

     for (k = 0; k < 4; ++k, linux_lun >>= 16) {
        u = linux_lun & 0xffff;
        t10_lun[(2 * k) + 1] = u & 0xff;
        t10_lun[2 * k] = (u >> 8) & 0xff;
    }
}

static uint64_t
t10_2linux_lun(const unsigned char t10_lun[])
{
    const unsigned char * cp;
    uint64_t res;

     res = (t10_lun[6] << 8) + t10_lun[7];
     for (cp = t10_lun + 4; cp >= t10_lun; cp -= 2) {
        res <<= 16;
        res += (*cp << 8) + *(cp + 1);
    }
    return res;
}

/* Copy of t10_lun --> Linux unsigned int (i.e. 32 bit ) present in Linux
 * kernel, up to least lk 3.8.0, extended to 64 bits.
 * BEWARE: for sizeof(int==4) this function is BROKEN and is left here as
 * as example and may soon be removed. */
static uint64_t
t10_2linux_lun64bitBR(const unsigned char t10_lun[])
{
    int i;
    uint64_t lun;

    lun = 0;
    for (i = 0; i < (int)sizeof(lun); i += 2)
        lun = lun | (((t10_lun[i] << 8) | t10_lun[i + 1]) << (i * 8));
    return lun;
}
#endif  /* SG_LIB_LINUX */


static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

int
main(int argc, char * argv[])
{
    int sg_fd, k, m, off, res, c, list_len, len_cap, luns, trunc;
    int decode = 0;
    int do_hex = 0;
#ifdef SG_LIB_LINUX
    int do_linux = 0;
#endif
    int maxlen = 0;
    int do_quiet = 0;
    int do_raw = 0;
    int o_readonly = 0;
    int select_rep = 0;
    int verbose = 0;
#ifdef SG_LIB_LINUX
    int test_linux_in = 0;
    int test_linux_out = 0;
    int test_linux_out2 = 0;
#endif
    unsigned int h;
    const char * test_arg = NULL;
    const char * device_name = NULL;
    const char * cp;
    unsigned char lun_arr[8];
    unsigned char * reportLunsBuff = NULL;
    int ret = 0;

    while (1) {
        int option_index = 0;

#ifdef SG_LIB_LINUX
        c = getopt_long(argc, argv, "dhHlm:qrRs:t:vV", long_options,
                        &option_index);
#else
        c = getopt_long(argc, argv, "dhHm:qrRs:t:vV", long_options,
                        &option_index);
#endif
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
#ifdef SG_LIB_LINUX
        case 'l':
            ++do_linux;
            break;
#endif
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MAX_RLUNS_BUFF_LEN)) {
                fprintf(stderr, "argument to '--maxlen' should be %d or "
                        "less\n", MAX_RLUNS_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'q':
            ++do_quiet;
            break;
        case 'r':
            ++do_raw;
            break;
        case 'R':
            ++o_readonly;
            break;
        case 's':
           select_rep = sg_get_num(optarg);
           if ((select_rep < 0) || (select_rep > 255)) {
                fprintf(stderr, "bad argument to '--select', expect 0 to "
                        "255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 't':
            test_arg = optarg;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
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
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (test_arg) {
        memset(lun_arr, 0, sizeof(lun_arr));
        cp = test_arg;
        /* check for leading 'L' */
#ifdef SG_LIB_LINUX
        if ('L' == toupper(cp[0])) {
            uint64_t ull;

            if (1 != sscanf(cp + 1, " %" SCNu64, &ull)) {
                fprintf(stderr, "Unable to read Linux style LUN integer "
                        "given to --test=\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            linux2t10_lun(ull, lun_arr);
            test_linux_in = 1;
        } else
#endif
        {
            /* Check if trailing 'L' or 'W' */
            m = strlen(cp);    /* must be at least 1 char in test_arg */
#ifdef SG_LIB_LINUX
            if ('L' == toupper(cp[m - 1]))
                test_linux_out = 1;
            else if ('W' == toupper(cp[m - 1]))
                test_linux_out2 = 1;
#endif
            if (('0' == cp[0]) && ('X' == toupper(cp[1])))
                cp += 2;
            if (strchr(cp, ' ') || strchr(cp, '\t')) {
                for (k = 0; k < 8; ++k, cp += m) {
                    if (1 != sscanf(cp, " %2x%n", &h, &m))
                        break;
                    lun_arr[k] = h & 0xff;
                }
            } else {
                for (k = 0; k < 8; ++k, cp += 2) {
                if (1 != sscanf(cp, "%2x", &h))
                        break;
                    lun_arr[k] = h & 0xff;
                }
            }
            if (0 == k) {
                fprintf(stderr, "expected a hex number, optionally prefixed "
                        "by '0x'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        }
#ifdef SG_LIB_LINUX
        if (verbose || test_linux_in || test_linux_out2)
#else
        if (verbose)
#endif
        {
            printf("64 bit LUN in T10 preferred (hex) format: ");
            for (k = 0; k < 8; ++k)
                printf(" %02x", lun_arr[k]);
            printf("\n");
        }
#ifdef SG_LIB_LINUX
        if (test_linux_out) {
            if (do_hex > 1)
                printf("Linux 'word flipped' integer LUN representation: "
                       "0x%016" PRIx64 "\n", t10_2linux_lun(lun_arr));
            else if (do_hex)
                printf("Linux 'word flipped' integer LUN representation: 0x%"
                       PRIx64 "\n", t10_2linux_lun(lun_arr));
            else
                printf("Linux 'word flipped' integer LUN representation: %"
                       PRIu64 "\n", t10_2linux_lun(lun_arr));
        } else if (test_linux_out2) {
            if (do_hex > 1)
                printf("Linux internal 64 bit LUN representation: 0x%016"
                       PRIx64 "\n", t10_2linux_lun64bitBR(lun_arr));
            else if (do_hex)
                printf("Linux internal 64 bit LUN representation: 0x%"
                       PRIx64 "\n", t10_2linux_lun64bitBR(lun_arr));
            else
                printf("Linux internal 64 bit LUN representation: %"
                       PRIu64 "\n", t10_2linux_lun64bitBR(lun_arr));
        }
#endif
        printf("Decoded LUN:\n");
        decode_lun("  ", lun_arr, do_hex, verbose);
        return 0;
    }
    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (0 == maxlen)
        maxlen = DEF_RLUNS_BUFF_LEN;
    reportLunsBuff = (unsigned char *)calloc(1, maxlen);
    if (NULL == reportLunsBuff) {
        fprintf(stderr, "unable to malloc %d bytes\n", maxlen);
        return SG_LIB_CAT_OTHER;
    }
    trunc = 0;

    res = sg_ll_report_luns(sg_fd, select_rep, reportLunsBuff, maxlen, 1,
                            verbose);
    ret = res;
    if (0 == res) {
        list_len = (reportLunsBuff[0] << 24) + (reportLunsBuff[1] << 16) +
                   (reportLunsBuff[2] << 8) + reportLunsBuff[3];
        len_cap = list_len + 8;
        if (len_cap > maxlen)
            len_cap = maxlen;
        if (do_raw) {
            dStrRaw((const char *)reportLunsBuff, len_cap);
            goto the_end;
        }
        if (1 == do_hex) {
            dStrHex((const char *)reportLunsBuff, len_cap, 1);
            goto the_end;
        }
        luns = (list_len / 8);
        if (0 == do_quiet)
            printf("Lun list length = %d which imples %d lun entr%s\n",
                   list_len, luns, ((1 == luns) ? "y" : "ies"));
        if ((list_len + 8) > maxlen) {
            luns = ((maxlen - 8) / 8);
            trunc = 1;
            fprintf(stderr, "  <<too many luns for internal buffer, will "
                    "show %d lun%s>>\n", luns, ((1 == luns) ? "" : "s"));
        }
        if (verbose > 1) {
            fprintf(stderr, "\nOutput response in hex\n");
            dStrHexErr((const char *)reportLunsBuff,
                       (trunc ? maxlen : list_len + 8), 1);
        }
        for (k = 0, off = 8; k < luns; ++k, off += 8) {
            if (0 == do_quiet) {
                if (0 == k)
                    printf("Report luns [select_report=0x%x]:\n", select_rep);
                printf("    ");
            }
            for (m = 0; m < 8; ++m)
                printf("%02x", reportLunsBuff[off + m]);
#ifdef SG_LIB_LINUX
            if (do_linux) {
                uint64_t lin_lun;

                lin_lun = t10_2linux_lun(reportLunsBuff + off);
                if (do_hex > 1)
                    printf("    [0x%" PRIx64 "]", lin_lun);
                else
                    printf("    [%" PRIu64 "]", lin_lun);
            }
#endif
            printf("\n");
            if (decode)
                decode_lun("      ", reportLunsBuff + off, do_hex,
                           verbose);
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
    if (reportLunsBuff)
        free(reportLunsBuff);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
