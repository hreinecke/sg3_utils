/*
 * Copyright (c) 2004-2020 Douglas Gilbert.
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
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI REPORT LUNS command to the given SCSI device
 * and decodes the response.
 */

static const char * version_str = "1.44 20200115";

#define MAX_RLUNS_BUFF_LEN (1024 * 1024)
#define DEF_RLUNS_BUFF_LEN (1024 * 8)


static struct option long_options[] = {
        {"decode", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
#ifdef SG_LIB_LINUX
        {"linux", no_argument, 0, 'l'},
#endif
        {"lu_cong", no_argument, 0, 'L'},
        {"lu-cong", no_argument, 0, 'L'},
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
    pr2serr("Usage: sg_luns    [--decode] [--help] [--hex] [--linux] "
            "[--lu_cong]\n"
            "                  [--maxlen=LEN] [--quiet] [--raw] "
            "[--readonly]\n"
            "                  [--select=SR] [--verbose] [--version] "
            "DEVICE\n");
#else
    pr2serr("Usage: sg_luns    [--decode] [--help] [--hex] [--lu_cong] "
            "[--maxlen=LEN]\n"
            "                  [--quiet] [--raw] [--readonly] "
            "[--select=SR]\n"
            "                  [--verbose] [--version] DEVICE\n");
#endif
    pr2serr("     or\n"
            "       sg_luns    --test=ALUN [--decode] [--hex] [--lu_cong] "
            "[--verbose]\n"
            "  where:\n"
            "    --decode|-d        decode all luns into component parts\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           output response in hexadecimal; used "
            "twice\n"
            "                       shows decoded values in hex\n");
#ifdef SG_LIB_LINUX
    pr2serr("    --linux|-l         show Linux integer lun after T10 "
            "representation\n");
#endif
    pr2serr("    --lu_cong|-L       decode as if LU_CONG is set; used "
            "twice:\n"
            "                       decode as if LU_CONG is clear\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n"
            "    --quiet|-q         output only ASCII hex lun values\n"
            "    --raw|-r           output response in binary\n"
            "    --readonly|-R      open DEVICE read-only (def: read-write)\n"
            "    --select=SR|-s SR    select report SR (def: 0)\n"
            "                          0 -> luns apart from 'well "
            "known' lus\n"
            "                          1 -> only 'well known' "
            "logical unit numbers\n"
            "                          2 -> all luns\n"
            "                          0x10 -> administrative luns\n"
            "                          0x11 -> admin luns + "
            "non-conglomerate luns\n"
            "                          0x12 -> admin lun + its "
            "subsidiary luns\n"
            "    --test=ALUN|-t ALUN    decode ALUN and ignore most other "
            "options\n"
            "                           and DEVICE (apart from '-H')\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI REPORT LUNS command or decodes the given ALUN. "
            "When SR is\n0x10 or 0x11 DEVICE must be LUN 0 or REPORT LUNS "
            "well known logical unit;\nwhen SR is 0x12 DEVICE must be an "
            "administrative logical unit. When the\n--test=ALUN option is "
            "given, decodes ALUN rather than sending a REPORT\nLUNS "
            "command.\n", DEF_RLUNS_BUFF_LEN );
}

/* Decoded according to SAM-5 rev 10. Note that one draft: BCC rev 0,
 * defines its own "bridge addressing method" in place of the SAM-3
 * "logical addressing method".  */
static void
decode_lun(const char * leadin, const uint8_t * lunp, bool lu_cong,
           int do_hex, int verbose)
{
    bool next_level, admin_lu_cong;
    int k, x, a_method, bus_id, target, lun, len_fld, e_a_method;
    uint64_t ull;
    char l_leadin[128];
    char b[256];

    if (0xff == lunp[0]) {
        printf("%sLogical unit _not_ specified\n", leadin);
        return;
    }
    admin_lu_cong = lu_cong;
    memset(l_leadin, 0, sizeof(l_leadin));
    for (k = 0; k < 4; ++k, lunp += 2) {
        next_level = false;
        strncpy(l_leadin, leadin, sizeof(l_leadin) - 3);
        if (k > 0) {
            if (lu_cong) {
                admin_lu_cong = false;
                if ((0 == lunp[0]) && (0 == lunp[1])) {
                    printf("%s>>>> Administrative LU\n", l_leadin);
                    if (do_hex || verbose)
                         printf("        since Subsidiary element is "
                                "0x0000\n");
                    break;
                } else
                    printf("%s>>Subsidiary element:\n", l_leadin);
            } else
                printf("%s>>%s level addressing:\n", l_leadin, ((1 == k) ?
                         "Second" : ((2 == k) ? "Third" : "Fourth")));
            strcat(l_leadin, "  ");
        } else if (lu_cong) {
            printf("%s>>Administrative element:\n", l_leadin);
            strcat(l_leadin, "  ");
        }
        a_method = (lunp[0] >> 6) & 0x3;
        switch (a_method) {
        case 0:         /* peripheral device addressing method */
            if (lu_cong) {
                snprintf(b, sizeof(b), "%sSimple lu addressing: ",
                         l_leadin);
                x = 0x3fff & sg_get_unaligned_be16(lunp + 0);
                if (do_hex)
                    printf("%s0x%04x\n", b, x);
                else
                    printf("%s%d\n", b, x);
                if (admin_lu_cong)
                    next_level = true;
            } else {
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
                    next_level = true;
            }
            break;
        case 1:         /* flat space addressing method */
            lun = 0x3fff & sg_get_unaligned_be16(lunp + 0);
            if (lu_cong) {
                printf("%sSince LU_CONG=1, unexpected Flat space "
                       "addressing: lun=0x%04x\n", l_leadin, lun);
                break;
            }
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
            if (lu_cong) {
                printf("%sSince LU_CONG=1, unexpected lu addressing: "
                       "bus_id=0x%x, target=0x%02x, lun=0x%02x\n", l_leadin,
                       bus_id, target, lun);
                break;
            }
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
                case 2:         /* obsolete in spc5r01 */
                    printf("%sACCESS CONTROLS %s\n", l_leadin, b);
                    break;
                case 3:
                    printf("%sTARGET LOG PAGES %s\n", l_leadin, b);
                    break;
                case 4:
                    printf("%sSECURITY PROTOCOL %s\n", l_leadin, b);
                    break;
                case 5:
                    printf("%sMANAGEMENT PROTOCOL %s\n", l_leadin, b);
                    break;
                case 6:
                    printf("%sTARGET COMMANDS %s\n", l_leadin, b);
                    break;
                default:
                    if (do_hex)
                        printf("%s%s 0x%02x\n", l_leadin, b, x);
                    else
                        printf("%s%s %d\n", l_leadin, b, x);
                    break;
                }
            } else if ((1 == len_fld) && (2 == e_a_method)) {
                x = sg_get_unaligned_be24(lunp + 1);
                if (do_hex)
                    printf("%sExtended flat space addressing: lun=0x%06x\n",
                           l_leadin, x);
                else
                    printf("%sExtended flat space addressing: lun=%d\n",
                           l_leadin, x);
            } else if ((2 == len_fld) && (2 == e_a_method)) {
                ull = sg_get_unaligned_be(5, lunp + 1);
                if (do_hex)
                    printf("%sLong extended flat space addressing: "
                           "lun=0x%010" PRIx64 "\n", l_leadin, ull);
                else
                    printf("%sLong extended flat space addressing: "
                           "lun=%" PRIu64 "\n", l_leadin, ull);
            } else if ((3 == len_fld) && (0xf == e_a_method))
                printf("%sLogical unit _not_ specified addressing\n",
                       l_leadin);
            else {
                if (len_fld < 2) {
                    if (1 == len_fld)
                        x = sg_get_unaligned_be24(lunp + 1);
                    if (do_hex)
                        printf("%sExtended logical unit addressing: "
                               "length=%d, e.a. method=%d, value=0x%06x\n",
                               l_leadin, len_fld, e_a_method, x);
                    else
                        printf("%sExtended logical unit addressing: "
                               "length=%d, e.a. method=%d, value=%d\n",
                               l_leadin, len_fld, e_a_method, x);
                } else {
                    ull = sg_get_unaligned_be(((2 == len_fld) ? 5 : 7),
                                              lunp + 1);
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
linux2t10_lun(uint64_t linux_lun, uint8_t t10_lun[])
{
    int k;

    for (k = 0; k < 8; k += 2, linux_lun >>= 16)
        sg_put_unaligned_be16((uint16_t)linux_lun, t10_lun + k);
}

static uint64_t
t10_2linux_lun(const uint8_t t10_lun[])
{
    int k;
    const uint8_t * cp;
    uint64_t res;

    res = sg_get_unaligned_be16(t10_lun + 6);
    for (cp = t10_lun + 4, k = 0; k < 3; ++k, cp -= 2)
        res = (res << 16) + sg_get_unaligned_be16(cp);
    return res;
}
#endif  /* SG_LIB_LINUX */


static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

int
main(int argc, char * argv[])
{
#ifdef SG_LIB_LINUX
    bool do_linux = false;
#endif
    bool do_quiet = false;
    bool do_raw = false;
    bool lu_cong_arg_given = false;
    bool o_readonly = false;
#ifdef SG_LIB_LINUX
    bool test_linux_in = false;
    bool test_linux_out = false;
#endif
    bool trunc;
    bool verbose_given = false;
    bool version_given = false;
    int sg_fd, k, m, off, res, c, list_len, len_cap, luns;
    int decode_arg = 0;
    int do_hex = 0;
    int lu_cong_arg = 0;
    int maxlen = 0;
    int ret = 0;
    int select_rep = 0;
    int verbose = 0;
    unsigned int h;
    const char * test_arg = NULL;
    const char * device_name = NULL;
    const char * cp;
    uint8_t * reportLunsBuff = NULL;
    uint8_t * free_reportLunsBuff = NULL;
    uint8_t lun_arr[8];
    struct sg_simple_inquiry_resp sir;

    while (1) {
        int option_index = 0;

#ifdef SG_LIB_LINUX
        c = getopt_long(argc, argv, "dhHlLm:qrRs:t:vV", long_options,
                        &option_index);
#else
        c = getopt_long(argc, argv, "dhHLm:qrRs:t:vV", long_options,
                        &option_index);
#endif
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            ++decode_arg;
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
            do_linux = false;
            break;
#endif
        case 'L':
            ++lu_cong_arg;
            lu_cong_arg_given = true;
            break;
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MAX_RLUNS_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_RLUNS_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'q':
            do_quiet = true;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
            break;
        case 's':
           select_rep = sg_get_num(optarg);
           if ((select_rep < 0) || (select_rep > 255)) {
                pr2serr("bad argument to '--select', expect 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 't':
            test_arg = optarg;
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
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (test_arg) {
        memset(lun_arr, 0, sizeof(lun_arr));
        cp = test_arg;
        /* check for leading 'L' */
#ifdef SG_LIB_LINUX
        if ('L' == toupper(cp[0])) {
            uint64_t ull;

            if (('0' == cp[1]) && ('X' == toupper(cp[2])))
                k = sscanf(cp + 3, " %" SCNx64, &ull);
            else
                k = sscanf(cp + 1, " %" SCNu64, &ull);
            if (1 != k) {
                pr2serr("Unable to read Linux style LUN integer given to "
                        "--test=\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            linux2t10_lun(ull, lun_arr);
            test_linux_in = true;
        } else
#endif
        {
            /* Check if trailing 'L' */
#ifdef SG_LIB_LINUX
            m = strlen(cp);    /* must be at least 1 char in test_arg */
            if ('L' == toupper(cp[m - 1]))
                test_linux_out = true;
#endif
            if (('0' == cp[0]) && ('X' == toupper(cp[1])))
                cp += 2;
            if (strchr(cp, ' ') || strchr(cp, '\t') || strchr(cp, '-')) {
                for (k = 0; k < 8; ++k, cp += 2) {
                    c = *cp;
                    if ('\0' == c)
                        break;
                    else if (! isxdigit(c))
                        ++cp;
                    if (1 != sscanf(cp, "%2x", &h))
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
                pr2serr("expected a hex number, optionally prefixed by "
                        "'0x'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        }
#ifdef SG_LIB_LINUX
        if (verbose || test_linux_in || decode_arg)
#else
        if (verbose || decode_arg)
#endif
        {
            if (decode_arg > 1) {
                printf("64 bit LUN in T10 (hex, dashed) format: ");
                for (k = 0; k < 8; k += 2)
                    printf("%c%02x%02x", (k ? '-' : ' '), lun_arr[k],
                           lun_arr[k + 1]);
            } else {
                printf("64 bit LUN in T10 preferred (hex) format: ");
                for (k = 0; k < 8; ++k)
                    printf(" %02x", lun_arr[k]);
            }
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
        }
#endif
        printf("Decoded LUN:\n");
        decode_lun("  ", lun_arr, (lu_cong_arg % 2), do_hex, verbose);
        return 0;
    }
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

    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        return sg_convert_errno(-sg_fd);
    }
    if (decode_arg && (! lu_cong_arg_given)) {
        if (verbose > 1)
            pr2serr("in order to decode LUN and since --lu_cong not given, "
                    "do standard\nINQUIRY to find LU_CONG bit\n");
        /* check if LU_CONG set in standard INQUIRY response */
        res = sg_simple_inquiry(sg_fd, &sir, false, verbose);
        ret = res;
        if (res) {
            pr2serr("fetching standard INQUIRY response failed\n");
            goto the_end;
        }
        lu_cong_arg = !!(0x40 & sir.byte_1);
        if (verbose && lu_cong_arg)
            pr2serr("LU_CONG bit set in standard INQUIRY response\n");
    }

    if (0 == maxlen)
        maxlen = DEF_RLUNS_BUFF_LEN;
    reportLunsBuff = (uint8_t *)sg_memalign(maxlen, 0, &free_reportLunsBuff,
                                            verbose > 3);
    if (NULL == reportLunsBuff) {
        pr2serr("unable to sg_memalign %d bytes\n", maxlen);
        return sg_convert_errno(ENOMEM);
    }
    trunc = false;

    res = sg_ll_report_luns(sg_fd, select_rep, reportLunsBuff, maxlen, true,
                            verbose);
    ret = res;
    if (0 == res) {
        list_len = sg_get_unaligned_be32(reportLunsBuff + 0);
        len_cap = list_len + 8;
        if (len_cap > maxlen)
            len_cap = maxlen;
        if (do_raw) {
            dStrRaw((const char *)reportLunsBuff, len_cap);
            goto the_end;
        }
        if (1 == do_hex) {
            hex2stdout(reportLunsBuff, len_cap, 1);
            goto the_end;
        }
        luns = (list_len / 8);
        if (! do_quiet)
            printf("Lun list length = %d which imples %d lun entr%s\n",
                   list_len, luns, ((1 == luns) ? "y" : "ies"));
        if ((list_len + 8) > maxlen) {
            luns = ((maxlen - 8) / 8);
            trunc = true;
            pr2serr("  <<too many luns for internal buffer, will show %d "
                    "lun%s>>\n", luns, ((1 == luns) ? "" : "s"));
        }
        if (verbose > 1) {
            pr2serr("\nOutput response in hex\n");
            hex2stderr(reportLunsBuff, (trunc ? maxlen : list_len + 8), 1);
        }
        for (k = 0, off = 8; k < luns; ++k, off += 8) {
            if (! do_quiet) {
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
            if (decode_arg)
                decode_lun("      ", reportLunsBuff + off,
                           (bool)(lu_cong_arg % 2), do_hex, verbose);
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("Report Luns command not supported (support mandatory in "
                "SPC-3)\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        pr2serr("Report Luns, aborted command\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        pr2serr("Report Luns command has bad field in cdb\n");
    else {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Report Luns command: %s\n", b);
    }

the_end:
    if (free_reportLunsBuff)
        free(free_reportLunsBuff);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return sg_convert_errno(-res);
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_luns failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
