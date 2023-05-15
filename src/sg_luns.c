/*
 * Copyright (c) 2004-2023 Douglas Gilbert.
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
#include "sg_json_sg_lib.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI REPORT LUNS command to the given SCSI device
 * and decodes the response.
 */

static const char * version_str = "1.56 20230514";      /* spc6r08 */

#define MY_NAME "sg_luns"

#define MAX_RLUNS_BUFF_LEN (1024 * 1024)
#define DEF_RLUNS_BUFF_LEN (1024 * 8)

struct opts_t {
    bool do_json;
#ifdef SG_LIB_LINUX
    bool do_linux;
#endif
    bool do_quiet;
    bool do_raw;
    bool lu_cong_arg_given;
    bool o_readonly;
    bool std_inq_a_valid;
#ifdef SG_LIB_LINUX
    bool test_linux_in;
    bool test_linux_out;
#endif
    bool verbose_given;
    bool version_given;
    int do_hex;
    int lu_cong_arg;
    int maxlen;
    int decode_arg;
    int select_rep;
    int verbose;
    const char * device_name;
    const char * inhex_fn;
    const char * json_arg;
    const char * js_file;
    const char * sinq_inraw_fn;
    const char * test_arg;
    sgj_state json_st;
};


static struct option long_options[] = {
    {"decode", no_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"inhex", required_argument, 0, 'i'},
    {"inner-hex", no_argument, 0, 'I'},
    {"inner_hex", no_argument, 0, 'I'},
    {"json", optional_argument, 0, 'j'},
    {"js-file", required_argument, 0, 'J'},
    {"js_file", required_argument, 0, 'J'},
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
    {"sinq_inraw", required_argument, 0, 'Q'},
    {"sinq-inraw", required_argument, 0, 'Q'},
    {"test", required_argument, 0, 't'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

static const char * rl_pd_sn = "report_luns_parameter_data";


static void
usage()
{
#ifdef SG_LIB_LINUX
    pr2serr("Usage: sg_luns    [--decode] [--help] [--hex] [--inhex-FN] "
            "[--inner-hex]\n"
            "                  [--json[=JO]] [--js-file=JFN] [--linux] "
            "[--lu_cong]\n"
            "                  [--maxlen=LEN] [--quiet] [--raw] "
            "[--readonly]\n"
            "                  [--select=SR] [--sinq_inraw=RFN] [--verbose] "
            "[--version]\n"
            "                  DEVICE\n");
#else
    pr2serr("Usage: sg_luns    [--decode] [--help] [--hex] [--inhex-FN] "
            "[--inner-hex]\n"
            "                  [--json[=JO]] [--js-file=JFN] [--lu_cong] "
            "[--maxlen=LEN]\n"
            "                  [--quiet] [--raw] [--readonly] "
            "[--select=SR]\n"
            "                  [--sinq_inraw=RFN] [--verbose] [--version] "
            "DEVICE\n");
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
    pr2serr("    --inhex=FN|-i FN    contents of file FN treated as hex "
            "and used\n"
            "                        instead of DEVICE which is ignored\n"
            "    --inner-hex|-I     when --decode given, output decoded "
            "values in\n"
            "                       hex (def: decimal)\n"
            "    --json[=JO]|-j[=JO]    output in JSON instead of plain "
            "text\n"
            "                           Use --json=? for JSON help\n"
            "    --js-file=JFN|-J JFN    JFN is a filename to which JSON "
            "output is\n"
            "                            written (def: stdout); truncates "
            "then writes\n");
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
            "    --sinq_inraw=RFN|-Q RFN    read raw (binary) standard "
            "INQUIRY\n"
            "                               response from the RFN filename\n"
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
decode_lun(const char * leadin, const uint8_t * lunp, struct opts_t * op,
           sgj_opaque_p jop)
{
    bool next_level, admin_lu_cong, decoded;
    bool lu_cong = (op->lu_cong_arg % 2);
    int k, x, a_method, bus_id, target, lun, len_fld, e_a_method;
    uint64_t ull;
    const char * am_s;
    const char * second_s;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    char l_leadin[128];
    char b[256];
    static const int leadin_len = sizeof(l_leadin);
    static const int blen = sizeof(b);
    static const char * tname_sn = "type_name";

    jo2p = sgj_named_subobject_r(jsp, jop, "decode_level");
    sgj_js_nv_ihex_nex(jsp, jo2p, "lu_cong", (int)lu_cong, false,
                       "Logical Unit CONGlomerate");
    admin_lu_cong = lu_cong;
    memset(l_leadin, 0, leadin_len);
    for (k = 0, next_level = false; k < 4; ++k, lunp += 2) {
        if (next_level) {
            jo2p = sgj_named_subobject_r(jsp, jo2p, "decode_level");
            next_level = false;
        }
        strncpy(l_leadin, leadin, leadin_len - 3);
        if (k > 0) {
            if (lu_cong) {
                admin_lu_cong = false;
                if ((0 == lunp[0]) && (0 == lunp[1])) {
                    sgj_pr_hr(jsp, "%s>>>> Administrative LU\n", l_leadin);
                    sgj_js_nv_s(jsp, jo2p, "class",
                                "Administrative logical unit");
                    sgj_js_nv_ihex(jsp, jo2p, "administrative", 1);
                    sgj_js_nv_ihex(jsp, jo2p, "decoded", 1);
                    if (op->do_hex || op->verbose)
                        sgj_pr_hr(jsp, "        since Subsidiary element "
                                  "is 0x0000\n");
                    break;
                } else {
                    sgj_pr_hr(jsp, "%s>>Subsidiary element:\n", l_leadin);
                    sgj_js_nv_s(jsp, jo2p, "logical_unit_conglomerate",
                                "Subsidiary element");
                    sgj_js_nv_s(jsp, jo2p, "class",
                                "Subsidiary logical unit");
                    sgj_js_nv_ihex(jsp, jo2p, "administrative", 0);
                }
            } else
                 sgj_pr_hr(jsp, "%s>>%s level addressing:\n", l_leadin,
                           ((1 == k) ? "Second" :
                                       ((2 == k) ? "Third" : "Fourth")));
            strcat(l_leadin, "  ");
        } else if (lu_cong) {
            sgj_js_nv_s(jsp, jo2p, "logical_unit_conglomerate",
                        "Administrative element");
            sgj_pr_hr(jsp, "%s>>Administrative element:\n", l_leadin);
            strcat(l_leadin, "  ");
        }
        a_method = (lunp[0] >> 6) & 0x3;
        sgj_js_nv_ihex(jsp, jo2p, "access_method", a_method);
        am_s = NULL;
        decoded = true;

        switch (a_method) {
        case 0:         /* peripheral device addressing method */
            if (lu_cong) {
                am_s = "Simple logical unit addressing";
                sgj_js_nv_s(jsp, jo2p, tname_sn, am_s);
                x = 0x3fff & sg_get_unaligned_be16(lunp + 0);
                sgj_js_nv_ihex(jsp, jo2p, "value", x);
                if (op->do_hex)
                     sgj_pr_hr(jsp, "%s%s: 0x%04x\n", l_leadin, am_s, x);
                else
                     sgj_pr_hr(jsp, "%s%s: %d\n", l_leadin, am_s, x);
                if (admin_lu_cong)
                    next_level = true;
            } else {
                bus_id = lunp[0] & 0x3f;
                x = lunp[1];
                am_s = "Peripheral device addressing";
                sgj_js_nv_s(jsp, jo2p, tname_sn, am_s);
                if ((0 == bus_id) && (0 == op->verbose)) {
                    sgj_js_nv_ihex(jsp, jo2p, "lun", x);
                    if (op->do_hex)
                         sgj_pr_hr(jsp, "%s%s: lun=0x%02x\n", l_leadin, am_s,
                                   x);
                    else
                         sgj_pr_hr(jsp, "%s%s: lun=%d\n", l_leadin, am_s, x);
                } else {
                    sgj_js_nv_ihex(jsp, jo2p, "bus_identifier", bus_id);
                    sgj_js_nv_ihex(jsp, jo2p, "target_or_lun", x);
                    if (op->do_hex)
                         sgj_pr_hr(jsp, "%s%s: bus_id=0x%02x, %s=0x%02x\n",
                                   l_leadin, am_s, bus_id,
                                   (bus_id ? "target" : "lun"), x);
                    else
                         sgj_pr_hr(jsp, "%s%s: bus_id=%d, %s=%d\n", l_leadin,
                                   am_s, bus_id,
                                   (bus_id ? "target" : "lun"), x);
                }
                if (bus_id)
                    next_level = true;
            }
            break;
        case 1:         /* flat space addressing method */
            lun = 0x3fff & sg_get_unaligned_be16(lunp + 0);
            am_s = "Flat space addressing";
            sgj_js_nv_s(jsp, jo2p, tname_sn, am_s);
            sgj_js_nv_ihex(jsp, jo2p, "lun", lun);
            if (lu_cong) {
                 sgj_pr_hr(jsp, "%sSince LU_CONG=1, unexpected %s: "
                           "lun=0x%04x\n", l_leadin, am_s, lun);
                break;
            }
            if (op->do_hex)
                 sgj_pr_hr(jsp, "%s%s: lun=0x%04x\n", l_leadin, am_s, lun);
            else
                 sgj_pr_hr(jsp, "%s%s: lun=%d\n", l_leadin, am_s, lun);
            break;
        case 2:         /* logical unit addressing method */
            target = (lunp[0] & 0x3f);
            bus_id = (lunp[1] >> 5) & 0x7;
            lun = lunp[1] & 0x1f;
            am_s = "Logical Unit addressing";
            sgj_js_nv_s(jsp, jo2p, tname_sn, am_s);
            sgj_js_nv_ihex(jsp, jo2p, "target", target);
            sgj_js_nv_ihex(jsp, jo2p, "bus_identifier", bus_id);
            sgj_js_nv_ihex(jsp, jo2p, "lun", lun);
            if (lu_cong) {
                sgj_pr_hr(jsp, "%sSince LU_CONG=1, unexpected %s: "
                          "bus_id=0x%x, target=0x%02x, lun=0x%02x\n",
                          l_leadin, am_s, bus_id, target, lun);
                break;
            }
            if (op->do_hex)
                sgj_pr_hr(jsp, "%s%s: bus_id=0x%x, target=0x%02x, lun="
                          "0x%02x\n", l_leadin, am_s, bus_id, target, lun);
            else
                sgj_pr_hr(jsp, "%s%s: bus_id=%d, target=%d, lun=%d\n",
                          l_leadin, am_s, bus_id, target, lun);
            break;
        case 3:         /* extended logical unit + flat space addressing */
            len_fld = (lunp[0] & 0x30) >> 4;
            sgj_js_nv_ihex(jsp, jo2p, "length", len_fld);
            e_a_method = lunp[0] & 0xf;
            sgj_js_nv_ihex(jsp, jo2p, "extended_address_method", e_a_method);
            if (1 == e_a_method) {
                if (0 == len_fld) {
                    am_s = "Well known logical unit";
                    x = lunp[1];
                    if (1 == x)
                        second_s = "REPORT LUNS";
                    else if (2 == x)
                        second_s = "ACCESS CONTROLS";
                    else if (3 == x)
                        second_s = "TARGET LOG PAGES";
                    else if (4 == x)
                        second_s = "SECURITY PROTOCOL";
                    else if (5 == x)
                        second_s = "MANAGEMENT PROTOCOL";
                    else if (6 == x)
                        second_s = "TARGET COMMANDS";
                    else
                        second_s = "Unknown";
                    snprintf(b, blen, "%s %s", second_s, am_s);
                    sgj_pr_hr(jsp, "%s%s\n", l_leadin, b);
                    sgj_js_nv_ihex(jsp, jo2p, "w_lun", x);
                    sgj_js_nv_s(jsp, jo2p, tname_sn, b);
                } else
                    decoded = false;
            } else if (2 == e_a_method) {
                if (1 == len_fld) {
                    x = sg_get_unaligned_be24(lunp + 1);
                    am_s = "Extended flat space addressing";
                    sgj_js_nv_s(jsp, jo2p, tname_sn, am_s);
                    sgj_js_nv_ihex(jsp, jo2p, "extended_flat_space_lun", x);
                    if (op->do_hex)
                        sgj_pr_hr(jsp, "%s%s: lun=0x%06x\n", l_leadin, am_s,
                                  x);
                    else
                         sgj_pr_hr(jsp, "%s%s: lun=%d\n", l_leadin, am_s, x);
                } else if (2 == len_fld) {
                    am_s = "Long extended flat space addressing";
                    sgj_js_nv_s(jsp, jo2p, tname_sn, am_s);
                    ull = sg_get_unaligned_be(5, lunp + 1);
                    sgj_js_nv_ihex(jsp, jo2p, "long_extended_flat_space_lun",
                                   ull);
                    if (op->do_hex)
                        sgj_pr_hr(jsp, "%s%s: lun=0x%010" PRIx64 "\n",
                                  l_leadin, am_s, ull);
                    else
                        sgj_pr_hr(jsp, "%s%s: lun=%" PRIu64 "\n", l_leadin,
                                  am_s, ull);
                } else
                    decoded = false;
            } else if (0xd == e_a_method) {
                decoded = false;
                if (3 == len_fld)
                    am_s = "Restricted for T11";
            } else if (0xe == e_a_method) {
                decoded = false;
                if (3 == len_fld)
                    am_s = "Restricted for FC-SB-5";
            } else if (0xf == e_a_method) {
                decoded = false;
                if (3 == len_fld)
                    am_s = "Logical unit _not_ specified";
            } else      /* includes 0x0 == e_a_method */
                decoded = false;
            break;
        }               /* end of big case statement */
        if (! decoded) {
            if (am_s) {
                sgj_pr_hr(jsp, "%s%s\n", l_leadin, am_s);
                sgj_js_nv_s(jsp, jo2p, tname_sn, am_s);
            } else {
                sgj_pr_hr(jsp, "%sUnable to decode\n", l_leadin);
                sgj_js_nv_s(jsp, jo2p, tname_sn, "Unable to decode");
            }
        }
        if ((k > 0) || (! lu_cong))
            sgj_js_nv_ihex(jsp, jo2p, "decoded", decoded);
        if (next_level)
            continue;
        if ((2 == a_method) && (k < 3) && (lunp[2] || lunp[3]))
             sgj_pr_hr(jsp, "%s<<unexpected data at next level, continue>>\n",
                       l_leadin);
        break;
    }           /* end of large for loop */
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

/* Handles short options after '-j' including a sequence of short options
 * that include one 'j' (for JSON). Want optional argument to '-j' to be
 * prefixed by '='. Return 0 for good, SG_LIB_SYNTAX_ERROR for syntax error
 * and SG_LIB_OK_FALSE for exit with no error. */
static int
chk_short_opts(const char sopt_ch, struct opts_t * op)
{
    /* only need to process short, non-argument options */
    switch (sopt_ch) {
    case 'd':
        ++op->decode_arg;
        break;
    case 'h':
    case '?':
        usage();
        return SG_LIB_OK_FALSE;
    case 'H':
        ++op->do_hex;
        break;
    case 'I':
        op->do_hex = 2;
        break;
    case 'j':
        break;  /* simply ignore second 'j' (e.g. '-jxj') */
#ifdef SG_LIB_LINUX
    case 'l':
        op->do_linux = false;
        break;
#endif
    case 'L':
        ++op->lu_cong_arg;
        op->lu_cong_arg_given = true;
        break;
    case 'q':
        op->do_quiet = true;
        break;
    case 'r':
        op->do_raw = true;
        break;
    case 'R':
        op->o_readonly = true;
        break;
    case 'v':
        op->verbose_given = true;
        ++op->verbose;
        break;
    case 'V':
        op->version_given = true;
        break;
    default:
        pr2serr("unrecognised option code %c, [0x%x] ??\n", sopt_ch, sopt_ch);
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool trunc;
    int sg_fd, k, m, n, off, c, list_len, len_cap, luns, in_len;
    int inraw_len;
    int ret = 0;
    unsigned int h;
    const uint32_t pg_sz = sg_get_page_size();
    const char * cp;
    struct opts_t * op;
    sgj_state * jsp;
    sgj_opaque_p jop = NULL;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    uint8_t * reportLunsBuff = NULL;
    uint8_t * free_reportLunsBuff = NULL;
    uint8_t lun_arr[8];
    uint8_t std_inq_a[36] SG_C_CPP_ZERO_INIT;
    char b[144];
    struct opts_t opts SG_C_CPP_ZERO_INIT;
    struct sg_simple_inquiry_resp sir;
    static const int blen = sizeof(b);

    op = &opts;
    if (getenv("SG3_UTILS_INVOCATION"))
        sg_rep_invocation(MY_NAME, version_str, argc, argv, stderr);
    while (1) {
        int option_index = 0;

#ifdef SG_LIB_LINUX
        c = getopt_long(argc, argv, "dhHi:Ij::J:lLm:qQ:rRs:t:vV",
                        long_options, &option_index);
#else
        c = getopt_long(argc, argv, "dhHi:Ij::J:Lm:qQ:rRs:t:vV", long_options,
                        &option_index);
#endif
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            ++op->decode_arg;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++op->do_hex;
            break;
       case 'i':
            op->inhex_fn = optarg;
            break;
       case 'I':
            op->do_hex = 2;
            break;
        case 'j':
            op->do_json = true;
            /* Now want '=' to precede JSON optional arguments */
            if (optarg) {
                if ('=' == *optarg) {
                    op->json_arg = optarg + 1;
                    break;
                }
                n = strlen(optarg);
                for (k = 0; k < n; ++k) {
                    int q = chk_short_opts(*(optarg + k), op);

                    if (SG_LIB_SYNTAX_ERROR == q)
                        return SG_LIB_SYNTAX_ERROR;
                    if (SG_LIB_OK_FALSE == q)
                        return 0;
                }
            } else
                op->json_arg = NULL;
            break;
        case 'J':
            op->do_json = true;
            op->js_file = optarg;
            break;
#ifdef SG_LIB_LINUX
        case 'l':
            op->do_linux = false;
            break;
#endif
        case 'L':
            ++op->lu_cong_arg;
            op->lu_cong_arg_given = true;
            break;
        case 'm':
            op->maxlen = sg_get_num(optarg);
            if ((op->maxlen < 0) || (op->maxlen > MAX_RLUNS_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_RLUNS_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            } else if (op->maxlen < 4) {
                pr2serr("Warning: setting '--maxlen' to 4\n");
                op->maxlen = 4;
            }
            break;
        case 'q':
            op->do_quiet = true;
            break;
        case 'Q':
            op->sinq_inraw_fn = optarg;
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'R':
            op->o_readonly = true;
            break;
        case 's':
           op->select_rep = sg_get_num(optarg);
           if ((op->select_rep < 0) || (op->select_rep > 255)) {
                pr2serr("bad argument to '--select', expect 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 't':
            op->test_arg = optarg;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x] ??\n", c, c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == op->device_name) {
            op->device_name = argv[optind];
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
    if (op->verbose_given && op->version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->verbose = 0;
    } else if (! op->verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (op->verbose_given && op->version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }
    jsp = &op->json_st;
    if (op->do_json) {
        if (! sgj_init_state(jsp, op->json_arg)) {
            int bad_char = jsp->first_bad_char;
            char e[1500];

            if (bad_char) {
                pr2serr("bad argument to --json= option, unrecognized "
                        "character '%c'\n\n", bad_char);
            }
            sg_json_usage(0, e, sizeof(e));
            pr2serr("%s", e);
            return SG_LIB_SYNTAX_ERROR;
        }
        jop = sgj_start_r(MY_NAME, version_str, argc, argv, jsp);
        jo2p = sgj_named_subobject_r(jsp, jop, "pseudo_inquiry_data");
        sgj_js_nv_ihex(jsp, jo2p, "lu_cong", 1 == (op->lu_cong_arg % 2));
        jo2p = sgj_named_subobject_r(jsp, jop, rl_pd_sn);
    }

    if (op->test_arg) {
        memset(lun_arr, 0, sizeof(lun_arr));
        cp = op->test_arg;
        /* check for leading 'L' */
#ifdef SG_LIB_LINUX
        if ('L' == toupper(cp[0])) {
            uint64_t ull;

            if (('0' == cp[1]) && ('X' == toupper((uint8_t)cp[2])))
                k = sscanf(cp + 3, " %" SCNx64, &ull);
            else
                k = sscanf(cp + 1, " %" SCNu64, &ull);
            if (1 != k) {
                pr2serr("Unable to read Linux style LUN integer given to "
                        "--test=\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            linux2t10_lun(ull, lun_arr);
            op->test_linux_in = true;
        } else
#endif
        {
            /* Check if trailing 'L' */
#ifdef SG_LIB_LINUX
            m = strlen(cp);    /* must be at least 1 char in test_arg */
            if ('L' == toupper(cp[m - 1]))
                op->test_linux_out = true;
#endif
            if (('0' == cp[0]) && ('X' == toupper((uint8_t)cp[1])))
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
        if (op->verbose || op->test_linux_in || op->decode_arg)
#else
        if (op->verbose || op->decode_arg)
#endif
        {
            if (op->decode_arg > 1) {
                n = sg_scnpr(b, blen, "64 bit LUN in T10 (hex, dashed) "
                             "format: ");
                for (k = 0; k < 8; k += 2)
                    n += sg_scnpr(b + n, blen - n, "%c%02x%02x",
                                  (k ? '-' : ' '), lun_arr[k],
                                  lun_arr[k + 1]);
            } else {
                n = sg_scnpr(b, blen, "64 bit LUN in T10 preferred (hex) "
                             "format: ");
                for (k = 0; k < 8; ++k)
                    n += sg_scnpr(b + n, blen - n, " %02x", lun_arr[k]);
            }
            sgj_pr_hr(jsp, "%s\n", b);
        }
#ifdef SG_LIB_LINUX
        if (op->test_linux_out) {
            uint64_t lin_lun = t10_2linux_lun(lun_arr);
            static const char * lwfilr_s = "Linux 'word flipped' integer LUN "
                                           "representation";
            if (op->do_hex > 1)
                sgj_pr_hr(jsp, "%s: 0x%016" PRIx64 "\n", lwfilr_s, lin_lun);
            else if (op->do_hex)
                sgj_pr_hr(jsp, "%s: 0x%" PRIx64 "\n", lwfilr_s, lin_lun);
            else
                sgj_pr_hr(jsp, "%s: %" PRIu64 "\n", lwfilr_s, lin_lun);
        }
#endif
        sgj_pr_hr(jsp, "Decoded LUN:\n");
        decode_lun("  ", lun_arr, op, jo2p);
        return 0;
    }

    if (op->inhex_fn) {
        if (op->device_name) {
            if (! op->do_json)
                pr2serr("ignoring DEVICE, best to give DEVICE or "
                        "--inhex=FN, but not both\n");
            op->device_name = NULL;
        }
    } else if (NULL == op->device_name) {
        pr2serr("missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if (NULL == op->inhex_fn) {
        sg_fd = sg_cmds_open_device(op->device_name, op->o_readonly,
                                    op->verbose);
        if (sg_fd < 0) {
            int err = -sg_fd;

            pr2serr("open error: %s: %s\n", op->device_name,
                    safe_strerror(err));
            if ((! op->o_readonly) && ((err == EACCES) || (err == EROFS)))
                pr2serr("Perhaps try again with --readonly option or with "
                        "root permissions\n");
            return sg_convert_errno(-sg_fd);
        }
    } else
        sg_fd = -1;

    if (0 == op->maxlen)
        op->maxlen = DEF_RLUNS_BUFF_LEN;
    reportLunsBuff = (uint8_t *)sg_memalign(op->maxlen, 0,
                                            &free_reportLunsBuff,
                                            op->verbose > 3);
    if (NULL == reportLunsBuff) {
        pr2serr("unable to sg_memalign %d bytes\n", op->maxlen);
        return sg_convert_errno(ENOMEM);
    }
    trunc = false;
    if (op->sinq_inraw_fn) {
        /* Note: want to support both --sinq_inraw= and --inhex= options */
        if ((ret = sg_f2hex_arr(op->sinq_inraw_fn, true, false,
                                reportLunsBuff, &inraw_len, op->maxlen))) {
            goto the_end;
        }
        if (inraw_len < 36) {
            pr2serr("Unable to read 36 or more bytes from %s\n",
                    op->sinq_inraw_fn);
            ret = SG_LIB_FILE_ERROR;
            goto the_end;
        }
        memcpy(std_inq_a,  reportLunsBuff, 36);
        op->std_inq_a_valid = true;
    }
    if (op->decode_arg) {
        if (op->std_inq_a_valid) {
            int lu_cong = !!(0x40 & std_inq_a[1]);

            if (op->lu_cong_arg_given && (lu_cong != (op->lu_cong_arg % 2))) {
                pr2serr("LU_CONG in --sinq_inraw and --lu_cong= "
                        "contradict\n");
                return SG_LIB_CONTRADICT;
            }
            op->lu_cong_arg = lu_cong;
        } else if ((! op->lu_cong_arg_given) && (sg_fd >= 0)) {
            if (op->verbose > 1)
                pr2serr("in order to decode LUN and since --lu_cong not "
                        "given, do standard\nINQUIRY to find LU_CONG bit\n");
            /* check if LU_CONG set in standard INQUIRY response */
            ret = sg_simple_inquiry(sg_fd, &sir, false, op->verbose);
            if (ret) {
                pr2serr("fetching standard INQUIRY response failed\n");
                goto the_end;
            }
            op->lu_cong_arg = !!(0x40 & sir.byte_1);
        }
        if (op->verbose && op->lu_cong_arg)
            pr2serr("LU_CONG bit set in standard INQUIRY response\n");
    }
    if (op->inhex_fn) {
        if ((ret = sg_f2hex_arr(op->inhex_fn, op->do_raw, false,
                                reportLunsBuff, &in_len, pg_sz))) {
            if (SG_LIB_LBA_OUT_OF_RANGE == ret)
                pr2serr("decode buffer [%d] not large enough??\n", pg_sz);
            goto the_end;
        }
        if (op->verbose > 2)
            pr2serr("Read %d [0x%x] bytes of user supplied data\n",
                    in_len, in_len);
        if (op->do_raw)
            op->do_raw = false;    /* can interfere on decode */
        if (in_len < 4) {
            pr2serr("--inhex=%s only decoded %d bytes (needs 4 at "
                    "least)\n", op->inhex_fn, in_len);
            ret = SG_LIB_SYNTAX_ERROR;
            goto the_end;
        }
        ret = 0;
    } else
        ret = sg_ll_report_luns(sg_fd, op->select_rep, reportLunsBuff,
                                op->maxlen, true, op->verbose);
    if (0 == ret) {
        list_len = sg_get_unaligned_be32(reportLunsBuff + 0);
        len_cap = list_len + 8;
        if (len_cap > op->maxlen)
            len_cap = op->maxlen;
        if (op->do_raw) {
            dStrRaw((const char *)reportLunsBuff, len_cap);
            goto the_end;
        }
        if (op->do_hex > 0) {
            if (1 == op->do_hex) {
                hex2stdout(reportLunsBuff, len_cap, 1);
                goto the_end;
            } else if (op->do_hex > 2) {
                if (op->do_hex > 3)
                    sgj_pr_hr(jsp, "\n# %s\n", rl_pd_sn);
                hex2stdout(reportLunsBuff, len_cap, -1);
                goto the_end;
            }
        }
        sgj_js_nv_ihex(jsp, jo2p, "lun_list_length", list_len);
        jap = sgj_named_subarray_r(jsp, jo2p, "lun_list");
        luns = (list_len / 8);
        if (! op->do_quiet)
            sgj_pr_hr(jsp, "Lun list length = %d which imples %d lun "
                      "entr%s\n", list_len, luns,
                      ((1 == luns) ? "y" : "ies"));
        if ((list_len + 8) > op->maxlen) {
            luns = ((op->maxlen - 8) / 8);
            trunc = true;
            pr2serr("  <<too many luns for internal buffer, will show %d "
                    "lun%s>>\n", luns, ((1 == luns) ? "" : "s"));
        }
        if (op->verbose > 1) {
            pr2serr("\nOutput response in hex\n");
            hex2stderr(reportLunsBuff,
                       (trunc ? op->maxlen : list_len + 8), 1);
        }
        for (k = 0, off = 8; k < luns; ++k, off += 8) {
            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_hex_bytes(jsp, jo3p, "lun", reportLunsBuff + off, 8);
            n = 0;
            if (! op->do_quiet) {
                if (0 == k)
                    sgj_pr_hr(jsp, "Report luns [select_report=0x%x]:\n",
                              op->select_rep);
                n = sg_scnpr(b + n, blen - n, "    ");
            }
            for (m = 0; m < 8; ++m)
                n += sg_scnpr(b + n, blen - n, "%02x",
                              reportLunsBuff[off + m]);
#ifdef SG_LIB_LINUX
            if (op->do_linux) {
                uint64_t lin_lun;

                lin_lun = t10_2linux_lun(reportLunsBuff + off);
                if (op->do_hex > 1)
                    sg_scnpr(b + n, blen - n, "    [0x%" PRIx64 "]", lin_lun);
                else
                    sg_scnpr(b + n, blen - n, "    [%" PRIu64 "]", lin_lun);
            }
#endif
            sgj_pr_hr(jsp, "%s\n", b);
            if (op->decode_arg)
                decode_lun("      ", reportLunsBuff + off, op, jo3p);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
    } else if (SG_LIB_CAT_INVALID_OP == ret)
        pr2serr("Report Luns command not supported (support mandatory in "
                "SPC-3)\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == ret)
        pr2serr("Report Luns, aborted command\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == ret)
        pr2serr("Report Luns command has bad field in cdb\n");
    else {
        char d[80];

        sg_get_category_sense_str(ret, sizeof(d), d, op->verbose);
        pr2serr("Report Luns command: %s\n", d);
    }

the_end:
    if (free_reportLunsBuff)
        free(free_reportLunsBuff);
    if (sg_fd >= 0) {
        int res = sg_cmds_close_device(sg_fd);

        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_luns failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    ret = (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
    if (op->do_json) {
        FILE * fp = stdout;

        if (op->js_file) {
            if ((1 != strlen(op->js_file)) || ('-' != op->js_file[0])) {
                fp = fopen(op->js_file, "w");   /* truncate if exists */
                if (NULL == fp) {
                    pr2serr("unable to open file: %s\n", op->js_file);
                    if (0 == ret)
                        ret = SG_LIB_FILE_ERROR;
                }
            }
            /* '--js-file=-' will send JSON output to stdout */
        }
        if (fp)
            sgj_js2file(jsp, NULL, ret, fp);
        if (op->js_file && fp && (stdout != fp))
            fclose(fp);
        sgj_finish(jsp);
    }
    return ret;
}
