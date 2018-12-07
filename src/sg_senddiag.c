/*
 * A utility program originally written for the Linux OS SCSI subsystem
 *    Copyright (C) 2003-2018 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later

   This program issues the SCSI SEND DIAGNOSTIC command and in one case
   the SCSI RECEIVE DIAGNOSTIC command to list supported diagnostic pages.
*/

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#if SG_LIB_WIN32
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */
#endif
#include "sg_unaligned.h"
#include "sg_pr2serr.h"


static const char * version_str = "0.63 20180628";

#define ME "sg_senddiag: "

#define DEF_ALLOC_LEN (1024 * 4)

static struct option long_options[] = {
        {"doff", no_argument, 0, 'd'},
        {"extdur", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"list", no_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"new", no_argument, 0, 'N'},
        {"old", no_argument, 0, 'O'},
        {"page", required_argument, 0, 'P'},
        {"pf", no_argument, 0, 'p'},
        {"raw", required_argument, 0, 'r'},
        {"selftest", required_argument, 0, 's'},
        {"test", no_argument, 0, 't'},
        {"timeout", required_argument, 0, 'T'},
        {"uoff", no_argument, 0, 'u'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    bool do_deftest;
    bool do_doff;
    bool do_extdur;
    bool do_list;
    bool do_pf;
    bool do_raw;
    bool do_uoff;
    bool opt_new;
    bool verbose_given;
    bool version_given;
    int do_help;
    int do_hex;
    int maxlen;
    int page_code;
    int do_selftest;
    int timeout;
    int verbose;
    const char * device_name;
    const char * raw_arg;
};


static void
usage()
{
    printf("Usage: sg_senddiag [--doff] [--extdur] [--help] [--hex] "
           "[--list]\n"
           "                   [--maxlen=LEN] [--page=PG] [--pf] "
           "[--raw=H,H...]\n"
           "                   [--selftest=ST] [--test] [--timeout=SECS] "
           "[--uoff]\n"
           "                   [--verbose] [--version] [DEVICE]\n"
           "  where:\n"
           "    --doff|-d       device online (def: 0, only with '--test')\n"
           "    --extdur|-e     duration of an extended self-test (from mode "
           "page 0xa)\n"
           "    --help|-h       print usage message then exit\n"
           "    --hex|-H        output RDR in hex; twice: plus ASCII; thrice: "
           "suitable\n"
           "                    for '--raw=-' with later invocation\n"
           "    --list|-l       list supported page codes (with or without "
           "DEVICE)\n"
           "    --maxlen=LEN|-m LEN    parameter list length or maximum "
           "allocation\n"
           "                           length (default: 4096 bytes)\n"
           "    --page=PG|-P PG    do RECEIVE DIAGNOSTIC RESULTS only, set "
           "PCV\n"
           "    --pf|-p         set PF bit (def: 0)\n"
           "    --raw=H,H...|-r H,H...    sequence of hex bytes to form "
           "diag page to send\n"
           "    --raw=-|-r -    read stdin for sequence of bytes to send\n"
           "    --selftest=ST|-s ST    self-test code, default: 0 "
           "(inactive)\n"
           "                           1->background short, 2->background "
           "extended\n"
           "                           4->abort test\n"
           "                           5->foreground short, 6->foreground "
           "extended\n"
           "    --test|-t       default self-test\n"
           "    --timeout=SECS|-T SECS    timeout for foreground self tests\n"
           "                            unit: second (def: 7200 seconds)\n"
           "    --uoff|-u       unit offline (def: 0, only with '--test')\n"
           "    --verbose|-v    increase verbosity\n"
           "    --old|-O        use old interface (use as first option)\n"
           "    --version|-V    output version string then exit\n\n"
           "Performs a SCSI SEND DIAGNOSTIC (and/or a RECEIVE DIAGNOSTIC "
           "RESULTS) command\n"
        );
}

static void
usage_old()
{
    printf("Usage: sg_senddiag [-doff] [-e] [-h] [-H] [-l] [-pf]"
           " [-raw=H,H...]\n"
           "                   [-s=SF] [-t] [-T=SECS] [-uoff] [-v] [-V] "
           "[DEVICE]\n"
           "  where:\n"
           "    -doff   device online (def: 0, only with '-t')\n"
           "    -e      duration of an extended self-test (from mode page "
           "0xa)\n"
           "    -h      output in hex\n"
           "    -H      output in hex (same as '-h')\n"
           "    -l      list supported page codes\n"
           "    -pf     set PF bit (def: 0)\n"
           "    -raw=H,H...    sequence of bytes to form diag page to "
           "send\n"
           "    -raw=-  read stdin for sequence of bytes to send\n"
           "    -s=SF   self-test code (def: 0)\n"
           "            1->background short, 2->background extended,"
           " 4->abort test\n"
           "            5->foreground short, 6->foreground extended\n"
           "    -t      default self-test\n"
           "    -T SECS    timeout for foreground self tests\n"
           "    -uoff   unit offline (def: 0, only with '-t')\n"
           "    -v      increase verbosity (print issued SCSI cmds)\n"
           "    -V      output version string\n"
           "    -N|--new   use new interface\n"
           "    -?      output this usage message\n\n"
           "Performs a SCSI SEND DIAGNOSTIC (and/or a RECEIVE DIAGNOSTIC "
           "RESULTS) command\n"
        );
}

static int
new_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dehHlm:NOpP:r:s:tT:uvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            op->do_doff = true;
            break;
        case 'e':
            op->do_extdur = true;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'H':
            ++op->do_hex;
            break;
        case 'l':
            op->do_list = true;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 0xffff)) {
                pr2serr("bad argument to '--maxlen=' or greater than 65535 "
                        "[0xffff]\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->maxlen = n;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = false;
            return 0;
        case 'p':
            op->do_pf = true;
            break;
        case 'P':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 0xff)) {
                pr2serr("bad argument to '--page=' or greater than 255 "
                        "[0xff]\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->page_code = n;
            break;
        case 'r':
            op->raw_arg = optarg;
            op->do_raw = true;
            break;
        case 's':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 7)) {
                pr2serr("bad argument to '--selftest='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_selftest = n;
            break;
        case 't':
            op->do_deftest = true;
            break;
        case 'T':
            n = sg_get_num(optarg);
            if (n < 0) {
                pr2serr("bad argument to '--timeout=SECS'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->timeout = n;
            break;
        case 'u':
            op->do_uoff = true;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
            if (op->do_help)
                break;
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
    return 0;
}

static int
old_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    bool jmp_out;
    int k, plen, num, n;
    unsigned int u;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'd':
                    if (0 == strncmp("doff", cp, 4)) {
                        op->do_doff = true;
                        cp += 3;
                        plen -= 3;
                    } else
                        jmp_out = true;
                    break;
                case 'e':
                    op->do_extdur = true;
                    break;
                case 'h':
                case 'H':
                    ++op->do_hex;
                    break;
                case 'l':
                    op->do_list = true;
                    break;
                case 'N':
                    op->opt_new = true;
                    return 0;
                case 'O':
                    break;
                case 'p':
                    if (0 == strncmp("pf", cp, 2)) {
                        op->do_pf = true;
                        ++cp;
                        --plen;
                    } else
                        jmp_out = true;
                    break;
                case 't':
                    op->do_deftest = true;
                    break;
                case 'u':
                    if (0 == strncmp("uoff", cp, 4)) {
                        op->do_uoff = true;
                        cp += 3;
                        plen -= 3;
                    } else
                        jmp_out = true;
                    break;
                case 'v':
                    op->verbose_given = true;
                    ++op->verbose;
                    break;
                case 'V':
                    op->version_given = true;
                    break;
                case '?':
                    ++op->do_help;
                    break;
                default:
                    jmp_out = true;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("raw=", cp, 4)) {
                op->raw_arg = cp + 4;
                op->do_raw = true;
            } else if (0 == strncmp("s=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 7)) {
                    printf("Bad page code after '-s=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->do_selftest = u;
            } else if (0 == strncmp("T=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 0)) {
                    printf("Bad page code after '-T=SECS' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->timeout = n;
            } else if (0 == strncmp("-old", cp, 5))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == op->device_name)
            op->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not expecting: %s\n",
                    op->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int
parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = false;
        res = old_parse_cmd_line(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = new_parse_cmd_line(op, argc, argv);
    } else {
        op->opt_new = true;
        res = new_parse_cmd_line(op, argc, argv);
        if ((0 == res) && (! op->opt_new))
            res = old_parse_cmd_line(op, argc, argv);
    }
    return res;
}

/* Return of 0 -> success, otherwise see sg_ll_send_diag() */
static int
do_senddiag(int sg_fd, int sf_code, bool pf_bit, bool sf_bit,
            bool devofl_bit, bool unitofl_bit, void * outgoing_pg,
            int outgoing_len, int tmout, bool noisy, int verbose)
{
    int long_duration = 0;

    if ((0 == sf_bit) && ((5 == sf_code) || (6 == sf_code))) {
        /* foreground self-tests */
        if (tmout <= 0)
            long_duration = 1;
        else
            long_duration = tmout;
    }
    return sg_ll_send_diag(sg_fd, sf_code, pf_bit, sf_bit, devofl_bit,
                           unitofl_bit, long_duration, outgoing_pg,
                           outgoing_len, noisy, verbose);
}

/* Get expected extended self-test time from mode page 0xa (for '-e') */
static int
do_modes_0a(int sg_fd, void * resp, int mx_resp_len, bool mode6, bool noisy,
            int verbose)
{
    int res;
    int resid = 0;

    if (mode6)
        res = sg_ll_mode_sense6(sg_fd, true /* dbd */, false /* pc */,
                                0xa /* page */, false, resp, mx_resp_len,
                                noisy, verbose);
    else
        res = sg_ll_mode_sense10_v2(sg_fd, false /* llbaa */, true /* dbd */,
                                    false, 0xa, false, resp, mx_resp_len,
                                    0, &resid, noisy, verbose);
    if (res) {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Mode sense (%s): %s\n", (mode6 ? "6" : "10"), b);
    } else {
        mx_resp_len -= resid;
        if (mx_resp_len < 4) {
            pr2serr("%s: response length (%d) too small (resid=%d)\n",
                    __func__, mx_resp_len, resid);
            res = SG_LIB_WILD_RESID;
        }
    }
    return res;
}

/* Read hex numbers from command line (comma separated list) or from */
/* stdin (one per line, comma separated list or space separated list). */
/* Returns 0 if ok, or 1 if error. */
static int
build_diag_page(const char * inp, uint8_t * mp_arr, int * mp_arr_len,
                int max_arr_len)
{
    int in_len, k, j, m;
    unsigned int h;
    const char * lcp;
    char * cp;
    char * c2p;

    if ((NULL == inp) || (NULL == mp_arr) ||
        (NULL == mp_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *mp_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        bool split_line;
        int off = 0;
        char line[512];
        char carry_over[4];

        carry_over[0] = 0;
        for (j = 0; j < 512; ++j) {
            if (NULL == fgets(line, sizeof(line), stdin))
                break;
            in_len = strlen(line);
            if (in_len > 0) {
                if ('\n' == line[in_len - 1]) {
                    --in_len;
                    line[in_len] = '\0';
                    split_line = false;
                } else
                    split_line = true;
            }
            if (in_len < 1) {
                carry_over[0] = 0;
                continue;
            }
            if (carry_over[0]) {
                if (isxdigit(line[0])) {
                    carry_over[1] = line[0];
                    carry_over[2] = '\0';
                    if (1 == sscanf(carry_over, "%x", &h))
                        mp_arr[off - 1] = h;       /* back up and overwrite */
                    else {
                        pr2serr("build_diag_page: carry_over error ['%s'] "
                                "around line %d\n", carry_over, j + 1);
                        return 1;
                    }
                    lcp = line + 1;
                    --in_len;
                } else
                    lcp = line;
                carry_over[0] = 0;
            } else
                lcp = line;
            m = strspn(lcp, " \t");
            if (m == in_len)
                continue;
            lcp += m;
            in_len -= m;
            if ('#' == *lcp)
                continue;
            k = strspn(lcp, "0123456789aAbBcCdDeEfF ,\t");
            if ((k < in_len) && ('#' != lcp[k])) {
                pr2serr("build_diag_page: syntax error at line %d, pos %d\n",
                        j + 1, m + k + 1);
                return 1;
            }
            for (k = 0; k < 1024; ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        pr2serr("build_diag_page: hex number larger than "
                                "0xff in line %d, pos %d\n", j + 1,
                                (int)(lcp - line + 1));
                        return 1;
                    }
                    if (split_line && (1 == strlen(lcp))) {
                        /* single trailing hex digit might be a split pair */
                        carry_over[0] = *lcp;
                    }
                    if ((off + k) >= max_arr_len) {
                        pr2serr("build_diag_page: array length exceeded\n");
                        return 1;
                    }
                    mp_arr[off + k] = h;
                    lcp = strpbrk(lcp, " ,\t");
                    if (NULL == lcp)
                        break;
                    lcp += strspn(lcp, " ,\t");
                    if ('\0' == *lcp)
                        break;
                } else {
                    if ('#' == *lcp) {
                        --k;
                        break;
                    }
                    pr2serr("build_diag_page: error in line %d, at pos %d\n",
                            j + 1, (int)(lcp - line + 1));
                    return 1;
                }
            }
            off += (k + 1);
        }
        *mp_arr_len = off;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF, ");
        if (in_len != k) {
            pr2serr("build_diag_page: error at pos %d\n", k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    pr2serr("build_diag_page: hex number larger than 0xff at "
                            "pos %d\n", (int)(lcp - inp + 1));
                    return 1;
                }
                mp_arr[k] = h;
                cp = (char *)strchr(lcp, ',');
                c2p = (char *)strchr(lcp, ' ');
                if (NULL == cp)
                    cp = c2p;
                if (NULL == cp)
                    break;
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                pr2serr("build_diag_page: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *mp_arr_len = k + 1;
        if (k == max_arr_len) {
            pr2serr("build_diag_page: array length exceeded\n");
            return 1;
        }
    }
    return 0;
}


struct page_code_desc {
        int page_code;
        const char * desc;
};
static struct page_code_desc pc_desc_arr[] = {
        {0x0, "Supported diagnostic pages"},
        {0x1, "Configuration (SES)"},
        {0x2, "Enclosure status/control (SES)"},
        {0x3, "Help text (SES)"},
        {0x4, "String In/Out (SES)"},
        {0x5, "Threshold In/Out (SES)"},
        {0x6, "Array Status/Control (SES, obsolete)"},
        {0x7, "Element descriptor (SES)"},
        {0x8, "Short enclosure status (SES)"},
        {0x9, "Enclosure busy (SES-2)"},
        {0xa, "Additional (device) element status (SES-2)"},
        {0xb, "Subenclosure help text (SES-2)"},
        {0xc, "Subenclosure string In/Out (SES-2)"},
        {0xd, "Supported SES diagnostic pages (SES-2)"},
        {0xe, "Download microcode diagnostic pages (SES-2)"},
        {0xf, "Subenclosure nickname diagnostic pages (SES-2)"},
        {0x3f, "Protocol specific (SAS transport)"},
        {0x40, "Translate address (direct access)"},
        {0x41, "Device status (direct access)"},
        {0x42, "Rebuild assist (direct access)"}, /* sbc3r31 */
};

static const char *
find_page_code_desc(int page_num)
{
    int k;
    int num = SG_ARRAY_SIZE(pc_desc_arr);
    const struct page_code_desc * pcdp = &pc_desc_arr[0];

    for (k = 0; k < num; ++k, ++pcdp) {
        if (page_num == pcdp->page_code)
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            return NULL;
    }
    return NULL;
}

static void
list_page_codes()
{
    int k;
    int num = SG_ARRAY_SIZE(pc_desc_arr);
    const struct page_code_desc * pcdp = &pc_desc_arr[0];

    printf("Page_Code  Description\n");
    for (k = 0; k < num; ++k, ++pcdp)
        printf(" 0x%02x      %s\n", pcdp->page_code,
               (pcdp->desc ? pcdp->desc : "<unknown>"));
}


int
main(int argc, char * argv[])
{
    int k, num, rsp_len, res, rsp_buff_size, pg, bd_len, resid, vb;
    int sg_fd = -1;
    int read_in_len = 0;
    int ret = 0;
    struct opts_t opts;
    struct opts_t * op;
    uint8_t * rsp_buff = NULL;
    uint8_t * free_rsp_buff = NULL;
    const char * cp;
    uint8_t * read_in = NULL;
    uint8_t * free_read_in = NULL;

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->maxlen = DEF_ALLOC_LEN;
    op->page_code = -1;
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (op->do_help) {
        if (op->opt_new)
            usage();
        else
            usage_old();
        return 0;
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
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }

    rsp_buff_size = op->maxlen;

    if (NULL == op->device_name) {
        if (op->do_list) {
            list_page_codes();
            return 0;
        }
        pr2serr("No DEVICE argument given\n\n");
        if (op->opt_new)
            usage();
        else
            usage_old();
        return SG_LIB_SYNTAX_ERROR;
    }
    vb = op->verbose;
    if (op->do_raw) {
        read_in = sg_memalign(op->maxlen, 0, &free_read_in, vb > 3);
        if (NULL == read_in) {
            pr2serr("unable to allocate %d bytes\n", op->maxlen);
            return SG_LIB_CAT_OTHER;
        }
        if (build_diag_page(op->raw_arg, read_in, &read_in_len, op->maxlen)) {
            if (op->opt_new) {
                printf("Bad sequence after '--raw=' option\n");
                usage();
            } else {
                printf("Bad sequence after '-raw=' option\n");
                usage_old();
            }
            ret = SG_LIB_SYNTAX_ERROR;
            goto fini;
        }
    }

    if ((op->do_doff || op->do_uoff) && (! op->do_deftest)) {
        if (op->opt_new) {
            printf("setting --doff or --uoff only useful when -t is set\n");
            usage();
        } else {
            printf("setting -doff or -uoff only useful when -t is set\n");
            usage_old();
        }
        ret = SG_LIB_CONTRADICT;
        goto fini;
    }
    if ((op->do_selftest > 0) && op->do_deftest) {
        if (op->opt_new) {
            printf("either set --selftest=SF or --test (not both)\n");
            usage();
        } else {
            printf("either set -s=SF or -t (not both)\n");
            usage_old();
        }
        ret = SG_LIB_CONTRADICT;
        goto fini;
    }
    if (op->do_raw) {
        if ((op->do_selftest > 0) || op->do_deftest || op->do_extdur ||
            op->do_list) {
            if (op->opt_new) {
                printf("'--raw=' cannot be used with self-tests, '-e' or "
                       "'-l'\n");
                usage();
            } else {
                printf("'-raw=' cannot be used with self-tests, '-e' or "
                       "'-l'\n");
                usage_old();
            }
            ret = SG_LIB_CONTRADICT;
            goto fini;
        }
        if (! op->do_pf) {
            if (op->opt_new)
                printf(">>> warning, '--pf' probably should be used with "
                       "'--raw='\n");
            else
                printf(">>> warning, '-pf' probably should be used with "
                       "'-raw='\n");
        }
    }
#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (vb > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    if (op->maxlen >= 16384)
        scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    if ((sg_fd = sg_cmds_open_device(op->device_name, false /* rw */, vb)) <
         0) {
        if (vb)
            pr2serr(ME "error opening file: %s: %s\n", op->device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }
    rsp_buff = sg_memalign(op->maxlen, 0, &free_rsp_buff, vb > 3);
    if (NULL == rsp_buff) {
        pr2serr("unable to allocate %d bytes (2)\n", op->maxlen);
        ret = SG_LIB_CAT_OTHER;
        goto close_fini;
    }
    if (op->do_extdur) {  /* fetch Extended self-test time from Control
                           * mode page with Mode Sense(10) command*/
        res = do_modes_0a(sg_fd, rsp_buff, 32, false /* mode6 */,
                          true /* noisy */, vb);
        if (0 == res) {
            /* Mode sense(10) response, step over any block descriptors */
            num = sg_msense_calc_length(rsp_buff, 32, false, &bd_len);
            num -= (8 /* MS(10) header length */ + bd_len);
            if (num >= 0xc) {
                int secs;

                secs = sg_get_unaligned_be16(rsp_buff + 8 + bd_len + 10);
#ifdef SG_LIB_MINGW
                printf("Expected extended self-test duration=%d seconds "
                       "(%g minutes)\n", secs, secs / 60.0);
#else
                printf("Expected extended self-test duration=%d seconds "
                       "(%.2f minutes)\n", secs, secs / 60.0);
#endif
            } else
                printf("Extended self-test duration not available\n");
        } else {
            ret = res;
            printf("Extended self-test duration (mode page 0xa) failed\n");
            goto err_out9;
        }
    } else if (op->do_list || (op->page_code >= 0x0)) {
        pg = op->page_code;
        if (pg < 0)
            res = do_senddiag(sg_fd, 0, true /* pf */, false, false, false,
                              rsp_buff, 4, op->timeout, 1, vb);
        else
            res = 0;
        if (0 == res) {
            resid = 0;
            if (0 == sg_ll_receive_diag_v2(sg_fd, (pg >= 0x0),
                                           ((pg >= 0x0) ? pg : 0), rsp_buff,
                                           rsp_buff_size, 0, &resid,
                                           true, vb)) {
                rsp_buff_size -= resid;
                if (rsp_buff_size < 4) {
                    pr2serr("RD resid (%d) indicates response too small "
                            "(lem=%d)\n", resid, rsp_buff_size);
                    goto err_out;
                }
                rsp_len = sg_get_unaligned_be16(rsp_buff + 2) + 4;
                rsp_len= (rsp_len < rsp_buff_size) ? rsp_len : rsp_buff_size;
                if (op->do_hex > 1)
                    hex2stdout(rsp_buff, rsp_len,
                            (2 == op->do_hex) ? 0 : -1);
                else if (pg < 0x1) {
                    printf("Supported diagnostic pages response:\n");
                    if (op->do_hex)
                        hex2stdout(rsp_buff, rsp_len, 1);
                    else {
                        for (k = 0; k < (rsp_len - 4); ++k) {
                            pg = rsp_buff[k + 4];
                            cp = find_page_code_desc(pg);
                            if (NULL == cp)
                                cp = (pg < 0x80) ? "<unknown>" :
                                                   "<vendor specific>";
                            printf("  0x%02x  %s\n", pg, cp);
                        }
                    }
                } else {
                    cp = find_page_code_desc(pg);
                    if (cp)
                        printf("%s diagnostic page [0x%x] response in "
                               "hex:\n", cp, pg);
                    else
                        printf("diagnostic page 0x%x response in hex:\n", pg);
                    hex2stdout(rsp_buff, rsp_len, 1);
                }
            } else {
                ret = res;
                pr2serr("RECEIVE DIAGNOSTIC RESULTS command failed\n");
                goto err_out9;
            }
        } else {
            ret = res;
            goto err_out;
        }
    } else if (op->do_raw) {
        res = do_senddiag(sg_fd, 0, op->do_pf, false, false, false, read_in,
                          read_in_len, op->timeout, 1, vb);
        if (res) {
            ret = res;
            goto err_out;
        }
    } else {
        res = do_senddiag(sg_fd, op->do_selftest, op->do_pf, op->do_deftest,
                          op->do_doff, op->do_uoff, NULL, 0, op->timeout, 1,
                          vb);
        if (0 == res) {
            if ((5 == op->do_selftest) || (6 == op->do_selftest))
                printf("Foreground self-test returned GOOD status\n");
            else if (op->do_deftest && (! op->do_doff) && (! op->do_uoff))
                printf("Default self-test returned GOOD status\n");
        } else {
            ret = res;
            goto err_out;
        }
    }
    goto close_fini;

err_out:
    if (SG_LIB_CAT_UNIT_ATTENTION == res)
        pr2serr("SEND DIAGNOSTIC, unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        pr2serr("SEND DIAGNOSTIC, aborted command\n");
    else if (SG_LIB_CAT_NOT_READY == res)
        pr2serr("SEND DIAGNOSTIC, device not ready\n");
    else
        pr2serr("SEND DIAGNOSTIC command, failed\n");
err_out9:
    if (vb < 2)
        pr2serr("  try again with '-vv' for more information\n");
close_fini:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (0 == ret)
            ret = sg_convert_errno(-res);
    }
fini:
    if (free_read_in)
        free(free_read_in);
    if (free_rsp_buff)
        free(free_rsp_buff);
    if (0 == vb) {
        if (! sg_if_can2stderr("sg_senddiag failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
