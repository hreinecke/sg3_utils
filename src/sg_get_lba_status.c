/*
 * Copyright (c) 2009-2023 Douglas Gilbert.
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
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"
#include "sg_json_sg_lib.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI GET LBA STATUS command to the given SCSI
 * device.
 */

static const char * version_str = "1.41 20230517";      /* sbc5r04 */

#define MY_NAME "sg_get_lba_status"

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif

#define MAX_GLBAS_BUFF_LEN (1024 * 1024)
#define DEF_GLBAS_BUFF_LEN 1024
#define MIN_MAXLEN 16

static uint8_t glbasFixedBuff[DEF_GLBAS_BUFF_LEN];

struct opts_t {
    bool do_16;
    bool do_32;
    bool do_json;
    bool do_raw;
    bool o_readonly;
    bool verbose_given;
    bool version_given;
    int blockhex;
    int do_brief;
    int do_hex;
    int maxlen;
    int rt;
    int verbose;
    uint32_t element_id;
    uint32_t scan_len;
    uint64_t lba;
    const char * in_fn;
    const char * json_arg;
    const char * js_file;
    sgj_state json_st;
};


static struct option long_options[] = {
    {"16", no_argument, 0, 'S'},
    {"32", no_argument, 0, 'T'},
    {"brief", no_argument, 0, 'b'},
    {"blockhex", no_argument, 0, 'B'},
    {"element-id", required_argument, 0, 'e'},
    {"element_id", required_argument, 0, 'e'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"in", required_argument, 0, 'i'},      /* silent, same as --inhex= */
    {"inhex", required_argument, 0, 'i'},
    {"json", optional_argument, 0, '^'},    /* short option is '-j' */
    {"js-file", required_argument, 0, 'J'},
    {"js_file", required_argument, 0, 'J'},
    {"lba", required_argument, 0, 'l'},
    {"maxlen", required_argument, 0, 'm'},
    {"raw", no_argument, 0, 'r'},
    {"readonly", no_argument, 0, 'R'},
    {"report-type", required_argument, 0, 't'},
    {"report_type", required_argument, 0, 't'},
    {"scan-len", required_argument, 0, 's'},
    {"scan_len", required_argument, 0, 's'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_get_lba_status  [--16] [--32] [--blockhex] "
            "[--brief]\n"
            "                          [--element-id=EI] [--help] [--hex] "
            "[--inhex=FN]\n"
            "                          [--json[=JO]] [--js_file=JFN] "
            "[--lba=LBA]\n"
            "                          [--maxlen=LEN] [--raw] [--readonly]\n"
            "                          [--report-type=RT] [--scan-len=SL] "
            "[--verbose]\n"
            "                          [--version] DEVICE\n"
            "  where:\n"
            "    --16|-S           use GET LBA STATUS(16) cdb (def)\n"
            "    --32|-T           use GET LBA STATUS(32) cdb\n"
            "    --blockhex|-B     outputs the (number of) blocks field "
            " in hex\n"
            "    --brief|-b        a descriptor per line:\n"
            "                          <lba_hex blocks_hex p_status "
            "add_status>\n"
            "                      use twice ('-bb') for given LBA "
            "provisioning status\n"
            "    --element-id=EI|-e EI      EI is the element identifier "
            "(def: 0)\n"
            "    --help|-h         print out usage message\n"
            "    --hex|-H          output in hexadecimal\n"
            "    --inhex=FN|-i FN    input taken from file FN rather than "
            "DEVICE,\n"
            "                        assumed to be ASCII hex or, if --raw, "
            "in binary\n"
            "    --json[=JO]|-j[=JO]    output in JSON instead of plain "
            "text\n"
            "                           Use --json=? for JSON help\n"
            "    --js-file=JFN|-J JFN    JFN is a filename to which JSON "
            "output is\n"
            "                            written (def: stdout); truncates "
            "then writes\n"
            "    --lba=LBA|-l LBA    starting LBA (logical block address) "
            "(def: 0)\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n",
            DEF_GLBAS_BUFF_LEN );
    pr2serr("    --raw|-r          output in binary, unless if --inhex=FN "
            "is given,\n"
            "                      in which case input file is binary\n"
            "    --readonly|-R     open DEVICE read-only (def: read-write)\n"
            "    --report-type=RT|-t RT    report type: 0->all LBAs (def);\n"
            "                                1-> LBAs with non-zero "
            "provisioning status\n"
            "                                2-> LBAs that are mapped\n"
            "                                3-> LBAs that are deallocated\n"
            "                                4-> LBAs that are anchored\n"
            "                                16-> LBAs that may return "
            "unrecovered error\n"
            "    --scan-len=SL|-s SL    SL in maximum scan length (unit: "
            "logical blocks)\n"
            "                           (def: 0 which implies no limit)\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Performs a SCSI GET LBA STATUS(16) or GET LBA STATUS(32) "
            "command (SBC-3 and\nSBC-4). The --element-id=EI and the "
            "--scan-len=SL fields are only active\non the 32 byte cdb "
            "variant. If --inhex=FN is given then contents of FN is\n"
            "assumed to be a response to this command.\n"
            );
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Decodes given LBA status descriptor passing back the starting LBA,
 * the number of blocks and returns the provisioning status, -1 for error.
 */
static int
decode_lba_status_desc(const uint8_t * bp, uint64_t * slbap,
                       uint32_t * blocksp, uint8_t * lba_accessp,
                       uint8_t * add_statusp)
{
    uint32_t blocks;
    uint64_t ull;

    if (NULL == bp)
        return -1;
    ull = sg_get_unaligned_be64(bp + 0);
    blocks = sg_get_unaligned_be32(bp + 8);
    if (slbap)
        *slbap = ull;
    if (blocksp)
        *blocksp = blocks;
    if (lba_accessp)    /* addition in sbc5r04.pdf */
        *lba_accessp = (bp[12] >> 4) & 0x7;
    if (add_statusp)
        *add_statusp = bp[13];
    return bp[12] & 0xf;        /* Provisioning status */
}

static char *
get_prov_status_str(int ps, char * b, int blen)
{
    switch (ps) {
    case 0:
        sg_scnpr(b, blen, "mapped (or unknown)");
        break;
    case 1:
        sg_scnpr(b, blen, "deallocated");
        break;
    case 2:
        sg_scnpr(b, blen, "anchored");
        break;
    case 3:
        sg_scnpr(b, blen, "mapped");         /* sbc4r12 */
        break;
    case 4:
        sg_scnpr(b, blen, "unknown");        /* sbc4r12 */
        break;
    default:
        sg_scnpr(b, blen, "unknown provisioning status: %d", ps);
        break;
    }
    return b;
}

static char *
get_pr_status_str(int as, char * b, int blen)
{
    switch (as) {
    case 0:
        sg_scnpr(b, blen, "%s", "");
        break;
    case 1:
        sg_scnpr(b, blen, "may contain unrecovered errors");
        break;
    default:
        sg_scnpr(b, blen, "unknown additional status: %d", as);
        break;
    }
    return b;
}

static char *
get_lba_access_str(int la, char * b, int blen, bool short_form)
{
    switch (la) {
    case 0:
        sg_scnpr(b, blen, "LBA access%s not reported",
                 short_form ? "" : "ibility is");
        break;
    case 1:
        sg_scnpr(b, blen, "LBA extent %s", short_form ? "inaccessible" :
                 "is not able to be written and not able to be read");
        break;
    case 2:
        sg_scnpr(b, blen, "LBA extent %sread-only", short_form ? "" : "is ");
        break;
    default:
        sg_scnpr(b, blen, "%sReserved [0x%x]", short_form ? "LBA access " :
                 "", la);       /* yes, short form is longer ! */
        break;
    }
    return b;
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
    case 'b':
        ++op->do_brief;
        break;
    case 'B':
        ++op->blockhex;
        break;
    case 'h':
    case '?':
        usage();
        return SG_LIB_OK_FALSE;
    case 'H':
        ++op->do_hex;
        break;
    case 'j':
        break;  /* simply ignore second 'j' (e.g. '-jxj') */
    case 'r':
        op->do_raw = true;
        break;
    case 'R':
        op->o_readonly = true;
        break;
    case 'S':
        op->do_16 = true;
        break;
    case 'T':
        op->do_32 = true;
        break;
    case 'v':
        op->verbose_given = true;
        ++op->verbose;
        break;
    case 'V':
        op->version_given = true;
        break;
    default:
        pr2serr("unrecognised option code %c [0x%x] ??\n", sopt_ch, sopt_ch);
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool no_final_msg = false;
    int k, res, c, n, rlen, num_descs, completion_cond, in_len;
    int sg_fd = -1;
    int ret = 0;
    uint8_t add_status = 0;     /* keep gcc quiet */
    uint8_t lba_access = 0;     /* keep gcc quiet */
    uint64_t d_lba = 0;
    uint32_t d_blocks = 0;
    int64_t ll;
    const char * device_name = NULL;
    const uint8_t * bp;
    uint8_t * glbasBuffp = glbasFixedBuff;
    uint8_t * free_glbasBuffp = NULL;
    struct opts_t * op;
    sgj_opaque_p jop = NULL;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_state * jsp;
    struct opts_t opts SG_C_CPP_ZERO_INIT;
    char b[196];
    static const size_t blen = sizeof(b);
    static const char * prov_stat_sn = "provisoning_status";
    static const char * add_stat_sn = "additional_status";
    static const char * lba_access_sn = "lba_accessibility";
    static const char * compl_cond_s = "Completion condition";
    static const char * compl_cond_sn = "completion_condition";

    op = &opts;
    op->maxlen = DEF_GLBAS_BUFF_LEN;
    if (getenv("SG3_UTILS_INVOCATION"))
        sg_rep_invocation(MY_NAME, version_str, argc, argv, stderr);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "^bBe:hi:j::J:Hl:m:rRs:St:TvV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            ++op->do_brief;
            break;
        case 'B':
            ++op->blockhex;
            break;
        case 'e':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--element-id'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->element_id = (uint32_t)ll;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            op->in_fn = optarg;
            break;
        case 'j':       /* for: -j[=JO] */
        case '^':       /* for: --json[=JO] */
            op->do_json = true;
            /* Now want '=' to precede all JSON optional arguments */
            if (optarg) {
                if ('^' == c) {
                    op->json_arg = optarg;
                    break;
                } else if ('=' == *optarg) {
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
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->lba = (uint64_t)ll;
            break;
        case 'm':
            op->maxlen = sg_get_num(optarg);
            if ((op->maxlen < 0) || (op->maxlen > MAX_GLBAS_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_GLBAS_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (0 == op->maxlen)
                op->maxlen = DEF_GLBAS_BUFF_LEN;
            else if (op->maxlen < MIN_MAXLEN) {
                pr2serr("Warning: --maxlen=LEN less than %d ignored\n",
                        MIN_MAXLEN);
                op->maxlen = DEF_GLBAS_BUFF_LEN;
            }
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'R':
            op->o_readonly = true;
            break;
        case 's':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--scan-len'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->scan_len = (uint32_t)ll;
            break;
        case 'S':
            op->do_16 = true;
            break;
        case 't':
            op->rt = sg_get_num_nomult(optarg);
            if ((op->rt < 0) || (op->rt > 255)) {
                pr2serr("'--report-type=RT' should be between 0 and 255 "
                        "(inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'T':
            op->do_32 = true;
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
            ret = SG_LIB_SYNTAX_ERROR;
            goto fini;
        }
        jop = sgj_start_r(MY_NAME, version_str, argc, argv, jsp);
    }

    if (op->maxlen > DEF_GLBAS_BUFF_LEN) {
        glbasBuffp = (uint8_t *)sg_memalign(op->maxlen, 0, &free_glbasBuffp,
                                            op->verbose > 3);
        if (NULL == glbasBuffp) {
            pr2serr("unable to allocate %d bytes on heap\n", op->maxlen);
            return sg_convert_errno(ENOMEM);
        }
    }
    if (device_name && op->in_fn) {
        pr2serr("ignoring DEVICE, best to give DEVICE or --inhex=FN, but "
                "not both\n");
        device_name = NULL;
    }
    if (NULL == device_name) {
        if (op->in_fn) {
            if ((ret = sg_f2hex_arr(op->in_fn, op->do_raw, false, glbasBuffp,
                                    &in_len, op->maxlen))) {
                if (SG_LIB_LBA_OUT_OF_RANGE == ret) {
                    no_final_msg = true;
                    pr2serr("... decode what we have, --maxlen=%d needs to "
                            "be increased\n", op->maxlen);
                } else
                    goto fini;
            }
            if (op->verbose > 2)
                pr2serr("Read %d [0x%x] bytes of user supplied data\n",
                        in_len, in_len);
            if (op->do_raw)
                op->do_raw = false;    /* can interfere on decode */
            if (in_len < 4) {
                pr2serr("--in=%s only decoded %d bytes (needs 4 at least)\n",
                        op->in_fn, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
                goto fini;
            }
            goto start_response;
        } else {
            pr2serr("missing device name!\n\n");
            usage();
            ret = SG_LIB_FILE_ERROR;
            no_final_msg = true;
            goto fini;
        }
    }
    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
    }
    if (op->do_16 && op->do_32) {
        pr2serr("both --16 and --32 given, choose --16\n");
        op->do_32 = false;
    } else if ((! op->do_16) && (! op->do_32)) {
        if (op->verbose > 3)
            pr2serr("choosing --16\n");
        op->do_16 = true;
    }
    if (op->do_16) {
        if (op->element_id != 0)
            pr2serr("Warning: --element_id= ignored with 16 byte cdb\n");
        if (op->scan_len != 0)
            pr2serr("Warning: --scan_len= ignored with 16 byte cdb\n");
    }
    sg_fd = sg_cmds_open_device(device_name, op->o_readonly, op->verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    res = 0;
    if (op->do_16)
        res = sg_ll_get_lba_status16(sg_fd, op->lba, op->rt, glbasBuffp,
                                     op->maxlen, true, op->verbose);
    else if (op->do_32)     /* keep analyser happy since do_32 must be true */
        res = sg_ll_get_lba_status32(sg_fd, op->lba, op->scan_len,
                                     op->element_id, op->rt, glbasBuffp,
                                     op->maxlen, true, op->verbose);

    ret = res;
    if (res)
        goto error;

start_response:
    /* in sbc3r25 offset for calculating the 'parameter data length'
     * (rlen variable below) was reduced from 8 to 4. */
    if (op->maxlen >= 4)
        rlen = sg_get_unaligned_be32(glbasBuffp + 0) + 4;
    else
        rlen = op->maxlen;
    k = (rlen > op->maxlen) ? op->maxlen : rlen;
    if (op->do_raw) {
        dStrRaw((const char *)glbasBuffp, k);
        goto fini;
    }
    if (op->do_hex) {
        if (op->do_hex > 2)
            hex2stdout(glbasBuffp, k, -1);
        else
            hex2stdout(glbasBuffp, k, (2 == op->do_hex) ? 0 : 1);
        goto fini;
    }
    if (op->maxlen < 4) {
        if (op->verbose)
            pr2serr("Exiting because allocation length (maxlen) less "
                    "than 4\n");
        goto fini;
    }
    if ((op->verbose > 1) || (op->verbose && (rlen > op->maxlen))) {
        pr2serr("response length %d bytes\n", rlen);
        if (rlen > op->maxlen)
            pr2serr("  ... which is greater than maxlen (allocation "
                    "length %d), truncation\n", op->maxlen);
    }
    if (rlen > op->maxlen)
        rlen = op->maxlen;

    if (op->do_brief > 1) {
        if (rlen > DEF_GLBAS_BUFF_LEN) {
            pr2serr("Need maxlen and response length to be at least %d, "
                    "have %d bytes\n", DEF_GLBAS_BUFF_LEN, rlen);
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
        res = decode_lba_status_desc(glbasBuffp + 8, &d_lba, &d_blocks,
                                     &lba_access, &add_status);
        if ((res < 0) || (res > 15)) {
            pr2serr("first LBA status descriptor returned %d ??\n", res);
            ret = SG_LIB_LOGIC_ERROR;
            goto fini;
        }
        if ((op->lba < d_lba) || (op->lba >= (d_lba + d_blocks))) {
            pr2serr("given LBA not in range of first descriptor:\n"
                    "  descriptor LBA: 0x%" PRIx64, d_lba);
            pr2serr("  blocks: 0x%x  lba_access: %d  p_status: %d  "
                    "add_status: 0x%x\n", (unsigned int)d_blocks, lba_access,
                    res, (unsigned int)add_status);
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
        sgj_pr_hr(jsp,"lba_access: %d, p_status: %d  add_status: 0x%x\n",
                  lba_access, res, (unsigned int)add_status);
        if (jsp->pr_as_json) {
            sgj_js_nv_i(jsp, jop, lba_access_sn, lba_access);
            sgj_js_nv_i(jsp, jop, prov_stat_sn, res);
            sgj_js_nv_i(jsp, jop, add_stat_sn, add_status);
        }
        goto fini;
    }

    if (rlen < 24) {
        sgj_pr_hr(jsp, "No complete LBA status descriptors available\n");
        goto fini;
    }
    num_descs = (rlen - 8) / 16;
    completion_cond = (*(glbasBuffp + 7) >> 1) & 7; /* added sbc4r14 */
    if (op->do_brief)
        sgj_haj_vi(jsp, jop, 0, compl_cond_s, SGJ_SEP_EQUAL_NO_SPACE,
                   completion_cond, true);
    else {
        switch (completion_cond) {
        case 0:
            snprintf(b, blen, "No indication of the completion condition");
            break;
        case 1:
            snprintf(b, blen, "Command completed due to meeting allocation "
                     "length");
            break;
        case 2:
            snprintf(b, blen, "Command completed due to meeting scan length");
            break;
        case 3:
            snprintf(b, blen, "Command completed due to meeting capacity of "
                   "medium");
            break;
        default:
            snprintf(b, blen, "Command completion is reserved [%d]",
                   completion_cond);
            break;
        }
        sgj_pr_hr(jsp, "%s\n", b);
        sgj_js_nv_istr(jsp, jop, compl_cond_sn, completion_cond,
                       NULL /* "meaning" */, b);
    }
    sgj_haj_vi(jsp, jop, 0, "RTP", SGJ_SEP_EQUAL_NO_SPACE,
               *(glbasBuffp + 7) & 0x1, true);    /* added sbc4r12 */
    if (op->verbose)
        pr2serr("%d complete LBA status descriptors found\n", num_descs);
    if (jsp->pr_as_json)
        jap = sgj_named_subarray_r(jsp, jop, "lba_status_descriptor");

    for (bp = glbasBuffp + 8, k = 0; k < num_descs; bp += 16, ++k) {
        res = decode_lba_status_desc(bp, &d_lba, &d_blocks, &lba_access,
                                     &add_status);
        if ((res < 0) || (res > 15))
            pr2serr("descriptor %d: bad LBA status descriptor returned "
                    "%d\n", k + 1, res);
        if (jsp->pr_as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        if (op->do_brief) { /* no LBA accessibility field */
            n = 0;
            n += sg_scnpr(b + n, blen - n, "0x%" PRIx64, d_lba);
            if ((0 == op->blockhex) || (1 == (op->blockhex % 2)))
                sg_scnpr(b + n, blen - n, "  0x%x  %d  %d",
                         (unsigned int)d_blocks, res, add_status);
            else
                sg_scnpr(b + n, blen - n, "  %u  %d  %d",
                         (unsigned int)d_blocks, res, add_status);
            sgj_pr_hr(jsp, "%s\n", b);
            sgj_js_nv_ihex(jsp, jo2p, "lba", d_lba);
            sgj_js_nv_ihex(jsp, jo2p, "blocks", d_blocks);
            sgj_js_nv_i(jsp, jo2p, prov_stat_sn, res);
            sgj_js_nv_i(jsp, jo2p, add_stat_sn, add_status);
        } else {
            if (jsp->pr_as_json) {
                sgj_js_nv_ihex(jsp, jo2p, "lba", d_lba);
                sgj_js_nv_ihex(jsp, jo2p, "blocks", d_blocks);
                sgj_js_nv_istr(jsp, jo2p, lba_access_sn, lba_access, NULL,
                       get_lba_access_str(lba_access, b, blen, false));
                sgj_js_nv_istr(jsp, jo2p, prov_stat_sn, res, NULL,
                               get_prov_status_str(res, b, blen));
                sgj_js_nv_istr(jsp, jo2p, add_stat_sn, add_status, NULL,
                               get_pr_status_str(add_status, b, blen));
            } else {
                char d[64];

                n = sg_scnpr(b, blen, "[%d] LBA: 0x%" PRIx64, k + 1, d_lba);
                if (n < 24)     /* add some padding spaces */
                    n += sg_scnpr(b + n, blen - n,  "%*c", 24 - n, ' ');
                if (1 == (op->blockhex % 2)) {

                    snprintf(d, sizeof(d), "0x%x", d_blocks);
                    n += sg_scnpr(b + n, blen - n, " blocks: %10s", d);
                } else
                    n += sg_scnpr(b + n, blen - n, " blocks: %10u", d_blocks);
                get_prov_status_str(res, d, sizeof(d));
                n += sg_scnpr(b + n, blen - n, "  %s;", d);
                get_lba_access_str(lba_access, d, sizeof(d), true);
                n += sg_scnpr(b + n, blen - n, "  %s", d);
                get_pr_status_str(add_status, d, sizeof(d));
                if (strlen(d) > 0)
                    sg_scnpr(b + n, blen - n, "  [%s]", d);
                sgj_pr_hr(jsp, "%s\n", b);
            }
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    if ((num_descs * 16) + 8 < rlen)
        pr2serr("incomplete trailing LBA status descriptors found\n");
    goto fini;

error:
    if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("Get LBA Status command not supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        pr2serr("Get LBA Status command: bad field in cdb\n");
    else {
        sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
        pr2serr("Get LBA Status command: %s\n", b);
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
    if (free_glbasBuffp)
        free(free_glbasBuffp);
    if ((0 == op->verbose) && (! no_final_msg)) {
        if (! sg_if_can2stderr("sg_get_lba_status failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    ret = (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
    if (jsp->pr_as_json) {
        FILE * fp = stdout;

        if (op->js_file) {
            if ((1 != strlen(op->js_file)) || ('-' != op->js_file[0])) {
                fp = fopen(op->js_file, "w");   /* truncate if exists */
                if (NULL == fp) {
                    int e = errno;

                    pr2serr("unable to open file: %s [%s]\n", op->js_file,
                            safe_strerror(e));
                    ret = sg_convert_errno(e);
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
