/*
 * Copyright (c) 2019-2023 Douglas Gilbert.
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
#include "sg_lib_data.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"
#include "sg_json.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI GET PHYSICAL ELEMENT STATUS command to the
 * given SCSI device.
 */

static const char * version_str = "1.22 20230519";      /* sbc5r04 */

#define MY_NAME "sg_get_elem_status"

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif

#define GET_PHY_ELEM_STATUS_SA 0x17
#define DEF_GPES_BUFF_LEN (1024 + 32)
#define MAX_GPES_BUFF_LEN ((1024 * 1024) + DEF_GPES_BUFF_LEN)
#define GPES_DESC_OFFSET 32     /* descriptors starts at this byte offset */
#define GPES_DESC_LEN 32
#define MIN_MAXLEN 16

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

struct opts_t {
    bool do_json;
    bool do_raw;
    bool o_readonly;
    bool verbose_given;
    bool version_given;
    uint8_t filter;
    uint8_t rt;
    int do_brief;
    int do_hex;
    int maxlen;
    int verbose;
    uint32_t starting_elem;
    const char * in_fn;
    const char * json_arg;
    const char * js_file;
    sgj_state json_st;
};

struct gpes_desc_t {    /* info in returned physical status descriptor */
    bool restoration_allowed;   /* RALWD bit in sbc4r20a */
    uint32_t elem_id;
    uint8_t phys_elem_type;
    uint8_t phys_elem_health;
    uint64_t assoc_cap;   /* number of LBs removed if depopulated */
};

static uint8_t gpesBuff[DEF_GPES_BUFF_LEN];


static struct option long_options[] = {
    {"brief", no_argument, 0, 'b'},
    {"filter", required_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"in", required_argument, 0, 'i'},      /* silent, same as --inhex= */
    {"inhex", required_argument, 0, 'i'},
    {"json", optional_argument, 0, '^'},    /* short option is '-j' */
    {"js-file", required_argument, 0, 'J'},
    {"js_file", required_argument, 0, 'J'},
    {"maxlen", required_argument, 0, 'm'},
    {"raw", no_argument, 0, 'r'},
    {"readonly", no_argument, 0, 'R'},
    {"report-type", required_argument, 0, 't'},
    {"report_type", required_argument, 0, 't'},
    {"starting", required_argument, 0, 's'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_get_elem_status  [--brief] [--filter=FLT] [--help] "
            "[--hex]\n"
            "                           [--inhex=FN] [--json[=JO]] "
            "[--js-file=JFN]\n"
            "                           [--maxlen=LEN] [--raw] "
            "[--readonly]\n"
            "                           [--report-type=RT] [--starting=ELEM] "
            "[--verbose]\n"
            "                           [--version] DEVICE\n"
            "  where:\n"
            "    --brief|-b        one descriptor per line\n"
            "    --filter=FLT|-f FLT    FLT is 0 (def) for all physical "
            "elements;\n"
            "                           1 for out of spec and depopulated "
            "elements\n"
            "    --help|-h         print out usage message\n"
            "    --hex|-H          output in hexadecimal\n"
            "    --inhex=FN|-i FN    input taken from file FN rather than "
            "DEVICE,\n"
            "                        assumed to be ASCII hex or, if --raw, "
            "in binary\n"
            "    --json[=JO]|-j[=JO]     output in JSON instead of plain "
            "text\n"
            "                            use --json=? for JSON help\n"
            "    --js-file=JFN|-J JFN    JFN is a filename to which JSON "
            "output is\n"
            "                            written (def: stdout); truncates "
            "then writes\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n",
            DEF_GPES_BUFF_LEN );
    pr2serr("    --raw|-r          output in binary, unless --inhex=FN is "
            "given in\n"
            "                      in which case the input is assumed to be "
            "binary\n"
            "    --readonly|-R     open DEVICE read-only (def: read-write)\n"
            "    --report-type=RT|-t RT    report type: 0-> physical "
            "elements (def);\n"
            "                                           1-> storage "
            "elements\n"
            "    --starting=ELEM|-s ELEM    ELEM is the lowest identifier "
            "returned\n"
            "                               (def: 1 which is lowest "
            "identifier)\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Performs a SCSI GET PHYSICAL ELEMENT STATUS command (see SBC-3 "
            "or SBC-4).\nStorage elements are a sub-set of physical "
            "elements. Currently the only\ntype of physical element is a "
            "storage element. If --inhex=FN is given then\ncontents of FN "
            "is assumed to be a response to this command in ASCII hex.\n"
            "Returned element descriptors should be in ascending "
            "identifier order.\n"
            );
}

/* Invokes a SCSI GET PHYSICAL ELEMENT STATUS command (SBC-4).  Return of
 * 0 -> success, various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_get_phy_elem_status(int sg_fd, uint8_t * resp, int * residp,
                          struct opts_t * op)
{
    int k, ret, res, sense_cat;
    uint8_t gpesCmd[16] = {SG_SERVICE_ACTION_IN_16,
                           GET_PHY_ELEM_STATUS_SA, 0, 0, 0, 0,
                           0, 0, 0, 0,  0, 0, 0, 0,  0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    struct sg_pt_base * ptvp;
    static const char * const cmd_name = "Get physical element status";

    if (op->starting_elem)
        sg_put_unaligned_be32(op->starting_elem, gpesCmd + 6);
    sg_put_unaligned_be32(op->maxlen, gpesCmd + 10);
    if (op->filter)
        gpesCmd[14] |= op->filter << 6;
    if (op->rt)
        gpesCmd[14] |= (0xf & op->rt);
    if (op->verbose) {
        char b[128];

        pr2serr("    %s cdb: %s\n", cmd_name,
                sg_get_command_str(gpesCmd, (int)sizeof(gpesCmd), false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj_with_fd(sg_fd, op->verbose);
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", cmd_name);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, gpesCmd, sizeof(gpesCmd));
    set_scsi_pt_data_in(ptvp, resp, op->maxlen);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, -1, DEF_PT_TIMEOUT, op->verbose);
    ret = sg_cmds_process_resp(ptvp, cmd_name, res, true, op->verbose,
                               &sense_cat);
    if (-1 == ret) {
        if (get_scsi_pt_transport_err(ptvp))
            ret = SG_LIB_TRANSPORT_ERROR;
        else
            ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    } else if (-2 == ret) {
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
    k = ret ? (int)op->maxlen : get_scsi_pt_resid(ptvp);
    if (residp)
        *residp = k;
    if ((op->verbose > 2) && ((op->maxlen - k) > 0)) {
        pr2serr("%s: parameter data returned:\n", cmd_name);
        hex2stderr((const uint8_t *)resp, op->maxlen - k,
                   ((op->verbose > 3) ? -1 : 1));
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Decodes given physical element status descriptor.  */
static void
decode_elem_status_desc(const uint8_t * bp, struct gpes_desc_t * pedp)
{
    if ((NULL == bp) || (NULL == pedp))
        return;
    pedp->elem_id = sg_get_unaligned_be32(bp + 4);
    pedp->restoration_allowed = (bool)(bp[13] & 1);
    pedp->phys_elem_type = bp[14];
    pedp->phys_elem_health = bp[15];
    pedp->assoc_cap = sg_get_unaligned_be64(bp + 16);
}

static bool
fetch_health_str(uint8_t health, char * bp, int max_blen)
{
    bool add_val = false;
    const char * cp = NULL;

    if  (0 == health)
        cp = "not reported";
    else if (health < 0x64) {
        cp = "within manufacturer's specification limits";
        add_val = true;
    } else if (0x64 == health) {
        cp = "at manufacturer's specification limits";
        add_val = true;
    } else if (health < 0xd0) {
        cp = "outside manufacturer's specification limits";
        add_val = true;
    } else if (health < 0xfb) {
        cp = "reserved";
        add_val = true;
    } else if (0xfb == health)
        cp = "depopulation revocation completed, errors detected";
    else if (0xfc == health)
        cp = "depopulation revocation in progress";
    else if (0xfd == health)
        cp = "depopulation completed, errors detected";
    else if (0xfe == health)
        cp = "depopulation operations in progress";
    else if (0xff == health)
        cp = "depopulation completed, no errors";
    snprintf(bp, max_blen, "%s", cp);
    return add_val;
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
    int k, j, m, n, q, res, c, rlen, in_len;
    int sg_fd = -1;
    int resid = 0;
    int ret = 0;
    uint16_t cur_max_num_depop, cur_num_depop;
    uint32_t num_desc, num_desc_ret, id_elem_depop;
    int64_t ll;
    const char * device_name = NULL;
    const char * cp;
    const uint8_t * bp;
    uint8_t * gpesBuffp = gpesBuff;
    uint8_t * free_gpesBuffp = NULL;
    struct opts_t * op;
    sgj_opaque_p jop = NULL;
    sgj_opaque_p jo2p;
    sgj_opaque_p jap = NULL;
    sgj_state * jsp;
    struct gpes_desc_t a_ped;
    char b[80];
    struct opts_t opts SG_C_CPP_ZERO_INIT;
    static const int blen = sizeof(b);
    static const char * cmnode_s =
                "Current maximum number of depopulated elements";

    op = &opts;
    op->maxlen = DEF_GPES_BUFF_LEN;
    if (getenv("SG3_UTILS_INVOCATION"))
        sg_rep_invocation(MY_NAME, version_str, argc, argv, stderr);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "^bf:hHi:j::J:m:rRs:St:TvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            ++op->do_brief;
            break;
        case 'f':
            n = sg_get_num_nomult(optarg);
            if ((n < 0) || (n > 15)) {
                pr2serr("'--filter=RT' should be between 0 and 15 "
                        "(inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->filter = n;
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
                    q = chk_short_opts(*(optarg + k), op);
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
        case 'm':
            op->maxlen = sg_get_num(optarg);
            if ((op->maxlen < 0) || (op->maxlen > MAX_GPES_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_GPES_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (0 == op->maxlen)
                op->maxlen = DEF_GPES_BUFF_LEN;
            else if (op->maxlen < MIN_MAXLEN) {
                pr2serr("Warning: --maxlen=LEN less than %d ignored\n",
                        MIN_MAXLEN);
                op->maxlen = DEF_GPES_BUFF_LEN;
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
                pr2serr("bad argument to '--starting='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->starting_elem = (uint32_t)ll;
            break;
        case 't':       /* --report-type=RT */
            n = sg_get_num_nomult(optarg);
            if ((n < 0) || (n > 15)) {
                pr2serr("'--report-type=RT' should be between 0 and 15 "
                        "(inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->rt = n;
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

    if (op->maxlen > DEF_GPES_BUFF_LEN) {
        gpesBuffp = (uint8_t *)sg_memalign(op->maxlen, 0, &free_gpesBuffp,
                                           op->verbose > 3);
        if (NULL == gpesBuffp) {
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
            if ((ret = sg_f2hex_arr(op->in_fn, op->do_raw, false, gpesBuffp,
                                    &in_len, op->maxlen))) {
                if (SG_LIB_LBA_OUT_OF_RANGE == ret) {
                    pr2serr("--maxlen=%d needs to be increased", op->maxlen);
                    if (in_len > 7) {
                        n = (sg_get_unaligned_be32(gpesBuffp + 4) *
                             GPES_DESC_LEN) + GPES_DESC_OFFSET;
                        pr2serr(" to at least %d\n", n);
                    } else
                        pr2serr("\n");
                    pr2serr("... decode what we have\n");
                    no_final_msg = true;
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
    sg_fd = sg_cmds_open_device(device_name, op->o_readonly, op->verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    res = sg_ll_get_phy_elem_status(sg_fd, gpesBuffp, &resid, op);
    ret = res;
    if (res)
        goto error;

start_response:
    k = op->maxlen - resid;
    if (k < 4) {
        pr2serr("Response too short (%d bytes) due to resid (%d)\n", k,
                resid);
        if ((k > 0) && (op->do_raw || op->do_hex)) {
            if (op->do_hex) {
                if (op->do_hex > 2)
                    hex2stdout(gpesBuffp, k, -1);
                else
                    hex2stdout(gpesBuffp, k, (2 == op->do_hex) ? 0 : 1);
            } else
                dStrRaw((const char *)gpesBuffp, k);
        }
        ret = SG_LIB_CAT_MALFORMED;
        goto fini;
    } else
        op->maxlen -= resid;
    num_desc = sg_get_unaligned_be32(gpesBuffp + 0);
    if (op->maxlen > 7) {
        num_desc_ret = sg_get_unaligned_be32(gpesBuffp + 4);
        id_elem_depop = (op->maxlen > 11) ?
                                sg_get_unaligned_be32(gpesBuffp + 8) : 0;
        cur_max_num_depop = (op->maxlen > 13) ?
                                sg_get_unaligned_be16(gpesBuffp + 12) : 0;
        cur_num_depop = (op->maxlen > 15) ?
                                sg_get_unaligned_be16(gpesBuffp + 14) : 0;
    } else {
        num_desc_ret = 0;
        id_elem_depop = 0;
        cur_max_num_depop = 0;
        cur_num_depop = 0;
    }
    rlen = (num_desc_ret * GPES_DESC_LEN) + GPES_DESC_OFFSET;
    if ((op->verbose > 1) || (op->verbose && (rlen > op->maxlen))) {
        pr2serr("response length %d bytes\n", rlen);
        if (rlen > op->maxlen)
            pr2serr("  ... which is greater than maxlen (allocation "
                    "length %d), truncation\n", op->maxlen);
    }
    if (rlen > op->maxlen)
        rlen = op->maxlen;
    if (op->do_raw) {
        dStrRaw((const char *)gpesBuffp, rlen);
        goto fini;
    }
    if (op->do_hex) {
        if (op->do_hex > 2)
            hex2stdout(gpesBuffp, rlen, -1);
        else
            hex2stdout(gpesBuffp, rlen,  (2 == op->do_hex) ? 0 : 1);
        goto fini;
    }

    sgj_haj_vi(jsp, jop, 0, "Number of descriptors",
               SGJ_SEP_COLON_1_SPACE, num_desc, true);
    sgj_haj_vi(jsp, jop, 0, "Number of descriptors returned",
               SGJ_SEP_COLON_1_SPACE, num_desc_ret, true);
    sgj_haj_vi(jsp, jop, 0, "Identifier of element being depopulated",
               SGJ_SEP_COLON_1_SPACE, id_elem_depop, true);
    if (cur_max_num_depop > 0)
        sgj_haj_vi(jsp, jop, 0, cmnode_s, SGJ_SEP_COLON_1_SPACE,
                   cur_max_num_depop, false);
    else
        sgj_haj_vs(jsp, jop, 0, cmnode_s, SGJ_SEP_COLON_1_SPACE,
                   "not reported");
    sgj_haj_vi(jsp, jop, 0, "Current number of depopulated elements",
               SGJ_SEP_COLON_1_SPACE, cur_num_depop, false);
    if (rlen < 64) {
        sgj_pr_hr(jsp, "No complete physical element status descriptors "
                  "available\n");
        goto fini;
    } else {
        if (op->do_brief > 2)
            goto fini;
        sgj_pr_hr(jsp, "\n");
    }

    if (jsp->pr_as_json)
        jap = sgj_named_subarray_r(jsp, jop,
                                   "physical_element_status_descriptor_list");
    for (bp = gpesBuffp + GPES_DESC_OFFSET, k = 0; k < (int)num_desc_ret;
         bp += GPES_DESC_LEN, ++k) {
        if ((0 == k) && (op->do_brief < 2))
            sgj_pr_hr(jsp, "Element descriptors:\n");
        decode_elem_status_desc(bp, &a_ped);
        if (jsp->pr_as_json) {
            jo2p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihex(jsp, jo2p, "element_identifier",
                           (int64_t)a_ped.elem_id);
            cp = (1 == a_ped.phys_elem_type) ? "storage" : "reserved";
            sgj_js_nv_istr(jsp, jo2p, "physical_element_type",
                           a_ped.phys_elem_type, "meaning", cp);
            j = a_ped.phys_elem_health;
            fetch_health_str(j, b, blen);
            sgj_js_nv_istr(jsp, jo2p, "physical_element_health", j, NULL, b);
            sgj_js_nv_ihex(jsp, jo2p, "associated_capacity",
                           (int64_t)a_ped.assoc_cap);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        } else if (op->do_brief) {
            sgj_pr_hr(jsp, "%u: %u,%u\n", a_ped.elem_id, a_ped.phys_elem_type,
                      a_ped.phys_elem_health);
        } else {
            char b2[144];
            static const int b2len = sizeof(b2);

            m = sg_scnpr(b2, b2len, "[%d] identifier: 0x%06x", k + 1,
                         a_ped.elem_id);
            if (sg_all_ffs((const uint8_t *)&a_ped.assoc_cap, 8))
                m += sg_scn3pr(b2, b2len, m,
                               "  associated LBs: not specified;  ");
            else
                m += sg_scn3pr(b2, b2len, m, "  associated LBs: 0x%" PRIx64
                               ";  ", a_ped.assoc_cap);
            m += sg_scn3pr(b2, b2len, m, "health: ");
            j = a_ped.phys_elem_health;
            if (fetch_health_str(j, b, blen))
                m += sg_scn3pr(b2, b2len, m, "%s <%d>", b, j);
            else
                m += sg_scn3pr(b2, b2len, m, "%s", b);
            if (a_ped.restoration_allowed)
                sg_scn3pr(b2, b2len, m, " [restoration allowed [RALWD]]");
            sgj_pr_hr(jsp, "%s\n", b2);
        }
    }
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
    if (free_gpesBuffp)
        free(free_gpesBuffp);
    if ((0 == op->verbose) && (! no_final_msg)) {
        if (! sg_if_can2stderr("sg_get_elem_status failed: ", ret))
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
        if (fp) {
            const char * estr = NULL;

            if (sg_exit2str(ret, jsp->verbose, blen, b)) {
                if (strlen(b) > 0)
                    estr = b;
            }
            sgj_js2file_estr(jsp, NULL, ret, estr, fp);
        }
        if (op->js_file && fp && (stdout != fp))
            fclose(fp);
        sgj_finish(jsp);
    }
    return ret;
}
