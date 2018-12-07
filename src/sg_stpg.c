/*
* Copyright (c) 2004-2018 Hannes Reinecke, Christophe Varoqui, Douglas Gilbert
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
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command SET TARGET PORT GROUPS
 * to the given SCSI device.
 */

static const char * version_str = "1.19 20180628";

#define TGT_GRP_BUFF_LEN 1024
#define MX_ALLOC_LEN (0xc000 + 0x80)

#define TPGS_STATE_OPTIMIZED 0x0
#define TPGS_STATE_NONOPTIMIZED 0x1
#define TPGS_STATE_STANDBY 0x2
#define TPGS_STATE_UNAVAILABLE 0x3
#define TPGS_STATE_OFFLINE 0xe          /* SPC-4 rev 9 */
#define TPGS_STATE_TRANSITIONING 0xf

/* See also table 306 - Target port group descriptor format in SPC-4 rev 36e */
#ifdef __cplusplus

// C++ does not support designated initializers
static const uint8_t state_sup_mask[] = {
    0x1, 0x2, 0x4, 0x8, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x80,
};

#else

static const uint8_t state_sup_mask[] = {
        [TPGS_STATE_OPTIMIZED]     = 0x01,
        [TPGS_STATE_NONOPTIMIZED]  = 0x02,
        [TPGS_STATE_STANDBY]       = 0x04,
        [TPGS_STATE_UNAVAILABLE]   = 0x08,
        [TPGS_STATE_OFFLINE]       = 0x40,
        [TPGS_STATE_TRANSITIONING] = 0x80,
};

#endif  /* C or C++ ? */

#define VPD_DEVICE_ID  0x83
#define DEF_VPD_DEVICE_ID_LEN  252

#define MAX_PORT_LIST_ARR_LEN 16

struct tgtgrp {
        int id;
        int current;
        int valid;
};

static struct option long_options[] = {
        {"active", no_argument, 0, 'a'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"offline", no_argument, 0, 'l'},
        {"optimized", no_argument, 0, 'o'},
        {"raw", no_argument, 0, 'r'},
        {"standby", no_argument, 0, 's'},
        {"state", required_argument, 0, 'S'},
        {"tp", required_argument, 0, 't'},
        {"unavailable", no_argument, 0, 'u'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_stpg   [--active] [--help] [--hex] [--offline] "
            "[--optimized] [--raw]\n"
            "                 [--standby] [--state=S,S...] [--tp=P,P...] "
            "[--unavailable]\n"
            "                 [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --active|-a        set asymm. access state to "
            "active/non-optimized\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           print out report response in hex, then "
            "exit\n"
            "    --offline|-l|-O    set asymm. access state to offline, takes "
            "relative\n"
            "                       target port id, rather than target port "
            "group id\n"
            "    --optimized|-o     set asymm. access state to "
            "active/optimized\n"
            "    --raw|-r           output report response in binary to "
            "stdout, then exit\n"
            "    --standby|-s       set asymm. access state to standby\n"
            "    --state=S,S.. |-S S,S...     list of states (values or "
            "acronyms)\n"
            "    --tp=P,P.. |-t P,P...        list of target port group "
            "identifiers,\n"
            "                                 or relative target port "
            "identifiers\n"
            "    --unavailable|-u   set asymm. access state to unavailable\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI SET TARGET PORT GROUPS command\n");
}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

static int
decode_target_port(uint8_t * buff, int len, int *d_id, int *d_tpg)
{
    int c_set, assoc, desig_type, i_len;
    int off, u;
    const uint8_t * bp;
    const uint8_t * ip;

    *d_id = -1;
    *d_tpg = -1;
    off = -1;
    while ((u = sg_vpd_dev_id_iter(buff, len, &off, -1, -1, -1)) == 0) {
        bp = buff + off;
        i_len = bp[3];
        if ((off + i_len + 4) > len) {
            pr2serr("    VPD page error: designator length longer than\n     "
                    "remaining response length=%d\n", (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        ip = bp + 4;
        c_set = (bp[0] & 0xf);
        /* piv = ((bp[1] & 0x80) ? 1 : 0); */
        assoc = ((bp[1] >> 4) & 0x3);
        desig_type = (bp[1] & 0xf);
        switch (desig_type) {
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                pr2serr("      << expected binary code_set, target port "
                        "association, length 4>>\n");
                hex2stderr(ip, i_len, 0);
                break;
            }
            *d_id = sg_get_unaligned_be16(ip + 2);
            break;
        case 5: /* (primary) Target port group */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                pr2serr("      << expected binary code_set, target port "
                        "association, length 4>>\n");
                hex2stderr(ip, i_len, 0);
                break;
            }
            *d_tpg = sg_get_unaligned_be16(ip + 2);
            break;
        default:
            break;
        }
    }
    if (-1 == *d_id || -1 == *d_tpg) {
        pr2serr("VPD page error: no target port group information\n");
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
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
    case TPGS_STATE_OFFLINE:
        printf(" (offline)");
        break;
    case TPGS_STATE_TRANSITIONING:
        printf(" (transitioning between states)");
        break;
    default:
        printf(" (unknown: 0x%x)", st);
        break;
    }
}

static int
transition_tpgs_states(struct tgtgrp *tgtState, int numgrp, int portgroup,
                       int newstate)
{
     int i,oldstate;

     for ( i = 0; i < numgrp; i++) {
          if (tgtState[i].id == portgroup)
               break;
     }
     if (i == numgrp) {
          printf("Portgroup 0x%02x does not exist\n", portgroup);
          return 1;
     }

     if (!( state_sup_mask[newstate] & tgtState[i].valid )) {
          printf("Portgroup 0x%02x: Invalid state 0x%x\n",
                 portgroup, newstate);
          return 1;
     }
     oldstate = tgtState[i].current;
     tgtState[i].current = newstate;
     if (newstate == TPGS_STATE_OPTIMIZED) {
          /* Switch with current optimized path */
          for ( i = 0; i < numgrp; i++) {
               if (tgtState[i].id == portgroup)
                    continue;
               if (tgtState[i].current == TPGS_STATE_OPTIMIZED)
                    tgtState[i].current = oldstate;
          }
     } else if (oldstate == TPGS_STATE_OPTIMIZED) {
          /* Enable next path group */
          for ( i = 0; i < numgrp; i++) {
               if (tgtState[i].id == portgroup)
                    continue;
               if (tgtState[i].current == TPGS_STATE_NONOPTIMIZED) {
                    tgtState[i].current = TPGS_STATE_OPTIMIZED;
                    break;
               }
          }
     }
     printf("New target port groups:\n");
     for (i = 0; i < numgrp; i++) {
            printf("  target port group id : 0x%x\n",
                   tgtState[i].id);
            printf("    target port group asymmetric access state : ");
            printf("0x%02x\n", tgtState[i].current);
     }
     return 0;
}

static void
encode_tpgs_states(uint8_t *buff, struct tgtgrp *tgtState, int numgrp)
{
     int i;
     uint8_t *desc;

     for (i = 0, desc = buff + 4; i < numgrp; desc += 4, i++) {
          desc[0] = tgtState[i].current & 0x0f;
          sg_put_unaligned_be16((uint16_t)tgtState[i].id, desc + 2);
     }
}

/* Read numbers (up to 32 bits in size) from command line (comma separated
 * list). Assumed decimal unless prefixed by '0x', '0X' or contains traling
 * 'h' or 'H' (which indicate hex). Returns 0 if ok, else error code. */
static int
build_port_arr(const char * inp, int * port_arr, int * port_arr_len,
               int max_arr_len)
{
    int in_len, k;
    const char * lcp;
    int v;
    char * cp;

    if ((NULL == inp) || (NULL == port_arr) ||
        (NULL == port_arr_len))
        return SG_LIB_LOGIC_ERROR;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *port_arr_len = 0;
    k = strspn(inp, "0123456789aAbBcCdDeEfFhHxX,");
    if (in_len != k) {
        pr2serr("%s: error at pos %d\n", __func__, k + 1);
        return SG_LIB_SYNTAX_ERROR;
    }
    for (k = 0; k < max_arr_len; ++k) {
        v = sg_get_num_nomult(lcp);
        if (-1 != v) {
            port_arr[k] = v;
            cp = (char *)strchr(lcp, ',');
            if (NULL == cp)
                break;
            lcp = cp + 1;
        } else {
            pr2serr("%s: error at pos %d\n", __func__, (int)(lcp - inp + 1));
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    *port_arr_len = k + 1;
    if (k == max_arr_len) {
        pr2serr("%s: array length exceeded\n", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    return 0;
}

/* Read numbers (up to 32 bits in size) from command line (comma separated
 * list). Assumed decimal unless prefixed by '0x', '0X' or contains trailing
 * 'h' or 'H' (which indicate hex). Also accepts 'ao' for active optimized
 * [0], 'an' for active/non-optimized [1], 's' for standby [2], 'u' for
 * unavailable [3], 'o' for offline [14]. Returns 0 if ok, else error code. */
static int
build_state_arr(const char * inp, int * state_arr, int * state_arr_len,
                int max_arr_len)
{
    bool try_num;
    int in_len, k, v;
    const char * lcp;
    char * cp;

    if ((NULL == inp) || (NULL == state_arr) ||
        (NULL == state_arr_len))
        return SG_LIB_LOGIC_ERROR;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *state_arr_len = 0;
    k = strspn(inp, "0123456789aAbBcCdDeEfFhHnNoOsSuUxX,");
    if (in_len != k) {
        pr2serr("%s: error at pos %d\n", __func__, k + 1);
        return SG_LIB_SYNTAX_ERROR;
    }
    for (k = 0; k < max_arr_len; ++k) {
        try_num = true;
        if (isalpha(*lcp)) {
            try_num = false;
            switch (toupper(*lcp)) {
            case 'A':
                if ('N' == toupper(*(lcp + 1)))
                    state_arr[k] = 1;
                else if ('O' == toupper(*(lcp + 1)))
                    state_arr[k] = 0;
                else
                    try_num = true;
                break;
            case 'O':
                state_arr[k] = 14;
                break;
            case 'S':
                state_arr[k] = 2;
                break;
            case 'U':
                state_arr[k] = 3;
                break;
            default:
                pr2serr("%s: expected 'ao', 'an', 'o', 's' or 'u' at pos "
                        "%d\n", __func__, (int)(lcp - inp + 1));
                return SG_LIB_SYNTAX_ERROR;
            }
        }
        if (try_num) {
            v = sg_get_num_nomult(lcp);
            if (((v >= 0) && (v <= 3)) || (14 ==v))
                state_arr[k] = v;
            else if (-1 == v) {
                pr2serr("%s: error at pos %d\n", __func__,
                        (int)(lcp - inp + 1));
                return SG_LIB_SYNTAX_ERROR;
            } else {
                pr2serr("%s: expect 0,1,2,3 or 14\n", __func__);
                return SG_LIB_SYNTAX_ERROR;
            }
        }
        cp = (char *)strchr(lcp, ',');
        if (NULL == cp)
            break;
        lcp = cp + 1;
    }
    *state_arr_len = k + 1;
    if (k == max_arr_len) {
        pr2serr("%s: array length exceeded\n", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool hex = false;
    bool raw = false;
    bool verbose_given = false;
    bool version_given = false;
    int k, off, res, c, report_len, tgt_port_count;
    int sg_fd = -1;
    int port_arr_len = 0;
    int verbose = 0;
    uint8_t reportTgtGrpBuff[TGT_GRP_BUFF_LEN];
    uint8_t setTgtGrpBuff[TGT_GRP_BUFF_LEN];
    uint8_t rsp_buff[MX_ALLOC_LEN + 2];
    uint8_t * bp;
    struct tgtgrp tgtGrpState[256], *tgtStatePtr;
    int state = -1;
    const char * state_arg = NULL;
    const char * tp_arg = NULL;
    int port_arr[MAX_PORT_LIST_ARR_LEN];
    int state_arr[MAX_PORT_LIST_ARR_LEN];
    char b[80];
    int state_arr_len = 0;
    int portgroup = -1;
    int relport = -1;
    int numgrp = 0;
    const char * device_name = NULL;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ahHloOrsS:t:uvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            state = TPGS_STATE_NONOPTIMIZED;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            hex = true;
            break;
        case 'l':
        case 'O':
            state = TPGS_STATE_OFFLINE;
            break;
        case 'o':
            state = TPGS_STATE_OPTIMIZED;
            break;
        case 'r':
            raw = true;
            break;
        case 's':
            state = TPGS_STATE_STANDBY;
            break;
        case 'S':
            state_arg = optarg;
            break;
        case 't':
            tp_arg = optarg;
            break;
        case 'u':
            state = TPGS_STATE_UNAVAILABLE;
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

    if (state_arg) {
        if ((ret = build_state_arr(state_arg, state_arr, &state_arr_len,
                                   MAX_PORT_LIST_ARR_LEN))) {
            usage();
            return ret;
        }
    }
    if (tp_arg) {
        if ((ret = build_port_arr(tp_arg, port_arr, &port_arr_len,
                                  MAX_PORT_LIST_ARR_LEN))) {
            usage();
            return ret;
        }
    }
    if ((state >= 0) && (state_arr_len > 0)) {
        pr2serr("either use individual state option or '--state=' but not "
                "both\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((0 == state_arr_len) && (0 == port_arr_len) && (-1 == state))
        state = 0;      /* default to active/optimized */
    if ((1 == state_arr_len) && (0 == port_arr_len) && (-1 == state)) {
        state = state_arr[0];
        state_arr_len = 0;
    }
    if (state_arr_len > port_arr_len) {
        pr2serr("'state=' list longer than expected\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((port_arr_len > 0) && (0 == state_arr_len)) {
        if (-1 == state) {
            pr2serr("target port list given but no state indicated\n");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
        state_arr[0] = state;
        state_arr_len = 1;
        state = -1;
    }
    if ((port_arr_len > 1) && (1 == state_arr_len)) {
        for (k = 1; k < port_arr_len; ++k)
            state_arr[k] = state_arr[0];
        state_arr_len = port_arr_len;
    }
    if (port_arr_len != state_arr_len) {
        pr2serr("'state=' and '--tp=' lists mismatched\n");
        usage();
        return SG_LIB_CONTRADICT;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, false /* rw */, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto err_out;
    }

    if (0 == port_arr_len) {
        res = sg_ll_inquiry(sg_fd, false, true /* EVPD */, VPD_DEVICE_ID,
                            rsp_buff, DEF_VPD_DEVICE_ID_LEN, true, verbose);
        if (0 == res) {
            report_len = sg_get_unaligned_be16(rsp_buff + 2) + 4;
            if (VPD_DEVICE_ID != rsp_buff[1]) {
                pr2serr("invalid VPD response; probably a STANDARD INQUIRY "
                        "response\n");
                if (verbose) {
                    pr2serr("First 32 bytes of bad response\n");
                    hex2stderr(rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (report_len > MX_ALLOC_LEN) {
                pr2serr("response length too long: %d > %d\n", report_len,
                        MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (report_len > DEF_VPD_DEVICE_ID_LEN) {
                if (sg_ll_inquiry(sg_fd, false, true, VPD_DEVICE_ID, rsp_buff,
                                  report_len, true, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            decode_target_port(rsp_buff + 4, report_len - 4, &relport,
                               &portgroup);
            printf("Device is at port Group 0x%02x, relative port 0x%02x\n",
                   portgroup, relport);
        }

        memset(reportTgtGrpBuff, 0x0, sizeof(reportTgtGrpBuff));
        /* trunc = 0; */

        res = sg_ll_report_tgt_prt_grp2(sg_fd, reportTgtGrpBuff,
                                        sizeof(reportTgtGrpBuff),
                                        false /* extended */, true, verbose);
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
            memset(tgtGrpState, 0, sizeof(struct tgtgrp) * 256);
            tgtStatePtr = tgtGrpState;
            printf("Current target port groups:\n");
            for (k = 4, bp = reportTgtGrpBuff + 4, numgrp = 0; k < report_len;
                 k += off, bp += off, numgrp ++) {

                printf("  target port group id : 0x%x , Pref=%d\n",
                       sg_get_unaligned_be16(bp + 2), !!(bp[0] & 0x80));
                printf("    target port group asymmetric access state : ");
                printf("0x%02x", bp[0] & 0x0f);
                printf("\n");
                tgtStatePtr->id = sg_get_unaligned_be16(bp + 2);
                tgtStatePtr->current = bp[0] & 0x0f;
                tgtStatePtr->valid = bp[1];

                tgt_port_count = bp[7];

                tgtStatePtr++;
                off = 8 + tgt_port_count * 4;
            }
        } else {
            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("Report Target Port Groups: %s\n", b);
            if (0 == verbose)
                pr2serr("    try '-v' for more information\n");
        }
        if (0 != res)
             goto err_out;

        printf("Port group 0x%02x: Set asymmetric access state to", portgroup);
        decode_tpgs_state(state);
        printf("\n");

        transition_tpgs_states(tgtGrpState, numgrp, portgroup, state);

        memset(setTgtGrpBuff, 0x0, sizeof(setTgtGrpBuff));
        /* trunc = 0; */

        encode_tpgs_states(setTgtGrpBuff, tgtGrpState, numgrp);
        report_len = numgrp * 4 + 4;
    } else { /* port_arr_len > 0 */
        memset(setTgtGrpBuff, 0x0, sizeof(setTgtGrpBuff));
        for (k = 0, bp = setTgtGrpBuff + 4; k < port_arr_len; ++k, bp +=4) {
            bp[0] = state_arr[k] & 0xf;
            sg_put_unaligned_be16((uint16_t)port_arr[k], bp + 2);
        }
        report_len = port_arr_len * 4 + 4;
    }

    res = sg_ll_set_tgt_prt_grp(sg_fd, setTgtGrpBuff, report_len, true,
                                verbose);

    if (0 == res)
        goto err_out;
    else {
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Set Target Port Groups: %s\n", b);
        if (0 == verbose)
            pr2serr("    try '-v' for more information\n");
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
        if (! sg_if_can2stderr("sg_stpg failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
