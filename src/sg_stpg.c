/*
 * Copyright (c) 2004-2010 Hannes Reinecke, Christophe Varoqui and Douglas Gilbert.
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

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command SET TARGET PORT GROUPS
 * to the given SCSI device.
 */

static char * version_str = "1.2 20100312";

#define TGT_GRP_BUFF_LEN 1024
#define MX_ALLOC_LEN (0xc000 + 0x80)

#define TPGS_STATE_OPTIMIZED 0x0
#define TPGS_STATE_NONOPTIMIZED 0x1
#define TPGS_STATE_STANDBY 0x2
#define TPGS_STATE_UNAVAILABLE 0x3
#define TPGS_STATE_OFFLINE 0xe          /* SPC-4 rev 9 */
#define TPGS_STATE_TRANSITIONING 0xf

#define VPD_DEVICE_ID  0x83
#define DEF_VPD_DEVICE_ID_LEN  252

#define MAX_PORT_LIST_ARR_LEN 16

struct tgtgrp {
        int id;
        int current;
        int valid;
};

static struct option long_options[] = {
        {"active", 0, 0, 'a'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"offline", 0, 0, 'l'},
        {"optimized", 0, 0, 'o'},
        {"raw", 0, 0, 'r'},
        {"standby", 0, 0, 's'},
        {"state", required_argument, 0, 'S'},
        {"tp", required_argument, 0, 't'},
        {"unavailable", 0, 0, 'u'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
    fprintf(stderr, "Usage: "
          "sg_stpg   [--active] [--help] [--hex] [--offline] [--optimized] "
          "[--raw]\n"
          "                 [--standby] [--state=S,S...] [--tp=P,P...] "
          "[--unavailable]\n"
          "                 [--verbose] [--version] DEVICE\n"
          "  where:\n"
          "    --active|-a        set asymm. access state to "
          "active/non-optimized\n"
          "    --help|-h          print out usage message\n"
          "    --hex|-H           print out report response in hex, then "
          "exit\n"
          "    --offline|-l       set asymm. access state to offline, takes "
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
          "Performs a SCSI SET TARGET PORT GROUPS command\n"
          );

}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

static int
decode_target_port(unsigned char * buff, int len, int *d_id, int *d_tpg)
{
    int c_set, piv, assoc, desig_type, i_len;
    int off, u;
    const unsigned char * ucp;
    const unsigned char * ip;

    *d_id = -1;
    *d_tpg = -1;
    off = -1;
    while ((u = sg_vpd_dev_id_iter(buff, len, &off, -1, -1, -1)) == 0) {
        ucp = buff + off;
        i_len = ucp[3];
        if ((off + i_len + 4) > len) {
            fprintf(stderr, "    VPD page error: designator length longer "
                    "than\n     remaining response length=%d\n", (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        ip = ucp + 4;
        c_set = (ucp[0] & 0xf);
        piv = ((ucp[1] & 0x80) ? 1 : 0);
        assoc = ((ucp[1] >> 4) & 0x3);
        desig_type = (ucp[1] & 0xf);
        switch (desig_type) {
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                fprintf(stderr, "      << expected binary code_set, target "
                        "port association, length 4>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            *d_id = ((ip[2] << 8) | ip[3]);
            break;
        case 5: /* (primary) Target port group */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                fprintf(stderr, "      << expected binary code_set, target "
                        "port association, length 4>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            *d_tpg = ((ip[2] << 8) | ip[3]);
            break;
        default:
            break;
        }
    }
    if (-1 == *d_id || -1 == *d_tpg) {
        fprintf(stderr, "VPD page error: no target port group information\n");
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

     if (!( (1 << newstate) & tgtState[i].valid )) {
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
encode_tpgs_states(unsigned char *buff, struct tgtgrp *tgtState, int numgrp)
{
     int i;
     unsigned char *desc;

     for (i = 0, desc = buff + 4; i < numgrp; desc += 4, i++) {
          desc[0] = tgtState[i].current & 0x0f;
          desc[2] = (tgtState[i].id >> 8) & 0x0f;
          desc[3] = tgtState[i].id & 0x0f;
     }
}

/* Read numbers (up to 32 bits in size) from command line (comma separated */
/* list). Assumed decimal unless prefixed by '0x', '0X' or contains */
/* trailing 'h' or 'H' (which indicate hex). Returns 0 if ok, 1 if error. */
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
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *port_arr_len = 0;
    k = strspn(inp, "0123456789aAbBcCdDeEfFhHxX,");
    if (in_len != k) {
        fprintf(stderr, "build_port_arr: error at pos %d\n", k + 1);
        return 1;
    }
    for (k = 0; k < max_arr_len; ++k) {
        v = sg_get_num_nomult(lcp);
        if (-1 != v) {
            port_arr[k] = v;
            cp = strchr(lcp, ',');
            if (NULL == cp)
                break;
            lcp = cp + 1;
        } else {
            fprintf(stderr, "build_port_arr: error at pos %d\n",
                    (int)(lcp - inp + 1));
            return 1;
        }
    }
    *port_arr_len = k + 1;
    if (k == max_arr_len) {
        fprintf(stderr, "build_port_arr: array length exceeded\n");
        return 1;
    }
    return 0;
}

/* Read numbers (up to 32 bits in size) from command line (comma separated */
/* list). Assumed decimal unless prefixed by '0x', '0X' or contains */
/* trailing 'h' or 'H' (which indicate hex). Also accepts 'ao' for active */
/* optimized [0], 'an' for active/non-optimized [1], 's' for standby [2], */
/* 'u' for unavailable [3], 'o' for offline [14]. */
/* Returns 0 if ok, 1 if error. */
static int
build_state_arr(const char * inp, int * state_arr, int * state_arr_len,
                int max_arr_len)
{
    int in_len, k, v, try_num;
    const char * lcp;
    char * cp;

    if ((NULL == inp) || (NULL == state_arr) ||
        (NULL == state_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *state_arr_len = 0;
    k = strspn(inp, "0123456789aAbBcCdDeEfFhHnNoOsSuUxX,");
    if (in_len != k) {
        fprintf(stderr, "build_state_arr: error at pos %d\n", k + 1);
        return 1;
    }
    for (k = 0; k < max_arr_len; ++k) {
        try_num = 1;
        if (isalpha(*lcp)) {
            try_num = 0;
            switch (toupper(*lcp)) {
            case 'A':
                if ('N' == toupper(*(lcp + 1)))
                    state_arr[k] = 1;
                else if ('O' == toupper(*(lcp + 1)))
                    state_arr[k] = 0;
                else
                    try_num = 1;
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
                fprintf(stderr, "build_state_arr: expected 'ao', 'an', 'o', "
                        "'s' or 'u' at pos %d\n", (int)(lcp - inp + 1));
                return 1;
            }
        }
        if (try_num) {
            v = sg_get_num_nomult(lcp);
            if (((v >= 0) && (v <= 3)) || (14 ==v))
                state_arr[k] = v;
            else if (-1 == v) {
                fprintf(stderr, "build_state_arr: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            } else {
                fprintf(stderr, "build_state_arr: expect 0,1,2,3 or 14\n");
                return 1;
            }
        }
        cp = strchr(lcp, ',');
        if (NULL == cp)
            break;
        lcp = cp + 1;
    }
    *state_arr_len = k + 1;
    if (k == max_arr_len) {
        fprintf(stderr, "build_state_arr: array length exceeded\n");
        return 1;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    int sg_fd, k, off, res, c, report_len, tgt_port_count, trunc;
    unsigned char reportTgtGrpBuff[TGT_GRP_BUFF_LEN];
    unsigned char setTgtGrpBuff[TGT_GRP_BUFF_LEN];
    unsigned char rsp_buff[MX_ALLOC_LEN + 2];
    unsigned char * ucp;
    struct tgtgrp tgtGrpState[256], *tgtStatePtr;
    int state = -1;
    const char * state_arg = NULL;
    const char * tp_arg = NULL;
    int hex = 0;
    int raw = 0;
    int verbose = 0;
    int port_arr[MAX_PORT_LIST_ARR_LEN];
    int port_arr_len = 0;
    int state_arr[MAX_PORT_LIST_ARR_LEN];
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
            hex = 1;
            break;
        case 'l':
        case 'O':
            state = TPGS_STATE_OFFLINE;
            break;
        case 'o':
            state = TPGS_STATE_OPTIMIZED;
            break;
        case 'r':
            raw = 1;
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
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "Version: %s\n", version_str);
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

    if (state_arg) {
        if (build_state_arr(state_arg, state_arr, &state_arr_len,
                            MAX_PORT_LIST_ARR_LEN)) {
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (tp_arg) {
        if (build_port_arr(tp_arg, port_arr, &port_arr_len,
                           MAX_PORT_LIST_ARR_LEN)) {
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if ((state >= 0) && (state_arr_len > 0)) {
        fprintf(stderr, "either use individual state option or '--state=' "
                "but not both\n");
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
        fprintf(stderr, "'state=' list longer than expected\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((port_arr_len > 0) && (0 == state_arr_len)) {
        if (-1 == state) {
            fprintf(stderr, "target port list given but no state "
                    "indicated\n");
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
        fprintf(stderr, "'state=' and '--tp=' lists mismatched\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (0 == port_arr_len) {
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_DEVICE_ID, rsp_buff,
                            DEF_VPD_DEVICE_ID_LEN, 1, verbose);
        if (0 == res) {
            report_len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (VPD_DEVICE_ID != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                    dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (report_len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", report_len,
                        MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (report_len > DEF_VPD_DEVICE_ID_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_DEVICE_ID, rsp_buff,
                                  report_len, 1, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            decode_target_port(rsp_buff + 4, report_len - 4, &relport, &portgroup);
            printf("Device is at port Group 0x%02x, relative port 0x%02x\n",
                   portgroup, relport);
        }

        memset(reportTgtGrpBuff, 0x0, sizeof(reportTgtGrpBuff));
        trunc = 0;

        res = sg_ll_report_tgt_prt_grp(sg_fd, reportTgtGrpBuff,
                                sizeof(reportTgtGrpBuff), 1, verbose);
        ret = res;
        if (0 == res) {
            report_len = (reportTgtGrpBuff[0] << 24) +
                         (reportTgtGrpBuff[1] << 16) +
                         (reportTgtGrpBuff[2] << 8) +
                         reportTgtGrpBuff[3] + 4;
            if (report_len > (int)sizeof(reportTgtGrpBuff)) {
                trunc = 1;
                fprintf(stderr, "  <<report too long for internal buffer,"
                        " output truncated\n");
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
                    fprintf(stderr, "\nOutput response in hex:\n");
                dStrHex((const char *)reportTgtGrpBuff, report_len, 1);
                goto err_out;
            }
            memset(tgtGrpState, 0, sizeof(struct tgtgrp) * 256);
            tgtStatePtr = tgtGrpState;
            printf("Current target port groups:\n");
            for (k = 4, ucp = reportTgtGrpBuff + 4, numgrp = 0; k < report_len;
                 k += off, ucp += off, numgrp ++) {

                printf("  target port group id : 0x%x , Pref=%d\n",
                       (ucp[2] << 8) + ucp[3], !!(ucp[0] & 0x80));
                printf("    target port group asymmetric access state : ");
                printf("0x%02x", ucp[0] & 0x0f);
                printf("\n");
                tgtStatePtr->id = (ucp[2] << 8) + ucp[3];
                tgtStatePtr->current = ucp[0] & 0x0f;
                tgtStatePtr->valid = ucp[1];

                tgt_port_count = ucp[7];

                tgtStatePtr++;
                off = 8 + tgt_port_count * 4;
            }
        } else if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "Report Target Port Groups command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in Report Target Port Groups cdb "
                    "including unsupported service action\n");
        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
            fprintf(stderr, "Report Target Port Groups, unit attention\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "Report Target Port Groups, aborted command\n");
        else {
            fprintf(stderr, "Report Target Port Groups command failed\n");
            if (0 == verbose)
                fprintf(stderr, "    try '-v' for more information\n");
        }
        if (0 != res)
             goto err_out;

        printf("Port group 0x%02x: Set asymmetric access state to", portgroup);
        decode_tpgs_state(state);
        printf("\n");

        transition_tpgs_states(tgtGrpState, numgrp, portgroup, state);

        memset(setTgtGrpBuff, 0x0, sizeof(setTgtGrpBuff));
        trunc = 0;

        encode_tpgs_states(setTgtGrpBuff, tgtGrpState, numgrp);
        report_len = numgrp * 4 + 4;
    } else { /* port_arr_len > 0 */
        memset(setTgtGrpBuff, 0x0, sizeof(setTgtGrpBuff));
        for (k = 0, ucp = setTgtGrpBuff + 4; k < port_arr_len; ++k, ucp +=4) {
            ucp[0] = state_arr[k] & 0xf;
            ucp[2] = (port_arr[k] >> 8) & 0xff;
            ucp[3] = port_arr[k] & 0xff;
        }
        report_len = port_arr_len * 4 + 4;
    }

    res = sg_ll_set_tgt_prt_grp(sg_fd, setTgtGrpBuff, report_len, 1, verbose);

    if (0 == res)
        goto err_out;
    else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Set Target Port Groups command not supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "bad field in Report Target Port Groups cdb "
                "including unsupported service action\n");
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "Set Target Port Groups, unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "Set Target Port Groups, aborted command\n");
    else {
        fprintf(stderr, "Set Target Port Groups command failed\n");
        if (0 == verbose)
            fprintf(stderr, "    try '-v' for more information\n");
    }

err_out:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
