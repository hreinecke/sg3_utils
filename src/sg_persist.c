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
#include "sg_cmds_extra.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
*  Copyright (C) 2004-2009 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program issues the SCSI PERSISTENT IN and OUT commands.

*/

static char * version_str = "0.37 20090903";


#define PRIN_RKEY_SA     0x0
#define PRIN_RRES_SA     0x1
#define PRIN_RCAP_SA     0x2
#define PRIN_RFSTAT_SA   0x3
#define PROUT_REG_SA     0x0
#define PROUT_RES_SA     0x1
#define PROUT_REL_SA     0x2
#define PROUT_CLEAR_SA   0x3
#define PROUT_PREE_SA    0x4
#define PROUT_PREE_AB_SA 0x5
#define PROUT_REG_IGN_SA 0x6
#define PROUT_REG_MOVE_SA 0x7
#define MX_ALLOC_LEN 8192
#define MX_TIDS 32
#define MX_TID_LEN 256

struct opts_t {
    unsigned int prout_type;
    uint64_t param_rk;
    uint64_t param_sark;
    unsigned int param_rtp;
    int prin;
    int prin_sa;
    int prout_sa;
    int param_alltgpt;
    int param_aptpl;
    int param_unreg;
    int inquiry;
    int hex;
    unsigned char transportid_arr[MX_TIDS * MX_TID_LEN];
    int num_transportids;
    unsigned int alloc_len;
    int verbose;
};


static struct option long_options[] = {
    {"alloc-length", 1, 0, 'l'},
    {"clear", 0, 0, 'C'},
    {"device", 1, 0, 'd'},
    {"help", 0, 0, 'h'},
    {"hex", 0, 0, 'H'},
    {"in", 0, 0, 'i'},
    {"no-inquiry", 0, 0, 'n'},
    {"out", 0, 0, 'o'},
    {"param-alltgpt", 0, 0, 'Y'},
    {"param-aptpl", 0, 0, 'Z'},
    {"param-rk", 1, 0, 'K'},
    {"param-sark", 1, 0, 'S'},
    {"param-unreg", 0, 0, 'U'},
    {"preempt", 0, 0, 'P'},
    {"preempt-abort", 0, 0, 'A'},
    {"prout-type", 1, 0, 'T'},
    {"read-full-status", 0, 0, 's'},
    {"read-keys", 0, 0, 'k'},
    {"read-reservation", 0, 0, 'r'},
    {"read-status", 0, 0, 's'},
    {"register", 0, 0, 'G'},
    {"register-ignore", 0, 0, 'I'},
    {"register-move", 0, 0, 'M'},
    {"release", 0, 0, 'L'},
    {"relative-target-port", 1, 0, 'Q'},
    {"report-capabilities", 0, 0, 'c'},
    {"reserve", 0, 0, 'R'},
    {"transport-id", 1, 0, 'X'},
    {"unreg", 0, 0, 'U'},
    {"verbose", 0, 0, 'v'},
    {"version", 0, 0, 'V'},
    {0, 0, 0, 0}
};

static const char * prin_sa_strs[] = {
    "Read keys",
    "Read reservation",
    "Report capabilities",
    "Read full status",
    "[reserved 0x4]",
    "[reserved 0x5]",
    "[reserved 0x6]",
    "[reserved 0x7]",
};
static const int num_prin_sa_strs = sizeof(prin_sa_strs) /
                                    sizeof(prin_sa_strs[0]);

static const char * prout_sa_strs[] = {
    "Register",
    "Reserve",
    "Release",
    "Clear",
    "Preempt",
    "Preempt and abort",
    "Register and ignore existing key",
    "Register and move",
    "[reserved 0x8]",
};
static const int num_prout_sa_strs = sizeof(prout_sa_strs) /
                                     sizeof(prout_sa_strs[0]);

static const char * pr_type_strs[] = {
    "obsolete [0]",
    "Write Exclusive",
    "obsolete [2]",
    "Exclusive Access",
    "obsolete [4]",
    "Write Exclusive, registrants only",
    "Exclusive Access, registrants only",
    "Write Exclusive, all registrants",
    "Exclusive Access, all registrants",
    "obsolete [9]", "obsolete [0xa]", "obsolete [0xb]", "obsolete [0xc]",
    "obsolete [0xd]", "obsolete [0xe]", "obsolete [0xf]",
};


static void
usage()
{
    fprintf(stderr,
            "Usage: sg_persist [OPTIONS] [DEVICE]\n"
            "  where OPTIONS include:\n"
            "    --alloc-length=LEN|-l LEN    allocation length hex value "
            "(used with\n"
            "                                 PR In only) (default: 8192 "
            "(2000 in hex))\n"
            "    --clear|-C                 PR Out: Clear\n"
            "    --device=DEVICE|-d DEVICE    query or change DEVICE\n"
            "    --help|-h                  output this usage message\n"
            "    --hex|-H                   output response in hex\n"
            "    --in|-i                    request PR In command (default)\n"
            "    --no-inquiry|-n            skip INQUIRY (default: do "
            "INQUIRY)\n"
            "    --out|-o                   request PR Out command\n"
            "    --param-alltgpt|-Y         PR Out parameter 'ALL_TG_PT'\n"
            "    --param-aptpl|-Z           PR Out parameter 'APTPL'\n"
            "    --param-rk=RK|-K RK        PR Out parameter reservation key\n"
            "                               (RK is in hex)\n"
            "    --param-sark=SARK|-S SARK    PR Out parameter service "
            "action\n"
            "                               reservation key (SARK is in "
            "hex)\n"
            "    --preempt|-P               PR Out: Preempt\n"
            "    --preempt-abort|-A         PR Out: Preempt and Abort\n"
            "    --prout-type=TYPE|-T TYPE    PR Out command type\n"
            "    --read-full-status|-s      PR In: Read Full Status\n"
            "    --read-keys|-k             PR In: Read Keys\n");
    fprintf(stderr,
            "    --read-reservation|-r      PR In: Read Reservation\n"
            "    --read-status|-s           PR In: Read Full Status\n"
            "    --register|-G              PR Out: Register\n"
            "    --register-ignore|-I       PR Out: Register and Ignore\n"
            "    --register-move|-M         PR Out: Register and Move\n"
            "    --relative-target-port=RTPI|-Q RTPI    relative target port "
            "identifier\n"
            "                               for '--register-move'\n"
            "    --release|-L               PR Out: Release\n"
            "    --report-capabilities|-c   PR In: Report Capabilities\n"
            "    --reserve|-R               PR Out: Reserve\n"
            "    --transport-id=TIDS|-X TIDS    one or more "
            "TransportIDs can\n"
            "                               be given in several forms\n"
            "    --unreg|-U                 optional with PR Out Register "
            "and Move\n"
            "    --verbose|-v               output additional debug "
            "information\n"
            "    --version|-V               output version string\n"
            "    -?                         output this usage message\n\n"
            "Performs a SCSI PERSISTENT RESERVE (IN or OUT) command\n");
}

static void
decode_transport_id(const char * leadin, unsigned char * ucp, int len,
                    int num_tids)
{
    int format_code, proto_id, num, j, k;
    uint64_t ull;
    int bump;

    if (num_tids > 0)
        len = num_tids * MX_TID_LEN; 
    for (k = 0, bump = MX_TID_LEN; k < len; k += bump, ucp += bump) {
        if ((len < 24) || (0 != (len % 4)))
            printf("%sTransport Id short or not multiple of 4 "
                   "[length=%d]:\n", leadin, len);
        else
            printf("%sTransport Id of initiator:\n", leadin);
        format_code = ((ucp[0] >> 6) & 0x3);
        proto_id = (ucp[0] & 0xf);
        switch (proto_id) {
        case TPROTO_FCP: /* Fibre channel */
            printf("%s  FCP-2 World Wide Name:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, 0);
            break;
        case TPROTO_SPI: /* Parallel SCSI */
            printf("%s  Parallel SCSI initiator SCSI address: 0x%x\n",
                   leadin, ((ucp[2] << 8) | ucp[3]));
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            printf("%s  relative port number (of corresponding target): "
                   "0x%x\n", leadin, ((ucp[6] << 8) | ucp[7]));
            break;
        case TPROTO_SSA:
            printf("%s  SSA (transport id not defined):\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            break;
        case TPROTO_1394: /* IEEE 1394 */
            printf("%s  IEEE 1394 EUI-64 name:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, 0);
            break;
        case TPROTO_SRP:
            printf("%s  RDMA initiator port identifier:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 16, 0);
            break;
        case TPROTO_ISCSI:
            printf("%s  iSCSI ", leadin);
            num = ((ucp[2] << 8) | ucp[3]);
            if (0 == format_code)
                printf("name: %.*s\n", num, &ucp[4]);
            else if (1 == format_code)
                printf("name and session id: %.*s\n", num, &ucp[4]);
            else {
                printf("  [Unexpected format code: %d]\n", format_code);
                dStrHex((const char *)ucp, num + 4, 0);
            }
            break;
        case TPROTO_SAS:
            ull = 0;
            for (j = 0; j < 8; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= ucp[4 + j];
            }
            printf("%s  SAS address: 0x%016" PRIx64 "\n", leadin, ull);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            break;
        case TPROTO_ADT:
            printf("%s  ADT:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            break;
        case TPROTO_ATA:
            printf("%s  ATAPI:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            break;
        case TPROTO_NONE:
        default:
            fprintf(stderr, "%s  unknown protocol id=0x%x  "
                    "format_code=%d\n", leadin, proto_id, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            break;
        }
    }
}

static int
prin_work(int sg_fd, const struct opts_t * optsp)
{
    int k, j, num, res, add_len, add_desc_len, rel_pt_addr;
    unsigned int pr_gen;
    uint64_t ull;
    unsigned char * ucp;
    unsigned char pr_buff[MX_ALLOC_LEN];

    memset(pr_buff, 0, sizeof(pr_buff));
    res = sg_ll_persistent_reserve_in(sg_fd, optsp->prin_sa, pr_buff,
                                      optsp->alloc_len, 1, optsp->verbose);
    if (res) {
       if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "PR in: command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "PR in: bad field in cdb including "
                    "unsupported service action\n");
        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
            fprintf(stderr, "PR in: unit attention\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "PR in: aborted command\n");
        else
            fprintf(stderr, "PR in: command failed\n");
        return res;
    }
    if (PRIN_RCAP_SA == optsp->prin_sa) {
        if (8 != pr_buff[1]) {
            fprintf(stderr, "Unexpected response for PRIN Report "
                            "Capabilities\n");
            return SG_LIB_CAT_MALFORMED;
        }
        if (optsp->hex)
            dStrHex((const char *)pr_buff, 8, 1);
        else {
            printf("Report capabilities response:\n");
            printf("  Compatible Reservation Handling(CRH): %d\n",
                   !!(pr_buff[2] & 0x10));
            printf("  Specify Initiator Ports Capable(SIP_C): %d\n",
                   !!(pr_buff[2] & 0x8));
            printf("  All Target Ports Capable(ATP_C): %d\n",
                   !!(pr_buff[2] & 0x4));
            printf("  Persist Through Power Loss Capable(PTPL_C): %d\n",
                   !!(pr_buff[2] & 0x1));
            printf("  Type Mask Valid(TMV): %d\n", !!(pr_buff[3] & 0x80));
            printf("  Allow Commands: %d\n", (pr_buff[3] >> 4) & 0x7);
            printf("  Persist Through Power Loss Active(PTPL_A): %d\n",
                   !!(pr_buff[3] & 0x1));
            if (pr_buff[3] & 0x80) {
                printf("    Support indicated in Type mask:\n");
                printf("      %s: %d\n", pr_type_strs[7],
                       !!(pr_buff[4] & 0x80));
                printf("      %s: %d\n", pr_type_strs[6],
                       !!(pr_buff[4] & 0x40));
                printf("      %s: %d\n", pr_type_strs[5],
                       !!(pr_buff[4] & 0x20));
                printf("      %s: %d\n", pr_type_strs[3],
                       !!(pr_buff[4] & 0x8));
                printf("      %s: %d\n", pr_type_strs[1],
                       !!(pr_buff[4] & 0x2));
                printf("      %s: %d\n", pr_type_strs[8],
                       !!(pr_buff[5] & 0x1));
            }
        }
    } else {
        pr_gen = ((pr_buff[0] << 24) | (pr_buff[1] << 16) |
                  (pr_buff[2] << 8) | pr_buff[3]);
        add_len = ((pr_buff[4] << 24) | (pr_buff[5] << 16) |
                   (pr_buff[6] << 8) | pr_buff[7]);
        if (optsp->hex) {
            printf("  PR generation=0x%x, ", pr_gen);
            if (add_len <= 0)
                printf("Additional length=%d\n", add_len);
            if (add_len > ((int)sizeof(pr_buff) - 8)) {
                printf("Additional length too large=%d, truncate\n",
                       add_len);
                dStrHex((const char *)(pr_buff + 8), sizeof(pr_buff) - 8, 1);
            } else {
                printf("Additional length=%d\n", add_len);
                dStrHex((const char *)(pr_buff + 8), add_len, 1);
            }
        } else if (PRIN_RKEY_SA == optsp->prin_sa) {
            printf("  PR generation=0x%x, ", pr_gen);
            num = add_len / 8;
            if (num > 0) {
                if (1 == num)
                    printf("1 registered reservation key follows:\n");
                else
                    printf("%d registered reservation keys follow:\n", num);
                ucp = pr_buff + 8;
                for (k = 0; k < num; ++k, ucp += 8) {
                    ull = 0;
                    for (j = 0; j < 8; ++j) {
                        if (j > 0)
                            ull <<= 8;
                        ull |= ucp[j];
                    }
                    printf("    0x%" PRIx64 "\n", ull);
                }
            } else
                printf("there are NO registered reservation keys\n");
        } else if (PRIN_RRES_SA == optsp->prin_sa) {
            printf("  PR generation=0x%x, ", pr_gen);
            num = add_len / 16;
            if (num > 0) {
                printf("Reservation follows:\n");
                ucp = pr_buff + 8;
                ull = 0;
                for (j = 0; j < 8; ++j) {
                    if (j > 0)
                        ull <<= 8;
                    ull |= ucp[j];
                }
                printf("    Key=0x%" PRIx64 "\n", ull);
                j = ((ucp[13] >> 4) & 0xf);
                if (0 == j)
                    printf("    scope: LU_SCOPE, ");
                else
                    printf("    scope: %d ", j);
                j = (ucp[13] & 0xf);
                printf(" type: %s\n", pr_type_strs[j]);
            } else
                printf("there is NO reservation held\n");
        } else if (PRIN_RFSTAT_SA == optsp->prin_sa) {
            printf("  PR generation=0x%x\n", pr_gen);
            ucp = pr_buff + 8;
            if (0 == add_len) {
                printf("  No full status descriptors\n");
                if (optsp->verbose)
                printf("  So there are no registered IT nexuses\n");
            }
            for (k = 0; k < add_len; k += num, ucp += num) {
                add_desc_len = ((ucp[20] << 24) | (ucp[21] << 16) |
                                (ucp[22] << 8) | ucp[23]);
                num = 24 + add_desc_len;
                ull = 0;
                for (j = 0; j < 8; ++j) {
                    if (j > 0)
                        ull <<= 8;
                    ull |= ucp[j];
                }
                printf("    Key=0x%" PRIx64 "\n", ull);
                if (ucp[12] & 0x2)
                    printf("      All target ports bit set\n");
                else {
                    printf("      All target ports bit clear\n");
                    rel_pt_addr = ((ucp[18] << 8) | ucp[19]);
                    printf("      Relative port address: 0x%x\n",
                           rel_pt_addr);
                }
                if (ucp[12] & 0x1) {
                    printf("      << Reservation holder >>\n");
                    j = ((ucp[13] >> 4) & 0xf);
                    if (0 == j)
                        printf("      scope: LU_SCOPE, ");
                    else
                        printf("      scope: %d ", j);
                    j = (ucp[13] & 0xf);
                    printf(" type: %s\n", pr_type_strs[j]);
                } else
                    printf("      not reservation holder\n");
                if (add_desc_len > 0)
                    decode_transport_id("      ", &ucp[24], add_desc_len, 0);
            }
        }
    }
    return 0;
}

/* Compact the 2 dimensional transportid_arr into a one dimensional
 * array in place returning the length. */
static int
compact_transportid_array(struct opts_t * optsp)
{
    int k, off, protocol_id, len;
    int compact_len = 0;
    unsigned char * ucp = optsp->transportid_arr;

    for (k = 0, off = 0; ((k < optsp->num_transportids) && (k < MX_TIDS));
         ++k, off += MX_TID_LEN) {
        protocol_id = ucp[off] & 0xf;
        if (TPROTO_ISCSI == protocol_id) {
            len = (ucp[off + 2] << 8) + ucp[off + 3] + 4;
            if (len < 24)
                len = 24;
            if (off > compact_len)
                memmove(ucp + compact_len, ucp + off, len);
            compact_len += len;

        } else {
            if (off > compact_len)
                memmove(ucp + compact_len, ucp + off, 24);
            compact_len += 24;
        }
    }
    return compact_len;
}

static int
prout_work(int sg_fd, struct opts_t * optsp)
{
    int j, len, res, t_arr_len;
    unsigned char pr_buff[MX_ALLOC_LEN];
    uint64_t param_rk;
    uint64_t param_sark;

    t_arr_len = compact_transportid_array(optsp);
    param_rk = optsp->param_rk;
    memset(pr_buff, 0, sizeof(pr_buff));
    for (j = 7; j >= 0; --j) {
        pr_buff[j] = (param_rk & 0xff);
        param_rk >>= 8;
    }
    param_sark = optsp->param_sark;
    for (j = 7; j >= 0; --j) {
        pr_buff[8 + j] = (param_sark & 0xff);
        param_sark >>= 8;
    }
    if (optsp->param_alltgpt)
        pr_buff[20] |= 0x4;
    if (optsp->param_aptpl)
        pr_buff[20] |= 0x1;
    len = 24;
    if (t_arr_len > 0) {
        pr_buff[20] |= 0x8;     /* set SPEC_I_PT bit */
        memcpy(&pr_buff[28], optsp->transportid_arr, t_arr_len);
        len += (t_arr_len + 4);
        pr_buff[24] = (unsigned char)((t_arr_len >> 24) & 0xff);
        pr_buff[25] = (unsigned char)((t_arr_len >> 16) & 0xff);
        pr_buff[26] = (unsigned char)((t_arr_len >> 8) & 0xff);
        pr_buff[27] = (unsigned char)(t_arr_len & 0xff);
    }
    res = sg_ll_persistent_reserve_out(sg_fd, optsp->prout_sa, 0,
                                       optsp->prout_type, pr_buff, len, 1,
                                       optsp->verbose);
    if (res) {
       if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "PR out:, command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "PR out: bad field in cdb including "
                    "unsupported service action\n");
        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
            fprintf(stderr, "PR out: unit attention\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "PR out: aborted command\n");
        else
            fprintf(stderr, "PR out: command failed\n");
        return res;
    } else if (optsp->verbose) {
        char buff[64];

        if (optsp->prout_sa < num_prout_sa_strs)
            strncpy(buff, prout_sa_strs[optsp->prout_sa], sizeof(buff));
        else
            snprintf(buff, sizeof(buff), "service action=0x%x",
                     optsp->prout_sa);
        fprintf(stderr, "PR out: command (%s) successful\n", buff);
    }
    return 0;
}

static int
prout_reg_move_work(int sg_fd, struct opts_t * optsp)
{
    int j, len, res, t_arr_len;
    unsigned char pr_buff[MX_ALLOC_LEN];
    uint64_t param_rk;
    uint64_t param_sark;

    t_arr_len = compact_transportid_array(optsp);
    param_rk = optsp->param_rk;
    memset(pr_buff, 0, sizeof(pr_buff));
    for (j = 7; j >= 0; --j) {
        pr_buff[j] = (param_rk & 0xff);
        param_rk >>= 8;
    }
    param_sark = optsp->param_sark;
    for (j = 7; j >= 0; --j) {
        pr_buff[8 + j] = (param_sark & 0xff);
        param_sark >>= 8;
    }
    if (optsp->param_unreg)
        pr_buff[17] |= 0x2;
    if (optsp->param_aptpl)
        pr_buff[17] |= 0x1;
    pr_buff[18] = (unsigned char)((optsp->param_rtp >> 8) & 0xff);
    pr_buff[19] = (unsigned char)(optsp->param_rtp & 0xff);
    len = 24;
    if (t_arr_len > 0) {
        memcpy(&pr_buff[24], optsp->transportid_arr, t_arr_len);
        len += t_arr_len;
        pr_buff[20] = (unsigned char)((t_arr_len >> 24) & 0xff);
        pr_buff[21] = (unsigned char)((t_arr_len >> 16) & 0xff);
        pr_buff[22] = (unsigned char)((t_arr_len >> 8) & 0xff);
        pr_buff[23] = (unsigned char)(t_arr_len & 0xff);
    }
    res = sg_ll_persistent_reserve_out(sg_fd, PROUT_REG_MOVE_SA, 0,
                                       optsp->prout_type, pr_buff, len, 1,
                                       optsp->verbose);
    if (res) {
       if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "PR out: command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "PR out: bad field in cdb including "
                    "unsupported service action\n");
        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
            fprintf(stderr, "PR out: unit attention\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "PR out: aborted command\n");
        else
            fprintf(stderr, "PR out: command failed\n");
        return res;
    } else if (optsp->verbose)
        fprintf(stderr, "PR out: 'register and move' "
                "command successful\n");
    return 0;
}

/* Decode various symbolic forms of TransportIDs into SPC-4 format.
 * Returns 1 if one found, else returns 0. */
static int
decode_sym_transportid(const char * lcp, unsigned char * tidp)
{
    int k, j, n, b, c, len, alen;
    const char * ecp;
    const char * isip;

    if ((0 == memcmp("sas,", lcp, 4)) || (0 == memcmp("SAS,", lcp, 4))) {
        lcp += 4;
        k = strspn(lcp, "0123456789aAbBcCdDeEfF");
        if (16 != k) {
            fprintf(stderr, "badly formed symbolic SAS TransportID: %s\n",
                    lcp);
            return 0;
        }
        memset(tidp, 0, 24);
        tidp[0] = TPROTO_SAS;
        for (k = 0, j = 0, b = 0; k < 16; ++k) {
            c = lcp[k];
            if (isdigit(c))
                n = c - 0x30;
            else if (isupper(c))
                n = c - 0x37;
            else
                n = c - 0x57;
            if (k & 1) {
                tidp[4 + j] = b | n;
                ++j;
            } else
                b = n << 4; 
        }
        return 1;
    } else if ((0 == memcmp("spi,", lcp, 4)) ||
               (0 == memcmp("SPI,", lcp, 4))) {
        lcp += 4;
        if (2 != sscanf(lcp, "%d,%d", &b, &c)) {
            fprintf(stderr, "badly formed symbolic SPI TransportID: %s\n",
                    lcp);
            return 0;
        }
        tidp[0] = TPROTO_SPI;
        tidp[2] = (b >> 8) & 0xff;
        tidp[3] = b & 0xff;
        tidp[6] = (c >> 8) & 0xff;
        tidp[7] = c & 0xff;
        return 1;
    } else if ((0 == memcmp("fcp,", lcp, 4)) ||
               (0 == memcmp("FCP,", lcp, 4))) {
        lcp += 4;
        k = strspn(lcp, "0123456789aAbBcCdDeEfF");
        if (16 != k) {
            fprintf(stderr, "badly formed symbolic FCP TransportID: %s\n",
                    lcp);
            return 0;
        }
        memset(tidp, 0, 24);
        tidp[0] = TPROTO_FCP;
        for (k = 0, j = 0, b = 0; k < 16; ++k) {
            c = lcp[k];
            if (isdigit(c))
                n = c - 0x30;
            else if (isupper(c))
                n = c - 0x37;
            else
                n = c - 0x57;
            if (k & 1) {
                tidp[8 + j] = b | n;
                ++j;
            } else
                b = n << 4; 
        }
        return 1;
    } else if ((0 == memcmp("sbp,", lcp, 4)) ||
               (0 == memcmp("SBP,", lcp, 4))) {
        lcp += 4;
        k = strspn(lcp, "0123456789aAbBcCdDeEfF");
        if (16 != k) {
            fprintf(stderr, "badly formed symbolic SBP TransportID: %s\n",
                    lcp);
            return 0;
        }
        memset(tidp, 0, 24);
        tidp[0] = TPROTO_1394;
        for (k = 0, j = 0, b = 0; k < 16; ++k) {
            c = lcp[k];
            if (isdigit(c))
                n = c - 0x30;
            else if (isupper(c))
                n = c - 0x37;
            else
                n = c - 0x57;
            if (k & 1) {
                tidp[8 + j] = b | n;
                ++j;
            } else
                b = n << 4; 
        }
        return 1;
    } else if ((0 == memcmp("srp,", lcp, 4)) ||
               (0 == memcmp("SRP,", lcp, 4))) {
        lcp += 4;
        k = strspn(lcp, "0123456789aAbBcCdDeEfF");
        if (16 != k) {
            fprintf(stderr, "badly formed symbolic SRP TransportID: %s\n",
                    lcp);
            return 0;
        }
        memset(tidp, 0, 24);
        tidp[0] = TPROTO_SRP;
        for (k = 0, j = 0, b = 0; k < 32; ++k) {
            c = lcp[k];
            if (isdigit(c))
                n = c - 0x30;
            else if (isupper(c))
                n = c - 0x37;
            else
                n = c - 0x57;
            if (k & 1) {
                tidp[8 + j] = b | n;
                ++j;
            } else
                b = n << 4; 
        }
        return 1;
    } else if (0 == memcmp("iqn.", lcp, 4)) {
        ecp = strpbrk(lcp, " \t");
        isip = strstr(lcp, ",i,0x");
        if (ecp && (isip > ecp))
            isip = NULL;
        len = ecp ? (ecp - lcp) : (int)strlen(lcp);
        memset(tidp, 0, 24);
        tidp[0] = TPROTO_ISCSI | (isip ? 0x40 : 0x0);
        alen = len + 1; /* at least one trailing null */
        if (alen < 20)
            alen = 20;
        else if (0 != (alen % 4))
            alen = ((alen / 4) + 1) * 4;
        if (alen > 241) { /* sam5r02.pdf A.2 (Annex) */
            fprintf(stderr, "iSCSI name too long, alen=%d\n", alen); 
            return 0;
        }
        tidp[3] = alen & 0xff;
        memcpy(tidp + 4, lcp, len);
        return 1;
    }
    fprintf(stderr, "unable to parse symbolic TransportID: %s\n", lcp);
    return 0;
}

/* Read one or more TransportIDs from the given file or from stdin.
 * Returns 0 if successful, 1 otherwise. */
static int
decode_file_tids(const char * fnp, struct opts_t * optsp)
{
    FILE * fp = stdin;
    int in_len, k, j, m;
    unsigned int h;
    const char * lcp;
    char line[512];
    int off = 0;
    int num = 0;
    unsigned char * tid_arr = optsp->transportid_arr;

    if (fnp) {
        fp = fopen(fnp, "r");
        if (NULL == fp) {
            fprintf(stderr, "decode_file_tids: unable to open %s\n", fnp);
            return 1;
        }
    }
    for (j = 0, off = 0; j < 512; ++j) {
        if (NULL == fgets(line, sizeof(line), fp))
            break;
        in_len = strlen(line);
        if (in_len > 0) {
            if ('\n' == line[in_len - 1]) {
                --in_len;
                line[in_len] = '\0';
            }
        }
        if (0 == in_len)
            continue;
        lcp = line;
        m = strspn(lcp, " \t");
        if (m == in_len)
            continue;
        lcp += m;
        in_len -= m;
        if ('#' == *lcp)
            continue;
        if (decode_sym_transportid(lcp, tid_arr + off))
            goto my_cont_a;
        k = strspn(lcp, "0123456789aAbBcCdDeEfF ,\t");
        if ((k < in_len) && ('#' != lcp[k])) {
            fprintf(stderr, "decode_file_tids: syntax error at "
                    "line %d, pos %d\n", j + 1, m + k + 1);
            goto bad;
        }
        for (k = 0; k < 1024; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    fprintf(stderr, "decode_file_tids: hex number "
                            "larger than 0xff in line %d, pos %d\n",
                            j + 1, (int)(lcp - line + 1));
                    goto bad;
                }
                if ((off + k) >= (int)sizeof(optsp->transportid_arr)) {
                    fprintf(stderr, "decode_file_tids: array length "
                            "exceeded\n");
                    goto bad;
                }
                tid_arr[off + k] = h;
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
                fprintf(stderr, "decode_file_tids: error in "
                        "line %d, at pos %d\n", j + 1,
                        (int)(lcp - line + 1));
                goto bad;
            }
        }
my_cont_a:
        off += MX_TID_LEN;
        if (off >= (MX_TIDS * MX_TID_LEN)) {
            fprintf(stderr, "decode_file_tids: array length exceeded\n");
            goto bad;
        }
        ++num;
    }
    optsp->num_transportids = num;
    return 0;

bad:
   if (fnp)
        fclose(fp);
   return 1;
}

/* Build transportid array which may contain one or more TransportIDs.
 * A single TransportID can appear on the command line either as a list of
 * comma (or single space) separated ASCII hex bytes, or in some transport
 * protocol specific form (e.g. "sas,5000c50005b32001"). One or more
 * TransportIDs may be given in a file (syntax: "file=<name>") or read from
 * stdin in (when "-" is given). Fuller description in manpage of
 * sg_persist(8). Returns 0 if successful, else 1 .
 */
static int
build_transportid(const char * inp, struct opts_t * optsp)
{
    int in_len;
    int k = 0;
    unsigned int h;
    const char * lcp;
    unsigned char * tid_arr = optsp->transportid_arr;
    char * cp;
    char * c2p;

    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len) {
        optsp->num_transportids = 0;
    }
    if (('-' == inp[0]) ||
        (0 == memcmp("file=", inp, 5)) ||
        (0 == memcmp("FILE=", inp, 5))) {
        if ('-' == inp[0])
            lcp = NULL;         /* read from stdin */
        else
            lcp = inp + 5;      /* read from given file */
        return decode_file_tids(lcp, optsp);
    } else {        /* TransportID given directly on command line */
        if (decode_sym_transportid(lcp, tid_arr))
            goto my_cont_b;
        k = strspn(inp, "0123456789aAbBcCdDeEfF, ");
        if (in_len != k) {
            fprintf(stderr, "build_transportid: error at pos %d\n",
                    k + 1);
            return 1;
        }
        for (k = 0; k < (int)sizeof(optsp->transportid_arr); ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    fprintf(stderr, "build_transportid: hex number larger "
                            "than 0xff at pos %d\n", (int)(lcp - inp + 1));
                    return 1;
                }
                tid_arr[k] = h;
                cp = strchr(lcp, ',');
                c2p = strchr(lcp, ' ');
                if (NULL == cp)
                    cp = c2p;
                if (NULL == cp)
                    break;
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                fprintf(stderr, "build_transportid: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
my_cont_b:
        optsp->num_transportids = 1;
        if (k >= (int)sizeof(optsp->transportid_arr)) {
            fprintf(stderr, "build_transportid: array length exceeded\n");
            return 1;
        }
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    int sg_fd, c, res;
    const char * device_name = NULL;
    char buff[48];
    int num_prin_sa = 0;
    int num_prout_sa = 0;
    int num_prout_param = 0;
    int want_prin = 0;
    int want_prout = 0;
    int peri_type = 0;
    int ret = 0;
    struct sg_simple_inquiry_resp inq_resp;
    const char * cp;
    struct opts_t opts;

    memset(&opts, 0, sizeof(opts));
    opts.prin = 1;
    opts.prin_sa = -1;
    opts.prout_sa = -1;
    opts.inquiry = 1;
    opts.alloc_len = MX_ALLOC_LEN;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "AcCd:GHhiIkK:l:LMnoPQrRsS:T:UvVX:YZ",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'A':
            opts.prout_sa = PROUT_PREE_AB_SA;
            ++num_prout_sa;
            break;
        case 'c':
            opts.prin_sa = PRIN_RCAP_SA;
            ++num_prin_sa;
            break;
        case 'C':
            opts.prout_sa = PROUT_CLEAR_SA;
            ++num_prout_sa;
            break;
        case 'd':
            device_name = optarg;
            break;
        case 'G':
            opts.prout_sa = PROUT_REG_SA;
            ++num_prout_sa;
            break;
        case 'h':
            usage();
            return 0;
        case 'H':
            ++opts.hex;
            break;
        case 'i':
            want_prin = 1;
            break;
        case 'I':
            opts.prout_sa = PROUT_REG_IGN_SA;
            ++num_prout_sa;
            break;
        case 'k':
            opts.prin_sa = PRIN_RKEY_SA;
            ++num_prin_sa;
            break;
        case 'K':
            if (1 != sscanf(optarg, "%" SCNx64 "", &opts.param_rk)) {
                fprintf(stderr, "bad argument to '--param-rk'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++num_prout_param;
            break;
        case 'l':
            if (1 != sscanf(optarg, "%x", &opts.alloc_len)) {
                fprintf(stderr, "bad argument to '--alloc-length'\n");
                return SG_LIB_SYNTAX_ERROR;
            } else if (MX_ALLOC_LEN < opts.alloc_len) {
                fprintf(stderr, "'--alloc-length' argument exceeds maximum"
                        " value(%d)\n", MX_ALLOC_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'L':
            opts.prout_sa = PROUT_REL_SA;
            ++num_prout_sa;
            break;
        case 'M':
            opts.prout_sa = PROUT_REG_MOVE_SA;
            ++num_prout_sa;
            break;
        case 'n':
            opts.inquiry = 0;
            break;
        case 'o':
            want_prout = 1;
            break;
        case 'P':
            opts.prout_sa = PROUT_PREE_SA;
            ++num_prout_sa;
            break;
        case 'Q':
            if (1 != sscanf(optarg, "%x", &opts.param_rtp)) {
                fprintf(stderr, "bad argument to '--relative-target-port'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (opts.param_rtp > 0xffff) {
                fprintf(stderr, "argument to '--relative-target-port' 0 to "
                        "ffff inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++num_prout_param;
            break;
        case 'r':
            opts.prin_sa = PRIN_RRES_SA;
            ++num_prin_sa;
            break;
        case 'R':
            opts.prout_sa = PROUT_RES_SA;
            ++num_prout_sa;
            break;
        case 's':
            opts.prin_sa = PRIN_RFSTAT_SA;
            ++num_prin_sa;
            break;
        case 'S':
            if (1 != sscanf(optarg, "%" SCNx64 "", &opts.param_sark)) {
                fprintf(stderr, "bad argument to '--param-sark'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++num_prout_param;
            break;
        case 'T':
            if (1 != sscanf(optarg, "%x", &opts.prout_type)) {
                fprintf(stderr, "bad argument to '--prout-type'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++num_prout_param;
            break;
        case 'U':
            opts.param_unreg = 1;
            break;
        case 'v':
            ++opts.verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
        case 'X':
            if (0 != build_transportid(optarg, &opts)) {
                fprintf(stderr, "bad argument to '--transport-id'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++num_prout_param;
            break;
        case 'Y':
            opts.param_alltgpt = 1;
            ++num_prout_param;
            break;
        case 'Z':
            opts.param_aptpl = 1;
            ++num_prout_param;
            break;
        case '?':
            usage();
            return 0;
        default:
            fprintf(stderr, "unrecognised switch "
                                "code 0x%x ??\n", c);
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

    if (NULL == device_name) {
        fprintf(stderr, "No device name given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((want_prout + want_prin) > 1) {
        fprintf(stderr, "choose '--in' _or_ '--out' (not both)\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    } else if (want_prout) { /* syntax check on PROUT arguments */
        opts.prin = 0;
        if ((1 != num_prout_sa) || (0 != num_prin_sa)) {
            fprintf(stderr, ">> For Persistent Reserve Out one and "
                    "only one appropriate\n>> service action must be "
                    "chosen (e.g. '--register')\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    } else { /* syntax check on PRIN arguments */
        if (num_prout_sa > 0) {
            fprintf(stderr, ">> When a service action for Persistent "
                    "Reserve Out is chosen the\n"
                    ">> '--out' option must be given (as a safeguard)\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (0 == num_prin_sa) {
            fprintf(stderr, ">> No service action given; assume Persistent"
                    " Reserve In command\n"
                    ">> with Read Keys service action\n");
            opts.prin_sa = 0;
            ++num_prin_sa;
        } else if (num_prin_sa > 1)  {
            fprintf(stderr, "Too many service actions given; choose "
                    "one only\n");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if ((opts.param_unreg || opts.param_rtp) &&
        (PROUT_REG_MOVE_SA != opts.prout_sa)) {
        fprintf(stderr, "--unreg or --relative-target-port"
                " only useful with --register-move\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((PROUT_REG_MOVE_SA == opts.prout_sa) &&
        (1 != opts.num_transportids)) {
        fprintf(stderr, "with --register-move one (and only one) "
                "--transport-id should be given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (((PROUT_RES_SA == opts.prout_sa) ||
         (PROUT_REL_SA == opts.prout_sa) ||
         (PROUT_PREE_SA == opts.prout_sa) ||
         (PROUT_PREE_AB_SA == opts.prout_sa)) &&
        (0 == opts.prout_type)) {
        fprintf(stderr, "warning>>> --prout-type probably needs to be "
                "given\n");
    }
    if ((opts.verbose > 2) && opts.num_transportids) {
        fprintf(stderr, "number of tranport-ids decoded from "
                "command line (or stdin): %d\n", opts.num_transportids);
        fprintf(stderr, "  Decode given transport-ids:\n");
        decode_transport_id("      ", opts.transportid_arr,
                            0, opts.num_transportids);
    }

    if (opts.inquiry) {
        if ((sg_fd = sg_cmds_open_device(device_name, 1 /* ro */,
                                         opts.verbose)) < 0) {
            fprintf(stderr, "sg_persist: error opening file (ro): %s: %s\n",
                     device_name, safe_strerror(-sg_fd));
            return SG_LIB_FILE_ERROR;
        }
        if (0 == sg_simple_inquiry(sg_fd, &inq_resp, 1, opts.verbose)) {
            printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor, inq_resp.product,
                   inq_resp.revision);
            peri_type = inq_resp.peripheral_type;
            cp = sg_get_pdt_str(peri_type, sizeof(buff), buff);
            if (strlen(cp) > 0)
                printf("  Peripheral device type: %s\n", cp);
            else
                printf("  Peripheral device type: 0x%x\n", peri_type);
        } else {
            printf("sg_persist: %s doesn't respond to a SCSI INQUIRY\n",
                   device_name);
            return SG_LIB_CAT_OTHER;
        }
        sg_cmds_close_device(sg_fd);
    }

    if ((sg_fd = sg_cmds_open_device(device_name, 0 /* rw */,
                                     opts.verbose)) < 0) {
        fprintf(stderr, "sg_persist: error opening file (rw): %s: %s\n",
                device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (opts.prin)
        ret = prin_work(sg_fd, &opts);
    else if (PROUT_REG_MOVE_SA == opts.prout_sa)
        ret = prout_reg_move_work(sg_fd, &opts);
    else /* PROUT commands other than 'register and move' */
        ret = prout_work(sg_fd, &opts);

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
