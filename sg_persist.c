#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
*  Copyright (C) 2004-2006 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program issues the SCSI PERSISTENT IN and OUT commands. 

*/

static char * version_str = "0.25 20060117";


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


static struct option long_options[] = {
        {"clear", 0, 0, 'C'},
        {"device", 1, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"in", 0, 0, 'i'},
        {"out", 0, 0, 'o'},
        {"no-inquiry", 0, 0, 'n'},
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


static void usage()
{
    fprintf(stderr,
            "Usage: 'sg_persist [<options>] [<scsi_device>]\n"
            " where Persistent Reservation (PR) <options> include:\n"
            "       --clear|-C             PR Out: Clear\n"
            "       --device=<scsi_device> device to query or change\n"
            "       -d <scsi_device>       device to query or change "
            "('-d' optional)\n"
            "       --help|-h    output this usage message (no <scsi_device> "
            "required)\n"
            "       --hex|-H     output response in hex (default ACSII)\n"
            "       --in|-i                request PR In command (default)\n"
            "       --out|-o               request PR Out command\n"
            "       --no-inquiry|-n        skip INQUIRY (default: do "
            "INQUIRY)\n"
            "       --param-alltgpt|-Y     PR Out parameter 'ALL_TG_PT'\n"
            "       --param-aptpl|-Z       PR Out parameter 'APTPL'\n"
            "       --param-rk=<h>|-K <h>  PR Out parameter reservation key\n"
            "                 (argument in hex)\n"
            "       --param-sark=<h>|-S <h>  PR Out parameter service action\n"
            "                 reservation key (argument in hex)\n"
            "       --preempt|-P           PR Out: Preempt\n"
            "       --preempt-abort|-A     PR Out: Preempt and Abort\n"
            "       --prout-type=<h>|-T <n>  PR Out command type\n"
            "       --read-keys|-k         PR In: Read Keys\n"
            "       --read-reservation|-r  PR In: Read Reservation\n"
            "       --read-status|-s       PR In: Read Full Status\n"
            "       --read-full-status|-s  PR In: Read Full Status\n"
            "       --register|-G          PR Out: Register\n"
            "       --register-ignore|-I   PR Out: Register and Ignore\n"
            "       --register-move|-M     PR Out: Register and Move\n"
            "       --relative-target-port=<h>|-Q <h>  PR Out parameter for "
            "'-M'\n"
            "       --release|-L           PR Out: Release\n"
            "       --report-capabilities|-c   PR In: Report Capabilities\n"
            "       --reserve|-R           PR Out: Reserve\n"
            "       --transport-id=<h>,<h>...|-X <h>,<h>...  TransportID "
            "hex number\n"
            "                 comma separated list\n"
            "       --transport-id=-|-X -  read TransportID from stdin\n"
            "       --unreg|-U     optional with PR Out Register and Move\n"
            "       --verbose|-v   output additional debug information\n"
            "       --version|-V   output version string\n"
            "       -?   output this usage message\n\n"
            "Performs a PERSISTENT RESERVATION (IN or OUT) SCSI command\n");
}

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

static void decode_transport_id(const char * leadin, unsigned char * ucp,
                                int len)
{
    int format_code, proto_id, num, j, k;
    unsigned long long ull;
    int bump;

    for (k = 0, bump; k < len; k += bump, ucp += bump) {
        if ((len < 24) || (0 != (len % 4)))
            printf("%sTransport Id short or not multiple of 4 "
                   "[length=%d]:\n", leadin, len);
        else
            printf("%sTransport Id of initiator:\n", leadin);
        format_code = ((ucp[0] >> 6) & 0x3);
        proto_id = (ucp[0] & 0xf);
        switch (proto_id) {
        case 0: /* Fibre channel */
            printf("%s  FCP-2 World Wide Name:\n", leadin);
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, 0);
            bump = 24;
            break;
        case 1: /* Parallel SCSI */
            printf("%s  Parallel SCSI initiator SCSI address: 0x%x\n",
                   leadin, ((ucp[2] << 8) | ucp[3]));
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            printf("%s  relative port number (of corresponding target): "
                   "0x%x\n", leadin, ((ucp[6] << 8) | ucp[7]));
            bump = 24;
            break;
        case 2: /* SSA */
            printf("%s  SSA (transport id not defined):\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case 3: /* IEEE 1394 */
            printf("%s  IEEE 1394 EUI-64 name:\n", leadin);
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, 0);
            bump = 24;
            break;
        case 4: /* Remote Direct Memory Access (RDMA) */
            printf("%s  RDMA initiator port identifier:\n", leadin);
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 16, 0);
            bump = 24;
            break;
        case 5: /* iSCSI */
            printf("%s  iSCSI ", leadin);
            num = ((ucp[2] << 8) | ucp[3]);
            if (0 == format_code)
                printf("name: %.*s\n", num, &ucp[4]);
            else if (1 == format_code)
                printf("world wide unique port id: %.*s\n", num, &ucp[4]);
            else {
                printf("  [Unexpected format code: %d]\n", format_code);
                dStrHex((const char *)ucp, num + 4, 0);
            }
            bump = (((num + 4) < 24) ? 24 : num + 4);
            break;
        case 6: /* SAS */
            ull = 0;
            for (j = 0; j < 8; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= ucp[4 + j];
            }
            printf("%s  SAS address: 0x%llx\n", leadin, ull);
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            bump = 24;
            break;
        case 7: /* Automation/Drive Interface */
            printf("%s  ADT:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case 8: /* ATAPI */
            printf("%s  ATAPI:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        default:
            fprintf(stderr, "%s  unknown protocol id=0x%x  "
                    "format_code=%d\n", leadin, proto_id, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        }
    }
}

static int prin_work(int sg_fd, int prin_sa, int do_verbose, int do_hex)
{
    int k, j, num, res, add_len, add_desc_len, rel_pt_addr;
    unsigned int pr_gen;
    unsigned long long ull;
    unsigned char * ucp;
    unsigned char pr_buff[MX_ALLOC_LEN];

    memset(pr_buff, 0, sizeof(pr_buff));
    res = sg_ll_persistent_reserve_in(sg_fd, prin_sa, pr_buff,
                                      sizeof(pr_buff), 1, do_verbose);
    if (res) {
       if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "Persistent reserve in command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in Persistent reserve in cdb\n");
        else
            fprintf(stderr, "Persistent reserve in command failed\n");
        return 1;
    }
    if (PRIN_RCAP_SA == prin_sa) {
        if (8 != pr_buff[1]) {
            fprintf(stderr, "Unexpected response for PRIN Report "
                            "Capabilities\n");
            return 1;
        }
        if (do_hex)
            dStrHex((const char *)pr_buff, 8, 1);
        else {
            printf("Report capabilities response:\n");
            printf("  Compatible Reservation handling(CRH): %d\n",
                   !!(pr_buff[2] & 0x10));
            printf("  Specify Initiator Ports capable(SIP_C): %d\n",
                   !!(pr_buff[2] & 0x8));
            printf("  All target ports capable(ATP_C): %d\n",
                   !!(pr_buff[2] & 0x4));
            printf("  Persist Through Power Loss capable(PTPL_C): %d\n",
                   !!(pr_buff[2] & 0x1));
            printf("  Type Mask Valid(TMV): %d\n",
                   !!(pr_buff[3] & 0x80));
            printf("  Allow commands: %d\n", (pr_buff[3] >> 4) & 0x7);
            printf("  Persist Through Power Loss active(PTPL_A): %d\n",
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
        if (do_hex) {
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
        } else if (PRIN_RKEY_SA == prin_sa) {
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
                    printf("    0x%llx\n", ull);
                }
            } else
                printf("there are NO registered reservation keys\n");
        } else if (PRIN_RRES_SA == prin_sa) {
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
                printf("    Key=0x%llx\n", ull);
                j = ((ucp[13] >> 4) & 0xf);
                if (0 == j)
                    printf("    scope: LU_SCOPE, ");
                else
                    printf("    scope: %d ", j);
                j = (ucp[13] & 0xf);
                printf(" type: %s\n", pr_type_strs[j]);
            } else
                printf("there is NO reservation held\n");
        } else if (PRIN_RFSTAT_SA == prin_sa) {
            printf("  PR generation=0x%x\n", pr_gen);
            ucp = pr_buff + 8;
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
                printf("    Key=0x%llx\n", ull);
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
                    decode_transport_id("      ", &ucp[24], add_desc_len);
            }
        }
    }
    return 0;
}

static int prout_work(int sg_fd, int prout_sa, unsigned int prout_type, 
                      unsigned long long param_rk, 
                      unsigned long long param_sark, int param_alltgpt,
                      int param_aptpl, unsigned char * transportidp,
                      int transportid_len, int do_verbose)
{
    int j, len, res;
    unsigned char pr_buff[MX_ALLOC_LEN];

    memset(pr_buff, 0, sizeof(pr_buff));
    for (j = 7; j >= 0; --j) {
        pr_buff[j] = (param_rk & 0xff);
        param_rk >>= 8;
    }
    for (j = 7; j >= 0; --j) {
        pr_buff[8 + j] = (param_sark & 0xff);
        param_sark >>= 8;
    }
    if (param_alltgpt)
        pr_buff[20] |= 0x4;
    if (param_aptpl)
        pr_buff[20] |= 0x1;
    len = 24;
    if (transportid_len > 0) {
        pr_buff[20] |= 0x8;     /* set SPEC_I_PT bit */
        memcpy(&pr_buff[28], transportidp, transportid_len);
        len += (transportid_len + 4);
        pr_buff[24] = (unsigned char)((transportid_len >> 24) & 0xff);
        pr_buff[25] = (unsigned char)((transportid_len >> 16) & 0xff);
        pr_buff[26] = (unsigned char)((transportid_len >> 8) & 0xff);
        pr_buff[27] = (unsigned char)(transportid_len & 0xff);
    }
    res = sg_ll_persistent_reserve_out(sg_fd, prout_sa, 0, prout_type,
                                       pr_buff, len, 1, do_verbose);
    if (res) {
       if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "Persistent reserve out command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in Persistent reserve out cdb\n");
        else
            fprintf(stderr, "Persistent reserve out command failed\n");
        return 1;
    } else if (do_verbose) {
        char buff[64];

        if (prout_sa < num_prout_sa_strs)
            strncpy(buff, prout_sa_strs[prout_sa], sizeof(buff));
        else
            snprintf(buff, sizeof(buff), "service action=0x%x", prout_sa);
        fprintf(stderr, "Persistent Reservation Out command (%s) "
                "successful\n", buff);
    }
    return 0;
}

static int prout_rmove_work(int sg_fd, unsigned int prout_type, 
                      unsigned long long param_rk, 
                      unsigned long long param_sark, int param_unreg,
                      int param_aptpl, unsigned int rel_target_port,
                      unsigned char * transportidp, int transportid_len,
                      int do_verbose)
{
    int j, len, res;
    unsigned char pr_buff[MX_ALLOC_LEN];

    memset(pr_buff, 0, sizeof(pr_buff));
    for (j = 7; j >= 0; --j) {
        pr_buff[j] = (param_rk & 0xff);
        param_rk >>= 8;
    }
    for (j = 7; j >= 0; --j) {
        pr_buff[8 + j] = (param_sark & 0xff);
        param_sark >>= 8;
    }
    if (param_unreg)
        pr_buff[17] |= 0x2;
    if (param_aptpl)
        pr_buff[17] |= 0x1;
    pr_buff[18] = (unsigned char)((rel_target_port >> 8) & 0xff);
    pr_buff[19] = (unsigned char)(rel_target_port & 0xff);
    len = 24;
    if (transportid_len > 0) {
        memcpy(&pr_buff[24], transportidp, transportid_len);
        len += transportid_len;
        pr_buff[20] = (unsigned char)((transportid_len >> 24) & 0xff);
        pr_buff[21] = (unsigned char)((transportid_len >> 16) & 0xff);
        pr_buff[22] = (unsigned char)((transportid_len >> 8) & 0xff);
        pr_buff[23] = (unsigned char)(transportid_len & 0xff);
    }
    res = sg_ll_persistent_reserve_out(sg_fd, PROUT_REG_MOVE_SA, 0,
                                       prout_type, pr_buff, len, 1,
                                       do_verbose);
    if (res) {
       if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "Persistent reserve out command not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in Persistent reserve out cdb\n");
        else
            fprintf(stderr, "Persistent reserve out command failed\n");
        return 1;
    } else if (do_verbose)
        fprintf(stderr, "Persistent Reservation Out 'register and move' "
                "command successful\n");
    return 0;
}

static int build_transportid(const char * inp, unsigned char * tid_arr,
                             int * tid_arr_len, int * num_tids,
                             int max_arr_len)
{
    int in_len, k, j, m;
    unsigned int h;
    const char * lcp;
    char * cp;

    if ((NULL == inp) || (NULL == tid_arr) ||
        (NULL == tid_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len) {
        *tid_arr_len = 0;
        if (num_tids)
            *num_tids = 0;
    }
    if ('-' == inp[0]) {        /* read from stdin */
        char line[512];
        int off = 0;
        int num = 0;

        for (j = 0, off = 0; j < 512; ++j) {
            if (NULL == fgets(line, sizeof(line), stdin))
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
            k = strspn(lcp, "0123456789aAbBcCdDeEfF ,\t");
            if ((k < in_len) && ('#' != lcp[k])) {
                fprintf(stderr, "build_transportid: syntax error at "
                        "line %d, pos %d\n", j + 1, m + k + 1);
                return 1;
            }
            for (k = 0; k < 1024; ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        fprintf(stderr, "build_transportid: hex number "
                                "larger than 0xff in line %d, pos %d\n",
                                j + 1, (int)(lcp - line + 1));
                        return 1;
                    }
                    if ((off + k) >= max_arr_len) {
                        fprintf(stderr, "build_transportid: array length "
                                "exceeded\n");
                        return 1;
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
                    fprintf(stderr, "build_transportid: error in "
                            "line %d, at pos %d\n", j + 1,
                            (int)(lcp - line + 1));
                    return 1;
                }
            }
            if (k < 24)
                k = 24;
            else if (0 != (k % 4))
                k = ((k / 4) + 1) * 4;
            off += k;
            ++num;
        }
        *tid_arr_len = off;
        if (num_tids)
            *num_tids = num;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF,");
        if (in_len != k) {
            fprintf(stderr, "build_transportid: error at pos %d\n",
                    k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    fprintf(stderr, "build_transportid: hex number larger "
                            "than 0xff at pos %d\n", (int)(lcp - inp + 1));
                    return 1;
                }
                tid_arr[k] = h;
                cp = strchr(lcp, ',');
                if (NULL == cp)
                    break;
                lcp = cp + 1;
            } else {
                fprintf(stderr, "build_transportid: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        if (k < 24)
            k = 24;
        else if (0 != (k % 4))
            k = ((k / 4) + 1) * 4;
        *tid_arr_len = k;
        if (num_tids)
            *num_tids = 1;
        if (k >= max_arr_len) {
            fprintf(stderr, "build_transportid: array length exceeded\n");
            return 1;
        }
    }
    return 0;
}


int main(int argc, char * argv[])
{
    int sg_fd, c;
    unsigned int prout_type;
    unsigned long long param_rk = 0;
    unsigned long long param_sark = 0;
    unsigned int param_rtp = 0;
    char device_name[256];
    char buff[48];
    int num_prin_sa = 0;
    int num_prout_sa = 0;
    int num_prout_param = 0;
    int want_prin = 0;
    int want_prout = 0;
    int prin = 1;
    int prin_sa = -1;
    int prout_sa = -1;
    int param_alltgpt = 0;
    int param_aptpl = 0;
    int param_unreg = 0;
    int do_inquiry = 1;
    int do_hex = 0;
    int do_verbose = 0;
    int peri_type = 0;
    int ret = 0;
    unsigned char transportid_arr[MX_ALLOC_LEN];
    int transportid_arr_len = 0;
    int num_transportids = 0;
    struct sg_simple_inquiry_resp inq_resp;
    const char * cp;

    device_name[0] = '\0';
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "AcCd:GHhiIkK:LMnoPQrRsS:T:UvVX:YZ", 
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'A':
            prout_sa = PROUT_PREE_AB_SA;
            ++num_prout_sa;
            break;
        case 'c':
            prin_sa = PRIN_RCAP_SA;
            ++num_prin_sa;
            break;
        case 'C':
            prout_sa = PROUT_CLEAR_SA;
            ++num_prout_sa;
            break;
        case 'd':
            strncpy(device_name, optarg, sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            break;
        case 'G':
            prout_sa = PROUT_REG_SA;
            ++num_prout_sa;
            break;
        case 'h':
            usage();
            return 0;
        case 'H':
            do_hex = 1;
            break;
        case 'i':
            want_prin = 1;
            break;
        case 'I':
            prout_sa = PROUT_REG_IGN_SA;
            ++num_prout_sa;
            break;
        case 'k':
            prin_sa = PRIN_RKEY_SA;
            ++num_prin_sa;
            break;
        case 'K':
            if (1 != sscanf(optarg, "%llx", &param_rk)) {
                fprintf(stderr, "bad argument to '--param-rk'\n");
                return 1;
            }
            ++num_prout_param;
            break;
        case 'L':
            prout_sa = PROUT_REL_SA;
            ++num_prout_sa;
            break;
        case 'M':
            prout_sa = PROUT_REG_MOVE_SA;
            ++num_prout_sa;
            break;
        case 'n':
            do_inquiry = 0;
            break;
        case 'o':
            want_prout = 1;
            break;
        case 'P':
            prout_sa = PROUT_PREE_SA;
            ++num_prout_sa;
            break;
        case 'Q':
            if (1 != sscanf(optarg, "%x", &param_rtp)) {
                fprintf(stderr, "bad argument to '--relative-target-port'\n");
                return 1;
            }
            if (param_rtp > 0xffff) {
                fprintf(stderr, "argument to '--relative-target-port' 0 to "
                        "ffff inclusive\n");
                return 1;
            }
            ++num_prout_param;
            break;
        case 'r':
            prin_sa = PRIN_RRES_SA;
            ++num_prin_sa;
            break;
        case 'R':
            prout_sa = PROUT_RES_SA;
            ++num_prout_sa;
            break;
        case 's':
            prin_sa = PRIN_RFSTAT_SA;
            ++num_prin_sa;
            break;
        case 'S':
            if (1 != sscanf(optarg, "%llx", &param_sark)) {
                fprintf(stderr, "bad argument to '--param-sark'\n");
                return 1;
            }
            ++num_prout_param;
            break;
        case 'T':
            if (1 != sscanf(optarg, "%x", &prout_type)) {
                fprintf(stderr, "bad argument to '--prout-type'\n");
                return 1;
            }
            ++num_prout_param;
            break;
        case 'U':
            param_unreg = 1;
            break;
        case 'v':
            ++do_verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
        case 'X':
            memset(transportid_arr, 0, sizeof(transportid_arr));
            if (0 != build_transportid(optarg, transportid_arr, 
                                       &transportid_arr_len, 
                                       &num_transportids,
                                       sizeof(transportid_arr))) {
                fprintf(stderr, "bad argument to '--transport-id'\n");
                return 1;
            }
            ++num_prout_param;
            break;
        case 'Y':
            param_alltgpt = 1;
            ++num_prout_param;
            break;
        case 'Z':
            param_aptpl = 1;
            ++num_prout_param;
            break;
        case '?':
            usage();
            return 1;
        default:
            fprintf(stderr, "unrecognised switch "
                                "code 0x%x ??\n", c);
            usage();
            return 1;
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
            return 1;
        }
    }

    if ('\0' == device_name[0]) {
        fprintf(stderr, "No device name given\n");
        usage();
        return 1;
    }
    if ((want_prout + want_prin) > 1) {
        fprintf(stderr, "choose '--in' _or_ '--out' (not both)\n");
        usage();
        return 1;
    } else if (want_prout) { /* syntax check on PROUT arguments */
        prin = 0;
        if ((1 != num_prout_sa) || (0 != num_prin_sa)) {
            fprintf(stderr, ">> For Persistent Reservation Out one and "
                    "only one appropriate\n>> service action must be "
                    "chosen (e.g. '--register')\n");
            return 1;
        }
    } else { /* syntax check on PRIN arguments */
        if (num_prout_sa > 0) {
            fprintf(stderr, ">> When a service action for Persistent "
                    "Reservation Out is chosen the\n"
                    ">> '--out' option must be given (as a safeguard)\n");
            return 1;
        }
        if (0 == num_prin_sa) {
            fprintf(stderr, ">> No service action given; assume Persistent"
                    " Reservations In command\n"
                    ">> with Read Keys service action\n");
            prin_sa = 0;
            ++num_prin_sa;
        } else if (num_prin_sa > 1)  {
            fprintf(stderr, "Too many service actions given; choose "
                    "one only\n");
            usage();
            return 1;
        }
    }
    if ((param_unreg || param_rtp) && (PROUT_REG_MOVE_SA != prout_sa)) {
        fprintf(stderr, "--unreg or --relative-target-port"
                " only useful with --register-move\n");
        usage();
        return 1;
    }
    if ((PROUT_REG_MOVE_SA == prout_sa) && (1 != num_transportids)) {
        fprintf(stderr, "with --register-move one (and only one) "
                "--transport-id should be given\n");
        usage();
        return 1;
    }
    if (((PROUT_RES_SA == prout_sa) ||
         (PROUT_REL_SA == prout_sa) ||
         (PROUT_PREE_SA == prout_sa) ||
         (PROUT_PREE_AB_SA == prout_sa)) &&
        (0 == prout_type)) {
        fprintf(stderr, "warning>>> --prout-type probably needs to be "
                "given\n");
    }
    if ((do_verbose > 2) && num_transportids) {
        fprintf(stderr, "number of tranport-ids decoded from "
                "command line (or stdin): %d\n", num_transportids);
        fprintf(stderr, "  Decode given transport-ids:\n");
        decode_transport_id("      ", transportid_arr, transportid_arr_len);
    }

    if (do_inquiry) {
        if ((sg_fd = sg_cmds_open_device(device_name, 1 /* ro */,
                                         do_verbose)) < 0) {
            fprintf(stderr, "sg_persist: error opening file (ro): %s: %s\n",
                     device_name, safe_strerror(-sg_fd));
            return 1;
        }
        if (0 == sg_simple_inquiry(sg_fd, &inq_resp, 1, do_verbose)) {
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
            return 1;
        }
        sg_cmds_close_device(sg_fd);
    }

    if ((sg_fd = sg_cmds_open_device(device_name, 0 /* rw */,
                                     do_verbose)) < 0) {
        fprintf(stderr, "sg_persist: error opening file (rw): %s: %s\n",
                device_name, safe_strerror(-sg_fd));
        return 1;
    }

    if (prin)
        ret = prin_work(sg_fd, prin_sa, do_verbose, do_hex);
    else if (PROUT_REG_MOVE_SA == prout_sa)
        ret = prout_rmove_work(sg_fd, prout_type, param_rk,
                         param_sark, param_unreg, param_aptpl,
                         param_rtp, transportid_arr, transportid_arr_len,
                         do_verbose);

    else /* PROUT commands other than 'register and move' */
        ret = prout_work(sg_fd, prout_sa, prout_type, param_rk,
                         param_sark, param_alltgpt, param_aptpl,
                         transportid_arr, transportid_arr_len, do_verbose);

    sg_cmds_close_device(sg_fd);
    return ret;
}
