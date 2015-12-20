/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 2004-2015 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.

    This program outputs information provided by a SCSI REPORT SUPPORTED
    OPERATION CODES [0xa3/0xc] and REPORT SUPPORTED TASK MANAGEMENT
    FUNCTIONS [0xa3/0xd] commands.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

#include "sg_pt.h"

static const char * version_str = "0.45 20151219";    /* spc5r07 */


#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_TIMEOUT_SECS 60

#define SG_MAINTENANCE_IN 0xa3
#define RSOC_SA     0xc
#define RSTMF_SA    0xd
#define RSOC_CMD_LEN 12
#define RSTMF_CMD_LEN 12
#define MX_ALLOC_LEN 8192

#define NAME_BUFF_SZ 128


static int peri_type = 0; /* ugly but not easy to pass to alpha compare */

static int do_rsoc(int sg_fd, int rctd, int rep_opts, int rq_opcode,
                   int rq_servact, void * resp, int mx_resp_len, int noisy,
                   int verbose);
static int do_rstmf(int sg_fd, int repd, void * resp, int mx_resp_len,
                    int noisy, int verbose);


static struct option long_options[] = {
        {"alpha", 0, 0, 'a'},
        {"compact", 0, 0, 'c'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"mask", 0, 0, 'm'},
        {"no-inquiry", 0, 0, 'n'},
        {"new", 0, 0, 'N'},
        {"opcode", 1, 0, 'o'},
        {"old", 0, 0, 'O'},
        {"raw", 0, 0, 'r'},
        {"rctd", 0, 0, 'R'},
        {"repd", 0, 0, 'q'},
        {"sa", 1, 0, 's'},
        {"tmf", 0, 0, 't'},
        {"unsorted", 0, 0, 'u'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_alpha;
    int do_compact;
    int do_help;
    int do_hex;
    int no_inquiry;
    int do_mask;
    int do_opcode;
    int do_raw;
    int do_rctd;
    int do_repd;
    int do_servact;
    int do_verbose;
    int do_version;
    int do_unsorted;
    int do_taskman;
    const char * device_name;
    int opt_new;
};


static void
usage()
{
    pr2serr("Usage:  sg_opcodes [--alpha] [--compact] [--help] [--hex] "
            "[--mask]\n"
            "                   [--no-inquiry] [--opcode=OP[,SA]] [--raw] "
            "[--rctd]\n"
            "                   [--repd] [--sa=SA] [--tmf] [--unsorted] "
            "[--verbose]\n"
            "                   [--version] DEVICE\n"
            "  where:\n"
            "    --alpha|-a      output list of operation codes sorted "
            "alphabetically\n"
            "    --compact|-c    more compact output\n"
            "    --help|-h       print usage message then exit\n"
            "    --hex|-H        output response in hex\n"
            "    --mask|-m       and show cdb usage data (a mask) when "
            "all listed\n"
            "    --no-inquiry|-n    don't output INQUIRY information\n"
            "    --opcode=OP|-o OP    first byte of command to query\n"
            "                         (decimal, prefix with '0x' for hex)\n"
            "    --opcode=OP,SA|-o OP,SA    opcode (OP) and service action "
            "(SA)\n"
            "                         (decimal, each prefix with '0x' for "
            "hex)\n"
            "    --raw|-r        output response in binary to stdout\n"
            "    --rctd|-R       set RCTD (return command timeout "
            "descriptor) bit\n"
            "    --repd|-q       set Report Extended Parameter Data bit, "
            "with --tmf\n"
            "    --sa=SA|-s SA    service action in addition to opcode\n"
            "                     (decimal, prefix with '0x' for hex)\n"
            "    --tmf|-t        output list of supported task management "
            "functions\n"
            "    --unsorted|-u    output list of operation codes as is\n"
            "                     (def: sort by opcode (then service "
            "action))\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version string then exit\n\n"
            "Performs a SCSI REPORT SUPPORTED OPERATION CODES or a REPORT "
            "SUPPORTED\nTASK MANAGEMENT FUNCTIONS command.\n");
}

static void
usage_old()
{
    pr2serr("Usage:  sg_opcodes [-a] [-c] [-H] [-m] [-n] [-o=OP] [-q] [-r] "
            "[-R] [-s=SA]\n"
            "                   [-t] [-u] [-v] [-V] DEVICE\n"
            "  where:\n"
            "    -a    output list of operation codes sorted "
            "alphabetically\n"
            "    -c    more compact output\n"
            "    -H    print response in hex\n"
            "    -m    and show cdb usage data (a mask) when all listed\n"
            "    -n    don't output INQUIRY information\n"
            "    -o=OP    first byte of command to query (in hex)\n"
            "    -q    set REPD bit for tmf_s\n"
            "    -r    output response in binary to stdout\n"
            "    -R    set RCTD (return command timeout "
            "descriptor) bit\n"
            "    -s=SA    in addition to opcode (in hex)\n"
            "    -t    output list of supported task management functions\n"
            "    -u    output list of operation codes as is (unsorted)\n"
            "    -v    verbose\n"
            "    -V    output version string\n"
            "    -?    output this usage message\n\n"
            "Performs a SCSI REPORT SUPPORTED OPERATION CODES (or a REPORT "
            "TASK MANAGEMENT\nFUNCTIONS) command\n");
}

static int
process_cl_new(struct opts_t * optsp, int argc, char * argv[])
{
    int c, n;
    char * cp;
    char b[32];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "achHmnNo:OqrRs:tuvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ++optsp->do_alpha;
            break;
        case 'c':
            ++optsp->do_compact;
            break;
        case 'h':
        case '?':
            ++optsp->do_help;
            break;
        case 'H':
            ++optsp->do_hex;
            break;
        case 'm':
            ++optsp->do_mask;
            break;
        case 'n':
            ++optsp->no_inquiry;
            break;
        case 'N':
            break;      /* ignore */
        case 'o':
            if (strlen(optarg) >= (sizeof(b) - 1)) {
                pr2serr("argument to '--opcode' too long\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            cp = strchr(optarg, ',');
            if (cp) {
                memset(b, 0, sizeof(b));
                strncpy(b, optarg, cp - optarg);
                n = sg_get_num(b);
                if ((n < 0) || (n > 255)) {
                    pr2serr("bad OP argument to '--opcode'\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->do_opcode = n;
                n = sg_get_num(cp + 1);
                if ((n < 0) || (n > 0xffff)) {
                    pr2serr("bad SA argument to '--opcode'\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->do_servact = n;
            } else {
                n = sg_get_num(optarg);
                if ((n < 0) || (n > 255)) {
                    pr2serr("bad argument to '--opcode'\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->do_opcode = n;
            }
            break;
        case 'O':
            optsp->opt_new = 0;
            return 0;
        case 'q':
            ++optsp->do_repd;
            break;
        case 'r':
            ++optsp->do_raw;
            break;
        case 'R':
            ++optsp->do_rctd;
            break;
        case 's':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 0xffff)) {
                pr2serr("bad argument to '--sa'\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->do_servact = n;
            break;
        case 't':
            ++optsp->do_taskman;
            break;
        case 'u':
            ++optsp->do_unsorted;
            break;
        case 'v':
            ++optsp->do_verbose;
            break;
        case 'V':
            ++optsp->do_version;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
            if (optsp->do_help)
                break;
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == optsp->device_name) {
            optsp->device_name = argv[optind];
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
process_cl_old(struct opts_t * optsp, int argc, char * argv[])
{
    int k, jmp_out, plen, n, num;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'a':
                    ++optsp->do_alpha;
                    break;
                case 'c':
                    ++optsp->do_compact;
                    break;
                case 'H':
                    ++optsp->do_hex;
                    break;
                case 'm':
                    ++optsp->do_mask;
                    break;
                case 'n':
                    ++optsp->no_inquiry;
                    break;
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'q':
                    ++optsp->do_repd;
                    break;
                case 'R':
                    ++optsp->do_rctd;
                    break;
                case 't':
                    ++optsp->do_taskman;
                    break;
                case 'u':
                    ++optsp->do_unsorted;
                    break;
                case 'v':
                    ++optsp->do_verbose;
                    break;
                case 'V':
                    ++optsp->do_version;
                    break;
                case 'h':
                case '?':
                    ++optsp->do_help;
                    break;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("o=", cp, 2)) {
                num = sscanf(cp + 2, "%x", (unsigned int *)&n);
                if ((1 != num) || (n > 255)) {
                    pr2serr("Bad number after 'o=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->do_opcode = n;
            } else if (0 == strncmp("s=", cp, 2)) {
                num = sscanf(cp + 2, "%x", (unsigned int *)&n);
                if (1 != num) {
                    pr2serr("Bad number after 's=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->do_servact = n;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (NULL == optsp->device_name)
            optsp->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not expecting: %s\n",
                    optsp->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int
process_cl(struct opts_t * optsp, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        optsp->opt_new = 0;
        res = process_cl_old(optsp, argc, argv);
        if ((0 == res) && optsp->opt_new)
            res = process_cl_new(optsp, argc, argv);
    } else {
        optsp->opt_new = 1;
        res = process_cl_new(optsp, argc, argv);
        if ((0 == res) && (0 == optsp->opt_new))
            res = process_cl_old(optsp, argc, argv);
    }
    return res;
}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

/* returns -1 when left < right, 0 when left == right, else returns 1 */
static int
opcode_num_compare(const void * left, const void * right)
{
    const unsigned char * ll = *(unsigned char **)left;
    const unsigned char * rr = *(unsigned char **)right;
    int l_serv_act = 0;
    int r_serv_act = 0;
    int l_opc, r_opc;

    if (NULL == ll)
        return -1;
    if (NULL == rr)
        return -1;
    l_opc = ll[0];
    if (ll[5] & 1)
        l_serv_act = sg_get_unaligned_be16(ll + 2);
    r_opc = rr[0];
    if (rr[5] & 1)
        r_serv_act = sg_get_unaligned_be16(rr + 2);
    if (l_opc < r_opc)
        return -1;
    if (l_opc > r_opc)
        return 1;
    if (l_serv_act < r_serv_act)
        return -1;
    if (l_serv_act > r_serv_act)
        return 1;
    return 0;
}

/* returns -1 when left < right, 0 when left == right, else returns 1 */
static int
opcode_alpha_compare(const void * left, const void * right)
{
    const unsigned char * ll = *(unsigned char **)left;
    const unsigned char * rr = *(unsigned char **)right;
    int l_serv_act = 0;
    int r_serv_act = 0;
    char l_name_buff[NAME_BUFF_SZ];
    char r_name_buff[NAME_BUFF_SZ];
    int l_opc, r_opc;

    if (NULL == ll)
        return -1;
    if (NULL == rr)
        return -1;
    l_opc = ll[0];
    if (ll[5] & 1)
        l_serv_act = sg_get_unaligned_be16(ll + 2);
    l_name_buff[0] = '\0';
    sg_get_opcode_sa_name(l_opc, l_serv_act, peri_type,
                          NAME_BUFF_SZ, l_name_buff);
    r_opc = rr[0];
    if (rr[5] & 1)
        r_serv_act = sg_get_unaligned_be16(rr + 2);
    r_name_buff[0] = '\0';
    sg_get_opcode_sa_name(r_opc, r_serv_act, peri_type,
                          NAME_BUFF_SZ, r_name_buff);
    return strncmp(l_name_buff, r_name_buff, NAME_BUFF_SZ);
}

static void
list_all_codes(unsigned char * rsoc_buff, int rsoc_len, struct opts_t * op,
               int sg_fd)
{
    int k, j, m, cd_len, serv_act, len, sa_v, opcode, res;
    unsigned int to;
    unsigned char * ucp;
    char name_buff[NAME_BUFF_SZ];
    char sa_buff[8];
    unsigned char ** sort_arr = NULL;

    cd_len = sg_get_unaligned_be32(rsoc_buff + 0);
    if (cd_len > (rsoc_len - 4)) {
        printf("sg_opcodes: command data length=%d, allocation=%d; "
               "truncate\n", cd_len, rsoc_len - 4);
        cd_len = ((rsoc_len - 4) / 8) * 8;
    }
    if (0 == cd_len) {
        printf("sg_opcodes: no commands to display\n");
        return;
    }
    if (op->do_rctd) {
        if (op->do_compact) {
            printf("\nOpcode,sa  Nominal  Recommended  Name\n");
            printf(  "  (hex)    timeout  timeout(sec)     \n");
            printf("-----------------------------------------------"
                   "---------\n");
        } else {
            printf("\nOpcode  Service    CDB   Nominal  Recommended  Name\n");
            printf(  "(hex)   action(h)  size  timeout  timeout(sec)     \n");
            printf("-------------------------------------------------------"
                   "---------\n");
        }
    } else {
        if (op->do_compact) {
            printf("\nOpcode,sa  Name\n");
            printf(  "  (hex)        \n");
            printf("---------------------------------------\n");
        } else {
            printf("\nOpcode  Service    CDB    Name\n");
            printf(  "(hex)   action(h)  size       \n");
            printf("-----------------------------------------------\n");
        }
    }
    /* SPC-4 does _not_ require any ordering of opcodes in the response */
    if (! op->do_unsorted) {
        sort_arr = (unsigned char **)malloc(cd_len * sizeof(unsigned char *));
        if (NULL == sort_arr) {
            printf("sg_opcodes: no memory to sort operation codes, "
                   "try '-u'\n");
            return;
        }
        memset(sort_arr, 0, cd_len * sizeof(unsigned char *));
        ucp = rsoc_buff + 4;
        for (k = 0, j = 0; k < cd_len; ++j, k += len, ucp += len) {
            sort_arr[j] = ucp;
            len = (ucp[5] & 0x2) ? 20 : 8;
        }
        qsort(sort_arr, j, sizeof(unsigned char *),
              (op->do_alpha ? opcode_alpha_compare : opcode_num_compare));
    }
    for (k = 0, j = 0; k < cd_len; ++j, k += len) {
        ucp = op->do_unsorted ? (rsoc_buff + 4 + k) : sort_arr[j];
        len = (ucp[5] & 0x2) ? 20 : 8;
        opcode = ucp[0];
        sa_v = ucp[5] & 1;
        serv_act = 0;
        if (sa_v) {
            serv_act = sg_get_unaligned_be16(ucp + 2);
            sg_get_opcode_sa_name(opcode, serv_act, peri_type, NAME_BUFF_SZ,
                                  name_buff);
            if (op->do_compact)
                snprintf(sa_buff, sizeof(sa_buff), "%-4x", serv_act);
            else
                snprintf(sa_buff, sizeof(sa_buff), "%4x", serv_act);
        } else {
            sg_get_opcode_name(opcode, peri_type, NAME_BUFF_SZ, name_buff);
            memset(sa_buff, ' ', sizeof(sa_buff));
        }
        if (op->do_rctd) {
            if (ucp[5] & 0x2) {
                if (op->do_compact)
                    printf(" %.2x%c%.4s", opcode, (sa_v ? ',' : ' '),
                           sa_buff);
                else
                    printf(" %.2x     %.4s       %3d", opcode, sa_buff,
                           sg_get_unaligned_be16(ucp + 6));
                to = sg_get_unaligned_be32(ucp + 12);
                if (0 == to)
                    printf("         -");
                else
                    printf("  %8u", to);
                to = sg_get_unaligned_be32(ucp + 16);
                if (0 == to)
                    printf("          -");
                else
                    printf("   %8u", to);
                printf("    %s\n", name_buff);
            } else
                if (op->do_compact)
                    printf(" %.2x%c%.4s                        %s\n", opcode,
                           (sa_v ? ',' : ' '), sa_buff, name_buff);
                else
                    printf(" %.2x     %.4s       %3d                         "
                           "%s\n", opcode, sa_buff,
                           sg_get_unaligned_be16(ucp + 6), name_buff);
        } else
            if (op->do_compact)
                printf(" %.2x%c%.4s   %s\n", ucp[0], (sa_v ? ',' : ' '),
                       sa_buff, name_buff);
            else
                printf(" %.2x     %.4s       %3d    %s\n", ucp[0], sa_buff,
                       sg_get_unaligned_be16(ucp + 6), name_buff);
        if (op->do_mask) {
            int cdb_sz;
            unsigned char b[64];

            memset(b, 0, sizeof(b));
            res = do_rsoc(sg_fd, 0, (sa_v ? 2 : 1), opcode, serv_act,
                          b, sizeof(b), 1, op->do_verbose);
            if (0 == res) {
                cdb_sz = sg_get_unaligned_be16(b + 2);
                if ((cdb_sz > 0) && (cdb_sz <= 80)) {
                    if (op->do_compact)
                        printf("             usage: ");
                    else
                        printf("        cdb usage: ");
                    for (m = 0; m < cdb_sz; ++m)
                        printf("%.2x ", b[4 + m]);
                    printf("\n");
                }
            }
        }
    }
    if (sort_arr)
        free(sort_arr);
}

static void
decode_cmd_to_descriptor(unsigned char * dp, int max_b_len, char * b)
{
    int len;
    unsigned int to;

    if ((max_b_len < 2) || (NULL == dp))
        return;
    b[max_b_len - 1] = '\0';
    --max_b_len;
    len = sg_get_unaligned_be16(dp + 0);
    if (10 != len) {
        snprintf(b, max_b_len, "command timeout descriptor length %d "
                 "(expect 10)", len);
        return;
    }
    to = sg_get_unaligned_be32(dp + 4);
    if (0 == to)
        snprintf(b, max_b_len, "no nominal timeout, ");
    else
        snprintf(b, max_b_len, "nominal timeout: %u secs, ", to);
    len = strlen(b);
    max_b_len -= len;
    b += len;
    to = sg_get_unaligned_be32(dp + 8);
    if (0 == to)
        snprintf(b, max_b_len, "no recommended timeout");
    else
        snprintf(b, max_b_len, "recommended timeout: %u secs", to);
    return;
}

static void
list_one(unsigned char * rsoc_buff, int cd_len, int rep_opts,
         struct opts_t * op)
{
    int k;
    char name_buff[NAME_BUFF_SZ];
    unsigned char * ucp;
    const char * cp;
    int v = 0;


    printf("\n  Opcode=0x%.2x", op->do_opcode);
    if (rep_opts > 1)
        printf("  Service_action=0x%.4x", op->do_servact);
    printf("\n");
    sg_get_opcode_sa_name(((op->do_opcode > 0) ? op->do_opcode : 0),
                          ((op->do_servact > 0) ? op->do_servact : 0),
                          peri_type, NAME_BUFF_SZ, name_buff);
    printf("  Command_name: %s\n", name_buff);
    switch((int)(rsoc_buff[1] & 7)) {
    case 0:
        cp = "not currently available";
        break;
    case 1:
        cp = "NOT supported";
        break;
    case 3:
        cp = "supported [conforming to SCSI standard]";
        v = 1;
        break;
    case 5:
        cp = "supported [in a vendor specific manner]";
        v = 1;
        break;
    default:
        snprintf(name_buff, NAME_BUFF_SZ, "support reserved [0x%x]",
                 rsoc_buff[1] & 7);
        cp = name_buff;
        break;
    }
    printf("  Command %s\n", cp);
    if (v) {
        printf("  Usage data: ");
        ucp = rsoc_buff + 4;
        for (k = 0; k < cd_len; ++k)
            printf("%.2x ", ucp[k]);
        printf("\n");
    }
    if (0x80 & rsoc_buff[1]) {      /* CTDP */
        ucp = rsoc_buff + 4 + cd_len;
        decode_cmd_to_descriptor(ucp, NAME_BUFF_SZ, name_buff);
        printf("  %s\n", name_buff);
    }
}


int
main(int argc, char * argv[])
{
    int sg_fd, cd_len, res, len;
    unsigned char rsoc_buff[MX_ALLOC_LEN];
    int rep_opts = 0;
    const char * cp;
    char buff[48];
    char b[80];
    struct sg_simple_inquiry_resp inq_resp;
    const char * op_name;
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->do_opcode = -1;
    op->do_servact = -1;
    res = process_cl(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (op->do_help) {
        if (op->opt_new)
            usage();
        else
            usage_old();
        return 0;
    }
    if (op->do_version) {
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == op->device_name) {
        pr2serr("No DEVICE argument given\n");
        if (op->opt_new)
            usage();
        else
            usage_old();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((-1 != op->do_servact) && (-1 == op->do_opcode)) {
        pr2serr("When '-s' is chosen, so must '-o' be chosen\n");
        if (op->opt_new)
            usage();
        else
            usage_old();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_unsorted && op->do_alpha)
        pr2serr("warning: unsorted ('-u') and alpha ('-a') options chosen, "
                "ignoring alpha\n");
    if (op->do_taskman && ((-1 != op->do_opcode) || op->do_alpha ||
        op->do_unsorted)) {
        pr2serr("warning: task management functions ('-t') chosen so alpha "
                "('-a'),\n          unsorted ('-u') and opcode ('-o') "
                "options ignored\n");
    }
    op_name = op->do_taskman ? "Report supported task management functions" :
              "Report supported operation codes";

    if (op->do_opcode < 0) {
        if ((sg_fd = scsi_pt_open_device(op->device_name, 1 /* RO */,
                                         op->do_verbose)) < 0) {
            pr2serr("sg_opcodes: error opening file (ro): %s: %s\n",
                    op->device_name, safe_strerror(-sg_fd));
            return SG_LIB_FILE_ERROR;
        }
        if (0 == sg_simple_inquiry(sg_fd, &inq_resp, 1, op->do_verbose)) {
            peri_type = inq_resp.peripheral_type;
            if (! (op->do_raw || op->no_inquiry)) {
                printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor,
                       inq_resp.product, inq_resp.revision);
                cp = sg_get_pdt_str(peri_type, sizeof(buff), buff);
                if (strlen(cp) > 0)
                    printf("  Peripheral device type: %s\n", cp);
                else
                    printf("  Peripheral device type: 0x%x\n", peri_type);
            }
        } else {
            pr2serr("sg_opcodes: %s doesn't respond to a SCSI INQUIRY\n",
                    op->device_name);
            return SG_LIB_CAT_OTHER;
        }
        res = scsi_pt_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = scsi_pt_open_device(op->device_name, 0 /* RW */,
                                     op->do_verbose)) < 0) {
        pr2serr("sg_opcodes: error opening file (rw): %s: %s\n",
                op->device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (op->do_opcode >= 0)
        rep_opts = ((op->do_servact >= 0) ? 2 : 1);
    memset(rsoc_buff, 0, sizeof(rsoc_buff));
    if (op->do_taskman)
        res = do_rstmf(sg_fd, op->do_repd, rsoc_buff,
                       (op->do_repd ? 16 : 4), 1, op->do_verbose);
    else
        res = do_rsoc(sg_fd, op->do_rctd, rep_opts, op->do_opcode,
                      op->do_servact, rsoc_buff, sizeof(rsoc_buff), 1,
                      op->do_verbose);
    if (res) {
        sg_get_category_sense_str(res, sizeof(b), b, op->do_verbose);
        pr2serr("%s: %s\n", op_name, b);
        goto err_out;
    }
    if (op->do_taskman) {
        if (op->do_raw) {
            dStrRaw((const char *)rsoc_buff, (op->do_repd ? 16 : 4));
            goto err_out;
        }
        printf("\nTask Management Functions supported by device:\n");
        if (op->do_hex) {
            dStrHex((const char *)rsoc_buff, (op->do_repd ? 16 : 4), 1);
            goto err_out;
        }
        if (rsoc_buff[0] & 0x80)
            printf("    Abort task\n");
        if (rsoc_buff[0] & 0x40)
            printf("    Abort task set\n");
        if (rsoc_buff[0] & 0x20)
            printf("    Clear ACA\n");
        if (rsoc_buff[0] & 0x10)
            printf("    Clear task set\n");
        if (rsoc_buff[0] & 0x8)
            printf("    Logical unit reset\n");
        if (rsoc_buff[0] & 0x4)
            printf("    Query task\n");
        if (rsoc_buff[0] & 0x2)
            printf("    Target reset\n");
        if (rsoc_buff[0] & 0x1)
            printf("    Wakeup\n");
        if (rsoc_buff[1] & 0x4)
            printf("    Query asynchronous event\n");
        if (rsoc_buff[1] & 0x2)
            printf("    Query task set\n");
        if (rsoc_buff[1] & 0x1)
            printf("    I_T nexus reset\n");
        if (op->do_repd) {
            if (rsoc_buff[3] < 0xc) {
                pr2serr("when REPD given, byte 3 of response should be >= "
                        "12\n");
                res = SG_LIB_CAT_OTHER;
                goto err_out;
            } else
                printf("  Extended parameter data:\n");
            printf("    TMFTMOV=%d\n", !!(rsoc_buff[4] & 0x1));
            printf("    ATTS=%d\n", !!(rsoc_buff[6] & 0x80));
            printf("    ATSTS=%d\n", !!(rsoc_buff[6] & 0x40));
            printf("    CACATS=%d\n", !!(rsoc_buff[6] & 0x20));
            printf("    CTSTS=%d\n", !!(rsoc_buff[6] & 0x10));
            printf("    LURTS=%d\n", !!(rsoc_buff[6] & 0x8));
            printf("    QTTS=%d\n", !!(rsoc_buff[6] & 0x4));
            printf("    QAETS=%d\n", !!(rsoc_buff[7] & 0x4));
            printf("    QTSTS=%d\n", !!(rsoc_buff[7] & 0x2));
            printf("    ITNRTS=%d\n", !!(rsoc_buff[7] & 0x1));
            printf("    tmf long timeout: %d (100 ms units)\n",
                   sg_get_unaligned_be32(rsoc_buff + 8));
            printf("    tmf short timeout: %d (100 ms units)\n",
                   sg_get_unaligned_be32(rsoc_buff + 12));
        }
    } else if (0 == rep_opts) {  /* list all supported operation codes */
        len = sg_get_unaligned_be32(rsoc_buff + 0) + 4;
        if (len > (int)sizeof(rsoc_buff))
            len = sizeof(rsoc_buff);
        if (op->do_raw) {
            dStrRaw((const char *)rsoc_buff, len);
            goto err_out;
        }
        if (op->do_hex) {
            dStrHex((const char *)rsoc_buff, len, 1);
            goto err_out;
        }
        list_all_codes(rsoc_buff, sizeof(rsoc_buff), op, sg_fd);
    } else {    /* asked about specific command */
        cd_len = sg_get_unaligned_be16(rsoc_buff + 2);
        len = cd_len + 4;
        if (len > (int)sizeof(rsoc_buff))
            len = sizeof(rsoc_buff);
        if (op->do_raw) {
            dStrRaw((const char *)rsoc_buff, len);
            goto err_out;
        }
        if (op->do_hex) {
            dStrHex((const char *)rsoc_buff, len, 1);
            goto err_out;
        }
        list_one(rsoc_buff, cd_len, rep_opts, op);
    }
    res = 0;

err_out:
    scsi_pt_close_device(sg_fd);
    return res;
}

static int
do_rsoc(int sg_fd, int rctd, int rep_opts, int rq_opcode, int rq_servact,
        void * resp, int mx_resp_len, int noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rsocCmdBlk[RSOC_CMD_LEN] = {SG_MAINTENANCE_IN, RSOC_SA, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (rctd)
        rsocCmdBlk[2] |= 0x80;
    if (rep_opts)
        rsocCmdBlk[2] |= (rep_opts & 0x7);
    if (rq_opcode > 0)
        rsocCmdBlk[3] = (rq_opcode & 0xff);
    if (rq_servact > 0)
        sg_put_unaligned_be16((uint16_t)rq_servact, rsocCmdBlk + 4);
    sg_put_unaligned_be32((uint32_t)mx_resp_len, rsocCmdBlk + 6);

    if (verbose) {
        pr2serr("    Report Supported Operation Codes cmd: ");
        for (k = 0; k < RSOC_CMD_LEN; ++k)
            pr2serr("%02x ", rsocCmdBlk[k]);
        pr2serr("\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Report Supported Operation Codes: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rsocCmdBlk, sizeof(rsocCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_TIMEOUT_SECS, verbose);
    ret = sg_cmds_process_resp(ptvp, "Report Supported Operation Codes", res,
                               mx_resp_len, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
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

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static int
do_rstmf(int sg_fd, int repd, void * resp, int mx_resp_len, int noisy,
         int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rstmfCmdBlk[RSTMF_CMD_LEN] = {SG_MAINTENANCE_IN, RSTMF_SA,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (repd)
        rstmfCmdBlk[2] = 0x80;
    sg_put_unaligned_be32((uint32_t)mx_resp_len, rstmfCmdBlk + 6);

    if (verbose) {
        pr2serr("    Report Supported Task Management Functions cmd: ");
        for (k = 0; k < RSTMF_CMD_LEN; ++k)
            pr2serr("%02x ", rstmfCmdBlk[k]);
        pr2serr("\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Report Supported Task Management Functions: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rstmfCmdBlk, sizeof(rstmfCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_TIMEOUT_SECS, verbose);
    ret = sg_cmds_process_resp(ptvp, "Report Supported Task management "
                               "functions", res, mx_resp_len, sense_b, noisy,
                                verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
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

    destruct_scsi_pt_obj(ptvp);
    return ret;
}
