/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 2004-2018 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program outputs information provided by a SCSI REPORT SUPPORTED
 *  OPERATION CODES [0xa3/0xc] and REPORT SUPPORTED TASK MANAGEMENT
 *  FUNCTIONS [0xa3/0xd] commands.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
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

static const char * version_str = "0.54 20180205";    /* spc5r14 */


#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_TIMEOUT_SECS 60

#define SG_MAINTENANCE_IN 0xa3
#define RSOC_SA     0xc
#define RSTMF_SA    0xd
#define RSOC_CMD_LEN 12
#define RSTMF_CMD_LEN 12
#define MX_ALLOC_LEN 8192

#define NAME_BUFF_SZ 128


static int peri_dtype = -1; /* ugly but not easy to pass to alpha compare */

static struct option long_options[] = {
        {"alpha", no_argument, 0, 'a'},
        {"compact", no_argument, 0, 'c'},
        {"enumerate", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"mask", no_argument, 0, 'm'},
        {"no-inquiry", no_argument, 0, 'n'},
        {"no_inquiry", no_argument, 0, 'n'},
        {"new", no_argument, 0, 'N'},
        {"opcode", required_argument, 0, 'o'},
        {"old", no_argument, 0, 'O'},
        {"pdt", required_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"rctd", no_argument, 0, 'R'},
        {"repd", no_argument, 0, 'q'},
        {"sa", required_argument, 0, 's'},
        {"tmf", no_argument, 0, 't'},
        {"unsorted", no_argument, 0, 'u'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    bool do_alpha;
    bool do_compact;
    bool do_enumerate;
    bool no_inquiry;
    bool do_mask;
    bool do_raw;
    bool do_rctd;
    bool do_repd;
    bool do_version;
    bool do_unsorted;
    bool do_taskman;
    bool opt_new;
    int do_help;
    int do_hex;
    int opcode;
    int servact;
    int verbose;
    const char * device_name;
};


static void
usage()
{
    pr2serr("Usage:  sg_opcodes [--alpha] [--compact] [--enumerate] "
            "[--help] [--hex]\n"
            "                   [--mask] [--no-inquiry] [--opcode=OP[,SA]] "
            "[--pdt=DT]\n"
            "                   [--raw] [--rctd] [--repd] [--sa=SA] [--tmf] "
            "[--unsorted]\n"
            "                   [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --alpha|-a      output list of operation codes sorted "
            "alphabetically\n"
            "    --compact|-c    more compact output\n"
            "    --enumerate|-e    use '--opcode=' and '--pdt=' to look up "
            "name,\n"
            "                      ignore DEVICE\n"
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
            "    --pdt=DT|-p DT    give peripheral device type for "
            "'--no-inquiry'\n"
            "                      '--enumerate'\n"
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
            "    --old|-O        use old interface (use as first option)\n"
            "    --version|-V    print version string then exit\n\n"
            "Performs a SCSI REPORT SUPPORTED OPERATION CODES or a REPORT "
            "SUPPORTED\nTASK MANAGEMENT FUNCTIONS command.\n");
}

static void
usage_old()
{
    pr2serr("Usage:  sg_opcodes [-a] [-c] [-e] [-H] [-m] [-n] [-o=OP] "
            "[-p=DT] [-q]\n"
            "                   [-r] [-R] [-s=SA] [-t] [-u] [-v] [-V] "
            "DEVICE\n"
            "  where:\n"
            "    -a    output list of operation codes sorted "
            "alphabetically\n"
            "    -c    more compact output\n"
            "    -e    use '--opcode=' and '--pdt=' to look up name, "
            "ignore DEVICE\n"
            "    -H    print response in hex\n"
            "    -m    and show cdb usage data (a mask) when all listed\n"
            "    -n    don't output INQUIRY information\n"
            "    -o=OP    first byte of command to query (in hex)\n"
            "    -p=DT    alternate source of pdt (normally obtained from "
            "inquiry)\n"
            "    -q    set REPD bit for tmf_s\n"
            "    -r    output response in binary to stdout\n"
            "    -R    set RCTD (return command timeout "
            "descriptor) bit\n"
            "    -s=SA    in addition to opcode (in hex)\n"
            "    -t    output list of supported task management functions\n"
            "    -u    output list of operation codes as is (unsorted)\n"
            "    -v    verbose\n"
            "    -V    output version string\n"
            "    -N|--new   use new interface\n"
            "    -?    output this usage message\n\n"
            "Performs a SCSI REPORT SUPPORTED OPERATION CODES (or a REPORT "
            "TASK MANAGEMENT\nFUNCTIONS) command\n");
}

static const char * const rsoc_s = "Report supported operation codes";

static int
do_rsoc(int sg_fd, bool rctd, int rep_opts, int rq_opcode, int rq_servact,
        void * resp, int mx_resp_len, int * act_resp_lenp, bool noisy,
        int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rsoc_cdb[RSOC_CMD_LEN] = {SG_MAINTENANCE_IN, RSOC_SA, 0,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (rctd)
        rsoc_cdb[2] |= 0x80;
    if (rep_opts)
        rsoc_cdb[2] |= (rep_opts & 0x7);
    if (rq_opcode > 0)
        rsoc_cdb[3] = (rq_opcode & 0xff);
    if (rq_servact > 0)
        sg_put_unaligned_be16((uint16_t)rq_servact, rsoc_cdb + 4);
    if (act_resp_lenp)
        *act_resp_lenp = 0;
    sg_put_unaligned_be32((uint32_t)mx_resp_len, rsoc_cdb + 6);

    if (verbose) {
        pr2serr("    %s cdb: ", rsoc_s);
        for (k = 0; k < RSOC_CMD_LEN; ++k)
            pr2serr("%02x ", rsoc_cdb[k]);
        pr2serr("\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", rsoc_s);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rsoc_cdb, sizeof(rsoc_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_TIMEOUT_SECS, verbose);
    ret = sg_cmds_process_resp(ptvp, rsoc_s, res, mx_resp_len, sense_b, noisy,
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
    } else {
        if (act_resp_lenp)
            *act_resp_lenp = ret;
        if ((verbose > 2) && (ret > 0)) {
            pr2serr("%s response:\n", rsoc_s);
            hex2stderr((const uint8_t *)resp, ret, 1);
        }
        ret = 0;
    }

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static const char * const rstmf_s = "Report supported task management "
                                    "functions";

static int
do_rstmf(int sg_fd, bool repd, void * resp, int mx_resp_len,
         int * act_resp_lenp, bool noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rstmf_cdb[RSTMF_CMD_LEN] = {SG_MAINTENANCE_IN, RSTMF_SA,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (repd)
        rstmf_cdb[2] = 0x80;
    if (act_resp_lenp)
        *act_resp_lenp = 0;
    sg_put_unaligned_be32((uint32_t)mx_resp_len, rstmf_cdb + 6);

    if (verbose) {
        pr2serr("    %s: ", rstmf_s);
        for (k = 0; k < RSTMF_CMD_LEN; ++k)
            pr2serr("%02x ", rstmf_cdb[k]);
        pr2serr("\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", rstmf_s);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rstmf_cdb, sizeof(rstmf_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_TIMEOUT_SECS, verbose);
    ret = sg_cmds_process_resp(ptvp, rstmf_s, res, mx_resp_len, sense_b,
                               noisy, verbose, &sense_cat);
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
    } else {
        if (act_resp_lenp)
            *act_resp_lenp = ret;
        if ((verbose > 2) && (ret > 0)) {
            pr2serr("%s response:\n", rstmf_s);
            hex2stderr((const uint8_t *)resp, ret, 1);
        }
        ret = 0;
    }

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static int
process_cl_new(struct opts_t * op, int argc, char * argv[])
{
    int c, n;
    char * cp;
    char b[32];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "acehHmnNo:Op:qrRs:tuvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            op->do_alpha = true;
            break;
        case 'c':
            op->do_compact = true;
            break;
        case 'e':
            op->do_enumerate = true;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'H':
            ++op->do_hex;
            break;
        case 'm':
            op->do_mask = true;
            break;
        case 'n':
            op->no_inquiry = true;
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
                op->opcode = n;
                n = sg_get_num(cp + 1);
                if ((n < 0) || (n > 0xffff)) {
                    pr2serr("bad SA argument to '--opcode'\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->servact = n;
            } else {
                n = sg_get_num(optarg);
                if ((n < 0) || (n > 255)) {
                    pr2serr("bad argument to '--opcode'\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->opcode = n;
            }
            break;
        case 'O':
            op->opt_new = false;
            return 0;
        case 'p':
            n = -2;
            if (isdigit(optarg[0]))
                n = sg_get_num(optarg);
            else if ((2 == strlen(optarg)) && (0 == strcmp("-1", optarg)))
                n = -1;
            if ((n < -1) || (n > 0x1f)) {
                pr2serr("bad argument to '--pdt=DT', expect -1 to 31\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            peri_dtype = n;
            break;
        case 'q':
            op->do_repd = true;
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'R':
            op->do_rctd = true;
            break;
        case 's':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 0xffff)) {
                pr2serr("bad argument to '--sa'\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->servact = n;
            break;
        case 't':
            op->do_taskman = true;
            break;
        case 'u':
            op->do_unsorted = true;
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            op->do_version = true;
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
process_cl_old(struct opts_t * op, int argc, char * argv[])
{
    bool jmp_out;
    int k, plen, n, num;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'a':
                    op->do_alpha = true;
                    break;
                case 'c':
                    op->do_compact = true;
                    break;
                case 'e':
                    op->do_enumerate = true;
                    break;
                case 'H':
                    ++op->do_hex;
                    break;
                case 'm':
                    op->do_mask = true;
                    break;
                case 'n':
                    op->no_inquiry = true;
                    break;
                case 'N':
                    op->opt_new = true;
                    return 0;
                case 'O':
                    break;
                case 'q':
                    op->do_repd = true;
                    break;
                case 'r':
                    op->do_raw = true;
                    break;
                case 'R':
                    op->do_rctd = true;
                    break;
                case 't':
                    op->do_taskman = true;
                    break;
                case 'u':
                    op->do_unsorted = true;
                    break;
                case 'v':
                    ++op->verbose;
                    break;
                case 'V':
                    op->do_version = true;
                    break;
                case 'h':
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
            if (0 == strncmp("o=", cp, 2)) {
                num = sscanf(cp + 2, "%x", (unsigned int *)&n);
                if ((1 != num) || (n > 255)) {
                    pr2serr("Bad number after 'o=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->opcode = n;
            } else if (0 == strncmp("p=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n > 0x1f) || (n < -1)) {
                    pr2serr("Bad number after 'p=' option, expect -1 to "
                            "31\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                peri_dtype = n;
            } else if (0 == strncmp("s=", cp, 2)) {
                num = sscanf(cp + 2, "%x", (unsigned int *)&n);
                if (1 != num) {
                    pr2serr("Bad number after 's=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->servact = n;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (NULL == op->device_name)
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
process_cl(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = false;
        res = process_cl_old(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = process_cl_new(op, argc, argv);
    } else {
        op->opt_new = true;
        res = process_cl_new(op, argc, argv);
        if ((0 == res) && (! op->opt_new))
            res = process_cl_old(op, argc, argv);
    }
    return res;
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* returns -1 when left < right, 0 when left == right, else returns 1 */
static int
opcode_num_compare(const void * left, const void * right)
{
    int l_serv_act = 0;
    int r_serv_act = 0;
    int l_opc, r_opc;
    const unsigned char * ll = *(unsigned char **)left;
    const unsigned char * rr = *(unsigned char **)right;

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
    sg_get_opcode_sa_name(l_opc, l_serv_act, peri_dtype,
                          NAME_BUFF_SZ, l_name_buff);
    r_opc = rr[0];
    if (rr[5] & 1)
        r_serv_act = sg_get_unaligned_be16(rr + 2);
    r_name_buff[0] = '\0';
    sg_get_opcode_sa_name(r_opc, r_serv_act, peri_dtype,
                          NAME_BUFF_SZ, r_name_buff);
    return strncmp(l_name_buff, r_name_buff, NAME_BUFF_SZ);
}

static void
list_all_codes(unsigned char * rsoc_buff, int rsoc_len, struct opts_t * op,
               int sg_fd)
{
    bool sa_v;
    int k, j, m, cd_len, serv_act, len, act_len, opcode, res;
    unsigned int timeout;
    unsigned char * bp;
    unsigned char ** sort_arr = NULL;
    char name_buff[NAME_BUFF_SZ];
    char sa_buff[8];

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
    if (op->do_rctd) {  /* Return command timeout descriptor */
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
    } else {            /* RCTD clear in cdb */
        if (op->do_compact) {
            printf("\nOpcode,sa  Name\n");
            printf(  "  (hex)        \n");
            printf("---------------------------------------\n");
        } else {
            printf("\nOpcode  Service    CDB    CDLP   Name\n");
            printf(  "(hex)   action(h)  size              \n");
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
        bp = rsoc_buff + 4;
        for (k = 0, j = 0; k < cd_len; ++j, k += len, bp += len) {
            sort_arr[j] = bp;
            len = (bp[5] & 0x2) ? 20 : 8;
        }
        qsort(sort_arr, j, sizeof(unsigned char *),
              (op->do_alpha ? opcode_alpha_compare : opcode_num_compare));
    }
    for (k = 0, j = 0; k < cd_len; ++j, k += len) {
        bp = op->do_unsorted ? (rsoc_buff + 4 + k) : sort_arr[j];
        len = (bp[5] & 0x2) ? 20 : 8;
        opcode = bp[0];
        sa_v = !!(bp[5] & 1);
        serv_act = 0;
        if (sa_v) {
            serv_act = sg_get_unaligned_be16(bp + 2);
            sg_get_opcode_sa_name(opcode, serv_act, peri_dtype, NAME_BUFF_SZ,
                                  name_buff);
            if (op->do_compact)
                snprintf(sa_buff, sizeof(sa_buff), "%-4x", serv_act);
            else
                snprintf(sa_buff, sizeof(sa_buff), "%4x", serv_act);
        } else {
            sg_get_opcode_name(opcode, peri_dtype, NAME_BUFF_SZ, name_buff);
            memset(sa_buff, ' ', sizeof(sa_buff));
        }
        if (op->do_rctd) {
            if (bp[5] & 0x2) {          /* CTDP set */
                /* don't show CDLP because it makes line too long */
                if (op->do_compact)
                    printf(" %.2x%c%.4s", opcode, (sa_v ? ',' : ' '),
                           sa_buff);
                else
                    printf(" %.2x     %.4s       %3d", opcode, sa_buff,
                           sg_get_unaligned_be16(bp + 6));
                timeout = sg_get_unaligned_be32(bp + 12);
                if (0 == timeout)
                    printf("         -");
                else
                    printf("  %8u", timeout);
                timeout = sg_get_unaligned_be32(bp + 16);
                if (0 == timeout)
                    printf("          -");
                else
                    printf("   %8u", timeout);
                printf("    %s\n", name_buff);
            } else                      /* CTDP clear */
                if (op->do_compact)
                    printf(" %.2x%c%.4s                        %s\n", opcode,
                           (sa_v ? ',' : ' '), sa_buff, name_buff);
                else
                    printf(" %.2x     %.4s       %3d                         "
                           "%s\n", opcode, sa_buff,
                           sg_get_unaligned_be16(bp + 6), name_buff);
        } else {                        /* RCTD clear in cdb */
            if (op->do_compact)
                printf(" %.2x%c%.4s   %s\n", bp[0], (sa_v ? ',' : ' '),
                       sa_buff, name_buff);
            else
                printf(" %.2x     %.4s       %3d     %2d    %s\n", bp[0],
                       sa_buff, sg_get_unaligned_be16(bp + 6),
                       (*(bp + 5) >> 2) & 0x3, name_buff);
        }
        if (op->do_mask) {
            int cdb_sz;
            unsigned char b[64];

            memset(b, 0, sizeof(b));
            res = do_rsoc(sg_fd, false, (sa_v ? 2 : 1), opcode, serv_act,
                          b, sizeof(b), &act_len, true, op->verbose);
            if (0 == res) {
                cdb_sz = sg_get_unaligned_be16(b + 2);
                cdb_sz = (cdb_sz < act_len) ? cdb_sz : act_len;
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
decode_cmd_timeout_desc(unsigned char * dp, int max_b_len, char * b)
{
    int len;
    unsigned int timeout;

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
    timeout = sg_get_unaligned_be32(dp + 4);
    if (0 == timeout)
        snprintf(b, max_b_len, "no nominal timeout, ");
    else
        snprintf(b, max_b_len, "nominal timeout: %u secs, ", timeout);
    len = strlen(b);
    max_b_len -= len;
    b += len;
    timeout = sg_get_unaligned_be32(dp + 8);
    if (0 == timeout)
        snprintf(b, max_b_len, "no recommended timeout");
    else
        snprintf(b, max_b_len, "recommended timeout: %u secs", timeout);
    return;
}

/* One command descriptor (includes cdb usage data) */
static void
list_one(unsigned char * rsoc_buff, int cd_len, int rep_opts,
         struct opts_t * op)
{
    bool valid = false;
    int k;
    unsigned char * bp;
    const char * cp;
    const char * dlp;
    char name_buff[NAME_BUFF_SZ];


    printf("\n  Opcode=0x%.2x", op->opcode);
    if (rep_opts > 1)
        printf("  Service_action=0x%.4x", op->servact);
    printf("\n");
    sg_get_opcode_sa_name(((op->opcode > 0) ? op->opcode : 0),
                          ((op->servact > 0) ? op->servact : 0),
                          peri_dtype, NAME_BUFF_SZ, name_buff);
    printf("  Command_name: %s\n", name_buff);
    switch((int)(rsoc_buff[1] & 7)) {   /* SUPPORT field */
    case 0:
        cp = "not currently available";
        break;
    case 1:
        cp = "NOT supported";
        break;
    case 3:
        cp = "supported [conforming to SCSI standard]";
        valid = true;
        break;
    case 5:
        cp = "supported [in a vendor specific manner]";
        valid = true;
        break;
    default:
        snprintf(name_buff, NAME_BUFF_SZ, "support reserved [0x%x]",
                 rsoc_buff[1] & 7);
        cp = name_buff;
        break;
    }
    k = 0x3 & (rsoc_buff[1] >> 3);
    switch (k) {        /* CDLP field */
    case 0:
        dlp = "no command duration limit mode page";
        break;
    case 1:
        dlp = "command duration limit A mode page";
        break;
    case 2:
        dlp = "command duration limit B mode page";
        break;
    default:
        dlp = "reserved [CDLP=3]";
        break;
    }
    printf("  Command %s, [%s]\n", cp, dlp);
    if (valid) {
        printf("  Usage data: ");
        bp = rsoc_buff + 4;
        for (k = 0; k < cd_len; ++k)
            printf("%.2x ", bp[k]);
        printf("\n");
    }
    if (0x80 & rsoc_buff[1]) {      /* CTDP */
        bp = rsoc_buff + 4 + cd_len;
        decode_cmd_timeout_desc(bp, NAME_BUFF_SZ, name_buff);
        printf("  %s\n", name_buff);
    }
}


int
main(int argc, char * argv[])
{
    int sg_fd, cd_len, res, len, act_len, rq_len;
    int rep_opts = 0;
    const char * cp;
    struct opts_t * op;
    const char * op_name;
    unsigned char rsoc_buff[MX_ALLOC_LEN];
    char buff[48];
    char b[80];
    struct sg_simple_inquiry_resp inq_resp;
    struct opts_t opts;

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->opcode = -1;
    op->servact = -1;
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

    if ((NULL == op->device_name) && (! op->do_enumerate)) {
        pr2serr("No DEVICE argument given\n");
        if (op->opt_new)
            usage();
        else
            usage_old();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((-1 != op->servact) && (-1 == op->opcode)) {
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
    if (op->do_taskman && ((-1 != op->opcode) || op->do_alpha ||
        op->do_unsorted)) {
        pr2serr("warning: task management functions ('-t') chosen so alpha "
                "('-a'),\n          unsorted ('-u') and opcode ('-o') "
                "options ignored\n");
    }
    if (op->do_enumerate) {
        char name_buff[NAME_BUFF_SZ];

        if (op->do_taskman)
            printf("enumerate not supported with task management "
                   "functions\n");
        else {  /* SCSI command */
            if (op->opcode < 0)
                op->opcode = 0;
            if (op->servact < 0)
                op->servact = 0;
            if (peri_dtype < 0)
                peri_dtype = 0;
            printf("SCSI command:");
            if (op->verbose)
                printf(" [opcode=0x%x, sa=0x%x, pdt=0x%x]\n", op->opcode,
                       op->servact, peri_dtype);
            else
                printf("\n");
            sg_get_opcode_sa_name(op->opcode, op->servact, peri_dtype,
                                  NAME_BUFF_SZ, name_buff);
            printf("  %s\n", name_buff);
        }
        return 0;
    }
    op_name = op->do_taskman ? "Report supported task management functions" :
              "Report supported operation codes";

    if (op->opcode < 0) {
        if ((sg_fd = scsi_pt_open_device(op->device_name, 1 /* RO */,
                                         op->verbose)) < 0) {
            pr2serr("sg_opcodes: error opening file (ro): %s: %s\n",
                    op->device_name, safe_strerror(-sg_fd));
            return SG_LIB_FILE_ERROR;
        }
        if (op->no_inquiry && (peri_dtype < 0))
            pr2serr("--no-inquiry ignored because --pdt= not given\n");
        if (op->no_inquiry && (peri_dtype >= 0))
            ;
        else if (0 == sg_simple_inquiry(sg_fd, &inq_resp, 1, op->verbose)) {
            peri_dtype = inq_resp.peripheral_type;
            if (! (op->do_raw || op->no_inquiry)) {
                printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor,
                       inq_resp.product, inq_resp.revision);
                cp = sg_get_pdt_str(peri_dtype, sizeof(buff), buff);
                if (strlen(cp) > 0)
                    printf("  Peripheral device type: %s\n", cp);
                else
                    printf("  Peripheral device type: 0x%x\n", peri_dtype);
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
                                     op->verbose)) < 0) {
        pr2serr("sg_opcodes: error opening file (rw): %s: %s\n",
                op->device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (op->opcode >= 0)
        rep_opts = ((op->servact >= 0) ? 2 : 1);
    memset(rsoc_buff, 0, sizeof(rsoc_buff));
    if (op->do_taskman) {
        rq_len = (op->do_repd ? 16 : 4);
        res = do_rstmf(sg_fd, op->do_repd, rsoc_buff,
                       rq_len, &act_len, true, op->verbose);
    } else {
        rq_len = sizeof(rsoc_buff);
        res = do_rsoc(sg_fd, op->do_rctd, rep_opts, op->opcode, op->servact,
                      rsoc_buff, rq_len, &act_len, true, op->verbose);
    }
    if (res) {
        sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
        pr2serr("%s: %s\n", op_name, b);
        goto err_out;
    }
    act_len = (rq_len < act_len) ? rq_len : act_len;
    if (op->do_taskman) {
        if (op->do_raw) {
            dStrRaw((const char *)rsoc_buff, act_len);
            goto err_out;
        }
        printf("\nTask Management Functions supported by device:\n");
        if (op->do_hex) {
            hex2stdout(rsoc_buff, act_len, 1);
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
            printf("    Target reset (obsolete)\n");
        if (rsoc_buff[0] & 0x1)
            printf("    Wakeup (obsolete)\n");
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
            printf("    tmf long timeout: %u (100 ms units)\n",
                   sg_get_unaligned_be32(rsoc_buff + 8));
            printf("    tmf short timeout: %u (100 ms units)\n",
                   sg_get_unaligned_be32(rsoc_buff + 12));
        }
    } else if (0 == rep_opts) {  /* list all supported operation codes */
        len = sg_get_unaligned_be32(rsoc_buff + 0) + 4;
        len = (len < act_len) ? len : act_len;
        if (op->do_raw) {
            dStrRaw((const char *)rsoc_buff, len);
            goto err_out;
        }
        if (op->do_hex) {
            hex2stdout(rsoc_buff, len, 1);
            goto err_out;
        }
        list_all_codes(rsoc_buff, len, op, sg_fd);
    } else {    /* asked about specific command */
        cd_len = sg_get_unaligned_be16(rsoc_buff + 2);
        len = cd_len + 4;
        len = (len < act_len) ? len : act_len;
        cd_len = (cd_len < act_len) ? cd_len : act_len;
        if (op->do_raw) {
            dStrRaw((const char *)rsoc_buff, len);
            goto err_out;
        }
        if (op->do_hex) {
            hex2stdout(rsoc_buff, len, 1);
            goto err_out;
        }
        list_one(rsoc_buff, cd_len, rep_opts, op);
    }
    res = 0;

err_out:
    scsi_pt_close_device(sg_fd);
    return res;
}
