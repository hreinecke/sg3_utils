/* A utility program originally written for the Linux OS SCSI subsystem.
*  Copyright (C) 2000-2013 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI LOG SENSE command.

*/

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

static char * version_str = "1.08 20130228";    /* spc4r35 + sbc3r30 */

#define MX_ALLOC_LEN (0xfffc)
#define SHORT_RESP_LEN 128

#define SUPP_PAGES_LPAGE 0x0
#define BUFF_OVER_UNDER_LPAGE 0x1
#define WRITE_ERR_LPAGE 0x2
#define READ_ERR_LPAGE 0x3
#define READ_REV_ERR_LPAGE 0x4
#define VERIFY_ERR_LPAGE 0x5
#define NON_MEDIUM_LPAGE 0x6
#define LAST_N_ERR_LPAGE 0x7
#define FORMAT_STATUS_LPAGE 0x8
#define LAST_N_DEFERRED_LPAGE 0xb
#define LB_PROV_LPAGE 0xc
#define TEMPERATURE_LPAGE 0xd
#define START_STOP_LPAGE 0xe
#define APP_CLIENT_LPAGE 0xf
#define SELF_TEST_LPAGE 0x10
#define SOLID_STATE_MEDIA_LPAGE 0x11
#define SAT_ATA_RESULTS_LPAGE 0x16
#define PROTO_SPECIFIC_LPAGE 0x18
#define STATS_LPAGE 0x19
#define PCT_LPAGE 0x1a
#define TAPE_ALERT_LPAGE 0x2e
#define IE_LPAGE 0x2f
#define NOT_SPG_SUBPG 0x0
#define SUPP_SPGS_SUBPG 0xff
#define LOW_GRP_STATS_SUBPG 0x1
#define HIGH_GRP_STATS_SUBPG 0x1f
#define CACHE_STATS_SUBPG 0x20

#define PCB_STR_LEN 128

#define LOG_SENSE_PROBE_ALLOC_LEN 4

static unsigned char rsp_buff[MX_ALLOC_LEN + 4];

static struct option long_options[] = {
        {"all", no_argument, 0, 'a'},
        {"brief", no_argument, 0, 'b'},
        {"control", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"list", no_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"name", no_argument, 0, 'n'},
        {"new", no_argument, 0, 'N'},
        {"old", no_argument, 0, 'O'},
        {"page", required_argument, 0, 'p'},
        {"paramp", required_argument, 0, 'P'},
        {"pcb", no_argument, 0, 'q'},
        {"ppc", no_argument, 0, 'Q'},
        {"raw", no_argument, 0, 'r'},
        {"reset", no_argument, 0, 'R'},
        {"sp", no_argument, 0, 's'},
        {"select", no_argument, 0, 'S'},
        {"temperature", no_argument, 0, 't'},
        {"transport", no_argument, 0, 'T'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_all;
    int do_brief;
    int do_help;
    int do_hex;
    int do_list;
    int do_name;
    int do_pcb;
    int do_ppc;
    int do_raw;
    int do_pcreset;
    int do_select;
    int do_sp;
    int do_temperature;
    int do_transport;
    int do_verbose;
    int do_version;
    int page_control;
    int maxlen;
    int pg_code;
    int subpg_code;
    int paramp;
    const char * device_name;
    int opt_new;
};

static void
usage()
{
    printf("Usage: sg_logs [--all] [--brief] [--control=PC] [--help] [--hex] "
           "[--list]\n"
           "               [--maxlen=LEN] [--name] [--page=PG[,SPG]] "
           "[--paramp=PP] [--pcb]\n"
           "               [--ppc] [--raw] [--reset] [--select] [--sp] "
           "[--temperature]\n"
           "               [--transport] [--verbose] [--version] DEVICE\n"
           "  where:\n"
           "    --all|-a        fetch and decode all log pages\n"
           "                    use twice to fetch and decode all log pages "
           "and subpages\n"
           "    --brief|-b      shorten the output of some log pages\n"
           "    --control=PC|-c PC    page control(PC) (default: 1)\n"
           "                          0: current threshhold, 1: current "
           "cumulative\n"
           "                          2: default threshhold, 3: default "
           "cumulative\n"
           "    --help|-h       print usage message then exit\n"
           "    --hex|-H        output response in hex (default: decode if "
           "known)\n"
           "    --list|-l       list supported log page names (equivalent to "
           "'-p 0')\n"
           "                    use twice to list supported log page and "
           "subpage names\n"
           "    --maxlen=LEN|-m LEN    max response length (def: 0 "
           "-> everything)\n"
           "                           when > 1 will request LEN bytes\n"
           "    --name|-n       decode some pages into multiple name=value "
           "lines\n"
           "    --page=PG|-p PG    page code (in decimal)\n"
           "    --page=PG,SPG|-p PG,SPG\n"
           "                    page code plus subpage code (both default "
           "to 0)\n"
           "    --paramp=PP|-P PP    parameter pointer (decimal) (def: 0)\n"
           "    --pcb|-q        show parameter control bytes in decoded "
           "output\n");
    printf("    --ppc|-Q        set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
           "                    the PPC bit made obsolete in SPC-4 rev 18\n"
           "    --raw|-r        output response in binary to stdout\n"
           "    --reset|-R      reset log parameters (takes PC and SP into "
           "account)\n"
           "                    (uses PCR bit in LOG SELECT)\n"
           "    --select|-S     perform LOG SELECT using SP and PC values\n"
           "    --sp|-s         set the Saving Parameters (SP) bit (def: 0)\n"
           "    --temperature|-t    decode temperature (log page 0xd or "
           "0x2f)\n"
           "    --transport|-T    decode transport (protocol specific port "
           "0x18) log page\n"
           "    --verbose|-v    increase verbosity\n"
           "    --version|-V    output version string then exit\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command\n");
}

static void
usage_old()
{
    printf("Usage:  sg_logs [-a] [-A] [-b] [-c=PC] [-h] [-H] [-l] [-L] "
           "[-m=LEN] [-n]\n"
           "                [-p=PG[,SPG]] [-paramp=PP] [-pcb] [-ppc] "
           "[-r] [-select]\n"
           "                [-sp] [-t] [-T] [-v] [-V] [-?] DEVICE\n"
           "  where:\n"
           "    -a     fetch and decode all log pages\n"
           "    -A     fetch and decode all log pages and subpages\n"
           "    -b     shorten the output of some log pages\n"
           "    -c=PC  page control(PC) (default: 1)\n"
           "                  0: current threshhold, 1: current cumulative\n"
           "                  2: default threshhold, 3: default cumulative\n"
           "    -h     output in hex (default: decode if known)\n"
           "    -H     output in hex (same as '-h')\n"
           "    -l     list supported log page names (equivalent to "
           "'-p=0')\n"
           "    -L     list supported log page and subpages names "
           "(equivalent to\n"
           "           '-p=0,ff')\n"
           "    -m=LEN   max response length (decimal) (def: 0 "
           "-> everything)\n"
           "    -n       decode some pages into multiple name=value "
           "lines\n"
           "    -p=PG    page code in hex (def: 0)\n"
           "    -p=PG,SPG    both in hex, (defs: 0,0)\n"
           "    -paramp=PP   (in hex) (def: 0)\n"
           "    -pcb   show parameter control bytes in decoded "
           "output\n");
    printf("    -ppc   set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
           "    -r     reset log parameters (takes PC and SP into "
           "account)\n"
           "           (uses PCR bit in LOG SELECT)\n"
           "    -select  perform LOG SELECT using SP and PC values\n"
           "    -sp    set the Saving Parameters (SP) bit (def: 0)\n"
           "    -t     outputs temperature log page (0xd)\n"
           "    -T     outputs transport (protocol specific port) log "
           "page (0x18)\n"
           "    -v     increase verbosity\n"
           "    -V     output version string\n"
           "    -?     output this usage message\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command\n");
}

static void
usage_for(const struct opts_t * optsp)
{
    if (optsp->opt_new)
        usage();
    else
        usage_old();
}

/* Processes command line options according to new option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
process_cl_new(struct opts_t * optsp, int argc, char * argv[])
{
    int c, n, nn;
    char * cp;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aAbc:hHlLm:nNOp:P:qQrRsStTvV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ++optsp->do_all;
            break;
        case 'A':
            optsp->do_all += 2;
            break;
        case 'b':
            ++optsp->do_brief;
            break;
        case 'c':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 3)) {
                fprintf(stderr, "bad argument to '--control='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->page_control = n;
            break;
        case 'h':
        case '?':
            ++optsp->do_help;
            break;
        case 'H':
            ++optsp->do_hex;
            break;
        case 'l':
            ++optsp->do_list;
            break;
        case 'L':
            optsp->do_list += 2;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (1 == n) || (n > 0xffff)) {
                fprintf(stderr, "bad argument to '--maxlen=', from 2 to "
                        "65535 (inclusive) expected\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->maxlen = n;
            break;
        case 'n':
            ++optsp->do_name;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            optsp->opt_new = 0;
            return 0;
        case 'p':
            cp = strchr(optarg, ',');
            n = sg_get_num_nomult(optarg);
            if ((n < 0) || (n > 63)) {
                fprintf(stderr, "Bad argument to '--page='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            if (cp) {
                nn = sg_get_num_nomult(cp + 1);
                if ((nn < 0) || (nn > 255)) {
                    fprintf(stderr, "Bad second value in argument to "
                            "'--page='\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else
                nn = 0;
            optsp->pg_code = n;
            optsp->subpg_code = nn;
            break;
        case 'P':
            n = sg_get_num(optarg);
            if (n < 0) {
                fprintf(stderr, "bad argument to '--paramp='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->paramp = n;
            break;
        case 'q':
            ++optsp->do_pcb;
            break;
        case 'Q':       /* N.B. PPC bit obsoleted in SPC-4 rev 18 */
            ++optsp->do_ppc;
            break;
        case 'r':
            ++optsp->do_raw;
            break;
        case 'R':
            ++optsp->do_pcreset;
            ++optsp->do_select;
            break;
        case 's':
            ++optsp->do_sp;
            break;
        case 'S':
            ++optsp->do_select;
            break;
        case 't':
            ++optsp->do_temperature;
            break;
        case 'T':
            ++optsp->do_transport;
            break;
        case 'v':
            ++optsp->do_verbose;
            break;
        case 'V':
            ++optsp->do_version;
            break;
        default:
            fprintf(stderr, "unrecognised option code %c [0x%x]\n", c, c);
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
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Processes command line options according to old option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
process_cl_old(struct opts_t * optsp, int argc, char * argv[])
{
    int k, jmp_out, plen, num, n;
    unsigned int u, uu;
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
                    ++optsp->do_all;
                    break;
                case 'A':
                    optsp->do_all += 2;
                    break;
                case 'b':
                    ++optsp->do_brief;
                    break;
                case 'h':
                case 'H':
                    ++optsp->do_hex;
                    break;
                case 'l':
                    ++optsp->do_list;
                    break;
                case 'L':
                    optsp->do_list += 2;
                    break;
                case 'n':
                    ++optsp->do_name;
                    break;
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'r':
                    optsp->do_pcreset = 1;
                    optsp->do_select = 1;
                    break;
                case 't':
                    ++optsp->do_temperature;
                    break;
                case 'T':
                    ++optsp->do_transport;
                    break;
                case 'v':
                    ++optsp->do_verbose;
                    break;
                case 'V':
                    ++optsp->do_version;
                    break;
                case '?':
                    ++optsp->do_help;
                    break;
                case '-':
                    ++cp;
                    jmp_out = 1;
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
            if (0 == strncmp("c=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 3)) {
                    printf("Bad page control after '-c=' option [0..3]\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->page_control = u;
            } else if (0 == strncmp("m=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 0) || (n > MX_ALLOC_LEN)) {
                    printf("Bad maximum response length after '-m=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->maxlen = n;
            } else if (0 == strncmp("p=", cp, 2)) {
                if (NULL == strchr(cp + 2, ',')) {
                    num = sscanf(cp + 2, "%x", &u);
                    if ((1 != num) || (u > 63)) {
                        fprintf(stderr, "Bad page code value after '-p=' "
                                "option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    optsp->pg_code = u;
                } else if (2 == sscanf(cp + 2, "%x,%x", &u, &uu)) {
                    if (uu > 255) {
                        fprintf(stderr, "Bad sub page code value after '-p=' "
                                "option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    optsp->pg_code = u;
                    optsp->subpg_code = uu;
                } else {
                    fprintf(stderr, "Bad page code, subpage code sequence "
                            "after '-p=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else if (0 == strncmp("paramp=", cp, 7)) {
                num = sscanf(cp + 7, "%x", &u);
                if ((1 != num) || (u > 0xffff)) {
                    printf("Bad parameter pointer after '-paramp=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->paramp = u;
            } else if (0 == strncmp("pcb", cp, 3))
                optsp->do_pcb = 1;
            else if (0 == strncmp("ppc", cp, 3))
                optsp->do_ppc = 1;
            else if (0 == strncmp("select", cp, 6))
                optsp->do_select = 1;
            else if (0 == strncmp("sp", cp, 2))
                optsp->do_sp = 1;
            else if (0 == strncmp("old", cp, 3))
                ;
            else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == optsp->device_name)
            optsp->device_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", optsp->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Process command line options. First check using new option format unless
 * the SG3_UTILS_OLD_OPTS environment variable is defined which causes the
 * old option format to be checked first. Both new and old format can be
 * countermanded by a '-O' and '-N' options respectively. As soon as either
 * of these options is detected (when processing the other format), processing
 * stops and is restarted using the other format. Clear? */
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

/* Call LOG SENSE twice: the first time ask for 4 byte response to determine
   actual length of response; then a second time requesting the
   min(actual_len, mx_resp_len) bytes. If the calculated length for the
   second fetch is odd then it is incremented (perhaps should be made modulo
   4 in the future for SAS). Returns 0 if ok, SG_LIB_CAT_INVALID_OP for
   log_sense not supported, SG_LIB_CAT_ILLEGAL_REQ for bad field in log sense
   command, SG_LIB_CAT_NOT_READY, SG_LIB_CAT_UNIT_ATTENTION,
   SG_LIB_CAT_ABORTED_COMMAND and -1 for other errors. */
static int
do_logs(int sg_fd, unsigned char * resp, int mx_resp_len,
        const struct opts_t * optsp)
{
    int actual_len, res, vb;

    memset(resp, 0, mx_resp_len);
    vb = optsp->do_verbose;
    if (optsp->maxlen > 1)
        actual_len = mx_resp_len;
    else {
        if ((res = sg_ll_log_sense(sg_fd, optsp->do_ppc, optsp->do_sp,
                                   optsp->page_control, optsp->pg_code,
                                   optsp->subpg_code, optsp->paramp,
                                   resp, LOG_SENSE_PROBE_ALLOC_LEN,
                                   1 /* noisy */, vb))) {
            switch (res) {
            case SG_LIB_CAT_NOT_READY:
            case SG_LIB_CAT_INVALID_OP:
            case SG_LIB_CAT_ILLEGAL_REQ:
            case SG_LIB_CAT_UNIT_ATTENTION:
            case SG_LIB_CAT_ABORTED_COMMAND:
                return res;
            default:
                return -1;
            }
        }
        actual_len = (resp[2] << 8) + resp[3] + 4;
        if ((0 == optsp->do_raw) && (vb > 1)) {
            fprintf(stderr, "  Log sense (find length) response:\n");
            dStrHex((const char *)resp, LOG_SENSE_PROBE_ALLOC_LEN, 1);
            fprintf(stderr, "  hence calculated response length=%d\n",
                    actual_len);
        }
        if (optsp->pg_code != (0x3f & resp[0])) {
            if (vb)
                fprintf(stderr, "Page code does not appear in first byte "
                        "of response so it's suspect\n");
            if (actual_len > 0x40) {
                actual_len = 0x40;
                if (vb)
                    fprintf(stderr, "Trim response length to 64 bytes due "
                            "to suspect response format\n");
            }
        }
        /* Some HBAs don't like odd transfer lengths */
        if (actual_len % 2)
            actual_len += 1;
        if (actual_len > mx_resp_len)
            actual_len = mx_resp_len;
    }
    if ((res = sg_ll_log_sense(sg_fd, optsp->do_ppc, optsp->do_sp,
                               optsp->page_control, optsp->pg_code,
                               optsp->subpg_code, optsp->paramp,
                               resp, actual_len, 1 /* noisy */, vb))) {
        switch (res) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            return res;
        default:
            return -1;
        }
    }
    if ((0 == optsp->do_raw) && (vb > 1)) {
        fprintf(stderr, "  Log sense response:\n");
        dStrHex((const char *)resp, actual_len, 1);
    }
    return 0;
}

static void
show_page_name(int pg_code, int subpg_code,
               struct sg_simple_inquiry_resp * inq_dat)
{
    int done;
    char b[64];

    memset(b, 0, sizeof(b));
    /* first process log pages that do not depend on peripheral type */
    if (NOT_SPG_SUBPG == subpg_code)
        snprintf(b, sizeof(b) - 1, "    0x%02x        ", pg_code);
    else
        snprintf(b, sizeof(b) - 1, "    0x%02x,0x%02x   ", pg_code,
                 subpg_code);
    done = 1;
    if ((NOT_SPG_SUBPG == subpg_code) || (SUPP_SPGS_SUBPG == subpg_code)) {
        switch (pg_code) {
        case SUPP_PAGES_LPAGE: printf("%sSupported log pages", b); break;
        case BUFF_OVER_UNDER_LPAGE:
            printf("%sBuffer over-run/under-run", b);
            break;
        case WRITE_ERR_LPAGE: printf("%sError counters (write)", b); break;
        case READ_ERR_LPAGE: printf("%sError counters (read)", b); break;
        case READ_REV_ERR_LPAGE:
             printf("%sError counters (read reverse)", b);
             break;
        case VERIFY_ERR_LPAGE: printf("%sError counters (verify)", b); break;
        case NON_MEDIUM_LPAGE: printf("%sNon-medium errors", b); break;
        case LAST_N_ERR_LPAGE: printf("%sLast n error events", b); break;
        case LAST_N_DEFERRED_LPAGE: printf("%sLast n deferred errors or "
                         "asynchronous events", b); break;
        case TEMPERATURE_LPAGE: printf("%sTemperature", b); break;
        case START_STOP_LPAGE: printf("%sStart-stop cycle counter", b); break;
        case APP_CLIENT_LPAGE: printf("%sApplication client", b); break;
        case SELF_TEST_LPAGE: printf("%sSelf-test results", b); break;
        case PROTO_SPECIFIC_LPAGE:
            printf("%sProtocol specific port", b);
            break;
        case STATS_LPAGE:
            printf("%sGeneral statistics and performance", b);
            break;
        case PCT_LPAGE:
            printf("%sPower condition transition", b);
            break;
        case IE_LPAGE:
            printf("%sInformational exceptions (SMART)", b);
            break;
        default:
            done = 0;
            break;
        }
        if (done) {
            if (SUPP_SPGS_SUBPG == subpg_code)
                printf(" and subpages\n");
            else
                printf("\n");
            return;
        }
    }

    /* There are not many log subpages currently */
    if (STATS_LPAGE == pg_code) {
        if ((subpg_code >= LOW_GRP_STATS_SUBPG) &&
            (subpg_code <= HIGH_GRP_STATS_SUBPG)) {
            printf("%sGroup statistics and performance (%d)\n", b, subpg_code);
            return;
        } else if (subpg_code == CACHE_STATS_SUBPG) {
            printf("%sCache memory statistics\n", b);
            return;
        }
    }
    if (subpg_code > 0) {
        printf("%s??\n", b);
        return;
    }

    done = 1;
    switch (inq_dat->peripheral_type) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_RBC:
        /* disk (direct access) type devices */
        {
            switch (pg_code) {
            case FORMAT_STATUS_LPAGE:
                printf("%sFormat status (sbc-2)\n", b);
                break;
            case LB_PROV_LPAGE:                 /* 0xc */
                printf("%sLogical block provisioning (sbc-3)\n", b);
                break;
            case 0x15:
                printf("%sBackground scan results (sbc-3)\n", b);
                break;
            case SOLID_STATE_MEDIA_LPAGE:       /* 0x11 */
                printf("%sSolid state media (sbc-3)\n", b);
                break;
            case SAT_ATA_RESULTS_LPAGE:
                printf("%sATA pass-through results (sat-2)\n", b);
                break;
            case 0x17:
                printf("%sNon-volatile cache (sbc-2)\n", b);
                break;
            case 0x30:
                printf("%sPerformance counters (Hitachi)\n", b);
                break;
            case 0x37:
                printf("%sCache (Seagate), Miscellaneous (Hitachi)\n", b);
                break;
            case 0x3e:
                printf("%sFactory (Seagate/Hitachi)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case PDT_TAPE: case PDT_PRINTER:
        /* tape (streaming) and printer (obsolete) devices */
        {
            switch (pg_code) {
            case 0xc:
                printf("%sSequential access device (ssc-2)\n", b);
                break;
            case 0x11:
                printf("%sDT Device status (ssc-3)\n", b);
                break;
            case 0x12:
                printf("%sTape alert response (ssc-3)\n", b);
                break;
            case 0x13:
                printf("%sRequested recovery (ssc-3)\n", b);
                break;
            case 0x14:
                printf("%sDevice statistics (ssc-3)\n", b);
                break;
            case 0x16:
                printf("%sTape diagnostic (ssc-3)\n", b);
                done = 0;
                break;
            case 0x17:
                printf("%sVolume statistics (ssc-4)\n", b);
                done = 0;
                break;
            case 0x2d:
                printf("%sCurrent service information (ssc-3)\n", b);
                break;
            case TAPE_ALERT_LPAGE:
                printf("%sTapeAlert (ssc-2)\n", b);
                break;
            case 0x30:
                printf("%sTape usage log (IBM specific)\n", b);
                break;
            case 0x31:
                printf("%sTape capacity log (IBM specific)\n", b);
                break;
            case 0x32:
                printf("%sData compression log (IBM specific)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case PDT_MCHANGER:
        /* medium changer type devices */
        {
            switch (pg_code) {
            case 0x14:
                printf("%sMedia changer statistics (smc-3)\n", b);
                break;
            case 0x15:
                printf("%sElement statistics (smc-3)\n", b);
                break;
            case 0x16:
                printf("%sMedia changer diagnostic data (smc-3)\n", b);
                break;
            case 0x2e:
                printf("%sTapeAlert (smc-3)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case PDT_ADC: /* Automation Device interface (ADC) */
        {
            switch (pg_code) {
            case 0x11:
                printf("%sDT Device status (adc)\n", b);
                break;
            case 0x12:
                printf("%sTape alert response (adc)\n", b);
                break;
            case 0x13:
                printf("%sRequested recovery (adc)\n", b);
                break;
            case 0x14:
                printf("%sDevice statistics (adc)\n", b);
                break;
            case 0x15:
                printf("%sService buffers information (adc)\n", b);
                done = 0;
                break;
            case 0x16:
                printf("%sTape diagnostic (adc)\n", b);
                done = 0;
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    default:
        done = 0;
        break;
    }
    if (done)
        return;
    if (pg_code >= 0x30)
        printf("%s[unknown vendor specific page code]\n", b);
    else
        printf("%s??\n", b);
}

static void
get_pcb_str(int pcb, char * outp, int maxoutlen)
{
    char buff[PCB_STR_LEN];
    int n;

    n = sprintf(buff, "du=%d [ds=%d] tsd=%d etc=%d ", ((pcb & 0x80) ? 1 : 0),
                ((pcb & 0x40) ? 1 : 0), ((pcb & 0x20) ? 1 : 0),
                ((pcb & 0x10) ? 1 : 0));
    if (pcb & 0x10)
        n += sprintf(buff + n, "tmc=%d ", ((pcb & 0xc) >> 2));
#if 1
    n += sprintf(buff + n, "format+linking=%d  [0x%.2x]", pcb & 3,
                 pcb);
#else
    if (pcb & 0x1)
        n += sprintf(buff + n, "lbin=%d ", ((pcb & 0x2) >> 1));
    n += sprintf(buff + n, "lp=%d  [0x%.2x]", pcb & 0x1, pcb);
#endif
    if (outp && (n < maxoutlen)) {
        memcpy(outp, buff, n);
        outp[n] = '\0';
    } else if (outp && (maxoutlen > 0))
        outp[0] = '\0';
}

/* BUFF_OVER_UNDER_LPAGE */
static void
show_buffer_under_overrun_page(unsigned char * resp, int len, int show_pcb)
{
    int k, j, num, pl, count_basis, cause, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    printf("Buffer over-run/under-run page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pl = ucp[3] + 4;
        count_basis = (ucp[1] >> 5) & 0x7;
        cause = (ucp[1] >> 1) & 0xf;
        if ((0 == count_basis) && (0 == cause))
            printf("Count basis+Cause both undefined(0), unsupported??");
        else {
            printf("  Count basis: ");
            switch (count_basis) {
            case 0 : printf("undefined"); break;
            case 1 : printf("per command"); break;
            case 2 : printf("per failed reconnect"); break;
            case 3 : printf("per unit of time"); break;
            default: printf("reserved [0x%x]", count_basis); break;
            }
            printf(", Cause: ");
            switch (cause) {
            case 0 : printf("undefined"); break;
            case 1 : printf("bus busy"); break;
            case 2 : printf("transfer rate too slow"); break;
            default: printf("reserved [0x%x]", cause); break;
            }
            printf(", Type: ");
            if (ucp[1] & 1)
                printf("over-run");
            else
                printf("under-run");
            printf(", count");
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= xp[j];
            }
            printf(" = %" PRIu64 "", ull);
        }
        if (show_pcb) {
            pcb = ucp[2];
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

/* WRITE_ERR_LPAGE; READ_ERR_LPAGE; READ_REV_ERR_LPAGE; VERIFY_ERR_LPAGE */
static void
show_error_counter_page(unsigned char * resp, int len, int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    switch(resp[0] & 0x3f) {
    case WRITE_ERR_LPAGE:
        printf("Write error counter page\n");
        break;
    case READ_ERR_LPAGE:
        printf("Read error counter page\n");
        break;
    case READ_REV_ERR_LPAGE:
        printf("Read Reverse error counter page\n");
        break;
    case VERIFY_ERR_LPAGE:
        printf("Verify error counter page\n");
        break;
    default:
        printf("expecting error counter page, got page = 0x%x\n", resp[0]);
        return;
    }
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0: printf("  Errors corrected without substantial delay"); break;
        case 1: printf("  Errors corrected with possible delays"); break;
        case 2: printf("  Total rewrites or rereads"); break;
        case 3: printf("  Total errors corrected"); break;
        case 4: printf("  Total times correction algorithm processed"); break;
        case 5: printf("  Total bytes processed"); break;
        case 6: printf("  Total uncorrected errors"); break;
        case 0x8009: printf("  Track following errors [Hitachi]"); break;
        case 0x8015: printf("  Positioning errors [Hitachi]"); break;
        default: printf("  Reserved or vendor specific [0x%x]", pc); break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %" PRIu64 "", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

/* NON_MEDIUM_LPAGE */
static void
show_non_medium_error_page(unsigned char * resp, int len, int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    printf("Non-medium error page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Non-medium error count"); break;
        default:
            if (pc <= 0x7fff)
                printf("  Reserved [0x%x]", pc);
            else
                printf("  Vendor specific [0x%x]", pc);
            break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %" PRIu64 "", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

/* PCT_LPAGE */
static void
show_power_condition_transitions_page(unsigned char * resp, int len,
                                      int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    printf("Power condition transitions page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Accumulated transitions to active"); break;
        case 1:
            printf("  Accumulated transitions to idle_a"); break;
        case 2:
            printf("  Accumulated transitions to idle_b"); break;
        case 3:
            printf("  Accumulated transitions to idle_c"); break;
        case 8:
            printf("  Accumulated transitions to standby_z"); break;
        case 9:
            printf("  Accumulated transitions to standby_y"); break;
        default:
            printf("  Reserved [0x%x]", pc);
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %" PRIu64 "", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void
show_tape_usage_log_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    uint64_t ull;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed tape usage log page\n");
        return;
    }
    printf("Tape usage log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        extra = ucp[3] + 4;
        ull = n = 0;
        switch (ucp[3]) {
        case 2:
            n = (ucp[4] << 8) | ucp[5];
            break;
        case 4:
            n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
            break;
        case 8:
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            break;
        }
        switch (pc) {
        case 0x01:
            if (extra == 8)
                printf("  Thread count: %u", n);
            break;
        case 0x02:
            if (extra == 12)
                printf("  Total data sets written: %" PRIu64, ull);
            break;
        case 0x03:
            if (extra == 8)
                printf("  Total write retries: %u", n);
            break;
        case 0x04:
            if (extra == 6)
                printf("  Total unrecovered write errors: %u", n);
            break;
        case 0x05:
            if (extra == 6)
                printf("  Total suspended writes: %u", n);
            break;
        case 0x06:
            if (extra == 6)
                printf("  Total fatal suspended writes: %u", n);
            break;
        case 0x07:
            if (extra == 12)
                printf("  Total data sets read: %" PRIu64, ull);
            break;
        case 0x08:
            if (extra == 8)
                printf("  Total read retries: %u", n);
            break;
        case 0x09:
            if (extra == 6)
                printf("  Total unrecovered read errors: %u", n);
            break;
        case 0x0a:
            if (extra == 6)
                printf("  Total suspended reads: %u", n);
            break;
        case 0x0b:
            if (extra == 6)
                printf("  Total fatal suspended reads: %u", n);
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void
show_tape_capacity_log_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed tape capacity log page\n");
        return;
    }
    printf("Tape capacity log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        extra = ucp[3] + 4;
        if (extra != 8)
            continue;
        n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
        switch (pc) {
        case 0x01:
            printf("  Main partition remaining capacity (in MiB): %u", n);
            break;
        case 0x02:
            printf("  Alternate partition remaining capacity (in MiB): %u", n);
            break;
        case 0x03:
            printf("  Main partition maximum capacity (in MiB): %u", n);
            break;
        case 0x04:
            printf("  Alternate partition maximum capacity (in MiB): %u", n);
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void
show_data_compression_log_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed data compression log page\n");
        return;
    }
    printf("Data compression log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        extra = ucp[3] + 4;
        switch (ucp[3]) {
        case 2:
            n = (ucp[4] << 8) | ucp[5];
            break;
        case 4:
            n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
            break;
        default:
            n = 0;
        }
        switch (pc) {
        case 0x00:
            if (extra == 6)
                printf("  Read compression ratio x100: %u", n);
            break;
        case 0x01:
            if (extra == 6)
                printf("  Write compression ratio x100: %u", n);
            break;
        case 0x02:
            if (extra == 8)
                printf("  Megabytes transferred to server: %u", n);
            break;
        case 0x03:
            if (extra == 8)
                printf("  Bytes transferred to server: %u", n);
            break;
        case 0x04:
            if (extra == 8)
                printf("  Megabytes read from tape: %u", n);
            break;
        case 0x05:
            if (extra == 8)
                printf("  Bytes read from tape: %u", n);
            break;
        case 0x06:
            if (extra == 8)
                printf("  Megabytes transferred from server: %u", n);
            break;
        case 0x07:
            if (extra == 8)
                printf("  Bytes transferred from server: %u", n);
            break;
        case 0x08:
            if (extra == 8)
                printf("  Megabytes written to tape: %u", n);
            break;
        case 0x09:
            if (extra == 8)
                printf("  Bytes written to tape: %u", n);
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

/* LAST_N_ERR_LPAGE */
static void
show_last_n_error_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("No error events logged\n");
        return;
    }
    printf("Last n error events log page\n");
    for (k = num; k > 0; k -= pl, ucp += pl) {
        if (k < 3) {
            printf("short Last n error events log page\n");
            return;
        }
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        printf("  Error event %d:\n", pc);
        if (pl > 4) {
            if ((pcb & 0x1) && (pcb & 0x2)) {
                printf("    [binary]:\n");
                dStrHex((const char *)ucp + 4, pl - 4, 1);
            } else if (pcb & 0x1)
                printf("    %.*s\n", pl - 4, (const char *)(ucp + 4));
            else {
                printf("    [data counter?? (LP bit should be set)]:\n");
                dStrHex((const char *)ucp + 4, pl - 4, 1);
            }
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
    }
}

/* LAST_N_DEFERRED_LPAGE */
static void
show_last_n_deferred_error_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("No deferred errors logged\n");
        return;
    }
    printf("Last n deferred errors log page\n");
    for (k = num; k > 0; k -= pl, ucp += pl) {
        if (k < 3) {
            printf("short Last n deferred errors log page\n");
            return;
        }
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        printf("  Deferred error %d:\n", pc);
        dStrHex((const char *)ucp + 4, pl - 4, 1);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
    }
}

static const char * self_test_code[] = {
    "default", "background short", "background extended", "reserved",
    "aborted background", "foreground short", "foreground extended",
    "reserved"};

static const char * self_test_result[] = {
    "completed without error",
    "aborted by SEND DIAGNOSTIC",
    "aborted other than by SEND DIAGNOSTIC",
    "unknown error, unable to complete",
    "self test completed with failure in test segment (which one unknown)",
    "first segment in self test failed",
    "second segment in self test failed",
    "another segment in self test failed",
    "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
    "reserved",
    "self test in progress"};

/* SELF_TEST_LPAGE */
static void
show_self_test_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, n, res, pcb;
    unsigned char * ucp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    if (num < 0x190) {
        printf("short self-test results page [length 0x%x rather than "
               "0x190 bytes]\n", num);
        return;
    }
    printf("Self-test results page\n");
    for (k = 0, ucp = resp + 4; k < 20; ++k, ucp += 20 ) {
        pcb = ucp[2];
        n = (ucp[6] << 8) | ucp[7];
        if ((0 == n) && (0 == ucp[4]))
            break;
        printf("  Parameter code = %d, accumulated power-on hours = %d\n",
               (ucp[0] << 8) | ucp[1], n);
        printf("    self-test code: %s [%d]\n",
               self_test_code[(ucp[4] >> 5) & 0x7], (ucp[4] >> 5) & 0x7);
        res = ucp[4] & 0xf;
        printf("    self-test result: %s [%d]\n",
               self_test_result[res], res);
        if (ucp[5])
            printf("    self-test number = %d\n", (int)ucp[5]);
        ull = ucp[8]; ull <<= 8; ull |= ucp[9]; ull <<= 8; ull |= ucp[10];
        ull <<= 8; ull |= ucp[11]; ull <<= 8; ull |= ucp[12];
        ull <<= 8; ull |= ucp[13]; ull <<= 8; ull |= ucp[14];
        ull <<= 8; ull |= ucp[15];
        if ((0xffffffffffffffffULL != ull) && (res > 0) && ( res < 0xf))
            printf("    address of first error = 0x%" PRIx64 "\n", ull);
        if (ucp[16] & 0xf)
            printf("    sense key = 0x%x, asc = 0x%x, asq = 0x%x",
                   ucp[16] & 0xf, ucp[17], ucp[18]);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

/* TEMPERATURE_LPAGE */
static void
show_temperature_page(unsigned char * resp, int len, int show_pcb, int hdr,
                      int show_unknown)
{
    int k, num, extra, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Temperature log page\n");
        return;
    }
    if (hdr)
        printf("Temperature log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Temperature log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (0 == pc) {
            if ((extra > 5) && (k > 5)) {
                if (ucp[5] < 0xff)
                    printf("  Current temperature = %d C", ucp[5]);
                else
                    printf("  Current temperature = <not available>");
            }
        } else if (1 == pc) {
            if ((extra > 5) && (k > 5)) {
                if (ucp[5] < 0xff)
                    printf("  Reference temperature = %d C", ucp[5]);
                else
                    printf("  Reference temperature = <not available>");
            }

        } else if (show_unknown) {
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
        } else
            continue;
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

/* START_STOP_LPAGE */
static void
show_start_stop_page(unsigned char * resp, int len, int show_pcb, int verbose)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Start-stop cycle counter log page\n");
        return;
    }
    printf("Start-stop cycle counter log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Start-stop cycle counter log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        switch (pc) {
        case 1:
            if (10 == extra)
                printf("  Date of manufacture, year: %.4s, week: %.2s",
                       &ucp[4], &ucp[8]);
            else if (verbose) {
                printf("  Date of manufacture parameter length "
                       "strange: %d\n", extra - 4);
                dStrHex((const char *)ucp, extra, 1);
            }
            break;
        case 2:
            if (10 == extra)
                printf("  Accounting date, year: %.4s, week: %.2s",
                       &ucp[4], &ucp[8]);
            else if (verbose) {
                printf("  Accounting date parameter length strange: %d\n",
                       extra - 4);
                dStrHex((const char *)ucp, extra, 1);
            }
            break;
        case 3:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Specified cycle count over device lifetime "
                           "= -1");
                else
                    printf("  Specified cycle count over device lifetime "
                           "= %u", n);
            }
            break;
        case 4:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Accumulated start-stop cycles = -1");
                else
                    printf("  Accumulated start-stop cycles = %u", n);
            }
            break;
        case 5:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Specified load-unload count over device "
                           "lifetime = -1");
                else
                    printf("  Specified load-unload count over device "
                           "lifetime = %u", n);
            }
            break;
        case 6:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Accumulated load-unload cycles = -1");
                else
                    printf("  Accumulated load-unload cycles = %u", n);
            }
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

/* IE_LPAGE */
static void
show_ie_page(unsigned char * resp, int len, int show_pcb, int full)
{
    int k, num, extra, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];
    char b[256];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Informational Exceptions log page\n");
        return;
    }
    if (full)
        printf("Informational Exceptions log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Informational Exceptions log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (0 == pc) {
            if (extra > 5) {
                if (full) {
                    printf("  IE asc = 0x%x, ascq = 0x%x", ucp[4], ucp[5]);
                    if (ucp[4]) {
                        if(sg_get_asc_ascq_str(ucp[4], ucp[5], sizeof(b), b))
                            printf("\n    [%s]", b);
                    }
                }
                if (extra > 6) {
                    if (ucp[6] < 0xff)
                        printf("\n  Current temperature = %d C", ucp[6]);
                    else
                        printf("\n  Current temperature = <not available>");
                    if (extra > 7) {
                        if (ucp[7] < 0xff)
                            printf("\n  Threshold temperature = %d C  [IBM "
                                   "extension]", ucp[7]);
                        else
                            printf("\n  Threshold temperature = <not "
                                   "available>");
                     }
                }
            }
        } else if (full) {
            printf("  parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

/* from sas2r15 */
static void
show_sas_phy_event_info(int pes, unsigned int val, unsigned int thresh_val)
{
    unsigned int u;

    switch (pes) {
    case 0:
        printf("     No event\n");
        break;
    case 0x1:
        printf("     Invalid word count: %u\n", val);
        break;
    case 0x2:
        printf("     Running disparity error count: %u\n", val);
        break;
    case 0x3:
        printf("     Loss of dword synchronization count: %u\n", val);
        break;
    case 0x4:
        printf("     Phy reset problem count: %u\n", val);
        break;
    case 0x5:
        printf("     Elasticity buffer overflow count: %u\n", val);
        break;
    case 0x6:
        printf("     Received ERROR  count: %u\n", val);
        break;
    case 0x20:
        printf("     Received address frame error count: %u\n", val);
        break;
    case 0x21:
        printf("     Transmitted abandon-class OPEN_REJECT count: %u\n", val);
        break;
    case 0x22:
        printf("     Received abandon-class OPEN_REJECT count: %u\n", val);
        break;
    case 0x23:
        printf("     Transmitted retry-class OPEN_REJECT count: %u\n", val);
        break;
    case 0x24:
        printf("     Received retry-class OPEN_REJECT count: %u\n", val);
        break;
    case 0x25:
        printf("     Received AIP (WATING ON PARTIAL) count: %u\n", val);
        break;
    case 0x26:
        printf("     Received AIP (WAITING ON CONNECTION) count: %u\n", val);
        break;
    case 0x27:
        printf("     Transmitted BREAK count: %u\n", val);
        break;
    case 0x28:
        printf("     Received BREAK count: %u\n", val);
        break;
    case 0x29:
        printf("     Break timeout count: %u\n", val);
        break;
    case 0x2a:
        printf("     Connection count: %u\n", val);
        break;
    case 0x2b:
        printf("     Peak transmitted pathway blocked count: %u\n",
               val & 0xff);
        printf("         Peak value detector threshold: %u\n",
               thresh_val & 0xff);
        break;
    case 0x2c:
        u = val & 0xffff;
        if (u < 0x8000)
            printf("     Peak transmitted arbitration wait time (us): "
                   "%u\n", u);
        else
            printf("     Peak transmitted arbitration wait time (ms): "
                   "%u\n", 33 + (u - 0x8000));
        u = thresh_val & 0xffff;
        if (u < 0x8000)
            printf("         Peak value detector threshold (us): %u\n",
                   u);
        else
            printf("         Peak value detector threshold (ms): %u\n",
                   33 + (u - 0x8000));
        break;
    case 0x2d:
        printf("     Peak arbitration time (us): %u\n", val);
        printf("         Peak value detector threshold: %u\n", thresh_val);
        break;
    case 0x2e:
        printf("     Peak connection time (us): %u\n", val);
        printf("         Peak value detector threshold: %u\n", thresh_val);
        break;
    case 0x40:
        printf("     Transmitted SSP frame count: %u\n", val);
        break;
    case 0x41:
        printf("     Received SSP frame count: %u\n", val);
        break;
    case 0x42:
        printf("     Transmitted SSP frame error count: %u\n", val);
        break;
    case 0x43:
        printf("     Received SSP frame error count: %u\n", val);
        break;
    case 0x44:
        printf("     Transmitted CREDIT_BLOCKED count: %u\n", val);
        break;
    case 0x45:
        printf("     Received CREDIT_BLOCKED count: %u\n", val);
        break;
    case 0x50:
        printf("     Transmitted SATA frame count: %u\n", val);
        break;
    case 0x51:
        printf("     Received SATA frame count: %u\n", val);
        break;
    case 0x52:
        printf("     SATA flow control buffer overflow count: %u\n", val);
        break;
    case 0x60:
        printf("     Transmitted SMP frame count: %u\n", val);
        break;
    case 0x61:
        printf("     Received SMP frame count: %u\n", val);
        break;
    case 0x63:
        printf("     Received SMP frame error count: %u\n", val);
        break;
    default:
        printf("     Unknown phy event source: %d, val=%u, thresh_val=%u\n",
               pes, val, thresh_val);
        break;
    }
}

/* PROTO_SPECIFIC_LPAGE for a SAS port */
static void
show_sas_port_param(unsigned char * ucp, int param_len,
                    const struct opts_t * optsp)
{
    int j, m, n, nphys, pcb, t, sz, spld_len;
    unsigned char * vcp;
    uint64_t ull;
    unsigned int ui;
    char pcb_str[PCB_STR_LEN];
    char s[64];

    sz = sizeof(s);
    pcb = ucp[2];
    t = (ucp[0] << 8) | ucp[1];
    if (optsp->do_name)
        printf("rel_target_port=%d\n", t);
    else
        printf("relative target port id = %d\n", t);
    if (optsp->do_name)
        printf("  gen_code=%d\n", ucp[6]);
    else
        printf("  generation code = %d\n", ucp[6]);
    nphys = ucp[7];
    if (optsp->do_name)
        printf("  num_phys=%d\n", nphys);
    else {
        printf("  number of phys = %d", nphys);
        if ((optsp->do_pcb) && (0 == optsp->do_name)) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }

    for (j = 0, vcp = ucp + 8; j < (param_len - 8);
         vcp += spld_len, j += spld_len) {
        if (optsp->do_name)
            printf("    phy_id=%d\n", vcp[1]);
        else
            printf("  phy identifier = %d\n", vcp[1]);
        spld_len = vcp[3];
        if (spld_len < 44)
            spld_len = 48;      /* in SAS-1 and SAS-1.1 vcp[3]==0 */
        else
            spld_len += 4;
        if (optsp->do_name) {
            t = ((0x70 & vcp[4]) >> 4);
            printf("      att_dev_type=%d\n", t);
            printf("      att_iport_mask=0x%x\n", vcp[6]);
            printf("      att_phy_id=%d\n", vcp[24]);
            printf("      att_reason=0x%x\n", (vcp[4] & 0xf));
            for (n = 0, ull = vcp[16]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[16 + n];
            }
            printf("      att_sas_addr=0x%" PRIx64 "\n", ull);
            printf("      att_tport_mask=0x%x\n", vcp[7]);
            ui = (vcp[32] << 24) | (vcp[33] << 16) | (vcp[34] << 8) | vcp[35];
            printf("      inv_dwords=%u\n", ui);
            ui = (vcp[40] << 24) | (vcp[41] << 16) | (vcp[42] << 8) | vcp[43];
            printf("      loss_dword_sync=%u\n", ui);
            printf("      neg_log_lrate=%d\n", 0xf & vcp[5]);
            ui = (vcp[44] << 24) | (vcp[45] << 16) | (vcp[46] << 8) | vcp[47];
            printf("      phy_reset_probs=%u\n", ui);
            ui = (vcp[36] << 24) | (vcp[37] << 16) | (vcp[38] << 8) | vcp[39];
            printf("      running_disparity=%u\n", ui);
            printf("      reason=0x%x\n", (vcp[5] & 0xf0) >> 4);
            for (n = 0, ull = vcp[8]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[8 + n];
            }
            printf("      sas_addr=0x%" PRIx64 "\n", ull);
        } else {
            t = ((0x70 & vcp[4]) >> 4);
            /* attached device type. In SAS-1.1 case 2 was an edge expander;
             * in SAS-2 case 3 is marked as obsolete. */
            switch (t) {
            case 0: snprintf(s, sz, "no device attached"); break;
            case 1: snprintf(s, sz, "end device"); break;
            case 2: snprintf(s, sz, "expander device"); break;
            case 3: snprintf(s, sz, "expander device (fanout)"); break;
            default: snprintf(s, sz, "reserved [%d]", t); break;
            }
            printf("    attached device type: %s\n", s);
            t = 0xf & vcp[4];
            switch (t) {
            case 0: snprintf(s, sz, "unknown"); break;
            case 1: snprintf(s, sz, "power on"); break;
            case 2: snprintf(s, sz, "hard reset"); break;
            case 3: snprintf(s, sz, "SMP phy control function"); break;
            case 4: snprintf(s, sz, "loss of dword synchronization"); break;
            case 5: snprintf(s, sz, "mux mix up"); break;
            case 6: snprintf(s, sz, "I_T nexus loss timeout for STP/SATA");
                break;
            case 7: snprintf(s, sz, "break timeout timer expired"); break;
            case 8: snprintf(s, sz, "phy test function stopped"); break;
            case 9: snprintf(s, sz, "expander device reduced functionality");
                 break;
            default: snprintf(s, sz, "reserved [0x%x]", t); break;
            }
            printf("    attached reason: %s\n", s);
            t = (vcp[5] & 0xf0) >> 4;
            switch (t) {
            case 0: snprintf(s, sz, "unknown"); break;
            case 1: snprintf(s, sz, "power on"); break;
            case 2: snprintf(s, sz, "hard reset"); break;
            case 3: snprintf(s, sz, "SMP phy control function"); break;
            case 4: snprintf(s, sz, "loss of dword synchronization"); break;
            case 5: snprintf(s, sz, "mux mix up"); break;
            case 6: snprintf(s, sz, "I_T nexus loss timeout for STP/SATA");
                break;
            case 7: snprintf(s, sz, "break timeout timer expired"); break;
            case 8: snprintf(s, sz, "phy test function stopped"); break;
            case 9: snprintf(s, sz, "expander device reduced functionality");
                 break;
            default: snprintf(s, sz, "reserved [0x%x]", t); break;
            }
            printf("    reason: %s\n", s);
            t = (0xf & vcp[5]);
            switch (t) {
            case 0:
                snprintf(s, sz, "phy enabled; unknown reason");
                break;
            case 1:
                snprintf(s, sz, "phy disabled");
                break;
            case 2:
                snprintf(s, sz, "phy enabled; speed negotiation failed");
                break;
            case 3:
                snprintf(s, sz, "phy enabled; SATA spinup hold state");
                break;
            case 4:
                snprintf(s, sz, "phy enabled; port selector");
                break;
            case 5:
                snprintf(s, sz, "phy enabled; reset in progress");
                break;
            case 6:
                snprintf(s, sz, "phy enabled; unsupported phy attached");
                break;
            case 8:
                snprintf(s, sz, "1.5 Gbps");
                break;
            case 9:
                snprintf(s, sz, "3 Gbps");
                break;
            case 0xa:
                snprintf(s, sz, "6 Gbps");
                break;
            case 0xb:
                snprintf(s, sz, "12 Gbps");
                break;
            default:
                snprintf(s, sz, "reserved [%d]", t);
                break;
            }
            printf("    negotiated logical link rate: %s\n", s);
            printf("    attached initiator port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[6] & 8), !! (vcp[6] & 4), !! (vcp[6] & 2));
            printf("    attached target port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[7] & 8), !! (vcp[7] & 4), !! (vcp[7] & 2));
            for (n = 0, ull = vcp[8]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[8 + n];
            }
            printf("    SAS address = 0x%" PRIx64 "\n", ull);
            for (n = 0, ull = vcp[16]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[16 + n];
            }
            printf("    attached SAS address = 0x%" PRIx64 "\n", ull);
            printf("    attached phy identifier = %d\n", vcp[24]);
            ui = (vcp[32] << 24) | (vcp[33] << 16) | (vcp[34] << 8) | vcp[35];
            printf("    Invalid DWORD count = %u\n", ui);
            ui = (vcp[36] << 24) | (vcp[37] << 16) | (vcp[38] << 8) | vcp[39];
            printf("    Running disparity error count = %u\n", ui);
            ui = (vcp[40] << 24) | (vcp[41] << 16) | (vcp[42] << 8) | vcp[43];
            printf("    Loss of DWORD synchronization = %u\n", ui);
            ui = (vcp[44] << 24) | (vcp[45] << 16) | (vcp[46] << 8) | vcp[47];
            printf("    Phy reset problem = %u\n", ui);
        }
        if (spld_len > 51) {
            int num_ped, pes;
            unsigned char * xcp;
            unsigned int pvdt;

            num_ped = vcp[51];
            if (optsp->do_verbose > 1)
                printf("    <<Phy event descriptors: %d, spld_len: %d, "
                       "calc_ped: %d>>\n", num_ped, spld_len,
                       (spld_len - 52) / 12);
            if (num_ped > 0) {
                if (optsp->do_name) {
                   printf("      phy_event_desc_num=%d\n", num_ped);
                   return;      /* don't decode at this stage */
                } else
                   printf("    Phy event descriptors:\n");
            }
            xcp = vcp + 52;
            for (m = 0; m < (num_ped * 12); m += 12, xcp += 12) {
                pes = xcp[3];
                ui = (xcp[4] << 24) | (xcp[5] << 16) | (xcp[6] << 8) |
                     xcp[7];
                pvdt = (xcp[8] << 24) | (xcp[9] << 16) | (xcp[10] << 8) |
                       xcp[11];
                show_sas_phy_event_info(pes, ui, pvdt);
            }
        } else if (optsp->do_verbose)
           printf("    <<No phy event descriptors>>\n");
    }
}

/* PROTO_SPECIFIC_LPAGE */
static int
show_protocol_specific_page(unsigned char * resp, int len,
                            const struct opts_t * optsp)
{
    int k, num, param_len;
    unsigned char * ucp;

    num = len - 4;
    if (optsp->do_name)
        printf("log_page=0x%x\n", PROTO_SPECIFIC_LPAGE);
    for (k = 0, ucp = resp + 4; k < num; ) {
        param_len = ucp[3] + 4;
        if (6 != (0xf & ucp[4]))
            return 0;   /* only decode SAS log page */
        if ((0 == k) && (0 == optsp->do_name))
            printf("Protocol Specific port log page for SAS SSP\n");
        show_sas_port_param(ucp, param_len, optsp);
        k += param_len;
        ucp += param_len;
    }
    return 1;
}

/* Returns 1 if processed page, 0 otherwise */
/* STATS_LPAGE, 0x0 to 0x1f */
static int
show_stats_perform_page(unsigned char * resp, int len,
                        const struct opts_t * optsp)
{
    int k, num, n, param_len, param_code, spf, subpg_code, extra;
    int pcb, nam;
    unsigned char * ucp;
    const char * ccp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    nam = optsp->do_name;
    num = len - 4;
    ucp = resp + 4;
    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : 0;
    if (nam) {
        printf("log_page=0x%x\n", STATS_LPAGE);
        if (subpg_code > 0)
            printf("log_subpage=0x%x\n", subpg_code);
    }
    if (subpg_code > 31)
        return 0;
    if (0 == subpg_code) { /* General statistics and performance log page */
        if (num < 0x5c)
            return 0;
        for (k = num; k > 0; k -= extra, ucp += extra) {
            if (k < 3)
                return 0;
            param_len = ucp[3];
            extra = param_len + 4;
            param_code = (ucp[0] << 8) + ucp[1];
            pcb = ucp[2];
            switch (param_code) {
            case 1:     /* Statistics and performance log parameter */
                ccp = nam ? "parameter_code=1" : "Statistics and performance "
                        "log parameter";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "read_commands=" : "number of read commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[12]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[12 + n];
                }
                ccp = nam ? "write_commands=" : "number of write commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[20]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[20 + n];
                }
                ccp = nam ? "lb_received="
                          : "number of logical blocks received = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[28]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[28 + n];
                }
                ccp = nam ? "lb_transmitted="
                          : "number of logical blocks transmitted = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[36]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[36 + n];
                }
                ccp = nam ? "read_proc_intervals="
                          : "read command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[44]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[44 + n];
                }
                ccp = nam ? "write_proc_intervals="
                          : "write command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[52]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[52 + n];
                }
                ccp = nam ? "weight_rw_commands=" : "weighted number of "
                                "read commands plus write commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[60]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[60 + n];
                }
                ccp = nam ? "weight_rw_processing=" : "weighted read command "
                                "processing plus write command processing = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 2:     /* Idle time log parameter */
                ccp = nam ? "parameter_code=2" : "Idle time log parameter";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "idle_time_intervals=" : "idle time "
                                "intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 3:     /* Time interval log parameter for general stats */
                ccp = nam ? "parameter_code=3" : "Time interval log "
                        "parameter for general stats";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 4; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "time_interval_neg_exp=" : "time interval "
                                "negative exponent = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[8]; n < 4; ++n) {
                    ull <<= 8; ull |= ucp[8 + n];
                }
                ccp = nam ? "time_interval_int=" : "time interval "
                                "integer = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 4:     /* FUA statistics and performance log parameter */
                ccp = nam ? "parameter_code=4" : "Force unit access "
                        "statistics and performance log parameter ";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "read_fua_commands=" : "number of read FUA "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[12]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[12 + n];
                }
                ccp = nam ? "write_fua_commands=" : "number of write FUA "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[20]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[20 + n];
                }
                ccp = nam ? "read_fua_nv_commands="
                          : "number of read FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[28]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[28 + n];
                }
                ccp = nam ? "write_fua_nv_commands="
                          : "number of write FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[36]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[36 + n];
                }
                ccp = nam ? "read_fua_proc_intervals="
                          : "read FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[44]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[44 + n];
                }
                ccp = nam ? "write_fua_proc_intervals="
                          : "write FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[52]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[52 + n];
                }
                ccp = nam ? "read_fua_nv_proc_intervals="
                          : "read FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[60]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[60 + n];
                }
                ccp = nam ? "write_fua_nv_proc_intervals="
                          : "write FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 6:     /* Time interval log parameter for cache stats */
                ccp = nam ? "parameter_code=6" : "Time interval log "
                        "parameter for cache stats";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 4; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "time_interval_neg_exp=" : "time interval "
                                "negative exponent = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[8]; n < 4; ++n) {
                    ull <<= 8; ull |= ucp[8 + n];
                }
                ccp = nam ? "time_interval_int=" : "time interval "
                                "integer = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            default:
                if (nam) {
                    printf("parameter_code=%d\n", param_code);
                    printf("  unknown=1\n");
                } else
                    fprintf(stderr, "show_performance...  unknown parameter "
                            "code %d\n", param_code);
                if (optsp->do_verbose)
                    dStrHex((const char *)ucp, extra, 1);
                break;
            }
            if ((optsp->do_pcb) && (0 == optsp->do_name)) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("    <%s>\n", pcb_str);
            }
        }
    } else {    /* Group statistics and performance (n) log page */
        if (num < 0x34)
            return 0;
        for (k = num; k > 0; k -= extra, ucp += extra) {
            if (k < 3)
                return 0;
            param_len = ucp[3];
            extra = param_len + 4;
            param_code = (ucp[0] << 8) + ucp[1];
            pcb = ucp[2];
            switch (param_code) {
            case 1:     /* Group n Statistics and performance log parameter */
                if (nam)
                    printf("parameter_code=1\n");
                else
                    printf("Group %d Statistics and performance log "
                           "parameter\n", subpg_code);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "gn_read_commands=" : "group n number of read "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[12]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[12 + n];
                }
                ccp = nam ? "gn_write_commands=" : "group n number of write "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[20]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[20 + n];
                }
                ccp = nam ? "gn_lb_received="
                          : "group n number of logical blocks received = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[28]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[28 + n];
                }
                ccp = nam ? "gn_lb_transmitted="
                          : "group n number of logical blocks transmitted = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[36]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[36 + n];
                }
                ccp = nam ? "gn_read_proc_intervals="
                          : "group n read command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[44]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[44 + n];
                }
                ccp = nam ? "gn_write_proc_intervals="
                          : "group n write command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 4: /* Group n FUA statistics and performance log parameter */
                ccp = nam ? "parameter_code=4" : "Group n force unit access "
                        "statistics and performance log parameter";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "gn_read_fua_commands="
                          : "group n number of read FUA commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[12]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[12 + n];
                }
                ccp = nam ? "gn_write_fua_commands="
                          : "group n number of write FUA commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[20]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[20 + n];
                }
                ccp = nam ? "gn_read_fua_nv_commands="
                          : "group n number of read FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[28]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[28 + n];
                }
                ccp = nam ? "gn_write_fua_nv_commands="
                          : "group n number of write FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[36]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[36 + n];
                }
                ccp = nam ? "gn_read_fua_proc_intervals="
                          : "group n read FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[44]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[44 + n];
                }
                ccp = nam ? "gn_write_fua_proc_intervals=" : "group n write "
                            "FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[52]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[52 + n];
                }
                ccp = nam ? "gn_read_fua_nv_proc_intervals=" : "group n "
                            "read FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[60]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[60 + n];
                }
                ccp = nam ? "gn_write_fua_nv_proc_intervals=" : "group n "
                            "write FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            default:
                if (nam) {
                    printf("parameter_code=%d\n", param_code);
                    printf("  unknown=1\n");
                } else
                    fprintf(stderr, "show_performance...  unknown parameter "
                            "code %d\n", param_code);
                if (optsp->do_verbose)
                    dStrHex((const char *)ucp, extra, 1);
                break;
            }
            if ((optsp->do_pcb) && (0 == optsp->do_name)) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("    <%s>\n", pcb_str);
            }
        }
    }
    return 1;
}

/* Returns 1 if processed page, 0 otherwise */
/* STATS_LPAGE, CACHE_STATS_SUBPG */
static int
show_cache_stats_page(unsigned char * resp, int len,
                      const struct opts_t * optsp)
{
    int k, num, n, pc, spf, subpg_code, extra;
    int pcb, nam;
    unsigned char * ucp;
    const char * ccp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    nam = optsp->do_name;
    num = len - 4;
    ucp = resp + 4;
    if (num < 4) {
        printf("badly formed Cache memory statistics log page\n");
        return 0;
    }
    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : 0;
    if (nam) {
        printf("log_page=0x%x\n", STATS_LPAGE);
        if (subpg_code > 0)
            printf("log_subpage=0x%x\n", subpg_code);
    } else
        printf("Cache memory statistics log page\n");

    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Cache memory statistics log page\n");
            return 0;
        }
        if (8 != ucp[3]) {
            printf("Cache memory statistics log page parameter length not "
                   "8\n");
            return 0;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        switch (pc) {
        case 1:     /* Read cache memory hits log parameter */
            ccp = nam ? "parameter_code=1" :
                        "Read cache memory hits log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "read_cache_memory_hits=" :
                        "read cache memory hits = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 2:     /* Reads to cache memory log parameter */
            ccp = nam ? "parameter_code=2" :
                        "Reads to cache memory log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "reads_to_cache_memory=" :
                        "reads to cache memory = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 3:     /* Write cache memory hits log parameter */
            ccp = nam ? "parameter_code=3" :
                        "Write cache memory hits log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "write_cache_memory_hits=" :
                        "write cache memory hits = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 4:     /* Writes from cache memory log parameter */
            ccp = nam ? "parameter_code=4" :
                        "Writes from cache memory log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "writes_from_cache_memory=" :
                        "writes from cache memory = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 5:     /* Time from last hard reset log parameter */
            ccp = nam ? "parameter_code=5" :
                        "Time from last hard reset log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "time_from_last_hard_reset=" :
                        "time from last hard reset = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 6:     /* Time interval log parameter for cache stats */
            ccp = nam ? "parameter_code=6" :
                        "Time interval log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 4; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "time_interval_neg_exp=" : "time interval "
                            "negative exponent = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            for (n = 0, ull = ucp[8]; n < 4; ++n) {
                ull <<= 8; ull |= ucp[8 + n];
            }
            ccp = nam ? "time_interval_int=" : "time interval "
                            "integer = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        default:
            if (nam) {
                printf("parameter_code=%d\n", pc);
                printf("  unknown=1\n");
            } else
                fprintf(stderr, "show_performance...  unknown parameter "
                        "code %d\n", pc);
            if (optsp->do_verbose)
                dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if ((optsp->do_pcb) && (0 == optsp->do_name)) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("    <%s>\n", pcb_str);
        }
    }
    return 1;
}

/* FORMAT_STATUS_LPAGE */
static void
show_format_status_page(unsigned char * resp, int len, int show_pcb)
{
    int k, j, num, pl, pc, pcb, all_ff, counter;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    printf("Format status page (sbc-2) [0x8]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        counter = 1;
        switch (pc) {
        case 0: printf("  Format data out:\n");
            counter = 0;
            dStrHex((const char *)ucp, pl, 0);
            break;
        case 1: printf("  Grown defects during certification"); break;
        case 2: printf("  Total blocks reassigned during format"); break;
        case 3: printf("  Total new blocks reassigned"); break;
        case 4: printf("  Power on minutes since format"); break;
        default:
            printf("  Unknown Format status code = 0x%x\n", pc);
            counter = 0;
            dStrHex((const char *)ucp, pl, 0);
            break;
        }
        if (counter) {
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (all_ff = 0, j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                else
                    all_ff = 1;
                ull |= xp[j];
                if (0xff != xp[j])
                    all_ff = 0;
            }
            if (all_ff)
                printf(" <not available>");
            else
                printf(" = %" PRIu64 "", ull);
            if (show_pcb) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("\n        <%s>\n", pcb_str);
            } else
                printf("\n");
        } else {
            if (show_pcb) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("\n        <%s>\n", pcb_str);
            }
        }
        num -= pl;
        ucp += pl;
    }
}

static void
show_non_volatile_cache_page(unsigned char * resp, int len, int show_pcb)
{
    int j, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    printf("Non-volatile cache page (sbc-2) [0x17]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Remaining non-volatile time: ");
            if (3 == ucp[4]) {
                j = (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
                switch (j) {
                case 0:
                    printf("0 (i.e. it is now volatile)\n");
                    break;
                case 1:
                    printf("<unknown>\n");
                    break;
                case 0xffffff:
                    printf("<indefinite>\n");
                    break;
                default:
                    printf("%d minutes [%d:%d]\n", j, (j / 60), (j % 60));
                    break;
                }
            } else
                printf("<unexpected parameter length=%d>\n", ucp[4]);
            break;
        case 1:
            printf("  Maximum non-volatile time: ");
            if (3 == ucp[4]) {
                j = (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
                switch (j) {
                case 0:
                    printf("0 (i.e. it is now volatile)\n");
                    break;
                case 1:
                    printf("<reserved>\n");
                    break;
                case 0xffffff:
                    printf("<indefinite>\n");
                    break;
                default:
                    printf("%d minutes [%d:%d]\n", j, (j / 60), (j % 60));
                    break;
                }
            } else
                printf("<unexpected parameter length=%d>\n", ucp[4]);
            break;
        default:
            printf("  Unknown Format status code = 0x%x\n", pc);
            dStrHex((const char *)ucp, pl, 0);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        }
        num -= pl;
        ucp += pl;
    }
}

/* LB_PROV_LPAGE [0xc] */
static void
show_lb_provisioning_page(unsigned char * resp, int len, int show_pcb)
{
    int j, num, pl, pc, pcb;
    unsigned char * ucp;
    char * cp;
    char str[PCB_STR_LEN];

    printf("Logical block provisioning page (sbc-3) [0xc]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0x1:
            cp = "  Available LBA mapping threshold";
            break;
        case 0x2:
            cp = "  Used LBA mapping threshold";
            break;
        case 0x100:
            cp = "  De-duplicated LBA";
            break;
        case 0x101:
            cp = "  Compressed LBA";
            break;
        case 0x102:
            cp = "  Total efficiency LBA";
            break;
        default:
            cp = NULL;
            break;
        }
        if (cp) {
            printf("  %s resource count:", cp);
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    fprintf(stderr, "\n    truncated by response length, "
                            "expected at least 8 bytes\n");
                else
                    fprintf(stderr, "\n    parameter length >= 8 expected, "
                            "got %d\n", pl);
                break;
            }
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf(" %d\n", j);
            if (pl > 8) {
                switch (ucp[8] & 0x3) {
                case 0: cp = "not reported"; break;
                case 1: cp = "dedicated to lu"; break;
                case 2: cp = "not dedicated to lu"; break;
                case 3: cp = "reserved"; break;
                }
                printf("    Scope: %s\n", cp);
            }
        } else if ((pc >= 0xfff0) && (pc <= 0xffff)) {
            printf("  Vendor specific [0x%x]:", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
        } else {
            printf("  Reserved [parameter_code=0x%x]:", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
        }
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

/* SOLID_STATE_MEDIA_LPAGE */
static void
show_solid_state_media_page(unsigned char * resp, int len, int show_pcb)
{
    int num, pl, pc, pcb;
    unsigned char * ucp;
    char str[PCB_STR_LEN];

    printf("Solid state media page (sbc-3) [0x11]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (0x1 == pc) {
            printf("  Percentage used endurance indicator:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    fprintf(stderr, "\n    truncated by response length, "
                            "expected at least 8 bytes\n");
                else
                    fprintf(stderr, "\n    parameter length >= 8 expected, "
                            "got %d\n", pl);
                break;
            }
            printf(" %d%%\n", ucp[7]);
        } else {
            printf("  Reserved [parameter_code=0x%x]:", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
        }
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

/* SAT_ATA_RESULTS_LPAGE (SAT-2) */
static void
show_ata_pt_results_page(unsigned char * resp, int len, int show_pcb)
{
    int num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * dp;
    char str[PCB_STR_LEN];

    printf("ATA pass-through results page (sat-2) [0x16]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if ((pc < 0xf) && (pl > 17)) {
            int extend, sector_count;

            dp = ucp + 4;
            printf("  Log_index=0x%x (parameter_code=0x%x)\n", pc + 1, pc);
            extend = dp[2] & 1;
            sector_count = dp[5] + (extend ? (dp[4] << 8) : 0);
            printf("    extend=%d  error=0x%x sector_count=0x%x\n", extend,
                   dp[3], sector_count);
            if (extend)
                printf("    lba=0x%02x%02x%02x%02x%02x%02x\n", dp[10], dp[8],
                       dp[6], dp[11], dp[9], dp[7]);
            else
                printf("    lba=0x%02x%02x%02x\n", dp[11], dp[9], dp[7]);
            printf("    device=0x%x  status=0x%x\n", dp[12], dp[13]);
        } else {
            printf("  Reserved [parameter_code=0x%x]:", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
        }
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

static const char * bms_status[] = {
    "no background scans active",
    "background medium scan is active",
    "background pre-scan is active",
    "background scan halted due to fatal error",
    "background scan halted due to a vendor specific pattern of error",
    "background scan halted due to medium formatted without P-List",
    "background scan halted - vendor specific cause",
    "background scan halted due to temperature out of range",
    "background scan enabled, none active (waiting for BMS interval timer "
        "to expire)", /* 8 */
};

static const char * reassign_status[] = {
    "Reassign status: Reserved [0x0]",
    "Reassignment pending receipt of Reassign or Write command",
    "Logical block successfully reassigned by device server",
    "Reassign status: Reserved [0x3]",
    "Reassignment by device server failed",
    "Logical block recovered by device server via rewrite",
    "Logical block reassigned by application client, has valid data",
    "Logical block reassigned by application client, contains no valid data",
    "Logical block unsuccessfully reassigned by application client", /* 8 */
};

static void
show_background_scan_results_page(unsigned char * resp, int len, int show_pcb,
                                  int verbose)
{
    int j, m, num, pl, pc, pcb;
    unsigned char * ucp;
    char str[PCB_STR_LEN];

    printf("Background scan results page (sbc-3) [0x15]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Status parameters:\n");
            if ((pl < 16) || (num < 16)) {
                if (num < 16)
                    fprintf(stderr, "    truncated by response length, "
                            "expected at least 16 bytes\n");
                else
                    fprintf(stderr, "    parameter length >= 16 expected, "
                            "got %d\n", pl);
                break;
            }
            printf("    Accumulated power on minutes: ");
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf("%d [h:m  %d:%d]\n", j, (j / 60), (j % 60));
            printf("    Status: ");
            j = ucp[9];
            if (j < (int)(sizeof(bms_status) / sizeof(bms_status[0])))
                printf("%s\n", bms_status[j]);
            else
                printf("unknown [0x%x] background scan status value\n", j);
            j = (ucp[10] << 8) + ucp[11];
            printf("    Number of background scans performed: %d\n", j);
            j = (ucp[12] << 8) + ucp[13];
#ifdef SG_LIB_MINGW
            printf("    Background medium scan progress: %g%%\n",
                   (double)(j * 100.0 / 65536.0));
#else
            printf("    Background medium scan progress: %.2f%%\n",
                   (double)(j * 100.0 / 65536.0));
#endif
            j = (ucp[14] << 8) + ucp[15];
            if (0 == j)
                printf("    Number of background medium scans performed: 0 "
                       "[not reported]\n");
            else
                printf("    Number of background medium scans performed: "
                       "%d\n", j);
            break;
        default:
            if (pc > 0x800) {
                if ((pc >= 0x8000) && (pc <= 0xafff))
                    printf("  Medium scan parameter # %d [0x%x], vendor "
                           "specific\n", pc, pc);
                else
                    printf("  Medium scan parameter # %d [0x%x], "
                           "reserved\n", pc, pc);
                dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
                break;
            } else
                printf("  Medium scan parameter # %d [0x%x]\n", pc, pc);
            if ((pl < 24) || (num < 24)) {
                if (num < 24)
                    fprintf(stderr, "    truncated by response length, "
                            "expected at least 24 bytes\n");
                else
                    fprintf(stderr, "    parameter length >= 24 expected, "
                            "got %d\n", pl);
                break;
            }
            printf("    Power on minutes when error detected: ");
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf("%d [%d:%d]\n", j, (j / 60), (j % 60));
            j = (ucp[8] >> 4) & 0xf;
            if (j <
                (int)(sizeof(reassign_status) / sizeof(reassign_status[0])))
                printf("    %s\n", reassign_status[j]);
            else
                printf("    Reassign status: reserved [0x%x]\n", j);
            printf("    sense key: %s  [sk,asc,ascq: 0x%x,0x%x,0x%x]\n",
                   sg_get_sense_key_str(ucp[8] & 0xf, sizeof(str), str),
                   ucp[8] & 0xf, ucp[9], ucp[10]);
            printf("      %s\n", sg_get_asc_ascq_str(ucp[9], ucp[10],
                                                     sizeof(str), str));
            if (verbose) {
                printf("    vendor bytes [11 -> 15]: ");
                for (m = 0; m < 5; ++m)
                    printf("0x%02x ", ucp[11 + m]);
                printf("\n");
            }
            printf("    LBA (associated with medium error): 0x");
            for (m = 0; m < 8; ++m)
                printf("%02x", ucp[16 + m]);
            printf("\n");
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

static void
show_sequential_access_page(unsigned char * resp, int len, int show_pcb,
                            int verbose)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull, gbytes;
    char pcb_str[PCB_STR_LEN];

    printf("Sequential access device page (ssc-3)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        gbytes = ull / 1000000000;
        switch (pc) {
        case 0:
            printf("  Data bytes received with WRITE commands: %" PRIu64
                   " GB", gbytes);
            if (verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 1:
            printf("  Data bytes written to media by WRITE commands: %" PRIu64
                   " GB", gbytes);
            if (verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 2:
            printf("  Data bytes read from media by READ commands: %" PRIu64
                   " GB", gbytes);
            if (verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 3:
            printf("  Data bytes transferred by READ commands: %" PRIu64
                   " GB", gbytes);
            if (verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 4:
            printf("  Native capacity from BOP to EOD: %" PRIu64 " MB\n",
                   ull);
            break;
        case 5:
            printf("  Native capacity from BOP to EW of current partition: "
                   "%" PRIu64 " MB\n", ull);
            break;
        case 6:
            printf("  Minimum native capacity from EW to EOP of current "
                   "partition: %" PRIu64 " MB\n", ull);
            break;
        case 7:
            printf("  Native capacity from BOP to current position: %"
                   PRIu64 " MB\n", ull);
            break;
        case 8:
            printf("  Maximum native capacity in device object buffer: %"
                   PRIu64 " MB\n", ull);
            break;
        case 0x100:
            if (ull > 0)
                printf("  Cleaning action required\n");
            else
                printf("  Cleaning action not required (or completed)\n");
            if (verbose)
                printf("    cleaning value: %" PRIu64 "\n", ull);
            break;
        default:
            if (pc >= 0x8000)
                printf("  Vendor specific parameter [0x%x] value: %" PRIu64
                       "\n", pc, ull);
            else
                printf("  Reserved parameter [0x%x] value: %" PRIu64 "\n",
                       pc, ull);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void
show_device_stats_page(unsigned char * resp, int len, int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    printf("Device statistics page (ssc-3 and adc)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (pc < 0x1000) {
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= xp[j];
            }
            switch (pc) {
            case 0:
                printf("  Lifetime media loads: %" PRIu64 "\n", ull);
                break;
            case 1:
                printf("  Lifetime cleaning operations: %" PRIu64 "\n", ull);
                break;
            case 2:
                printf("  Lifetime power on hours: %" PRIu64 "\n", ull);
                break;
            case 3:
                printf("  Lifetime media motion (head) hours: %" PRIu64 "\n",
                       ull);
                break;
            case 4:
                printf("  Lifetime metres of tape processed: %" PRIu64 "\n",
                       ull);
                break;
            case 5:
                printf("  Lifetime media motion (head) hours when "
                       "incompatible media last loaded: %" PRIu64 "\n", ull);
                break;
            case 6:
                printf("  Lifetime power on hours when last temperature "
                       "condition occurred: %" PRIu64 "\n", ull);
                break;
            case 7:
                printf("  Lifetime power on hours when last power "
                       "consumption condition occurred: %" PRIu64 "\n", ull);
                break;
            case 8:
                printf("  Media motion (head) hours since last successful "
                       "cleaning operation: %" PRIu64 "\n", ull);
                break;
            case 9:
                printf("  Media motion (head) hours since 2nd to last "
                       "successful cleaning: %" PRIu64 "\n", ull);
                break;
            case 0xa:
                printf("  Media motion (head) hours since 3rd to last "
                       "successful cleaning: %" PRIu64 "\n", ull);
                break;
            case 0xb:
                printf("  Lifetime power on hours when last operator "
                       "initiated forced reset\n    and/or emergency "
                       "eject occurred: %" PRIu64 "\n", ull);
                break;
            default:
                printf("  Reserved parameter [0x%x] value: %" PRIu64 "\n",
                       pc, ull);
                break;
            }
        } else {
            switch (pc) {
            case 0x1000:
                printf("  Media motion (head) hours for each medium type:\n");
                printf("      <<to be decoded, dump in hex for now>>:\n");
                dStrHex((const char *)ucp, pl, 0);
                break;
            default:
                printf("  Reserved parameter [0x%x], dump in hex:\n", pc);
                dStrHex((const char *)ucp, pl, 0);
                break;
            }
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void
show_media_stats_page(unsigned char * resp, int len, int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    printf("Media statistics page (smc-3)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        switch (pc) {
        case 0:
            printf("  Number of moves: %" PRIu64 "\n", ull);
            break;
        case 1:
            printf("  Number of picks: %" PRIu64 "\n", ull);
            break;
        case 2:
            printf("  Number of pick retries: %" PRIu64 "\n", ull);
            break;
        case 3:
            printf("  Number of places: %" PRIu64 "\n", ull);
            break;
        case 4:
            printf("  Number of place retries: %" PRIu64 "\n", ull);
            break;
        case 5:
            printf("  Number of volume tags read by volume "
                   "tag reader: %" PRIu64 "\n", ull);
            break;
        case 6:
            printf("  Number of invalid volume tags returned by "
                   "volume tag reader: %" PRIu64 "\n", ull);
            break;
        case 7:
            printf("  Number of library door opens: %" PRIu64 "\n", ull);
            break;
        case 8:
            printf("  Number of import/export door opens: %" PRIu64 "\n",
                   ull);
            break;
        case 9:
            printf("  Number of physical inventory scans: %" PRIu64 "\n",
                   ull);
            break;
        case 0xa:
            printf("  Number of medium transport unrecovered errors: "
                   "%" PRIu64 "\n", ull);
            break;
        case 0xb:
            printf("  Number of medium transport recovered errors: "
                   "%" PRIu64 "\n", ull);
            break;
        case 0xc:
            printf("  Number of medium transport X axis translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0xd:
            printf("  Number of medium transport X axis translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0xe:
            printf("  Number of medium transport Y axis translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0xf:
            printf("  Number of medium transport Y axis translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x10:
            printf("  Number of medium transport Z axis translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x11:
            printf("  Number of medium transport Z axis translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x12:
            printf("  Number of medium transport rotational translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x13:
            printf("  Number of medium transport rotational translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x14:
            printf("  Number of medium transport inversion translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x15:
            printf("  Number of medium transport inversion translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x16:
            printf("  Number of medium transport auxiliary translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x17:
            printf("  Number of medium transport auxiliary translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        default:
            printf("  Reserved parameter [0x%x] value: %" PRIu64 "\n",
                   pc, ull);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void
show_element_stats_page(unsigned char * resp, int len, int show_pcb)
{
    int num, pl, pc, pcb;
    unsigned int v;
    unsigned char * ucp;
    char str[PCB_STR_LEN];

    printf("Element statistics page (smc-3) [0x15]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        printf("  Element address: %d\n", pc);
        v = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
        printf("    Number of places: %u\n", v);
        v = (ucp[8] << 24) + (ucp[9] << 16) + (ucp[10] << 8) + ucp[11];
        printf("    Number of place retries: %u\n", v);
        v = (ucp[12] << 24) + (ucp[13] << 16) + (ucp[14] << 8) + ucp[15];
        printf("    Number of picks: %u\n", v);
        v = (ucp[16] << 24) + (ucp[17] << 16) + (ucp[18] << 8) + ucp[19];
        printf("    Number of pick retries: %u\n", v);
        v = (ucp[20] << 24) + (ucp[21] << 16) + (ucp[22] << 8) + ucp[23];
        printf("    Number of determined volume identifiers: %u\n", v);
        v = (ucp[24] << 24) + (ucp[25] << 16) + (ucp[26] << 8) + ucp[27];
        printf("    Number of unreadable volume identifiers: %u\n", v);
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

static void
show_mchanger_diag_data_page(unsigned char * resp, int len, int show_pcb)
{
    int num, pl, pc, pcb;
    unsigned int v;
    unsigned char * ucp;
    char str[PCB_STR_LEN];

    printf("Media changer diagnostics data page (smc-3) [0x16]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        printf("  Parameter code: %d\n", pc);
        printf("    Repeat: %d\n", !!(ucp[5] & 0x80));
        printf("    Sense key: 0x%x\n", ucp[5] & 0xf);
        printf("    Additional sense code: 0x%x\n", ucp[6]);
        printf("    Additional sense code qualifier: 0x%x\n", ucp[7]);
        v = (ucp[8] << 24) + (ucp[9] << 16) + (ucp[10] << 8) + ucp[11];
        printf("    Vendor specific code qualifier: 0x%x\n", v);
        v = (ucp[12] << 24) + (ucp[13] << 16) + (ucp[14] << 8) + ucp[15];
        printf("    Product revision level: %u\n", v);
        v = (ucp[16] << 24) + (ucp[17] << 16) + (ucp[18] << 8) + ucp[19];
        printf("    Number of moves: %u\n", v);
        v = (ucp[20] << 24) + (ucp[21] << 16) + (ucp[22] << 8) + ucp[23];
        printf("    Number of pick: %u\n", v);
        v = (ucp[24] << 24) + (ucp[25] << 16) + (ucp[26] << 8) + ucp[27];
        printf("    Number of pick retries: %u\n", v);
        v = (ucp[28] << 24) + (ucp[29] << 16) + (ucp[30] << 8) + ucp[31];
        printf("    Number of places: %u\n", v);
        v = (ucp[32] << 24) + (ucp[33] << 16) + (ucp[34] << 8) + ucp[35];
        printf("    Number of place retries: %u\n", v);
        v = (ucp[36] << 24) + (ucp[37] << 16) + (ucp[38] << 8) + ucp[39];
        printf("    Number of determined volume identifiers: %u\n", v);
        v = (ucp[40] << 24) + (ucp[41] << 16) + (ucp[42] << 8) + ucp[43];
        printf("    Number of unreadable volume identifiers: %u\n", v);
        printf("    Operation code: 0x%x\n", ucp[44]);
        printf("    Service action: 0x%x\n", ucp[45] & 0xf);
        printf("    Media changer error type: 0x%x\n", ucp[46]);
        printf("    MTAV: %d\n", !!(ucp[47] & 0x8));
        printf("    IAV: %d\n", !!(ucp[47] & 0x4));
        printf("    LSAV: %d\n", !!(ucp[47] & 0x2));
        printf("    DAV: %d\n", !!(ucp[47] & 0x1));
        v = (ucp[48] << 8) + ucp[49];
        printf("    Medium transport address: 0x%x\n", v);
        v = (ucp[50] << 8) + ucp[51];
        printf("    Intial address: 0x%x\n", v);
        v = (ucp[52] << 8) + ucp[53];
        printf("    Last successful address: 0x%x\n", v);
        v = (ucp[54] << 8) + ucp[55];
        printf("    Destination address: 0x%x\n", v);
        if (pl > 91) {
            printf("    Volume tag information:\n");
            dStrHex((const char *)(ucp + 56), 36, 0);
        }
        if (pl > 99) {
            printf("    Timestamp origin: 0x%x\n", ucp[92] & 0xf);
            printf("    Timestamp:\n");
            dStrHex((const char *)(ucp + 94), 6, 1);
        }
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

static char * tape_alert_strs[] = {
    "<parameter code 0, unknown>",              /* 0x0 */
    "Read warning",
    "Write warning",
    "Hard error",
    "Media",
    "Read failure",
    "Write failure",
    "Media life",
    "Not data grade",                           /* 0x8 */
    "Write protect",
    "No removal",
    "Cleaning media",
    "Unsupported format",
    "Recoverable mechanical cartridge failure",
    "Unrecoverable mechanical cartridge failure",
    "Memory chip in cartridge failure",
    "Forced eject",                             /* 0x10 */
    "Read only format",
    "Tape directory corrupted on load",
    "Nearing media life",
    "Cleaning required",
    "Cleaning requested",
    "Expired cleaning media",
    "Invalid cleaning tape",
    "Retension requested",                      /* 0x18 */
    "Dual port interface error",
    "Cooling fan failing",
    "Power supply failure",
    "Power consumption",
    "Drive maintenance",
    "Hardware A",
    "Hardware B",
    "Interface",                                /* 0x20 */
    "Eject media",
    "Microcode update fail",
    "Drive humidity",
    "Drive temperature",
    "Drive voltage",
    "Predictive failure",
    "Diagnostics required",
    "Obsolete (28h)",                           /* 0x28 */
    "Obsolete (29h)",
    "Obsolete (2Ah)",
    "Obsolete (2Bh)",
    "Obsolete (2Ch)",
    "Obsolete (2Dh)",
    "Obsolete (2Eh)",
    "Reserved (2Fh)",
    "Reserved (30h)",                           /* 0x30 */
    "Reserved (31h)",
    "Lost statistics",
    "Tape directory invalid at unload",
    "Tape system area write failure",
    "Tape system area read failure",
    "No start of data",
    "Loading failure",
    "Unrecoverable unload failure",             /* 0x38 */
    "Automation interface failure",
    "Firmware failure",
    "WORM medium - integrity check failed",
    "WORM medium - overwrite attempted",
};

static void
show_tape_alert_ssc_page(unsigned char * resp, int len, int show_pcb,
                         const struct opts_t * optsp)
{
    int num, pl, pc, pcb, flag;
    unsigned char * ucp;
    char str[PCB_STR_LEN];

    /* N.B. the Tape alert log page for smc-3 is different */
    printf("Tape alert page (ssc-3) [0x2e]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        flag = ucp[4] & 1;
        if (optsp->do_verbose && (0 == optsp->do_brief) && flag)
            printf("  >>>> ");
        if ((0 == optsp->do_brief) || optsp->do_verbose || flag) {
            if (pc < (int)(sizeof(tape_alert_strs) /
                           sizeof(tape_alert_strs[0])))
                printf("  %s: %d\n", tape_alert_strs[pc], flag);
            else
                printf("  Reserved parameter code 0x%x, flag: %d\n", pc,
                       flag);
        }
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

static void
show_seagate_cache_page(unsigned char * resp, int len, int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    printf("Seagate cache page [0x37]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0: printf("  Blocks sent to initiator"); break;
        case 1: printf("  Blocks received from initiator"); break;
        case 2:
            printf("  Blocks read from cache and sent to initiator");
            break;
        case 3:
            printf("  Number of read and write commands whose size "
                   "<= segment size");
            break;
        case 4:
            printf("  Number of read and write commands whose size "
                   "> segment size"); break;
        default: printf("  Unknown Seagate parameter code = 0x%x", pc); break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %" PRIu64 "", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void
show_seagate_factory_page(unsigned char * resp, int len, int show_pcb)
{
    int k, j, num, pl, pc, pcb, valid;
    unsigned char * ucp;
    unsigned char * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    printf("Seagate/Hitachi factory page [0x3e]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        valid = 1;
        switch (pc) {
        case 0: printf("  number of hours powered up"); break;
        case 8: printf("  number of minutes until next internal SMART test");
            break;
        default:
            valid = 0;
            printf("  Unknown Seagate/Hitachi parameter code = 0x%x", pc);
            break;
        }
        if (valid) {
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= xp[j];
            }
            if (0 == pc)
                printf(" = %.2f", ((double)ull) / 60.0 );
            else
                printf(" = %" PRIu64 "", ull);
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void
show_ascii_page(unsigned char * resp, int len,
                struct sg_simple_inquiry_resp * inq_dat,
                const struct opts_t * optsp)
{
    int k, num, done, pg_code, subpg_code, spf;

    if (len < 0) {
        printf("response has bad length\n");
        return;
    }
    num = len - 4;
    done = 1;
    spf = !!(resp[0] & 0x40);
    pg_code = resp[0] & 0x3f;
    subpg_code = spf ? resp[1] : 0;

    if ((SUPP_PAGES_LPAGE != pg_code ) && (SUPP_SPGS_SUBPG == subpg_code)) {
        printf("Supported subpages for log page=0x%x\n", pg_code);
        for (k = 0; k < num; k += 2)
            show_page_name((int)resp[4 + k], (int)resp[4 + k + 1],
                           inq_dat);
        return;
    }
    switch (pg_code) {
    case SUPP_PAGES_LPAGE:      /* 0x0 */
        if (spf) {
            printf("Supported log pages and subpages:\n");
            for (k = 0; k < num; k += 2)
                show_page_name((int)resp[4 + k], (int)resp[4 + k + 1],
                               inq_dat);
        } else {
            printf("Supported log pages:\n");
            for (k = 0; k < num; ++k)
                show_page_name((int)resp[4 + k], 0, inq_dat);
        }
        break;
    case BUFF_OVER_UNDER_LPAGE: /* 0x1 */
        show_buffer_under_overrun_page(resp, len, optsp->do_pcb);
        break;
    case WRITE_ERR_LPAGE:       /* 0x2 */
    case READ_ERR_LPAGE:        /* 0x3 */
    case READ_REV_ERR_LPAGE:    /* 0x4 */
    case VERIFY_ERR_LPAGE:      /* 0x5 */
        show_error_counter_page(resp, len, optsp->do_pcb);
        break;
    case NON_MEDIUM_LPAGE:      /* 0x6 */
        show_non_medium_error_page(resp, len, optsp->do_pcb);
        break;
    case LAST_N_ERR_LPAGE:      /* 0x7 */
        show_last_n_error_page(resp, len, optsp->do_pcb);
        break;
    case FORMAT_STATUS_LPAGE:   /* 0x8 */
        {
            switch (inq_dat->peripheral_type) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_RBC:
                /* disk (direct access) type devices */
                show_format_status_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case LAST_N_DEFERRED_LPAGE: /* 0xb */
        show_last_n_deferred_error_page(resp, len, optsp->do_pcb);
        break;
    case 0xc:
        {
            switch (inq_dat->peripheral_type) {
            case PDT_DISK: /* LB_PROV_LPAGE */
                show_lb_provisioning_page(resp, len, optsp->do_pcb);
                break;
            case PDT_TAPE: case PDT_PRINTER:
                /* tape and (printer) type devices */
                show_sequential_access_page(resp, len, optsp->do_pcb,
                                            optsp->do_verbose);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case TEMPERATURE_LPAGE:     /* 0xd */
        show_temperature_page(resp, len, optsp->do_pcb, 1, 1);
        break;
    case START_STOP_LPAGE:      /* 0xe */
        show_start_stop_page(resp, len, optsp->do_pcb, optsp->do_verbose);
        break;
    case SELF_TEST_LPAGE:       /* 0x10 */
        show_self_test_page(resp, len, optsp->do_pcb);
        break;
    case SOLID_STATE_MEDIA_LPAGE:       /* 0x11 */
        show_solid_state_media_page(resp, len, optsp->do_pcb);
        break;
    case 0x14:
        {
            switch (inq_dat->peripheral_type) {
            case PDT_TAPE: case PDT_ADC:
                /* tape and adc type devices */
                show_device_stats_page(resp, len, optsp->do_pcb);
                break;
            case PDT_MCHANGER: /* smc-3 */
                show_media_stats_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x15:
        {
            switch (inq_dat->peripheral_type) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_RBC:
                /* disk (direct access) type devices */
                show_background_scan_results_page(resp, len, optsp->do_pcb,
                                                  optsp->do_verbose);
                break;
            case PDT_MCHANGER: /* smc-3 */
                show_element_stats_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case SAT_ATA_RESULTS_LPAGE:         /* 0x16 */
        {
            switch (inq_dat->peripheral_type) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_RBC:
                /* disk (direct access) type devices */
                show_ata_pt_results_page(resp, len, optsp->do_pcb);
                break;
            case PDT_MCHANGER: /* smc-3 */
                show_mchanger_diag_data_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x17:
        {
            switch (inq_dat->peripheral_type) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_RBC:
                /* disk (direct access) type devices */
                show_non_volatile_cache_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case PROTO_SPECIFIC_LPAGE:
        done = show_protocol_specific_page(resp, len, optsp);
        break;
    case STATS_LPAGE: /* defined for subpages 0 to 32 inclusive */
        if (subpg_code <= HIGH_GRP_STATS_SUBPG)
            done = show_stats_perform_page(resp, len, optsp);
        else if (subpg_code == CACHE_STATS_SUBPG)
            done = show_cache_stats_page(resp, len, optsp);
        else
            done = 0;
        break;
    case PCT_LPAGE:
        show_power_condition_transitions_page(resp, len, optsp->do_pcb);
        break;
    case TAPE_ALERT_LPAGE:
        {
            switch (inq_dat->peripheral_type) {
            case PDT_TAPE:     /* ssc only */
                show_tape_alert_ssc_page(resp, len, optsp->do_pcb, optsp);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x30:
        show_tape_usage_log_page(resp, len, optsp->do_pcb);
        break;
    case 0x31:
        show_tape_capacity_log_page(resp, len, optsp->do_pcb);
        break;
    case 0x32:
        show_data_compression_log_page(resp, len, optsp->do_pcb);
        break;
    case IE_LPAGE:
        show_ie_page(resp, len, optsp->do_pcb, 1);
        break;
    case 0x37:
        {
            switch (inq_dat->peripheral_type) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_RBC:
                /* disk (direct access) type devices */
                show_seagate_cache_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x3e:
        {
            switch (inq_dat->peripheral_type) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_RBC:
                /* disk (direct access) type devices */
                show_seagate_factory_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    default:
        done = 0;
        break;
    }
    if (! done) {
        printf("No ascii information for page = 0x%x, here is hex:\n",
               resp[0] & 0x3f);
        if (len > 128) {
            dStrHex((const char *)resp, 64, 1);
            printf(" .....  [truncated after 64 of %d bytes (use '-H' to "
                   "see the rest)]\n", len);
        }
        else
            dStrHex((const char *)resp, len, 1);
    }
}

static int
fetchTemperature(int sg_fd, unsigned char * resp, int max_len,
                 struct opts_t * optsp)
{
    int len;
    int res = 0;

    optsp->pg_code = TEMPERATURE_LPAGE;
    optsp->subpg_code = NOT_SPG_SUBPG;
    res = do_logs(sg_fd, resp, max_len, optsp);
    if (0 == res) {
        len = (resp[2] << 8) + resp[3] + 4;
        if (optsp->do_raw)
            dStrRaw((const char *)resp, len);
        else if (optsp->do_hex)
            dStrHex((const char *)resp, len, (1 == optsp->do_hex));
        else
            show_temperature_page(resp, len, optsp->do_pcb, 0, 0);
    }else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "Device not ready\n");
    else {
        optsp->pg_code = IE_LPAGE;
        res = do_logs(sg_fd, resp, max_len, optsp);
        if (0 == res) {
            len = (resp[2] << 8) + resp[3] + 4;
            if (optsp->do_raw)
                dStrRaw((const char *)resp, len);
            else if (optsp->do_hex)
                dStrHex((const char *)resp, len, (1 == optsp->do_hex));
            else
                show_ie_page(resp, len, 0, 0);
        } else
            fprintf(stderr, "Unable to find temperature in either log page "
                    "(temperature or IE)\n");
    }
    sg_cmds_close_device(sg_fd);
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}


int
main(int argc, char * argv[])
{
    int sg_fd, k, pg_len, res, resp_len;
    int ret = 0;
    struct sg_simple_inquiry_resp inq_out;
    struct opts_t opts;

    memset(&opts, 0, sizeof(opts));
    memset(rsp_buff, 0, sizeof(rsp_buff));
    /* N.B. some disks only give data for current cumulative */
    opts.page_control = 1;
    res = process_cl(&opts, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (opts.do_help) {
        usage_for(&opts);
        return 0;
    }
    if (opts.do_version) {
        fprintf(stderr, "Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == opts.device_name) {
        fprintf(stderr, "No DEVICE argument given\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = sg_cmds_open_device(opts.device_name, 0 /* rw */,
                                     opts.do_verbose)) < 0) {
        if ((sg_fd = sg_cmds_open_device(opts.device_name, 1 /* r0 */,
                                         opts.do_verbose)) < 0) {
            fprintf(stderr, "error opening file: %s: %s \n",
                    opts.device_name, safe_strerror(-sg_fd));
            return SG_LIB_FILE_ERROR;
        }
    }
    if (opts.do_list || opts.do_all) {
        opts.pg_code = SUPP_PAGES_LPAGE;
        if ((opts.do_list > 1) || (opts.do_all > 1))
            opts.subpg_code = SUPP_SPGS_SUBPG;
    }
    if (opts.do_transport) {
        if ((opts.pg_code > 0) || (opts.subpg_code > 0) ||
            opts.do_temperature) {
            fprintf(stderr, "'-T' should not be mixed with options "
                    "implying other pages\n");
            return SG_LIB_FILE_ERROR;
        }
        opts.pg_code = PROTO_SPECIFIC_LPAGE;
    }
    pg_len = 0;

    if (0 == opts.do_raw) {
        if (sg_simple_inquiry(sg_fd, &inq_out, 1, opts.do_verbose)) {
            fprintf(stderr, "%s doesn't respond to a SCSI INQUIRY\n",
                    opts.device_name);
            sg_cmds_close_device(sg_fd);
            return SG_LIB_CAT_OTHER;
        } else if ((0 == opts.do_hex) && (0 == opts.do_name))
            printf("    %.8s  %.16s  %.4s\n", inq_out.vendor,
                   inq_out.product, inq_out.revision);
    } else
        memset(&inq_out, 0, sizeof(inq_out));

    if (1 == opts.do_temperature)
        return fetchTemperature(sg_fd, rsp_buff, SHORT_RESP_LEN, &opts);

    if (opts.do_select) {
        k = sg_ll_log_select(sg_fd, !!(opts.do_pcreset), opts.do_sp,
                             opts.page_control, opts.pg_code, opts.subpg_code,
                             NULL, 0, 1, opts.do_verbose);
        if (k) {
            if (SG_LIB_CAT_NOT_READY == k)
                fprintf(stderr, "log_select: device not ready\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "log_select: field in cdb illegal\n");
            else if (SG_LIB_CAT_INVALID_OP == k)
                fprintf(stderr, "log_select: not supported\n");
            else if (SG_LIB_CAT_UNIT_ATTENTION == k)
                fprintf(stderr, "log_select: unit attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == k)
                fprintf(stderr, "log_select: aborted command\n");
            else
                fprintf(stderr, "log_select: failed (%d), try '-v' for more "
                        "information\n", k);
        }
        return (k >= 0) ?  k : SG_LIB_CAT_OTHER;
    }
    resp_len = (opts.maxlen > 0) ? opts.maxlen : MX_ALLOC_LEN;
    res = do_logs(sg_fd, rsp_buff, resp_len, &opts);
    if (0 == res) {
        pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
        if ((pg_len + 4) > resp_len) {
            printf("Only fetched %d bytes of response (available: %d "
                   "bytes)\n    truncate output\n",
                   resp_len, pg_len + 4);
            pg_len = resp_len - 4;
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "log_sense: not supported\n");
    else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "log_sense: device not ready\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "log_sense: field in cdb illegal\n");
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "log_sense: unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "log_sense: aborted command\n");
    if (0 == opts.do_all) {
        if (opts.do_raw)
            dStrRaw((const char *)rsp_buff, pg_len + 4);
        else if (opts.do_hex > 1)
            dStrHex((const char *)rsp_buff, pg_len + 4, (2 == opts.do_hex));
        else if (pg_len > 1) {
            if (opts.do_hex) {
                if (rsp_buff[0] & 0x40)
                    printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, "
                           "page_len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                           !!(rsp_buff[0] & 0x80), pg_len);
                else
                    printf("Log page code=0x%x, DS=%d, SPF=0, page_len=0x%x\n",
                           rsp_buff[0] & 0x3f, !!(rsp_buff[0] & 0x80), pg_len);
                dStrHex((const char *)rsp_buff, pg_len + 4, 1);
            }
            else
                show_ascii_page(rsp_buff, pg_len + 4, &inq_out, &opts);
        }
    }
    ret = res;

    if (opts.do_all && (pg_len > 1)) {
        int my_len = pg_len;
        int spf;
        unsigned char parr[1024];

        spf = !!(rsp_buff[0] & 0x40);
        if (my_len > (int)sizeof(parr)) {
            fprintf(stderr, "Unexpectedly large page_len=%d, trim to %d\n",
                    my_len, (int)sizeof(parr));
            my_len = sizeof(parr);
        }
        memcpy(parr, rsp_buff + 4, my_len);
        for (k = 0; k < my_len; ++k) {
            if (0 == opts.do_raw)
                printf("\n");
            opts.pg_code = parr[k] & 0x3f;
            if (spf)
                opts.subpg_code = parr[++k];
            else
                opts.subpg_code = NOT_SPG_SUBPG;

            res = do_logs(sg_fd, rsp_buff, resp_len, &opts);
            if (0 == res) {
                pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
                if ((pg_len + 4) > resp_len) {
                    fprintf(stderr, "Only fetched %d bytes of response, "
                            "truncate output\n", resp_len);
                    pg_len = resp_len - 4;
                }
                if (opts.do_raw)
                    dStrRaw((const char *)rsp_buff, pg_len + 4);
                else if (opts.do_hex > 1)
                    dStrHex((const char *)rsp_buff, pg_len + 4,
                            (2 == opts.do_hex));
                else if (opts.do_hex) {
                    if (rsp_buff[0] & 0x40)
                        printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, page_"
                               "len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                               !!(rsp_buff[0] & 0x80), pg_len);
                    else
                        printf("Log page code=0x%x, DS=%d, SPF=0, page_len="
                               "0x%x\n", rsp_buff[0] & 0x3f,
                               !!(rsp_buff[0] & 0x80), pg_len);
                    dStrHex((const char *)rsp_buff, pg_len + 4, 1);
                }
                else
                    show_ascii_page(rsp_buff, pg_len + 4, &inq_out, &opts);
            } else if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, "log_sense: page=0x%x,0x%x not supported\n",
                        opts.pg_code, opts.subpg_code);
            else if (SG_LIB_CAT_NOT_READY == res)
                fprintf(stderr, "log_sense: device not ready\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "log_sense: field in cdb illegal "
                        "[page=0x%x,0x%x]\n", opts.pg_code, opts.subpg_code);
            else if (SG_LIB_CAT_UNIT_ATTENTION == res)
                fprintf(stderr, "log_sense: unit attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                fprintf(stderr, "log_sense: aborted command\n");
            else
                fprintf(stderr, "log_sense: failed, try '-v' for more "
                        "information\n");
        }
    }
    sg_cmds_close_device(sg_fd);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
