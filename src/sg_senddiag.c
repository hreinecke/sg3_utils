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

/* A utility program originally written for the Linux OS SCSI subsystem
*  Copyright (C) 2003-2011 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program issues the SCSI SEND DIAGNOSTIC command and in one case
   the SCSI RECEIVE DIAGNOSTIC command to list supported diagnostic pages.
*/

static char * version_str = "0.37 20110607";

#define ME "sg_senddiag: "

#define MX_ALLOC_LEN (1024 * 4)

static struct option long_options[] = {
        {"doff", 0, 0, 'd'},
        {"extdur", 0, 0, 'e'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"list", 0, 0, 'l'},
        {"new", 0, 0, 'N'},
        {"old", 0, 0, 'O'},
        {"pf", 0, 0, 'p'},
        {"raw", 1, 0, 'r'},
        {"selftest", 1, 0, 's'},
        {"test", 0, 0, 't'},
        {"uoff", 0, 0, 'u'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_doff;
    int do_extdur;
    int do_help;
    int do_hex;
    int do_list;
    int do_pf;
    int do_raw;
    int do_selftest;
    int do_deftest;
    int do_uoff;
    int do_verbose;
    int do_version;
    const char * device_name;
    const char * raw_arg;
    int opt_new;
};

static void usage()
{
    printf("Usage: sg_senddiag [--doff] [--extdur] [--help] [--hex] "
           "[--list] [--pf]\n"
           "                   [--raw=H,H...] [--selftest=ST] "
           "[--test] [--uoff]\n"
           "                   [--verbose] [--version] "
           "[DEVICE]\n"
           "  where:\n"
           "    --doff|-d       device online (def: 0, only with '--test')\n"
           "    --extdur|-e     duration of an extended self-test (from mode "
           "page 0xa)\n"
           "    --help|-h       print usage message then exit\n"
           "    --hex|H         output in hex\n"
           "    --list|-l       list supported page codes (with or without "
           "DEVICE)\n"
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
           "    --uoff|-u       unit offline (def: 0, only with '--test')\n"
           "    --verbose|-v    increase verbosity\n"
           "    --version|-V    output version string then exit\n\n"
           "Performs a SCSI SEND DIAGNOSTIC (and/or a RECEIVE DIAGNOSTIC "
           "RESULTS) command\n"
        );
}

static void usage_old()
{
    printf("Usage: sg_senddiag [-doff] [-e] [-h] [-H] [-l] [-pf]"
           " [-raw=H,H...]\n"
           "                   [-s=SF] [-t] [-uoff] [-v] [-V] "
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
           "    -uoff   unit offline (def: 0, only with '-t')\n"
           "    -v      increase verbosity (print issued SCSI cmds)\n"
           "    -V      output version string\n"
           "    -?      output this usage message\n\n"
           "Performs a SCSI SEND DIAGNOSTIC (and/or a RECEIVE DIAGNOSTIC "
           "RESULTS) command\n"
        );
}

static int process_cl_new(struct opts_t * optsp, int argc, char * argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dehHlNOpr:s:tuvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            optsp->do_doff = 1;
            break;
        case 'e':
            optsp->do_extdur = 1;
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
        case 'N':
            break;      /* ignore */
        case 'O':
            optsp->opt_new = 0;
            return 0;
        case 'p':
            optsp->do_pf = 1;
            break;
        case 'r':
            optsp->raw_arg = optarg;
            optsp->do_raw = 1;
            break;
        case 's':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 7)) {
                fprintf(stderr, "bad argument to '--selftest='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->do_selftest = n;
            break;
        case 't':
            optsp->do_deftest = 1;
            break;
        case 'u':
            optsp->do_uoff = 1;
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

static int process_cl_old(struct opts_t * optsp, int argc, char * argv[])
{
    int k, jmp_out, plen, num;
    unsigned int u;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'd':
                    if (0 == strncmp("doff", cp, 4)) {
                        optsp->do_doff = 1;
                        cp += 3;
                        plen -= 3;
                    } else
                        jmp_out = 1;
                    break;
                case 'e':
                    optsp->do_extdur = 1;
                    break;
                case 'h':
                case 'H':
                    ++optsp->do_hex;
                    break;
                case 'l':
                    ++optsp->do_list;
                    break;
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'p':
                    if (0 == strncmp("pf", cp, 2)) {
                        optsp->do_pf = 1;
                        ++cp;
                        --plen;
                    } else
                        jmp_out = 1;
                    break;
                case 't':
                    optsp->do_deftest = 1;
                    break;
                case 'u':
                    if (0 == strncmp("uoff", cp, 4)) {
                        optsp->do_uoff = 1;
                        cp += 3;
                        plen -= 3;
                    } else
                        jmp_out = 1;
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
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("raw=", cp, 4)) {
                optsp->raw_arg = cp + 4;
                optsp->do_raw = 1;
            } else if (0 == strncmp("s=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 7)) {
                    printf("Bad page code after '-s=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->do_selftest = u;
            } else if (0 == strncmp("-old", cp, 5))
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

static int process_cl(struct opts_t * optsp, int argc, char * argv[])
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

/* Return of 0 -> success, otherwise see sg_ll_send_diag() */
static int do_senddiag(int sg_fd, int sf_code, int pf_bit, int sf_bit,
                       int devofl_bit, int unitofl_bit, void * outgoing_pg,
                       int outgoing_len, int noisy, int verbose)
{
    int long_duration = 0;

    if ((0 == sf_bit) && ((5 == sf_code) || (6 == sf_code)))
        long_duration = 1;      /* foreground self-tests */
    return sg_ll_send_diag(sg_fd, sf_code, pf_bit, sf_bit, devofl_bit,
                           unitofl_bit, long_duration, outgoing_pg,
                           outgoing_len, noisy, verbose);
}

/* Get expected extended self-test time from mode page 0xa (for '-e' option) */
static int do_modes_0a(int sg_fd, void * resp, int mx_resp_len, int noisy,
                       int mode6, int verbose)
{
    int res;

    if (mode6)
        res = sg_ll_mode_sense6(sg_fd, 1 /* dbd */, 0 /* pc */, 0xa /* page */,
                                0, resp, mx_resp_len, noisy, verbose);
    else
        res = sg_ll_mode_sense10(sg_fd, 0 /* llbaa */, 1 /* dbd */, 0, 0xa, 0,
                                 resp, mx_resp_len, noisy, verbose);
    if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Mode sense (%s) command not supported\n",
                (mode6 ? "6" : "10"));
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "bad field in Mode sense (%s) command\n",
                (mode6 ? "6" : "10"));
    else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "Mode sense (%s) failed, device not ready\n",
                (mode6 ? "6" : "10"));
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "Mode sense (%s) failed, unit attention\n",
                (mode6 ? "6" : "10"));
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "Mode sense (%s) failed, aborted command\n",
                (mode6 ? "6" : "10"));
    return res;
}

/* Read hex numbers from command line (comma separated list) or from */
/* stdin (one per line, comma separated list or space separated list). */
/* Returns 0 if ok, or 1 if error. */
static int build_diag_page(const char * inp, unsigned char * mp_arr,
                           int * mp_arr_len, int max_arr_len)
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
        char line[512];
        int off = 0;

        for (j = 0; j < 512; ++j) {
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
                fprintf(stderr, "build_diag_page: syntax error at "
                        "line %d, pos %d\n", j + 1, m + k + 1);
                return 1;
            }
            for (k = 0; k < 1024; ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        fprintf(stderr, "build_diag_page: hex number "
                                "larger than 0xff in line %d, pos %d\n",
                                j + 1, (int)(lcp - line + 1));
                        return 1;
                    }
                    if ((off + k) >= max_arr_len) {
                        fprintf(stderr, "build_diag_page: array length "
                                "exceeded\n");
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
                    fprintf(stderr, "build_diag_page: error in "
                            "line %d, at pos %d\n", j + 1,
                            (int)(lcp - line + 1));
                    return 1;
                }
            }
            off += (k + 1);
        }
        *mp_arr_len = off;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF, ");
        if (in_len != k) {
            fprintf(stderr, "build_diag_page: error at pos %d\n", k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    fprintf(stderr, "build_diag_page: hex number larger "
                            "than 0xff at pos %d\n", (int)(lcp - inp + 1));
                    return 1;
                }
                mp_arr[k] = h;
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
                fprintf(stderr, "build_diag_page: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *mp_arr_len = k + 1;
        if (k == max_arr_len) {
            fprintf(stderr, "build_diag_page: array length exceeded\n");
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
};

static const char * find_page_code_desc(int page_num)
{
    int k;
    int num = sizeof(pc_desc_arr) / sizeof(pc_desc_arr[0]);
    const struct page_code_desc * pcdp = &pc_desc_arr[0];

    for (k = 0; k < num; ++k, ++pcdp) {
        if (page_num == pcdp->page_code)
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            return NULL;
    }
    return NULL;
}

static void list_page_codes()
{
    int k;
    int num = sizeof(pc_desc_arr) / sizeof(pc_desc_arr[0]);
    const struct page_code_desc * pcdp = &pc_desc_arr[0];

    printf("Page_Code  Description\n");
    for (k = 0; k < num; ++k, ++pcdp)
        printf(" 0x%02x      %s\n", pcdp->page_code,
               (pcdp->desc ? pcdp->desc : "<unknown>"));
}


int main(int argc, char * argv[])
{
    int sg_fd, k, num, rsp_len, res;
    unsigned char rsp_buff[MX_ALLOC_LEN];
    int rsp_buff_size = MX_ALLOC_LEN;
    int read_in_len = 0;
    const char * cp;
    unsigned char read_in[MX_ALLOC_LEN];
    int ret = 0;
    struct opts_t opts;

    memset(&opts, 0, sizeof(opts));
    res = process_cl(&opts, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (opts.do_help) {
        if (opts.opt_new)
            usage();
        else
            usage_old();
        return 0;
    }
    if (opts.do_version) {
        fprintf(stderr, "Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == opts.device_name) {
        if (opts.do_list) {
            list_page_codes();
            return 0;
        }
        fprintf(stderr, "No DEVICE argument given\n");
        if (opts.opt_new)
            usage();
        else
            usage_old();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.do_raw) {
        if (build_diag_page(opts.raw_arg, read_in, &read_in_len,
                            sizeof(read_in))) {
            if (opts.opt_new) {
                printf("Bad sequence after '--raw=' option\n");
                usage();
            } else {
                printf("Bad sequence after '-raw=' option\n");
                usage_old();
            }
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if ((opts.do_doff || opts.do_uoff) && (! opts.do_deftest)) {
        if (opts.opt_new) {
            printf("setting --doff or --uoff only useful when -t is set\n");
            usage();
        } else {
            printf("setting -doff or -uoff only useful when -t is set\n");
            usage_old();
        }
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((opts.do_selftest > 0) && opts.do_deftest) {
        if (opts.opt_new) {
            printf("either set --selftest=SF or --test (not both)\n");
            usage();
        } else {
            printf("either set -s=SF or -t (not both)\n");
            usage_old();
        }
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.do_raw) {
        if ((opts.do_selftest > 0) || opts.do_deftest || opts.do_extdur ||
            opts.do_list) {
            if (opts.opt_new) {
                printf("'--raw=' cannot be used with self-tests, '-e' or "
                       "'-l'\n");
                usage();
            } else {
                printf("'-raw=' cannot be used with self-tests, '-e' or "
                       "'-l'\n");
                usage_old();
            }
            return SG_LIB_SYNTAX_ERROR;
        }
        if (! opts.do_pf) {
            if (opts.opt_new)
                printf(">>> warning, '--pf' probably should be used with "
                       "'--raw='\n");
            else
                printf(">>> warning, '-pf' probably should be used with "
                       "'-raw='\n");
        }
    }

    if ((sg_fd = sg_cmds_open_device(opts.device_name, 0 /* rw */,
                                     opts.do_verbose)) < 0) {
        fprintf(stderr, ME "error opening file: %s: %s\n", opts.device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (opts.do_extdur) {
        res = do_modes_0a(sg_fd, rsp_buff, 32, 1, 0, opts.do_verbose);
        if (0 == res) {
            /* Assume mode sense(10) response without block descriptors */
            num = (rsp_buff[0] << 8) + rsp_buff[1] - 6;
            if (num >= 0xc) {
                int secs;

                secs = (rsp_buff[18] << 8) + rsp_buff[19];
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
    } else if (opts.do_list) {
        memset(rsp_buff, 0, sizeof(rsp_buff));
        res = do_senddiag(sg_fd, 0, 1 /* pf */, 0, 0, 0, rsp_buff, 4, 1,
                          opts.do_verbose);
        if (0 == res) {
            if (0 == sg_ll_receive_diag(sg_fd, 0, 0, rsp_buff,
                                        rsp_buff_size, 1, opts.do_verbose)) {
                printf("Supported diagnostic pages response:\n");
                rsp_len = (rsp_buff[2] << 8) + rsp_buff[3] + 4;
                if (opts.do_hex)
                    dStrHex((const char *)rsp_buff, rsp_len, 1);
                else {
                    for (k = 0; k < (rsp_len - 4); ++k) {
                        cp = find_page_code_desc(rsp_buff[k + 4]);
                        printf("  0x%02x  %s\n", rsp_buff[k + 4],
                               (cp ? cp : "<unknown>"));
                    }
                }
            } else {
                ret = res;
                fprintf(stderr, "RECEIVE DIAGNOSTIC RESULTS command "
                        "failed\n");
                goto err_out9;
            }
        } else {
            ret = res;
            goto err_out;
        }
    } else if (opts.do_raw) {
        res = do_senddiag(sg_fd, 0, opts.do_pf, 0, 0, 0, read_in,
                          read_in_len, 1, opts.do_verbose);
        if (res) {
            ret = res;
            goto err_out;
        }
    } else {
        res = do_senddiag(sg_fd, opts.do_selftest, opts.do_pf,
                          opts.do_deftest, opts.do_doff, opts.do_uoff, NULL,
                          0, 1, opts.do_verbose);
        if (0 == res) {
            if ((5 == opts.do_selftest) || (6 == opts.do_selftest))
                printf("Foreground self-test returned GOOD status\n");
            else if (opts.do_deftest && (! opts.do_doff) && (! opts.do_uoff))
                printf("Default self-test returned GOOD status\n");
        } else {
            ret = res;
            goto err_out;
        }
    }
    res = sg_cmds_close_device(sg_fd);
    if ((res < 0) && (0 == ret))
        return SG_LIB_SYNTAX_ERROR;
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;

err_out:
    if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "SEND DIAGNOSTIC, unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "SEND DIAGNOSTIC, aborted command\n");
    else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "SEND DIAGNOSTIC, device not "
                "ready\n");
    else
        fprintf(stderr, "SEND DIAGNOSTIC command, failed\n");
err_out9:
    if (opts.do_verbose < 2)
        fprintf(stderr, "  try again with '-vv' for more information\n");
    res = sg_cmds_close_device(sg_fd);
    if ((res < 0) && (0 == ret))
        return SG_LIB_FILE_ERROR;
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
