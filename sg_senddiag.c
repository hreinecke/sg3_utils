#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2003-2005 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program issues the SCSI SEND DIAGNOSTIC command and in one case
   the SCSI RECEIVE DIAGNOSTIC command to list supported diagnostic pages.
*/

static char * version_str = "0.27 20060106";

#define ME "sg_senddiag: "

#define MX_ALLOC_LEN (1024 * 4)


/* Return of 0 -> success, SG_LIB_CAT_INVALID_OP -> Send diagnostic not
 * supported, SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other
 * failure */
static int do_senddiag(int sg_fd, int sf_code, int pf_bit, int sf_bit,
                       int devofl_bit, int unitofl_bit, void * outgoing_pg, 
                       int outgoing_len, int noisy, int verbose)
{
    int long_duration = 0;

    if ((0 == sf_bit) && ((5 == sf_code) || (6 == sf_code)))
        long_duration = 1;      /* foreground self tests */
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
        k = strspn(inp, "0123456789aAbBcCdDeEfF,");
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
                if (NULL == cp)
                    break;
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
        {0x3f, "Protocol specific SAS (SAS-1)"},
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

static void usage()
{
    printf("Usage: 'sg_senddiag [-doff] [-e] [-h] [-H] [-l] [-pf]"
           " [-raw=<h>,<h>...]\n"
           "                    [-s=<self_test_code>] [-t] [-uoff] [-v] "
           "[-V]\n"
           "                    [<scsi_device>]'\n"
           " where -doff device online (def: 0, only with '-t')\n"
           "       -e   duration of an extended test (from mode page 0xa)\n"
           "       -h   output in hex\n"
           "       -H   output in hex (same as '-h')\n"
           "       -l   list supported page codes\n"
           "       -pf  set PF bit (def: 0)\n"
           "       -raw=<h>,<h>...  sequence of bytes to form diag page to "
           "send\n"
           "       -raw=-           read stdin for sequence of bytes to send\n"
           "       -s=<self_test_code> (def: 0)\n"
           "          1->background short, 2->background extended,"
           " 4->abort test\n"
           "          5->foreground short, 6->foreground extended\n"
           "       -t   default self test\n"
           "       -uoff unit online (def: 0, only with '-t')\n"
           "       -v   increase verbosity (print issued SCSI cmds)\n"
           "       -V   output version string\n"
           "       -?   output this usage message\n\n"
           "Performs a SEND DIAGNOSTIC (and/or a RECEIVE DIAGNOSTIC RESULTS)"
           " SCSI command\n"
        );
}


int main(int argc, char * argv[])
{
    int sg_fd, k, num, rsp_len, plen, jmp_out;
    const char * file_name = 0;
    unsigned char rsp_buff[MX_ALLOC_LEN];
    int rsp_buff_size = MX_ALLOC_LEN;
    unsigned int u;
    int self_test_code = 0;
    int do_pf = 0;
    int do_doff = 0;
    int do_hex = 0;
    int do_list = 0;
    int do_def_test = 0;
    int do_uoff = 0;
    int do_ext_time = 0;
    int do_raw = 0;
    int verbose = 0;
    int read_in_len = 0;
    const char * cp;
    unsigned char read_in[MX_ALLOC_LEN];
    int ret = 1;

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
                        do_doff = 1;
                        cp += 3;
                        plen -= 3;
                    } else
                        jmp_out = 1;
                    break;
                case 'e':
                    do_ext_time = 1;
                    break;
                case 'h':
                case 'H':
                    do_hex = 1;
                    break;
                case 'l':
                    do_list = 1;
                    break;
                case 'p':
                    if (0 == strncmp("pf", cp, 2)) {
                        do_pf = 1;
                        ++cp;
                        --plen;
                    } else
                        jmp_out = 1;
                    break;
                case 't':
                    do_def_test = 1;
                    break;
                case 'u':
                    if (0 == strncmp("uoff", cp, 4)) {
                        do_uoff = 1;
                        cp += 3;
                        plen -= 3;
                    } else
                        jmp_out = 1;
                    break;
                case 'v':
                    ++verbose;
                    break;
                case 'V':
                    fprintf(stderr, "Version string: %s\n", version_str);
                    exit(0);
                case '?':
                    usage();
                    return 1;
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
                if (build_diag_page(cp + 4, read_in, &read_in_len,
                                    sizeof(read_in))) {
                    printf("Bad sequence after 'raw=' option\n");
                    usage();
                    return 1;
                }
                do_raw = 1;
            } else if (0 == strncmp("s=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 7)) {
                    printf("Bad page code after 's=' option\n");
                    usage();
                    return 1;
                }
                self_test_code = u;
            } else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage();
                return 1;
            }
        } else if (0 == file_name)
            file_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", file_name, cp);
            usage();
            return 1;
        }
    }
    
    if ((do_doff || do_uoff) && (! do_def_test)) {
        printf("setting -doff or -uoff only useful when -t is set\n");
        usage();
        return 1;
    }
    if ((self_test_code > 0) && do_def_test) {
        printf("either set -s=<num> or -t (not both)\n");
        usage();
        return 1;
    }
    if (do_raw) {
        if ((self_test_code > 0) || do_def_test || do_ext_time || do_list) {
            printf("'--raw=' cannot be used with self tests, '-e' or "
                   "'-l'\n");
            usage();
            return 1;
        }
        if (! do_pf)
            printf(">>> warning, '-pf' probably should be used with "
                   "'--raw='\n");
    }
    if (0 == file_name) {
        if (do_list) {
            list_page_codes();
            return 0;
        }
        fprintf(stderr, "No <scsi_device> argument given\n");
        usage();
        return 1;
    }

    if ((sg_fd = sg_cmds_open_device(file_name, 0 /* rw */, verbose)) < 0) {
        fprintf(stderr, ME "error opening file: %s: %s\n", file_name,
                safe_strerror(-sg_fd));
        return 1;
    }
    if (do_ext_time) {
        if (0 == do_modes_0a(sg_fd, rsp_buff, 32, 1, 0, verbose)) {
            /* Assume mode sense(10) response without block descriptors */
            num = (rsp_buff[0] << 8) + rsp_buff[1] - 6;
            if (num >= 0xc) {
                int secs;

                secs = (rsp_buff[18] << 8) + rsp_buff[19];
                printf("Expected extended self-test duration=%d seconds "
                       "(%.2f minutes)\n", secs, secs / 60.0);
            } else
                printf("Extended self-test duration not available\n");
        } else {
            printf("Extended self-test duration (mode page 0xa) failed\n");
            goto err_out9;
        }
    } else if (do_list) {
        memset(rsp_buff, 0, sizeof(rsp_buff));
        if (0 == do_senddiag(sg_fd, 0, 1 /* pf */, 0, 0, 0, rsp_buff, 4, 1,
                             verbose)) {
            if (0 == sg_ll_receive_diag(sg_fd, 0, 0, rsp_buff,
                                        rsp_buff_size, 1, verbose)) {
                printf("Supported diagnostic pages response:\n");
                rsp_len = (rsp_buff[2] << 8) + rsp_buff[3] + 4;
                if (do_hex)
                    dStrHex((const char *)rsp_buff, rsp_len, 1);
                else {
                    for (k = 0; k < (rsp_len - 4); ++k) {
                        cp = find_page_code_desc(rsp_buff[k + 4]);
                        printf("  %s\n", (cp ? cp : "<unknown>"));
                    }
                }
            } else {
                fprintf(stderr, "RECEIVE DIAGNOSTIC command failed\n");
                goto err_out9;
            }
        } else
            goto err_out;
    } else if (do_raw) {
        if (do_senddiag(sg_fd, 0, do_pf, 0, 0, 0, read_in, read_in_len, 1,
                        verbose))
            goto err_out;
    } else if (0 == do_senddiag(sg_fd, self_test_code, do_pf, do_def_test,
                                do_doff, do_uoff, NULL, 0, 1, verbose)) {
        if ((5 == self_test_code) || (6 == self_test_code))
            printf("Foreground self test returned GOOD status\n");
        else if (do_def_test && (! do_doff) && (! do_uoff))
            printf("Default self test returned GOOD status\n");
    } else
        goto err_out;
    sg_cmds_close_device(sg_fd);
    return 0;

err_out:
    fprintf(stderr, "SEND DIAGNOSTIC command failed\n");
err_out9:
    if (verbose < 2)
        fprintf(stderr, "  try again with '-vv' for more information\n");
    sg_cmds_close_device(sg_fd);
    return ret;
}
