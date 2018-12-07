/*
 * Copyright (c) 2009-2018 Douglas Gilbert.
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
#include <limits.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

#if defined(MSC_VER) || defined(__MINGW32__)
#define HAVE_MS_SLEEP
#endif

#ifdef HAVE_MS_SLEEP
#include <windows.h>
#define sleep_for(seconds)    Sleep( (seconds) * 1000)
#else
#define sleep_for(seconds)    sleep(seconds)
#endif

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 * This utility invokes the UNMAP SCSI command to unmap (trim) one or more
 * logical blocks. Note that DATA MAY BE LOST.
 */

static const char * version_str = "1.17 20180628";


#define DEF_TIMEOUT_SECS 60
#define MAX_NUM_ADDR 128
#define RCAP10_RESP_LEN 8
#define RCAP16_RESP_LEN 32

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif


static struct option long_options[] = {
        {"all", required_argument, 0, 'A'},
        {"anchor", no_argument, 0, 'a'},
        {"dry-run", no_argument, 0, 'd'},
        {"dry_run", no_argument, 0, 'd'},
        {"force", no_argument, 0, 'f'},
        {"grpnum", required_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"in", required_argument, 0, 'I'},
        {"lba", required_argument, 0, 'l'},
        {"num", required_argument, 0, 'n'},
        {"timeout", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
          "sg_unmap [--all=ST,RN[,LA]] [--anchor] [--dry-run] [--force]\n"
          "                [--grpnum=GN] [--help] [--in=FILE] "
          "[--lba=LBA,LBA...]\n"
          "                [--num=NUM,NUM...] [--timeout=TO] [--verbose] "
          "[--version]\n"
          "                DEVICE\n"
          "  where:\n"
          "    --all=ST,RN[,LA]|-A ST,RN[,LA]    start unmaps at LBA ST, "
          "RN blocks\n"
          "                         per unmap until the end of disk, or "
          "until\n"
          "                         and including LBA LA (last)\n"
          "    --anchor|-a          set anchor field in cdb\n"
          "    --dry-run|-d         prepare but skip UNMAP call(s)\n"
          "    --force|-f           don't ask for confirmation before "
          "zapping media\n"
          "    --grpnum=GN|-g GN    GN is group number field (def: 0)\n"
          "    --help|-h            print out usage message\n"
          "    --in=FILE|-I FILE    read LBA, NUM pairs from FILE (if "
          "FILE is '-'\n"
          "                         then stdin is read)\n"
          "    --lba=LBA,LBA...|-l LBA,LBA...    LBA is the logical block "
          "address\n"
          "                                      to start NUM unmaps\n"
          "    --num=NUM,NUM...|-n NUM,NUM...    NUM is number of logical "
          "blocks to\n"
          "                                      unmap starting at "
          "corresponding LBA\n"
          "    --timeout=TO|-t TO    command timeout (unit: seconds) "
          "(def: 60)\n"
          "    --verbose|-v         increase verbosity\n"
          "    --version|-V         print version string and exit\n\n"
          "Perform a SCSI UNMAP command. LBA, NUM and the values in FILE "
          "are assumed\nto be decimal. Use '0x' prefix or 'h' suffix for "
          "hex values.\n"
          "Example to unmap LBA 0x12345:\n"
          "    sg_unmap --lba=0x12345 --num=1 /dev/sdb\n"
          "Example to unmap starting at LBA 0x12345, 256 blocks per command:"
          "\n    sg_unmap --all=0x12345,256 /dev/sg2\n"
          "until the end if /dev/sg2 (assumed to be a storage device)\n\n"
          );
    pr2serr("WARNING: This utility will destroy data on DEVICE in the given "
            "range(s)\nthat will be unmapped. Unmap is also known as 'trim' "
            "and is irreversible.\n");
}

/* Read numbers (up to 64 bits in size) from command line (comma (or
 * (single) space) separated list). Assumed decimal unless prefixed
 * by '0x', '0X' or contains trailing 'h' or 'H' (which indicate hex).
 * Returns 0 if ok, or 1 if error. */
static int
build_lba_arr(const char * inp, uint64_t * lba_arr, int * lba_arr_len,
              int max_arr_len)
{
    int in_len, k;
    int64_t ll;
    const char * lcp;
    char * cp;
    char * c2p;

    if ((NULL == inp) || (NULL == lba_arr) ||
        (NULL == lba_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *lba_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        pr2serr("'--lba' cannot be read from stdin\n");
        return 1;
    } else {        /* list of numbers (default decimal) on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP, ");
        if (in_len != k) {
            pr2serr("build_lba_arr: error at pos %d\n", k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                lba_arr[k] = (uint64_t)ll;
                cp = (char *)strchr(lcp, ',');
                c2p = (char *)strchr(lcp, ' ');
                if (NULL == cp)
                    cp = c2p;
                if (NULL == cp)
                    break;
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                pr2serr("build_lba_arr: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *lba_arr_len = k + 1;
        if (k == max_arr_len) {
            pr2serr("build_lba_arr: array length exceeded\n");
            return 1;
        }
    }
    return 0;
}

/* Read numbers (up to 32 bits in size) from command line (comma (or
 * (single) space) separated list). Assumed decimal unless prefixed
 * by '0x', '0X' or contains trailing 'h' or 'H' (which indicate hex).
 * Returns 0 if ok, or 1 if error. */
static int
build_num_arr(const char * inp, uint32_t * num_arr, int * num_arr_len,
              int max_arr_len)
{
    int in_len, k;
    const char * lcp;
    int64_t ll;
    char * cp;
    char * c2p;

    if ((NULL == inp) || (NULL == num_arr) ||
        (NULL == num_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *num_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        pr2serr("'--len' cannot be read from stdin\n");
        return 1;
    } else {        /* list of numbers (default decimal) on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP, ");
        if (in_len != k) {
            pr2serr("build_num_arr: error at pos %d\n", k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                if (ll > UINT32_MAX) {
                    pr2serr("build_num_arr: number exceeds 32 bits at pos "
                            "%d\n", (int)(lcp - inp + 1));
                    return 1;
                }
                num_arr[k] = (uint32_t)ll;
                cp = (char *)strchr(lcp, ',');
                c2p = (char *)strchr(lcp, ' ');
                if (NULL == cp)
                    cp = c2p;
                if (NULL == cp)
                    break;
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                pr2serr("build_num_arr: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *num_arr_len = k + 1;
        if (k == max_arr_len) {
            pr2serr("build_num_arr: array length exceeded\n");
            return 1;
        }
    }
    return 0;
}


/* Read numbers from filename (or stdin) line by line (comma (or
 * (single) space) separated list). Assumed decimal unless prefixed
 * by '0x', '0X' or contains trailing 'h' or 'H' (which indicate hex).
 * Returns 0 if ok, or 1 if error. */
static int
build_joint_arr(const char * file_name, uint64_t * lba_arr, uint32_t * num_arr,
                int * arr_len, int max_arr_len)
{
    bool have_stdin;
    int off = 0;
    int in_len, k, j, m, ind, bit0;
    int64_t ll;
    char line[1024];
    char * lcp;
    FILE * fp;

    have_stdin = ((1 == strlen(file_name)) && ('-' == file_name[0]));
    if (have_stdin)
        fp = stdin;
    else {
        fp = fopen(file_name, "r");
        if (NULL == fp) {
            pr2serr("%s: unable to open %s\n", __func__, file_name);
            return 1;
        }
    }

    for (j = 0; j < 512; ++j) {
        if (NULL == fgets(line, sizeof(line), fp))
            break;
        // could improve with carry_over logic if sizeof(line) too small
        in_len = strlen(line);
        if (in_len > 0) {
            if ('\n' == line[in_len - 1]) {
                --in_len;
                line[in_len] = '\0';
            }
        }
        if (in_len < 1)
            continue;
        lcp = line;
        m = strspn(lcp, " \t");
        if (m == in_len)
            continue;
        lcp += m;
        in_len -= m;
        if ('#' == *lcp)
            continue;
        k = strspn(lcp, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP ,\t");
        if ((k < in_len) && ('#' != lcp[k])) {
            pr2serr("%s: syntax error at line %d, pos %d\n", __func__, j + 1,
                    m + k + 1);
            goto bad_exit;
        }
        for (k = 0; k < 1024; ++k) {
            ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                ind = ((off + k) >> 1);
                bit0 = 0x1 & (off + k);
                if (ind >= max_arr_len) {
                    pr2serr("%s: array length exceeded\n", __func__);
                    goto bad_exit;
                }
                if (bit0) {
                    if (ll > UINT32_MAX) {
                        pr2serr("%s: number exceeds 32 bits in line %d, at "
                                "pos %d\n", __func__, j + 1,
                                (int)(lcp - line + 1));
                        goto bad_exit;
                    }
                    num_arr[ind] = (uint32_t)ll;
                } else
                   lba_arr[ind] = (uint64_t)ll;
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
                pr2serr("%s: error on line %d, at pos %d\n", __func__, j + 1,
                        (int)(lcp - line + 1));
                goto bad_exit;
            }
        }
        off += (k + 1);
    }
    if (0x1 & off) {
        pr2serr("%s: expect LBA,NUM pairs but decoded odd number\n  from "
                "%s\n", __func__, have_stdin ? "stdin" : file_name);
        goto bad_exit;
    }
    *arr_len = off >> 1;
    if (fp && (stdin != fp))
        fclose(fp);
    return 0;

bad_exit:
    if (fp && (stdin != fp))
        fclose(fp);
    return 1;
}


int
main(int argc, char * argv[])
{
    bool anchor = false;
    bool do_force = false;
    bool dry_run = false;
    bool err_printed = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c, num, k, j;
    int sg_fd = -1;
    int grpnum = 0;
    int addr_arr_len = 0;
    int num_arr_len = 0;
    int param_len = 4;
    int ret = 0;
    int timeout = DEF_TIMEOUT_SECS;
    int vb = 0;
    uint32_t all_rn = 0;        /* Repetition Number, 0 for inactive */
    uint64_t all_start = 0;
    uint64_t all_last = 0;
    int64_t ll;
    const char * lba_op = NULL;
    const char * num_op = NULL;
    const char * in_op = NULL;
    const char * device_name = NULL;
    char * first_comma = NULL;
    char * second_comma = NULL;
    struct sg_simple_inquiry_resp inq_resp;
    uint64_t addr_arr[MAX_NUM_ADDR];
    uint32_t num_arr[MAX_NUM_ADDR];
    uint8_t param_arr[8 + (MAX_NUM_ADDR * 16)];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aA:dfg:hI:Hl:n:t:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            anchor = true;
            break;
        case 'A':
            first_comma = strchr(optarg, ',');
            if (NULL == first_comma) {
                pr2serr("--all=ST,RN[,LA] expects at least one comma in "
                        "argument, found none\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ll = sg_get_llnum(optarg);
            if (ll < 0) {
                pr2serr("unable to decode --all=ST,.... (starting LBA)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            all_start = (uint64_t)ll;
            ll = sg_get_llnum(first_comma + 1);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("unable to decode --all=ST,RN.... (repeat number)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            all_rn = (uint32_t)ll;
            if (0 == ll)
                pr2serr("warning: --all=ST,RN... being ignored because RN "
                        "is 0\n");
            second_comma = strchr(first_comma + 1, ',');
            if (second_comma) {
                ll = sg_get_llnum(second_comma + 1);
                if (ll < 0) {
                    pr2serr("unable to decode --all=ST,NR,LA (last LBA)\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                all_last = (uint64_t)ll;
            }
            break;
        case 'd':
            dry_run = true;
            break;
        case 'f':
            do_force = true;
            break;
        case 'g':
            num = sscanf(optarg, "%d", &res);
            if ((1 == num) && (res >= 0) && (res <= 63))
                grpnum = res;
            else {
                pr2serr("value for '--grpnum=' must be 0 to 63\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'I':
            in_op = optarg;
            break;
        case 'l':
            lba_op = optarg;
            break;
        case 'n':
            num_op = optarg;
            break;
        case 't':
            timeout = sg_get_num(optarg);
            if (timeout < 0)  {
                pr2serr("bad argument to '--timeout'\n");
                return SG_LIB_SYNTAX_ERROR;
            } else if (0 == timeout)
                timeout = DEF_TIMEOUT_SECS;
            break;
        case 'v':
            verbose_given = true;
            ++vb;
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
        vb = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        vb = 2;
    } else
        pr2serr("keep verbose=%d\n", vb);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (all_rn > 0) {
        if (lba_op || num_op || in_op) {
            pr2serr("Can't have --all= together with --lba=, --num= or "
                    "--in=\n\n");
            usage();
            return SG_LIB_CONTRADICT;
        }
        /* here if --all= looks okay so far */
    } else if (in_op && (lba_op || num_op)) {
        pr2serr("expect '--in=' by itself, or both '--lba=' and "
                "'--num='\n\n");
        usage();
        return SG_LIB_CONTRADICT;
    } else if (in_op || (lba_op && num_op))
        ;
    else {
        if (lba_op)
            pr2serr("since '--lba=' is given, also need '--num='\n\n");
        else
            pr2serr("expect either both '--lba=' and '--num=', or "
                    "'--in=', or '--all='\n\n");
        usage();
        return SG_LIB_CONTRADICT;
    }

    if (all_rn > 0) {
        if ((all_last > 0) && (all_start > all_last)) {
            pr2serr("in --all=ST,RN,LA start address (ST) exceeds last "
                    "address (LA)\n");
            return SG_LIB_CONTRADICT;
        }
    } else {
        memset(addr_arr, 0, sizeof(addr_arr));
        memset(num_arr, 0, sizeof(num_arr));
        addr_arr_len = 0;
        if (lba_op && num_op) {
            if (0 != build_lba_arr(lba_op, addr_arr, &addr_arr_len,
                                   MAX_NUM_ADDR)) {
                pr2serr("bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (0 != build_num_arr(num_op, num_arr, &num_arr_len,
                                   MAX_NUM_ADDR)) {
                pr2serr("bad argument to '--num'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((addr_arr_len != num_arr_len) || (num_arr_len <= 0)) {
                pr2serr("need same number of arguments to '--lba=' "
                        "and '--num=' options\n");
                return SG_LIB_CONTRADICT;
            }
        }
        if (in_op) {
            if (0 != build_joint_arr(in_op, addr_arr, num_arr, &addr_arr_len,
                                     MAX_NUM_ADDR)) {
                pr2serr("bad argument to '--in'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (addr_arr_len <= 0) {
                pr2serr("no addresses found in '--in=' argument, file: %s\n",
                        in_op);
                return SG_LIB_SYNTAX_ERROR;
            }
        }
        param_len = 8 + (16 * addr_arr_len);
        memset(param_arr, 0, param_len);
        k = 8;
        for (j = 0; j < addr_arr_len; ++j) {
            sg_put_unaligned_be64(addr_arr[j], param_arr + k);
            k += 8;
            sg_put_unaligned_be32(num_arr[j], param_arr + k);
            k += 4 + 4;
        }
        k = 0;
        num = param_len - 2;
        sg_put_unaligned_be16((uint16_t)num, param_arr + k);
        k += 2;
        num = param_len - 8;
        sg_put_unaligned_be16((uint16_t)num, param_arr + k);
    }

    sg_fd = sg_cmds_open_device(device_name, false /* rw */, vb);
    if (sg_fd < 0) {
        ret = sg_convert_errno(-sg_fd);
        pr2serr("open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        goto err_out;
    }
    ret = sg_simple_inquiry(sg_fd, &inq_resp, true, vb);

    if (all_rn > 0) {
        bool last_retry;
        bool to_end_of_device = false;
        uint64_t ull;
        uint32_t bump;

        if (0 == all_last) {    /* READ CAPACITY(10 or 16) to find last */
            uint8_t resp_buff[RCAP16_RESP_LEN];

            res = sg_ll_readcap_16(sg_fd, false /* pmi */, 0 /* llba */,
                                   resp_buff, RCAP16_RESP_LEN, true, vb);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                pr2serr("Read capacity(16) unit attention, try again\n");
                res = sg_ll_readcap_16(sg_fd, false, 0, resp_buff,
                                       RCAP16_RESP_LEN, true, vb);
            }
            if (0 == res) {
                if (vb > 3) {
                    pr2serr("Read capacity(16) response:\n");
                    hex2stderr(resp_buff, RCAP16_RESP_LEN, 1);
                }
                all_last = sg_get_unaligned_be64(resp_buff + 0);
            } else if ((SG_LIB_CAT_INVALID_OP == res) ||
                       (SG_LIB_CAT_ILLEGAL_REQ == res)) {
                if (vb)
                    pr2serr("Read capacity(16) not supported, try Read "
                            "capacity(10)\n");
                res = sg_ll_readcap_10(sg_fd, false /* pmi */, 0 /* lba */,
                                       resp_buff, RCAP10_RESP_LEN, true,
                                       vb);
                if (0 == res) {
                    if (vb > 3) {
                        pr2serr("Read capacity(10) response:\n");
                        hex2stderr(resp_buff, RCAP10_RESP_LEN, 1);
                    }
                    all_last = (uint64_t)sg_get_unaligned_be32(resp_buff + 0);
                } else {
                    if (res < 0)
                        res = sg_convert_errno(-res);
                    pr2serr("Read capacity(10) failed\n");
                    ret = res;
                    goto err_out;
                }
            } else {
                if (res < 0)
                    res = sg_convert_errno(-res);
                pr2serr("Read capacity(16) failed\n");
                ret = res;
                goto err_out;
            }
            if (all_start > all_last) {
                pr2serr("after READ CAPACITY the last block (0x%" PRIx64
                        ") less than start address (0x%" PRIx64 ")\n",
                        all_start, all_last);
                ret = SG_LIB_CONTRADICT;
                goto err_out;
            }
            to_end_of_device = true;
        }
        if (! do_force) {
            char b[120];

            printf("%s is:  %.8s  %.16s  %.4s\n", device_name,
                   inq_resp.vendor, inq_resp.product, inq_resp.revision);
            sleep_for(3);
            if (to_end_of_device)
                snprintf(b, sizeof(b), "LBA 0x%" PRIx64 " to end of %s "
                         "(0x%" PRIx64 ")", all_start, device_name, all_last);
            else
                snprintf(b, sizeof(b), "LBA 0x%" PRIx64 " to 0x%" PRIx64
                         " on %s", all_start, all_last, device_name);
            printf("\nAn UNMAP (a.k.a. trim) will commence in 15 seconds\n");
            printf("    ALL data from %s will be LOST\n", b);
            printf("        Press control-C to abort\n");
            sleep_for(5);
            printf("\nAn UNMAP will commence in 10 seconds\n");
            printf("    ALL data from %s will be LOST\n", b);
            printf("        Press control-C to abort\n");
            sleep_for(5);
            printf("\nAn UNMAP (a.k.a. trim) will commence in 5 seconds\n");
            printf("    ALL data from %s will be LOST\n", b);
            printf("        Press control-C to abort\n");
            sleep_for(7);
        }
        if (dry_run) {
            pr2serr("Doing dry-run, would have unmapped from LBA 0x%" PRIx64
                    " to 0x%" PRIx64 "\n    %u blocks per UNMAP command\n",
                    all_start, all_last, all_rn);
           goto err_out;
        }
        last_retry = false;
        param_len = 8 + (16 * 1);
        for (ull = all_start, j = 0; ull <= all_last; ull += bump, ++j) {
            if ((all_last - ull) < all_rn)
                bump = (uint32_t)(all_last + 1 - ull);
            else
                bump = all_rn;
retry:
            memset(param_arr, 0, param_len);
            k = 8;
            sg_put_unaligned_be64(ull, param_arr + k);
            k += 8;
            sg_put_unaligned_be32(bump, param_arr + k);
            k = 0;
            num = param_len - 2;
            sg_put_unaligned_be16((uint16_t)num, param_arr + k);
            k += 2;
            num = param_len - 8;
            sg_put_unaligned_be16((uint16_t)num, param_arr + k);
            ret = sg_ll_unmap_v2(sg_fd, anchor, grpnum, timeout, param_arr,
                                 param_len, true, (vb > 2 ? vb - 2 : 0));
            if (last_retry)
                break;
            if (ret) {
                if ((SG_LIB_LBA_OUT_OF_RANGE == ret) &&
                    ((ull + bump) > all_last)) {
                    pr2serr("Typical end of disk out-of-range, decrement "
                            "count and retry\n");
                    if (bump > 1) {
                        --bump;
                        last_retry = true;
                        goto retry;
                    }  /* if bump==1 can't do last, so we are finished */
                }
                break;
            }
        }       /* end of for loop doing unmaps */
        if (vb)
            pr2serr("Completed %d UNMAP commands\n", j);
    } else {            /* --all= not given */
        if (dry_run) {
            pr2serr("Doing dry-run so here is 'LBA, number_of_blocks' list "
                    "of candidates\n");
            k = 8;
            for (j = 0; j < addr_arr_len; ++j) {
                printf("    0x%" PRIx64 ", 0x%u\n",
                      sg_get_unaligned_be64(param_arr + k),
                      sg_get_unaligned_be32(param_arr + k + 8));
                k += (8 + 4 + 4);
            }
            goto err_out;
        }
        if (! do_force) {
            printf("%s is:  %.8s  %.16s  %.4s\n", device_name,
                   inq_resp.vendor, inq_resp.product, inq_resp.revision);
            sleep_for(3);
            printf("\nAn UNMAP (a.k.a. trim) will commence in 15 seconds\n");
            printf("    Some data will be LOST\n");
            printf("        Press control-C to abort\n");
            sleep_for(5);
            printf("\nAn UNMAP will commence in 10 seconds\n");
            printf("    Some data will be LOST\n");
            printf("        Press control-C to abort\n");
            sleep_for(5);
            printf("\nAn UNMAP (a.k.a. trim) will commence in 5 seconds\n");
            printf("    Some data will be LOST\n");
            printf("        Press control-C to abort\n");
            sleep_for(7);
        }
        res = sg_ll_unmap_v2(sg_fd, anchor, grpnum, timeout, param_arr,
                             param_len, true, vb);
        ret = res;
        err_printed = true;
        switch (ret) {
        case SG_LIB_CAT_NOT_READY:
            pr2serr("UNMAP failed, device not ready\n");
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            pr2serr("UNMAP, unit attention\n");
            break;
        case SG_LIB_CAT_ABORTED_COMMAND:
            pr2serr("UNMAP, aborted command\n");
            break;
        case SG_LIB_CAT_INVALID_OP:
            pr2serr("UNMAP not supported\n");
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            pr2serr("bad field in UNMAP cdb\n");
            break;
        default:
            err_printed = false;
            break;
        }
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
    if ((0 == vb) && (! err_printed)) {
        if (! sg_if_can2stderr("sg_unmap failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
