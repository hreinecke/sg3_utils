/*
 * Copyright (c) 2009-2016 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 * This utility invokes the UNMAP SCSI command to unmap one or more
 * logical blocks.
 */

static const char * version_str = "1.10 20160201";


#define DEF_TIMEOUT_SECS 60
#define MAX_NUM_ADDR 128

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif


static struct option long_options[] = {
        {"anchor", no_argument, 0, 'a'},
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
          "sg_unmap [--anchor] [--grpnum=GN] [--help] [--in=FILE]\n"
          "                [--lba=LBA,LBA...] [--num=NUM,NUM...] "
          "[--timeout=TO]\n"
          "                [--verbose] [--version] DEVICE\n"
          "  where:\n"
          "    --anchor|-a          set anchor field in cdb\n"
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
          "are assumed\n"
          "to be decimal. Use '0x' prefix or 'h' suffix for hex values.\n"
          "Example to unmap LBA 0x12345:\n"
          "    sg_unmap --lba=0x12345 --num=1 /dev/sdb\n"
          );
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
    const char * lcp;
    int64_t ll;
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
build_num_arr(const char * inp, uint32_t * num_arr,
              int * num_arr_len, int max_arr_len)
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
    char line[1024];
    int off = 0;
    int in_len, k, j, m, ind, bit0;
    bool have_stdin;
    char * lcp;
    FILE * fp;
    int64_t ll;

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
    int sg_fd, res, c, num, k, j;
    int grpnum = 0;
    const char * lba_op = NULL;
    const char * num_op = NULL;
    const char * in_op = NULL;
    int addr_arr_len = 0;
    int num_arr_len = 0;
    int anchor = 0;
    int timeout = DEF_TIMEOUT_SECS;
    int verbose = 0;
    const char * device_name = NULL;
    uint64_t addr_arr[MAX_NUM_ADDR];
    uint32_t num_arr[MAX_NUM_ADDR];
    unsigned char param_arr[8 + (MAX_NUM_ADDR * 16)];
    int param_len = 4;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ag:hIHl:n:t:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ++anchor;
            break;
        case 'g':
            num = sscanf(optarg, "%d", &res);
            if ((1 == num) && (res >= 0) && (res <= 31))
                grpnum = res;
            else {
                pr2serr("value for '--grpnum=' must be 0 to 31\n");
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
            ++verbose;
            break;
        case 'V':
            pr2serr("version: %s\n", version_str);
            return 0;
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
    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (in_op && (lba_op || num_op)) {
        pr2serr("expect '--in=' by itself, or both '--lba=' and '--num='\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    } else if (in_op || (lba_op && num_op))
        ;
    else {
        if (lba_op)
            pr2serr("since '--lba=' is given, also need '--num='\n");
        else
            pr2serr("expect either both '--lba=' and '--num=', or "
                    "'--in=' by itself\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

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
            return SG_LIB_SYNTAX_ERROR;
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


    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    res = sg_ll_unmap_v2(sg_fd, anchor, grpnum, timeout, param_arr, param_len,
                         1, verbose);
    ret = res;
    if (SG_LIB_CAT_NOT_READY == res) {
        pr2serr("UNMAP failed, device not ready\n");
        goto err_out;
    } else if (SG_LIB_CAT_UNIT_ATTENTION == res) {
        pr2serr("UNMAP, unit attention\n");
        goto err_out;
    } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
        pr2serr("UNMAP, aborted command\n");
        goto err_out;
    } else if (SG_LIB_CAT_INVALID_OP == res) {
        pr2serr("UNMAP not supported\n");
        goto err_out;
    } else if (SG_LIB_CAT_ILLEGAL_REQ == res) {
        pr2serr("bad field in UNMAP cdb\n");
        goto err_out;
    } else if (0 != res) {
        pr2serr("UNMAP failed (use '-v' to get more information)\n");
        goto err_out;
    }

err_out:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
