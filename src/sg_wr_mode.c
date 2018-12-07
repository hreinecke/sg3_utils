/*
 * Copyright (c) 2004-2018 Douglas Gilbert.
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
#include <getopt.h>
#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 * This program writes the given mode page contents to the corresponding
 * mode page on the given device.
 */

static const char * version_str = "1.26 20180628";

#define ME "sg_wr_mode: "

#define MX_ALLOC_LEN 2048
#define SHORT_ALLOC_LEN 252

#define EBUFF_SZ 256


static struct option long_options[] = {
        {"contents", required_argument, 0, 'c'},
        {"dbd", no_argument, 0, 'd'},
        {"force", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"len", required_argument, 0, 'l'},
        {"mask", required_argument, 0, 'm'},
        {"page", required_argument, 0, 'p'},
        {"rtd", no_argument, 0, 'R'},
        {"save", no_argument, 0, 's'},
        {"six", no_argument, 0, '6'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_wr_mode [--contents=H,H...] [--dbd] [--force] "
            "[--help]\n"
            "                  [--len=10|6] [--mask=M,M...] "
            "[--page=PG_H[,SPG_H]]\n"
            "                  [--rtd] [--save] [--six] [--verbose] "
            "[--version]\n"
            "                  DEVICE\n"
            "  where:\n"
            "    --contents=H,H... | -c H,H...    comma separated string "
            "of hex numbers\n"
            "                                     that is mode page contents "
            "to write\n"
            "    --contents=- | -c -   read stdin for mode page contents"
            " to write\n"
            "    --dbd | -d            disable block descriptors (DBD bit"
            " in cdb)\n"
            "    --force | -f          force the contents to be written\n"
            "    --help | -h           print out usage message\n"
            "    --len=10|6 | -l 10|6    use 10 byte (def) or 6 byte "
            "variants of\n"
            "                            SCSI MODE SENSE/SELECT commands\n"
            "    --mask=M,M... | -m M,M...   comma separated "
            "string of hex\n"
            "                                numbers that mask contents"
            " to write\n"
            "    --page=PG_H | -p PG_H     page_code to be written (in hex)\n"
            "    --page=PG_H,SPG_H | -p PG_H,SPG_H    page and subpage code "
            "to be\n"
            "                                         written (in hex)\n"
            "    --rtd | -R            set RTD bit (revert to defaults) in "
            "cdb\n"
            "    --save | -s           set 'save page' (SP) bit; default "
            "don't so\n"
            "                          only 'current' values changed\n"
            "    --six | -6            do SCSI MODE SENSE/SELECT(6) "
            "commands\n"
            "    --verbose | -v        increase verbosity\n"
            "    --version | -V        print version string and exit\n\n"
            "writes given mode page with SCSI MODE SELECT (10 or 6) "
            "command\n");
}


/* Read hex numbers from command line or stdin. On the command line can
 * either be comma or space separated list. Space separated list need to be
 * quoted. For stdin (indicated by *inp=='-') there should be either
 * one entry per line, a comma separated list or space separated list.
 * Returns 0 if ok, or sg3_utils error code if error. */
static int
build_mode_page(const char * inp, uint8_t * mp_arr, int * mp_arr_len,
                int max_arr_len)
{
    int in_len, k, j, m;
    unsigned int h;
    const char * lcp;
    char * cp;
    char * c2p;

    if ((NULL == inp) || (NULL == mp_arr) ||
        (NULL == mp_arr_len))
        return SG_LIB_LOGIC_ERROR;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *mp_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        bool split_line;
        int off = 0;
        char carry_over[4];
        char line[512];

        carry_over[0] = 0;
        for (j = 0; j < 512; ++j) {
            if (NULL == fgets(line, sizeof(line), stdin))
                break;
            in_len = strlen(line);
            if (in_len > 0) {
                if ('\n' == line[in_len - 1]) {
                    --in_len;
                    line[in_len] = '\0';
                    split_line = false;
                } else
                    split_line = true;
            }
            if (in_len < 1) {
                carry_over[0] = 0;
                continue;
            }
            if (carry_over[0]) {
                if (isxdigit(line[0])) {
                    carry_over[1] = line[0];
                    carry_over[2] = '\0';
                    if (1 == sscanf(carry_over, "%x", &h))
                        mp_arr[off - 1] = h;       /* back up and overwrite */
                    else {
                        pr2serr("%s: carry_over error ['%s'] around line "
                                "%d\n", __func__, carry_over, j + 1);
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    lcp = line + 1;
                    --in_len;
                } else
                    lcp = line;
                carry_over[0] = 0;
            } else
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
                pr2serr("%s: syntax error at line %d, pos %d\n", __func__,
                        j + 1, m + k + 1);
                return SG_LIB_SYNTAX_ERROR;
            }
            for (k = 0; k < 1024; ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        pr2serr("%s: hex number larger than 0xff in line %d, "
                                "pos %d\n", __func__, j + 1,
                                (int)(lcp - line + 1));
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    if (split_line && (1 == strlen(lcp))) {
                        /* single trailing hex digit might be a split pair */
                        carry_over[0] = *lcp;
                    }
                    if ((off + k) >= max_arr_len) {
                        pr2serr("%s: array length exceeded\n", __func__);
                        return SG_LIB_SYNTAX_ERROR;
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
                    pr2serr("%s: error in line %d, at pos %d\n", __func__,
                            j + 1, (int)(lcp - line + 1));
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            off += (k + 1);
        }
        *mp_arr_len = off;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF, ");
        if (in_len != k) {
            pr2serr("%s: error at pos %d\n", __func__, k + 1);
            return SG_LIB_SYNTAX_ERROR;
        }
        for (k = 0; k < max_arr_len; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    pr2serr("%s: hex number larger than 0xff at pos %d\n",
                            __func__, (int)(lcp - inp + 1));
                    return SG_LIB_SYNTAX_ERROR;
                }
                mp_arr[k] = h;
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
                pr2serr("%s: error at pos %d\n", __func__,
                        (int)(lcp - inp + 1));
                return SG_LIB_SYNTAX_ERROR;
            }
        }
        *mp_arr_len = k + 1;
        if (k == max_arr_len) {
            pr2serr("%s: array length exceeded\n", __func__);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Read hex numbers from command line (comma separated list).
 * Can also be (single) space separated list but needs to be quoted on the
 * command line. Returns 0 if ok, or 1 if error. */
static int
build_mask(const char * inp, uint8_t * mask_arr, int * mask_arr_len,
           int max_arr_len)
{
    int in_len, k;
    unsigned int h;
    const char * lcp;
    char * cp;
    char * c2p;

    if ((NULL == inp) || (NULL == mask_arr) ||
        (NULL == mask_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *mask_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        pr2serr("'--mask' does not accept input from stdin\n");
        return 1;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF, ");
        if (in_len != k) {
            pr2serr("%s: error at pos %d\n", __func__, k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    pr2serr("%s: hex number larger than 0xff at pos %d\n",
                            __func__, (int)(lcp - inp + 1));
                    return 1;
                }
                mask_arr[k] = h;
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
                pr2serr("%s: error at pos %d\n", __func__,
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *mask_arr_len = k + 1;
        if (k == max_arr_len) {
            pr2serr("%s: array length exceeded\n", __func__);
            return 1;
        }
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool dbd = false;
    bool force = false;
    bool got_contents = false;
    bool got_mask = false;
    bool mode_6 = false;        /* so default is mode_10 */
    bool rtd = false;   /* added in spc5r11 */
    bool save = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c, num, alloc_len, off, pdt, k, md_len, hdr_len, bd_len;
    int mask_in_len;
    int sg_fd = -1;
    int pg_code = -1;
    int sub_pg_code = 0;
    int verbose = 0;
    int read_in_len = 0;
    int ret = 0;
    unsigned u, uu;
    const char * device_name = NULL;
    uint8_t read_in[MX_ALLOC_LEN];
    uint8_t mask_in[MX_ALLOC_LEN];
    uint8_t ref_md[MX_ALLOC_LEN];
    char ebuff[EBUFF_SZ];
    char errStr[128];
    char b[80];
    struct sg_simple_inquiry_resp inq_data;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "6c:dfhl:m:p:RsvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case '6':
            mode_6 = true;
            break;
        case 'c':
            memset(read_in, 0, sizeof(read_in));
            if ((ret = build_mode_page(optarg, read_in, &read_in_len,
                                       sizeof(read_in)))) {
                pr2serr("bad argument to '--contents='\n");
                return ret;
            }
            got_contents = true;
            break;
        case 'd':
            dbd = true;
            break;
        case 'f':
            force = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            num = sscanf(optarg, "%d", &res);
            if ((1 == num) && ((6 == res) || (10 == res)))
                mode_6 = (6 == res);
            else {
                pr2serr("length (of cdb) must be 6 or 10\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'm':
            memset(mask_in, 0xff, sizeof(mask_in));
            if (0 != build_mask(optarg, mask_in, &mask_in_len,
                                sizeof(mask_in))) {
                pr2serr("bad argument to '--mask'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            got_mask = true;
            break;
        case 'p':
           if (NULL == strchr(optarg, ',')) {
                num = sscanf(optarg, "%x", &u);
                if ((1 != num) || (u > 62)) {
                    pr2serr("Bad hex page code value after '--page' "
                            "switch\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                pg_code = u;
            } else if (2 == sscanf(optarg, "%x,%x", &u, &uu)) {
                if (uu > 254) {
                    pr2serr("Bad hex sub page code value after '--page' "
                            "switch\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                pg_code = u;
                sub_pg_code = uu;
            } else {
                pr2serr("Bad hex page code, subpage code sequence after "
                        "'--page' switch\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'R':
            rtd = true;
            break;
        case 's':
            save = true;
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
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
        verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr(ME "version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((pg_code < 0) && (! rtd)) {
        pr2serr("need page code (see '--page=')\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (got_mask && force) {
        pr2serr("cannot use both '--force' and '--mask'\n\n");
        usage();
        return SG_LIB_CONTRADICT;
    }

    sg_fd = sg_cmds_open_device(device_name, false /* rw */, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }
    if (rtd)
        goto revert_to_defaults;

    if (0 == sg_simple_inquiry(sg_fd, &inq_data, false, verbose))
        pdt = inq_data.peripheral_type;
    else
        pdt = 0x1f;

    /* do MODE SENSE to fetch current values */
    memset(ref_md, 0, MX_ALLOC_LEN);
    snprintf(errStr, sizeof(errStr), "MODE SENSE (%d): ", mode_6 ? 6 : 10);
    alloc_len = mode_6 ? SHORT_ALLOC_LEN : MX_ALLOC_LEN;
    if (mode_6)
        res = sg_ll_mode_sense6(sg_fd, dbd, 0 /*current */, pg_code,
                                sub_pg_code, ref_md, alloc_len, true,
                                verbose);
     else
        res = sg_ll_mode_sense10(sg_fd, false /* llbaa */, dbd,
                                 0 /* current */, pg_code, sub_pg_code,
                                 ref_md, alloc_len, true, verbose);
    ret = res;
    if (res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr("%snot supported, try '--len=%d'\n", errStr,
                    (mode_6 ? 10 : 6));
        else {
            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("%s%s\n", errStr, b);
        }
        goto fini;
    }
    off = sg_mode_page_offset(ref_md, alloc_len, mode_6, ebuff, EBUFF_SZ);
    if (off < 0) {
        pr2serr("%s%s\n", errStr, ebuff);
        goto fini;
    }
    md_len = sg_msense_calc_length(ref_md, alloc_len, mode_6, &bd_len);
    if (md_len < 0) {
        pr2serr("%ssg_msense_calc_length() failed\n", errStr);
        goto fini;
    }
    hdr_len = mode_6 ? 4 : 8;
    if (got_contents) {
        if (read_in_len < 2) {
            pr2serr("contents length=%d too short\n", read_in_len);
            goto fini;
        }
        ref_md[0] = 0;  /* mode data length reserved for mode select */
        if (! mode_6)
            ref_md[1] = 0;    /* mode data length reserved for mode select */
        if (0 == pdt)   /* for disks mask out DPOFUA bit */
            ref_md[mode_6 ? 2 : 3] &= 0xef;
        if (md_len > alloc_len) {
            pr2serr("mode data length=%d exceeds allocation length=%d\n",
                    md_len, alloc_len);
            goto fini;
        }
        if (got_mask) {
            for (k = 0; k < (md_len - off); ++k) {
                if ((0x0 == mask_in[k]) || (k > read_in_len))
                   read_in[k] = ref_md[off + k];
                else if (mask_in[k] < 0xff) {
                   c = (ref_md[off + k] & (0xff & ~mask_in[k]));
                   read_in[k] = (c | (read_in[k] & mask_in[k]));
                }
            }
            read_in_len = md_len - off;
        }
        if (! force) {
            if ((! (ref_md[off] & 0x80)) && save) {
                pr2serr("PS bit in existing mode page indicates that it is "
                        "not saveable\n    but '--save' option given\n");
                goto fini;
            }
            read_in[0] &= 0x7f; /* mask out PS bit, reserved in mode select */
            if ((md_len - off) != read_in_len) {
                pr2serr("contents length=%d but reference mode page "
                        "length=%d\n", read_in_len, md_len - off);
                goto fini;
            }
            if (pg_code != (read_in[0] & 0x3f)) {
                pr2serr("contents page_code=0x%x but reference "
                        "page_code=0x%x\n", (read_in[0] & 0x3f), pg_code);
                goto fini;
            }
            if ((read_in[0] & 0x40) != (ref_md[off] & 0x40)) {
                pr2serr("contents flags subpage but reference page does not "
                        "(or vice versa)\n");
                goto fini;
            }
            if ((read_in[0] & 0x40) && (read_in[1] != sub_pg_code)) {
                pr2serr("contents subpage_code=0x%x but reference "
                        "sub_page_code=0x%x\n", read_in[1], sub_pg_code);
                goto fini;
            }
        } else
            md_len = off + read_in_len; /* force length */

        memcpy(ref_md + off, read_in, read_in_len);
        if (mode_6)
            res = sg_ll_mode_select6_v2(sg_fd, true /* PF */, rtd, save,
                                        ref_md, md_len, true, verbose);
        else
            res = sg_ll_mode_select10_v2(sg_fd, true /* PF */, rtd, save,
                                         ref_md, md_len, true, verbose);
        ret = res;
        if (res)
            goto fini;
    } else {
        printf(">>> No contents given, so show current mode page data:\n");
        printf("  header:\n");
        hex2stdout(ref_md, hdr_len, -1);
        if (bd_len) {
            printf("  block descriptor(s):\n");
            hex2stdout(ref_md + hdr_len, bd_len, -1);
        } else
            printf("  << no block descriptors >>\n");
        printf("  mode page:\n");
        hex2stdout(ref_md + off, md_len - off, -1);
    }
    ret = 0;
    goto fini;

revert_to_defaults:
    if (verbose)
        pr2serr("Doing MODE SELECT(%d) with revert to defaults (RTD) set "
                "and SP=%d\n", mode_6 ? 6 : 10, !! save);
    if (mode_6)
        res = sg_ll_mode_select6_v2(sg_fd, false /* PF */, true /* rtd */,
                                    save, NULL, 0, true, verbose);
    else
        res = sg_ll_mode_select10_v2(sg_fd, false /* PF */, true /* rtd */,
                                     save, NULL, 0, true, verbose);
    ret = res;
fini:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_wr_mode failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
