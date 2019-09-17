/*
 * Copyright (c) 2009-2019 Douglas Gilbert.
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
#include <errno.h>
#include <getopt.h>
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
 *
 * This program issues the SCSI GET LBA STATUS command to the given SCSI
 * device.
 */

static const char * version_str = "1.21 20190913";      /* sbc4r15 */

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif

#define MAX_GLBAS_BUFF_LEN (1024 * 1024)
#define DEF_GLBAS_BUFF_LEN 24

static uint8_t glbasFixedBuff[DEF_GLBAS_BUFF_LEN];


static struct option long_options[] = {
        {"16", no_argument, 0, 'S'},
        {"32", no_argument, 0, 'T'},
        {"brief", no_argument, 0, 'b'},
        {"element-id", required_argument, 0, 'e'},
        {"element_id", required_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"in", required_argument, 0, 'i'},      /* silent, same as --inhex= */
        {"inhex", required_argument, 0, 'i'},
        {"lba", required_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"report-type", required_argument, 0, 't'},
        {"report_type", required_argument, 0, 't'},
        {"scan-len", required_argument, 0, 's'},
        {"scan_len", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_get_lba_status  [--16] [--32][--brief] "
            "[--element-id=EI]\n"
            "                          [--help] [--hex] [--inhex=FN] "
            "[--lba=LBA]\n"
            "                          [--maxlen=LEN] [--raw] [--readonly]\n"
            "                          [--report-type=RT] [--scan-len=SL] "
            "[--verbose]\n"
            "                          [--version] DEVICE\n"
            "  where:\n"
            "    --16|-S           use GET LBA STATUS(16) cdb (def)\n"
            "    --32|-T           use GET LBA STATUS(32) cdb\n"
            "    --brief|-b        a descriptor per line:\n"
            "                          <lba_hex blocks_hex p_status "
            "add_status>\n"
            "                      use twice ('-bb') for given LBA "
            "provisioning status\n"
            "    --element-id=EI|-e EI      EI is the element identifier "
            "(def: 0)\n"
            "    --help|-h         print out usage message\n"
            "    --hex|-H          output in hexadecimal\n"
            "    --inhex=FN        input taken from file FN rather than "
            "DEVICE,\n"
            "                      assumed to be ASCII hex or, if --raw, "
            "in binary\n"
            "    --lba=LBA|-l LBA    starting LBA (logical block address) "
            "(def: 0)\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n",
            DEF_GLBAS_BUFF_LEN );
    pr2serr("    --raw|-r          output in binary, unless if --inhex=FN "
            "is given,\n"
            "                      in which case input file is binary\n"
            "    --readonly|-R     open DEVICE read-only (def: read-write)\n"
            "    --report-type=RT|-t RT    report type: 0->all LBAs (def);\n"
            "                                1-> LBAs with non-zero "
            "provisioning status\n"
            "                                2-> LBAs that are mapped\n"
            "                                3-> LBAs that are deallocated\n"
            "                                4-> LBAs that are anchored\n"
            "                                16-> LBAs that may return "
            "unrecovered error\n"
            "    --scan-len=SL|-s SL    SL in maximum scan length (unit: "
            "logical blocks)\n"
            "                           (def: 0 which implies no limit)\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Performs a SCSI GET LBA STATUS(16) or GET LBA STATUS(32) "
            "command (SBC-3 and\nSBC-4). If --inhex=FN is given then "
            "contents of FN is assumed to be a response\nto this command.\n"
            );
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Decodes given LBA status descriptor passing back the starting LBA,
 * the number of blocks and returns the provisioning status, -1 for error.
 */
static int
decode_lba_status_desc(const uint8_t * bp, uint64_t * slbap,
                       uint32_t * blocksp, uint8_t * add_statusp)
{
    uint32_t blocks;
    uint64_t ull;

    if (NULL == bp)
        return -1;
    ull = sg_get_unaligned_be64(bp + 0);
    blocks = sg_get_unaligned_be32(bp + 8);
    if (slbap)
        *slbap = ull;
    if (blocksp)
        *blocksp = blocks;
    if (add_statusp)
        *add_statusp = bp[13];
    return bp[12] & 0xf;
}


int
main(int argc, char * argv[])
{
    bool do_16 = false;
    bool do_32 = false;
    bool do_raw = false;
    bool no_final_msg = false;
    bool o_readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int k, j, res, c, rlen, num_descs, completion_cond, in_len;
    int sg_fd = -1;
    int do_brief = 0;
    int do_hex = 0;
    int ret = 0;
    int maxlen = DEF_GLBAS_BUFF_LEN;
    int rt = 0;
    int verbose = 0;
    uint8_t add_status = 0;     /* keep gcc quiet */
    uint64_t d_lba = 0;
    uint32_t d_blocks = 0;
    uint32_t element_id = 0;
    uint32_t scan_len = 0;
    int64_t ll;
    uint64_t lba = 0;
    const char * device_name = NULL;
    const char * in_fn = NULL;
    const uint8_t * bp;
    uint8_t * glbasBuffp = glbasFixedBuff;
    uint8_t * free_glbasBuffp = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "be:hi:Hl:m:rRs:St:TvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            ++do_brief;
            break;
        case 'e':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--element-id'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            element_id = (uint32_t)ll;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'i':
            in_fn = optarg;
            break;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            lba = (uint64_t)ll;
            break;
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MAX_GLBAS_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_GLBAS_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (0 == maxlen)
                maxlen = DEF_GLBAS_BUFF_LEN;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
            break;
        case 's':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--scan-len'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            scan_len = (uint32_t)ll;
            break;
        case 'S':
            do_16 = true;
            break;
        case 't':
            rt = sg_get_num_nomult(optarg);
            if ((rt < 0) || (rt > 255)) {
                pr2serr("'--report-type=RT' should be between 0 and 255 "
                        "(inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'T':
            do_32 = true;
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
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (maxlen > DEF_GLBAS_BUFF_LEN) {
        glbasBuffp = (uint8_t *)sg_memalign(maxlen, 0, &free_glbasBuffp,
                                            verbose > 3);
        if (NULL == glbasBuffp) {
            pr2serr("unable to allocate %d bytes on heap\n", maxlen);
            return sg_convert_errno(ENOMEM);
        }
    }
    if (device_name && in_fn) {
        pr2serr("ignoring DEVICE, best to give DEVICE or --inhex=FN, but "
                "not both\n");
        device_name = NULL;
    }
    if (NULL == device_name) {
        if (in_fn) {
            if ((ret = sg_f2hex_arr(in_fn, do_raw, false, glbasBuffp,
                                    &in_len, maxlen))) {
                if (SG_LIB_LBA_OUT_OF_RANGE == ret) {
                    no_final_msg = true;
                    pr2serr("... decode what we have, --maxlen=%d needs to "
                            "be increased\n", maxlen);
                } else
                    goto fini;
            }
            if (verbose > 2)
                pr2serr("Read %d [0x%x] bytes of user supplied data\n",
                        in_len, in_len);
            if (do_raw)
                do_raw = false;    /* can interfere on decode */
            if (in_len < 4) {
                pr2serr("--in=%s only decoded %d bytes (needs 4 at least)\n",
                        in_fn, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
                goto fini;
            }
            res = 0;
            goto start_response;
        } else {
            pr2serr("missing device name!\n\n");
            usage();
            ret = SG_LIB_FILE_ERROR;
            no_final_msg = true;
            goto fini;
        }
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
    }
    if (do_16 && do_32) {
        pr2serr("both --16 and --32 given, choose --16\n");
        do_32 = false;
    } else if ((! do_16) && (! do_32)) {
        if (verbose > 3)
            pr2serr("choosing --16\n");
        do_16 = true;
    }
    if (do_16) {
        if (element_id != 0)
            pr2serr("Warning: --element_id= ignored with 16 byte cdb\n");
        if (scan_len != 0)
            pr2serr("Warning: --scan_len= ignored with 16 byte cdb\n");
    }
    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    res = 0;
    if (do_16)
        res = sg_ll_get_lba_status16(sg_fd, lba, rt, glbasBuffp, maxlen, true,
                                     verbose);
    else if (do_32)     /* keep analyser happy since do_32 must be true */
        res = sg_ll_get_lba_status32(sg_fd, lba, scan_len, element_id, rt,
                                     glbasBuffp, maxlen, true, verbose);

    ret = res;
    if (res)
        goto error;

start_response:
    /* in sbc3r25 offset for calculating the 'parameter data length'
     * (rlen variable below) was reduced from 8 to 4. */
    if (maxlen >= 4)
        rlen = sg_get_unaligned_be32(glbasBuffp + 0) + 4;
    else
        rlen = maxlen;
    k = (rlen > maxlen) ? maxlen : rlen;
    if (do_raw) {
        dStrRaw((const char *)glbasBuffp, k);
        goto fini;
    }
    if (do_hex) {
        hex2stdout(glbasBuffp, k, 1);
        goto fini;
    }
    if (maxlen < 4) {
        if (verbose)
            pr2serr("Exiting because allocation length (maxlen) less "
                    "than 4\n");
        goto fini;
    }
    if ((verbose > 1) || (verbose && (rlen > maxlen))) {
        pr2serr("response length %d bytes\n", rlen);
        if (rlen > maxlen)
            pr2serr("  ... which is greater than maxlen (allocation "
                    "length %d), truncation\n", maxlen);
    }
    if (rlen > maxlen)
        rlen = maxlen;

    if (do_brief > 1) {
        if (rlen < 24) {
            pr2serr("Need maxlen and response length to be at least 24, "
                    "have %d bytes\n", rlen);
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
        res = decode_lba_status_desc(glbasBuffp + 8, &d_lba, &d_blocks,
                                     &add_status);
        if ((res < 0) || (res > 15)) {
            pr2serr("first LBA status descriptor returned %d ??\n", res);
            ret = SG_LIB_LOGIC_ERROR;
            goto fini;
        }
        if ((lba < d_lba) || (lba >= (d_lba + d_blocks))) {
            pr2serr("given LBA not in range of first descriptor:\n"
                    "  descriptor LBA: 0x");
            for (j = 0; j < 8; ++j)
                pr2serr("%02x", glbasBuffp[8 + j]);
            pr2serr("  blocks: 0x%x  p_status: %d  add_status: 0x%x\n",
                    (unsigned int)d_blocks, res,
                    (unsigned int)add_status);
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
        printf("%d\n", res);
        goto fini;
    }

    if (rlen < 24) {
        printf("No complete LBA status descriptors available\n");
        goto fini;
    }
    num_descs = (rlen - 8) / 16;
    completion_cond = (*(glbasBuffp + 7) >> 1) & 7; /* added sbc4r14 */
    if (do_brief)
        printf("Completion condition=%d\n", completion_cond);
    else {
        switch (completion_cond) {
        case 0:
            printf("No indication of the completion condition\n");
            break;
        case 1:
            printf("Command completed due to meeting allocation length "
                   "(--maxlen=LEN (def 24))\n");
            break;
        case 2:
            printf("Command completed due to meeting scan length "
                   "(--scan-len=SL)\n");
            break;
        case 3:
            printf("Command completed due to meeting capacity of "
                   "medium\n");
            break;
        default:
            printf("Command completion is reserved [%d]\n",
                   completion_cond);
            break;
        }
    }
    printf("RTP=%d\n", *(glbasBuffp + 7) & 0x1);    /* added sbc4r12 */
    if (verbose)
        pr2serr("%d complete LBA status descriptors found\n", num_descs);
    for (bp = glbasBuffp + 8, k = 0; k < num_descs; bp += 16, ++k) {
        res = decode_lba_status_desc(bp, &d_lba, &d_blocks, &add_status);
        if ((res < 0) || (res > 15))
            pr2serr("descriptor %d: bad LBA status descriptor returned "
                    "%d\n", k + 1, res);
        if (do_brief) {
            printf("0x");
            for (j = 0; j < 8; ++j)
                printf("%02x", bp[j]);
            printf("  0x%x  %d  %d\n", (unsigned int)d_blocks, res,
                   add_status);
        } else {
            printf("[%d] LBA: 0x", k + 1);
            for (j = 0; j < 8; ++j)
                printf("%02x", bp[j]);
            printf("  blocks: %10u", (unsigned int)d_blocks);
            switch (res) {
            case 0:
                printf("  mapped (or unknown)");
                break;
            case 1:
                printf("  deallocated");
                break;
            case 2:
                printf("  anchored");
                break;
            case 3:
                printf("  mapped");         /* sbc4r12 */
                break;
            case 4:
                printf("  unknown");        /* sbc4r12 */
                break;
            default:
                printf("  Provisioning status: %d", res);
                break;
            }
            switch (add_status) {
            case 0:
                printf("\n");
                break;
            case 1:
                printf(" [may return unrecovered errors]\n");
                break;
            default:
                printf(" [add_status: 0x%x]\n", (unsigned int)add_status);
                break;
            }
        }
    }
    if ((num_descs * 16) + 8 < rlen)
        pr2serr("incomplete trailing LBA status descriptors found\n");
    goto fini;

error:
    if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("Get LBA Status command not supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        pr2serr("Get LBA Status command: bad field in cdb\n");
    else {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Get LBA Status command: %s\n", b);
    }

fini:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (free_glbasBuffp)
        free(free_glbasBuffp);
    if ((0 == verbose) && (! no_final_msg)) {
        if (! sg_if_can2stderr("sg_get_lba_status failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
