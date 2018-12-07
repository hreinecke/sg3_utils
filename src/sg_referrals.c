/*
 * Copyright (c) 2010-2018 Hannes Reinecke.
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

/*
 * A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI REPORT REFERRALS command to the given
 * SCSI device.
 */

static const char * version_str = "1.13 20180628";    /* sbc4r10 */

#define MAX_REFER_BUFF_LEN (1024 * 1024)
#define DEF_REFER_BUFF_LEN 256

#define TPGS_STATE_OPTIMIZED 0x0
#define TPGS_STATE_NONOPTIMIZED 0x1
#define TPGS_STATE_STANDBY 0x2
#define TPGS_STATE_UNAVAILABLE 0x3
#define TPGS_STATE_LB_DEPENDENT 0x4
#define TPGS_STATE_OFFLINE 0xe          /* SPC-4 rev 9 */
#define TPGS_STATE_TRANSITIONING 0xf

static uint8_t referralBuff[DEF_REFER_BUFF_LEN];

static const char *decode_tpgs_state(const int st)
{
    switch (st) {
    case TPGS_STATE_OPTIMIZED:
        return "active/optimized";
        break;
    case TPGS_STATE_NONOPTIMIZED:
        return "active/non optimized";
        break;
    case TPGS_STATE_STANDBY:
        return "standby";
        break;
    case TPGS_STATE_UNAVAILABLE:
        return "unavailable";
        break;
    case TPGS_STATE_LB_DEPENDENT:
        return "logical block dependent";
        break;
    case TPGS_STATE_OFFLINE:
        return "offline";
        break;
    case TPGS_STATE_TRANSITIONING:
        return "transitioning between states";
        break;
    default:
        return "unknown";
        break;
    }
}

static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"lba", required_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"one-segment", no_argument, 0, 's'},
        {"one_segment", no_argument, 0, 's'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_referrals  [--help] [--hex] [--lba=LBA] "
            "[--maxlen=LEN]\n"
            "                     [--one-segment] [--raw] [--readonly] "
            "[--verbose]\n"
            "                     [--version] DEVICE\n"
            "  where:\n"
            "    --help|-h         print out usage message\n"
            "    --hex|-H          output in hexadecimal\n"
            "    --lba=LBA|-l LBA    starting LBA (logical block address) "
            "(def: 0)\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n",
            DEF_REFER_BUFF_LEN );
    pr2serr("    --one-segment|-s    return information about the specified "
            "segment only\n"
            "    --raw|-r          output in binary\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Performs a SCSI REPORT REFERRALS command (SBC-3)\n"
            );
}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Decodes given user data referral segment descriptor
 * the number of blocks and returns the number of bytes processed,
 * -1 for error.
 */
static int
decode_referral_desc(const uint8_t * bp, int bytes)
{
    int j, n;
    uint64_t first, last;

    if (NULL == bp)
        return -1;

    if (bytes < 20)
        return -1;

    first = sg_get_unaligned_be64(bp + 4);
    last = sg_get_unaligned_be64(bp + 12);

    printf("    target port descriptors: %d\n", bp[3]);
    printf("    user data segment: first lba %" PRIu64 ", last lba %"
          PRIu64 "\n", first, last);
    n = 20;
    bytes -= n;
    for (j = 0; j < bp[3]; j++) {
        if (bytes < 4)
            return -1;
        printf("      target port descriptor %d:\n", j);
        printf("        port group %x state (%s)\n",
               sg_get_unaligned_be16(bp + n + 2),
               decode_tpgs_state(bp[n] & 0xf));
        n += 4;
        bytes -= 4;
    }
    return n;
}


int
main(int argc, char * argv[])
{
    bool do_one_segment = false;
    bool o_readonly = false;
    bool do_raw = false;
    bool verbose_given = false;
    bool version_given = false;
    int k, res, c, rlen;
    int sg_fd = -1;
    int do_hex = 0;
    int maxlen = DEF_REFER_BUFF_LEN;
    int verbose = 0;
    int desc = 0;
    int ret = 0;
    int64_t ll;
    uint64_t lba = 0;
    const char * device_name = NULL;
    const uint8_t * bp;
    uint8_t * referralBuffp = referralBuff;
    uint8_t * free_referralBuffp = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHl:m:rRsvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
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
            if ((maxlen < 0) || (maxlen > MAX_REFER_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_REFER_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 's':
            do_one_segment = true;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
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

    if (NULL == device_name) {
        pr2serr("No DEVICE argument given\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (maxlen > DEF_REFER_BUFF_LEN) {
        referralBuffp = (uint8_t *)sg_memalign(maxlen, 0,
                                               &free_referralBuffp,
                                               verbose > 3);
        if (NULL == referralBuffp) {
            pr2serr("unable to allocate %d bytes on heap\n", maxlen);
            return sg_convert_errno(ENOMEM);
        }
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto free_buff;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto free_buff;
    }

    res = sg_ll_report_referrals(sg_fd, lba, do_one_segment, referralBuffp,
                                 maxlen, true, verbose);
    ret = res;
    if (0 == res) {
        if (maxlen >= 4)
            /*
             * This is strictly speaking incorrect. However, the
             * spec reserved bytes 0 and 1, so some implementations
             * might want to use them to increase the number of
             * possible user segments.
             * And maybe someone takes a pity and updates the spec ...
             */
            rlen = sg_get_unaligned_be32(referralBuffp + 0) + 4;
        else
            rlen = maxlen;
        k = (rlen > maxlen) ? maxlen : rlen;
        if (do_raw) {
            dStrRaw(referralBuffp, k);
            goto the_end;
        }
        if (do_hex) {
            hex2stdout(referralBuffp, k, 1);
            goto the_end;
        }
        if (maxlen < 4) {
            if (verbose)
                pr2serr("Exiting because allocation length (maxlen)  less "
                        "than 4\n");
            goto the_end;
        }
        if ((verbose > 1) || (verbose && (rlen > maxlen))) {
            pr2serr("response length %d bytes\n", rlen);
            if (rlen > maxlen)
                pr2serr("  ... which is greater than maxlen (allocation "
                        "length %d), truncation\n", maxlen);
        }
        if (rlen > maxlen)
            rlen = maxlen;

        bp = referralBuffp + 4;
        k = 0;
        printf("Report referrals:\n");
        while (k < rlen - 4) {
            printf("  descriptor %d:\n", desc);
            res = decode_referral_desc(bp + k, rlen - 4 - k);
            if (res < 0) {
                pr2serr("bad user data segment referral descriptor\n");
                break;
            }
            k += res;
            desc++;
        }
    } else {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Report Referrals command failed: %s\n", b);
    }

the_end:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            ret = sg_convert_errno(-res);
    }
free_buff:
    if (free_referralBuffp)
        free(free_referralBuffp);
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_referrals failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
