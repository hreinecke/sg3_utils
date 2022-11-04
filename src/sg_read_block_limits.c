/*
 * Copyright (c) 2009-2022 Douglas Gilbert.
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
 * This program issues the SCSI READ BLOCK LIMITS command (SSC) to the given
 * SCSI device.
 */

static const char * version_str = "1.09 20221101";

#define DEF_READ_BLOCK_LIMITS_LEN 6
#define MLIO_READ_BLOCK_LIMITS_LEN 20
#define MAX_READ_BLOCK_LIMITS_LEN MLIO_READ_BLOCK_LIMITS_LEN

static uint8_t readBlkLmtBuff[MAX_READ_BLOCK_LIMITS_LEN];


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"mloi", no_argument, 0, 'm'},  /* added in ssc4r02.pdf */
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_read_block_limits  [--help] [--hex] [--mloi] "
            "[--raw]\n"
            "                             [--readonly] [--verbose] "
            "[--version]\n"
            "                             DEVICE\n"
            "  where:\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           output response in hexadecimal\n"
            "    --mloi|-m          output maximum logical object "
            "identifier\n"
            "    --raw|-r           output response in binary to stdout\n"
            "    --readonly|-R      open DEVICE in read-only mode\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI READ BLOCK LIMITS command and decode the "
            "response\n"
            );
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

int
main(int argc, char * argv[])
{
    bool do_mloi = false;
    bool do_raw = false;
    bool readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int sg_fd, k, m, res, c, max_resp_len;
    int resid = 0;
    int actual_len = 0;
    int do_hex = 0;
    int verbose = 0;
    int ret = 0;
    uint32_t max_block_size;
    uint64_t mloi;
    uint16_t min_block_size;
    uint8_t granularity;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHmrRvV", long_options,
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
        case 'm':
            do_mloi = true;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            readonly = true;
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
        default:
            pr2serr("invalid option -%c ??\n", c);
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
        printf("version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto the_end2;
    }

    max_resp_len = do_mloi ? MLIO_READ_BLOCK_LIMITS_LEN :
                             DEF_READ_BLOCK_LIMITS_LEN;
    memset(readBlkLmtBuff, 0x0, sizeof(readBlkLmtBuff));
    res = sg_ll_read_block_limits_v2(sg_fd, do_mloi, readBlkLmtBuff,
                                     max_resp_len, &resid, true, verbose);
    ret = res;
    if (0 == res) {
        actual_len =  max_resp_len - resid;
        if (do_hex) {
            int fl = -1;

            if (1 == do_hex)
                fl = 1;
            else if (2 == do_hex)
                fl = 0;
            hex2stdout(readBlkLmtBuff, actual_len, fl);
            goto the_end;
        } else if (do_raw) {
            dStrRaw((const char *)readBlkLmtBuff, actual_len);
            goto the_end;
        }

        if (do_mloi) {
            if (actual_len < MLIO_READ_BLOCK_LIMITS_LEN) {
                pr2serr("Expected at least %d bytes in response but only "
                        "%d bytes\n", MLIO_READ_BLOCK_LIMITS_LEN, actual_len);
                goto the_end;
            }
            printf("Read Block Limits (MLOI=1) results:\n");
            mloi = sg_get_unaligned_be64(readBlkLmtBuff + 12);
            printf("    Maximum logical block identifier: %" PRIu64 "\n",
                   mloi);
        } else {        /* MLOI=0 (only case before ssc4r02.pdf) */
            if (actual_len < DEF_READ_BLOCK_LIMITS_LEN) {
                pr2serr("Expected at least %d bytes in response but only "
                        "%d bytes\n", DEF_READ_BLOCK_LIMITS_LEN, actual_len);
                goto the_end;
            }
            max_block_size = sg_get_unaligned_be32(readBlkLmtBuff + 0);
            // first byte contains granularity field
            granularity = (max_block_size >> 24) & 0x1F;
            max_block_size = max_block_size & 0xFFFFFF;
            min_block_size = sg_get_unaligned_be16(readBlkLmtBuff + 4);
            k = min_block_size / 1024;
            printf("Read Block Limits results:\n");
            printf("    Minimum block size: %u byte(s)",
                   (unsigned int)min_block_size);
            if (k != 0)
                printf(", %d KB", k);
            printf("\n");
            k = max_block_size / 1024;
            m = max_block_size / 1048576;
            printf("    Maximum block size: %u byte(s)",
                   (unsigned int)max_block_size);
            if (k != 0)
                printf(", %d KB", k);
            if (m != 0)
                printf(", %d MB", m);
            printf("\n");
            printf("    Granularity: %u",
                   (unsigned int)granularity);
            printf("\n");
        }
    } else {    /* error detected */
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Read block limits: %s\n", b);
        if (0 == verbose)
            pr2serr("    try '-v' option for more information\n");
    }

the_end:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            ret = sg_convert_errno(-res);
    }
the_end2:
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_read_block_limits failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
