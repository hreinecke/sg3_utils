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

static const char * version_str = "1.08 20180219";

#define MAX_READ_BLOCK_LIMITS_LEN 6

static uint8_t readBlkLmtBuff[MAX_READ_BLOCK_LIMITS_LEN];


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_read_block_limits  [--help] [--hex] [--raw] "
            "[--readonly]\n"
            "                             [--verbose] [--version] "
            "DEVICE\n"
            "  where:\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           output response in hexadecimal\n"
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
    bool do_raw = false;
    bool readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int sg_fd, k, m, res, c;
    int do_hex = 0;
    int verbose = 0;
    int ret = 0;
    uint32_t max_block_size;
    uint16_t min_block_size;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHrRvV", long_options,
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
        pr2serr("version: %s\n", version_str);
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

    memset(readBlkLmtBuff, 0x0, 6);
    res = sg_ll_read_block_limits(sg_fd, readBlkLmtBuff, 6, true, verbose);
    ret = res;
    if (0 == res) {
      if (do_hex) {
        hex2stdout(readBlkLmtBuff, sizeof(readBlkLmtBuff), 1);
        goto the_end;
      } else if (do_raw) {
        dStrRaw((const char *)readBlkLmtBuff, sizeof(readBlkLmtBuff));
        goto the_end;
      }

      max_block_size = sg_get_unaligned_be32(readBlkLmtBuff + 0);
      min_block_size = sg_get_unaligned_be16(readBlkLmtBuff + 4);
      k = min_block_size / 1024;
      pr2serr("Read Block Limits results:\n");
      pr2serr("\tMinimum block size: %u byte(s)",
              (unsigned int)min_block_size);
      if (k != 0)
        pr2serr(", %d KB", k);
      pr2serr("\n");
      k = max_block_size / 1024;
      m = max_block_size / 1048576;
      pr2serr("\tMaximum block size: %u byte(s)",
              (unsigned int)max_block_size);
      if (k != 0)
        pr2serr(", %d KB", k);
      if (m != 0)
        pr2serr(", %d MB", m);
      pr2serr("\n");
    } else {
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
