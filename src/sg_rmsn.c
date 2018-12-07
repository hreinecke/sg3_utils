/*
 * Copyright (c) 2005-2018 Douglas Gilbert.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program was originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command READ MEDIA SERIAL NUMBER
 * to the given SCSI device.
 */

static const char * version_str = "1.18 20180628";

#define SERIAL_NUM_SANITY_LEN (16 * 1024)


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    pr2serr("Usage: sg_rmsn   [--help] [--raw] [--readonly] [--verbose] "
            "[--version]\n"
            "                 DEVICE\n"
            "  where:\n"
            "    --help|-h       print out usage message\n"
            "    --raw|-r        output serial number to stdout "
            "(potentially binary)\n"
            "    --readonly|-R    open DEVICE read-only (def: open it "
            "read-write)\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version string and exit\n\n"
            "Performs a SCSI READ MEDIA SERIAL NUMBER command\n");
}

int main(int argc, char * argv[])
{
    bool raw = false;
    bool readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c, sn_len, n;
    int sg_fd = -1;
    int ret = 0;
    int verbose = 0;
    uint8_t rmsn_buff[4];
    uint8_t * bp = NULL;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hrRvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'r':
            raw = true;
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
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto err_out;
    }

    memset(rmsn_buff, 0x0, sizeof(rmsn_buff));

    res = sg_ll_read_media_serial_num(sg_fd, rmsn_buff, sizeof(rmsn_buff),
                                      true, verbose);
    ret = res;
    if (0 == res) {
        sn_len = sg_get_unaligned_be32(rmsn_buff + 0);
        if (! raw)
            printf("Reported serial number length = %d\n", sn_len);
        if (0 == sn_len) {
            pr2serr("    This implies the media has no serial number\n");
            goto err_out;
        }
        if (sn_len > SERIAL_NUM_SANITY_LEN) {
            pr2serr("    That length (%d) seems too long for a serial "
                    "number\n", sn_len);
            goto err_out;
        }
        sn_len += 4;
        bp = (uint8_t *)malloc(sn_len);
        if (NULL == bp) {
            pr2serr("    Out of memory (ram)\n");
            goto err_out;
        }
        res = sg_ll_read_media_serial_num(sg_fd, bp, sn_len, true, verbose);
        if (0 == res) {
            sn_len = sg_get_unaligned_be32(bp + 0);
            if (raw) {
                if (sn_len > 0) {
                    n = fwrite(bp + 4, 1, sn_len, stdout);
                    if (n) { ; }  /* unused, dummy to suppress warning */
                }
            } else {
                printf("Serial number:\n");
                if (sn_len > 0)
                    hex2stdout(bp + 4, sn_len, 0);
            }
        }
    }
    if (res) {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Read Media Serial Number: %s\n", b);
        if (0 == verbose)
            pr2serr("    try '-v' for more information\n");
    }

err_out:
    if (bp)
        free(bp);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_rmsn failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
