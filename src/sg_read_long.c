/* A utility program for the Linux OS SCSI subsystem.
 *  Copyright (C) 2004-2018 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program issues the SCSI command READ LONG to a given SCSI device.
 * It sends the command with the logical block address passed as the lba
 * argument, and the transfer length set to the xfer_len argument. the
 * buffer to be written to the device filled with 0xff, this buffer includes
 * the sector data and the ECC bytes.
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
#include <errno.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.27 20180627";

#define MAX_XFER_LEN 10000

#define ME "sg_read_long: "

#define EBUFF_SZ 512


static struct option long_options[] = {
        {"16", no_argument, 0, 'S'},
        {"correct", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"lba", required_argument, 0, 'l'},
        {"out", required_argument, 0, 'o'},
        {"pblock", no_argument, 0, 'p'},
        {"readonly", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"xfer_len", required_argument, 0, 'x'},
        {"xfer-len", required_argument, 0, 'x'},
        {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_read_long [--16] [--correct] [--help] [--lba=LBA] "
            "[--out=OF]\n"
            "                    [--pblock] [--readonly] [--verbose] "
            "[--version]\n"
            "                    [--xfer_len=BTL] DEVICE\n"
            "  where:\n"
            "    --16|-S              do READ LONG(16) (default: "
            "READ LONG(10))\n"
            "    --correct|-c         use ECC to correct data "
            "(default: don't)\n"
            "    --help|-h            print out usage message\n"
            "    --lba=LBA|-l LBA     logical block address"
            " (default: 0)\n"
            "    --out=OF|-o OF       output in binary to file named OF\n"
            "    --pblock|-p          fetch physical block containing LBA\n"
            "    --readonly|-r        open DEVICE read-only (def: open it "
            "read-write)\n"
            "    --verbose|-v         increase verbosity\n"
            "    --version|-V         print version string and"
            " exit\n"
            "    --xfer_len=BTL|-x BTL    byte transfer length (< 10000)"
            " default 520\n\n"
            "Perform a SCSI READ LONG (10 or 16) command. Reads a single "
            "block with\nassociated ECC data. The user data could be "
            "encoded or encrypted.\n");
}

/* Returns 0 if successful */
static int
process_read_long(int sg_fd, bool do_16, bool pblock, bool correct,
                  uint64_t llba, void * data_out, int xfer_len, int verbose)
{
    int offset, res;
    const char * ten_or;
    char b[80];

    if (do_16)
        res = sg_ll_read_long16(sg_fd, pblock, correct, llba, data_out,
                                xfer_len, &offset, true, verbose);
    else
        res = sg_ll_read_long10(sg_fd, pblock, correct, (unsigned int)llba,
                                data_out, xfer_len, &offset, true, verbose);
    ten_or = do_16 ? "16" : "10";
    switch (res) {
    case 0:
        break;
    case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:
        pr2serr("<<< device indicates 'xfer_len' should be %d >>>\n",
                xfer_len - offset);
        break;
    default:
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("  SCSI READ LONG (%s): %s\n", ten_or, b);
        break;
    }
    return res;
}


int
main(int argc, char * argv[])
{
    bool correct = false;
    bool do_16 = false;
    bool pblock = false;
    bool readonly = false;
    bool got_stdout;
    bool verbose_given = false;
    bool version_given = false;
    int outfd, res, c;
    int sg_fd = -1;
    int ret = 0;
    int xfer_len = 520;
    int verbose = 0;
    uint64_t llba = 0;
    int64_t ll;
    uint8_t * readLongBuff = NULL;
    uint8_t * rawp = NULL;
    uint8_t * free_rawp = NULL;
    const char * device_name = NULL;
    char out_fname[256];
    char ebuff[EBUFF_SZ];

    memset(out_fname, 0, sizeof out_fname);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "chl:o:prSvVx:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            correct = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            llba = (uint64_t)ll;
            break;
        case 'o':
            strncpy(out_fname, optarg, sizeof(out_fname) - 1);
            break;
        case 'p':
            pblock = true;
            break;
        case 'r':
            readonly = true;
            break;
        case 'S':
            do_16 = true;
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
        case 'x':
            xfer_len = sg_get_num(optarg);
           if (-1 == xfer_len) {
                pr2serr("bad argument to '--xfer_len'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
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
        pr2serr("Missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (xfer_len >= MAX_XFER_LEN){
        pr2serr("xfer_len (%d) is out of range ( < %d)\n", xfer_len,
                MAX_XFER_LEN);
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto err_out;
    }

    if (NULL == (rawp = (uint8_t *)sg_memalign(MAX_XFER_LEN, 0, &free_rawp,
                                               false))) {
        if (verbose)
            pr2serr(ME "out of memory\n");
        ret = sg_convert_errno(ENOMEM);
        goto err_out;
    }
    readLongBuff = (uint8_t *)rawp;
    memset(rawp, 0x0, MAX_XFER_LEN);

    pr2serr(ME "issue read long (%s) to device %s\n    xfer_len=%d (0x%x), "
            "lba=%" PRIu64 " (0x%" PRIx64 "), correct=%d\n",
            (do_16 ? "16" : "10"), device_name, xfer_len, xfer_len, llba,
            llba, (int)correct);

    if ((ret = process_read_long(sg_fd, do_16, pblock, correct, llba,
                                 readLongBuff, xfer_len, verbose)))
        goto err_out;

    if ('\0' == out_fname[0])
        hex2stdout((const uint8_t *)rawp, xfer_len, 0);
    else {
        got_stdout = (0 == strcmp(out_fname, "-"));
        if (got_stdout)
            outfd = STDOUT_FILENO;
        else {
            if ((outfd = open(out_fname, O_WRONLY | O_CREAT | O_TRUNC,
                              0666)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for writing", out_fname);
                perror(ebuff);
                goto err_out;
            }
        }
        if (sg_set_binary_mode(outfd) < 0) {
            perror("sg_set_binary_mode");
            goto err_out;
        }
        res = write(outfd, readLongBuff, xfer_len);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, ME "couldn't write to %s", out_fname);
            perror(ebuff);
            goto err_out;
        }
        if (! got_stdout)
            close(outfd);
    }

err_out:
    if (free_rawp)
        free(free_rawp);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_read_long failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
