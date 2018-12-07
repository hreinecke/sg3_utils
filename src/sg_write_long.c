/* A utility program for the Linux OS SCSI subsystem.
 *  Copyright (C) 2004-2018 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program issues the SCSI command WRITE LONG to a given SCSI device.
 * It sends the command with the logical block address passed as the lba
 * argument, and the transfer length set to the xfer_len argument. the
 * buffer to be written to the device filled with 0xff, this buffer includes
 * the sector data and the ECC bytes.
 *
 * This code was contributed by Saeed Bishara
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
#include "sg_pr2serr.h"

static const char * version_str = "1.21 20180723";


#define MAX_XFER_LEN (15 * 1024)

#define ME "sg_write_long: "

#define EBUFF_SZ 512

static struct option long_options[] = {
        {"16", no_argument, 0, 'S'},
        {"cor_dis", no_argument, 0, 'c'},
        {"cor-dis", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"in", required_argument, 0, 'i'},
        {"lba", required_argument, 0, 'l'},
        {"pblock", no_argument, 0, 'p'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wr_uncor", no_argument, 0, 'w'},
        {"wr-uncor", no_argument, 0, 'w'},
        {"xfer_len", required_argument, 0, 'x'},
        {"xfer-len", required_argument, 0, 'x'},
        {0, 0, 0, 0},
};



static void
usage()
{
  pr2serr("Usage: sg_write_long [--16] [--cor_dis] [--help] [--in=IF] "
          "[--lba=LBA]\n"
          "                     [--pblock] [--verbose] [--version] "
          "[--wr_uncor]\n"
          "                     [--xfer_len=BTL] DEVICE\n"
          "  where:\n"
          "    --16|-S              do WRITE LONG(16) (default: 10)\n"
          "    --cor_dis|-c         set correction disabled bit\n"
          "    --help|-h            print out usage message\n"
          "    --in=IF|-i IF        input from file called IF (default: "
          "use\n"
          "                         0xff bytes as fill)\n"
          "    --lba=LBA|-l LBA     logical block address "
          "(default: 0)\n"
          "    --pblock|-p          physical block (default: logical "
          "block)\n"
          "    --verbose|-v         increase verbosity\n"
          "    --version|-V         print version string then exit\n"
          "    --wr_uncor|-w        set an uncorrectable error (no "
          "data transferred)\n"
          "    --xfer_len=BTL|-x BTL    byte transfer length (< 10000) "
          "(default:\n"
          "                             520 bytes)\n\n"
          "Performs a SCSI WRITE LONG (10 or 16) command. Writes a single "
          "block\nincluding associated ECC data. That data may be obtained "
          "from the\nSCSI READ LONG command. See the sg_read_long utility.\n"
          );
}

int
main(int argc, char * argv[])
{
    bool do_16 = false;
    bool cor_dis = false;
    bool got_stdin;
    bool pblock = false;
    bool verbose_given = false;
    bool version_given = false;
    bool wr_uncor = false;
    int res, c, infd, offset;
    int sg_fd = -1;
    int xfer_len = 520;
    int ret = 1;
    int verbose = 0;
    int64_t ll;
    uint64_t llba = 0;
    const char * device_name = NULL;
    uint8_t * writeLongBuff = NULL;
    void * rawp = NULL;
    uint8_t * free_rawp = NULL;
    const char * ten_or;
    char file_name[256];
    char b[80];
    char ebuff[EBUFF_SZ];

    memset(file_name, 0, sizeof file_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "chi:l:pSvVwx:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            cor_dis = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            strncpy(file_name, optarg, sizeof(file_name) - 1);
            file_name[sizeof(file_name) - 1] = '\0';
            break;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            llba = (uint64_t)ll;
            break;
        case 'p':
            pblock = true;
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
        case 'w':
            wr_uncor = true;
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
    if (wr_uncor)
        xfer_len = 0;
    else if (xfer_len >= MAX_XFER_LEN) {
        pr2serr("xfer_len (%d) is out of range ( < %d)\n", xfer_len,
                MAX_XFER_LEN);
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, false /* rw */, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto err_out;
    }

    if (wr_uncor) {
        if ('\0' != file_name[0])
            pr2serr(">>> warning: when '--wr_uncor' given '-in=' is "
                    "ignored\n");
    } else {
        if (NULL == (rawp = sg_memalign(MAX_XFER_LEN, 0, &free_rawp, false))) {
            pr2serr(ME "out of memory\n");
            ret = sg_convert_errno(ENOMEM);
            goto err_out;
        }
        writeLongBuff = (uint8_t *)rawp;
        memset(rawp, 0xff, MAX_XFER_LEN);
        if (file_name[0]) {
            got_stdin = (0 == strcmp(file_name, "-"));
            if (got_stdin) {
                infd = STDIN_FILENO;
                if (sg_set_binary_mode(STDIN_FILENO) < 0)
                    perror("sg_set_binary_mode");
            } else {
                if ((infd = open(file_name, O_RDONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for reading", file_name);
                    perror(ebuff);
                    goto err_out;
                } else if (sg_set_binary_mode(infd) < 0)
                    perror("sg_set_binary_mode");
            }
            res = read(infd, writeLongBuff, xfer_len);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s",
                         file_name);
                perror(ebuff);
                if (! got_stdin)
                    close(infd);
                goto err_out;
            }
            if (res < xfer_len) {
                pr2serr("tried to read %d bytes from %s, got %d bytes\n",
                        xfer_len, file_name, res);
                pr2serr("pad with 0xff bytes and continue\n");
            }
            if (! got_stdin)
                close(infd);
        }
    }
    if (verbose)
        pr2serr(ME "issue write long to device %s\n\t\txfer_len= %d (0x%x), "
                "lba=%" PRIu64 " (0x%" PRIx64 ")\n    cor_dis=%d, "
                "wr_uncor=%d, pblock=%d\n", device_name, xfer_len, xfer_len,
                llba, llba, (int)cor_dis, (int)wr_uncor, (int)pblock);

    ten_or = do_16 ? "16" : "10";
    if (do_16)
        res = sg_ll_write_long16(sg_fd, cor_dis, wr_uncor, pblock, llba,
                                 writeLongBuff, xfer_len, &offset, true,
                                 verbose);
    else
        res = sg_ll_write_long10(sg_fd, cor_dis, wr_uncor, pblock,
                                 (unsigned int)llba, writeLongBuff, xfer_len,
                                 &offset, true, verbose);
    ret = res;
    switch (res) {
    case 0:
        break;
    case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:
        pr2serr("<<< device indicates 'xfer_len' should be %d >>>\n",
                xfer_len - offset);
        break;
    default:
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("  SCSI WRITE LONG (%s): %s\n", ten_or, b);
        break;
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
        if (! sg_if_can2stderr("sg_write_long failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
