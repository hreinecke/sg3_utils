#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* A utility program for the Linux OS SCSI subsystem.
   *  Copyright (C) 2004-2010 D. Gilbert
   *  This program is free software; you can redistribute it and/or modify
   *  it under the terms of the GNU General Public License as published by
   *  the Free Software Foundation; either version 2, or (at your option)
   *  any later version.

   This program issues the SCSI command READ LONG to a given SCSI device.
   It sends the command with the logical block address passed as the lba
   argument, and the transfer length set to the xfer_len argument. the
   buffer to be writen to the device filled with 0xff, this buffer includes
   the sector data and the ECC bytes.
*/

static char * version_str = "1.18 20101215";

#define MAX_XFER_LEN 10000

#define ME "sg_read_long: "

#define EBUFF_SZ 256


static struct option long_options[] = {
        {"16", 0, 0, 'S'},
        {"correct", 0, 0, 'c'},
        {"help", 0, 0, 'h'},
        {"lba", 1, 0, 'l'},
        {"out", 1, 0, 'o'},
        {"pblock", 0, 0, 'p'},
        {"readonly", 0, 0, 'r'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {"xfer_len", 1, 0, 'x'},
        {0, 0, 0, 0},
};

static void
usage()
{
    fprintf(stderr, "Usage: "
          "sg_read_long [--16] [--correct] [--help] [--lba=LBA] "
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
          "block with\nassociated ECC data. User data could be scrambled.\n"
          );
}

/* Returns 0 if successful */
static int
process_read_long(int sg_fd, int do_16, int pblock, int correct,
                  uint64_t llba, void * data_out, int xfer_len, int verbose)
{
    int offset, res;
    const char * ten_or;

    if (do_16)
        res = sg_ll_read_long16(sg_fd, pblock, correct, llba, data_out,
                                xfer_len, &offset, 1, verbose);
    else
        res = sg_ll_read_long10(sg_fd, pblock, correct, (unsigned int)llba,
                                data_out, xfer_len, &offset, 1, verbose);
    ten_or = do_16 ? "16" : "10";
    switch (res) {
    case 0:
        break;
    case SG_LIB_CAT_NOT_READY:
        fprintf(stderr, "  SCSI READ LONG (%s) failed, device not ready\n",
                ten_or);
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:
        fprintf(stderr, "  SCSI READ LONG (%s) failed, unit attention\n",
                ten_or);
        break;
    case SG_LIB_CAT_ABORTED_COMMAND:
        fprintf(stderr, "  SCSI READ LONG (%s) failed, aborted command\n",
                ten_or);
        break;
    case SG_LIB_CAT_INVALID_OP:
        fprintf(stderr, "  SCSI READ LONG (%s) command not supported\n",
                ten_or);
        break;
    case SG_LIB_CAT_ILLEGAL_REQ:
        fprintf(stderr, "  SCSI READ LONG (%s) command, bad field in cdb\n",
                ten_or);
        break;
    case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:
        fprintf(stderr, "<<< device indicates 'xfer_len' should be %d "
                ">>>\n", xfer_len - offset);
        break;
    default:
        fprintf(stderr, "  SCSI READ LONG (%s) command error\n", ten_or);
        break;
    }
    return res;
}


int
main(int argc, char * argv[])
{
    int sg_fd, outfd, res, c;
    unsigned char * readLongBuff = NULL;
    void * rawp = NULL;
    int correct = 0;
    int xfer_len = 520;
    int do_16 = 0;
    int pblock = 0;
    uint64_t llba = 0;
    int readonly = 0;
    int verbose = 0;
    int64_t ll;
    int got_stdout;
    const char * device_name = NULL;
    char out_fname[256];
    char ebuff[EBUFF_SZ];
    int ret = 0;

    memset(out_fname, 0, sizeof out_fname);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "chl:o:prSvVx:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            correct = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            llba = (uint64_t)ll;
            break;
        case 'o':
            strncpy(out_fname, optarg, sizeof(out_fname) - 1);
            break;
        case 'p':
            pblock = 1;
            break;
        case 'r':
            ++readonly;
            break;
        case 'S':
            do_16 = 1;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        case 'x':
            xfer_len = sg_get_num(optarg);
           if (-1 == xfer_len) {
                fprintf(stderr, "bad argument to '--xfer_len'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
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
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (xfer_len >= MAX_XFER_LEN){
        fprintf(stderr, "xfer_len (%d) is out of range ( < %d)\n",
                xfer_len, MAX_XFER_LEN);
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (NULL == (rawp = malloc(MAX_XFER_LEN))) {
        fprintf(stderr, ME "out of memory\n");
        sg_cmds_close_device(sg_fd);
        return SG_LIB_SYNTAX_ERROR;
    }
    readLongBuff = (unsigned char *)rawp;
    memset(rawp, 0x0, MAX_XFER_LEN);

    fprintf(stderr, ME "issue read long (%s) to device %s\n    xfer_len=%d "
            "(0x%x), lba=%" PRIu64 " (0x%" PRIx64 "), correct=%d\n",
            (do_16 ? "16" : "10"), device_name, xfer_len, xfer_len, llba,
            llba, correct);

    if ((ret = process_read_long(sg_fd, do_16, pblock, correct, llba,
                                 readLongBuff, xfer_len, verbose)))
        goto err_out;

    if ('\0' == out_fname[0])
        dStrHex((const char *)rawp, xfer_len, 0);
    else {
        got_stdout = (0 == strcmp(out_fname, "-")) ? 1 : 0;
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
    if (rawp) free(rawp);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
