#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
   *  Copyright (C) 2004-2006 D. Gilbert
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

static char * version_str = "1.07 20060106";

#define MAX_XFER_LEN 10000

#define ME "sg_read_long: "

#define EBUFF_SZ 256


static struct option long_options[] = {
        {"correct", 0, 0, 'c'},
        {"help", 0, 0, 'h'},
        {"lba", 1, 0, 'l'},
        {"out", 1, 0, 'o'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {"xfer_len", 1, 0, 'x'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_read_long [--correct] [--help] [--lba=<num>] [--out=<name>]\n"
          "                    [--verbose] [--version] [--xfer_len=<num>]"
          " <scsi_device>\n"
          "  where: --correct|-c               use ECC to correct data "
          "(default: don't)\n"
          "         --help|-h                  print out usage message\n"
          "         --lba=<num>|-l <num>       logical block address"
          " (default 0)\n"
          "         --out=<name>|-o <name>     output to file <name>\n"
          "         --verbose|-v               increase verbosity\n"
          "         --version|-V               print version string and"
          " exit\n"
          "         --xfer_len=<num>|-x <num>  transfer length (< 10000)"
          " default 520\n\n"
          "Perform a READ LONG SCSI command\n"
          );
}

/* Returns 0 if successful, else -1 */
static int process_read_long(int sg_fd, int correct, unsigned long lba,
                             void * data_out, int xfer_len, int verbose)
{
    int offset, res;

    res = sg_ll_read_long10(sg_fd, correct, lba, data_out, xfer_len,
                            &offset, 1, verbose);
    switch (res) {
    case 0:
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        fprintf(stderr, "  SCSI READ LONG (10) command not supported\n");
        return -1;
    case SG_LIB_CAT_ILLEGAL_REQ:
        fprintf(stderr, "  SCSI READ LONG (10) command, bad field in cdb\n");
        return -1;
    case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:
        fprintf(stderr, "<<< device indicates 'xfer_len' should be %d "
                ">>>\n", xfer_len - offset);
        return -1;
    default:
        fprintf(stderr, "  SCSI READ LONG (10) command error\n");
        return -1;
    }
}


int main(int argc, char * argv[])
{
    int sg_fd, outfd, res, c;
    unsigned char * readLongBuff = NULL;
    void * rawp = NULL;
    int correct = 0;
    int xfer_len = 520;
    unsigned int lba = 0;
    int verbose = 0;
    int got_stdout;
    char device_name[256];
    char out_fname[256];
    char ebuff[EBUFF_SZ];
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    memset(out_fname, 0, sizeof out_fname);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "chl:o:vVx:", long_options,
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
            lba = sg_get_num(optarg);
            if ((unsigned int)(-1) == lba) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return 1;
            }
            break;
        case 'o':
            strncpy(out_fname, optarg, sizeof(out_fname));
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
                return 1;
            }
            break;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if ('\0' == device_name[0]) {
            strncpy(device_name, argv[optind], sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }

    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    if (xfer_len >= MAX_XFER_LEN){
        fprintf(stderr, "xfer_len (%d) is out of range ( < %d)\n",
                xfer_len, MAX_XFER_LEN);
        usage();
        return 1;
    }
    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return 1;
    }

    if (NULL == (rawp = malloc(MAX_XFER_LEN))) {
        fprintf(stderr, ME "out of memory (query)\n");
        sg_cmds_close_device(sg_fd);
        return 1;
    }
    readLongBuff = rawp;
    memset(rawp, 0x0, MAX_XFER_LEN);

    fprintf(stderr, ME "issue read long (10) to device %s\n\t\txfer_len=%d "
            "(0x%x), lba=%d (0x%x), correct=%d\n", device_name, xfer_len,
            xfer_len, lba, lba, correct);

    if (process_read_long(sg_fd, correct, lba, readLongBuff, xfer_len,
                          verbose))
        goto err_out;

    if ('\0' == out_fname[0])
        dStrHex(rawp, xfer_len, 0);
    else {
        got_stdout = (0 == strcmp(out_fname, "-")) ? 1 : 0;
        if (got_stdout)
            outfd = 1;
        else {
            if ((outfd = open(out_fname, O_WRONLY | O_CREAT | O_TRUNC,
                              0666)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for writing", out_fname);
                perror(ebuff);
                goto err_out;
            }
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

    ret = 0;
err_out:
    if (rawp) free(rawp);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, ME "close error: %s\n", safe_strerror(-res));
        return 1;
    }
    return ret;
}
