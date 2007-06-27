#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
   *  Copyright (C) 2004-2006 D. Gilbert
   *  This program is free software; you can redistribute it and/or modify
   *  it under the terms of the GNU General Public License as published by
   *  the Free Software Foundation; either version 2, or (at your option)
   *  any later version.

   This program issues the SCSI command WRITE LONG to a given SCSI device. 
   It sends the command with the logical block address passed as the lba
   argument, and the transfer length set to the xfer_len argument. the
   buffer to be writen to the device filled with 0xff, this buffer includes
   the sector data and the ECC bytes.

   This code was contributed by Saeed Bishara
*/

static char * version_str = "1.10 20060623";


#define MAX_XFER_LEN 10000

/* #define SG_DEBUG */

#define ME "sg_write_long: "

#define EBUFF_SZ 256

static struct option long_options[] = {
        {"cor_dis", 0, 0, 'c'},
        {"help", 0, 0, 'h'},
        {"in", 1, 0, 'i'},
        {"lba", 1, 0, 'l'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {"xfer_len", 1, 0, 'x'},
        {0, 0, 0, 0},
};

static void usage()
{
  fprintf(stderr, "Usage: "
          "sg_write_long [--cor_dis] [--help] [--in=<name>] [--lba=<num>]\n"
          "                     [--verbose] [--version] [--xfer_len=<num>] "
          "<scsi_device>\n"
          "  where: --cor_dis         set correction disabled bit\n"
          "         --help            print out usage message\n"
          "         --in=<name>       input from file <name> (default write "
          "0xff bytes)\n"
          "         --lba=<num>|-l <num>  logical block address (default 0)\n"
          "         --verbose|-v      increase verbosity\n"
          "         --version|-V      print version string then exit\n"
          "         --xfer_len=<num>|-x <num>  transfer length (< 10000) "
          "default 520\n"
          "\n To read from a defected sector use:\n"
          "    sg_dd if=<scsi_device> skip=<lba> of=/dev/null bs=512 "
          "count=1\n"
          " To write to a defected sector use:\n"
          "    sg_dd of=<scsi_device> seek=<lba> if=/dev/zero bs=512 "
          "count=1\n\n"       
          "Performs a WRITE LONG (10) SCSI command\n"
          );
}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, infd, offset;
    unsigned char * writeLongBuff = NULL;
    void * rawp = NULL;
    int xfer_len = 520;
    int cor_dis = 0;
    unsigned long lba = 0;
    int verbose = 0;
    int got_stdin;
    char device_name[256];
    char file_name[256];
    char ebuff[EBUFF_SZ];
    int ret = 1;
    
    memset(device_name, 0, sizeof device_name);
    memset(file_name, 0, sizeof file_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "chi:l:vVx:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            cor_dis = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            strncpy(file_name, optarg, sizeof(file_name));
            break;
        case 'l':
            lba = sg_get_num(optarg);
            if ((unsigned long)(-1) == lba) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
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
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
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
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (0 == device_name[0]) {
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
    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
  
    if (NULL == (rawp = malloc(MAX_XFER_LEN))) {
        fprintf(stderr, ME "out of memory (query)\n");
        sg_cmds_close_device(sg_fd);
        return SG_LIB_SYNTAX_ERROR;
    }
    writeLongBuff = rawp;
    memset(rawp, 0xff, MAX_XFER_LEN);
    if (file_name[0]) {
        got_stdin = (0 == strcmp(file_name, "-")) ? 1 : 0;
        if (got_stdin)
            infd = 0;
        else {
            if ((infd = open(file_name, O_RDONLY)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", file_name);
                perror(ebuff);
                goto err_out;
            }
        }
        res = read(infd, writeLongBuff, xfer_len);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s", file_name);
            perror(ebuff);
            goto err_out;
        }
        if (res < xfer_len) {
            fprintf(stderr, "tried to read %d bytes from %s, got %d bytes\n",
                    xfer_len, file_name, res);
            fprintf(stderr, "pad with 0xff bytes and continue\n");
        }
        if (! got_stdin)
            close(infd);
    }
    if (verbose)
        fprintf(stderr, ME "issue write long to device %s\n\t\txfer_len= %d "
                "(0x%x), lba=%lu (0x%lx)\n", device_name, xfer_len, xfer_len,
                lba, lba);

    res = sg_ll_write_long10(sg_fd, cor_dis, lba, writeLongBuff, xfer_len,
                             &offset, 1, verbose);
    ret = res;
    switch (res) {
    case 0:
        break;
    case SG_LIB_CAT_NOT_READY:
        fprintf(stderr, "  SCSI WRITE LONG (10) failed, device not ready\n");
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:
        fprintf(stderr, "  SCSI WRITE LONG (10), unit attention\n");
        break;
    case SG_LIB_CAT_INVALID_OP:
        fprintf(stderr, "  SCSI WRITE LONG (10) command not supported\n");
        break;
    case SG_LIB_CAT_ILLEGAL_REQ:
        fprintf(stderr, "  SCSI WRITE LONG (10) command, bad field in cdb\n");
        break;
    case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:
        fprintf(stderr, "<<< device indicates 'xfer_len' should be %d "
                ">>>\n", xfer_len - offset);
        break;
    default:
        fprintf(stderr, "  SCSI WRITE LONG (10) command error\n");
        break;
    }

err_out:
    if (rawp)
        free(rawp);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
