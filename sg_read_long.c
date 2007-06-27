#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"

/* A utility program for the Linux OS SCSI subsystem.
   *  Copyright (C) 2004-2005 D. Gilbert
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

static char * version_str = "1.04 20050118";

#define READ_LONG_OPCODE 0x3E
#define READ_LONG_CMD_LEN 10

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
          "         --xfer_len=<num>|-x <num>  transfer length (<1000)"
          " default 520\n"
          );
}

static int info_offset(unsigned char * sensep, int sb_len)
{
    int resp_code;

    if (sb_len < 8)
        return 0;
    resp_code = (0x7f & sensep[0]);
    if (resp_code>= 0x72) { /* descriptor format */
        unsigned long long ull = 0;

        /* if Information field, fetch it; contains signed number */
        if (sg_get_sense_info_fld(sensep, sb_len, &ull))
            return (int)(long long)ull;
    } else if (sensep[0] & 0x80) { /* fixed, valid set */
        if ((0 == sensep[3]) && (0 == sensep[4]))
            return ((sensep[5] << 8) + sensep[6]);
        else if ((0xff == sensep[3]) && (0xff == sensep[4]))
            return ((sensep[5] << 8) + sensep[6] - (int)0x10000);
    }
    return 0;
}

static int has_ili(unsigned char * sensep, int sb_len)
{
    int resp_code;
    const unsigned char * cup;

    if (sb_len < 8)
        return 0;
    resp_code = (0x7f & sensep[0]);
    if (resp_code>= 0x72) { /* descriptor format */
        /* find block command descriptor */
        if ((cup = sg_scsi_sense_desc_find(sensep, sb_len, 0x5)))
            return ((cup[3] & 0x20) ? 1 : 0);
    } else /* fixed */
        return ((sensep[2] & 0x20) ? 1 : 0);
    return 0;
}

int main(int argc, char * argv[])
{
    int sg_fd, outfd, res, c, k, offset;
    unsigned char readLongCmdBlk [READ_LONG_CMD_LEN];
    unsigned char * readLongBuff = NULL;
    void * rawp = NULL;
    unsigned char sense_buffer[32];
    int correct = 0;
    int xfer_len = 520;
    unsigned int lba = 0;
    int verbose = 0;
    int got_stdout;
    char device_name[256];
    char file_name[256];
    char ebuff[EBUFF_SZ];
    struct sg_io_hdr io_hdr;
    struct sg_scsi_sense_hdr ssh;
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    memset(file_name, 0, sizeof file_name);
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
            strncpy(file_name, optarg, sizeof(file_name));
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
    if (xfer_len >= 1000){
        fprintf(stderr, "xfer_len (%d) is out of range ( < 1000)\n",
                xfer_len);
        usage();
        return 1;
    }
    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", device_name);
        perror("");
        return 1;
    }

    if (NULL == (rawp = malloc(1000))) {
        fprintf(stderr, ME "out of memory (query)\n");
        close(sg_fd);
        return 1;
    }
    readLongBuff = rawp;
    memset(rawp, 0x0, 1000);
    memset(readLongCmdBlk, 0, READ_LONG_CMD_LEN);
    readLongCmdBlk[0] = READ_LONG_OPCODE;
    if (correct)
        readLongCmdBlk[1] |= 0x2;

    /*lba*/
    readLongCmdBlk[2] = (lba & 0xff000000) >> 24;
    readLongCmdBlk[3] = (lba & 0x00ff0000) >> 16;
    readLongCmdBlk[4] = (lba & 0x0000ff00) >> 8;
    readLongCmdBlk[5] = (lba & 0x000000ff);
    /*size*/
    readLongCmdBlk[7] = (xfer_len & 0x0000ff00) >> 8;
    readLongCmdBlk[8] = (xfer_len & 0x000000ff);

    fprintf(stderr, ME "issue read long to device %s\n\t\txfer_len=%d "
            "(0x%x), lba=%d (0x%x), correct=%d\n", device_name, xfer_len,
            xfer_len, lba, lba, correct);

    if (verbose) {
        fprintf(stderr, "    Read Long (10) cmd: ");
        for (k = 0; k < READ_LONG_CMD_LEN; ++k)
            fprintf(stderr, "%02x ", readLongCmdBlk[k]);
        fprintf(stderr, "\n");
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(readLongCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = xfer_len;
    io_hdr.dxferp = readLongBuff;
    io_hdr.cmdp = readLongCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */
    /* do normal IO to find RB size (not dio or mmap-ed at this stage) */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror(ME "SG_IO ioctl READ LONG error");
        goto err_out;
    }

    /* now for the error processing */
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        fprintf(stderr, "Recovered error on READ LONG command, "
                "continuing\n");
        break;
    default: /* won't bother decoding other categories */
        if ((sg_normalize_sense(&io_hdr, &ssh)) &&
            (ssh.sense_key == ILLEGAL_REQUEST) &&
            ((offset = info_offset(io_hdr.sbp, io_hdr.sb_len_wr)))) {
            if (verbose)
                sg_chk_n_print3("READ LONG command problem", &io_hdr);
            fprintf(stderr, "<<< device indicates 'xfer_len' should be %d "
                    ">>>\n", xfer_len - offset);
            if (! has_ili(io_hdr.sbp, io_hdr.sb_len_wr))
                fprintf(stderr, "    [Invalid Length Indication (ILI) flag "
                        "expected but not found]\n");
            goto err_out;
        }
        sg_chk_n_print3("READ LONG command problem", &io_hdr);
        goto err_out;
    }
    if ('\0' == file_name[0])
        dStrHex(rawp, xfer_len, 0);
    else {
        got_stdout = (0 == strcmp(file_name, "-")) ? 1 : 0;
        if (got_stdout)
            outfd = 1;
        else {
            if ((outfd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC,
                              0666)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for writing", file_name);
                perror(ebuff);
                goto err_out;
            }
        }
        res = write(outfd, readLongBuff, xfer_len);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, ME "couldn't write to %s", file_name);
            perror(ebuff);
            goto err_out;
        }
        if (! got_stdout)
            close(outfd);
    }

    ret = 0;
err_out:
    if (rawp) free(rawp);
    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}
