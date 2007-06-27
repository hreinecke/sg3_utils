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

static char * version_str = "1.06 20051025";

#define READ_LONG_OPCODE 0x3E
#define READ_LONG_CMD_LEN 10
#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
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

static int info_offset(unsigned char * sensep, int sb_len)
{
    int resp_code;

    if (sb_len < 8)
        return 0;
    resp_code = (0x7f & sensep[0]);
    if (resp_code >= 0x72) { /* descriptor format */
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

static int has_blk_ili(unsigned char * sensep, int sb_len)
{
    int resp_code;
    const unsigned char * cup;

    if (sb_len < 8)
        return 0;
    resp_code = (0x7f & sensep[0]);
    if (resp_code >= 0x72) { /* descriptor format */
        /* find block command descriptor */
        if ((cup = sg_scsi_sense_desc_find(sensep, sb_len, 0x5)))
            return ((cup[3] & 0x20) ? 1 : 0);
    } else /* fixed */
        return ((sensep[2] & 0x20) ? 1 : 0);
    return 0;
}

/* Invokes a SCSI READ LONG (10) command. Return of 0 -> success,
 * 1 -> ILLEGAL REQUEST with info field written to offsetp,
 * SG_LIB_CAT_INVALID_OP -> Verify(10) not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
static int sg_ll_read_long10(int sg_fd, int correct, unsigned long lba,
                             void * data_out, int xfer_len, int * offsetp,
                             int verbose)
{
    int k, res, offset;
    unsigned char readLongCmdBlk[READ_LONG_CMD_LEN];
    struct sg_io_hdr io_hdr;
    struct sg_scsi_sense_hdr ssh;
    unsigned char sense_buffer[SENSE_BUFF_LEN];

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
    io_hdr.dxferp = data_out;
    io_hdr.cmdp = readLongCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror(ME "SG_IO ioctl READ LONG(10) error");
        return -1;
    }

    /* now for the error processing */
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("READ LONG(10), continuing", &io_hdr, verbose > 1);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        if (verbose > 1)
            sg_chk_n_print3("READ LONG(10) command problem", &io_hdr, 1);
        return res;
    default:
        if (verbose > 1)
            sg_chk_n_print3("READ LONG(10) sense", &io_hdr, 1);
        if ((sg_normalize_sense(&io_hdr, &ssh)) &&
            (ssh.sense_key == ILLEGAL_REQUEST) &&
            ((offset = info_offset(io_hdr.sbp, io_hdr.sb_len_wr)))) {
            if (has_blk_ili(io_hdr.sbp, io_hdr.sb_len_wr)) {
                if (offsetp)
                        *offsetp = offset;
                return 1;
            } else if (verbose)
                fprintf(stderr, "  info field [%d], but ILI clear ??\n",
                        offset);
        }
        if (SG_LIB_CAT_ILLEGAL_REQ == res)
            return res;
        return -1;
    }
}

/* Returns 0 if successful, else -1 */
static int process_read_long(int sg_fd, int correct, unsigned long lba,
                             void * data_out, int xfer_len, int verbose)
{
    int offset, res;

    res = sg_ll_read_long10(sg_fd, correct, lba, data_out, xfer_len,
                            &offset, verbose);
    switch (res) {
    case 0:
        return 0;
    case 1:
        fprintf(stderr, "<<< device indicates 'xfer_len' should be %d "
                ">>>\n", xfer_len - offset);
        return -1;
    case SG_LIB_CAT_INVALID_OP:
        fprintf(stderr, "  SCSI READ LONG (10) command not supported\n");
        return -1;
    case SG_LIB_CAT_ILLEGAL_REQ:
        fprintf(stderr, "  SCSI READ LONG (10) command, bad field in cdb\n");
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
    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", device_name);
        perror("");
        return 1;
    }

    if (NULL == (rawp = malloc(MAX_XFER_LEN))) {
        fprintf(stderr, ME "out of memory (query)\n");
        close(sg_fd);
        return 1;
    }
    readLongBuff = rawp;
    memset(rawp, 0x0, MAX_XFER_LEN);

    fprintf(stderr, ME "issue read long to device %s\n\t\txfer_len=%d "
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
    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}
