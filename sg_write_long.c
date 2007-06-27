#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include "sg_include.h"
#include "sg_lib.h"

/* A utility program for the Linux OS SCSI subsystem.
   *  Copyright (C) 2004 D. Gilbert
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

static char * version_str = "5.36 20041011";

#define WRITE_LONG_OPCODE 0x3F
#define WRITE_LONG_CMD_LEN 10

/* #define SG_DEBUG */

#define ME "sg_write_long: "

#define EBUFF_SZ 256

static struct option long_options[] = {
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
          "sg_write_long [--help] [--in=<name>] [--lba=<num>] [--verbose]\n"
          "                     [--version] [--xfer_len=<num>] <scsi_device>\n"
          "  where: --help            print out usage message\n"
          "         --in=<name>       input from file <name> (default write "
          "0xff bytes)\n"
          "         --lba=<num>|-l <num>  logical block address (default 0)\n"
          "         --verbose|-v      increase verbosity\n"
          "         --version|-V      print version string then exit\n"
          "         --xfer_len=<num>|-x <num>  transfer length (<1000) "
          "default 520\n"
          "\n To read from a defected sector use:\n"
          "    sg_dd if=<scsi_device> skip=<lba> of=/dev/null bs=512 "
          "count=1\n"
          " To write to a defected sector use:\n"
          "    sg_dd of=<scsi_device> seek=<lba> if=/dev/zero bs=512 "
          "count=1\n"       
          );
}

static int info_offset(unsigned char * sensep, int sb_len)
{
    int resp_code;
    const unsigned char * cup;

    if (sb_len < 8)
        return 0;
    resp_code = (0x7f & sensep[0]);
    if (resp_code>= 0x72) { /* descriptor format */
        /* find Information descriptor */
        if ((cup = sg_scsi_sense_desc_find(sensep, sb_len, 0x0))) {
            if ((0 == cup[4]) && (0 == cup[5]) && (0 == cup[6]) &&
                (0 == cup[7]) && (0 == cup[8]) && (0 == cup[9]))
                return ((cup[10] << 8) + cup[11]);
            else if ((0xff == cup[4]) && (0xff == cup[5]) &&
                     (0xff == cup[6]) && (0xff == cup[7]) &&
                     (0xff == cup[8]) && (0xff == cup[9]))
                return ((cup[10] << 8) + cup[11] - (int)0x10000);
        }
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
    int sg_fd, res, c, infd, sb_len, offset, k;
    unsigned char writeLongCmdBlk [WRITE_LONG_CMD_LEN];
    unsigned char * writeLongBuff = NULL;
    void * rawp = NULL;
    unsigned char sense_buffer[64];
    int xfer_len = 520;
    unsigned int lba = 0;
    int verbose = 0;
    int got_stdin;
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

        c = getopt_long(argc, argv, "hi:l:vVx:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            strncpy(file_name, optarg, sizeof(file_name));
            break;
        case 'l':
            lba = sg_get_num(optarg);
            if ((unsigned int)(-1) == lba) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return 1;
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
    sg_fd = open(device_name, O_RDWR);
    if (sg_fd < 0) {
        perror(ME "open error");
        return 1;
    }
  
    if (NULL == (rawp = malloc(1000))) {
        fprintf(stderr, ME "out of memory (query)\n");
        close(sg_fd);
        return 1;
    }
    writeLongBuff = rawp;
    memset(rawp, 0xff, 1000);
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

    memset(writeLongCmdBlk, 0, WRITE_LONG_CMD_LEN);
    writeLongCmdBlk[0] = WRITE_LONG_OPCODE;
  
    /*lba*/
    writeLongCmdBlk[2] = (lba & 0xff000000) >> 24;
    writeLongCmdBlk[3] = (lba & 0x00ff0000) >> 16;
    writeLongCmdBlk[4] = (lba & 0x0000ff00) >> 8;
    writeLongCmdBlk[5] = (lba & 0x000000ff);
    /*size*/
    writeLongCmdBlk[7] = (xfer_len & 0x0000ff00) >> 8;
    writeLongCmdBlk[8] = (xfer_len & 0x000000ff);
  
    fprintf(stderr, ME "issue write long to device %s\n\t\txfer_len= %d "
            "(0x%x), lba=%d (0x%x)\n", device_name, xfer_len, xfer_len,
            lba, lba);
  
    if (verbose) {
        fprintf(stderr, "    Write Long (10) cmd: ");
        for (k = 0; k < WRITE_LONG_CMD_LEN; ++k)
            fprintf(stderr, "%02x ", writeLongCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(writeLongCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = xfer_len;
    io_hdr.dxferp = writeLongBuff;
    io_hdr.cmdp = writeLongCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */
    /* do normal IO to find RB size (not dio or mmap-ed at this stage) */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror(ME "SG_IO ioctl WRITE LONG error");
        goto err_out;
    }

    sb_len = io_hdr.sb_len_wr;
    /* now for the error processing */
    switch (sg_err_category3(&io_hdr)) {
        case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        fprintf(stderr, "Recovered error on WRITE LONG command, "
                "continuing\n");
        break;
    default: /* won't bother decoding other categories */
        if ((sg_normalize_sense(&io_hdr, &ssh)) &&
            (ssh.sense_key == ILLEGAL_REQUEST) &&
            ((offset = info_offset(io_hdr.sbp, io_hdr.sb_len_wr)))) {
            if (verbose)
                sg_chk_n_print3("WRITE LONG command problem", &io_hdr);
            fprintf(stderr, "<<< nothing written to device >>>\n");
            fprintf(stderr, "<<< device indicates 'xfer_len' should be %d "
                    ">>>\n", xfer_len - offset);
            if (! has_ili(io_hdr.sbp, io_hdr.sb_len_wr))
                fprintf(stderr, "    [Invalid Length Indication (ILI) flag "
                        "expected but not found]\n");
            goto err_out;
        }
        sg_chk_n_print3("WRITE LONG problem error", &io_hdr);
        goto err_out;
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
