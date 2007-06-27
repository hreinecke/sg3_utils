#define _XOPEN_SOURCE 500
#define _GNU_SOURCE     /* resolves u_char typedef in scsi/scsi.h [lk 2.4] */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h> 
#include <linux/major.h>
#include <linux/fs.h>   /* <sys/mount.h> */
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"
#include "llseek.h"

/* A utility program for copying files. Specialised for "files" that
*  represent devices that understand the SCSI command set.
*
*  Copyright (C) 1999 - 2005 D. Gilbert and P. Allworth
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program is a specialisation of the Unix "dd" command in which
   either the input or the output file is a scsi generic device, raw
   device, a block device or a normal file. The block size ('bs') is 
   assumed to be 512 if not given. This program complains if 'ibs' or 
   'obs' are given with a value that differs from 'bs' (or the default 512).
   If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
   not given or 'of=-' then stdout assumed.

   A non-standard argument "bpt" (blocks per transfer) is added to control
   the maximum number of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16 KiB
   in this case) is transferred to or from the sg device in a single SCSI
   command. The actual size of the SCSI READ or WRITE command block can be
   selected with the "cdbsz" argument.

   This version is designed for the linux kernel 2.4 and 2.6 series.
*/

static char * version_str = "5.38 20050309";

#define ME "sg_dd: "

/* #define SG_DEBUG */

#define STR_SZ 1024
#define INOUTF_SZ 512
#define EBUFF_SZ 512

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define DEF_MODE_CDB_SZ 10
#define DEF_MODE_RESP_LEN 252
#define RW_ERR_RECOVERY_MP 1
#define CACHING_MP 8
#define CONTROL_MP 0xa

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32
#define READ_LONG_OPCODE 0x3E
#define READ_LONG_CMD_LEN 10

#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikey value */
#endif 

#define FT_OTHER 1              /* filetype is probably normal */
#define FT_SG 2                 /* filetype is sg char device or supports
                                   SG_IO ioctl */
#define FT_RAW 4                /* filetype is raw char device */
#define FT_DEV_NULL 8           /* either "/dev/null" or "." as filename */
#define FT_ST 16                /* filetype is st char device (tape) */
#define FT_BLOCK 32             /* filetype is block device */

#define DEV_NULL_MINOR_NUM 3

/* If platform does not support O_DIRECT then define it harmlessly */
#ifndef O_DIRECT
#define O_DIRECT 0
#endif

static int sum_of_resids = 0;

static long long dd_count = -1;
static long long req_count = 0;
static long long in_full = 0;
static int in_partial = 0;
static long long out_full = 0;
static int out_partial = 0;
static int recovered_errs = 0;
static int unrecovered_errs = 0;
static int read_longs = 0;

static int do_coe = 0;
static int do_time = 0;
static int verbose = 0;
static int start_tm_valid = 0;
struct timeval start_tm;
static int blk_sz = 0;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

static void calc_duration_throughput();

static void install_handler (int sig_num, void (*sig_handler) (int sig))
{
    struct sigaction sigact;
    sigaction (sig_num, NULL, &sigact);
    if (sigact.sa_handler != SIG_IGN)
    {
        sigact.sa_handler = sig_handler;
        sigemptyset (&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction (sig_num, &sigact, NULL);
    }
}

static void print_stats(const char * str)
{
    if (0 != dd_count)
        fprintf(stderr, "  remaining block count=%lld\n", dd_count);
    fprintf(stderr, "%s%lld+%d records in\n", str, in_full - in_partial, 
            in_partial);
    fprintf(stderr, "%s%lld+%d records out\n", str, out_full - out_partial, 
            out_partial);
    if (recovered_errs > 0)
        fprintf(stderr, "%s%d recovered errors\n", str, recovered_errs);
    if (do_coe) {
        fprintf(stderr, "%s%d unrecovered errors\n", str, unrecovered_errs);
        fprintf(stderr, "%s%d read_longs fetched part of unrecovered "
                "read errors\n", str, read_longs);
    } else if (unrecovered_errs)
        fprintf(stderr, "%s%d unrecovered read error(s)\n", str,
                unrecovered_errs);
}

static void interrupt_handler(int sig)
{
    struct sigaction sigact;

    sigact.sa_handler = SIG_DFL;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(sig, &sigact, NULL);
    fprintf(stderr, "Interrupted by signal,");
    if (do_time)
        calc_duration_throughput();
    print_stats("");
    kill(getpid (), sig);
}

static void siginfo_handler(int sig)
{
    sig = sig;  /* dummy to stop -W warning messages */
    fprintf(stderr, "Progress report, continuing ...\n");
    if (do_time)
        calc_duration_throughput();
    print_stats("  ");
}

static int dd_filetype(const char * filename)
{
    struct stat st;
    size_t len = strlen(filename);

    if ((1 == len) && ('.' == filename[0]))
        return FT_DEV_NULL;
    if (stat(filename, &st) < 0)
        return FT_OTHER;
    if (S_ISCHR(st.st_mode)) {
        if ((MEM_MAJOR == major(st.st_rdev)) && 
            (DEV_NULL_MINOR_NUM == minor(st.st_rdev)))
            return FT_DEV_NULL;
        if (RAW_MAJOR == major(st.st_rdev))
            return FT_RAW;
        if (SCSI_GENERIC_MAJOR == major(st.st_rdev))
            return FT_SG;
        if (SCSI_TAPE_MAJOR == major(st.st_rdev))
            return FT_ST;
    } else if (S_ISBLK(st.st_mode))
        return FT_BLOCK;
    return FT_OTHER;
}

static char * dd_filetype_str(int ft, char * buff)
{
    int off = 0;

    if (FT_DEV_NULL & ft)
        off += snprintf(buff + off, 32, "null device ");
    if (FT_SG & ft)
        off += snprintf(buff + off, 32, "SCSI generic (sg) device ");
    if (FT_BLOCK & ft)
        off += snprintf(buff + off, 32, "block device ");
    if (FT_ST & ft)
        off += snprintf(buff + off, 32, "SCSI tape device ");
    if (FT_RAW & ft)
        off += snprintf(buff + off, 32, "raw device ");
    if (FT_OTHER & ft)
        off += snprintf(buff + off, 32, "other (perhaps name file) ");
    return buff;
}

static void usage()
{
    fprintf(stderr, "Usage: "
           "sg_dd  [if=<infile>] [skip=<n>] [of=<ofile>] [seek=<n> | "
           "append=0|1]\n"
           "              [bs=<num>] [bpt=<num>] [count=<n>] [time=0|1]"
           " [dio=0|1]\n"
           "              [sync=0|1] [cdbsz=6|10|12|16] [fua=0|1|2|3]"
           " [coe=0|1]\n"
           "              [odir=0|1] [blk_sgio=0|1] [verbose=<n>]"
           " [--version]\n"
           " where:\n"
           "  append  1->append output to normal <ofile>, (default is 0)\n"
           "  blk_sgio  0->block device use normal I/O(def), 1->use SG_IO\n"
           "  bpt     is blocks_per_transfer (default is 128)\n"
           "  bs      block size (default is 512)\n");
    fprintf(stderr,
           "  cdbsz   size of SCSI READ or WRITE command (default is 10)\n"
           "  coe     0->exit on error (def), 1->continue on sg error (zero\n"
           "          fill), try read_long on unrecovered read block\n"
           "  dio     is direct IO, 1->attempt, 0->indirect IO (def)\n"
           "  fua     force unit access: 0->don't(def), 1->of, 2->if, "
           "3->of+if\n"
           "  ibs     input block size (if given must be same as 'bs')\n"
           "  if      file or device to read from (def stdin)\n"
           "  obs     output block size (if given must be same as 'bs')\n"
           "  odir    1->use O_DIRECT when opening block dev, 0->don't(def)\n"
           "  of      file or device to write to (def stdout), name '.' "
           "translated to\n");
    fprintf(stderr,
           "          /dev/null\n"
           "  seek    block position to start writing to 'of'\n"
           "  skip    block position to start reading from 'if'\n"
           "  sync    0->no sync(def), 1->SYNCHRONIZE CACHE after "
           "xfer\n"
           "  time    0->no timing(def), 1->time plus calculate throughput\n"
           "  verbose  0->quiet(def), 1->some noise, 2->more noise, etc\n"
           "  --version  print version information then exit\n");
}

/* Return of 0 -> success, SG_LIB_CAT_INVALID_OP -> invalid opcode,
 * SG_LIB_CAT_MEDIA_CHANGED -> media changed, SG_LIB_CAT_ILLEGAL_REQ
 * -> bad field in cdb, -1 -> other failure */
static int scsi_read_capacity(int sg_fd, long long * num_sect, int * sect_sz)
{
    int k, res;
    unsigned char rcBuff[RCAP16_REPLY_LEN];
    int verb;

    verb = (verbose ? verbose - 1: 0);
    res = sg_ll_readcap_10(sg_fd, 0, 0, rcBuff, READ_CAP_REPLY_LEN, verb);
    if (0 != res)
        return res;

    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3])) {
        long long ls;

        res = sg_ll_readcap_16(sg_fd, 0, 0, rcBuff, RCAP16_REPLY_LEN, verb);
        if (0 != res)
            return res;
        for (k = 0, ls = 0; k < 8; ++k) {
            ls <<= 8;
            ls |= rcBuff[k];
        }
        *num_sect = ls + 1;
        *sect_sz = (rcBuff[8] << 24) | (rcBuff[9] << 16) |
                   (rcBuff[10] << 8) | rcBuff[11];
    } else {
        *num_sect = 1 + ((rcBuff[0] << 24) | (rcBuff[1] << 16) |
                    (rcBuff[2] << 8) | rcBuff[3]);
        *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
                   (rcBuff[6] << 8) | rcBuff[7];
    }
    if (verbose)
        fprintf(stderr, "      number of blocks=%lld [0x%llx], block "
                "size=%d\n", *num_sect, *num_sect, *sect_sz);
    return 0;
}

/* Return of 0 -> success, -1 -> failure. BLKGETSIZE64, BLKGETSIZE and */
/* BLKSSZGET macros problematic (from <linux/fs.h> or <sys/mount.h>). */
static int read_blkdev_capacity(int sg_fd, long long * num_sect,
                                int * sect_sz)
{
#ifdef BLKSSZGET
    if ((ioctl(sg_fd, BLKSSZGET, sect_sz) < 0) && (*sect_sz > 0)) {
        perror("BLKSSZGET ioctl error");
        return -1;
    } else {
 #ifdef BLKGETSIZE64
        unsigned long long ull;

        if (ioctl(sg_fd, BLKGETSIZE64, &ull) < 0) {

            perror("BLKGETSIZE64 ioctl error");
            return -1;
        }
        *num_sect = ((long long)ull / (long long)*sect_sz);
        if (verbose)
            fprintf(stderr, "      [bgs64] number of blocks=%lld [0x%llx], "
                    "block size=%d\n", *num_sect, *num_sect, *sect_sz);
 #else
        unsigned long ul;

        if (ioctl(sg_fd, BLKGETSIZE, &ul) < 0) {
            perror("BLKGETSIZE ioctl error");
            return -1;
        }
        *num_sect = (long long)ul;
        if (verbose)
            fprintf(stderr, "      [bgs] number of blocks=%lld [0x%llx], "
                    " block size=%d\n", *num_sect, *num_sect, *sect_sz);
 #endif
    }
    return 0;
#else
    if (verbose)
        fprintf(stderr, "      BLKSSZGET+BLKGETSIZE ioctl not available\n");
    *num_sect = 0;
    *sect_sz = 0;
    return -1;
#endif
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
                             int vverbose)
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

    if (vverbose) {
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
        sg_chk_n_print3("READ LONG(10), continuing", &io_hdr);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        if (vverbose > 1)
            sg_chk_n_print3("READ LONG(10) command problem", &io_hdr);
        return res;
    default:
        if (vverbose > 1)
            sg_chk_n_print3("READ LONG(10) sense", &io_hdr);
        if ((sg_normalize_sense(&io_hdr, &ssh)) &&
            (ssh.sense_key == ILLEGAL_REQUEST) &&
            ((offset = info_offset(io_hdr.sbp, io_hdr.sb_len_wr)))) {
            if (has_blk_ili(io_hdr.sbp, io_hdr.sb_len_wr)) {
                if (offsetp)
                        *offsetp = offset;
                return 1;
            } else if (vverbose)
                fprintf(stderr, "  info field [%d], but ILI clear ??\n",
                        offset);
        }
        if (SG_LIB_CAT_ILLEGAL_REQ == res)
            return res;
        return -1;
    }
}

static int sg_build_scsi_cdb(unsigned char * cdbp, int cdb_sz,
                             unsigned int blocks, long long start_block,
                             int write_true, int fua, int dpo)
{
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};
    int sz_ind;

    memset(cdbp, 0, cdb_sz);
    if (dpo)
        cdbp[1] |= 0x10;
    if (fua)
        cdbp[1] |= 0x8;
    switch (cdb_sz) {
    case 6:
        sz_ind = 0;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[1] = (unsigned char)((start_block >> 16) & 0x1f);
        cdbp[2] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[3] = (unsigned char)(start_block & 0xff);
        cdbp[4] = (256 == blocks) ? 0 : (unsigned char)blocks;
        if (blocks > 256) {
            fprintf(stderr, ME "for 6 byte commands, maximum number of "
                            "blocks is 256\n");
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            fprintf(stderr, ME "for 6 byte commands, can't address blocks"
                            " beyond %d\n", 0x1fffff);
            return 1;
        }
        if (dpo || fua) {
            fprintf(stderr, ME "for 6 byte commands, neither dpo nor fua"
                            " bits supported\n");
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[8] = (unsigned char)(blocks & 0xff);
        if (blocks & (~0xffff)) {
            fprintf(stderr, ME "for 10 byte commands, maximum number of "
                            "blocks is %d\n", 0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[6] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[8] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[9] = (unsigned char)(blocks & 0xff);
        break;
    case 16:
        sz_ind = 3;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 56) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 48) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 40) & 0xff);
        cdbp[5] = (unsigned char)((start_block >> 32) & 0xff);
        cdbp[6] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[7] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[8] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[9] = (unsigned char)(start_block & 0xff);
        cdbp[10] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[11] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[12] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[13] = (unsigned char)(blocks & 0xff);
        break;
    default:
        fprintf(stderr, ME "expected cdb size of 6, 10, 12, or 16 but got"
                        "=%d\n", cdb_sz);
        return 1;
    }
    return 0;
}

/* 0 -> successful, 1 -> recoverable (ENOMEM), 2 -> try again (ua),
   3 -> unrecoverable error with io_addr, -2 -> ioctl or request error,
   -1 -> other SCSI error */
static int sg_read_low(int sg_fd, unsigned char * buff, int blocks,
                       long long from_block, int bs, int cdbsz, int fua,
                       int pdt, int * diop, unsigned long long * io_addrp)
{
    unsigned char rdCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int res, k, info_valid;

    if (sg_build_scsi_cdb(rdCmd, cdbsz, blocks, from_block, 0, fua, 0)) {
        fprintf(stderr, ME "bad rd cdb build, from_block=%lld, blocks=%d\n",
                from_block, blocks);
        return -2;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)from_block;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    if (verbose > 2) {
        fprintf(stderr, "    read cdb: ");
        for (k = 0; k < cdbsz; ++k)
            fprintf(stderr, "%02x ", rdCmd[k]);
        fprintf(stderr, "\n");
    }
    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("reading (SG_IO) on sg device, error");
        return -2;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        ++recovered_errs;
        info_valid = sg_get_sense_info_fld(io_hdr.sbp, io_hdr.sb_len_wr,
                                           io_addrp);
        if (info_valid) {
            fprintf(stderr, "    lba of last recovered error in this "
                    "READ=0x%llx\n", *io_addrp);
            if (verbose > 1)
                sg_chk_n_print3("reading", &io_hdr);
        } else {
            fprintf(stderr, "Recovered error: [no info] reading from "
                    "block=0x%llx, num=%d\n", from_block, blocks);
            sg_chk_n_print3("reading", &io_hdr);
        }
        break;
    case SG_LIB_CAT_MEDIA_CHANGED:
        return 2;
    case SG_LIB_CAT_MEDIUM_HARD:
        if (verbose > 1)
            sg_chk_n_print3("reading", &io_hdr);
        ++unrecovered_errs;
        info_valid = sg_get_sense_info_fld(io_hdr.sbp, io_hdr.sb_len_wr,
                                           io_addrp);
        if ((info_valid) || ((5 == pdt) && (*io_addrp > 0)))
            return 3;   /* MMC devices don't necessarily set VALID bit */
        else {
            fprintf(stderr, "Medium or hardware error but no lba of failure"
                    " given\n");
            return -1;
        }
        break;
    default:
        sg_chk_n_print3("reading", &io_hdr);
        return -1;
    }
    if (diop && *diop && 
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0;      /* flag that dio not done (completely) */
    sum_of_resids += io_hdr.resid;
    if (verbose > 3)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    return 0;
}

/* Returns >= 0 -> number of blocks read, -1 -> unrecoverable error,
   -2 -> recoverable (ENOMEM) */
static int sg_read(int sg_fd, unsigned char * buff, int blocks,
                   long long from_block, int bs, int cdbsz, int fua,
                   int * diop, int pdt)
{
    unsigned long long io_addr;
    long long lba;
    int res, blks, cont, xferred;
    unsigned char * bp;

    for (xferred = 0, blks = blocks, lba = from_block, bp = buff;
         blks > 0; blks = blocks - xferred) {
        io_addr = 0;
        cont = 0;
        res = sg_read_low(sg_fd, bp, blks, lba, bs, cdbsz, fua, pdt, 
                          diop, &io_addr);
        switch (res) {
        case 0:
            return xferred + blks;
        case 1:
            return -2;
        case 2:
            fprintf(stderr, 
                    "Unit attention, media changed, continuing (r)\n");
            cont = 1;
            break;
        case -1:
            goto err_out;
        case -2:
            do_coe = 0;
            goto err_out;
        case 3:
            break; /* unrecovered read error at lba=io_addr */
        default:
            fprintf(stderr, ">> unexpected result=%d from sg_read_low()\n",
                    res);
            return -1;
        }
        if (cont)
            continue;
        if ((io_addr < (unsigned long long)lba) ||
            (io_addr >= (unsigned long long)(lba + blks))) {
                fprintf(stderr, "  Unrecovered error lba 0x%llx not in "
                    "correct range:\n\t[0x%llx,0x%llx]\n", io_addr,
                    (unsigned long long)lba,
                    (unsigned long long)(lba + blks - 1));
            goto err_out;
        }
        blks = (int)(io_addr - (unsigned long long)lba);
        if (blks > 0) {
            res = sg_read_low(sg_fd, bp, blks, lba, bs, cdbsz, fua,
                              pdt, diop, &io_addr);
            switch (res) {
            case 0:
                break;
            case 1:
                fprintf(stderr, "ENOMEM again, unexpected (r)\n");
                return -1;
            case 2:
                fprintf(stderr, 
                        "Unit attention, media changed, unexpected (r)\n");
                return -1;
            case -2:
                do_coe = 0;
                goto err_out;
            case -1: case 3:
                goto err_out;
            default:
                fprintf(stderr, ">> unexpected result=%d from "
                        "sg_read_low() 2\n", res);
                return -1;
            }
        }
        xferred += blks;
        if (! do_coe)
            return xferred; /* give up at block before problem unless 'coe' */
        if (bs < 32) {
            fprintf(stderr, ">> bs=%d too small for read_long\n", bs);
            return -1;  /* nah, block size can't be that small */
        }
        bp += (blks * bs);
        lba += blks;
        if (0 != pdt) {
            fprintf(stderr, ">> unrecovered read error at blk=%lld, "
                    "pdt=%d, use zeros\n", lba, pdt);
            memset(bp, 0, bs);
        } else if (io_addr < UINT_MAX) {
            unsigned char * buffp;
            int offset, nl, r, ok;

            buffp = malloc(bs * 2);
            if (NULL == buffp) {
                fprintf(stderr, ">> heap problems\n");
                return -1;
            }
            res = sg_ll_read_long10(sg_fd, 0 /*corrct */, lba,
                                    buffp, bs + 8, &offset, verbose);
            ok = 0;
            switch (res) {
            case 0:
                ok = 1;
                ++read_longs;
                break;
            case 1:
                nl = bs + 8 - offset;
                if ((nl < 32) || (nl > (bs * 2))) {
                    fprintf(stderr, ">> read_long(10) len=%d unexpected\n",
                            nl);
                    break;
                }
                r = sg_ll_read_long10(sg_fd, 0 /*corrct */, lba,
                                      buffp, nl, &offset, verbose);
                if (0 == r) {
                    ok = 1;
                    ++read_longs;
                    break;
                } else
                    fprintf(stderr, ">> unexpected result=%d on second "
                            "read_long(10)\n", r);
                break;
            case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, ">> read_long(10) not supported\n");
                break;
            case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, ">> read_long(10) bad cdb field\n");
                break;
            default:
                fprintf(stderr, ">> read_long(10) problem\n");
                break;
            }
            if (ok)
                memcpy(bp, buffp, bs);
            else
                memset(bp, 0, bs);
            free(buffp);
        } else {
            fprintf(stderr, ">> read_long(10) cannot handle blk=%lld, "
                    "use zeros\n", lba);
            memset(bp, 0, bs);
        }
        ++xferred;
        ++blks;
        bp += bs;
        ++lba;
    }
    return xferred;

err_out:
    if (do_coe) {
        memset(bp, 0, bs * blks);
        fprintf(stderr, ">> unable to read at blk=%lld for "
                "%d bytes, use zeros\n", lba, bs * blks);
        return xferred + blks; /* fudge success */
    } else
        return -1;
}

/* 0 -> successful, -1 -> unrecoverable error, -2 -> recoverable (ENOMEM),
   -3 -> try again (media changed unit attention) */
static int sg_write(int sg_fd, unsigned char * buff, int blocks,
                    long long to_block, int bs, int cdbsz, int fua,
                    int * diop)
{
    unsigned char wrCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int res, k, info_valid;
    unsigned long long io_addr = 0;

    if (sg_build_scsi_cdb(wrCmd, cdbsz, blocks, to_block, 1, fua, 0)) {
        fprintf(stderr, ME "bad wr cdb build, to_block=%lld, blocks=%d\n",
                to_block, blocks);
        return -1;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = wrCmd;
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)to_block;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    if (verbose > 2) {
        fprintf(stderr, "    write cdb: ");
        for (k = 0; k < cdbsz; ++k)
            fprintf(stderr, "%02x ", wrCmd[k]);
        fprintf(stderr, "\n");
    }
    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return -2;
        perror("writing (SG_IO) on sg device, error");
        return -1;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        ++recovered_errs;
        info_valid = sg_get_sense_info_fld(io_hdr.sbp, io_hdr.sb_len_wr,
                                           &io_addr);
        if (info_valid) {
            fprintf(stderr, "    lba of last recovered error in this "
                    "WRITE=0x%llx\n", io_addr);
            if (verbose > 1)
                sg_chk_n_print3("writing", &io_hdr);
        } else {
            fprintf(stderr, "Recovered error: [no info] writing to "
                    "block=0x%llx, num=%d\n", to_block, blocks);
            sg_chk_n_print3("writing", &io_hdr);
        }
        break;
    case SG_LIB_CAT_MEDIA_CHANGED:
        return -3;
    default:
        sg_chk_n_print3("writing", &io_hdr);
        if (do_coe) {
            fprintf(stderr, ">> ignored errors for out blk=%lld for "
                    "%d bytes\n", to_block, bs * blocks);
            return 0; /* fudge success */
        }
        else
            return -1;
    }
    if (diop && *diop && 
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0;      /* flag that dio not done (completely) */
    if (verbose > 3)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    return 0;
}

static void calc_duration_throughput()
{
    struct timeval end_tm, res_tm;
    double a, b;

    if (start_tm_valid && (start_tm.tv_sec || start_tm.tv_usec)) {
        gettimeofday(&end_tm, NULL);
        res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
        if (res_tm.tv_usec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        a = res_tm.tv_sec;
        a += (0.000001 * res_tm.tv_usec);
        b = (double)blk_sz * (req_count - dd_count);
        fprintf(stderr, " time to transfer data: %d.%06d secs",
               (int)res_tm.tv_sec, (int)res_tm.tv_usec);
        if ((a > 0.00001) && (b > 511))
            fprintf(stderr, " at %.2f MB/sec\n", b / (a * 1000000.0));
        else
            fprintf(stderr, "\n");
    }
}

static void print_mp_bit(const char * pre, int smask, int byte_off,
                int bit_mask, const unsigned char * cur_mp,
                const unsigned char * cha_mp, const unsigned char * def_mp,
                const unsigned char * sav_mp)
{
    int sep = 0;

    fprintf(stderr, "%s%d", pre, !!(cur_mp[byte_off] & bit_mask));
    if (smask & 0xe) {
        fprintf(stderr, "  [");
        if (smask & 2) {
            fprintf(stderr, "Changeable: %s",
                    (cha_mp[byte_off] & bit_mask) ? "y" : "n");
            sep = 1;
        }
        if (smask & 4) {
            fprintf(stderr, "%sdef: %d", (sep ? ", " : " "),
                    !!(def_mp[2] & bit_mask));
            sep = 1;
        }
        if (smask & 8)
            fprintf(stderr, "%ssaved: %d", (sep ? ", " : " "),
                    !!(sav_mp[2] & bit_mask));
        fprintf(stderr, "]\n");
    } else
        fprintf(stderr, "\n");
}

static void print_scsi_dev_info(int sg_fd, int pdt)
{
    int res, verb, smask;
    unsigned char cur_mp[DEF_MODE_RESP_LEN];
    unsigned char cha_mp[DEF_MODE_RESP_LEN];
    unsigned char def_mp[DEF_MODE_RESP_LEN];
    unsigned char sav_mp[DEF_MODE_RESP_LEN];
    int mode6;

    mode6 = (6 == DEF_MODE_CDB_SZ) ? 1 : 0;
    verb = (verbose > 0) ? verbose - 1 : 0;
    res = sg_get_mode_page_types(sg_fd, mode6, RW_ERR_RECOVERY_MP,
                           0 /* subpage */ , DEF_MODE_RESP_LEN,
                           &smask, cur_mp, cha_mp, def_mp, sav_mp, verb);
    if (SG_LIB_CAT_INVALID_OP == res) {
        mode6 = !mode6;         /* flip between mode sense(10) and (6) */
        res = sg_get_mode_page_types(sg_fd, mode6, RW_ERR_RECOVERY_MP,
                               0 /* subpage */ , DEF_MODE_RESP_LEN,
                               &smask, cur_mp, cha_mp, def_mp, sav_mp, verb);
    }
    if (0 == (smask & 1)) {
        if (verbose > 1)
            fprintf(stderr, "  Read write error recovery mode page not "
                    "supported, res=%d\n", res);
    } else if (cur_mp[1] < 0xa)
        fprintf(stderr, "  Read write error recovery mode page too "
                    "short, page len=%d\n", cur_mp[1]);
    else {
        fprintf(stderr, "  Read write error recovery mode page:\n");
        print_mp_bit("    AWRE:      ", smask, 2, 0x80, cur_mp, cha_mp,
                     def_mp, sav_mp);
        print_mp_bit("    ARRE:      ", smask, 2, 0x40, cur_mp, cha_mp,
                     def_mp, sav_mp);
        print_mp_bit("    RC:        ", smask, 2, 0x10, cur_mp, cha_mp,
                     def_mp, sav_mp);
        if (0 == pdt)
            print_mp_bit("    EER:       ", smask, 2, 0x8, cur_mp, cha_mp,
                         def_mp, sav_mp);
        print_mp_bit("    PER:       ", smask, 2, 0x4, cur_mp, cha_mp,
                     def_mp, sav_mp);
        print_mp_bit("    DTE:       ", smask, 2, 0x2, cur_mp, cha_mp,
                     def_mp, sav_mp);
        print_mp_bit("    DCR:       ", smask, 2, 0x1, cur_mp, cha_mp,
                     def_mp, sav_mp);
    }
    res = sg_get_mode_page_types(sg_fd, mode6, CACHING_MP,
                           0 /* subpage */ , DEF_MODE_RESP_LEN,
                           &smask, cur_mp, cha_mp, def_mp, sav_mp, verb);
    if (0 == (smask & 1)) {
        if (verbose > 1)
            fprintf(stderr, "  Caching mode page not "
                    "supported, res=%d\n", res);
    } else if (cur_mp[1] < 0xa)
        fprintf(stderr, "  Caching mode page too "
                    "short, page len=%d\n", cur_mp[1]);
    else {
        fprintf(stderr, "  Caching mode page:\n");
        print_mp_bit("    WRE:       ", smask, 2, 0x4, cur_mp, cha_mp,
                     def_mp, sav_mp);
        print_mp_bit("    RCD:       ", smask, 2, 0x1, cur_mp, cha_mp,
                     def_mp, sav_mp);
    }
    res = sg_get_mode_page_types(sg_fd, mode6, CONTROL_MP,
                           0 /* subpage */ , DEF_MODE_RESP_LEN,
                           &smask, cur_mp, cha_mp, def_mp, sav_mp, verb);
    if (0 == (smask & 1)) {
        if (verbose > 1)
            fprintf(stderr, "  Control mode page not "
                    "supported, res=%d\n", res);
    } else if (cur_mp[1] < 0xa)
        fprintf(stderr, "  Control mode page too "
                    "short, page len=%d\n", cur_mp[1]);
    else {
        fprintf(stderr, "  Control mode page:\n");
        print_mp_bit("    SWP:       ", smask, 4, 0x8, cur_mp, cha_mp,
                     def_mp, sav_mp);
    }
}


int main(int argc, char * argv[])
{
    long long skip = 0;
    long long seek = 0;
    int ibs = 0;
    int obs = 0;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    char str[STR_SZ];
    char * key;
    char * buf;
    char inf[INOUTF_SZ];
    int in_type = FT_OTHER;
    char outf[INOUTF_SZ];
    int out_type = FT_OTHER;
    int dio = 0;
    int dio_incomplete = 0;
    int do_odir = 0;
    int scsi_cdbsz_in = DEF_SCSI_CDBSZ;
    int scsi_cdbsz_out = DEF_SCSI_CDBSZ;
    int fua_mode = 0;
    int do_sync = 0;
    int do_blk_sgio = 0;
    int do_append = 0;
    int verb = 0;
    int res, k, t, buf_sz, dio_tmp, flags;
    int infd, outfd, blocks, in_pdt, out_pdt;
    unsigned char * wrkBuff;
    unsigned char * wrkPos;
    long long in_num_sect = -1;
    long long out_num_sect = -1;
    int in_sect_sz, out_sect_sz;
    char ebuff[EBUFF_SZ];
    int blocks_per;
    struct sg_simple_inquiry_resp sir;

    inf[0] = '\0';
    outf[0] = '\0';
    if (argc < 2) {
        fprintf(stderr, 
                "Can't have both 'if' as stdin _and_ 'of' as stdout\n");
        usage();
        return 1;
    }

    for(k = 1; k < argc; k++) {
        if (argv[k]) {
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
        }
        else
            continue;
        for(key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        if (strcmp(key,"if") == 0) {
            if ('\0' != inf[0]) {
                fprintf(stderr, "Second 'if=' argument??\n");
                return 1;
            } else 
                strncpy(inf, buf, INOUTF_SZ);
        } else if (strcmp(key,"of") == 0) {
            if ('\0' != outf[0]) {
                fprintf(stderr, "Second 'of=' argument??\n");
                return 1;
            } else 
                strncpy(outf, buf, INOUTF_SZ);
        } else if (0 == strcmp(key,"ibs"))
            ibs = sg_get_num(buf);
        else if (0 == strcmp(key,"obs"))
            obs = sg_get_num(buf);
        else if (0 == strcmp(key,"bs")) {
            blk_sz = sg_get_num(buf);
            if (-1 == blk_sz) {
                fprintf(stderr, ME "bad argument to 'bs'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"bpt")) {
            bpt = sg_get_num(buf);
            if (-1 == bpt) {
                fprintf(stderr, ME "bad argument to 'bpt'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"skip")) {
            skip = sg_get_llnum(buf);
            if (-1LL == skip) {
                fprintf(stderr, ME "bad argument to 'skip'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"seek")) {
            seek = sg_get_llnum(buf);
            if (-1LL == seek) {
                fprintf(stderr, ME "bad argument to 'seek'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"count")) {
            dd_count = sg_get_llnum(buf);
            if (-1LL == dd_count) {
                fprintf(stderr, ME "bad argument to 'count'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"dio"))
            dio = sg_get_num(buf);
        else if (0 == strcmp(key,"coe"))
            do_coe = sg_get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = sg_get_num(buf);
        else if (0 == strcmp(key,"cdbsz")) {
            scsi_cdbsz_in = sg_get_num(buf);
            scsi_cdbsz_out = scsi_cdbsz_in;
        } else if (0 == strcmp(key,"fua"))
            fua_mode = sg_get_num(buf);
        else if (0 == strcmp(key,"sync"))
            do_sync = sg_get_num(buf);
        else if (0 == strcmp(key,"odir"))
            do_odir = sg_get_num(buf);
        else if (0 == strcmp(key,"blk_sgio"))
            do_blk_sgio = sg_get_num(buf);
        else if (0 == strncmp(key,"app", 3))
            do_append = sg_get_num(buf);
        else if (0 == strncmp(key, "verb", 4)) {
            verbose = sg_get_num(buf);
            verb = (verbose ? verbose - 1: 0);
        } else if (0 == strncmp(key, "--vers", 6)) {
            fprintf(stderr, ME "%s\n", version_str);
            return 0;
        } else {
            fprintf(stderr, "Unrecognized argument '%s'\n", key);
            usage();
            return 1;
        }
    }
    if (blk_sz <= 0) {
        blk_sz = DEF_BLOCK_SIZE;
        fprintf(stderr, "Assume default 'bs' (block size) of %d bytes\n",
                blk_sz);
    }
    if ((ibs && (ibs != blk_sz)) || (obs && (obs != blk_sz))) {
        fprintf(stderr, "If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return 1;
    }
    if ((skip < 0) || (seek < 0)) {
        fprintf(stderr, "skip and seek cannot be negative\n");
        return 1;
    }
    if ((do_append > 0) && (seek > 0)) {
        fprintf(stderr, "Can't use both append and seek switches\n");
        return 1;
    }
    if (bpt < 1) {
        fprintf(stderr, "bpt must be greater than 0\n");
        return 1;
    }
#ifdef SG_DEBUG
    fprintf(stderr, ME "if=%s skip=%lld of=%s seek=%lld count=%lld\n",
           inf, skip, outf, seek, dd_count);
#endif
    install_handler (SIGINT, interrupt_handler);
    install_handler (SIGQUIT, interrupt_handler);
    install_handler (SIGPIPE, interrupt_handler);
    install_handler (SIGUSR1, siginfo_handler);

    infd = STDIN_FILENO;
    outfd = STDOUT_FILENO;
    in_pdt = -1;
    out_pdt = -1;
    if (inf[0] && ('-' != inf[0])) {
        in_type = dd_filetype(inf);

        if (verbose)
            fprintf(stderr, " >> Input file type: %s\n",
                    dd_filetype_str(in_type, ebuff));
        if ((FT_BLOCK & in_type) && do_blk_sgio)
            in_type |= FT_SG;

        if (FT_ST & in_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", inf);
            return 1;
        }
        else if (FT_SG & in_type) {
            flags = O_RDWR;
            if ((do_odir && (FT_BLOCK & in_type)))
                flags |= O_DIRECT;
            if ((infd = open(inf, flags)) < 0) {
                flags = O_RDONLY;
                if ((do_odir && (FT_BLOCK & in_type)))
                    flags |= O_DIRECT;
                if ((infd = open(inf, flags)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for sg reading", inf);
                    perror(ebuff);
                    return 1;
                }
            }
            if (verbose)
                fprintf(stderr, "        open input(sg_io), flags=0x%x\n",
                        flags);
            if (sg_simple_inquiry(infd, &sir, 0, verb)) {
                fprintf(stderr, "INQUIRY failed on %s\n", inf);
                return -1;
            }
            in_pdt = sir.peripheral_type;
            if (verbose)
                fprintf(stderr, "    %s: %.8s  %.16s  %.4s  [pdt=%d]\n",
                        inf, sir.vendor, sir.product, sir.revision, in_pdt);
            if (! (FT_BLOCK & in_type)) {
                t = blk_sz * bpt;
                res = ioctl(infd, SG_SET_RESERVED_SIZE, &t);
                if (res < 0)
                    perror(ME "SG_SET_RESERVED_SIZE error");
                res = ioctl(infd, SG_GET_VERSION_NUM, &t);
                if ((res < 0) || (t < 30000)) {
                    if (FT_BLOCK & in_type)
                        fprintf(stderr, ME "SG_IO unsupported on this block"
                                        " device\n");
                    else
                        fprintf(stderr, ME "sg driver prior to 3.x.y\n");
                    return 1;
                }
            }
            if (verbose)
                print_scsi_dev_info(infd, in_pdt);
        }
        else {
            flags = O_RDONLY;
            if (do_odir && (FT_BLOCK & in_type))
                flags |= O_DIRECT;
            infd = open(inf, flags);
            if (infd < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", inf);
                perror(ebuff);
                return 1;
            }
            else {
                if (verbose)
                    fprintf(stderr, "        open input, flags=0x%x\n",
                            flags);
                if (skip > 0) {
                    llse_loff_t offset = skip;

                    offset *= blk_sz;       /* could exceed 32 bits here! */
                    if (llse_llseek(infd, offset, SEEK_SET) < 0) {
                        snprintf(ebuff, EBUFF_SZ, ME "couldn't skip to "
                                 "required position on %s", inf);
                        perror(ebuff);
                        return 1;
                    }
                    if (verbose)
                        fprintf(stderr, "  >> skip: llseek SEEK_SET, "
                                "byte offset=0x%llx\n", offset);
                }
            }
        }
    }

    if (outf[0] && ('-' != outf[0])) {
        out_type = dd_filetype(outf);

        if (verbose)
            fprintf(stderr, " >> Output file type: %s\n",
                    dd_filetype_str(out_type, ebuff));
        if ((FT_BLOCK & out_type) && do_blk_sgio)
            out_type |= FT_SG;

        if (FT_ST & out_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", outf);
            return 1;
        }
        else if (FT_SG & out_type) {
            flags = O_RDWR;
            if ((do_odir && (FT_BLOCK & out_type)))
                flags |= O_DIRECT;
            if ((outfd = open(outf, flags)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for sg writing", outf);
                perror(ebuff);
                return 1;
            }
            if (verbose)
                fprintf(stderr, "        open output(sg_io), flags=0x%x\n",
                        flags);
            if (sg_simple_inquiry(outfd, &sir, 0, verb)) {
                fprintf(stderr, "INQUIRY failed on %s\n", outf);
                return -1;
            }
            out_pdt = sir.peripheral_type;
            if (verbose)
                fprintf(stderr, "    %s: %.8s  %.16s  %.4s  [pdt=%d]\n",
                        outf, sir.vendor, sir.product, sir.revision, out_pdt);
            if (! (FT_BLOCK & out_type)) {
                t = blk_sz * bpt;
                res = ioctl(outfd, SG_SET_RESERVED_SIZE, &t);
                if (res < 0)
                    perror(ME "SG_SET_RESERVED_SIZE error");
                res = ioctl(outfd, SG_GET_VERSION_NUM, &t);
                if ((res < 0) || (t < 30000)) {
                    fprintf(stderr, ME "sg driver prior to 3.x.y\n");
                    return 1;
                }
            }
            if (verbose)
                print_scsi_dev_info(outfd, out_pdt);
        }
        else if (FT_DEV_NULL & out_type)
            outfd = -1; /* don't bother opening */
        else {
            if (! (FT_RAW & out_type)) {
                flags = O_WRONLY | O_CREAT;
                if (do_odir && (FT_BLOCK & out_type) && (! (FT_SG & out_type)))
                    flags |= O_DIRECT;
                else if (do_append && (! (FT_BLOCK & out_type)))
                    flags |= O_APPEND;
                if ((outfd = open(outf, flags, 0666)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                            ME "could not open %s for writing", outf);
                    perror(ebuff);
                    return 1;
                }
            }
            else {
                flags = O_WRONLY;
                if ((outfd = open(outf, flags)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                            ME "could not open %s for raw writing", outf);
                    perror(ebuff);
                    return 1;
                }
            }
            if (verbose)
                fprintf(stderr, "        open output, flags=0x%x\n", flags);
            if (seek > 0) {
                llse_loff_t offset = seek;

                offset *= blk_sz;       /* could exceed 32 bits here! */
                if (llse_llseek(outfd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                        ME "couldn't seek to required position on %s", outf);
                    perror(ebuff);
                    return 1;
                }
                if (verbose)
                    fprintf(stderr, "   >> seek: llseek SEEK_SET, "
                            "byte offset=0x%llx\n", offset);
            }
        }
    }
    if ((STDIN_FILENO == infd) && (STDOUT_FILENO == outfd)) {
        fprintf(stderr, 
                "Can't have both 'if' as stdin _and_ 'of' as stdout\n");
        return 1;
    }

    if ((dd_count < 0) || ((verbose > 0) && (0 == dd_count))) {
        in_num_sect = -1;
        if (FT_SG & in_type) {
            res = scsi_read_capacity(infd, &in_num_sect, &in_sect_sz);
            if (SG_LIB_CAT_MEDIA_CHANGED == res) {
                fprintf(stderr, 
                        "Unit attention, media changed(in), continuing\n");
                res = scsi_read_capacity(infd, &in_num_sect, &in_sect_sz);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    fprintf(stderr, "read capacity not supported on %s\n",
                            inf);
                else
                    fprintf(stderr, "Unable to read capacity on %s\n", inf);
                in_num_sect = -1;
            }
        } else if (FT_BLOCK & in_type) {
            if (0 != read_blkdev_capacity(infd, &in_num_sect, &in_sect_sz)) {
                fprintf(stderr, "Unable to read block capacity on %s\n", inf);
                in_num_sect = -1;
            }
            if (blk_sz != in_sect_sz) {
                fprintf(stderr, "block size on %s confusion; bs=%d, "
                        "device claims=%d\n", inf, blk_sz, in_sect_sz);
                in_num_sect = -1;
            }
        }
        if (in_num_sect > skip)
            in_num_sect -= skip;

        out_num_sect = -1;
        if (FT_SG & out_type) {
            res = scsi_read_capacity(outfd, &out_num_sect, &out_sect_sz);
            if (SG_LIB_CAT_MEDIA_CHANGED == res) {
                fprintf(stderr, 
                        "Unit attention, media changed(out), continuing\n");
                res = scsi_read_capacity(outfd, &out_num_sect, &out_sect_sz);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    fprintf(stderr, "read capacity not supported on %s\n",
                            outf);
                else
                    fprintf(stderr, "Unable to read capacity on %s\n", outf);
                out_num_sect = -1;
            }
        } else if (FT_BLOCK & out_type) {
            if (0 != read_blkdev_capacity(outfd, &out_num_sect, 
                                          &out_sect_sz)) {
                fprintf(stderr, "Unable to read block capacity on %s\n",
                        outf);
                out_num_sect = -1;
            }
            if (blk_sz != out_sect_sz) {
                fprintf(stderr, "block size on %s confusion: bs=%d, "
                        "device claims=%d\n", outf, blk_sz, out_sect_sz);
                out_num_sect = -1;
            }
        }
        if (out_num_sect > seek)
            out_num_sect -= seek;
#ifdef SG_DEBUG
        fprintf(stderr, 
            "Start of loop, count=%lld, in_num_sect=%lld, out_num_sect=%lld\n", 
            dd_count, in_num_sect, out_num_sect);
#endif
        if (dd_count < 0) {
            if (in_num_sect > 0) {
                if (out_num_sect > 0)
                    dd_count = (in_num_sect > out_num_sect) ? out_num_sect :
                                                           in_num_sect;
                else
                    dd_count = in_num_sect;
            }
            else
                dd_count = out_num_sect;
        }
    }

    if (dd_count < 0) {
        fprintf(stderr, "Couldn't calculate count, please give one\n");
        return 1;
    }
    if ((FT_SG & in_type) && ((dd_count + skip) > UINT_MAX) &&
        (MAX_SCSI_CDBSZ != scsi_cdbsz_in)) {
        fprintf(stderr, "Note: SCSI command size increased to 16 bytes "
                "(for 'if')\n");
        scsi_cdbsz_in = MAX_SCSI_CDBSZ;
    }
    if ((FT_SG & out_type) && ((dd_count + seek) > UINT_MAX) &&
        (MAX_SCSI_CDBSZ != scsi_cdbsz_out)) {
        fprintf(stderr, "Note: SCSI command size increased to 16 bytes "
                "(for 'of')\n");
        scsi_cdbsz_out = MAX_SCSI_CDBSZ;
    }

    if (dio || do_odir || (FT_RAW & in_type) || (FT_RAW & out_type)) {
        size_t psz = getpagesize();
        wrkBuff = malloc(blk_sz * bpt + psz);
        if (0 == wrkBuff) {
            fprintf(stderr, "Not enough user memory for raw\n");
            return 1;
        }
        wrkPos = (unsigned char *)(((unsigned long)wrkBuff + psz - 1) &
                                   (~(psz - 1)));
    }
    else {
        wrkBuff = malloc(blk_sz * bpt);
        if (0 == wrkBuff) {
            fprintf(stderr, "Not enough user memory\n");
            return 1;
        }
        wrkPos = wrkBuff;
    }

    blocks_per = bpt;
#ifdef SG_DEBUG
    fprintf(stderr, "Start of loop, count=%lld, blocks_per=%d\n",
            dd_count, blocks_per);
#endif
    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
        start_tm_valid = 1;
    }
    req_count = dd_count;

    /* main loop that does the copy ... */
    while (dd_count > 0) {
        blocks = (dd_count > blocks_per) ? blocks_per : dd_count;
        if (FT_SG & in_type) {
            int fua = fua_mode & 2;

            dio_tmp = dio;
            res = sg_read(infd, wrkPos, blocks, skip, blk_sz, scsi_cdbsz_in,
                          fua, &dio_tmp, in_pdt);
            if (-2 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + blk_sz - 1) / blk_sz;
                if (blocks_per < blocks) {
                    blocks = blocks_per;
                    fprintf(stderr, "Reducing read to %d blocks per "
                            "loop\n", blocks_per);
                    res = sg_read(infd, wrkPos, blocks, skip, blk_sz,
                                  scsi_cdbsz_in, fua, &dio_tmp, in_pdt);
                }
            }
            if (res < 0) {
                fprintf(stderr, "sg_read failed,%s at or after lba=%lld "
                        "[0x%llx]\n",
                        ((-2 == res) ? " try reducing bpt," : ""), skip, skip);
                break;
            } else {
                if (res < blocks) {
                    dd_count = 0;   /* force exit after write */
                    blocks = res;
                }
                in_full += blocks;
                if (dio && (0 == dio_tmp))
                    dio_incomplete++;
            }
        }
        else {
            while (((res = read(infd, wrkPos, blocks * blk_sz)) < 0) &&
                   (EINTR == errno))
                ;
            if (verbose > 2)
                fprintf(stderr, "read(unix): count=%d, res=%d\n",
                        blocks * blk_sz, res);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "reading, skip=%lld ", skip);
                perror(ebuff);
                break;
            }
            else if (res < blocks * blk_sz) {
                dd_count = 0;
                blocks = res / blk_sz;
                if ((res % blk_sz) > 0) {
                    blocks++;
                    in_partial++;
                }
            }
            in_full += blocks;
        }

        if (0 == blocks)
            break;      /* nothing read so leave loop */

        if (FT_SG & out_type) {
            int fua = fua_mode & 1;

            dio_tmp = dio;
            res = sg_write(outfd, wrkPos, blocks, seek, blk_sz,
                           scsi_cdbsz_out, fua, &dio_tmp);
            if (-2 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(outfd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + blk_sz - 1) / blk_sz;
                if (blocks_per < blocks) {
                    blocks = blocks_per;
                    fprintf(stderr, 
                            "Reducing write to %d blocks per loop\n", blocks);
                    res = sg_write(outfd, wrkPos, blocks, seek, blk_sz, 
                                   scsi_cdbsz_out, fua, &dio_tmp);
                }
            }
            else if (-3 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed, continuing (w)\n");
                res = sg_write(outfd, wrkPos, blocks, seek, blk_sz,
                               scsi_cdbsz_out, fua, &dio_tmp);
            }
            if (res < 0) {
                fprintf(stderr, "sg_write failed,%s seek=%lld\n", 
                        ((-2 == res) ? " try reducing bpt," : ""), seek);
                break;
            }
            else {
                out_full += blocks;
                if (dio && (0 == dio_tmp))
                    dio_incomplete++;
            }
        }
        else if (FT_DEV_NULL & out_type)
            out_full += blocks; /* act as if written out without error */
        else {
            while (((res = write(outfd, wrkPos, blocks * blk_sz)) < 0)
                   && (EINTR == errno))
                ;
            if (verbose > 2)
                fprintf(stderr, "write(unix): count=%d, res=%d\n",
                        blocks * blk_sz, res);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "writing, seek=%lld ", seek);
                perror(ebuff);
                break;
            }
            else if (res < blocks * blk_sz) {
                fprintf(stderr, "output file probably full, seek=%lld ", seek);
                blocks = res / blk_sz;
                out_full += blocks;
                if ((res % blk_sz) > 0)
                    out_partial++;
                break;
            }
            else
                out_full += blocks;
        }
        if (dd_count > 0)
            dd_count -= blocks;
        skip += blocks;
        seek += blocks;
    } /* end of main loop that does the copy ... */

    if (do_time)
        calc_duration_throughput();

    if (do_sync) {
        if (FT_SG & out_type) {
            fprintf(stderr, ">> Synchronizing cache on %s\n", outf);
            res = sg_ll_sync_cache_10(outfd, 0, 0, 0, 0, 0, 0, 0);
            if (2 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed(in), continuing\n");
                res = sg_ll_sync_cache_10(outfd, 0, 0, 0, 0, 0, 0, 0);
            }
            if (0 != res)
                fprintf(stderr, "Unable to synchronize cache\n");
        }
    }
    free(wrkBuff);
    if (STDIN_FILENO != infd)
        close(infd);
    if (! ((STDOUT_FILENO == outfd) || (FT_DEV_NULL & out_type)))
        close(outfd);
    res = 0;
    if (0 != dd_count) {
        fprintf(stderr, "Some error occurred,");
        res = 2;
    }
    print_stats("");
    if (dio_incomplete) {
        int fd;
        char c;

        fprintf(stderr, ">> Direct IO requested but incomplete %d times\n", 
                dio_incomplete);
        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    fprintf(stderr, ">>> %s set to '0' but should be set "
                            "to '1' for direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    }
    if (sum_of_resids)
        fprintf(stderr, ">> Non-zero sum of residual counts=%d\n", 
                sum_of_resids);
    return res;
}
