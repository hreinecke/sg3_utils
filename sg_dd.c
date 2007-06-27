#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

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
#include <linux/fs.h>
#include "sg_include.h"
#include "sg_err.h"
#include "llseek.h"

/* A utility program for copying files. Specialised for "files" that
*  represent devices that understand the SCSI command set.
*
*  Copyright (C) 1999 - 2004 D. Gilbert and P. Allworth
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
   not given or 'of=-' then stdout assumed. Multipliers:
     'c','C'  *1       'b','B' *512      'k' *1024      'K' *1000
     'm' *(1024^2)     'M' *(1000^2)     'g' *(1024^3)  'G' *(1000^3)
     't' *(1024^4)     'T' *(1000^4)
   This convention (lower case powers of two, upper case powers of 10
   (apart from 'B')) is borrowed from lmdd from the lmbench suite.

   A non-standard argument "bpt" (blocks per transfer) is added to control
   the maximum number of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16KB
   in this case) is transferred to or from the sg device in a single SCSI
   command. The actual size of the SCSI READ or WRITE command block can be
   selected with the "cdbsz" argument.

   This version is designed for the linux kernel 2.4 and 2.6 series.
*/

static char * version_str = "5.33 20040708";


#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define ME "sg_dd: "

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 12

#ifndef SERVICE_ACTION_IN
#define SERVICE_ACTION_IN     0x9e
#endif
#ifndef SAI_READ_CAPACITY_16
#define SAI_READ_CAPACITY_16  0x10
#endif

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

static int sum_of_resids = 0;

static long long dd_count = -1;
static long long in_full = 0;
static int in_partial = 0;
static long long out_full = 0;
static int out_partial = 0;
static int do_coe = 0;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

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

void print_stats(const char * str)
{
    if (0 != dd_count)
        fprintf(stderr, "  remaining block count=%lld\n", dd_count);
    fprintf(stderr, "%s%lld+%d records in\n", str, in_full - in_partial, 
            in_partial);
    fprintf(stderr, "%s%lld+%d records out\n", str, out_full - out_partial, 
            out_partial);
}

static void interrupt_handler(int sig)
{
    struct sigaction sigact;

    sigact.sa_handler = SIG_DFL;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(sig, &sigact, NULL);
    fprintf(stderr, "Interrupted by signal,");
    print_stats("");
    kill(getpid (), sig);
}

static void siginfo_handler(int sig)
{
    sig = sig;  /* dummy to stop -W warning messages */
    fprintf(stderr, "Progress report, continuing ...\n");
    print_stats("  ");
}

int dd_filetype(const char * filename)
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

void usage()
{
    fprintf(stderr, "Usage: "
           "sg_dd  [if=<infile>] [skip=<n>] [of=<ofile>] [seek=<n> | "
           "append=0|1]\n"
           "              [bs=<num>] [bpt=<num>] [count=<n>] [time=0|1]"
           " [dio=0|1]\n"
           "              [sync=0|1] [cdbsz=6|10|12|16] [fua=0|1|2|3]"
           " [coe=0|1]\n"
           "              [odir=0|1] [blk_sgio=0|1] [--version]\n"
           " 'append' 1->append output to normal <ofile>, (default is 0)\n"
           " 'bpt' is blocks_per_transfer (default is 128)\n"
           " 'dio' is direct IO, 1->attempt, 0->indirect IO (def)\n"
           " 'coe' 1->continue on sg error, 0->exit on error (def)\n"
           " 'time' 0->no timing(def), 1->time plus calculate throughput\n"
           " 'fua' force unit access: 0->don't(def), 1->of, 2->if, 3->of+if\n"
           " 'odir' 1->use O_DIRECT when opening block dev, 0->don't(def)\n"
           " 'sync' 0->no sync(def), 1->SYNCHRONIZE CACHE on of after xfer\n"
           " 'cdbsz' size of SCSI READ or WRITE command (default is 10)\n"
           " 'blk_sgio' 0->block device use normal I/O(def), 1->use SG_IO\n");
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
int read_capacity(int sg_fd, long long * num_sect, int * sect_sz)
{
    int res;
    unsigned char rcCmdBlk[10] = {READ_CAPACITY, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char rcBuff[READ_CAP_REPLY_LEN];
    unsigned char sense_b[64];
    struct sg_io_hdr io_hdr;

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = sizeof(rcBuff);
    io_hdr.dxferp = rcBuff;
    io_hdr.cmdp = rcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("read_capacity (SG_IO) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    if (SG_ERR_CAT_MEDIA_CHANGED == res)
        return 2; /* probably have another go ... */
    else if (SG_ERR_CAT_CLEAN != res) {
        sg_chk_n_print3("read capacity", &io_hdr);
        return -1;
    }
    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3])) {
        unsigned char rcCmdBlk16[16] = {SERVICE_ACTION_IN, 
                            SAI_READ_CAPACITY_16,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        unsigned char rcBuff16[RCAP16_REPLY_LEN];
        int k;
        long long ls;

        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rcCmdBlk16);
        io_hdr.mx_sb_len = sizeof(sense_b);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = sizeof(rcBuff16);
        io_hdr.dxferp = rcBuff16;
        io_hdr.cmdp = rcCmdBlk16;
        io_hdr.sbp = sense_b;
        io_hdr.timeout = DEF_TIMEOUT;

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
            perror("read_capacity_16 (SG_IO) error");
            return -1;
        }
        res = sg_err_category3(&io_hdr);
        if (SG_ERR_CAT_CLEAN != res) {
            sg_chk_n_print3("read capacity_16", &io_hdr);
            return -1;
        }
        for (k = 0, ls = 0; k < 8; ++k) {
            ls <<= 8;
            ls |= rcBuff16[k];
        }
        *num_sect = ls + 1;
        *sect_sz = (rcBuff16[8] << 24) | (rcBuff16[9] << 16) |
                   (rcBuff16[10] << 8) | rcBuff16[11];
    } else {
        *num_sect = 1 + ((rcBuff[0] << 24) | (rcBuff[1] << 16) |
                    (rcBuff[2] << 8) | rcBuff[3]);
        *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
                   (rcBuff[6] << 8) | rcBuff[7];
    }
    return 0;
}

/* Return of 0 -> success, -1 -> failure */
int read_blkdev_capacity(int sg_fd, long long * num_sect, int * sect_sz)
{
#ifdef BLKGETSIZE64
    unsigned long long ull;

    if (ioctl(sg_fd, BLKGETSIZE64, &ull) < 0) {

        perror("BLKGETSIZE64 ioctl error");
        return -1;
    }
    if (ioctl(sg_fd, BLKSSZGET, sect_sz) < 0) {
        perror("BLKSSZGET ioctl error");
        return -1;
    }
    *num_sect = ((long long)ull / (long long)*sect_sz);
#else
    unsigned long ul;

    if (ioctl(sg_fd, BLKGETSIZE, &ul) < 0) {
        perror("BLKGETSIZE ioctl error");
        return -1;
    }
    *num_sect = (long long)ul;
    if (ioctl(sg_fd, BLKSSZGET, sect_sz) < 0) {
        perror("BLKSSZGET ioctl error");
        return -1;
    }
#endif
    return 0;
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
int sync_cache(int sg_fd)
{
    int res;
    unsigned char scCmdBlk [10] = {SYNCHRONIZE_CACHE, 0, 0, 0, 0, 0, 0, 
                                   0, 0, 0};
    unsigned char sense_b[64];
    struct sg_io_hdr io_hdr;

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(scCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.dxfer_len = 0;
    io_hdr.dxferp = NULL;
    io_hdr.cmdp = scCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("synchronize_cache (SG_IO) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    if (SG_ERR_CAT_MEDIA_CHANGED == res)
        return 2; /* probably have another go ... */
    else if (SG_ERR_CAT_CLEAN != res) {
        sg_chk_n_print3("synchronize cache", &io_hdr);
        return -1;
    }
    return 0;
}

int sg_build_scsi_cdb(unsigned char * cdbp, int cdb_sz, unsigned int blocks,
                      long long start_block, int write_true, int fua,
                      int dpo)
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

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
int sg_read(int sg_fd, unsigned char * buff, int blocks, long long from_block,
            int bs, int cdbsz, int fua, int * diop)
{
    unsigned char rdCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int res;

    if (sg_build_scsi_cdb(rdCmd, cdbsz, blocks, from_block, 0, fua, 0)) {
        fprintf(stderr, ME "bad rd cdb build, from_block=%lld, blocks=%d\n",
                from_block, blocks);
        return -1;
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

    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("reading (SG_IO) on sg device, error");
        return -1;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_ERR_CAT_CLEAN:
        break;
    case SG_ERR_CAT_RECOVERED:
        fprintf(stderr, "Recovered error while reading block=%lld, num=%d\n",
               from_block, blocks);
        break;
    case SG_ERR_CAT_MEDIA_CHANGED:
        return 2;
    default:
        sg_chk_n_print3("reading", &io_hdr);
        if (do_coe) {
            memset(buff, 0, bs * blocks);
            fprintf(stderr, ">> unable to read at blk=%lld for "
                        "%d bytes, use zeros\n", from_block, bs * blocks);
            return 0; /* fudge success */
        }
        else
            return -1;
    }
    if (diop && *diop && 
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0;      /* flag that dio not done (completely) */
    sum_of_resids += io_hdr.resid;
#ifdef SG_DEBUG
    fprintf(stderr, "duration=%u ms\n", io_hdr.duration);
#endif
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
int sg_write(int sg_fd, unsigned char * buff, int blocks, long long to_block,
             int bs, int cdbsz, int fua, int * diop)
{
    unsigned char wrCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int res;

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

    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("writing (SG_IO) on sg device, error");
        return -1;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_ERR_CAT_CLEAN:
        break;
    case SG_ERR_CAT_RECOVERED:
        fprintf(stderr, "Recovered error while writing block=%lld, num=%d\n",
               to_block, blocks);
        break;
    case SG_ERR_CAT_MEDIA_CHANGED:
        return 2;
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
    return 0;
}

int get_num(char * buf)
{
    int res, num;
    char c = 'c';

    if ('\0' == buf[0])
        return -1;
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1])))
        res = sscanf(buf + 2, "%x", &num);
    else
        res = sscanf(buf, "%d%c", &num, &c);
    if (1 == res)
        return num;
    else if (2 != res)
        return -1;
    else {
        switch (c) {
        case 'c':
        case 'C':
            return num;
        case 'b':
        case 'B':
            return num * 512;
        case 'k':
            return num * 1024;
        case 'K':
            return num * 1000;
        case 'm':
            return num * 1024 * 1024;
        case 'M':
            return num * 1000000;
        case 'g':
            return num * 1024 * 1024 * 1024;
        case 'G':
            return num * 1000000000;
        default:
            fprintf(stderr, "unrecognized multiplier\n");
            return -1;
        }
    }
}

long long get_llnum(char * buf)
{
    int res;
    long long num;
    char c = 'c';

    if ('\0' == buf[0])
        return -1;
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1])))
        res = sscanf(buf + 2, "%llx", &num);
    else
        res = sscanf(buf, "%lld%c", &num, &c);
    if (1 == res)
        return num;
    else if (2 != res)
        return -1;
    else {
        switch (c) {
        case 'c':
        case 'C':
            return num;
        case 'b':
        case 'B':
            return num * 512;
        case 'k':
            return num * 1024;
        case 'K':
            return num * 1000;
        case 'm':
            return num * 1024 * 1024;
        case 'M':
            return num * 1000000;
        case 'g':
            return num * 1024 * 1024 * 1024;
        case 'G':
            return num * 1000000000;
        case 't':
            return num * 1024LL * 1024LL * 1024LL * 1024LL;
        case 'T':
            return num * 1000000000000LL;
        default:
            fprintf(stderr, "unrecognized multiplier\n");
            return -1;
        }
    }
}

#define STR_SZ 1024
#define INOUTF_SZ 512
#define EBUFF_SZ 512


int main(int argc, char * argv[])
{
    long long skip = 0;
    long long seek = 0;
    int bs = 0;
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
    int do_time = 0;
    int do_odir = 0;
    int scsi_cdbsz_in = DEF_SCSI_CDBSZ;
    int scsi_cdbsz_out = DEF_SCSI_CDBSZ;
    int fua_mode = 0;
    int do_sync = 0;
    int do_blk_sgio = 0;
    int do_append = 0;
    int res, k, t, buf_sz, dio_tmp;
    int infd, outfd, blocks;
    unsigned char * wrkBuff;
    unsigned char * wrkPos;
    long long in_num_sect = -1;
    long long out_num_sect = -1;
    int in_sect_sz, out_sect_sz;
    char ebuff[EBUFF_SZ];
    int blocks_per;
    long long req_count;
    struct timeval start_tm, end_tm;

    inf[0] = '\0';
    outf[0] = '\0';
    if (argc < 2) {
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
            ibs = get_num(buf);
        else if (0 == strcmp(key,"obs"))
            obs = get_num(buf);
        else if (0 == strcmp(key,"bs"))
            bs = get_num(buf);
        else if (0 == strcmp(key,"bpt"))
            bpt = get_num(buf);
        else if (0 == strcmp(key,"skip"))
            skip = get_llnum(buf);
        else if (0 == strcmp(key,"seek"))
            seek = get_llnum(buf);
        else if (0 == strcmp(key,"count"))
            dd_count = get_llnum(buf);
        else if (0 == strcmp(key,"dio"))
            dio = get_num(buf);
        else if (0 == strcmp(key,"coe"))
            do_coe = get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = get_num(buf);
        else if (0 == strcmp(key,"cdbsz")) {
            scsi_cdbsz_in = get_num(buf);
            scsi_cdbsz_out = scsi_cdbsz_in;
        } else if (0 == strcmp(key,"fua"))
            fua_mode = get_num(buf);
        else if (0 == strcmp(key,"sync"))
            do_sync = get_num(buf);
        else if (0 == strcmp(key,"odir"))
            do_odir = get_num(buf);
        else if (0 == strcmp(key,"blk_sgio"))
            do_blk_sgio = get_num(buf);
        else if (0 == strncmp(key,"app", 3))
            do_append = get_num(buf);
        else if (0 == strncmp(key, "--vers", 6)) {
            fprintf(stderr, ME "for Linux sg version 3 driver: %s\n",
                    version_str);
            return 0;
        }
        else {
            fprintf(stderr, "Unrecognized argument '%s'\n", key);
            usage();
            return 1;
        }
    }
    if (bs <= 0) {
        bs = DEF_BLOCK_SIZE;
        fprintf(stderr, "Assume default 'bs' (block size) of %d bytes\n", bs);
    }
    if ((ibs && (ibs != bs)) || (obs && (obs != bs))) {
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
    if (inf[0] && ('-' != inf[0])) {
        in_type = dd_filetype(inf);

        if ((FT_BLOCK & in_type) && do_blk_sgio)
            in_type |= FT_SG;

        if (FT_ST & in_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", inf);
            return 1;
        }
        else if (FT_SG & in_type) {
            if ((infd = open(inf, O_RDWR)) < 0) {
                if ((infd = open(inf, O_RDONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for sg reading", inf);
                    perror(ebuff);
                    return 1;
                }
            }
            t = bs * bpt;
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
        else {
            if (do_odir && (FT_BLOCK & in_type))
                infd = open(inf, O_RDONLY | O_DIRECT);
            else
                infd = open(inf, O_RDONLY);
            if (infd < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", inf);
                perror(ebuff);
                return 1;
            }
            else if (skip > 0) {
                llse_loff_t offset = skip;

                offset *= bs;       /* could exceed 32 bits here! */
                if (llse_llseek(infd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                        ME "couldn't skip to required position on %s", inf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
    }

    if (outf[0] && ('-' != outf[0])) {
        out_type = dd_filetype(outf);

        if ((FT_BLOCK & out_type) && do_blk_sgio)
            out_type |= FT_SG;

        if (FT_ST & out_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", outf);
            return 1;
        }
        else if (FT_SG & out_type) {
            if ((outfd = open(outf, O_RDWR)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for sg writing", outf);
                perror(ebuff);
                return 1;
            }
            t = bs * bpt;
            res = ioctl(outfd, SG_SET_RESERVED_SIZE, &t);
            if (res < 0)
                perror(ME "SG_SET_RESERVED_SIZE error");
            res = ioctl(outfd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30000)) {
                fprintf(stderr, ME "sg driver prior to 3.x.y\n");
                return 1;
            }
        }
        else if (FT_DEV_NULL & out_type)
            outfd = -1; /* don't bother opening */
        else {
            if (! (FT_RAW & out_type)) {
                int flags = O_WRONLY | O_CREAT;

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
                if ((outfd = open(outf, O_WRONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                            ME "could not open %s for raw writing", outf);
                    perror(ebuff);
                    return 1;
                }
            }
            if (seek > 0) {
                llse_loff_t offset = seek;

                offset *= bs;       /* could exceed 32 bits here! */
                if (llse_llseek(outfd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                        ME "couldn't seek to required position on %s", outf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
    }
    if ((STDIN_FILENO == infd) && (STDOUT_FILENO == outfd)) {
        fprintf(stderr, 
                "Can't have both 'if' as stdin _and_ 'of' as stdout\n");
        return 1;
    }

    if (dd_count < 0) {
        in_num_sect = -1;
        if (FT_SG & in_type) {
            res = read_capacity(infd, &in_num_sect, &in_sect_sz);
            if (2 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed(in), continuing\n");
                res = read_capacity(infd, &in_num_sect, &in_sect_sz);
            }
            if (0 != res) {
                fprintf(stderr, "Unable to read capacity on %s\n", inf);
                in_num_sect = -1;
            }
        } else if (FT_BLOCK & in_type) {
            if (0 != read_blkdev_capacity(infd, &in_num_sect, &in_sect_sz)) {
                fprintf(stderr, "Unable to read block capacity on %s\n", inf);
                in_num_sect = -1;
            }
            if (bs != in_sect_sz) {
                fprintf(stderr, "block size on %s confusion; bs=%d, from "
                        "device=%d\n", inf, bs, in_sect_sz);
                in_num_sect = -1;
            }
        }
        if (in_num_sect > skip)
            in_num_sect -= skip;

        out_num_sect = -1;
        if (FT_SG & out_type) {
            res = read_capacity(outfd, &out_num_sect, &out_sect_sz);
            if (2 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed(out), continuing\n");
                res = read_capacity(outfd, &out_num_sect, &out_sect_sz);
            }
            if (0 != res) {
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
            if (bs != out_sect_sz) {
                fprintf(stderr, "block size on %s confusion: bs=%d, from "
                        "device=%d\n", outf, bs, out_sect_sz);
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
        wrkBuff = malloc(bs * bpt + psz);
        if (0 == wrkBuff) {
            fprintf(stderr, "Not enough user memory for raw\n");
            return 1;
        }
        wrkPos = (unsigned char *)(((unsigned long)wrkBuff + psz - 1) &
                                   (~(psz - 1)));
    }
    else {
        wrkBuff = malloc(bs * bpt);
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
    }
    req_count = dd_count;

    /* main loop that does the copy ... */
    while (dd_count > 0) {
        blocks = (dd_count > blocks_per) ? blocks_per : dd_count;
        if (FT_SG & in_type) {
            int fua = fua_mode & 2;

            dio_tmp = dio;
            res = sg_read(infd, wrkPos, blocks, skip, bs, scsi_cdbsz_in, fua, 
                          &dio_tmp);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + bs - 1) / bs;
                if (blocks_per < blocks) {
                    blocks = blocks_per;
                    fprintf(stderr, "Reducing read to %d blocks per "
                            "loop\n", blocks_per);
                    res = sg_read(infd, wrkPos, blocks, skip, bs, 
                                  scsi_cdbsz_in, fua, &dio_tmp);
                }
            }
            else if (2 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed, continuing (r)\n");
                res = sg_read(infd, wrkPos, blocks, skip, bs, scsi_cdbsz_in,
                              fua, &dio_tmp);
            }
            if (0 != res) {
                fprintf(stderr, "sg_read failed,%s seek=%lld\n", 
                        ((1 == res) ? " try reducing bpt," : ""), seek);
                break;
            }
            else {
                in_full += blocks;
                if (dio && (0 == dio_tmp))
                    dio_incomplete++;
            }
        }
        else {
            while (((res = read(infd, wrkPos, blocks * bs)) < 0) &&
                   (EINTR == errno))
                ;
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "reading, skip=%lld ", skip);
                perror(ebuff);
                break;
            }
            else if (res < blocks * bs) {
                dd_count = 0;
                blocks = res / bs;
                if ((res % bs) > 0) {
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
            res = sg_write(outfd, wrkPos, blocks, seek, bs, scsi_cdbsz_out,
                           fua, &dio_tmp);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(outfd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + bs - 1) / bs;
                if (blocks_per < blocks) {
                    blocks = blocks_per;
                    fprintf(stderr, 
                            "Reducing write to %d blocks per loop\n", blocks);
                    res = sg_write(outfd, wrkPos, blocks, seek, bs, 
                                   scsi_cdbsz_out, fua, &dio_tmp);
                }
            }
            else if (2 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed, continuing (w)\n");
                res = sg_write(outfd, wrkPos, blocks, seek, bs, scsi_cdbsz_out,
                               fua, &dio_tmp);
            }
            if (0 != res) {
                fprintf(stderr, "sg_write failed,%s seek=%lld\n", 
                        ((1 == res) ? " try reducing bpt," : ""), seek);
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
            while (((res = write(outfd, wrkPos, blocks * bs)) < 0)
                   && (EINTR == errno))
                ;
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "writing, seek=%lld ", seek);
                perror(ebuff);
                break;
            }
            else if (res < blocks * bs) {
                fprintf(stderr, "output file probably full, seek=%lld ", seek);
                blocks = res / bs;
                out_full += blocks;
                if ((res % bs) > 0)
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

    if ((do_time) && (start_tm.tv_sec || start_tm.tv_usec)) {
        struct timeval res_tm;
        double a, b;

        gettimeofday(&end_tm, NULL);
        res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
        if (res_tm.tv_usec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        a = res_tm.tv_sec;
        a += (0.000001 * res_tm.tv_usec);
        b = (double)bs * (req_count - dd_count);
        fprintf(stderr, "time to transfer data was %d.%06d secs",
               (int)res_tm.tv_sec, (int)res_tm.tv_usec);
        if ((a > 0.00001) && (b > 511))
            fprintf(stderr, ", %.2f MB/sec\n", b / (a * 1000000.0));
        else
            fprintf(stderr, "\n");
    }
    if (do_sync) {
        if (FT_SG & out_type) {
            fprintf(stderr, ">> Synchronizing cache on %s\n", outf);
            res = sync_cache(outfd);
            if (2 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed(in), continuing\n");
                res = sync_cache(outfd);
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
