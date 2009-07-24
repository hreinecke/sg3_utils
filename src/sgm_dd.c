#define _XOPEN_SOURCE 500
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/major.h>
#include <linux/fs.h>   /* <sys/mount.h> */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_io_linux.h"

/* A utility program for copying files. Specialised for "files" that
*  represent devices that understand the SCSI command set.
*
*  Copyright (C) 1999 - 2007 D. Gilbert and P. Allworth
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program is a specialisation of the Unix "dd" command in which
   either the input or the output file is a scsi generic device or a
   raw device. The block size ('bs') is assumed to be 512 if not given.
   This program complains if 'ibs' or 'obs' are given with a value
   that differs from 'bs' (or the default 512).
   If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
   not given or 'of=-' then stdout assumed.

   A non-standard argument "bpt" (blocks per transfer) is added to control
   the maximum number of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16 KiB
   in this case) is transferred to or from the sg device in a single SCSI
   command.

   This version uses memory-mapped transfers (i.e. mmap() call from the user
   space) to speed transfers. If both sides of copy are sg devices
   then only the read side will be mmap-ed, while the write side will
   use normal IO.

   This version is designed for the linux kernel 2.4 and 2.6 series.
*/

/* #define SG_WANT_SHARED_MMAP_IO 1 */

#ifdef SG_WANT_SHARED_MMAP_IO
static char * version_str = "1.35 20080205 shared_mmap";
#else
static char * version_str = "1.35 20080205";
#endif

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_BLOCKS_PER_2048TRANSFER 32
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define ME "sgm_dd: "

/* #define SG_DEBUG */

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

#ifndef SERVICE_ACTION_IN
#define SERVICE_ACTION_IN     0x9e
#endif
#ifndef SAI_READ_CAPACITY_16
#define SAI_READ_CAPACITY_16  0x10
#endif

#ifdef SG_WANT_SHARED_MMAP_IO
#ifndef SG_FLAG_SHARED_MMAP_IO
#define SG_FLAG_SHARED_MMAP_IO 8
#endif
#ifndef SG_INFO_SHARED_MMAP_IO
#define SG_INFO_SHARED_MMAP_IO 8
#endif
#endif

#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikey value */
#endif

#define FT_OTHER 1              /* filetype other than one of following */
#define FT_SG 2                 /* filetype is sg char device */
#define FT_RAW 4                /* filetype is raw char device */
#define FT_DEV_NULL 8           /* either "/dev/null" or "." as filename */
#define FT_ST 16                /* filetype is st char device (tape) */
#define FT_BLOCK 32             /* filetype is a block device */
#define FT_ERROR 64             /* couldn't "stat" file */

#define DEV_NULL_MINOR_NUM 3

#define MIN_RESERVED_SIZE 8192

static int sum_of_resids = 0;

static int64_t dd_count = -1;
static int64_t req_count = 0;
static int64_t in_full = 0;
static int in_partial = 0;
static int64_t out_full = 0;
static int out_partial = 0;
static int verbose = 0;

static int do_time = 0;
static int start_tm_valid = 0;
static struct timeval start_tm;
static int blk_sz = 0;

#ifdef SG_WANT_SHARED_MMAP_IO
static int shared_mm_req = 0;
static int shared_mm_done = 0;
#endif

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

struct flags_t {
    int append;
    int dio;
    int direct;
    int dpo;
    int dsync;
    int excl;
    int fua;
#ifdef SG_WANT_SHARED_MMAP_IO
    int smmap;
#endif
};


static void
install_handler(int sig_num, void (*sig_handler) (int sig))
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

static void
print_stats()
{
    if (0 != dd_count)
        fprintf(stderr, "  remaining block count=%"PRId64"\n", dd_count);
    fprintf(stderr, "%"PRId64"+%d records in\n", in_full - in_partial, in_partial);
    fprintf(stderr, "%"PRId64"+%d records out\n", out_full - out_partial,
            out_partial);
}

static void
calc_duration_throughput(int contin)
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
        fprintf(stderr, "time to transfer data%s: %d.%06d secs",
                (contin ? " so far" : ""), (int)res_tm.tv_sec,
                (int)res_tm.tv_usec);
        if ((a > 0.00001) && (b > 511))
            fprintf(stderr, " at %.2f MB/sec\n", b / (a * 1000000.0));
        else
            fprintf(stderr, "\n");
    }
}

static void
interrupt_handler(int sig)
{
    struct sigaction sigact;

    sigact.sa_handler = SIG_DFL;
    sigemptyset (&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction (sig, &sigact, NULL);
    fprintf(stderr, "Interrupted by signal,");
    print_stats ();
    if (do_time)
        calc_duration_throughput(0);
    kill (getpid (), sig);
}

static void
siginfo_handler(int sig)
{
    sig = sig;  /* dummy to stop -W warning messages */
    fprintf(stderr, "Progress report, continuing ...\n");
    print_stats();
    if (do_time)
        calc_duration_throughput(1);
}

static int
dd_filetype(const char * filename)
{
    struct stat st;
    size_t len = strlen(filename);

    if ((1 == len) && ('.' == filename[0]))
        return FT_DEV_NULL;
    if (stat(filename, &st) < 0)
        return FT_ERROR;
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

static char *
dd_filetype_str(int ft, char * buff)
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
        off += snprintf(buff + off, 32, "other (perhaps ordinary file) ");
    if (FT_ERROR & ft)
        off += snprintf(buff + off, 32, "unable to 'stat' file ");
    return buff;
}

static void
usage()
{
   fprintf(stderr, "Usage: "
           "sgm_dd  [bs=BS] [count=COUNT] [ibs=BS] [if=IFILE]"
           " [iflag=FLAGS]\n"
           "               [obs=BS] [of=OFILE] [oflag=FLAGS] "
           "[seek=SEEK] [skip=SKIP]\n"
           "               [--help] [--version]\n\n");
    fprintf(stderr,
           "               [bpt=BPT] [cdbsz=6|10|12|16] [dio=0|1] "
           "[fua=0|1|2|3]\n"
           "               [sync=0|1] [time=0|1] [verbose=VERB]\n\n"
           "  where:\n"
           "    bpt         is blocks_per_transfer (default is 128)\n"
           "    bs          must be device block size (default 512)\n"
           "    cdbsz       size of SCSI READ or WRITE cdb (default is 10)\n"
           "    count       number of blocks to copy (def: device size)\n"
           "    dio         0->indirect IO on write, 1->direct IO on write\n"
           "                (only when read side is sg device (using mmap))\n"
           "    fua         force unit access: 0->don't(def), 1->OFILE, "
           "2->IFILE,\n"
           "                3->OFILE+IFILE\n"
           "    if          file or device to read from (def: stdin)\n");
    fprintf(stderr,
           "    iflag       comma separated list from: [direct,dpo,dsync,"
           "excl,fua,\n"
           "                null]\n"
           "    of          file or device to write to (def: stdout), "
           "OFILE of '.'\n"
           "                treated as /dev/null\n"
           "    oflag       comma separated list from: [append,dio,direct,"
           "dpo,dsync,\n"
#ifdef SG_WANT_SHARED_MMAP_IO
           "                excl,fua,null,smmap]\n"
#else
           "                excl,fua,null]\n"
#endif
           "    seek        block position to start writing to OFILE\n"
           "    skip        block position to start reading from IFILE\n"
           "    sync        0->no sync(def), 1->SYNCHRONIZE CACHE on OFILE "
           "after copy\n"
           "    time        0->no timing(def), 1->time plus calculate "
           "throughput\n"
           "    verbose     0->quiet(def), 1->some noise, 2->more noise, "
           "etc\n"
           "    --help      print usage message then exit\n"
           "    --version   print version information then exit\n\n"
           "Copy from IFILE to OFILE, similar to dd command\n"
           "specialized for SCSI devices for which mmap-ed IO attempted\n");
}

/* Return of 0 -> success, see sg_ll_read_capacity*() otherwise */
static int
scsi_read_capacity(int sg_fd, int64_t * num_sect, int * sect_sz)
{
    int k, res;
    unsigned int ui;
    unsigned char rcBuff[RCAP16_REPLY_LEN];
    int verb;

    verb = (verbose ? verbose - 1: 0);
    res = sg_ll_readcap_10(sg_fd, 0, 0, rcBuff, READ_CAP_REPLY_LEN, 0,
                           verb);
    if (0 != res)
        return res;

    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3])) {
        int64_t ls;

        res = sg_ll_readcap_16(sg_fd, 0, 0, rcBuff, RCAP16_REPLY_LEN, 0,
                               verb);
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
        ui = ((rcBuff[0] << 24) | (rcBuff[1] << 16) | (rcBuff[2] << 8) |
              rcBuff[3]);
        /* take care not to sign extend values > 0x7fffffff */
        *num_sect = (int64_t)ui + 1;
        *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
                   (rcBuff[6] << 8) | rcBuff[7];
    }
    if (verbose)
        fprintf(stderr, "      number of blocks=%"PRId64" [0x%"PRIx64"], block "
                "size=%d\n", *num_sect, *num_sect, *sect_sz);
    return 0;
}

/* Return of 0 -> success, -1 -> failure. BLKGETSIZE64, BLKGETSIZE and */
/* BLKSSZGET macros problematic (from <linux/fs.h> or <sys/mount.h>). */
static int
read_blkdev_capacity(int sg_fd, int64_t * num_sect, int * sect_sz)
{
#ifdef BLKSSZGET
    if ((ioctl(sg_fd, BLKSSZGET, sect_sz) < 0) && (*sect_sz > 0)) {
        perror("BLKSSZGET ioctl error");
        return -1;
    } else {
 #ifdef BLKGETSIZE64
        uint64_t ull;

        if (ioctl(sg_fd, BLKGETSIZE64, &ull) < 0) {

            perror("BLKGETSIZE64 ioctl error");
            return -1;
        }
        *num_sect = ((int64_t)ull / (int64_t)*sect_sz);
        if (verbose)
            fprintf(stderr, "      [bgs64] number of blocks=%"PRId64" [0x%"PRIx64"], "
                    "block size=%d\n", *num_sect, *num_sect, *sect_sz);
 #else
        unsigned long ul;

        if (ioctl(sg_fd, BLKGETSIZE, &ul) < 0) {
            perror("BLKGETSIZE ioctl error");
            return -1;
        }
        *num_sect = (int64_t)ul;
        if (verbose)
            fprintf(stderr, "      [bgs] number of blocks=%"PRId64" [0x%"PRIx64"], "
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

static int
sg_build_scsi_cdb(unsigned char * cdbp, int cdb_sz, unsigned int blocks,
                  int64_t start_block, int write_true, int fua, int dpo)
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
                        " %d\n", cdb_sz);
        return 1;
    }
    return 0;
}

/* 0 -> successful, SG_LIB_CAT_UNIT_ATTENTION, SG_LIB_SYNTAX_ERROR,
 * SG_LIB_CAT_NOT_READY, SG_LIB_CAT_MEDIUM_HARD, SG_LIB_CAT_ILLEGAL_REQ,
 * SG_LIB_CAT_ABORTED_COMMAND, -2 -> recoverable (ENOMEM),
 * -1 -> unrecoverable error */
static int
sg_read(int sg_fd, unsigned char * buff, int blocks, int64_t from_block,
        int bs, int cdbsz, int fua, int dpo, int do_mmap)
{
    unsigned char rdCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int k, res;

    if (sg_build_scsi_cdb(rdCmd, cdbsz, blocks, from_block, 0, fua, dpo)) {
        fprintf(stderr, ME "bad rd cdb build, from_block=%"PRId64", blocks=%d\n",
                from_block, blocks);
        return SG_LIB_SYNTAX_ERROR;
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = bs * blocks;
    if (! do_mmap)
        io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)from_block;
    if (do_mmap)
        io_hdr.flags |= SG_FLAG_MMAP_IO;
    if (verbose > 2) {
        fprintf(stderr, "    read cdb: ");
        for (k = 0; k < cdbsz; ++k)
            fprintf(stderr, "%02x ", rdCmd[k]);
        fprintf(stderr, "\n");
    }

#if 1
    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        sleep(1);
    if (res < 0) {
        perror(ME "SG_IO error (sg_read)");
        return -1;
    }
#else
    while (((res = write(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return -2;
        perror("reading (wr) on sg device, error");
        return -1;
    }

    while (((res = read(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        perror("reading (rd) on sg device, error");
        return -1;
    }
#endif
    if (verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    res =  sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("Reading, continuing", &io_hdr, verbose > 1);
        break;
    case SG_LIB_CAT_NOT_READY:
    case SG_LIB_CAT_MEDIUM_HARD:
        return res;
    case SG_LIB_CAT_ABORTED_COMMAND:
    case SG_LIB_CAT_UNIT_ATTENTION:
    case SG_LIB_CAT_ILLEGAL_REQ:
    default:
        sg_chk_n_print3("reading", &io_hdr, verbose > 1);
        return res;
    }
    sum_of_resids += io_hdr.resid;
#ifdef SG_DEBUG
    fprintf(stderr, "duration=%u ms\n", io_hdr.duration);
#endif
    return 0;
}

/* 0 -> successful, SG_LIB_CAT_UNIT_ATTENTION, SG_LIB_SYNTAX_ERROR,
 * SG_LIB_CAT_NOT_READY, SG_LIB_CAT_MEDIUM_HARD, SG_LIB_CAT_ILLEGAL_REQ,
 * SG_LIB_CAT_ABORTED_COMMAND, -2 -> recoverable (ENOMEM),
 * -1 -> unrecoverable error */
static int
sg_write(int sg_fd, unsigned char * buff, int blocks, int64_t to_block,
         int bs, int cdbsz, int fua, int dpo, int do_mmap,
#ifdef SG_WANT_SHARED_MMAP_IO
         int mmap_shareable,
#endif
         int * diop)
{
    unsigned char wrCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int k, res;

    if (sg_build_scsi_cdb(wrCmd, cdbsz, blocks, to_block, 1, fua, dpo)) {
        fprintf(stderr, ME "bad wr cdb build, to_block=%"PRId64", blocks=%d\n",
                to_block, blocks);
        return SG_LIB_SYNTAX_ERROR;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = wrCmd;
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = bs * blocks;
#ifdef SG_WANT_SHARED_MMAP_IO
    if (mmap_shareable || (! do_mmap))
#else
    if (! do_mmap)
#endif
        io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)to_block;
#ifdef SG_WANT_SHARED_MMAP_IO
    if (mmap_shareable) {
        io_hdr.flags |= SG_FLAG_SHARED_MMAP_IO;
        ++shared_mm_req;
    } else
#endif
    /* nasty conditional split */ if (do_mmap)
        io_hdr.flags |= SG_FLAG_MMAP_IO;
    else if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;
    if (verbose > 2) {
        fprintf(stderr, "    write cdb: ");
        for (k = 0; k < cdbsz; ++k)
            fprintf(stderr, "%02x ", wrCmd[k]);
        fprintf(stderr, "\n");
    }

#if 1
    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        sleep(1);
    if (res < 0) {
        perror(ME "SG_IO error (sg_write)");
        return -1;
    }
#else
    while (((res = write(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return -2;
        perror("writing (wr) on sg device, error");
        return -1;
    }

    while (((res = read(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        perror("writing (rd) on sg device, error");
        return -1;
    }
#endif
    if (verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("Writing, continuing", &io_hdr, verbose > 1);
        break;
    case SG_LIB_CAT_NOT_READY:
    case SG_LIB_CAT_MEDIUM_HARD:
        return res;
    case SG_LIB_CAT_ABORTED_COMMAND:
    case SG_LIB_CAT_UNIT_ATTENTION:
    case SG_LIB_CAT_ILLEGAL_REQ:
    default:
        sg_chk_n_print3("writing", &io_hdr, verbose > 1);
        return res;
    }
#ifdef SG_WANT_SHARED_MMAP_IO
    if ((mmap_shareable) && (SG_INFO_SHARED_MMAP_IO & io_hdr.info))
        ++shared_mm_done;
#endif
    if (diop && *diop &&
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0;      /* flag that dio not done (completely) */
    return 0;
}

static int
process_flags(const char * arg, struct flags_t * fp)
{
    char buff[256];
    char * cp;
    char * np;

    strncpy(buff, arg, sizeof(buff));
    buff[sizeof(buff) - 1] = '\0';
    if ('\0' == buff[0]) {
        fprintf(stderr, "no flag found\n");
        return 1;
    }
    cp = buff;
    do {
        np = strchr(cp, ',');
        if (np)
            *np++ = '\0';
        if (0 == strcmp(cp, "append"))
            fp->append = 1;
        else if (0 == strcmp(cp, "dio"))
            fp->dio = 1;
        else if (0 == strcmp(cp, "direct"))
            fp->direct = 1;
        else if (0 == strcmp(cp, "dpo"))
            fp->dpo = 1;
        else if (0 == strcmp(cp, "dsync"))
            fp->dsync = 1;
        else if (0 == strcmp(cp, "excl"))
            fp->excl = 1;
        else if (0 == strcmp(cp, "fua"))
            fp->fua = 1;
        else if (0 == strcmp(cp, "null"))
            ;
#ifdef SG_WANT_SHARED_MMAP_IO
        else if (0 == strcmp(cp, "smmap"))
            fp->smmap = 1;
#endif
        else {
            fprintf(stderr, "unrecognised flag: %s\n", cp);
            return 1;
        }
        cp = np;
    } while (cp);
    return 0;
}


#define STR_SZ 1024
#define INOUTF_SZ 512
#define EBUFF_SZ 512


int
main(int argc, char * argv[])
{
    int64_t skip = 0;
    int64_t seek = 0;
    int ibs = 0;
    int obs = 0;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    int bpt_given = 0;
    char str[STR_SZ];
    char * key;
    char * buf;
    char inf[INOUTF_SZ];
    int in_type = FT_OTHER;
    char outf[INOUTF_SZ];
    int out_type = FT_OTHER;
    int res, k, t;
    int infd, outfd, blocks;
    unsigned char * wrkPos;
    unsigned char * wrkBuff = NULL;
    unsigned char * wrkMmap = NULL;
    int64_t in_num_sect = -1;
    int in_res_sz = 0;
    int64_t out_num_sect = -1;
    int out_res_sz = 0;
    int scsi_cdbsz_in = DEF_SCSI_CDBSZ;
    int scsi_cdbsz_out = DEF_SCSI_CDBSZ;
    int cdbsz_given = 0;
    int do_coe = 0;     /* dummy, just accept + ignore */
    int do_sync = 0;
    int num_dio_not_done = 0;
    int in_sect_sz, out_sect_sz;
    int n, flags;
    char ebuff[EBUFF_SZ];
    int blocks_per;
    size_t psz = getpagesize();
    struct flags_t in_flags;
    struct flags_t out_flags;
#ifdef SG_WANT_SHARED_MMAP_IO
    int mmap_shareable = 0;
#endif
    int ret = 0;

    inf[0] = '\0';
    outf[0] = '\0';
    memset(&in_flags, 0, sizeof(in_flags));
    memset(&out_flags, 0, sizeof(out_flags));

    for (k = 1; k < argc; k++) {
        if (argv[k])
            strncpy(str, argv[k], STR_SZ);
        else
            continue;
        for (key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        if (0 == strcmp(key,"bpt")) {
            bpt = sg_get_num(buf);
            if (-1 == bpt) {
                fprintf(stderr, ME "bad argument to 'bpt'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            bpt_given = 1;
        } else if (0 == strcmp(key,"bs")) {
            blk_sz = sg_get_num(buf);
            if (-1 == blk_sz) {
                fprintf(stderr, ME "bad argument to 'bs'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"cdbsz")) {
            scsi_cdbsz_in = sg_get_num(buf);
            scsi_cdbsz_out = scsi_cdbsz_in;
            cdbsz_given = 1;
        } else if (0 == strcmp(key,"coe"))
            do_coe = sg_get_num(buf);   /* dummy, just accept + ignore */
        else if (0 == strcmp(key,"count")) {
            if (0 != strcmp("-1", buf)) {
                dd_count = sg_get_llnum(buf);
                if (-1LL == dd_count) {
                    fprintf(stderr, ME "bad argument to 'count'\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            }   /* treat 'count=-1' as calculate count (same as not given) */
        } else if (0 == strcmp(key,"dio"))
            out_flags.dio = sg_get_num(buf);
        else if (0 == strcmp(key,"fua")) {
            n = sg_get_num(buf);
            if (n & 1)
                out_flags.fua = 1;
            if (n & 2)
                in_flags.fua = 1;
        } else if (0 == strcmp(key,"ibs")) {
            ibs = sg_get_num(buf);
            if (-1 == ibs) {
                fprintf(stderr, ME "bad argument to 'ibs'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"if") == 0) {
            if ('\0' != inf[0]) {
                fprintf(stderr, "Second 'if=' argument??\n");
                return SG_LIB_SYNTAX_ERROR;
            } else
                strncpy(inf, buf, INOUTF_SZ);
        } else if (0 == strcmp(key, "iflag")) {
            if (process_flags(buf, &in_flags)) {
                fprintf(stderr, ME "bad argument to 'iflag'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"of") == 0) {
            if ('\0' != outf[0]) {
                fprintf(stderr, "Second 'of=' argument??\n");
                return SG_LIB_SYNTAX_ERROR;
            } else
                strncpy(outf, buf, INOUTF_SZ);
        } else if (0 == strcmp(key, "oflag")) {
            if (process_flags(buf, &out_flags)) {
                fprintf(stderr, ME "bad argument to 'oflag'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"obs")) {
            obs = sg_get_num(buf);
            if (-1 == obs) {
                fprintf(stderr, ME "bad argument to 'obs'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"seek")) {
            seek = sg_get_llnum(buf);
            if (-1LL == seek) {
                fprintf(stderr, ME "bad argument to 'seek'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"skip")) {
            skip = sg_get_llnum(buf);
            if (-1LL == skip) {
                fprintf(stderr, ME "bad argument to 'skip'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"sync"))
            do_sync = sg_get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = sg_get_num(buf);
        else if (0 == strncmp(key, "verb", 4))
            verbose = sg_get_num(buf);
        else if ((0 == strncmp(key, "--help", 7)) ||
                 (0 == strcmp(key, "-?"))) {
            usage();
            return 0;
        } else if ((0 == strncmp(key, "--vers", 6)) ||
                   (0 == strcmp(key, "-V"))) {
            fprintf(stderr, ME ": %s\n", version_str);
            return 0;
        }
        else {
            fprintf(stderr, "Unrecognized option '%s'\n", key);
            fprintf(stderr, "For more information use '--help'\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (blk_sz <= 0) {
        blk_sz = DEF_BLOCK_SIZE;
        fprintf(stderr, "Assume default 'bs' (block size) of %d bytes\n", blk_sz);
    }
    if ((ibs && (ibs != blk_sz)) || (obs && (obs != blk_sz))) {
        fprintf(stderr, "If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((skip < 0) || (seek < 0)) {
        fprintf(stderr, "skip and seek cannot be negative\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((out_flags.append > 0) && (seek > 0)) {
        fprintf(stderr, "Can't use both append and seek switches\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (bpt < 1) {
        fprintf(stderr, "bpt must be greater than 0\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    /* defaulting transfer size to 128*2048 for CD/DVDs is too large
       for the block layer in lk 2.6 and results in an EIO on the
       SG_IO ioctl. So reduce it in that case. */
    if ((blk_sz >= 2048) && (0 == bpt_given))
        bpt = DEF_BLOCKS_PER_2048TRANSFER;

#ifdef SG_DEBUG
    fprintf(stderr, ME "if=%s skip=%"PRId64" of=%s seek=%"PRId64" count=%"PRId64"\n",
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
        if (verbose)
            fprintf(stderr, " >> Input file type: %s\n",
                    dd_filetype_str(in_type, ebuff));

        if (FT_ERROR == in_type) {
            fprintf(stderr, ME "unable to access %s\n", inf);
            return SG_LIB_FILE_ERROR;
        } else if (FT_ST == in_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", inf);
            return SG_LIB_FILE_ERROR;
        } else if (FT_SG == in_type) {
            flags = O_RDWR | O_NONBLOCK;
            if (in_flags.direct)
                flags |= O_DIRECT;
            if (in_flags.excl)
                flags |= O_EXCL;
            if (in_flags.dsync)
                flags |= O_SYNC;
            if ((infd = open(inf, flags)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for sg reading", inf);
                perror(ebuff);
                return SG_LIB_FILE_ERROR;
            }
            res = ioctl(infd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30122)) {
                fprintf(stderr, ME "sg driver prior to 3.1.22\n");
                return SG_LIB_FILE_ERROR;
            }
            in_res_sz = blk_sz * bpt;
            if (0 != (in_res_sz % psz)) /* round up to next page */
                in_res_sz = ((in_res_sz / psz) + 1) * psz;
            if (ioctl(infd, SG_GET_RESERVED_SIZE, &t) < 0) {
                perror(ME "SG_GET_RESERVED_SIZE error");
                return SG_LIB_FILE_ERROR;
            }
            if (t < MIN_RESERVED_SIZE)
                t = MIN_RESERVED_SIZE;
            if (in_res_sz > t) {
                if (ioctl(infd, SG_SET_RESERVED_SIZE, &in_res_sz) < 0) {
                    perror(ME "SG_SET_RESERVED_SIZE error");
                    return SG_LIB_FILE_ERROR;
                }
            }
            wrkMmap = (unsigned char *)mmap(NULL, in_res_sz,
                                 PROT_READ | PROT_WRITE, MAP_SHARED, infd, 0);
            if (MAP_FAILED == wrkMmap) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "error using mmap() on file: %s", inf);
                perror(ebuff);
                return SG_LIB_FILE_ERROR;
            }
#ifdef SG_WANT_SHARED_MMAP_IO
            mmap_shareable = 1;
#endif
        }
        else {
            flags = O_RDONLY;
            if (in_flags.direct)
                flags |= O_DIRECT;
            if (in_flags.excl)
                flags |= O_EXCL;
            if (in_flags.dsync)
                flags |= O_SYNC;
            if ((infd = open(inf, flags)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", inf);
                perror(ebuff);
                return SG_LIB_FILE_ERROR;
            }
            else if (skip > 0) {
                off64_t offset = skip;

                offset *= blk_sz;       /* could exceed 32 bits here! */
                if (lseek64(infd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ, ME "couldn't skip to "
                             "required position on %s", inf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
                if (verbose)
                    fprintf(stderr, "  >> skip: lseek64 SEEK_SET, "
                            "byte offset=0x%"PRIx64"\n",
                            (uint64_t)offset);
            }
        }
    }

    if (outf[0] && ('-' != outf[0])) {
        out_type = dd_filetype(outf);
        if (verbose)
            fprintf(stderr, " >> Output file type: %s\n",
                    dd_filetype_str(out_type, ebuff));

        if (FT_ST == out_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", outf);
            return SG_LIB_FILE_ERROR;
        }
        else if (FT_SG == out_type) {
            flags = O_RDWR | O_NONBLOCK;
            if (out_flags.direct)
                flags |= O_DIRECT;
            if (out_flags.excl)
                flags |= O_EXCL;
            if (out_flags.dsync)
                flags |= O_SYNC;
            if ((outfd = open(outf, flags)) < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "could not open %s for "
                         "sg writing", outf);
                perror(ebuff);
                return SG_LIB_FILE_ERROR;
            }
            res = ioctl(outfd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30122)) {
                fprintf(stderr, ME "sg driver prior to 3.1.22\n");
                return SG_LIB_FILE_ERROR;
            }
            if (ioctl(outfd, SG_GET_RESERVED_SIZE, &t) < 0) {
                perror(ME "SG_GET_RESERVED_SIZE error");
                return SG_LIB_FILE_ERROR;
            }
           if (t < MIN_RESERVED_SIZE)
                t = MIN_RESERVED_SIZE;
            out_res_sz = blk_sz * bpt;
            if (out_res_sz > t) {
                if (ioctl(outfd, SG_SET_RESERVED_SIZE, &out_res_sz) < 0) {
                    perror(ME "SG_SET_RESERVED_SIZE error");
                    return SG_LIB_FILE_ERROR;
                }
            }
            if (NULL == wrkMmap) {
                wrkMmap = (unsigned char *)mmap(NULL, out_res_sz,
                                PROT_READ | PROT_WRITE, MAP_SHARED, outfd, 0);
                if (MAP_FAILED == wrkMmap) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "error using mmap() on file: %s", outf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
            }
        }
        else if (FT_DEV_NULL == out_type)
            outfd = -1; /* don't bother opening */
        else {
            if (FT_RAW != out_type) {
                flags = O_WRONLY | O_CREAT;
                if (out_flags.direct)
                    flags |= O_DIRECT;
                if (out_flags.excl)
                    flags |= O_EXCL;
                if (out_flags.dsync)
                    flags |= O_SYNC;
                if (out_flags.append)
                    flags |= O_APPEND;
                if ((outfd = open(outf, flags, 0666)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for writing", outf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
            }
            else {
                if ((outfd = open(outf, O_WRONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ, ME "could not open %s "
                             "for raw writing", outf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
            }
            if (seek > 0) {
                off64_t offset = seek;

                offset *= blk_sz;       /* could exceed 32 bits here! */
                if (lseek64(outfd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ, ME "couldn't seek to "
                             "required position on %s", outf);
                    perror(ebuff);
                    return SG_LIB_FILE_ERROR;
                }
                if (verbose)
                    fprintf(stderr, "   >> seek: lseek64 SEEK_SET, "
                            "byte offset=0x%"PRIx64"\n",
                            (uint64_t)offset);
            }
        }
    }
    if ((STDIN_FILENO == infd) && (STDOUT_FILENO == outfd)) {
        fprintf(stderr, "Won't default both IFILE to stdin _and_ OFILE "
                "to as stdout\n");
        fprintf(stderr, "For more information use '--help'\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (dd_count < 0) {
        in_num_sect = -1;
        if (FT_SG == in_type) {
            res = scsi_read_capacity(infd, &in_num_sect, &in_sect_sz);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                fprintf(stderr, "Unit attention(in), continuing\n");
                res = scsi_read_capacity(infd, &in_num_sect, &in_sect_sz);
            } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
                fprintf(stderr, "Aborted command(in), continuing\n");
                res = scsi_read_capacity(infd, &in_num_sect, &in_sect_sz);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    fprintf(stderr, "read capacity not supported on %s\n",
                            inf);
                else if (res == SG_LIB_CAT_NOT_READY)
                    fprintf(stderr, "read capacity failed, %s not ready\n",
                            inf);
                else
                    fprintf(stderr, "Unable to read capacity on %s\n", inf);
                in_num_sect = -1;
            }
        } else if (FT_BLOCK == in_type) {
            if (0 != read_blkdev_capacity(infd, &in_num_sect, &in_sect_sz)) {
                fprintf(stderr, "Unable to read block capacity on %s\n", inf);
                in_num_sect = -1;
            }
            if (blk_sz != in_sect_sz) {
                fprintf(stderr, "block size on %s confusion; bs=%d, from "
                        "device=%d\n", inf, blk_sz, in_sect_sz);
                in_num_sect = -1;
            }
        }
        if (in_num_sect > skip)
            in_num_sect -= skip;

        out_num_sect = -1;
        if (FT_SG == out_type) {
            res = scsi_read_capacity(outfd, &out_num_sect, &out_sect_sz);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                fprintf(stderr, "Unit attention(out), continuing\n");
                res = scsi_read_capacity(outfd, &out_num_sect, &out_sect_sz);
            } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
                fprintf(stderr, "Aborted command(out), continuing\n");
                res = scsi_read_capacity(outfd, &out_num_sect, &out_sect_sz);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    fprintf(stderr, "read capacity not supported on %s\n",
                            outf);
                else if (res == SG_LIB_CAT_NOT_READY)
                    fprintf(stderr, "read capacity failed, %s not ready\n",
                            outf);
                else
                    fprintf(stderr, "Unable to read capacity on %s\n", outf);
                out_num_sect = -1;
            }
        } else if (FT_BLOCK == out_type) {
            if (0 != read_blkdev_capacity(outfd, &out_num_sect,
                                          &out_sect_sz)) {
                fprintf(stderr, "Unable to read block capacity on %s\n",
                        outf);
                out_num_sect = -1;
            }
            if (blk_sz != out_sect_sz) {
                fprintf(stderr, "block size on %s confusion: bs=%d, from "
                        "device=%d\n", outf, blk_sz, out_sect_sz);
                out_num_sect = -1;
            }
        }
        if (out_num_sect > seek)
            out_num_sect -= seek;
#ifdef SG_DEBUG
        fprintf(stderr,
            "Start of loop, count=%"PRId64", in_num_sect=%"PRId64", out_num_sect=%"PRId64"\n",
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
        return SG_LIB_SYNTAX_ERROR;
    }
    if (! cdbsz_given) {
        if ((FT_SG == in_type) && (MAX_SCSI_CDBSZ != scsi_cdbsz_in) &&
            (((dd_count + skip) > UINT_MAX) || (bpt > USHRT_MAX))) {
            fprintf(stderr, "Note: SCSI command size increased to 16 bytes "
                    "(for 'if')\n");
            scsi_cdbsz_in = MAX_SCSI_CDBSZ;
        }
        if ((FT_SG == out_type) && (MAX_SCSI_CDBSZ != scsi_cdbsz_out) &&
            (((dd_count + seek) > UINT_MAX) || (bpt > USHRT_MAX))) {
            fprintf(stderr, "Note: SCSI command size increased to 16 bytes "
                    "(for 'of')\n");
            scsi_cdbsz_out = MAX_SCSI_CDBSZ;
        }
    }

    if (out_flags.dio && (FT_SG != in_type)) {
        out_flags.dio = 0;
        fprintf(stderr, ">>> dio only performed on 'of' side when 'if' is"
                " an sg device\n");
    }
    if (out_flags.dio) {
        int fd;
        char c;

        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    fprintf(stderr, ">>> %s set to '0' but should be set "
                            "to '1' for direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    }

    if (wrkMmap) {
        wrkPos = wrkMmap;
#ifdef SG_WANT_SHARED_MMAP_IO
        if (! (mmap_shareable && out_flags.smmap &&  (FT_SG == out_type)))
            mmap_shareable = 0;
#endif
    } else {
        if ((FT_RAW == in_type) || (FT_RAW == out_type)) {
            wrkBuff = (unsigned char *)malloc(blk_sz * bpt + psz);
            if (0 == wrkBuff) {
                fprintf(stderr, "Not enough user memory for raw\n");
                return SG_LIB_FILE_ERROR;
            }
            wrkPos = (unsigned char *)(((unsigned long)wrkBuff + psz - 1) &
                                       (~(psz - 1)));
        }
        else {
            wrkBuff = (unsigned char *)malloc(blk_sz * bpt);
            if (0 == wrkBuff) {
                fprintf(stderr, "Not enough user memory\n");
                return SG_LIB_FILE_ERROR;
            }
            wrkPos = wrkBuff;
        }
    }

    blocks_per = bpt;
#ifdef SG_DEBUG
    fprintf(stderr, "Start of loop, count=%"PRId64", blocks_per=%d\n",
            dd_count, blocks_per);
#endif
    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
        start_tm_valid = 1;
    }
    req_count = dd_count;

#ifdef SG_WANT_SHARED_MMAP_IO
    if (verbose && (dd_count > 0) && (0 == out_flags.dio) &&
        (FT_SG == in_type) && (FT_SG == out_type) && (! mmap_shareable))
#else
    if (verbose && (dd_count > 0) && (0 == out_flags.dio) &&
        (FT_SG == in_type) && (FT_SG == out_type))
#endif
        fprintf(stderr, "Since both 'if' and 'of' are sg devices, only do "
                "mmap-ed transfers on 'if'\n");

    while (dd_count > 0) {
        blocks = (dd_count > blocks_per) ? blocks_per : dd_count;
        if (FT_SG == in_type) {
            ret = sg_read(infd, wrkPos, blocks, skip, blk_sz, scsi_cdbsz_in,
                          in_flags.fua, in_flags.dpo, 1);
            if ((SG_LIB_CAT_UNIT_ATTENTION == ret) ||
                (SG_LIB_CAT_ABORTED_COMMAND == ret)) {
                fprintf(stderr, "Unit attention or aborted command, "
                        "continuing (r)\n");
                ret = sg_read(infd, wrkPos, blocks, skip, blk_sz,
                              scsi_cdbsz_in, in_flags.fua, in_flags.dpo, 1);
            }
            if (0 != ret) {
                fprintf(stderr, "sg_read failed, skip=%"PRId64"\n", skip);
                break;
            }
            else
                in_full += blocks;
        }
        else {
            while (((res = read(infd, wrkPos, blocks * blk_sz)) < 0) &&
                   (EINTR == errno))
                ;
            if (verbose > 2)
                fprintf(stderr, "read(unix): count=%d, res=%d\n",
                        blocks * blk_sz, res);
            if (ret < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "reading, skip=%"PRId64" ", skip);
                perror(ebuff);
                ret = -1;
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
            break;      /* read nothing so leave loop */

        if (FT_SG == out_type) {
            int do_mmap = (FT_SG == in_type) ? 0 : 1;
            int dio_res = out_flags.dio;

            ret = sg_write(outfd, wrkPos, blocks, seek, blk_sz, scsi_cdbsz_out,
                           out_flags.fua, out_flags.dpo, do_mmap,
#ifdef SG_WANT_SHARED_MMAP_IO
                           mmap_shareable,
#endif
                           &dio_res);
            if ((SG_LIB_CAT_UNIT_ATTENTION == ret) ||
                (SG_LIB_CAT_ABORTED_COMMAND == ret)) {
                fprintf(stderr, "Unit attention or aborted command, "
                        "continuing (w)\n");
                dio_res = out_flags.dio;
                ret = sg_write(outfd, wrkPos, blocks, seek, blk_sz,
                               scsi_cdbsz_out, out_flags.fua, out_flags.dpo,
                               do_mmap,
#ifdef SG_WANT_SHARED_MMAP_IO
                               mmap_shareable,
#endif
                               &dio_res);
            }
            if (0 != ret) {
                fprintf(stderr, "sg_write failed, seek=%"PRId64"\n", seek);
                break;
            }
            else {
                out_full += blocks;
                if (out_flags.dio && (0 == dio_res))
                    num_dio_not_done++;
            }
        }
        else if (FT_DEV_NULL == out_type)
            out_full += blocks; /* act as if written out without error */
        else {
            while (((res = write(outfd, wrkPos, blocks * blk_sz)) < 0)
                   && (EINTR == errno))
                ;
            if (verbose > 2)
                fprintf(stderr, "write(unix): count=%d, res=%d\n",
                        blocks * blk_sz, res);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "writing, seek=%"PRId64" ", seek);
                perror(ebuff);
                break;
            }
            else if (res < blocks * blk_sz) {
                fprintf(stderr, "output file probably full, seek=%"PRId64" ", seek);
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
    }

    if (do_time)
        calc_duration_throughput(0);
    if (do_sync) {
        if (FT_SG == out_type) {
            fprintf(stderr, ">> Synchronizing cache on %s\n", outf);
            res = sg_ll_sync_cache_10(outfd, 0, 0, 0, 0, 0, 0, 0);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                fprintf(stderr, "Unit attention(out), continuing\n");
                res = sg_ll_sync_cache_10(outfd, 0, 0, 0, 0, 0, 0, 0);
            }
            if (0 != res)
                fprintf(stderr, "Unable to synchronize cache\n");
        }
    }

    if (wrkBuff) free(wrkBuff);
    if (STDIN_FILENO != infd)
        close(infd);
    if ((STDOUT_FILENO != outfd) && (FT_DEV_NULL != out_type))
        close(outfd);
    if (0 != dd_count) {
        fprintf(stderr, "Some error occurred,");
        if (0 == ret)
            ret = SG_LIB_CAT_OTHER;
    }
    print_stats();
    if (sum_of_resids)
        fprintf(stderr, ">> Non-zero sum of residual counts=%d\n",
                sum_of_resids);
    if (num_dio_not_done)
        fprintf(stderr, ">> dio requested but _not_ done %d times\n",
                num_dio_not_done);
#ifdef SG_WANT_SHARED_MMAP_IO
    if ((verbose > 0) && out_flags.smmap && (shared_mm_req > 0)) {
        fprintf(stderr, ">> shared_mm_req=%d,  shared_mm_done=%d\n",
                shared_mm_req, shared_mm_done);
    }
#endif
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
