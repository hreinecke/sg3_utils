/* A utility program for copying files. Specialised for "files" that
 * represent devices that understand the SCSI command set.
 *
 * Copyright (C) 1999 - 2020 D. Gilbert and P. Allworth
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later

   This program is a specialisation of the Unix "dd" command in which
   either the input or the output file is a scsi generic device. The block
   size ('bs') is assumed to be 512 if not given. This program complains if
   'ibs' or 'obs' are given with a value that differs from 'bs' (or the
   default, 512). If 'if' is not given or 'if=-' then stdin is assumed.
   If 'of' is not given or 'of=-' then stdout assumed.

   A non-standard argument "bpt" (blocks per transfer) is added to control
   the maximum number of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16 KiB
   in this case) is transferred to or from the sg device in a single SCSI
   command.

   This version uses memory-mapped transfers (i.e. mmap() call from the user
   space) to speed transfers. If both sides of copy are sg devices
   then only the read side will be mmap-ed, while the write side will
   use normal IO.

   This version is designed for the linux kernel 2.4, 2.6, 3 and 4 series.
*/

#define _XOPEN_SOURCE 600
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#ifndef major
#include <sys/types.h>
#endif
#include <linux/major.h>        /* for MEM_MAJOR, SCSI_GENERIC_MAJOR, etc */
#include <linux/fs.h>           /* for BLKSSZGET and friends */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"


static const char * version_str = "1.65 20200216";

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_BLOCKS_PER_2048TRANSFER 32
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define ME "sgm_dd: "


#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

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
static int dry_run = 0;

static bool do_time = false;
static bool start_tm_valid = false;
static struct timeval start_tm;
static int blk_sz = 0;
static uint32_t glob_pack_id = 0;       /* pre-increment */

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

struct flags_t {
    bool append;
    bool dio;
    bool direct;
    bool dpo;
    bool dsync;
    bool excl;
    bool fua;
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
        pr2serr("  remaining block count=%" PRId64 "\n", dd_count);
    pr2serr("%" PRId64 "+%d records in\n", in_full - in_partial, in_partial);
    pr2serr("%" PRId64 "+%d records out\n", out_full - out_partial,
            out_partial);
}

static void
calc_duration_throughput(bool contin)
{
    double a, b;
    struct timeval end_tm, res_tm;

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
        pr2serr("time to transfer data%s: %d.%06d secs",
                (contin ? " so far" : ""), (int)res_tm.tv_sec,
                (int)res_tm.tv_usec);
        if ((a > 0.00001) && (b > 511))
            pr2serr(" at %.2f MB/sec\n", b / (a * 1000000.0));
        else
            pr2serr("\n");
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
    pr2serr("Interrupted by signal,");
    print_stats ();
    if (do_time)
        calc_duration_throughput(false);
    kill (getpid (), sig);
}

static void
siginfo_handler(int sig)
{
    if (sig) { ; }      /* unused, dummy to suppress warning */
    pr2serr("Progress report, continuing ...\n");
    print_stats();
    if (do_time)
        calc_duration_throughput(true);
}

static int
dd_filetype(const char * filename)
{
    size_t len = strlen(filename);
    struct stat st;

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
        off += sg_scnpr(buff + off, 32, "null device ");
    if (FT_SG & ft)
        off += sg_scnpr(buff + off, 32, "SCSI generic (sg) device ");
    if (FT_BLOCK & ft)
        off += sg_scnpr(buff + off, 32, "block device ");
    if (FT_ST & ft)
        off += sg_scnpr(buff + off, 32, "SCSI tape device ");
    if (FT_RAW & ft)
        off += sg_scnpr(buff + off, 32, "raw device ");
    if (FT_OTHER & ft)
        off += sg_scnpr(buff + off, 32, "other (perhaps ordinary file) ");
    if (FT_ERROR & ft)
        sg_scnpr(buff + off, 32, "unable to 'stat' file ");
    return buff;
}

static void
usage()
{
    pr2serr("Usage: sgm_dd  [bs=BS] [count=COUNT] [ibs=BS] [if=IFILE]"
            " [iflag=FLAGS]\n"
            "               [obs=BS] [of=OFILE] [oflag=FLAGS] "
            "[seek=SEEK] [skip=SKIP]\n"
            "               [--help] [--version]\n\n");
    pr2serr("               [bpt=BPT] [cdbsz=6|10|12|16] [dio=0|1] "
            "[fua=0|1|2|3]\n"
            "               [sync=0|1] [time=0|1] [verbose=VERB] "
            "[--dry-run] [--verbose]\n\n"
            "  where:\n"
            "    bpt         is blocks_per_transfer (default is 128)\n"
            "    bs          must be device logical block size (default "
            "512)\n"
            "    cdbsz       size of SCSI READ or WRITE cdb (default is 10)\n"
            "    count       number of blocks to copy (def: device size)\n"
            "    dio         0->indirect IO on write, 1->direct IO on write\n"
            "                (only when read side is sg device (using mmap))\n"
            "    fua         force unit access: 0->don't(def), 1->OFILE, "
            "2->IFILE,\n"
            "                3->OFILE+IFILE\n"
            "    if          file or device to read from (def: stdin)\n");
    pr2serr("    iflag       comma separated list from: [direct,dpo,dsync,"
            "excl,fua,\n"
            "                null]\n"
            "    of          file or device to write to (def: stdout), "
            "OFILE of '.'\n"
            "                treated as /dev/null\n"
            "    oflag       comma separated list from: [append,dio,direct,"
            "dpo,dsync,\n"
            "                excl,fua,null]\n"
            "    seek        block position to start writing to OFILE\n"
            "    skip        block position to start reading from IFILE\n"
            "    sync        0->no sync(def), 1->SYNCHRONIZE CACHE on OFILE "
            "after copy\n"
            "    time        0->no timing(def), 1->time plus calculate "
            "throughput\n"
            "    verbose     0->quiet(def), 1->some noise, 2->more noise, "
            "etc\n"
            "    --dry-run|-d    prepare but bypass copy/read\n"
            "    --help|-h       print usage message then exit\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version information then exit\n\n"
            "Copy from IFILE to OFILE, similar to dd command\n"
            "specialized for SCSI devices for which mmap-ed IO attempted\n");
}

/* Return of 0 -> success, see sg_ll_read_capacity*() otherwise */
static int
scsi_read_capacity(int sg_fd, int64_t * num_sect, int * sect_sz)
{
    int res, verb;
    unsigned int ui;
    uint8_t rcBuff[RCAP16_REPLY_LEN];

    verb = (verbose ? verbose - 1: 0);
    res = sg_ll_readcap_10(sg_fd, 0, 0, rcBuff, READ_CAP_REPLY_LEN, false,
                           verb);
    if (0 != res)
        return res;

    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3])) {

        res = sg_ll_readcap_16(sg_fd, 0, 0, rcBuff, RCAP16_REPLY_LEN, false,
                               verb);
        if (0 != res)
            return res;
        *num_sect = sg_get_unaligned_be64(rcBuff + 0) + 1;
        *sect_sz = sg_get_unaligned_be32(rcBuff + 8);
    } else {
        ui = sg_get_unaligned_be32(rcBuff + 0);
        /* take care not to sign extend values > 0x7fffffff */
        *num_sect = (int64_t)ui + 1;
        *sect_sz = sg_get_unaligned_be32(rcBuff + 4);
    }
    if (verbose)
        pr2serr("      number of blocks=%" PRId64 " [0x%" PRIx64 "], block "
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
            pr2serr("      [bgs64] number of blocks=%" PRId64 " [0x%" PRIx64
                    "], logical block size=%d\n", *num_sect, *num_sect,
                    *sect_sz);
 #else
        unsigned long ul;

        if (ioctl(sg_fd, BLKGETSIZE, &ul) < 0) {
            perror("BLKGETSIZE ioctl error");
            return -1;
        }
        *num_sect = (int64_t)ul;
        if (verbose)
            pr2serr("      [bgs] number of blocks=%" PRId64 " [0x%" PRIx64
                    "], logical block size=%d\n", *num_sect, *num_sect,
                    *sect_sz);
 #endif
    }
    return 0;
#else
    if (verbose)
        pr2serr("      BLKSSZGET+BLKGETSIZE ioctl not available\n");
    *num_sect = 0;
    *sect_sz = 0;
    return -1;
#endif
}

static int
sg_build_scsi_cdb(uint8_t * cdbp, int cdb_sz, unsigned int blocks,
                  int64_t start_block, bool write_true, bool fua, bool dpo)
{
    int sz_ind;
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};

    memset(cdbp, 0, cdb_sz);
    if (dpo)
        cdbp[1] |= 0x10;
    if (fua)
        cdbp[1] |= 0x8;
    switch (cdb_sz) {
    case 6:
        sz_ind = 0;
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        sg_put_unaligned_be24(0x1fffff & start_block, cdbp + 1);
        cdbp[4] = (256 == blocks) ? 0 : (uint8_t)blocks;
        if (blocks > 256) {
            pr2serr(ME "for 6 byte commands, maximum number of blocks is "
                    "256\n");
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            pr2serr(ME "for 6 byte commands, can't address blocks beyond "
                    "%d\n", 0x1fffff);
            return 1;
        }
        if (dpo || fua) {
            pr2serr(ME "for 6 byte commands, neither dpo nor fua bits "
                    "supported\n");
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        sg_put_unaligned_be32((uint32_t)start_block, cdbp + 2);
        sg_put_unaligned_be16((uint16_t)blocks, cdbp + 7);
        if (blocks & (~0xffff)) {
            pr2serr(ME "for 10 byte commands, maximum number of blocks is "
                    "%d\n", 0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        sg_put_unaligned_be32((uint32_t)start_block, cdbp + 2);
        sg_put_unaligned_be32((uint32_t)blocks, cdbp + 6);
        break;
    case 16:
        sz_ind = 3;
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        sg_put_unaligned_be64((uint64_t)start_block, cdbp + 2);
        sg_put_unaligned_be32((uint32_t)blocks, cdbp + 10);
        break;
    default:
        pr2serr(ME "expected cdb size of 6, 10, 12, or 16 but got %d\n",
                cdb_sz);
        return 1;
    }
    return 0;
}

/* Returns 0 -> successful, various SG_LIB_CAT_* positive values,
 * -2 -> recoverable (ENOMEM), -1 -> unrecoverable error */
static int
sg_read(int sg_fd, uint8_t * buff, int blocks, int64_t from_block,
        int bs, int cdbsz, bool fua, bool dpo, bool do_mmap)
{
    int res;
    uint8_t rdCmd[MAX_SCSI_CDBSZ];
    uint8_t senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (sg_build_scsi_cdb(rdCmd, cdbsz, blocks, from_block, false, fua,
                          dpo)) {
        pr2serr(ME "bad rd cdb build, from_block=%" PRId64 ", blocks=%d\n",
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
    io_hdr.pack_id = (int)++glob_pack_id;
    if (do_mmap)
        io_hdr.flags |= SG_FLAG_MMAP_IO;
    if (verbose > 2) {
        char b[128];

        pr2serr("    Read cdb: %s\n",
                sg_get_command_str(rdCmd, cdbsz, false, sizeof(b), b));
    }

#if 1
    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        sleep(1);
    if (res < 0) {
        perror(ME "SG_IO error (sg_read)");
        return -1;
    }
#else
    while (((res = write(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return -2;
        perror("reading (wr) on sg device, error");
        return -1;
    }

    while (((res = read(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    if (res < 0) {
        perror("reading (rd) on sg device, error");
        return -1;
    }
#endif
    if (verbose > 2)
        pr2serr("      duration=%u ms\n", io_hdr.duration);
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
#ifdef DEBUG
    pr2serr("duration=%u ms\n", io_hdr.duration);
#endif
    return 0;
}

/* Returns 0 -> successful, various SG_LIB_CAT_* positive values,
 * -2 -> recoverable (ENOMEM), -1 -> unrecoverable error */
static int
sg_write(int sg_fd, uint8_t * buff, int blocks, int64_t to_block,
         int bs, int cdbsz, bool fua, bool dpo, bool do_mmap, bool * diop)
{
    int res;
    uint8_t wrCmd[MAX_SCSI_CDBSZ];
    uint8_t senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (sg_build_scsi_cdb(wrCmd, cdbsz, blocks, to_block, true, fua, dpo)) {
        pr2serr(ME "bad wr cdb build, to_block=%" PRId64 ", blocks=%d\n",
                to_block, blocks);
        return SG_LIB_SYNTAX_ERROR;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = wrCmd;
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = bs * blocks;
    if (! do_mmap)
        io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)++glob_pack_id;
    if (do_mmap)
        io_hdr.flags |= SG_FLAG_MMAP_IO;
    else if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;
    if (verbose > 2) {
        char b[128];

        pr2serr("    Write cdb: %s\n",
                sg_get_command_str(wrCmd, cdbsz, false, sizeof(b), b));
    }

#if 1
    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        sleep(1);
    if (res < 0) {
        perror(ME "SG_IO error (sg_write)");
        return -1;
    }
#else
    while (((res = write(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return -2;
        perror("writing (wr) on sg device, error");
        return -1;
    }

    while (((res = read(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    if (res < 0) {
        perror("writing (rd) on sg device, error");
        return -1;
    }
#endif
    if (verbose > 2)
        pr2serr("      duration=%u ms\n", io_hdr.duration);
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
    if (diop && *diop &&
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = false;      /* flag that dio not done (completely) */
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
        pr2serr("no flag found\n");
        return 1;
    }
    cp = buff;
    do {
        np = strchr(cp, ',');
        if (np)
            *np++ = '\0';
        if (0 == strcmp(cp, "append"))
            fp->append = true;
        else if (0 == strcmp(cp, "dio"))
            fp->dio = true;
        else if (0 == strcmp(cp, "direct"))
            fp->direct = true;
        else if (0 == strcmp(cp, "dpo"))
            fp->dpo = true;
        else if (0 == strcmp(cp, "dsync"))
            fp->dsync = true;
        else if (0 == strcmp(cp, "excl"))
            fp->excl = true;
        else if (0 == strcmp(cp, "fua"))
            fp->fua = true;
        else if (0 == strcmp(cp, "null"))
            ;
        else {
            pr2serr("unrecognised flag: %s\n", cp);
            return 1;
        }
        cp = np;
    } while (cp);
    return 0;
}

/* Returns the number of times 'ch' is found in string 's' given the
 * string's length. */
static int
num_chs_in_str(const char * s, int slen, int ch)
{
    int res = 0;

    while (--slen >= 0) {
        if (ch == s[slen])
            ++res;
    }
    return res;
}


#define STR_SZ 1024
#define INOUTF_SZ 512
#define EBUFF_SZ 768

int
main(int argc, char * argv[])
{
    bool bpt_given = false;
    bool cdbsz_given = false;
    bool do_coe = false;     /* dummy, just accept + ignore */
    bool do_sync = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, k, t, infd, outfd, blocks, n, flags, blocks_per, err, keylen;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    int ibs = 0;
    int in_res_sz = 0;
    int in_sect_sz;
    int in_type = FT_OTHER;
    int obs = 0;
    int out_res_sz = 0;
    int out_sect_sz;
    int out_type = FT_OTHER;
    int num_dio_not_done = 0;
    int ret = 0;
    int scsi_cdbsz_in = DEF_SCSI_CDBSZ;
    int scsi_cdbsz_out = DEF_SCSI_CDBSZ;
    size_t psz;
    int64_t in_num_sect = -1;
    int64_t out_num_sect = -1;
    int64_t skip = 0;
    int64_t seek = 0;
    char * buf;
    char * key;
    uint8_t * wrkPos;
    uint8_t * wrkBuff = NULL;
    uint8_t * wrkMmap = NULL;
    char inf[INOUTF_SZ];
    char str[STR_SZ];
    char outf[INOUTF_SZ];
    char ebuff[EBUFF_SZ];
    char b[80];
    struct flags_t in_flags;
    struct flags_t out_flags;

#if defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
    psz = sysconf(_SC_PAGESIZE); /* POSIX.1 (was getpagesize()) */
#else
    psz = 4096;     /* give up, pick likely figure */
#endif
    inf[0] = '\0';
    outf[0] = '\0';
    memset(&in_flags, 0, sizeof(in_flags));
    memset(&out_flags, 0, sizeof(out_flags));

    for (k = 1; k < argc; k++) {
        if (argv[k])
            snprintf(str, STR_SZ, "%s", argv[k]);
        else
            continue;
        for (key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        keylen = strlen(key);
        if (0 == strcmp(key,"bpt")) {
            bpt = sg_get_num(buf);
            if (-1 == bpt) {
                pr2serr(ME "bad argument to 'bpt'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            bpt_given = true;
        } else if (0 == strcmp(key,"bs")) {
            blk_sz = sg_get_num(buf);
            if (-1 == blk_sz) {
                pr2serr(ME "bad argument to 'bs'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"cdbsz")) {
            scsi_cdbsz_in = sg_get_num(buf);
            scsi_cdbsz_out = scsi_cdbsz_in;
            cdbsz_given = true;
        } else if (0 == strcmp(key,"coe")) {
            do_coe = !! sg_get_num(buf);   /* dummy, just accept + ignore */
            if (do_coe) { ; }   /* unused, dummy to suppress warning */
        } else if (0 == strcmp(key,"count")) {
            if (0 != strcmp("-1", buf)) {
                dd_count = sg_get_llnum(buf);
                if (-1LL == dd_count) {
                    pr2serr(ME "bad argument to 'count'\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            }   /* treat 'count=-1' as calculate count (same as not given) */
        } else if (0 == strcmp(key,"dio"))
            out_flags.dio = !! sg_get_num(buf);
        else if (0 == strcmp(key,"fua")) {
            n = sg_get_num(buf);
            if (n & 1)
                out_flags.fua = true;
            if (n & 2)
                in_flags.fua = true;
        } else if (0 == strcmp(key,"ibs")) {
            ibs = sg_get_num(buf);
            if (-1 == ibs) {
                pr2serr(ME "bad argument to 'ibs'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"if") == 0) {
            if ('\0' != inf[0]) {
                pr2serr("Second 'if=' argument??\n");
                return SG_LIB_CONTRADICT;
            } else {
                memcpy(inf, buf, INOUTF_SZ);
                inf[INOUTF_SZ - 1] = '\0';
            }
        } else if (0 == strcmp(key, "iflag")) {
            if (process_flags(buf, &in_flags)) {
                pr2serr(ME "bad argument to 'iflag'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"of") == 0) {
            if ('\0' != outf[0]) {
                pr2serr("Second 'of=' argument??\n");
                return SG_LIB_CONTRADICT;
            } else {
                memcpy(outf, buf, INOUTF_SZ);
                outf[INOUTF_SZ - 1] = '\0';
            }
        } else if (0 == strcmp(key, "oflag")) {
            if (process_flags(buf, &out_flags)) {
                pr2serr(ME "bad argument to 'oflag'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"obs")) {
            obs = sg_get_num(buf);
            if (-1 == obs) {
                pr2serr(ME "bad argument to 'obs'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"seek")) {
            seek = sg_get_llnum(buf);
            if (-1LL == seek) {
                pr2serr(ME "bad argument to 'seek'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"skip")) {
            skip = sg_get_llnum(buf);
            if (-1LL == skip) {
                pr2serr(ME "bad argument to 'skip'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"sync"))
            do_sync = !! sg_get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = sg_get_num(buf);
        else if (0 == strncmp(key, "verb", 4))
            verbose = sg_get_num(buf);
        else if ((keylen > 1) && ('-' == key[0]) && ('-' != key[1])) {
            res = 0;
            n = num_chs_in_str(key + 1, keylen - 1, 'd');
            dry_run += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'h');
            if (n > 0) {
                usage();
                return 0;
            }
            n = num_chs_in_str(key + 1, keylen - 1, 'v');
            verbose += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'V');
            if (n > 0)
                version_given = true;
            res += n;
            if (res < (keylen - 1)) {
                pr2serr("Unrecognised short option in '%s', try '--help'\n",
                        key);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if ((0 == strncmp(key, "--dry-run", 9)) ||
                 (0 == strncmp(key, "--dry_run", 9)))
            ++dry_run;
        else if ((0 == strncmp(key, "--help", 6)) ||
                 (0 == strcmp(key, "-?"))) {
            usage();
            return 0;
        } else if (0 == strncmp(key, "--verb", 6))
            ++verbose;
        else if (0 == strncmp(key, "--vers", 6))
            version_given = true;
        else {
            pr2serr("Unrecognized option '%s'\n", key);
            pr2serr("For more information use '--help'\n");
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
        pr2serr(ME ": %s\n", version_str);
        return 0;
    }

    if (blk_sz <= 0) {
        blk_sz = DEF_BLOCK_SIZE;
        pr2serr("Assume default 'bs' ((logical) block size) of %d bytes\n",
                blk_sz);
    }
    if ((ibs && (ibs != blk_sz)) || (obs && (obs != blk_sz))) {
        pr2serr("If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return SG_LIB_CONTRADICT;
    }
    if ((skip < 0) || (seek < 0)) {
        pr2serr("skip and seek cannot be negative\n");
        return SG_LIB_CONTRADICT;
    }
    if (out_flags.append && (seek > 0)) {
        pr2serr("Can't use both append and seek switches\n");
        return SG_LIB_CONTRADICT;
    }
    if (bpt < 1) {
        pr2serr("bpt must be greater than 0\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    /* defaulting transfer size to 128*2048 for CD/DVDs is too large
       for the block layer in lk 2.6 and results in an EIO on the
       SG_IO ioctl. So reduce it in that case. */
    if ((blk_sz >= 2048) && (! bpt_given))
        bpt = DEF_BLOCKS_PER_2048TRANSFER;

#ifdef DEBUG
    pr2serr(ME "if=%s skip=%" PRId64 " of=%s seek=%" PRId64 " count=%" PRId64
            "\n", inf, skip, outf, seek, dd_count);
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
            pr2serr(" >> Input file type: %s\n",
                    dd_filetype_str(in_type, ebuff));

        if (FT_ERROR == in_type) {
            pr2serr(ME "unable to access %s\n", inf);
            return SG_LIB_FILE_ERROR;
        } else if (FT_ST == in_type) {
            pr2serr(ME "unable to use scsi tape device %s\n", inf);
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
                err = errno;
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for sg reading", inf);
                perror(ebuff);
                return sg_convert_errno(err);
            }
            res = ioctl(infd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30122)) {
                pr2serr(ME "sg driver prior to 3.1.22\n");
                return SG_LIB_FILE_ERROR;
            }
            in_res_sz = blk_sz * bpt;
            if (0 != (in_res_sz % psz)) /* round up to next page */
                in_res_sz = ((in_res_sz / psz) + 1) * psz;
            if (ioctl(infd, SG_GET_RESERVED_SIZE, &t) < 0) {
                err = errno;
                perror(ME "SG_GET_RESERVED_SIZE error");
                return sg_convert_errno(err);
            }
            if (t < MIN_RESERVED_SIZE)
                t = MIN_RESERVED_SIZE;
            if (in_res_sz > t) {
                if (ioctl(infd, SG_SET_RESERVED_SIZE, &in_res_sz) < 0) {
                    err = errno;
                    perror(ME "SG_SET_RESERVED_SIZE error");
                    return sg_convert_errno(err);
                }
            }
            wrkMmap = (uint8_t *)mmap(NULL, in_res_sz,
                                 PROT_READ | PROT_WRITE, MAP_SHARED, infd, 0);
            if (MAP_FAILED == wrkMmap) {
                err = errno;
                snprintf(ebuff, EBUFF_SZ,
                         ME "error using mmap() on file: %s", inf);
                perror(ebuff);
                return sg_convert_errno(err);
            }
        } else {
            flags = O_RDONLY;
            if (in_flags.direct)
                flags |= O_DIRECT;
            if (in_flags.excl)
                flags |= O_EXCL;
            if (in_flags.dsync)
                flags |= O_SYNC;
            if ((infd = open(inf, flags)) < 0) {
                err = errno;
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", inf);
                perror(ebuff);
                return sg_convert_errno(err);
            }
            else if (skip > 0) {
                off64_t offset = skip;

                offset *= blk_sz;       /* could exceed 32 bits here! */
                if (lseek64(infd, offset, SEEK_SET) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, ME "couldn't skip to "
                             "required position on %s", inf);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
                if (verbose)
                    pr2serr("  >> skip: lseek64 SEEK_SET, byte offset=0x%"
                            PRIx64 "\n", (uint64_t)offset);
            }
        }
    }

    if (outf[0] && ('-' != outf[0])) {
        out_type = dd_filetype(outf);
        if (verbose)
            pr2serr(" >> Output file type: %s\n",
                    dd_filetype_str(out_type, ebuff));

        if (FT_ST == out_type) {
            pr2serr(ME "unable to use scsi tape device %s\n", outf);
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
                err = errno;
                snprintf(ebuff, EBUFF_SZ, ME "could not open %s for "
                         "sg writing", outf);
                perror(ebuff);
                return sg_convert_errno(err);
            }
            res = ioctl(outfd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30122)) {
                pr2serr(ME "sg driver prior to 3.1.22\n");
                return SG_LIB_FILE_ERROR;
            }
            if (ioctl(outfd, SG_GET_RESERVED_SIZE, &t) < 0) {
                err = errno;
                perror(ME "SG_GET_RESERVED_SIZE error");
                return sg_convert_errno(err);
            }
           if (t < MIN_RESERVED_SIZE)
                t = MIN_RESERVED_SIZE;
            out_res_sz = blk_sz * bpt;
            if (out_res_sz > t) {
                if (ioctl(outfd, SG_SET_RESERVED_SIZE, &out_res_sz) < 0) {
                    err = errno;
                    perror(ME "SG_SET_RESERVED_SIZE error");
                    return sg_convert_errno(err);
                }
            }
            if (NULL == wrkMmap) {
                wrkMmap = (uint8_t *)mmap(NULL, out_res_sz,
                                PROT_READ | PROT_WRITE, MAP_SHARED, outfd, 0);
                if (MAP_FAILED == wrkMmap) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ,
                             ME "error using mmap() on file: %s", outf);
                    perror(ebuff);
                    return sg_convert_errno(err);
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
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for writing", outf);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
            }
            else {
                if ((outfd = open(outf, O_WRONLY)) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, ME "could not open %s "
                             "for raw writing", outf);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
            }
            if (seek > 0) {
                off64_t offset = seek;

                offset *= blk_sz;       /* could exceed 32 bits here! */
                if (lseek64(outfd, offset, SEEK_SET) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, ME "couldn't seek to "
                             "required position on %s", outf);
                    perror(ebuff);
                    return sg_convert_errno(err);
                }
                if (verbose)
                    pr2serr("   >> seek: lseek64 SEEK_SET, byte offset=0x%"
                            PRIx64 "\n", (uint64_t)offset);
            }
        }
    }
    if ((STDIN_FILENO == infd) && (STDOUT_FILENO == outfd)) {
        pr2serr("Won't default both IFILE to stdin _and_ OFILE to as "
                "stdout\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_CONTRADICT;
    }
    if (dd_count < 0) {
        in_num_sect = -1;
        if (FT_SG == in_type) {
            res = scsi_read_capacity(infd, &in_num_sect, &in_sect_sz);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                pr2serr("Unit attention(in), continuing\n");
                res = scsi_read_capacity(infd, &in_num_sect, &in_sect_sz);
            } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
                pr2serr("Aborted command(in), continuing\n");
                res = scsi_read_capacity(infd, &in_num_sect, &in_sect_sz);
            }
            if (0 != res) {
                sg_get_category_sense_str(res, sizeof(b), b, verbose);
                pr2serr("Read capacity (if=%s): %s\n", inf, b);
                in_num_sect = -1;
            }
        } else if (FT_BLOCK == in_type) {
            if (0 != read_blkdev_capacity(infd, &in_num_sect, &in_sect_sz)) {
                pr2serr("Unable to read block capacity on %s\n", inf);
                in_num_sect = -1;
            }
            if (blk_sz != in_sect_sz) {
                pr2serr("logical block size on %s confusion; bs=%d, from "
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
                pr2serr("Unit attention(out), continuing\n");
                res = scsi_read_capacity(outfd, &out_num_sect, &out_sect_sz);
            } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
                pr2serr("Aborted command(out), continuing\n");
                res = scsi_read_capacity(outfd, &out_num_sect, &out_sect_sz);
            }
            if (0 != res) {
                sg_get_category_sense_str(res, sizeof(b), b, verbose);
                pr2serr("Read capacity (of=%s): %s\n", inf, b);
                out_num_sect = -1;
            }
        } else if (FT_BLOCK == out_type) {
            if (0 != read_blkdev_capacity(outfd, &out_num_sect,
                                          &out_sect_sz)) {
                pr2serr("Unable to read block capacity on %s\n", outf);
                out_num_sect = -1;
            }
            if (blk_sz != out_sect_sz) {
                pr2serr("logical block size on %s confusion: bs=%d, from "
                        "device=%d\n", outf, blk_sz, out_sect_sz);
                out_num_sect = -1;
            }
        }
        if (out_num_sect > seek)
            out_num_sect -= seek;
#ifdef DEBUG
        pr2serr("Start of loop, count=%" PRId64 ", in_num_sect=%" PRId64 ", "
                "out_num_sect=%" PRId64 "\n", dd_count, in_num_sect,
                out_num_sect);
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
        pr2serr("Couldn't calculate count, please give one\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (! cdbsz_given) {
        if ((FT_SG == in_type) && (MAX_SCSI_CDBSZ != scsi_cdbsz_in) &&
            (((dd_count + skip) > UINT_MAX) || (bpt > USHRT_MAX))) {
            pr2serr("Note: SCSI command size increased to 16 bytes (for "
                    "'if')\n");
            scsi_cdbsz_in = MAX_SCSI_CDBSZ;
        }
        if ((FT_SG == out_type) && (MAX_SCSI_CDBSZ != scsi_cdbsz_out) &&
            (((dd_count + seek) > UINT_MAX) || (bpt > USHRT_MAX))) {
            pr2serr("Note: SCSI command size increased to 16 bytes (for "
                    "'of')\n");
            scsi_cdbsz_out = MAX_SCSI_CDBSZ;
        }
    }

    if (out_flags.dio && (FT_SG != in_type)) {
        out_flags.dio = false;
        pr2serr(">>> dio only performed on 'of' side when 'if' is an sg "
                "device\n");
    }
    if (out_flags.dio) {
        int fd;
        char c;

        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    pr2serr(">>> %s set to '0' but should be set to '1' for "
                            "direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    }

    if (wrkMmap) {
        wrkPos = wrkMmap;
    } else {
        wrkPos = (uint8_t *)sg_memalign(blk_sz * bpt, 0, &wrkBuff,
                                        verbose > 3);
        if (NULL == wrkPos) {
            pr2serr("Not enough user memory\n");
            return sg_convert_errno(ENOMEM);
        }
    }

    blocks_per = bpt;
#ifdef DEBUG
    pr2serr("Start of loop, count=%" PRId64 ", blocks_per=%d\n", dd_count,
            blocks_per);
#endif
    if (dry_run > 0)
        goto fini;

    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
        start_tm_valid = true;
    }
    req_count = dd_count;

    if (verbose && (dd_count > 0) && (! out_flags.dio) &&
        (FT_SG == in_type) && (FT_SG == out_type))
        pr2serr("Since both 'if' and 'of' are sg devices, only do mmap-ed "
                "transfers on 'if'\n");

    while (dd_count > 0) {
        blocks = (dd_count > blocks_per) ? blocks_per : dd_count;
        if (FT_SG == in_type) {
            ret = sg_read(infd, wrkPos, blocks, skip, blk_sz, scsi_cdbsz_in,
                          in_flags.fua, in_flags.dpo, true);
            if ((SG_LIB_CAT_UNIT_ATTENTION == ret) ||
                (SG_LIB_CAT_ABORTED_COMMAND == ret)) {
                pr2serr("Unit attention or aborted command, continuing "
                        "(r)\n");
                ret = sg_read(infd, wrkPos, blocks, skip, blk_sz,
                              scsi_cdbsz_in, in_flags.fua, in_flags.dpo,
                              true);
            }
            if (0 != ret) {
                pr2serr("sg_read failed, skip=%" PRId64 "\n", skip);
                break;
            }
            else
                in_full += blocks;
        }
        else {
            while (((res = read(infd, wrkPos, blocks * blk_sz)) < 0) &&
                   ((EINTR == errno) || (EAGAIN == errno) ||
                    (EBUSY == errno)))
                ;
            if (verbose > 2)
                pr2serr("read(unix): count=%d, res=%d\n", blocks * blk_sz,
                        res);
            if (ret < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "reading, skip=%" PRId64 " ",
                         skip);
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
            bool dio_res = out_flags.dio;
            bool do_mmap = (FT_SG != in_type);

            ret = sg_write(outfd, wrkPos, blocks, seek, blk_sz, scsi_cdbsz_out,
                           out_flags.fua, out_flags.dpo, do_mmap, &dio_res);
            if ((SG_LIB_CAT_UNIT_ATTENTION == ret) ||
                (SG_LIB_CAT_ABORTED_COMMAND == ret)) {
                pr2serr("Unit attention or aborted command, continuing (w)\n");
                dio_res = out_flags.dio;
                ret = sg_write(outfd, wrkPos, blocks, seek, blk_sz,
                               scsi_cdbsz_out, out_flags.fua, out_flags.dpo,
                               do_mmap, &dio_res);
            }
            if (0 != ret) {
                pr2serr("sg_write failed, seek=%" PRId64 "\n", seek);
                break;
            }
            else {
                out_full += blocks;
                if (out_flags.dio && (! dio_res))
                    num_dio_not_done++;
            }
        }
        else if (FT_DEV_NULL == out_type)
            out_full += blocks; /* act as if written out without error */
        else {
            while (((res = write(outfd, wrkPos, blocks * blk_sz)) < 0) &&
                   ((EINTR == errno) || (EAGAIN == errno) ||
                    (EBUSY == errno)))
                ;
            if (verbose > 2)
                pr2serr("write(unix): count=%d, res=%d\n", blocks * blk_sz,
                        res);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "writing, seek=%" PRId64 " ",
                         seek);
                perror(ebuff);
                break;
            }
            else if (res < blocks * blk_sz) {
                pr2serr("output file probably full, seek=%" PRId64 " ", seek);
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
        calc_duration_throughput(false);
    if (do_sync) {
        if (FT_SG == out_type) {
            pr2serr(">> Synchronizing cache on %s\n", outf);
            res = sg_ll_sync_cache_10(outfd, 0, 0, 0, 0, 0, false, 0);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                pr2serr("Unit attention(out), continuing\n");
                res = sg_ll_sync_cache_10(outfd, 0, 0, 0, 0, 0, false, 0);
            }
            if (0 != res) {
                sg_get_category_sense_str(res, sizeof(b), b, verbose);
                pr2serr("Synchronize cache(out): %s\n", b);
            }
        }
    }

fini:
    if (wrkBuff)
        free(wrkBuff);
    if (STDIN_FILENO != infd)
        close(infd);
    if ((STDOUT_FILENO != outfd) && (FT_DEV_NULL != out_type))
        close(outfd);
    if ((0 != dd_count) && (0 == dry_run)) {
        pr2serr("Some error occurred,");
        if (0 == ret)
            ret = SG_LIB_CAT_OTHER;
    }
    print_stats();
    if (sum_of_resids)
        pr2serr(">> Non-zero sum of residual counts=%d\n", sum_of_resids);
    if (num_dio_not_done)
        pr2serr(">> dio requested but _not_ done %d times\n",
                num_dio_not_done);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
