/*
 *  A utility program for the Linux OS SCSI generic ("sg") device driver.
 *    Copyright (C) 2001 - 2019 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later

   This program reads data from the given SCSI device (typically a disk
   or cdrom) and discards that data. Its primary goal is to time
   multiple reads all starting from the same logical address. Its interface
   is a subset of another member of this package: sg_dd which is a
   "dd" variant. The input file can be a scsi generic device, a block device,
   or a seekable file. Streams such as stdin are not acceptable. The block
   size ('bs') is assumed to be 512 if not given.

   This version should compile with Linux sg drivers with version numbers
   >= 30000 . For mmap-ed IO the sg version number >= 30122 .

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
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#ifndef major
#include <sys/types.h>
#endif
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/major.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"


static const char * version_str = "1.36 20191220";

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define ME "sg_read: "

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 40000       /* 40,000 millisecs == 40 seconds */

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikey value */
#endif

#define FT_OTHER 1              /* filetype other than sg and ... */
#define FT_SG 2                 /* filetype is sg char device */
#define FT_RAW 4                /* filetype is raw char device */
#define FT_BLOCK 8              /* filetype is block device */
#define FT_ERROR 64             /* couldn't "stat" file */

#define MIN_RESERVED_SIZE 8192

static int sum_of_resids = 0;

static int64_t dd_count = -1;
static int64_t orig_count = 0;
static int64_t in_full = 0;
static int in_partial = 0;

static int pack_id_count = 0;
static int verbose = 0;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";


static void
install_handler (int sig_num, void (*sig_handler) (int sig))
{
    struct sigaction sigact;

    sigaction (sig_num, NULL, &sigact);
    if (sigact.sa_handler != SIG_IGN) {
        sigact.sa_handler = sig_handler;
        sigemptyset (&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction (sig_num, &sigact, NULL);
    }
}

static void
print_stats(int iters, const char * str)
{
    if (orig_count > 0) {
        if (0 != dd_count)
            pr2serr("  remaining block count=%" PRId64 "\n", dd_count);
        pr2serr("%" PRId64 "+%d records in", in_full - in_partial,
                in_partial);
        if (iters > 0)
            pr2serr(", %s commands issued: %d\n", (str ? str : ""), iters);
        else
            pr2serr("\n");
    } else if (iters > 0)
        pr2serr("%s commands issued: %d\n", (str ? str : ""), iters);
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
    print_stats(0, NULL);
    kill (getpid (), sig);
}

static void
siginfo_handler(int sig)
{
    if (sig) { ; }      /* unused, dummy to suppress warning */
    pr2serr("Progress report, continuing ...\n");
    print_stats(0, NULL);
}

static int
dd_filetype(const char * filename)
{
    struct stat st;

    if (stat(filename, &st) < 0)
        return FT_ERROR;
    if (S_ISCHR(st.st_mode)) {
        if (RAW_MAJOR == major(st.st_rdev))
            return FT_RAW;
        else if (SCSI_GENERIC_MAJOR == major(st.st_rdev))
            return FT_SG;
    } else if (S_ISBLK(st.st_mode))
        return FT_BLOCK;
    return FT_OTHER;
}

static void
usage()
{
    pr2serr("Usage: sg_read  [blk_sgio=0|1] [bpt=BPT] [bs=BS] "
            "[cdbsz=6|10|12|16]\n"
            "                count=COUNT [dio=0|1] [dpo=0|1] [fua=0|1] "
            "if=IFILE\n"
            "                [mmap=0|1] [no_dfxer=0|1] [odir=0|1] "
            "[skip=SKIP]\n"
            "                [time=TI] [verbose=VERB] [--help] "
            "[--verbose]\n"
            "                [--version] "
            "  where:\n"
            "    blk_sgio 0->normal IO for block devices, 1->SCSI commands "
            "via SG_IO\n"
            "    bpt      is blocks_per_transfer (default is 128, or 64 KiB "
            "for default BS)\n"
            "             setting 'bpt=0' will do COUNT zero block SCSI "
            "READs\n"
            "    bs       must match sector size if IFILE accessed via SCSI "
            "commands\n"
            "             (def=512)\n"
            "    cdbsz    size of SCSI READ command (default is 10)\n"
            "    count    total bytes read will be BS*COUNT (if no "
            "error)\n"
            "             (if negative, do |COUNT| zero block SCSI READs)\n"
            "    dio      1-> attempt direct IO on sg device, 0->indirect IO "
            "(def)\n");
    pr2serr("    dpo      1-> set disable page out (DPO) in SCSI READs\n"
            "    fua      1-> set force unit access (FUA) in SCSI READs\n"
            "    if       an sg, block or raw device, or a seekable file (not "
            "stdin)\n"
            "    mmap     1->perform mmaped IO on sg device, 0->indirect IO "
            "(def)\n"
            "    no_dxfer 1->DMA to kernel buffers only, not user space, "
            "0->normal(def)\n"
            "    odir     1->open block device O_DIRECT, 0->don't (def)\n"
            "    skip     each transfer starts at this logical address "
            "(def=0)\n"
            "    time     0->do nothing(def), 1->time from 1st cmd, 2->time "
            "from 2nd, ...\n"
            "    verbose  increase level of verbosity (def: 0)\n"
            "    --help|-h    print this usage message then exit\n"
            "    --verbose|-v   increase level of verbosity (def: 0)\n"
            "    --version|-V   print version number then exit\n\n"
            "Issue SCSI READ commands, each starting from the same logical "
            "block address\n");
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
        sg_put_unaligned_be64(start_block, cdbp + 2);
        sg_put_unaligned_be32((uint32_t)blocks, cdbp + 10);
        break;
    default:
        pr2serr(ME "expected cdb size of 6, 10, 12, or 16 but got %d\n",
                cdb_sz);
        return 1;
    }
    return 0;
}

/* -3 medium/hardware error, -2 -> not ready, 0 -> successful,
   1 -> recoverable (ENOMEM), 2 -> try again (e.g. unit attention),
   3 -> try again (e.g. aborted command), -1 -> other unrecoverable error */
static int
sg_bread(int sg_fd, uint8_t * buff, int blocks, int64_t from_block, int bs,
         int cdbsz, bool fua, bool dpo, bool * diop, bool do_mmap,
         bool no_dxfer)
{
    uint8_t rdCmd[MAX_SCSI_CDBSZ];
    uint8_t senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (sg_build_scsi_cdb(rdCmd, cdbsz, blocks, from_block, false, fua,
                          dpo)) {
        pr2serr(ME "bad cdb build, from_block=%" PRId64 ", blocks=%d\n",
                from_block, blocks);
        return -1;
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = rdCmd;
    if (blocks > 0) {
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = bs * blocks;
        /* next: shows dxferp unused during mmap-ed IO */
        if (! do_mmap)
            io_hdr.dxferp = buff;
        if (diop && *diop)
            io_hdr.flags |= SG_FLAG_DIRECT_IO;
        else if (do_mmap)
            io_hdr.flags |= SG_FLAG_MMAP_IO;
        else if (no_dxfer)
            io_hdr.flags |= SG_FLAG_NO_DXFER;
    } else
        io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = pack_id_count++;
    if (verbose > 1) {
        char b[128];

        pr2serr("    READ cdb: %s\n",
                sg_get_command_str(rdCmd, cdbsz, false, sizeof(b), b));
    }

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("reading (SG_IO) on sg device, error");
        return -1;
    }

    if (verbose > 2)
        pr2serr( "      duration=%u ms\n", io_hdr.duration);
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        if (verbose > 1)
                sg_chk_n_print3("reading, continue", &io_hdr, true);
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:
        if (verbose)
            sg_chk_n_print3("reading", &io_hdr, (verbose > 1));
        return 2;
    case SG_LIB_CAT_ABORTED_COMMAND:
        if (verbose)
            sg_chk_n_print3("reading", &io_hdr, (verbose > 1));
        return 3;
    case SG_LIB_CAT_NOT_READY:
        if (verbose)
            sg_chk_n_print3("reading", &io_hdr, (verbose > 1));
        return -2;
    case SG_LIB_CAT_MEDIUM_HARD:
        if (verbose)
            sg_chk_n_print3("reading", &io_hdr, (verbose > 1));
        return -3;
    default:
        sg_chk_n_print3("reading", &io_hdr, !! verbose);
        return -1;
    }
    if (blocks > 0) {
        if (diop && *diop &&
            ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
            *diop = 0;      /* flag that dio not done (completely) */
        sum_of_resids += io_hdr.resid;
    }
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
#define INF_SZ 512
#define EBUFF_SZ 768


int
main(int argc, char * argv[])
{
    bool count_given = false;
    bool dio_tmp;
    bool do_blk_sgio = false;
    bool do_dio = false;
    bool do_mmap = false;
    bool do_odir = false;
    bool dpo = false;
    bool fua = false;
    bool no_dxfer = false;
    bool verbose_given = false;
    bool version_given = false;
    int bs = 0;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    int dio_incomplete = 0;
    int do_time = 0;
    int in_type = FT_OTHER;
    int ret = 0;
    int scsi_cdbsz = DEF_SCSI_CDBSZ;
    int res, k, t, buf_sz, iters, infd, blocks, flags, blocks_per, err;
    int n, keylen;
    size_t psz;
    int64_t skip = 0;
    char * key;
    char * buf;
    uint8_t * wrkBuff = NULL;
    uint8_t * wrkPos = NULL;
    char inf[INF_SZ];
    char outf[INF_SZ];
    char str[STR_SZ];
    char ebuff[EBUFF_SZ];
    const char * read_str;
    struct timeval start_tm, end_tm;

#if defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
    psz = sysconf(_SC_PAGESIZE); /* POSIX.1 (was getpagesize()) */
#else
    psz = 4096;     /* give up, pick likely figure */
#endif
    inf[0] = '\0';

    for (k = 1; k < argc; k++) {
        if (argv[k]) {
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
        } else
            continue;
        for (key = str, buf = key; (*buf && (*buf != '=')); )
            buf++;
        if (*buf)
            *buf++ = '\0';
        keylen = strlen(key);
        if (0 == strcmp(key,"blk_sgio"))
            do_blk_sgio = !! sg_get_num(buf);
        else if (0 == strcmp(key,"bpt")) {
            bpt = sg_get_num(buf);
            if (-1 == bpt) {
                pr2serr( ME "bad argument to 'bpt'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"bs")) {
            bs = sg_get_num(buf);
            if (-1 == bs) {
                pr2serr( ME "bad argument to 'bs'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"cdbsz"))
            scsi_cdbsz = sg_get_num(buf);
        else if (0 == strcmp(key,"count")) {
            count_given = true;
            if ('-' == *buf) {
                dd_count = sg_get_llnum(buf + 1);
                if (-1 == dd_count) {
                    pr2serr( ME "bad argument to 'count'\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                dd_count = - dd_count;
            } else {
                dd_count = sg_get_llnum(buf);
                if (-1 == dd_count) {
                    pr2serr( ME "bad argument to 'count'\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
        } else if (0 == strcmp(key,"dio"))
            do_dio = !! sg_get_num(buf);
        else if (0 == strcmp(key,"dpo"))
            dpo = !! sg_get_num(buf);
        else if (0 == strcmp(key,"fua"))
            fua = !! sg_get_num(buf);
        else if (strcmp(key,"if") == 0) {
            memcpy(inf, buf, INF_SZ - 1);
            inf[INF_SZ - 1] = '\0';
        } else if (0 == strcmp(key,"mmap"))
            do_mmap = !! sg_get_num(buf);
        else if (0 == strcmp(key,"no_dxfer"))
            no_dxfer = !! sg_get_num(buf);
        else if (0 == strcmp(key,"odir"))
            do_odir = !! sg_get_num(buf);
        else if (strcmp(key,"of") == 0) {
            memcpy(outf, buf, INF_SZ - 1);
            outf[INF_SZ - 1] = '\0';
        } else if (0 == strcmp(key,"skip")) {
            skip = sg_get_llnum(buf);
            if (-1 == skip) {
                pr2serr( ME "bad argument to 'skip'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"time"))
            do_time = sg_get_num(buf);
        else if (0 == strncmp(key, "verb", 4)) {
            verbose_given = true;
            verbose = sg_get_num(buf);
        } else if (0 == strncmp(key, "--help", 6)) {
            usage();
            return 0;
        } else if (0 == strncmp(key, "--verb", 6)) {
            verbose_given = true;
            ++verbose;
        } else if (0 == strncmp(key, "--vers", 6))
            version_given = true;
        else if ((keylen > 1) && ('-' == key[0]) && ('-' != key[1])) {
            res = 0;
            n = num_chs_in_str(key + 1, keylen - 1, 'h');
            if (n > 0) {
                usage();
                return 0;
            }
            n = num_chs_in_str(key + 1, keylen - 1, 'v');
            if (n > 0)
                verbose_given = true;
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
        } else {
            pr2serr( "Unrecognized argument '%s'\n", key);
            usage();
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
        pr2serr( ME ": %s\n", version_str);
        return 0;
    }

    if (bs <= 0) {
        bs = DEF_BLOCK_SIZE;
        if ((dd_count > 0) && (bpt > 0))
            pr2serr( "Assume default 'bs' (block size) of %d bytes\n", bs);
    }
    if (! count_given) {
        pr2serr("'count' must be given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (skip < 0) {
        pr2serr("skip cannot be negative\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (bpt < 1) {
        if (0 == bpt) {
            if (dd_count > 0)
                dd_count = - dd_count;
        } else {
            pr2serr("bpt must be greater than 0\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (do_dio && do_mmap) {
        pr2serr("cannot select both dio and mmap\n");
        return SG_LIB_CONTRADICT;
    }
    if (no_dxfer && (do_dio || do_mmap)) {
        pr2serr("cannot select no_dxfer with dio or mmap\n");
        return SG_LIB_CONTRADICT;
    }

    install_handler (SIGINT, interrupt_handler);
    install_handler (SIGQUIT, interrupt_handler);
    install_handler (SIGPIPE, interrupt_handler);
    install_handler (SIGUSR1, siginfo_handler);

    if (! inf[0]) {
        pr2serr("must provide 'if=<filename>'\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (0 == strcmp("-", inf)) {
        pr2serr("'-' (stdin) invalid as <filename>\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    in_type = dd_filetype(inf);
    if (FT_ERROR == in_type) {
        pr2serr("Unable to access: %s\n", inf);
        return SG_LIB_FILE_ERROR;
    } else if ((FT_BLOCK & in_type) && do_blk_sgio)
        in_type |= FT_SG;

    if (FT_SG & in_type) {
        if ((dd_count < 0) && (6 == scsi_cdbsz)) {
            pr2serr(ME "SCSI READ (6) can't do zero block reads\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        flags = O_RDWR;
        if (do_odir)
            flags |= O_DIRECT;
        if ((infd = open(inf, flags)) < 0) {
            flags = O_RDONLY;
            if (do_odir)
                flags |= O_DIRECT;
            if ((infd = open(inf, flags)) < 0) {
                err = errno;
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for sg reading", inf);
                perror(ebuff);
                return sg_convert_errno(err);
            }
        }
        if (verbose)
            pr2serr("Opened %s for SG_IO with flags=0x%x\n", inf, flags);
        if ((dd_count > 0) && (! (FT_BLOCK & in_type))) {
            if (verbose > 2) {
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &t) >= 0)
                    pr2serr("  SG_GET_RESERVED_SIZE yields: %d\n", t);
            }
            t = bs * bpt;
            if ((do_mmap) && (0 != (t % psz)))
                t = ((t / psz) + 1) * psz;    /* round up to next pagesize */
            res = ioctl(infd, SG_SET_RESERVED_SIZE, &t);
            if (res < 0)
                perror(ME "SG_SET_RESERVED_SIZE error");
            res = ioctl(infd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30000)) {
                pr2serr(ME "sg driver prior to 3.x.y\n");
                return SG_LIB_CAT_OTHER;
            }
            if (do_mmap && (t < 30122)) {
                pr2serr(ME "mmap-ed IO needs a sg driver version >= 3.1.22\n");
                return SG_LIB_CAT_OTHER;
            }
        }
    } else {
        if (do_mmap) {
            pr2serr(ME "mmap-ed IO only support on sg devices\n");
            return SG_LIB_CAT_OTHER;
        }
        if (dd_count < 0) {
            pr2serr(ME "negative 'count' only supported with SCSI READs\n");
            return SG_LIB_CAT_OTHER;
        }
        flags = O_RDONLY;
        if (do_odir)
            flags |= O_DIRECT;
        if ((infd = open(inf, flags)) < 0) {
            err = errno;
            snprintf(ebuff,  EBUFF_SZ,
                     ME "could not open %s for reading", inf);
            perror(ebuff);
            return sg_convert_errno(err);
        }
        if (verbose)
            pr2serr("Opened %s for Unix reads with flags=0x%x\n", inf, flags);
        if (skip > 0) {
            off64_t offset = skip;

            offset *= bs;       /* could exceed 32 bits here! */
            if (lseek64(infd, offset, SEEK_SET) < 0) {
                err = errno;
                snprintf(ebuff,  EBUFF_SZ,
                    ME "couldn't skip to required position on %s", inf);
                perror(ebuff);
                return sg_convert_errno(err);
            }
        }
    }

    if (0 == dd_count)
        return 0;
    orig_count = dd_count;

    if (dd_count > 0) {
        if (do_dio || do_odir || (FT_RAW & in_type)) {
            wrkBuff = (uint8_t *)malloc(bs * bpt + psz);
            if (0 == wrkBuff) {
                pr2serr("Not enough user memory for aligned storage\n");
                return SG_LIB_CAT_OTHER;
            }
            /* perhaps use posix_memalign() instead */
            wrkPos = (uint8_t *)(((sg_uintptr_t)wrkBuff + psz - 1) &
                                       (~(psz - 1)));
        } else if (do_mmap) {
            wrkPos = (uint8_t *)mmap(NULL, bs * bpt,
                        PROT_READ | PROT_WRITE, MAP_SHARED, infd, 0);
            if (MAP_FAILED == wrkPos) {
                perror(ME "error from mmap()");
                return SG_LIB_CAT_OTHER;
            }
        } else {
            wrkBuff = (uint8_t *)malloc(bs * bpt);
            if (0 == wrkBuff) {
                pr2serr("Not enough user memory\n");
                return SG_LIB_CAT_OTHER;
            }
            wrkPos = wrkBuff;
        }
    }

    blocks_per = bpt;
    start_tm.tv_sec = 0;   /* just in case start set condition not met */
    start_tm.tv_usec = 0;

    if (verbose && (dd_count < 0))
        pr2serr("About to issue %" PRId64 " zero block SCSI READs\n",
                0 - dd_count);

    /* main loop */
    for (iters = 0; dd_count != 0; ++iters) {
        if ((do_time > 0) && (iters == (do_time - 1)))
            gettimeofday(&start_tm, NULL);
        if (dd_count < 0)
            blocks = 0;
        else
            blocks = (dd_count > blocks_per) ? blocks_per : dd_count;
        if (FT_SG & in_type) {
            dio_tmp = do_dio;
            res = sg_bread(infd, wrkPos, blocks, skip, bs, scsi_cdbsz,
                           fua, dpo, &dio_tmp, do_mmap, no_dxfer);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                if (buf_sz < MIN_RESERVED_SIZE)
                    buf_sz = MIN_RESERVED_SIZE;
                blocks_per = (buf_sz + bs - 1) / bs;
                blocks = blocks_per;
                pr2serr("Reducing read to %d blocks per loop\n", blocks_per);
                res = sg_bread(infd, wrkPos, blocks, skip, bs, scsi_cdbsz,
                               fua, dpo, &dio_tmp, do_mmap, no_dxfer);
            } else if (2 == res) {
                pr2serr("Unit attention, try again (r)\n");
                res = sg_bread(infd, wrkPos, blocks, skip, bs, scsi_cdbsz,
                               fua, dpo, &dio_tmp, do_mmap, no_dxfer);
            }
            if (0 != res) {
                switch (res) {
                case -3:
                    ret = SG_LIB_CAT_MEDIUM_HARD;
                    pr2serr(ME "SCSI READ medium/hardware error\n");
                    break;
                case -2:
                    ret = SG_LIB_CAT_NOT_READY;
                    pr2serr(ME "device not ready\n");
                    break;
                case 2:
                    ret = SG_LIB_CAT_UNIT_ATTENTION;
                    pr2serr(ME "SCSI READ unit attention\n");
                    break;
                case 3:
                    ret = SG_LIB_CAT_ABORTED_COMMAND;
                    pr2serr(ME "SCSI READ aborted command\n");
                    break;
                default:
                    ret = SG_LIB_CAT_OTHER;
                    pr2serr(ME "SCSI READ failed\n");
                    break;
                }
                break;
            } else {
                in_full += blocks;
                if (do_dio && (0 == dio_tmp))
                    dio_incomplete++;
            }
        } else {
            if (iters > 0) { /* subsequent iteration reset skip position */
                off64_t offset = skip;

                offset *= bs;       /* could exceed 32 bits here! */
                if (lseek64(infd, offset, SEEK_SET) < 0) {
                    perror(ME "could not reset skip position");
                    break;
                }
            }
            while (((res = read(infd, wrkPos, blocks * bs)) < 0) &&
                   (EINTR == errno))
                ;
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "reading, skip=%" PRId64 " ",
                         skip);
                perror(ebuff);
                break;
            } else if (res < blocks * bs) {
                pr2serr(ME "short read: wanted/got=%d/%d bytes, stop\n",
                        blocks * bs, res);
                blocks = res / bs;
                if ((res % bs) > 0) {
                    blocks++;
                    in_partial++;
                }
                dd_count -= blocks;
                in_full += blocks;
                break;
            }
            in_full += blocks;
        }
        if (dd_count > 0)
            dd_count -= blocks;
        else if (dd_count < 0)
            ++dd_count;
    }
    read_str = (FT_SG & in_type) ? "SCSI READ" : "read";
    if (do_time > 0) {
        gettimeofday(&end_tm, NULL);
        if (start_tm.tv_sec || start_tm.tv_usec) {
            struct timeval res_tm;
            double a, b, c;

            res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
            res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
            if (res_tm.tv_usec < 0) {
                --res_tm.tv_sec;
                res_tm.tv_usec += 1000000;
            }
            a = res_tm.tv_sec;
            a += (0.000001 * res_tm.tv_usec);
            if (orig_count > 0) {
                b = (double)bs * (orig_count - dd_count);
                if (do_time > 1)
                    c = b - ((double)bs * ((do_time - 1.0) * bpt));
                else
                    c = 0.0;
            } else {
                b = 0.0;
                c = 0.0;
            }

            if (1 == do_time) {
                pr2serr("Time for all %s commands was %d.%06d secs", read_str,
                        (int)res_tm.tv_sec, (int)res_tm.tv_usec);
                if ((orig_count > 0) && (a > 0.00001) && (b > 511))
                    pr2serr(", %.2f MB/sec\n", b / (a * 1000000.0));
                else
                    pr2serr("\n");
            } else if (2 == do_time) {
                pr2serr("Time from second %s command to end was %d.%06d secs",
                        read_str, (int)res_tm.tv_sec,
                        (int)res_tm.tv_usec);
                if ((orig_count > 0) && (a > 0.00001) && (c > 511))
                    pr2serr(", %.2f MB/sec\n", c / (a * 1000000.0));
                else
                    pr2serr("\n");
            } else {
                pr2serr("Time from start of %s command "
                        "#%d to end was %d.%06d secs", read_str, do_time,
                        (int)res_tm.tv_sec, (int)res_tm.tv_usec);
                if ((orig_count > 0) && (a > 0.00001) && (c > 511))
                    pr2serr(", %.2f MB/sec\n", c / (a * 1000000.0));
                else
                    pr2serr("\n");
            }
            if ((iters > 0) && (a > 0.00001))
                pr2serr("Average number of %s commands per second was %.2f\n",
                        read_str, (double)iters / a);
        }
    }

    if (wrkBuff)
        free(wrkBuff);

    close(infd);
    if (0 != dd_count) {
        pr2serr("Some error occurred,");
        if (0 == ret)
            ret = SG_LIB_CAT_OTHER;
    }
    print_stats(iters, read_str);

    if (dio_incomplete) {
        int fd;
        char c;

        pr2serr(">> Direct IO requested but incomplete %d times\n",
                dio_incomplete);
        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    pr2serr(">>> %s set to '0' but should be set to '1' for "
                            "direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    }
    if (sum_of_resids)
        pr2serr(">> Non-zero sum of residual counts=%d\n", sum_of_resids);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
