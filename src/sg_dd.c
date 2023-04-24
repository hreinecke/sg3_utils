/* A utility program for copying files. Specialised for "files" that
 * represent devices that understand the SCSI command set.
 *
 * Copyright (C) 1999 - 2023 D. Gilbert and P. Allworth
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is a specialisation of the Unix "dd" command in which
 * either the input or the output file is a scsi generic device, raw
 * device, a block device or a normal file. The logical block size ('bs')
 * is assumed to be 512 if not given. This program complains if 'ibs' or
 * 'obs' are given with a value that differs from 'bs' (or the default 512).
 * If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
 * not given or 'of=-' then stdout assumed.
 *
 * A non-standard argument "bpt" (blocks per transfer) is added to control
 * the maximum number of blocks in each transfer. The default value is 128.
 * For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16 KiB
 * in this case) is transferred to or from the sg device in a single SCSI
 * command. The actual size of the SCSI READ or WRITE command block can be
 * selected with the "cdbsz" argument.
 *
 * This version is designed for the Linux kernel 2, 3, 4 and 5 series.
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
#include <time.h>               /* for clock_gettime() */
#include <limits.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#ifndef major
#include <sys/types.h>
#endif
#include <linux/major.h>        /* for MEM_MAJOR, SCSI_GENERIC_MAJOR, etc */
#include <linux/fs.h>           /* for BLKSSZGET and friends */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_GETRANDOM
#include <sys/random.h>         /* for getrandom() system call */
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"
#include "sg_pt.h"              /* used to get to SNTL for NVMe devices */

static const char * version_str = "6.43 20230421";

static const char * my_name = "sg_dd: ";

/* Uncomment next line to turn on compiled debug */
/* #define DEBUG 1 */

#ifndef BLOCK_EXT_MAJOR
#define BLOCK_EXT_MAJOR 259     /* used by NVMe block devices */
#endif

#define STR_SZ 1024
#define INOUTF_SZ 512
#define EBUFF_SZ 768

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_BLOCKS_PER_2048TRANSFER 32
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16
#define MAX_BPT_VALUE (1 << 24)         /* used for maximum bs as well */
#define MAX_COUNT_SKIP_SEEK (1LL << 48) /* coverity wants upper bound */

#define DEF_MODE_CDB_SZ 10
#define DEF_MODE_RESP_LEN 252
#define RW_ERR_RECOVERY_MP 1
#define CACHING_MP 8
#define CONTROL_MP 0xa

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32
#define READ_LONG_OPCODE 0x3E
#define READ_LONG_CMD_LEN 10
#define READ_LONG_DEF_BLK_INC 8
#define VERIFY10 0x2f
#define VERIFY12 0xaf
#define VERIFY16 0x8f

#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikely value */
#endif

#define SG_LIB_FLOCK_ERR 90

/* found in flags_t::file_type, several may be OR-ed together */
#define FT_INIT 0               /* filetype not examined yet */
#define FT_OTHER 1              /* filetype is probably normal */
#define FT_SG 2                 /* filetype is sg char device or supports
                                   SG_IO ioctl */
#define FT_RAW 4                /* filetype is raw char device */
#define FT_DEV_NULL 8           /* either "/dev/null" or "." as filename */
#define FT_ST 16                /* filetype is st char device (tape) */
#define FT_BLOCK 32             /* filetype is block device */
#define FT_FIFO 64              /* filetype is a fifo (name pipe) */
#define FT_NVME 128             /* NVMe char(-generic)/block device */
#define FT_RANDOM_0_FF 256      /* iflag=00, iflag=ff and iflag=random
                                   overriding if=IFILE */
#define FT_ERROR 512           /* couldn't "stat" file */

#define DEV_NULL_MINOR_NUM 3

#define SG_DD_BYPASS 999        /* failed but coe set */

/* If platform does not support O_DIRECT then define it harmlessly */
#ifndef O_DIRECT
#define O_DIRECT 0
#endif

#define MIN_RESERVED_SIZE 8192

#define MAX_UNIT_ATTENTIONS 10
#define MAX_ABORTED_CMDS 256

#define PROGRESS_TRIGGER_MS 120000      /* milliseconds: 2 minutes */
#define PROGRESS2_TRIGGER_MS 60000      /* milliseconds: 1 minute */
#define PROGRESS3_TRIGGER_MS 30000      /* milliseconds: 30 seconds */

// static int sum_of_resids = 0;

// static int64_t dd_count = -1;   /* number of block given to count=COUNT */
static int64_t in_full = 0;     /* count so far of full blocks read */
static int in_partial = 0;      /* count so far of partial blocks read */
static int64_t out_full = 0;    /* count so far of full blocks written */
static int out_partial = 0;     /* count so far of partial blocks written */
static int64_t out_sparse_num = 0;
static int recovered_errs = 0;
static int unrecovered_errs = 0;
static int miscompare_errs = 0;
static int read_longs = 0;
static int num_retries = 0;

static bool start_tm_valid = false;
static int max_uas = MAX_UNIT_ATTENTIONS;
static int max_aborted = MAX_ABORTED_CMDS;
static uint32_t glob_pack_id = 0;       /* pre-increment */
static struct timeval start_tm;

static uint8_t * zeros_buff = NULL;
static uint8_t * free_zeros_buff = NULL;
static int read_long_blk_inc = READ_LONG_DEF_BLK_INC;

static long seed;
#ifdef HAVE_SRAND48_R   /* gcc extension. N.B. non-reentrant version slower */
static struct drand48_data drand;/* opaque, used by srand48_r and mrand48_r */
#endif

static const char * sg_allow_dio = "/sys/module/sg/parameters/allow_dio";

struct flags_t {
    bool append;
    bool dio;
    bool direct;
    bool dpo;
    bool dsync;
    bool excl;
    bool flock;
    bool ff;
    bool fua;
    bool nocreat;
    bool random;
    bool sgio;
    bool sparse;
    bool zero;
    int cdbsz;
    int cdl;
    int coe;
    int nocache;
    int pdt;
    int retries;
    int file_type;  /* not user input; from file/device examination: FT_* */
};

struct opts_t
{
    bool bpt_given;
    bool cdbsz_given;
    bool cdl_given;
    bool do_sync;
    bool do_time;
    bool do_verify;          /* when false: do copy (which is default) */
    bool verbose_given;
    bool version_given;
    int infd;
    int cmd_timeout;            /* in milliseconds */
    int coe_limit;
    int coe_count;
    int64_t skip;
    int64_t dd_count;           /* main copy block counter */
    struct flags_t iflag;
    int outfd;
    int64_t seek;
    struct flags_t oflag;
    int out2fd;
    int out2_type;
    int blk_sz;                 /* _logical_ block size (e.g. 512 or 4096) */
    int bpt;
    int dio_incomplete_count;
    int sum_of_resids;
    int progress;       /* --progress or -p, checked in sig_listen_thread */
    int verbose;
    int dry_run;
    struct sg_pt_base *in_ptp;    /* these two pointers only used if NVMe */
    struct sg_pt_base *out_ptp;   /* ... devices are detected */
    char in_fname[INOUTF_SZ];
    char out_fname[INOUTF_SZ];
    char out2_fname[INOUTF_SZ];
};

struct opts_t * fscope_op;      /* file scope pointer to opts_t instance */

static void calc_duration_throughput(bool contin);


static void
install_handler(int sig_num, void (*sig_handler)(int sig))
{
    struct sigaction sigact;

    sigaction(sig_num, NULL, &sigact);
    if (sigact.sa_handler != SIG_IGN) {
        sigact.sa_handler = sig_handler;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction(sig_num, &sigact, NULL);
    }
}


static void
print_stats(const char * str)
{
    if (0 != fscope_op->dd_count)
        pr2serr("  remaining block count=%" PRId64 "\n", fscope_op->dd_count);
    pr2serr("%s%" PRId64 "+%d records in\n", str, in_full - in_partial,
            in_partial);
    pr2serr("%s%" PRId64 "+%d records %s\n", str, out_full - out_partial,
            out_partial, (fscope_op->do_verify ? "verified" : "out"));
    if (fscope_op->oflag.sparse)
        pr2serr("%s%" PRId64 " bypassed records out\n", str, out_sparse_num);
    if (recovered_errs > 0)
        pr2serr("%s%d recovered errors\n", str, recovered_errs);
    if (num_retries > 0)
        pr2serr("%s%d retries attempted\n", str, num_retries);
    if (unrecovered_errs > 0) {
        pr2serr("%s%d unrecovered error(s)\n", str, unrecovered_errs);
        if (fscope_op->iflag.coe || fscope_op->oflag.coe)
            pr2serr("%s%d read_longs fetched part of unrecovered read "
                    "errors\n", str, read_longs);
    }
    if (miscompare_errs > 0)
        pr2serr("%s%d miscompare error(s)\n", str, miscompare_errs);
}


static void
interrupt_handler(int sig)
{
    struct sigaction sigact;

    sigact.sa_handler = SIG_DFL;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(sig, &sigact, NULL);
    pr2serr("Interrupted by signal,");
    if (fscope_op->do_time)
        calc_duration_throughput(false);
    print_stats("");
    kill(getpid (), sig);
}


static void
siginfo_handler(int sig)
{
    if (sig) { ; }      /* unused, dummy to suppress warning */
    pr2serr("Progress report, continuing ...\n");
    if (fscope_op->do_time)
        calc_duration_throughput(true);
    print_stats("  ");
}

static const char * proc_devices_s = "/proc/devices";
static const char * pdevs_ch_s = "Character";

static bool bsg_nvme_majors_checked = false;

static int bsg_major = 0;
static int nvme_major = 0;
static int nvme_gen_major = 0;

static void
find_bsg_nvme_majors(const struct opts_t * op)
{
    int n;
    int num_found = 0;
    char *cp;
    FILE *fp;
    char a[128];
    char b[128];
    static const int blen = sizeof(b);

    if (NULL == (fp = fopen(proc_devices_s, "r"))) {
        if (op->verbose)
            pr2serr("fopen %s failed: %s\n", proc_devices_s, strerror(errno));
        return;
    }
    while ((cp = fgets(b, blen, fp))) {
        if ((1 == sscanf(b, "%126s", a)) &&
            (0 == memcmp(a, pdevs_ch_s, 9)))
            break;
    }
    while (cp && (cp = fgets(b, blen, fp))) {
        if (2 == sscanf(b, "%d %126s", &n, a)) {
            if (0 == strcmp("bsg", a)) {
                bsg_major = n;
                if (++num_found > 2)
                    break;
            } else if (0 == memcmp("nvme", a, 4)) {
                if (0 == strcmp("nvme-generic", a)) {
                    nvme_gen_major = n;
                    if (++num_found > 2)
                        break;
                } else {
                    nvme_major = n;
                    if (++num_found > 2)
                        break;
                }
            }
        } else
            break;
    }
    if (op->verbose > 5) {
        if (cp) {
            if (bsg_major > 0)
                pr2serr("found bsg_major=%d\n", bsg_major);
            if (nvme_major > 0)
                pr2serr("found nvme_major=%d\n", nvme_major);
            if (nvme_gen_major > 0)
                pr2serr("found nvme_gen_major=%d\n", nvme_gen_major);
        } else
            pr2serr("found no nvme char device in %s\n", proc_devices_s);
    }
    fclose(fp);
}


static int
dd_filetype(const char * filename, const struct opts_t * op)
{
    size_t len = strlen(filename);
    struct stat st;

    if ((1 == len) && ('.' == filename[0]))
        return FT_DEV_NULL;
    if (stat(filename, &st) < 0)
        return FT_ERROR;
    if (S_ISCHR(st.st_mode)) {
        /* major() and minor() defined in sys/sysmacros.h */
        if ((MEM_MAJOR == major(st.st_rdev)) &&
            (DEV_NULL_MINOR_NUM == minor(st.st_rdev)))
            return FT_DEV_NULL;
        if (RAW_MAJOR == major(st.st_rdev))
            return FT_RAW;
        if (SCSI_GENERIC_MAJOR == major(st.st_rdev))
            return FT_SG;
        if (SCSI_TAPE_MAJOR == major(st.st_rdev))
            return FT_ST;
        if (! bsg_nvme_majors_checked) {
            bsg_nvme_majors_checked = true;
            find_bsg_nvme_majors(op);
        }
        if (bsg_major == (int)major(st.st_rdev))
            return FT_SG;
        if (nvme_major == (int)major(st.st_rdev))       /* e.g. /dev/nvme0 */
            return FT_SG | FT_NVME;     /* treat as sg device */
        if (nvme_gen_major == (int)major(st.st_rdev))   /* e.g. /dev/ng0n1 */
            return FT_SG | FT_NVME;     /* treat as sg device */
    } else if (S_ISBLK(st.st_mode)) {
        if (BLOCK_EXT_MAJOR)
            return FT_BLOCK | FT_NVME;
        else
            return FT_BLOCK;
    } else if (S_ISFIFO(st.st_mode))
        return FT_FIFO;
    return FT_OTHER;
}


static char *
dd_filetype_str(int ft, char * b, bool sgio_pt)
{
    int off = 0;
    static const char * abpt_s = "accessed via pass-through";
    static const int blen = 64;

    if (FT_DEV_NULL & ft)
        off += sg_scnpr(b + off, blen - off, "null device");
    if (FT_NVME & ft) {
        if (FT_BLOCK & ft) {
            off += sg_scnpr(b + off, blen - off, "NVMe block device");
            if (sgio_pt)
                off += sg_scnpr(b + off, blen - off, ", %s", abpt_s);
        } else
            off += sg_scnpr(b + off, blen - off, "NVMe char device, %s",
                            abpt_s);
    } else if (FT_SG & ft)
        off += sg_scnpr(b + off, blen - off, "SCSI generic (sg) device, %s",
                        abpt_s);
    else if (FT_BLOCK & ft) {
        off += sg_scnpr(b + off, blen - off, "block device");
        if (sgio_pt)
            off += sg_scnpr(b + off, blen - off, ", %s", abpt_s);
    }
    if (FT_FIFO & ft)
        off += sg_scnpr(b + off, blen - off, "fifo (named pipe)");
    if (FT_ST & ft)
        off += sg_scnpr(b + off, blen - off, "SCSI tape device");
    if (FT_RAW & ft)
        off += sg_scnpr(b + off, blen - off, "raw device");
    if (FT_OTHER & ft)
        off += sg_scnpr(b + off, blen - off, "other (perhaps ordinary file)");
    if (FT_ERROR & ft)
        off += sg_scnpr(b + off, blen - off, "unable to 'stat' file");
    sg_scnpr(b + off, blen - off, " ");
    return b;
}


static void
usage()
{
    pr2serr("Usage: sg_dd  [bs=BS] [conv=CONV] [count=COUNT] [ibs=BS] "
            "[if=IFILE]\n"
            "              [iflag=FLAGS] [obs=BS] [of=OFILE] [oflag=FLAGS] "
            "[seek=SEEK]\n"
            "              [skip=SKIP] [--dry-run] [--help] [--verbose] "
            "[--version]\n\n"
            "              [blk_sgio=0|1] [bpt=BPT] [cdbsz=6|10|12|16] "
            "[cdl=CDL]\n"
            "              [coe=0|1|2|3] [coe_limit=CL] [dio=0|1] "
            "[odir=0|1]\n"
            "              [of2=OFILE2] [retries=RETR] [sync=0|1] "
            "[time=0|1[,TO]]\n"
            "              [verbose=VERB] [--compare] [--progress] "
            "[--verify]\n"
            "  where:\n"
            "    blk_sgio    0->block device use normal I/O(def), 1->use "
            "SG_IO\n"
            "    bpt         is blocks_per_transfer (default is 128 or 32 "
            "when BS>=2048)\n"
            "    bs          logical block size (default is 512)\n");
    pr2serr("    cdbsz       size of SCSI READ or WRITE cdb (default is "
            "10)\n"
            "    cdl         command duration limits value 0 to 7 (def: "
            "0 (no cdl))\n"
            "    coe         0->exit on error (def), 1->continue on sg "
            "error (zero\n"
            "                fill), 2->also try read_long on unrecovered "
            "reads,\n"
            "                3->and set the CORRCT bit on the read long\n"
            "    coe_limit   limit consecutive 'bad' blocks on reads to CL "
            "times\n"
            "                when COE>1 (default: 0 which is no limit)\n"
            "    conv        comma separated list from: [nocreat,noerror,"
            "notrunc,\n"
            "                null,sparse,sync]\n"
            "    count       number of blocks to copy (def: device size)\n"
            "    dio         for direct IO, 1->attempt, 0->indirect IO "
            "(def)\n"
            "    ibs         input logical block size (if given must be same "
            "as 'bs=')\n"
            "    if          file or device to read from (def: stdin)\n"
            "    iflag       comma separated list from: [00,coe,dio,direct,"
            "dpo,dsync,\n"
            "                excl,ff,flock,fua,nocache,null,pt,random,sgio]\n"
            "    obs         output logical block size (if given must be "
            "same as 'bs=')\n"
            "    odir        1->use O_DIRECT when opening block dev, "
            "0->don't(def)\n"
            "    of          file or device to write to (def: stdout), "
            "OFILE of '.'\n");
    pr2serr("                treated as /dev/null\n"
            "    of2         additional output file (def: /dev/null), "
            "OFILE2 should be\n"
            "                normal file or pipe\n"
            "    oflag       comma separated list from: [append,coe,dio,"
            "direct,dpo,\n"
            "                dsync,excl,flock,fua,nocache,nocreat,null,pt,"
            "sgio,sparse]\n"
            "    retries     retry sgio errors RETR times (def: 0)\n"
            "    seek        block position to start writing to OFILE\n"
            "    skip        block position to start reading from IFILE\n"
            "    sync        0->no sync(def), 1->SYNCHRONIZE CACHE on "
            "OFILE after copy\n"
            "    time        0->no timing(def), 1->time plus calculate "
            "throughput;\n"
            "                TO is command timeout in seconds (def: 60)\n"
            "    verbose     0->quiet(def), 1->some noise, 2->more noise, "
            "etc\n"
            "    --compare|-c    same as --verify, compare IFILE with "
            "OFILE\n"
            "    --dry-run|-d    do preparation but bypass copy (or read)\n"
            "    --help|-h    print out this usage message then exit\n"
            "    --progress|-p    print progress report every 2 minutes\n"
            "    --verbose|-v   same as 'verbose=1', can be used multiple "
            "times\n"
            "    --verify|-x    do verify/compare rather than copy "
            "(OFILE must\n"
            "                   be a sg device)\n"
            "    --version|-V    print version information then exit\n\n"
            "Copy from IFILE to OFILE, similar to dd command; specialized "
            "for SCSI\ndevices. If the --verify option is given then IFILE "
            "is read and that data\nis used to compare with OFILE using "
            "the VERIFY(n) SCSI command (with\nBYTCHK=1).\n");
}


/* Return of 0 -> success, see sg_ll_read_capacity*() otherwise */
static int
scsi_read_capacity(int sg_fd, int64_t * num_sect, int * sect_sz,
                   struct opts_t * op)
{
    int res, verb;
    unsigned int ui;
    uint8_t rcBuff[RCAP16_REPLY_LEN];

    verb = (op->verbose ? op->verbose - 1: 0);
    res = sg_ll_readcap_10(sg_fd, false, 0, rcBuff, READ_CAP_REPLY_LEN, true,
                           verb);
    if (0 != res)
        return res;

    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3])) {
        int64_t ls;

        res = sg_ll_readcap_16(sg_fd, false, 0, rcBuff, RCAP16_REPLY_LEN,
                               true, verb);
        if (0 != res)
            return res;
        ls = (int64_t)sg_get_unaligned_be64(rcBuff);
        *num_sect = ls + 1;
        *sect_sz = (int)sg_get_unaligned_be32(rcBuff + 8);
    } else {
        ui = sg_get_unaligned_be32(rcBuff);
        /* take care not to sign extend values > 0x7fffffff */
        *num_sect = (int64_t)ui + 1;
        *sect_sz = (int)sg_get_unaligned_be32(rcBuff + 4);
    }
    if (verb)
        pr2serr("      number of blocks=%" PRId64 " [0x%" PRIx64 "], "
                "logical block size=%d\n", *num_sect, *num_sect, *sect_sz);
    return 0;
}


/* Return of 0 -> success, -1 -> failure. BLKGETSIZE64, BLKGETSIZE and */
/* BLKSSZGET macros problematic (from <linux/fs.h> or <sys/mount.h>). */
static int
read_blkdev_capacity(int sg_fd, int64_t * num_sect, int * sect_sz,
                     struct opts_t * op)
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
        if (op->verbose)
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
        if (op->verbose)
            pr2serr("      [bgs] number of blocks=%" PRId64 " [0x%" PRIx64
                    "],  logical block size=%d\n", *num_sect, *num_sect,
                    *sect_sz);
 #endif
    }
    return 0;
#else
    if (op->verbose)
        pr2serr("      BLKSSZGET+BLKGETSIZE ioctl not available\n");
    *num_sect = 0;
    *sect_sz = 0;
    return -1;
#endif
}


static int
sg_build_scsi_cdb(uint8_t * cdbp, unsigned int blocks, int64_t start_block,
                  bool is_verify, bool write_true, struct opts_t * op)
{
    int sz_ind;
    const struct flags_t * flagp = write_true ? &op->oflag : &op->iflag;
    static const int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    static const int ve_opcode[] = {0xff /* no VERIFY(6) */, VERIFY10,
                                    VERIFY12, VERIFY16};
    static const int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};

    memset(cdbp, 0, flagp->cdbsz);
    if (is_verify)
        cdbp[1] = 0x2;  /* (BYTCHK=1) << 1 */
    else {
        if (flagp->dpo)
            cdbp[1] |= 0x10;
        if (flagp->fua)
            cdbp[1] |= 0x8;
    }
    switch (flagp->cdbsz) {
    case 6:
        sz_ind = 0;
        if (is_verify && write_true) {
            pr2serr("%sthere is no VERIFY(6), choose a larger cdbsz\n",
                     my_name);
            return 1;
        }
        cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                         rd_opcode[sz_ind]);
        sg_put_unaligned_be24(0x1fffff & start_block, cdbp + 1);
        cdbp[4] = (256 == blocks) ? 0 : (uint8_t)blocks;
        if (blocks > 256) {
            pr2serr("%sfor 6 byte commands, maximum number of blocks is "
                    "256\n", my_name);
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            pr2serr("%sfor 6 byte commands, can't address blocks beyond %d\n",
                    my_name, 0x1fffff);
            return 1;
        }
        if (flagp->dpo || flagp->fua) {
            pr2serr("%sfor 6 byte commands, neither dpo nor fua bits "
                    "supported\n", my_name);
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        if (is_verify && write_true)
            cdbp[0] = ve_opcode[sz_ind];
        else
            cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                             rd_opcode[sz_ind]);
        sg_put_unaligned_be32(start_block, cdbp + 2);
        sg_put_unaligned_be16(blocks, cdbp + 7);
        if (blocks & (~0xffff)) {
            pr2serr("%sfor 10 byte commands, maximum number of blocks "
                    "is %d\n", my_name, 0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        if (is_verify && write_true)
            cdbp[0] = ve_opcode[sz_ind];
        else
            cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                             rd_opcode[sz_ind]);
        sg_put_unaligned_be32(start_block, cdbp + 2);
        sg_put_unaligned_be32(blocks, cdbp + 6);
        break;
    case 16:
        sz_ind = 3;
        if (is_verify && write_true)
            cdbp[0] = ve_opcode[sz_ind];
        else
            cdbp[0] = (uint8_t)(write_true ? wr_opcode[sz_ind] :
                                             rd_opcode[sz_ind]);
        if ((! is_verify) && (flagp->cdl > 0)) {
            if (flagp->cdl & 0x4)
                cdbp[1] |= 0x1;
            if (flagp->cdl & 0x3)
                cdbp[14] |= ((flagp->cdl & 0x3) << 6);
        }
        sg_put_unaligned_be64(start_block, cdbp + 2);
        sg_put_unaligned_be32(blocks, cdbp + 10);
        break;
    default:
        pr2serr("%sexpected cdb size of 6, 10, 12, or 16 but got %d\n",
                my_name, flagp->cdbsz);
        return 1;
    }
    return 0;
}

static int
use_sntl(const uint8_t * scsiCdb, uint8_t * buff, int blocks,
         int64_t start_block, bool write_true, uint64_t * io_addrp,
         struct opts_t * op)
{
    int to, res, ret, vb, slen, sense_cat, info_valid;
    int sg_fd = write_true ? op->outfd : op->infd;
    struct sg_pt_base * ptvp = write_true ? op->out_ptp : op->in_ptp;
    struct flags_t * flagp = write_true ? &op->oflag : &op->iflag;
    const char * cmd_s = write_true ? "write" : "read";
    uint8_t sense_b[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;

    if (ptvp)
        clear_scsi_pt_obj(ptvp);
    else {
        ptvp = construct_scsi_pt_obj_with_fd(sg_fd, op->verbose);
        if (NULL == ptvp)
            return -ENOMEM;
        if (write_true)
            op->out_ptp = ptvp;
        else
            op->in_ptp = ptvp;
    }
    set_scsi_pt_cdb(ptvp, scsiCdb, flagp->cdbsz);
    if (write_true)
        set_scsi_pt_data_out(ptvp, buff, blocks * op->blk_sz);
    else
        set_scsi_pt_data_in(ptvp, buff, blocks * op->blk_sz);
    set_scsi_pt_sense(ptvp, sense_b, SENSE_BUFF_LEN);
    to = op->cmd_timeout / 1000;
    if (to < 1)
        to = 1;
    vb = ((op->verbose > 1) ? (op->verbose - 1) : op->verbose);
    while (((res = do_scsi_pt(ptvp, -1, to, vb)) < 0) &&
           ((-EINTR == res) || (-EAGAIN == res) || (-EBUSY == res))) {
        ;
    }
    ret = sg_cmds_process_resp(ptvp, cmd_s, res, false /* noisy */, vb,
                               &sense_cat);
    if (-1 == ret) {
        if (get_scsi_pt_transport_err(ptvp))
            ret = SG_LIB_TRANSPORT_ERROR;
        else
            ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    } else if (-2 == ret) {
        slen = get_scsi_pt_sense_len(ptvp);
        ret = sense_cat;

        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_RES_CONFLICT:
        case SG_LIB_CAT_DATA_PROTECT:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ++unrecovered_errs;
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            break;
        case SG_LIB_CAT_PROTECTION:
            /* no retry, might have INFO field */
            ++unrecovered_errs;
            info_valid = sg_get_sense_info_fld(sense_b, slen, io_addrp);
            if (info_valid)
                ret = SG_LIB_CAT_PROTECTION_WITH_INFO;
            break;
        case SG_LIB_CAT_RECOVERED:
            ++recovered_errs;
            info_valid = sg_get_sense_info_fld(sense_b, slen, io_addrp);
            if (info_valid)
                pr2serr("    lba of last recovered error in this READ=0x%"
                        PRIx64 "\n", *io_addrp);
            else
                pr2serr("Recovered error: [no info] reading from "
                        "block=0x%" PRIx64 ", num=%d\n", start_block, blocks);
            ret = 0;    /* quash error so copy will continue */
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            ++unrecovered_errs;
            info_valid = sg_get_sense_info_fld(sense_b, slen, io_addrp);
            /* MMC and MO devices don't necessarily set VALID bit */
            if (info_valid)
                ret = SG_LIB_CAT_MEDIUM_HARD_WITH_INFO;
            else
                pr2serr("Medium, hardware or blank check error but no lba "
                        "of failure in sense data\n");
            break;
        case SG_LIB_CAT_NO_SENSE:
        case SG_LIB_CAT_CONDITION_MET:
            ret = 0;
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            if (op->verbose > 0)
                sg_print_command_len(scsiCdb, flagp->cdbsz);
            break;
        case SG_LIB_LBA_OUT_OF_RANGE:
            break;
        default:
            break;
        }
    } else
        ret = 0;

    /* We are going to re-read those good blocks */
    if ((SG_LIB_CAT_MEDIUM_HARD_WITH_INFO != ret) &&
        (SG_LIB_CAT_PROTECTION_WITH_INFO != ret))
        op->sum_of_resids += get_scsi_pt_resid(ptvp);
    return ret;
}

/* Does SCSI READ on IFILE. Returns 0 -> successful,
 * SG_LIB_SYNTAX_ERROR -> unable to build cdb,
 * SG_LIB_CAT_UNIT_ATTENTION -> try again,
 * SG_LIB_CAT_MEDIUM_HARD_WITH_INFO -> 'io_addrp' written to,
 * SG_LIB_CAT_MEDIUM_HARD -> no info field,
 * SG_LIB_CAT_NOT_READY, SG_LIB_CAT_ABORTED_COMMAND,
 * -2 -> ENOMEM, -1 other errors */
static int
sg_read_low(uint8_t * buff, int blocks, int64_t from_block,
            bool * diop, uint64_t * io_addrp, struct opts_t * op)
{
    bool info_valid;
    bool print_cdb_after = false;
    int res, slen;
    const struct flags_t * ifp = &op->iflag;
    const uint8_t * sbp;
    uint8_t rdCmd[MAX_SCSI_CDBSZ];
    uint8_t senseBuff[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    struct sg_io_hdr io_hdr;

    if (sg_build_scsi_cdb(rdCmd, blocks, from_block, op->do_verify,
                          false, op)) {
        pr2serr("%sbad rd cdb build, from_block=%" PRId64 ", blocks=%d\n",
                my_name, from_block, blocks);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (FT_NVME & ifp->file_type)
        return use_sntl(rdCmd, buff, blocks, from_block, false, io_addrp, op);

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = ifp->cdbsz;
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = op->blk_sz * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = op->cmd_timeout;
    io_hdr.pack_id = (int)++glob_pack_id;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    if (op->verbose > 2)
        sg_print_command_len(rdCmd, ifp->cdbsz);

    while (((res = ioctl(op->infd, SG_IO, &io_hdr)) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return -2;
        perror("reading (SG_IO) on sg device, error");
        return -1;
    }
    if (op->verbose > 2)
        pr2serr("      duration=%u ms\n", io_hdr.duration);
    res = sg_err_category3(&io_hdr);
    sbp = io_hdr.sbp;
    slen = io_hdr.sb_len_wr;
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_CONDITION_MET:
        break;
    case SG_LIB_CAT_RECOVERED:
        ++recovered_errs;
        info_valid = sg_get_sense_info_fld(sbp, slen, io_addrp);
        if (info_valid) {
            pr2serr("    lba of last recovered error in this READ=0x%" PRIx64
                    "\n", *io_addrp);
            if (op->verbose > 1)
                sg_chk_n_print3("reading", &io_hdr, true);
        } else {
            pr2serr("Recovered error: [no info] reading from block=0x%" PRIx64
                    ", num=%d\n", from_block, blocks);
            sg_chk_n_print3("reading", &io_hdr, op->verbose > 1);
        }
        break;
    case SG_LIB_CAT_ABORTED_COMMAND:
    case SG_LIB_CAT_UNIT_ATTENTION:
        sg_chk_n_print3("reading", &io_hdr, op->verbose > 1);
        return res;
    case SG_LIB_CAT_MEDIUM_HARD:
        if (op->verbose > 1)
            sg_chk_n_print3("reading", &io_hdr, op->verbose > 1);
        ++unrecovered_errs;
        info_valid = sg_get_sense_info_fld(sbp, slen, io_addrp);
        /* MMC devices don't necessarily set VALID bit */
        if (info_valid || ((5 == ifp->pdt) && (*io_addrp > 0)))
            return SG_LIB_CAT_MEDIUM_HARD_WITH_INFO;
        else {
            pr2serr("Medium, hardware or blank check error but no lba of "
                    "failure in sense\n");
            return res;
        }
        break;
    case SG_LIB_CAT_NOT_READY:
        ++unrecovered_errs;
        if (op->verbose > 0)
            sg_chk_n_print3("reading", &io_hdr, op->verbose > 1);
        return res;
    case SG_LIB_CAT_ILLEGAL_REQ:
        if (5 == ifp->pdt) {    /* MMC READs can go down this path */
            bool ili;
            struct sg_scsi_sense_hdr ssh;

            if (op->verbose > 1)
                sg_chk_n_print3("reading", &io_hdr, op->verbose > 1);
            if (sg_scsi_normalize_sense(sbp, slen, &ssh) &&
                (0x64 == ssh.asc) && (0x0 == ssh.ascq)) {
                if (sg_get_sense_filemark_eom_ili(sbp, slen, NULL, NULL,
                                                  &ili) && ili) {
                    sg_get_sense_info_fld(sbp, slen, io_addrp);
                    if (*io_addrp > 0) {
                        ++unrecovered_errs;
                        return SG_LIB_CAT_MEDIUM_HARD_WITH_INFO;
                    } else
                        pr2serr("MMC READ gave 'illegal mode for this track' "
                                "and ILI but no LBA of failure\n");
                }
                ++unrecovered_errs;
                return SG_LIB_CAT_MEDIUM_HARD;
            }
        }
        if (op->verbose > 0)
            print_cdb_after = true;
#if defined(__GNUC__)
#if (__GNUC__ >= 7)
        __attribute__((fallthrough));
        /* FALL THROUGH */
#endif
#endif
    default:
        ++unrecovered_errs;
        if (op->verbose > 0)
            sg_chk_n_print3("reading", &io_hdr, op->verbose > 1);
        if (print_cdb_after)
            sg_print_command_len(rdCmd, ifp->cdbsz);
        return res;
    }
    if (diop && *diop &&
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = false;      /* flag that dio not done (completely) */
    op->sum_of_resids += io_hdr.resid;
    return 0;
}


/* Does repeats associated with a SCSI READ on IFILE. Returns 0 -> successful,
 * SG_LIB_SYNTAX_ERROR  -> unable to build cdb, SG_LIB_CAT_UNIT_ATTENTION ->
 * try again, SG_LIB_CAT_NOT_READY, SG_LIB_CAT_MEDIUM_HARD,
 * SG_LIB_CAT_ABORTED_COMMAND, -2 -> ENOMEM, -1 other errors */
static int
sg_read(uint8_t * buff, int blocks, int64_t from_block, bool * diop,
        int * blks_readp, struct opts_t * op)
{
    bool may_coe = false;
    bool repeat;
    int res, blks, xferred;
    int ret = 0;
    int bs = op->blk_sz;
    int retries_tmp;
    uint64_t io_addr;
    int64_t lba;
    struct flags_t * ifp = &op->iflag;
    uint8_t * bp;

    retries_tmp = ifp->retries;
    for (xferred = 0, blks = blocks, lba = from_block, bp = buff;
         blks > 0; blks = blocks - xferred) {
        io_addr = 0;
        repeat = false;
        may_coe = false;
        res = sg_read_low(bp, blks, lba, diop, &io_addr, op);
        switch (res) {
        case 0:
            if (blks_readp)
                *blks_readp = xferred + blks;
            if (op->coe_limit > 0)
                op->coe_count = 0;  /* good read clears coe_count */
            return 0;
        case -2:        /* ENOMEM */
            return res;
        case SG_LIB_CAT_NOT_READY:
            pr2serr("Device (r) not ready\n");
            return res;
        case SG_LIB_CAT_ABORTED_COMMAND:
            if (--max_aborted > 0) {
                pr2serr("Aborted command, continuing (r)\n");
                repeat = true;
            } else {
                pr2serr("Aborted command, too many (r)\n");
                return res;
            }
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            if (--max_uas > 0) {
                pr2serr("Unit attention, continuing (r)\n");
                repeat = true;
            } else {
                pr2serr("Unit attention, too many (r)\n");
                return res;
            }
            break;
        case SG_LIB_CAT_MEDIUM_HARD_WITH_INFO:
            if (retries_tmp > 0) {
                pr2serr(">>> retrying a sgio read, lba=0x%" PRIx64 "\n",
                        (uint64_t)lba);
                --retries_tmp;
                ++num_retries;
                if (unrecovered_errs > 0)
                    --unrecovered_errs;
                repeat = true;
            }
            ret = SG_LIB_CAT_MEDIUM_HARD;
            break; /* unrecovered read error at lba=io_addr */
        case SG_LIB_SYNTAX_ERROR:
            ifp->coe = 0;
            ret = res;
            goto err_out;
        case -1:
            ret = res;
            goto err_out;
        case SG_LIB_CAT_MEDIUM_HARD:
            may_coe = true;
#if defined(__GNUC__)
#if (__GNUC__ >= 7)
            __attribute__((fallthrough));
            /* FALL THROUGH */
#endif
#endif
        default:
            if (retries_tmp > 0) {
                pr2serr(">>> retrying a sgio read, lba=0x%" PRIx64 "\n",
                        (uint64_t)lba);
                --retries_tmp;
                ++num_retries;
                if (unrecovered_errs > 0)
                    --unrecovered_errs;
                repeat = true;
                break;
            }
            ret = res;
            goto err_out;
        }
        if (repeat)
            continue;
        if ((io_addr < (uint64_t)lba) ||
            (io_addr >= (uint64_t)(lba + blks))) {
                pr2serr("  Unrecovered error lba 0x%" PRIx64 " not in "
                        "correct range:\n\t[0x%" PRIx64 ",0x%" PRIx64 "]\n",
                        io_addr, (uint64_t)lba,
                        (uint64_t)(lba + blks - 1));
            may_coe = true;
            goto err_out;
        }
        blks = (int)(io_addr - (uint64_t)lba);
        if (blks > 0) {
            if (op->verbose)
                pr2serr("  partial read of %d blocks prior to medium error\n",
                        blks);
            res = sg_read_low(bp, blks, lba, diop, &io_addr, op);
            switch (res) {
            case 0:
                break;
            case -1:
                ifp->coe = 0;
                ret = res;
                goto err_out;
            case -2:
                pr2serr("ENOMEM again, unexpected (r)\n");
                return -1;
            case SG_LIB_CAT_NOT_READY:
                pr2serr("device (r) not ready\n");
                return res;
            case SG_LIB_CAT_UNIT_ATTENTION:
                pr2serr("Unit attention, unexpected (r)\n");
                return res;
            case SG_LIB_CAT_ABORTED_COMMAND:
                pr2serr("Aborted command, unexpected (r)\n");
                return res;
            case SG_LIB_CAT_MEDIUM_HARD_WITH_INFO:
            case SG_LIB_CAT_MEDIUM_HARD:
                ret = SG_LIB_CAT_MEDIUM_HARD;
                goto err_out;
            case SG_LIB_SYNTAX_ERROR:
            default:
                pr2serr(">> unexpected result=%d from sg_read_low() 2\n",
                        res);
                ret = res;
                goto err_out;
            }
        }
        xferred += blks;
        if (0 == ifp->coe) {
            /* give up at block before problem unless 'coe' */
            if (blks_readp)
                *blks_readp = xferred;
            return ret;
        }
        if (bs < 32) {
            pr2serr(">> bs=%d too small for read_long\n", bs);
            return -1;  /* nah, block size can't be that small */
        }
        bp += (blks * bs);
        lba += blks;
        if ((0 != ifp->pdt) || (ifp->coe < 2)) {
            pr2serr(">> unrecovered read error at blk=%" PRId64 ", pdt=%d, "
                    "use zeros\n", lba, ifp->pdt);
            memset(bp, 0, bs);
        } else if (io_addr < UINT_MAX) {
            bool corrct, ok;
            int offset, nl, r;
            uint8_t * buffp;
            uint8_t * free_buffp;

            buffp = sg_memalign(bs * 2, 0, &free_buffp, false);
            if (NULL == buffp) {
                pr2serr(">> heap problems\n");
                return -1;
            }
            corrct = (ifp->coe > 2);
            res = sg_ll_read_long10(op->infd, /* pblock */false, corrct, lba,
                                    buffp, bs + read_long_blk_inc, &offset,
                                    true, op->verbose);
            ok = false;
            switch (res) {
            case 0:
                ok = true;
                ++read_longs;
                break;
            case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:
                nl = bs + read_long_blk_inc - offset;
                if ((nl < 32) || (nl > (bs * 2))) {
                    pr2serr(">> read_long(10) len=%d unexpected\n", nl);
                    break;
                }
                /* remember for next read_long attempt, if required */
                read_long_blk_inc = nl - bs;

                if (op->verbose)
                    pr2serr("read_long(10): adjusted len=%d\n", nl);
                r = sg_ll_read_long10(op->infd, false, corrct, lba, buffp, nl,
                                      &offset, true, op->verbose);
                if (0 == r) {
                    ok = true;
                    ++read_longs;
                    break;
                } else
                    pr2serr(">> unexpected result=%d on second "
                            "read_long(10)\n", r);
                break;
            case SG_LIB_CAT_INVALID_OP:
                pr2serr(">> read_long(10); not supported\n");
                break;
            case SG_LIB_CAT_ILLEGAL_REQ:
                pr2serr(">> read_long(10): bad cdb field\n");
                break;
            case SG_LIB_CAT_NOT_READY:
                pr2serr(">> read_long(10): device not ready\n");
                break;
            case SG_LIB_CAT_UNIT_ATTENTION:
                pr2serr(">> read_long(10): unit attention\n");
                break;
            case SG_LIB_CAT_ABORTED_COMMAND:
                pr2serr(">> read_long(10): aborted command\n");
                break;
            default:
                pr2serr(">> read_long(10): problem (%d)\n", res);
                break;
            }
            if (ok)
                memcpy(bp, buffp, bs);
            else
                memset(bp, 0, bs);
            free(free_buffp);
        } else {
            pr2serr(">> read_long(10) cannot handle blk=%" PRId64 ", use "
                    "zeros\n", lba);
            memset(bp, 0, bs);
        }
        ++xferred;
        bp += bs;
        ++lba;
        if ((op->coe_limit > 0) && (++op->coe_count > op->coe_limit)) {
            if (blks_readp)
                *blks_readp = xferred + blks;
            pr2serr(">> coe_limit on consecutive reads exceeded\n");
            return SG_LIB_CAT_MEDIUM_HARD;
        }
    }
    if (blks_readp)
        *blks_readp = xferred;
    return 0;

err_out:
    if (ifp->coe) {
        memset(bp, 0, bs * blks);
        pr2serr(">> unable to read at blk=%" PRId64 " for %d bytes, use "
                "zeros\n", lba, bs * blks);
        if (blks > 1)
            pr2serr(">>   try reducing bpt to limit number of zeros written "
                    "near bad block(s)\n");
        /* fudge success */
        if (blks_readp)
            *blks_readp = xferred + blks;
        if ((op->coe_limit > 0) && (++op->coe_count > op->coe_limit)) {
            pr2serr(">> coe_limit on consecutive reads exceeded\n");
            return ret;
        }
        return may_coe ? 0 : ret;
    } else
        return ret;
}


/* Does a SCSI WRITE or VERIFY (if do_verify set) on OFILE. Returns:
 * 0 -> successful, SG_LIB_SYNTAX_ERROR -> unable to build cdb,
 * SG_LIB_CAT_NOT_READY, SG_LIB_CAT_UNIT_ATTENTION, SG_LIB_CAT_MEDIUM_HARD,
 * SG_LIB_CAT_ABORTED_COMMAND, -2 -> recoverable (ENOMEM),
 * -1 -> unrecoverable error + others. SG_DD_BYPASS -> failed but coe set. */
static int
sg_write(int sg_fd, uint8_t * buff, int blocks, int64_t to_block,
         bool * diop, struct opts_t * op)
{
    bool info_valid;
    int res;
    int bs = op->blk_sz;
    uint64_t io_addr = 0;
    const struct flags_t * ofp = &op->oflag;
    uint8_t wrCmd[MAX_SCSI_CDBSZ];
    uint8_t senseBuff[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    struct sg_io_hdr io_hdr;
    const char * op_str = op->do_verify ? "verifying" : "writing";

    if (sg_build_scsi_cdb(wrCmd, blocks, to_block, op->do_verify, true, op)) {
        pr2serr("%sbad wr cdb build, to_block=%" PRId64 ", blocks=%d\n",
                my_name, to_block, blocks);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (FT_NVME & ofp->file_type)
        return use_sntl(wrCmd, buff, blocks, to_block, true, &io_addr, op);

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = ofp->cdbsz;
    io_hdr.cmdp = wrCmd;
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = op->cmd_timeout;
    io_hdr.pack_id = (int)++glob_pack_id;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    if (op->verbose > 2)
        sg_print_command_len(wrCmd, ofp->cdbsz);

    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return -2;
#if 0
        if (op->do_verify)
            perror("verifying (SG_IO) on sg device, error");
        else
            perror("writing (SG_IO) on sg device, error");
#endif
        return -1;
    }

    if (op->verbose > 2)
        pr2serr("      duration=%u ms\n", io_hdr.duration);
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_CONDITION_MET:
        break;
    case SG_LIB_CAT_RECOVERED:
        ++recovered_errs;
        info_valid = sg_get_sense_info_fld(io_hdr.sbp, io_hdr.sb_len_wr,
                                           &io_addr);
        if (info_valid) {
            pr2serr("    lba of last recovered error in this WRITE=0x%" PRIx64
                    "\n", io_addr);
            if (op->verbose > 1)
                sg_chk_n_print3(op_str, &io_hdr, true);
        } else {
            pr2serr("Recovered error: [no info] %s to block=0x%" PRIx64
                    ", num=%d\n", op_str, to_block, blocks);
            sg_chk_n_print3(op_str, &io_hdr, op->verbose > 1);
        }
        break;
    case SG_LIB_CAT_ABORTED_COMMAND:
    case SG_LIB_CAT_UNIT_ATTENTION:
        sg_chk_n_print3(op_str, &io_hdr, op->verbose > 1);
        return res;
    case SG_LIB_CAT_MISCOMPARE: /* must be VERIFY cpommand */
        ++miscompare_errs;
        if (ofp->coe) {
            if (op->verbose > 1)
                pr2serr(">> bypass due to miscompare: out blk=%" PRId64
                        " for %d blocks\n", to_block, blocks);
            return SG_DD_BYPASS; /* fudge success */
        } else {
            pr2serr("VERIFY reports miscompare\n");
            return res;
        }
    case SG_LIB_CAT_NOT_READY:
        ++unrecovered_errs;
        pr2serr("device not ready (w)\n");
        return res;
    case SG_LIB_CAT_MEDIUM_HARD:
    default:
        sg_chk_n_print3(op_str, &io_hdr, op->verbose > 1);
        if ((SG_LIB_CAT_ILLEGAL_REQ == res) && op->verbose)
            sg_print_command_len(wrCmd, ofp->cdbsz);
        ++unrecovered_errs;
        if (ofp->coe) {
            if (op->verbose > 1)
                pr2serr(">> ignored errors for out blk=%" PRId64 " for %d "
                        "bytes\n", to_block, bs * blocks);
            return SG_DD_BYPASS; /* fudge success */
        } else
            return res;
    }
    if (diop && *diop &&
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = false;      /* flag that dio not done (completely) */
    return 0;
}

/* Note that duration measurements may be effected by "discontinuous jumps
 * in the system time". */
static void
calc_duration_throughput(bool contin)
{
    int elapsed_secs;
    int n = 0;
    int64_t blks;
    double a, b, r, da, db;
    struct opts_t * fop = fscope_op;
    char f[128];
    struct timeval end_tm, res_tm, delta_tm;
    static const int flen = sizeof(f);
    static bool prev_valid = false;
    static struct timeval prev_tm;
    static int64_t prev_blks;

    f[0] = '\0';
    if (start_tm_valid && (start_tm.tv_sec || start_tm.tv_usec)) {
        blks = (in_full > out_full) ? in_full : out_full;
        gettimeofday(&end_tm, NULL);
        res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
        if (res_tm.tv_usec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        elapsed_secs = res_tm.tv_sec;
        a = res_tm.tv_sec;
        a += (0.000001 * res_tm.tv_usec);
        if (prev_valid) {
            delta_tm.tv_sec = end_tm.tv_sec - prev_tm.tv_sec;
            delta_tm.tv_usec = end_tm.tv_usec - prev_tm.tv_usec;
            if (delta_tm.tv_usec < 0) {
                --delta_tm.tv_sec;
                delta_tm.tv_usec += 1000000;
            }
            da = delta_tm.tv_sec;
            da += (0.000001 * delta_tm.tv_usec);
        } else
            da = 0.0000001;

        b = (double)fop->blk_sz * blks;
#if 0
        n = sg_scnpr(f, flen, "time to %s data%s: %d.%06d secs",
                     (do_verify ? "verify" : "copy"),
                     (contin ? " so far" : ""),
                     (int)res_tm.tv_sec, (int)res_tm.tv_usec);
#endif
        r = 0.0;
        if ((a > 0.00001) && (b > 511)) {
            r = b / (a * 1000000.0);
            if (r < 1.0)
                n += sg_scnpr(f + n, flen - n, " at %.1f kB/sec", r * 1000);
            else
                n += sg_scnpr(f + n, flen - n, " at %.2f MB/sec", r);
        }
        if (prev_valid && (da > 0.00001)) {
            db = (double)fop->blk_sz * (blks - prev_blks);
            if (db > 511) {
                double dr = db / (da * 1000000.0);

                if (dr < 1.0)
                    sg_scnpr(f + n, flen - n, " (delta %.1f KB/sec)",
                             dr * 1000);
                else
                    sg_scnpr(f + n, flen - n, " (delta %.2f MB/sec)", dr);
            }
        }
        pr2serr("%s\n", f);
        if (contin && (r > 0.01) && (fop->dd_count > 100)) {
            int secs = (int)(((double)fop->blk_sz * fop->dd_count) /
                             (r * 1000000));
            int h, m;

            if (secs > 10) {
                n = sg_scnpr(f, flen, "%d%% complete, ",
                             (100 * elapsed_secs) / (secs + elapsed_secs));
                h = secs / 3600;
                secs = secs - (h * 3600);
                m = secs / 60;
                secs = secs - (m * 60);
                n += sg_scnpr(f + n, flen - n, "estimated time remaining: ");
                if (h > 0)
                    sg_scnpr(f + n, flen - n, "%d:%02d:%02d", h, m, secs);
                else
                    sg_scnpr(f + n, flen - n, "%d:%02d", m, secs);
                pr2serr("%s\n", f);
            }
        }
        prev_tm = end_tm;
        prev_blks = blks;
        if (! prev_valid)
            prev_valid = true;
    }
}

/* Process arguments given to 'iflag=" or 'oflag=" options. Returns 0
 * on success, 1 on error. */
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
        if (0 == strcmp(cp, "00"))
            fp->zero = true;
        else if (0 == strcmp(cp, "append"))
            fp->append = true;
        else if (0 == strcmp(cp, "coe"))
            ++fp->coe;
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
        else if (0 == strcmp(cp, "flock"))
            fp->flock = true;
        else if (0 == strcmp(cp, "ff"))
            fp->ff = true;
        else if (0 == strcmp(cp, "fua"))
            fp->fua = true;
        else if (0 == strcmp(cp, "nocache"))
            ++fp->nocache;
        else if (0 == strcmp(cp, "nocreat"))
            fp->nocreat = true;
        else if (0 == strcmp(cp, "null"))
            ;
        else if (0 == strcmp(cp, "pt"))
            fp->sgio = true;
        else if (0 == strcmp(cp, "random"))
            fp->random = true;
        else if (0 == strcmp(cp, "sgio"))
            fp->sgio = true;
        else if (0 == strcmp(cp, "sparse"))
            fp->sparse = true;
        else {
            pr2serr("unrecognised flag: %s\n", cp);
            return 1;
        }
        cp = np;
    } while (cp);
    return 0;
}

/* Process arguments given to 'conv=" option. Returns 0 on success,
 * 1 on error. */
static int
process_conv(const char * arg, struct flags_t * ifp, struct flags_t * ofp)
{
    char buff[256];
    char * cp;
    char * np;

    strncpy(buff, arg, sizeof(buff));
    buff[sizeof(buff) - 1] = '\0';
    if ('\0' == buff[0]) {
        pr2serr("no conversions found\n");
        return 1;
    }
    cp = buff;
    do {
        np = strchr(cp, ',');
        if (np)
            *np++ = '\0';
        if (0 == strcmp(cp, "nocreat"))
            ofp->nocreat = true;
        else if (0 == strcmp(cp, "noerror"))
            ++ifp->coe;         /* will still fail on write error */
        else if (0 == strcmp(cp, "notrunc"))
            ;         /* this is the default action of sg_dd so ignore */
        else if (0 == strcmp(cp, "null"))
            ;
        else if (0 == strcmp(cp, "sparse"))
            ofp->sparse = true;
        else if (0 == strcmp(cp, "sync"))
            ;   /* dd(susv4): pad errored block(s) with zeros but sg_dd does
                 * that by default. Typical dd use: 'conv=noerror,sync' */
        else {
            pr2serr("unrecognised flag: %s\n", cp);
            return 1;
        }
        cp = np;
    } while (cp);
    return 0;
}

/* Returns open input file descriptor (>= 0) or a negative value
 * (-SG_LIB_FILE_ERROR or -SG_LIB_CAT_OTHER) if error.
 */
static int
open_if(struct opts_t * op)
{
    int infd = -1;
    int flags, fl, t, res, ft;
    int vb = op->verbose;
    const char * inf = op->in_fname;
    struct flags_t * ifp = &op->iflag;
    char ebuff[EBUFF_SZ];
    struct sg_simple_inquiry_resp sir;

    ft = dd_filetype(inf, op);
    if (op->verbose)
        pr2serr(" >> Input file type: %s\n",
                dd_filetype_str(ft, ebuff, ifp->sgio));
    if (FT_ERROR & ft) {
        pr2serr("%sunable access %s\n", my_name, inf);
        goto file_err;
    } else if ((FT_BLOCK & ft) && ifp->sgio)
        ft |= FT_SG;    /* might also have FT_NVME set */
    ifp->file_type = ft;

    if (FT_ST & ft) {
        pr2serr("%sunable to use scsi tape device %s\n", my_name, inf);
        goto file_err;
    } else if (FT_SG & ft) {
        flags = O_NONBLOCK;
        if (ifp->direct)
            flags |= O_DIRECT;
        if (ifp->excl)
            flags |= O_EXCL;
        if (ifp->dsync)
            flags |= O_SYNC;
        fl = O_RDWR;
        if ((infd = open(inf, fl | flags)) < 0) {
            fl = O_RDONLY;
            if ((infd = open(inf, fl | flags)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         "%scould not open %s for sg reading", my_name, inf);
                perror(ebuff);
                goto file_err;
            }
        }
        if (vb)
            pr2serr("        open input(sg_io), flags=0x%x\n", fl | flags);
        if (sg_simple_inquiry(infd, &sir, false, (vb ? (vb - 1) : 0))) {
            pr2serr("INQUIRY failed on %s\n", inf);
            goto other_err;
        }
        ifp->pdt = sir.peripheral_type;
        if (vb)
            pr2serr("    %s: %.8s  %.16s  %.4s  [pdt=%d]\n", inf, sir.vendor,
                    sir.product, sir.revision, ifp->pdt);
        if (! ((FT_BLOCK & ft) || (FT_NVME & ft))) {
            t = op->blk_sz * op->bpt;
            res = ioctl(infd, SG_SET_RESERVED_SIZE, &t);
            if (res < 0) {
                snprintf(ebuff, sizeof(ebuff), "%sSG_SET_RESERVED_SIZE error",
                         my_name);
                perror(ebuff);
            }
            res = ioctl(infd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30000)) {
                if (FT_BLOCK & ifp->file_type)
                    pr2serr("%sSG_IO unsupported on this block device\n",
                            my_name);
                else
                    pr2serr("%s: sg driver prior to 3.x.y\n", my_name);
                goto file_err;
            }
        }
    } else {
        flags = O_RDONLY;
        if (ifp->direct)
            flags |= O_DIRECT;
        if (ifp->excl)
            flags |= O_EXCL;
        if (ifp->dsync)
            flags |= O_SYNC;
        infd = open(inf, flags);
        if (infd < 0) {
            snprintf(ebuff, EBUFF_SZ,
                     "%scould not open %s for reading", my_name, inf);
            perror(ebuff);
            goto file_err;
        } else {
            if (vb)
                pr2serr("        open input, flags=0x%x\n", flags);
            if (op->skip > 0) {
                off64_t offset = op->skip;

                offset *= op->blk_sz;   /* could exceed 32 bits here! */
                if (lseek64(infd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ, "%scouldn't skip to required "
                             "position on %s", my_name, inf);
                    perror(ebuff);
                    goto file_err;
                }
                if (vb)
                    pr2serr("  >> skip: lseek64 SEEK_SET, byte offset=0x%"
                            PRIx64 "\n", (uint64_t)offset);
            }
#ifdef HAVE_POSIX_FADVISE
            if (ifp->nocache) {
                int rt;

                rt = posix_fadvise(infd, 0, 0, POSIX_FADV_SEQUENTIAL);
                if (rt)
                    pr2serr("open_if: posix_fadvise(SEQUENTIAL), err=%d\n",
                            rt);
            }
#endif
        }
    }
    if (ifp->flock && (infd >= 0)) {
        res = flock(infd, LOCK_EX | LOCK_NB);
        if (res < 0) {
            close(infd);
            snprintf(ebuff, EBUFF_SZ, "%sflock(LOCK_EX | LOCK_NB) on %s "
                     "failed", my_name, inf);
            perror(ebuff);
            return -SG_LIB_FLOCK_ERR;
        }
    }
    return infd;

file_err:
    if (infd >= 0)
        close(infd);
    return -SG_LIB_FILE_ERROR;
other_err:
    if (infd >= 0)
        close(infd);
    return -SG_LIB_CAT_OTHER;
}

/* Returns open output file descriptor (>= 0), -1 for don't
 * bother opening (e.g. /dev/null), or a more negative value
 * (-SG_LIB_FILE_ERROR or -SG_LIB_CAT_OTHER) if error.
 */
static int
open_of(struct opts_t * op)
{
    bool not_found;
    int outfd = -1;
    int flags, t, res, ft;
    int vb = op->verbose;
    const char * outf = op->out_fname;
    struct flags_t * ofp = &op->oflag;
    char ebuff[EBUFF_SZ];
    struct sg_simple_inquiry_resp sir;

    ft = dd_filetype(outf, op);
    if (vb)
        pr2serr(" >> Output file type: %s\n",
                dd_filetype_str(ft, ebuff, ofp->sgio));
    not_found = (FT_ERROR & ft);/* assume error was regular file not found */

    if ((FT_BLOCK & ft) && ofp->sgio)
        ft |= FT_SG;    /* might also have FT_NVME set */
    ofp->file_type = ft;

    if (FT_ST & ft) {
        pr2serr("%sunable to use scsi tape device %s\n", my_name, outf);
        goto file_err;
    } else if (FT_SG & ft) {
        flags = O_RDWR | O_NONBLOCK;
        if (ofp->direct)
            flags |= O_DIRECT;
        if (ofp->excl)
            flags |= O_EXCL;
        if (ofp->dsync)
            flags |= O_SYNC;
        if ((outfd = open(outf, flags)) < 0) {
            snprintf(ebuff, EBUFF_SZ,
                     "%scould not open %s for sg writing", my_name, outf);
            perror(ebuff);
            goto file_err;
        }
        if (vb)
            pr2serr("        open output(sg_io), flags=0x%x\n", flags);
        if (sg_simple_inquiry(outfd, &sir, false, (vb ? (vb - 1) : 0))) {
            pr2serr("INQUIRY failed on %s\n", outf);
            goto other_err;
        }
        ofp->pdt = sir.peripheral_type;
        if (vb)
            pr2serr("    %s: %.8s  %.16s  %.4s  [pdt=%d]\n", outf, sir.vendor,
                    sir.product, sir.revision, ofp->pdt);
        if (! ((FT_BLOCK & ft) || (FT_NVME & ft))) {
            t = op->blk_sz * op->bpt;
            res = ioctl(outfd, SG_SET_RESERVED_SIZE, &t);
            if (res < 0) {
                snprintf(ebuff, sizeof(ebuff), "%sSG_SET_RESERVED_SIZE error",
                         my_name);
                perror(ebuff);
            }
            res = ioctl(outfd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30000)) {
                pr2serr("%ssg driver prior to 3.x.y\n", my_name);
                goto file_err;
            }
        }
    } else if (FT_DEV_NULL & ft)
        outfd = -1; /* don't bother opening */
    else if (FT_RAW & ft) {
        flags = O_WRONLY;
        if (ofp->direct)
            flags |= O_DIRECT;
        if (ofp->excl)
            flags |= O_EXCL;
        if (ofp->dsync)
            flags |= O_SYNC;
        if ((outfd = open(outf, flags)) < 0) {
            snprintf(ebuff, EBUFF_SZ,
                    "%scould not open %s for raw writing", my_name, outf);
            perror(ebuff);
            goto file_err;
        }
    } else {    /* FT_OTHER or FT_ERROR (not found so create) */
        flags = O_WRONLY;
        if (! ofp->nocreat)
            flags |= O_CREAT;
        if (ofp->direct)
            flags |= O_DIRECT;
        if (ofp->excl)
            flags |= O_EXCL;
        if (ofp->dsync)
            flags |= O_SYNC;
        if (ofp->append)
            flags |= O_APPEND;
        if ((outfd = open(outf, flags, 0666)) < 0) {
            snprintf(ebuff, EBUFF_SZ,
                    "%scould not open %s for writing", my_name, outf);
            perror(ebuff);
            goto file_err;
        }
        if (vb)
            pr2serr("        %s output, flags=0x%x\n",
                    (not_found ? "create" : "open"), flags);
        if (op->seek > 0) {
            off64_t offset = op->seek;

            offset *= op->blk_sz;       /* could exceed 32 bits here! */
            if (lseek64(outfd, offset, SEEK_SET) < 0) {
                snprintf(ebuff, EBUFF_SZ, "%scouldn't seek to required "
                         "position on %s", my_name, outf);
                perror(ebuff);
                goto file_err;
            }
            if (vb)
                pr2serr("   >> seek: lseek64 SEEK_SET, byte offset=0x%" PRIx64
                        "\n", (uint64_t)offset);
        }
    }
    if (ofp->flock && (outfd >= 0)) {
        res = flock(outfd, LOCK_EX | LOCK_NB);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, "%sflock(LOCK_EX | LOCK_NB) on %s "
                     "failed", my_name, outf);
            perror(ebuff);
            close(outfd);
            return -SG_LIB_FLOCK_ERR;
        }
    }
    return outfd;

file_err:
    if (outfd >= 0)
        close(outfd);
    return -SG_LIB_FILE_ERROR;
other_err:
    if (outfd >= 0)
        close(outfd);
    return -SG_LIB_CAT_OTHER;
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

/* Returns true when it time to output a progress report; else false. */
static bool
check_progress(struct opts_t * op)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    bool res = false;
    uint32_t elapsed_ms, ms;
    struct timespec now_tm, res_tm;
    static bool have_prev, measure;
    static struct timespec prev_true_tm;
    static int count, threshold;

    if (op->progress) {
        if (! have_prev) {
            have_prev = true;
            measure = true;
            clock_gettime(CLOCK_MONOTONIC, &prev_true_tm);
            return false;       /* starting reference */
        }
        if (! measure) {
            if (++count >= threshold)
                count = 0;
            else
                return false;
        }
        clock_gettime(CLOCK_MONOTONIC, &now_tm);
        res_tm.tv_sec = now_tm.tv_sec - prev_true_tm.tv_sec;
        res_tm.tv_nsec = now_tm.tv_nsec - prev_true_tm.tv_nsec;
        if (res_tm.tv_nsec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_nsec += 1000000000;
        }
        elapsed_ms = (1000 * res_tm.tv_sec) + (res_tm.tv_nsec / 1000000);
        if (measure) {
            ++threshold;
            if (elapsed_ms > 80)        /* 80 milliseconds */
                measure = false;
        }
        if (elapsed_ms >= PROGRESS3_TRIGGER_MS) {
            if (elapsed_ms >= PROGRESS2_TRIGGER_MS) {
                if (elapsed_ms >= PROGRESS_TRIGGER_MS) {
                    ms = PROGRESS_TRIGGER_MS;
                    res = true;
                } else if (op->progress > 1) {
                    ms = PROGRESS2_TRIGGER_MS;
                    res = true;
                }
            } else if (op->progress > 2) {
                ms = PROGRESS3_TRIGGER_MS;
                res = true;
            }
        }
        if (res) {
            prev_true_tm.tv_sec += (ms / 1000);
            prev_true_tm.tv_nsec += (ms % 1000) * 1000000;
            if (prev_true_tm.tv_nsec >= 1000000000) {
                ++prev_true_tm.tv_sec;
                prev_true_tm.tv_nsec -= 1000000000;
            }
        }
    }
    return res;

#elif defined(HAVE_GETTIMEOFDAY)
    static bool have_prev, measure;
    static struct timeval prev_true_tm;
    static int count, threshold;
    bool res = false;
    uint32_t elapsed_ms, ms;
    struct timeval now_tm, res_tm;

    if (op->progress) {
        if (! have_prev) {
            have_prev = true;
            gettimeofday(&prev_true_tm, NULL);
            return false;       /* starting reference */
        }
        if (! measure) {
            if (++count >= threshold)
                count = 0;
            else
                return false;
        }
        gettimeofday(&now_tm, NULL);
        res_tm.tv_sec = now_tm.tv_sec - prev_true_tm.tv_sec;
        res_tm.tv_usec = now_tm.tv_usec - prev_true_tm.tv_usec;
        if (res_tm.tv_usec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        elapsed_ms = (1000 * res_tm.tv_sec) + (res_tm.tv_usec / 1000);
        if (measure) {
            ++threshold;
            if (elapsed_ms > 80)        /* 80 milliseconds */
                measure = false;
        }
        if (elapsed_ms >= PROGRESS3_TRIGGER_MS) {
            if (elapsed_ms >= PROGRESS2_TRIGGER_MS) {
                if (elapsed_ms >= PROGRESS_TRIGGER_MS) {
                    ms = PROGRESS_TRIGGER_MS;
                    res = true;
                } else if (op->progress > 1) {
                    ms = PROGRESS2_TRIGGER_MS;
                    res = true;
                }
            } else if (op->progress > 2) {
                ms = PROGRESS3_TRIGGER_MS;
                res = true;
            }
        }
        if (res) {
            prev_true_tm.tv_sec += (ms / 1000);
            prev_true_tm.tv_usec += (ms % 1000) * 1000;
            if (prev_true_tm.tv_usec >= 1000000) {
                ++prev_true_tm.tv_sec;
                prev_true_tm.tv_usec -= 1000000;
            }
        }
    }
    return res;

#else   /* no clock reading functions available */
    return false;
#endif
}

static int
parse_cmd_line(int argc, char * argv[], struct opts_t * op)
{
    int k, n, t, res, keylen;
    int ibs = 0;
    int obs = 0;
    char * key;
    char * buf;
    struct flags_t * ifp = &op->iflag;
    struct flags_t * ofp = &op->oflag;
    char str[STR_SZ];

    for (k = 1; k < argc; k++) {
        if (argv[k]) {
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
        } else
            continue;
        for (key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        keylen = strlen(key);
        if (0 == strncmp(key, "app", 3)) {
            ifp->append = !! sg_get_num(buf);
            ofp->append = ifp->append;
        } else if (0 == strcmp(key, "blk_sgio")) {
            ifp->sgio = !! sg_get_num(buf);
            ofp->sgio = ifp->sgio;
        } else if (0 == strcmp(key, "bpt")) {
            op->bpt = sg_get_num(buf);
            if (-1 == op->bpt) {
                pr2serr("%sbad argument to 'bpt='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->bpt_given = true;
        } else if (0 == strcmp(key, "bs")) {
            op->blk_sz = sg_get_num(buf);
            if ((op->blk_sz < 0) || (op->blk_sz > MAX_BPT_VALUE)) {
                pr2serr("%sbad argument to 'bs='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "cdbsz")) {
            ifp->cdbsz = sg_get_num(buf);
            if ((ifp->cdbsz < 6) || (ifp->cdbsz > 32)) {
                pr2serr("%s'cdbsz' expects 6, 10, 12, 16 or 32\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
            ofp->cdbsz = ifp->cdbsz;
            op->cdbsz_given = true;
        } else if (0 == strcmp(key, "cdl")) {
            const char * cp = strchr(buf, ',');

            ifp->cdl = sg_get_num(buf);
            if ((ifp->cdl < 0) || (ifp->cdl > 7)) {
                pr2serr("%sbad argument to 'cdl=', expect 0 to 7\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (cp) {
                ofp->cdl = sg_get_num(cp + 1);
                if ((ofp->cdl < 0) || (ofp->cdl > 7)) {
                    pr2serr("%sbad argument to 'cdl=ICDL,OCDL', expect "
                            "OCDL to be 0 to 7\n", my_name);
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else
                ofp->cdl = ifp->cdl;
            op->cdl_given = true;
        } else if (0 == strcmp(key, "coe")) {
            ifp->coe = sg_get_num(buf);
            ofp->coe = ifp->coe;
        } else if (0 == strcmp(key, "coe_limit")) {
            op->coe_limit = sg_get_num(buf);
            if (-1 == op->coe_limit) {
                pr2serr("%sbad argument to 'coe_limit='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "conv")) {
            if (process_conv(buf, ifp, ofp)) {
                pr2serr("%sbad argument to 'conv='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "count")) {
            if (0 != strcmp("-1", buf)) {
                op->dd_count = sg_get_llnum(buf);
                if ((op->dd_count < 0) ||
                    (op->dd_count > MAX_COUNT_SKIP_SEEK)) {
                    pr2serr("%sbad argument to 'count='\n", my_name);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }   /* treat 'count=-1' as calculate count (same as not given) */
        } else if (0 == strcmp(key, "dio")) {
            ofp->dio = !! sg_get_num(buf);
            ifp->dio = ofp->dio;
        } else if (0 == strcmp(key, "fua")) {
            t = sg_get_num(buf);
            ofp->fua = !! (t & 1);
            ifp->fua = !! (t & 2);
        } else if (0 == strcmp(key, "ibs")) {
            ibs = sg_get_num(buf);
            if ((ibs < 0) || (ibs > MAX_BPT_VALUE)) {
                pr2serr("%sbad argument to 'ibs='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key, "if") == 0) {
            if ('\0' != op->in_fname[0]) {
                pr2serr("Second IFILE argument??\n");
                return SG_LIB_SYNTAX_ERROR;
            } else {
                memcpy(op->in_fname, buf, INOUTF_SZ - 1);
                op->in_fname[INOUTF_SZ - 1] = '\0';
            }
        } else if (0 == strcmp(key, "iflag")) {
            if (process_flags(buf, ifp)) {
                pr2serr("%sbad argument to 'iflag='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "obs")) {
            obs = sg_get_num(buf);
            if ((obs < 0) || (obs > MAX_BPT_VALUE)) {
                pr2serr("%sbad argument to 'obs='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "odir")) {
            ifp->direct = !! sg_get_num(buf);
            ofp->direct = ifp->direct;
        } else if (strcmp(key, "of") == 0) {
            if ('\0' != op->out_fname[0]) {
                pr2serr("Second OFILE argument??\n");
                return SG_LIB_CONTRADICT;
            } else {
                memcpy(op->out_fname, buf, INOUTF_SZ - 1);
                op->out_fname[INOUTF_SZ - 1] = '\0';
            }
        } else if (strcmp(key, "of2") == 0) {
            if ('\0' != op->out2_fname[0]) {
                pr2serr("Second OFILE2 argument??\n");
                return SG_LIB_CONTRADICT;
            } else {
                memcpy(op->out2_fname, buf, INOUTF_SZ - 1);
                op->out2_fname[INOUTF_SZ - 1] = '\0';
            }
        } else if (0 == strcmp(key, "oflag")) {
            if (process_flags(buf, ofp)) {
                pr2serr("%sbad argument to 'oflag='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "retries")) {
            ifp->retries = sg_get_num(buf);
            ofp->retries = ifp->retries;
            if (-1 == ifp->retries) {
                pr2serr("%sbad argument to 'retries='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "seek")) {
            op->seek = sg_get_llnum(buf);
            if ((op->seek < 0) || (op->seek > MAX_COUNT_SKIP_SEEK)) {
                pr2serr("%sbad argument to 'seek='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "skip")) {
            op->skip = sg_get_llnum(buf);
            if ((op->skip < 0) || (op->skip > MAX_COUNT_SKIP_SEEK)) {
                pr2serr("%sbad argument to 'skip='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "sync"))
            op->do_sync = !! sg_get_num(buf);
        else if (0 == strcmp(key, "time")) {
            const char * cp = strchr(buf, ',');

            op->do_time = !! sg_get_num(buf);
            if (cp) {
                n = sg_get_num(cp + 1);
                if (n < 0) {
                    pr2serr("%sbad argument to 'time=0|1,TO'\n", my_name);
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->cmd_timeout = n ? (n * 1000) : DEF_TIMEOUT;
            }
        } else if (0 == strncmp(key, "verb", 4))
            op->verbose = sg_get_num(buf);
        else if ((keylen > 1) && ('-' == key[0]) && ('-' != key[1])) {
            res = 0;
            n = num_chs_in_str(key + 1, keylen - 1, 'c');
            if (n > 0)
                op->do_verify = true;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'd');
            op->dry_run += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'h');
            if (n > 0) {
                usage();
                return SG_LIB_OK_FALSE;
            }
            n = num_chs_in_str(key + 1, keylen - 1, 'p');
            op->progress += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'v');
            if (n > 0)
                op->verbose_given = true;
            op->verbose += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'V');
            if (n > 0)
                op->version_given = true;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'x');
            if (n > 0)
                op->do_verify = true;
            res += n;
            if (res < (keylen - 1)) {
                pr2serr("Unrecognised short option in '%s', try '--help'\n",
                        key);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strncmp(key, "--comp", 6))
            op->do_verify = true;
        else if ((0 == strncmp(key, "--dry-run", 9)) ||
                 (0 == strncmp(key, "--dry_run", 9)))
            ++op->dry_run;
        else if ((0 == strncmp(key, "--help", 6)) ||
                 (0 == strcmp(key, "-?"))) {
            usage();
            return 0;
        } else if (0 == strncmp(key, "--progress", 10))
            ++op->progress;
        else if (0 == strncmp(key, "--verb", 6)) {
            op->verbose_given = true;
            ++op->verbose;
        } else if (0 == strncmp(key, "--veri", 6))
            op->do_verify = true;
        else if (0 == strncmp(key, "--vers", 6))
            op->version_given = true;
        else {
            pr2serr("Unrecognized option '%s'\n", key);
            pr2serr("For more information use '--help'\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (op->version_given)
        return 0;
    if (op->blk_sz <= 0) {
        op->blk_sz = DEF_BLOCK_SIZE;
        pr2serr("Assume default 'bs' ((logical) block size) of %d bytes\n",
                op->blk_sz);
    }
    if ((ibs && (ibs != op->blk_sz)) || (obs && (obs != op->blk_sz))) {
        pr2serr("If 'ibs' or 'obs' given must be same as 'bs'\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_CONTRADICT;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    // bool bpt_given = false;
    // bool cdbsz_given = false;
    // bool cdl_given = false;
    bool dio_tmp, first;
    bool do_sync = false;
    bool penult_sparse_skip = false;
    bool sparse_skip = false;
    // bool verbose_given = false;
    // bool version_given = false;
    int k, res, buf_sz, blocks_per, bs;
    int retries_tmp, blks_read, bytes_read, bytes_of2, bytes_of;
    int in_sect_sz, out_sect_sz;
    int blocks = 0;
    // int bpt = DEF_BLOCKS_PER_TRANSFER;
    // int ibs = 0;
    // int obs = 0;
    // int out2fd = -1;
    int penult_blocks = 0;
    int ret = 0;
    // int64_t skip = 0;
    // int64_t seek = 0;
    int64_t in_num_sect = -1;
    int64_t out_num_sect = -1;
    const char * ccp = NULL;
    const char * cc2p;
    uint8_t * wrkBuff = NULL;
    uint8_t * wrkPos;
    struct opts_t * op;
    struct flags_t * ifp;
    struct flags_t * ofp;
    struct opts_t opts SG_C_CPP_ZERO_INIT;
    // char inf[INOUTF_SZ];
    // char outf[INOUTF_SZ];
    // char out2f[INOUTF_SZ];
    char ebuff[EBUFF_SZ];

    op = &opts;
    fscope_op = op;
    op->bpt = DEF_BLOCKS_PER_TRANSFER;
    op->cmd_timeout = DEF_TIMEOUT;   /* in milliseconds */
    op->dd_count = -1;
    op->out2fd = -1;
    ifp = &op->iflag;
    ofp = &op->oflag;
    ifp->cdbsz = DEF_SCSI_CDBSZ;
    ofp->cdbsz = DEF_SCSI_CDBSZ;
    // inf[0] = '\0';
    // outf[0] = '\0';
    // out2f[0] = '\0';

    if (getenv("SG3_UTILS_INVOCATION"))
        sg_rep_invocation(my_name, version_str, argc, argv, stderr);
    res = parse_cmd_line(argc, argv, op);
    if (res > 0)
        return (SG_LIB_OK_FALSE == res) ? 0 : res;

#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (op->verbose_given && op->version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->verbose = 0;
    } else if (! op->verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (op->verbose_given && op->version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr2serr("%sversion: %s\n", my_name, version_str);
        return 0;
    }
    if (op->progress > 0 && !op->do_time)
        op->do_time = true;
    if (argc < 2) {
        pr2serr("Won't default both IFILE to stdin _and_ OFILE to stdout\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_CONTRADICT;
    }
    if ((op->skip < 0) || (op->seek < 0)) {
        pr2serr("skip and seek cannot be negative\n");
        return SG_LIB_CONTRADICT;
    }
    if (ofp->append && (op->seek > 0)) {
        pr2serr("Can't use both append and seek switches\n");
        return SG_LIB_CONTRADICT;
    }
    if ((op->bpt < 1) || (op->bpt > MAX_BPT_VALUE)) {
        pr2serr("bpt must be > 0 and <= %d\n", MAX_BPT_VALUE);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (ifp->sparse)
        pr2serr("sparse flag ignored for iflag\n");

    /* defaulting transfer size to 128*2048 for CD/DVDs is too large
       for the block layer in lk 2.6 and results in an EIO on the
       SG_IO ioctl. So reduce it in that case. */
    if ((op->blk_sz >= 2048) && (! op->bpt_given))
        op->bpt = DEF_BLOCKS_PER_2048TRANSFER;
#ifdef DEBUG
    pr2serr("%sif=%s skip=%" PRId64 " of=%s seek=%" PRId64 " count=%"
            PRId64 "\n", my_name, op->in_fname, op->skip, op->out_fname,
            op->seek, op->dd_count);
#endif
    install_handler(SIGINT, interrupt_handler);
    install_handler(SIGQUIT, interrupt_handler);
    install_handler(SIGPIPE, interrupt_handler);
    install_handler(SIGUSR1, siginfo_handler);

    op->infd = STDIN_FILENO;
    op->outfd = STDOUT_FILENO;
    ifp->pdt = -1;
    ofp->pdt = -1;
    if (ifp->zero && ifp->ff) {
        ccp = "<addr_as_data>";
        cc2p = "addr_as_data";
    } else if (ifp->ff) {
        ccp = "<0xff bytes>";
        cc2p = "ff";
    } else if (ifp->random) {
        ccp = "<random>";
        cc2p = "random";
#ifdef HAVE_GETRANDOM
        {
            ssize_t ssz = getrandom(&seed, sizeof(seed), GRND_NONBLOCK);

            if (ssz < (ssize_t)sizeof(seed)) {
                pr2serr("getrandom() failed, ret=%d\n", (int)ssz);
                seed = (long)time(NULL);
            }
        }
#else
        seed = (long)time(NULL);    /* use seconds since epoch as proxy */
#endif
        if (op->verbose > 1)
            pr2serr("seed=%ld\n", seed);
#ifdef HAVE_SRAND48_R
        srand48_r(seed, &drand);
#else
        srand48(seed);
#endif
    } else if (ifp->zero) {
       ccp = "<zero bytes>";
       cc2p = "00";
    }
    if (ccp) {
        if (op->in_fname[0]) {
            pr2serr("iflag=%s and if=%s contradict\n", cc2p, op->in_fname);
            return SG_LIB_CONTRADICT;
        }
        ifp->file_type = FT_RANDOM_0_FF;
        strcpy(op->in_fname, ccp);
        op->infd = -1;
    } else if (op->in_fname[0] && ('-' != op->in_fname[0])) {
        op->infd = open_if(op);
        if (op->infd < 0)
            return -op->infd;
    }

    if (op->out_fname[0] && ('-' != op->out_fname[0])) {
        op->outfd = open_of(op);
        if (op->outfd < -1)
            return -op->outfd;
    }
    if (op->do_verify) {
        if (! (FT_SG & ofp->file_type)) {
            pr2serr("--verify only supported when OFILE is a sg device or "
                    "oflag=sgio\n");
            ret = SG_LIB_CONTRADICT;
            goto bypass_copy;
        }
        if (ofp->sparse) {
            pr2serr("--verify cannot be used with oflag=sparse\n");
            ret = SG_LIB_CONTRADICT;
            goto bypass_copy;
        }
    }
    if (op->cdl_given && (! op->cdbsz_given)) {
        bool changed = false;

        if ((ifp->cdbsz < 16) && (ifp->cdl > 0)) {
            ifp->cdbsz = 16;
            changed = true;
        }
        if ((ofp->cdbsz < 16) && (! op->do_verify) && (ofp->cdl > 0)) {
            ofp->cdbsz = 16;
            changed = true;
        }
        if (changed)
            pr2serr(">> increasing cdbsz to 16 due to cdl > 0\n");
    }
    if (op->out2_fname[0]) {
        op->out2_type = dd_filetype(op->out2_fname, op);
        if ((op->out2fd = open(op->out2_fname, O_WRONLY | O_CREAT,
                               0666)) < 0) {
            res = errno;
            snprintf(ebuff, EBUFF_SZ, "%scould not open %s for writing",
                     my_name, op->out2_fname);
            perror(ebuff);
            return res;
        }
    }

    if ((STDIN_FILENO == op->infd) && (STDOUT_FILENO == op->outfd)) {
        pr2serr("Can't have both 'if' as stdin _and_ 'of' as stdout\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_CONTRADICT;
    }
    if (ofp->sparse) {
        if (STDOUT_FILENO == op->outfd) {
            pr2serr("oflag=sparse needs seekable output file\n");
            return SG_LIB_CONTRADICT;
        }
    }

    bs = op->blk_sz;
    if ((op->dd_count < 0) || ((op->verbose > 0) && (0 == op->dd_count))) {
        in_num_sect = -1;
        in_sect_sz = -1;
        if (FT_SG & ifp->file_type) {
            res = scsi_read_capacity(op->infd, &in_num_sect, &in_sect_sz, op);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                pr2serr("Unit attention (readcap in), continuing\n");
                res = scsi_read_capacity(op->infd, &in_num_sect, &in_sect_sz,
                                         op);
            } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
                pr2serr("Aborted command (readcap in), continuing\n");
                res = scsi_read_capacity(op->infd, &in_num_sect, &in_sect_sz,
                                         op);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    pr2serr("read capacity not supported on %s\n",
                            op->in_fname);
                else if (res == SG_LIB_CAT_NOT_READY)
                    pr2serr("read capacity failed on %s - not ready\n",
                            op->in_fname);
                else
                    pr2serr("Unable to read capacity on %s\n", op->in_fname);
                in_num_sect = -1;
            } else if (in_sect_sz != bs)
                pr2serr(">> warning: logical block size on %s confusion: "
                        "bs=%d, device claims=%d\n", op->in_fname,
                        bs, in_sect_sz);
        } else if (FT_BLOCK & ifp->file_type) {
            if (0 != read_blkdev_capacity(op->infd, &in_num_sect,
                                          &in_sect_sz, op)) {
                pr2serr("Unable to read block capacity on %s\n",
                        op->in_fname);
                in_num_sect = -1;
            }
            if (bs != in_sect_sz) {
                pr2serr("logical block size on %s confusion: bs=%d, device "
                        "claims=%d\n", op->in_fname, bs, in_sect_sz);
                in_num_sect = -1;
            }
        }
        if (in_num_sect > op->skip)
            in_num_sect -= op->skip;

        out_num_sect = -1;
        out_sect_sz = -1;
        if (FT_SG & ofp->file_type) {
            res = scsi_read_capacity(op->outfd, &out_num_sect, &out_sect_sz,
                                     op);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                pr2serr("Unit attention (readcap out), continuing\n");
                res = scsi_read_capacity(op->outfd, &out_num_sect,
                                         &out_sect_sz, op);
            } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
                pr2serr("Aborted command (readcap out), continuing\n");
                res = scsi_read_capacity(op->outfd, &out_num_sect,
                                         &out_sect_sz, op);
            }
            if (0 != res) {
                if (res == SG_LIB_CAT_INVALID_OP)
                    pr2serr("read capacity not supported on %s\n",
                            op->out_fname);
                else
                    pr2serr("Unable to read capacity on %s\n", op->out_fname);
                out_num_sect = -1;
            } else if (bs != out_sect_sz)
                pr2serr(">> warning: logical block size on %s confusion: "
                        "bs=%d, device claims=%d\n", op->out_fname,
                        bs, out_sect_sz);
        } else if (FT_BLOCK & ofp->file_type) {
            if (0 != read_blkdev_capacity(op->outfd, &out_num_sect,
                                          &out_sect_sz, op)) {
                pr2serr("Unable to read block capacity on %s\n",
                        op->out_fname);
                out_num_sect = -1;
            } else if (bs != out_sect_sz) {
                pr2serr("logical block size on %s confusion: bs=%d, device "
                        "claims=%d\n", op->out_fname, bs, out_sect_sz);
                out_num_sect = -1;
            }
        }
        if (out_num_sect > op->seek)
            out_num_sect -= op->seek;
#ifdef DEBUG
        pr2serr("Start of loop, count=%" PRId64 ", in_num_sect=%" PRId64
                ", out_num_sect=%" PRId64 "\n", op->dd_count, in_num_sect,
                out_num_sect);
#endif
        if (op->dd_count < 0) {
            if (in_num_sect > 0) {
                if (out_num_sect > 0)
                    op->dd_count = (in_num_sect > out_num_sect) ?
                                        out_num_sect : in_num_sect;
                else
                    op->dd_count = in_num_sect;
            } else
                op->dd_count = out_num_sect;
        }
    }

    if (op->dd_count < 0) {
        pr2serr("Couldn't calculate count, please give one\n");
        return SG_LIB_CAT_OTHER;
    }
    if (! op->cdbsz_given) {
        if ((FT_SG & ifp->file_type) && (MAX_SCSI_CDBSZ != ifp->cdbsz) &&
            (((op->dd_count + op->skip) > UINT_MAX) ||
             (op->bpt > USHRT_MAX))) {
            pr2serr("Note: SCSI command size increased to 16 bytes (for "
                    "'if')\n");
            ifp->cdbsz = MAX_SCSI_CDBSZ;
        }
        if ((FT_SG & ofp->file_type) && (MAX_SCSI_CDBSZ != ofp->cdbsz) &&
            (((op->dd_count + op->seek) > UINT_MAX) ||
             (op->bpt > USHRT_MAX))) {
            pr2serr("Note: SCSI command size increased to 16 bytes (for "
                    "'of')\n");
            ofp->cdbsz = MAX_SCSI_CDBSZ;
        }
    }

    if (ifp->dio || ifp->direct || ofp->direct ||
        (FT_RAW & ifp->file_type) || (FT_RAW & ofp->file_type)) {
        /* want heap buffer aligned to page_size */
        wrkPos = sg_memalign(bs * op->bpt, 0, &wrkBuff, false);
        if (NULL == wrkPos) {
            pr2serr("sg_memalign: error, out of memory?\n");
            return sg_convert_errno(ENOMEM);
        }
    } else {
        wrkPos = sg_memalign(bs * op->bpt, 0, &wrkBuff, false);
        if (0 == wrkPos) {
            pr2serr("Not enough user memory\n");
            return sg_convert_errno(ENOMEM);
        }
    }

    blocks_per = op->bpt;
#ifdef DEBUG
    pr2serr("Start of loop, count=%" PRId64 ", blocks_per=%d\n",
            op->dd_count, blocks_per);
#endif
    if (op->do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
        start_tm_valid = true;
    }

    if (op->dry_run > 0) {
        pr2serr("Since --dry-run option given, bypassing copy\n");
        goto bypass_copy;
    }

    /* <<< main loop that does the copy >>> */
    while (op->dd_count > 0) {
        bytes_read = 0;
        bytes_of = 0;
        bytes_of2 = 0;
        penult_sparse_skip = sparse_skip;
        penult_blocks = penult_sparse_skip ? blocks : 0;
        sparse_skip = false;
        blocks = (op->dd_count > blocks_per) ? blocks_per : op->dd_count;
        if (FT_SG & ifp->file_type) {
            dio_tmp = ifp->dio;
            res = sg_read(wrkPos, blocks, op->skip, &dio_tmp, &blks_read, op);
            if (-2 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(op->infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    ret = res;
                    break;
                }
                if (buf_sz < MIN_RESERVED_SIZE)
                    buf_sz = MIN_RESERVED_SIZE;
                blocks_per = (buf_sz + bs - 1) / bs;
                if (blocks_per < blocks) {
                    blocks = blocks_per;
                    pr2serr("Reducing read to %d blocks per loop\n",
                            blocks_per);
                    res = sg_read(wrkPos, blocks, op->skip, &dio_tmp,
                                  &blks_read, op);
                }
            }
            if (res) {
                pr2serr("sg_read failed,%s at or after lba=%" PRId64 " [0x%"
                        PRIx64 "]\n", ((-2 == res) ?  " try reducing bpt," :
                                                   ""), op->skip, op->skip);
                ret = res;
                break;
            } else {
                if (blks_read < blocks) {
                    op->dd_count = 0;   /* force exit after write */
                    blocks = blks_read;
                }
                in_full += blocks;
                if (ifp->dio && (! dio_tmp))
                    op->dio_incomplete_count++;
            }
        } else if (FT_RANDOM_0_FF & ifp->file_type) {
            int j;

            res = blocks * bs;
            if (ifp->zero && ifp->ff && (bs >= 4)) {
                uint32_t pos = (uint32_t)op->skip;
                uint32_t off;

                for (k = 0, off = 0; k < blocks; ++k, off += bs, ++pos) {
                    for (j = 0; j < (bs - 3); j += 4)
                        sg_put_unaligned_be32(pos, wrkPos + off + j);
                }
            } else if (ifp->zero)
                memset(wrkPos, 0, res);
            else if (ifp->ff)
                memset(wrkPos, 0xff, res);
            else {
                int kk, jj;
                const int jbump = sizeof(uint32_t);
                long rn;
                uint8_t * bp;

                bp = wrkPos;
                for (kk = 0; kk < blocks; ++kk, bp += bs) {
                    for (jj = 0; jj < bs; jj += jbump) {
                       /* mrand48 takes uniformly from [-2^31, 2^31) */
#ifdef HAVE_SRAND48_R
                        mrand48_r(&drand, &rn);
#else
                        rn = mrand48();
#endif
                        *((uint32_t *)(bp + jj)) = (uint32_t)rn;
                    }
                }
            }
            bytes_read = res;
            in_full += blocks;
        } else {
            while (((res = read(op->infd, wrkPos, blocks * bs)) < 0) &&
                   ((EINTR == errno) || (EAGAIN == errno) ||
                    (EBUSY == errno)))
                ;
            if (op->verbose > 2)
                pr2serr("read(unix): count=%d, res=%d\n", blocks * bs,
                        res);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, "%sreading, skip=%" PRId64 " ",
                         my_name, op->skip);
                perror(ebuff);
                ret = -1;
                break;
            } else if (res < blocks * bs) {
                op->dd_count = 0;
                blocks = res / bs;
                if ((res % bs) > 0) {
                    blocks++;
                    in_partial++;
                }
            }
            bytes_read = res;
            in_full += blocks;
        }

        if (0 == blocks)
            break;      /* nothing read so leave loop */

        if (op->out2fd >= 0) {
            while (((res = write(op->out2fd, wrkPos, blocks * bs)) < 0) &&
                   ((EINTR == errno) || (EAGAIN == errno) ||
                    (EBUSY == errno)))
                ;
            if (op->verbose > 2)
                pr2serr("write to of2: count=%d, res=%d\n", blocks * bs,
                        res);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, "%swriting to of2, seek=%"
                         PRId64 " ", my_name, op->seek);
                perror(ebuff);
                ret = -1;
                break;
            }
            bytes_of2 = res;
        }

        if (ofp->sparse && (op->dd_count > blocks) &&
            (! (FT_DEV_NULL & ofp->file_type))) {
            if (NULL == zeros_buff) {
                zeros_buff = sg_memalign(blocks * bs, 0, &free_zeros_buff,
                                         false);
                if (NULL == zeros_buff) {
                    pr2serr("zeros_buff sg_memalign failed\n");
                    ret = -1;
                    break;
                }
            }
            if (0 == memcmp(wrkPos, zeros_buff, blocks * bs))
                sparse_skip = true;
        }
        if (sparse_skip) {
            if (FT_SG & ofp->file_type) {
                out_sparse_num += blocks;
                if (op->verbose > 2)
                    pr2serr("sparse bypassing sg_write: seek blk=%" PRId64
                            ", offset blks=%d\n", op->seek, blocks);
            } else if (FT_DEV_NULL & ofp->file_type)
                ;
            else {
                off64_t offset = (off64_t)blocks * bs;
                off64_t off_res;

                if (op->verbose > 2)
                    pr2serr("sparse bypassing write: seek=%" PRId64 ", rel "
                            "offset=%" PRId64 "\n", (op->seek * bs),
                            (int64_t)offset);
                off_res = lseek64(op->outfd, offset, SEEK_CUR);
                if (off_res < 0) {
                    pr2serr("sparse tried to bypass write: seek=%" PRId64
                            ", rel offset=%" PRId64 " but ...\n",
                            (op->seek * bs), (int64_t)offset);
                    perror("lseek64 on output");
                    ret = SG_LIB_FILE_ERROR;
                    break;
                } else if (op->verbose > 4)
                    pr2serr("oflag=sparse lseek64 result=%" PRId64 "\n",
                            (int64_t)off_res);
                out_sparse_num += blocks;
            }
        } else if (FT_SG & ofp->file_type) {
            dio_tmp = ofp->dio;
            retries_tmp = ofp->retries;
            first = true;
            while (1) {
                ret = sg_write(op->outfd, wrkPos, blocks, op->seek,
                               &dio_tmp, op);
                if ((0 == ret) || (SG_DD_BYPASS == ret))
                    break;
                if ((SG_LIB_CAT_NOT_READY == ret) ||
                    (SG_LIB_SYNTAX_ERROR == ret))
                    break;
                else if ((-2 == ret) && first) {
                    /* ENOMEM: find what's available and try that */
                    if (ioctl(op->outfd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                        perror("RESERVED_SIZE ioctls failed");
                        break;
                    }
                    if (buf_sz < MIN_RESERVED_SIZE)
                        buf_sz = MIN_RESERVED_SIZE;
                    blocks_per = (buf_sz + bs - 1) / bs;
                    if (blocks_per < blocks) {
                        blocks = blocks_per;
                        pr2serr("Reducing %s to %d blocks per loop\n",
                                (op->do_verify ? "verify" : "write"), blocks);
                    } else
                        break;
                } else if ((SG_LIB_CAT_UNIT_ATTENTION == ret) && first) {
                    if (--max_uas > 0)
                        pr2serr("Unit attention, continuing (w)\n");
                    else {
                        pr2serr("Unit attention, too many (w)\n");
                        break;
                    }
                } else if ((SG_LIB_CAT_ABORTED_COMMAND == ret) && first) {
                    if (--max_aborted > 0)
                        pr2serr("Aborted command, continuing (w)\n");
                    else {
                        pr2serr("Aborted command, too many (w)\n");
                        break;
                    }
                } else if (ret < 0)
                    break;
                else if (retries_tmp > 0) {
                    pr2serr(">>> retrying a sgio %s, lba=0x%" PRIx64 "\n",
                            (op->do_verify ? "verify" : "write"),
                            (uint64_t)op->seek);
                    --retries_tmp;
                    ++num_retries;
                    if (unrecovered_errs > 0)
                        --unrecovered_errs;
                } else
                    break;
                first = false;
            }
            if (SG_DD_BYPASS == ret)
                ret = 0;        /* not bumping out_full */
            else if (0 != ret) {
                pr2serr("sg_write failed,%s seek=%" PRId64 "\n",
                        ((-2 == ret) ? " try reducing bpt," : ""), op->seek);
                break;
            } else {
                out_full += blocks;
                if (ofp->dio && (! dio_tmp))
                    op->dio_incomplete_count++;
            }
        } else if (FT_DEV_NULL & ofp->file_type)
            out_full += blocks; /* act as if written out without error */
        else {
            while (((res = write(op->outfd, wrkPos, blocks * bs)) < 0) &&
                   ((EINTR == errno) || (EAGAIN == errno) ||
                    (EBUSY == errno)))
                ;
            if (op->verbose > 2)
                pr2serr("write(unix): count=%d, res=%d\n", blocks * bs,
                        res);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, "%swriting, seek=%" PRId64 " ",
                         my_name, op->seek);
                perror(ebuff);
                ret = -1;
                break;
            } else if (res < blocks * bs) {
                pr2serr("output file probably full, seek=%" PRId64 " ",
                        op->seek);
                blocks = res / bs;
                out_full += blocks;
                if ((res % bs) > 0)
                    out_partial++;
                ret = -1;
                break;
            } else {
                out_full += blocks;
                bytes_of = res;
            }
        }
#ifdef HAVE_POSIX_FADVISE
        {
            bool in_valid, out2_valid, out_valid;
            int rt;

            in_valid = !! ((FT_OTHER | FT_BLOCK) & ifp->file_type);
            out_valid = !! ((FT_OTHER | FT_BLOCK) & ofp->file_type);
            out2_valid = !! ((FT_OTHER | FT_BLOCK) & op->out2_type);
            if (ifp->nocache && (bytes_read > 0) && in_valid) {
                rt = posix_fadvise(op->infd, 0, (op->skip * bs) + bytes_read,
                                   POSIX_FADV_DONTNEED);
                // rt = posix_fadvise(op->infd, (op->skip * bs), bytes_read,
                                   // POSIX_FADV_DONTNEED);
                // rt = posix_fadvise(op->infd, 0, 0, POSIX_FADV_DONTNEED);
                if (rt)         /* returns error as result */
                    pr2serr("posix_fadvise on read, skip=%" PRId64
                            " ,err=%d\n", op->skip, rt);
            }
            if ((ofp->nocache & 2) && (bytes_of2 > 0) && out2_valid) {
                rt = posix_fadvise(op->out2fd, 0, 0, POSIX_FADV_DONTNEED);
                if (rt)
                    pr2serr("posix_fadvise on of2, seek=%" PRId64
                            " ,err=%d\n", op->seek, rt);
            }
            if ((ofp->nocache & 1) && (bytes_of > 0) && out_valid) {
                rt = posix_fadvise(op->outfd, 0, 0, POSIX_FADV_DONTNEED);
                if (rt)
                    pr2serr("posix_fadvise on output, seek=%" PRId64
                            " ,err=%d\n", op->seek, rt);
            }
        }
#endif
        if (op->dd_count > 0)
            op->dd_count -= blocks;
        op->skip += blocks;
        op->seek += blocks;
        if (op->progress > 0) {
            if (check_progress(op)) {
                calc_duration_throughput(true);
                print_stats("");
            }
        }
    } /* end of main loop that does the copy ... */

    if (ret && penult_sparse_skip && (penult_blocks > 0)) {
        /* if error and skipped last output due to sparse ... */
        if ((FT_SG & ofp->file_type) || (FT_DEV_NULL & ofp->file_type))
            ;
        else {
            /* ... try writing to extend ofile to length prior to error */
            while (((res = write(op->outfd, zeros_buff, penult_blocks * bs))
                    < 0) && ((EINTR == errno) || (EAGAIN == errno) ||
                             (EBUSY == errno)))
                ;
            if (op->verbose > 2)
                pr2serr("write(unix, sparse after error): count=%d, res=%d\n",
                        penult_blocks * bs, res);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, "%swriting(sparse after error), "
                         "seek=%" PRId64 " ", my_name,  op->seek);
                perror(ebuff);
            }
        }
    }

    if (do_sync) {
        if (FT_SG & ofp->file_type) {
            pr2serr(">> Synchronizing cache on %s\n", op->out_fname);
            res = sg_ll_sync_cache_10(op->outfd, false, false, 0, 0, 0, true,
                                      0);
            if (SG_LIB_CAT_UNIT_ATTENTION == res) {
                pr2serr("Unit attention (out, sync cache), continuing\n");
                res = sg_ll_sync_cache_10(op->outfd, false, false, 0, 0, 0,
                                          false, 0);
            }
            if (0 != res)
                pr2serr("Unable to synchronize cache\n");
        }
    }

bypass_copy:
    if (op->do_time)
        calc_duration_throughput(false);
    if (op->progress > 0)
        pr2serr("\nCompleted:\n");

    if (wrkBuff)
        free(wrkBuff);
    if (free_zeros_buff)
        free(free_zeros_buff);
    if (op->in_ptp)
        destruct_scsi_pt_obj(op->in_ptp);
    if (op->out_ptp)
        destruct_scsi_pt_obj(op->out_ptp);
    if ((STDIN_FILENO != op->infd) && (op->infd >= 0))
        close(op->infd);
    if (! ((STDOUT_FILENO == op->outfd) || (FT_DEV_NULL & ofp->file_type))) {
        if (op->outfd >= 0)
            close(op->outfd);
    }
    if (op->dry_run > 0)
        goto bypass2;

    if (0 != op->dd_count) {
        pr2serr("Some error occurred,");
        if (0 == ret)
            ret = SG_LIB_CAT_OTHER;
    }
    print_stats("");
    if (op->dio_incomplete_count) {
        int fd;
        char c;

        pr2serr(">> Direct IO requested but incomplete %d times\n",
                op->dio_incomplete_count);
        if ((fd = open(sg_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    pr2serr(">>> %s set to '0' but should be set to '1' for "
                            "direct IO\n", sg_allow_dio);
            }
            close(fd);
        }
    }
    if (op->sum_of_resids)
        pr2serr(">> Non-zero sum of residual counts=%d\n", op->sum_of_resids);

bypass2:
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
