/* A utility program for copying files. Similar to 'dd' but using
 * the 'Extended Copy' command.
 *
 *  Copyright (c) 2011-2019 Hannes Reinecke, SUSE Labs
 *
 *  Largely taken from 'sg_dd', which has the
 *
 *  Copyright (C) 1999 - 2010 D. Gilbert and P. Allworth
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is a specialisation of the Unix "dd" command in which
 * either the input or the output file is a scsi generic device, raw
 * device, a block device or a normal file. The block size ('bs') is
 * assumed to be 512 if not given. This program complains if 'ibs' or
 * 'obs' are given with a value that differs from 'bs' (or the default 512).
 * If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
 * not given or 'of=-' then stdout assumed.
 *
 * A non-standard argument "bpt" (blocks per transfer) is added to control
 * the maximum number of blocks in each transfer. The default value is 128.
 * For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16 KiB
 * in this case) is transferred to or from the sg device in a single SCSI
 * command.
 *
 * This version is designed for the linux kernel 2.4, 2.6, 3 and 4 series.
 */

#define _XOPEN_SOURCE 600
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
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
#include <sys/file.h>
#include <sys/sysmacros.h>
#ifndef major
#include <sys/types.h>
#endif
#include <linux/major.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "0.70 20190501";

#define ME "sg_xcopy: "

#define STR_SZ 1024
#define INOUTF_SZ 512
#define EBUFF_SZ 1024

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define MAX_BLOCKS_PER_TRANSFER 65535

#define DEF_MODE_RESP_LEN 252
#define RW_ERR_RECOVERY_MP 1
#define CACHING_MP 8
#define CONTROL_MP 0xa

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikey value */
#endif

#define SG_LIB_FLOCK_ERR 90

/* In SPC-4 the cdb opcodes have more generic names */
#define THIRD_PARTY_COPY_OUT_CMD 0x83
#define THIRD_PARTY_COPY_IN_CMD 0x84

/* Third party copy IN (opcode 0x84) and OUT (opcode 0x83) command service
 * actions */
#define SA_XCOPY_LID1           0x0     /* OUT, originate */
#define SA_XCOPY_LID4           0x1     /* OUT, originate */
#define SA_POP_TOK              0x10    /* OUT, originate */
#define SA_WR_USING_TOK         0x11    /* OUT, originate */
#define SA_COPY_ABORT           0x1C    /* OUT, abort */
#define SA_COPY_STATUS_LID1     0x0     /* IN, retrieve */
#define SA_COPY_DATA_LID1       0x1     /* IN, retrieve */
#define SA_COPY_OP_PARAMS       0x3     /* IN, retrieve */
#define SA_COPY_FAIL_DETAILS    0x4     /* IN, retrieve */
#define SA_COPY_STATUS_LID4     0x5     /* IN, retrieve */
#define SA_COPY_DATA_LID4       0x6     /* IN, retrieve */
#define SA_ROD_TOK_INFO         0x7     /* IN, retrieve */
#define SA_ALL_ROD_TOKS         0x8     /* IN, retrieve */

#define DEF_3PC_OUT_TIMEOUT (10 * 60)   /* is 10 minutes enough? */
#define DEF_GROUP_NUM 0x0

#define VPD_DEVICE_ID 0x83
#define VPD_3PARTY_COPY 0x8f

#define FT_OTHER 1              /* filetype is probably normal */
#define FT_SG 2                 /* filetype is sg or bsg char device */
#define FT_RAW 4                /* filetype is raw char device */
#define FT_DEV_NULL 8           /* either "/dev/null" or "." as filename */
#define FT_ST 16                /* filetype is st char device (tape) */
#define FT_BLOCK 32             /* filetype is block device */
#define FT_FIFO 64              /* filetype is a fifo (name pipe) */
#define FT_ERROR 128            /* couldn't "stat" file */

#define TD_FC_WWPN 1
#define TD_FC_PORT 2
#define TD_FC_WWPN_AND_PORT 4
#define TD_SPI 8
#define TD_VPD 16
#define TD_IPV4 32
#define TD_ALIAS 64
#define TD_RDMA 128
#define TD_FW 256
#define TD_SAS 512
#define TD_IPV6 1024
#define TD_IP_COPY_SERVICE 2048
#define TD_ROD 4096

#define XCOPY_TO_SRC "XCOPY_TO_SRC"
#define XCOPY_TO_DST "XCOPY_TO_DST"
#define DEF_XCOPY_SRC0_DST1 1

#define DEV_NULL_MINOR_NUM 3

#define MIN_RESERVED_SIZE 8192

#define MAX_UNIT_ATTENTIONS 10
#define MAX_ABORTED_CMDS 256

static int64_t dd_count = -1;
static int64_t in_full = 0;
static int in_partial = 0;
static int64_t out_full = 0;
static int out_partial = 0;

static bool do_time = false;
static bool start_tm_valid = false;
static bool xcopy_flag_cat = false;
static bool xcopy_flag_dc = false;
static bool xcopy_flag_fco = false;     /* fast copy only, spc5r20 */
static int blk_sz = 0;
static int list_id_usage = -1;
static int priority = 1;
static int verbose = 0;
static struct timeval start_tm;


struct xcopy_fp_t {
    bool append;
    bool excl;
    bool flock;
    bool pad;     /* Data descriptor PAD bit (residual data treatment) */
    bool xcopy_given;
    int sect_sz;
    int sg_type, sg_fd;
    int pdt;     /* Peripheral device type */
    dev_t devno;
    uint32_t min_bytes;
    uint32_t max_bytes;
    int64_t num_sect;
    char fname[INOUTF_SZ];
};

static struct xcopy_fp_t ixcf;
static struct xcopy_fp_t oxcf;

static const char * read_cap_str = "Read capacity";
static const char * rec_copy_op_params_str = "Receive copy operating "
                                             "parameters";

static void calc_duration_throughput(int contin);


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
print_stats(const char * str)
{
    if (0 != dd_count)
        pr2serr("  remaining block count=%" PRId64 "\n", dd_count);
    pr2serr("%s%" PRId64 "+%d records in\n", str, in_full - in_partial,
            in_partial);
    pr2serr("%s%" PRId64 "+%d records out\n", str, out_full - out_partial,
            out_partial);
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
    if (do_time)
        calc_duration_throughput(0);
    print_stats("");
    kill(getpid (), sig);
}

static void
siginfo_handler(int sig)
{
    if (sig) { ; }      /* unused, dummy to suppress warning */
    pr2serr("Progress report, continuing ...\n");
    if (do_time)
        calc_duration_throughput(1);
    print_stats("  ");
}

static bool bsg_major_checked = false;
static int bsg_major = 0;

static void
find_bsg_major(void)
{
    const char * proc_devices = "/proc/devices";
    FILE *fp;
    char a[128];
    char b[128];
    char * cp;
    int n;

    if (NULL == (fp = fopen(proc_devices, "r"))) {
        if (verbose)
            pr2serr("fopen %s failed: %s\n", proc_devices, strerror(errno));
        return;
    }
    while ((cp = fgets(b, sizeof(b), fp))) {
        if ((1 == sscanf(b, "%126s", a)) &&
            (0 == memcmp(a, "Character", 9)))
            break;
    }
    while (cp && (cp = fgets(b, sizeof(b), fp))) {
        if (2 == sscanf(b, "%d %126s", &n, a)) {
            if (0 == strcmp("bsg", a)) {
                bsg_major = n;
                break;
            }
        } else
            break;
    }
    if (verbose > 5) {
        if (cp)
            pr2serr("found bsg_major=%d\n", bsg_major);
        else
            pr2serr("found no bsg char device in %s\n", proc_devices);
    }
    fclose(fp);
}

/* Returns a file descriptor on success (0 or greater), -1 for an open
 * error, -2 for a standard INQUIRY problem. */
static int
open_sg(struct xcopy_fp_t * fp, int vb)
{
    int devmajor, devminor, offset;
    struct sg_simple_inquiry_resp sir;
    char ebuff[EBUFF_SZ];
    int len;

    devmajor = major(fp->devno);
    devminor = minor(fp->devno);

    if (fp->sg_type & FT_SG) {
        snprintf(ebuff, EBUFF_SZ, "%.500s", fp->fname);
    } else if (fp->sg_type & FT_BLOCK || fp->sg_type & FT_OTHER) {
        int fd;

        snprintf(ebuff, EBUFF_SZ, "/sys/dev/block/%d:%d/partition",
                 devmajor, devminor);
        if ((fd = open(ebuff, O_RDONLY)) >= 0) {
            ebuff[EBUFF_SZ - 1] = '\0';
            len = read(fd, ebuff, EBUFF_SZ - 1);
            if (len < 0) {
                perror("read partition");
            } else {
                offset = strtoul(ebuff, NULL, 10);
                devminor -= offset;
            }
            close(fd);
        }
        snprintf(ebuff, EBUFF_SZ, "/dev/block/%d:%d", devmajor, devminor);
    } else {
        snprintf(ebuff, EBUFF_SZ, "/dev/char/%d:%d", devmajor, devminor);
    }
    fp->sg_fd = sg_cmds_open_device(ebuff, false /* rw mode */, vb);
    if (fp->sg_fd < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 ME "could not open %s device %d:%d for sg",
                 fp->sg_type & FT_BLOCK ? "block" : "char",
                 devmajor, devminor);
        perror(ebuff);
        return -sg_convert_errno(-fp->sg_fd);
    }
    if (sg_simple_inquiry(fp->sg_fd, &sir, false, vb)) {
        pr2serr("INQUIRY failed on %s\n", ebuff);
        sg_cmds_close_device(fp->sg_fd);
        fp->sg_fd = -1;
        return -1;
    }

    fp->pdt = sir.peripheral_type;
    if (vb)
        pr2serr("    %s: %.8s  %.16s  %.4s  [pdt=%d, 3pc=%d]\n", fp->fname,
                sir.vendor, sir.product, sir.revision, fp->pdt,
                !! (0x8 & sir.byte_5));

    return fp->sg_fd;
}

static int
dd_filetype(struct xcopy_fp_t * fp)
{
    struct stat st;
    size_t len = strlen(fp->fname);

    if ((1 == len) && ('.' == fp->fname[0]))
        return FT_DEV_NULL;
    if (stat(fp->fname, &st) < 0)
        return FT_ERROR;
    if (S_ISCHR(st.st_mode)) {
        fp->devno = st.st_rdev;
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
        if (! bsg_major_checked) {
            bsg_major_checked = true;
            find_bsg_major();
        }
        if (bsg_major == (int)major(st.st_rdev))
            return FT_SG;
    } else if (S_ISBLK(st.st_mode)) {
        fp->devno = st.st_rdev;
        return FT_BLOCK;
    } else if (S_ISFIFO(st.st_mode)) {
        fp->devno = st.st_dev;
        return FT_FIFO;
    }
    fp->devno = st.st_dev;
    return FT_OTHER | FT_BLOCK;
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
    if (FT_FIFO & ft)
        off += sg_scnpr(buff + off, 32, "fifo (named pipe) ");
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

static int
simplified_ft(const struct xcopy_fp_t * xfp)
{
    int ftype = xfp->sg_type;

    switch (ftype) {
    case FT_BLOCK:
    case FT_ST:
    case FT_OTHER:      /* typically regular file */
    case FT_DEV_NULL:
    case FT_FIFO:
    case FT_ERROR:
        return ftype;
    default:
        if (FT_SG & ftype) {
            if ((0 == xfp->pdt) || (0xe == xfp->pdt)) /* D-A or RBC */
            return FT_BLOCK;
        else if (0x1 == xfp->pdt)
            return FT_ST;
        }
        return FT_OTHER;
    }
}

static int
seg_desc_from_dd_type(int in_ft, int in_off, int out_ft, int out_off)
{
    int desc_type = -1;

    switch (in_ft) {
    case FT_BLOCK:
        switch (out_ft) {
        case FT_ST:
            if (out_off)
                break;

            if (in_off)
                desc_type = 0x8;
            else
                desc_type = 0;
            break;
        case FT_BLOCK:
            if (in_off || out_off)
                desc_type = 0xA;
            else
                desc_type = 2;
            break;
        default:
            break;
        }
        break;
    case FT_ST:
        if (in_off)
            break;

        switch (out_ft) {
        case FT_ST:
            if (!out_off) {
                desc_type = 3;
                break;
            }
            break;
        case FT_BLOCK:
            if (out_off)
                desc_type = 9;
            else
                desc_type = 3;
            break;
        case FT_DEV_NULL:
            desc_type = 6;
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }

    return desc_type;
}

static void
usage(int n_help)
{
    if (n_help < 2)
        goto primary_help;
    else
        goto secondary_help;

primary_help:
    pr2serr("Usage: "
            "sg_xcopy [app=0|1] [bpt=BPT] [bs=BS] [cat=0|1] [conv=CONV]\n"
            "                [count=COUNT] [dc=0|1] [ibs=BS]\n"
            "                [id_usage=hold|discard|disable] [if=IFILE] "
            "[iflag=FLAGS]\n"
            "                [list_id=ID] [obs=BS] [of=OFILE] "
            "[oflag=FLAGS] [prio=PRIO]\n"
            "                [seek=SEEK] [skip=SKIP] [time=0|1] "
            "[verbose=VERB]\n"
            "                [--help] [--on_dst|--on_src] [--verbose] "
            "[--version]\n\n"
            "  where:\n"
            "    app         if argument is 1 then open OFILE in append "
            "mode\n"
            "    bpt         is blocks_per_transfer (default: 128)\n"
            "    bs          block size (default is 512)\n");
    pr2serr("    cat         xcopy segment descriptor CAT bit (default: "
            "0)\n"
            "    conv        ignored\n"
            "    count       number of blocks to copy (def: device size)\n"
            "    dc          xcopy segment descriptor DC bit (default: 0)\n"
            "    fco         xcopy segment descriptor FCO bit (default: 0)\n"
            "    ibs         input block size (if given must be same as "
            "'bs=')\n"
            "    id_usage    sets list_id_usage field to hold (0), "
            "discard (2) or\n"
            "                disable (3)\n"
            "    if          file or device to read from (def: stdin)\n"
            "    iflag       comma separated list of flags applying to "
            "IFILE\n"
            "    list_id     sets list_id field to ID (default: 1 or 0)\n"
            "    obs         output block size (if given must be same as "
            "'bs=')\n"
            "    of          file or device to write to (def: stdout), "
            "OFILE of '.'\n");
    pr2serr("                treated as /dev/null\n"
            "    oflag       comma separated list of flags applying to "
            "OFILE\n"
            "    prio        set xcopy priority field to PRIO (def: 1)\n"
            "    seek        block position to start writing to OFILE\n"
            "    skip        block position to start reading from IFILE\n"
            "    time        0->no timing(def), 1->time plus calculate "
            "throughput\n"
            "    verbose     0->quiet(def), 1->some noise, 2->more noise, "
            "etc\n"
            "    --help|-h   print out this usage message then exit\n"
            "    --on_dst    send XCOPY command to OFILE\n"
            "    --on_src    send XCOPY command to IFILE\n"
            "    --verbose|-v   same action as verbose=1\n"
            "    --version|-V   print version information then exit\n\n"
            "Copy from IFILE to OFILE, similar to dd command; "
            "but using the SCSI\nEXTENDED COPY (XCOPY(LID1)) command. For "
            "list of flags, use '-hh'.\n");
    return;

secondary_help:
    pr2serr("FLAGS:\n"
            "  append (o)     open OFILE in append mode\n"
            "  excl           open corresponding device with O_EXCL\n"
            "  flock          call flock(LOCK_EX|LOCK_NB)\n"
            "  null           does nothing, placeholder\n"
            "  pad            set xcopy data descriptor PAD bit on\n"
            "                 corresponding device\n"
            "  xcopy          send XCOPY command to corresponding device\n"
            "\n"
            "ENVIRONMENT VARIABLES:\n"
            "  XCOPY_TO_DST   send XCOPY command to OFILE (destination) "
            "if no other\n"
            "                 indication\n"
            "  XCOPY_TO_SRC   send XCOPY command to IFILE (source)\n"
           );
}

static int
scsi_encode_seg_desc(uint8_t *seg_desc, int seg_desc_type,
                     int64_t num_blk, uint64_t src_lba, uint64_t dst_lba)
{
    int seg_desc_len = 0;

    seg_desc[0] = (uint8_t)seg_desc_type;
    seg_desc[1] = 0x0;
    if (xcopy_flag_cat)
        seg_desc[1] |= 0x1;
    if (xcopy_flag_dc)
        seg_desc[1] |= 0x2;
    if (xcopy_flag_fco)
        seg_desc[1] |= 0x4;
    if (seg_desc_type == 0x02) {
        seg_desc_len = 0x18;
        seg_desc[4] = 0;
        seg_desc[5] = 0; /* Source target index */
        seg_desc[7] = 1; /* Destination target index */
        sg_put_unaligned_be16(num_blk, seg_desc + 10);
        sg_put_unaligned_be64(src_lba, seg_desc + 12);
        sg_put_unaligned_be64(dst_lba, seg_desc + 20);
    }
    sg_put_unaligned_be16(seg_desc_len, seg_desc + 2);
    return seg_desc_len + 4;
}

static int
scsi_extended_copy(int sg_fd, uint8_t list_id,
                   uint8_t *src_desc, int src_desc_len,
                   uint8_t *dst_desc, int dst_desc_len,
                   int seg_desc_type, int64_t num_blk,
                   uint64_t src_lba, uint64_t dst_lba)
{
    uint8_t xcopyBuff[256];
    int desc_offset = 16;
    int seg_desc_len;
    int verb, res;
    char b[80];

    verb = (verbose > 1) ? (verbose - 2) : 0;
    memset(xcopyBuff, 0, 256);
    xcopyBuff[0] = list_id;
    xcopyBuff[1] = (list_id_usage << 3) | priority;
    xcopyBuff[2] = 0;
    xcopyBuff[3] = src_desc_len + dst_desc_len; /* Two target descriptors */
    memcpy(xcopyBuff + desc_offset, src_desc, src_desc_len);
    desc_offset += src_desc_len;
    memcpy(xcopyBuff + desc_offset, dst_desc, dst_desc_len);
    desc_offset += dst_desc_len;
    seg_desc_len = scsi_encode_seg_desc(xcopyBuff + desc_offset,
                                        seg_desc_type, num_blk,
                                        src_lba, dst_lba);
    xcopyBuff[11] = seg_desc_len; /* One segment descriptor */
    desc_offset += seg_desc_len;
    /* set noisy so if a UA happens it will be printed to stderr */
    res = sg_ll_3party_copy_out(sg_fd, SA_XCOPY_LID1, list_id,
                                DEF_GROUP_NUM, DEF_3PC_OUT_TIMEOUT,
                                xcopyBuff, desc_offset, true, verb);
    if (res) {
        sg_get_category_sense_str(res, sizeof(b), b, verb);
        pr2serr("Xcopy(LID1): %s\n", b);
    }
    return res;
}

/* Return of 0 -> success, see sg_ll_read_capacity*() otherwise */
static int
scsi_read_capacity(struct xcopy_fp_t *xfp)
{
    int res;
    unsigned int ui;
    uint8_t rcBuff[RCAP16_REPLY_LEN];
    int verb;
    char b[80];

    verb = (verbose ? verbose - 1: 0);
    res = sg_ll_readcap_10(xfp->sg_fd, false /* pmi */, 0, rcBuff,
                           READ_CAP_REPLY_LEN, true, verb);
    if (0 != res) {
        sg_get_category_sense_str(res, sizeof(b), b, verb);
        pr2serr("Read capacity(10): %s\n", b);
        return res;
    }

    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3])) {
        uint64_t ls;

        res = sg_ll_readcap_16(xfp->sg_fd, false /* pmi */, 0, rcBuff,
                               RCAP16_REPLY_LEN, true, verb);
        if (0 != res) {
            sg_get_category_sense_str(res, sizeof(b), b, verb);
            pr2serr("Read capacity(16): %s\n", b);
            return res;
        }
        ls = sg_get_unaligned_be64(rcBuff + 0);
        xfp->num_sect = (int64_t)(ls + 1);
        xfp->sect_sz = sg_get_unaligned_be32(rcBuff + 8);
    } else {
        ui = sg_get_unaligned_be32(rcBuff + 0);
        /* take care not to sign extend values > 0x7fffffff */
        xfp->num_sect = (int64_t)ui + 1;
        xfp->sect_sz = sg_get_unaligned_be32(rcBuff + 4);
    }
    if (verbose)
        pr2serr("    %s: number of blocks=%" PRId64 " [0x%" PRIx64 "], block "
                "size=%d\n", xfp->fname, xfp->num_sect, xfp->num_sect,
                xfp->sect_sz);
    return 0;
}

static int
scsi_operating_parameter(struct xcopy_fp_t *xfp, int is_target)
{
    bool valid = false;
    int res, ftype, snlid, verb;
    uint32_t rcBuffLen = 256, len, n, td_list = 0;
    uint32_t num, max_target_num, max_segment_num, max_segment_len;
    uint32_t max_desc_len, max_inline_data, held_data_limit;
    uint8_t rcBuff[256];
    char b[80];

    verb = (verbose ? verbose - 1: 0);
    ftype = xfp->sg_type;
    if (FT_SG & ftype) {
        if ((0 == xfp->pdt) || (0xe == xfp->pdt)) /* direct-access or RBC */
            ftype |= FT_BLOCK;
        else if (0x1 == xfp->pdt)
            ftype |= FT_ST;
    }
    res = sg_ll_receive_copy_results(xfp->sg_fd, SA_COPY_OP_PARAMS, 0, rcBuff,
                                     rcBuffLen, true, verb);
    if (0 != res) {
        sg_get_category_sense_str(res, sizeof(b), b, verb);
        pr2serr("Xcopy operating parameters: %s\n", b);
        return -res;
    }

    len = sg_get_unaligned_be32(rcBuff + 0);
    if (len > rcBuffLen) {
        pr2serr("  <<report len %d > %d too long for internal buffer, output "
                "truncated\n", len, rcBuffLen);
    }
    if (verbose > 2) {
        pr2serr("\nOutput response in hex:\n");
        hex2stderr(rcBuff, len, 1);
    }
    snlid = rcBuff[4] & 0x1;
    max_target_num = sg_get_unaligned_be16(rcBuff + 8);
    max_segment_num = sg_get_unaligned_be16(rcBuff + 10);
    max_desc_len = sg_get_unaligned_be32(rcBuff + 12);
    max_segment_len = sg_get_unaligned_be32(rcBuff + 16);
    xfp->max_bytes = max_segment_len ? max_segment_len : UINT32_MAX;
    max_inline_data = sg_get_unaligned_be32(rcBuff + 20);
    if (verbose) {
        pr2serr(" >> %s response:\n", rec_copy_op_params_str);
        pr2serr("    Support No List IDentifier (SNLID): %d\n", snlid);
        pr2serr("    Maximum target descriptor count: %u\n",
                (unsigned int)max_target_num);
        pr2serr("    Maximum segment descriptor count: %u\n",
                (unsigned int)max_segment_num);
        pr2serr("    Maximum descriptor list length: %u\n",
                (unsigned int)max_desc_len);
        pr2serr("    Maximum segment length: %u\n",
                (unsigned int)max_segment_len);
        pr2serr("    Maximum inline data length: %u\n",
                (unsigned int)max_inline_data);
    }
    held_data_limit = sg_get_unaligned_be32(rcBuff + 24);
    if (list_id_usage < 0) {
        if (!held_data_limit)
            list_id_usage = 2;
        else
            list_id_usage = 0;
    }
    if (verbose) {
        pr2serr("    Held data limit: %u (list_id_usage: %d)\n",
                (unsigned int)held_data_limit, list_id_usage);
        num = sg_get_unaligned_be32(rcBuff + 28);
        pr2serr("    Maximum stream device transfer size: %u\n",
                (unsigned int)num);
        pr2serr("    Maximum concurrent copies: %u\n", rcBuff[36]);
        if (rcBuff[37] > 30)
            pr2serr("    Data segment granularity: 2**%u bytes\n",
                    rcBuff[37]);
        else
            pr2serr("    Data segment granularity: %u bytes\n",
                    1 << rcBuff[37]);
        if (rcBuff[38] > 30)
            pr2serr("    Inline data granularity: 2**%u bytes\n", rcBuff[38]);
        else
            pr2serr("    Inline data granularity: %u bytes\n",
                    1 << rcBuff[38]);
        if (rcBuff[39] > 30)
            pr2serr("    Held data granularity: 2**%u bytes\n",
                    1 << rcBuff[39]);
        else
            pr2serr("    Held data granularity: %u bytes\n", 1 << rcBuff[39]);

        pr2serr("    Implemented descriptor list:\n");
    }
    xfp->min_bytes = 1 << rcBuff[37];

    for (n = 0; n < rcBuff[43]; n++) {
        switch(rcBuff[44 + n]) {
        case 0x00: /* copy block to stream device */
            if (!is_target && (ftype & FT_BLOCK))
                valid = true;
            if (is_target && (ftype & FT_ST))
                valid = true;
            if (verbose)
                pr2serr("        Copy Block to Stream device\n");
            break;
        case 0x01: /* copy stream to block device */
            if (!is_target && (ftype & FT_ST))
                valid = true;
            if (is_target && (ftype & FT_BLOCK))
                valid = true;
            if (verbose)
                pr2serr("        Copy Stream to Block device\n");
            break;
        case 0x02: /* copy block to block device */
            if (!is_target && (ftype & FT_BLOCK))
                valid = true;
            if (is_target && (ftype & FT_BLOCK))
                valid = true;
            if (verbose)
                pr2serr("        Copy Block to Block device\n");
            break;
        case 0x03: /* copy stream to stream device */
            if (!is_target && (ftype & FT_ST))
                valid = true;
            if (is_target && (ftype & FT_ST))
                valid = true;
            if (verbose)
                pr2serr("        Copy Stream to Stream device\n");
            break;
        case 0x04: /* copy inline data to stream device */
            if (!is_target && (ftype & FT_OTHER))
                valid = true;
            if (is_target && (ftype & FT_ST))
                valid = true;
            if (verbose)
                pr2serr("        Copy inline data to Stream device\n");
            break;
        case 0x05: /* copy embedded data to stream device */
            if (!is_target && (ftype & FT_OTHER))
                valid = true;
            if (is_target && (ftype & FT_ST))
                valid = true;
            if (verbose)
                pr2serr("        Copy embedded data to Stream device\n");
            break;
        case 0x06: /* Read from stream device and discard */
            if (!is_target && (ftype & FT_ST))
                valid = true;
            if (is_target && (ftype & FT_DEV_NULL))
                valid = true;
            if (verbose)
                pr2serr("        Read from stream device and discard\n");
            break;
        case 0x07: /* Verify block or stream device operation */
            if (!is_target && (ftype & (FT_ST | FT_BLOCK)))
                valid = true;
            if (is_target && (ftype & (FT_ST | FT_BLOCK)))
                valid = true;
            if (verbose)
                pr2serr("        Verify block or stream device operation\n");
            break;
        case 0x08: /* copy block device with offset to stream device */
            if (!is_target && (ftype & FT_BLOCK))
                valid = true;
            if (is_target && (ftype & FT_ST))
                valid = true;
            if (verbose)
                pr2serr("        Copy block device with offset to stream "
                       "device\n");
            break;
        case 0x09: /* copy stream device to block device with offset */
            if (!is_target && (ftype & FT_ST))
                valid = true;
            if (is_target && (ftype & FT_BLOCK))
                valid = true;
            if (verbose)
                pr2serr("        Copy stream device to block device with "
                       "offset\n");
            break;
        case 0x0a: /* copy block device with offset to block device with
                    * offset */
            if (!is_target && (ftype & FT_BLOCK))
                valid = true;
            if (is_target && (ftype & FT_BLOCK))
                valid = true;
            if (verbose)
                pr2serr("        Copy block device with offset to block "
                       "device with offset\n");
            break;
        case 0x0b: /* copy block device to stream device and hold data */
            if (!is_target && (ftype & FT_BLOCK))
                valid = true;
            if (is_target && (ftype & FT_ST))
                valid = true;
            if (verbose)
                pr2serr("        Copy block device to stream device and hold "
                       "data\n");
            break;
        case 0x0c: /* copy stream device to block device and hold data */
            if (!is_target && (ftype & FT_ST))
                valid = true;
            if (is_target && (ftype & FT_BLOCK))
                valid = true;
            if (verbose)
                pr2serr("        Copy stream device to block device and hold "
                       "data\n");
            break;
        case 0x0d: /* copy block device to block device and hold data */
            if (!is_target && (ftype & FT_BLOCK))
                valid = true;
            if (is_target && (ftype & FT_BLOCK))
                valid = true;
            if (verbose)
                pr2serr("        Copy block device to block device and hold "
                       "data\n");
            break;
        case 0x0e: /* copy stream device to stream device and hold data */
            if (!is_target && (ftype & FT_ST))
                valid = true;
            if (is_target && (ftype & FT_ST))
                valid = true;
            if (verbose)
                pr2serr("        Copy block device to block device and hold "
                       "data\n");
            break;
        case 0x0f: /* read from stream device and hold data */
            if (!is_target && (ftype & FT_ST))
                valid = true;
            if (is_target && (ftype & FT_DEV_NULL))
                valid = true;
            if (verbose)
                pr2serr("        Read from stream device and hold data\n");
            break;
        case 0xe0: /* FC N_Port_Name */
            if (verbose)
                pr2serr("        FC N_Port_Name target descriptor\n");
            td_list |= TD_FC_WWPN;
            break;
        case 0xe1: /* FC Port_ID */
            if (verbose)
                pr2serr("        FC Port_ID target descriptor\n");
            td_list |= TD_FC_PORT;
            break;
        case 0xe2: /* FC N_Port_ID with N_Port_Name checking */
            if (verbose)
                pr2serr("        FC N_Port_ID with N_Port_Name target "
                       "descriptor\n");
            td_list |= TD_FC_WWPN_AND_PORT;
            break;
        case 0xe3: /* Parallel Interface T_L  */
            if (verbose)
                pr2serr("        SPI T_L target descriptor\n");
            td_list |= TD_SPI;
            break;
        case 0xe4: /* identification descriptor */
            if (verbose)
                pr2serr("        Identification target descriptor\n");
            td_list |= TD_VPD;
            break;
        case 0xe5: /* IPv4  */
            if (verbose)
                pr2serr("        IPv4 target descriptor\n");
            td_list |= TD_IPV4;
            break;
        case 0xe6: /* Alias */
            if (verbose)
                pr2serr("        Alias target descriptor\n");
            td_list |= TD_ALIAS;
            break;
        case 0xe7: /* RDMA */
            if (verbose)
                pr2serr("        RDMA target descriptor\n");
            td_list |= TD_RDMA;
            break;
        case 0xe8: /* FireWire */
            if (verbose)
                pr2serr("        IEEE 1394 target descriptor\n");
            td_list |= TD_FW;
            break;
        case 0xe9: /* SAS */
            if (verbose)
                pr2serr("        SAS target descriptor\n");
            td_list |= TD_SAS;
            break;
        case 0xea: /* IPv6 */
            if (verbose)
                pr2serr("        IPv6 target descriptor\n");
            td_list |= TD_IPV6;
            break;
        case 0xeb: /* IP Copy Service */
            if (verbose)
                pr2serr("        IP Copy Service target descriptor\n");
            td_list |= TD_IP_COPY_SERVICE;
            break;
        case 0xfe: /* ROD */
            if (verbose)
                pr2serr("        ROD target descriptor\n");
            td_list |= TD_ROD;
            break;
        default:
            pr2serr(">> Unhandled target descriptor 0x%02x\n",
                    rcBuff[44 + n]);
            break;
        }
    }
    if (! valid) {
        pr2serr(">> no matching target descriptor supported\n");
        td_list = 0;
    }
    return td_list;
}

static void
decode_designation_descriptor(const uint8_t * bp, int i_len)
{
    char c[2048];

    sg_get_designation_descriptor_str(NULL, bp, i_len, 1, verbose,
                                      sizeof(c), c);
    pr2serr("%s", c);
}

static int
desc_from_vpd_id(int sg_fd, uint8_t *desc, int desc_len,
                 unsigned int block_size, bool pad)
{
    int res, verb;
    uint8_t rcBuff[256], *bp, *best = NULL;
    unsigned int len = 254;
    int off = -1, u, i_len, best_len = 0, assoc, desig, f_desig = 0;
    char b[80];

    verb = (verbose ? verbose - 1: 0);
    memset(rcBuff, 0xff, len);
    res = sg_ll_inquiry(sg_fd, false, true /* evpd */, VPD_DEVICE_ID, rcBuff,
                        4, true, verb);
    if (0 != res) {
        if (SG_LIB_CAT_ILLEGAL_REQ == res)
            pr2serr("Device identification VPD page not found\n");
        else {
            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("VPD inquiry (Device ID): %s\n", b);
            pr2serr("   try again with '-vv'\n");
        }
        return res;
    } else if (rcBuff[1] != VPD_DEVICE_ID) {
        pr2serr("invalid VPD response\n");
        return SG_LIB_CAT_MALFORMED;
    }
    len = sg_get_unaligned_be16(rcBuff + 2) + 4;
    res = sg_ll_inquiry(sg_fd, false, true, VPD_DEVICE_ID, rcBuff, len, true,
                        verb);
    if (0 != res) {
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("VPD inquiry (Device ID): %s\n", b);
        return res;
    } else if (rcBuff[1] != VPD_DEVICE_ID) {
        pr2serr("invalid VPD response\n");
        return SG_LIB_CAT_MALFORMED;
    }
    if (verbose > 2) {
        pr2serr("Output response in hex:\n");
        hex2stderr(rcBuff, len, 1);
    }

    while ((u = sg_vpd_dev_id_iter(rcBuff + 4, len - 4, &off, 0, -1, -1)) ==
           0) {
        bp = rcBuff + 4 + off;
        i_len = bp[3];
        if (((unsigned int)off + i_len + 4) > len) {
            pr2serr("    VPD page error: designator length %d longer "
                    "than\n     remaining response length=%d\n", i_len,
                    (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        assoc = ((bp[1] >> 4) & 0x3);
        desig = (bp[1] & 0xf);
        if (verbose > 2)
            pr2serr("    Desc %d: assoc %u desig %u len %d\n", off, assoc,
                    desig, i_len);
        /* Descriptor must be less than 16 bytes */
        if (i_len > 16)
            continue;
        if (desig == 3) {
            best = bp;
            best_len = i_len;
            break;
        }
        if (desig == 2) {
            if (!best || f_desig < 2) {
                best = bp;
                best_len = i_len;
                f_desig = 2;
            }
        } else if (desig == 1) {
            if (!best || f_desig == 0) {
                best = bp;
                best_len = i_len;
                f_desig = desig;
            }
        } else if (desig == 0) {
            if (!best) {
                best = bp;
                best_len = i_len;
                f_desig = desig;
            }
        }
    }
    if (best) {
        if (verbose)
            decode_designation_descriptor(best, best_len);
        if (best_len + 4 < desc_len) {
            memset(desc, 0, 32);
            desc[0] = 0xe4;
            memcpy(desc + 4, best, best_len + 4);
            desc[4] &= 0x1f;
            if (pad)
                desc[28] = 0x4;
            sg_put_unaligned_be24((uint32_t)block_size, desc + 29);
            if (verbose > 3) {
                pr2serr("Descriptor in hex (bs %d):\n", block_size);
                hex2stderr(desc, 32, 1);
            }
            return 32;
        }
        return  best_len + 8;
    }
    return 0;
}

static void
calc_duration_throughput(int contin)
{
    struct timeval end_tm, res_tm;
    double a, b;
    int64_t blks;

    if (start_tm_valid && (start_tm.tv_sec || start_tm.tv_usec)) {
        blks = (in_full > out_full) ? in_full : out_full;
        gettimeofday(&end_tm, NULL);
        res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
        if (res_tm.tv_usec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        a = res_tm.tv_sec;
        a += (0.000001 * res_tm.tv_usec);
        b = (double)blk_sz * blks;
        pr2serr("time to transfer data%s: %d.%06d secs",
                (contin ? " so far" : ""), (int)res_tm.tv_sec,
                (int)res_tm.tv_usec);
        if ((a > 0.00001) && (b > 511))
            pr2serr(" at %.2f MB/sec\n", b / (a * 1000000.0));
        else
            pr2serr("\n");
    }
}

/* Process arguments given to 'iflag=" or 'oflag=" options. Returns 0
 * on success, 1 on error. */
static int
process_flags(const char * arg, struct xcopy_fp_t * fp)
{
    char buff[256];
    char * cp;
    char * np;

    strncpy(buff, arg, sizeof(buff) - 1);
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
        else if (0 == strcmp(cp, "excl"))
            fp->excl = true;
        else if (0 == strcmp(cp, "flock"))
            fp->flock = true;
        else if (0 == strcmp(cp, "null"))
            ;
        else if (0 == strcmp(cp, "pad"))
            fp->pad = true;
        else if (0 == strcmp(cp, "xcopy"))
            fp->xcopy_given = true;   /* for ddpt compatibility */
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
open_if(struct xcopy_fp_t * ifp, int vb)
{
    int infd = -1, flags, fl, res, err;
    char ebuff[EBUFF_SZ];

    ifp->sg_type = dd_filetype(ifp);

    if (vb)
        pr2serr(" >> Input file type: %s, devno %d:%d\n",
                dd_filetype_str(ifp->sg_type, ebuff),
                major(ifp->devno), minor(ifp->devno));
    if (FT_ERROR & ifp->sg_type) {
        pr2serr(ME "unable access %s\n", ifp->fname);
        return -SG_LIB_FILE_ERROR;
    }
    flags = O_NONBLOCK;
    if (ifp->excl)
        flags |= O_EXCL;
    fl = O_RDWR;
    if ((infd = open(ifp->fname, fl | flags)) < 0) {
        fl = O_RDONLY;
        if ((infd = open(ifp->fname, fl | flags)) < 0) {
            err = errno;
            snprintf(ebuff, EBUFF_SZ,
                     ME "could not open %.500s for sg reading", ifp->fname);
            perror(ebuff);
            return -sg_convert_errno(err);
        }
    }
    if (vb)
        pr2serr("        open input(sg_io), flags=0x%x\n", fl | flags);

    if (ifp->flock) {
        res = flock(infd, LOCK_EX | LOCK_NB);
        if (res < 0) {
            close(infd);
            snprintf(ebuff, EBUFF_SZ, ME "flock(LOCK_EX | LOCK_NB) on %.500s "
                     "failed", ifp->fname);
            perror(ebuff);
            return -SG_LIB_FLOCK_ERR;
        }
    }
    return infd;
}

/* Returns open output file descriptor (>= 0), -1 for don't
 * bother opening (e.g. /dev/null), or a more negative value
 * (-SG_LIB_FILE_ERROR or -SG_LIB_CAT_OTHER) if error.
 */
static int
open_of(struct xcopy_fp_t * ofp, int vb)
{
    int outfd, flags, res, err;
    char ebuff[EBUFF_SZ];

    ofp->sg_type = dd_filetype(ofp);
    if (vb)
        pr2serr(" >> Output file type: %s, devno %d:%d\n",
                dd_filetype_str(ofp->sg_type, ebuff),
                major(ofp->devno), minor(ofp->devno));

    if (!(FT_DEV_NULL & ofp->sg_type)) {
        flags = O_RDWR | O_NONBLOCK;
        if (ofp->excl)
            flags |= O_EXCL;
        if (ofp->append)
            flags |= O_APPEND;
        if ((outfd = open(ofp->fname, flags)) < 0) {
            err = errno;
            snprintf(ebuff, EBUFF_SZ,
                     ME "could not open %.500s for sg writing", ofp->fname);
            perror(ebuff);
            return -sg_convert_errno(err);
        }
        if (vb)
            pr2serr("        open output(sg_io), flags=0x%x\n", flags);
    } else
        outfd = -1; /* don't bother opening */
    if ((outfd >= 0) && ofp->flock) {
        res = flock(outfd, LOCK_EX | LOCK_NB);
        if (res < 0) {
            close(outfd);
            snprintf(ebuff, EBUFF_SZ, ME "flock(LOCK_EX | LOCK_NB) on %.500s "
                     "failed", ofp->fname);
            perror(ebuff);
            return -SG_LIB_FLOCK_ERR;
        }
    }
    return outfd;
}

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


int
main(int argc, char * argv[])
{
    bool bpt_given = false;
    bool list_id_given = false;
    bool on_src = false;
    bool on_src_dst_given = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, k, n, keylen, infd, outfd, xcopy_fd;
    int blocks = 0;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    int dst_desc_len;
    int ibs = 0;
    int num_help = 0;
    int num_xcopy = 0;
    int obs = 0;
    int ret = 0;
    int seg_desc_type;
    int src_desc_len;
    int64_t skip = 0;
    int64_t seek = 0;
    uint8_t list_id = 1;
    char * key;
    char * buf;
    char str[STR_SZ];
    uint8_t src_desc[256];
    uint8_t dst_desc[256];

    ixcf.fname[0] = '\0';
    oxcf.fname[0] = '\0';
    ixcf.num_sect = -1;
    oxcf.num_sect = -1;

    if (argc < 2) {
        pr2serr("Won't default both IFILE to stdin _and_ OFILE to stdout\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_CONTRADICT;
    }

    for (k = 1; k < argc; k++) {
        if (argv[k]) {
            strncpy(str, argv[k], STR_SZ - 1);
            str[STR_SZ - 1] = '\0';
        } else
            continue;
        for (key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        keylen = (int)strlen(key);
        if (0 == strncmp(key, "app", 3)) {
            ixcf.append = !! sg_get_num(buf);
            oxcf.append = ixcf.append;
        } else if (0 == strcmp(key, "bpt")) {
            bpt = sg_get_num(buf);
            if (-1 == bpt) {
                pr2serr(ME "bad argument to 'bpt='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            bpt_given = true;
        } else if (0 == strcmp(key, "bs")) {
            blk_sz = sg_get_num(buf);
            if (-1 == blk_sz) {
                pr2serr(ME "bad argument to 'bs='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "list_id")) {
            ret = sg_get_num(buf);
            if (-1 == ret || ret > 0xff) {
                pr2serr(ME "bad argument to 'list_id='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            list_id = (ret & 0xff);
            list_id_given = true;
        } else if (0 == strcmp(key, "id_usage")) {
            if (!strncmp(buf, "hold", 4))
                list_id_usage = 0;
            else if (!strncmp(buf, "discard", 7))
                list_id_usage = 2;
            else if (!strncmp(buf, "disable", 7))
                list_id_usage = 3;
            else {
                pr2serr(ME "bad argument to 'id_usage='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "conv"))
            pr2serr(ME ">>> ignoring all 'conv=' arguments\n");
        else if (0 == strcmp(key, "count")) {
            if (0 != strcmp("-1", buf)) {
                dd_count = sg_get_llnum(buf);
                if (-1LL == dd_count) {
                    pr2serr(ME "bad argument to 'count='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            }   /* treat 'count=-1' as calculate count (same as not given) */
        } else if (0 == strcmp(key, "prio")) {
            priority = sg_get_num(buf);
        } else if (0 == strcmp(key, "cat")) {
            n = sg_get_num(buf);
            if (n < 0 || n > 1) {
                pr2serr(ME "bad argument to 'cat='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            xcopy_flag_cat = !! n;
        } else if (0 == strcmp(key, "dc")) {
            n = sg_get_num(buf);
            if (n < 0 || n > 1) {
                pr2serr(ME "bad argument to 'dc='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            xcopy_flag_dc = !! n;
        } else if (0 == strcmp(key, "fco")) {
            n = sg_get_num(buf);
            if (n < 0 || n > 1) {
                pr2serr(ME "bad argument to 'fco='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            xcopy_flag_fco = !! n;
        } else if (0 == strcmp(key, "ibs")) {
            ibs = sg_get_num(buf);
        } else if (strcmp(key, "if") == 0) {
            if ('\0' != ixcf.fname[0]) {
                pr2serr("Second IFILE argument??\n");
                return SG_LIB_CONTRADICT;
            } else {
                memcpy(ixcf.fname, buf, INOUTF_SZ - 1);
                ixcf.fname[INOUTF_SZ - 1] = '\0';
            }
        } else if (0 == strcmp(key, "iflag")) {
            if (process_flags(buf, &ixcf)) {
                pr2serr(ME "bad argument to 'iflag='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "obs")) {
            obs = sg_get_num(buf);
        } else if (strcmp(key, "of") == 0) {
            if ('\0' != oxcf.fname[0]) {
                pr2serr("Second OFILE argument??\n");
                return SG_LIB_CONTRADICT;
            } else {
                memcpy(oxcf.fname, buf, INOUTF_SZ - 1);
                oxcf.fname[INOUTF_SZ - 1] = '\0';
            }
        } else if (0 == strcmp(key, "oflag")) {
            if (process_flags(buf, &oxcf)) {
                pr2serr(ME "bad argument to 'oflag='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "seek")) {
            seek = sg_get_llnum(buf);
            if (-1LL == seek) {
                pr2serr(ME "bad argument to 'seek='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "skip")) {
            skip = sg_get_llnum(buf);
            if (-1LL == skip) {
                pr2serr(ME "bad argument to 'skip='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key, "time"))
            do_time = !! sg_get_num(buf);
        else if (0 == strncmp(key, "verb", 4))
            verbose = sg_get_num(buf);
        /* look for long options that start with '--' */
        else if (0 == strncmp(key, "--help", 6))
            ++num_help;
        else if (0 == strncmp(key, "--on_dst", 8)) {
            on_src = false;
            if (on_src_dst_given) {
                pr2serr("Syntax error - either specify --on_src OR "
                        "--on_dst\n");
                pr2serr("For more information use '--help'\n");
                return SG_LIB_CONTRADICT;
            }
            on_src_dst_given = true;
        } else if (0 == strncmp(key, "--on_src", 8)) {
            on_src = true;
            if (on_src_dst_given) {
                pr2serr("Syntax error - either specify --on_src OR "
                        "--on_dst\n");
                pr2serr("For more information use '--help'\n");
                return SG_LIB_CONTRADICT;
            }
            on_src_dst_given = true;
        } else if (0 == strncmp(key, "--verb", 6)) {
            verbose_given = true;
            verbose += 1;
        } else if (0 == strncmp(key, "--vers", 6))
            version_given = true;
        else if (0 == strncmp(key, "--xcopy", 7))
            ;   /* ignore; for compatibility with ddpt */
        /* look for short options that start with a single '-', they can be
         * concaternated (e.g. '-vvvV') */
        else if ((keylen > 1) && ('-' == key[0]) && ('-' != key[1])) {
            res = 0;
            n = num_chs_in_str(key + 1, keylen - 1, 'h');
            num_help += n;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'v');
            verbose += n;
            if (n > 0)
                verbose_given = true;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'V');
            if (n > 0)
                version_given = true;
            res += n;
            n = num_chs_in_str(key + 1, keylen - 1, 'x');
            /* accept and ignore; for compatibility with ddpt */
            res += n;
            if (res < (keylen - 1)) {
                pr2serr(ME "Unrecognised short option in '%s', try "
                        "'--help'\n", key);
                if (0 == num_help)
                    return -1;
            }
        } else {
            pr2serr("Unrecognized option '%s'\n", key);
            if (num_help)
                usage(num_help);
            else
                pr2serr("For more information use '--help'\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (num_help) {
        usage(num_help);
        return 0;
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
        pr2serr(ME "%s\n", version_str);
        return 0;
    }

    if (! on_src_dst_given) {
        if (ixcf.xcopy_given == oxcf.xcopy_given) {
            char * csp;
            char * cdp;

            csp = getenv(XCOPY_TO_SRC);
            cdp = getenv(XCOPY_TO_DST);
            if ((!! csp) == (!! cdp)) {
#if DEF_XCOPY_SRC0_DST1 == 0
                on_src = true;
#else
                on_src = false;
#endif
            } else if (csp)
                on_src = true;
            else
                on_src = false;
        } else if (ixcf.xcopy_given)
            on_src = true;
        else
            on_src = false;
    }
    if (verbose > 1)
        pr2serr(" >>> Extended Copy(LID1) command will be sent to %s device "
                "[%s]\n", (on_src ? "src" : "dst"),
                (on_src ? ixcf.fname : oxcf.fname));

    if ((ibs && blk_sz && (ibs != blk_sz)) ||
        (obs && blk_sz && (obs != blk_sz))) {
        pr2serr("If 'ibs' or 'obs' given must be same as 'bs'\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_CONTRADICT;
    }
    if (blk_sz && !ibs)
        ibs = blk_sz;
    if (blk_sz && !obs)
        obs = blk_sz;

    if ((skip < 0) || (seek < 0)) {
        pr2serr("skip and seek cannot be negative\n");
        return SG_LIB_CONTRADICT;
    }
    if (oxcf.append && (seek > 0)) {
        pr2serr("Can't use both append and seek switches\n");
        return SG_LIB_CONTRADICT;
    }
    if (bpt < 1) {
        pr2serr("bpt must be greater than 0\n");
        return SG_LIB_SYNTAX_ERROR;
    } else if (bpt > MAX_BLOCKS_PER_TRANSFER) {
        pr2serr("bpt must be less than or equal to %d\n",
                MAX_BLOCKS_PER_TRANSFER);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (list_id_usage == 3) { /* list_id usage disabled */
        if (! list_id_given)
            list_id = 0;
        if (list_id) {
            pr2serr("list_id disabled by id_usage flag\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (verbose > 1)
        pr2serr(" >>> " ME " if=%s skip=%" PRId64 " of=%s seek=%" PRId64
                " count=%" PRId64 "\n", ixcf.fname, skip, oxcf.fname, seek,
                dd_count);
    install_handler(SIGINT, interrupt_handler);
    install_handler(SIGQUIT, interrupt_handler);
    install_handler(SIGPIPE, interrupt_handler);
    install_handler(SIGUSR1, siginfo_handler);

    ixcf.pdt = -1;
    oxcf.pdt = -1;
    if (ixcf.fname[0] && ('-' != ixcf.fname[0])) {
        infd = open_if(&ixcf, verbose);
        if (infd < 0)
            return -infd;
    } else {
        pr2serr("stdin not acceptable for IFILE\n");
        return SG_LIB_FILE_ERROR;
    }

    if (oxcf.fname[0] && ('-' != oxcf.fname[0])) {
        outfd = open_of(&oxcf, verbose);
        if (outfd < -1)
            return -outfd;
    } else {
        pr2serr("stdout not acceptable for OFILE\n");
        return SG_LIB_FILE_ERROR;
    }

    res = open_sg(&ixcf, verbose);
    if (res < 0) {
        if (-1 == res)
            return SG_LIB_FILE_ERROR;
        else
            return SG_LIB_CAT_OTHER;
    }
    res = open_sg(&oxcf, verbose);
    if (res < 0) {
        if (-1 == res)
            return SG_LIB_FILE_ERROR;
        else
            return SG_LIB_CAT_OTHER;
    }

    if ((STDIN_FILENO == infd) && (STDOUT_FILENO == outfd)) {
        pr2serr("Can't have both 'if' as stdin _and_ 'of' as stdout\n");
        pr2serr("For more information use '--help'\n");
        return SG_LIB_CONTRADICT;
    }

    res = scsi_read_capacity(&ixcf);
    if (SG_LIB_CAT_UNIT_ATTENTION == res) {
        pr2serr("Unit attention (%s in), continuing\n", read_cap_str);
        res = scsi_read_capacity(&ixcf);
    } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
        pr2serr("Aborted command (%s in), continuing\n", read_cap_str);
        res = scsi_read_capacity(&ixcf);
    }
    if (0 != res) {
        if (res == SG_LIB_CAT_INVALID_OP)
            pr2serr("%s command not supported on %s\n", read_cap_str,
                    ixcf.fname);
        else if (res == SG_LIB_CAT_NOT_READY)
            pr2serr("%s failed on %s - not ready\n", read_cap_str,
                    ixcf.fname);
        else
            pr2serr("Unable to %s on %s\n", read_cap_str, ixcf.fname);
        ixcf.num_sect = -1;
    } else if (ibs && ixcf.sect_sz != ibs) {
        pr2serr(">> warning: block size on %s confusion: "
                "ibs=%d, device claims=%d\n", ixcf.fname, ibs, ixcf.sect_sz);
    }
    if (skip && ixcf.num_sect < skip) {
        pr2serr("argument to 'skip=' exceeds device size (max %" PRId64 ")\n",
                ixcf.num_sect);
        return SG_LIB_SYNTAX_ERROR;
    }

    res = scsi_read_capacity(&oxcf);
    if (SG_LIB_CAT_UNIT_ATTENTION == res) {
        pr2serr("Unit attention (%s out), continuing\n", read_cap_str);
        res = scsi_read_capacity(&oxcf);
    } else if (SG_LIB_CAT_ABORTED_COMMAND == res) {
        pr2serr("Aborted command (%s out), continuing\n", read_cap_str);
        res = scsi_read_capacity(&oxcf);
    }
    if (0 != res) {
        if (res == SG_LIB_CAT_INVALID_OP)
            pr2serr("%s command not supported on %s\n", read_cap_str,
                    oxcf.fname);
        else
            pr2serr("Unable to %s on %s\n", read_cap_str, oxcf.fname);
        oxcf.num_sect = -1;
    } else if (obs && obs != oxcf.sect_sz) {
        pr2serr(">> warning: block size on %s confusion: obs=%d, device "
                "claims=%d\n", oxcf.fname, obs, oxcf.sect_sz);
    }
    if (seek && oxcf.num_sect < seek) {
        pr2serr("argument to 'seek=' exceeds device size (max %" PRId64 ")\n",
                oxcf.num_sect);
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((dd_count < 0) || ((verbose > 0) && (0 == dd_count))) {
        if (xcopy_flag_dc == 0) {
            dd_count = ixcf.num_sect - skip;
            if ((dd_count * ixcf.sect_sz) >
                ((oxcf.num_sect - seek) * oxcf.sect_sz))
                dd_count = (oxcf.num_sect - seek) * oxcf.sect_sz /
                           ixcf.sect_sz;
        } else {
            dd_count = oxcf.num_sect - seek;
            if ((dd_count * oxcf.sect_sz) >
                ((ixcf.num_sect - skip) * ixcf.sect_sz))
                dd_count = (ixcf.num_sect - skip) * ixcf.sect_sz /
                           oxcf.sect_sz;
        }
    } else {
        int64_t dd_bytes;

        if (xcopy_flag_dc)
            dd_bytes = dd_count * oxcf.sect_sz;
        else
            dd_bytes = dd_count * ixcf.sect_sz;

        if (dd_bytes > ixcf.num_sect * ixcf.sect_sz) {
            pr2serr("access beyond end of source device (max %" PRId64 ")\n",
                    ixcf.num_sect);
            return SG_LIB_SYNTAX_ERROR;
        }
        if (dd_bytes > oxcf.num_sect * oxcf.sect_sz) {
            pr2serr("access beyond end of target device (max %" PRId64 ")\n",
                    oxcf.num_sect);
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    res = scsi_operating_parameter(&ixcf, 0);
    if (res < 0) {
        if (SG_LIB_CAT_UNIT_ATTENTION == -res) {
            pr2serr("Unit attention (%s), continuing\n",
                    rec_copy_op_params_str);
            res = scsi_operating_parameter(&ixcf, 0);
        }
        if (-res == SG_LIB_CAT_INVALID_OP) {
            pr2serr("%s command not supported on %s\n",
                    rec_copy_op_params_str, ixcf.fname);
            ret = sg_convert_errno(EINVAL);
            goto fini;
        } else if (-res == SG_LIB_CAT_NOT_READY)
            pr2serr("%s failed on %s - not ready\n",
                    rec_copy_op_params_str, ixcf.fname);
        else {
            pr2serr("Unable to %s on %s\n", rec_copy_op_params_str,
                    ixcf.fname);
            ret = -res;
            goto fini;
        }
    } else if (res == 0) {
        ret = SG_LIB_CAT_INVALID_OP;
        goto fini;
    }

    if (res & TD_VPD) {
        if (verbose)
            pr2serr("  >> using VPD identification for source %s\n",
                    ixcf.fname);
        src_desc_len = desc_from_vpd_id(ixcf.sg_fd, src_desc,
                                 sizeof(src_desc), ixcf.sect_sz, ixcf.pad);
        if (src_desc_len > (int)sizeof(src_desc)) {
            pr2serr("source descriptor too large (%d bytes)\n", res);
            ret = SG_LIB_CAT_MALFORMED;
            goto fini;
        }
    } else {
        ret = SG_LIB_CAT_INVALID_OP;
        goto fini;
    }

    res = scsi_operating_parameter(&oxcf, 1);
    if (res < 0) {
        if (SG_LIB_CAT_UNIT_ATTENTION == -res) {
            pr2serr("Unit attention (%s), continuing\n",
                    rec_copy_op_params_str);
            res = scsi_operating_parameter(&oxcf, 1);
        }
        if (-res == SG_LIB_CAT_INVALID_OP) {
            pr2serr("%s command not supported on %s\n",
                    rec_copy_op_params_str, oxcf.fname);
            ret = sg_convert_errno(EINVAL);
            goto fini;
        } else if (-res == SG_LIB_CAT_NOT_READY)
            pr2serr("%s failed on %s - not ready\n",
                    rec_copy_op_params_str, oxcf.fname);
        else {
            pr2serr("Unable to %s on %s\n", rec_copy_op_params_str,
                    oxcf.fname);
            ret = -res;
            goto fini;
        }
    } else if (res == 0) {
        ret = SG_LIB_CAT_INVALID_OP;
        goto fini;
    }

    if (res & TD_VPD) {
        if (verbose)
            pr2serr("  >> using VPD identification for destination %s\n",
                    oxcf.fname);
        dst_desc_len = desc_from_vpd_id(oxcf.sg_fd, dst_desc,
                                 sizeof(dst_desc), oxcf.sect_sz, oxcf.pad);
        if (dst_desc_len > (int)sizeof(dst_desc)) {
            pr2serr("destination descriptor too large (%d bytes)\n", res);
            ret = SG_LIB_CAT_MALFORMED;
            goto fini;
        }
    } else {
        ret = SG_LIB_CAT_INVALID_OP;
        goto fini;
    }

    if (dd_count < 0) {
        pr2serr("Couldn't calculate count, please give one\n");
        return SG_LIB_CAT_OTHER;
    }

    if (dd_count < (ixcf.min_bytes / (uint32_t)ixcf.sect_sz)) {
        pr2serr("not enough data to read (min %" PRIu32 " bytes)\n",
                oxcf.min_bytes);
        return SG_LIB_CAT_OTHER;
    }
    if (dd_count < (oxcf.min_bytes / (uint32_t)oxcf.sect_sz)) {
        pr2serr("not enough data to write (min %" PRIu32 " bytes)\n",
                oxcf.min_bytes);
        return SG_LIB_CAT_OTHER;
    }

    if (bpt_given) {
        if (xcopy_flag_dc) {
            if ((uint32_t)(bpt * oxcf.sect_sz) > oxcf.max_bytes) {
                pr2serr("bpt too large (max %" PRIu32 " blocks)\n",
                        oxcf.max_bytes / (uint32_t)oxcf.sect_sz);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else {
            if ((uint32_t)(bpt * ixcf.sect_sz) > ixcf.max_bytes) {
                pr2serr("bpt too large (max %" PRIu32 " blocks)\n",
                        ixcf.max_bytes / (uint32_t)ixcf.sect_sz);
                return SG_LIB_SYNTAX_ERROR;
            }
        }
    } else {
        uint32_t r;

        if (xcopy_flag_dc)
            r = oxcf.max_bytes / (uint32_t)oxcf.sect_sz;
        else
            r = ixcf.max_bytes / (uint32_t)ixcf.sect_sz;
        bpt = (r > MAX_BLOCKS_PER_TRANSFER) ? MAX_BLOCKS_PER_TRANSFER : r;
    }

    seg_desc_type = seg_desc_from_dd_type(simplified_ft(&ixcf), 0,
                                          simplified_ft(&oxcf), 0);

    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
        start_tm_valid = true;
    }

    if (verbose)
        pr2serr("Start of loop, count=%" PRId64 ", bpt=%d, lba_in=%" PRId64
                ", lba_out=%" PRId64 "\n", dd_count, bpt, skip, seek);

    xcopy_fd = (on_src) ? infd : outfd;

    while (dd_count > 0) {
        if (dd_count > bpt)
            blocks = bpt;
        else
            blocks = dd_count;
        res = scsi_extended_copy(xcopy_fd, list_id, src_desc, src_desc_len,
                                 dst_desc, dst_desc_len, seg_desc_type,
                                 blocks, skip, seek);
        if (res != 0)
            break;
        in_full += blocks;
        skip += blocks;
        seek += blocks;
        dd_count -= blocks;
        num_xcopy++;
    }

    if (do_time)
        calc_duration_throughput(0);
    if (res)
        pr2serr("sg_xcopy: failed with error %d (%" PRId64 " blocks left)\n",
                res, dd_count);
    else
        pr2serr("sg_xcopy: %" PRId64 " blocks, %d command%s\n", in_full,
                num_xcopy, ((num_xcopy > 1) ? "s" : ""));
    ret = res;

fini:
    /* file handles not explicitly closed; let process cleanup do that */
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_xcopy failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
