/*
 * Copyright (c) 2017 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.01 20171008";


#define ME "sg_write_atomic: "

#define WRITE_ATOMIC16_OP 0x9c
#define WRITE_16_OP 0x8a
#define VARIABLE_LEN_OP 0x7f
#define WRITE_ATOMIC32_SA 0xf
#define WRITE_32_SA 0xb
#define WRITE_ATOMIC32_ADD 0x18
#define WRITE_32_ADD 0x18
#define WRITE_ATOMIC16_LEN 16
#define WRITE_ATOMIC32_LEN 32
#define WRITE_16_LEN 16
#define WRITE_32_LEN 32
#define RCAP10_RESP_LEN 8
#define RCAP16_RESP_LEN 32
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_TIMEOUT_SECS 120    /* might need more for large NUM */
#define DEF_WA_CDB_SIZE WRITE_ATOMIC16_LEN
#define DEF_WA_NUMBLOCKS 0      /* do nothing; for safety */
#define MAX_XFER_LEN (64 * 1024)
#define EBUFF_SZ 256

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif
#ifndef UINT16_MAX
#define UINT16_MAX ((uint16_t)-1)
#endif

static struct option long_options[] = {
    {"16", no_argument, 0, 'S'},
    {"32", no_argument, 0, 'T'},
    {"app-tag", required_argument, 0, 'a'},
    {"app_tag", required_argument, 0, 'a'},
    {"boundary", required_argument, 0, 'B'},
    {"bs", required_argument, 0, 'b'},
    {"dld", required_argument, 0, 'D'},
    {"dpo", no_argument, 0, 'd'},
    {"fua", no_argument, 0, 'f'},
    {"grpnum", required_argument, 0, 'g'},
    {"help", no_argument, 0, 'h'},
    {"in", required_argument, 0, 'i'},
    {"lba", required_argument, 0, 'l'},
    {"non-atomic", no_argument, 0, 'N'},
    {"non_atomic", no_argument, 0, 'N'},
    {"num", required_argument, 0, 'n'},
    {"offset", required_argument, 0, 'o'},
    {"ref-tag", required_argument, 0, 'r'},
    {"ref_tag", required_argument, 0, 'r'},
    {"strict", no_argument, 0, 's'},
    {"tag-mask", required_argument, 0, 'M'},
    {"tag_mask", required_argument, 0, 'M'},
    {"timeout", required_argument, 0, 't'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"wrprotect", required_argument, 0, 'w'},
    {0, 0, 0, 0},
};

struct opts_t {
    bool do_16;
    bool do_32;
    bool dpo;
    bool fua;
    bool non_atomic;
    bool strict;
    int dld;            /* only used by WRITE(16) [why not WRITE(32) ?] */
    int grpnum;
    int timeout;
    int verbose;
    int wrprotect;
    uint16_t app_tag;
    uint16_t atomic_boundary;
    uint16_t tag_mask;
    uint32_t bs;        /* 0 implies use READ CAPACITY(10 or 16) */
    uint32_t numblocks;
    uint32_t ref_tag;
    uint64_t lba;
    uint64_t offset;
    ssize_t xfer_bytes;     /* derived value: bs*numblocks */
    const char * ifilename;
};



static void
usage()
{
    pr2serr("Usage: sg_write_atomic [--16] [--32] [--app-tag=AT] "
            "[--boundary=AB]\n"
            "                       [--bs=LBS] [--dld=DLD] [--dpo] "
            "[--fua] "
            "[--grpnum=GN]\n"
            "                       [--help] --in=IF [--lba=LBA] "
            "[--non-atomic] [--num=NUM]\n"
            "                       [--offset=OFF] [--ref-tag=RT] "
            "[--strict]\n"
            "                       [--tag-mask=TM] [--timeout=TO] "
            "[--verbose] [--version]\n"
            "                       [--wrprotect=WRP] DEVICE\n"
            "  where:\n"
            "    --16|-S              send WRITE ATOMIC(16) or WRITE(16) "
            "(default)\n"
            "    --32|-T              send WRITE ATOMIC(32) or WRITE(32)\n"
            "    --app-tag=AT|-a AT     set expected application tag field "
            "in 32 cdb\n"
            "    --boundary=AB|-B AB    set atomic boundary field\n"
            "    --bs=LBS|-b LBS      logical block size (def: use READ "
            "CAPACITY)\n"
            "    --dld=DLD|-D DLD     set duration limit descriptor (dld) "
            "(def: 0)\n"
            "    --dpo|-d             set DPO (disable page out) field "
            "(def: clear)\n"
            "    --fua|-f             set FUA (force unit access) field "
            "(def: clear)\n"
            "    --grpnum=GN|-g GN    GN is group number field (def: 0)\n"
            "    --help|-h            print out usage message\n"
            "    --in=IF|-i IF        IF is file to fetch NUM blocks of "
            "data from.\n"
            "                         Blocks written to DEVICE\n"
            "    --lba=LBA|-l LBA     LBA is the logical block address to "
            "start (def: 0)\n"
            "    --non-atomic|-N      do normal WRITE(16) or WRITE(32) "
            "(def: send\n"
            "                         WRITE ATOMIC(16 or 32)\n"
            "    --num=NUM|-n NUM     NUM is number of logical blocks to "
            "write (def: 0)\n"
            "    --offset=OFF|-o OFF    byte offset in IF to start reading "
            "from\n"
            "    --ref-tag=RT|-r RT     set expected reference tag field in "
            "32 byte cdb\n"
            "    --strict|-s          exit if read less than requested from "
            "IF\n"
            "    --tag-mask=TM|-M TM    set tag mask field in 32 byte cdb\n"
            "    --timeout=TO|-t TO    command timeout (unit: seconds) (def: "
            "120)\n"
            "    --verbose|-v         increase verbosity\n"
            "    --version|-V         print version string then exit\n"
            "    --wrprotect=WPR|-w WPR    WPR is the WRPROTECT field value "
            "(def: 0)\n\n"
            "Performs a SCSI WRITE ATOMIC (16 or 32) command. The --in=IF "
            "option is\nrequired. If --non-atomic option is given then "
            "normal WRITE(16 or 32)\nis performed. The --num=NUM field "
            "defaults to 0 (do nothing) for safety.\n"
            );
}

static int
do_write_atomic(int sg_fd, const struct opts_t * op, const void * dataoutp)
{
    int k, ret, res, sense_cat, cdb_len;
    unsigned char wa_cdb[WRITE_ATOMIC32_LEN];
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    cdb_len = op->do_16 ? WRITE_ATOMIC16_LEN : WRITE_ATOMIC32_LEN;
    if (WRITE_ATOMIC16_LEN == cdb_len) {
        if (op->numblocks > UINT16_MAX) {
            pr2serr("Need WRITE ATOMIC(32) since blocks exceed 65535\n");
            return -1;
        }
    }
    memset(wa_cdb, 0, sizeof(wa_cdb));
    switch (cdb_len) {
    case WRITE_ATOMIC16_LEN:
        wa_cdb[0] = WRITE_ATOMIC16_OP;
        wa_cdb[1] = ((op->wrprotect & 0x7) << 5);
        if (op->dpo)
            wa_cdb[1] |= 0x10;
        if (op->fua)
            wa_cdb[1] |= 0x8;
        sg_put_unaligned_be64(op->lba, wa_cdb + 2);
        sg_put_unaligned_be16(op->atomic_boundary, wa_cdb + 10);
        sg_put_unaligned_be16((uint16_t)op->numblocks, wa_cdb + 12);
        wa_cdb[14] = (op->grpnum & 0x1f);
        break;
    case WRITE_ATOMIC32_LEN:
        wa_cdb[0] = VARIABLE_LEN_OP;
        sg_put_unaligned_be16(op->atomic_boundary, wa_cdb + 4);
        wa_cdb[6] = (op->grpnum & 0x1f);
        wa_cdb[7] = WRITE_ATOMIC32_ADD;
        sg_put_unaligned_be16((uint16_t)WRITE_ATOMIC32_SA, wa_cdb + 8);
        wa_cdb[10] = ((op->wrprotect & 0x7) << 5);
        if (op->dpo)
            wa_cdb[10] |= 0x10;
        if (op->fua)
            wa_cdb[10] |= 0x8;
        sg_put_unaligned_be64(op->lba, wa_cdb + 12);
        sg_put_unaligned_be32(op->ref_tag, wa_cdb + 20);
        sg_put_unaligned_be16(op->app_tag, wa_cdb + 24);
        sg_put_unaligned_be16(op->tag_mask, wa_cdb + 26);
        sg_put_unaligned_be32(op->numblocks, wa_cdb + 28);
        break;
    default:
        pr2serr("do_write_atomic: bad cdb length %d\n", cdb_len);
        return -1;
    }

    if (op->verbose > 1) {
        pr2serr("    Write atomic(%d) cdb: ", cdb_len);
        for (k = 0; k < cdb_len; ++k)
            pr2serr("%02x ", wa_cdb[k]);
        pr2serr("\n");
    }
    if ((op->verbose > 3) && (op->xfer_bytes > 0)) {
        pr2serr("    Data-out buffer contents:\n");
        dStrHexErr((const char *)dataoutp, op->xfer_bytes, 1);
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Write atomic(%d): out of memory\n", cdb_len);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, wa_cdb, cdb_len);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)dataoutp, op->xfer_bytes);
    res = do_scsi_pt(ptvp, sg_fd, op->timeout, op->verbose);
    ret = sg_cmds_process_resp(ptvp, "Write atomic", res, SG_NO_DATA_IN,
                               sense_b, true /*noisy */, op->verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            {
                bool valid;
                int slen;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                if (valid)
                    pr2serr("Medium or hardware error starting at lba=%"
                            PRIu64 " [0x%" PRIx64 "]\n", ull, ull);
            }
            ret = sense_cat;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static int
do_write_normal(int sg_fd, const struct opts_t * op, const void * dataoutp)
{
    int k, ret, res, sense_cat, cdb_len;
    unsigned char wr_cdb[WRITE_32_LEN];
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    cdb_len = op->do_16 ? WRITE_16_LEN : WRITE_32_LEN;
    if (WRITE_16_LEN == cdb_len) {
        if (op->numblocks > UINT16_MAX) {
            pr2serr("Need WRITE(32) since blocks exceed 65535\n");
            return -1;
        }
    }
    memset(wr_cdb, 0, sizeof(wr_cdb));
    switch (cdb_len) {
    case WRITE_16_LEN:
        wr_cdb[0] = WRITE_16_OP;
        wr_cdb[1] = ((op->wrprotect & 0x7) << 5);
        if (op->dpo)
            wr_cdb[1] |= 0x10;
        if (op->fua)
            wr_cdb[1] |= 0x8;
        if (op->dld) {
            if (op->dld & 1)
                wr_cdb[14] |= 0x40;
            if (op->dld & 2)
                wr_cdb[14] |= 0x80;
            if (op->dld & 4)
                wr_cdb[1] |= 0x1;
        }
        sg_put_unaligned_be64(op->lba, wr_cdb + 2);
        sg_put_unaligned_be32(op->numblocks, wr_cdb + 10);
        wr_cdb[14] = (op->grpnum & 0x1f);
        break;
    case WRITE_32_LEN:
        wr_cdb[0] = VARIABLE_LEN_OP;
        wr_cdb[6] = (op->grpnum & 0x1f);
        wr_cdb[7] = WRITE_32_ADD;
        sg_put_unaligned_be16((uint16_t)WRITE_32_SA, wr_cdb + 8);
        wr_cdb[10] = ((op->wrprotect & 0x7) << 5);
        if (op->dpo)
            wr_cdb[10] |= 0x10;
        if (op->fua)
            wr_cdb[10] |= 0x8;
        sg_put_unaligned_be64(op->lba, wr_cdb + 12);
        sg_put_unaligned_be32(op->ref_tag, wr_cdb + 20);
        sg_put_unaligned_be16(op->app_tag, wr_cdb + 24);
        sg_put_unaligned_be16(op->tag_mask, wr_cdb + 26);
        sg_put_unaligned_be32(op->numblocks, wr_cdb + 28);
        break;
    default:
        pr2serr("%s: bad cdb length %d\n", __func__, cdb_len);
        return -1;
    }

    if (op->verbose > 1) {
        pr2serr("    Write(%d) cdb: ", cdb_len);
        for (k = 0; k < cdb_len; ++k)
            pr2serr("%02x ", wr_cdb[k]);
        pr2serr("\n");
    }
    if ((op->verbose > 3) && (op->xfer_bytes > 0)) {
        pr2serr("    Data-out buffer contents:\n");
        dStrHexErr((const char *)dataoutp, op->xfer_bytes, 1);
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Write(%d): out of memory\n", cdb_len);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, wr_cdb, cdb_len);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)dataoutp, op->xfer_bytes);
    res = do_scsi_pt(ptvp, sg_fd, op->timeout, op->verbose);
    ret = sg_cmds_process_resp(ptvp, "Write", res, SG_NO_DATA_IN, sense_b,
                               true /*noisy */, op->verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            {
                bool valid;
                int slen;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                if (valid)
                    pr2serr("Medium or hardware error starting at lba=%"
                            PRIu64 " [0x%" PRIx64 "]\n", ull, ull);
            }
            ret = sense_cat;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}


int
main(int argc, char * argv[])
{
    bool prot_en;
    bool got_stdin = false;
    int c, j, vb;
    int infd = -1;
    int sg_fd = -1;
    int ret = -1;
    ssize_t res;
    int64_t ll;
    const char * device_name = NULL;
    struct opts_t * op;
    unsigned char * wBuff = NULL;
    char ebuff[EBUFF_SZ];
    char b[80];
    unsigned char resp_buff[RCAP16_RESP_LEN];
    struct opts_t opts;

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->numblocks = DEF_WA_NUMBLOCKS;
    op->timeout = DEF_TIMEOUT_SECS;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "a:b:B:dD:fg:hi:l:M:n:No:r:sSt:TvVw:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            j = sg_get_num(optarg);
            if ((j < 0) || (j > UINT16_MAX)) {
                pr2serr("bad argument to '--app-tag='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->app_tag = (uint16_t)j;
            break;
        case 'b':                        /* logical block size in bytes */
            j = sg_get_num(optarg); /* 0 -> look up with READ CAPACITY */
            if ((j < 0) || (j > (1 << 28))) {
                pr2serr("bad argument to '--bs='. Expect 0 or greater\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->bs = (uint32_t)j;
            break;
        case 'B':       /* atomic boundary */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > UINT16_MAX)) {
                pr2serr("bad argument to '--boundary='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->atomic_boundary = (uint16_t)j;
            break;
        case 'd':
            op->dpo = true;
            break;
        case 'D':
            op->dld = sg_get_num(optarg);
            if ((op->dld < 0) || (op->dld > 7))  {
                pr2serr("bad argument to '--dld=', expect 0 to 7 "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'f':
            op->fua = true;
            break;
        case 'g':
            op->grpnum = sg_get_num(optarg);
            if ((op->grpnum < 0) || (op->grpnum > 63))  {
                pr2serr("bad argument to '--grpnum'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            op->ifilename = optarg;
            break;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--lba='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->lba = (uint64_t)ll;
            break;
        case 'M':               /* same as --tag-mask= */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > UINT16_MAX)) {
                pr2serr("bad argument to '--tag-mask='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->tag_mask = (uint16_t)j;
            break;
        case 'n':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX))  {
                pr2serr("bad argument to '--num='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->numblocks = (uint32_t)ll;
            break;
        case 'N':
            op->non_atomic = true;
            break;
        case 'o':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--offset='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->offset = (uint64_t)ll;
            break;
        case 'r':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--ref-tag='. Expect 0 to "
                        "0xffffffff inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->ref_tag = (uint32_t)ll;
            break;
        case 's':
            op->strict = true;
            break;
        case 'S':       /* same as --16 */
            op->do_16 = true;
            break;
        case 't':
            op->timeout = sg_get_num(optarg);
            if (op->timeout < 0)  {
                pr2serr("bad argument to '--timeout='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'T':       /* same as --32 */
            op->do_32 = true;
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
        case 'w':
            op->wrprotect = sg_get_num(optarg);
            if ((op->wrprotect < 0) || (op->wrprotect > 7))  {
                pr2serr("bad argument to '--wrprotect'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if ((! op->do_16) && (! op->do_32)) {
        op->do_16 = true;
        if (op->verbose > 1)
            pr2serr("Since neither --16 nor --32 given, choose --16\n");
    } else if (op->do_16 && op->do_32) {
        op->do_16 = false;
        if (op->verbose > 1)
            pr2serr("Since both --16 and --32 given, choose --32\n");
    }
    if (NULL == op->ifilename) {
        pr2serr("Need --if=FN option to be given, exiting. Add -h for "
                "help\n");
        if (op->verbose > 1)
            pr2serr("To write zeros use --in=/dev/zero\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    vb = op->verbose;
    if (vb) {
        if (op->do_16 && (op->app_tag | op->ref_tag | op->tag_mask))
            pr2serr("--app-tag=, --ref-tag= and --tag-mask= options ignored "
                    "with 16 byte commands\n");
        if (op->non_atomic)
            pr2serr("Doing normal (non-atomic) WRITE(%d) because "
                    "--non-atomic option given\n", op->do_16 ? 16 : 32);
    }
    if ((1 == strlen(op->ifilename)) && ('-' == op->ifilename[0]))
        got_stdin = true;
    if (got_stdin) {
        infd = STDIN_FILENO;
        if (sg_set_binary_mode(STDIN_FILENO) < 0)
            perror("sg_set_binary_mode");
    } else {
        if ((infd = open(op->ifilename, O_RDONLY)) < 0) {
            snprintf(ebuff, EBUFF_SZ, "could not open %s for reading",
                     op->ifilename);
            perror(ebuff);
            return SG_LIB_FILE_ERROR;
        } else if (sg_set_binary_mode(infd) < 0)
            perror("sg_set_binary_mode");
    }
    if (op->offset > 0) {
        off64_t off = op->offset;

/* lseek64() won't work with stdin or pipes, for example */
        if (lseek64(infd, off, SEEK_SET) < 0) {
            snprintf(ebuff,  EBUFF_SZ,
                "couldn't offset to required position on %s",
                 op->ifilename);
            perror(ebuff);
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, false /* rw */, vb);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (0 == op->bs) {  /* ask DEVICE about logical/actual block size */
        res = sg_ll_readcap_16(sg_fd, false /* pmi */, 0 /* llba */,
                               resp_buff, RCAP16_RESP_LEN, true,
                               (vb ? (vb - 1): 0));
        if (SG_LIB_CAT_UNIT_ATTENTION == res) {
            pr2serr("Read capacity(16) unit attention, try again\n");
            res = sg_ll_readcap_16(sg_fd, false, 0, resp_buff,
                                   RCAP16_RESP_LEN, true,
                                   (vb ? (vb - 1): 0));
        }
        if (0 == res) {
            if (vb > 3)
                dStrHexErr((const char *)resp_buff, RCAP16_RESP_LEN, 1);
            op->bs = sg_get_unaligned_be32(resp_buff + 8);
            prot_en = !!(resp_buff[12] & 0x1);
            if (prot_en && (op->wrprotect > 0)) {
                op->bs += 8;
                if (vb > 1)
                    pr2serr("Bumping block size to %u (from %u) because "
                            "PROT_EN=1 and WRPROTECT>0\n", op->bs,
                            op->bs -8);
            }
        } else if ((SG_LIB_CAT_INVALID_OP == res) ||
                   (SG_LIB_CAT_ILLEGAL_REQ == res)) {
            if (vb)
                pr2serr("Read capacity(16) not supported, try Read "
                        "capacity(10)\n");
            res = sg_ll_readcap_10(sg_fd, false /* pmi */, 0 /* lba */,
                                   resp_buff, RCAP10_RESP_LEN, true,
                                   (vb ? (vb - 1): 0));
            if (0 == res) {
                if (vb > 3)
                    dStrHexErr((const char *)resp_buff, RCAP10_RESP_LEN, 1);
                op->bs = sg_get_unaligned_be32(resp_buff + 4);
            } else {
                sg_get_category_sense_str(res, sizeof(b), b, vb);
                pr2serr("Read capacity(10): %s\n", b);
                pr2serr("Unable to calculate block size\n");
            }
        } else if (vb) {
            sg_get_category_sense_str(res, sizeof(b), b, vb);
            pr2serr("Read capacity(16): %s\n", b);
            pr2serr("Unable to calculate block size\n");
        }
    }
    op->xfer_bytes = op->numblocks * op->bs;

    if (op->xfer_bytes > 0) {
        /* fill allocated buffer with zeros */
        wBuff = (unsigned char*)calloc(op->numblocks, op->bs);
        if (NULL == wBuff) {
            pr2serr("unable to allocate %zd bytes of memory with "
                    "calloc()\n", op->xfer_bytes);
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        res = read(infd, wBuff, op->xfer_bytes);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, "couldn't read from %s", op->ifilename);
            perror(ebuff);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        if (op->strict && (res != op->xfer_bytes)) {
            if (vb)
                pr2serr("Wanted to read %zd bytes but got %zd bytes and "
                        "--strict given\n", op->xfer_bytes, res);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
    } else if (op->xfer_bytes < 0) {
        pr2serr("Product of block size (%" PRIu32 ") and number of blocks "
                "(%" PRIu32 ") too\nlarge for single read\n", op->bs,
                op->numblocks);
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }

    if (op->non_atomic)
        ret = do_write_normal(sg_fd, op, wBuff);
    else
        ret = do_write_atomic(sg_fd, op, wBuff);
    if (ret) {
        sg_get_category_sense_str(ret, sizeof(b), b, vb);
        pr2serr("Write%s(%d): %s\n", (op->non_atomic ? "" : " atomic"),
                op->do_16 ? 16 : 32, b);
    }

err_out:
    if (wBuff)
        free(wBuff);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("sg_fd close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                return SG_LIB_FILE_ERROR;
        }
    }
    if ((! got_stdin) && (infd >= 0)) {
        if (close(infd) < 0) {
            perror("infd close error");
            if (0 == ret)
                return SG_LIB_FILE_ERROR;
        }
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
