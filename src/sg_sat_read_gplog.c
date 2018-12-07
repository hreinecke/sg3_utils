/*
 * Copyright (c) 2014-2018 Hannes Reinecke, SUSE Linux GmbH.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* This program uses a ATA PASS-THROUGH SCSI command. This usage is
 * defined in the SCSI to ATA Translation (SAT) drafts and standards.
 * See http://www.t10.org for drafts. SAT is a standard: SAT ANSI INCITS
 * 431-2007 (draft prior to that is sat-r09.pdf). SAT-2 is also a
 * standard: SAT-2 ANSI INCITS 465-2010 and the draft prior to that is
 * sat2r09.pdf . The SAT-3 project has started and the most recent draft
 * is sat3r01.pdf .
 */

/* This program performs a ATA PASS-THROUGH (16) SCSI command in order
 * to perform an ATA READ LOG EXT or ATA READ LOG DMA EXT command.
 *
 * See man page (sg_sat_read_gplog.8) for details.
 */

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_PASS_THROUGH12 0xa1     /* clashes with MMC BLANK command */
#define SAT_ATA_PASS_THROUGH12_LEN 12
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */
#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d

#define ATA_READ_LOG_EXT 0x2f
#define ATA_READ_LOG_DMA_EXT 0x47

#define DEF_TIMEOUT 20

static const char * version_str = "1.20 20180628";

struct opts_t {
    bool ck_cond;
    bool rdonly;
    int cdb_len;
    int count;
    int hex;
    int la;             /* log address */
    int pn;             /* page number within log address */
    int verbose;
    const char * device_name;
};

static struct option long_options[] = {
    {"count", required_argument, 0, 'c'},
    {"ck_cond", no_argument, 0, 'C'},
    {"ck-cond", no_argument, 0, 'C'},
    {"dma", no_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"len", required_argument, 0, 'l'},
    {"log", required_argument, 0, 'L'},
    {"page", required_argument, 0, 'p'},
    {"readonly", no_argument, 0, 'r'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
          "sg_sat_read_gplog [--ck_cond] [--count=CO] [--dma] [--help]\n"
          "                         [--hex] [--len=16|12] [--log=LA] "
          "[--page=PN]\n"
          "                         [--readonly] [--verbose] [--version] "
          "DEVICE\n"
          "  where:\n"
          "    --ck_cond | -C          set ck_cond field in pass-through "
          "(def: 0)\n"
          "    --count=CO | -c CO      block count (def: 1)\n"
          "    --dma | -d              Use READ LOG DMA EXT (def: READ LOG "
          "EXT)\n"
          "    --help | -h             output this usage message\n"
          "    --hex | -H              output response in hex bytes, -HH "
          "yields hex\n"
          "                            words + ASCII (def), -HHH hex words "
          "only\n"
          "    --len=16|12 | -l 16|12    cdb length: 16 or 12 bytes "
          "(def: 16)\n"
          "    --log=LA | -L LA        Log address to be read (def: 0)\n"
          "    --page=PN|-p PN         Log page number within address (def: "
          "0)\n"
          "    --readonly | -r         open DEVICE read-only (def: "
          "read-write)\n"
          "    --verbose | -v          increase verbosity\n"
          "                            recommended if DEVICE is ATA disk\n"
          "    --version | -V          print version string and exit\n\n"
          "Sends an ATA READ LOG EXT (or READ LOG DMA EXT) command via a "
          "SAT pass\nthrough to fetch a General Purpose (GP) log page. Each "
          "page is accessed\nvia a log address and then a page number "
          "within that address: LA,PN .\n"
          "By default the output is the response in hex (16 bit) words.\n"
           );
}

static int
do_read_gplog(int sg_fd, int ata_cmd, uint8_t *inbuff,
              const struct opts_t * op)
{
    const bool extend = true;
    const bool t_dir = true; /* false -> to device, true -> from device */
    const bool byte_block = true;/* false -> bytes, true -> 512 byte blocks */
    const bool t_type = false; /* false -> 512 byte blocks, true -> logical
                                  sectors */
    bool got_ard = false;      /* got ATA result descriptor */
    int res, ret;
    int protocol;
    int t_length = 2;   /* 0 -> no data transferred, 2 -> sector count */
    int resid = 0;
    int sb_sz;
    struct sg_scsi_sense_hdr ssh;
    uint8_t sense_buffer[64];
    uint8_t ata_return_desc[16];
    uint8_t apt_cdb[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t apt12_cdb[SAT_ATA_PASS_THROUGH12_LEN] =
                {SAT_ATA_PASS_THROUGH12, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0};
    char cmd_name[32];

    snprintf(cmd_name, sizeof(cmd_name), "ATA PASS-THROUGH (%d)",
             op->cdb_len);
    if (ata_cmd == ATA_READ_LOG_DMA_EXT) {
        protocol = 6; /* DMA */
    } else {
        protocol = 4; /* PIO Data-In */
    }
    sb_sz = sizeof(sense_buffer);
    memset(sense_buffer, 0, sb_sz);
    memset(ata_return_desc, 0, sizeof(ata_return_desc));
    memset(inbuff, 0, op->count * 512);
    if (op->verbose > 1)
        pr2serr("Building ATA READ LOG%s EXT command; la=0x%x, pn=0x%x\n",
                ((ata_cmd == ATA_READ_LOG_DMA_EXT) ? " DMA" : ""), op->la,
                op->pn);
    if (op->cdb_len == 16) {
        /* Prepare ATA PASS-THROUGH COMMAND (16) command */
        apt_cdb[14] = ata_cmd;
        sg_put_unaligned_be16((uint16_t)op->count, apt_cdb + 5);
        apt_cdb[8] = op->la;
        sg_put_unaligned_be16((uint16_t)op->pn, apt_cdb + 9);
        apt_cdb[1] = (protocol << 1) | extend;
        if (extend)
            apt_cdb[1] |= 0x1;
        apt_cdb[2] = t_length;
        if (op->ck_cond)
            apt_cdb[2] |= 0x20;
        if (t_type)
            apt_cdb[2] |= 0x10;
        if (t_dir)
            apt_cdb[2] |= 0x8;
        if (byte_block)
            apt_cdb[2] |= 0x4;
        res = sg_ll_ata_pt(sg_fd, apt_cdb, op->cdb_len, DEF_TIMEOUT, inbuff,
                           NULL, op->count * 512, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, op->verbose);
    } else {
        /* Prepare ATA PASS-THROUGH COMMAND (12) command */
        /* Cannot map upper 8 bits of the pn since no LBA (39:32) field */
        apt12_cdb[9] = ata_cmd;
        apt12_cdb[4] = op->count;
        apt12_cdb[5] = op->la;
        apt12_cdb[6] = op->pn & 0xff;
        /* apt12_cdb[7] = (op->pn >> 8) & 0xff; */
        apt12_cdb[1] = (protocol << 1);
        apt12_cdb[2] = t_length;
        if (op->ck_cond)
            apt12_cdb[2] |= 0x20;
        if (t_type)
            apt12_cdb[2] |= 0x10;
        if (t_dir)
            apt12_cdb[2] |= 0x8;
        if (byte_block)
            apt12_cdb[2] |= 0x4;
        res = sg_ll_ata_pt(sg_fd, apt12_cdb, op->cdb_len, DEF_TIMEOUT,
                           inbuff, NULL, op->count * 512, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, op->verbose);
    }
    if (0 == res) {
        if (op->verbose > 2)
            pr2serr("command completed with SCSI GOOD status\n");
        if ((0 == op->hex) || (2 == op->hex))
            dWordHex((const unsigned short *)inbuff, op->count * 256, 0,
                     sg_is_big_endian());
        else if (1 == op->hex)
            hex2stdout(inbuff, 512, 0);
        else if (3 == op->hex)  /* '-HHH' suitable for "hdparm --Istdin" */
            dWordHex((const unsigned short *)inbuff, 256, -2,
                     sg_is_big_endian());
        else    /* '-HHHH' hex bytes only */
            hex2stdout(inbuff, 512, -1);
    } else if ((res > 0) && (res & SAM_STAT_CHECK_CONDITION)) {
        if (op->verbose > 1) {
            pr2serr("ATA pass through:\n");
            sg_print_sense(NULL, sense_buffer, sb_sz,
                           ((op->verbose > 2) ? 1 : 0));
        }
        if (sg_scsi_normalize_sense(sense_buffer, sb_sz, &ssh)) {
            switch (ssh.sense_key) {
            case SPC_SK_ILLEGAL_REQUEST:
                if ((0x20 == ssh.asc) && (0x0 == ssh.ascq)) {
                    ret = SG_LIB_CAT_INVALID_OP;
                    if (op->verbose < 2)
                        pr2serr("%s not supported\n", cmd_name);
                } else {
                    ret = SG_LIB_CAT_ILLEGAL_REQ;
                    if (op->verbose < 2)
                        pr2serr("%s, bad field in cdb\n", cmd_name);
                }
                return ret;
            case SPC_SK_NO_SENSE:
            case SPC_SK_RECOVERED_ERROR:
                if ((0x0 == ssh.asc) &&
                    (ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq)) {
                    if (SAT_ATA_RETURN_DESC != ata_return_desc[0]) {
                        if (op->verbose)
                            pr2serr("did not find ATA Return (sense) "
                                    "Descriptor\n");
                        return SG_LIB_CAT_RECOVERED;
                    }
                    got_ard = true;
                    break;
                } else if (SPC_SK_RECOVERED_ERROR == ssh.sense_key)
                    return SG_LIB_CAT_RECOVERED;
                else {
                    if ((0x0 == ssh.asc) && (0x0 == ssh.ascq))
                        break;
                    return SG_LIB_CAT_SENSE;
                }
            case SPC_SK_UNIT_ATTENTION:
                if (op->verbose < 2)
                    pr2serr("%s, Unit Attention detected\n", cmd_name);
                return SG_LIB_CAT_UNIT_ATTENTION;
            case SPC_SK_NOT_READY:
                if (op->verbose < 2)
                    pr2serr("%s, device not ready\n", cmd_name);
                return SG_LIB_CAT_NOT_READY;
            case SPC_SK_MEDIUM_ERROR:
            case SPC_SK_HARDWARE_ERROR:
                if (op->verbose < 2)
                    pr2serr("%s, medium or hardware error\n", cmd_name);
                return SG_LIB_CAT_MEDIUM_HARD;
            case SPC_SK_ABORTED_COMMAND:
                if (0x10 == ssh.asc) {
                    pr2serr("Aborted command: protection information\n");
                    return SG_LIB_CAT_PROTECTION;
                } else {
                    pr2serr("Aborted command\n");
                    return SG_LIB_CAT_ABORTED_COMMAND;
                }
            case SPC_SK_DATA_PROTECT:
                pr2serr("%s: data protect, read only media?\n", cmd_name);
                return SG_LIB_CAT_DATA_PROTECT;
            default:
                if (op->verbose < 2)
                    pr2serr("%s, some sense data, use '-v' for more "
                            "information\n", cmd_name);
                return SG_LIB_CAT_SENSE;
            }
        } else {
            pr2serr("CHECK CONDITION without response code ??\n");
            return SG_LIB_CAT_SENSE;
        }
        if (0x72 != (sense_buffer[0] & 0x7f)) {
            pr2serr("expected descriptor sense format, response "
                    "code=0x%x\n", sense_buffer[0]);
            return SG_LIB_CAT_MALFORMED;
        }
    } else if (res > 0) {
        if (SAM_STAT_RESERVATION_CONFLICT == res) {
            pr2serr("SCSI status: RESERVATION CONFLICT\n");
            return SG_LIB_CAT_RES_CONFLICT;
        } else {
            pr2serr("Unexpected SCSI status=0x%x\n", res);
            return SG_LIB_CAT_MALFORMED;
        }
    } else {
        pr2serr("%s failed\n", cmd_name);
        if (op->verbose < 2)
            pr2serr("    try adding '-v' for more information\n");
        return -1;
    }

    if ((SAT_ATA_RETURN_DESC == ata_return_desc[0]) && (! got_ard))
        pr2serr("Seem to have got ATA Result Descriptor but it was not "
                "indicated\n");
    if (got_ard) {
        if (ata_return_desc[3] & 0x4) {
                pr2serr("error indication in returned FIS: aborted "
                        "command\n");
                return SG_LIB_CAT_ABORTED_COMMAND;
        }
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool verbose_given = false;
    bool version_given = false;
    int c, ret, res, n;
    int sg_fd = -1;
    int ata_cmd = ATA_READ_LOG_EXT;
    uint8_t *inbuff = NULL;
    uint8_t *free_inbuff = NULL;
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->cdb_len = SAT_ATA_PASS_THROUGH16_LEN;
    op->count = 1;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "c:CdhHl:L:p:rvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            op->count = sg_get_num(optarg);
            if ((op->count < 1) || (op->count > 0xffff)) {
                pr2serr("bad argument for '--count'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'C':
            op->ck_cond = true;
            break;
        case 'd':
            ata_cmd = ATA_READ_LOG_DMA_EXT;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++op->hex;
            break;
        case 'l':
           op->cdb_len = sg_get_num(optarg);
           if (! ((op->cdb_len == 12) || (op->cdb_len == 16))) {
                pr2serr("argument to '--len' should be 12 or 16\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'L':
            op->la = sg_get_num(optarg);
            if (op->la < 0 || op->la > 0xff) {
                pr2serr("bad argument for '--log'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            op->pn = sg_get_num(optarg);
            if ((op->pn < 0) || (op->pn > 0xffff)) {
                pr2serr("bad argument for '--page'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            op->rdonly = true;
            break;
        case 'v':
            verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            version_given = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == op->device_name) {
            op->device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n",
                        argv[optind]);
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
        op->verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (NULL == op->device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return 1;
    }

    if ((op->count > 0xff) && (12 == op->cdb_len)) {
        op->cdb_len = 16;
        if (op->verbose)
            pr2serr("Since count > 0xff, forcing cdb length to "
                    "16\n");
    }

    n = op->count * 512;
    inbuff = (uint8_t *)sg_memalign(n, 0, &free_inbuff, op->verbose > 3);
    if (!inbuff) {
        pr2serr("Cannot allocate output buffer of size %d\n", n);
        return SG_LIB_CAT_OTHER;
    }

    if ((sg_fd = sg_cmds_open_device(op->device_name, op->rdonly,
                                     op->verbose)) < 0) {
        if (op->verbose)
            pr2serr("error opening file: %s: %s\n", op->device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    ret = do_read_gplog(sg_fd, ata_cmd, inbuff, op);

fini:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_sat_read_gplog failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    if (free_inbuff)
        free(free_inbuff);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
