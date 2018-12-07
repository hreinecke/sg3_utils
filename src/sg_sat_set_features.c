/*
 * Copyright (c) 2006-2018 Douglas Gilbert.
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
 * to perform an ATA SET FEATURES command.
 *
 * See man page (sg_sat_set_features.8) for details.
 */

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_PASS_THROUGH12 0xa1     /* clashes with MMC BLANK command */
#define SAT_ATA_PASS_THROUGH12_LEN 12
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */
#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d

#define ATA_SET_FEATURES 0xef

#define DEF_TIMEOUT 20

static const char * version_str = "1.18 20180628";

static struct option long_options[] = {
    {"count", required_argument, 0, 'c'},
    {"ck_cond", no_argument, 0, 'C'},
    {"ck-cond", no_argument, 0, 'C'},
    {"extended", no_argument, 0, 'e'},
    {"feature", required_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
    {"len", required_argument, 0, 'l'},
    {"lba", required_argument, 0, 'L'},
    {"readonly", no_argument, 0, 'r'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_sat_set_features [--count=CO] [--ck_cond] [--extended] "
            "[--feature=FEA]\n"
            "                           [--help] [--lba=LBA] [--len=16|12] "
            "[--readonly]\n"
            "                           [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --count=CO | -c CO      count field contents (def: 0)\n"
            "    --ck_cond | -C          set ck_cond field in pass-through "
            "(def: 0)\n"
            "    --extended | -e         enable extended lba values\n"
            "    --feature=FEA|-f FEA    feature field contents\n"
            "                            (def: 0 (which is reserved))\n"
            "    --help | -h             output this usage message\n"
            "    --lba=LBA | -L LBA      LBA field contents (def: 0)\n"
            "                            meaning depends on sub-command "
            "(feature)\n"
            "    --len=16|12 | -l 16|12    cdb length: 16 or 12 bytes "
            "(def: 16)\n"
            "    --verbose | -v          increase verbosity\n"
            "    --readonly | -r         open DEVICE read-only (def: "
            "read-write)\n"
            "                            recommended if DEVICE is ATA disk\n"
            "    --version | -V          print version string and exit\n\n"
            "Sends an ATA SET FEATURES command via a SAT pass through.\n"
            "Primary feature code is placed in '--feature=FEA' with "
            "'--count=CO' and\n"
            "'--lba=LBA' being auxiliaries for some features.  The arguments "
            "CO, FEA\n"
            "and LBA are decimal unless prefixed by '0x' or have a trailing "
            "'h'.\n"
            "Example enabling write cache: 'sg_sat_set_feature --feature=2 "
            "/dev/sdc'\n");
}

static int
do_set_features(int sg_fd, int feature, int count, uint64_t lba,
                int cdb_len, bool ck_cond, bool extend, int verbose)
{
    const bool t_type = false;  /* false -> 512 byte blocks, true -> device's
                                   LB size */
    const bool t_dir = true;    /* false -> to device, true -> from device */
    const bool byte_block = true; /* false -> bytes, true -> 512 byte blocks
                                     (if t_type=false) */
    bool got_ard = false;       /* got ATA result descriptor */
    int res, ret;
    /* Following for ATA READ/WRITE MULTIPLE (EXT) cmds, normally 0 */
    int multiple_count = 0;
    int protocol = 3;   /* non-data */
    int t_length = 0;   /* 0 -> no data transferred, 2 -> sector count */
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

    sb_sz = sizeof(sense_buffer);
    memset(sense_buffer, 0, sb_sz);
    memset(ata_return_desc, 0, sizeof(ata_return_desc));
    if (16 == cdb_len) {
        /* Prepare ATA PASS-THROUGH COMMAND (16) command */
        apt_cdb[14] = ATA_SET_FEATURES;
        apt_cdb[4] = feature;
        apt_cdb[6] = count;
        apt_cdb[8] = lba & 0xff;
        apt_cdb[10] = (lba >> 8) & 0xff;
        apt_cdb[12] = (lba >> 16) & 0xff;
        apt_cdb[7] = (lba >> 24) & 0xff;
        apt_cdb[9] = (lba >> 32) & 0xff;
        apt_cdb[11] = (lba >> 40) & 0xff;
        apt_cdb[1] = (multiple_count << 5) | (protocol << 1);
        if (extend)
           apt_cdb[1] |= 0x1;
        apt_cdb[2] = t_length;
        if (ck_cond)
            apt_cdb[2] |= 0x20;
        if (t_type)
            apt_cdb[2] |= 0x10;
        if (t_dir)
            apt_cdb[2] |= 0x8;
        if (byte_block)
            apt_cdb[2] |= 0x4;
        res = sg_ll_ata_pt(sg_fd, apt_cdb, cdb_len, DEF_TIMEOUT, NULL,
                           NULL /* doutp */, 0, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, verbose);
    } else {
        /* Prepare ATA PASS-THROUGH COMMAND (12) command */
        apt12_cdb[9] = ATA_SET_FEATURES;
        apt12_cdb[3] = feature;
        apt12_cdb[4] = count;
        apt12_cdb[5] = lba & 0xff;
        apt12_cdb[6] = (lba >> 8) & 0xff;
        apt12_cdb[7] = (lba >> 16) & 0xff;
        apt12_cdb[1] = (multiple_count << 5) | (protocol << 1);
        apt12_cdb[2] = t_length;
        if (ck_cond)
            apt12_cdb[2] |= 0x20;
        if (t_type)
            apt12_cdb[2] |= 0x10;
        if (t_dir)
            apt12_cdb[2] |= 0x8;
        if (byte_block)
            apt12_cdb[2] |= 0x4;
        res = sg_ll_ata_pt(sg_fd, apt12_cdb, cdb_len, DEF_TIMEOUT, NULL,
                           NULL /* doutp */, 0, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, verbose);
    }
    if (0 == res) {
        if (verbose > 2)
            pr2serr("command completed with SCSI GOOD status\n");
    } else if ((res > 0) && (res & SAM_STAT_CHECK_CONDITION)) {
        if (verbose > 1) {
            pr2serr("ATA pass through:\n");
            sg_print_sense(NULL, sense_buffer, sb_sz,
                           ((verbose > 2) ? 1 : 0));
        }
        if (sg_scsi_normalize_sense(sense_buffer, sb_sz, &ssh)) {
            switch (ssh.sense_key) {
            case SPC_SK_ILLEGAL_REQUEST:
                if ((0x20 == ssh.asc) && (0x0 == ssh.ascq)) {
                    ret = SG_LIB_CAT_INVALID_OP;
                    if (verbose < 2)
                        pr2serr("ATA PASS-THROUGH (%d) not supported\n",
                                cdb_len);
                } else {
                    ret = SG_LIB_CAT_ILLEGAL_REQ;
                    if (verbose < 2)
                        pr2serr("ATA PASS-THROUGH (%d), bad field in cdb\n",
                                cdb_len);
                }
                return ret;
            case SPC_SK_NO_SENSE:
            case SPC_SK_RECOVERED_ERROR:
                if ((0x0 == ssh.asc) &&
                    (ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq)) {
                    if (SAT_ATA_RETURN_DESC != ata_return_desc[0]) {
                        if (verbose)
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
                if (verbose < 2)
                    pr2serr("ATA PASS-THROUGH (%d), Unit Attention detected\n",
                            cdb_len);
                return SG_LIB_CAT_UNIT_ATTENTION;
            case SPC_SK_NOT_READY:
                if (verbose < 2)
                    pr2serr("ATA PASS-THROUGH (%d), device not ready\n",
                            cdb_len);
                return SG_LIB_CAT_NOT_READY;
            case SPC_SK_MEDIUM_ERROR:
            case SPC_SK_HARDWARE_ERROR:
                if (verbose < 2)
                    pr2serr("ATA PASS-THROUGH (%d), medium or hardware "
                            "error\n", cdb_len);
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
                pr2serr("ATA PASS-THROUGH (%d): data protect, read only "
                        "media?\n", cdb_len);
                return SG_LIB_CAT_DATA_PROTECT;
            default:
                if (verbose < 2)
                    pr2serr("ATA PASS-THROUGH (%d), some sense data, use "
                            "'-v' for more information\n", cdb_len);
                return SG_LIB_CAT_SENSE;
            }
        } else {
            pr2serr("CHECK CONDITION without response code ??\n");
            return SG_LIB_CAT_SENSE;
        }
        if (0x72 != (sense_buffer[0] & 0x7f)) {
            pr2serr("expected descriptor sense format, response code=0x%x\n",
                    sense_buffer[0]);
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
        pr2serr("ATA pass through (%d) failed\n", cdb_len);
        if (verbose < 2)
            pr2serr("    try adding '-v' for more information\n");
        return -1;
    }

    if ((SAT_ATA_RETURN_DESC == ata_return_desc[0]) && (! got_ard))
        pr2serr("Seem to have got ATA Result Descriptor but it was not "
                "indicated\n");
    if (got_ard) {
        if (ata_return_desc[3] & 0x4) {
                pr2serr("error indication in returned FIS: aborted command\n");
                return SG_LIB_CAT_ABORTED_COMMAND;
        }
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool ck_cond = false;
    bool extend = false;
    bool rdonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int c, ret, res;
    int sg_fd = -1;
    int count = 0;
    int feature = 0;
    int verbose = 0;
    int cdb_len = SAT_ATA_PASS_THROUGH16_LEN;
    uint64_t lba = 0;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "c:Cef:hl:L:rvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            count = sg_get_num(optarg);
            if ((count < 0) || (count > 255)) {
                pr2serr("bad argument for '--count'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'C':
            ck_cond = true;
            break;
        case 'e':
            extend = true;
            break;
        case 'f':
            feature = sg_get_num(optarg);
            if ((feature < 0) || (feature > 255)) {
                pr2serr("bad argument for '--feature'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            cdb_len = sg_get_num(optarg);
            if (! ((cdb_len == 12) || (cdb_len == 16))) {
                pr2serr("argument to '--len' should be 12 or 16\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'L':       /* up to 32 bits, allow for 48 bits (less -1) */
            lba = sg_get_llnum(optarg);
            if ((uint64_t)-1 == lba) {
                pr2serr("bad argument for '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            rdonly = true;
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
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
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return 1;
    }

    if (lba > 0xffffff) {
        if (12 == cdb_len) {
            cdb_len = 16;
            if (verbose)
                pr2serr("Since lba > 0xffffff, forcing cdb length to 16\n");
        }
        if (16 == cdb_len) {
            if (! extend) {
                extend = true;
                if (verbose)
                    pr2serr("Since lba > 0xffffff, set extend bit\n");
            }
        }
    }

    if ((sg_fd = sg_cmds_open_device(device_name, rdonly, verbose)) < 0) {
        if (verbose)
            pr2serr("error opening file: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    ret = do_set_features(sg_fd, feature, count, lba, cdb_len, ck_cond,
                          extend, verbose);

fini:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_sat_set_feature failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
