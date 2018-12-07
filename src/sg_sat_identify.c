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
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_pr2serr.h"
#include "sg_unaligned.h"

/* This program uses a ATA PASS-THROUGH SCSI command to package an
 * ATA IDENTIFY (PACKAGE) DEVICE command. It is based on the SCSI to
 * ATA Translation (SAT) drafts and standards. See http://www.t10.org
 * for drafts. SAT is a standard: SAT ANSI INCITS 431-2007 (draft prior
 * to that is sat-r09.pdf). SAT-2 is also a standard: SAT-2 ANSI INCITS
 * 465-2010 and the draft prior to that is sat2r09.pdf . The SAT-3 is
 * now a standard: SAT-3 ANSI INCITS 517-2015. The most current draft of
 * SAT-4 is revision 5c (sat4r05c.pdf).
 */

#define SAT_ATA_PASS_THROUGH32_LEN 32
#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_PASS_THROUGH12 0xa1     /* clashes with MMC BLANK command */
#define SAT_ATA_PASS_THROUGH12_LEN 12
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */
#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d

#define ATA_IDENTIFY_DEVICE 0xec
#define ATA_IDENTIFY_PACKET_DEVICE 0xa1
#define ID_RESPONSE_LEN 512

#define DEF_TIMEOUT 20

#define EBUFF_SZ 256

static const char * version_str = "1.17 20180515";

static struct option long_options[] = {
        {"ck-cond", no_argument, 0, 'c'},
        {"ck_cond", no_argument, 0, 'c'},
        {"extend", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"len", required_argument, 0, 'l'},
        {"ident", no_argument, 0, 'i'},
        {"packet", no_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_sat_identify [--ck_cond] [--extend] [--help] [--hex] "
            "[--ident]\n"
            "                       [--len=CLEN] [--packet] [--raw] "
            "[--readonly]\n"
            "                       [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --ck_cond|-c     sets ck_cond bit in cdb (def: 0)\n"
            "    --extend|-e      sets extend bit in cdb (def: 0)\n"
            "    --help|-h        print out usage message then exit\n"
            "    --hex|-H         output response in hex\n"
            "    --ident|-i       output WWN prefixed by 0x, if not "
            "available output\n"
            "                     0x0000000000000000\n"
            "    --len=CLEN| -l CLEN    CLEN is cdb length: 12, 16 or 32 "
            "bytes\n"
            "                           (default: 16)\n"
            "    --packet|-p      do IDENTIFY PACKET DEVICE (def: IDENTIFY "
            "DEVICE)\n"
            "                     command\n"
            "    --raw|-r         output response in binary to stdout\n"
            "    --readonly|-R    open DEVICE read-only (def: read-write)\n"
            "    --verbose|-v     increase verbosity\n"
            "    --version|-V     print version string and exit\n\n"
            "Performs a ATA IDENTIFY (PACKET) DEVICE command via a SAT "
            "layer using\na SCSI ATA PASS-THROUGH(12), (16) or (32) command. "
            "Only SAT layers\ncompliant with SAT-4 revision 5 or later will "
            "support the SCSI ATA\nPASS-THROUGH(32) command.\n");
}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

static int
do_identify_dev(int sg_fd, bool do_packet, int cdb_len, bool ck_cond,
                bool extend, bool do_ident, int do_hex, bool do_raw,
                int verbose)
{
    bool t_type = false;/* false -> 512 byte blocks,
                           true -> device's LB size */
    bool t_dir = true;  /* false -> to device, true -> from device */
    bool byte_block = true; /* false -> bytes, true -> 512 byte blocks (if
                               t_type=false) */
    bool got_ard = false;         /* got ATA result descriptor */
    bool got_fixsense = false;    /* got ATA result in fixed format sense */
    bool ok;
    int j, res, ret, sb_sz;
    /* Following for ATA READ/WRITE MULTIPLE (EXT) cmds, normally 0 */
    int multiple_count = 0;
    int protocol = 4;   /* PIO data-in */
    int t_length = 2;   /* 0 -> no data transferred, 2 -> sector count */
    int resid = 0;
    uint64_t ull;
    struct sg_scsi_sense_hdr ssh;
    uint8_t inBuff[ID_RESPONSE_LEN];
    uint8_t sense_buffer[64];
    uint8_t ata_return_desc[16];
    uint8_t apt_cdb[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t apt12_cdb[SAT_ATA_PASS_THROUGH12_LEN] =
                {SAT_ATA_PASS_THROUGH12, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0};
    uint8_t apt32_cdb[SAT_ATA_PASS_THROUGH32_LEN];
    const unsigned short * usp;

    sb_sz = sizeof(sense_buffer);
    memset(sense_buffer, 0, sb_sz);
    memset(apt32_cdb, 0, sizeof(apt32_cdb));
    memset(ata_return_desc, 0, sizeof(ata_return_desc));
    ok = false;
    switch (cdb_len) {
    case SAT_ATA_PASS_THROUGH32_LEN:    /* SAT-4 revision 5 or later */
        /* Prepare SCSI ATA PASS-THROUGH COMMAND(32) command */
        sg_put_unaligned_be16(1, apt32_cdb + 22);     /* count=1 */
        apt32_cdb[25] = (do_packet ? ATA_IDENTIFY_PACKET_DEVICE :
                                       ATA_IDENTIFY_DEVICE);
        apt32_cdb[10] = (multiple_count << 5) | (protocol << 1);
        if (extend)
            apt32_cdb[10] |= 0x1;
        apt32_cdb[11] = t_length;
        if (ck_cond)
            apt32_cdb[11] |= 0x20;
        if (t_type)
            apt32_cdb[11] |= 0x10;
        if (t_dir)
            apt32_cdb[11] |= 0x8;
        if (byte_block)
            apt32_cdb[11] |= 0x4;
        /* following call takes care of all bytes below offset 10 in cdb */
        res = sg_ll_ata_pt(sg_fd, apt32_cdb, cdb_len, DEF_TIMEOUT, inBuff,
                           NULL /* doutp */, ID_RESPONSE_LEN, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, verbose);
        break;
    case SAT_ATA_PASS_THROUGH16_LEN:
        /* Prepare SCSI ATA PASS-THROUGH COMMAND(16) command */
        apt_cdb[6] = 1;   /* sector count */
        apt_cdb[14] = (do_packet ? ATA_IDENTIFY_PACKET_DEVICE :
                                     ATA_IDENTIFY_DEVICE);
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
        res = sg_ll_ata_pt(sg_fd, apt_cdb, cdb_len, DEF_TIMEOUT, inBuff,
                           NULL /* doutp */, ID_RESPONSE_LEN, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, verbose);
        break;
    case SAT_ATA_PASS_THROUGH12_LEN:
        /* Prepare SCSI ATA PASS-THROUGH COMMAND(12) command */
        apt12_cdb[4] = 1;   /* sector count */
        apt12_cdb[9] = (do_packet ? ATA_IDENTIFY_PACKET_DEVICE :
                                      ATA_IDENTIFY_DEVICE);
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
        res = sg_ll_ata_pt(sg_fd, apt12_cdb, cdb_len, DEF_TIMEOUT, inBuff,
                           NULL /* doutp */, ID_RESPONSE_LEN, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, verbose);
        break;
    default:
        pr2serr("%s: bad cdb_len=%d\n", __func__, cdb_len);
        return -1;
    }
    if (0 == res) {
        ok = true;
        if (verbose > 2)
            pr2serr("command completed with SCSI GOOD status\n");
    } else if ((res > 0) && (res & SAM_STAT_CHECK_CONDITION)) {
        if (verbose > 1) {
            pr2serr("ATA pass-through:\n");
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
                    if (0x72 == ssh.response_code) {
                        if (SAT_ATA_RETURN_DESC != ata_return_desc[0]) {
                            if (verbose)
                                pr2serr("did not find ATA Return (sense) "
                                        "Descriptor\n");
                            return SG_LIB_CAT_RECOVERED;
                        }
                        got_ard = true;
                        break;
                    } else if (0x70 == ssh.response_code) {
                        got_fixsense = true;
                        break;
                    } else {
                        if (verbose < 2)
                            pr2serr("ATA PASS-THROUGH (%d), unexpected  "
                                    "response_code=0x%x\n", ssh.response_code,
                                    cdb_len);
                        return SG_LIB_CAT_RECOVERED;
                    }
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
                    pr2serr("Aborted command: try again with%s '-p' option\n",
                            (do_packet ? "out" : ""));
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
        pr2serr("ATA pass-through (%d) failed\n", cdb_len);
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
                pr2serr("    try again with%s '-p' option\n",
                        (do_packet ? "out" : ""));
                return SG_LIB_CAT_ABORTED_COMMAND;
        }
        ok = true;
    }
    if (got_fixsense) {
        if (0x4 & sense_buffer[3]) { /* Error is MSB of Info field */
                pr2serr("error indication in returned FIS: aborted command\n");
                pr2serr("    try again with%s '-p' option\n",
                        (do_packet ? "out" : ""));
                return SG_LIB_CAT_ABORTED_COMMAND;
        }
        ok = true;
    }

    if (ok) { /* output result if it is available */
        if (do_raw)
            dStrRaw(inBuff, 512);
        else if (0 == do_hex) {
            if (do_ident) {
                usp = (const unsigned short *)inBuff;
                ull = 0;
                for (j = 0; j < 4; ++j) {
                    if (j > 0)
                        ull <<= 16;
                    ull |= usp[108 + j];
                }
                printf("0x%016" PRIx64 "\n", ull);
            } else {
                printf("Response for IDENTIFY %sDEVICE ATA command:\n",
                       (do_packet ? "PACKET " : ""));
                dWordHex((const unsigned short *)inBuff, 256, 0,
                         sg_is_big_endian());
            }
        } else if (1 == do_hex)
            hex2stdout(inBuff, 512, 0);
        else if (2 == do_hex)
            dWordHex((const unsigned short *)inBuff, 256, 0,
                     sg_is_big_endian());
        else if (3 == do_hex) /* '-HHH' suitable for "hdparm --Istdin" */
            dWordHex((const unsigned short *)inBuff, 256, -2,
                     sg_is_big_endian());
        else     /* '-HHHH' hex bytes only */
            hex2stdout(inBuff, 512, -1);
    }
    return 0;
}

int
main(int argc, char * argv[])
{
    bool do_packet = false;
    bool do_ident = false;
    bool do_raw = false;
    bool o_readonly = false;
    bool ck_cond = false;    /* set to true to read register(s) back */
    bool extend = false;    /* set to true to send 48 bit LBA with command */
    bool verbose_given = false;
    bool version_given = false;
    int c, res;
    int sg_fd = -1;
    int cdb_len = SAT_ATA_PASS_THROUGH16_LEN;
    int do_hex = 0;
    int verbose = 0;
    int ret = 0;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "cehHil:prRvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            ck_cond = true;
            break;
        case 'e':
            extend = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'i':
            do_ident = true;
            break;
        case 'l':
            cdb_len = sg_get_num(optarg);
            switch (cdb_len) {
            case 12:
            case 16:
            case 32:
                break;
            default:
                pr2serr("argument to '--len' should be 12, 16 or 32\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            do_packet = true;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
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
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose)) < 0) {
        if (verbose)
            pr2serr("error opening file: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    ret = do_identify_dev(sg_fd, do_packet, cdb_len, ck_cond, extend,
                          do_ident, do_hex, do_raw, verbose);

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
        if (! sg_if_can2stderr("sg_sat_identify failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
