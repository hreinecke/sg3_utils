/*
 * Copyright (c) 2006-2011 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

/* This program uses a ATA PASS-THROUGH SCSI command to package an
 * ATA IDENTIFY (PACKAGE) DEVICE command. It is based on the SCSI to
 * ATA Translation (SAT) drafts and standards. See http://www.t10.org
 * for drafts. SAT is a standard: SAT ANSI INCITS 431-2007 (draft prior
 * to that is sat-r09.pdf). SAT-2 is also a standard: SAT-2 ANSI INCITS
 * 465-2010 and the draft prior to that is sat2r09.pdf . The SAT-3
 * project has started and the most recent draft is sat3r01.pdf .
 */

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_PASS_THROUGH12 0xa1     /* clashes with MMC BLANK comand */
#define SAT_ATA_PASS_THROUGH12_LEN 12
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */
#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d

#define ATA_IDENTIFY_DEVICE 0xec
#define ATA_IDENTIFY_PACKET_DEVICE 0xa1
#define ID_RESPONSE_LEN 512

#define DEF_TIMEOUT 20

#define EBUFF_SZ 256

static char * version_str = "1.08 20110513";

static struct option long_options[] = {
        {"ck_cond", no_argument, 0, 'c'},
        {"extend", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"len", required_argument, 0, 'l'},
        {"ident", no_argument, 0, 'i'},
        {"packet", no_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_sat_identify [--ck_cond] [--extend] [--help] [--hex] "
          "[--ident]\n"
          "                       [--len=16|12] [--packet] [--raw] "
          "[--verbose]\n"
          "                       [--version] DEVICE\n"
          "  where:\n"
          "    --ck_cond|-c     sets ck_cond bit in cdb (def: 0)\n"
          "    --extend|-e      sets extend bit in cdb (def: 0)\n"
          "    --help|-h        print out usage message then exit\n"
          "    --hex|-H         output response in hex\n"
          "    --ident|-i       output WWN prefixed by 0x, if not available "
          "output\n"
          "                     0x0000000000000000\n"
          "    --len=16|12 | -l 16|12    cdb length: 16 or 12 bytes "
          "(default: 16)\n"
          "    --packet|-p      do IDENTIFY PACKET DEVICE (def: IDENTIFY "
          "DEVICE) command\n"
          "    --raw|-r         output response in binary to stdout\n"
          "    --verbose|-v     increase verbosity\n"
          "    --version|-V     print version string and exit\n\n"
          "Performs a ATA IDENTIFY (PACKET) DEVICE command via a SAT "
          "layer\n");
}

static void dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

static int do_identify_dev(int sg_fd, int do_packet, int cdb_len,
                           int ck_cond, int extend, int do_indent,
                           int do_hex, int do_raw, int verbose)
{
    int ok, j, res, ret;
    int protocol = 4;   /* PIO data-in */
    int t_dir = 1;      /* 0 -> to device, 1 -> from device */
    int byte_block = 1; /* 0 -> bytes, 1 -> 512 byte blocks */
    int t_length = 2;   /* 0 -> no data transferred, 2 -> sector count */
    int resid = 0;
    int got_ard = 0;    /* got ATA result descriptor */
    int sb_sz;
    struct sg_scsi_sense_hdr ssh;
    unsigned char inBuff[ID_RESPONSE_LEN];
    unsigned char sense_buffer[64];
    unsigned char ata_return_desc[16];
    unsigned char aptCmdBlk[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char apt12CmdBlk[SAT_ATA_PASS_THROUGH12_LEN] =
                {SAT_ATA_PASS_THROUGH12, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0};
    const unsigned short * usp;
    uint64_t ull;

    sb_sz = sizeof(sense_buffer);
    memset(sense_buffer, 0, sb_sz);
    memset(ata_return_desc, 0, sizeof(ata_return_desc));
    ok = 0;
    if (SAT_ATA_PASS_THROUGH16_LEN == cdb_len) {
        /* Prepare ATA PASS-THROUGH COMMAND (16) command */
        aptCmdBlk[6] = 1;   /* sector count */
        aptCmdBlk[14] = (do_packet ? ATA_IDENTIFY_PACKET_DEVICE :
                                     ATA_IDENTIFY_DEVICE);
        aptCmdBlk[1] = (protocol << 1) | extend;
        aptCmdBlk[2] = (ck_cond << 5) | (t_dir << 3) |
                       (byte_block << 2) | t_length;
        res = sg_ll_ata_pt(sg_fd, aptCmdBlk, cdb_len, DEF_TIMEOUT, inBuff,
                           NULL /* doutp */, ID_RESPONSE_LEN, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, verbose);
    } else {
        /* Prepare ATA PASS-THROUGH COMMAND (12) command */
        apt12CmdBlk[4] = 1;   /* sector count */
        apt12CmdBlk[9] = (do_packet ? ATA_IDENTIFY_PACKET_DEVICE :
                                      ATA_IDENTIFY_DEVICE);
        apt12CmdBlk[1] = (protocol << 1);
        apt12CmdBlk[2] = (ck_cond << 5) | (t_dir << 3) |
                         (byte_block << 2) | t_length;
        res = sg_ll_ata_pt(sg_fd, apt12CmdBlk, cdb_len, DEF_TIMEOUT, inBuff,
                           NULL /* doutp */, ID_RESPONSE_LEN, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, verbose);
    }
    if (0 == res) {
        ok = 1;
        if (verbose > 2)
            fprintf(stderr, "command completed with SCSI GOOD status\n");
    } else if ((res > 0) && (res & SAM_STAT_CHECK_CONDITION)) {
        if (verbose > 1)
            sg_print_sense("ATA pass through", sense_buffer, sb_sz,
                           ((verbose > 2) ? 1 : 0));
        if (sg_scsi_normalize_sense(sense_buffer, sb_sz, &ssh)) {
            switch (ssh.sense_key) {
            case SPC_SK_ILLEGAL_REQUEST:
                if ((0x20 == ssh.asc) && (0x0 == ssh.ascq)) {
                    ret = SG_LIB_CAT_INVALID_OP;
                    if (verbose < 2)
                        fprintf(stderr, "ATA PASS-THROUGH (%d) not "
                                "supported\n", cdb_len);
                } else {
                    ret = SG_LIB_CAT_ILLEGAL_REQ;
                    if (verbose < 2)
                        fprintf(stderr, "ATA PASS-THROUGH (%d), bad "
                                "field in cdb\n", cdb_len);
                }
                return ret;
            case SPC_SK_NO_SENSE:
            case SPC_SK_RECOVERED_ERROR:
                if ((0x0 == ssh.asc) &&
                    (ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq)) {
                    if (SAT_ATA_RETURN_DESC != ata_return_desc[0]) {
                        if (verbose)
                            fprintf(stderr, "did not find ATA Return "
                                    "(sense) Descriptor\n");
                        return SG_LIB_CAT_RECOVERED;
                    }
                    got_ard = 1;
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
                    fprintf(stderr, "ATA PASS-THROUGH (%d), Unit Attention "
                                "detected\n", cdb_len);
                return SG_LIB_CAT_UNIT_ATTENTION;
            case SPC_SK_NOT_READY:
                if (verbose < 2)
                    fprintf(stderr, "ATA PASS-THROUGH (%d), device not "
                                "ready\n", cdb_len);
                return SG_LIB_CAT_NOT_READY;
            case SPC_SK_MEDIUM_ERROR:
            case SPC_SK_HARDWARE_ERROR:
                if (verbose < 2)
                    fprintf(stderr, "ATA PASS-THROUGH (%d), medium or "
                            "hardware error\n", cdb_len);
                return SG_LIB_CAT_MEDIUM_HARD;
            case SPC_SK_ABORTED_COMMAND:
                fprintf(stderr, "Aborted command: try again with%s '-p' "
                        "option\n", (do_packet ? "out" : ""));
                return SG_LIB_CAT_ABORTED_COMMAND;
            default:
                if (verbose < 2)
                    fprintf(stderr, "ATA PASS-THROUGH (%d), some sense "
                            "data, use '-v' for more information\n", cdb_len);
                return SG_LIB_CAT_SENSE;
            }
        } else {
            fprintf(stderr, "CHECK CONDITION without response code ??\n");
            return SG_LIB_CAT_SENSE;
        }
        if (0x72 != (sense_buffer[0] & 0x7f)) {
            fprintf(stderr, "expected descriptor sense format, response "
                    "code=0x%x\n", sense_buffer[0]);
            return SG_LIB_CAT_MALFORMED;
        }
    } else if (res > 0) {
        fprintf(stderr, "Unexpected SCSI status=0x%x\n", res);
        return SG_LIB_CAT_MALFORMED;
    } else {
        fprintf(stderr, "ATA pass through (%d) failed\n", cdb_len);
        if (verbose < 2)
            fprintf(stderr, "    try adding '-v' for more information\n");
        return -1;
    }

    if ((SAT_ATA_RETURN_DESC == ata_return_desc[0]) && (0 == got_ard))
        fprintf(stderr, "Seem to have got ATA Result Descriptor but "
                "it was not indicated\n");
    if (got_ard) {
        if (ata_return_desc[3] & 0x4) {
                fprintf(stderr, "error indication in returned FIS: aborted "
                        "command\n");
                fprintf(stderr, "    try again with%s '-p' option\n",
                        (do_packet ? "out" : ""));
                return SG_LIB_CAT_ABORTED_COMMAND;
        }
        ok = 1;
    }

    if (ok) { /* output result if it is available */
        if (do_raw)
            dStrRaw((const char *)inBuff, 512);
        else if (0 == do_hex) {
            if (do_indent) {
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
            dStrHex((const char *)inBuff, 512, 0);
        else if (2 == do_hex)
            dWordHex((const unsigned short *)inBuff, 256, 0,
                     sg_is_big_endian());
        else            /* '-HHH' output suitable for "hdparm --Istdin" */
            dWordHex((const unsigned short *)inBuff, 256, -2,
                     sg_is_big_endian());
    }
    return 0;
}

int main(int argc, char * argv[])
{
    int sg_fd, c, res;
    const char * device_name = NULL;
    int cdb_len = SAT_ATA_PASS_THROUGH16_LEN;
    int do_packet = 0;
    int do_hex = 0;
    int do_indent = 0;
    int do_raw = 0;
    int verbose = 0;
    int ck_cond = 0;   /* set to 1 to read register(s) back */
    int extend = 0;    /* set to 1 to send 48 bit LBA with command */
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "cehHil:prvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            ++ck_cond;
            break;
        case 'e':
            ++extend;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'i':
            ++do_indent;
            break;
        case 'l':
           cdb_len = sg_get_num(optarg);
           if (! ((cdb_len == 12) || (cdb_len == 16))) {
                fprintf(stderr, "argument to '--len' should be 12 or 16\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            ++do_packet;
            break;
        case 'r':
            ++do_raw;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
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
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = sg_cmds_open_device(device_name, 0 /* rw */,
                                     verbose)) < 0) {
        fprintf(stderr, "error opening file: %s: %s\n",
                device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    ret = do_identify_dev(sg_fd, do_packet, cdb_len, ck_cond, extend,
                          do_indent, do_hex, do_raw, verbose);

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
