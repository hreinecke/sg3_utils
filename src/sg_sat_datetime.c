/*
 * Copyright (c) 2023 Jeremy Bauer and Daniel Woeste, Western Digital
 * Corporation.
 * Heavily based on Douglas Gilbert's sg_timestamp and sg_sat_read_gplog.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * This program issues the ATA SET DATE & TIME EXT or READ LOG EXT/READ LOG
 * DMA EXT commands through ATA pass-through to set or return the date and
 * time on ATA devices. Based on ATA Command Set-5 (ACS-5).
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
#include <time.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_unaligned.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_pr2serr.h"

/* This program uses a ATA PASS-THROUGH SCSI command. This usage is
 * defined in the SCSI to ATA Translation (SAT) drafts and standards.
 * See https://www.t10.org for drafts. SAT is a standard: SAT ANSI INCITS
 * 431-2007 (draft prior to that is sat-r09.pdf). SAT-2 is also a
 * standard: SAT-2 ANSI INCITS 465-2010 and the draft prior to that is
 * sat2r09.pdf . The SAT-3 project has started and the most recent draft
 * is sat3r01.pdf .
 */

/* This program performs a ATA PASS-THROUGH (16) SCSI command in order
 * to perform a ATA SET DATE TIME EXT and ATA READ LOG (DMA) EXT commands.
 *
 * See man page (sg_sat_datetime.8) for details.
 */

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */
#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d

#define ATA_SET_DATE_AND_TIME_EXT 0x77
#define ATA_READ_LOG_EXT 0x2f
#define ATA_READ_LOG_DMA_EXT 0x47

#define DEF_TIMEOUT 20

static const char * version_str = "1.04 20230622";

static const struct option long_options[] = {
    {"ck_cond", no_argument, 0, 'C'},
    {"ck-cond", no_argument, 0, 'C'},
    {"dma", no_argument, 0, 'd'},
    {"elapsed", no_argument, 0, 'e'},
    {"format", no_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"milliseconds", required_argument, 0, 'm'},
    {"readonly", no_argument, 0, 'R'},
    {"seconds", required_argument, 0, 's'},
    {"srep", no_argument, 0, 'S'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};


static void
usage(int num)
{
    if (num > 1)
        goto page2;

    pr2serr("Usage: "
            "sg_sat_datetime [--dma] [--elapsed] [--format] [--help] [--hex]\n"
            "                       [--milliseconds=MS] [--readonly] "
            "[--seconds=SECS]\n                       "
            "[--srep] [--verbose] [--version] DEVICE\n"
           );
    pr2serr("  where:\n"
            "    --dma|-d           use DMA to read date and time from log\n"
            "    --elapsed|-e       show time as '<n> days hh:mm:ss.xxx' "
            "where\n"
            "                       '.xxx' is the remainder milliseconds. "
            "Don't show\n"
            "                       '<n> days' if <n> is 0 (unless '-e' "
            "given twice)\n"
            "    --format|-f        output formatted date and time using\n"
            "                       the default locale setting\n"
            "    --help|-h          print out usage message, use twice for "
            "examples\n"
            "    --hex|-H           output date and time in ASCII "
            "hexadecimal\n"
            "    --milliseconds=MS|-m MS  set date and time to MS "
            "milliseconds since\n"
            "                             1970-01-01 00:00:00 UTC\n"
            "    --seconds=SECS|-s SECS   set date and time to SECS "
            "seconds since\n"
            "                             1970-01-01 00:00:00 UTC\n"
            "    --srep|-S          output date and time in seconds "
            "(def:\n"
            "                       milliseconds)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
          );
    pr2serr("Performs the ATA SET DATE TIME EXT command to set the device "
            "time if either\nthe --milliseconds=MS or --seconds=SECS option "
            "is given.  If --seconds\nor --milliseconds options are not "
            "provided, the READ LOG EXT or READ LOG\nDMA EXT command is "
            "issued to read the current date and time from device\nstatisics "
            "log address (04h) general statistics log page (01h). If the "
            "date\nand time has not been set, the ATA DEVICE returns the the "
            "number of\nmilliseconds of power-on hours. The date and time "
            "value is based on\n1970-01-01 00:00:00 UTC which also happens "
            "to be the time 'epoch'\nof Unix machines.\n\n"
            "Use '-hh' (the '-h' option twice) for examples.\n"
#if 0
 "The 'date +%%s' command in "
            "Unix returns the number of\nseconds since the epoch. To "
            "convert a reported timestamp (in seconds since\nthe epoch) "
            "to a more readable form use "
            "'date --date=@<secs_since_epoch>' .\n"
#endif
           );
    return;
page2:
    pr2serr("sg_sat_datetime examples:\n"
            "Per ATA standard, the date and time statisic is equivalent to\n"
            "the millisecond equivalent of the POH value or the date and "
            "time\nvalue set by the SET DATE & TIME EXT command.  If a "
            "power-on\nreset occurs after date and time are set, the date "
            "and time\nstatistic is reset to the millisecond equivalent of "
            "the POH value.\n\n"
           );
    pr2serr("Set the device clock to the current time:\n\n"
            " $ sg_sat_datetime --seconds=`date +%%s` /dev/sg1\n\n"
           );
    pr2serr("Return the current device time in milliseconds since the "
            "epoch:\n\n"
            " $ sg_sat_datetime /dev/sg1\n"
            "1680880311400\n\n"
            );
    pr2serr("Return the formatted current time:\n\n"
            " $ sg_sat_datetime -f /dev/sg1\n"
            "Fri Apr  7 10:13:05 2023\n\n"
           );
    pr2serr("Return elapsed POH time or since epoch (if date and time "
            "set):\n\n"
            " $ sg_sat_datetime -e /dev/sg1\n"
            "740 days 17:46:43.000\n\n"
           );
}

static int
do_read_datetime(int sg_fd, int ata_cmd, bool ck_cond, int verbose,
                 bool format, bool do_hex, bool do_srep, int elapsed)
{
    const bool extend = true;
    const bool t_dir = true; /* false -> to device, true -> from device */
    const bool byte_block = true; /* false -> bytes, true -> 512 byte blocks */
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
    char cmd_name[32];
    uint8_t inbuff[512];
    uint64_t timestamp;

    struct tm  ts;
    char       tbuf[80];

    snprintf(cmd_name, sizeof(cmd_name), "ATA PASS-THROUGH (%d)",
             SAT_ATA_PASS_THROUGH16_LEN);
    if (ata_cmd == ATA_READ_LOG_DMA_EXT) {
        protocol = 6; /* DMA */
    } else {
        protocol = 4; /* PIO Data-In */
    }
    sb_sz = sizeof(sense_buffer);
    memset(sense_buffer, 0, sb_sz);
    memset(ata_return_desc, 0, sizeof(ata_return_desc));
    memset(inbuff, 0, 512);
    if (verbose > 1)
        pr2serr("Building ATA READ LOG%s EXT command; la=0x4, pn=0x1\n",
                ((ata_cmd == ATA_READ_LOG_DMA_EXT) ? " DMA" : ""));

    /* Prepare ATA PASS-THROUGH COMMAND (16) command */
    apt_cdb[14] = ata_cmd;
    sg_put_unaligned_be16((uint16_t)1, apt_cdb + 5);
    apt_cdb[8] = 4;  /* Device Statistics Log Address 04h */
    sg_put_unaligned_be16((uint16_t)1, apt_cdb + 9); /* General Stats LP 01h */
    apt_cdb[1] = (protocol << 1) | extend;
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

    res = sg_ll_ata_pt(sg_fd, apt_cdb, SAT_ATA_PASS_THROUGH16_LEN, DEF_TIMEOUT,
                       inbuff, NULL, 512, sense_buffer, sb_sz, ata_return_desc,
                       sizeof(ata_return_desc), &resid, verbose);

    if (0 == res) {

        if (sg_is_big_endian()) {
            timestamp = (uint64_t)(inbuff[61]);
            timestamp += (uint64_t)(inbuff[60]) << 8;
            timestamp += (uint64_t)(inbuff[59]) << 16;
            timestamp += (uint64_t)(inbuff[58]) << 24;
            timestamp += (uint64_t)(inbuff[57]) << 32;
            timestamp += (uint64_t)(inbuff[56]) << 40;
        } else {
            timestamp = (uint64_t)(inbuff[56]);
            timestamp += (uint64_t)(inbuff[57]) << 8;
            timestamp += (uint64_t)(inbuff[58]) << 16;
            timestamp += (uint64_t)(inbuff[59]) << 24;
            timestamp += (uint64_t)(inbuff[60]) << 32;
            timestamp += (uint64_t)(inbuff[61]) << 40;
        }

        if (format) {
            time_t fmtvalue = timestamp / 1000;
            ts = *localtime(&fmtvalue);
            strftime(tbuf, sizeof(tbuf), "%c", &ts);
            printf("%s\n", tbuf);
        } else if (do_hex)
            printf("%" PRIx64 "\n", do_srep ? (timestamp / 1000) : timestamp);
        else if (elapsed) {
            int days = (int)(timestamp / 1000 / 60 / 60 / 24);
            int hours = (int)(timestamp / 1000 / 60 / 60 % 24);
            int mins = (int)(timestamp / 1000 / 60 % 60);
            int secs_in_min =(int)( timestamp / 1000 % 60);
            int rem_msecs = (int)(timestamp % 1000);

            if ((elapsed > 1) || (days > 0))
                printf("%d day%s ", days,
                       ((1 == days) ? "" : "s"));
            printf("%02d:%02d:%02d.%03d\n", hours, mins,
                   secs_in_min, rem_msecs);
        } else
            pr2serr("%" PRIu64 "\n",
                    do_srep ? (timestamp / 1000) : timestamp);

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
                        pr2serr("%s not supported\n", cmd_name);
                } else {
                    ret = SG_LIB_CAT_ILLEGAL_REQ;
                    if (verbose < 2)
                        pr2serr("%s, bad field in cdb\n", cmd_name);
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
                    pr2serr("%s, Unit Attention detected\n", cmd_name);
                return SG_LIB_CAT_UNIT_ATTENTION;
            case SPC_SK_NOT_READY:
                if (verbose < 2)
                    pr2serr("%s, device not ready\n", cmd_name);
                return SG_LIB_CAT_NOT_READY;
            case SPC_SK_MEDIUM_ERROR:
            case SPC_SK_HARDWARE_ERROR:
                if (verbose < 2)
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
                if (verbose < 2)
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
        if (verbose < 2)
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


static int
do_set_datetimeext(int sg_fd, uint64_t timestamp, int cdb_len, bool ck_cond,
                   int verbose)
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

    sb_sz = sizeof(sense_buffer);
    memset(sense_buffer, 0, sb_sz);
    memset(ata_return_desc, 0, sizeof(ata_return_desc));

    /* Prepare ATA PASS-THROUGH COMMAND (16) command */
    apt_cdb[14] = ATA_SET_DATE_AND_TIME_EXT;
    apt_cdb[8] = timestamp & 0xff;
    apt_cdb[10] = (timestamp >> 8) & 0xff;
    apt_cdb[12] = (timestamp >> 16) & 0xff;
    apt_cdb[7] = (timestamp >> 24) & 0xff;
    apt_cdb[9] = (timestamp >> 32) & 0xff;
    apt_cdb[11] = (timestamp >> 40) & 0xff;
    apt_cdb[1] = (multiple_count << 5) | (protocol << 1);
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
    bool do_hex = false;
    bool do_srep = false;
    bool format = false;
    bool readonly = false;
    bool secs_given = false;
    bool verbose_given = false;
    bool version_given = false;
    bool is_set = false;
    int c, ret, res;
    int do_help = 0;
    int elapsed = 0;
    int sg_fd = -1;
    int verbose = 0;
    int cdb_len = SAT_ATA_PASS_THROUGH16_LEN;
    int ata_read_cmd = ATA_READ_LOG_EXT;
    uint64_t msecs = 0;
    uint64_t secs = 0;
    int64_t ll = 0;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "CdefhHm:Rs:SvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'C':
            ck_cond = true;
            break;
        case 'd':
            ata_read_cmd = ATA_READ_LOG_DMA_EXT;
            break;
        case 'e':
            ++elapsed;
            break;
        case 'f':
            format = true;
            break;
        case 'h':
        case '?':
            do_help++;
            break;
        case 'H':
            do_hex = true;
            break;
        case 'm':       /* up to 32 bits, allow for 48 bits (less -1) */
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument for '--milliseconds'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            msecs = (uint64_t)ll;
            is_set = true;
            break;
        case 'R':
            readonly = true;
            break;
        case 's':       /* up to 32 bits, allow for 48 bits (less -1) */
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument for '--seconds'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            secs = (uint64_t)ll;
            secs_given = true;
            is_set = true;
            break;
        case 'S':
            do_srep = true;
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
            usage(0);
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
            usage(0);
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (do_help > 0) {
        usage(do_help);
        return 0;
    }


#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        /* verbose_given = false; */
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
        usage(0);
        return 1;
    }

    if ((sg_fd = sg_cmds_open_device(device_name, readonly, verbose)) < 0) {
        if (verbose)
            pr2serr("error opening file: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    if (is_set)
        ret = do_set_datetimeext(sg_fd, secs_given ? (secs * 1000) : msecs,
                                 cdb_len, ck_cond, verbose);
    else
        ret = do_read_datetime(sg_fd, ata_read_cmd, ck_cond, verbose, format,
                               do_hex, do_srep, elapsed);

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
        if (! sg_if_can2stderr("sg_sat_datetime failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
