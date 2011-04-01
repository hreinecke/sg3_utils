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
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"

/* This program uses a ATA PASS-THROUGH SCSI command. This usage is
 * defined in the SCSI to ATA Translation (SAT) drafts and standards.
 * See http://www.t10.org for drafts. SAT is a standard: SAT ANSI INCITS
 * 431-2007 (draft prior to that is sat-r09.pdf). SAT-2 is also a
 * standard: SAT-2 ANSI INCITS 465-2010 and the draft prior to that is
 * sat2r09.pdf . The SAT-3 project has started and the most recent draft
 * is sat3r01.pdf .
 */

/* This program uses a ATA PASS-THROUGH (16 or 12) SCSI command defined
 * by SAT to package an ATA READ LOG EXT (2Fh) command to fetch
 * log page 11h. That page contains SATA phy event counters.
 * For ATA READ LOG EXT command see ATA-8/ACS at www.t13.org .
 * For SATA phy counter definitions see SATA 2.5 .
 *
 * Invocation: see the usage() function below
 */

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_PASS_THROUGH12 0xa1     /* clashes with MMC BLANK comand */
#define SAT_ATA_PASS_THROUGH12_LEN 12
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */
#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d

#define ATA_READ_LOG_EXT 0x2f
#define SATA_PHY_EVENT_LPAGE 0x11
#define READ_LOG_EXT_RESPONSE_LEN 512

#define DEF_TIMEOUT 20

#define EBUFF_SZ 256

static char * version_str = "1.03 20110401";

static struct option long_options[] = {
        {"ck_cond", no_argument, 0, 'c'},
        {"extend", no_argument, 0, 'e'},
        {"hex", no_argument, 0, 'H'},
        {"ignore", no_argument, 0, 'i'},
        {"len", no_argument, 0, 'l'},
        {"raw", no_argument, 0, 'r'},
        {"reset", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct phy_event_t {
    int id;
    char * desc;
};

static struct phy_event_t phy_event_arr[] = {   /* SATA 2.5 section 13.7.2 */
    {0x1, "Command failed and ICRC error bit set in Error register"}, /* M */
    {0x2, "R_ERR(p) response for data FIS"},
    {0x3, "R_ERR(p) response for device-to-host data FIS"},
    {0x4, "R_ERR(p) response for host-to-device data FIS"},
    {0x5, "R_ERR(p) response for non-data FIS"},
    {0x6, "R_ERR(p) response for device-to-host non-data FIS"},
    {0x7, "R_ERR(p) response for host-to-device non-data FIS"},
    {0x8, "Device-to-host non-data FIS retries"},
    {0x9, "Transition from drive PHYRDY to drive PHYRDYn"},
    {0xa, "Signature device-to-host register FISes due to COMRESET"}, /* M */
    {0xb, "CRC errors within host-to-device FIS"},
    {0xd, "non CRC errors within host-to-device FIS"},
    {0xf, "R_ERR(p) response for host-to-device data FIS, CRC"},
    {0x10, "R_ERR(p) response for host-to-device data FIS, non-CRC"},
    {0x12, "R_ERR(p) response for host-to-device non-data FIS, CRC"},
    {0x13, "R_ERR(p) response for host-to-device non-data FIS, non-CRC"},
    {0xc00, "PM: host-to-device non-data FIS, R_ERR(p) due to collision"},
    {0xc01, "PM: signature register - device-to-host FISes"},
    {0xc02, "PM: corrupts CRC propagation of device-to-host FISes"},
    {0x0, NULL},        /* end marker */        /* M(andatory) */
};

static void
usage()
{
    fprintf(stderr, "Usage: "
          "sg_sat_phy_event [--ck_cond] [--extend] [--help] [--hex] "
          "[--ignore]\n"
          "                        [--len=16|12] [--raw] [--reset] "
          "[--verbose]\n"
          "                        [--version] DEVICE\n"
          "  where:\n"
          "    --ck_cond|-c    sets ck_cond bit in cdb (def: 0)\n"
          "    --extend|-e     sets extend bit in cdb (def: 0)\n"
          "    --help|-h       print this usage message then exit\n"
          "    --hex|-H        output response in hex bytes, use twice for\n"
          "                    hex words\n"
          "    --ignore|-i     ignore identifier names, output id value "
          "instead\n"
          "    --len=16|12 | -l 16|12    cdb length: 16 or 12 bytes "
          "(default: 16)\n"
          "    --raw|-r        output response in binary to stdout\n"
          "    --reset|-R      reset counters (after read)\n"
          "    --verbose|-v    increase verbosity\n"
          "    --version|-V    print version string then exit\n\n"
          "Sends an ATA READ LOG EXT command via a SAT pass through to "
          "fetch\nlog page 11h which contains SATA phy event counters\n");
}

static const char *
find_phy_desc(int id)
{
    const struct phy_event_t * pep;

    for (pep = phy_event_arr; pep->desc; ++pep) {
        if ((id & 0xfff) == pep->id)
            return pep->desc;
    }
    return NULL;
}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

/* ATA READ LOG EXT command [2Fh, PIO data-in] */
/* N.B. "log_addr" is the log page number, "page_in_log" is usually zero */
static int
do_read_log_ext(int sg_fd, int log_addr, int page_in_log, int feature,
                int blk_count, void * resp, int mx_resp_len, int cdb_len,
                int ck_cond, int extend, int do_hex, int do_raw, int verbose)
{
    int ok, res, ret;
    int protocol = 4;   /* PIO data-in */
    int t_dir = 1;      /* 0 -> to device, 1 -> from device */
    int byte_block = 1; /* 0 -> bytes, 1 -> 512 byte blocks */
    int t_length = 2;   /* 0 -> no data transferred, 2 -> sector count */
    int resid = 0;
    int got_ard = 0;    /* got ATA result descriptor */
    int sb_sz;
    struct sg_scsi_sense_hdr ssh;
    unsigned char sense_buffer[64];
    unsigned char ata_return_desc[16];
    unsigned char aptCmdBlk[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char apt12CmdBlk[SAT_ATA_PASS_THROUGH12_LEN] =
                {SAT_ATA_PASS_THROUGH12, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0};

    sb_sz = sizeof(sense_buffer);
    memset(sense_buffer, 0, sb_sz);
    memset(ata_return_desc, 0, sizeof(ata_return_desc));
    ok = 0;
    if (SAT_ATA_PASS_THROUGH16_LEN == cdb_len) {
        /* Prepare ATA PASS-THROUGH COMMAND (16) command */
        aptCmdBlk[3] = (feature >> 8) & 0xff;   /* feature(15:8) */
        aptCmdBlk[4] = feature & 0xff;          /* feature(7:0) */
        aptCmdBlk[5] = (blk_count >> 8) & 0xff; /* sector_count(15:8) */
        aptCmdBlk[6] = blk_count & 0xff;        /* sector_count(7:0) */
        aptCmdBlk[8] = log_addr & 0xff;  /* lba_low(7:0) == LBA(7:0) */
        aptCmdBlk[9] = (page_in_log >> 8) & 0xff;
                /* lba_mid(15:8) == LBA(39:32) */
        aptCmdBlk[10] = page_in_log & 0xff; /* lba_mid(7:0) == LBA(15:8) */
        aptCmdBlk[14] = ATA_READ_LOG_EXT;
        aptCmdBlk[1] = (protocol << 1) | extend;
        aptCmdBlk[2] = (ck_cond << 5) | (t_dir << 3) |
                       (byte_block << 2) | t_length;
        res = sg_ll_ata_pt(sg_fd, aptCmdBlk, cdb_len, DEF_TIMEOUT, resp,
                           NULL /* doutp */, mx_resp_len, sense_buffer,
                           sb_sz, ata_return_desc,
                           sizeof(ata_return_desc), &resid, verbose);
    } else {
        /* Prepare ATA PASS-THROUGH COMMAND (12) command */
        apt12CmdBlk[3] = feature & 0xff;        /* feature(7:0) */
        apt12CmdBlk[4] = blk_count & 0xff;        /* sector_count(7:0) */
        apt12CmdBlk[5] = log_addr & 0xff;  /* lba_low(7:0) == LBA(7:0) */
        apt12CmdBlk[6] = page_in_log & 0xff; /* lba_mid(7:0) == LBA(15:8) */
        apt12CmdBlk[9] = ATA_READ_LOG_EXT;
        apt12CmdBlk[1] = (protocol << 1);
        apt12CmdBlk[2] = (ck_cond << 5) | (t_dir << 3) |
                         (byte_block << 2) | t_length;
        res = sg_ll_ata_pt(sg_fd, apt12CmdBlk, cdb_len, DEF_TIMEOUT, resp,
                           NULL /* doutp */, mx_resp_len, sense_buffer,
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
                fprintf(stderr, "Aborted command\n");
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
                return SG_LIB_CAT_ABORTED_COMMAND;
        }
        ok = 1;
    }

    if (ok) { /* output result if ok and --hex or --raw given */
        if (do_raw)
            dStrRaw((const char *)resp, mx_resp_len);
        else if (1 == do_hex)
            dStrHex((const char *)resp, mx_resp_len, 0);
        else if (do_hex > 1)
            dWordHex((const unsigned short *)resp, mx_resp_len / 2, 0,
                     sg_is_big_endian());
    }
    return 0;
}


int main(int argc, char * argv[])
{
    int sg_fd, c, k, j, res, id, len, vendor;
    char * device_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char inBuff[READ_LOG_EXT_RESPONSE_LEN];
    int cdb_len = 16;
    int hex = 0;
    int ignore = 0;
    int raw = 0;
    int reset = 0;
    int verbose = 0;
    int ck_cond = 0;   /* set to 1 to read register(s) back */
    int extend = 0;
    int ret = 0;
    uint64_t ull;
    const char * cp;

    memset(inBuff, 0, sizeof(inBuff));
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "cehHil:rRvV",
                        long_options, &option_index);
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
            exit(0);
        case 'H':
            ++hex;
            break;
        case 'i':
            ++ignore;
            break;
        case 'l':
           cdb_len = sg_get_num(optarg);
           if (! ((cdb_len == 12) || (cdb_len == 16))) {
                fprintf(stderr, "argument to '--len' should be 12 or 16\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            ++raw;
            break;
        case 'R':
            ++reset;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            exit(0);
        default:
            fprintf(stderr, "unrecognised option code %c [0x%x]\n", c, c);
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
    if (0 == device_name) {
        fprintf(stderr, "no DEVICE name detected\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = open(device_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg_sat_phy_event: error opening file: %s", device_name);
        perror(ebuff);
        return SG_LIB_FILE_ERROR;
    }
    ret = do_read_log_ext(sg_fd, SATA_PHY_EVENT_LPAGE, 0 /* page_in_log */,
                          (reset ? 1 : 0) /* feature */,
                          1 /* blk_count */, inBuff,
                          READ_LOG_EXT_RESPONSE_LEN, cdb_len, ck_cond,
                          extend, hex, raw, verbose);

    if ((0 == ret) && (0 == hex) && (0 == raw)) {
        printf("SATA phy event counters:\n");
        for (k = 4; k < 512; k += (len + 2)) {
            id = (inBuff[k + 1] << 8) + inBuff[k];
            if (0 == id)
                break;
            len = ((id >> 12) & 0x7) * 2;
            vendor = !!(id & 0x8000);
            id = id & 0xfff;
            ull = 0;
            for (j = len - 1; j >= 0; --j) {
                if (j < (len - 1))
                    ull <<= 8;
                ull |= inBuff[k + 2 + j];
            }
            cp = NULL;
            if ((0 == vendor) && (0 == ignore))
                cp = find_phy_desc(id);
            if (cp)
                printf("  %s: %" PRIu64 "\n", cp, ull);
            else
                printf("  id=0x%x, vendor=%d, data_len=%d, "
                       "val=%" PRIu64 "\n", id, vendor, len, ull);
        }
    }

    res = close(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
