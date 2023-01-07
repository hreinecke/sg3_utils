/*
 * Copyright (c) 2014-2023 Hannes Reinecke, SUSE Linux GmbH.
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
 * See https://www.t10.org for drafts. SAT is a standard: SAT ANSI INCITS
 * 431-2007 (draft prior to that is sat-r09.pdf). SAT-2 is also a
 * standard: SAT-2 ANSI INCITS 465-2010 and the draft prior to that is
 * sat2r09.pdf . The SAT-3 project has started and the most recent draft
 * is sat3r01.pdf .
 */

/* This program performs a ATA PASS-THROUGH (12|16|32) SCSI command in order
 * to perform/tunnel an ATA READ LOG EXT, ATA READ LOG DMA EXT, or ATA READ
 * SMART LOG command.
 *
 * See man page (sg_sat_read_gplog.8) for details.
 */

#define MY_NAME "sg_sat_read_gplog"

#define SAT_ATA_PASS_THROUGH32_LEN 32
#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_PASS_THROUGH12 0xa1     /* clashes with MMC BLANK command */
#define SAT_ATA_PASS_THROUGH12_LEN 12
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */
#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d

#define ATA_READ_LOG_EXT 0x2f
#define ATA_READ_LOG_DMA_EXT 0x47
#define ATA_SMART_READ_LOG 0xb0
#define ATA_SMART_READ_LOG_FEATURE 0xd5
#define DIRECTORY_LOG_ADDR 0x0

#define DEF_PPT 64
#define DEF_TIMEOUT 20

#define MAX_LAR_LIST_ELEMS 8

static const char * version_str = "1.26 20230106";

struct opts_t {
    bool ck_cond;
    bool do_multiple;
    bool do_smart;
    bool rdonly;
    bool no_output;
    int cdb_len;
    int count;
    int hex;
    int pn;             /* page number within log address */
    int ppt;            /* pages per transfer */
    int verbose;
    uint8_t la_lo_a[MAX_LAR_LIST_ELEMS];
    uint8_t la_hi_a[MAX_LAR_LIST_ELEMS];
    const char * device_name;
};

static struct option long_options[] = {
    {"address", required_argument, 0, 'a'},
    {"count", required_argument, 0, 'c'},
    {"ck_cond", no_argument, 0, 'C'},
    {"ck-cond", no_argument, 0, 'C'},
    {"dma", no_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"len", required_argument, 0, 'l'},
    {"log", required_argument, 0, 'L'},
    {"page", required_argument, 0, 'p'},
    {"ppt", required_argument, 0, 'P'},
    {"readonly", no_argument, 0, 'r'},
    {"smart", no_argument, 0, 's'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
          "sg_sat_read_gplog [--address=LA_L] [--ck_cond] [--count=CO] "
          "[--dma]\n"
          "                         [--help] [--hex] [--len=CDB_LEN] "
          "[--log=LA_L]\n"
          "                         [--ppt=PPT] [--readonly] [--smart] "
          "[--verbose]\n"
          "                         [--version] DEVICE\n"
          "  where:\n"
          "    --address=LA_L | -a LA_L    same as --log=LA_L option below\n"
          "    --ck_cond | -C          set ck_cond field in pass-through "
          "(def: 0)\n"
          "    --count=CO | -c CO      count of page numbers to fetch "
          "(def: 1)\n"
          "    --dma | -d              Use READ LOG DMA EXT (def: READ LOG "
          "EXT)\n"
          "    --help | -h             output this usage message\n"
          "    --hex | -H              output response in hex bytes, -HH "
          "yields hex\n"
          "                            words + ASCII (def), -HHH hex words "
          "only\n"
          "    --len=CDB_LEN | -l CDB_LEN    cdb length: 12, 16 or 32 bytes "
          "(def: 16)\n"
          "    --log=LA_L | -L LA_L    Log address, log address range or "
          "list of ...\n"
          "                            See below for syntax\n"
          "    --page=PN|-p PN         Log page number within address (def: "
          "0)\n"
          "    --ppt=PPT|-P PPT        pages per transfer (def: %d)\n"
          "    --readonly | -r         open DEVICE read-only (def: "
          "read-write)\n"
          "    --smart | -s            send the ATA SMART READ LOG command "
          "instead\n"
          "    --verbose | -v          increase verbosity\n"
          "                            recommended if DEVICE is ATA disk\n"
          "    --version | -V          print version string and exit\n\n"
          "Sends an ATA READ LOG (DMA) EXT or a SMART READ LOG command via "
          "a SAT\npass-through to fetch one or more General Purpose (GP) "
          "or SMART log pages.\nEach page is accessed via a log address "
          "(LA) and then a page number\nwithin that address. Multiple "
          "log addresses can be given in the LA_L\nargument to the "
          "--address= and --log= options. It may contain a comma\nseparated "
          "list with each element either being a single LA or a range with\n"
          "this format: 'lo:hi'. LA_R syntax summary: "
          "lo:hi,lo2:hi2,lo3:hi3,...\n",
           DEF_PPT);
}

static void
show_x_log_directory(int ata_cmd, const uint8_t * buff, int num_bytes)
{
    int k;
    const char * ccp = (ATA_SMART_READ_LOG == ata_cmd) ?
                                "SMART" : "General purpose";
    uint16_t w;


    printf("%s log directory:\n", ccp);
    for (k = 0; (k < num_bytes) && (k < 512); k += 2) {
        w = sg_get_unaligned_le16(buff + k);
        if (0 == k)
            printf("  %s logging version: %xh\n", ccp, w);
        else if (w > 0)
            printf("    Number of log pages at log address %02xh: %u\n",
                   k >> 1, w);
    }
}

/* Return of 0 is good. If read broken into multiple pieces due to
 * --count=CO being > --ppt=PPT then inbuff will contain the last piece
 * read and *inbuff_wr_bytesp wil hold its length in bytes. */
static int
do_read_gplog(int sg_fd, int ata_cmd, uint8_t la, uint8_t * inbuff,
              int * inbuff_wr_bytesp, const struct opts_t * op)
{
    bool got_ard = false;      /* got ATA result descriptor */
    int k, ppt, res, ret, protocol, num_bytes, num_words, max;
    int resid = 0;
    const int vb = op->verbose;
    const int vb_1 = (vb > 0) ? vb - 1 : vb;
    const char * ata_cmd_name = "READ LOG EXT";
    struct sg_scsi_sense_hdr ssh;
    uint8_t sense_buffer[64] SG_C_CPP_ZERO_INIT;
    uint8_t ata_ret_desc[16] SG_C_CPP_ZERO_INIT;
    uint8_t apt_cdb[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t apt12_cdb[SAT_ATA_PASS_THROUGH12_LEN] =
                {SAT_ATA_PASS_THROUGH12, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0};
    uint8_t apt32_cdb[SAT_ATA_PASS_THROUGH32_LEN] SG_C_CPP_ZERO_INIT;
    char pt_name[48];
    static const int sb_sz = sizeof(sense_buffer);
    static const int ard_sz = sizeof(ata_ret_desc);
    static const bool extend = true;
    /* vvv, false -> 512 byte blocks, true -> logical sectors */
    static const bool t_type = false;
    /* vvv, false: to device, true: from device */
    static const bool t_dir = true;
    /* vvv, false: bytes, true: 512 byte blocks */
    static const bool byte_block = true;
    /* vvv, 0 -> no data transferred, 2 -> sector count */
    static const int t_length = 2;

    snprintf(pt_name, sizeof(pt_name), "ATA PASS-THROUGH (%d)",
             op->cdb_len);
    if (ata_cmd == ATA_READ_LOG_DMA_EXT) {
        protocol = 6; /* DMA */
        ata_cmd_name = "READ LOG DMA EXT";
    } else {
        protocol = 4; /* PIO Data-In */
        if (ata_cmd == ATA_SMART_READ_LOG)
            ata_cmd_name = "SMART READ LOG";
    }
    if ((! op->no_output) && (op->hex > 4))
        printf("\n# Log address: 0x%x, page number: %d, count: %d\n",
               la, op->pn, op->count);
    if (inbuff_wr_bytesp)
        *inbuff_wr_bytesp = 0;
    max = op->pn + op->count;

    /* k should not exceed 255 for the ATA_SMART_READ_LOG command */
    for (k = op->pn; k < max; k += op->ppt) {
        ppt = ((k + op->ppt) > max) ? max - k : op->ppt;
        num_bytes = ppt * 512;
        num_words = ppt * 256;
        memset(inbuff, 0, num_bytes);
        if (vb > 1)
            pr2serr("Building ATA %s command; la=0x%x, pn=0x%x, "
                    "this_count=%d\n", ata_cmd_name, la, k, ppt);
        switch (op->cdb_len) {
        case 32:    /* SAT-4 revision 5 or later */
            if (ATA_SMART_READ_LOG == ata_cmd) {
                apt32_cdb[21] = ATA_SMART_READ_LOG_FEATURE;
                apt32_cdb[18] = 0x4f;
                apt32_cdb[17] = 0xc2;
            } else {    /* ugly split for page number */
                apt32_cdb[15] = (k >> 8) & 0xff;
                apt32_cdb[18] = k & 0xff;
            }
            sg_put_unaligned_be16(ppt, apt32_cdb + 22);/* this xfer's count */
            apt32_cdb[19] = la;
            apt32_cdb[25] = ata_cmd;
            apt32_cdb[10] = (protocol << 1);
            if (extend)
                apt32_cdb[10] |= 0x1;
            apt32_cdb[11] = t_length;
            if (op->ck_cond)
                apt32_cdb[11] |= 0x20;
            if (t_type)
                apt32_cdb[11] |= 0x10;
            if (t_dir)
                apt32_cdb[11] |= 0x8;
            if (byte_block)
                apt32_cdb[11] |= 0x4;
            /* following call fixes all bytes below offset 10 in cdb */
            res = sg_ll_ata_pt(sg_fd, apt32_cdb, op->cdb_len, DEF_TIMEOUT,
                               inbuff, NULL /* doutp */, num_bytes,
                               sense_buffer, sb_sz, ata_ret_desc,
                               ard_sz, &resid, vb_1);
            break;
        case 16:
            /* Prepare ATA PASS-THROUGH COMMAND (16) command */
            apt_cdb[14] = ata_cmd;
            if (ATA_SMART_READ_LOG == ata_cmd) {
                apt_cdb[4] = ATA_SMART_READ_LOG_FEATURE;
                apt_cdb[10] = 0x4f;
                apt_cdb[12] = 0xc2;
            } else
                sg_put_unaligned_be16((uint16_t)k, apt_cdb + 9);
            sg_put_unaligned_be16((uint16_t)ppt, apt_cdb + 5);
            apt_cdb[8] = la;
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
            res = sg_ll_ata_pt(sg_fd, apt_cdb, op->cdb_len, DEF_TIMEOUT,
                               inbuff, NULL, num_bytes, sense_buffer, sb_sz,
                               ata_ret_desc, ard_sz, &resid, vb_1);
            break;
        case 12:
            /* Prepare ATA PASS-THROUGH COMMAND (12) command */
            /* Cannot map upper 8 bits of the pn since no LBA (39:32) field */
            apt12_cdb[9] = ata_cmd;
            if (ATA_SMART_READ_LOG == ata_cmd) {
                apt12_cdb[3] = ATA_SMART_READ_LOG_FEATURE;
                apt12_cdb[6] = 0x4f;
                apt12_cdb[7] = 0xc2;
            } else
                apt12_cdb[6] = k & 0xff;
            apt12_cdb[4] = ppt;
            apt12_cdb[5] = la;
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
                               inbuff, NULL, num_bytes, sense_buffer, sb_sz,
                               ata_ret_desc, ard_sz, &resid, vb_1);
            break;
        default:
            pr2serr("%s: logic error\n", __func__);
            return SG_LIB_SYNTAX_ERROR;
        }
        if (0 == res) {
            if (vb > 2) {
                pr2serr("SCSI %s command completed with GOOD status\n",
                        pt_name);
                if (vb > 3)
                    pr2serr("    requested_bytes=%d, resid=%d\n", num_bytes,
                            resid);
            }
            if (resid > 0) {
                num_bytes -= resid;
                if (vb > 0)
                    pr2serr(">>> resid=%d leaving num_bytes=%d\n", resid,
                            num_bytes);
                num_words >>= 1;
            }
            if (inbuff_wr_bytesp)
                *inbuff_wr_bytesp = num_bytes;

            if (op->no_output)
                ;
            else if ((DIRECTORY_LOG_ADDR == la) && (0 == op->hex))
                show_x_log_directory(ata_cmd, inbuff, num_bytes);
            else if ((0 == op->hex) || (2 == op->hex))
                dWordHex((const unsigned short *)inbuff, num_words, 0,
                         sg_is_big_endian());
            else if (1 == op->hex)
                hex2stdout(inbuff, num_bytes, 0);
            else if (3 == op->hex)  /* '-HHH' suitable for "hdparm --Istdin" */
                dWordHex((const unsigned short *)inbuff, num_words, -2,
                         sg_is_big_endian());
            else    /* '-HHHH' hex bytes only */
                hex2stdout(inbuff, num_bytes, -1);
        } else if ((res > 0) && (res & SAM_STAT_CHECK_CONDITION)) {
            if (vb > 1) {
                pr2serr("ATA pass through:\n");
                sg_print_sense(NULL, sense_buffer, sb_sz,
                               ((vb > 2) ? 1 : 0));
            }
            if (sg_scsi_normalize_sense(sense_buffer, sb_sz, &ssh)) {
                switch (ssh.sense_key) {
                case SPC_SK_ILLEGAL_REQUEST:
                    if ((0x20 == ssh.asc) && (0x0 == ssh.ascq)) {
                        ret = SG_LIB_CAT_INVALID_OP;
                        if (vb < 2)
                            pr2serr("%s not supported\n", pt_name);
                    } else {
                        ret = SG_LIB_CAT_ILLEGAL_REQ;
                        if (vb < 2)
                            pr2serr("%s, bad field in cdb\n", pt_name);
                    }
                    return ret;
                case SPC_SK_NO_SENSE:
                case SPC_SK_RECOVERED_ERROR:
                    if ((0x0 == ssh.asc) &&
                        (ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq)) {
                        if (SAT_ATA_RETURN_DESC != ata_ret_desc[0]) {
                            if (vb)
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
                    if (vb < 2)
                        pr2serr("%s, Unit Attention detected\n", pt_name);
                    return SG_LIB_CAT_UNIT_ATTENTION;
                case SPC_SK_NOT_READY:
                    if (vb < 2)
                        pr2serr("%s, device not ready\n", pt_name);
                    return SG_LIB_CAT_NOT_READY;
                case SPC_SK_MEDIUM_ERROR:
                case SPC_SK_HARDWARE_ERROR:
                    if (vb < 2)
                        pr2serr("%s, medium or hardware error\n", pt_name);
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
                    pr2serr("%s: data protect, read only media?\n", pt_name);
                    return SG_LIB_CAT_DATA_PROTECT;
                default:
                    if (vb < 2)
                        pr2serr("%s, some sense data, use '-v' for more "
                                "information\n", pt_name);
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
            pr2serr("%s failed\n", pt_name);
            if (vb < 2)
                pr2serr("    try adding '-v' for more information\n");
            return -1;
        }

        if ((SAT_ATA_RETURN_DESC == ata_ret_desc[0]) && (! got_ard))
            pr2serr("Seem to have got ATA Result Descriptor but it was not "
                    "indicated\n");
        if (got_ard) {
            if (ata_ret_desc[3] & 0x4) {
                    pr2serr("error indication in returned FIS: aborted "
                            "command\n");
                    return SG_LIB_CAT_ABORTED_COMMAND;
            }
        }
    }
    return 0;
}

/* Expects list like: 'lo:hi,lo2:hi2,....' where commas separate range
 * elements and range elements are of the form: 'lo:hi' which can degenerate
 * to: 'lo' or 'lo:lo' or 'lo:' or ':hi' or just a single ':' . If the 'lo'
 * is missing, it defaults to 0. If the 'hi' is missing, it defaults to 255.
 * 'lo' and 'lo:lo' have the same meaning. */
static bool
decode_la_list(const char * aname, const char * arg, struct opts_t * op)
{
    uint8_t lo = 0;
    uint8_t hi = 0;;
    int k, j, n;
    const char * lcp;           /* colon pointer */
    const char * mcp;           /* comma pointer */
    const char * ap = arg;
    char an[32];
    char e[64];                 /* each element */
    char q[64];                 /* error string */
    static const int elen = sizeof(e);
    static const int qlen = sizeof(q);
    static const char * le_s = "list element";

    snprintf(an, sizeof(an), "%s option:", aname);
    if (strchr(ap, '-')) {
        pr2serr("%s '-' is invalid in this argument\n", aname);
        pr2serr("  use ':' for ranges and ',' as a list separator\n");
        return false;
    }
    k = 0;
    memset(q, 0, qlen);

    while (0 == q[0]) {
        mcp = strchr(ap, ',');
        if (mcp) {
            if (ap == mcp) {    /* skip empty elements */
                ++ap;
                continue;
            }
            n = (mcp - ap);
            if ('\0' == *(mcp + 1)) {
                pr2serr("%s trailing comma at argument position %d "
                        "suggests an error\n", an, (int)((mcp - arg) + 1));
                return false;
            }
        } else
            n = strlen(ap);
        if (n >= (elen - 1)) {
            snprintf(q, qlen, "%s %d too long", le_s, k + 1);
            break;
        }
        memcpy(e, ap, n);       /* move element into e[] buffer */
        e[n] = '\0';

        lcp = strchr(e, ':');
        if (lcp) {
            if (1 == n) {
                lo = 0;
                hi = 255;
            } else if (':' == e[0]) {
                j = sg_get_num_nomult(lcp + 1);
                if (j < 0 || j > 0xff)
                    snprintf(q, qlen, "%s %d bad high", le_s, k + 1);
                lo = 0;
                hi = j;
            } else {
                j = sg_get_num_nomult(e);
                if (j < 0 || j > 0xff)
                    snprintf(q, qlen, "%s %d bad low", le_s, k + 1);
                else if (':' == *(e + n - 1))   /* is last character ':' */
                    hi = 255;
                else {
                    lo = j;
                    j = sg_get_num_nomult(lcp + 1);
                    if (j < 0 || j > 0xff)
                        snprintf(q, qlen, "%s %d bad high", le_s, k + 1);
                    hi = j;
                }
            }
        } else {
            j = sg_get_num_nomult(e);
            if (j < 0 || j > 0xff) {
                if (0 == k)
                    snprintf(q, qlen, "expect a value between 0 and 255");
                else
                    snprintf(q, qlen, "%s %d bad value", le_s, k + 1);
            } else {
                lo = j;
                hi = lo;
            }
        }
        if (q[0])
            break;
        else {
            if (hi < lo)
                snprintf(q, qlen, "%s %d hi is less than lo", le_s, k + 1);
            else if ((k > 0) && (op->la_hi_a[k - 1] >= lo))
                snprintf(q, qlen, "%s %d overlaps with previous", le_s,
                         k + 1);
            op->la_lo_a[k] = lo;
            op->la_hi_a[k] = hi;
        }
        if (NULL == mcp || q[0])
            break;
        ++k;
        if (k >= MAX_LAR_LIST_ELEMS)
            snprintf(q, qlen, "too many list elements, maximum %d",
                    MAX_LAR_LIST_ELEMS);
        ap = mcp + 1;
    }
    if (q[0]) {
        pr2serr("%s %s\n", an, q);
        return false;
    }
    return true;
}

static int
get_next_la(int * prev_la_indp, int * prev_la_valp, const struct opts_t * op)
{
    int la_in, la, ind;

    la_in = *prev_la_valp;
    if (la_in < 0) {
        *prev_la_indp = 0;
        return op->la_lo_a[0];
    }
    ind = *prev_la_indp;
    la = op->la_lo_a[ind];
    if (la_in < la)
        return la;
    la = op->la_hi_a[ind];
    if (la_in >= la) {
        ++ind;
        if (ind >= MAX_LAR_LIST_ELEMS)
            return -1;
        *prev_la_indp = ind;
        la = op->la_lo_a[ind];
        return (0 == la) ? -1 : la;
    } else
        return la_in + 1;
}


int
main(int argc, char * argv[])
{
    bool verbose_given = false;
    bool version_given = false;
    uint8_t la = 0;
    int c, k, ret, res, n, bytes_fetched;
    int sg_fd = -1;
    int ata_cmd = ATA_READ_LOG_EXT;
    const char *ccp;
    uint8_t *inbuff = NULL;
    uint8_t *free_inbuff = NULL;
    struct opts_t opts;
    struct opts_t * op;
    char b[80];

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->cdb_len = SAT_ATA_PASS_THROUGH16_LEN;
    op->ppt = DEF_PPT;
    op->count = 1;
    if (getenv("SG3_UTILS_INVOCATION"))
        sg_rep_invocation(MY_NAME, version_str, argc, argv, NULL);

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "a:c:CdhHl:L:p:P:rsvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
        case 'L':
            ccp = ('a' == c) ? "--address=" : "--log=";
            if (! decode_la_list(ccp, optarg, op))
                return SG_LIB_SYNTAX_ERROR;
            la = op->la_hi_a[0];
            if ((op->la_lo_a[0] < la) || (la < op->la_lo_a[1]))
                op->do_multiple = true;
            break;
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
            if (ATA_SMART_READ_LOG == ata_cmd) {
                pr2serr("Can't have both READ LOG DMA EXT and SMART LOG "
                        "READ\n");
                return SG_LIB_SYNTAX_ERROR;
            }
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
           if (! ((op->cdb_len == 12) || (op->cdb_len == 16) ||
                 (op->cdb_len == 32))) {
                pr2serr("argument to '--len' should be 12, 16 or 32\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            op->pn = sg_get_num(optarg);
            if ((op->pn < 0) || (op->pn > 0xffff)) {
                pr2serr("bad argument for '--page=', expect 0 to 0xffff\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'P':
            op->ppt = sg_get_num(optarg);
            if ((op->ppt < 1) || (op->ppt > 0xffff)) {
                pr2serr("bad argument for '--ppt=', expect 1 to 0xffff\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            op->rdonly = true;
            break;
        case 's':
            if (ATA_READ_LOG_DMA_EXT == ata_cmd) {
                pr2serr("Can't have both READ LOG DMA EXT and SMART LOG "
                        "READ\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_smart = true;
            ata_cmd = ATA_SMART_READ_LOG;
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
        return SG_LIB_FILE_ERROR;
    }

    if ((op->count > 0xff) && (12 == op->cdb_len)) {
        op->cdb_len = 16;
        if (op->verbose)
            pr2serr("Since count > 0xff, forcing cdb length to "
                    "16\n");
    }
    if (ATA_SMART_READ_LOG == ata_cmd) {
        if (op->count > 0xff) {
            pr2serr("The ATA SMART READ LOG command can only accept count "
                    "values to 255\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if ((! op->do_multiple) && (op->pn > 0)) {
            pr2serr("For a single ATA SMART READ LOG command the page "
                    "number is always 0\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    n = op->ppt * 512;
    inbuff = (uint8_t *)sg_memalign(n, 0, &free_inbuff, op->verbose > 3);
    if (!inbuff) {
        pr2serr("Cannot allocate output buffer of size %d\n", n);
        return SG_LIB_CAT_OTHER;
    } else if (op->verbose > 3)
        pr2serr("allocated %d bytes successfully on heap\n", n);

    if ((sg_fd = sg_cmds_open_device(op->device_name, op->rdonly,
                                     op->verbose)) < 0) {
        if (op->verbose)
            pr2serr("error opening file: %s: %s\n", op->device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }
    if (op->do_multiple) {
        int hold_pn = op->pn;
        int la_val;
        int prev_la_ind = 0;
        int prev_la_val = -1;

        if (op->verbose > 3) {
            pr2serr("decoded LA_L list (in hex):\n");
            for (k = 0; k < MAX_LAR_LIST_ELEMS; ++k)
                pr2serr("0x%x:0x%x, ", op->la_lo_a[k], op->la_hi_a[k]);
            pr2serr("\n");
        }
        la_val = get_next_la(&prev_la_ind, &prev_la_val, op);
        if (la_val < 0)
            goto fini;
        else if (la_val > 0)
            op->no_output = true;
        la = la_val;
        op->count = 1;
        la = DIRECTORY_LOG_ADDR;
        op->pn = 0;
        /* read log directory page */
        ret = do_read_gplog(sg_fd, ata_cmd, la, inbuff, &bytes_fetched, op);
        if (0 == ret) {
            uint8_t b[512];

            /* need copy of log directory cause inbuff gets overwritten */
            memcpy(b, inbuff, bytes_fetched);
            op->no_output = false;
            if (0 == la_val) {
                prev_la_val = la_val;
                la_val = get_next_la(&prev_la_ind, &prev_la_val, op);
            }

            /* loop over each page address (skipping version word) */
            while (la_val > 0) {
                uint16_t w;

                k = (la_val << 1);
                if ((k + 1) >= bytes_fetched)
                    continue;
                w = sg_get_unaligned_le16(b + k);
                if (w > 0) {
                    if ((hold_pn > 0) && (w > hold_pn))
                        w = hold_pn;
                    op->count = w;  /* --ppt=PPT may break into smaller */
                    la = la_val;
                    op->pn = 0;
                    ret = do_read_gplog(sg_fd, ata_cmd, la, inbuff, NULL, op);
                    if (ret)
                        break;
                }
                prev_la_val = la_val;
                la_val = get_next_la(&prev_la_ind, &prev_la_val, op);
            }
        }
    } else {
        la = op->la_lo_a[0];
        ret = do_read_gplog(sg_fd, ata_cmd, la, inbuff, NULL, op);
    }

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
        snprintf(b, sizeof(b), "%s failed: ", MY_NAME);
        if (! sg_if_can2stderr(b, ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    if (free_inbuff)
        free(free_inbuff);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
