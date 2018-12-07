/*
 * Copyright (c) 2011-2018 Hannes Reinecke, SUSE Labs
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
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/*
 * A utility program for the Linux OS SCSI subsystem.
 *  Copyright (C) 2004-2010 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program issues the SCSI command RECEIVE COPY RESULTS to a given
 * SCSI device.
 * It sends the command with the service action passed as the sa argument,
 * and the optional list identifier passed as the list_id argument.
 */

static const char * version_str = "1.23 20180625";


#define MAX_XFER_LEN 10000


#define ME "sg_copy_results: "

#define EBUFF_SZ 256

struct descriptor_type {
    int code;
    char desc[124];
};

struct descriptor_type target_descriptor_codes[] = {
    { 0xe0, "Fibre Channel N_Port_Name"},
    { 0xe1, "Fibre Channel N_port_ID"},
    { 0xe2, "Fibre Channesl N_port_ID with N_Port_Name checking"},
    { 0xe3, "Parallel Interface T_L" },
    { 0xe4, "Identification descriptor" },
    { 0xe5, "IPv4" },
    { 0xe6, "Alias" },
    { 0xe7, "RDMA" },
    { 0xe8, "IEEE 1395 EUI-64" },
    { 0xe9, "SAS Serial SCSI Protocol" },
    { 0xea, "IPv6" },
    { 0xeb, "IP Copy Service" },
    { -1, "" }
};

struct descriptor_type segment_descriptor_codes [] = {
    { 0x00, "Copy from block device to stream device" },
    { 0x01, "Copy from stream device to block device" },
    { 0x02, "Copy from block device to block device" },
    { 0x03, "Copy from stream device to stream device" },
    { 0x04, "Copy inline data to stream device" },
    { 0x05, "Copy embedded data to stream device" },
    { 0x06, "Read from stream device and discard" },
    { 0x07, "Verify block or stream device operation" },
    { 0x08, "Copy block device with offset to stream device" },
    { 0x09, "Copy stream device to block device with offset" },
    { 0x0A, "Copy block device with offset to block device with offset" },
    { 0x0B, "Copy from block device to stream device "
      "and hold a copy of processed data for the application client" },
    { 0x0C, "Copy from stream device to block device "
      "and hold a copy of processed data for the application client" },
    { 0x0D, "Copy from block device to block device "
      "and hold a copy of processed data for the application client" },
    { 0x0E, "Copy from stream device to stream device "
      "and hold a copy of processed data for the application client" },
    { 0x0F, "Read from stream device "
      "and hold a copy of processed data for the application client" },
    { 0x10, "Write filemarks to sequential-access device" },
    { 0x11, "Space records or filemarks on sequential-access device" },
    { 0x12, "Locate on sequential-access device" },
    { 0x13, "Image copy from sequential-access device to sequential-access "
            "device" },
    { 0x14, "Register persistent reservation key" },
    { 0x15, "Third party persistent reservations source I_T nexus" },
    { -1, "" }
};


static void
scsi_failed_segment_details(uint8_t *rcBuff, unsigned int rcBuffLen)
{
    int senseLen;
    unsigned int len;
    char senseBuff[1024];

    if (rcBuffLen < 4) {
        pr2serr("  <<not enough data to procedd report>>\n");
        return;
    }
    len = sg_get_unaligned_be32(rcBuff + 0);
    if (len + 4 > rcBuffLen) {
        pr2serr("  <<report len %d > %d too long for internal buffer, output "
                "truncated\n", len, rcBuffLen);
    }
    if (len < 52) {
        pr2serr("  <<no segment details, response data length %d\n", len);
        return;
    }
    printf("Receive copy results (failed segment details):\n");
    printf("    Extended copy command status: %d\n", rcBuff[56]);
    senseLen = sg_get_unaligned_be16(rcBuff + 58);
    sg_get_sense_str("    ", &rcBuff[60], senseLen, 0, 1024, senseBuff);
    printf("%s", senseBuff);
}

static void
scsi_copy_status(uint8_t *rcBuff, unsigned int rcBuffLen)
{
    unsigned int len;

    if (rcBuffLen < 4) {
        pr2serr("  <<not enough data to proceed report>>\n");
        return;
    }
    len = sg_get_unaligned_be32(rcBuff + 0);
    if (len + 4 > rcBuffLen) {
        pr2serr("  <<report len %d > %d too long for internal buffer, output "
                "truncated\n", len, rcBuffLen);
    }
    printf("Receive copy results (copy status):\n");
    printf("    Held data discarded: %s\n", rcBuff[4] & 0x80 ? "Yes":"No");
    printf("    Copy manager status: ");
    switch (rcBuff[4] & 0x7f) {
    case 0:
        printf("Operation in progress\n");
        break;
    case 1:
        printf("Operation completed without errors\n");
        break;
    case 2:
        printf("Operation completed with errors\n");
        break;
    default:
        printf("Unknown/Reserved\n");
        break;
    }
    printf("    Segments processed: %u\n", sg_get_unaligned_be16(rcBuff + 5));
    printf("    Transfer count units: %u\n", rcBuff[7]);
    printf("    Transfer count: %u\n", sg_get_unaligned_be32(rcBuff + 8));
}

static void
scsi_operating_parameters(uint8_t *rcBuff, unsigned int rcBuffLen)
{
    unsigned int len, n;

    len = sg_get_unaligned_be32(rcBuff + 0);
    if (len + 4 > rcBuffLen) {
        pr2serr("  <<report len %d > %d too long for internal buffer, output "
                "truncated\n", len, rcBuffLen);
    }
    printf("Receive copy results (report operating parameters):\n");
    printf("    Supports no list identifier (SNLID): %s\n",
           rcBuff[4] & 1 ? "yes" : "no");
    n = sg_get_unaligned_be16(rcBuff + 8);
    printf("    Maximum target descriptor count: %u\n", n);
    n = sg_get_unaligned_be16(rcBuff + 10);
    printf("    Maximum segment descriptor count: %u\n", n);
    n = sg_get_unaligned_be32(rcBuff + 12);
    printf("    Maximum descriptor list length: %u bytes\n", n);
    n = sg_get_unaligned_be32(rcBuff + 16);
    printf("    Maximum segment length: %u bytes\n", n);
    n = sg_get_unaligned_be32(rcBuff + 20);
    if (n == 0) {
        printf("    Inline data not supported\n");
    } else {
        printf("    Maximum inline data length: %u bytes\n", n);
    }
    n = sg_get_unaligned_be32(rcBuff + 24);
    printf("    Held data limit: %u bytes\n", n);
    n = sg_get_unaligned_be32(rcBuff + 28);
    printf("    Maximum stream device transfer size: %u bytes\n", n);
    n = sg_get_unaligned_be16(rcBuff + 34);
    printf("    Total concurrent copies: %u\n", n);
    printf("    Maximum concurrent copies: %u\n", rcBuff[36]);
    if (rcBuff[37] > 30)
        printf("    Data segment granularity: 2**%u bytes\n", rcBuff[37]);
    else
        printf("    Data segment granularity: %u bytes\n",
               (unsigned int)(1 << rcBuff[37]));
    if (rcBuff[38] > 30)
        printf("    Inline data granularity: %u bytes\n", rcBuff[38]);
    else
        printf("    Inline data granularity: %u bytes\n",
               (unsigned int)(1 << rcBuff[38]));
    if (rcBuff[39] > 30)
        printf("    Held data granularity: 2**%u bytes\n", rcBuff[39]);
    else
        printf("    Held data granularity: %u bytes\n",
               (unsigned int)(1 << rcBuff[39]));

    printf("    Implemented descriptor list:\n");
    for (n = 0; n < rcBuff[43]; n++) {
        int code = rcBuff[44 + n];

        if (code < 0x16) {
            struct descriptor_type *seg_desc = segment_descriptor_codes;
            while (strlen(seg_desc->desc)) {
                if (seg_desc->code == code)
                    break;
                seg_desc++;
            }
            printf("        Segment descriptor 0x%02x: %s\n", code,
                   strlen(seg_desc->desc) ? seg_desc->desc : "Reserved");
        } else if (code < 0xc0) {
            printf("        Segment descriptor 0x%02x: Reserved\n", code);
        } else if (code < 0xe0) {
            printf("        Vendor specific descriptor 0x%02x\n", code);
        } else {
            struct descriptor_type *tgt_desc = target_descriptor_codes;

            while (strlen(tgt_desc->desc)) {
                if (tgt_desc->code == code)
                    break;
                tgt_desc++;
            }
            printf("        Target descriptor 0x%02x: %s\n", code,
                   strlen(tgt_desc->desc) ? tgt_desc->desc : "Reserved");
        }
    }
    printf("\n");
}

static struct option long_options[] = {
        {"failed", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"list_id", required_argument, 0, 'l'},
        {"list-id", required_argument, 0, 'l'},
        {"params", no_argument, 0, 'p'},
        {"readonly", no_argument, 0, 'R'},
        {"receive", no_argument, 0, 'r'},
        {"status", no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"xfer_len", required_argument, 0, 'x'},
        {0, 0, 0, 0},
};

static void
usage()
{
  pr2serr("Usage: "
          "sg_copy_results [--failed|--params|--receive|--status] [--help]\n"
          "                       [--hex] [--list_id=ID] [--readonly] "
          "[--verbose]\n"
          "                       [--version] [--xfer_len=BTL] DEVICE\n"
          "  where:\n"
          "    --failed|-f          use FAILED SEGMENT DETAILS service "
          "action\n"
          "    --help|-h            print out usage message\n"
          "    --hex|-H             print out response buffer in hex\n"
          "    --list_id=ID|-l ID   list identifier (default: 0)\n"
          "    --params|-p          use OPERATING PARAMETERS service "
          "action\n"
          "    --readonly|-R        open DEVICE read-only (def: read-write)\n"
          "    --receive|-r         use RECEIVE DATA service action\n"
          "    --status|-s          use COPY STATUS service action\n"
          "    --verbose|-v         increase verbosity\n"
          "    --version|-V         print version string then exit\n"
          "    --xfer_len=BTL|-x BTL    byte transfer length (< 10000) "
          "(default:\n"
          "                             520 bytes)\n\n"
          "Performs a SCSI RECEIVE COPY RESULTS command. Returns the "
          "response as\nspecified by the service action parameters.\n"
          );
}

static const char * rec_copy_name_arr[] = {
    "Receive copy status(LID1)",
    "Receive copy data(LID1)",
    "Receive copy [0x2]",
    "Receive copy operating parameters",
    "Receive copy failure details(LID1)",
};

int
main(int argc, char * argv[])
{
    bool do_hex = false;
    bool o_readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c, k;
    int ret = 1;
    int sa = 3;
    int sg_fd = -1;
    int verbose = 0;
    int xfer_len = 520;
    uint32_t list_id = 0;
    const char * cp;
    uint8_t * cpResultBuff = NULL;
    uint8_t * free_cprb = NULL;
    const char * device_name = NULL;
    char file_name[256];

    memset(file_name, 0, sizeof file_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "fhHl:prRsvVx:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'f':
            sa = 4;
            break;
        case 'H':
            do_hex = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            k = sg_get_num(optarg);
            if (-1 == k) {
                pr2serr("bad argument to '--list_id'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            list_id = (uint32_t)k;
            break;
        case 'p':
            sa = 3;
            break;
        case 'r':
            sa = 1;
            break;
        case 'R':
            o_readonly = true;
            break;
        case 's':
            sa = 0;
            break;
        case 'v':
            ++verbose;
            verbose_given = true;
            break;
        case 'V':
            version_given = true;
            break;
        case 'x':
            xfer_len = sg_get_num(optarg);
            if (-1 == xfer_len) {
                pr2serr("bad argument to '--xfer_len'\n");
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
        pr2serr(ME "version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (xfer_len >= MAX_XFER_LEN) {
        pr2serr("xfer_len (%d) is out of range ( < %d)\n", xfer_len,
                MAX_XFER_LEN);
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    cpResultBuff = (uint8_t *)sg_memalign(xfer_len, 0, &free_cprb,
                                          verbose > 3);
    if (NULL == cpResultBuff) {
            pr2serr(ME "out of memory\n");
            return sg_convert_errno(ENOMEM);
    }

    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto finish;
    }

    if ((sa < 0) || (sa >= (int)SG_ARRAY_SIZE(rec_copy_name_arr)))
        cp = "Out of range service action";
    else
        cp = rec_copy_name_arr[sa];
    if (verbose)
        pr2serr(ME "issue %s to device %s\n\t\txfer_len= %d (0x%x), list_id=%"
                PRIu32 "\n", cp, device_name, xfer_len, xfer_len, list_id);

    res = sg_ll_receive_copy_results(sg_fd, sa, list_id, cpResultBuff,
                                     xfer_len, true, verbose);
    ret = res;
    if (res) {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("  SCSI %s failed: %s\n", cp, b);
        goto finish;
    }
    if (do_hex) {
        hex2stdout(cpResultBuff, xfer_len, 1);
        goto finish;
    }
    switch (sa) {
    case 4: /* Failed segment details */
        scsi_failed_segment_details(cpResultBuff, xfer_len);
        break;
    case 3: /* Operating parameters */
        scsi_operating_parameters(cpResultBuff, xfer_len);
        break;
    case 0: /* Copy status */
        scsi_copy_status(cpResultBuff, xfer_len);
        break;
    default:
        hex2stdout(cpResultBuff, xfer_len, 1);
        break;
    }

finish:
    if (free_cprb)
        free(free_cprb);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr(ME "close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_copy_results failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
