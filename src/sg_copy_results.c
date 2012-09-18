/*
 * Copyright (c) 2011-2012 Hannes Reinecke, SUSE Labs
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

/* A utility program for the Linux OS SCSI subsystem.
   *  Copyright (C) 2004-2010 D. Gilbert
   *  This program is free software; you can redistribute it and/or modify
   *  it under the terms of the GNU General Public License as published by
   *  the Free Software Foundation; either version 2, or (at your option)
   *  any later version.

   This program issues the SCSI command RECEIVE COPY RESULTS to a given
   SCSI device.
   It sends the command with the service action passed as the sa argument,
   and the optional list identifier passed as the list_id argument.
*/

static char * version_str = "1.1 20120905";


#define MAX_XFER_LEN 10000

/* #define SG_DEBUG */

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
scsi_failed_segment_details(unsigned char *rcBuff, unsigned int rcBuffLen)
{
    unsigned int len;
    char senseBuff[1024];
    int senseLen;

    if (rcBuffLen < 4) {
        fprintf(stderr, "  <<not enough data to procedd report>>\n");
        return;
    }
    len = (rcBuff[0] << 24) | (rcBuff[1] << 16) | (rcBuff[2] << 8) |
          rcBuff[3];
    if (len + 3 > rcBuffLen) {
        fprintf(stderr, "  <<report too long for internal buffer,"
                " output truncated\n");
    }
    if (len < 52) {
        fprintf(stderr, "  <<no segment details, response data length %d\n",
                len);
        return;
    }
    printf("Receive copy results (failed segment details):\n");
    printf("    Extended copy command status: %d\n", rcBuff[56]);
    senseLen = (rcBuff[58] << 8) | rcBuff[59];
    sg_get_sense_str("    ", &rcBuff[60], senseLen, 0, 1024, senseBuff);
    printf("%s", senseBuff);
}

static void
scsi_copy_status(unsigned char *rcBuff, unsigned int rcBuffLen)
{
    unsigned int len;

    if (rcBuffLen < 4) {
        fprintf(stderr, "  <<not enough data to procedd report>>\n");
        return;
    }
    len = (rcBuff[0] << 24) | (rcBuff[1] << 16) | (rcBuff[2] << 8) |
          rcBuff[3];
    if (len > rcBuffLen) {
        fprintf(stderr, "  <<report too long for internal buffer,"
                " output truncated\n");
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
    printf("    Segments processed: %u\n", (rcBuff[5] << 8) | rcBuff[6]);
    printf("    Transfer count units: %u\n", rcBuff[7]);
    printf("    Transfer count: %u\n",
           rcBuff[8] << 24 | rcBuff[9] << 16 | rcBuff[10] << 8 | rcBuff[11]);
}

static void
scsi_operating_parameters(unsigned char *rcBuff, unsigned int rcBuffLen)
{
    unsigned int len, n;

    len = (rcBuff[0] << 24) | (rcBuff[1] << 16) | (rcBuff[2] << 8) |
          rcBuff[3];
    if (len > rcBuffLen) {
        fprintf(stderr, "  <<report too long for internal buffer,"
                " output truncated\n");
    }
    printf("Receive copy results (report operating parameters):\n");
    printf("    Supports no list identifier: %s\n",
           rcBuff[4] & 1 ? "yes" : "no");
    n = (rcBuff[8] << 8) | rcBuff[9];
    printf("    Maximum target descriptor count: %u\n", n);
    n = (rcBuff[10] << 8) | rcBuff[11];
    printf("    Maximum segment descriptor count: %u\n", n);
    n = (rcBuff[12] << 24) | (rcBuff[13] << 16) |
        (rcBuff[14] << 8) | rcBuff[15];
    printf("    Maximum descriptor list length: %u bytes\n", n);
    n = (rcBuff[16] << 24) | (rcBuff[17] << 16) |
        (rcBuff[18] << 8) | rcBuff[19];
    printf("    Maximum segment length: %u bytes\n", n);
    n = (rcBuff[20] << 24) | (rcBuff[21] << 16) |
        (rcBuff[22] << 8) | rcBuff[23];
    if (n == 0) {
        printf("    Inline data not supported\n");
    } else {
        printf("    Maximum inline data length: %u bytes\n", n);
    }
    n = (rcBuff[24] << 24) | (rcBuff[25] << 16) |
        (rcBuff[26] << 8) | rcBuff[27];
    printf("    Held data limit: %u bytes\n", n);
    n = (rcBuff[28] << 24) | (rcBuff[29] << 16) |
        (rcBuff[30] << 8) | rcBuff[31];
    printf("    Maximum stream device transfer size: %u bytes\n", n);
    n = (rcBuff[34] << 8) | rcBuff[35];
    printf("    Total concurrent copies: %u\n", n);
    printf("    Maximum concurrent copies: %u\n", rcBuff[36]);
    printf("    Data segment granularity: %lu bytes\n",
           (unsigned long)(1 << rcBuff[37]));
    printf("    Inline data granularity: %lu bytes\n",
           (unsigned long)(1 << rcBuff[38]));
    printf("    Held data granularity: %lu bytes\n",
           (unsigned long)(1 << rcBuff[39]));

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
        {"failed", 0, 0, 'f'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"list_id", 1, 0, 'l'},
        {"params", 0, 0, 'p'},
        {"receive", 0, 0, 'r'},
        {"status", 0, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {"xfer_len", 1, 0, 'x'},
        {0, 0, 0, 0},
};

static void
usage()
{
  fprintf(stderr, "Usage: "
          "sg_copy_results [--failed|--params|--receive|--status] [--help]\n"
          "                       [--hex] [--list_id=ID] [--verbose] "
          "[--version]\n"
          "                       DEVICE\n"
          "  where:\n"
          "    --failed|-f          use FAILED SEGMENT DETAILS service "
          "action\n"
          "    --help|-h            print out usage message\n"
          "    --hex|-H             print out response buffer in hex\n"
          "    --list_id=ID|-l ID   list identifier (default: 0)\n"
          "    --params|-p          use OPERATING PARAMETERS service "
          "action\n"
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

int
main(int argc, char * argv[])
{
    int sg_fd, res, c;
    unsigned char * cpResultBuff = NULL;
    int xfer_len = 520;
    int sa = 3;
    int list_id = 0;
    int do_hex = 0;
    int verbose = 0;
    const char * device_name = NULL;
    char file_name[256];
    int ret = 1;

    memset(file_name, 0, sizeof file_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "fhHl:prsvVx:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'f':
            sa = 4;
            break;
        case 'H':
            do_hex = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            list_id = sg_get_num(optarg);
            if (-1 == list_id) {
                fprintf(stderr, "bad argument to '--list_id'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            sa = 3;
            break;
        case 'r':
            sa = 1;
            break;
        case 's':
            sa = 0;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        case 'x':
            xfer_len = sg_get_num(optarg);
            if (-1 == xfer_len) {
                fprintf(stderr, "bad argument to '--xfer_len'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
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
        return SG_LIB_SYNTAX_ERROR;
    }
    if (xfer_len >= MAX_XFER_LEN) {
        fprintf(stderr, "xfer_len (%d) is out of range ( < %d)\n",
                xfer_len, MAX_XFER_LEN);
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (NULL == (cpResultBuff = malloc(xfer_len))) {
            fprintf(stderr, ME "out of memory\n");
            return SG_LIB_FILE_ERROR;
    }
    memset(cpResultBuff, 0x00, xfer_len);

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (verbose)
        fprintf(stderr, ME "issue receive copy results to device %s\n"
                "\t\txfer_len= %d (0x%x), sa=%d, list_id=%d\n",
                device_name, xfer_len, xfer_len, sa, list_id);

    res = sg_ll_receive_copy_results(sg_fd, sa, list_id, cpResultBuff,
                                     xfer_len, 0, verbose);
    ret = res;
    switch (res) {
    case 0:
        break;
    case SG_LIB_CAT_NOT_READY:
        fprintf(stderr, "  SCSI RECEIVE COPY RESULTS failed, "
                "device not ready\n");
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:
        fprintf(stderr, "  SCSI RECEIVE COPY RESULTS failed, "
                "unit attention\n");
        break;
    case SG_LIB_CAT_ABORTED_COMMAND:
        fprintf(stderr, "  SCSI RECEIVE COPY RESULTS failed, "
                "aborted command\n");
        break;
    case SG_LIB_CAT_INVALID_OP:
        fprintf(stderr, "  SCSI RECEIVE COPY RESULTS command not "
                "supported\n");
        break;
    case SG_LIB_CAT_ILLEGAL_REQ:
        fprintf(stderr, "  SCSI RECEIVE COPY RESULTS failed, "
                "bad field in cdb\n");
        break;
    default:
        fprintf(stderr, "  SCSI RECEIVE COPY RESULTS command error %d\n",
                res);
        break;
    }
    if (res != 0)
        goto finish;
    if (1 == do_hex) {
        dStrHex((const char *)cpResultBuff, xfer_len, 1);
        res = 0;
        goto finish;
    }
    switch (sa) {
    case 4: /* Failed segment details */
        scsi_failed_segment_details(cpResultBuff, xfer_len);
        res = 0;
        break;
    case 3: /* Operating parameters */
        scsi_operating_parameters(cpResultBuff, xfer_len);
        res = 0;
        break;
    case 0: /* Copy status */
        scsi_copy_status(cpResultBuff, xfer_len);
        res = 0;
        break;
    default:
        dStrHex((const char *)cpResultBuff, xfer_len, 1);
        res = 0;
        break;
    }

finish:
    free(cpResultBuff);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, ME "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
