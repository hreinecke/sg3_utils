/*
 * Copyright (c) 2009-2011 Douglas Gilbert.
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

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI READ BLOCK LIMITS command (SSC) to the given
 * SCSI device.
 */

static char * version_str = "1.02 20110204";

#define MAX_READ_BLOCK_LIMITS_LEN 6

static unsigned char readBlkLmtBuff[MAX_READ_BLOCK_LIMITS_LEN];


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"raw", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    fprintf(stderr, "Usage: "
            "sg_read_block_limits  [--help] [--hex] [--raw] [--verbose] "
            "[--version]\n"
            "                             DEVICE\n"
            "  where:\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           output response in hexadecimal\n"
            "    --raw|-r           output response in binary to stdout\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI READ BLOCK LIMITS command and decode the "
            "response\n"
            );
}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

int
main(int argc, char * argv[])
{
    int sg_fd, k, m, res, c;
    int do_hex = 0;
    int do_raw = 0;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;
    uint32_t max_block_size;
    uint16_t min_block_size;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHrvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
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
            fprintf(stderr, "invalid option -%c ??\n", c);
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

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    memset(readBlkLmtBuff, 0x0, 6);
    res = sg_ll_read_block_limits(sg_fd, readBlkLmtBuff, 6, 1,
                            verbose);
    ret = res;
    if (0 == res) {
      if (do_hex) {
        dStrHex((const char *)readBlkLmtBuff, sizeof(readBlkLmtBuff), 1);
        goto the_end;
      } else if (do_raw) {
        dStrRaw((const char *)readBlkLmtBuff, sizeof(readBlkLmtBuff));
        goto the_end;
      }

      max_block_size = (readBlkLmtBuff[0] << 24) +
                       (readBlkLmtBuff[1] << 16) +
                       (readBlkLmtBuff[2] << 8) + readBlkLmtBuff[3];
      min_block_size = (readBlkLmtBuff[4] << 8) + readBlkLmtBuff[5];
      k = min_block_size / 1024;
      fprintf(stderr, "Read Block Limits results:\n");
      fprintf(stderr, "\tMinimum block size: %u byte(s)",
              (unsigned int)min_block_size);
      if (k != 0)
        fprintf(stderr, ", %d KB", k);
      fprintf(stderr, "\n");
      k = max_block_size / 1024;
      m = max_block_size / 1048576;
      fprintf(stderr, "\tMaximum block size: %u byte(s)",
              (unsigned int)max_block_size);
      if (k != 0)
        fprintf(stderr, ", %d KB", k);
      if (m != 0)
        fprintf(stderr, ", %d MB", m);
      fprintf(stderr, "\n");
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Read block limits not supported\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "Read block limits, aborted command\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "Read block limits command has bad field in cdb\n");
    else {
        fprintf(stderr, "Read block limits command failed\n");
        if (0 == verbose)
            fprintf(stderr, "    try '-v' option for more information\n");
    }

the_end:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
