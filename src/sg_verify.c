/*
 * Copyright (c) 2004-2011 Douglas Gilbert.
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

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This program issues the SCSI VERIFY command to the given SCSI block device.
 */

static char * version_str = "1.15 20110206";

#define ME "sg_verify: "


static struct option long_options[] = {
        {"bpc", 1, 0, 'b'},
        {"count", 1, 0, 'c'},
        {"dpo", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"lba", 1, 0, 'l'},
        {"readonly", 0, 0, 'r'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {"vrprotect", 1, 0, 'P'},
        {0, 0, 0, 0},
};

static void
usage()
{
    fprintf(stderr, "Usage: "
          "sg_verify [--bpc=BPC] [--count=COUNT] [--dpo] [--help] "
          "[--lba=LBA]\n"
          "                 [--readonly] [--verbose] [--version] "
          "[--vrprotect=VRP]\n"
          "                 DEVICE\n"
          "  where:\n"
          "    --bpc=BPC|-b BPC    max blocks per verify command "
          "(def 128)\n"
          "    --count=COUNT|-c COUNT    count of blocks to verify "
          "(def 1)\n"
          "    --dpo|-d            disable page out (cache retention "
          "priority)\n"
          "    --help|-h           print out usage message\n"
          "    --lba=LBA|-l LBA    logical block address to start "
          "verify (def 0)\n"
          "    --readonly|-r       open DEVICE read-only (def: open it "
          "read-write)\n"
          "    --verbose|-v        increase verbosity\n"
          "    --version|-V        print version string and exit\n"
          "    --vrprotect=VRP|-P VRP    set vrprotect field to VRP "
          "(def 0)\n"
          "Performs a SCSI VERIFY(10) command\n"
          );
}

int
main(int argc, char * argv[])
{
    int sg_fd, res, c, num;
    int64_t ll;
    int dpo = 0;
    int bytechk = 0;
    int vrprotect = 0;
    int64_t count = 1;
    int64_t orig_count;
    int bpc = 128;
    uint64_t lba = 0;
    uint64_t orig_lba;
    int readonly = 0;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;
    unsigned int info = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:c:dhl:P:rvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            bpc = sg_get_num(optarg);
            if (bpc < 1) {
                fprintf(stderr, "bad argument to '--bpc'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'c':
            count = sg_get_llnum(optarg);
            if (count < 0) {
                fprintf(stderr, "bad argument to '--count'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'd':
            dpo = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            lba = (uint64_t)ll;
            break;
        case 'P':
            vrprotect = sg_get_num(optarg);
            if (-1 == vrprotect) {
                fprintf(stderr, "bad argument to '--vrprotect'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((vrprotect < 0) || (vrprotect > 7)) {
                fprintf(stderr, "'--vrprotect' requires a value from 0 to "
                        "7 (inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            ++readonly;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
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
    if (bpc > 0xffff) {
        fprintf(stderr, "'bpc' cannot exceed 65535\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (lba > 0xffffffffLLU) {
        fprintf(stderr, "'lba' cannot exceed 32 bits\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    orig_count = count;
    orig_lba = lba;

    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    for (; count > 0; count -= bpc, lba +=bpc) {
        num = (count > bpc) ? bpc : count;
        res = sg_ll_verify10(sg_fd, vrprotect, dpo, bytechk,
                             (unsigned int)lba, num, NULL, 0,
                             &info, 1, verbose);
        if (0 != res) {
            ret = res;
            switch (res) {
            case SG_LIB_CAT_NOT_READY:
                fprintf(stderr, "Verify(10) failed, device not ready\n");
                break;
            case SG_LIB_CAT_UNIT_ATTENTION:
                fprintf(stderr, "Verify(10), unit attention\n");
                break;
            case SG_LIB_CAT_ABORTED_COMMAND:
                fprintf(stderr, "Verify(10), aborted command\n");
                break;
            case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, "Verify(10) command not supported\n");
                break;
            case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, "bad field in Verify(10) cdb, near "
                        "lba=0x%" PRIx64 "\n", lba);
                break;
            case SG_LIB_CAT_MEDIUM_HARD:
                fprintf(stderr, "medium or hardware error near "
                        "lba=0x%" PRIx64 "\n", lba);
                break;
            case SG_LIB_CAT_MEDIUM_HARD_WITH_INFO:
                fprintf(stderr, "medium or hardware error, reported "
                        "lba=0x%x\n", info);
                break;
            default:
                fprintf(stderr, "Verify(10) failed near lba=%" PRIu64
                        " [0x%" PRIx64 "]\n", lba, lba);
                break;
            }
            break;
        }
    }

    if (verbose && (0 == ret) && (orig_count > 1))
        fprintf(stderr, "Verified %" PRId64 " [0x%" PRIx64 "] blocks from "
                "lba %" PRIu64 " [0x%" PRIx64 "]\n    without error\n",
                orig_count, (uint64_t)orig_count, orig_lba, orig_lba);

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
