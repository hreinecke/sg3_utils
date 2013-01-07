/*
 * Copyright (c) 2004-2012 Douglas Gilbert.
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
 * This program issues the SCSI VERIFY(10) or VERIFY(16) command to the given
 * SCSI block device.
 */

static char * version_str = "1.18 20120927";

#define ME "sg_verify: "

#define EBUFF_SZ 256


static struct option long_options[] = {
        {"16", 0, 0, 'S'},
        {"bpc", 1, 0, 'b'},
        {"bytchk", 1, 0, 'B'},
        {"count", 1, 0, 'c'},
        {"dpo", 0, 0, 'd'},
        {"group", 1, 0, 'g'},
        {"help", 0, 0, 'h'},
        {"in", 1, 0, 'i'},
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
          "sg_verify [--16] [--bpc=BPC] [--bytchk=NDO] [--count=COUNT] "
          "[--dpo]\n"
          "                 [--group=GN] [--help] [--in=IF] [--lba=LBA] "
          "[--readonly]\n"
          "                 [--verbose] [--version] [--vrprotect=VRP] "
          "DEVICE\n"
          "  where:\n"
          "    --16|-S             use VERIFY(16) (def: use "
          "VERIFY(10) )\n"
          "    --bpc=BPC|-b BPC    max blocks per verify command "
          "(def: 128)\n"
          "    --bytchk=NDO|-B NDO    set BYTCHK (byte check) bit, NDO is "
          "number of\n"
          "                           bytes placed in data-out buffer. "
          "These are\n"
          "                           fetched from IF (or stdin) and used "
          "to verify\n"
          "                           the device data against. Forces "
          "--bpc=COUNT\n"
          "    --count=COUNT|-c COUNT    count of blocks to verify "
          "(def: 1)\n"
          "    --dpo|-d            disable page out (cache retention "
          "priority)\n"
          "    --group=GN|-g GN    set group number field to GN (def: 0)\n"
          "    --help|-h           print out usage message\n"
          "    --in=IF|-i IF       input from file called IF (def: "
          "stdin)\n"
          "                        only active if --bytchk=N given\n"
          "    --lba=LBA|-l LBA    logical block address to start "
          "verify (def: 0)\n"
          "    --readonly|-r       open DEVICE read-only (def: open it "
          "read-write)\n"
          "    --verbose|-v        increase verbosity\n"
          "    --version|-V        print version string and exit\n"
          "    --vrprotect=VRP|-P VRP    set vrprotect field to VRP "
          "(def: 0)\n"
          "Performs one or more SCSI VERIFY(10) or SCSI VERIFY(16) "
          "commands\n"
          );
}

int
main(int argc, char * argv[])
{
    int sg_fd, res, c, num, nread, infd;
    int64_t ll;
    int dpo = 0;
    int bytchk = 0;
    char *ref_data = NULL;
    int vrprotect = 0;
    int64_t count = 1;
    int64_t orig_count;
    int bpc = 128;
    int bpc_given = 0;
    int got_stdin = 0;
    int group = 0;
    uint64_t lba = 0;
    uint64_t orig_lba;
    int readonly = 0;
    int verbose = 0;
    int verify16 = 0;
    const char * device_name = NULL;
    const char * file_name = NULL;
    const char * vc;
    int ret = 0;
    unsigned int info = 0;
    uint64_t info64 = 0;
    char ebuff[EBUFF_SZ];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:B:c:dg:hi:l:P:rSvV", long_options,
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
            ++bpc_given;
            break;
        case 'B':
            bytchk = sg_get_num(optarg);
            if (bytchk < 1) {
                fprintf(stderr, "bad argument to '--bytchk'\n");
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
        case 'g':
            group = sg_get_num(optarg);
            if ((group < 0) || (group > 31)) {
                fprintf(stderr, "bad argument to '--group'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            file_name = optarg;
            break;
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
        case 'S':
            ++verify16;
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
    if (bytchk > 0) {
        if (bpc_given && (bpc != count))
            fprintf(stderr, "'bpc' argument ignored, using --bpc=COUNT\n");
        if (count > 0x7fffffffLL) {
            fprintf(stderr, "count exceed 31 bits, way too large\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        bpc = (int)count;
    }
    if ((bpc > 0xffff) && (0 == verify16)) {
        fprintf(stderr, "'%s' exceeds 65535, so use VERIFY(16)\n",
                (bytchk > 0) ? "count" : "bpc");
        ++verify16;
    }
    if (((lba + count - 1) > 0xffffffffLLU) && (0 == verify16)) {
        fprintf(stderr, "'lba' exceed 32 bits, so use VERIFY(16)\n");
        ++verify16;
    }
    if ((group > 0) && (0 == verify16))
        fprintf(stderr, "group number ignored with VERIFY(10) command, "
                "use the --16 option\n");

    orig_count = count;
    orig_lba = lba;

    if (bytchk > 0) {
        ref_data = malloc(bytchk);
        if (NULL == ref_data) {
            fprintf(stderr, "failed to allocate %d byte buffer\n", bytchk);
            return SG_LIB_FILE_ERROR;
        }
        if ((NULL == file_name) || (0 == strcmp(file_name, "-"))) {
            ++got_stdin;
            infd = STDIN_FILENO;
            if (sg_set_binary_mode(STDIN_FILENO) < 0)
                perror("sg_set_binary_mode");
        } else {
            if ((infd = open(file_name, O_RDONLY)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", file_name);
                perror(ebuff);
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            } else if (sg_set_binary_mode(infd) < 0)
                perror("sg_set_binary_mode");
        }
        if (verbose && got_stdin)
                fprintf(stderr, "about to wait on STDIN\n");
        for (nread = 0; nread < bytchk; nread += res) {
            res = read(infd, ref_data + nread, bytchk - nread);
            if (res <= 0) {
                fprintf(stderr, "reading from %s failed at file offset=%d\n",
                        (got_stdin ? "stdin" : file_name), nread);
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
        }
        if (! got_stdin)
            close(infd);
    }

    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }
    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        ret = SG_LIB_FILE_ERROR;
        goto err_out;
    }

    vc = verify16 ? "VERIFY(16)" : "VERIFY(10)";
    for (; count > 0; count -= bpc, lba += bpc) {
        num = (count > bpc) ? bpc : count;
        if (verify16)
            res = sg_ll_verify16(sg_fd, vrprotect, dpo, bytchk > 0,
                                 lba, num, group, ref_data,
                                 bytchk, &info64, 1, verbose);
        else
            res = sg_ll_verify10(sg_fd, vrprotect, dpo, bytchk > 0,
                                 (unsigned int)lba, num, ref_data,
                                 bytchk, &info, 1, verbose);
        if (0 != res) {
            ret = res;
            switch (res) {
            case SG_LIB_CAT_NOT_READY:
                fprintf(stderr, "%s failed, device not ready\n", vc);
                break;
            case SG_LIB_CAT_UNIT_ATTENTION:
                fprintf(stderr, "%s, unit attention\n", vc);
                break;
            case SG_LIB_CAT_ABORTED_COMMAND:
                fprintf(stderr, "%s, aborted command\n", vc);
                break;
            case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, "%s command not supported\n", vc);
                break;
            case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, "bad field in %s cdb, near lba=0x%" PRIx64
                        "\n", vc, lba);
                break;
            case SG_LIB_CAT_MEDIUM_HARD:
                fprintf(stderr, "%s medium or hardware error near "
                        "lba=0x%" PRIx64 "\n", vc, lba);
                break;
            case SG_LIB_CAT_MEDIUM_HARD_WITH_INFO:
                if (verify16)
                    fprintf(stderr, "%s medium or hardware error, reported "
                            "lba=0x%" PRIx64 "\n", vc, info64);
                else
                    fprintf(stderr, "%s medium or hardware error, reported "
                            "lba=0x%x\n", vc, info);
                break;
            default:
                fprintf(stderr, "%s failed near lba=%" PRIu64 " [0x%" PRIx64
                        "]\n", vc, lba, lba);
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
            ret = SG_LIB_FILE_ERROR;
    }

 err_out:
    if (ref_data)
        free(ref_data);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
