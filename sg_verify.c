/*
 * Copyright (c) 2004-2005 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This program issues the SCSI VERIFY command to the given SCSI block device.
 */

static char * version_str = "1.06 20060322";

#define ME "sg_verify: "


static struct option long_options[] = {
        {"bpc", 1, 0, 'b'},
        {"count", 1, 0, 'c'},
        {"dpo", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"lba", 1, 0, 'l'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_verify [--bpc=<n>] [--count=<n>] [--dpo] [--help] [--lba=<n>]\n"
          "                   [--verbose] [--version] <scsi_device>\n"
          "  where: --bpc=<n>|-b <n>   max blocks per verify command "
          "(def 128)\n"
          "         --count=<n>|-c <n> count of blocks to verify (def 1)\n"
          "         --dpo|-d           disable page out (cache retention "
          "priority)\n"
          "         --help|-h          print out usage message\n"
          "         --lba=<n>|-l <n>   logical block address to start "
          "verify (def 0)\n"
          "         --verbose|-v       increase verbosity\n"
          "         --version|-V       print version string and exit\n\n"
          "Performs a VERIFY SCSI command\n"
          );

}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, num;
    long long ll;
    int dpo = 0;
    int bytechk = 0;
    long long count = 1;
    long long orig_count;
    int bpc = 128;
    unsigned long long lba = 0;
    unsigned long long orig_lba;
    int verbose = 0;
    char device_name[256];
    int ret = 1;
    unsigned long info = 0;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:c:dhl:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
           bpc = sg_get_num(optarg);
           if (bpc < 1) {
                fprintf(stderr, "bad argument to '--bpc'\n");
                return 1;
            }
            break;
        case 'c':
           count = sg_get_llnum(optarg);
           if (count < 0) {
                fprintf(stderr, "bad argument to '--count'\n");
                return 1;
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
                return 1;
            }
            lba = (unsigned long long)ll;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if ('\0' == device_name[0]) {
            strncpy(device_name, argv[optind], sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }
    if (bpc > 0xffff) {
        fprintf(stderr, "'bpc' cannot exceed 65535\n");
        usage();
        return 1;
    }
    if (lba > 0xffffffffLLU) {
        fprintf(stderr, "'lba' cannot exceed 32 bits\n");
        usage();
        return 1;
    }
    orig_count = count;
    orig_lba = lba;

    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return 1;
    }

    for (; count > 0; count -= bpc, lba +=bpc) {
        num = (count > bpc) ? bpc : count;
        res = sg_ll_verify10(sg_fd, dpo, bytechk, (unsigned long)lba, num,
                             NULL, 0, &info, 1, verbose);
        if (0 != res) {
            switch (res) {
            case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, "Verify(10) command not supported\n");
                break;
            case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, "bad field in Verify(10) cdb, near "
                        "lba=0x%llx\n", lba);
                break;
            case SG_LIB_CAT_MEDIUM_HARD:
                fprintf(stderr, "medium or hardware error near "
                        "lba=0x%llx\n", lba);
                break;
            case SG_LIB_CAT_MEDIUM_HARD_WITH_INFO:
                fprintf(stderr, "medium or hardware error, reported "
                        "lba=0x%lx\n", info);
                break;
            default:
                fprintf(stderr, "Verify(10) failed near lba=%llu [0x%llx]\n",
                        lba, lba);
                break;
            }
            break;
        }
    }
    if (count <= 0)
        ret = 0;

    if (verbose && (0 == ret) && (orig_count > 1))
        fprintf(stderr, "Verified %lld [0x%llx] blocks from lba %llu "
                "[0x%llx]\n    without error\n", orig_count,
                (unsigned long long)orig_count, orig_lba, orig_lba);

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, ME "close error: %s\n", safe_strerror(-sg_fd));
        return 1;
    }
    return ret;
}
