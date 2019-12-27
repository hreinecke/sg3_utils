/*
 * Copyright (c) 2004-2019 Douglas Gilbert.
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
#include <errno.h>
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
#include "sg_pr2serr.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This program issues the SCSI VERIFY(10) or VERIFY(16) command to the given
 * SCSI block device.
 *
 * N.B. This utility should, but doesn't, check the logical block size with
 * the SCSI READ CAPACITY command. It is up to the user to make sure that
 * the count of blocks requested and the number of bytes transferred (when
 * BYTCHK>0) are "in sync". That caclculation is somewhat complicated by
 * the possibility of protection data (DIF).
 */

static const char * version_str = "1.26 20191216";    /* sbc4r17 */

#define ME "sg_verify: "

#define EBUFF_SZ 256


static struct option long_options[] = {
        {"0", no_argument, 0, '0'},
        {"16", no_argument, 0, 'S'},
        {"bpc", required_argument, 0, 'b'},
        {"bytchk", required_argument, 0, 'B'},  /* 4 backward compatibility */
        {"count", required_argument, 0, 'c'},
        {"dpo", no_argument, 0, 'd'},
        {"ebytchk", required_argument, 0, 'E'}, /* extended bytchk (2 bits) */
        {"group", required_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"in", required_argument, 0, 'i'},
        {"lba", required_argument, 0, 'l'},
        {"nbo", required_argument, 0, 'n'},     /* misspelling, legacy */
        {"ndo", required_argument, 0, 'n'},
        {"quiet", no_argument, 0, 'q'},
        {"readonly", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"vrprotect", required_argument, 0, 'P'},
        {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_verify [--0] [--16] [--bpc=BPC] [--count=COUNT] "
            "[--dpo]\n"
            "                 [--ebytchk=BCH] [--ff] [--group=GN] [--help] "
            "[--in=IF]\n"
            "                 [--lba=LBA] [--ndo=NDO] [--quiet] "
            "[--readonly]\n"
            "                 [--verbose] [--version] [--vrprotect=VRP] "
            "DEVICE\n"
            "  where:\n"
            "    --0|-0              fill buffer with zeros (don't read "
            "stdin)\n"
            "    --16|-S             use VERIFY(16) (def: use "
            "VERIFY(10) )\n"
            "    --bpc=BPC|-b BPC    max blocks per verify command "
            "(def: 128)\n"
            "    --count=COUNT|-c COUNT    count of blocks to verify "
            "(def: 1).\n"
            "    --dpo|-d            disable page out (cache retention "
            "priority)\n"
            "    --ebytchk=BCH|-E BCH    sets BYTCHK value, either 1, 2 "
            "or 3 (def: 0).\n"
            "                            BCH overrides BYTCHK=1 set by "
            "'--ndo='. If\n"
            "                            BCH is 3 then NDO must be the LBA "
            "size\n"
            "                            (plus protection size if DIF "
            "active)\n"
            "    --ff|-f             fill buffer with 0xff bytes (don't read "
            "stdin)\n"
            "    --group=GN|-g GN    set group number field to GN (def: 0)\n"
            "    --help|-h           print out usage message\n"
            "    --in=IF|-i IF       input from file called IF (def: "
            "stdin)\n"
            "                        only active if --ebytchk=BCH given\n"
            "    --lba=LBA|-l LBA    logical block address to start "
            "verify (def: 0)\n"
            "    --ndo=NDO|-n NDO    NDO is number of bytes placed in "
            "data-out buffer.\n"
            "                        These are fetched from IF (or "
            "stdin) and used\n"
            "                        to verify the device data against. "
            "Forces\n"
            "                        --bpc=COUNT. Sets BYTCHK (byte check) "
            "to 1\n"
            "    --quiet|-q          suppress miscompare report to stderr, "
            "still\n"
            "                        causes an exit status of 14\n"
            "    --readonly|-r       open DEVICE read-only (def: open it "
            "read-write)\n"
            "    --verbose|-v        increase verbosity\n"
            "    --version|-V        print version string and exit\n"
            "    --vrprotect=VRP|-P VRP    set vrprotect field to VRP "
            "(def: 0)\n"
            "Performs one or more SCSI VERIFY(10) or SCSI VERIFY(16) "
            "commands. sbc3r34\nmade the BYTCHK field two bits wide "
            "(it was a single bit).\n");
}

int
main(int argc, char * argv[])
{
    bool bpc_given = false;
    bool dpo = false;
    bool ff_given = false;
    bool got_stdin = false;
    bool quiet = false;
    bool readonly = false;
    bool verbose_given = false;
    bool verify16 = false;
    bool version_given = false;
    bool zero_given = false;
    int res, c, num, nread, infd;
    int sg_fd = -1;
    int bpc = 128;
    int group = 0;
    int bytchk = 0;
    int ndo = 0;        /* number of bytes in data-out buffer */
    int verbose = 0;
    int ret = 0;
    int vrprotect = 0;
    unsigned int info = 0;
    int64_t count = 1;
    int64_t ll;
    int64_t orig_count;
    uint64_t info64 = 0;
    uint64_t lba = 0;
    uint64_t orig_lba;
    uint8_t * ref_data = NULL;
    uint8_t * free_ref_data = NULL;
    const char * device_name = NULL;
    const char * file_name = NULL;
    const char * vc;
    char ebuff[EBUFF_SZ];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "0b:B:c:dE:fg:hi:l:n:P:qrSvV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case '0':
            zero_given = true;
            break;
        case 'b':
            bpc = sg_get_num(optarg);
            if (bpc < 1) {
                pr2serr("bad argument to '--bpc'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            bpc_given = true;
            break;
        case 'c':
            count = sg_get_llnum(optarg);
            if (count < 0) {
                pr2serr("bad argument to '--count'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'd':
            dpo = true;
            break;
        case 'E':
            bytchk = sg_get_num(optarg);
            if ((bytchk < 0) || (bytchk > 3)) {
                pr2serr("bad argument to '--ebytchk'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'f':
            ff_given = true;
            break;
        case 'g':
            group = sg_get_num(optarg);
            if ((group < 0) || (group > 63)) {
                pr2serr("bad argument to '--group'\n");
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
                pr2serr("bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            lba = (uint64_t)ll;
            break;
        case 'n':       /* number of bytes in data-out buffer */
        case 'B':       /* undocumented, old --bytchk=NDO option */
            ndo = sg_get_num(optarg);
            if (ndo < 1) {
                pr2serr("bad argument to '--ndo'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'P':
            vrprotect = sg_get_num(optarg);
            if (-1 == vrprotect) {
                pr2serr("bad argument to '--vrprotect'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((vrprotect < 0) || (vrprotect > 7)) {
                pr2serr("'--vrprotect' requires a value from 0 to 7 "
                        "(inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'q':
            quiet = true;
            break;
        case 'r':
            readonly = true;
            break;
        case 'S':
            verify16 = true;
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

    if (ndo > 0) {
        if (0 == bytchk)
            bytchk = 1;
        if (bpc_given && (bpc != count))
            pr2serr("'bpc' argument ignored, using --bpc=%" PRIu64 "\n",
                    count);
        if (count > 0x7fffffffLL) {
            pr2serr("count exceed 31 bits, way too large\n");
            return SG_LIB_SYNTAX_ERROR;
        }
#if 0
        if ((3 == bytchk) && (1 != count)) {
            pr2serr("count must be 1 when bytchk=3\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        // bpc = (int)count;
#endif
    } else if (bytchk > 0) {
        pr2serr("when the 'ebytchk=BCH' option is given, then '--ndo=NDO' "
                "must also be given\n");
        return SG_LIB_CONTRADICT;
    }
    if ((zero_given || ff_given) && file_name) {
        pr2serr("giving --0 or --ff is not compatible with --if=%s\n",
                file_name);
        return SG_LIB_CONTRADICT;
    }

    if ((bpc > 0xffff) && (! verify16)) {
        pr2serr("'%s' exceeds 65535, so use VERIFY(16)\n",
                (ndo > 0) ? "count" : "bpc");
        verify16 = true;
    }
    if (((lba + count - 1) > 0xffffffffLLU) && (! verify16)) {
        pr2serr("'lba' exceed 32 bits, so use VERIFY(16)\n");
        verify16 = true;
    }
    if ((group > 0) && (! verify16))
        pr2serr("group number ignored with VERIFY(10) command, use the --16 "
                "option\n");

    orig_count = count;
    orig_lba = lba;

    if (ndo > 0) {
        ref_data = (uint8_t *)sg_memalign(ndo, 0, &free_ref_data, verbose > 4);
        if (NULL == ref_data) {
            pr2serr("failed to allocate %d byte buffer\n", ndo);
            ret = sg_convert_errno(ENOMEM);
            goto err_out;
        }
        if (ff_given)
            memset(ref_data, 0xff, ndo);
        if (zero_given || ff_given)
            goto skip;
        if ((NULL == file_name) || (0 == strcmp(file_name, "-"))) {
            got_stdin = true;
            infd = STDIN_FILENO;
            if (sg_set_binary_mode(STDIN_FILENO) < 0)
                perror("sg_set_binary_mode");
        } else {
            if ((infd = open(file_name, O_RDONLY)) < 0) {
                ret = sg_convert_errno(errno);
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", file_name);
                perror(ebuff);
                goto err_out;
            } else if (sg_set_binary_mode(infd) < 0)
                perror("sg_set_binary_mode");
        }
        if (verbose && got_stdin)
                pr2serr("about to wait on STDIN\n");
        for (nread = 0; nread < ndo; nread += res) {
            res = read(infd, ref_data + nread, ndo - nread);
            if (res <= 0) {
                ret = sg_convert_errno(errno);
                pr2serr("reading from %s failed at file offset=%d\n",
                        (got_stdin ? "stdin" : file_name), nread);
                goto err_out;
            }
        }
        if (! got_stdin)
            close(infd);
    }
skip:
    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }
    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto err_out;
    }

    vc = verify16 ? "VERIFY(16)" : "VERIFY(10)";
    for (; count > 0; count -= bpc, lba += bpc) {
        num = (count > bpc) ? bpc : count;
        if (verify16)
            res = sg_ll_verify16(sg_fd, vrprotect, dpo, bytchk,
                                 lba, num, group, ref_data,
                                 ndo, &info64, !quiet , verbose);
        else
            res = sg_ll_verify10(sg_fd, vrprotect, dpo, bytchk,
                                 (unsigned int)lba, num, ref_data,
                                 ndo, &info, !quiet, verbose);
        if (0 != res) {
            char b[80];

            ret = res;
            switch (res) {
            case SG_LIB_CAT_ILLEGAL_REQ:
                pr2serr("bad field in %s cdb, near lba=0x%" PRIx64 "\n", vc,
                        lba);
                break;
            case SG_LIB_CAT_MEDIUM_HARD:
                pr2serr("%s medium or hardware error near lba=0x%" PRIx64 "\n",
                        vc, lba);
                break;
            case SG_LIB_CAT_MEDIUM_HARD_WITH_INFO:
                if (verify16)
                    pr2serr("%s medium or hardware error, reported lba=0x%"
                            PRIx64 "\n", vc, info64);
                else
                    pr2serr("%s medium or hardware error, reported lba=0x%x\n",
                            vc, info);
                break;
            case SG_LIB_CAT_MISCOMPARE:
                if ((0 == quiet) || verbose)
                    pr2serr("%s MISCOMPARE: started at LBA 0x%" PRIx64 "\n",
                            vc, lba);
                break;
            default:
                sg_get_category_sense_str(res, sizeof(b), b, verbose);
                pr2serr("%s: %s\n", vc, b);
                pr2serr("    failed near lba=%" PRIu64 " [0x%" PRIx64 "]\n",
                        lba, lba);
                break;
            }
            break;
        }
    }

    if (verbose && (0 == ret) && (orig_count > 1))
        pr2serr("Verified %" PRId64 " [0x%" PRIx64 "] blocks from lba %" PRIu64
                " [0x%" PRIx64 "]\n    without error\n", orig_count,
                (uint64_t)orig_count, orig_lba, orig_lba);

 err_out:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (free_ref_data)
        free(free_ref_data);
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_verify failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
