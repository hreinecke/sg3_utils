/*
 * Copyright (c) 2018-2020 Douglas Gilbert.
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
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
#include <time.h>
#elif defined(HAVE_GETTIMEOFDAY)
#include <time.h>
#include <sys/time.h>
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/*
 * This program issues one or more SCSI SEEK(10), PRE-FETCH(10) or
 * PRE-FETCH(16) commands. Both PRE-FETCH commands are current and appear
 * in the most recent SBC-4 draft (sbc4r15.pdf at time of writing) while
 * SEEK(10) has been obsolete since SBC-2 (2004). Currently more hard disks
 * and SSDs support SEEK(10) than PRE-FETCH. It is even unclear what
 * SEEK(10) means (defined in SBC-1 as moving the hard disk heads to the
 * track containing the given LBA) for a SSD. But if the manufacturers'
 * support it, then it must have a use, presumably to speed the next access
 * to that LBA ...
 */

static const char * version_str = "1.08 20200115";

#define BACKGROUND_CONTROL_SA 0x15

#define CMD_ABORT_TIMEOUT  60      /* 60 seconds */


static struct option long_options[] = {
        {"10", no_argument, 0, 'T'},
        {"count", required_argument, 0, 'c'},
        {"grpnum", required_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"immed", no_argument, 0, 'i'},
        {"lba", required_argument, 0, 'l'},
        {"num-blocks", required_argument, 0, 'n'},
        {"num_blocks", required_argument, 0, 'n'},
        {"pre-fetch", no_argument, 0, 'p'},
        {"pre_fetch", no_argument, 0, 'p'},
        {"readonly", no_argument, 0, 'r'},
        {"skip", required_argument, 0, 's'},
        {"time", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wrap-offset", required_argument, 0, 'w'},
        {"wrap_offset", required_argument, 0, 'w'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
            "sg_seek  [--10] [--count=NC] [--grpnum=GN] [--help] [--immed]\n"
            "                [--lba=LBA] [--num-blocks=NUM] [--pre-fetch] "
            "[--readonly]\n"
            "                [--skip=SB] [--time] [--verbose] [--version]\n"
            "                [--wrap-offset=WO] DEVICE\n");
    pr2serr("  where:\n"
            "    --10|-T             do PRE-FETCH(10) command (def: "
            "SEEK(10), or\n"
            "                        PRE-FETCH(16) if --pre-fetch also "
            "given)\n"
            "    --count=NC|-c NC    NC is number of commands to execute "
            "(def: 1)\n"
            "    --grpnum=GN|-g GN    GN is group number to place in "
            "PRE-FETCH\n"
            "                         cdb; 0 to 63 (def: 0)\n"
            "    --help|-h           print out usage message\n"
            "    --immed|-i          set IMMED bit in PRE-FETCH command\n"
            "    --lba=LBA|-l LBA    starting Logical Block Address (LBA) "
            "(def: 0)\n"
            "    --num-blocks=NUM|-n NUM    number of blocks to cache (for "
            "PRE-FETCH)\n"
            "                               (def: 1). Ignored by "
            "SEEK(10)\n");
    pr2serr("    --pre-fetch|-p     do PRE-FETCH command, 16 byte variant if "
            "--10 not\n"
            "                       given (def: do SEEK(10))\n"
            "    --readonly|-r      open DEVICE read-only (if supported)\n"
            "    --skip=SB|-s SB    when NC>1 skip SB blocks to next LBA "
            "(def: 1)\n"
            "    --time|-t          time the command(s) and if NC>1 show "
            "usecs/command\n"
            "                       (def: don't time)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n"
            "    --wrap-offset=WO|-w WO    if SB>0 and WO>0 then if "
            "LBAn>LBA+WO\n"
            "                       then reset LBAn back to LBA (def: 0)\n\n"
            "Performs SCSI SEEK(10), PRE-FETCH(10) or PRE-FETCH(16) "
            "command(s).If no\noptions are given does one SEEK(10) command "
            "with an LBA of 0 . If NC>1\nthen a tally is kept of successes, "
            "'condition-met's and errors that is\nprinted on completion. "
            "'condition-met' is from PRE-FETCH when NUM blocks\nfit in "
            "the DEVICE's cache.\n"
           );
}


int
main(int argc, char * argv[])
{
    bool cdb10 = false;
    bool count_given = false;
    bool do_time = false;
    bool immed = false;
    bool prefetch = false;
    bool readonly = false;
    bool start_tm_valid = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c;
    int sg_fd = -1;
    int first_err = 0;
    int last_err = 0;
    int ret = 0;
    int verbose = 0;
    uint32_t count = 1;
    int32_t l;
    uint32_t grpnum = 0;
    uint32_t k;
    uint32_t num_cond_met = 0;
    uint32_t num_err = 0;
    uint32_t num_good = 0;
    uint32_t numblocks = 1;
    uint32_t skip = 1;
    uint32_t wrap_offs = 0;
    int64_t ll;
    int64_t elapsed_usecs = 0;
    uint64_t lba = 0;
    uint64_t lba_n;
    const char * device_name = NULL;
    const char * cdb_name = NULL;
    char b[64];
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    struct timespec start_tm, end_tm;
#elif defined(HAVE_GETTIMEOFDAY)
    struct timeval start_tm, end_tm;
#endif

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "c:g:hil:n:prs:tTvVw:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            l = sg_get_num(optarg);
            if (l < 0) {
                pr2serr("--count= unable to decode argument, want 0 or "
                        "higher\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            count = (uint32_t)l;
            count_given = true;
            break;
        case 'g':
            l = sg_get_num(optarg);
            if ((l > 63) || (l < 0)) {
                pr2serr("--grpnum= expect argument in range 0 to 63\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            grpnum = (uint32_t)l;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            immed = true;
            break;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("--lba= unable to decode argument\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            lba = (uint64_t)ll;
            break;
        case 'n':
            l = sg_get_num(optarg);
            if (-1 == l) {
                pr2serr("--num= unable to decode argument\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            numblocks = (uint32_t)l;
            break;
        case 'p':
            prefetch = true;
            break;
        case 'r':
            readonly = true;
            break;
        case 's':
            l = sg_get_num(optarg);
            if (-1 == l) {
                pr2serr("--skip= unable to decode argument\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            skip = (uint32_t)l;
            break;
        case 't':
            do_time = true;
            break;
        case 'T':
            cdb10 = true;
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
        case 'w':
            l = sg_get_num(optarg);
            if (-1 == l) {
                pr2serr("--wrap-offset= unable to decode argument\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            wrap_offs = (uint32_t)l;
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
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (prefetch) {
        if (cdb10)
            cdb_name = "Pre-fetch(10)";
        else
            cdb_name = "Pre-fetch(16)";
    } else
        cdb_name = "Seek(10)";

    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s %s\n", device_name, cdb_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_nsec = 0;
        if (0 == clock_gettime(CLOCK_MONOTONIC, &start_tm))
            start_tm_valid = true;
        else
            perror("clock_gettime(CLOCK_MONOTONIC)\n");
    }
#elif defined(HAVE_GETTIMEOFDAY)
    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
        start_tm_valid = true;
    }
#else
    start_tm_valid = false;
#endif

    for (k = 0, lba_n = lba; k < count; ++k, lba_n += skip) {
        if (wrap_offs && (lba_n > lba) && ((lba_n - lba) > wrap_offs))
            lba_n = lba;
        res = sg_ll_pre_fetch_x(sg_fd, ! prefetch, ! cdb10, immed, lba_n,
                                numblocks, grpnum, 0, (verbose > 0), verbose);
        ret = res;      /* last command executed sets exit status */
        if (SG_LIB_CAT_CONDITION_MET == res)
            ++num_cond_met;
        else if (res) {
            ++num_err;
            if (0 == first_err)
                first_err = res;
            last_err = res;
        } else
            ++num_good;
    }

#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    if ((count > 0) && start_tm_valid &&
        (start_tm.tv_sec || start_tm.tv_nsec)) {
        int err;

        res = clock_gettime(CLOCK_MONOTONIC, &end_tm);
        if (res < 0) {
            err = errno;
            perror("clock_gettime");
            if (EINVAL == err)
                pr2serr("clock_gettime(CLOCK_MONOTONIC) not supported\n");
        }
        elapsed_usecs = (end_tm.tv_sec - start_tm.tv_sec) * 1000000;
        /* Note that (end_tm.tv_nsec - start_tm.tv_nsec) may be negative */
        elapsed_usecs += (end_tm.tv_nsec - start_tm.tv_nsec) / 1000;
    }
#elif defined(HAVE_GETTIMEOFDAY)
    if ((count > 0) && start_tm_valid &&
        (start_tm.tv_sec || start_tm.tv_usec)) {
        gettimeofday(&end_tm, NULL);
        elapsed_usecs = (end_tm.tv_sec - start_tm.tv_sec) * 1000000;
        elapsed_usecs += (end_tm.tv_usec - start_tm.tv_usec);
    }
#endif

    if (elapsed_usecs > 0) {
        if (elapsed_usecs > 1000000)
            snprintf(b, sizeof(b), " (over %d seconds)",
                    (int)elapsed_usecs / 1000000);
        else
            b[0] = '\0';
        printf("Elapsed time: %" PRId64 " microseconds%s, per command time: "
               "%" PRId64 "\n", elapsed_usecs, b, elapsed_usecs / count);
    }

    if (count_given && verbose_given)
        printf("Command count=%u, number of condition_mets=%u, number of "
               "goods=%u\n", count, num_cond_met, num_good);
    if (first_err) {
        bool printed;

        printf(" number of errors=%d\n", num_err);
        printf("    first error");
        printed = sg_if_can2stdout(": ", first_err);
        if (! printed)
            printf(" code: %d\n", first_err);
        if (num_err > 1) {
            printf("    last error");
            printed = sg_if_can2stdout(": ", last_err);
            if (! printed)
                printf(" code: %d\n", last_err);
        }
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
    if (0 == verbose) {
	const char * e_str = (SG_LIB_CAT_CONDITION_MET == ret) ?
			     "sg_seek: " : "sg_seek: failed";
	
        if (! sg_if_can2stderr(e_str, ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
