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
#include <string.h>
#include <limits.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command SYNCHRONIZE CACHE(10 or 16) to the
 * given device. This command is defined for SCSI "direct access" devices
 * (e.g. disks).
 */

static const char * version_str = "1.25 20191220";

#define SYNCHRONIZE_CACHE16_CMD     0x91
#define SYNCHRONIZE_CACHE16_CMDLEN  16
#define SENSE_BUFF_LEN  64
#define DEF_PT_TIMEOUT  60       /* 60 seconds */


static struct option long_options[] = {
        {"16", no_argument, 0, 'S'},
        {"count", required_argument, 0, 'c'},
        {"group", required_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"immed", no_argument, 0, 'i'},
        {"lba", required_argument, 0, 'l'},
        {"sync-nv", no_argument, 0, 's'},
        {"timeout", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    pr2serr("Usage: sg_sync    [--16] [--count=COUNT] [--group=GN] [--help] "
            "[--immed]\n"
            "                  [--lba=LBA] [--sync-nv] [--timeout=SECS] "
            "[--verbose]\n"
            "                  [--version] DEVICE\n"
            "  where:\n"
            "    --16|-S             calls SYNCHRONIZE CACHE(16) (def: is "
            "10 byte\n"
            "                        variant)\n"
            "    --count=COUNT|-c COUNT    number of blocks to sync (def: 0 "
            "which\n"
            "                              implies rest of device)\n"
            "    --group=GN|-g GN    set group number field to GN (def: 0)\n"
            "    --help|-h           print out usage message\n"
            "    --immed|-i          command returns immediately when set "
            "else wait\n"
            "                        for 'sync' to complete\n"
            "    --lba=LBA|-l LBA    logical block address to start sync "
            "operation\n"
            "                        from (def: 0)\n"
            "    --sync-nv|-s        synchronize to non-volatile storage "
            "(if distinct\n"
            "                        from medium). Obsolete in sbc3r35d.\n"
            "    --timeout=SECS|-t SECS    command timeout in seconds, only "
            "active\n"
            "                              if '--16' given (def: 60 seconds)\n"
            "    --verbose|-v        increase verbosity\n"
            "    --version|-V        print version string and exit\n\n"
            "Performs a SCSI SYNCHRONIZE CACHE(10 or 16) command\n");
}

static int
sg_ll_sync_cache_16(int sg_fd, bool sync_nv, bool immed, int group,
                    uint64_t lba, unsigned int num_lb, int to_secs,
                    bool noisy, int verbose)
{
    int res, ret, sense_cat;
    uint8_t sc_cdb[SYNCHRONIZE_CACHE16_CMDLEN] =
                {SYNCHRONIZE_CACHE16_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (sync_nv)
        sc_cdb[1] |= 4;       /* obsolete in sbc3r35d */
    if (immed)
        sc_cdb[1] |= 2;
    sg_put_unaligned_be64(lba, sc_cdb + 2);
    sc_cdb[14] = group & 0x1f;
    sg_put_unaligned_be32((uint32_t)num_lb, sc_cdb + 10);

    if (verbose) {
        char b[128];

        pr2serr("    Synchronize cache(16) cdb: %s\n",
                sg_get_command_str(sc_cdb, SYNCHRONIZE_CACHE16_CMDLEN, false,
                                   sizeof(b), b));
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("synchronize cache(16): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, sc_cdb, sizeof(sc_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, to_secs, verbose);
    ret = sg_cmds_process_resp(ptvp, "synchronize cache(16)", res,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}


int main(int argc, char * argv[])
{
    bool do_16 = false;
    bool immed = false;
    bool sync_nv = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c;
    int sg_fd = -1;
    int group = 0;
    int ret = 0;
    int to_secs = DEF_PT_TIMEOUT;
    int verbose = 0;
    unsigned int num_lb = 0;
    int64_t count = 0;
    int64_t lba = 0;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "c:g:hil:sSt:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            count = sg_get_llnum(optarg);
            if ((count < 0) || (count > UINT_MAX)) {
                pr2serr("bad argument to '--count'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            num_lb = (unsigned int)count;
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
            immed = true;
            break;
        case 'l':
            lba = sg_get_llnum(optarg);
            if (lba < 0) {
                pr2serr("bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 's':
            sync_nv = true;
            break;
        case 'S':
            do_16 = true;
            break;
        case 't':
            to_secs = sg_get_num(optarg);
            if (to_secs < 0) {
                pr2serr("bad argument to '--timeout'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
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
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, false /* rw */, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    if (do_16)
        res = sg_ll_sync_cache_16(sg_fd, sync_nv, immed, group, lba, num_lb,
                                  to_secs, true, verbose);
    else
        res = sg_ll_sync_cache_10(sg_fd, sync_nv, immed, group,
                                  (unsigned int)lba, num_lb, true, verbose);
    ret = res;
    if (res) {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Synchronize cache failed: %s\n", b);
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
        if (! sg_if_can2stderr("sg_sync failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
