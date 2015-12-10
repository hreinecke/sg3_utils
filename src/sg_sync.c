/*
 * Copyright (c) 2004-2015 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <getopt.h>

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"
#include "sg_unaligned.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command SYNCHRONIZE CACHE(10 or 16) to the
 * given device. This command is defined for SCSI "direct access" devices
 * (e.g. disks).
 */

static const char * version_str = "1.13 20151208";

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
    fprintf(stderr, "Usage: "
          "sg_sync    [--16] [--count=COUNT] [--group=GN] [--help] "
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
          "Performs a SCSI SYNCHRONIZE CACHE(10 or 16) command\n"
          );
}

static int
ll_sync_cache_16(int sg_fd, int sync_nv, int immed, int group,
                 uint64_t lba, unsigned int num_lb, int to_secs,
                 int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char scCmdBlk[SYNCHRONIZE_CACHE16_CMDLEN] =
                {SYNCHRONIZE_CACHE16_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (sync_nv)
        scCmdBlk[1] |= 4;       /* obsolete in sbc3r35d */
    if (immed)
        scCmdBlk[1] |= 2;
    sg_put_unaligned_be64(lba, scCmdBlk + 2);
    scCmdBlk[14] = group & 0x1f;
    sg_put_unaligned_be32((uint32_t)num_lb, scCmdBlk + 10);

    if (verbose) {
        fprintf(stderr, "    synchronize cache(16) cdb: ");
        for (k = 0; k < SYNCHRONIZE_CACHE16_CMDLEN; ++k)
            fprintf(stderr, "%02x ", scCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(stderr, "synchronize cache(16): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, scCmdBlk, sizeof(scCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, to_secs, verbose);
    ret = sg_cmds_process_resp(ptvp, "synchronize cache(16)", res, 0,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
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
    int sg_fd, res, c;
    int64_t count = 0;
    unsigned int num_lb = 0;
    int do_16 = 0;
    int group = 0;
    int64_t lba = 0;
    int immed = 0;
    int sync_nv = 0;
    int to_secs = DEF_PT_TIMEOUT;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;

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
                fprintf(stderr, "bad argument to '--count'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            num_lb = (unsigned int)count;
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
            immed = 1;
            break;
        case 'l':
            lba = sg_get_llnum(optarg);
            if (lba < 0) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 's':
            sync_nv = 1;
            break;
        case 'S':
            do_16 = 1;
            break;
        case 't':
            to_secs = sg_get_num(optarg);
            if (to_secs < 0) {
                fprintf(stderr, "bad argument to '--timeout'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
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

    if (do_16)
        res = ll_sync_cache_16(sg_fd, sync_nv, immed, group, lba, num_lb,
                               to_secs, 1, verbose);
    else
        res = sg_ll_sync_cache_10(sg_fd, sync_nv, immed, group,
                                  (unsigned int)lba, num_lb, 1, verbose);
    ret = res;
    if (res) {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        fprintf(stderr, "Synchronize cache failed: %s\n", b);
    }

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
