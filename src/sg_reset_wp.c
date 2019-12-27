/*
 * Copyright (c) 2014-2019 Douglas Gilbert.
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
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI RESET WRITE POINTER command to the given SCSI
 * device. Based on zbc-r04c.pdf .
 */

static const char * version_str = "1.14 20191220";

#define SG_ZONING_OUT_CMDLEN 16
#define RESET_WRITE_POINTER_SA 0x4

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */


static struct option long_options[] = {
        {"all", no_argument, 0, 'a'},
        {"count", required_argument, 0, 'C'},
        {"help", no_argument, 0, 'h'},
        {"reset-all", no_argument, 0, 'R'},
        {"reset_all", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"zone", required_argument, 0, 'z'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
            "sg_reset_wp  [--all] [--count=ZC] [--help] [--verbose]\n"
            "                    [--version] [--zone=ID] DEVICE\n");
    pr2serr("  where:\n"
            "    --all|-a           sets the ALL flag in the cdb\n"
            "    --count=ZC|-C ZC    set zone count field (def: 0)\n"
            "    --help|-h          print out usage message\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n"
            "    --zone=ID|-z ID    ID is the starting LBA of the zone "
            "whose\n"
            "                       write pointer is to be reset\n\n"
            "Performs a SCSI RESET WRITE POINTER command. ID is decimal by "
            "default,\nfor hex use a leading '0x' or a trailing 'h'. "
            "Either the --zone=ID\nor --all option needs to be given.\n");
}

/* Invokes a SCSI RESET WRITE POINTER command (ZBC).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_reset_write_pointer(int sg_fd, uint64_t zid, uint16_t zc, bool all,
                          bool noisy, int verbose)
{
    int ret, res, sense_cat;
    uint8_t rwp_cdb[SG_ZONING_OUT_CMDLEN] = {SG_ZONING_OUT,
         RESET_WRITE_POINTER_SA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be64(zid, rwp_cdb + 2);
    sg_put_unaligned_be16(zc, rwp_cdb + 12);
    if (all)
        rwp_cdb[14] = 0x1;
    if (verbose) {
        char b[128];

        pr2serr("    Reset write pointer cdb: %s\n",
                sg_get_command_str(rwp_cdb, SG_ZONING_OUT_CMDLEN, false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Reset write pointer: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rwp_cdb, sizeof(rwp_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "reset write pointer", res, noisy,
                               verbose, &sense_cat);
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


int
main(int argc, char * argv[])
{
    bool all = false;
    bool verbose_given = false;
    bool version_given = false;
    bool zid_given = false;
    int res, c, n;
    int sg_fd = -1;
    int ret = 0;
    int verbose = 0;
    uint16_t zc = 0;
    uint64_t zid = 0;
    int64_t ll;
    const char * device_name = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aC:hRvVz:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
        case 'R':
            all = true;
            break;
        case 'C':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 0xffff)) {
                pr2serr("--count= expects an argument between 0 and 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            zc = (uint16_t)n;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
        case 'z':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--zone=ID'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            zid = (uint64_t)ll;
            zid_given = true;
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

    if ((! zid_given) && (! all)) {
        pr2serr("either the --zone=ID or --all option is required\n\n");
        usage();
        return SG_LIB_CONTRADICT;
    }
    if (NULL == device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    sg_fd = sg_cmds_open_device(device_name, false /* rw */, verbose);
    if (sg_fd < 0) {
        int err = -sg_fd;

        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(err));
        ret = sg_convert_errno(err);
        goto fini;
    }

    res = sg_ll_reset_write_pointer(sg_fd, zid, zc, all, true, verbose);
    ret = res;
    if (res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr("Reset write pointer command not supported\n");
        else {
            char b[80];

            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("Reset write pointer command: %s\n", b);
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
        if (! sg_if_can2stderr("sg_reset_wp failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
