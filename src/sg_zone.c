/*
 * Copyright (c) 2014-2016 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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
 * This program issues a SCSI CLOSE ZONE, FINISH ZONE or OPEN ZONE command
 * to the given SCSI device. Based on zbc-r04c.pdf .
 */

static const char * version_str = "1.03 20160528";

#define SG_ZONING_OUT_CMDLEN 16
#define CLOSE_ZONE_SA 0x1
#define FINISH_ZONE_SA 0x2
#define OPEN_ZONE_SA 0x3

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */


static struct option long_options[] = {
        {"all", no_argument, 0, 'a'},
        {"close", no_argument, 0, 'c'},
        {"finish", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"open", no_argument, 0, 'o'},
        {"reset-all", no_argument, 0, 'R'},
        {"reset_all", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"zone", required_argument, 0, 'z'},
        {0, 0, 0, 0},
};

/* Indexed by service action */
static const char * sa_name_arr[] = {
    "no SA=0",
    "Close zone",
    "Finish zone",
    "Open zone",
};


static void
usage()
{
    pr2serr("Usage: "
            "sg_zone  [--all] [--close] [--finish] [--help] [--open]\n"
            "                [--verbose] [--version] [--zone=ID] DEVICE\n");
    pr2serr("  where:\n"
            "    --all|-a           sets the ALL flag in the cdb\n"
            "    --close|-c         issue CLOSE ZONE command\n"
            "    --finish|-f        issue FINISH ZONE command\n"
            "    --help|-h          print out usage message\n"
            "    --open|-o          issue OPEN ZONE command\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n"
            "    --zone=ID|-z ID    ID is the starting LBA of the zone\n\n"
            "Performs a SCSI OPEN ZONE, CLOSE ZONE or FINISH ZONE command. "
            "ID is\ndecimal by default, for hex use a leading '0x' or a "
            "trailing 'h'.\nEither --close, --finish, or --open option "
            "needs to be given.\n");
}

/* Invokes the zone out command indicated by 'sa' (ZBC).  Return of 0
 * -> success, various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_zone_out(int sg_fd, int sa, uint64_t zid, int all, int noisy,
               int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char zo_cdb[SG_ZONING_OUT_CMDLEN] =
          {SG_ZONING_OUT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;
    char b[64];

    zo_cdb[1] = 0x1f & sa;
    sg_put_unaligned_be64(zid, zo_cdb + 2);
    if (all)
        zo_cdb[14] = 0x1;
    sg_get_opcode_sa_name(zo_cdb[0], sa, -1, sizeof(b), b);
    if (verbose) {
        pr2serr("    %s cdb: ", b);
        for (k = 0; k < SG_ZONING_OUT_CMDLEN; ++k)
            pr2serr("%02x ", zo_cdb[k]);
        pr2serr("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", b);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, zo_cdb, sizeof(zo_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "reset write pointer", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
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


int
main(int argc, char * argv[])
{
    int sg_fd, res, c;
    int all = 0;
    int close = 0;
    int finish = 0;
    int open = 0;
    int verbose = 0;
    int zid_given = 0;
    int sa = 0;
    uint64_t zid = 0;
    int64_t ll;
    const char * device_name = NULL;
    const char * sa_name;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "acfhoRvVz:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
        case 'R':
            ++all;
            break;
        case 'c':
            ++close;
            sa = CLOSE_ZONE_SA;
            break;
        case 'f':
            ++finish;
            sa = FINISH_ZONE_SA;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'o':
            ++open;
            sa = OPEN_ZONE_SA;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr("version: %s\n", version_str);
            return 0;
        case 'z':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--zone=ID'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            zid = (uint64_t)ll;
            ++zid_given;
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

    if (1 != ((!! close) + (!! finish) + (!! open))) {
        pr2serr("one from the --close, --finish and --open options must be "
                "given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sa_name = sa_name_arr[sa];

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    sg_fd = sg_cmds_open_device(device_name, 0, verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    res = sg_ll_zone_out(sg_fd, sa, zid, all, 1, verbose);
    ret = res;
    if (res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr("%s command not supported\n", sa_name);
        else {
            char b[80];

            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("%s command: %s\n", sa_name, b);
        }
    }

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
