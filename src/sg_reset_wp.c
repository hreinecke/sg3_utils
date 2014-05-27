/*
 * Copyright (c) 2014 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI RESET WRITE POINTER command to the given SCSI
 * device.
 */

static const char * version_str = "1.00 20140527";

#define SERVICE_ACTION_OUT_16_CMD 0x9f
#define SERVICE_ACTION_OUT_16_CMDLEN 16
#define RESET_WRITE_POINTER_SA 0x14

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"reset-all", no_argument, 0, 'R'},
        {"reset_all", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"zone", required_argument, 0, 'z'},
        {0, 0, 0, 0},
};


#ifdef __GNUC__
static int pr2serr(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
static int pr2serr(const char * fmt, ...);
#endif


static int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

static void
usage()
{
    pr2serr("Usage: "
            "sg_reset_wp  [--help] [--reset-all] [--verbose] [--version]\n"
            "                    [--zone=ID] DEVICE\n");
    pr2serr("  where:\n"
            "    --help|-h          print out usage message\n"
            "    --reset-all|-R     sets the RESET ALL flag in the cdb\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "    --zone=ID|-z ID    ID is the starting LBA of the zone "
            "whose\n"
            "                       write pointer is to be reset\n"
            "Performs a SCSI RESET WRITE POINTER command. ID is decimal by "
            "default,\nfor hex use a leading '0x' or a trailing 'h'. "
            "Either the --zone=ID\nor --reset-all needs to be given.\n");
}

/* Invokes a SCSI RESET WRITE POINTER command (ZBC).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_reset_write_pointer(int sg_fd, uint64_t zid, int reset_all, int noisy,
                          int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rwpCmdBlk[SERVICE_ACTION_OUT_16_CMDLEN] =
          {SERVICE_ACTION_OUT_16_CMD, RESET_WRITE_POINTER_SA, 0, 0,
           0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if ((zid >> 56) & 0xff) {
        pr2serr("%s: zone id (LBA) too large\n", __func__);
        return SG_LIB_CAT_MALFORMED;
    }
    /* a 7 byte field as zbc-r01a claims ?? */
    rwpCmdBlk[3] = (zid >> 48) & 0xff;
    rwpCmdBlk[4] = (zid >> 40) & 0xff;
    rwpCmdBlk[5] = (zid >> 32) & 0xff;
    rwpCmdBlk[6] = (zid >> 24) & 0xff;
    rwpCmdBlk[7] = (zid >> 16) & 0xff;
    rwpCmdBlk[8] = (zid >> 8) & 0xff;
    rwpCmdBlk[9] = zid & 0xff;
    if (reset_all)
        rwpCmdBlk[14] = 0x1;
    if (verbose) {
        pr2serr("    Reset write pointer cdb: ");
        for (k = 0; k < SERVICE_ACTION_OUT_16_CMDLEN; ++k)
            pr2serr("%02x ", rwpCmdBlk[k]);
        pr2serr("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Reset write pointer: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rwpCmdBlk, sizeof(rwpCmdBlk));
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
    int reset_all = 0;
    int verbose = 0;
    int zid_given = 0;
    uint64_t zid = 0;
    int64_t ll;
    const char * device_name = NULL;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hRvVz:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'R':
            ++reset_all;
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
                fprintf(stderr, "bad argument to '--zone=ID'\n");
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

    if ((! zid_given) && (0 == reset_all)) {
        pr2serr("either the --zone=ID or --reset-all option is required\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
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

    res = sg_ll_reset_write_pointer(sg_fd, zid, reset_all, 1, verbose);
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

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
