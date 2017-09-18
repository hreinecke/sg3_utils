/*
 * Copyright (c) 2016-2017 Douglas Gilbert.
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
 * This program issues the SCSI BACKGROUND CONTROL command to the given SCSI
 * device. Based on sbc4r10.pdf .
 */

static const char * version_str = "1.01 20170917";

#define BACKGROUND_CONTROL_SA 0x15

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

static const char * cmd_name = "Background control";


static struct option long_options[] = {
        {"ctl", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"time", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
            "sg_bg_ctl  [--ctl=CTL] [--help] [--time=TN] [--verbose] "
            "[--version]\n"
            "                  DEVICE\n");
    pr2serr("  where:\n"
            "    --ctl=CTL|-c CTL    CTL is background operation control "
            "value\n"
            "                        default: 0 -> don't change background "
            "operations\n"
            "                        1 -> start; 2 -> stop\n"
            "    --help|-h          print out usage message\n"
            "    --time=TN|-t TN    TN (units 100 ms) is max time to perform "
            "background\n"
            "                       operations (def: 0 -> no limit)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI BACKGROUND CONTROL command. It can start or "
            "stop\n'advanced background operations'. Operations started by "
            "this command\n(i.e. when ctl=1) are termed as 'host initiated' "
            "and allow a resource or\nthin provisioned device (disk) to "
            "perform garbage collection type operations.\nThese may "
            "degrade performance while they occur. Hence it is best to\n"
            "perform this action while the computer is not too busy.\n");
}

/* Invokes a SCSI BACKGROUND CONTROL command (SBC-4).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_background_control(int sg_fd, unsigned int bo_ctl, unsigned int bo_time,
                         bool noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char bcCDB[16] = {SG_SERVICE_ACTION_IN_16,
           BACKGROUND_CONTROL_SA, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
           0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (bo_ctl)
        bcCDB[2] |= (bo_ctl & 0x3) << 6;
    if (bo_time)
        bcCDB[3] = bo_time;
    if (verbose) {
        pr2serr("    %s cdb: ", cmd_name);
        for (k = 0; k < (int)sizeof(bcCDB); ++k)
            pr2serr("%02x ", bcCDB[k]);
        pr2serr("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", cmd_name);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, bcCDB, sizeof(bcCDB));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, cmd_name, res, 0, sense_b, noisy,
                               verbose, &sense_cat);
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
    unsigned int ctl = 0;
    unsigned int time_tnth = 0;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "c:ht:vV", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            if ((1 != sscanf(optarg, "%4u", &ctl)) || (ctl > 3)) {
                pr2serr("--ctl= expects a number from 0 to 3\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 't':
            if ((1 != sscanf(optarg, "%4u", &time_tnth)) ||
                (time_tnth > 255)) {
                pr2serr("--time= expects a number from 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr("version: %s\n", version_str);
            return 0;
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

    res = sg_ll_background_control(sg_fd, ctl, time_tnth, true, verbose);
    ret = res;
    if (res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr("%s command not supported\n", cmd_name);
        else {
            char b[80];

            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("%s command: %s\n", cmd_name, b);
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
