/*
 * Copyright (c) 2014-2020 Douglas Gilbert.
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
#include <errno.h>
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
 * This program issues the SCSI REPORT PROVISIONING INITIALIZATION PATTERN
 * command to the given SCSI device and outputs the response. Based on
 * sbc4r21.pdf
 */

static const char * version_str = "1.01 20200605";

#define MAX_RPIP_BUFF_LEN (1024 * 1024)
#define DEF_RPIP_BUFF_LEN 512

#define SG_MAINT_IN_CMDLEN 12

#define REPORT_PROVISIONING_INITIALIZATION_PATTERN_SA 0x1d

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

static const char * rpip_s = "Report provisioning initialization pattern";


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"maxlen", required_argument, 0, 'm'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage(void)
{
    pr2serr("Usage: "
            "sg_rep_pip  [--help] [--hex] [--maxlen=LEN] [--raw] "
            "[--readonly]\n"
            "                   [--verbose] [--version] DEVICE\n");
    pr2serr("  where:\n"
            "    --help|-h          prints out this usage message\n"
            "    --hex|-H           output response in hexadecimal "
            "(default); used\n"
            "                       twice: hex without addresses at start "
            "of line\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 512 bytes)\n"
            "    --raw|-r           output response in binary\n"
            "    --readonly|-R      open DEVICE read-only (def: read-write)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Sends a SCSI REPORT PROVISIONING INITIALIZATION PATTERN "
            "command and outputs\nthe response in ASCII hexadecimal or "
            "binary.\n");
}

/* Invokes a SCSI REPORT PROVISIONING INITIALIZATION PATTERN command (SBC).
 * Return of 0 -> success, various SG_LIB_CAT_* positive values or
 * -1 -> other errors */
static int
sg_ll_report_pip(int sg_fd, void * resp, int mx_resp_len, int * residp,
                 bool noisy, int verbose)
{
    int ret, res, sense_cat;
    uint8_t rz_cdb[SG_MAINT_IN_CMDLEN] =
          {SG_MAINTENANCE_IN, REPORT_PROVISIONING_INITIALIZATION_PATTERN_SA,
           0, 0,  0, 0, 0, 0,  0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32((uint32_t)mx_resp_len, rz_cdb + 6);
    if (verbose) {
        char b[128];

        pr2serr("    %s cdb: %s\n", rpip_s,
                sg_get_command_str(rz_cdb, SG_MAINT_IN_CMDLEN, false,
                                   sizeof(b), b));
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rz_cdb, sizeof(rz_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, rpip_s, res, noisy, verbose, &sense_cat);
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
    if (residp)
        *residp = get_scsi_pt_resid(ptvp);
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}


int
main(int argc, char * argv[])
{
    bool do_raw = false;
    bool o_readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c, resid, rlen;
    int sg_fd = -1;
    int do_help = 0;
    int do_hex = 1;
    int maxlen = 0;
    int ret = 0;
    int verbose = 0;
    const char * device_name = NULL;
    uint8_t * rpipBuff = NULL;
    uint8_t * free_rpip = NULL;
    char b[80];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHm:rRvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            ++do_help;
            break;
        case 'H':
            ++do_hex;
            break;
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MAX_RPIP_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_RPIP_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
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

    if (do_help) {
        usage();
        return 0;
    }
    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto the_end;
    }

    if (0 == maxlen)
        maxlen = DEF_RPIP_BUFF_LEN;
    rpipBuff = (uint8_t *)sg_memalign(maxlen, 0, &free_rpip, verbose > 3);
    if (NULL == rpipBuff) {
        pr2serr("unable to sg_memalign %d bytes\n", maxlen);
        return sg_convert_errno(ENOMEM);
    }
    res = sg_ll_report_pip(sg_fd, rpipBuff, maxlen, &resid, true, verbose);
    ret = res;
    if (0 == res) {
        rlen = maxlen - resid;
        if (rlen < 4) {
            pr2serr("Response length (%d) too short\n", rlen);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        if (do_raw) {
            dStrRaw(rpipBuff, rlen);
            goto the_end;
        }
        if (do_hex && (2 != do_hex)) {
            hex2stdout(rpipBuff, rlen, ((1 == do_hex) ? 1 : -1));
            goto the_end;
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("%s command not supported\n", rpip_s);
    else {
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("%s command: %s\n", rpip_s, b);
    }

the_end:
    if (free_rpip)
        free(free_rpip);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_rep_pip failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
