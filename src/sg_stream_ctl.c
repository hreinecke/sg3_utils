/*
 * Copyright (c) 2018-2019 Douglas Gilbert.
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
#include <getopt.h>
#include <errno.h>
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

/*
 * This program issues the SCSI STREAM CONTROL or GET STREAM STATUS command
 * to the given SCSI device. Based on sbc4r15.pdf .
 */

static const char * version_str = "1.08 20191220";

#define STREAM_CONTROL_SA 0x14
#define GET_STREAM_STATUS_SA 0x16

#define STREAM_CONTROL_OPEN 0x1
#define STREAM_CONTROL_CLOSE 0x2

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */


static struct option long_options[] = {
        {"brief", no_argument, 0, 'b'},
        {"close", no_argument, 0, 'c'},
        {"ctl", required_argument, 0, 'C'},
        {"get", no_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"id", required_argument, 0, 'i'},
        {"maxlen", required_argument, 0, 'm'},
        {"open", no_argument, 0, 'o'},
        {"readonly", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
            "sg_stream_ctl  [-brief] [--close] [--ctl=CTL] [-get] [--help]\n"
            "                      [--id=SID] [--maxlen=LEN] [--open] "
            "[--readonly]\n"
            "                      [--verbose] [--version] DEVICE\n");
    pr2serr("  where:\n"
            "    --brief|-b          for open, output assigned stream id to "
            "stdout, or\n"
            "                        -1 if error; for close, output 0, or "
            "-1; for get\n"
            "                        output list of stream id, 1 per line\n"
            "    --close|-c          close stream given by --id=SID\n"
            "    --ctl=CTL|-C CTL    CTL is stream control value, "
            "(STR_CTL field)\n"
            "                        1 -> open; 2 -> close\n"
            "    --get|-g            do GET STREAM STATUS command (default "
            "if no other)\n"
            "    --help|-h           print out usage message\n"
            "    --id=SID|-i SID     for close, SID is stream_id to close; "
            "for get,\n"
            "                        list from and include this stream id\n"
            "    --maxlen=LEN|-m LEN    length in bytes of buffer to "
            "receive data-in\n"
            "                           (def: 8 (for open and close); 252 "
            "(for get,\n"
            "                           but increase if needed)\n"
            "    --open|-o           open a new stream, return assigned "
            "stream id\n"
            "    --readonly|-r       open DEVICE read-only (if supported)\n"
            "    --verbose|-v        increase verbosity\n"
            "    --version|-V        print version string and exit\n\n"
            "Performs a SCSI STREAM CONTROL or GET STREAM STATUS command. "
            "If --open,\n--close or --ctl=CTL given (only one) then "
            "performs STREAM CONTROL\ncommand. If --get or no other "
            "selecting option given then performs a\nGET STREAM STATUS "
            "command. A successful --open will output the assigned\nstream "
            "id to stdout (and ignore --id=SID , if given).\n"
           );
}

/* Invokes a SCSI GET STREAM STATUS command (SBC-4).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_get_stream_status(int sg_fd, uint16_t s_str_id, uint8_t * resp,
                        uint32_t alloc_len, int * residp, bool noisy,
                        int verbose)
{
    int k, ret, res, sense_cat;
    uint8_t gssCdb[16] = {SG_SERVICE_ACTION_IN_16,
           GET_STREAM_STATUS_SA, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;
    static const char * const cmd_name = "Get stream status";

    if (s_str_id)         /* starting stream id, fetch from and including */
        sg_put_unaligned_be16(s_str_id, gssCdb + 4);
    sg_put_unaligned_be32(alloc_len, gssCdb + 10);
    if (verbose) {
        char b[128];

        pr2serr("    %s cdb: %s\n", cmd_name,
                sg_get_command_str(gssCdb, (int)sizeof(gssCdb), false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj_with_fd(sg_fd, verbose);
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", cmd_name);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, gssCdb, sizeof(gssCdb));
    set_scsi_pt_data_in(ptvp, resp, alloc_len);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, -1, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, cmd_name, res, noisy, verbose,
                               &sense_cat);
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
    k = ret ? (int)alloc_len : get_scsi_pt_resid(ptvp);
    if (residp)
        *residp = k;
    if ((verbose > 2) && ((alloc_len - k) > 0)) {
        pr2serr("%s: parameter data returned:\n", cmd_name);
        hex2stderr((const uint8_t *)resp, alloc_len - k,
                   ((verbose > 3) ? -1 : 1));
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI STREAM CONTROL command (SBC-4).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors.
 * N.B. The is a device modifying command that is SERVICE ACTION IN(16)
 * command since it has data-in buffer that for open returns the
 * ASSIGNED_STR_ID field . */
static int
sg_ll_stream_control(int sg_fd, uint32_t str_ctl, uint16_t str_id,
                     uint8_t * resp, uint32_t alloc_len, int * residp,
                     bool noisy, int verbose)
{
    int k, ret, res, sense_cat;
    uint8_t scCdb[16] = {SG_SERVICE_ACTION_IN_16,
           STREAM_CONTROL_SA, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;
    static const char * const cmd_name = "Stream control";

    if (str_ctl)
        scCdb[1] |= (str_ctl & 0x3) << 5;
    if (str_id)         /* Only used for close, stream id to close */
        sg_put_unaligned_be16(str_id, scCdb + 4);
    sg_put_unaligned_be32(alloc_len, scCdb + 10);
    if (verbose) {
        char b[128];

        pr2serr("    %s cdb: %s\n", cmd_name,
                sg_get_command_str(scCdb, (int)sizeof(scCdb), false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj_with_fd(sg_fd, verbose);
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", cmd_name);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, scCdb, sizeof(scCdb));
    set_scsi_pt_data_in(ptvp, resp, alloc_len);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, -1, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, cmd_name, res, noisy, verbose,
                               &sense_cat);
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
    k = ret ? (int)alloc_len : get_scsi_pt_resid(ptvp);
    if (residp)
        *residp = k;
    if ((verbose > 2) && ((alloc_len - k) > 0)) {
        pr2serr("%s: parameter data returned:\n", cmd_name);
        hex2stderr((const uint8_t *)resp, alloc_len - k,
                   ((verbose > 3) ? -1 : 1));
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}


int
main(int argc, char * argv[])
{
    bool do_brief = false;
    bool do_close = false;
    bool do_get = false;
    bool do_open = false;
    bool ctl_given = false;
    bool maxlen_given = false;
    bool read_only = false;
    bool verbose_given = false;
    bool version_given = false;
    int c, k, res, resid;
    int sg_fd = -1;
    int maxlen = 0;
    int ret = 0;
    int verbose = 0;
    uint16_t stream_id = 0;
    uint16_t num_streams = 0;
    uint32_t ctl = 0;
    uint32_t pg_sz = sg_get_page_size();
    uint32_t param_dl;
    const char * device_name = NULL;
    const char * cmd_name = NULL;
    uint8_t * arr = NULL;
    uint8_t * free_arr = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "bcC:ghi:m:orvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            do_brief = true;
            break;
        case 'c':
            do_close = true;
            break;
        case 'C':
            if ((1 != sscanf(optarg, "%4u", &ctl)) || (ctl > 3)) {
                pr2serr("--ctl= expects a number from 0 to 3\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ctl_given = true;
            break;
        case 'g':
            do_get = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            k = sg_get_num(optarg);
            if ((k < 0) || (k > UINT16_MAX)) {
                pr2serr("--id= expects a number from 0 to 65535\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            stream_id = (uint16_t)k;
            break;
        case 'm':
            k = sg_get_num(optarg);
            if (k < 0) {
                pr2serr("--maxlen= unable to decode argument\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            maxlen_given = true;
            if (k > 0)
                maxlen = k;
            break;
        case 'o':
            do_open = true;
            break;
        case 'r':
            read_only = true;
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
        pr2serr("missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    k = (int)do_close + (int)do_get + (int)do_open + (int)ctl_given;
    if (k > 1) {
        pr2serr("Can only have one of: --close, --ctl==, --get, or --open\n");
        return SG_LIB_CONTRADICT;
    } else if (0 == k)
        do_get = true;
    if (do_close)
        ctl = STREAM_CONTROL_CLOSE;
    else if (do_open)
        ctl = STREAM_CONTROL_OPEN;

    if (maxlen_given) {
        if (0 == maxlen)
            maxlen = do_get ? 248 : 8;
    } else
        maxlen = do_get ? 248 : 8;

    if (verbose) {
        if (read_only && (! do_get))
            pr2serr("Probably need to open %s read-write\n", device_name);
        if (do_open && (stream_id > 0))
            pr2serr("With --open the --id-SID option is ignored\n");
    }

    sg_fd = sg_cmds_open_device(device_name, read_only, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    if (maxlen > (int)pg_sz)
        arr = sg_memalign(maxlen, pg_sz, &free_arr, verbose > 3);
    else
        arr = sg_memalign(pg_sz, pg_sz, &free_arr, verbose > 3);
    if (NULL == arr) {
        pr2serr("Unable to allocate space for response\n");
        ret = sg_convert_errno(ENOMEM);
        goto fini;
    }

    resid = 0;
    if (do_get) {       /* Get stream status */
        cmd_name = "Get stream status";
        ret = sg_ll_get_stream_status(sg_fd, stream_id, arr, maxlen,
                                      &resid, false, verbose);
        if (ret) {
            if (SG_LIB_CAT_INVALID_OP == ret)
                pr2serr("%s command not supported\n", cmd_name);
            else {
                char b[80];

                sg_get_category_sense_str(ret, sizeof(b), b, verbose);
                pr2serr("%s command: %s\n", cmd_name, b);
            }
            goto fini;
        }
        if ((maxlen - resid) < 4) {
            pr2serr("Response too short (%d bytes) assigned stream id\n",
                        k);
            printf("-1\n");
            ret = SG_LIB_CAT_MALFORMED;
            goto fini;
        } else
            maxlen -= resid;
        param_dl = sg_get_unaligned_be32(arr + 0) + 4;
        if (param_dl > (uint32_t)maxlen) {
            pr2serr("Response truncated, need to set --maxlen=%u\n",
                    param_dl);
            if (maxlen < (8 /* header */ + 4 /* enough of first */)) {
                pr2serr("Response too short to continue\n");
                goto fini;
            }
        }
        num_streams = sg_get_unaligned_be16(arr + 6);
        if (! do_brief) {
            if (stream_id > 0)
            printf("Starting at stream id: %u\n", stream_id);
            printf("Number of open streams: %u\n", num_streams);
        }
        maxlen = ((uint32_t)maxlen < param_dl) ? maxlen : (int)param_dl;
        for (k = 8; k < (maxlen - 4); k += 8) {
            stream_id = sg_get_unaligned_be16(arr + k + 2);
            if (do_brief)
                printf("%u\n", stream_id);
            else
                printf("Open stream id: %u\n", stream_id);
        }
    } else {            /* Stream control */
        cmd_name = "Stream control";
        ret = sg_ll_stream_control(sg_fd, ctl, stream_id, arr, maxlen,
                                   &resid, false, verbose);
        if (ret) {
            if (SG_LIB_CAT_INVALID_OP == ret)
                pr2serr("%s command not supported\n", cmd_name);
            else {
                char b[80];

                sg_get_category_sense_str(ret, sizeof(b), b, verbose);
                pr2serr("%s command: %s\n", cmd_name, b);
            }
            goto fini;
        }
        if (do_open) {
            k = arr[0] + 1;
            k = (k < (maxlen - resid)) ? k : (maxlen - resid);
            if (k < 5) {
                pr2serr("Response too short (%d bytes) assigned stream id\n",
                        k);
                printf("-1\n");
                ret = SG_LIB_CAT_MALFORMED;
            } else {
                stream_id = sg_get_unaligned_be16(arr + 4);
                if (do_brief)
                    printf("%u\n", stream_id);
                else
                    printf("Assigned stream id: %u\n", stream_id);
            }
        }
    }

fini:
    if (free_arr)
        free(free_arr);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_stream_ctl failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
