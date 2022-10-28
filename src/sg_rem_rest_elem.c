/*
 * Copyright (c) 2022 Douglas Gilbert.
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
 * This program issues one of the following SCSI commands:
 *   - REMOVE ELEMENT AND TRUNCATE
 *   - RESTORE ELEMENTS AND REBUILD
 */

static const char * version_str = "1.01 20221027";

#define REMOVE_ELEM_SA 0x18
#define RESTORE_ELEMS_SA 0x19

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */


static struct option long_options[] = {
        {"capacity", required_argument, 0, 'c'},
        {"element", required_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"quick", no_argument, 0, 'q'},
        {"remove", no_argument, 0, 'r'},
        {"restore", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static const char * remove_cmd_s = "Remove element and truncate";
static const char * restore_cmd_s = "Restore elements and rebuild";


static void
usage()
{
    pr2serr("Usage: "
            "sg_rem_rest_elem  [--capacity=RC] [--element=EID] [--help] "
            "[--quick]\n"
            "                         [--remove] [--restore] [--verbose] "
            "[--version]\n"
            "                         DEVICE\n");
    pr2serr("  where:\n"
            "    --capacity=RC|-c RC    RC is requested capacity (unit: "
            "block; def: 0)\n"
            "    --element=EID|-e EID    EID is the element identifier to "
            "remove;\n"
            "                            default is 0 which is an invalid "
            "EID\n"
            "    --help|-h          print out usage message\n"
            "    --quick|-q         bypass 15 second warn and wait\n"
            "    --remove|-r        issue REMOVE ELEMENT AND TRUNCATE "
            "command\n"
            "    --restore|-R       issue RESTORE ELEMENTS AND REBUILD "
            "command\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI REMOVE ELEMENT AND TRUNCATE or RESTORE "
            "ELEMENTS AND\nREBUILD command. Either the --remove or "
            "--restore option needs to be given.\n");
}

/* Return of 0 -> success, various SG_LIB_CAT_* positive values or -1 ->
 * other errors */
static int
sg_ll_rem_rest_elem(int sg_fd, int sa, uint64_t req_cap, uint32_t e_id,
                    bool noisy, int verbose)
{
    int ret, res, sense_cat;
    struct sg_pt_base * ptvp;
    uint8_t sai16_cdb[16] =
          {SG_SERVICE_ACTION_IN_16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    const char * cmd_name;

    sai16_cdb[1] = 0x1f & sa;
    if (REMOVE_ELEM_SA == sa) {
        sg_put_unaligned_be64(req_cap, sai16_cdb + 2);
        sg_put_unaligned_be32(e_id, sai16_cdb + 10);
        cmd_name = remove_cmd_s;
    } else
        cmd_name = restore_cmd_s;
    if (verbose) {
        char d[128];

        pr2serr("    %s cdb: %s\n", cmd_name,
                sg_get_command_str(sai16_cdb, 16, false, sizeof(d), d));
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", cmd_name);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, sai16_cdb, sizeof(sai16_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, cmd_name, res, noisy,
                               verbose, &sense_cat);
    if (-1 == ret) {
        if (get_scsi_pt_transport_err(ptvp))
            ret = SG_LIB_TRANSPORT_ERROR;
        else
            ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    } else if (-2 == ret) {
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
    bool quick = false;
    bool reat = false;
    bool resar = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c;
    int sg_fd = -1;
    int verbose = 0;
    int ret = 0;
    int sa = 0;
    uint32_t e_id = 0;
    uint64_t req_cap = 0;
    int64_t ll;
    const char * device_name = NULL;
    const char * cmd_name;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "c:e:hqrRvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("--capacity= expects a numeric argument\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            req_cap = (uint64_t)ll;
            break;
        case 'e':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--element=EID'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (0 == ll)
                pr2serr("Warning: 0 is an invalid element identifier\n");
            e_id = (uint64_t)ll;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'q':
            quick = true;
            break;
        case 'r':
            reat = true;
            sa = REMOVE_ELEM_SA;
            break;
        case 'R':
            resar = true;
            sa = RESTORE_ELEMS_SA;
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

    if (1 != ((int)reat + (int)resar)) {
        pr2serr("One, and only one, of these options needs to be given:\n"
                "   --remove or --restore\n\n");
        usage();
        return SG_LIB_CONTRADICT;
    }
    cmd_name = reat ? remove_cmd_s : restore_cmd_s;

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
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
    if (! quick) {
        int k;
        char b[80] SG_C_CPP_ZERO_INIT;
        char ch;

        for (k = 0; k < (int)sizeof(b) - 1; ++k) {
            ch = cmd_name[k];
            if ('\0' == ch)
                break;
            else if (islower(ch))
                b[k] = toupper(ch);
            else
                b[k] = ch;
        }
        sg_warn_and_wait(b, device_name, false);
    }

    res = sg_ll_rem_rest_elem(sg_fd, sa, req_cap, e_id, true, verbose);
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
        if (! sg_if_can2stderr("sg_rem_rest_elem failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
