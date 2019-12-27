/*
 * Copyright (c) 2019 Douglas Gilbert.
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
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI GET PHYSICAL ELEMENT STATUS command to the
 * given SCSI device.
 */

static const char * version_str = "1.01 20191220";      /* sbc4r15,17 */


#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif

#define GET_PHY_ELEM_STATUS_SA 0x17
#define DEF_GPES_BUFF_LEN 32
#define MAX_GPES_BUFF_LEN ((1024 * 1024) + DEF_GPES_BUFF_LEN)
#define GPES_DESC_OFFSET 32     /* descriptors starts at this byte offset */
#define GPES_DESC_LEN 32

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

struct gpes_desc_t {    /* info in returned physical status descriptor */
    bool restore_allowed;
    uint32_t elem_id;
    uint8_t phys_elem_type;
    uint8_t phys_elem_health;
    uint64_t assoc_cap;   /* number of LBs removed if depopulated */
};

static uint8_t gpesBuff[DEF_GPES_BUFF_LEN];


static struct option long_options[] = {
        {"brief", no_argument, 0, 'b'},
        {"filter", required_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"in", required_argument, 0, 'i'},      /* silent, same as --inhex= */
        {"inhex", required_argument, 0, 'i'},
        {"maxlen", required_argument, 0, 'm'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"report-type", required_argument, 0, 't'},
        {"report_type", required_argument, 0, 't'},
        {"starting", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
    pr2serr("Usage: sg_get_elem_status  [--brief] [--filter=FLT] [--help] "
            "[--hex]\n"
            "                           [--inhex=FN] [--maxlen=LEN] [--raw] "
            "[--readonly]\n"
            "                           [--report-type=RT] [--starting=ELEM] "
            "[--verbose]\n"
            "                           [--version] DEVICE\n"
            "  where:\n"
            "    --brief|-b        one descriptor per line\n"
            "    --filter=FLT|-f FLT    FLT is 0 (def) for all physical "
            "elements;\n"
            "                           1 for out of spec and depopulated "
            "elements\n"
            "    --help|-h         print out usage message\n"
            "    --hex|-H          output in hexadecimal\n"
            "    --inhex=FN        input taken from file FN rather than "
            "DEVICE,\n"
            "                      assumed to be ASCII hex or, if --raw, "
            "in binary\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n",
            DEF_GPES_BUFF_LEN );
    pr2serr("    --raw|-r          output in binary, unless --inhex=FN is "
            "given in\n"
            "                      in which case the input is assumed to be "
            "binary\n"
            "    --readonly|-R     open DEVICE read-only (def: read-write)\n"
            "    --report-type=RT|-t RT    report type: 0-> physical "
            "elements (def);\n"
            "                                           1-> storage "
            "elements\n"
            "    --starting=ELEM|-s ELEM    ELEM is the lowest identifier "
            "returned\n"
            "                               (def: 1 which is lowest "
            "identifier)\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Performs a SCSI GET PHYSICAL ELEMENT STATUS command (see SBC-3 "
            "or SBC-4).\nIf --inhex=FN is given then contents of FN is "
            "assumed to be a response\nto this command in ASCII hex. "
            "Returned element descriptors should be\nin ascending "
            "identifier order.\n"
            );
}

/* Invokes a SCSI GET PHYSICAL ELEMENT STATUS command (SBC-4).  Return of
 * 0 -> success, various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_get_phy_elem_status(int sg_fd, uint32_t starting_elem, uint8_t filter,
                          uint8_t report_type, uint8_t * resp,
                          uint32_t alloc_len, int * residp, bool noisy,
                          int verbose)
{
    int k, ret, res, sense_cat;
    uint8_t gpesCmd[16] = {SG_SERVICE_ACTION_IN_16,
                           GET_PHY_ELEM_STATUS_SA, 0, 0, 0, 0,
                           0, 0, 0, 0,  0, 0, 0, 0,  0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;
    static const char * const cmd_name = "Get physical element status";

    if (starting_elem)
        sg_put_unaligned_be32(starting_elem, gpesCmd + 6);
    sg_put_unaligned_be32(alloc_len, gpesCmd + 10);
    if (filter)
        gpesCmd[14] |= filter << 6;
    if (report_type)
        gpesCmd[14] |= (0xf & report_type);
    if (verbose) {
        char b[128];

        pr2serr("    %s cdb: %s\n", cmd_name,
                sg_get_command_str(gpesCmd, (int)sizeof(gpesCmd), false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj_with_fd(sg_fd, verbose);
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", cmd_name);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, gpesCmd, sizeof(gpesCmd));
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

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Decodes given physical element status descriptor.  */
static void
decode_elem_status_desc(const uint8_t * bp, struct gpes_desc_t * pedp)
{
    if ((NULL == bp) || (NULL == pedp))
        return;
    pedp->elem_id = sg_get_unaligned_be32(bp + 4);
    pedp->restore_allowed = (bool)(bp[13] & 1);
    pedp->phys_elem_type = bp[14];
    pedp->phys_elem_health = bp[15];
    pedp->assoc_cap = sg_get_unaligned_be64(bp + 16);
}


int
main(int argc, char * argv[])
{
    bool do_raw = false;
    bool no_final_msg = false;
    bool o_readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int k, j, n, res, c, rlen, in_len;
    int sg_fd = -1;
    int do_brief = 0;
    int do_hex = 0;
    int resid = 0;
    int ret = 0;
    int maxlen = DEF_GPES_BUFF_LEN;
    int verbose = 0;
    uint8_t filter = 0;
    uint8_t rt = 0;
    uint32_t num_desc, num_desc_ret, id_elem_depop;
    uint32_t d_blocks = 0;
    uint32_t starting_elem = 0;
    int64_t ll;
    const char * device_name = NULL;
    const char * in_fn = NULL;
    const uint8_t * bp;
    uint8_t * gpesBuffp = gpesBuff;
    uint8_t * free_gpesBuffp = NULL;
    struct gpes_desc_t a_ped;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "bf:hHi:m:rRs:St:TvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            ++do_brief;
            break;
        case 'f':
            n = sg_get_num_nomult(optarg);
            if ((n < 0) || (n > 15)) {
                pr2serr("'--filter=RT' should be between 0 and 15 "
                        "(inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            filter = n;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'i':
            in_fn = optarg;
            break;
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MAX_GPES_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_GPES_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (0 == maxlen)
                maxlen = DEF_GPES_BUFF_LEN;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
            break;
        case 's':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--starting='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            starting_elem = (uint32_t)ll;
            break;
        case 't':       /* --report-type=RT */
            n = sg_get_num_nomult(optarg);
            if ((n < 0) || (n > 15)) {
                pr2serr("'--report-type=RT' should be between 0 and 15 "
                        "(inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            rt = n;
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

    if (maxlen > DEF_GPES_BUFF_LEN) {
        gpesBuffp = (uint8_t *)sg_memalign(maxlen, 0, &free_gpesBuffp,
                                           verbose > 3);
        if (NULL == gpesBuffp) {
            pr2serr("unable to allocate %d bytes on heap\n", maxlen);
            return sg_convert_errno(ENOMEM);
        }
    }
    if (device_name && in_fn) {
        pr2serr("ignoring DEVICE, best to give DEVICE or --inhex=FN, but "
                "not both\n");
        device_name = NULL;
    }
    if (NULL == device_name) {
        if (in_fn) {
            if ((ret = sg_f2hex_arr(in_fn, do_raw, false, gpesBuffp,
                                    &in_len, maxlen))) {
                if (SG_LIB_LBA_OUT_OF_RANGE == ret) {
                    pr2serr("--maxlen=%d needs to be increased", maxlen);
                    if (in_len > 7) {
                        n = (sg_get_unaligned_be32(gpesBuffp + 4) *
                             GPES_DESC_LEN) + GPES_DESC_OFFSET;
                        pr2serr(" to at least %d\n", n);
                    } else
                        pr2serr("\n");
                    pr2serr("... decode what we have\n");
                    no_final_msg = true;
                } else
                    goto fini;
            }
            if (verbose > 2)
                pr2serr("Read %d [0x%x] bytes of user supplied data\n",
                        in_len, in_len);
            if (do_raw)
                do_raw = false;    /* can interfere on decode */
            if (in_len < 4) {
                pr2serr("--in=%s only decoded %d bytes (needs 4 at least)\n",
                        in_fn, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
                goto fini;
            }
            res = 0;
            goto start_response;
        } else {
            pr2serr("missing device name!\n\n");
            usage();
            ret = SG_LIB_FILE_ERROR;
            no_final_msg = true;
            goto fini;
        }
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
    }
    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    res = sg_ll_get_phy_elem_status(sg_fd, starting_elem, filter, rt,
                                    gpesBuffp, maxlen, &resid, true, verbose);
    ret = res;
    if (res)
        goto error;

start_response:
    k = maxlen - resid;
    if (k < 4) {
        pr2serr("Response too short (%d bytes) due to resid (%d)\n", k,
                resid);
        if ((k > 0) && (do_raw || do_hex)) {
            if (do_hex)
                hex2stdout(gpesBuffp, k, 1);
            else
                dStrRaw((const char *)gpesBuffp, k);
        }
        ret = SG_LIB_CAT_MALFORMED;
        goto fini;
    } else
        maxlen -= resid;
    num_desc = sg_get_unaligned_be32(gpesBuffp + 0);
    if (maxlen > 7) {
        num_desc_ret = sg_get_unaligned_be32(gpesBuffp + 4);
        id_elem_depop = (maxlen > 11) ? sg_get_unaligned_be32(gpesBuffp + 8) :
                                        0;
    } else {
        num_desc_ret = 0;
        id_elem_depop = 0;
    }
    rlen = (num_desc_ret * GPES_DESC_LEN) + GPES_DESC_OFFSET;
    if ((verbose > 1) || (verbose && (rlen > maxlen))) {
        pr2serr("response length %d bytes\n", rlen);
        if (rlen > maxlen)
            pr2serr("  ... which is greater than maxlen (allocation "
                    "length %d), truncation\n", maxlen);
    }
    if (rlen > maxlen)
        rlen = maxlen;
    if (do_raw) {
        dStrRaw((const char *)gpesBuffp, rlen);
        goto fini;
    }
    if (do_hex) {
        hex2stdout(gpesBuffp, rlen, 1);
        goto fini;
    }

#if 0
    if (do_brief > 1) {
        if (rlen < 24) {
            pr2serr("Need maxlen and response length to be at least 24, "
                    "have %d bytes\n", rlen);
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
        res = decode_lba_status_desc(gpesBuffp + 8, &d_lba, &d_blocks,
                                     &add_status);
        if ((res < 0) || (res > 15)) {
            pr2serr("first LBA status descriptor returned %d ??\n", res);
            ret = SG_LIB_LOGIC_ERROR;
            goto fini;
        }
        if ((lba < d_lba) || (lba >= (d_lba + d_blocks))) {
            pr2serr("given LBA not in range of first descriptor:\n"
                    "  descriptor LBA: 0x");
            for (j = 0; j < 8; ++j)
                pr2serr("%02x", gpesBuffp[8 + j]);
            pr2serr("  blocks: 0x%x  p_status: %d  add_status: 0x%x\n",
                    (unsigned int)d_blocks, res,
                    (unsigned int)add_status);
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
        printf("%d\n", res);
        goto fini;
    }
#endif

    printf("Number of descriptors: %u\n", num_desc);
    printf("Number of descriptors returned: %u\n", num_desc_ret);
    printf("Identifier of element being depopulated: %u\n", id_elem_depop);
    if (rlen < 64) {
        printf("No complete physical element status descriptors available\n");
        goto fini;
    } else
        printf("\n");

    for (bp = gpesBuffp + GPES_DESC_OFFSET, k = 0; k < (int)num_desc_ret;
         bp += GPES_DESC_LEN, ++k) {
        if (0 == k)
            printf("Element descriptors:\n");
        decode_elem_status_desc(bp, &a_ped);
        if (do_brief) {
            printf("0x");
            for (j = 0; j < 8; ++j)
                printf("%02x", bp[j]);
            printf("  0x%x  %d\n", (unsigned int)d_blocks, res);
        } else {
            printf("[%d] identifier: 0x%06x", k + 1, a_ped.elem_id);
            if (sg_all_ffs((const uint8_t *)&a_ped.assoc_cap, 8))
                printf("  associated LBs: not specified  ");
            else
                printf("  associated LBs: 0x%" PRIx64 "  ", a_ped.assoc_cap);
            printf("health: ");
            j = a_ped.phys_elem_health;
            if  (0 == j)
                printf("not reported");
            else if (j < 0x64)
                printf("within manufacturer's specification limits <%d>", j);
            else if (0x64 == j)
                printf("at manufacturer's specification limits <%d>", j);
            else if (j < 0xd0)
                printf("outside manufacturer's specification limits <%d>", j);
            else if (j < 0xfd)
                printf("reserved [0x%x]", j);
            else if (0xfd == j)
                printf("depopulation completed, errors detected");
            else if (0xfe == j)
                printf("depopulation operations in progress");
            else if (0xff == j)
                printf("depopulation completed, no errors");
            if (a_ped.restore_allowed)
                printf(" [restore allowed]");
            printf("\n");
        }
    }
    goto fini;

error:
    if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("Get LBA Status command not supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        pr2serr("Get LBA Status command: bad field in cdb\n");
    else {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Get LBA Status command: %s\n", b);
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
    if (free_gpesBuffp)
        free(free_gpesBuffp);
    if ((0 == verbose) && (! no_final_msg)) {
        if (! sg_if_can2stderr("sg_get_elem_status failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
