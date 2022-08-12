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
 * This program issues the SCSI REPORT DENSITY SUPPORT command to the given
 * SCSI (tape) device and outputs the response. Based on ssc5r06.pdf
 */

static const char * version_str = "1.00 20220120";

#define MAX_RDS_BUFF_LEN (64 * 1024 - 1)
#define DEF_RDS_BUFF_LEN 4096

#define REPORT_DENSITY_SUPPORT_CMD 0x44
#define REPORT_DENSITY_SUPPORT_CMDLEN 10

#define RDS_DENSITY_DESC_LEN 52
#define RDS_MEDIUM_T_DESC_LEN 56

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

static const char * rds_s = "Report density support";


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"in", required_argument, 0, 'i'},      /* silent, same as --inhex= */
        {"inhex", required_argument, 0, 'i'},
        {"maxlen", required_argument, 0, 'm'},
        {"media", no_argument, 0, 'M'}, /* Media field; byte 1, bit 0 */
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"typem", no_argument, 0, 't'}, /* Medium type field, byte 1, bit 1 */
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage(void)
{
    pr2serr("Usage: "
            "sg_rep_density  [--help] [--hex] [--inhex=FN] [--maxlen=LEN] "
            "[--media]\n"
            "                   [--raw] [--readonly] [--typem] [--verbose] "
            "[--version]\n"
            "                   DEVICE\n");
    pr2serr("  where:\n"
            "    --help|-h          prints out this usage message\n"
            "    --hex|-H           output response in hexadecimal "
            "(default); used\n"
            "                       twice: hex without addresses at start "
            "of line\n"
            "    --inhex=FN         decode contents of FN, ignore DEVICE\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 512 bytes)\n"
            "    --media|-M         report on media in drive (def: report "
            "on drive)\n"
            "    --raw|-r           output response in binary\n"
            "    --readonly|-R      open DEVICE read-only (def: read-write)\n"
            "    --typem|-t         report medium types (def: density "
            "codes)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Sends a SCSI REPORT DENSITY SUPPORT command outputs the "
            "response in\nASCII hexadecimal or binary. By default it reports "
            "on density codes supported\nby the drive (LU).\n");
}

/* Invokes a SCSI REPORT PROVISIONING INITIALIZATION PATTERN command (SBC).
 * Return of 0 -> success, various SG_LIB_CAT_* positive values or
 * -1 -> other errors */
static int
sg_ll_report_density(int sg_fd, bool media, bool m_type, void * resp,
                     int mx_resp_len, int * residp, bool noisy, int verbose)
{
    int ret, res, sense_cat;
    uint8_t rds_cdb[REPORT_DENSITY_SUPPORT_CMDLEN] =
          {REPORT_DENSITY_SUPPORT_CMD, 0, 0, 0,  0, 0, 0, 0,  0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    struct sg_pt_base * ptvp;

    if (media)
        rds_cdb[1] |= 0x1;
    if (m_type)
        rds_cdb[1] |= 0x2;
    sg_put_unaligned_be16((uint16_t)mx_resp_len, rds_cdb + 7);
    if (verbose) {
        char b[128];

        pr2serr("    %s cdb: %s\n", rds_s,
                sg_get_command_str(rds_cdb, REPORT_DENSITY_SUPPORT_CMDLEN,
                                   false, sizeof(b), b));
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rds_cdb, sizeof(rds_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, rds_s, res, noisy, verbose, &sense_cat);
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
    if (residp)
        *residp = get_scsi_pt_resid(ptvp);
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static void
decode_medium_type(const uint8_t * up, int num_desc)
{
    int k, j, n, q;

    for (k = 0; k < num_desc; ++k, up += RDS_MEDIUM_T_DESC_LEN) {
        if (0 == k)
            printf("Medium type descriptor%s\n", ((num_desc > 1) ? "s" : ""));
        printf("  descriptor %d\n", k + 1);
        printf("    Medium type: %u\n", up[0]);
        n = up[4];
        printf("    Number of density codes: %d\n", n);
        if (n > 9)
            n = 9;
        for (j = 0; j < n; ++j) {
            q = up[5 + j];
            if (q > 0)
                printf("      Primary density code: %d\n", q);
        }
        printf("    Media width: %u\n", sg_get_unaligned_be16(up + 14));
        printf("    Medium length: %u\n", sg_get_unaligned_be16(up + 16));
        printf("    Assigning organization: %.8s\n", (const char *)(up + 20));
        printf("    Medium type name: %.8s\n", (const char *)(up + 28));
        printf("    Description: %.20s\n", (const char *)(up + 36));
    }
}

static void
decode_density_code(const uint8_t * up, int num_desc)
{
    int k;

    for (k = 0; k < num_desc; ++k, up += RDS_DENSITY_DESC_LEN) {
        if (0 == k)
            printf("Density support data block descriptor%s\n",
                   ((num_desc > 1) ? "s" : ""));
        printf("  descriptor %d\n", k + 1);
        printf("    Primary density code: %u\n", up[0]);
        printf("    Secondary density code: %u\n", up[1]);
        printf("    WRT: %u\n", !!(0x80 & up[2]));
        printf("    DUP: %u\n", !!(0x40 & up[2]));
        printf("    DEFLT: %u\n", !!(0x20 & up[2]));
        printf("    DLV: %u\n", !!(0x1 & up[2]));
        printf("    Bits per mm: %u\n", sg_get_unaligned_be24(up + 5));
        printf("    Media width: %u\n", sg_get_unaligned_be16(up + 8));
        printf("    Tracks: %u\n", sg_get_unaligned_be16(up + 10));
        printf("    Capacity: %u\n", sg_get_unaligned_be32(up + 12));
        printf("    Assigning organization: %.8s\n", (const char *)(up + 16));
        printf("    Density name: %.8s\n", (const char *)(up + 24));
        printf("    Description: %.20s\n", (const char *)(up + 32));
    }
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
    bool media = false;
    bool m_type = false;
    bool no_final_msg = false;
    bool o_readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c, rlen, desc_len, ads_len, num_desc;
    int resid = 0;
    int sg_fd = -1;
    int do_help = 0;
    int do_hex = 0;
    int maxlen = 0;
    int in_len = 0;
    int ret = 0;
    int verbose = 0;
    const char * device_name = NULL;
    const char * inhex_fn = NULL;
    uint8_t * rdsBuff = NULL;
    uint8_t * free_rds = NULL;
    char b[80];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHi:m:MrRtvV", long_options,
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
        case 'i':
            inhex_fn = optarg;
            break;
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MAX_RDS_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MAX_RDS_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'M':
            media = true;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
            break;
        case 't':
            m_type = true;
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
    if (device_name && inhex_fn) {
        pr2serr("ignoring DEVICE, best to give DEVICE or --inhex=FN, but "
                "not both\n");
        device_name = NULL;
    }
    if (0 == maxlen)
        maxlen = DEF_RDS_BUFF_LEN;
    rdsBuff = (uint8_t *)sg_memalign(maxlen, 0, &free_rds, verbose > 3);
    if (NULL == rdsBuff) {
        pr2serr("unable to sg_memalign %d bytes\n", maxlen);
        return sg_convert_errno(ENOMEM);
    }
    if (NULL == device_name) {
        if (inhex_fn) {
            if ((ret = sg_f2hex_arr(inhex_fn, do_raw, false, rdsBuff,
                                    &in_len, maxlen))) {
                if (SG_LIB_LBA_OUT_OF_RANGE == ret) {
                    no_final_msg = true;
                    pr2serr("... decode what we have, --maxlen=%d needs to "
                            "be increased\n", maxlen);
                } else
                    goto the_end;
            }
            if (verbose > 2)
                pr2serr("Read %d [0x%x] bytes of user supplied data\n",
                        in_len, in_len);
            if (do_raw)
                do_raw = false;    /* otherwise interferes with decoding */
            if (in_len < 4) {
                pr2serr("--inhex=%s only decoded %d bytes (needs 4 at "
                        "least)\n", inhex_fn, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
                goto the_end;
            }
            res = 0;
            maxlen = in_len;
            goto start_response;
        } else {
            pr2serr("missing device name!\n\n");
            usage();
            ret = SG_LIB_FILE_ERROR;
            no_final_msg = true;
            goto the_end;
        }
    } else
        in_len = 0;

    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            no_final_msg = true;
            goto the_end;
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

    res = sg_ll_report_density(sg_fd, media, m_type, rdsBuff, maxlen, &resid,
                               true, verbose);
start_response:
    ret = res;
    if (0 == res) {
        rlen = maxlen - resid;
        if (rlen < 4) {
            pr2serr("Response length (%d) too short\n", rlen);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        if (do_raw) {
            dStrRaw(rdsBuff, rlen);
            goto the_end;
        }
        if (do_hex) {
            if (2 != do_hex)
                hex2stdout(rdsBuff, rlen, ((1 == do_hex) ? 1 : -1));
            else
                hex2stdout(rdsBuff, rlen, 0);
            goto the_end;
        }
        desc_len = m_type ? RDS_MEDIUM_T_DESC_LEN : RDS_DENSITY_DESC_LEN;
        ads_len = sg_get_unaligned_be16(rdsBuff + 0) + 2;
        if (4 == ads_len)
            goto the_end;
        if (ads_len < 4) {
            pr2serr("Badly formatted response, ads_len=%d\n", ads_len - 2);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        if (ads_len > rlen) {
            if (verbose)
                pr2serr("Trimming response from %d to %d bytes\n", ads_len,
                        rlen);
            ads_len = rlen;
            if (4 == ads_len)
                goto the_end;
        }
        num_desc = (ads_len - 4) / desc_len;
        if (0 != ((ads_len - 4) % desc_len)) {
            if (verbose)
                pr2serr("Truncating response to %d descriptors\n", num_desc);
        }
        if (m_type)
            decode_medium_type(rdsBuff + 4, num_desc);
        else
            decode_density_code(rdsBuff + 4, num_desc);
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("%s command not supported\n", rds_s);
    else {
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("%s command: %s\n", rds_s, b);
    }

the_end:
    if (free_rds)
        free(free_rds);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if ((0 == verbose) && (! no_final_msg)) {
        if (! sg_if_can2stderr("sg_rep_density failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
