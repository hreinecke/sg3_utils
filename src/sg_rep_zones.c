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
 * This program issues the SCSI REPORT ZONES command to the given SCSI device
 * and decodes the response. Based on zbc-r02.pdf
 */

static const char * version_str = "1.21 20200220";

#define MAX_RZONES_BUFF_LEN (1024 * 1024)
#define DEF_RZONES_BUFF_LEN (1024 * 8)

#define SG_ZONING_IN_CMDLEN 16

#define REPORT_ZONES_SA 0x0

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"maxlen", required_argument, 0, 'm'},
        {"num", required_argument, 0, 'n'},
        {"partial", no_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"report", required_argument, 0, 'o'},
        {"start", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wp", no_argument, 0, 'w'},
        {0, 0, 0, 0},
};


static void
usage(int h)
{
    if (h > 1) goto h_twoormore;
    pr2serr("Usage: "
            "sg_rep_zones  [--help] [--hex] [--maxlen=LEN] [--partial]\n"
            "                     [--raw] [--readonly] [--report=OPT] "
            "[--start=LBA]\n"
            "                     [--verbose] [--version] DEVICE\n");
    pr2serr("  where:\n"
            "    --help|-h          print out usage message, use twice for "
            "more help\n"
            "    --hex|-H           output response in hexadecimal; used "
            "twice\n"
            "                       shows decoded values in hex\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> 8192 bytes)\n"
            "    --num=NUM|-n NUM    number of zones to output (def: 0 -> "
            "all)\n"
            "    --partial|-p       sets PARTIAL bit in cdb (def: 0 -> "
            "zone list\n"
            "                       length not altered by allocation length "
            "in cdb)\n"
            "    --raw|-r           output response in binary\n"
            "    --readonly|-R      open DEVICE read-only (def: read-write)\n"
            "    --report=OPT|-o OP    reporting options (def: 0: all "
            "zones)\n"
            "    --start=LBA|-s LBA    report zones from the LBA (def: 0)\n"
            "                          need not be a zone starting LBA\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n"
            "    --wp|-w            output write pointer only\n\n"
            "Sends a SCSI REPORT ZONES command and decodes the response. "
            "Give\nhelp option twice (e.g. '-hh') to see reporting options "
            "enumerated.\n");
    return;
h_twoormore:
    pr2serr("Reporting options:\n"
            "    0x0    list all zones\n"
            "    0x1    list zones with a zone condition of EMPTY\n"
            "    0x2    list zones with a zone condition of IMPLICITLY "
            "OPENED\n"
            "    0x3    list zones with a zone condition of EXPLICITLY "
            "OPENED\n"
            "    0x4    list zones with a zone condition of CLOSED\n"
            "    0x5    list zones with a zone condition of FULL\n"
            "    0x6    list zones with a zone condition of READ ONLY\n"
            "    0x7    list zones with a zone condition of OFFLINE\n"
            "    0x8    list zones with a zone condition of INACTIVE\n"
            "    0x10   list zones with RWP Recommended set to true\n"
            "    0x11   list zones with Non-sequential write resources "
            "active set to true\n"
            "    0x3f   list zones with a zone condition of NOT WRITE "
            "POINTER\n");
}

/* Invokes a SCSI REPORT ZONES command (ZBC).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_report_zones(int sg_fd, uint64_t zs_lba, bool partial, int report_opts,
                   void * resp, int mx_resp_len, int * residp, bool noisy,
                   int verbose)
{
    int ret, res, sense_cat;
    uint8_t rz_cdb[SG_ZONING_IN_CMDLEN] =
          {SG_ZONING_IN, REPORT_ZONES_SA, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be64(zs_lba, rz_cdb + 2);
    sg_put_unaligned_be32((uint32_t)mx_resp_len, rz_cdb + 10);
    rz_cdb[14] = report_opts & 0x3f;
    if (partial)
        rz_cdb[14] |= 0x80;
    if (verbose) {
        char b[128];

        pr2serr("    Report zones cdb: %s\n",
                sg_get_command_str(rz_cdb, SG_ZONING_IN_CMDLEN, false,
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
    ret = sg_cmds_process_resp(ptvp, "report zones", res, noisy, verbose,
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

static const char *
zone_type_str(int zt, char * b, int blen, int vb)
{
    const char * cp;

    if (NULL == b)
        return "zone_type_str: NULL ptr)";
    switch (zt) {
    case 1:
        cp = "Conventional";
        break;
    case 2:
        cp = "Sequential write required";
        break;
    case 3:
        cp = "Sequential write preferred";
        break;
    case 4:
        cp = "Sequential or before required";
        break;
    case 5:
        cp = "Gap";
        break;
    default:
        cp = NULL;
        break;
    }
    if (cp) {
        if (vb)
            snprintf(b, blen, "%s [0x%x]", cp, zt);
        else
            snprintf(b, blen, "%s", cp);
    } else
        snprintf(b, blen, "Reserved [0x%x]", zt);
    return b;
}

static const char *
zone_condition_str(int zc, char * b, int blen, int vb)
{
    const char * cp;

    if (NULL == b)
        return "zone_condition_str: NULL ptr)";
    switch (zc) {
    case 0:
        cp = "Not write pointer";
        break;
    case 1:
        cp = "Empty";
        break;
    case 2:
        cp = "Implicitly opened";
        break;
    case 3:
        cp = "Explicitly opened";
        break;
    case 4:
        cp = "Closed";
        break;
    case 5:
        cp = "Inactive";
        break;
    case 0xd:
        cp = "Read only";
        break;
    case 0xe:
        cp = "Full";
        break;
    case 0xf:
        cp = "Offline";
        break;
    default:
        cp = NULL;
        break;
    }
    if (cp) {
        if (vb)
            snprintf(b, blen, "%s [0x%x]", cp, zc);
        else
            snprintf(b, blen, "%s", cp);
    } else
        snprintf(b, blen, "Reserved [0x%x]", zc);
    return b;
}

static const char * same_desc_arr[16] = {
    "zone type and length may differ in each descriptor",
    "zone type and length same in each descriptor",
    "zone type and length same apart from length in last descriptor",
    "zone type for each descriptor may be different",
    "Reserved [0x4]", "Reserved [0x5]", "Reserved [0x6]", "Reserved [0x7]",
    "Reserved [0x8]", "Reserved [0x9]", "Reserved [0xa]", "Reserved [0xb]",
    "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};


int
main(int argc, char * argv[])
{
    bool do_partial = false;
    bool do_raw = false;
    bool o_readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    bool wp_only = false;
    int k, res, c, zl_len, len, zones, resid, rlen, zt, zc, same;
    int sg_fd = -1;
    int do_help = 0;
    int do_hex = 0;
    int do_num = 0;
    int maxlen = 0;
    int reporting_opt = 0;
    int ret = 0;
    int verbose = 0;
    uint64_t st_lba = 0;
    int64_t ll;
    const char * device_name = NULL;
    uint8_t * reportZonesBuff = NULL;
    uint8_t * free_rzbp = NULL;
    uint8_t * bp;
    char b[80];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHm:n:o:prRs:vVw", long_options,
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
            if ((maxlen < 0) || (maxlen > MAX_RZONES_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or "
                        "less\n", MAX_RZONES_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'n':
            do_num = sg_get_num(optarg);
            if (do_num < 0) {
                pr2serr("argument to '--num' should be zero or more\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'o':
           reporting_opt = sg_get_num_nomult(optarg);
           if ((reporting_opt < 0) || (reporting_opt > 63)) {
                pr2serr("bad argument to '--report=OPT', expect 0 to "
                        "63\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            do_partial = true;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
            break;
        case 's':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--start=LBA'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            st_lba = (uint64_t)ll;
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
        case 'w':
            wp_only = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage(1);
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
            usage(1);
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
        usage(do_help);
        return 0;
    }
    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage(1);
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
        maxlen = DEF_RZONES_BUFF_LEN;
    reportZonesBuff = (uint8_t *)sg_memalign(maxlen, 0, &free_rzbp,
                                             verbose > 3);
    if (NULL == reportZonesBuff) {
        pr2serr("unable to sg_memalign %d bytes\n", maxlen);
        return sg_convert_errno(ENOMEM);
    }

    res = sg_ll_report_zones(sg_fd, st_lba, do_partial, reporting_opt,
                             reportZonesBuff, maxlen, &resid, true, verbose);
    ret = res;
    if (0 == res) {
        rlen = maxlen - resid;
        if (rlen < 4) {
            pr2serr("Response length (%d) too short\n", rlen);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        zl_len = sg_get_unaligned_be32(reportZonesBuff + 0) + 64;
        if (zl_len > rlen) {
            if (verbose)
                pr2serr("zl_len available is %d, response length is %d\n",
                        zl_len, rlen);
            len = rlen;
        } else
            len = zl_len;
        if (do_raw) {
            dStrRaw(reportZonesBuff, len);
            goto the_end;
        }
        if (do_hex && (2 != do_hex)) {
            hex2stdout(reportZonesBuff, len,
                    ((1 == do_hex) ? 1 : -1));
            goto the_end;
        }
        if (! wp_only)
            printf("Report zones response:\n");
        if (len < 64) {
            pr2serr("Zone length [%d] too short (perhaps after truncation\n)",
                    len);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        same = reportZonesBuff[4] & 0xf;
        if (! wp_only) {
            printf("  Same=%d: %s\n", same, same_desc_arr[same]);
            printf("  Maximum LBA: 0x%" PRIx64 "\n\n",
                   sg_get_unaligned_be64(reportZonesBuff + 8));
        }
        zones = (len - 64) / 64;
        if (do_num > 0)
                zones = (zones > do_num) ? do_num : zones;
        for (k = 0, bp = reportZonesBuff + 64; k < zones; ++k, bp += 64) {
            if (! wp_only)
                printf(" Zone descriptor: %d\n", k);
            if (do_hex) {
                hex2stdout(bp, len, -1);
                continue;
            }
            if (wp_only) {
                printf("0x%" PRIx64 "\n", sg_get_unaligned_be64(bp + 24));
                continue;
            }
            zt = bp[0] & 0xf;
            zc = (bp[1] >> 4) & 0xf;
            printf("   Zone type: %s\n", zone_type_str(zt, b, sizeof(b),
                   verbose));
            printf("   Zone condition: %s\n", zone_condition_str(zc, b,
                   sizeof(b), verbose));
            printf("   Non_seq: %d\n", !!(bp[1] & 0x2));
            printf("   Reset: %d\n", bp[1] & 0x1);
            printf("   Zone Length: 0x%" PRIx64 "\n",
                   sg_get_unaligned_be64(bp + 8));
            printf("   Zone start LBA: 0x%" PRIx64 "\n",
                   sg_get_unaligned_be64(bp + 16));
            printf("   Write pointer LBA: 0x%" PRIx64 "\n",
                   sg_get_unaligned_be64(bp + 24));
        }
        if ((do_num == 0) && (! wp_only)) {
            if ((64 + (64 * zones)) < zl_len)
                printf("\n>>> Beware: Zone list truncated, may need another "
                       "call\n");
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("Report zones command not supported\n");
    else {
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Report zones command: %s\n", b);
    }

the_end:
    if (free_rzbp)
        free(free_rzbp);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_rep_zones failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
