/*
 * Copyright (c) 2014-2021 Douglas Gilbert.
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
 * This program issues the SCSI REPORT ZONES, REPORT ZONE DOMAINS or REPORT
 * REALMS command to the given SCSI device and decodes the response.
 * Based on zbc2r10.pdf
 */

static const char * version_str = "1.28 20210922";

#define MAX_RZONES_BUFF_LEN (1024 * 1024)
#define DEF_RZONES_BUFF_LEN (1024 * 8)

#define SG_ZONING_IN_CMDLEN 16

#define REPORT_ZONES_SA 0x0
#define REPORT_ZONE_DOMAINS_SA 0x7
#define REPORT_REALMS_SA 0x6

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

struct opts_t {
    bool do_force;
    bool do_partial;
    bool do_raw;
    bool do_realms;
    bool do_zdomains;
    bool maxlen_given;
    bool o_readonly;
    bool verbose_given;
    bool version_given;
    bool wp_only;
    int do_help;
    int do_hex;
    int do_num;
    int maxlen;
    int reporting_opt;
    int vb;
    uint64_t st_lba;
    const char * in_fn;
};


static struct option long_options[] = {
        {"domain", no_argument, 0, 'd'},
        {"domains", no_argument, 0, 'd'},
        {"force", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"in", required_argument, 0, 'i'},      /* silent, same as --inhex= */
        {"inhex", required_argument, 0, 'i'},
        {"locator", required_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"num", required_argument, 0, 'n'},
        {"partial", no_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"realm", no_argument, 0, 'e'},
        {"realms", no_argument, 0, 'e'},
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
            "sg_rep_zones  [--domain] [--help] [--hex] [--inhex=FN]\n"
            "                     [--locator=LBA] [--maxlen=LEN] "
            "[--partial] [--raw]\n"
            "                     [--readonly] [--realm] [--report=OPT] "
            "[--start=LBA]\n"
            "                     [--verbose] [--version] DEVICE\n");
    pr2serr("  where:\n"
            "    --domain|-d        sends a REPORT ZONE DOMAINS command\n"
            "    --help|-h          print out usage message, use twice for "
            "more help\n"
            "    --hex|-H           output response in hexadecimal; used "
            "twice\n"
            "                       shows decoded values in hex\n"
            "    --inhex=FN|-i FN    decode contents of FN, ignore DEVICE\n"
            "    --locator=LBA|-l LBA    similar to --start= option\n"
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
            "    --realm|-e         sends a REPORT REALMS command\n"
            "    --report=OPT|-o OP    reporting options (def: 0: all "
            "zones)\n"
            "    --start=LBA|-s LBA    report zones from the LBA (def: 0)\n"
            "                          need not be a zone starting LBA\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n"
            "    --wp|-w            output write pointer only\n\n"
            "Sends a SCSI REPORT ZONES, REPORT ZONE DOMAINS or REPORT REALMS "
            "command.\n By default sends a REPORT ZONES command. Give help "
            "option twice\n(e.g. '-hh') to see reporting options "
            "enumerated.\n");
    return;
h_twoormore:
    pr2serr("Reporting options for REPORT ZONES:\n"
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
            "    0x3e   list zones except those with zone type: GAP\n"
            "    0x3f   list zones with a zone condition of NOT WRITE "
            "POINTER\n\n");
    pr2serr("Reporting options for REPORT ZONE DOMAINS:\n"
            "    0x0    list all zone domains\n"
            "    0x1    list all zone domains in which all zones are active\n"
            "    0x2    list all zone domains that contain active zones\n"
            "    0x3    list all zone domains that do not contain any active "
            "zones\n\n");
    pr2serr("Reporting options for REPORT REALMS:\n"
            "    0x0    list all realms\n"
            "    0x1    list all realms that contain active Sequential Or "
            "Before Required zones\n"
            "    0x2    list all realms that contain active Sequential Write "
            "Required zones\n"
            "    0x3    list all realms that contain active Sequential Write "
            "Preferred zones\n");
}

/* Invokes a SCSI REPORT ZONES, REPORT ZONE DOMAINS or REPORT REALMS command
 * (see ZBC and ZBC-2).  Return of 0 -> success, various SG_LIB_CAT_* positive
 * values or -1 -> other errors */
static int
sg_ll_report_zzz(int sg_fd, int serv_act, uint64_t zs_lba, bool partial,
                 int report_opts, void * resp, int mx_resp_len,
                 int * residp, bool noisy, int vb)
{
    int ret, res, sense_cat;
    uint8_t rz_cdb[SG_ZONING_IN_CMDLEN] =
          {SG_ZONING_IN, REPORT_ZONES_SA, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    rz_cdb[1] = serv_act;
    sg_put_unaligned_be64(zs_lba, rz_cdb + 2);
    sg_put_unaligned_be32((uint32_t)mx_resp_len, rz_cdb + 10);
    rz_cdb[14] = report_opts & 0x3f;
    if (partial)
        rz_cdb[14] |= 0x80;
    if (vb) {
        char b[128];

        pr2serr("    %s\n", sg_get_command_str(rz_cdb, SG_ZONING_IN_CMDLEN,
                                               true, sizeof(b), b));
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rz_cdb, sizeof(rz_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, vb);
    ret = sg_cmds_process_resp(ptvp, "report zone/domain/realm", res, noisy,
                               vb, &sense_cat);
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
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
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

static int
decode_rep_zones(const uint8_t * rzBuff, int act_len, uint32_t decod_len,
                 const struct opts_t * op)
{
    uint8_t zt;
    int k, same, zc, zones;
    uint64_t wp;
    const uint8_t * bp;
    char b[80];

    if ((uint32_t)act_len < decod_len) {
        zones = (act_len - 64) / 64;
        if (act_len == op->maxlen) {
            if (op->maxlen_given)
                pr2serr("decode length [%u bytes] may be constrained by "
                        "given --maxlen value, try increasing\n", decod_len);
            else
                pr2serr("perhaps --maxlen=%u needs to be used\n", decod_len);
        } else if (op->in_fn)
            pr2serr("perhaps %s has been truncated\n", op->in_fn);
    } else
        zones = (decod_len - 64) / 64;
    same = rzBuff[4] & 0xf;
    if (! op->wp_only) {
        printf("  Same=%d: %s\n", same, same_desc_arr[same]);
        printf("  Maximum LBA: 0x%" PRIx64 "\n\n",
               sg_get_unaligned_be64(rzBuff + 8));
    }
    if (op->do_num > 0)
            zones = (zones > op->do_num) ? op->do_num : zones;
    if (((uint32_t)act_len < decod_len) && ((zones * 64) + 64 > act_len)) {
        pr2serr("Skip due to truncated response, try using --num= to a "
                "value less than %d\n", zones);
        return SG_LIB_CAT_MALFORMED;
    }
    for (k = 0, bp = rzBuff + 64; k < zones; ++k, bp += 64) {
        if (! op->wp_only)
            printf(" Zone descriptor: %d\n", k);
        if (op->do_hex) {
            hex2stdout(bp, 64, -1);
            continue;
        }
        if (op->wp_only) {
            printf("0x%" PRIx64 "\n", sg_get_unaligned_be64(bp + 24));
            continue;
        }
        zt = bp[0] & 0xf;
        zc = (bp[1] >> 4) & 0xf;
        printf("   Zone type: %s\n", sg_get_zone_type_str(zt, sizeof(b),
               b));
        printf("   Zone condition: %s\n", zone_condition_str(zc, b,
               sizeof(b), op->vb));
        printf("   PUEP: %d\n", !!(bp[1] & 0x4));   /* added in zbc2r07 */
        printf("   Non_seq: %d\n", !!(bp[1] & 0x2));
        printf("   Reset: %d\n", bp[1] & 0x1);
        printf("   Zone Length: 0x%" PRIx64 "\n",
               sg_get_unaligned_be64(bp + 8));
        printf("   Zone start LBA: 0x%" PRIx64 "\n",
               sg_get_unaligned_be64(bp + 16));
        wp = sg_get_unaligned_be64(bp + 24);
        if (sg_all_ffs((const uint8_t *)&wp, sizeof(wp)))
            printf("   Write pointer LBA: -1\n");
        else
            printf("   Write pointer LBA: 0x%" PRIx64 "\n", wp);
    }
    if ((op->do_num == 0) && (! op->wp_only)) {
        if ((64 + (64 * (uint32_t)zones)) < decod_len)
            printf("\n>>> Beware: Zone list truncated, may need another "
                   "call\n");
    }
    return 0;
}

static int
decode_rep_realms(const uint8_t * rzBuff, int act_len,
                  const struct opts_t * op)
{
    uint32_t k, realms_count, derived_realms_count, r_desc_len,
             zdomains_count;
    uint64_t nr_locator;
    const uint8_t * bp;

    if (act_len < 12) {
        pr2serr("need more than 12 bytes to decode, got %u\n", act_len);
        return SG_LIB_CAT_MALFORMED;
    }
    realms_count = sg_get_unaligned_be32(rzBuff + 4);
    r_desc_len = sg_get_unaligned_be32(rzBuff + 8);
    if (act_len < 20)
        nr_locator = sg_get_unaligned_be64(rzBuff + 12);
    else
        nr_locator = 0;
    printf("Realms_count=%u\n", realms_count);
    printf("realms_descriptor_length=%u\n", r_desc_len);
    printf("next_realm_locator=0x%" PRIx64 "\n", nr_locator);
    if ((realms_count < 1) || (act_len < (64 + 16)) || (r_desc_len < 16)) {
        if (op->vb) {
            pr2serr("%s: exiting early because ", __func__);
            if (realms_count < 1)
                pr2serr("realms_count is zero\n");
            else if (r_desc_len < 16)
                pr2serr("realms descriptor length less than 16\n");
            else
                pr2serr("actual_length (%u) too short\n", act_len);
        }
        return 0;
    }
    derived_realms_count = (act_len - 64) / r_desc_len;
    if (derived_realms_count > realms_count) {
        if (op->vb)
            pr2serr("%s: derived_realms_count [%u] > realms_count [%u]\n",
                    __func__, derived_realms_count, realms_count);
    } else if (derived_realms_count < realms_count) {
        if (op->vb)
            pr2serr("%s: derived_realms_count [%u] < realms_count [%u], "
                    "use former\n", __func__, derived_realms_count,
                    realms_count);
        realms_count = derived_realms_count;
    }
    zdomains_count = (r_desc_len - 16) / 16;

    if (op->do_num > 0)
            realms_count = (realms_count > (uint32_t)op->do_num) ?
                                (uint32_t)op->do_num : realms_count;

    for (k = 0, bp = rzBuff + 64; k < realms_count; ++k, bp += r_desc_len) {
        uint32_t j;
        const uint8_t * zp;

        printf(" Realm_id=%u\n", sg_get_unaligned_be32(bp + 0));
        if (op->do_hex) {
            hex2stdout(bp, r_desc_len, -1);
            continue;
        }
        printf("   realm_restrictions=0x%hu\n",
               sg_get_unaligned_be16(bp + 4));
        printf("   active_zone_domain_id=%u\n", (uint32_t)bp[7]);
        for (j = 0, zp = bp + 16; j < zdomains_count; ++j, zp += 16) {
            printf("   zone_domain=%u\n", j);
            printf("     starting_lba=0x%" PRIx64 "\n",
                   sg_get_unaligned_be64(zp + 0));
            printf("     ending_lba=0x%" PRIx64 "\n",
                   sg_get_unaligned_be64(zp + 8));
        }
    }
    return 0;
}

static int
decode_rep_zdomains(const uint8_t * rzBuff, int act_len,
                  const struct opts_t * op)
{
    uint32_t k, zd_len, zd_ret_len, zdoms_sup, zdoms_rep, zd_rep_opts;
    uint32_t num, der_zdoms;
    uint64_t zd_locator;
    const uint8_t * bp;

    if (act_len < 12) {
        pr2serr("need more than 12 bytes to decode, got %u\n", act_len);
        return SG_LIB_CAT_MALFORMED;
    }
    zd_len = sg_get_unaligned_be32(rzBuff + 0);
    zd_ret_len = sg_get_unaligned_be32(rzBuff + 4);
    zdoms_sup = rzBuff[8];
    zdoms_rep = rzBuff[9];
    zd_rep_opts = rzBuff[10];
    if (act_len < 24)
        zd_locator = sg_get_unaligned_be64(rzBuff + 16);
    else
        zd_locator = 0;
    printf("Zone_domains_returned_list_length=%u\n", zd_ret_len);
    printf("Zone_domains_supported=%u\n", zdoms_sup);
    printf("Zone_domains_reported=%u\n", zdoms_rep);
    printf("Reporting_options=0x%x\n", zd_rep_opts);
    printf("Zone_domain_locator=0x%" PRIx64 "\n", zd_locator);

    der_zdoms = zd_len / 96;
    if (op->vb)
        pr2serr("Derived zdomains=%u\n", der_zdoms);
    num = ((der_zdoms < zdoms_rep) ? der_zdoms : zdoms_rep) * 96;
    for (k = 0, bp = rzBuff + 64; k < num; k += 96, bp += 96) {
        printf("   zone_domain=%u\n", bp[0]);
        printf("     zone_count=%" PRIu64 "\n",
               sg_get_unaligned_be64(bp + 16));
        printf("     starting_lba=0x%" PRIx64 "\n",
               sg_get_unaligned_be64(bp + 24));
        printf("     ending_lba=0x%" PRIx64 "\n",
               sg_get_unaligned_be64(bp + 32));
        printf("     zone_domain_zone_type=0x%x\n", bp[40]);
        printf("     VZDZT=%u\n", !!(0x2 & bp[42]));
        printf("     SRB=%u\n", !!(0x1 & bp[42]));
    }
    return 0;
}

int
main(int argc, char * argv[])
{
    bool no_final_msg = false;
    int res, c, act_len, rlen, in_len;
    int sg_fd = -1;
    int resid = 0;
    int ret = 0;
    int serv_act = REPORT_ZONES_SA;
    uint32_t decod_len;
    int64_t ll;
    const char * device_name = NULL;
    uint8_t * rzBuff = NULL;
    uint8_t * free_rzbp = NULL;
    const char * cmd_name = "Report zones";
    char b[80];
    struct opts_t opts;
    struct opts_t * op = &opts;

    memset(&opts, 0, sizeof(opts));
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "defhHi:l:m:n:o:prRs:vVw", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            op->do_zdomains = true;
            serv_act = REPORT_ZONE_DOMAINS_SA;
            break;
        case 'e':
            op->do_realms = true;
            serv_act = REPORT_REALMS_SA;
            break;
        case 'f':
            op->do_force = true;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'H':
            ++op->do_hex;
            break;
       case 'i':
            op->in_fn = optarg;
            break;
        /* case 'l': is under case 's': */
        case 'm':
            op->maxlen = sg_get_num(optarg);
            if ((op->maxlen < 0) || (op->maxlen > MAX_RZONES_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or "
                        "less\n", MAX_RZONES_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->maxlen_given = true;
            break;
        case 'n':
            op->do_num = sg_get_num(optarg);
            if (op->do_num < 0) {
                pr2serr("argument to '--num' should be zero or more\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'o':
           op->reporting_opt = sg_get_num_nomult(optarg);
           if ((op->reporting_opt < 0) || (op->reporting_opt > 63)) {
                pr2serr("bad argument to '--report=OPT', expect 0 to "
                        "63\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            op->do_partial = true;
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'R':
            op->o_readonly = true;
            break;
        case 's':
        case 'l':       /* --locator= and --start= are interchangeable */
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--start=LBA' or '--locator=LBA\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->st_lba = (uint64_t)ll;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->vb;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'w':
            op->wp_only = true;
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
    if (op->verbose_given && op->version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->vb = 0;
    } else if (! op->verbose_given) {
        pr2serr("set '-vv'\n");
        vb = 2;
    } else
        pr2serr("keep verbose=%d\n", vb);
#else
    if (op->verbose_given && op->version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (op->do_help) {
        usage(op->do_help);
        return 0;
    }
    if (op->do_zdomains && op->do_realms) {
        pr2serr("Can't have both --domain and --realm\n");
        return SG_LIB_SYNTAX_ERROR;
    } else if (op->do_zdomains)
        cmd_name = "Report zone domains";
    else if (op->do_realms)
        cmd_name = "Report realms";
    if ((serv_act != REPORT_ZONES_SA) && op->do_partial) {
        pr2serr("Can only use --partial with REPORT ZONES\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (device_name && op->in_fn) {
        pr2serr("ignoring DEVICE, best to give DEVICE or --inhex=FN, but "
                "not both\n");
        device_name = NULL;
    }
    if (0 == op->maxlen)
        op->maxlen = DEF_RZONES_BUFF_LEN;
    rzBuff = (uint8_t *)sg_memalign(op->maxlen, 0, &free_rzbp, op->vb > 3);
    if (NULL == rzBuff) {
        pr2serr("unable to sg_memalign %d bytes\n", op->maxlen);
        return sg_convert_errno(ENOMEM);
    }

    if (NULL == device_name) {
        if (op->in_fn) {
            if ((ret = sg_f2hex_arr(op->in_fn, op->do_raw, false, rzBuff,
                                    &in_len, op->maxlen))) {
                if (SG_LIB_LBA_OUT_OF_RANGE == ret) {
                    no_final_msg = true;
                    pr2serr("... decode what we have, --maxlen=%d needs to "
                            "be increased\n", op->maxlen);
                } else
                    goto the_end;
            }
            if (op->vb > 2)
                pr2serr("Read %d [0x%x] bytes of user supplied data\n",
                        in_len, in_len);
            if (op->do_raw)
                op->do_raw = false;    /* can interfere on decode */
            if (in_len < 4) {
                pr2serr("--inhex=%s only decoded %d bytes (needs 4 at "
                        "least)\n", op->in_fn, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
                goto the_end;
            }
            res = 0;
            goto start_response;
        } else {
            pr2serr("missing device name!\n\n");
            usage(1);
            ret = SG_LIB_FILE_ERROR;
            no_final_msg = true;
            goto the_end;
        }
    }

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, op->o_readonly, op->vb);
    if (sg_fd < 0) {
        if (op->vb)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto the_end;
    }

    res = sg_ll_report_zzz(sg_fd, serv_act, op->st_lba, op->do_partial,
                           op->reporting_opt, rzBuff, op->maxlen, &resid,
                           true, op->vb);
    ret = res;
start_response:
    if (0 == res) {
        rlen = op->in_fn ? in_len : (op->maxlen - resid);
        if (rlen < 4) {
            pr2serr("Decoded response length (%d) too short\n", rlen);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        decod_len = sg_get_unaligned_be32(rzBuff + 0) + 64;
        if (decod_len > MAX_RZONES_BUFF_LEN) {
            if (! op->do_force) {
                pr2serr("decode length [%u bytes] seems wild, use --force "
                        "override\n", decod_len);
                return SG_LIB_CAT_MALFORMED;
            }
        }
        if (decod_len > (uint32_t)rlen) {
            if ((REPORT_ZONES_SA == serv_act) && (! op->do_partial)) {
                printf("%u zones available but only %d zones returned\n",
                       (decod_len - 64) / 64, (rlen - 64) / 64);
                decod_len = rlen;
                act_len = rlen;
            } else {
                pr2serr("decoded response length is %u bytes, but system "
                        "reports %d bytes received??\n", decod_len, rlen);
                if (op->do_force)
                    act_len = rlen;
                else {
                    pr2serr("Exiting, use --force to override\n");
                    ret = SG_LIB_CAT_MALFORMED;
                    goto the_end;
                }
            }
        } else
            act_len = decod_len;
        if (op->do_raw) {
            dStrRaw(rzBuff, act_len);
            goto the_end;
        }
        if (op->do_hex && (2 != op->do_hex)) {
            hex2stdout(rzBuff, act_len, ((1 == op->do_hex) ? 1 : -1));
            goto the_end;
        }
        if (! op->wp_only)
            printf("%s response:\n", cmd_name);
        if (act_len < 64) {
            pr2serr("Zone length [%d] too short (perhaps after truncation\n)",
                    act_len);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        if (REPORT_ZONES_SA == serv_act)
            ret = decode_rep_zones(rzBuff, act_len, decod_len, op);
        else if (op->do_realms)
            ret = decode_rep_realms(rzBuff, act_len, op);
        else if (op->do_zdomains)
            ret = decode_rep_zdomains(rzBuff, act_len, op);
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("%s command not supported\n", cmd_name);
    else {
        sg_get_category_sense_str(res, sizeof(b), b, op->vb);
        pr2serr("%s command: %s\n", cmd_name, b);
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
    if ((0 == op->vb && (! no_final_msg))) {
        if (! sg_if_can2stderr("sg_rep_zones failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
