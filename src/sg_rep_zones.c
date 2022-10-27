/*
 * Copyright (c) 2014-2022 Douglas Gilbert.
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
#include <limits.h>
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
 * Based on zbc2r12.pdf
 */

static const char * version_str = "1.42 20220807";

#define MY_NAME "sg_rep_zones"

#define WILD_RZONES_BUFF_LEN (1 << 28)
#define MAX_RZONES_BUFF_LEN (2 * 1024 * 1024)
#define DEF_RZONES_BUFF_LEN (1024 * 16)
#define RCAP16_REPLY_LEN 32

#define SG_ZONING_IN_CMDLEN 16
#define REPORT_ZONES_DESC_LEN 64
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

/* Three zone service actions supported by this utility */
enum zone_report_sa_e {
    REPORT_ZONES_SA = 0x0,
    REPORT_REALMS_SA = 0x6,
    REPORT_ZONE_DOMAINS_SA = 0x7
};

struct opts_t {
    bool do_brief;
    bool do_force;
    bool do_partial;
    bool do_raw;
    bool do_realms;
    bool do_zdomains;
    bool maxlen_given;
    bool o_readonly;
    bool statistics;
    bool verbose_given;
    bool version_given;
    bool wp_only;
    enum zone_report_sa_e serv_act;
    int do_help;
    int do_hex;
    int do_num;
    int find_zt;        /* negative values: find first not equal to */
    int maxlen;
    int reporting_opt;
    int vb;
    uint64_t st_lba;
    const char * in_fn;
    sgj_state json_st;
};

struct zt_num2abbrev_t {
    int ztn;
    const char * abbrev;
};

static struct option long_options[] = {
        {"brief", no_argument, 0, 'b'}, /* only header and last descriptor */
        {"domain", no_argument, 0, 'd'},
        {"domains", no_argument, 0, 'd'},
        {"force", no_argument, 0, 'f'},
        {"find", required_argument, 0, 'F'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"in", required_argument, 0, 'i'},      /* silent, same as --inhex= */
        {"inhex", required_argument, 0, 'i'},
        {"json", optional_argument, 0, 'j'},
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
        {"statistics", no_argument, 0, 'S'},
        {"stats", no_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wp", no_argument, 0, 'w'},
        {0, 0, 0, 0},
};

/* Zone types */
static struct zt_num2abbrev_t zt_num2abbrev[] = {
    {0, "none"},
    {1, "c"},           /* conventionial */
    {2, "swr"},         /* sequential write required */
    {3, "swp"},         /* sequential write preferred */
    {4, "sobr"},        /* sequential or before required */
    {5, "g"},           /* gap */
    {-1, NULL},         /* sentinel */
};

static const char * zn_dnum_s = "zone descriptor number: ";

static const char * meaning_s = "meaning";


static void
prn_zone_type_abbrevs(void)
{
    const struct zt_num2abbrev_t * n2ap = zt_num2abbrev;
    char b[32];

    pr2serr("Zone type number\tAbbreviation\tName\n");
    pr2serr("----------------\t------------\t----\n");
    for ( ; n2ap->abbrev; ++n2ap) {
        if (n2ap == zt_num2abbrev)
            pr2serr("\t%d\t\t%s\t\t[reserved]\n",
                    n2ap->ztn, n2ap->abbrev);
        else
            pr2serr("\t%d\t\t%s\t\t%s\n", n2ap->ztn, n2ap->abbrev,
                    sg_get_zone_type_str(n2ap->ztn, sizeof(b), b));
    }
}

static void
usage(int h)
{
    if (h > 1) goto h_twoormore;
    pr2serr("Usage: "
            "sg_rep_zones  [--domain] [--find=ZT] [--force] [--help] "
            "[--hex]\n"
            "                     [--inhex=FN] [--json[=JO]] "
            "[--locator=LBA]\n"
            "                     [--maxlen=LEN] [--num=NUM] [--partial] "
            "[--raw]\n"
            "                     [--readonly] [--realm] [--report=OPT] "
            "[--start=LBA]\n"
            "                     [--statistics] [--verbose] [--version] "
            "[--wp]\n"
            "                     DEVICE\n");
    pr2serr("  where:\n"
            "    --domain|-d        sends a REPORT ZONE DOMAINS command\n"
            "    --find=ZT|-F ZT    find first zone with ZT zone type, "
            "starting at LBA\n"
            "                       if first character of ZT is - or !, "
            "find first\n"
            "                       zone that is not ZT\n"
            "    --force|-f         bypass some sanity checks when decoding "
            "response\n"
            "    --help|-h          print out usage message, use twice for "
            "more help\n"
            "    --hex|-H           output response in hexadecimal; used "
            "twice\n"
            "                       shows decoded values in hex\n"
            "    --inhex=FN|-i FN    decode contents of FN, ignore DEVICE\n"
            "    --json[=JO]|-j[JO]    output in JSON instead of human "
            "readable text.\n"
            "                          Use --json=? for JSON help\n"
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
            "    --statistics|-S    gather statistics by reviewing zones\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n"
            "    --wp|-w            output write pointer only\n\n"
            "Sends a SCSI REPORT ZONES, REPORT ZONE DOMAINS or REPORT REALMS "
            "command.\nBy default sends a REPORT ZONES command. Give help "
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
    pr2serr("\n");
    prn_zone_type_abbrevs();
}

/* Invokes a SCSI REPORT ZONES, REPORT ZONE DOMAINS or REPORT REALMS command
 * (see ZBC and ZBC-2).  Return of 0 -> success, various SG_LIB_CAT_* positive
 * values or -1 -> other errors */
static int
sg_ll_report_zzz(int sg_fd, enum zone_report_sa_e serv_act, uint64_t zs_lba,
                 bool partial, int report_opts, void * resp, int mx_resp_len,
                 int * residp, bool noisy, int vb)
{
    int ret, res, sense_cat;
    uint8_t rz_cdb[SG_ZONING_IN_CMDLEN] =
          {SG_ZONING_IN, REPORT_ZONES_SA, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    struct sg_pt_base * ptvp;

    rz_cdb[1] = (uint8_t)serv_act;
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

static uint64_t
prt_a_zn_desc(const uint8_t *bp, const struct opts_t * op,
              sgj_state * jsp, sgj_opaque_p jop)
{
    uint8_t zt, zc;
    uint64_t lba, len, wp;
    char b[80];

    jop = jop ? jop : jsp->basep;
    zt = bp[0] & 0xf;
    zc = (bp[1] >> 4) & 0xf;
    sg_get_zone_type_str(zt, sizeof(b), b);
    sgj_pr_hr(jsp, "   Zone type: %s\n", b);
    sgj_js_nv_istr(jsp, jop, "zone_type", zt, meaning_s, b);
    zone_condition_str(zc, b, sizeof(b), op->vb);
    sgj_pr_hr(jsp, "   Zone condition: %s\n", b);
    sgj_js_nv_istr(jsp, jop, "zone_condition", zc, meaning_s, b);
    sgj_haj_vi(jsp, jop, 3, "PUEP", SGJ_SEP_COLON_1_SPACE,
               !!(bp[1] & 0x4), false);
    sgj_haj_vi(jsp, jop, 3, "NON_SEQ", SGJ_SEP_COLON_1_SPACE,
               !!(bp[1] & 0x2), false);
    sgj_haj_vi(jsp, jop, 3, "RESET", SGJ_SEP_COLON_1_SPACE,
               !!(bp[1] & 0x1), false);
    len = sg_get_unaligned_be64(bp + 8);
    sgj_pr_hr(jsp, "   Zone Length: 0x%" PRIx64 "\n", len);
    sgj_js_nv_ihex(jsp, jop, "zone_length", (int64_t)len);
    lba = sg_get_unaligned_be64(bp + 16);
    sgj_pr_hr(jsp, "   Zone start LBA: 0x%" PRIx64 "\n", lba);
    sgj_js_nv_ihex(jsp, jop, "zone_start_lba", (int64_t)lba);
    wp = sg_get_unaligned_be64(bp + 24);
    if (sg_all_ffs((const uint8_t *)&wp, sizeof(wp)))
        sgj_pr_hr(jsp, "   Write pointer LBA: -1\n");
    else
        sgj_pr_hr(jsp, "   Write pointer LBA: 0x%" PRIx64 "\n", wp);
    sgj_js_nv_ihex(jsp, jop, "write_pointer_lba", (int64_t)wp);
    return lba + len;
}

static int
decode_rep_zones(const uint8_t * rzBuff, int act_len, uint32_t decod_len,
                 const struct opts_t * op, sgj_state * jsp)
{
    bool as_json = jsp ? jsp->pr_as_json : false;
    int k, same, num_zd;
    uint64_t wp, ul, mx_lba;
    sgj_opaque_p jop = jsp ? jsp->basep : NULL;
    sgj_opaque_p jap = NULL;
    const uint8_t * bp;

    if ((uint32_t)act_len < decod_len) {
        num_zd = (act_len >= 64) ? ((act_len - 64) / REPORT_ZONES_DESC_LEN)
                                 : 0;
        if (act_len == op->maxlen) {
            if (op->maxlen_given)
                pr2serr("decode length [%u bytes] may be constrained by "
                        "given --maxlen value, try increasing\n", decod_len);
            else
                pr2serr("perhaps --maxlen=%u needs to be used\n", decod_len);
        } else if (op->in_fn)
            pr2serr("perhaps %s has been truncated\n", op->in_fn);
    } else
        num_zd = (decod_len - 64) / REPORT_ZONES_DESC_LEN;
    same = rzBuff[4] & 0xf;
    mx_lba = sg_get_unaligned_be64(rzBuff + 8);
    if (op->wp_only) {
        ;
    } else if (op->do_hex) {
        hex2stdout(rzBuff, 64, -1);
        printf("\n");
    } else {
        uint64_t rzslbag = sg_get_unaligned_be64(rzBuff + 16);
        static const char * rzslbag_s = "Reported zone starting LBA "
                                        "granularity";

        sgj_pr_hr(jsp, "  Same=%d: %s\n", same, same_desc_arr[same]);
        sgj_js_nv_istr(jsp, jop, "same", same, meaning_s,
                       same_desc_arr[same]);
        sgj_pr_hr(jsp, "  Maximum LBA: 0x%" PRIx64 "\n\n", mx_lba);
        sgj_js_nv_ihex(jsp, jop, "maximum_lba", mx_lba);
        sgj_pr_hr(jsp, "  %s: 0x%" PRIx64 "\n\n", rzslbag_s, rzslbag);
        sgj_js_nv_ihex(jsp, jop, rzslbag_s, rzslbag);
    }
    if (op->do_num > 0)
            num_zd = (num_zd > op->do_num) ? op->do_num : num_zd;
    if (((uint32_t)act_len < decod_len) &&
        ((num_zd * REPORT_ZONES_DESC_LEN) + 64 > act_len)) {
        pr2serr("Skip due to truncated response, try using --num= to a "
                "value less than %d\n", num_zd);
        return SG_LIB_CAT_MALFORMED;
    }
    if (op->do_brief && (num_zd > 0)) {
        bp = rzBuff + 64 + ((num_zd - 1) * REPORT_ZONES_DESC_LEN);
        if (op->do_hex) {
            if (op->wp_only)
                hex2stdout(bp + 24, 8, -1);
            else
                hex2stdout(bp, 64, -1);
            return 0;
        }
        sgj_pr_hr(jsp, "From last descriptor in this response:\n");
        sgj_pr_hr(jsp, " %s%d\n", zn_dnum_s, num_zd - 1);
        sgj_js_nv_i(jsp, jop, "zone_descriptor_index", num_zd - 1);
        ul = prt_a_zn_desc(bp, op, jsp, jop);
        if (ul > mx_lba)
            sgj_pr_hr(jsp, "   >> This zone seems to be the last one\n");
        else
            sgj_pr_hr(jsp, "   >> Probable next Zone start LBA: 0x%" PRIx64
                      "\n", ul);
        return 0;
    }
    if (as_json)
        jap = sgj_named_subarray_r(jsp, NULL, "zone_descriptors_list");
    for (k = 0, bp = rzBuff + 64; k < num_zd;
         ++k, bp += REPORT_ZONES_DESC_LEN) {
        sgj_opaque_p jo2p;

        if (! op->wp_only)
             sgj_pr_hr(jsp, " %s%d\n", zn_dnum_s, k);
        if (op->do_hex) {
            hex2stdout(bp, 64, -1);
            continue;
        }
        if (op->wp_only) {
            if (op->do_hex)
                hex2stdout(bp + 24, 8, -1);
            else {
                wp = sg_get_unaligned_be64(bp + 24);
                if (sg_all_ffs((const uint8_t *)&wp, sizeof(wp)))
                    sgj_pr_hr(jsp, "-1\n");
                else
                    sgj_pr_hr(jsp, "0x%" PRIx64 "\n", wp);
                jo2p = sgj_new_unattached_object_r(jsp);
                sgj_js_nv_ihex(jsp, jo2p, "write_pointer_lba", (int64_t)wp);
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
            continue;
        }
        jo2p = sgj_new_unattached_object_r(jsp);
        prt_a_zn_desc(bp, op, jsp, jo2p);
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    if ((op->do_num == 0) && (! op->wp_only) && (! op->do_hex)) {
        if ((64 + (REPORT_ZONES_DESC_LEN * (uint32_t)num_zd)) < decod_len)
            sgj_pr_hr(jsp, "\n>>> Beware: Zone list truncated, may need "
                      "another call\n");
    }
    return 0;
}

static int
decode_rep_realms(const uint8_t * rzBuff, int act_len,
                  const struct opts_t * op, sgj_state * jsp)
{
    uint32_t k, realms_count, derived_realms_count, r_desc_len,
             zdomains_count;
    uint64_t nr_locator;
    const uint8_t * bp;
    sgj_opaque_p jop = jsp ? jsp->basep : NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;

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
    sgj_haj_vi(jsp, jop, 0, "Realms_count", SGJ_SEP_EQUAL_NO_SPACE,
               realms_count, true);
    sgj_haj_vi(jsp, jop, 0, "Realms_descriptor_length",
               SGJ_SEP_EQUAL_NO_SPACE, r_desc_len, true);
    sgj_pr_hr(jsp, "Next_realm_locator=0x%" PRIx64 "\n", nr_locator);
    sgj_js_nv_ihex(jsp, jop, "Next_realm_locator", nr_locator);
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
    jap = sgj_named_subarray_r(jsp, jop, "realm_descriptors_list");

    for (k = 0, bp = rzBuff + 64; k < realms_count; ++k, bp += r_desc_len) {
        uint32_t j;
        uint16_t restrictions;
        const uint8_t * zp;
        sgj_opaque_p jo2p;

        jo2p = sgj_new_unattached_object_r(jsp);
        sgj_haj_vi(jsp, jo2p, 1, "Realms_id", SGJ_SEP_EQUAL_NO_SPACE,
                   sg_get_unaligned_be32(bp + 0), true);
        if (op->do_hex) {
            hex2stdout(bp, r_desc_len, -1);
            continue;
        }
        restrictions = sg_get_unaligned_be16(bp + 4);
        sgj_pr_hr(jsp, "   realm_restrictions=0x%hu\n", restrictions);
        sgj_js_nv_ihex(jsp, jo2p, "realm_restrictions", restrictions);
        sgj_haj_vi(jsp, jo2p, 3, "active_zone_domain_id",
                   SGJ_SEP_EQUAL_NO_SPACE, bp[7], true);

        ja2p = sgj_named_subarray_r(jsp, jo2p,
                                    "realm_start_end_descriptors_list");
        for (j = 0, zp = bp + 16; j < zdomains_count; ++j, zp += 16) {
            uint64_t lba;
            sgj_opaque_p jo3p;

            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_pr_hr(jsp, "   zone_domain=%u\n", j);
            sgj_js_nv_i(jsp, jo3p, "corresponding_zone_domain_id", j);
            lba = sg_get_unaligned_be64(zp + 0);
            sgj_pr_hr(jsp, "     starting_lba=0x%" PRIx64 "\n", lba);
            sgj_js_nv_ihex(jsp, jo3p, "realm_starting_lba", (int64_t)lba);
            lba = sg_get_unaligned_be64(zp + 8);
            sgj_pr_hr(jsp, "     ending_lba=0x%" PRIx64 "\n", lba);
            sgj_js_nv_ihex(jsp, jo3p, "realm_ending_lba", (int64_t)lba);
            sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
        }
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    return 0;
}

static int
decode_rep_zdomains(const uint8_t * rzBuff, int act_len,
                   const struct opts_t * op, sgj_state * jsp)
{
    uint32_t k, zd_len, zd_ret_len, zdoms_sup, zdoms_rep, zd_rep_opts;
    uint32_t num, der_zdoms;
    uint64_t zd_locator;
    sgj_opaque_p jop = jsp ? jsp->basep : NULL;
    sgj_opaque_p jap = NULL;
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
    sgj_haj_vi(jsp, jop, 0, "Zone_domains_returned_list_length=",
               SGJ_SEP_EQUAL_NO_SPACE, zd_ret_len, true);
    sgj_haj_vi(jsp, jop, 0, "Zone_domains_supported",
               SGJ_SEP_EQUAL_NO_SPACE, zdoms_sup, true);
    sgj_haj_vi(jsp, jop, 0, "Zone_domains_reported",
               SGJ_SEP_EQUAL_NO_SPACE, zdoms_rep, true);
    sgj_pr_hr(jsp, "Reporting_options=0x%x\n", zd_rep_opts);
    sgj_js_nv_ihex(jsp, jop, "Reporting_options", zd_rep_opts);
    sgj_pr_hr(jsp, "Zone_domain_locator=0x%" PRIx64 "\n", zd_locator);
    sgj_js_nv_ihex(jsp, jop, "Zone_domain_locator", zd_locator);

    der_zdoms = zd_len / 96;
    if (op->vb > 1)
        pr2serr("Derived zdomains=%u\n", der_zdoms);
    num = ((der_zdoms < zdoms_rep) ? der_zdoms : zdoms_rep) * 96;
    jap = sgj_named_subarray_r(jsp, jop, "zone_domain_descriptors_list");

    for (k = 0, bp = rzBuff + 64; k < num; k += 96, bp += 96) {
        uint64_t lba;
        sgj_opaque_p jo2p;

        jo2p = sgj_new_unattached_object_r(jsp);
        sgj_haj_vi(jsp, jo2p, 3, "zone_domain",
                   SGJ_SEP_EQUAL_NO_SPACE, bp[0], true);
        lba = sg_get_unaligned_be64(bp + 16);
        sgj_pr_hr(jsp, "     zone_count=%" PRIu64 "\n", lba);
        sgj_js_nv_ihex(jsp, jo2p, "zone_count", lba);
        lba = sg_get_unaligned_be64(bp + 24);
        sgj_pr_hr(jsp, "     starting_lba=0x%" PRIx64 "\n", lba);
        sgj_js_nv_ihex(jsp, jo2p, "starting_lba", lba);
        lba = sg_get_unaligned_be64(bp + 32);
        sgj_pr_hr(jsp, "     ending_lba=0x%" PRIx64 "\n", lba);
        sgj_js_nv_ihex(jsp, jo2p, "ending_lba", lba);
        sgj_pr_hr(jsp, "     zone_domain_zone_type=0x%x\n", bp[40]);
        sgj_js_nv_ihex(jsp, jo2p, "zone_domain_zone_type", bp[40]);
        sgj_haj_vi(jsp, jo2p, 5, "VZDZT", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(0x2 & bp[42]), false);
        sgj_haj_vi(jsp, jo2p, 5, "SRB", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(0x1 & bp[42]), false);
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    return 0;
}

static int
find_report_zones(int sg_fd, uint8_t * rzBuff, const char * cmd_name,
                  struct opts_t * op, sgj_state * jsp)
{
    bool as_json = (jsp && (0 == op->do_hex)) ?  jsp->pr_as_json : false;
    bool found = false;
    uint8_t zt;
    int k, res, resid, rlen, num_zd, num_rem;
    uint32_t zn_dnum = 0;
    uint64_t slba = op->st_lba;
    uint64_t mx_lba = 0;
    const uint8_t * bp = rzBuff;
    char b[96];

    num_rem = op->do_num ? op->do_num : INT_MAX;
    for ( ; num_rem > 0; num_rem -= num_zd) {
        resid = 0;
        if (sg_fd >= 0) {
            res = sg_ll_report_zzz(sg_fd, REPORT_ZONES_SA, slba,
                                   true /* set partial */, op->reporting_opt,
                                   rzBuff, op->maxlen, &resid, true, op->vb);
            if (res) {
                if (SG_LIB_CAT_INVALID_OP == res)
                    pr2serr("%s: %s%u, %s command not supported\n", __func__,
                            zn_dnum_s, zn_dnum, cmd_name);
                else {
                    sg_get_category_sense_str(res, sizeof(b), b, op->vb);
                    pr2serr("%s: %s%u, %s command: %s\n", __func__,
                            zn_dnum_s, zn_dnum, cmd_name, b);
                }
                break;
            }
        } else
            res = 0;
        rlen = op->maxlen - resid;
        if (rlen <= 64)
            break;
        mx_lba = sg_get_unaligned_be64(rzBuff + 8);
        num_zd = (rlen - 64) / REPORT_ZONES_DESC_LEN;
        if (num_zd > num_rem)
            num_zd = num_rem;
        for (k = 0, bp = rzBuff + 64; k < num_zd;
             ++k, bp += REPORT_ZONES_DESC_LEN, ++zn_dnum) {
            zt = 0xf & bp[0];
            if (op->find_zt > 0) {
                if ((uint8_t)op->find_zt == zt )
                    break;
            } else if (op->find_zt < 0) {
                if ((uint8_t)(-op->find_zt) != zt )
                    break;
            }
            slba = sg_get_unaligned_be64(bp + 16) +
                   sg_get_unaligned_be64(bp + 8);
        }
        if (k < num_zd) {
            found = true;
            break;
        } else if ((slba > mx_lba) || (sg_fd < 0))
            break;
    }           /* end of outer for loop */
    if (res == 0) {
        sgj_opaque_p jo2p = as_json ?
                sgj_named_subobject_r(jsp, NULL, "find_condition") : NULL;

        if (found) {
            if (op->do_hex) {
                hex2stdout(rzBuff, 64, -1);
                printf("\n");
                hex2stdout(bp, 64, -1);
            } else {
                sgj_pr_hr(jsp, "Condition met at:\n");
                sgj_pr_hr(jsp, " %s: %d\n", zn_dnum_s, zn_dnum);
                sgj_js_nv_b(jsp, jo2p, "met", true);
                sgj_js_nv_i(jsp, jo2p, "zone_descriptor_index", zn_dnum);
                prt_a_zn_desc(bp, op, jsp, jo2p);
            }
        } else {
            if (op->do_hex) {
                memset(b, 0xff, 64);
                hex2stdout((const uint8_t *)b, 64, -1);
            } else {
                sgj_js_nv_b(jsp, jo2p, "met", false);
                sgj_js_nv_i(jsp, jo2p, "zone_descriptor_index", zn_dnum);
                if (num_rem < 1)
                    sgj_pr_hr(jsp, "Condition NOT met, checked %d zones; "
                              "next %s%u\n", op->do_num, zn_dnum_s, zn_dnum);
                else
                    sgj_pr_hr(jsp, "Condition NOT met; next %s%u\n",
                              zn_dnum_s, zn_dnum);
            }
        }
    }
    return res;
}

struct statistics_t {
    uint32_t zt_conv_num;
    uint32_t zt_swr_num;
    uint32_t zt_swp_num;
    uint32_t zt_sob_num;
    uint32_t zt_gap_num;
    uint32_t zt_unk_num;

    uint32_t zc_nwp_num;
    uint32_t zc_mt_num;
    uint32_t zc_iop_num;
    uint32_t zc_eop_num;
    uint32_t zc_cl_num;
    uint32_t zc_ina_num;
    uint32_t zc_ro_num;
    uint32_t zc_full_num;
    uint32_t zc_off_num;
    uint32_t zc_unk_num;

    /* The following LBAs have 1 added to them, initialized to 0 */
    uint64_t zt_swr_1st_lba1;
    uint64_t zt_swp_1st_lba1;
    uint64_t zt_sob_1st_lba1;
    uint64_t zt_gap_1st_lba1;

    uint64_t zc_nwp_1st_lba1;
    uint64_t zc_mt_1st_lba1;
    uint64_t zc_iop_1st_lba1;
    uint64_t zc_eop_1st_lba1;
    uint64_t zc_cl_1st_lba1;
    uint64_t zc_ina_1st_lba1;
    uint64_t zc_ro_1st_lba1;
    uint64_t zc_full_1st_lba1;
    uint64_t zc_off_1st_lba1;

    uint64_t wp_max_lba1;       /* ... that isn't Zone start LBA */
    uint64_t wp_blk_num;        /* sum of (zwp - zs_lba) */
    uint64_t conv_blk_num;      /* sum of (z_blks) of zt=conv */
};

static int
gather_statistics(int sg_fd, uint8_t * rzBuff, const char * cmd_name,
                  struct opts_t * op)
{
    uint8_t zt, zc;
    int k, res, resid, rlen, num_zd, num_rem;
    uint32_t zn_dnum = 0;
    uint64_t slba = op->st_lba;
    uint64_t mx_lba = 0;
    uint64_t zs_lba, zwp, z_blks;
    const uint8_t * bp = rzBuff;
    struct statistics_t st SG_C_CPP_ZERO_INIT;
    char b[96];

    if (op->serv_act != REPORT_ZONES_SA) {
        pr2serr("%s: do not support statistics for %s yet\n", __func__,
                cmd_name);
        return SG_LIB_SYNTAX_ERROR;
    }

    num_rem = op->do_num ? op->do_num : INT_MAX;
    for ( ; num_rem > 0; num_rem -= num_zd) {
        resid = 0;
        zs_lba = slba;
        if (sg_fd >= 0) {
            res = sg_ll_report_zzz(sg_fd, REPORT_ZONES_SA, slba,
                                   true /* set partial */, op->reporting_opt,
                                   rzBuff, op->maxlen, &resid, true, op->vb);
            if (res) {
                if (SG_LIB_CAT_INVALID_OP == res)
                    pr2serr("%s: %s%u, %s command not supported\n", __func__,
                            zn_dnum_s, zn_dnum, cmd_name);
                else {
                    sg_get_category_sense_str(res, sizeof(b), b, op->vb);
                    pr2serr("%s: %s%u, %s command: %s\n", __func__,
                            zn_dnum_s, zn_dnum, cmd_name, b);
                }
                break;
            }
        } else
            res = 0;
        rlen = op->maxlen - resid;
        if (rlen <= 64) {
            break;
        }
        mx_lba = sg_get_unaligned_be64(rzBuff + 8);
        num_zd = (rlen - 64) / REPORT_ZONES_DESC_LEN;
        if (num_zd > num_rem)
            num_zd = num_rem;
        for (k = 0, bp = rzBuff + 64; k < num_zd;
             ++k, bp += REPORT_ZONES_DESC_LEN, ++zn_dnum) {
            z_blks = sg_get_unaligned_be64(bp + 8);
            zs_lba = sg_get_unaligned_be64(bp + 16);
            zwp = sg_get_unaligned_be64(bp + 24);
            zt = 0xf & bp[0];
            switch (zt) {
            case 1:     /* conventional */
                ++st.zt_conv_num;
                st.conv_blk_num += z_blks;
                break;
            case 2:     /* sequential write required */
                ++st.zt_swr_num;
                if (0 == st.zt_swr_1st_lba1)
                    st.zt_swr_1st_lba1 = zs_lba + 1;
                break;
            case 3:     /* sequential write preferred */
                ++st.zt_swp_num;
                if (0 == st.zt_swp_1st_lba1)
                    st.zt_swp_1st_lba1 = zs_lba + 1;
                break;
            case 4:     /* sequential or before (write) */
                ++st.zt_sob_num;
                if (0 == st.zt_sob_1st_lba1)
                    st.zt_sob_1st_lba1 = zs_lba + 1;
                break;
            case 5:     /* gap */
                ++st.zt_gap_num;
                if (0 == st.zt_gap_1st_lba1)
                    st.zt_gap_1st_lba1 = zs_lba + 1;
                break;
            default:
                ++st.zt_unk_num;
                break;
            }
            zc = (bp[1] >> 4) & 0xf;
            switch (zc) {
            case 0:     /* not write pointer (zone) */
                ++st.zc_nwp_num;
                if (0 == st.zc_nwp_1st_lba1)
                    st.zc_nwp_1st_lba1 = zs_lba + 1;
                break;
            case 1:     /* empty */
                ++st.zc_mt_num;
                if (0 == st.zc_mt_1st_lba1)
                    st.zc_mt_1st_lba1 = zs_lba + 1;
                break;
            case 2:     /* implicitly opened */
                ++st.zc_iop_num;
                if (0 == st.zc_iop_1st_lba1)
                    st.zc_iop_1st_lba1 = zs_lba + 1;
                if (zwp > zs_lba) {
                    st.wp_max_lba1 = zwp + 1;
                    st.wp_blk_num += zwp - zs_lba;
                }
                break;
            case 3:     /* explicitly opened */
                ++st.zc_eop_num;
                if (0 == st.zc_eop_1st_lba1)
                    st.zc_eop_1st_lba1 = zs_lba + 1;
                if (zwp > zs_lba) {
                    st.wp_max_lba1 = zwp + 1;
                    st.wp_blk_num += zwp - zs_lba;
                }
                break;
            case 4:     /* closed */
                ++st.zc_cl_num;
                if (0 == st.zc_cl_1st_lba1)
                    st.zc_cl_1st_lba1 = zs_lba + 1;
                if (zwp > zs_lba) {
                    st.wp_max_lba1 = zwp + 1;
                    st.wp_blk_num += zwp - zs_lba;
                }
                break;
            case 5:     /* inactive */
                ++st.zc_ina_num;
                if (0 == st.zc_ina_1st_lba1)
                    st.zc_ina_1st_lba1 = zs_lba + 1;
                break;
            case 0xd:   /* read-only */
                ++st.zc_ro_num;
                if (0 == st.zc_ro_1st_lba1)
                    st.zc_ro_1st_lba1 = zs_lba + 1;
                break;
            case 0xe:   /* full */
                ++st.zc_full_num;
                if (0 == st.zc_full_1st_lba1)
                    st.zc_full_1st_lba1 = zs_lba + 1;
                st.wp_blk_num += z_blks;
                break;
            case 0xf:   /* offline */
                ++st.zc_off_num;
                if (0 == st.zc_off_1st_lba1)
                    st.zc_off_1st_lba1 = zs_lba + 1;
                break;
            default:
                ++st.zc_unk_num;
                break;
            }
            slba = zs_lba + z_blks;
        }       /* end of inner for loop */
        if ((slba > mx_lba) || (sg_fd < 0))
            break;
    }           /* end of outer for loop */
    printf("Number of conventional type zones: %u\n", st.zt_conv_num);
    if (st.zt_swr_num > 0)
        printf("Number of sequential write required type zones: %u\n",
               st.zt_swr_num);
    if (st.zt_swr_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zt_swr_1st_lba1 - 1);
    if (st.zt_swp_num > 0)
        printf("Number of sequential write preferred type zones: %u\n",
               st.zt_swp_num);
    if (st.zt_swp_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zt_swp_1st_lba1 - 1);
    if (st.zt_sob_num > 0)
        printf("Number of sequential or before type zones: %u\n",
               st.zt_sob_num);
    if (st.zt_sob_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zt_sob_1st_lba1 - 1);
    if (st.zt_gap_num > 0)
        printf("Number of gap type zones: %u\n", st.zt_gap_num);
    if (st.zt_gap_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zt_gap_1st_lba1 - 1);
    if (st.zt_unk_num > 0)
        printf("Number of unknown type zones: %u\n", st.zt_unk_num);

    printf("Number of 'not write pointer' condition zones: %u\n",
           st.zc_nwp_num);
    if (st.zc_nwp_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_nwp_1st_lba1 - 1);
    printf("Number of empty condition zones: %u\n", st.zc_mt_num);
    if (st.zc_mt_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_mt_1st_lba1 - 1);
    if (st.zc_iop_num > 0)
        printf("Number of implicitly open condition zones: %u\n",
               st.zc_iop_num);
    if (st.zc_iop_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_iop_1st_lba1 - 1);
    if (st.zc_eop_num)
        printf("Number of explicitly open condition zones: %u\n",
               st.zc_eop_num);
    if (st.zc_eop_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_eop_1st_lba1 - 1);
    if (st.zc_cl_num)
        printf("Number of closed condition zones: %u\n", st.zc_cl_num);
    if (st.zc_cl_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_cl_1st_lba1 - 1);
    if (st.zc_ina_num)
        printf("Number of inactive condition zones: %u\n", st.zc_ina_num);
    if (st.zc_ina_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_ina_1st_lba1 - 1);
    if (st.zc_ro_num)
        printf("Number of inactive condition zones: %u\n", st.zc_ro_num);
    if (st.zc_ro_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_ro_1st_lba1 - 1);
    if (st.zc_full_num)
        printf("Number of full condition zones: %u\n", st.zc_full_num);
    if (st.zc_full_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_full_1st_lba1 - 1);
    if (st.zc_off_num)
        printf("Number of offline condition zones: %u\n", st.zc_off_num);
    if (st.zc_off_1st_lba1 > 0)
        printf("    Lowest starting LBA: 0x%" PRIx64 "\n",
              st.zc_off_1st_lba1 - 1);
    if (st.zc_unk_num > 0)
        printf("Number of unknown condition zones: %u\n", st.zc_unk_num);

    if (st.wp_max_lba1 > 0)
        printf("Highest active write pointer LBA: 0x%" PRIx64 "\n",
              st.wp_max_lba1 - 1);
    printf("Number of used blocks in write pointer zones: 0x%" PRIx64 "\n",
           st.wp_blk_num);

    if ((sg_fd >= 0) && (op->maxlen >= RCAP16_REPLY_LEN) &&
        ((st.wp_blk_num > 0) || (st.conv_blk_num > 0))) {
        uint32_t block_size = 0;
        uint64_t total_sz;
        double sz_mb, sz_gb;

        res = sg_ll_readcap_16(sg_fd, false, 0, rzBuff,
                               RCAP16_REPLY_LEN, true, op->vb);
        if (SG_LIB_CAT_INVALID_OP == res) {
            pr2serr("READ CAPACITY (16) cdb not supported\n");
        } else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            pr2serr("bad field in READ CAPACITY (16) cdb including "
                    "unsupported service action\n");
        else if (res) {
            sg_get_category_sense_str(res, sizeof(b), b, op->vb);
            pr2serr("READ CAPACITY (16) failed: %s\n", b);
        } else
            block_size = sg_get_unaligned_be32(rzBuff + 8);

        if (st.wp_blk_num) {
            total_sz = st.wp_blk_num * block_size;
            sz_mb = (double)(total_sz) / (double)(1048576);
            sz_gb = (double)(total_sz) / (double)(1000000000L);
#ifdef SG_LIB_MINGW
            printf("   associated size: %" PRIu64 " bytes, %g MiB, %g GB",
                   total_sz, sz_mb, sz_gb);
#else
            printf("   associated size: %" PRIu64 " bytes, %.1f MiB, %.2f "
                   "GB", total_sz, sz_mb, sz_gb);
#endif
            if (sz_gb > 2000) {
#ifdef SG_LIB_MINGW
                printf(", %g TB", sz_gb / 1000);
#else
                printf(", %.2f TB", sz_gb / 1000);
#endif
            }
            printf("\n");
        }
        if (st.conv_blk_num) {
            total_sz = st.conv_blk_num * block_size;
            sz_mb = (double)(total_sz) / (double)(1048576);
            sz_gb = (double)(total_sz) / (double)(1000000000L);
            printf("Size of all conventional zones: ");
#ifdef SG_LIB_MINGW
            printf("%" PRIu64 " bytes, %g MiB, %g GB", total_sz, sz_mb,
                   sz_gb);
#else
            printf("%" PRIu64 " bytes, %.1f MiB, %.2f GB", total_sz,
                   sz_mb, sz_gb);
#endif
            if (sz_gb > 2000) {
#ifdef SG_LIB_MINGW
                printf(", %g TB", sz_gb / 1000);
#else
                printf(", %.2f TB", sz_gb / 1000);
#endif
            }
            printf("\n");
        }
    }
    return res;
}


int
main(int argc, char * argv[])
{
    bool no_final_msg = false;
    bool as_json;
    int res, c, act_len, rlen, in_len, off;
    int sg_fd = -1;
    int resid = 0;
    int ret = 0;
    uint32_t decod_len;
    int64_t ll;
    const char * device_name = NULL;
    uint8_t * rzBuff = NULL;
    uint8_t * free_rzbp = NULL;
    const char * cmd_name = "Report zones";
    sgj_state * jsp;
    sgj_opaque_p jop = NULL;
    char b[80];
    struct opts_t opts SG_C_CPP_ZERO_INIT;
    struct opts_t * op = &opts;

    op->serv_act = REPORT_ZONES_SA;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "bdefF:hHi:j::l:m:n:o:prRs:SvVw",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            op->do_brief = true;
            break;
        case 'd':
            op->do_zdomains = true;
            op->serv_act = REPORT_ZONE_DOMAINS_SA;
            break;
        case 'e':
            op->do_realms = true;
            op->serv_act = REPORT_REALMS_SA;
            break;
        case 'f':
            op->do_force = true;
            break;
        case 'F':
            off = (('-' == *optarg) || ('!' == *optarg)) ? 1 : 0;
            if (isdigit(*(optarg + off))) {
                op->find_zt = sg_get_num_nomult(optarg + off);
                if (op->find_zt < 0) {
                    pr2serr("bad numeric argument to '--find='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                if (off)
                    op->find_zt = -op->find_zt; /* find first not equal */
            } else {    /* check for abbreviation */
                struct zt_num2abbrev_t * zn2ap = zt_num2abbrev;

                for ( ; zn2ap->abbrev; ++zn2ap) {
                    if (0 == strcmp(optarg + off, zn2ap->abbrev))
                        break;
                }
                if (NULL == zn2ap->abbrev) {
                    pr2serr("bad abbreviation argument to '--find='\n\n");
                    prn_zone_type_abbrevs();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->find_zt = off ? -zn2ap->ztn : zn2ap->ztn;
            }
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
       case 'j':
            if (! sgj_init_state(&op->json_st, optarg)) {
                int bad_char = op->json_st.first_bad_char;
                char e[1500];

                if (bad_char) {
                    pr2serr("bad argument to --json= option, unrecognized "
                            "character '%c'\n\n", bad_char);
                }
                sg_json_usage(0, e, sizeof(e));
                pr2serr("%s", e);
                return SG_LIB_SYNTAX_ERROR;
            }
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
        if ((2 == strlen(optarg)) && (0 == memcmp("-1", optarg, 2))) {
                op->st_lba = UINT64_MAX;
                break;
            }
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--start=LBA' or '--locator=LBA\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->st_lba = (uint64_t)ll;
            break;
        case 'S':
            op->statistics = true;
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
        op->vb = 2;
    } else
        pr2serr("keep verbose=%d\n", op->vb);
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
    as_json = op->json_st.pr_as_json;
    jsp = &op->json_st;
    if (as_json)
        jop = sgj_start_r(MY_NAME, version_str, argc, argv, jsp);

    if (op->do_zdomains && op->do_realms) {
        pr2serr("Can't have both --domain and --realm\n");
        return SG_LIB_SYNTAX_ERROR;
    } else if (op->do_zdomains)
        cmd_name = "Report zone domains";
    else if (op->do_realms)
        cmd_name = "Report realms";
    if (as_json)
        sgj_js_nv_s(jsp, jop, "scsi_command_name", cmd_name);
    if ((op->serv_act != REPORT_ZONES_SA) && op->do_partial) {
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
            if (op->find_zt) {  /* so '-F none' will drop through */
                op->maxlen = in_len;
                ret = find_report_zones(sg_fd, rzBuff, cmd_name, op, jsp);
                goto the_end;
            } else if (op->statistics) {
                op->maxlen = in_len;
                ret = gather_statistics(sg_fd, rzBuff, cmd_name, op);
                goto the_end;
            }
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
            ret = SG_LIB_FILE_ERROR;
            goto the_end;
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

    if (op->find_zt) {  /* so '-F none' will drop through */
        ret = find_report_zones(sg_fd, rzBuff, cmd_name, op, jsp);
        goto the_end;
    } else if (op->statistics) {
        ret = gather_statistics(sg_fd, rzBuff, cmd_name, op);
        goto the_end;
    }
    res = sg_ll_report_zzz(sg_fd, op->serv_act, op->st_lba, op->do_partial,
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
        if (decod_len > WILD_RZONES_BUFF_LEN) {
            if (! op->do_force) {
                pr2serr("decode length [%u bytes] seems wild, use --force "
                        "override\n", decod_len);
                ret = SG_LIB_CAT_MALFORMED;
                goto the_end;
            }
        }
        if (decod_len > (uint32_t)rlen) {
            if ((REPORT_ZONES_SA == op->serv_act) && (! op->do_partial)) {
                pr2serr("%u zones starting from LBA 0x%" PRIx64 " available "
                        "but only %d zones returned\n",
                        (decod_len - 64) / REPORT_ZONES_DESC_LEN, op->st_lba,
                        (rlen - 64) / REPORT_ZONES_DESC_LEN);
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
        if (! op->wp_only && (! op->do_hex))
            sgj_pr_hr(jsp, "%s response:\n", cmd_name);

        if (act_len < 64) {
            pr2serr("Zone length [%d] too short (perhaps after truncation\n)",
                    act_len);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        if (REPORT_ZONES_SA == op->serv_act)
            ret = decode_rep_zones(rzBuff, act_len, decod_len, op, jsp);
        else if (op->do_realms)
            ret = decode_rep_realms(rzBuff, act_len, op, jsp);
        else if (op->do_zdomains)
            ret = decode_rep_zdomains(rzBuff, act_len, op, jsp);
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
    ret = (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
    if (as_json) {
        if (0 == op->do_hex)
            sgj_js2file(jsp, NULL, ret, stdout);
        sgj_finish(jsp);
    }
    return ret;
}
