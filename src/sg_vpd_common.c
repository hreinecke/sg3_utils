/*
 * Copyright (c) 2006-2022 Douglas Gilbert.
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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

#include "sg_vpd_common.h"

/* This file holds common code for sg_inq and sg_vpd as both those utilities
 * decode SCSI VPD pages. */

const char * t10_vendor_id_hr = "T10_vendor_identification";
const char * t10_vendor_id_js = "t10_vendor_identification";
const char * product_id_hr = "Product_identification";
const char * product_id_js = "product_identification";
const char * product_rev_lev_hr = "Product_revision_level";
const char * product_rev_lev_js = "product_revision_level";
static const char * const nl_s = "no limit";
static const char * const nlr_s = "no limit reported";
static const char * const nr_s = "not reported";
static const char * const ns_s = "not supported";
static const char * const rsv_s = "Reserved";
static const char * const vs_s = "Vendor specific";
static const char * const null_s = "";
static const char * const mn_s = "meaning";

sgj_opaque_p
sg_vpd_js_hdr(sgj_state * jsp, sgj_opaque_p jop, const char * name,
              const uint8_t * vpd_hdrp)
{
    int pdt = vpd_hdrp[0] & PDT_MASK;
    int pqual = (vpd_hdrp[0] & 0xe0) >> 5;
    int pn = vpd_hdrp[1];
    const char * pdt_str;
    sgj_opaque_p jo2p = sgj_snake_named_subobject_r(jsp, jop, name);
    char d[64];

    pdt_str = sg_get_pdt_str(pdt, sizeof(d), d);
    sgj_js_nv_ihexstr(jsp, jo2p, "peripheral_qualifier",
                      pqual, NULL, pqual_str(pqual));
    sgj_js_nv_ihexstr(jsp, jo2p, "peripheral_device_type",
                      pdt, NULL, pdt_str);
    sgj_js_nv_ihex(jsp, jo2p, "page_code", pn);
    return jo2p;
}

const char *
pqual_str(int pqual)
{
    switch (pqual) {
    case 0:
        return "LU accessible";
    case 1:
        return "LU temporarily unavailable";
    case 3:
        return "LU not accessible via this port";
    default:
        return "value reserved by T10";
    }
}

static const char * network_service_type_arr[] =
{
    "unspecified",
    "storage configuration service",
    "diagnostics",
    "status",
    "logging",
    "code download",
    "copy service",
    "administrative configuration service",
    "reserved[0x8]", "reserved[0x9]",
    "reserved[0xa]", "reserved[0xb]", "reserved[0xc]", "reserved[0xd]",
    "reserved[0xe]", "reserved[0xf]", "reserved[0x10]", "reserved[0x11]",
    "reserved[0x12]", "reserved[0x13]", "reserved[0x14]", "reserved[0x15]",
    "reserved[0x16]", "reserved[0x17]", "reserved[0x18]", "reserved[0x19]",
    "reserved[0x1a]", "reserved[0x1b]", "reserved[0x1c]", "reserved[0x1d]",
    "reserved[0x1e]", "reserved[0x1f]",
};

/* VPD_MAN_NET_ADDR     0x85 ["mna"] */
void
decode_net_man_vpd(uint8_t * buff, int len, struct opts_t * op,
                   sgj_opaque_p jap)
{
    int k, bump, na_len, assoc, nst;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    uint8_t * bp;
    const char * assoc_str;
    const char * nst_str;

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Management network addresses VPD page length too short=%d\n",
                len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        assoc = (bp[0] >> 5) & 0x3;
        assoc_str = sg_get_desig_assoc_str(assoc);
        nst = bp[0] & 0x1f;
        nst_str = network_service_type_arr[nst];
        sgj_pr_hr(jsp, "  %s, Service type: %s\n", assoc_str, nst_str);
        na_len = sg_get_unaligned_be16(bp + 2);
        if (jsp->pr_as_json) {
            jo2p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihexstr(jsp, jo2p, "association", assoc, NULL,
                              assoc_str);
            sgj_js_nv_ihexstr(jsp, jo2p, "service_type", nst, NULL,
                              nst_str);
            sgj_js_nv_s_len(jsp, jo2p, "network_address",
                            (const char *)(bp + 4), na_len);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
        if (na_len > 0) {
            if (op->do_hex > 1) {
                sgj_pr_hr(jsp, "    Network address:\n");
                hex2stdout((bp + 4), na_len, 0);
            } else
                sgj_pr_hr(jsp, "    %s\n", bp + 4);
        }
        bump = 4 + na_len;
        if ((k + bump) > len) {
            pr2serr("Management network addresses VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
    }
}

/* VPD_EXT_INQ    Extended Inquiry VPD ["ei"] */
void
decode_x_inq_vpd(uint8_t * b, int len, bool protect, struct opts_t * op,
                 sgj_opaque_p jop)
{
    bool do_long_nq = op->do_long && (! op->do_quiet);
    int n;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    const char * cp;
    const char * np;
    const char * nex_p;
    char d[128];
    static const int dlen = sizeof(d);

    if (len < 7) {
        pr2serr("Extended INQUIRY data VPD page length too short=%d\n", len);
        return;
    }
    if (op->do_hex) {
        hex2stdout(b, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (do_long_nq || jsp->pr_as_json) {
        n = (b[4] >> 6) & 0x3;
        if (1 == n)
            cp = "before final WRITE BUFFER";
        else if (2 == n)
            cp = "after power on or hard reset";
        else {
            cp = "none";
            d[0] = '\0';
        }
        if (cp[0])
            snprintf(d, dlen, " [%s]", cp);
        sgj_pr_hr(jsp, "  ACTIVATE_MICROCODE=%d%s\n", n, d);
        sgj_js_nv_ihexstr(jsp, jop, "activate_microcode", n, NULL, cp);
        n = (b[4] >> 3) & 0x7;
        if (protect) {
            switch (n)
            {
            case 0:
                cp = "protection type 1 supported";
                break;
            case 1:
                cp = "protection types 1 and 2 supported";
                break;
            case 2:
                cp = "protection type 2 supported";
                break;
            case 3:
                cp = "protection types 1 and 3 supported";
                break;
            case 4:
                cp = "protection type 3 supported";
                break;
            case 5:
                cp = "protection types 2 and 3 supported";
                break;
            case 6:
                cp = "see Supported block lengths and protection types "
                     "VPD page";
                break;
            case 7:
                cp = "protection types 1, 2 and 3 supported";
                break;
            }
        } else {
            cp = "none";
            d[0] = '\0';
        }
        if (cp[0])
            snprintf(d, dlen, " [%s]", cp);
        sgj_pr_hr(jsp, "  SPT=%d%s\n", n, d);
        sgj_js_nv_ihexstr_nex(jsp, jop, "spt", n, false, NULL,
                              cp, "Supported Protection Type");
        sgj_hr_js_vi_nex(jsp, jop, 2, "GRD_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[4] & 0x4), false, "guard check");
        sgj_hr_js_vi_nex(jsp, jop, 2, "APP_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[4] & 0x2), false, "application tag check");
        sgj_hr_js_vi_nex(jsp, jop, 2, "REF_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[4] & 0x1), false, "reference tag check");
        sgj_hr_js_vi_nex(jsp, jop, 2, "UASK_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[5] & 0x20), false, "Unit Attention "
                         "condition Sense Key specific data Supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "GROUP_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[5] & 0x10), false, "grouping function "
                         "supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "PRIOR_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[5] & 0x8), false, "priority supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "HEADSUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[5] & 0x4), false, "head of queue supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "ORDSUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[5] & 0x2), false, "ordered (task attribute) "
                         "supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "SIMPSUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[5] & 0x1), false, "simple (task attribute) "
                         "supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "WU_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[6] & 0x8), false, "Write uncorrectable "
                         "supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "CRD_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[6] & 0x4), false, "Correction disable "
                         "supported (obsolete SPC-5)");
        sgj_hr_js_vi_nex(jsp, jop, 2, "NV_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[6] & 0x2), false, "Nonvolatile cache "
                         "supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "V_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[6] & 0x1), false, "Volatile cache supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "NO_PI_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[7] & 0x20), false, "No protection "
                         "information checking");        /* spc5r02 */
        sgj_hr_js_vi_nex(jsp, jop, 2, "P_I_I_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[7] & 0x10), false, "Protection information "
                         "interval supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "LUICLR", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[7] & 0x1), false, "Logical unit I_T nexus "
                         "clear");
        np = "LU_COLL_TYPE";
        n = (b[8] >> 5) & 0x7;
        nex_p = "Logical unit collection type";
        if (jsp && (jsp->pr_string)) {
            switch (n) {
            case 0:
                cp = "not reported";
                break;
            case 1:
                cp = "Conglomerate";
                break;
            case 2:
                cp = "Logical unit group";
                break;
            default:
                cp = rsv_s;
                break;
            }
            jo2p = sgj_hr_js_subo_r(jsp, jop, 2, np, SGJ_SEP_EQUAL_NO_SPACE,
                                    n, false);
            sgj_js_nv_s(jsp, jo2p, mn_s, cp);
            if (jsp->pr_name_ex)
                sgj_js_nv_s(jsp, jo2p, "abbreviated_name_expansion", nex_p);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, np, SGJ_SEP_EQUAL_NO_SPACE, n,
                             true, nex_p);

        sgj_hr_js_vi_nex(jsp, jop, 2, "R_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[8] & 0x10), false, "Referrals supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "RTD_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[8] & 0x8), false,
                         "Revert to defaults supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "HSSRELEF", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[8] & 0x2), false,
                         "History snapshots release effects");
        sgj_hr_js_vi_nex(jsp, jop, 2, "CBCS", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[8] & 0x1), false, "Capability-based command "
                         "security (obsolete SPC-5)");
        sgj_hr_js_vi(jsp, jop, 2, "Multi I_T nexus microcode download",
                     SGJ_SEP_EQUAL_NO_SPACE, b[9] & 0xf, true);
        sgj_hr_js_vi(jsp, jop, 2, "Extended self-test completion minutes",
                      SGJ_SEP_EQUAL_NO_SPACE,
                      sg_get_unaligned_be16(b + 10), true);
        sgj_hr_js_vi_nex(jsp, jop, 2, "POA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                          !!(b[12] & 0x80), false,
                          "Power on activation supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "HRA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[12] & 0x40), false,
                         "Hard reset activation supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "VSA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[12] & 0x20), false,
                         "Vendor specific activation supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "DMS_VALID", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[12] & 0x10), false,
                         "Download microcode support byte valid");
        sgj_hr_js_vi(jsp, jop, 2, "Maximum supported sense data length",
                     SGJ_SEP_EQUAL_NO_SPACE, b[13], true);
        sgj_hr_js_vi_nex(jsp, jop, 2, "IBS", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[14] & 0x80), false,
                         "Implicit bind supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "IAS", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[14] & 0x40), false,
                         "Implicit affiliation supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "SAC", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[14] & 0x4), false,
                         "Set affiliation command supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "NRD1", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[14] & 0x2), false,
                         "No redirect one supported (BIND)");
        sgj_hr_js_vi_nex(jsp, jop, 2, "NRD0", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[14] & 0x1), false,
                         "No redirect zero supported (BIND)");
        sgj_hr_js_vi(jsp, jop, 2, "Maximum inquiry change logs",
                     SGJ_SEP_EQUAL_NO_SPACE,
                     sg_get_unaligned_be16(b + 15), true);
        sgj_hr_js_vi(jsp, jop, 2, "Maximum mode page change logs",
                     SGJ_SEP_EQUAL_NO_SPACE,
                     sg_get_unaligned_be16(b + 17), true);
        sgj_hr_js_vi_nex(jsp, jop, 2, "DM_MD_4", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[19] & 0x80), false,
                         "Download microcode mode 4 supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "DM_MD_5", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[19] & 0x40), false,
                         "Download microcode mode 5 supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "DM_MD_6", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[19] & 0x20), false,
                         "Download microcode mode 6 supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "DM_MD_7", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[19] & 0x10), false,
                         "Download microcode mode 7 supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "DM_MD_D", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[19] & 0x8), false,
                         "Download microcode mode 0xd supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "DM_MD_E", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[19] & 0x4), false,
                         "Download microcode mode 0xe supported");
        sgj_hr_js_vi_nex(jsp, jop, 2, "DM_MD_F", SGJ_SEP_EQUAL_NO_SPACE,
                         !!(b[19] & 0x2), false,
                         "Download microcode mode 0xf supported");
        if (do_long_nq || (! jsp->pr_out_hr))
            return;
    }
    sgj_pr_hr(jsp, "  ACTIVATE_MICROCODE=%d SPT=%d GRD_CHK=%d APP_CHK=%d "
              "REF_CHK=%d\n", ((b[4] >> 6) & 0x3), ((b[4] >> 3) & 0x7),
              !!(b[4] & 0x4), !!(b[4] & 0x2), !!(b[4] & 0x1));
    sgj_pr_hr(jsp, "  UASK_SUP=%d GROUP_SUP=%d PRIOR_SUP=%d HEADSUP=%d "
              "ORDSUP=%d SIMPSUP=%d\n", !!(b[5] & 0x20), !!(b[5] & 0x10),
              !!(b[5] & 0x8), !!(b[5] & 0x4), !!(b[5] & 0x2), !!(b[5] & 0x1));
    sgj_pr_hr(jsp, "  WU_SUP=%d [CRD_SUP=%d] NV_SUP=%d V_SUP=%d\n",
              !!(b[6] & 0x8), !!(b[6] & 0x4), !!(b[6] & 0x2), !!(b[6] & 0x1));
    sgj_pr_hr(jsp, "  NO_PI_CHK=%d P_I_I_SUP=%d LUICLR=%d\n", !!(b[7] & 0x20),
              !!(b[7] & 0x10), !!(b[7] & 0x1));
    /* RTD_SUP added in spc5r11, LU_COLL_TYPE added in spc5r09,
     * HSSRELEF added in spc5r02; CBCS obsolete in spc5r01 */
    sgj_pr_hr(jsp, "  LU_COLL_TYPE=%d R_SUP=%d RTD_SUP=%d HSSRELEF=%d "
              "[CBCS=%d]\n", (b[8] >> 5) & 0x7, !!(b[8] & 0x10),
              !!(b[8] & 0x8), !!(b[8] & 0x2), !!(b[8] & 0x1));
    sgj_pr_hr(jsp, "  Multi I_T nexus microcode download=%d\n", b[9] & 0xf);
    sgj_pr_hr(jsp, "  Extended self-test completion minutes=%d\n",
              sg_get_unaligned_be16(b + 10));    /* spc4r27 */
    sgj_pr_hr(jsp, "  POA_SUP=%d HRA_SUP=%d VSA_SUP=%d DMS_VALID=%d\n",
              !!(b[12] & 0x80), !!(b[12] & 0x40), !!(b[12] & 0x20),
              !!(b[12] & 0x10));                   /* spc5r20 */
    sgj_pr_hr(jsp, "  Maximum supported sense data length=%d\n",
              b[13]); /* spc4r34 */
    sgj_pr_hr(jsp, "  IBS=%d IAS=%d SAC=%d NRD1=%d NRD0=%d\n",
              !!(b[14] & 0x80), !!(b[14] & 0x40), !!(b[14] & 0x4),
              !!(b[14] & 0x2), !!(b[14] & 0x1));  /* added in spc5r09 */
    sgj_pr_hr(jsp, "  Maximum inquiry change logs=%u\n",
              sg_get_unaligned_be16(b + 15));        /* spc5r17 */
    sgj_pr_hr(jsp, "  Maximum mode page change logs=%u\n",
              sg_get_unaligned_be16(b + 17));        /* spc5r17 */
    sgj_pr_hr(jsp, "  DM_MD_4=%d DM_MD_5=%d DM_MD_6=%d DM_MD_7=%d\n",
              !!(b[19] & 0x80), !!(b[19] & 0x40), !!(b[19] & 0x20),
              !!(b[19] & 0x10));                     /* spc5r20 */
    sgj_pr_hr(jsp, "  DM_MD_D=%d DM_MD_E=%d DM_MD_F=%d\n",
              !!(b[19] & 0x8), !!(b[19] & 0x4), !!(b[19] & 0x2));
}

/* VPD_SOFTW_INF_ID   0x84 */
void
decode_softw_inf_id(uint8_t * buff, int len, struct opts_t * op,
                    sgj_opaque_p jap)
{
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jop;
    uint64_t ieee_id;

    if (op->do_hex) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    len -= 4;
    buff += 4;
    for ( ; len > 5; len -= 6, buff += 6) {
        ieee_id = sg_get_unaligned_be48(buff + 0);
        sgj_pr_hr(jsp, "    IEEE identifier: 0x%" PRIx64 "\n", ieee_id);
        if (jsp->pr_as_json) {
            jop = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihex(jsp, jop, "ieee_identifier", ieee_id);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jop);
        }
   }
}

static const char * mode_page_policy_arr[] =
{
    "shared",
    "per target port",
    "per initiator port",
    "per I_T nexus",
};

/* VPD_MODE_PG_POLICY  0x87 ["mpp"] */
void
decode_mode_policy_vpd(uint8_t * buff, int len, struct opts_t * op,
                       sgj_opaque_p jap)
{
    int k, n, bump, ppc, pspc;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    uint8_t * bp;
    char b[128];
    static const int blen = sizeof(b);

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Mode page policy VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            pr2serr("Mode page policy VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (op->do_hex > 1)
            hex2stdout(bp, 4, 1);
        else {
            n = 0;
            ppc =  (bp[0] & 0x3f);
            pspc = bp[1];
            n = snprintf(b + n, blen - n, "  Policy page code: 0x%x", ppc);
            if (pspc)
                n += snprintf(b + n, blen - n, ",  subpage code: 0x%x", pspc);
            sgj_pr_hr(jsp, "%s\n", b);
            if ((0 == k) && (0x3f == (0x3f & bp[0])) && (0xff == bp[1]))
                sgj_pr_hr(jsp, "  therefore the policy applies to all modes "
                          "pages and subpages\n");
            sgj_pr_hr(jsp, "    MLUS=%d,  Policy: %s\n", !!(bp[2] & 0x80),
                      mode_page_policy_arr[bp[2] & 0x3]);
            if (jsp->pr_as_json) {
                jo2p = sgj_new_unattached_object_r(jsp);
                sgj_js_nv_ihex(jsp, jo2p, "policy_page_code", ppc);
                sgj_js_nv_ihex(jsp, jo2p, "policy_subpage_code", pspc);
                sgj_js_nv_ihex_nex(jsp, jo2p, "mlus", !!(bp[2] & 0x80), false,
                                   "Multiple logical units share");
                sgj_js_nv_ihexstr(jsp, jo2p, "mode_page_policy", bp[2] & 0x3,
                                  NULL, mode_page_policy_arr[bp[2] & 0x3]);
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
        }
    }
}

/* VPD_POWER_CONDITION 0x8a ["pc"] */
void
decode_power_condition(uint8_t * buff, int len, struct opts_t * op,
                       sgj_opaque_p jop)
{
    sgj_state * jsp = &op->json_st;

    if (len < 18) {
        pr2serr("Power condition VPD page length too short=%d\n", len);
        return;
    }
    if (op->do_hex) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    sgj_pr_hr(jsp, "  Standby_y=%d Standby_z=%d Idle_c=%d Idle_b=%d "
              "Idle_a=%d\n", !!(buff[4] & 0x2), !!(buff[4] & 0x1),
              !!(buff[5] & 0x4), !!(buff[5] & 0x2), !!(buff[5] & 0x1));
    if (jsp->pr_as_json) {
        sgj_js_nv_ihex(jsp, jop, "standby_y", !!(buff[4] & 0x2));
        sgj_js_nv_ihex(jsp, jop, "standby_z", !!(buff[4] & 0x1));
        sgj_js_nv_ihex(jsp, jop, "idle_c", !!(buff[5] & 0x4));
        sgj_js_nv_ihex(jsp, jop, "idle_b", !!(buff[5] & 0x2));
        sgj_js_nv_ihex(jsp, jop, "idle_a", !!(buff[5] & 0x1));
    }
    sgj_hr_js_vi_nex(jsp, jop, 2, "Stopped condition recovery time",
                     SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 6),
                     true, "unit: millisecond");
    sgj_hr_js_vi_nex(jsp, jop, 2, "Standby_z condition recovery time",
                     SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 8),
                     true, "unit: millisecond");
    sgj_hr_js_vi_nex(jsp, jop, 2, "Standby_y condition recovery time",
                     SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 10),
                     true, "unit: millisecond");
    sgj_hr_js_vi_nex(jsp, jop, 2, "Idle_a condition recovery time",
                     SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 12),
                     true, "unit: millisecond");
    sgj_hr_js_vi_nex(jsp, jop, 2, "Idle_b condition recovery time",
                     SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 14),
                     true, "unit: millisecond");
    sgj_hr_js_vi_nex(jsp, jop, 2, "Idle_c condition recovery time",
                     SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 16),
                     true, "unit: millisecond");
}

int
filter_json_dev_ids(uint8_t * buff, int len, int m_assoc, struct opts_t * op,
                    sgj_opaque_p jap)
{
    int u, off, i_len;
    sgj_opaque_p jo2p;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;

    off = -1;
    while ((u = sg_vpd_dev_id_iter(buff, len, &off, m_assoc, -1, -1)) == 0) {
        bp = buff + off;
        i_len = bp[3];
        if ((off + i_len + 4) > len) {
            pr2serr("    VPD page error: designator length longer than\n"
                    "     remaining response length=%d\n", (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        jo2p = sgj_new_unattached_object_r(jsp);
        sgj_js_designation_descriptor(jsp, jo2p, bp, i_len + 4);
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    if (-2 == u) {
        pr2serr("VPD page error: short designator around offset %d\n", off);
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
}

/* VPD_ATA_INFO    0x89 ["ai"] */
void
decode_ata_info_vpd(const uint8_t * buff, int len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool do_long_nq = op->do_long && (! op->do_quiet);
    int num, is_be, cc, n;
    sgj_state * jsp = &op->json_st;
    const char * cp;
    const char * ata_transp;
    char b[512];
    char d[80];
    static const int blen = sizeof(b);
    static const int dlen = sizeof(d);
    static const char * sat_vip = "SAT Vendor identification";
    static const char * sat_pip = "SAT Product identification";
    static const char * sat_prlp = "SAT Product revision level";

    if (len < 36) {
        pr2serr("ATA information VPD page length too short=%d\n", len);
        return;
    }
    if (op->do_hex && (2 != op->do_hex)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    memcpy(b, buff + 8, 8);
    b[8] = '\0';
    sgj_pr_hr(jsp, "  %s: %s\n", sat_vip, b);
    memcpy(b, buff + 16, 16);
    b[16] = '\0';
    sgj_pr_hr(jsp, "  %s: %s\n", sat_pip, b);
    memcpy(b, buff + 32, 4);
    b[4] = '\0';
    sgj_pr_hr(jsp, "  %s: %s\n", sat_prlp, b);
    if (len < 56)
        return;
    ata_transp = (0x34 == buff[36]) ? "SATA" : "PATA";
    if (do_long_nq) {
        sgj_pr_hr(jsp, "  Device signature [%s] (in hex):\n", ata_transp);
        hex2stdout(buff + 36, 20, 0);
    } else
        sgj_pr_hr(jsp, "  Device signature indicates %s transport\n",
                  ata_transp);
    cc = buff[56];      /* 0xec for IDENTIFY DEVICE and 0xa1 for IDENTIFY
                         * PACKET DEVICE (obsolete) */
    n = snprintf(b, blen, "  Command code: 0x%x\n", cc);
    if (len < 60)
        return;
    if (0xec == cc)
        cp = null_s;
    else if (0xa1 == cc)
        cp = "PACKET ";
    else
        cp = NULL;
    is_be = sg_is_big_endian();
    if (cp) {
        n += sg_scnpr(b + n, blen - n, "  ATA command IDENTIFY %sDEVICE "
                      "response summary:\n", cp);
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 27, 20,
                               is_be, d);
        d[num] = '\0';
        n += sg_scnpr(b + n, blen - n, "    model: %s\n", d);
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 10, 10,
                               is_be, d);
        d[num] = '\0';
        n += sg_scnpr(b + n, blen - n, "    serial number: %s\n", d);
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 23, 4,
                               is_be, d);
        d[num] = '\0';
        n += sg_scnpr(b + n, blen - n, "    firmware revision: %s\n", d);
        sgj_pr_hr(jsp, "%s", b);
        if (do_long_nq)
            sgj_pr_hr(jsp, "  ATA command IDENTIFY %sDEVICE response in "
                      "hex:\n", cp);
    } else if (do_long_nq)
        sgj_pr_hr(jsp, "  ATA command 0x%x got following response:\n",
                  (unsigned int)cc);
    if (jsp->pr_as_json) {
        sgj_convert_to_snake_name(sat_vip, d, dlen);
        sgj_js_nv_s_len(jsp, jop, d, (const char *)(buff + 8), 8);
        sgj_convert_to_snake_name(sat_pip, d, dlen);
        sgj_js_nv_s_len(jsp, jop, d, (const char *)(buff + 16), 16);
        sgj_convert_to_snake_name(sat_prlp, d, dlen);
        sgj_js_nv_s_len(jsp, jop, d, (const char *)(buff + 32), 4);
        sgj_js_nv_hex_bytes(jsp, jop, "ata_device_signature", buff + 36, 20);
        sgj_js_nv_ihex(jsp, jop, "command_code", buff[56]);
        sgj_js_nv_s(jsp, jop, "ata_identify_device_data_example",
                    "sg_vpd -p ai -HHH /dev/sdc | hdparm --Istdin");
    }
    if (len < 572)
        return;
    if (2 == op->do_hex)
        hex2stdout((buff + 60), 512, 0);
    else if (do_long_nq)
        dWordHex((const unsigned short *)(buff + 60), 256, 0, is_be);
}

/* VPD_SCSI_FEATURE_SETS  0x92  ["sfs"] */
void
decode_feature_sets_vpd(uint8_t * buff, int len, struct opts_t * op,
                        sgj_opaque_p jap)
{
    int k, bump;
    uint16_t sf_code;
    bool found;
    uint8_t * bp;
    sgj_opaque_p jo2p;
    sgj_state * jsp = &op->json_st;
    char b[256];
    char d[80];

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("SCSI Feature sets VPD page length too short=%d\n", len);
        return;
    }
    len -= 8;
    bp = buff + 8;
    for (k = 0; k < len; k += bump, bp += bump) {
        jo2p = sgj_new_unattached_object_r(jsp);
        sf_code = sg_get_unaligned_be16(bp);
        bump = 2;
        if ((k + bump) > len) {
            pr2serr("SCSI Feature sets, short descriptor length=%d, "
                    "left=%d\n", bump, (len - k));
            return;
        }
        if (2 == op->do_hex)
            hex2stdout(bp + 8, 2, 1);
        else if (op->do_hex > 2)
            hex2stdout(bp, 2, 1);
        else {
             sg_scnpr(b, sizeof(b), "    %s",
                      sg_get_sfs_str(sf_code, -2, sizeof(d), d, &found,
                                     op->verbose));
            if (op->verbose == 1)
                sgj_pr_hr(jsp, "%s [0x%x]\n", b, (unsigned int)sf_code);
            else if (op->verbose > 1)
                sgj_pr_hr(jsp, "%s [0x%x] found=%s\n", b,
                          (unsigned int)sf_code, found ? "true" : "false");
            else
                sgj_pr_hr(jsp, "%s\n", b);
            sgj_js_nv_ihexstr(jsp, jo2p, "feature_set_code", sf_code, NULL,
                              d);
            if (jsp->verbose)
                sgj_js_nv_b(jsp, jo2p, "meaning_is_match", found);
        }
        sgj_js_nv_o(jsp, jap, NULL, jo2p);
    }
}

static const char * constituent_type_arr[] = {
    "Reserved",
    "Virtual tape library",
    "Virtual tape drive",
    "Direct access block device",
};

/* VPD_DEVICE_CONSTITUENTS   0x8b ["dc"] */
void
decode_dev_constit_vpd(const uint8_t * buff, int len, struct opts_t * op,
                       sgj_opaque_p jap, recurse_vpd_decodep fp)
{
    uint16_t constit_type;
    int k, j, res, bump, csd_len;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p, jo3p, ja2p;
    const uint8_t * bp;
    char b[256];
    char d[64];
    static const int blen = sizeof(b);
    static const int dlen = sizeof(d);

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("page length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0, j = 0; k < len; k += bump, bp += bump, ++j) {
        jo2p = sgj_new_unattached_object_r(jsp);
        if (j > 0)
            sgj_pr_hr(jsp, "\n");
        sgj_pr_hr(jsp, "  Constituent descriptor %d:\n", j + 1);
        if ((k + 36) > len) {
            pr2serr("short descriptor length=36, left=%d\n", (len - k));
            sgj_js_nv_o(jsp, jap, NULL, jo2p);
            return;
        }
        constit_type = sg_get_unaligned_be16(bp + 0);
        if (constit_type >= SG_ARRAY_SIZE(constituent_type_arr))
            sgj_pr_hr(jsp,"    Constituent type: unknown [0x%x]\n",
                      constit_type);
        else
            sgj_pr_hr(jsp, "    Constituent type: %s [0x%x]\n",
                      constituent_type_arr[constit_type], constit_type);
        sg_scnpr(b, blen, "    Constituent device type: ");
        if (0xff == bp[2])
            sgj_pr_hr(jsp, "%sUnknown [0xff]\n", b);
        else if (bp[2] >= 0x20)
            sgj_pr_hr(jsp, "%s%s [0x%x]\n", b, rsv_s, bp[2]);
        else
            sgj_pr_hr(jsp, "%s%s [0x%x]\n", b,
                   sg_get_pdt_str(PDT_MASK & bp[2], dlen, d), bp[2]);
        snprintf(b, blen, "%.8s", bp + 4);
        sgj_pr_hr(jsp, "    %s: %s\n", t10_vendor_id_hr, b);
        sgj_js_nv_s(jsp, jo2p, t10_vendor_id_js, b);
        snprintf(b, blen, "%.16s", bp + 12);
        sgj_pr_hr(jsp, "    %s: %s\n", product_id_hr, b);
        sgj_js_nv_s(jsp, jo2p, product_id_js, b);
        snprintf(b, blen, "%.4s", bp + 28);
        sgj_pr_hr(jsp, "    %s: %s\n", product_rev_lev_hr, b);
        sgj_js_nv_s(jsp, jo2p, product_rev_lev_js, b);
        csd_len = sg_get_unaligned_be16(bp + 34);
        bump = 36 + csd_len;
        if ((k + bump) > len) {
            pr2serr("short descriptor length=%d, left=%d\n", bump, (len - k));
            sgj_js_nv_o(jsp, jap, NULL, jo2p);
            return;
        }
        if (csd_len > 0) {
            int m, q, cs_bump;
            uint8_t cs_type;
            uint8_t cs_len;
            const uint8_t * cs_bp;

            sgj_pr_hr(jsp, "    Constituent specific descriptors:\n");
            ja2p = sgj_named_subarray_r(jsp, jo2p,
                                "constituent_specific_descriptor_list");
            for (m = 0, q = 0, cs_bp = bp + 36; m < csd_len;
                 m += cs_bump, ++q, cs_bp += cs_bump) {
                jo3p = sgj_new_unattached_object_r(jsp);
                cs_type = cs_bp[0];
                cs_len = sg_get_unaligned_be16(cs_bp + 2);
                cs_bump = cs_len + 4;
                sgj_js_nv_ihex(jsp, jo3p, "constituent_specific_type",
                               cs_type);
                if (1 == cs_type) {     /* VPD page */
                    int off = cs_bp + 4 - buff;

                    sgj_pr_hr(jsp, "      Constituent specific VPD page "
                              "%d:\n", q + 1);
                    /* SPC-5 says these shall _not_ themselves be Device
                     *  Constituent VPD pages. So no infinite recursion. */
                    res = (*fp)(op, jo3p, off);
                    if (res)
                        pr2serr("%s: recurse_vpd_decode() failed, res=%d\n",
                                __func__, res);
                } else {
                    if (0xff == cs_type)
                        sgj_pr_hr(jsp, "      Vendor specific data (in "
                                  "hex):\n");
                    else
                        sgj_pr_hr(jsp, "      %s [0x%x] specific data (in "
                                  "hex):\n", rsv_s, cs_type);
                    if (jsp->pr_as_json)
                        sgj_js_nv_hex_bytes(jsp, jo3p,
                                            "constituent_specific_data_hex",
                                            cs_bp + 4, cs_len);
                    else
                        hex2stdout(cs_bp + 4, cs_len, 0 /* plus ASCII */);
                }
                sgj_js_nv_o(jsp, ja2p, NULL, jo3p);
            }   /* end of Constituent specific descriptor loop */
        }
        sgj_js_nv_o(jsp, jap, NULL, jo2p);
    }   /* end Constituent descriptor loop */
}

/* Assume index is less than 16 */
static const char * sg_ansi_version_arr[16] =
{
    "no conformance claimed",
    "SCSI-1",           /* obsolete, ANSI X3.131-1986 */
    "SCSI-2",           /* obsolete, ANSI X3.131-1994 */
    "SPC",              /* withdrawn, ANSI INCITS 301-1997 */
    "SPC-2",            /* ANSI INCITS 351-2001, ISO/IEC 14776-452 */
    "SPC-3",            /* ANSI INCITS 408-2005, ISO/IEC 14776-453 */
    "SPC-4",            /* ANSI INCITS 513-2015 */
    "SPC-5",            /* ANSI INCITS 502-2020 */
    "ecma=1, [8h]",
    "ecma=1, [9h]",
    "ecma=1, [Ah]",
    "ecma=1, [Bh]",
    "reserved [Ch]",
    "reserved [Dh]",
    "reserved [Eh]",
    "reserved [Fh]",
};

static const char *
hot_pluggable_str(int hp)
{
    switch (hp) {
    case 0:
        return "No information";
    case 1:
        return "target device designed to be removed from SCSI domain";
    case 2:
        return "target device not designed to be removed from SCSI domain";
    default:
        return "value reserved by T10";
    }
}

static const char *
tpgs_str(int tpgs)
{
    switch (tpgs) {
    case 1:
        return "only implicit asymmetric logical unit access";
    case 2:
        return "only explicit asymmetric logical unit access";
    case 3:
        return "both explicit and implicit asymmetric logical unit access";
    case 0:
    default:
        return ns_s;
    }
}

sgj_opaque_p
std_inq_decode_js(const uint8_t * b, int len, struct opts_t * op,
                  sgj_opaque_p jop)
{
    int tpgs;
    int pqual = (b[0] & 0xe0) >> 5;
    int pdt = b[0] & PDT_MASK;
    int hp = (b[1] >> 4) & 0x3;
    int ver = b[2];
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    char c[256];
    static const int clen = sizeof(c);

    jo2p = sgj_named_subobject_r(jsp, jop, "standard_inquiry_data_format");
    sgj_js_nv_ihexstr(jsp, jo2p, "peripheral_qualifier", pqual, NULL,
                      pqual_str(pqual));
    sgj_js_nv_ihexstr(jsp, jo2p, "peripheral_device_type", pdt, NULL,
                      sg_get_pdt_str(pdt, clen, c));
    sgj_js_nv_ihex_nex(jsp, jo2p, "rmb", !!(b[1] & 0x80), false,
                       "Removable Medium Bit");
    sgj_js_nv_ihex_nex(jsp, jo2p, "lu_cong", !!(b[1] & 0x40), false,
                       "Logical Unit Conglomerate");
    sgj_js_nv_ihexstr(jsp, jo2p, "hot_pluggable", hp, NULL,
                      hot_pluggable_str(hp));
    snprintf(c, clen, "%s", (ver > 0xf) ? "old or reserved version code" :
                                          sg_ansi_version_arr[ver]);
    sgj_js_nv_ihexstr(jsp, jo2p, "version", ver, NULL, c);
    sgj_js_nv_ihex_nex(jsp, jo2p, "aerc", !!(b[3] & 0x80), false,
                       "Asynchronous Event Reporting Capability (obsolete "
                       "SPC-3)");
    sgj_js_nv_ihex_nex(jsp, jo2p, "trmtsk", !!(b[3] & 0x40), false,
                       "Terminate Task (obsolete SPC-2)");
    sgj_js_nv_ihex_nex(jsp, jo2p, "normaca", !!(b[3] & 0x20), false,
                       "Normal ACA (Auto Contingent Allegiance)");
    sgj_js_nv_ihex_nex(jsp, jo2p, "hisup", !!(b[3] & 0x10), false,
                       "Hierarchial Support");
    sgj_js_nv_ihex(jsp, jo2p, "response_data_format", b[3] & 0xf);
    sgj_js_nv_ihex_nex(jsp, jo2p, "sccs", !!(b[5] & 0x80), false,
                       "SCC (SCSI Storage Commands) Supported");
    sgj_js_nv_ihex_nex(jsp, jo2p, "acc", !!(b[5] & 0x40), false,
                       "Access Commands Coordinator (obsolete SPC-5)");
    tpgs = (b[5] >> 4) & 0x3;
    sgj_js_nv_ihexstr_nex(jsp, jo2p, "tpgs", tpgs, false, NULL,
                          tpgs_str(tpgs), "Target Port Group Support");
    sgj_js_nv_ihex_nex(jsp, jo2p, "3pc", !!(b[5] & 0x8), false,
                       "Third Party Copy");
    sgj_js_nv_ihex(jsp, jo2p, "protect", !!(b[5] & 0x1));
    /* Skip SPI specific flags which have been obsolete for a while) */
    sgj_js_nv_ihex_nex(jsp, jo2p, "bque", !!(b[6] & 0x80), false,
                       "Basic task management model (obsolete SPC-4)");
    sgj_js_nv_ihex_nex(jsp, jo2p, "encserv", !!(b[6] & 0x40), false,
                       "Enclousure Services supported");
    sgj_js_nv_ihex_nex(jsp, jo2p, "multip", !!(b[6] & 0x10), false,
                       "Multiple SCSI port");
    sgj_js_nv_ihex_nex(jsp, jo2p, "mchngr", !!(b[6] & 0x8), false,
                       "Medium changer (obsolete SPC-4)");
    sgj_js_nv_ihex_nex(jsp, jo2p, "reladr", !!(b[7] & 0x80), false,
                       "Relative Addressing (obsolete in SPC-4)");
    sgj_js_nv_ihex_nex(jsp, jo2p, "linked", !!(b[7] & 0x8), false,
                       "Linked Commands (obsolete in SPC-4)");
    sgj_js_nv_ihex_nex(jsp, jo2p, "cmdque", !!(b[7] & 0x2), false,
                       "Command Management Model (command queuing)");
    if (len < 16)
        return jo2p;
    snprintf(c, clen, "%.8s", b + 8);
    sgj_js_nv_s(jsp, jo2p, t10_vendor_id_js, c);
    if (len < 32)
        return jo2p;
    snprintf(c, clen, "%.16s", b + 16);
    sgj_js_nv_s(jsp, jo2p, product_id_js, c);
    if (len < 36)
        return jo2p;
    snprintf(c, clen, "%.4s", b + 32);
    sgj_js_nv_s(jsp, jo2p, product_rev_lev_js, c);
    return jo2p;
}

static const char * power_unit_arr[] =
{
    "Gigawatts",
    "Megawatts",
    "Kilowatts",
    "Watts",
    "Milliwatts",
    "Microwatts",
    "Unit reserved",
    "Unit reserved",
};

/* VPD_POWER_CONSUMPTION  0x8d  ["psm"] */
void
decode_power_consumption(uint8_t * buff, int len, struct opts_t * op,
                         sgj_opaque_p jap)
{
    int k, bump, pcmp_id, pcmp_unit;
    unsigned int pcmp_val;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    uint8_t * bp;
    char b[128];
    static const int blen = sizeof(b);
    static const char * pcmp = "power_consumption";
    static const char * pci = "Power consumption identifier";
    static const char * mpc = "Maximum power consumption";

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            pr2serr("short descriptor length=%d, left=%d\n", bump,
                    (len - k));
            return;
        }
        if (op->do_hex > 1)
            hex2stdout(bp, 4, 1);
        else {
            jo2p = sgj_new_unattached_object_r(jsp);
            pcmp_id = bp[0];
            pcmp_unit = 0x7 & bp[1];
            pcmp_val = sg_get_unaligned_be16(bp + 2);
            if (jsp->pr_as_json) {
                sgj_convert_to_snake_name(pci, b, blen);
                sgj_js_nv_ihex(jsp, jo2p, b, pcmp_id);
                snprintf(b, blen, "%s_units", pcmp);
                sgj_js_nv_ihexstr(jsp, jo2p, b, pcmp_unit, NULL,
                                  power_unit_arr[pcmp_unit]);
                snprintf(b, blen, "%s_value", pcmp);
                sgj_js_nv_ihex(jsp, jo2p, b, pcmp_val);
            }
            snprintf(b, blen, "  %s: 0x%x", pci, pcmp_id);
            if (pcmp_val >= 1000 && pcmp_unit > 0)
                sgj_pr_hr(jsp, "%s    %s: %d.%03d %s\n", b, mpc,
                          pcmp_val / 1000, pcmp_val % 1000,
                          power_unit_arr[pcmp_unit - 1]); /* up one unit */
            else
                sgj_pr_hr(jsp, "%s    %s: %u %s\n", b, mpc, pcmp_val,
                          power_unit_arr[pcmp_unit]);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
    }
}


/* VPD_BLOCK_LIMITS    0xb0 ["bl"] */
void
decode_block_limits_vpd(const uint8_t * buff, int len, struct opts_t * op,
                        sgj_opaque_p jop)
{
    int wsnz, ugavalid;
    uint32_t u;
    uint64_t ull;
    sgj_state * jsp = &op->json_st;
    char b[144];
    static const int blen = sizeof(b);
    static const char * mcawl = "Maximum compare and write length";
    static const char * otlg = "Optimal transfer length granularity";
    static const char * cni = "command not implemented";
    static const char * ul = "unlimited";
    static const char * mtl = "Maximum transfer length";
    static const char * otl = "Optimal transfer length";
    static const char * mpl = "Maximum prefetch length";
    static const char * mulc = "Maximum unmap LBA count";
    static const char * mubdc = "Maximum unmap block descriptor count";
    static const char * oug = "Optimal unmap granularity";
    static const char * ugav = "Unmap granularity alignment valid";
    static const char * uga = "Unmap granularity alignment";
    static const char * mwsl = "Maximum write same length";
    static const char * matl = "Maximum atomic transfer length";
    static const char * aa = "Atomic alignment";
    static const char * atlg = "Atomic transfer length granularity";
    static const char * matlwab = "Maximum atomic transfer length with "
                                  "atomic boundary";
    static const char * mabs = "Maximum atomic boundary size";

    if (len < 16) {
        pr2serr("page length too short=%d\n", len);
        return;
    }
    wsnz = !!(buff[4] & 0x1);
    sgj_pr_hr(jsp, "  Write same non-zero (WSNZ): %d\n", wsnz);
    sgj_js_nv_ihex_nex(jsp, jop, "wsnz", wsnz, false,
                "Write Same Non-Zero (number of LBs must be > 0)");
    u = buff[5];
    if (0 == u) {
        sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mcawl, cni);
        sgj_convert_to_snake_name(mcawl, b, blen);
        sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, cni);
    } else
        sgj_hr_js_vi_nex(jsp, jop, 2, mcawl, SGJ_SEP_COLON_1_SPACE, u,
                         true, "unit: LB");

    u = sg_get_unaligned_be16(buff + 6);
    if (0 == u) {
        sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", otlg, nr_s);
        sgj_convert_to_snake_name(otlg, b, blen);
        sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
    } else
        sgj_hr_js_vi_nex(jsp, jop, 2, otlg, SGJ_SEP_COLON_1_SPACE, u,
                            true, "unit: LB");

    u = sg_get_unaligned_be32(buff + 8);
    if (0 == u) {
        sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mtl, nr_s);
        sgj_convert_to_snake_name(mtl, b, blen);
        sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
    } else
        sgj_hr_js_vi_nex(jsp, jop, 2, mtl, SGJ_SEP_COLON_1_SPACE, u,
                         true, "unit: LB");

    u = sg_get_unaligned_be32(buff + 12);
    if (0 == u) {
        sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", otl, nr_s);
        sgj_convert_to_snake_name(otl, b, blen);
        sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
    } else
        sgj_hr_js_vi_nex(jsp, jop, 2, otl, SGJ_SEP_COLON_1_SPACE, u,
                         true, "unit: LB");
    if (len > 19) {     /* added in sbc3r09 */
        u = sg_get_unaligned_be32(buff + 16);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mpl, nr_s);
            sgj_convert_to_snake_name(mpl, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, mpl, SGJ_SEP_COLON_1_SPACE, u,
                             true, "unit: LB");
    }
    if (len > 27) {     /* added in sbc3r18 */
        u = sg_get_unaligned_be32(buff + 20);
        sgj_convert_to_snake_name(mulc, b, blen);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mulc, cni);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, cni);
        } else if (0xffffffff == u) {
            sgj_pr_hr(jsp, "  %s: %s blocks\n", ul, mulc);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, ul);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, mulc, SGJ_SEP_COLON_1_SPACE, u,
                             true, "unit: LB");

        u = sg_get_unaligned_be32(buff + 24);
        sgj_convert_to_snake_name(mulc, b, blen);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 block descriptors [%s]\n", mubdc, cni);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, cni);
        } else if (0xffffffff == u) {
            sgj_pr_hr(jsp, "  %s: %s block descriptors\n", ul, mubdc);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, ul);
        } else
            sgj_hr_js_vi(jsp, jop, 2, mubdc, SGJ_SEP_COLON_1_SPACE,
                         u, true);
    }
    if (len > 35) {     /* added in sbc3r19 */
        u = sg_get_unaligned_be32(buff + 28);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", oug, nr_s);
            sgj_convert_to_snake_name(oug, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, oug, SGJ_SEP_COLON_1_SPACE, u,
                             true, "unit: LB");

        ugavalid = !!(buff[32] & 0x80);
        sgj_pr_hr(jsp, "  %s: %s\n", ugav, ugavalid ? "true" : "false");
        sgj_js_nv_i(jsp, jop, ugav, ugavalid);
        if (ugavalid) {
            u = 0x7fffffff & sg_get_unaligned_be32(buff + 32);
            sgj_hr_js_vi_nex(jsp, jop, 2, uga, SGJ_SEP_COLON_1_SPACE, u,
                             true, "unit: LB");
        }
    }
    if (len > 43) {     /* added in sbc3r26 */
        ull = sg_get_unaligned_be64(buff + 36);
        if (0 == ull) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mwsl, nr_s);
            sgj_convert_to_snake_name(mwsl, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, ull, NULL, nr_s);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, mwsl, SGJ_SEP_COLON_1_SPACE,
                             ull, true, "unit: LB");
    }
    if (len > 47) {     /* added in sbc4r02 */
        u = sg_get_unaligned_be32(buff + 44);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", matl, nr_s);
            sgj_convert_to_snake_name(matl, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, matl, SGJ_SEP_COLON_1_SPACE,
                             u, true, "unit: LB");

        u = sg_get_unaligned_be32(buff + 48);
        if (0 == u) {
            static const char * uawp = "unaligned atomic writes permitted";

            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", aa, uawp);
            sgj_convert_to_snake_name(aa, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, uawp);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, aa, SGJ_SEP_COLON_1_SPACE,
                             u, true, "unit: LB");

        u = sg_get_unaligned_be32(buff + 52);
        if (0 == u) {
            static const char * ngr = "no granularity requirement";

            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", atlg, ngr);
            sgj_convert_to_snake_name(atlg, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, ngr);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, aa, SGJ_SEP_COLON_1_SPACE,
                             u, true, "unit: LB");
    }
    if (len > 56) {
        u = sg_get_unaligned_be32(buff + 56);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", matlwab, nr_s);
            sgj_convert_to_snake_name(matlwab, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, matlwab, SGJ_SEP_COLON_1_SPACE,
                             u, true, "unit: LB");

        u = sg_get_unaligned_be32(buff + 60);
        if (0 == u) {
            static const char * cowa1b = "can only write atomic 1 block";

            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mabs, cowa1b);
            sgj_convert_to_snake_name(mabs, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, cowa1b);
        } else
            sgj_hr_js_vi_nex(jsp, jop, 2, mabs, SGJ_SEP_COLON_1_SPACE,
                             u, true, "unit: LB");
    }
}

static const char * product_type_arr[] =
{
    "Not specified",
    "CFast",
    "CompactFlash",
    "MemoryStick",
    "MultiMediaCard",
    "Secure Digital Card (SD)",
    "XQD",
    "Universal Flash Storage Card (UFS)",
};

/* ZONED field here replaced by ZONED BLOCK DEVICE EXTENSION field in the
 * Zoned Block Device Characteristics VPD page. The new field includes
 * Zone Domains and Realms (see ZBC-2) */
static const char * bdc_zoned_strs[] = {
    nr_s,
    "host-aware",
    "host-managed",
    rsv_s,
};

/* VPD_BLOCK_DEV_CHARS    0xb1 ["bdc"] */
void
decode_block_dev_ch_vpd(const uint8_t * buff, int len, struct opts_t * op,
                        sgj_opaque_p jop)
{
    int zoned;
    unsigned int u, k;
    sgj_state * jsp = &op->json_st;
    const char * cp;
    char b[144];
    static const int blen = sizeof(b);
    static const char * mrr_j = "medium_rotation_rate";
    static const char * mrr_h = "Medium rotation rate";
    static const char * nrm = "Non-rotating medium (e.g. solid state)";
    static const char * pt_j = "product_type";

    if (len < 64) {
        pr2serr("page length too short=%d\n", len);
        return;
    }
    u = sg_get_unaligned_be16(buff + 4);
    if (0 == u) {
        sgj_pr_hr(jsp, "  %s is %s\n", mrr_h, nr_s);
        sgj_js_nv_ihexstr(jsp, jop, mrr_j, 0, NULL, nr_s);
    } else if (1 == u) {
        sgj_pr_hr(jsp, "  %s\n", nrm);
        sgj_js_nv_ihexstr(jsp, jop, mrr_j, 1, NULL, nrm);
    } else if ((u < 0x401) || (0xffff == u)) {
        sgj_pr_hr(jsp, "  %s [0x%x]\n", rsv_s, u);
        sgj_js_nv_ihexstr(jsp, jop, mrr_j, u, NULL, rsv_s);
    } else {
        sgj_js_nv_ihex_nex(jsp, jop, mrr_j, u, true,
                           "unit: rpm; nominal rotation rate");
    }
    u = buff[6];
    k = SG_ARRAY_SIZE(product_type_arr);
    if (u < k) {
        sgj_pr_hr(jsp, "  %s: %s\n", "Product type", product_type_arr[u]);
        sgj_js_nv_ihexstr(jsp, jop, pt_j, u, NULL, product_type_arr[u]);
    } else {
        sgj_pr_hr(jsp, "  %s: %s [0x%x]\n", "Product type",
                  (u < 0xf0) ? rsv_s : vs_s, u);
        sgj_js_nv_ihexstr(jsp, jop, pt_j, u, NULL, (u < 0xf0) ? rsv_s : vs_s);
    }
    sgj_hr_js_vi_nex(jsp, jop, 2, "WABEREQ", SGJ_SEP_EQUAL_NO_SPACE,
                     (buff[7] >> 6) & 0x3, false,
                     "Write After Block Erase REQuired");
    sgj_hr_js_vi_nex(jsp, jop, 2, "WACEREQ", SGJ_SEP_EQUAL_NO_SPACE,
                     (buff[7] >> 4) & 0x3, false,
                     "Write After Cryptographic Erase REQuired");
    u = buff[7] & 0xf;
    switch (u) {
    case 0:
        snprintf(b, blen, nr_s);
        break;
    case 1:
        snprintf(b, blen, "5.25 inch");
        break;
    case 2:
        snprintf(b, blen, "3.5 inch");
        break;
    case 3:
        snprintf(b, blen, "2.5 inch");
        break;
    case 4:
        snprintf(b, blen, "1.8 inch");
        break;
    case 5:
        snprintf(b, blen, "less then 1.8 inch");
        break;
    default:
        snprintf(b, blen, rsv_s);
        break;
    }
    sgj_pr_hr(jsp, "  Nominal form factor: %s\n", b);
    sgj_js_nv_ihexstr(jsp, jop, "nominal_forn_factor", u, NULL, b);
    sgj_hr_js_vi_nex(jsp, jop, 2, "MACT", SGJ_SEP_EQUAL_NO_SPACE,
                     !!(buff[8] & 0x40), false, "Multiple ACTuator");
    printf("  MACT=%d\n", !!(buff[8] & 0x40));      /* added sbc5r01 */
    zoned = (buff[8] >> 4) & 0x3;   /* added sbc4r04, obsolete sbc5r01 */
    cp = bdc_zoned_strs[zoned];
    sgj_pr_hr(jsp, "  ZONED=%d [%s]\n", zoned, cp);
    sgj_js_nv_ihexstr_nex(jsp, jop, "zoned", zoned, false, NULL,
                          cp, "Added in SBC-4, obsolete in SBC-5");
    sgj_hr_js_vi_nex(jsp, jop, 2, "RBWZ", SGJ_SEP_EQUAL_NO_SPACE,
                     !!(buff[8] & 0x4), false,
                     "Background Operation Control Supported");
    sgj_hr_js_vi_nex(jsp, jop, 2, "FUAB", SGJ_SEP_EQUAL_NO_SPACE,
                     !!(buff[8] & 0x2), false,
                     "Force Unit Access Behaviour");
    sgj_hr_js_vi_nex(jsp, jop, 2, "VBULS", SGJ_SEP_EQUAL_NO_SPACE,
                     !!(buff[8] & 0x1), false,
                     "Verify Byte check Unmapped Lba Supported");
    u = sg_get_unaligned_be32(buff + 12);
    sgj_hr_js_vi_nex(jsp, jop, 2, "DEPOPULATION TIME", SGJ_SEP_COLON_1_SPACE,
                     u, true, "unit: second");
}

static const char * prov_type_arr[8] = {
    "not known or fully provisioned",
    "resource provisioned",
    "thin provisioned",
    rsv_s,
    rsv_s,
    rsv_s,
    rsv_s,
    rsv_s,
};

/* VPD_LB_PROVISIONING   0xb2 ["lbpv"] */
int
decode_block_lb_prov_vpd(uint8_t * buff, int len, struct opts_t * op,
                         sgj_opaque_p jop)
{
    unsigned int u, dp, pt, t_exp;
    sgj_state * jsp = &op->json_st;
    const char * cp;
    char b[1024];
    static const int blen = sizeof(b);
    static const char * mp = "Minimum percentage";
    static const char * tp = "Threshold percentage";
    static const char * pgd = "Provisioning group descriptor";

    if (len < 4) {
        pr2serr("page too short=%d\n", len);
        return SG_LIB_CAT_MALFORMED;
    }
    t_exp = buff[4];
    sgj_js_nv_ihexstr(jsp, jop, "threshold_exponent", t_exp, NULL,
                      (0 == t_exp) ? ns_s : NULL);
    sgj_hr_js_vi_nex(jsp, jop, 2, "LBPU", SGJ_SEP_EQUAL_NO_SPACE,
                     !!(buff[5] & 0x80), false,
                     "Logical Block Provisioning Unmap command supported");
    sgj_hr_js_vi_nex(jsp, jop, 2, "LBPWS", SGJ_SEP_EQUAL_NO_SPACE,
                     !!(buff[5] & 0x40), false, "Logical Block Provisioning "
                     "Write Same (16) command supported");
    sgj_hr_js_vi_nex(jsp, jop, 2, "LBPWS10", SGJ_SEP_EQUAL_NO_SPACE,
                     !!(buff[5] & 0x20), false,
                     "Logical Block Provisioning Write Same (10) command "
                     "supported");
    sgj_hr_js_vi_nex(jsp, jop, 2, "LBPRZ", SGJ_SEP_EQUAL_NO_SPACE,
                     (0x7 & (buff[5] >> 2)), true,
                     "Logical Block Provisioning Read Zero");
    sgj_hr_js_vi_nex(jsp, jop, 2, "ANC_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                     !!(buff[5] & 0x2), false,
                     "ANChor SUPported");
    dp = !!(buff[5] & 0x1);
    sgj_hr_js_vi_nex(jsp, jop, 2, "DP", SGJ_SEP_EQUAL_NO_SPACE,
                     dp, false, "Descriptor Present");
    u = 0x1f & (buff[6] >> 3);  /* minimum percentage */
    if (0 == u)
        sgj_pr_hr(jsp, "  %s: 0 [%s]\n", mp, nr_s);
    else
        sgj_pr_hr(jsp, "  %s: %u\n", mp, u);
    sgj_convert_to_snake_name(mp, b, blen);
    sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, (0 == u) ? nr_s : NULL);
    pt = buff[6] & 0x7;
    cp = prov_type_arr[pt];
    if (pt > 2)
        snprintf(b, blen, " [%u]]", u);
    else
        b[0] = '\0';
    sgj_pr_hr(jsp, "  Provisioning type: %s%s\n", cp, b);
    sgj_js_nv_ihexstr(jsp, jop, "provisioning_type", pt, NULL, cp);
    u = buff[7];        /* threshold percentage */
    snprintf(b, blen, "%s ", tp);
    if (0 == u)
        sgj_pr_hr(jsp, "  %s: 0 [percentages %s]\n", b, ns_s);
    else
        sgj_pr_hr(jsp, "  %s: %u", b, u);
    sgj_convert_to_snake_name(tp, b, blen);
    sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, (0 == u) ? ns_s : NULL);
    if (dp && (len > 11)) {
        int i_len;
        const uint8_t * bp;
        sgj_opaque_p jo2p;

        bp = buff + 8;
        i_len = bp[3];
        if (0 == i_len) {
            pr2serr("%s too short=%d\n", pgd, i_len);
            return 0;
        }
        if (jsp->pr_as_json) {
            jo2p = sgj_snake_named_subobject_r(jsp, jop, pgd);
            sgj_js_designation_descriptor(jsp, jo2p, bp, i_len + 4);
        }
        sgj_pr_hr(jsp, "  %s:\n", pgd);
        sg_get_designation_descriptor_str("    ", bp, i_len + 4, true,
                                          op->do_long, blen, b);
        if (jsp->pr_as_json && jsp->pr_out_hr)
            sgj_js_str_out(jsp, b, strlen(b));
        else
            printf("%s", b);
    }
    return 0;
}

/* VPD_REFERRALS   0xb3 ["ref"] */
void
decode_referrals_vpd(uint8_t * buff, int len, struct opts_t * op,
                     sgj_opaque_p jop)
{
    uint32_t u;
    sgj_state * jsp = &op->json_st;
    char b[64];

    if (len < 16) {
        pr2serr("Referrals VPD page length too short=%d\n", len);
        return;
    }
    u = sg_get_unaligned_be32(buff + 8);
    snprintf(b, sizeof(b), "  User data segment size: ");
    if (0 == u)
        sgj_pr_hr(jsp, "%s0 [per sense descriptor]\n", b);
    else
        sgj_pr_hr(jsp, "%s%u\n", b, u);
    sgj_js_nv_ihex(jsp, jop, "user_data_segment_size", u);
    u = sg_get_unaligned_be32(buff + 12);
    sgj_hr_js_vi(jsp, jop, 2, "User data segment multiplier",
                 SGJ_SEP_COLON_1_SPACE, u, true);
}

/* VPD_SUP_BLOCK_LENS  0xb4 ["sbl"] (added sbc4r01) */
void
decode_sup_block_lens_vpd(uint8_t * buff, int len, struct opts_t * op,
                          sgj_opaque_p jap)
{
    int k;
    unsigned int u;
    uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;

    if (len < 4) {
        pr2serr("page length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += 8, bp += 8) {
        if (jsp->pr_as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        u = sg_get_unaligned_be32(bp);
        sgj_hr_js_vi(jsp, jo2p, 2, "Logical block length",
                     SGJ_SEP_COLON_1_SPACE, u, true);
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "P_I_I_SUP",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[4] & 0x40), false,
                         "Protection Information Interval SUPported");
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "NO_PI_CHK",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[4] & 0x8), false,
                         "NO Protection Information CHecKing");
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "GRD_CHK",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[4] & 0x4), false,
                         "GuaRD CHecK");
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "APP_CHK",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[4] & 0x2), false,
                         "APPlication tag CHecK");
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "REF_CHK",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[4] & 0x1), false,
                         "REFerence tag CHecK");
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "T3PS",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[5] & 0x8), false,
                         "Type 3 Protection Supported");
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "T2PS",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[5] & 0x4), false,
                         "Type 2 Protection Supported");
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "T1PS",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[5] & 0x2), false,
                         "Type 1 Protection Supported");
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "T0PS",
                         SGJ_SEP_COLON_1_SPACE, !!(bp[5] & 0x1), false,
                         "Type 0 Protection Supported");
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}

/* VPD_BLOCK_DEV_C_EXTENS  0xb5 ["bdce"] (added sbc4r02) */
void
decode_block_dev_char_ext_vpd(uint8_t * buff, int len, struct opts_t * op,
                              sgj_opaque_p jop)
{
    bool b_active = false;
    bool combined = false;
    int n;
    uint32_t u;
    sgj_state * jsp = &op->json_st;
    const char * utp = null_s;
    const char * uup = null_s;
    const char * uip = null_s;
    char b[128];
    static const int blen = sizeof(b);

    if (len < 16) {
        pr2serr("page length too short=%d\n", len);
        return;
    }
    switch (buff[5]) {
    case 1:
        utp = "Combined writes and reads";
        combined = true;
        break;
    case 2:
        utp = "Writes only";
        break;
    case 3:
        utp = "Separate writes and reads";
        b_active = true;
        break;
    default:
        utp = rsv_s;
        break;
    }
    sgj_hr_js_vistr(jsp, jop, 2, "Utilization type", SGJ_SEP_COLON_1_SPACE,
                    buff[5], true, utp);
    switch (buff[6]) {
    case 2:
        uup = "megabytes";
        break;
    case 3:
        uup = "gigabytes";
        break;
    case 4:
        uup = "terabytes";
        break;
    case 5:
        uup = "petabytes";
        break;
    case 6:
        uup = "exabytes";
        break;
    default:
        uup = rsv_s;
        break;
    }
    sgj_hr_js_vistr(jsp, jop, 2, "Utilization units", SGJ_SEP_COLON_1_SPACE,
                    buff[6], true, uup);
    switch (buff[7]) {
    case 0xa:
        uip = "per day";
        break;
    case 0xe:
        uip = "per year";
        break;
    default:
        uip = rsv_s;
        break;
    }
    sgj_hr_js_vistr(jsp, jop, 2, "Utilization interval",
                    SGJ_SEP_COLON_1_SPACE, buff[7], true, uip);
    u = sg_get_unaligned_be32(buff + 8);
    sgj_hr_js_vistr(jsp, jop, 2, "Utilization B", SGJ_SEP_COLON_1_SPACE,
                    u, true, (b_active ? NULL : rsv_s));
    n = sg_scnpr(b, blen, "%s: ", "Designed utilization");
    if (b_active)
        n += sg_scnpr(b + n, blen - n, "%u %s for reads and ", u, uup);
    u = sg_get_unaligned_be32(buff + 12);
    sgj_hr_js_vi(jsp, jop, 2, "Utilization A", SGJ_SEP_COLON_1_SPACE, u, true);
    n += sg_scnpr(b + n, blen - n, "%u %s for %swrites, %s", u, uup,
                  combined ? "reads and " : null_s, uip);
    sgj_pr_hr(jsp, "  %s\n", b);
    if (jsp->pr_string)
        sgj_js_nv_s(jsp, jop, "summary", b);
}

/* VPD_ZBC_DEV_CHARS 0xb6  ["zdbch"]  sbc or zbc [zbc2r04] */
void
decode_zbdch_vpd(uint8_t * buff, int len, struct opts_t * op,
                              sgj_opaque_p jop)
{
    uint32_t u, pdt;
    sgj_state * jsp = &op->json_st;
    char b[128];
    static const int blen = sizeof(b);

    if (op->do_hex) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (len < 64) {
        pr2serr("Zoned block device characteristics VPD page length too "
                "short=%d\n", len);
        return;
    }
    pdt = PDT_MASK & buff[0];
    sgj_pr_hr(jsp, "  Peripheral device type: %s\n",
              sg_get_pdt_str(pdt, blen, b));

    printf("  Zoned block device extension: ");
    u = (buff[4] >> 4) & 0xf;
    switch (u) {
    case 0:
        if (PDT_ZBC == (PDT_MASK & buff[0]))
            snprintf(b, blen, "host managed zoned block device");
        else
            snprintf(b, blen, "%s", nr_s);
        break;
    case 1:
        snprintf(b, blen, "host aware zoned block device model");
        break;
    case 2:
        snprintf(b, blen, "Domains and realms zoned block device model");
        break;
    default:
        snprintf(b, blen, "%s", rsv_s);
        break;
    }
    sgj_hr_js_vistr(jsp, jop, 2, "Zoned block device extension",
                    SGJ_SEP_COLON_1_SPACE, u, true, b);
    sgj_hr_js_vi_nex(jsp, jop, 2, "AAORB", SGJ_SEP_COLON_1_SPACE,
                     !!(buff[4] & 0x2), false,
                     "Activation Aligned On Realm Boundaries");
    sgj_hr_js_vi_nex(jsp, jop, 2, "URSWRZ", SGJ_SEP_COLON_1_SPACE,
                     !!(buff[4] & 0x1), false,
                     "Unrestricted Read in Sequential Write Required Zone");
    u = sg_get_unaligned_be32(buff + 8);
    sgj_hr_js_vistr(jsp, jop, 2, "Optimal number of open sequential write "
                    "preferred zones", SGJ_SEP_COLON_1_SPACE, u, true,
                    (SG_LIB_UNBOUNDED_32BIT == u) ? nr_s : NULL);
    u = sg_get_unaligned_be32(buff + 12);
    sgj_hr_js_vistr(jsp, jop, 2, "Optimal number of non-sequentially "
                    "written sequential write preferred zones",
                    SGJ_SEP_COLON_1_SPACE, u, true,
                    (SG_LIB_UNBOUNDED_32BIT == u) ? nr_s : NULL);
    u = sg_get_unaligned_be32(buff + 16);
    sgj_hr_js_vistr(jsp, jop, 2, "Maximum number of open sequential write "
                    "required zones", SGJ_SEP_COLON_1_SPACE, u, true,
                    (SG_LIB_UNBOUNDED_32BIT == u) ? nl_s : NULL);
    u = buff[23] & 0xf;
    switch (u) {
    case 0:
        snprintf(b, blen, "not reported\n");
        break;
    case 1:
        snprintf(b, blen, "Zoned starting LBAs aligned using constant zone "
                 "lengths");
        break;
    case 0x8:
        snprintf(b, blen, "Zoned starting LBAs potentially non-constant (as "
                 "reported by REPORT ZONES)");
        break;
    default:
        snprintf(b, blen, "%s", rsv_s);
        break;
    }
    sgj_hr_js_vistr(jsp, jop, 2, "Zoned alignment method",
                    SGJ_SEP_COLON_1_SPACE, u, true, b);
    sgj_hr_js_vi(jsp, jop, 2, "Zone starting LBA granularity",
                 SGJ_SEP_COLON_1_SPACE, sg_get_unaligned_be64(buff + 24),
                 true);
}

/* VPD_BLOCK_LIMITS_EXT  0xb7 ["ble"] SBC */
void
decode_block_limits_ext_vpd(uint8_t * buff, int len, struct opts_t * op,
                            sgj_opaque_p jop)
{
    uint32_t u;
    sgj_state * jsp = &op->json_st;

    if (op->do_hex) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (len < 12) {
        pr2serr("page length too short=%d\n", len);
        return;
    }
    u = sg_get_unaligned_be16(buff + 6);
    sgj_hr_js_vistr(jsp, jop, 2, "Maximum number of streams",
                    SGJ_SEP_COLON_1_SPACE, u, true,
                    (0 == u) ? "Stream control not supported" : NULL);
    u = sg_get_unaligned_be16(buff + 8);
    sgj_hr_js_vi_nex(jsp, jop, 2, "Optimal stream write size",
                     SGJ_SEP_COLON_1_SPACE, u, true, "unit: LB");
    u = sg_get_unaligned_be32(buff + 10);
    sgj_hr_js_vi_nex(jsp, jop, 2, "Stream granularity size",
                     SGJ_SEP_COLON_1_SPACE, u, true,
                     "unit: number of optimal stream write size blocks");
    if (len < 28)
        return;
    u = sg_get_unaligned_be32(buff + 16);
    sgj_hr_js_vistr_nex(jsp, jop, 2, "Maximum scattered LBA range transfer "
                        "length", SGJ_SEP_COLON_1_SPACE, u, true,
                        (0 == u ? nlr_s : NULL),
                        "unit: LB (in a single LBA range descriptor)");
    u = sg_get_unaligned_be16(buff + 22);
    sgj_hr_js_vistr(jsp, jop, 2, "Maximum scattered LBA range descriptor "
                    "count", SGJ_SEP_COLON_1_SPACE, u, true,
                    (0 == u ? nlr_s : NULL));
    u = sg_get_unaligned_be32(buff + 24);
    sgj_hr_js_vistr_nex(jsp, jop, 2, "Maximum scattered transfer length",
                        SGJ_SEP_COLON_1_SPACE, u, true,
                        (0 == u ? nlr_s : NULL),
                        "unit: LB (per single Write Scattered command)");
}

static const char * sch_type_arr[8] = {
    rsv_s,
    "non-zoned",
    "host aware zoned",
    "host managed zoned",
    "zone domain and realms zoned",
    rsv_s,
    rsv_s,
    rsv_s,
};

static char *
get_zone_align_method(uint8_t val, char * b, int blen)
{
   switch (val) {
    case 0:
        snprintf(b, blen, "%s", nr_s);
        break;
    case 1:
        snprintf(b, blen, "%s", "using constant zone lengths");
        break;
    case 8:
        snprintf(b, blen, "%s", "taking gap zones into account");
        break;
    default:
        snprintf(b, blen, "%s", rsv_s);
        break;
    }
    return b;
}

/* VPD_FORMAT_PRESETS  0xb8 ["fp"] (added sbc4r18) */
void
decode_format_presets_vpd(uint8_t * buff, int len, struct opts_t * op,
                          sgj_opaque_p jap)
{
    uint8_t sch_type;
    int k;
    uint32_t u;
    uint64_t ul;
    sgj_state * jsp = &op->json_st;
    uint8_t * bp;
    sgj_opaque_p jo2p, jo3p;
    const char * cp;
    char b[128];
    char d[64];
    static const int blen = sizeof(b);
    static const int dlen = sizeof(d);
    static const char * llczp = "Low LBA conventional zones percentage";
    static const char * hlczp = "High LBA conventional zones percentage";
    static const char * ztzd = "Zone type for zone domain";

    if (op->do_hex) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += 64, bp += 64) {
        jo2p = sgj_new_unattached_object_r(jsp);
        sgj_hr_js_vi(jsp, jo2p, 2, "Preset identifier", SGJ_SEP_COLON_1_SPACE,
                     sg_get_unaligned_be64(bp + 0), true);
        sch_type = bp[4];
        if (sch_type < 8) {
            cp = sch_type_arr[sch_type];
            if (rsv_s != cp)
                snprintf(b, blen, "%s block device", cp);
            else
                snprintf(b, blen, "%s", cp);
        } else
            snprintf(b, blen, "%s", rsv_s);
        sgj_hr_js_vistr(jsp, jo2p, 4, "Schema type", SGJ_SEP_COLON_1_SPACE,
                        sch_type, true, b);
        sgj_hr_js_vi(jsp, jo2p, 4, "Logical blocks per physical block "
                     "exponent", SGJ_SEP_COLON_1_SPACE,
                     0xf & bp[7], true);
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "Logical block length",
                         SGJ_SEP_COLON_1_SPACE, sg_get_unaligned_be32(bp + 8),
                         true, "unit: byte");
        sgj_hr_js_vi(jsp, jo2p, 4, "Designed last Logical Block Address",
                     SGJ_SEP_COLON_1_SPACE,
                     sg_get_unaligned_be64(bp + 16), true);
        sgj_hr_js_vi_nex(jsp, jo2p, 4, "FMTPINFO", SGJ_SEP_COLON_1_SPACE,
                         (bp[38] >> 6) & 0x3, false,
                         "ForMaT Protecion INFOrmation (see Format Unit)");
        sgj_hr_js_vi(jsp, jo2p, 4, "Protection field usage",
                     SGJ_SEP_COLON_1_SPACE, bp[38] & 0x7, false);
        sgj_hr_js_vi(jsp, jo2p, 4, "Protection interval exponent",
                     SGJ_SEP_COLON_1_SPACE, bp[39] & 0xf, true);
        jo3p = sgj_named_subobject_r(jsp, jo2p,
                                     "schema_type_specific_information");
        switch (sch_type) {
        case 2:
            sgj_pr_hr(jsp, "    Defines zones for host aware device:\n");
            u = bp[40 + 0];
            sgj_pr_hr(jsp, "      %s: %u.%u %%\n", llczp, u / 10, u % 10);
            sgj_convert_to_snake_name(llczp, b, blen);
            sgj_js_nv_ihex_nex(jsp, jo3p, b, u, true, "unit: 1/10 of a "
                               "percent");
            u = bp[40 + 1];
            sgj_pr_hr(jsp, "      %s: %u.%u %%\n", hlczp, u / 10, u % 10);
            sgj_convert_to_snake_name(hlczp, b, blen);
            sgj_js_nv_ihex_nex(jsp, jo3p, b, u, true, "unit: 1/10 of a "
                               "percent");
            u = sg_get_unaligned_be32(bp + 40 + 12);
            sgj_hr_js_vistr(jsp, jo3p, 6, "Logical blocks per zone",
                            SGJ_SEP_COLON_1_SPACE, u, true,
                            (0 == u ? rsv_s : NULL));
            break;
        case 3:
            sgj_pr_hr(jsp, "    Defines zones for host managed device:\n");
            u = bp[40 + 0];
            sgj_pr_hr(jsp, "      %s: %u.%u %%\n", llczp, u / 10, u % 10);
            sgj_convert_to_snake_name(llczp, b, blen);
            sgj_js_nv_ihex_nex(jsp, jo3p, b, u, true, "unit: 1/10 of a "
                               "percent");
            u = bp[40 + 1];
            sgj_pr_hr(jsp, "      %s: %u.%u %%\n", hlczp, u / 10, u % 10);
            sgj_convert_to_snake_name(hlczp, b, blen);
            sgj_js_nv_ihex_nex(jsp, jo3p, b, u, true, "unit: 1/10 of a "
                               "percent");
            u = bp[40 + 3] & 0x7;
            sgj_hr_js_vistr(jsp, jo3p, 6, "Designed zone alignment method",
                            SGJ_SEP_COLON_1_SPACE, u, true,
                            get_zone_align_method(u, b, blen));
            ul = sg_get_unaligned_be64(bp + 40 + 4);
            sgj_hr_js_vi_nex(jsp, jo3p, 6, "Designed zone starting LBA "
                             "granularity", SGJ_SEP_COLON_1_SPACE, ul, true,
                             "unit: LB");
            u = sg_get_unaligned_be32(bp + 40 + 12);
            sgj_hr_js_vistr(jsp, jo3p, 6, "Logical blocks per zone",
                            SGJ_SEP_COLON_1_SPACE, u, true,
                            (0 == u ? rsv_s : NULL));
            break;
        case 4:
            sgj_pr_hr(jsp, "    Defines zones for zone domains and realms "
                      "device:\n");
            snprintf(b, blen, "%s 0", ztzd);
            u = bp[40 + 0];
            sg_get_zone_type_str((u >> 4) & 0xf, dlen, d);
            sgj_hr_js_vistr(jsp, jo3p, 6, b, SGJ_SEP_COLON_1_SPACE, u, true,
                            d);
            snprintf(b, blen, "%s 1", ztzd);
            sg_get_zone_type_str(u & 0xf, dlen, d);
            sgj_hr_js_vistr(jsp, jo3p, 6, b, SGJ_SEP_COLON_1_SPACE, u, true,
                            d);

            snprintf(b, blen, "%s 2", ztzd);
            u = bp[40 + 1];
            sg_get_zone_type_str((u >> 4) & 0xf, dlen, d);
            sgj_hr_js_vistr(jsp, jo3p, 6, b, SGJ_SEP_COLON_1_SPACE, u, true,
                            d);
            snprintf(b, blen, "%s 3", ztzd);
            sg_get_zone_type_str(u & 0xf, dlen, d);
            sgj_hr_js_vistr(jsp, jo3p, 6, b, SGJ_SEP_COLON_1_SPACE, u, true,
                            d);
            u = bp[40 + 3] & 0x7;
            sgj_hr_js_vistr(jsp, jo3p, 6, "Designed zone alignment method",
                            SGJ_SEP_COLON_1_SPACE, u, true,
                            get_zone_align_method(u, d, dlen));
            ul = sg_get_unaligned_be64(bp + 40 + 4);
            sgj_hr_js_vi_nex(jsp, jo3p, 6, "Designed zone starting LBA "
                             "granularity", SGJ_SEP_COLON_1_SPACE, ul, true,
                             "unit: LB");
            u = sg_get_unaligned_be32(bp + 40 + 12);
            sgj_hr_js_vistr(jsp, jo3p, 6, "Logical blocks per zone",
                            SGJ_SEP_COLON_1_SPACE, u, true,
                            (0 == u ? rsv_s : NULL));
            ul = sg_get_unaligned_be64(bp + 40 + 16);
            sgj_hr_js_vi_nex(jsp, jo3p, 6, "Designed zone maximum address",
                             SGJ_SEP_COLON_1_SPACE, ul, true, "unit: LBA");
            break;
        default:
            sgj_pr_hr(jsp, "    No schema type specific information\n");
            break;
        }
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}
