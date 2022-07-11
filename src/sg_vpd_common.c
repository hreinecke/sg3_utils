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

sgj_opaque_p
sg_vpd_js_hdr(sgj_state * jsp, sgj_opaque_p jop, const char * name,
              const uint8_t * vpd_hdrp)
{
    int pdt = vpd_hdrp[0] & PDT_MASK;
    int pqual = (vpd_hdrp[0] & 0xe0) >> 5;
    int pn = vpd_hdrp[1];
    const char * pdt_str;
    sgj_opaque_p jo2p = sgj_new_snake_named_object(jsp, jop, name);
    char d[64];

    pdt_str = sg_get_pdt_str(pdt, sizeof(d), d);
    sgj_add_nv_ihexstr(jsp, jo2p, "peripheral_qualifier",
                       pqual, NULL, pqual_str(pqual));
    sgj_add_nv_ihexstr(jsp, jo2p, "peripheral_device_type",
                       pdt, NULL, pdt_str);
    sgj_add_nv_ihex(jsp, jo2p, "page_code", pn);
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
            jo2p = sgj_new_unattached_object(jsp);
            sgj_add_nv_ihexstr(jsp, jo2p, "association", assoc, NULL,
                               assoc_str);
            sgj_add_nv_ihexstr(jsp, jo2p, "service_type", nst, NULL,
                               nst_str);
            sgj_add_nv_s_len(jsp, jo2p, "network_address",
                             (const char *)(bp + 4), na_len);
            sgj_add_nv_o(jsp, jap, NULL /* name */, jo2p);
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
        sgj_add_nv_ihexstr(jsp, jop, "activate_microcode", n, NULL, cp);
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
        sgj_add_nv_ihexstr_nex(jsp, jop, "spt", n, false, NULL,
                               cp, "Supported Protection Type");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "GRD_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[4] & 0x4), "guard check");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "APP_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[4] & 0x2), "application tag check");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "REF_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[4] & 0x1), "reference tag check");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "UASK_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[5] & 0x20), "Unit Attention condition Sense "
                            "Key specific data Supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "GROUP_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[5] & 0x10), "grouping function supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "PRIOR_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[5] & 0x8), "priority supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "HEADSUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[5] & 0x4), "head of queue supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "ORDSUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[5] & 0x2), "ordered (task attribute) "
                            "supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "SIMPSUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[5] & 0x1), "simple (task attribute) "
                            "supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "WU_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[6] & 0x8), "Write uncorrectable supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "CRD_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[6] & 0x4), "Correction disable supported "
                            "(obsolete SPC-5)");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "NV_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[6] & 0x2), "Nonvolatile cache supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "V_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[6] & 0x1), "Volatile cache supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "NO_PI_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[7] & 0x20), "No protection information "
                            "checking");        /* spc5r02 */
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "P_I_I_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[7] & 0x10), "Protection information "
                            "interval supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "LUICLR", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[7] & 0x1), "Logical unit I_T nexus clear");
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
                cp = "reserved";
                break;
            }
            jo2p = sgj_pr_hr_js_subo(jsp, jop, 2, np, SGJ_SEP_EQUAL_NO_SPACE,
                                     n);
            sgj_add_nv_s(jsp, jo2p, "meaning", cp);
            if (jsp->pr_name_ex)
                sgj_add_nv_s(jsp, jo2p, "abbreviated_name_expansion", nex_p);
        } else
            sgj_pr_hr_js_vi_nex(jsp, jop, 2, np, SGJ_SEP_EQUAL_NO_SPACE, n,
                                nex_p);

        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "R_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[8] & 0x10), "Referrals supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "RTD_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[8] & 0x8), "Revert to defaults supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "HSSRELEF", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[8] & 0x2),
                            "History snapshots release effects");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "CBCS", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[8] & 0x1), "Capability-based command "
                            "security (obsolete SPC-5)");
        sgj_pr_hr_js_vi(jsp, jop, 2, "Multi I_T nexus microcode download",
                        SGJ_SEP_EQUAL_NO_SPACE, b[9] & 0xf);
        sgj_pr_hr_js_vi(jsp, jop, 2, "Extended self-test completion minutes",
                        SGJ_SEP_EQUAL_NO_SPACE,
                        sg_get_unaligned_be16(b + 10));
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "POA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[12] & 0x80),
                            "Power on activation supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "HRA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[12] & 0x40),
                            "Hard reset activation supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "VSA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[12] & 0x20),
                            "Vendor specific activation supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "DMS_VALID", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[12] & 0x10),
                            "Download microcode support byte valid");
        sgj_pr_hr_js_vi(jsp, jop, 2, "Maximum supported sense data length",
                        SGJ_SEP_EQUAL_NO_SPACE, b[13]);
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "IBS", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[14] & 0x80), "Implicit bind supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "IAS", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[14] & 0x40),
                            "Implicit affiliation supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "SAC", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[14] & 0x4),
                            "Set affiliation command supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "NRD1", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[14] & 0x2),
                            "No redirect one supported (BIND)");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "NRD0", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[14] & 0x1),
                            "No redirect zero supported (BIND)");
        sgj_pr_hr_js_vi(jsp, jop, 2, "Maximum inquiry change logs",
                        SGJ_SEP_EQUAL_NO_SPACE,
                        sg_get_unaligned_be16(b + 15));
        sgj_pr_hr_js_vi(jsp, jop, 2, "Maximum mode page change logs",
                        SGJ_SEP_EQUAL_NO_SPACE,
                        sg_get_unaligned_be16(b + 17));
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "DM_MD_4", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[19] & 0x80),
                            "Download microcode mode 4 supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "DM_MD_5", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[19] & 0x40),
                            "Download microcode mode 5 supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "DM_MD_6", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[19] & 0x20),
                            "Download microcode mode 6 supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "DM_MD_7", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[19] & 0x10),
                            "Download microcode mode 7 supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "DM_MD_D", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[19] & 0x8),
                            "Download microcode mode 0xd supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "DM_MD_E", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[19] & 0x4),
                            "Download microcode mode 0xe supported");
        sgj_pr_hr_js_vi_nex(jsp, jop, 2, "DM_MD_F", SGJ_SEP_EQUAL_NO_SPACE,
                            !!(b[19] & 0x2),
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
            jop = sgj_new_unattached_object(jsp);
            sgj_add_nv_ihex(jsp, jop, "ieee_identifier", ieee_id);
            sgj_add_nv_o(jsp, jap, NULL /* name */, jop);
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
            snprintf(b + n, blen - n, "  Policy page code: 0x%x", ppc);
            if (pspc)
                n += snprintf(b + n, blen - n, ",  subpage code: 0x%x", pspc);
            sgj_pr_hr(jsp, "%s\n", b);
            if ((0 == k) && (0x3f == (0x3f & bp[0])) && (0xff == bp[1]))
                sgj_pr_hr(jsp, "  therefore the policy applies to all modes "
                          "pages and subpages\n");
            sgj_pr_hr(jsp, "    MLUS=%d,  Policy: %s\n", !!(bp[2] & 0x80),
                      mode_page_policy_arr[bp[2] & 0x3]);
            if (jsp->pr_as_json) {
                jo2p = sgj_new_unattached_object(jsp);
                sgj_add_nv_ihex(jsp, jo2p, "policy_page_code", ppc);
                sgj_add_nv_ihex(jsp, jo2p, "policy_subpage_code", pspc);
                sgj_add_nv_ihex_nex(jsp, jo2p, "mlus", !!(bp[2] & 0x80), false,
                                    "Multiple logical units share");
                sgj_add_nv_ihexstr(jsp, jo2p, "mode_page_policy", bp[2] & 0x3,
                                   NULL, mode_page_policy_arr[bp[2] & 0x3]);
                sgj_add_nv_o(jsp, jap, NULL /* name */, jo2p);
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
        sgj_add_nv_ihex(jsp, jop, "standby_y", !!(buff[4] & 0x2));
        sgj_add_nv_ihex(jsp, jop, "standby_z", !!(buff[4] & 0x1));
        sgj_add_nv_ihex(jsp, jop, "idle_c", !!(buff[5] & 0x4));
        sgj_add_nv_ihex(jsp, jop, "idle_b", !!(buff[5] & 0x2));
        sgj_add_nv_ihex(jsp, jop, "idle_a", !!(buff[5] & 0x1));
    }
    sgj_pr_hr_js_vi(jsp, jop, 2, "Stopped condition recovery time (ms)",
                    SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 6));
    sgj_pr_hr_js_vi(jsp, jop, 2, "Standby_z condition recovery time (ms)",
                    SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 8));
    sgj_pr_hr_js_vi(jsp, jop, 2, "Standby_y condition recovery time (ms)",
                    SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 10));
    sgj_pr_hr_js_vi(jsp, jop, 2, "Idle_a condition recovery time (ms)",
                    SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 12));
    sgj_pr_hr_js_vi(jsp, jop, 2, "Idle_b condition recovery time (ms)",
                    SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 14));
    sgj_pr_hr_js_vi(jsp, jop, 2, "Idle_c condition recovery time (ms)",
                    SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 16));
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
        jo2p = sgj_new_unattached_object(jsp);
        sgj_pr_js_designation_descriptor(jsp, jo2p, bp, i_len + 4);
        sgj_add_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    if (-2 == u) {
        pr2serr("VPD page error: short designator around offset %d\n", off);
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
}
