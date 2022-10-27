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
#include <assert.h>
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
#include "sg_lib_data.h"
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
static const char * const y_s = "yes";
static const char * const n_s = "no";
static const char * const nl_s = "no limit";
static const char * const nlr_s = "no limit reported";
/* Earlier gcc compilers (e.g. 6.4) don't accept this first form when it is
 * used in another array of strings initialization (e.g. bdc_zoned_strs) */
// static const char * const nr_s = "not reported";
static char nr_s[] = "not reported";
static const char * const ns_s = "not supported";
// static const char * const rsv_s = "Reserved";
static char rsv_s[] = "Reserved";
static const char * const vs_s = "Vendor specific";
static const char * const null_s = "";
static const char * const mn_s = "meaning";

/* Supported vendor specific VPD pages */
/* Arrange in alphabetical order by acronym */
struct svpd_vp_name_t vp_arr[] = {
    {VPD_VP_DDS, "dds", "DDS tape family from IBM"},
    {VPD_VP_EMC, "emc", "EMC (company)"},
    {VPD_VP_WDC_HITACHI, "hit", "WDC/Hitachi disk"},
    {VPD_VP_HP3PAR, "hp3par", "3PAR array (HP was Left Hand)"},
    {VPD_VP_HP_LTO, "hp_lto", "HP LTO tape/systems"},
    {VPD_VP_IBM_LTO, "ibm_lto", "IBM LTO tape/systems"},
    {VPD_VP_NVME, "nvme", "NVMe related"},
    {VPD_VP_RDAC, "rdac", "RDAC array (NetApp E-Series)"},
    {VPD_VP_SEAGATE, "sea", "Seagate disk"},
    {VPD_VP_SG, "sg", "sg3_utils extensions"},
    {VPD_VP_WDC_HITACHI, "wdc", "WDC/Hitachi disk"},
    {0, NULL, NULL},
};

/* Supported vendor specific VPD pages */
/* 'subvalue' holds vendor/product number to disambiguate */
/* Arrange in alphabetical order by acronym */
struct svpd_values_name_t vendor_vpd_pg[] = {
    {VPD_V_ACI_LTO, VPD_VP_HP_LTO, 1, "aci", "ACI revision level (HP LTO)"},
    {VPD_V_DATC_SEA, VPD_VP_SEAGATE, 0, "datc", "Date code (Seagate)"},
    {VPD_V_DCRL_LTO, VPD_VP_IBM_LTO, 1, "dcrl", "Drive component revision "
     "levels (IBM LTO)"},
    {VPD_V_FVER_DDS, VPD_VP_DDS, 1, "ddsver", "Firmware revision (DDS)"},
    {VPD_V_DEV_BEH_SEA, VPD_VP_SEAGATE, 0, "devb", "Device behavior "
     "(Seagate)"},
    {VPD_V_DSN_LTO, VPD_VP_IBM_LTO, 1, "dsn", "Drive serial numbers (IBM "
     "LTO)"},
    {VPD_V_DUCD_LTO, VPD_VP_IBM_LTO, 1, "ducd", "Device unique "
     "configuration data (IBM LTO)"},
    {VPD_V_EDID_RDAC, VPD_VP_RDAC, 0, "edid", "Extended device "
     "identification (RDAC)"},
    {VPD_V_FIRM_SEA, VPD_VP_SEAGATE, 0, "firm", "Firmware numbers "
     "(Seagate)"},
    {VPD_V_FVER_LTO, VPD_VP_HP_LTO, 0, "frl", "Firmware revision level "
     "(HP LTO)"},
    {VPD_V_FVER_RDAC, VPD_VP_RDAC, 0, "fwr4", "Firmware version (RDAC)"},
    {VPD_V_HEAD_LTO, VPD_VP_HP_LTO, 1, "head", "Head Assy revision level "
     "(HP LTO)"},
    {VPD_V_HP3PAR, VPD_VP_HP3PAR, 0, "hp3par", "Volume information "
     "(HP/3PAR)"},
    {VPD_V_HVER_LTO, VPD_VP_HP_LTO, 1, "hrl", "Hardware revision level "
     "(HP LTO)"},
    {VPD_V_HVER_RDAC, VPD_VP_RDAC, 0, "hwr4", "Hardware version (RDAC)"},
    {VPD_V_JUMP_SEA, VPD_VP_SEAGATE, 0, "jump", "Jump setting (Seagate)"},
    {VPD_V_MECH_LTO, VPD_VP_HP_LTO, 1, "mech", "Mechanism revision level "
     "(HP LTO)"},
    {VPD_V_MPDS_LTO, VPD_VP_IBM_LTO, 1, "mpds", "Mode parameter default "
     "settings (IBM LTO)"},
    {SG_NVME_VPD_NICR, VPD_VP_SG, 0, "nicr",
     "NVMe Identify Controller Response (sg3_utils)"},
    {VPD_V_PCA_LTO, VPD_VP_HP_LTO, 1, "pca", "PCA revision level (HP LTO)"},
    {VPD_V_FEAT_RDAC, VPD_VP_RDAC, 0, "prm4", "Feature Parameters (RDAC)"},
    {VPD_V_RVSI_RDAC, VPD_VP_RDAC, 0, "rvsi", "Replicated volume source "
     "identifier (RDAC)"},
    {VPD_V_SAID_RDAC, VPD_VP_RDAC, 0, "said", "Storage array world wide "
     "name (RDAC)"},
    {VPD_V_SUBS_RDAC, VPD_VP_RDAC, 0, "subs", "Subsystem identifier (RDAC)"},
    {VPD_V_SVER_RDAC, VPD_VP_RDAC, 0, "swr4", "Software version (RDAC)"},
    {VPD_V_UPR_EMC, VPD_VP_EMC, 0, "upr", "Unit path report (EMC)"},
    {VPD_V_VAC_RDAC, VPD_VP_RDAC, 0, "vac1", "Volume access control (RDAC)"},
    {VPD_V_HIT_PG3, VPD_VP_WDC_HITACHI, 0, "wp3", "Page 0x3 (WDC/Hitachi)"},
    {VPD_V_HIT_PG_D1, VPD_VP_WDC_HITACHI, 0, "wpd1",
     "Page 0xd1 (WDC/Hitachi)"},
    {VPD_V_HIT_PG_D2, VPD_VP_WDC_HITACHI, 0, "wpd2",
     "Page 0xd2 (WDC/Hitachi)"},
    {0, 0, 0, NULL, NULL},
};


int
no_ascii_4hex(const struct opts_t * op)
{
    if (op->do_hex < 2)
        return 1;
    else if (2 == op->do_hex)
        return 0;
    else
        return -1;
}

int
svpd_find_vp_num_by_acron(const char * vp_ap)
{
    size_t len;
    const struct svpd_vp_name_t * vpp;

    for (vpp = vp_arr; vpp->acron; ++vpp) {
        len = strlen(vpp->acron);
        if (0 == strncmp(vpp->acron, vp_ap, len))
            return vpp->vend_prod_num;
    }
    return -1;
}

/* if vend_prod_num < -1 then list vendor_product ids + vendor pages, =-1
 * list only vendor_product ids, else list pages for that vend_prod_num */
void
svpd_enumerate_vendor(int vend_prod_num)
{
    bool seen;
    const struct svpd_vp_name_t * vpp;
    const struct svpd_values_name_t * vnp;

    if (vend_prod_num < 0) {
        for (seen = false, vpp = vp_arr; vpp->acron; ++vpp) {
            if (vpp->name) {
                if (! seen) {
                    printf("\nVendor/product identifiers:\n");
                    seen = true;
                }
                printf("  %-10s %d      %s\n", vpp->acron,
                       vpp->vend_prod_num, vpp->name);
            }
        }
    }
    if (-1 == vend_prod_num)
        return;
    for (seen = false, vnp = vendor_vpd_pg; vnp->acron; ++vnp) {
        if ((vend_prod_num >= 0) && (vend_prod_num != vnp->subvalue))
            continue;
        if (vnp->name) {
            if (! seen) {
                printf("\nVendor specific VPD pages:\n");
                seen = true;
            }
            printf("  %-10s 0x%02x,%d      %s\n", vnp->acron,
                   vnp->value, vnp->subvalue, vnp->name);
        }
    }
}

/* mxlen is command line --maxlen=LEN option (def: 0) or -1 for a VPD page
 * with a short length (1 byte). Returns 0 for success. */
int     /* global: use by sg_vpd_vendor.c */
vpd_fetch_page(int sg_fd, uint8_t * rp, int page, int mxlen, bool qt,
               int vb, int * rlenp)
{
    int res, resid, rlen, len, n;

    if (sg_fd < 0) {
        len = sg_get_unaligned_be16(rp + 2) + 4;
        if (vb && (len > mxlen))
            pr2serr("warning: VPD page's length (%d) > bytes in --inhex=FN "
                    "file (%d)\n",  len , mxlen);
        if (rlenp)
            *rlenp = (len < mxlen) ? len : mxlen;
        return 0;
    }
    if (mxlen > MX_ALLOC_LEN) {
        pr2serr("--maxlen=LEN too long: %d > %d\n", mxlen, MX_ALLOC_LEN);
        return SG_LIB_SYNTAX_ERROR;
    }
    n = (mxlen > 0) ? mxlen : DEF_ALLOC_LEN;
    res = sg_ll_inquiry_v2(sg_fd, true, page, rp, n, DEF_PT_TIMEOUT, &resid,
                           ! qt, vb);
    if (res)
        return res;
    rlen = n - resid;
    if (rlen < 4) {
        pr2serr("VPD response too short (len=%d)\n", rlen);
        return SG_LIB_CAT_MALFORMED;
    }
    if (page != rp[1]) {
        pr2serr("invalid VPD response; probably a STANDARD INQUIRY "
                "response\n");
        n = (rlen < 32) ? rlen : 32;
        if (vb) {
            pr2serr("First %d bytes of bad response\n", n);
            hex2stderr(rp, n, 0);
        }
        return SG_LIB_CAT_MALFORMED;
    } else if ((0x80 == page) && (0x2 == rp[2]) && (0x2 == rp[3])) {
        /* could be a Unit Serial number VPD page with a very long
         * length of 4+514 bytes; more likely standard response for
         * SCSI-2, RMB=1 and a response_data_format of 0x2. */
        pr2serr("invalid Unit Serial Number VPD response; probably a "
                "STANDARD INQUIRY response\n");
        return SG_LIB_CAT_MALFORMED;
    }
    if (mxlen < 0)
        len = rp[3] + 4;
    else
        len = sg_get_unaligned_be16(rp + 2) + 4;
    if (len <= rlen) {
        if (rlenp)
            *rlenp = len;
        return 0;
    } else if (mxlen) {
        if (rlenp)
            *rlenp = rlen;
        return 0;
    }
    if (len > MX_ALLOC_LEN) {
        pr2serr("response length too long: %d > %d\n", len, MX_ALLOC_LEN);
        return SG_LIB_CAT_MALFORMED;
    } else {
        res = sg_ll_inquiry_v2(sg_fd, true, page, rp, len, DEF_PT_TIMEOUT,
                               &resid, ! qt, vb);
        if (res)
            return res;
        rlen = len - resid;
        /* assume it is well behaved: hence page and len still same */
        if (rlenp)
            *rlenp = rlen;
        return 0;
    }
}

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
decode_net_man_vpd(const uint8_t * buff, int len, struct opts_t * op,
                   sgj_opaque_p jap)
{
    int k, bump, na_len, assoc, nst;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    const uint8_t * bp;
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
decode_x_inq_vpd(const uint8_t * b, int len, bool protect, struct opts_t * op,
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
        } else if (op->protect_not_sure) {
            cp = "Unsure because unable to read PROTECT bit in standard "
                 "INQUIRY response";
            d[0] = '\0';
        } else {
            cp = "none";
            d[0] = '\0';
        }
        if (cp[0])
            snprintf(d, dlen, " [%s]", cp);
        sgj_pr_hr(jsp, "  SPT=%d%s\n", n, d);
        sgj_js_nv_ihexstr_nex(jsp, jop, "spt", n, false, NULL,
                              cp, "Supported Protection Type");
        sgj_haj_vi_nex(jsp, jop, 2, "GRD_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[4] & 0x4), false, "guard check");
        sgj_haj_vi_nex(jsp, jop, 2, "APP_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[4] & 0x2), false, "application tag check");
        sgj_haj_vi_nex(jsp, jop, 2, "REF_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[4] & 0x1), false, "reference tag check");
        sgj_haj_vi_nex(jsp, jop, 2, "UASK_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[5] & 0x20), false, "Unit Attention "
                       "condition Sense Key specific data Supported");
        sgj_haj_vi_nex(jsp, jop, 2, "GROUP_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[5] & 0x10), false, "grouping function supported");
        sgj_haj_vi_nex(jsp, jop, 2, "PRIOR_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[5] & 0x8), false, "priority supported");
        sgj_haj_vi_nex(jsp, jop, 2, "HEADSUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[5] & 0x4), false, "head of queue supported");
        sgj_haj_vi_nex(jsp, jop, 2, "ORDSUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[5] & 0x2), false, "ordered (task attribute) "
                       "supported");
        sgj_haj_vi_nex(jsp, jop, 2, "SIMPSUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[5] & 0x1), false, "simple (task attribute) "
                       "supported");
        sgj_haj_vi_nex(jsp, jop, 2, "WU_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[6] & 0x8), false, "Write uncorrectable "
                       "supported");
        sgj_haj_vi_nex(jsp, jop, 2, "CRD_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[6] & 0x4), false, "Correction disable "
                       "supported (obsolete SPC-5)");
        sgj_haj_vi_nex(jsp, jop, 2, "NV_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[6] & 0x2), false, "Nonvolatile cache "
                       "supported");
        sgj_haj_vi_nex(jsp, jop, 2, "V_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[6] & 0x1), false, "Volatile cache supported");
        sgj_haj_vi_nex(jsp, jop, 2, "NO_PI_CHK", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[7] & 0x20), false, "No protection "
                       "information checking");        /* spc5r02 */
        sgj_haj_vi_nex(jsp, jop, 2, "P_I_I_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[7] & 0x10), false, "Protection information "
                       "interval supported");
        sgj_haj_vi_nex(jsp, jop, 2, "LUICLR", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[7] & 0x1), false, "Logical unit I_T nexus clear");
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
            jo2p = sgj_haj_subo_r(jsp, jop, 2, np, SGJ_SEP_EQUAL_NO_SPACE,
                                  n, false);
            sgj_js_nv_s(jsp, jo2p, mn_s, cp);
            if (jsp->pr_name_ex)
                sgj_js_nv_s(jsp, jo2p, "abbreviated_name_expansion", nex_p);
        } else
            sgj_haj_vi_nex(jsp, jop, 2, np, SGJ_SEP_EQUAL_NO_SPACE, n,
                           true, nex_p);

        sgj_haj_vi_nex(jsp, jop, 2, "R_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[8] & 0x10), false, "Referrals supported");
        sgj_haj_vi_nex(jsp, jop, 2, "RTD_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[8] & 0x8), false,
                       "Revert to defaults supported");
        sgj_haj_vi_nex(jsp, jop, 2, "HSSRELEF", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[8] & 0x2), false,
                       "History snapshots release effects");
        sgj_haj_vi_nex(jsp, jop, 2, "CBCS", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[8] & 0x1), false, "Capability-based command "
                       "security (obsolete SPC-5)");
        sgj_haj_vi(jsp, jop, 2, "Multi I_T nexus microcode download",
                   SGJ_SEP_EQUAL_NO_SPACE, b[9] & 0xf, true);
        sgj_haj_vi(jsp, jop, 2, "Extended self-test completion minutes",
                   SGJ_SEP_EQUAL_NO_SPACE,
                   sg_get_unaligned_be16(b + 10), true);
        sgj_haj_vi_nex(jsp, jop, 2, "POA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[12] & 0x80), false,
                       "Power on activation supported");
        sgj_haj_vi_nex(jsp, jop, 2, "HRA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[12] & 0x40), false,
                       "Hard reset activation supported");
        sgj_haj_vi_nex(jsp, jop, 2, "VSA_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[12] & 0x20), false,
                       "Vendor specific activation supported");
        sgj_haj_vi_nex(jsp, jop, 2, "DMS_VALID", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[12] & 0x10), false,
                       "Download microcode support byte valid");
        sgj_haj_vi(jsp, jop, 2, "Maximum supported sense data length",
                   SGJ_SEP_EQUAL_NO_SPACE, b[13], true);
        sgj_haj_vi_nex(jsp, jop, 2, "IBS", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[14] & 0x80), false, "Implicit bind supported");
        sgj_haj_vi_nex(jsp, jop, 2, "IAS", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[14] & 0x40), false,
                       "Implicit affiliation supported");
        sgj_haj_vi_nex(jsp, jop, 2, "SAC", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[14] & 0x4), false,
                       "Set affiliation command supported");
        sgj_haj_vi_nex(jsp, jop, 2, "NRD1", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[14] & 0x2), false,
                       "No redirect one supported (BIND)");
        sgj_haj_vi_nex(jsp, jop, 2, "NRD0", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[14] & 0x1), false,
                       "No redirect zero supported (BIND)");
        sgj_haj_vi(jsp, jop, 2, "Maximum inquiry change logs",
                   SGJ_SEP_EQUAL_NO_SPACE,
                   sg_get_unaligned_be16(b + 15), true);
        sgj_haj_vi(jsp, jop, 2, "Maximum mode page change logs",
                   SGJ_SEP_EQUAL_NO_SPACE,
                   sg_get_unaligned_be16(b + 17), true);
        sgj_haj_vi_nex(jsp, jop, 2, "DM_MD_4", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[19] & 0x80), false,
                       "Download microcode mode 4 supported");
        sgj_haj_vi_nex(jsp, jop, 2, "DM_MD_5", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[19] & 0x40), false,
                       "Download microcode mode 5 supported");
        sgj_haj_vi_nex(jsp, jop, 2, "DM_MD_6", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[19] & 0x20), false,
                       "Download microcode mode 6 supported");
        sgj_haj_vi_nex(jsp, jop, 2, "DM_MD_7", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[19] & 0x10), false,
                       "Download microcode mode 7 supported");
        sgj_haj_vi_nex(jsp, jop, 2, "DM_MD_D", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[19] & 0x8), false,
                       "Download microcode mode 0xd supported");
        sgj_haj_vi_nex(jsp, jop, 2, "DM_MD_E", SGJ_SEP_EQUAL_NO_SPACE,
                       !!(b[19] & 0x4), false,
                       "Download microcode mode 0xe supported");
        sgj_haj_vi_nex(jsp, jop, 2, "DM_MD_F", SGJ_SEP_EQUAL_NO_SPACE,
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
decode_softw_inf_id(const uint8_t * buff, int len, struct opts_t * op,
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
decode_mode_policy_vpd(const uint8_t * buff, int len, struct opts_t * op,
                       sgj_opaque_p jap)
{
    int k, n, bump, ppc, pspc;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    const uint8_t * bp;
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
            n = sg_scnpr(b + n, blen - n, "  Policy page code: 0x%x", ppc);
            if (pspc)
                n += sg_scnpr(b + n, blen - n, ",  subpage code: 0x%x", pspc);
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
decode_power_condition(const uint8_t * buff, int len, struct opts_t * op,
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
    sgj_haj_vi_nex(jsp, jop, 2, "Stopped condition recovery time",
                   SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 6),
                   true, "unit: millisecond");
    sgj_haj_vi_nex(jsp, jop, 2, "Standby_z condition recovery time",
                   SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 8),
                   true, "unit: millisecond");
    sgj_haj_vi_nex(jsp, jop, 2, "Standby_y condition recovery time",
                   SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 10),
                   true, "unit: millisecond");
    sgj_haj_vi_nex(jsp, jop, 2, "Idle_a condition recovery time",
                   SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 12),
                   true, "unit: millisecond");
    sgj_haj_vi_nex(jsp, jop, 2, "Idle_b condition recovery time",
                   SGJ_SEP_SPACE_1, sg_get_unaligned_be16(buff + 14),
                   true, "unit: millisecond");
    sgj_haj_vi_nex(jsp, jop, 2, "Idle_c condition recovery time",
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
    n = sg_scnpr(b, blen, "  Command code: 0x%x\n", cc);
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
decode_feature_sets_vpd(const uint8_t * buff, int len, struct opts_t * op,
                        sgj_opaque_p jap)
{
    int k, bump;
    uint16_t sf_code;
    bool found;
    const uint8_t * bp;
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

/* VPD_CFA_PROFILE_INFO  0x8c ["cfa"] */
void
decode_cga_profile_vpd(const uint8_t * buff, int len, struct opts_t * op,
                       sgj_opaque_p jap)
{
    int k;
    uint32_t u;
    sgj_state * jsp = &op->json_st;
    const uint8_t * bp;
    sgj_opaque_p jo2p;

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
    for (k = 0; k < len; k += 4, bp += 4) {
        jo2p = sgj_new_unattached_object_r(jsp);
        sgj_haj_vi(jsp, jo2p, 0, "CGA profile supported",
                   SGJ_SEP_COLON_1_SPACE, bp[0], true);
        u = sg_get_unaligned_be16(bp + 2);
        sgj_haj_vi_nex(jsp, jo2p, 2, "Sequential write data size",
                       SGJ_SEP_COLON_1_SPACE, u, true, "unit: LB");
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
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
decode_power_consumption(const uint8_t * buff, int len, struct opts_t * op,
                         sgj_opaque_p jap)
{
    int k, bump, pcmp_id, pcmp_unit;
    unsigned int pcmp_val;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    const uint8_t * bp;
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
        sgj_haj_vi_nex(jsp, jop, 2, mcawl, SGJ_SEP_COLON_1_SPACE, u,
                       true, "unit: LB");

    u = sg_get_unaligned_be16(buff + 6);
    if (0 == u) {
        sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", otlg, nr_s);
        sgj_convert_to_snake_name(otlg, b, blen);
        sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
    } else
        sgj_haj_vi_nex(jsp, jop, 2, otlg, SGJ_SEP_COLON_1_SPACE, u,
                       true, "unit: LB");

    u = sg_get_unaligned_be32(buff + 8);
    if (0 == u) {
        sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mtl, nr_s);
        sgj_convert_to_snake_name(mtl, b, blen);
        sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
    } else
        sgj_haj_vi_nex(jsp, jop, 2, mtl, SGJ_SEP_COLON_1_SPACE, u,
                       true, "unit: LB");

    u = sg_get_unaligned_be32(buff + 12);
    if (0 == u) {
        sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", otl, nr_s);
        sgj_convert_to_snake_name(otl, b, blen);
        sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
    } else
        sgj_haj_vi_nex(jsp, jop, 2, otl, SGJ_SEP_COLON_1_SPACE, u,
                       true, "unit: LB");
    if (len > 19) {     /* added in sbc3r09 */
        u = sg_get_unaligned_be32(buff + 16);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mpl, nr_s);
            sgj_convert_to_snake_name(mpl, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
        } else
            sgj_haj_vi_nex(jsp, jop, 2, mpl, SGJ_SEP_COLON_1_SPACE, u,
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
            sgj_haj_vi_nex(jsp, jop, 2, mulc, SGJ_SEP_COLON_1_SPACE, u,
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
            sgj_haj_vi(jsp, jop, 2, mubdc, SGJ_SEP_COLON_1_SPACE,
                       u, true);
    }
    if (len > 35) {     /* added in sbc3r19 */
        u = sg_get_unaligned_be32(buff + 28);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", oug, nr_s);
            sgj_convert_to_snake_name(oug, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
        } else
            sgj_haj_vi_nex(jsp, jop, 2, oug, SGJ_SEP_COLON_1_SPACE, u,
                           true, "unit: LB");

        ugavalid = !!(buff[32] & 0x80);
        sgj_pr_hr(jsp, "  %s: %s\n", ugav, ugavalid ? "true" : "false");
        sgj_js_nv_i(jsp, jop, ugav, ugavalid);
        if (ugavalid) {
            u = 0x7fffffff & sg_get_unaligned_be32(buff + 32);
            sgj_haj_vi_nex(jsp, jop, 2, uga, SGJ_SEP_COLON_1_SPACE, u,
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
            sgj_haj_vi_nex(jsp, jop, 2, mwsl, SGJ_SEP_COLON_1_SPACE,
                           ull, true, "unit: LB");
    }
    if (len > 47) {     /* added in sbc4r02 */
        u = sg_get_unaligned_be32(buff + 44);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", matl, nr_s);
            sgj_convert_to_snake_name(matl, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
        } else
            sgj_haj_vi_nex(jsp, jop, 2, matl, SGJ_SEP_COLON_1_SPACE,
                           u, true, "unit: LB");

        u = sg_get_unaligned_be32(buff + 48);
        if (0 == u) {
            static const char * uawp = "unaligned atomic writes permitted";

            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", aa, uawp);
            sgj_convert_to_snake_name(aa, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, uawp);
        } else
            sgj_haj_vi_nex(jsp, jop, 2, aa, SGJ_SEP_COLON_1_SPACE,
                           u, true, "unit: LB");

        u = sg_get_unaligned_be32(buff + 52);
        if (0 == u) {
            static const char * ngr = "no granularity requirement";

            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", atlg, ngr);
            sgj_convert_to_snake_name(atlg, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, ngr);
        } else
            sgj_haj_vi_nex(jsp, jop, 2, aa, SGJ_SEP_COLON_1_SPACE,
                           u, true, "unit: LB");
    }
    if (len > 56) {
        u = sg_get_unaligned_be32(buff + 56);
        if (0 == u) {
            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", matlwab, nr_s);
            sgj_convert_to_snake_name(matlwab, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, nr_s);
        } else
            sgj_haj_vi_nex(jsp, jop, 2, matlwab, SGJ_SEP_COLON_1_SPACE,
                           u, true, "unit: LB");

        u = sg_get_unaligned_be32(buff + 60);
        if (0 == u) {
            static const char * cowa1b = "can only write atomic 1 block";

            sgj_pr_hr(jsp, "  %s: 0 blocks [%s]\n", mabs, cowa1b);
            sgj_convert_to_snake_name(mabs, b, blen);
            sgj_js_nv_ihexstr(jsp, jop, b, u, NULL, cowa1b);
        } else
            sgj_haj_vi_nex(jsp, jop, 2, mabs, SGJ_SEP_COLON_1_SPACE,
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
    sgj_haj_vi_nex(jsp, jop, 2, "WABEREQ", SGJ_SEP_EQUAL_NO_SPACE,
                   (buff[7] >> 6) & 0x3, false,
                   "Write After Block Erase REQuired");
    sgj_haj_vi_nex(jsp, jop, 2, "WACEREQ", SGJ_SEP_EQUAL_NO_SPACE,
                   (buff[7] >> 4) & 0x3, false,
                   "Write After Cryptographic Erase REQuired");
    u = buff[7] & 0xf;
    switch (u) {
    case 0:
        strcpy(b, nr_s);
        break;
    case 1:
        strcpy(b, "5.25 inch");
        break;
    case 2:
        strcpy(b, "3.5 inch");
        break;
    case 3:
        strcpy(b, "2.5 inch");
        break;
    case 4:
        strcpy(b, "1.8 inch");
        break;
    case 5:
        strcpy(b, "less then 1.8 inch");
        break;
    default:
        strcpy(b, rsv_s);
        break;
    }
    sgj_pr_hr(jsp, "  Nominal form factor: %s\n", b);
    sgj_js_nv_ihexstr(jsp, jop, "nominal_forn_factor", u, NULL, b);
    sgj_haj_vi_nex(jsp, jop, 2, "MACT", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(buff[8] & 0x40), false, "Multiple ACTuator");
    zoned = (buff[8] >> 4) & 0x3;   /* added sbc4r04, obsolete sbc5r01 */
    cp = bdc_zoned_strs[zoned];
    sgj_pr_hr(jsp, "  ZONED=%d [%s]\n", zoned, cp);
    sgj_js_nv_ihexstr_nex(jsp, jop, "zoned", zoned, false, NULL,
                          cp, "Added in SBC-4, obsolete in SBC-5");
    sgj_haj_vi_nex(jsp, jop, 2, "RBWZ", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(buff[8] & 0x4), false,
                   "Background Operation Control Supported");
    sgj_haj_vi_nex(jsp, jop, 2, "FUAB", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(buff[8] & 0x2), false,
                   "Force Unit Access Behaviour");
    sgj_haj_vi_nex(jsp, jop, 2, "VBULS", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(buff[8] & 0x1), false,
                   "Verify Byte check Unmapped Lba Supported");
    u = sg_get_unaligned_be32(buff + 12);
    sgj_haj_vi_nex(jsp, jop, 2, "DEPOPULATION TIME", SGJ_SEP_COLON_1_SPACE,
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
decode_block_lb_prov_vpd(const uint8_t * buff, int len, struct opts_t * op,
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
    sgj_haj_vi_nex(jsp, jop, 2, "LBPU", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(buff[5] & 0x80), false,
                   "Logical Block Provisioning Unmap command supported");
    sgj_haj_vi_nex(jsp, jop, 2, "LBPWS", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(buff[5] & 0x40), false, "Logical Block Provisioning "
                   "Write Same (16) command supported");
    sgj_haj_vi_nex(jsp, jop, 2, "LBPWS10", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(buff[5] & 0x20), false, "Logical Block Provisioning "
                   "Write Same (10) command supported");
    sgj_haj_vi_nex(jsp, jop, 2, "LBPRZ", SGJ_SEP_EQUAL_NO_SPACE,
                   (0x7 & (buff[5] >> 2)), true,
                   "Logical Block Provisioning Read Zero");
    sgj_haj_vi_nex(jsp, jop, 2, "ANC_SUP", SGJ_SEP_EQUAL_NO_SPACE,
                   !!(buff[5] & 0x2), false,
                   "ANChor SUPported");
    dp = !!(buff[5] & 0x1);
    sgj_haj_vi_nex(jsp, jop, 2, "DP", SGJ_SEP_EQUAL_NO_SPACE,
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
        snprintf(b, blen, " [%u]", u);
    else
        b[0] = '\0';
    sgj_pr_hr(jsp, "  Provisioning type: %s%s\n", cp, b);
    sgj_js_nv_ihexstr(jsp, jop, "provisioning_type", pt, NULL, cp);
    u = buff[7];        /* threshold percentage */
    strcpy(b, tp);
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
            sgj_pr_hr(jsp, "%s", b);
    }
    return 0;
}

/* VPD_REFERRALS   0xb3 ["ref"] */
void
decode_referrals_vpd(const uint8_t * buff, int len, struct opts_t * op,
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
    strcpy(b, "  User data segment size: ");
    if (0 == u)
        sgj_pr_hr(jsp, "%s0 [per sense descriptor]\n", b);
    else
        sgj_pr_hr(jsp, "%s%u\n", b, u);
    sgj_js_nv_ihex(jsp, jop, "user_data_segment_size", u);
    u = sg_get_unaligned_be32(buff + 12);
    sgj_haj_vi(jsp, jop, 2, "User data segment multiplier",
               SGJ_SEP_COLON_1_SPACE, u, true);
}

/* VPD_SUP_BLOCK_LENS  0xb4 ["sbl"] (added sbc4r01) */
void
decode_sup_block_lens_vpd(const uint8_t * buff, int len, struct opts_t * op,
                          sgj_opaque_p jap)
{
    int k;
    unsigned int u;
    const uint8_t * bp;
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
        sgj_haj_vi(jsp, jo2p, 2, "Logical block length",
                   SGJ_SEP_COLON_1_SPACE, u, true);
        sgj_haj_vi_nex(jsp, jo2p, 4, "P_I_I_SUP",
                       SGJ_SEP_COLON_1_SPACE, !!(bp[4] & 0x40), false,
                       "Protection Information Interval SUPported");
        sgj_haj_vi_nex(jsp, jo2p, 4, "NO_PI_CHK",
                       SGJ_SEP_COLON_1_SPACE, !!(bp[4] & 0x8), false,
                       "NO Protection Information CHecKing");
        sgj_haj_vi_nex(jsp, jo2p, 4, "GRD_CHK", SGJ_SEP_COLON_1_SPACE,
                       !!(bp[4] & 0x4), false, "GuaRD CHecK");
        sgj_haj_vi_nex(jsp, jo2p, 4, "APP_CHK", SGJ_SEP_COLON_1_SPACE,
                       !!(bp[4] & 0x2), false, "APPlication tag CHecK");
        sgj_haj_vi_nex(jsp, jo2p, 4, "REF_CHK", SGJ_SEP_COLON_1_SPACE,
                       !!(bp[4] & 0x1), false, "REFerence tag CHecK");
        sgj_haj_vi_nex(jsp, jo2p, 4, "T3PS", SGJ_SEP_COLON_1_SPACE,
                       !!(bp[5] & 0x8), false, "Type 3 Protection Supported");
        sgj_haj_vi_nex(jsp, jo2p, 4, "T2PS", SGJ_SEP_COLON_1_SPACE,
                       !!(bp[5] & 0x4), false, "Type 2 Protection Supported");
        sgj_haj_vi_nex(jsp, jo2p, 4, "T1PS", SGJ_SEP_COLON_1_SPACE,
                       !!(bp[5] & 0x2), false, "Type 1 Protection Supported");
        sgj_haj_vi_nex(jsp, jo2p, 4, "T0PS", SGJ_SEP_COLON_1_SPACE,
                       !!(bp[5] & 0x1), false, "Type 0 Protection Supported");
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}

/* VPD_BLOCK_DEV_C_EXTENS  0xb5 ["bdce"] (added sbc4r02) */
void
decode_block_dev_char_ext_vpd(const uint8_t * buff, int len,
                              struct opts_t * op, sgj_opaque_p jop)
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
    sgj_haj_vistr(jsp, jop, 2, "Utilization type", SGJ_SEP_COLON_1_SPACE,
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
    sgj_haj_vistr(jsp, jop, 2, "Utilization units", SGJ_SEP_COLON_1_SPACE,
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
    sgj_haj_vistr(jsp, jop, 2, "Utilization interval", SGJ_SEP_COLON_1_SPACE,
                  buff[7], true, uip);
    u = sg_get_unaligned_be32(buff + 8);
    sgj_haj_vistr(jsp, jop, 2, "Utilization B", SGJ_SEP_COLON_1_SPACE,
                  u, true, (b_active ? NULL : rsv_s));
    n = sg_scnpr(b, blen, "%s: ", "Designed utilization");
    if (b_active)
        n += sg_scnpr(b + n, blen - n, "%u %s for reads and ", u, uup);
    u = sg_get_unaligned_be32(buff + 12);
    sgj_haj_vi(jsp, jop, 2, "Utilization A", SGJ_SEP_COLON_1_SPACE, u, true);
    n += sg_scnpr(b + n, blen - n, "%u %s for %swrites, %s", u, uup,
                  combined ? "reads and " : null_s, uip);
    sgj_pr_hr(jsp, "  %s\n", b);
    if (jsp->pr_string)
        sgj_js_nv_s(jsp, jop, "summary", b);
}

/* VPD_ZBC_DEV_CHARS 0xb6  ["zdbch"]  sbc or zbc [zbc2r04] */
void
decode_zbdch_vpd(const uint8_t * buff, int len, struct opts_t * op,
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

    sgj_pr_hr(jsp, "  Zoned block device extension: ");
    u = (buff[4] >> 4) & 0xf;
    switch (u) {
    case 0:
        if (PDT_ZBC == (PDT_MASK & buff[0]))
            strcpy(b, "host managed zoned block device");
        else
            strcpy(b, nr_s);
        break;
    case 1:
        strcpy(b, "host aware zoned block device model");
        break;
    case 2:
        strcpy(b, "Domains and realms zoned block device model");
        break;
    default:
        strcpy(b, rsv_s);
        break;
    }
    sgj_haj_vistr(jsp, jop, 2, "Zoned block device extension",
                  SGJ_SEP_COLON_1_SPACE, u, true, b);
    sgj_haj_vi_nex(jsp, jop, 2, "AAORB", SGJ_SEP_COLON_1_SPACE,
                   !!(buff[4] & 0x2), false,
                   "Activation Aligned On Realm Boundaries");
    sgj_haj_vi_nex(jsp, jop, 2, "URSWRZ", SGJ_SEP_COLON_1_SPACE,
                   !!(buff[4] & 0x1), false,
                   "Unrestricted Read in Sequential Write Required Zone");
    u = sg_get_unaligned_be32(buff + 8);
    sgj_haj_vistr(jsp, jop, 2, "Optimal number of open sequential write "
                  "preferred zones", SGJ_SEP_COLON_1_SPACE, u, true,
                  (SG_LIB_UNBOUNDED_32BIT == u) ? nr_s : NULL);
    u = sg_get_unaligned_be32(buff + 12);
    sgj_haj_vistr(jsp, jop, 2, "Optimal number of non-sequentially "
                  "written sequential write preferred zones",
                  SGJ_SEP_COLON_1_SPACE, u, true,
                  (SG_LIB_UNBOUNDED_32BIT == u) ? nr_s : NULL);
    u = sg_get_unaligned_be32(buff + 16);
    sgj_haj_vistr(jsp, jop, 2, "Maximum number of open sequential write "
                  "required zones", SGJ_SEP_COLON_1_SPACE, u, true,
                  (SG_LIB_UNBOUNDED_32BIT == u) ? nl_s : NULL);
    u = buff[23] & 0xf;
    switch (u) {
    case 0:
        strcpy(b, nr_s);
        break;
    case 1:
        strcpy(b, "Zoned starting LBAs aligned using constant zone lengths");
        break;
    case 0x8:
        strcpy(b, "Zoned starting LBAs potentially non-constant (as "
                 "reported by REPORT ZONES)");
        break;
    default:
        strcpy(b, rsv_s);
        break;
    }
    sgj_haj_vistr(jsp, jop, 2, "Zoned alignment method",
                  SGJ_SEP_COLON_1_SPACE, u, true, b);
    sgj_haj_vi(jsp, jop, 2, "Zone starting LBA granularity",
               SGJ_SEP_COLON_1_SPACE, sg_get_unaligned_be64(buff + 24), true);
}

/* VPD_BLOCK_LIMITS_EXT  0xb7 ["ble"] SBC */
void
decode_block_limits_ext_vpd(const uint8_t * buff, int len, struct opts_t * op,
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
    sgj_haj_vistr(jsp, jop, 2, "Maximum number of streams",
                  SGJ_SEP_COLON_1_SPACE, u, true,
                  (0 == u) ? "Stream control not supported" : NULL);
    u = sg_get_unaligned_be16(buff + 8);
    sgj_haj_vi_nex(jsp, jop, 2, "Optimal stream write size",
                   SGJ_SEP_COLON_1_SPACE, u, true, "unit: LB");
    u = sg_get_unaligned_be32(buff + 10);
    sgj_haj_vi_nex(jsp, jop, 2, "Stream granularity size",
                   SGJ_SEP_COLON_1_SPACE, u, true,
                   "unit: number of optimal stream write size blocks");
    if (len < 28)
        return;
    u = sg_get_unaligned_be32(buff + 16);
    sgj_haj_vistr_nex(jsp, jop, 2, "Maximum scattered LBA range transfer "
                      "length", SGJ_SEP_COLON_1_SPACE, u, true,
                      (0 == u ? nlr_s : NULL),
                      "unit: LB (in a single LBA range descriptor)");
    u = sg_get_unaligned_be16(buff + 22);
    sgj_haj_vistr(jsp, jop, 2, "Maximum scattered LBA range descriptor "
                  "count", SGJ_SEP_COLON_1_SPACE, u, true,
                  (0 == u ? nlr_s : NULL));
    u = sg_get_unaligned_be32(buff + 24);
    sgj_haj_vistr_nex(jsp, jop, 2, "Maximum scattered transfer length",
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
   assert(blen > 32);
   switch (val) {
    case 0:
        strcpy(b, nr_s);
        break;
    case 1:
        strcpy(b, "using constant zone lengths");
        break;
    case 8:
        strcpy(b, "taking gap zones into account");
        break;
    default:
        strcpy(b, rsv_s);
        break;
    }
    return b;
}

/* VPD_FORMAT_PRESETS  0xb8 ["fp"] (added sbc4r18) */
void
decode_format_presets_vpd(const uint8_t * buff, int len, struct opts_t * op,
                          sgj_opaque_p jap)
{
    uint8_t sch_type;
    int k;
    uint32_t u;
    uint64_t ul;
    sgj_state * jsp = &op->json_st;
    const uint8_t * bp;
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
        sgj_haj_vi(jsp, jo2p, 2, "Preset identifier", SGJ_SEP_COLON_1_SPACE,
                   sg_get_unaligned_be64(bp + 0), true);
        sch_type = bp[4];
        if (sch_type < 8) {
            cp = sch_type_arr[sch_type];
            if (rsv_s != cp)
                snprintf(b, blen, "%s block device", cp);
            else
                snprintf(b, blen, "%s", cp);
        } else
            strcpy(b, rsv_s);
        sgj_haj_vistr(jsp, jo2p, 4, "Schema type", SGJ_SEP_COLON_1_SPACE,
                      sch_type, true, b);
        sgj_haj_vi(jsp, jo2p, 4, "Logical blocks per physical block "
                   "exponent", SGJ_SEP_COLON_1_SPACE,
                   0xf & bp[7], true);
        sgj_haj_vi_nex(jsp, jo2p, 4, "Logical block length",
                       SGJ_SEP_COLON_1_SPACE, sg_get_unaligned_be32(bp + 8),
                       true, "unit: byte");
        sgj_haj_vi(jsp, jo2p, 4, "Designed last Logical Block Address",
                   SGJ_SEP_COLON_1_SPACE,
                   sg_get_unaligned_be64(bp + 16), true);
        sgj_haj_vi_nex(jsp, jo2p, 4, "FMTPINFO", SGJ_SEP_COLON_1_SPACE,
                       (bp[38] >> 6) & 0x3, false,
                       "ForMaT Protection INFOrmation (see Format Unit)");
        sgj_haj_vi(jsp, jo2p, 4, "Protection field usage",
                   SGJ_SEP_COLON_1_SPACE, bp[38] & 0x7, false);
        sgj_haj_vi(jsp, jo2p, 4, "Protection interval exponent",
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
            sgj_haj_vistr(jsp, jo3p, 6, "Logical blocks per zone",
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
            sgj_haj_vistr(jsp, jo3p, 6, "Designed zone alignment method",
                           SGJ_SEP_COLON_1_SPACE, u, true,
                           get_zone_align_method(u, d, dlen));
            ul = sg_get_unaligned_be64(bp + 40 + 4);
            sgj_haj_vi_nex(jsp, jo3p, 6, "Designed zone starting LBA "
                           "granularity", SGJ_SEP_COLON_1_SPACE, ul, true,
                           "unit: LB");
            u = sg_get_unaligned_be32(bp + 40 + 12);
            sgj_haj_vistr(jsp, jo3p, 6, "Logical blocks per zone",
                          SGJ_SEP_COLON_1_SPACE, u, true,
                          (0 == u ? rsv_s : NULL));
            break;
        case 4:
            sgj_pr_hr(jsp, "    Defines zones for zone domains and realms "
                      "device:\n");
            snprintf(b, blen, "%s 0", ztzd);
            u = bp[40 + 0];
            sg_get_zone_type_str((u >> 4) & 0xf, dlen, d);
            sgj_haj_vistr(jsp, jo3p, 6, b, SGJ_SEP_COLON_1_SPACE, u, true, d);
            snprintf(b, blen, "%s 1", ztzd);
            sg_get_zone_type_str(u & 0xf, dlen, d);
            sgj_haj_vistr(jsp, jo3p, 6, b, SGJ_SEP_COLON_1_SPACE, u, true, d);

            snprintf(b, blen, "%s 2", ztzd);
            u = bp[40 + 1];
            sg_get_zone_type_str((u >> 4) & 0xf, dlen, d);
            sgj_haj_vistr(jsp, jo3p, 6, b, SGJ_SEP_COLON_1_SPACE, u, true, d);
            snprintf(b, blen, "%s 3", ztzd);
            sg_get_zone_type_str(u & 0xf, dlen, d);
            sgj_haj_vistr(jsp, jo3p, 6, b, SGJ_SEP_COLON_1_SPACE, u, true, d);
            u = bp[40 + 3] & 0x7;
            sgj_haj_vistr(jsp, jo3p, 6, "Designed zone alignment method",
                          SGJ_SEP_COLON_1_SPACE, u, true,
                          get_zone_align_method(u, d, dlen));
            ul = sg_get_unaligned_be64(bp + 40 + 4);
            sgj_haj_vi_nex(jsp, jo3p, 6, "Designed zone starting LBA "
                           "granularity", SGJ_SEP_COLON_1_SPACE, ul, true,
                           "unit: LB");
            u = sg_get_unaligned_be32(bp + 40 + 12);
            sgj_haj_vistr(jsp, jo3p, 6, "Logical blocks per zone",
                          SGJ_SEP_COLON_1_SPACE, u, true,
                          (0 == u ? rsv_s : NULL));
            ul = sg_get_unaligned_be64(bp + 40 + 16);
            sgj_haj_vi_nex(jsp, jo3p, 6, "Designed zone maximum address",
                           SGJ_SEP_COLON_1_SPACE, ul, true, "unit: LBA");
            break;
        default:
            sgj_pr_hr(jsp, "    No schema type specific information\n");
            break;
        }
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}

/* VPD_CON_POS_RANGE  0xb9 (added sbc5r01) */
void
decode_con_pos_range_vpd(const uint8_t * buff, int len, struct opts_t * op,
                         sgj_opaque_p jap)
{
    int k;
    uint32_t u;
    sgj_state * jsp = &op->json_st;
    const uint8_t * bp;
    sgj_opaque_p jo2p;

    if (op->do_hex) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (len < 64) {
        pr2serr("VPD page length too short=%d\n", len);
        return;
    }
    len -= 64;
    bp = buff + 64;
    for (k = 0; k < len; k += 32, bp += 32) {
        jo2p = sgj_new_unattached_object_r(jsp);
        sgj_haj_vi(jsp, jo2p, 2, "LBA range number",
                   SGJ_SEP_COLON_1_SPACE, bp[0], true);
        u = bp[1];
        sgj_haj_vistr(jsp, jo2p, 4, "Number of storage elements",
                      SGJ_SEP_COLON_1_SPACE, u, true, (0 == u ? nr_s : NULL));
        sgj_haj_vi(jsp, jo2p, 4, "Starting LBA", SGJ_SEP_COLON_1_SPACE,
                   sg_get_unaligned_be64(bp + 8), true);
        sgj_haj_vi(jsp, jo2p, 4, "Number of LBAs", SGJ_SEP_COLON_1_SPACE,
                   sg_get_unaligned_be64(bp + 16), true);
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}

/* This is xcopy(LID4) related: "ROD" == Representation Of Data
 * Used by VPD_3PARTY_COPY   0x8f ["tpc"] */
static void
decode_rod_descriptor(const uint8_t * buff, int len, struct opts_t * op,
                      sgj_opaque_p jap)
{
    uint8_t pdt;
    uint32_t u;
    int k, bump;
    uint64_t ull;
    const uint8_t * bp = buff;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    char b[80];
    static const int blen = sizeof(b);
    static const char * ab_pdt = "abnormal use of 'pdt'";

    for (k = 0; k < len; k += bump, bp += bump) {
        jo2p = sgj_new_unattached_object_r(jsp);
        bump = sg_get_unaligned_be16(bp + 2) + 4;
        pdt = 0x1f & bp[0];
        u = (bp[0] >> 5) & 0x7;
        sgj_js_nv_i(jsp, jo2p, "descriptor_format", u);
        if (0 != u) {
            sgj_pr_hr(jsp, "  Unhandled descriptor (format %u, device type "
                      "%u)\n", u, pdt);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            break;
        }
        switch (pdt) {
        case 0:
            /* Block ROD device type specific descriptor */
            sgj_js_nv_ihexstr_nex(jsp, jo2p, "peripheral_device_type",
                                  pdt, false, NULL, "Block ROD device "
                                  "type specific descriptor", ab_pdt);
            sgj_haj_vi_nex(jsp, jo2p, 4, "Optimal block ROD length "
                           "granularity", SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be16(bp + 6), true, "unit: LB");
            ull = sg_get_unaligned_be64(bp + 8);
            sgj_haj_vi(jsp, jo2p, 4, "Maximum bytes in block ROD",
                       SGJ_SEP_COLON_1_SPACE, ull, true);
            ull = sg_get_unaligned_be64(bp + 16);
            sgj_haj_vistr(jsp, jo2p, 4, "Optimal Bytes in block ROD "
                          "transfer", SGJ_SEP_COLON_1_SPACE, ull, true,
                          (SG_LIB_UNBOUNDED_64BIT == ull) ? nl_s : NULL);
            ull = sg_get_unaligned_be64(bp + 24);
            sgj_haj_vistr(jsp, jo2p, 4, "Optimal Bytes to token per "
                          "segment", SGJ_SEP_COLON_1_SPACE, ull, true,
                          (SG_LIB_UNBOUNDED_64BIT == ull) ? nl_s : NULL);
            ull = sg_get_unaligned_be64(bp + 32);
            sgj_haj_vistr(jsp, jo2p, 4, "Optimal Bytes from token per "
                          "segment", SGJ_SEP_COLON_1_SPACE, ull, true,
                          (SG_LIB_UNBOUNDED_64BIT == ull) ? nl_s : NULL);
            break;
        case 1:
            /* Stream ROD device type specific descriptor */
            sgj_js_nv_ihexstr_nex(jsp, jo2p, "peripheral_device_type",
                                  pdt, false, NULL, "Stream ROD device "
                                  "type specific descriptor", ab_pdt);
            ull = sg_get_unaligned_be64(bp + 8);
            sgj_haj_vi(jsp, jo2p, 4, "Maximum bytes in stream ROD",
                       SGJ_SEP_COLON_1_SPACE, ull, true);
            ull = sg_get_unaligned_be64(bp + 16);
            snprintf(b, blen, "  Optimal Bytes in stream ROD transfer: ");
            if (SG_LIB_UNBOUNDED_64BIT == ull)
                sgj_pr_hr(jsp, "%s-1 [no limit]\n", b);
            else
                sgj_pr_hr(jsp, "%s%" PRIu64 "\n", b, ull);
            break;
        case 3:
            /* Copy manager ROD device type specific descriptor */
            sgj_js_nv_ihexstr_nex(jsp, jo2p, "peripheral_device_type",
                                  pdt, false, NULL, "Copy manager ROD "
                                  "device type specific descriptor",
                                  ab_pdt);
            sgj_pr_hr(jsp, "  Maximum Bytes in processor ROD: %" PRIu64 "\n",
                      sg_get_unaligned_be64(bp + 8));
            ull = sg_get_unaligned_be64(bp + 16);
            snprintf(b, blen, "  Optimal Bytes in processor ROD transfer: ");
            if (SG_LIB_UNBOUNDED_64BIT == ull)
                sgj_pr_hr(jsp, "%s-1 [no limit]\n", b);
            else
                sgj_pr_hr(jsp, "%s%" PRIu64 "\n", b, ull);
            break;
        default:
            sgj_js_nv_ihexstr(jsp, jo2p, "peripheral_device_type",
                              pdt, NULL, "unknown");
            break;
        }
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}

struct tpc_desc_type {
    uint8_t code;
    const char * name;
};

static struct tpc_desc_type tpc_desc_arr[] = {
    {0x0, "block -> stream"},
    {0x1, "stream -> block"},
    {0x2, "block -> block"},
    {0x3, "stream -> stream"},
    {0x4, "inline -> stream"},
    {0x5, "embedded -> stream"},
    {0x6, "stream -> discard"},
    {0x7, "verify CSCD"},
    {0x8, "block<o> -> stream"},
    {0x9, "stream -> block<o>"},
    {0xa, "block<o> -> block<o>"},
    {0xb, "block -> stream & application_client"},
    {0xc, "stream -> block & application_client"},
    {0xd, "block -> block & application_client"},
    {0xe, "stream -> stream&application_client"},
    {0xf, "stream -> discard&application_client"},
    {0x10, "filemark -> tape"},
    {0x11, "space -> tape"},            /* obsolete: spc5r02 */
    {0x12, "locate -> tape"},           /* obsolete: spc5r02 */
    {0x13, "<i>tape -> <i>tape"},
    {0x14, "register persistent reservation key"},
    {0x15, "third party persistent reservation source I_T nexus"},
    {0x16, "<i>block -> <i>block"},
    {0x17, "positioning -> tape"},      /* this and next added spc5r02 */
    {0x18, "<loi>tape -> <loi>tape"},   /* loi: logical object identifier */
    {0xbe, "ROD <- block range(n)"},
    {0xbf, "ROD <- block range(1)"},
    {0xe0, "CSCD: FC N_Port_Name"},
    {0xe1, "CSCD: FC N_Port_ID"},
    {0xe2, "CSCD: FC N_Port_ID with N_Port_Name, checking"},
    {0xe3, "CSCD: Parallel interface: I_T"},
    {0xe4, "CSCD: Identification Descriptor"},
    {0xe5, "CSCD: IPv4"},
    {0xe6, "CSCD: Alias"},
    {0xe7, "CSCD: RDMA"},
    {0xe8, "CSCD: IEEE 1394 EUI-64"},
    {0xe9, "CSCD: SAS SSP"},
    {0xea, "CSCD: IPv6"},
    {0xeb, "CSCD: IP copy service"},
    {0xfe, "CSCD: ROD"},
    {0xff, "CSCD: extension"},
    {0x0, NULL},
};

static const char *
get_tpc_desc_name(uint8_t code)
{
    const struct tpc_desc_type * dtp;

    for (dtp = tpc_desc_arr; dtp->name; ++dtp) {
        if (code == dtp->code)
            return dtp->name;
    }
    return "";
}

struct tpc_rod_type {
    uint32_t type;
    const char * name;
};

static struct tpc_rod_type tpc_rod_arr[] = {
    {0x0, "copy manager internal"},
    {0x10000, "access upon reference"},
    {0x800000, "point in time copy - default"},
    {0x800001, "point in time copy - change vulnerable"},
    {0x800002, "point in time copy - persistent"},
    {0x80ffff, "point in time copy - any"},
    {0xffff0001, "block device zero"},
    {0x0, NULL},
};

static const char *
get_tpc_rod_name(uint32_t rod_type)
{
    const struct tpc_rod_type * rtp;

    for (rtp = tpc_rod_arr; rtp->name; ++rtp) {
        if (rod_type == rtp->type)
            return rtp->name;
    }
    return "";
}

struct cscd_desc_id_t {
    uint16_t id;
    const char * name;
};

static struct cscd_desc_id_t cscd_desc_id_arr[] = {
    /* only values higher than 0x7ff are listed */
    {0xc000, "copy src or dst null LU, pdt=0"},
    {0xc001, "copy src or dst null LU, pdt=1"},
    {0xf800, "copy src or dst in ROD token"},
    {0xffff, "copy src or dst is copy manager LU"},
    {0x0, NULL},
};

static const char *
get_cscd_desc_id_name(uint16_t cscd_desc_id)
{
    const struct cscd_desc_id_t * cdip;

    for (cdip = cscd_desc_id_arr; cdip->name; ++cdip) {
        if (cscd_desc_id == cdip->id)
            return cdip->name;
    }
    return "";
}

static const char *
get_tpc_desc_type_s(uint32_t desc_type)
{
    switch(desc_type) {
    case 0:
        return "Block Device ROD Limits";
    case 1:
        return "Supported Commands";
    case 4:
        return "Parameter Data";
    case 8:
        return "Supported Descriptors";
    case 0xc:
        return "Supported CSCD Descriptor IDs";
    case 0xd:
        return "Copy Group Identifier";
    case 0x106:
        return "ROD Token Features";
    case 0x108:
        return "Supported ROD Token and ROD Types";
    case 0x8001:
        return "General Copy Operations";
    case 0x9101:
        return "Stream Copy Operations";
    case 0xC001:
        return "Held Data";
    default:
        if ((desc_type >= 0xE000) && (desc_type <= 0xEFFF))
            return "Restricted";
        else
            return "Reserved";
    }
}

/* VPD_3PARTY_COPY   3PC, third party copy  0x8f ["tpc"] */
void
decode_3party_copy_vpd(const uint8_t * buff, int len,
                       struct opts_t * op, sgj_opaque_p jap)
{
    int j, k, m, bump, desc_type, desc_len, sa_len, pdt;
    uint32_t u, v;
    uint64_t ull;
    const uint8_t * bp;
    const char * cp;
    const char * dtp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p ja2p = NULL;
    sgj_opaque_p jo3p = NULL;
    char b[144];
    static const int blen = sizeof(b);

    if (len < 4) {
        pr2serr("VPD page length too short=%d\n", len);
        return;
    }
    if (3 == op->do_hex) {
        hex2stdout(buff, len, -1);
        return;
    }
    pdt = buff[0] & PDT_MASK;
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        jo2p = sgj_new_unattached_object_r(jsp);
        desc_type = sg_get_unaligned_be16(bp);
        desc_len = sg_get_unaligned_be16(bp + 2);
        if (op->verbose)
            sgj_pr_hr(jsp, "Descriptor type=%d [0x%x] , len %d\n", desc_type,
                      desc_type, desc_len);
        bump = 4 + desc_len;
        if ((k + bump) > len) {
            pr2serr("VPD page, short descriptor length=%d, left=%d\n", bump,
                    (len - k));
            break;
        }
        if (0 == desc_len)
            goto skip;          /* continue plus attach jo2p */
        if (2 == op->do_hex)
            hex2stdout(bp + 4, desc_len, 1);
        else if (op->do_hex > 2)
            hex2stdout(bp, bump, 1);
        else {
            int csll;

            dtp = get_tpc_desc_type_s(desc_type);
            sgj_js_nv_ihexstr(jsp, jo2p, "third_party_copy_descriptor_type",
                              desc_type, NULL, dtp);
            sgj_js_nv_ihex(jsp, jo2p, "third_party_copy_descriptor_length",
                           desc_len);

            switch (desc_type) {
            case 0x0000:    /* Required if POPULATE TOKEN (or friend) used */
                sgj_pr_hr(jsp, " %s:\n", dtp);
                u = sg_get_unaligned_be16(bp + 10);
                sgj_haj_vistr(jsp, jo2p, 2, "Maximum range descriptors",
                              SGJ_SEP_COLON_1_SPACE, u, true,
                              (0 == u) ? nr_s : NULL);
                u = sg_get_unaligned_be32(bp + 12);
                if (0 == u)
                    cp = nr_s;
                else if (SG_LIB_UNBOUNDED_32BIT == u)
                    cp = "No maximum given";
                else
                    cp = NULL;
                sgj_haj_vistr_nex(jsp, jo2p, 2, "Maximum inactivity timeout",
                                  SGJ_SEP_COLON_1_SPACE, u, true, cp,
                                  "unit: second");
                u = sg_get_unaligned_be32(bp + 16);
                sgj_haj_vistr_nex(jsp, jo2p, 2, "Default inactivity timeout",
                                  SGJ_SEP_COLON_1_SPACE, u, true,
                                  (0 == u) ? nr_s : NULL, "unit: second");
                ull = sg_get_unaligned_be64(bp + 20);
                sgj_haj_vistr_nex(jsp, jo2p, 2, "Maximum token transfer size",
                                  SGJ_SEP_COLON_1_SPACE, ull, true,
                                  (0 == ull) ? nr_s : NULL, "unit: LB");
                ull = sg_get_unaligned_be64(bp + 28);
                sgj_haj_vistr_nex(jsp, jo2p, 2, "Optimal transfer count",
                                  SGJ_SEP_COLON_1_SPACE, ull, true,
                                  (0 == ull) ? nr_s : NULL, "unit: LB");
                break;
            case 0x0001:    /* Mandatory (SPC-4) */
                sgj_pr_hr(jsp, " %s:\n", "Commands supported list");
                ja2p = sgj_named_subarray_r(jsp, jo2p,
                                            "commands_supported_list");
                j = 0;
                csll = bp[4];
                if (csll >= desc_len) {
                    pr2serr("Command supported list length (%d) >= "
                            "descriptor length (%d), wrong so trim\n",
                            csll, desc_len);
                    csll = desc_len - 1;
                }
                while (j < csll) {
                    uint8_t opc, sa;
                    static const char * soc = "supported_operation_code";
                    static const char * ssa = "supported_service_action";

                    jo3p = NULL;
                    opc = bp[5 + j];
                    sa_len = bp[6 + j];
                    for (m = 0; (m < sa_len) && ((j + m) < csll); ++m) {
                        jo3p = sgj_new_unattached_object_r(jsp);
                        sa = bp[7 + j + m];
                        sg_get_opcode_sa_name(opc, sa, pdt, blen, b);
                        sgj_pr_hr(jsp, "  %s\n", b);
                        sgj_js_nv_s(jsp, jo3p, "name", b);
                        sgj_js_nv_ihex(jsp, jo3p, soc, opc);
                        sgj_js_nv_ihex(jsp, jo3p, ssa, sa);
                        sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
                    }
                    if (0 == sa_len) {
                        jo3p = sgj_new_unattached_object_r(jsp);
                        sg_get_opcode_name(opc, pdt, blen, b);
                        sgj_pr_hr(jsp, "  %s\n", b);
                        sgj_js_nv_s(jsp, jo3p, "name", b);
                        sgj_js_nv_ihex(jsp, jo3p, soc, opc);
                        sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
                    } else if (m < sa_len)
                        pr2serr("Supported service actions list length (%d) "
                                "is too large\n", sa_len);
                    j += m + 2;
                }
                break;
            case 0x0004:
                sgj_pr_hr(jsp, " %s:\n", dtp);
                sgj_haj_vi(jsp, jo2p, 2, "Maximum CSCD descriptor count",
                           SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be16(bp + 8), true);
                sgj_haj_vi(jsp, jo2p, 2, "Maximum segment descriptor count",
                           SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be16(bp + 10), true);
                sgj_haj_vi(jsp, jo2p, 2, "Maximum descriptor list length",
                           SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 12), true);
                sgj_haj_vi(jsp, jo2p, 2, "Maximum inline data length",
                           SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 17), true);
                break;
            case 0x0008:
                sgj_pr_hr(jsp, " Supported descriptors:\n");
                ja2p = sgj_named_subarray_r(jsp, jo2p,
                                            "supported_descriptor_list");
                for (j = 0; j < bp[4]; j++) {
                    bool found_name;

                    jo3p = sgj_new_unattached_object_r(jsp);
                    u = bp[5 + j];
                    cp = get_tpc_desc_name(u);
                    found_name = (strlen(cp) > 0);
                    if (found_name)
                        sgj_pr_hr(jsp, "  %s [0x%x]\n", cp, u);
                    else
                        sgj_pr_hr(jsp, "  0x%x\n", u);
                    sgj_js_nv_s(jsp, jo3p, "name", found_name ? cp : nr_s);
                    sgj_js_nv_ihex(jsp, jo3p, "code", u);
                    sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
                }
                break;
            case 0x000C:
                sgj_pr_hr(jsp, " Supported CSCD IDs (above 0x7ff):\n");
                ja2p = sgj_named_subarray_r(jsp, jo2p, "supported_cscd_"
                                            "descriptor_id_list");
                v = sg_get_unaligned_be16(bp + 4);
                for (j = 0; j < (int)v; j += 2) {
                    bool found_name;

                    jo3p = sgj_new_unattached_object_r(jsp);
                    u = sg_get_unaligned_be16(bp + 6 + j);
                    cp = get_cscd_desc_id_name(u);
                    found_name = (strlen(cp) > 0);
                    if (found_name)
                        sgj_pr_hr(jsp, "  %s [0x%04x]\n", cp, u);
                    else
                        sgj_pr_hr(jsp, "  0x%04x\n", u);
                    sgj_js_nv_s(jsp, jo3p, "name", found_name ? cp : nr_s);
                    sgj_js_nv_ihex(jsp, jo3p, "id", u);
                    sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
                }
                break;
            case 0x000D:
                sgj_pr_hr(jsp, " Copy group identifier:\n");
                u = bp[4];
                sg_t10_uuid_desig2str(bp + 5, u, 1 /* c_set */, false,
                                      true, NULL, blen, b);
                sgj_pr_hr(jsp, "  Locally assigned UUID: %s", b);
                sgj_js_nv_s(jsp, jo2p, "locally_assigned_uuid", b);
                break;
            case 0x0106:
                sgj_pr_hr(jsp, " ROD token features:\n");
                sgj_haj_vi(jsp, jo2p, 2, "Remote tokens",
                           SGJ_SEP_COLON_1_SPACE, bp[4] & 0x0f, true);
                u = sg_get_unaligned_be32(bp + 16);
                sgj_pr_hr(jsp, "  Minimum token lifetime: %u seconds\n", u);
                sgj_js_nv_ihex_nex(jsp, jo2p, "minimum_token_lifetime", u,
                                   true, "unit: second");
                u = sg_get_unaligned_be32(bp + 20);
                sgj_pr_hr(jsp, "  Maximum token lifetime: %u seconds\n", u);
                sgj_js_nv_ihex_nex(jsp, jo2p, "maximum_token_lifetime", u,
                                   true, "unit: second");
                u = sg_get_unaligned_be32(bp + 24);
                sgj_haj_vi_nex(jsp, jo2p, 2, "Maximum token inactivity "
                               "timeout", SGJ_SEP_COLON_1_SPACE, u,
                               true, "unit: second");
                u = sg_get_unaligned_be16(bp + 46);
                ja2p = sgj_named_subarray_r(jsp, jo2p,
                    "rod_device_type_specific_features_descriptor_list");
                decode_rod_descriptor(bp + 48, u, op, ja2p);
                break;
            case 0x0108:
                sgj_pr_hr(jsp, " Supported ROD token and ROD types:\n");
                ja2p = sgj_named_subarray_r(jsp, jo2p, "rod_type_"
                                            "descriptor_list");
                for (j = 0; j < sg_get_unaligned_be16(bp + 6); j+= 64) {
                    bool found_name;

                    jo3p = sgj_new_unattached_object_r(jsp);
                    u = sg_get_unaligned_be32(bp + 8 + j);
                    cp = get_tpc_rod_name(u);
                    found_name = (strlen(cp) > 0);
                    if (found_name > 0)
                        sgj_pr_hr(jsp, "  ROD type: %s [0x%x]\n", cp, u);
                    else
                        sgj_pr_hr(jsp, "  ROD type: 0x%x\n", u);
                    sgj_js_nv_ihexstr(jsp, jo3p, "rod_type", u, NULL,
                                      found_name ? cp : NULL);
                    u = bp[8 + j + 4];
                    sgj_pr_hr(jsp, "    ECPY_INT: %s\n",
                              (u & 0x80) ? y_s : n_s);
                    sgj_js_nv_ihex_nex(jsp, jo3p, "ecpy_int", !!(0x80 & u),
                                       false, "Extended CoPY INTernal rods");
                    sgj_pr_hr(jsp, "    Token in: %s\n",
                              (u & 0x2) ? y_s : n_s);
                    sgj_js_nv_i(jsp, jo3p, "token_in", !!(0x2 & u));
                    sgj_pr_hr(jsp, "    Token out: %s\n",
                              (u & 0x1) ? y_s : n_s);
                    sgj_js_nv_i(jsp, jo3p, "token_out", !!(0x2 & u));
                    u = sg_get_unaligned_be16(bp + 8 + j + 6);
                    sgj_haj_vi(jsp, jo3p, 4, "Preference indicator",
                               SGJ_SEP_COLON_1_SPACE, u, true);
                    sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
                }
                break;
            case 0x8001:    /* Mandatory (SPC-4) */
                sgj_pr_hr(jsp, " General copy operations:\n");
                u = sg_get_unaligned_be32(bp + 4);
                sgj_haj_vi(jsp, jo2p, 2, "Total concurrent copies",
                           SGJ_SEP_COLON_1_SPACE, u, true);
                u = sg_get_unaligned_be32(bp + 8);
                sgj_haj_vi(jsp, jo2p, 2, "Maximum identified concurrent "
                           "copies", SGJ_SEP_COLON_1_SPACE, u, true);
                u = sg_get_unaligned_be32(bp + 12);
                sgj_haj_vi_nex(jsp, jo2p, 2, "Maximum segment length",
                               SGJ_SEP_COLON_1_SPACE, u, true, "unit: byte");
                u = bp[16];     /* field is power of 2 */
                sgj_haj_vi_nex(jsp, jo2p, 2, "Data segment granularity",
                               SGJ_SEP_COLON_1_SPACE, u, true,
                               "unit: 2^val LB");
                u = bp[17];     /* field is power of 2 */
                sgj_haj_vi_nex(jsp, jo2p, 2, "Inline data granularity",
                               SGJ_SEP_COLON_1_SPACE, u, true,
                               "unit: 2^val LB");
                break;
            case 0x9101:
                sgj_pr_hr(jsp, " Stream copy operations:\n");
                u = sg_get_unaligned_be32(bp + 4);
                sgj_haj_vi_nex(jsp, jo2p, 2, "Maximum stream device transfer "
                               "size", SGJ_SEP_COLON_1_SPACE, u, true,
                               "unit: byte");
                break;
            case 0xC001:
                sgj_pr_hr(jsp, " Held data:\n");
                u = sg_get_unaligned_be32(bp + 4);
                sgj_haj_vi_nex(jsp, jo2p, 2, "Held data limit",
                               SGJ_SEP_COLON_1_SPACE, u, true,
                               "unit: byte; (lower limit: minimum)");
                sgj_haj_vi_nex(jsp, jo2p, 2, "Held data granularity",
                               SGJ_SEP_COLON_1_SPACE, bp[8], true,
                               "unit: 2^val byte");
                break;
            default:
                pr2serr("Unexpected type=%d\n", desc_type);
                hex2stderr(bp, bump, 1);
                break;
            }
        }
skip:
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        jo2p = NULL;
    }
    if (jo2p)
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
}

/* VPD_PROTO_LU  0x90 ["pslu"] */
void
decode_proto_lu_vpd(const uint8_t * buff, int len, struct opts_t * op,
                    sgj_opaque_p jap)
{
    int k, bump, rel_port, desc_len, proto;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    char b[128];
    static const int blen = sizeof(b);

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        jo2p = sgj_new_unattached_object_r(jsp);
        rel_port = sg_get_unaligned_be16(bp);
        sgj_haj_vi(jsp, jo2p, 2, "Relative port",
                   SGJ_SEP_COLON_1_SPACE, rel_port, true);
        proto = bp[2] & 0xf;
        sg_get_trans_proto_str(proto, blen, b);
        sgj_haj_vistr(jsp, jo2p, 4, "Protocol identifier",
                      SGJ_SEP_COLON_1_SPACE, proto, false, b);
        desc_len = sg_get_unaligned_be16(bp + 6);
        bump = 8 + desc_len;
        if ((k + bump) > len) {
            pr2serr("Protocol-specific logical unit information VPD page, "
                    "short descriptor length=%d, left=%d\n", bump, (len - k));
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            return;
        }
        if (0 == desc_len)
            goto again;
        if (2 == op->do_hex) {
            hex2stdout(bp + 8, desc_len, 1);
            goto again;
        }
        switch (proto) {
        case TPROTO_SAS:
            sgj_haj_vi(jsp, jo2p, 2, "TLR control supported",
                       SGJ_SEP_COLON_1_SPACE, !!(bp[8] & 0x1), false);
            break;
        default:
            pr2serr("Unexpected proto=%d\n", proto);
            hex2stderr(bp, bump, 1);
            break;
        }
again:
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}

/* VPD_PROTO_PORT  0x91 ["pspo"] */
void
decode_proto_port_vpd(const uint8_t * buff, int len, struct opts_t * op,
                      sgj_opaque_p jap)
{
    bool pds, ssp_pers;
    int k, j, bump, rel_port, desc_len, proto, phy;
    const uint8_t * bp;
    const uint8_t * pidp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p ja2p = NULL;
    sgj_opaque_p jo3p = NULL;
    char b[128];
    static const int blen = sizeof(b);

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        jo2p = sgj_new_unattached_object_r(jsp);
        rel_port = sg_get_unaligned_be16(bp);
        sgj_haj_vi(jsp, jo2p, 2, "Relative port",
                   SGJ_SEP_COLON_1_SPACE, rel_port, true);
        proto = bp[2] & 0xf;
        sg_get_trans_proto_str(proto, blen, b);
        sgj_haj_vistr(jsp, jo2p, 4, "Protocol identifier",
                      SGJ_SEP_COLON_1_SPACE, proto, false, b);
        desc_len = sg_get_unaligned_be16(bp + 6);
        bump = 8 + desc_len;
        if ((k + bump) > len) {
            pr2serr("VPD page, short descriptor length=%d, left=%d\n",
                    bump, (len - k));
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            return;
        }
        if (0 == desc_len)
            goto again;
        if (2 == op->do_hex) {
            hex2stdout(bp + 8, desc_len, 1);
            goto again;
        }
        switch (proto) {
        case TPROTO_SAS:    /* page added in spl3r02 */
            pds = !!(bp[3] & 0x1);
            sgj_pr_hr(jsp, "    power disable supported (pwr_d_s)=%d\n", pds);
            sgj_js_nv_ihex_nex(jsp, jo2p, "pwr_d_s", pds, false,
                       "PoWeR Disable Supported");
            ja2p = sgj_named_subarray_r(jsp, jo2p,
                                    "sas_phy_information_descriptor_list");
            pidp = bp + 8;
            for (j = 0; j < desc_len; j += 4, pidp += 4) {
                jo3p = sgj_new_unattached_object_r(jsp);
                phy = pidp[1];
                ssp_pers = !!(0x1 & pidp[2]);
                sgj_pr_hr(jsp, "      phy id=%d, SSP persistent capable=%d\n",
                          phy, ssp_pers);
                sgj_js_nv_ihex(jsp, jo3p, "phy_identifier", phy);
                sgj_js_nv_i(jsp, jo3p, "ssp_persistent_capable", ssp_pers);
                sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
            }
            break;
        default:
            pr2serr("Unexpected proto=%d\n", proto);
            hex2stderr(bp, bump, 1);
            break;
        }
again:
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}

/* VPD_LB_PROTECTION 0xb5 (SSC)  [added in ssc5r02a] */
void
decode_lb_protection_vpd(const uint8_t * buff, int len, struct opts_t * op,
                         sgj_opaque_p jap)
{
    int k, bump;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (len < 8) {
        pr2serr("VPD page length too short=%d\n", len);
        return;
    }
    len -= 8;
    bp = buff + 8;
    for (k = 0; k < len; k += bump, bp += bump) {
        jo2p = sgj_new_unattached_object_r(jsp);
        bump = 1 + bp[0];
        sgj_pr_hr(jsp, "  method: %d, info_len: %d, LBP_W_C=%d, LBP_R_C=%d, "
                  "RBDP_C=%d\n", bp[1], 0x3f & bp[2], !!(0x80 & bp[3]),
                  !!(0x40 & bp[3]), !!(0x20 & bp[3]));
        sgj_js_nv_ihex(jsp, jo2p, "logical_block_protection_method", bp[1]);
        sgj_js_nv_ihex_nex(jsp, jo2p,
                           "logical_block_protection_information_length",
                           0x3f & bp[2], true, "unit: byte");
        sgj_js_nv_ihex_nex(jsp, jo2p, "lbp_w_c", !!(0x80 & bp[3]), false,
                           "Logical Blocks Protected during Write supported");
        sgj_js_nv_ihex_nex(jsp, jo2p, "lbp_r_c", !!(0x40 & bp[3]), false,
                           "Logical Blocks Protected during Read supported");
        sgj_js_nv_ihex_nex(jsp, jo2p, "rbdp_c", !!(0x20 & bp[3]), false,
                           "Recover Buffered Data Protected supported");
        if ((k + bump) > len) {
            pr2serr("Logical block protection VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            return;
        }
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
}

/* VPD_TA_SUPPORTED  0xb2 ["tas"] */
void
decode_tapealert_supported_vpd(const uint8_t * buff, int len,
                               struct opts_t * op, sgj_opaque_p jop)
{
    bool have_ta_strs = !! sg_lib_tapealert_strs[0];
    int k, mod, div, n;
    unsigned int supp;
    sgj_state * jsp = &op->json_st;
    char b[144];
    char d[64];
    static const int blen = sizeof(b);

    if (len < 12) {
        pr2serr("VPD page length too short=%d\n", len);
        return;
    }
    b[0] ='\0';
    for (k = 1, n = 0; k < 0x41; ++k) {
        mod = ((k - 1) % 8);
        div = (k - 1) / 8;
        supp = !! (buff[4 + div] & (1 << (7 - mod)));
        if (jsp->pr_as_json) {
            snprintf(d, sizeof(d), "flag%02xh", k);
            if (have_ta_strs)
                sgj_js_nv_ihex_nex(jsp, jop, d, supp, false,
                                   sg_lib_tapealert_strs[k]);
            else
                sgj_js_nv_i(jsp, jop, d, supp);
        }
        if (0 == mod) {
            if (div > 0) {
                sgj_pr_hr(jsp, "%s\n", b);
                n = 0;
            }
            n += sg_scnpr(b + n, blen - n, "  Flag%02Xh: %d", k, supp);
        } else
            n += sg_scnpr(b + n, blen - n, "  %02Xh: %d", k, supp);
    }
    sgj_pr_hr(jsp, "%s\n", b);
}

/*
 * Some of the vendor specific VPD pages are common as well. So place them here
 * to save on code duplication.
 */

static const char * lun_state_arr[] =
{
    "LUN not bound or LUN_Z report",
    "LUN bound, but not owned by this SP",
    "LUN bound and owned by this SP",
};

static const char * ip_mgmt_arr[] =
{
    "No IP access",
    "Reserved (undefined)",
    "via IPv4",
    "via IPv6",
};

static const char * sp_arr[] =
{
    "SP A",
    "SP B",
};

static const char * lun_op_arr[] =
{
    "Normal operations",
    "I/O Operations being rejected, SP reboot or NDU in progress",
};

static const char * failover_mode_arr[] =
{
    "Legacy mode 0",
    "Unknown mode (1)",
    "Unknown mode (2)",
    "Unknown mode (3)",
    "Active/Passive (PNR) mode 1",
    "Unknown mode (5)",
    "Active/Active (ALUA) mode 4",
    "Unknown mode (7)",
    "Legacy mode 2",
    "Unknown mode (9)",
    "Unknown mode (10)",
    "Unknown mode (11)",
    "Unknown mode (12)",
    "Unknown mode (13)",
    "AIX Active/Passive (PAR) mode 3",
    "Unknown mode (15)",
};

/* VPD_UPR_EMC,VPD_V_UPR_EMC  0xc0  ["upr","upr"] */
void
decode_upr_vpd_c0_emc(uint8_t * buff, int len, struct opts_t * op,
                      sgj_opaque_p jop)
{
    uint8_t uc;
    int k, n, ip_mgmt, vpp80, lun_z;
    sgj_state * jsp = &op->json_st;
    const char * cp;
    const char * c2p;
    char b[256];
    static const int blen = sizeof(b);

    if (len < 3) {
        pr2serr("EMC upr VPD page [0xc0]: length too short=%d\n", len);
        return;
    }
    if (op->do_hex) {
        hex2stdout(buff, len, no_ascii_4hex(op));
        return;
    }
    if (buff[9] != 0x00) {
        pr2serr("Unsupported page revision %d, decoding not possible.\n",
                buff[9]);
        return;
    }
    for (k = 0, n = 0; k < 16; ++k)
        n += sg_scnpr(b + n, blen - n, "%02x", buff[10 + k]);
    sgj_haj_vs(jsp, jop, 2, "LUN WWN", SGJ_SEP_COLON_1_SPACE, b);
    snprintf(b, blen, "%.*s", buff[49], buff + 50);
    sgj_haj_vs(jsp, jop, 2, "Array Serial Number", SGJ_SEP_COLON_1_SPACE, b);

    if (buff[4] > 0x02)
       snprintf(b, blen, "Unknown (%x)", buff[4]);
    else
       snprintf(b, blen, "%s", lun_state_arr[buff[4]]);
    sgj_haj_vistr(jsp, jop, 2, "LUN State", SGJ_SEP_COLON_1_SPACE,
                  buff[4], true, b);

    uc = buff[8];
    n = 0;
    if (uc > 0x01)
       n += sg_scnpr(b + n, blen - n, "Unknown SP (%x)", uc);
    else
       n += sg_scnpr(b + n, blen - n, "%s", sp_arr[uc]);
    sgj_js_nv_ihexstr(jsp, jop, "path_connects_to", uc, NULL, b);
    n += sg_scnpr(b + n, blen - n, ", Port Number: %u", buff[7]);
    sgj_pr_hr(jsp, "  This path connects to: %s\n", b);
    sgj_js_nv_ihex(jsp, jop, "port_number", buff[7]);

    if (buff[5] > 0x01)
           snprintf(b, blen, "Unknown (%x)\n", buff[5]);
    else
           snprintf(b, blen, "%s\n", sp_arr[buff[5]]);
    sgj_haj_vistr(jsp, jop, 2, "Default owner", SGJ_SEP_COLON_1_SPACE,
                  buff[5], true, b);

    cp = (buff[6] & 0x40) ? "supported" : "not supported";
    sgj_pr_hr(jsp, "  NO_ATF: %s, Access Logix: %s\n",
              buff[6] & 0x80 ? "set" : "not set", cp);
    sgj_js_nv_i(jsp, jop, "no_atf", !! (buff[6] & 0x80));
    sgj_js_nv_istr(jsp, jop, "access_logix", !! (buff[6] & 0x40),
                   NULL, cp);

    ip_mgmt = (buff[6] >> 4) & 0x3;
    cp = ip_mgmt_arr[ip_mgmt];
    sgj_pr_hr(jsp, "  SP IP Management Mode: %s\n", cp);
    sgj_js_nv_istr(jsp, jop, "sp_ip_management_mode", !! ip_mgmt,
                   NULL, cp);
    if (ip_mgmt == 2) {
        snprintf(b, blen, "%u.%u.%u.%u", buff[44], buff[45], buff[46],
                 buff[47]);
        sgj_pr_hr(jsp, "  SP IPv4 address: %s\n", b);
        sgj_js_nv_s(jsp, jop, "sp_ipv4_address", b);
    } else if (ip_mgmt == 3) {
        printf("  SP IPv6 address: ");
        n = 0;
        for (k = 0; k < 16; ++k)
            n += sg_scnpr(b + n, blen - n, "%02x", buff[32 + k]);
        sgj_pr_hr(jsp, "  SP IPv6 address: %s\n", b);
        sgj_js_nv_hex_bytes(jsp, jop, "sp_ipv6_address", buff + 32, 16);
    }

    k = buff[28] & 0x0f;
    sgj_pr_hr(jsp, "  System Type: %x, Failover mode: %s\n",
              buff[27], failover_mode_arr[k]);
    sgj_js_nv_ihex(jsp, jop, "system_type", buff[27]);
    sgj_js_nv_ihexstr(jsp, jop, "failover_mode", k, NULL,
                      failover_mode_arr[k]);

    vpp80 = buff[30] & 0x08;
    lun_z = buff[30] & 0x04;
    cp = vpp80 ? "array serial#" : "LUN serial#";
    c2p = lun_z ? "Set to 1" : "Unknown";
    sgj_pr_hr(jsp, "  Inquiry VPP 0x80 returns: %s, Arraycommpath: %s\n",
              cp, c2p);
    sgj_js_nv_istr(jsp, jop, "inquiry_vpp_0x80_returns", !! vpp80, NULL, cp);
    sgj_js_nv_istr(jsp, jop, "arraycommpath", !! lun_z, NULL, c2p);

    cp = buff[48] > 1 ? "undefined" : lun_op_arr[buff[48]];
    sgj_pr_hr(jsp, "  Lun operations: %s\n", cp);
    sgj_js_nv_istr(jsp, jop, "lun_operations", 0x1 & buff[48], NULL, cp);

    return;
}

/*  VPD_RDAC_VERS,VPD_V_SVER_RDAC  0xc2 ["rdac_vers", "swr4"] */
void
decode_rdac_vpd_c2(uint8_t * buff, int len, struct opts_t * op,
                   sgj_opaque_p jop)
{
    int i, n, v, r, m, p, d, y, num_part;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    // const char * cp;
    // const char * c2p;
    char b[256];
    static const int blen = sizeof(b);
    char part[5];

    if (len < 3) {
        pr2serr("Software Version VPD page length too short=%d\n", len);
        return;
    }
    if (op->do_hex) {
        hex2stdout(buff, len, no_ascii_4hex(op));
        return;
    }
    if (buff[4] != 's' && buff[5] != 'w' && buff[6] != 'r') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    snprintf(b, blen, "%02x.%02x.%02x", buff[8], buff[9], buff[10]);
    sgj_haj_vs(jsp, jop, 2, "Software Version", SGJ_SEP_COLON_1_SPACE, b);
    snprintf(b, blen, "%02d/%02d/%02d\n", buff[11], buff[12], buff[13]);
    sgj_haj_vs(jsp, jop, 2, "Software Date", SGJ_SEP_COLON_1_SPACE, b);
    n = 0;
    n += sg_scnpr(b + n, blen - n, "  Features:");
    if (buff[14] & 0x01)
        n += sg_scnpr(b + n, blen - n, " Dual Active,");
    if (buff[14] & 0x02)
        n += sg_scnpr(b + n, blen - n, " Series 3,");
    if (buff[14] & 0x04)
        n += sg_scnpr(b + n, blen - n, " Multiple Sub-enclosures,");
    if (buff[14] & 0x08)
        n += sg_scnpr(b + n, blen - n, " DCE/DRM/DSS/DVE,");
    if (buff[14] & 0x10)
        n += sg_scnpr(b + n, blen - n, " Asymmetric Logical Unit Access,");
    sgj_pr_hr(jsp, "%s\n", b);
    if (jsp->pr_as_json) {
        jo2p = sgj_snake_named_subobject_r(jsp, jop, "features");
        sgj_js_nv_i(jsp, jo2p, "dual_active", !! (buff[14] & 0x01));
        sgj_js_nv_i(jsp, jo2p, "series_3", !! (buff[14] & 0x02));
        sgj_js_nv_i(jsp, jo2p, "multiple_sub_enclosures",
                    !! (buff[14] & 0x04));
        sgj_js_nv_i(jsp, jo2p, "dcm_drm_dss_dve", !! (buff[14] & 0x08));
        sgj_js_nv_i(jsp, jo2p, "asymmetric_logical_unit_access",
                    !! (buff[14] & 0x10));
    }
    sgj_haj_vi(jsp, jop, 2, "Maximum number of LUNS",
               SGJ_SEP_COLON_1_SPACE, buff[15], true);

    num_part = (len - 12) / 16;
    n = 16;
    printf("  Partitions: %d\n", num_part);
    sgj_haj_vi(jsp, jop, 2, "Partitions", SGJ_SEP_COLON_1_SPACE, num_part,
               true);
    if (num_part > 0)
        jap = sgj_named_subarray_r(jsp, jop, "partition_list");
    for (i = 0; i < num_part; i++) {
        memset(part,0, 5);
        memcpy(part, &buff[n], 4);
        sgj_pr_hr(jsp, "    Name: %s\n", part);
        if (jsp->pr_as_json) {
            jo2p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_s(jsp, jo2p, "name", part);
        }
        n += 4;
        v = buff[n++];
        r = buff[n++];
        m = buff[n++];
        p = buff[n++];
        snprintf(b, blen, "%d.%d.%d.%d", v, r, m, p);
        sgj_pr_hr(jsp, "    Version: %s\n", b);
        if (jsp->pr_as_json)
            sgj_js_nv_s(jsp, jo2p, "version", b);
        m = buff[n++];
        d = buff[n++];
        y = buff[n++];
        snprintf(b, blen, "%d/%d/%d\n", m, d, y);
        sgj_pr_hr(jsp, "    Date: %s\n", b);
        if (jsp->pr_as_json) {
            sgj_js_nv_s(jsp, jo2p, "date", b);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }

        n += 5;
    }
    return;
}

static char *
decode_rdac_vpd_c9_aas_s(uint8_t aas, char * b, int blen)
{
    // snprintf("  Asymmetric Access State:");
    switch(aas & 0x0F) {
        case 0x0:
            snprintf(b, blen, "Active/Optimized");
            break;
        case 0x1:
            snprintf(b, blen, "Active/Non-Optimized");
            break;
        case 0x2:
            snprintf(b, blen, "Standby");
            break;
        case 0x3:
            snprintf(b, blen, "Unavailable");
            break;
        case 0xE:
            snprintf(b, blen, "Offline");
            break;
        case 0xF:
            snprintf(b, blen, "Transitioning");
            break;
        default:
            snprintf(b, blen, "(unknown)");
            break;
    }
    return b;
}

static char *
decode_rdac_vpd_c9_vs_s(uint8_t vendor, char * b, int blen)
{
    // printf("  Vendor Specific Field:");
    switch(vendor) {
        case 0x01:
            snprintf(b, blen, "Operating normally");
            break;
        case 0x02:
            snprintf(b, blen, "Non-responsive to queries");
            break;
        case 0x03:
            snprintf(b, blen, "Controller being held in reset");
            break;
        case 0x04:
            snprintf(b, blen, "Performing controller firmware download (1st "
                   "controller)");
            break;
        case 0x05:
            snprintf(b, blen, "Performing controller firmware download (2nd "
                   "controller)");
            break;
        case 0x06:
            snprintf(b, blen,
                     "Quiesced as a result of an administrative request");
            break;
        case 0x07:
            snprintf(b, blen,
                     "Service mode as a result of an administrative request");
            break;
        case 0xFF:
            snprintf(b, blen, "Details are not available");
            break;
        default:
            snprintf(b, blen, "(unknown)");
            break;
    }
    return b;
}

/*  VPD_RDAC_VAC,VPD_V_VAC_RDAC  0xc9 ["rdac_vac", "vac1"] */
void
decode_rdac_vpd_c9(uint8_t * buff, int len, struct opts_t * op,
                   sgj_opaque_p jop)
{
    bool vav;
    int n, n_hold;
    sgj_state * jsp = &op->json_st;
    char b[196];
    static const int blen = sizeof(b);

    if (len < 3) {
        pr2serr("Volume Access Control VPD page length too short=%d\n", len);
        return;
    }
    if (op->do_hex) {
        hex2stdout(buff, len, no_ascii_4hex(op));
        return;
    }
    if (buff[4] != 'v' && buff[5] != 'a' && buff[6] != 'c') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    if (buff[7] != '1') {
        pr2serr("Invalid page version '%c' (should be 1)\n", buff[7]);
    }
    n = ((buff[8] & 0xE0) == 0xE0 );
    if (n) {
        sgj_pr_hr(jsp, "  IOShipping (ALUA): Enabled\n");
        sgj_js_nv_ihexstr_nex(jsp, jop, "ioshipping", n, true, NULL,
                              "Enabled",
                              "a.k.a. ALUA (Asymmetric Logical Unit Access)");
    } else {
        n = 0;
        n = snprintf(b, blen, "  AVT:");
        n_hold = n;
        if (buff[8] & 0x80) {
            n += sg_scnpr(b + n, blen - n, " Enabled");
            if (buff[8] & 0x40)
                n += sg_scnpr(b + n, blen - n, " (Allow reads on sector 0)");
            sgj_pr_hr(jsp, "%s\n", b);
            sgj_js_nv_ihexstr(jsp, jop, "avt", buff[8], NULL, b + n_hold);

        } else {
            sgj_pr_hr(jsp, "%s: Disabled\n", b);
            sgj_js_nv_ihexstr(jsp, jop, "avt", buff[8], NULL, "Disabled");
        }
    }
    vav = !! (0x1 & buff[8]);
    sgj_haj_vistr(jsp, jop, 2, "Volume access via", SGJ_SEP_COLON_1_SPACE,
                  (int)vav, false,
                  (vav ? "primary controller" : "alternate controller"));

    if (buff[8] & 0x08) {
        n = buff[15] & 0xf;
        // printf("  Path priority: %d ", n);
        switch (n) {
        case 0x1:
            snprintf(b, blen, "(preferred path)");
            break;
        case 0x2:
            snprintf(b, blen, "(secondary path)");
            break;
        default:
            snprintf(b, blen, "(unknown)");
            break;
        }
        sgj_haj_vistr(jsp, jop, 2, "Path priority", SGJ_SEP_COLON_1_SPACE, n,
                      true, b);

        // printf("  Preferred Path Auto Changeable:");
        n = buff[14] & 0x3C;
        switch (n) {
        case 0x14:
            snprintf(b, blen, "No (User Disabled and Host Type Restricted)");
            break;
        case 0x18:
            snprintf(b, blen, "No (User Disabled)");
            break;
        case 0x24:
            snprintf(b, blen, "No (Host Type Restricted)");
            break;
        case 0x28:
            snprintf(b, blen, "Yes");
            break;
        default:
            snprintf(b, blen, "(Unknown)");
            break;
        }
        sgj_haj_vistr(jsp, jop, 2, "Preferred path auto changeable",
                      SGJ_SEP_COLON_1_SPACE, n, true, b);

        n = buff[14] & 0x03;
        // printf("  Implicit Failback:");
        switch (n) {
        case 0x1:
            snprintf(b, blen, "Disabled");
            break;
        case 0x2:
            snprintf(b, blen, "Enabled");
            break;
        default:
            snprintf(b, blen, "(Unknown)");
            break;
        }
        sgj_haj_vistr(jsp, jop, 2, "Implicit failback",
                      SGJ_SEP_COLON_1_SPACE, n, false, b);
    } else {
        n = buff[9] & 0xf;
        // printf("  Path priority: %d ", buff[9] & 0xf);
        switch (n) {
        case 0x1:
            snprintf(b, blen, "(preferred path)");
            break;
        case 0x2:
            snprintf(b, blen, "(secondary path)");
            break;
        default:
            snprintf(b, blen, "(unknown)");
            break;
        }
        sgj_haj_vistr(jsp, jop, 2, "Path priority",
                      SGJ_SEP_COLON_1_SPACE, n, false, b);
    }

    n = !! (buff[8] & 0x80);
    sgj_haj_vi(jsp, jop, 2, "Target port group present",
               SGJ_SEP_COLON_1_SPACE, n, false);
    if (n) {
        sgj_opaque_p jo2p = NULL;
        sgj_opaque_p jo3p = NULL;
        static const char * tpg_s = "Target port group data";
        static const char * aas_s = "Asymmetric access state";
        static const char * vsf_s = "Vendor specific field";
        char d1[80];
        char d2[80];

        sgj_pr_hr(jsp, "  Target Port Group Data (This controller):\n");
        decode_rdac_vpd_c9_aas_s(buff[10], d1, sizeof(d1));
        decode_rdac_vpd_c9_vs_s(buff[11], d2, sizeof(d2));
        sgj_pr_hr(jsp, "    %s: %s\n", aas_s, d1);
        sgj_pr_hr(jsp, "    %s: %s\n", vsf_s, d2);
        if (jsp->pr_as_json) {
            jo2p = sgj_snake_named_subobject_r(jsp, jop, tpg_s);
            jo3p = sgj_snake_named_subobject_r(jsp, jo2p, "this_controller");
            sgj_convert_to_snake_name(aas_s, b, blen);
            sgj_js_nv_ihexstr(jsp, jo3p, b, buff[10], NULL, d1);
            sgj_convert_to_snake_name(vsf_s, b, blen);
            sgj_js_nv_ihexstr(jsp, jo3p, b, buff[11], NULL, d2);
        }
        sgj_pr_hr(jsp, " Target Port Group Data (Alternate controller):\n");
        // decode_rdac_vpd_c9_rtpg_data(buff[12], buff[13]);

        decode_rdac_vpd_c9_aas_s(buff[12], d1, sizeof(d1));
        decode_rdac_vpd_c9_vs_s(buff[13], d2, sizeof(d2));
        sgj_pr_hr(jsp, "    %s: %s\n", aas_s, d1);
        sgj_pr_hr(jsp, "    %s: %s\n", vsf_s, d2);
        if (jsp->pr_as_json) {
            jo2p = sgj_snake_named_subobject_r(jsp, jop, tpg_s);
            jo3p = sgj_snake_named_subobject_r(jsp, jo2p,
                                               "alternate_controller");
            sgj_convert_to_snake_name(aas_s, b, blen);
            sgj_js_nv_ihexstr(jsp, jo3p, b, buff[12], NULL, d1);
            sgj_convert_to_snake_name(vsf_s, b, blen);
            sgj_js_nv_ihexstr(jsp, jo3p, b, buff[13], NULL, d2);
        }
    }
}
