#ifndef SG_VPD_H
#define SG_VPD_H

/*
 * Copyright (c) 2022 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_pr2serr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* standard VPD pages, in ascending page number order */
#define VPD_SUPPORTED_VPDS 0x0
#define VPD_UNIT_SERIAL_NUM 0x80
#define VPD_IMP_OP_DEF 0x81             /* obsolete in SPC-2 */
#define VPD_ASCII_OP_DEF 0x82           /* obsolete in SPC-2 */
#define VPD_DEVICE_ID 0x83
#define VPD_SOFTW_INF_ID 0x84
#define VPD_MAN_NET_ADDR 0x85
#define VPD_EXT_INQ 0x86                /* Extended Inquiry */
#define VPD_MODE_PG_POLICY 0x87
#define VPD_SCSI_PORTS 0x88
#define VPD_ATA_INFO 0x89
#define VPD_POWER_CONDITION 0x8a
#define VPD_DEVICE_CONSTITUENTS 0x8b
#define VPD_CFA_PROFILE_INFO 0x8c
#define VPD_POWER_CONSUMPTION  0x8d
#define VPD_3PARTY_COPY 0x8f            /* 3PC, XCOPY, SPC-4, SBC-3 */
#define VPD_PROTO_LU 0x90
#define VPD_PROTO_PORT 0x91
#define VPD_SCSI_FEATURE_SETS 0x92      /* spc5r11 */
#define VPD_BLOCK_LIMITS 0xb0           /* SBC-3 */
#define VPD_SA_DEV_CAP 0xb0             /* SSC-3 */
#define VPD_OSD_INFO 0xb0               /* OSD */
#define VPD_BLOCK_DEV_CHARS 0xb1        /* SBC-3 */
#define VPD_MAN_ASS_SN 0xb1             /* SSC-3, ADC-2 */
#define VPD_SECURITY_TOKEN 0xb1         /* OSD */
#define VPD_TA_SUPPORTED 0xb2           /* SSC-3 */
#define VPD_LB_PROVISIONING 0xb2        /* SBC-3 */
#define VPD_REFERRALS 0xb3              /* SBC-3 */
#define VPD_AUTOMATION_DEV_SN 0xb3      /* SSC-3 */
#define VPD_SUP_BLOCK_LENS 0xb4         /* sbc4r01 */
#define VPD_DTDE_ADDRESS 0xb4           /* SSC-4 */
#define VPD_BLOCK_DEV_C_EXTENS 0xb5     /* sbc4r02 */
#define VPD_LB_PROTECTION 0xb5          /* SSC-5 */
#define VPD_ZBC_DEV_CHARS 0xb6          /* zbc-r01b */
#define VPD_BLOCK_LIMITS_EXT 0xb7       /* sbc4r08 */
#define VPD_FORMAT_PRESETS 0xb8         /* sbc4r18 */
#define VPD_CON_POS_RANGE 0xb9          /* sbc5r01 */
#define VPD_NOPE_WANT_STD_INQ -2        /* request for standard inquiry */

enum sg_vpd_invoker_e {
    SG_VPD_INV_NONE = 0,
    SG_VPD_INV_SG_INQ,
    SG_VPD_INV_SG_VPD,
};

/* This structure holds the union of options available in sg_inq and sg_vpd */
struct opts_t {
    enum sg_vpd_invoker_e invoker;  /* indicates if for sg_inq or sg_vpd */
    bool do_all;                /* sg_vpd */
    bool do_ata;                /* sg_inq */
    bool do_decode;             /* sg_inq */
    bool do_descriptors;        /* sg_inq */
    bool do_enum;               /* sg_enum */
    bool do_export;             /* sg_inq */
    bool do_force;              /* sg_inq + sg_vpd */
    bool do_only; /* sg_inq: --only after stdinq: don't fetch VPD page 0x80 */
    bool do_quiet;              /* sg_vpd */
    bool page_given;            /* sg_inq + sg_vpd */
    bool possible_nvme;         /* sg_inq */
    bool verbose_given;         /* sg_inq + sg_vpd */
    bool version_given;         /* sg_inq + sg_vpd */
    bool do_vpd;                /* sg_inq */
#ifdef SG_SCSI_STRINGS
    bool opt_new;               /* sg_inq */
#endif
    int do_block;               /* do_block */
    int do_cmddt;               /* sg_inq */
    int do_help;                /* sg_inq */
    int do_hex;                 /* sg_inq + sg_vpd */
    int do_ident;               /* sg_vpd */
    int do_long;                /* sg_inq[int] + sg_vpd[bool] */
    int do_raw;                 /* sg_inq + sg_vpd */
    int do_vendor;              /* sg_inq */
    int examine;                /* sg_vpd */
    int maxlen;                 /* sg_inq[was: resp_len] + sg_vpd */
    int num_pages;              /* sg_inq */
    int page_pdt;               /* sg_inq */
    int vend_prod_num;          /* sg_vpd */
    int verbose;                /* sg_inq + sg_vpd */
    int vpd_pn;                 /* sg_vpd */
    const char * device_name;   /* sg_inq + sg_vpd */
    const char * page_str;      /* sg_inq + sg_vpd */
    const char * inhex_fn;      /* sg_inq + sg_vpd */
    const char * vend_prod;     /* sg_vpd */
    sgj_state json_st;
};

struct svpd_values_name_t {
    int value;       /* VPD page number */
    int subvalue;    /* to differentiate if value+pdt are not unique */
    int pdt;         /* peripheral device type id, -1 is the default */
                     /* (all or not applicable) value */
    const char * acron;
    const char * name;
};

typedef int (*recurse_vpd_decodep)(struct opts_t *, sgj_opaque_p jop, int off);


sgj_opaque_p sg_vpd_js_hdr(sgj_state * jsp, sgj_opaque_p jop,
                           const char * name, const uint8_t * vpd_hdrp);
void decode_net_man_vpd(uint8_t * buff, int len, struct opts_t * op,
                        sgj_opaque_p jap);
void decode_x_inq_vpd(uint8_t * b, int len, bool protect, struct opts_t * op,
                      sgj_opaque_p jop);
void decode_softw_inf_id(uint8_t * buff, int len, struct opts_t * op,
                         sgj_opaque_p jap);
void decode_mode_policy_vpd(uint8_t * buff, int len, struct opts_t * op,
                            sgj_opaque_p jap);
void decode_power_condition(uint8_t * buff, int len, struct opts_t * op,
                            sgj_opaque_p jop);
int filter_json_dev_ids(uint8_t * buff, int len, int m_assoc,
                        struct opts_t * op, sgj_opaque_p jap);
void decode_ata_info_vpd(const uint8_t * buff, int len, struct opts_t * op,
                        sgj_opaque_p jop);
void decode_feature_sets_vpd(uint8_t * buff, int len, struct opts_t * op,
                             sgj_opaque_p jap);
void decode_dev_constit_vpd(const uint8_t * buff, int len,
                            struct opts_t * op, sgj_opaque_p jap,
                            recurse_vpd_decodep fp);
sgj_opaque_p std_inq_decode_js(const uint8_t * b, int len,
                               struct opts_t * op, sgj_opaque_p jop);
const char * pqual_str(int pqual);

void svpd_enumerate_vendor(int vend_prod_num);
int svpd_count_vendor_vpds(int vpd_pn, int vend_prod_num);
int svpd_decode_vendor(int sg_fd, struct opts_t * op, int off);
const struct svpd_values_name_t * svpd_find_vendor_by_acron(const char * ap);
int svpd_find_vp_num_by_acron(const char * vp_ap);
const struct svpd_values_name_t * svpd_find_vendor_by_num(int page_num,
                                                          int vend_prod_num);
int vpd_fetch_page(int sg_fd, uint8_t * rp, int page, int mxlen,
                   bool qt, int vb, int * rlenp);
void dup_sanity_chk(int sz_opts_t, int sz_values_name_t);

extern uint8_t * rsp_buff;
extern const char * t10_vendor_id_hr;
extern const char * t10_vendor_id_js;
extern const char * product_id_hr;
extern const char * product_id_js;
extern const char * product_rev_lev_hr;
extern const char * product_rev_lev_js;


#ifdef __cplusplus
}
#endif

#endif  /* end of SG_VPD_H */
