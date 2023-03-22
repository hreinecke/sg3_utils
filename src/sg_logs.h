#ifndef SG_LOGS_H
#define SG_LOGS_H

/*
 * Copyright (c) 2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* This is a header file for the sg_logs.c and sg_logs_vendor.c source
 * files which form the sg_logs utility */

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


#define DEF_DEV_PDT 0 /* assume disk if not unable to find PDT from INQUIRY */

#define MX_ALLOC_LEN (0xfffc)
#define MX_INLEN_ALLOC_LEN (0x1000 * 0x1000)
#define DEF_INLEN_ALLOC_LEN (0x40000)
#define SHORT_RESP_LEN 128

#define SUPP_PAGES_LPAGE 0x0
#define BUFF_OVER_UNDER_LPAGE 0x1
#define WRITE_ERR_LPAGE 0x2
#define READ_ERR_LPAGE 0x3
#define READ_REV_ERR_LPAGE 0x4
#define VERIFY_ERR_LPAGE 0x5
#define NON_MEDIUM_LPAGE 0x6
#define LAST_N_ERR_LPAGE 0x7
#define FORMAT_STATUS_LPAGE 0x8
#define LAST_N_DEFERRED_LPAGE 0xb
#define LB_PROV_LPAGE 0xc
#define TEMPERATURE_LPAGE 0xd
#define START_STOP_LPAGE 0xe
#define APP_CLIENT_LPAGE 0xf
#define SELF_TEST_LPAGE 0x10
#define SOLID_STATE_MEDIA_LPAGE 0x11
#define REQ_RECOVERY_LPAGE 0x13
#define DEVICE_STATS_LPAGE 0x14
#define BACKGROUND_SCAN_LPAGE 0x15
#define SAT_ATA_RESULTS_LPAGE 0x16
#define PROTO_SPECIFIC_LPAGE 0x18
#define STATS_LPAGE 0x19
#define PCT_LPAGE 0x1a
#define TAPE_ALERT_LPAGE 0x2e
#define IE_LPAGE 0x2f
#define NOT_SPG_SUBPG 0x0       /* specific or any page: but no subpages */
#define SUPP_SPGS_SUBPG 0xff                    /* all subpages of ... */
#define PENDING_DEFECTS_SUBPG 0x1               /* page 0x15 */
#define BACKGROUND_OP_SUBPG 0x2                 /* page 0x15 */
#define CACHE_STATS_SUBPG 0x20                  /* page 0x19 */
#define CMD_DUR_LIMITS_SUBPG 0x21               /* page 0x19 */
#define ENV_REPORTING_SUBPG 0x1                 /* page 0xd */
#define UTILIZATION_SUBPG 0x1                   /* page 0xe */
#define ENV_LIMITS_SUBPG 0x2                    /* page 0xd */
#define LPS_MISALIGNMENT_SUBPG 0x3              /* page 0x15 */
#define ZONED_BLOCK_DEV_STATS_SUBPG 0x1         /* page 0x14 */
#define LAST_N_INQUIRY_DATA_CH_SUBPG 0x1        /* page 0xb */
#define LAST_N_MODE_PG_DATA_CH_SUBPG 0x2        /* page 0xb */

/* Vendor product numbers/identifiers */
#define VP_NONE   (-1)
#define VP_SEAG   0
#define VP_HITA   1
#define VP_TOSH   2
#define VP_LTO5   3
#define VP_LTO6   4
#define VP_ALL    99

#define MVP_OFFSET 8

/* Vendor product masks
 * MVP_STD OR-ed with MVP_<vendor> is a T10 defined lpage with vendor
 * specific parameter codes (e.g. Information Exceptions lpage [0x2f]) */
#define MVP_STD    (1 << (MVP_OFFSET - 1))
#define MVP_SEAG   (1 << (VP_SEAG + MVP_OFFSET))
#define MVP_HITA   (1 << (VP_HITA + MVP_OFFSET))
#define MVP_TOSH   (1 << (VP_TOSH + MVP_OFFSET))
#define MVP_LTO5   (1 << (VP_LTO5 + MVP_OFFSET))
#define MVP_LTO6   (1 << (VP_LTO6 + MVP_OFFSET))

#define OVP_LTO    (MVP_LTO5 | MVP_LTO6)
#define OVP_ALL    (~0)


#define PCB_STR_LEN 128

#define LOG_SENSE_PROBE_ALLOC_LEN 4
#define LOG_SENSE_DEF_TIMEOUT 64        /* seconds */

struct opts_t;

struct log_elem {
    int pg_code;
    int subpg_code;     /* only unless subpg_high>0 then this is only */
    int subpg_high;     /* when >0 this is high end of subpage range */
    int pdt;            /* -1 for all */
    int flags;          /* bit mask; or-ed with MVP_* constants */
    const char * name;
    const char * acron;
    bool (*show_pagep)(const uint8_t * resp, int len, struct opts_t * op,
                       sgj_opaque_p jop);
                        /* Returns true if done */
};

struct opts_t {
    bool do_full;
    bool do_json;
    bool do_name;
    bool do_pcb;
    bool do_ppc;
    bool do_pcreset;
    bool do_select;
    bool do_sp;
    bool do_temperature;
    bool do_transport;
    bool exclude_vendor;
    bool filter_given;
    bool maxlen_given;
    bool o_readonly;
    bool opt_new;
    bool verbose_given;
    bool version_given;
    int do_all;
    int do_brief;
    int do_enumerate;
    int do_help;
    int do_hex;
    int do_list;
    int do_raw;
    int dstrhex_no_ascii;       /* value for dStrHex() no_ascii argument */
    int h2s_oformat;    /* value for hex2str() oformat argument */
    int vend_prod_num;  /* one of the VP_* constants or -1 (def) */
    int deduced_vpn;    /* deduced vendor_prod_num; from INQUIRY, etc */
    int verbose;
    int filter;
    int page_control;
    int maxlen;
    int pg_code;
    int subpg_code;
    int paramp;
    int no_inq;
    int dev_pdt;        /* from device or --pdt=DT */
    int decod_subpg_code;
    int undefined_hex;  /* hex format of undefined/unrecognized fields */
    const char * device_name;
    const char * inhex_fn;
    const char * json_arg;
    const char * js_file;
    const char * pg_arg;
    const char * vend_prod;
    const struct log_elem * lep;
    sgj_state json_st;
};

struct vp_name_t {
    int vend_prod_num;       /* vendor/product identifier */
    const char * acron;
    const char * name;
    const char * t10_vendorp;
    const char * t10_productp;
};

extern const char * const in_hex;
extern const char * const param_c;
extern const char * const param_c_sn;
extern const char * const rsv_s;
extern const char * const unkn_s;
extern const char * const vend_spec;

void
dStrRaw(const uint8_t * str, int len);
sgj_opaque_p sg_log_js_hdr(sgj_state * jsp, sgj_opaque_p jop,
			   const char * name, const uint8_t * log_hdrp);
void js_pcb(sgj_state * jsp, sgj_opaque_p jop, int pcb);
char * get_pcb_str(int pcb, char * outp, int maxoutlen);

bool show_data_compression_page(const uint8_t * resp, int len,
                                struct opts_t * op, sgj_opaque_p jop);
bool show_tape_usage_page(const uint8_t * resp, int len,
                          struct opts_t * op, sgj_opaque_p jop);
bool show_tape_capacity_page(const uint8_t * resp, int len,
                              struct opts_t * op, sgj_opaque_p jop);
bool show_seagate_cache_page(const uint8_t * resp, int len,
                             struct opts_t * op, sgj_opaque_p jop);
bool show_seagate_factory_page(const uint8_t * resp, int len,
                               struct opts_t * op, sgj_opaque_p jop);
bool show_seagate_farm_page(const uint8_t * resp, int len,
                            struct opts_t * op, sgj_opaque_p jop);
bool show_hgst_perf_page(const uint8_t * resp, int len,
                         struct opts_t * op, sgj_opaque_p jop);
bool show_hgst_misc_page(const uint8_t * resp, int len,
                         struct opts_t * op, sgj_opaque_p jop);

#ifdef __cplusplus
}
#endif

#endif  /* end of SG_LOGS_H */
