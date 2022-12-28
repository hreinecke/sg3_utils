/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 2000-2022 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program outputs information provided by a SCSI LOG SENSE command
 * and in some cases issues a LOG SELECT command.
 *
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_lib_names.h"
#include "sg_cmds_basic.h"
#ifdef SG_LIB_WIN32
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */
#endif
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "2.17 20221226";    /* spc6r06 + sbc5r03 */

#define MY_NAME "sg_logs"

#define DEF_DEV_PDT 0 /* assume disk if not unable to find PDT from INQUIRY */

#define MX_ALLOC_LEN (0xfffc)
#define MX_INLEN_ALLOC_LEN (0x800000)
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
#define NOT_SPG_SUBPG 0x0                       /* any page: no subpages */
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

static uint8_t * rsp_buff;
static uint8_t * free_rsp_buff;
static int rsp_buff_sz = MX_ALLOC_LEN + 4;
static const int parr_sz = 4096;

static const char * const as_s_s = "as_string";
static const char * const in_hex = "in_hex";
static const char * const lba_sn = "logical_block_address";
static const char * const not_avail = "not available";
static const char * const not_rep = "not reported";
static const char * const param_c = "Parameter code";
static const char * const pg_c_sn = "page_code";
static const char * const spg_c_sn = "subpage_code";
static const char * const param_c_sn = "parameter_code";
static const char * const param_s = "parameter";
static const char * const rstrict_s = "restricted";
static const char * const rsv_s = "reserved";
static const char * const vend_spec = "vendor specific";
static const char * const s_key = "sense key";
static const char * const unkn_s = "unknown";
static const char * const lp_sn = "log_page";

static struct option long_options[] = {
    {"All", no_argument, 0, 'A'},   /* equivalent to '-aa' */
    {"ALL", no_argument, 0, 'A'},   /* equivalent to '-aa' */
    {"all", no_argument, 0, 'a'},
    {"brief", no_argument, 0, 'b'},
    {"control", required_argument, 0, 'c'},
    {"enumerate", no_argument, 0, 'e'},
    {"exclude", no_argument, 0, 'E'},
    {"filter", required_argument, 0, 'f'},
    {"full", no_argument, 0, 'F'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"in", required_argument, 0, 'i'},
    {"inhex", required_argument, 0, 'i'},
    {"json", optional_argument, 0, 'j'},
    {"js_file", required_argument, 0, 'J'},
    {"js-file", required_argument, 0, 'J'},
    {"list", no_argument, 0, 'l'},
    {"maxlen", required_argument, 0, 'm'},
    {"name", no_argument, 0, 'n'},
    {"new", no_argument, 0, 'N'},
    {"no_inq", no_argument, 0, 'x'},
    {"no-inq", no_argument, 0, 'x'},
    {"old", no_argument, 0, 'O'},
    {"page", required_argument, 0, 'p'},
    {"paramp", required_argument, 0, 'P'},
    {"pcb", no_argument, 0, 'q'},
    {"ppc", no_argument, 0, 'Q'},
    {"pdt", required_argument, 0, 'D'},
    {"raw", no_argument, 0, 'r'},
    {"readonly", no_argument, 0, 'X'},
    {"reset", no_argument, 0, 'R'},
    {"sp", no_argument, 0, 's'},
    {"select", no_argument, 0, 'S'},
    {"temperature", no_argument, 0, 't'},
    {"transport", no_argument, 0, 'T'},
    {"undefined", no_argument, 0, 'u'},
    {"vendor", required_argument, 0, 'M'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

struct opts_t {
    bool do_full;
    bool do_json;
    bool do_name;
    bool do_pcb;
    bool do_ppc;
    bool do_raw;
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
    const char * in_fn;
    const char * json_arg;
    const char * js_file;
    const char * pg_arg;
    const char * vend_prod;
    const struct log_elem * lep;
    sgj_state json_st;
};


struct log_elem {
    int pg_code;
    int subpg_code;     /* only unless subpg_high>0 then this is only */
    int subpg_high;     /* when >0 this is high end of subpage range */
    int pdt;            /* -1 for all */
    int flags;          /* bit mask; or-ed with MVP_* constants */
    const char * name;
    const char * acron;
    bool (*show_pagep)(const uint8_t * resp, int len,
                       struct opts_t * op, sgj_opaque_p jop);
                        /* Returns true if done */
};

struct vp_name_t {
    int vend_prod_num;       /* vendor/product identifier */
    const char * acron;
    const char * name;
    const char * t10_vendorp;
    const char * t10_productp;
};

static const char * ls_s = "log_sense: ";

static bool show_supported_pgs_page(const uint8_t * resp, int len,
                                    struct opts_t * op, sgj_opaque_p jop);
static bool show_supported_pgs_sub_page(const uint8_t * resp, int len,
                                        struct opts_t * op, sgj_opaque_p jop);
static bool show_buffer_over_under_run_page(const uint8_t * resp, int len,
                                            struct opts_t * op,
                                            sgj_opaque_p jop);
static bool show_error_counter_page(const uint8_t * resp, int len,
                                    struct opts_t * op, sgj_opaque_p jop);
static bool show_non_medium_error_page(const uint8_t * resp, int len,
                                       struct opts_t * op, sgj_opaque_p jop);
static bool show_last_n_error_page(const uint8_t * resp, int len,
                                   struct opts_t * op, sgj_opaque_p jop);
static bool show_format_status_page(const uint8_t * resp, int len,
                                    struct opts_t * op, sgj_opaque_p jop);
static bool show_last_n_deferred_error_page(const uint8_t * resp, int len,
                                            struct opts_t * op,
                                            sgj_opaque_p jop);
static bool show_last_n_inq_data_ch_page(const uint8_t * resp, int len,
                                         struct opts_t * op,
                                         sgj_opaque_p jop);
static bool show_last_n_mode_pg_data_ch_page(const uint8_t * resp, int len,
                                             struct opts_t * op,
                                             sgj_opaque_p jop);
static bool show_lb_provisioning_page(const uint8_t * resp, int len,
                                      struct opts_t * op, sgj_opaque_p jop);
static bool show_sequential_access_page(const uint8_t * resp, int len,
                                        struct opts_t * op, sgj_opaque_p jop);
static bool show_temperature_page(const uint8_t * resp, int len,
                                  struct opts_t * op, sgj_opaque_p jop);
static bool show_start_stop_page(const uint8_t * resp, int len,
                                 struct opts_t * op, sgj_opaque_p jop);
static bool show_utilization_page(const uint8_t * resp, int len,
                                  struct opts_t * op, sgj_opaque_p jop);
static bool show_app_client_page(const uint8_t * resp, int len,
                                 struct opts_t * op, sgj_opaque_p jop);
static bool show_self_test_page(const uint8_t * resp, int len,
                                struct opts_t * op, sgj_opaque_p jop);
static bool show_solid_state_media_page(const uint8_t * resp, int len,
                                        struct opts_t * op, sgj_opaque_p jop);
static bool show_device_stats_page(const uint8_t * resp, int len,
                                   struct opts_t * op, sgj_opaque_p jop);
static bool show_media_stats_page(const uint8_t * resp, int len,
                                  struct opts_t * op, sgj_opaque_p jop);
static bool show_dt_device_status_page(const uint8_t * resp, int len,
                                       struct opts_t * op, sgj_opaque_p jop);
static bool show_tapealert_response_page(const uint8_t * resp, int len,
                                         struct opts_t * op,
                                         sgj_opaque_p jop);
static bool show_requested_recovery_page(const uint8_t * resp, int len,
                                         struct opts_t * op,
                                         sgj_opaque_p jop);
static bool show_background_scan_results_page(const uint8_t * resp, int len,
                                              struct opts_t * op,
                                              sgj_opaque_p jop);
static bool show_zoned_block_dev_stats(const uint8_t * resp, int len,
                                       struct opts_t * op, sgj_opaque_p jop);
static bool show_pending_defects_page(const uint8_t * resp, int len,
                                      struct opts_t * op, sgj_opaque_p jop);
static bool show_background_op_page(const uint8_t * resp, int len,
                                    struct opts_t * op, sgj_opaque_p jop);
static bool show_lps_misalignment_page(const uint8_t * resp, int len,
                                       struct opts_t * op, sgj_opaque_p jop);
static bool show_element_stats_page(const uint8_t * resp, int len,
                                    struct opts_t * op, sgj_opaque_p jop);
static bool show_service_buffer_info_page(const uint8_t * resp, int len,
                                          struct opts_t * op,
                                          sgj_opaque_p jop);
static bool show_ata_pt_results_page(const uint8_t * resp, int len,
                                     struct opts_t * op, sgj_opaque_p jop);
static bool show_tape_diag_data_page(const uint8_t * resp, int len,
                                     struct opts_t * op, sgj_opaque_p jop);
static bool show_mchanger_diag_data_page(const uint8_t * resp, int len,
                                         struct opts_t * op,
                                         sgj_opaque_p jop);
static bool show_non_volatile_cache_page(const uint8_t * resp, int len,
                                         struct opts_t * op,
                                         sgj_opaque_p jop);
static bool show_volume_stats_pages(const uint8_t * resp, int len,
                                    struct opts_t * op, sgj_opaque_p jop);
static bool show_protocol_specific_port_page(const uint8_t * resp, int len,
                                             struct opts_t * op,
                                             sgj_opaque_p jop);
static bool show_stats_perform_pages(const uint8_t * resp, int len,
                                     struct opts_t * op, sgj_opaque_p jop);
static bool show_cache_stats_page(const uint8_t * resp, int len,
                                  struct opts_t * op, sgj_opaque_p jop);
static bool show_power_condition_transitions_page(const uint8_t * resp,
                                 int len, struct opts_t * op,
                                                  sgj_opaque_p jop);
static bool show_environmental_reporting_page(const uint8_t * resp, int len,
                                              struct opts_t * op,
                                              sgj_opaque_p jop);
static bool show_environmental_limits_page(const uint8_t * resp, int len,
                                           struct opts_t * op,
                                           sgj_opaque_p jop);
static bool show_cmd_dur_limits_page(const uint8_t * resp, int len,
                                     struct opts_t * op, sgj_opaque_p jop);
static bool show_data_compression_page(const uint8_t * resp, int len,
                                       struct opts_t * op, sgj_opaque_p jop);
static bool show_tape_alert_ssc_page(const uint8_t * resp, int len,
                                     struct opts_t * op, sgj_opaque_p jop);
static bool show_ie_page(const uint8_t * resp, int len,
                         struct opts_t * op, sgj_opaque_p jop);
static bool show_tape_usage_page(const uint8_t * resp, int len,
                                 struct opts_t * op, sgj_opaque_p jop);
static bool show_tape_capacity_page(const uint8_t * resp, int len,
                                     struct opts_t * op, sgj_opaque_p jop);
static bool show_seagate_cache_page(const uint8_t * resp, int len,
                                    struct opts_t * op, sgj_opaque_p jop);
static bool show_seagate_factory_page(const uint8_t * resp, int len,
                                      struct opts_t * op, sgj_opaque_p jop);
static bool show_hgst_perf_page(const uint8_t * resp, int len,
                                struct opts_t * op, sgj_opaque_p jop);
static bool show_hgst_misc_page(const uint8_t * resp, int len,
                                struct opts_t * op, sgj_opaque_p jop);

/* elements in page_number/subpage_number order */
static struct log_elem log_arr[] = {
    {SUPP_PAGES_LPAGE, 0, 0, -1, MVP_STD, "Supported log pages", "sp",
     show_supported_pgs_page},          /* 0, 0 */
    {SUPP_PAGES_LPAGE, SUPP_SPGS_SUBPG, 0, -1, MVP_STD, "Supported log pages "
     "and subpages", "ssp", show_supported_pgs_sub_page}, /* 0, 0xff */
    {BUFF_OVER_UNDER_LPAGE, 0, 0, -1, MVP_STD, "Buffer over-run/under-run",
     "bou", show_buffer_over_under_run_page},  /* 0x1, 0x0 */
    {WRITE_ERR_LPAGE, 0, 0, -1, MVP_STD, "Write error counters", "we",
     show_error_counter_page},          /* 0x2, 0x0 */
    {READ_ERR_LPAGE, 0, 0, -1, MVP_STD, "Read error counters", "re",
     show_error_counter_page},          /* 0x3, 0x0 */
    {READ_REV_ERR_LPAGE, 0, 0, -1, MVP_STD, "Read reverse error counters",
     "rre", show_error_counter_page},          /* 0x4, 0x0 */
    {VERIFY_ERR_LPAGE, 0, 0, -1, MVP_STD, "Verify error counters", "ve",
     show_error_counter_page},          /* 0x5, 0x0 */
    {NON_MEDIUM_LPAGE, 0, 0, -1, MVP_STD, "Non medium", "nm",
     show_non_medium_error_page},       /* 0x6, 0x0 */
    {LAST_N_ERR_LPAGE, 0, 0, -1, MVP_STD, "Last n error", "lne",
     show_last_n_error_page},           /* 0x7, 0x0 */
    {FORMAT_STATUS_LPAGE, 0, 0, 0, MVP_STD, "Format status", "fs",
     show_format_status_page},          /* 0x8, 0x0  SBC */
    {LAST_N_DEFERRED_LPAGE, 0, 0, -1, MVP_STD, "Last n deferred error", "lnd",
     show_last_n_deferred_error_page},  /* 0xb, 0x0 */
    {LAST_N_DEFERRED_LPAGE, LAST_N_INQUIRY_DATA_CH_SUBPG, 0, -1, MVP_STD,
     "Last n inquiry data changed", "lnic",
     show_last_n_inq_data_ch_page},     /* 0xb, 0x1 */
    {LAST_N_DEFERRED_LPAGE, LAST_N_MODE_PG_DATA_CH_SUBPG, 0, -1, MVP_STD,
     "Last n mode page data changed", "lnmc",
     show_last_n_mode_pg_data_ch_page}, /* 0xb, 0x2 */
    {LB_PROV_LPAGE, 0, 0, 0, MVP_STD, "Logical block provisioning", "lbp",
     show_lb_provisioning_page},        /* 0xc, 0x0  SBC */
    {0xc, 0, 0, PDT_TAPE, MVP_STD, "Sequential access device", "sad",
     show_sequential_access_page},      /* 0xc, 0x0  SSC */
    {TEMPERATURE_LPAGE, 0, 0, -1, MVP_STD, "Temperature", "temp",
     show_temperature_page},            /* 0xd, 0x0 */
    {TEMPERATURE_LPAGE, ENV_REPORTING_SUBPG, 0, -1, MVP_STD,  /* 0xd, 0x1 */
     "Environmental reporting", "enr", show_environmental_reporting_page},
    {TEMPERATURE_LPAGE, ENV_LIMITS_SUBPG, 0, -1, MVP_STD,     /* 0xd, 0x2 */
     "Environmental limits", "enl", show_environmental_limits_page},
    {START_STOP_LPAGE, 0, 0, -1, MVP_STD, "Start-stop cycle counter", "sscc",
     show_start_stop_page},             /* 0xe, 0x0 */
    {START_STOP_LPAGE, UTILIZATION_SUBPG, 0, 0, MVP_STD, "Utilization",
     "util", show_utilization_page},    /* 0xe, 0x1 SBC */    /* sbc4r04 */
    {APP_CLIENT_LPAGE, 0, 0, -1, MVP_STD, "Application client", "ac",
     show_app_client_page},             /* 0xf, 0x0 */
    {SELF_TEST_LPAGE, 0, 0, -1, MVP_STD, "Self test results", "str",
     show_self_test_page},              /* 0x10, 0x0 */
    {SOLID_STATE_MEDIA_LPAGE, 0, 0, 0, MVP_STD, "Solid state media", "ssm",
     show_solid_state_media_page},      /* 0x11, 0x0  SBC */
    {0x11, 0, 0, PDT_TAPE, MVP_STD, "DT Device status", "dtds",
     show_dt_device_status_page},       /* 0x11, 0x0  SSC,ADC */
    {0x12, 0, 0, PDT_TAPE, MVP_STD, "Tape alert response", "tar",
     show_tapealert_response_page},      /* 0x12, 0x0  ADC,SSC */
    {REQ_RECOVERY_LPAGE, 0, 0, PDT_TAPE, MVP_STD, "Requested recovery", "rr",
     show_requested_recovery_page},     /* 0x13, 0x0  SSC,ADC */
    {DEVICE_STATS_LPAGE, 0, 0, PDT_TAPE, MVP_STD, "Device statistics", "ds",
     show_device_stats_page},           /* 0x14, 0x0  SSC,ADC */
    {DEVICE_STATS_LPAGE, 0, 0, PDT_MCHANGER, MVP_STD,   /* 0x14, 0x0  SMC */
     "Media changer statistics", "mcs", show_media_stats_page},
    {DEVICE_STATS_LPAGE, ZONED_BLOCK_DEV_STATS_SUBPG,   /* 0x14,0x1 zbc2r01 */
     0, 0, MVP_STD, "Zoned block device statistics", "zbds",
     show_zoned_block_dev_stats},
    {BACKGROUND_SCAN_LPAGE, 0, 0, 0, MVP_STD, "Background scan results",
     "bsr", show_background_scan_results_page}, /* 0x15, 0x0  SBC */
    {BACKGROUND_SCAN_LPAGE, BACKGROUND_OP_SUBPG, 0, 0, MVP_STD,
     "Background operation", "bop", show_background_op_page},
                                        /* 0x15, 0x2  SBC */
    {BACKGROUND_SCAN_LPAGE, LPS_MISALIGNMENT_SUBPG, 0, 0, MVP_STD,
     "LPS misalignment", "lps", show_lps_misalignment_page},
                                        /* 0x15, 0x3  SBC-4 */
    {0x15, 0, 0, PDT_MCHANGER, MVP_STD, "Element statistics", "els",
     show_element_stats_page},          /* 0x15, 0x0  SMC */
    {0x15, 0, 0, PDT_ADC, MVP_STD, "Service buffers information", "sbi",
     show_service_buffer_info_page},    /* 0x15, 0x0  ADC */
    {BACKGROUND_SCAN_LPAGE, PENDING_DEFECTS_SUBPG, 0, 0, MVP_STD,
     "Pending defects", "pd", show_pending_defects_page}, /* 0x15, 0x1  SBC */
    {SAT_ATA_RESULTS_LPAGE, 0, 0, 0, MVP_STD, "ATA pass-through results",
     "aptr", show_ata_pt_results_page}, /* 0x16, 0x0  SAT */
    {0x16, 0, 0, PDT_TAPE, MVP_STD, "Tape diagnostic data", "tdd",
     show_tape_diag_data_page},         /* 0x16, 0x0  SSC */
    {0x16, 0, 0, PDT_MCHANGER, MVP_STD, "Media changer diagnostic data",
     "mcdd", show_mchanger_diag_data_page}, /* 0x16, 0x0  SMC */
    {0x17, 0, 0, 0, MVP_STD, "Non volatile cache", "nvc",
     show_non_volatile_cache_page},     /* 0x17, 0x0  SBC */
    {0x17, 0, 0xf, PDT_TAPE, MVP_STD, "Volume statistics", "vs",
     show_volume_stats_pages},          /* 0x17, 0x0...0xf  SSC */
    {PROTO_SPECIFIC_LPAGE, 0, 0, -1, MVP_STD, "Protocol specific port",
     "psp", show_protocol_specific_port_page},  /* 0x18, 0x0  */
    {STATS_LPAGE, 0, 0, -1, MVP_STD, "General Statistics and Performance",
     "gsp", show_stats_perform_pages},  /* 0x19, 0x0  */
    {STATS_LPAGE, 0x1, 0x1f, -1, MVP_STD, "Group Statistics and Performance",
     "grsp", show_stats_perform_pages}, /* 0x19, 0x1...0x1f  */
    {STATS_LPAGE, CACHE_STATS_SUBPG, 0, -1, MVP_STD,    /* 0x19, 0x20  */
     "Cache memory statistics", "cms", show_cache_stats_page},
    {STATS_LPAGE, CMD_DUR_LIMITS_SUBPG, 0, -1, MVP_STD, /* 0x19, 0x21  */
     "Command duration limits statistics", "cdl",
     show_cmd_dur_limits_page /* spc6r01 */ },
    {PCT_LPAGE, 0, 0, -1, MVP_STD, "Power condition transitions", "pct",
     show_power_condition_transitions_page}, /* 0x1a, 0  */
    {0x1b, 0, 0, PDT_TAPE, MVP_STD, "Data compression", "dc",
     show_data_compression_page},       /* 0x1b, 0  SSC */
    {0x2d, 0, 0, PDT_TAPE, MVP_STD, "Current service information", "csi",
     NULL},                             /* 0x2d, 0  SSC */
    {TAPE_ALERT_LPAGE, 0, 0, PDT_TAPE, MVP_STD, "Tape alert", "ta",
     show_tape_alert_ssc_page},         /* 0x2e, 0  SSC */
    {IE_LPAGE, 0, 0, -1, (MVP_STD | MVP_HITA),
     "Informational exceptions", "ie", show_ie_page},       /* 0x2f, 0  */
/* vendor specific */
    {0x30, 0, 0, PDT_DISK, MVP_HITA, "Performance counters (Hitachi)",
     "pc_hi", show_hgst_perf_page},     /* 0x30, 0  SBC */
    {0x30, 0, 0, PDT_TAPE, OVP_LTO, "Tape usage (lto-5, 6)", "tu_",
     show_tape_usage_page},             /* 0x30, 0  SSC */
    {0x31, 0, 0, PDT_TAPE, OVP_LTO, "Tape capacity (lto-5, 6)",
     "tc_", show_tape_capacity_page},   /* 0x31, 0  SSC */
    {0x32, 0, 0, PDT_TAPE, MVP_LTO5, "Data compression (lto-5)",
     "dc_", show_data_compression_page}, /* 0x32, 0  SSC; redirect to 0x1b */
    {0x33, 0, 0, PDT_TAPE, MVP_LTO5, "Write errors (lto-5)", "we_",
     NULL},                             /* 0x33, 0  SSC */
    {0x34, 0, 0, PDT_TAPE, MVP_LTO5, "Read forward errors (lto-5)",
     "rfe_", NULL},                             /* 0x34, 0  SSC */
    {0x35, 0, 0, PDT_TAPE, OVP_LTO, "DT Device Error (lto-5, 6)",
     "dtde_", NULL},                             /* 0x35, 0  SSC */
    {0x37, 0, 0, PDT_DISK, MVP_SEAG, "Cache (seagate)", "c_se",
     show_seagate_cache_page},          /* 0x37, 0  SBC */
    {0x37, 0, 0, PDT_DISK, MVP_HITA, "Miscellaneous (hitachi)", "mi_hi",
     show_hgst_misc_page},                             /* 0x37, 0  SBC */
    {0x37, 0, 0, PDT_TAPE, MVP_LTO5, "Performance characteristics "
     "(lto-5)", "pc_", NULL},                             /* 0x37, 0  SSC */
    {0x38, 0, 0, PDT_TAPE, MVP_LTO5, "Blocks/bytes transferred "
     "(lto-5)", "bbt_", NULL},                             /* 0x38, 0  SSC */
    {0x39, 0, 0, PDT_TAPE, MVP_LTO5, "Host port 0 interface errors "
     "(lto-5)", "hp0_", NULL},                             /* 0x39, 0  SSC */
    {0x3a, 0, 0, PDT_TAPE, MVP_LTO5, "Drive control verification "
     "(lto-5)", "dcv_", NULL},                             /* 0x3a, 0  SSC */
    {0x3b, 0, 0, PDT_TAPE, MVP_LTO5, "Host port 1 interface errors "
     "(lto-5)", "hp1_", NULL},                             /* 0x3b, 0  SSC */
    {0x3c, 0, 0, PDT_TAPE, MVP_LTO5, "Drive usage information "
     "(lto-5)", "dui_", NULL},                             /* 0x3c, 0  SSC */
    {0x3d, 0, 0, PDT_TAPE, MVP_LTO5, "Subsystem statistics (lto-5)",
     "ss_", NULL},                             /* 0x3d, 0  SSC */
    {0x3e, 0, 0, PDT_DISK, MVP_SEAG, "Factory (seagate)", "f_se",
     show_seagate_factory_page},        /* 0x3e, 0  SBC */
    {0x3e, 0, 0, PDT_DISK, MVP_HITA, "Factory (hitachi)", "f_hi",
     NULL},                             /* 0x3e, 0  SBC */
    {0x3e, 0, 0, PDT_TAPE, OVP_LTO, "Device Status (lto-5, 6)",
     "ds_", NULL},                             /* 0x3e, 0  SSC */

    {-1, -1, -1, -1, 0, NULL, "zzzzz", NULL},           /* end sentinel */
};

/* Supported vendor product codes */
/* Arrange in alphabetical order by acronym */
static struct vp_name_t vp_arr[] = {
    {VP_SEAG, "sea", "Seagate", "SEAGATE", NULL},
    {VP_HITA, "hit", "Hitachi", "HGST", NULL},
    {VP_HITA, "wdc", "WDC/Hitachi", "WDC", NULL},
    {VP_TOSH, "tos", "Toshiba", "TOSHIBA", NULL},
    {VP_LTO5, "lto5", "LTO-5 (tape drive consortium)", NULL, NULL},
    {VP_LTO6, "lto6", "LTO-6 (tape drive consortium)", NULL, NULL},
    {VP_ALL, "all", "enumerate all vendor specific", NULL, NULL},
    {0, NULL, NULL, NULL, NULL},
};

static char t10_vendor_str[10];
static char t10_product_str[18];

#ifdef SG_LIB_WIN32
static bool win32_spt_init_state = false;
static bool win32_spt_curr_state = false;
#endif


static void
usage(int hval)
{
    if (1 == hval) {
        pr2serr(
           "Usage: sg_logs [-ALL] [--all] [--brief] [--control=PC] "
           "[--enumerate]\n"
           "               [--exclude] [--filter=FL] [--full] [--help] "
           "[--hex]\n"
           "               [--in=FN] [--json[=JO]] [--js_file=JFN] "
           "[--list]\n"
           "               [--maxlen=LEN] [--name] [--no_inq] "
           "[--page=PG]\n"
           "               [--paramp=PP] [--pcb] [--ppc] [--pdt=DT] "
           "[--raw]\n"
           "               [--readonly] [--reset] [--select] [--sp] "
           "[--temperature]\n"
           "               [--transport] [--undefined] [--vendor=VP] "
           "[--verbose]\n"
           "               [--version] DEVICE\n"
           "  where the main options are:\n"
           "    --ALL|-A        fetch and decode all log pages and "
           "subpages\n"
           "    --all|-a        fetch and decode all log pages, but not "
           "subpages; use\n"
           "                    twice to fetch and decode all log pages "
           "and subpages\n"
           "    --brief|-b      shorten the output of some log pages\n"
           "    --enumerate|-e    enumerate known pages, ignore DEVICE. "
           "Sort order,\n"
           "                      '-e': all by acronym; '-ee': non-vendor "
           "by acronym;\n"
           "                      '-eee': all numerically; '-eeee': "
           "non-v numerically\n"
           "    --filter=FL|-f FL    FL is parameter code to display (def: "
           "all);\n"
           "                         with '-e' then FL>=0 enumerate that "
           "pdt + spc\n"
           "                         FL=-1 all (default), FL=-2 spc only\n"
           "    --full|-F       drill down in application client log page\n"
           "    --help|-h       print usage message then exit. Use twice "
           "for more help\n"
           "    --hex|-H        output response in hex (default: decode if "
           "known)\n"
           "    --in=FN|-i FN    FN is a filename containing a log page "
           "in ASCII hex\n"
           "                     or binary if --raw also given. --inhex=FN "
           "also accepted\n"
           "    --json[=JO]|-j[JO]    output in JSON instead of human "
           "readable\n"
           "                          test. Use --json=? for JSON help\n"
           "    --js-file=JFN|-J JFN    JFN is a filename to which JSON "
           "output is\n"
           "                            written (def: stdout); truncates "
           "then writes\n"
           "    --list|-l       list supported log pages; twice: list "
           "supported log\n"
           "                    pages and subpages page; thrice: merge of "
           "both pages\n"
           "    --page=PG|-p PG    PG is either log page acronym, PGN or "
           "PGN,SPGN\n"
           "                       where (S)PGN is a (sub) page number\n");
        pr2serr(
           "    --raw|-r        either output response in binary to stdout "
           "or, if\n"
           "                    '--in=FN' is given, FN is decoded as "
           "binary\n"
           "    --temperature|-t    decode temperature (log page 0xd or "
           "0x2f)\n"
           "    --transport|-T    decode transport (protocol specific port "
           "0x18) page\n"
           "    --vendor=VP|-M VP    vendor/product abbreviation [or "
           "number]\n"
           "    --verbose|-v    increase verbosity\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command and decodes "
           "the response.\nIf only DEVICE is given then '-p sp' (supported "
           "pages) is assumed. Use\n'-e' to see known pages and their "
           "acronyms. For more help use '-hh'.\n");
    } else if (hval > 1) {
        pr2serr(
           "  where sg_logs' lesser used options are:\n"
           "    --control=PC|-c PC    page control(PC) (default: 1)\n"
           "                          0: current threshold, 1: current "
           "cumulative\n"
           "                          2: default threshold, 3: default "
           "cumulative\n"
           "    --exclude|-E    exclude vendor specific pages and "
           "parameters\n"
           "    --list|-l       list supported log page names (equivalent to "
           "'-p sp')\n"
           "                    use twice to list supported log page and "
           "subpage names\n"
           "    --maxlen=LEN|-m LEN    max response length (def: 0 "
           "-> everything)\n"
           "                           when > 1 will request LEN bytes\n"
           "    --name|-n       decode some pages into multiple name=value "
           "lines\n"
           "    --no_inq|-x     no initial INQUIRY output (twice: and no "
           "INQUIRY call)\n"
           "    --old|-O        use old interface (use as first option)\n"
           "    --paramp=PP|-P PP    place PP in parameter pointer field in "
           "cdb (def: 0)\n"
           "    --pcb|-q        show parameter control bytes in decoded "
           "output\n"
           "    --ppc|-Q        set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
           "    --pdt=DT|-D DT    DT is peripheral device type to use with "
           "'--in=FN'\n"
           "                      or when '--no_inq' is used\n"
           "    --readonly|-X    open DEVICE read-only (def: first "
           "read-write then if\n"
           "                     fails try open again read-only)\n"
           "    --reset|-R      reset log parameters (takes PC and SP into "
           "account)\n"
           "                    (uses PCR bit in LOG SELECT)\n"
           "    --select|-S     perform LOG SELECT (def: LOG SENSE)\n"
           "    --sp|-s         set the Saving Parameters (SP) bit (def: "
           "0)\n"
           "    --undefined|-u    hex format for undefined/unrecognized "
           "fields,\n"
           "                      use one or more times; format as per "
           "--hex\n"
           "    --version|-V    output version string then exit\n\n"
           "If DEVICE and --select are given, a LOG SELECT command will be "
           "issued.\nIf DEVICE is not given and '--in=FN' is given then FN "
           "will decoded as if\nit were a log page. The contents of FN "
           "generated by either a prior\n'sg_logs -HHH ...' invocation or "
           "by a text editor.\nLog pages defined in SPC are common "
           "to all device types.\n");
    }
}

static void
usage_old()
{
    printf("Usage: sg_logs [-a] [-A] [-b] [-c=PC] [-D=DT] [-e] [-E] [-f=FL] "
           "[-F]\n"
           "               [-h] [-H] [-i=FN] [-j] [-l] [-L] [-m=LEN] [-M=VP] "
           "[-n]\n"
           "               [-p=PG] [-paramp=PP] [-pcb] [-ppc] [-r] [-select] "
           "[-sp]i\n"
           "               [-t] [-T] [-u] [-v] [-V] [-x] [-X] [-?] DEVICE\n"
           "  where:\n"
           "    -a     fetch and decode all log pages\n"
           "    -A     fetch and decode all log pages and subpages\n"
           "    -b     shorten the output of some log pages\n"
           "    -c=PC    page control(PC) (default: 1)\n"
           "                  0: current threshold, 1: current cumulative\n"
           "                  2: default threshold, 3: default cumulative\n"
           "    -e     enumerate known log pages\n"
           "    -D=DT    DT is peripheral device type to use with "
           "'--in=FN'\n"
           "    -E     exclude vendor specific pages and parameters\n"
           "    -f=FL    filter match parameter code or pdt\n"
           "    -F     drill down in application client log page\n"
           "    -h     output in hex (default: decode if known)\n"
           "    -H     output in hex (same as '-h')\n"
           "    -i=FN    FN is a filename containing a log page "
           "in ASCII hex.\n"
           "    -j     produce JSON output instead of human readable "
           "form\n"
           "    -l     list supported log page names (equivalent to "
           "'-p=0')\n"
           "    -L     list supported log page and subpages names "
           "(equivalent to\n"
           "           '-p=0,ff')\n"
           "    -m=LEN   max response length (decimal) (def: 0 "
           "-> everything)\n"
           "    -M=VP    vendor/product abbreviation [or number]\n"
           "    -n       decode some pages into multiple name=value "
           "lines\n"
           "    -N|--new    use new interface\n"
           "    -p=PG    PG is an acronym (def: 'sp')\n"
           "    -p=PGN    page code in hex (def: 0)\n"
           "    -p=PGN,SPGN    page and subpage codes in hex, (defs: 0,0)\n"
           "    -paramp=PP   (in hex) (def: 0)\n"
           "    -pcb     show parameter control bytes in decoded "
           "output\n");
    printf("    -ppc     set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
           "    -r       reset log parameters (takes PC and SP into "
           "account)\n"
           "             (uses PCR bit in LOG SELECT)\n"
           "    -select  perform LOG SELECT (def: LOG SENSE)\n"
           "    -sp      set the Saving Parameters (SP) bit (def: 0)\n"
           "    -t       outputs temperature log page (0xd)\n"
           "    -T       outputs transport (protocol specific port) log "
           "page (0x18)\n"
           "    -u       hex format for undefined/unrecognized fields\n"
           "    -v       increase verbosity\n"
           "    -V       output version string\n"
           "    -x       no initial INQUIRY output (twice: no INQUIRY call)\n"
           "    -X       open DEVICE read-only (def: first read-write then "
           "if fails\n"
           "             try open again with read-only)\n"
           "    -?       output this usage message\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command\n");
}

/* Return vendor product mask given vendor product number */
static int
get_vp_mask(int vpn)
{
    if (vpn < 0)
        return 0;
    else
        return (vpn >= (32 - MVP_OFFSET)) ?  OVP_ALL :
                                             (1 << (vpn + MVP_OFFSET));
}

static int
asort_comp(const void * lp, const void * rp)
{
    const struct log_elem * const * lepp =
                (const struct log_elem * const *)lp;
    const struct log_elem * const * repp =
                (const struct log_elem * const *)rp;

    return strcmp((*lepp)->acron, (*repp)->acron);
}

static void
enumerate_helper(const struct log_elem * lep, bool first,
                 const struct opts_t * op)
{
    char b[80];
    char bb[80];
    const char * cp;
    bool vendor_lpage = ! (MVP_STD & lep->flags);

    if (first) {
        if (1 == op->verbose) {
            printf("acronym   pg[,spg]        name\n");
            printf("===============================================\n");
        } else if (2 == op->verbose) {
            printf("acronym   pg[,spg]        pdt   name\n");
            printf("===================================================\n");
        }
    }
    if ((0 == (op->do_enumerate % 2)) && vendor_lpage)
        return;     /* if do_enumerate is even then skip vendor pages */
    else if ((! op->filter_given) || (-1 == op->filter))
        ;           /* otherwise enumerate all lpages if no --filter= */
    else if (-2 == op->filter) {   /* skip non-SPC pages */
        if (lep->pdt >= 0)
            return;
    } else if (-10 == op->filter) {   /* skip non-disk like pages */
        if (sg_lib_pdt_decay(lep->pdt) != 0)
            return;
    } else if (-11 == op->filter) {   /* skip tape like device pages */
        if (sg_lib_pdt_decay(lep->pdt) != 1)
            return;
    } else if ((op->filter >= 0) && (op->filter <= 0x1f)) {
        if ((lep->pdt >= 0) && (lep->pdt != op->filter) &&
            (lep->pdt != sg_lib_pdt_decay(op->filter)))
            return;
    }
    if (op->vend_prod_num >= 0) {
        if (! (lep->flags & get_vp_mask(op->vend_prod_num)))
            return;
    }
    if (op->deduced_vpn >= 0) {
        if (! (lep->flags & get_vp_mask(op->deduced_vpn)))
            return;
    }
    if (lep->subpg_high > 0)
        snprintf(b, sizeof(b), "0x%x,0x%x->0x%x", lep->pg_code,
                 lep->subpg_code, lep->subpg_high);
    else if (lep->subpg_code > 0)
        snprintf(b, sizeof(b), "0x%x,0x%x", lep->pg_code,
                 lep->subpg_code);
    else
        snprintf(b, sizeof(b), "0x%x", lep->pg_code);
    snprintf(bb, sizeof(bb), "%-16s", b);
    cp = (op->verbose && (! lep->show_pagep)) ? " [hex only]" : "";
    if (op->verbose > 1) {
        if (lep->pdt < 0)
            printf("  %-8s%s-     %s%s\n", lep->acron, bb, lep->name, cp);
        else
            printf("  %-8s%s0x%02x  %s%s\n", lep->acron, bb, lep->pdt,
                   lep->name, cp);
    } else
        printf("  %-8s%s%s%s\n", lep->acron, bb, lep->name, cp);
}

static void
enumerate_pages(const struct opts_t * op)
{
    int j;
    struct log_elem * lep;
    struct log_elem ** lep_arr;

    if (op->do_enumerate < 3) { /* -e, -ee: sort by acronym */
        int k;
        struct log_elem ** lepp;

        for (k = 0, lep = log_arr; lep->pg_code >=0; ++lep, ++k)
            ;
        ++k;
        lep_arr = (struct log_elem **)calloc(k, sizeof(struct log_elem *));
        if (NULL == lep_arr) {
            pr2serr("%s: out of memory\n", __func__);
            return;
        }
        for (k = 0, lep = log_arr; lep->pg_code >=0; ++lep, ++k)
            lep_arr[k] = lep;
        lep_arr[k++] = lep;     /* put sentinel on end */
        qsort(lep_arr, k, sizeof(struct log_elem *), asort_comp);
        printf("Known log pages in acronym order:\n");
        for (lepp = lep_arr, j = 0; (*lepp)->pg_code >=0; ++lepp, ++j)
            enumerate_helper(*lepp, (0 == j), op);
        free(lep_arr);
    } else {    /* -eee, -eeee numeric sort (as per table) */
        printf("Known log pages in numerical order:\n");
        for (lep = log_arr, j = 0; lep->pg_code >=0; ++lep, ++j)
            enumerate_helper(lep, (0 == j), op);
    }
}

static const struct log_elem *
acron_search(const char * acron)
{
    const struct log_elem * lep;

    for (lep = log_arr; lep->pg_code >=0; ++lep) {
        if (0 == strcmp(acron, lep->acron))
            return lep;
    }
    return NULL;
}

static int
find_vpn_by_acron(const char * vp_ap)
{
    const struct vp_name_t * vpp;

    for (vpp = vp_arr; vpp->acron; ++vpp) {
        size_t k;
        size_t len = strlen(vpp->acron);

        for (k = 0; k < len; ++k) {
            if (tolower((uint8_t)vp_ap[k]) != (uint8_t)vpp->acron[k])
                break;
        }
        if (k < len)
            continue;
        return vpp->vend_prod_num;
    }
    return VP_NONE;
}

/* Find vendor product number using T10 VENDOR and PRODUCT ID fields in a
   INQUIRY response. */
static int
find_vpn_by_inquiry(void)
{
    size_t len;
    size_t t10_v_len = strlen(t10_vendor_str);
    size_t t10_p_len = strlen(t10_product_str);
    const struct vp_name_t * vpp;

    if ((0 == t10_v_len) && (0 == t10_p_len))
        return VP_NONE;
    for (vpp = vp_arr; vpp->acron; ++vpp) {
        bool matched = false;

        if (vpp->t10_vendorp && (t10_v_len > 0)) {
            len = strlen(vpp->t10_vendorp);
            len = (len > t10_v_len) ? t10_v_len : len;
            if (strncmp(vpp->t10_vendorp, t10_vendor_str, len))
                continue;
            matched = true;
        }
        if (vpp->t10_productp && (t10_p_len > 0)) {
            len = strlen(vpp->t10_productp);
            len = (len > t10_p_len) ? t10_p_len : len;
            if (strncmp(vpp->t10_productp, t10_product_str, len))
                continue;
            matched = true;
        }
        if (matched)
            return vpp->vend_prod_num;
    }
    return VP_NONE;
}

static void
enumerate_vp(void)
{
    const struct vp_name_t * vpp;
    bool seen = false;

    for (vpp = vp_arr; vpp->acron; ++vpp) {
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

static const struct log_elem *
pg_subpg_pdt_search(int pg_code, int subpg_code, int pdt, int vpn)
{
    const struct log_elem * lep;
    int d_pdt;
    int vp_mask = get_vp_mask(vpn);

    d_pdt = sg_lib_pdt_decay(pdt);
    for (lep = log_arr; lep->pg_code >=0; ++lep) {
        if (pg_code == lep->pg_code) {
            if (subpg_code == lep->subpg_code) {
                if ((MVP_STD & lep->flags) || (0 == vp_mask) ||
                    (vp_mask & lep->flags))
                    ;
                else
                    continue;
                if ((lep->pdt < 0) || (pdt == lep->pdt) || (pdt < 0))
                    return lep;
                else if (d_pdt == lep->pdt)
                    return lep;
                else if (pdt == sg_lib_pdt_decay(lep->pdt))
                    return lep;
            } else if ((lep->subpg_high > 0) &&
                     (subpg_code > lep->subpg_code) &&
                     (subpg_code <= lep->subpg_high))
                return lep;
        }
    }
    return NULL;
}

static void
js_snakenv_ihexstr_nex(sgj_state * jsp, sgj_opaque_p jop,
                       const char * conv2sname, int64_t val_i,
                       bool hex_as_well, const char * str_name,
                       const char * val_s, const char * nex_s)
{

    if ((NULL == jsp) || (NULL == jop))
        return;
    if (sgj_is_snake_name(conv2sname))
        sgj_js_nv_ihexstr_nex(jsp, jop, conv2sname, val_i, hex_as_well,
                              str_name, val_s, nex_s);
    else {
        char b[128];

        sgj_convert2snake(conv2sname, b, sizeof(b));
        sgj_js_nv_ihexstr_nex(jsp, jop, b, val_i, hex_as_well, str_name,
                              val_s, nex_s);
    }
}

static void
usage_for(int hval, const struct opts_t * op)
{
    if (op->opt_new)
        usage(hval);
    else
        usage_old();
}

/* Processes command line options according to new option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
new_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    while (1) {
        int c, n;
        int option_index = 0;

        c = getopt_long(argc, argv, "aAbc:D:eEf:FhHi:j::J:lLm:M:nNOp:P:qQrR"
                        "sStTuvVxX", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ++op->do_all;
            break;
        case 'A':
            op->do_all += 2;
            break;
        case 'b':
            ++op->do_brief;
            break;
        case 'c':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 3)) {
                pr2serr("bad argument to '--control='\n");
                usage(2);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->page_control = n;
            break;
        case 'D':
            if (0 == memcmp("-1", optarg, 3))
                op->dev_pdt = -1;
            else {
                n = sg_get_num(optarg);
                if ((n < 0) || (n > 31)) {
                    pr2serr("bad argument to '--pdt='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->dev_pdt = n;
            }
            break;
        case 'e':
            ++op->do_enumerate;
            break;
        case 'E':
            op->exclude_vendor = true;
            break;
        case 'f':
            if ('-' == optarg[0]) {
                n = sg_get_num(optarg + 1);
                if ((n < 0) || (n > 0x30)) {
                    pr2serr("bad negated argument to '--filter='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->filter = -n;
            } else {
                n = sg_get_num(optarg);
                if ((n < 0) || (n > 0xffff)) {
                    pr2serr("bad argument to '--filter='\n");
                    usage(1);
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->filter = n;
            }
            op->filter_given = true;
            break;
        case 'F':
            op->do_full = true;
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
            op->json_arg = optarg;
            op->do_json = true;
            break;
        case 'J':
            op->js_file = optarg;
            op->do_json = true;
            break;
        case 'l':
            ++op->do_list;
            break;
        case 'L':
            op->do_list += 2;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (1 == n)) {
                pr2serr("bad argument to '--maxlen=', from 2 and up "
                        "expected\n");
                usage(2);
                return SG_LIB_SYNTAX_ERROR;
            } else if (n < 4) {
                pr2serr("Warning: setting '--maxlen' to 4\n");
                n = 4;
            }
            op->maxlen = n;
            op->maxlen_given = true;
            break;
        case 'M':
            if (op->vend_prod) {
                pr2serr("only one '--vendor=' option permitted\n");
                usage(2);
                return SG_LIB_SYNTAX_ERROR;
            } else
                op->vend_prod = optarg;
            break;
        case 'n':
            op->do_name = true;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = false;
            return 0;
        case 'p':
            op->pg_arg = optarg;
            break;
        case 'P':
            n = sg_get_num(optarg);
            if (n < 0) {
                pr2serr("bad argument to '--paramp='\n");
                usage(2);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->paramp = n;
            break;
        case 'q':
            op->do_pcb = true;
            break;
        case 'Q':       /* N.B. PPC bit obsoleted in SPC-4 rev 18 */
            op->do_ppc = true;
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'R':
            op->do_pcreset = true;
            op->do_select = true;
            break;
        case 's':
            op->do_sp = true;
            break;
        case 'S':
            op->do_select = true;
            break;
        case 't':
            op->do_temperature = true;
            break;
        case 'T':
            op->do_transport = true;
            break;
        case 'u':
            ++op->undefined_hex;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'x':
            ++op->no_inq;
            break;
        case 'X':
            op->o_readonly = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
            if (op->do_help)
                break;
            usage(1);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == op->device_name) {
            op->device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage(1);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Processes command line options according to old option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
old_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    bool jmp_out;
    int k, num, n;
    unsigned int u, uu;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        int plen;

        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'a':
                    ++op->do_all;
                    break;
                case 'A':
                    op->do_all += 2;
                    break;
                case 'b':
                    ++op->do_brief;
                    break;
                case 'e':
                    ++op->do_enumerate;
                    break;
                case 'E':
                    op->exclude_vendor = true;
                    break;
                case 'F':
                    op->do_full = true;
                    break;
                case 'h':
                case 'H':
                    ++op->do_hex;
                    break;
                case 'j':
                    op->do_json = true;
                    break;
                case 'l':
                    ++op->do_list;
                    break;
                case 'L':
                    op->do_list += 2;
                    break;
                case 'n':
                    op->do_name = true;
                    break;
                case 'N':
                    op->opt_new = true;
                    return 0;
                case 'O':
                    break;
                case 'r':
                    op->do_pcreset = true;
                    op->do_select = true;
                    break;
                case 't':
                    op->do_temperature = true;
                    break;
                case 'T':
                    op->do_transport = true;
                    break;
                case 'u':
                    ++op->undefined_hex;
                    break;
                case 'v':
                    op->verbose_given = true;
                    ++op->verbose;
                    break;
                case 'V':
                    op->version_given = true;
                    break;
                case 'x':
                    ++op->no_inq;
                    break;
                case 'X':
                    op->o_readonly = true;
                    break;
                case '?':
                    ++op->do_help;
                    break;
                case '-':
                    ++cp;
                    jmp_out = true;
                    break;
                default:
                    jmp_out = true;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("c=", cp, 2)) {
                num = sscanf(cp + 2, "%6x", &u);
                if ((1 != num) || (u > 3)) {
                    pr2serr("Bad page control after '-c=' option [0..3]\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->page_control = u;
            } else if (0 == strncmp("D=", cp, 2)) {
                n = sg_get_num(cp + 2);
                if ((n < 0) || (n > 31)) {
                    pr2serr("Bad argument after '-D=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->dev_pdt = n;
            } else if (0 == strncmp("f=", cp, 2)) {
                n = sg_get_num(cp + 2);
                if ((n < 0) || (n > 0xffff)) {
                    pr2serr("Bad argument after '-f=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->filter = n;
                op->filter_given = true;
            } else if (0 == strncmp("i=", cp, 2))
                op->in_fn = cp + 2;
            else if (0 == strncmp("m=", cp, 2)) {
                num = sscanf(cp + 2, "%8d", &n);
                if ((1 != num) || (n < 0)) {
                    pr2serr("Bad maximum response length after '-m=' "
                            "option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->maxlen_given = true;
                op->maxlen = n;
            } else if (0 == strncmp("M=", cp, 2)) {
                if (op->vend_prod) {
                    pr2serr("only one '-M=' option permitted\n");
                    usage(2);
                    return SG_LIB_SYNTAX_ERROR;
                } else
                    op->vend_prod = cp + 2;
            } else if (0 == strncmp("p=", cp, 2)) {
                const char * ccp = cp + 2;
                const struct log_elem * lep;

                if (isalpha((uint8_t)ccp[0])) {
                    char * xp;
                    char b[80];

                    if (strlen(ccp) >= (sizeof(b) - 1)) {
                        pr2serr("argument to '-p=' is too long\n");
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    strcpy(b, ccp);
                    xp = (char *)strchr(b, ',');
                    if (xp)
                        *xp = '\0';
                    lep = acron_search(b);
                    if (NULL == lep) {
                        pr2serr("bad argument to '--page=' no acronyn match "
                                "to '%s'\n", b);
                        pr2serr("  Try using '-e' or'-ee' to see available "
                                "acronyns\n");
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    op->lep = lep;
                    op->pg_code = lep->pg_code;
                    if (xp) {
                        n = sg_get_num_nomult(xp + 1);
                        if ((n < 0) || (n > 255)) {
                            pr2serr("Bad second value in argument to "
                                    "'--page='\n");
                            return SG_LIB_SYNTAX_ERROR;
                        }
                        op->subpg_code = n;
                    } else
                        op->subpg_code = lep->subpg_code;
                } else {
                    /* numeric arg: either 'pg_num' or 'pg_num,subpg_num' */
                    if (NULL == strchr(cp + 2, ',')) {
                        num = sscanf(cp + 2, "%6x", &u);
                        if ((1 != num) || (u > 63)) {
                            pr2serr("Bad page code value after '-p=' "
                                    "option\n");
                            usage_old();
                            return SG_LIB_SYNTAX_ERROR;
                        }
                        op->pg_code = u;
                    } else if (2 == sscanf(cp + 2, "%4x,%4x", &u, &uu)) {
                        if (uu > 255) {
                            pr2serr("Bad sub page code value after '-p=' "
                                    "option\n");
                            usage_old();
                            return SG_LIB_SYNTAX_ERROR;
                        }
                        op->pg_code = u;
                        op->subpg_code = uu;
                    } else {
                        pr2serr("Bad page code, subpage code sequence after "
                                "'-p=' option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                }
            } else if (0 == strncmp("paramp=", cp, 7)) {
                num = sscanf(cp + 7, "%8x", &u);
                if ((1 != num) || (u > 0xffff)) {
                    pr2serr("Bad parameter pointer after '-paramp=' "
                            "option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->paramp = u;
            } else if (0 == strncmp("pcb", cp, 3))
                op->do_pcb = true;
            else if (0 == strncmp("ppc", cp, 3))
                op->do_ppc = true;
            else if (0 == strncmp("select", cp, 6))
                op->do_select = true;
            else if (0 == strncmp("sp", cp, 2))
                op->do_sp = true;
            else if (0 == strncmp("old", cp, 3))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == op->device_name)
            op->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not expecting: %s\n",
                    op->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Process command line options. First check using new option format unless
 * the SG3_UTILS_OLD_OPTS environment variable is defined which causes the
 * old option format to be checked first. Both new and old format can be
 * countermanded by a '-O' and '-N' options respectively. As soon as either
 * of these options is detected (when processing the other format), processing
 * stops and is restarted using the other format. Clear? */
static int
parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = false;
        res = old_parse_cmd_line(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = new_parse_cmd_line(op, argc, argv);
    } else {
        op->opt_new = true;
        res = new_parse_cmd_line(op, argc, argv);
        if ((0 == res) && (0 == op->opt_new))
            res = old_parse_cmd_line(op, argc, argv);
    }
    return res;
}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Call LOG SENSE twice: the first time ask for 4 byte response to determine
   actual length of response; then a second time requesting the
   min(actual_len, mx_resp_len) bytes. If the calculated length for the
   second fetch is odd then it is incremented (perhaps should be made modulo
   4 in the future for SAS). Returns 0 if ok, SG_LIB_CAT_INVALID_OP for
   log_sense not supported, SG_LIB_CAT_ILLEGAL_REQ for bad field in log sense
   command, SG_LIB_CAT_NOT_READY, SG_LIB_CAT_UNIT_ATTENTION,
   SG_LIB_CAT_ABORTED_COMMAND and -1 for other errors. */
static int
do_logs(int sg_fd, uint8_t * resp, int mx_resp_len,
        const struct opts_t * op)
{
    int calc_len, request_len, res, resid, vb;

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (! win32_spt_init_state) {
        if (win32_spt_curr_state) {
            if (mx_resp_len < 16384) {
                scsi_pt_win32_direct(0);
                win32_spt_curr_state = false;
            }
        } else {
            if (mx_resp_len >= 16384) {
                scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT direct */);
                win32_spt_curr_state = true;
            }
        }
    }
#endif
#endif
    memset(resp, 0, mx_resp_len);
    vb = op->verbose;
    if (op->maxlen > 1)
        request_len = mx_resp_len;
    else {
        request_len = LOG_SENSE_PROBE_ALLOC_LEN;
        if ((res = sg_ll_log_sense_v2(sg_fd, op->do_ppc, op->do_sp,
                                      op->page_control, op->pg_code,
                                      op->subpg_code, op->paramp,
                                      resp, request_len, LOG_SENSE_DEF_TIMEOUT,
                                      &resid, true /* noisy */, vb)))
            return res;
        if (resid > 0) {
            res = SG_LIB_WILD_RESID;
            goto resid_err;
        }
        calc_len = sg_get_unaligned_be16(resp + 2) + 4;
        if ((! op->do_raw) && (vb > 1)) {
            pr2serr("  Log sense (find length) response:\n");
            hex2stderr(resp, LOG_SENSE_PROBE_ALLOC_LEN, 1);
            pr2serr("  hence calculated response length=%d\n", calc_len);
        }
        if (op->pg_code != (0x3f & resp[0])) {
            if (vb)
                pr2serr("Page code does not appear in first byte of "
                        "response so it's suspect\n");
            if (calc_len > 0x40) {
                calc_len = 0x40;
                if (vb)
                    pr2serr("Trim response length to 64 bytes due to "
                            "suspect response format\n");
            }
        }
        /* Some HBAs don't like odd transfer lengths */
        if (calc_len % 2)
            calc_len += 1;
        if (calc_len > mx_resp_len)
            calc_len = mx_resp_len;
        request_len = calc_len;
    }
    if ((res = sg_ll_log_sense_v2(sg_fd, op->do_ppc, op->do_sp,
                                  op->page_control, op->pg_code,
                                  op->subpg_code, op->paramp,
                                  resp, request_len,
                                  LOG_SENSE_DEF_TIMEOUT, &resid,
                                  true /* noisy */, vb)))
        return res;
    if (resid > 0) {
        request_len -= resid;
        if (request_len < 4) {
            request_len += resid;
            res = SG_LIB_WILD_RESID;
            goto resid_err;
        }
    }
    if ((! op->do_raw) && (vb > 1)) {
        pr2serr("  Log sense response:\n");
        hex2stderr(resp, request_len, 1);
    }
    return 0;
resid_err:
    pr2serr("%s: request_len=%d, resid=%d, problems\n", __func__, request_len,
            resid);
    request_len -= resid;
    if ((request_len > 0) && (! op->do_raw) && (vb > 1)) {
        pr2serr("  Log sense (resid_err) response:\n");
        hex2stderr(resp, request_len, 1);
    }
    return res;
}

/* Apart from short names, names that do not end is "age" have " log page"
 * appended to them, unless they end in '?' in which case the '?' is
 * removed. */
sgj_opaque_p
sg_log_js_hdr(sgj_state * jsp, sgj_opaque_p jop, const char * name,
              const uint8_t * log_hdrp)
{
    bool ds = !! (log_hdrp[0] & 0x80);
    bool spf = !! (log_hdrp[0] & 0x40);
    int pg = log_hdrp[0] & 0x3f;
    int subpg = log_hdrp[1];
    size_t nlen = strlen(name);
    sgj_opaque_p jo2p;
    char b[80];

    if ((nlen < 4) || (0 != strcmp("age", name + nlen - 3))) {
        memcpy(b, name, nlen);
        if ('?' == name[nlen - 1])
            b[nlen - 1] = '\0';
        else
            memcpy(b + nlen, " log page", 10);
        jo2p = sgj_snake_named_subobject_r(jsp, jop, b);
    } else
        jo2p = sgj_snake_named_subobject_r(jsp, jop, name);

    sgj_js_nv_ihex_nex(jsp, jo2p, "ds", (int)ds, false, "Did not Save");
    sgj_js_nv_ihex_nex(jsp, jo2p, "spf", (int)spf, false, "SubPage Format");
    sgj_js_nv_ihex(jsp, jo2p, pg_c_sn, pg);
    sgj_js_nv_ihex(jsp, jo2p, spg_c_sn, subpg);
    return jo2p;
}



/* DS made obsolete in spc4r03; TMC and ETC made obsolete in spc5r03. */
static char *
get_pcb_str(int pcb, char * outp, int maxoutlen)
{
    char buff[PCB_STR_LEN];
    int n;

    n = sprintf(buff, "du=%d [ds=%d] tsd=%d [etc=%d] ", ((pcb & 0x80) ? 1 : 0),
                ((pcb & 0x40) ? 1 : 0), ((pcb & 0x20) ? 1 : 0),
                ((pcb & 0x10) ? 1 : 0));
    if (pcb & 0x10)
        n += sprintf(buff + n, "[tmc=%d] ", ((pcb & 0xc) >> 2));
#if 1
    n += sprintf(buff + n, "format+linking=%d  [0x%.2x]", pcb & 3,
                 pcb);
#else
    if (pcb & 0x1)
        n += sprintf(buff + n, "lbin=%d ", ((pcb & 0x2) >> 1));
    n += sprintf(buff + n, "lp=%d  [0x%.2x]", pcb & 0x1, pcb);
#endif
    if (outp && (n < maxoutlen)) {
        memcpy(outp, buff, n);
        outp[n] = '\0';
    } else if (outp && (maxoutlen > 0))
        outp[0] = '\0';
    return outp;
}

static void
js_pcb(sgj_state * jsp, sgj_opaque_p jop, int pcb)
{
    sgj_opaque_p jo2p = sgj_snake_named_subobject_r(jsp, jop,
                                                    "parameter_control_byte");

    sgj_js_nv_ihex_nex(jsp, jo2p, "du", (pcb & 0x80) ? 1 : 0, false,
                       "Disable Update");
    sgj_js_nv_ihex_nex(jsp, jo2p, "ds", (pcb & 0x40) ? 1 : 0, false,
                       "Disable Save [obsolete]");
    sgj_js_nv_ihex_nex(jsp, jo2p, "tsd", (pcb & 0x20) ? 1 : 0, false,
                       "Target Save Disable");
    sgj_js_nv_ihex_nex(jsp, jo2p, "etc", (pcb & 0x10) ? 1 : 0, false,
                       "Enable Threshold Comparison [obsolete]");
    sgj_js_nv_ihex_nex(jsp, jo2p, "tmc", (pcb & 0xc) >> 2, false,
                       "Threshold Met Criteria [obsolete]");
    sgj_js_nv_ihex_nex(jsp, jo2p, "format_and_linking", pcb & 0x3, false,
                       NULL);
}

/* SUPP_PAGES_LPAGE [0x0,0x0] <sp> */
static bool
show_supported_pgs_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    int num, k;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p, jo3p;
    sgj_opaque_p jap = NULL;
    char b[64];
    static const char * slpgs = "Supported log pages";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x0]:\n", slpgs);  /* introduced in: SPC-2 */
    num = len - 4;
    bp = &resp[0] + 4;
    if ((op->do_hex > 0) || op->do_raw) {
        if (op->do_raw)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, slpgs, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "supported_pages_list");
    }

    for (k = 0; k < num; ++k) {
        int pg_code = bp[k] & 0x3f;
        const struct log_elem * lep;

        snprintf(b, sizeof(b) - 1, "  0x%02x        ", pg_code);
        lep = pg_subpg_pdt_search(pg_code, 0, op->dev_pdt, -1);
        if (lep) {
            if (op->do_brief > 1)
                sgj_pr_hr(jsp, "    %s\n", lep->name);
            else if (op->do_brief)
                sgj_pr_hr(jsp, "%s%s\n", b, lep->name);
            else
                sgj_pr_hr(jsp, "%s%s [%s]\n", b, lep->name, lep->acron);
        } else
            sgj_pr_hr(jsp, "%s\n", b);
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihex(jsp, jo3p, pg_c_sn, pg_code);
            sgj_js_nv_s(jsp, jo3p, "name", lep ? lep->name : unkn_s);
            sgj_js_nv_s(jsp, jo3p, "acronym", lep ? lep->acron : unkn_s);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
    }
    return true;
}

/* SUPP_PAGES_LPAGE,SUPP_SPGS_SUBPG [0x0,0xff] <ssp> or all subpages of a
 * given page code: [<pg_code>,0xff] where <pg_code> > 0 */
static bool
show_supported_pgs_sub_page(const uint8_t * resp, int len,
                            struct opts_t * op, sgj_opaque_p jop)
{
    bool spf;
    int num, k;
    const uint8_t * bp;
    const struct log_elem * lep = NULL;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p, jo3p;
    sgj_opaque_p jap = NULL;
    char b[64];
    static const char * slpass = "Supported log pages and subpages";
    static const char * sss = "Supported subpages";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (op->pg_code > 0)
            sgj_pr_hr(jsp, "%s  [0x%x, 0xff]:\n", sss, op->pg_code);
        else
            sgj_pr_hr(jsp, "%s  [0x0, 0xff]:\n", sss);
    }
    num = len - 4;
    bp = &resp[0] + 4;
    if ((op->do_hex > 0) || op->do_raw) {
        if (op->do_raw)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    spf = !! (0x40 & bp[0]);
    if (jsp->pr_as_json) {
        if (spf) {
            jo2p = sg_log_js_hdr(jsp, jop, sss, resp);
            jap = sgj_named_subarray_r(jsp, jo2p,
                                       "supported_subpage_descriptors");
        } else {
            jo2p = sg_log_js_hdr(jsp, jop, slpass, resp);
            jap = sgj_named_subarray_r(jsp, jo2p,
                               "supported_page_subpage_descriptors");
        }
    }

    for (k = 0; k < num; k += 2) {
        bool pr_name = true;
        int pg_code = bp[k];
        int subpg_code = bp[k + 1];

        /* formerly ignored [pg, 0xff] when pg > 0, don't know why */
        if (NOT_SPG_SUBPG == subpg_code)
            snprintf(b, sizeof(b) - 1, "  0x%02x        ", pg_code);
        else
            snprintf(b, sizeof(b) - 1, "  0x%02x,0x%02x   ", pg_code,
                     subpg_code);
        if ((pg_code > 0) && (subpg_code == 0xff)) {
            sgj_pr_hr(jsp, "%s\n", b);
            pr_name = false;
        } else {
            lep = pg_subpg_pdt_search(pg_code, subpg_code, op->dev_pdt, -1);
            if (lep) {
                if (op->do_brief > 1)
                    sgj_pr_hr(jsp, "    %s\n", lep->name);
                else if (op->do_brief)
                    sgj_pr_hr(jsp, "%s%s\n", b, lep->name);
                else
                    sgj_pr_hr(jsp, "%s%s [%s]\n", b, lep->name, lep->acron);
            } else
                sgj_pr_hr(jsp, "%s\n", b);
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihex(jsp, jo3p, pg_c_sn, pg_code);
            sgj_js_nv_ihex(jsp, jo3p, spg_c_sn, subpg_code);
            if (pr_name) {
                sgj_js_nv_s(jsp, jo3p, "name", lep ? lep->name : unkn_s);
                sgj_js_nv_s(jsp, jo3p, "acronym", lep ? lep->acron :
                                                        unkn_s);
            }
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
    }
    return true;
}

/* BUFF_OVER_UNDER_LPAGE [0x1] <bou>  introduced: SPC-2 */
static bool
show_buffer_over_under_run_page(const uint8_t * resp, int len,
                                struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    uint64_t count;
    const uint8_t * bp;
    const char * cp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char str[PCB_STR_LEN];
    static const char * bourlp = "Buffer over-run/under-run log page";
    static const char * orurc = "over_run_under_run_counter";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x1]\n", bourlp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, bourlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                        "buffer_over_run_under_run_log_parameters");
    }
    while (num > 3) {
        cp = NULL;
        pl = bp[3] + 4;
        count = (pl > 4) ? sg_get_unaligned_be(pl - 4, bp + 4) : 0;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x0:
            cp = "under-run";
            break;
        case 0x1:
            cp = "over-run";
            break;
        case 0x2:
            cp = "service delivery subsystem busy, under-run";
            break;
        case 0x3:
            cp = "service delivery subsystem busy, over-run";
            break;
        case 0x4:
            cp = "transfer too slow, under-run";
            break;
        case 0x5:
            cp = "transfer too slow, over-run";
            break;
        case 0x20:
            cp = "command, under-run";
            break;
        case 0x21:
            cp = "command, over-run";
            break;
        case 0x22:
            cp = "command, service delivery subsystem busy, under-run";
            break;
        case 0x23:
            cp = "command, service delivery subsystem busy, over-run";
            break;
        case 0x24:
            cp = "command, transfer too slow, under-run";
            break;
        case 0x25:
            cp = "command, transfer too slow, over-run";
            break;
        case 0x40:
            cp = "I_T nexus, under-run";
            break;
        case 0x41:
            cp = "I_T nexus, over-run";
            break;
        case 0x42:
            cp = "I_T nexus, service delivery subsystem busy, under-run";
            break;
        case 0x43:
            cp = "I_T nexus, service delivery subsystem busy, over-run";
            break;
        case 0x44:
            cp = "I_T nexus, transfer too slow, under-run";
            break;
        case 0x45:
            cp = "I_T nexus, transfer too slow, over-run";
            break;
        case 0x80:
            cp = "time, under-run";
            break;
        case 0x81:
            cp = "time, over-run";
            break;
        case 0x82:
            cp = "time, service delivery subsystem busy, under-run";
            break;
        case 0x83:
            cp = "time, service delivery subsystem busy, over-run";
            break;
        case 0x84:
            cp = "time, transfer too slow, under-run";
            break;
        case 0x85:
            cp = "time, transfer too slow, over-run";
            break;
        default:
            pr2serr("  undefined %s [0x%x], count = %" PRIu64 "\n",
                    param_c, pc, count);
            break;
        }
        sgj_pr_hr(jsp, "  %s=0x%x\n", param_c, pc);
        sgj_js_nv_ihex(jsp, jo3p, param_c_sn, pc);
        if (cp) {
            sgj_pr_hr(jsp, "    %s = %" PRIu64 "\n", cp, count);
            js_snakenv_ihexstr_nex(jsp, jo3p, param_c, pc, true,
                                   NULL, cp, NULL);
            sgj_js_nv_ihex(jsp, jo3p, orurc, count);
        } else
            sgj_pr_hr(jsp, "    counter = %" PRIu64 "\n", count);

        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2],
                      str, sizeof(str)));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* WRITE_ERR_LPAGE; READ_ERR_LPAGE; READ_REV_ERR_LPAGE; VERIFY_ERR_LPAGE */
/* [0x2, 0x3, 0x4, 0x5] <we, re, rre, ve>  introduced: SPC-3 */
static bool
show_error_counter_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    bool skip_out = false;
    bool evsm_output = false;
    int n, num, pl, pc, pg_code;
    uint64_t val;
    const uint8_t * bp;
    const char * pg_cp = NULL;
    const char * par_cp = NULL;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[168] SG_C_CPP_ZERO_INIT;
    char d[128];
    char e[64];
    static const int blen = sizeof(b);
    static const char * wec = "Write error counter";
    static const char * rec = "Read error counter";
    static const char * rrec = "Read reverse error counter";
    static const char * vec = "Verify error counter";

    pg_code = resp[0] & 0x3f;
    switch(pg_code) {
    case WRITE_ERR_LPAGE:
        pg_cp = wec;
        break;
    case READ_ERR_LPAGE:
        pg_cp = rec;
        break;
    case READ_REV_ERR_LPAGE:
        pg_cp = rrec;
        break;
    case VERIFY_ERR_LPAGE:
        pg_cp = vec;
        break;
    default:
        pr2serr("expecting error counter page, got page = 0x%x\n",
                pg_code);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s log page  [0x%x]\n", pg_cp, pg_code);
    if (jsp->pr_as_json) {
        snprintf(b, blen, "%s %s", pg_cp, "log page");
        jo2p = sg_log_js_hdr(jsp, jop, b, resp);
        n = strlen(b);
        memcpy(b + n, " parameters", 11 + 1);
        sgj_convert2snake(b, d, sizeof(d) - 1);
        jap = sgj_named_subarray_r(jsp, jo2p, d);
    }
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        par_cp = NULL;
        switch (pc) {
        case 0:
            par_cp = "Errors corrected without substantial delay";
            break;
        case 1:
            par_cp = "Errors corrected with possible delays";
            break;
        case 2:
            par_cp = "Total rewrites or rereads";
            break;
        case 3:
            par_cp = "Total errors corrected";
            break;
        case 4:
            par_cp = "Total times correction algorithm processed";
            break;
        case 5:
            par_cp = "Total bytes processed";
            break;
        case 6:
            par_cp = "Total uncorrected errors";
            break;
        default:
            if (op->exclude_vendor) {
                skip_out = true;
                if ((op->verbose > 0) && (0 == op->do_brief) &&
                    (! evsm_output)) {
                    evsm_output = true;
                    pr2serr("  %s parameter(s) being ignored\n", vend_spec);
                }
            } else {
                if (0x8009 == pc)
                    par_cp = "Track following errors [Hitachi]";
                else if (0x8015 == pc)
                    par_cp = "Positioning errors [Hitachi]";
                else {
                    snprintf(e, sizeof(e), "Reserved or %s [0x%x]", vend_spec,
                             pc);
                    par_cp = e;
                }
            }
            break;
        }

        if (skip_out)
            skip_out = false;
        else if (par_cp) {
            val = sg_get_unaligned_be(pl - 4, bp + 4);
            if (val > ((uint64_t)1 << 40))
                snprintf(d, sizeof(d), "%" PRIu64 " [%" PRIu64 " TB]",
                         val, (val / (1000UL * 1000 * 1000 * 1000)));
            else if (val > ((uint64_t)1 << 30))
                snprintf(d, sizeof(d), "%" PRIu64 " [%" PRIu64 " GB]",
                         val, (val / (1000UL * 1000 * 1000)));
            else
                snprintf(d, sizeof(d), "%" PRIu64, val);
            sgj_pr_hr(jsp, "  %s = %s\n", par_cp, d);
            if (jsp->pr_as_json) {
                js_snakenv_ihexstr_nex(jsp, jo3p, param_c, pc, true,
                                       NULL, par_cp, NULL);
                sgj_convert2snake(pg_cp, e, sizeof(e) - 1);
                sgj_js_nv_ihexstr(jsp, jo3p, e, val, as_s_s, d);
            }
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* NON_MEDIUM_LPAGE [0x6] <nm>  introduced: SPC-2 */
static bool
show_non_medium_error_page(const uint8_t * resp, int len,
                           struct opts_t * op, sgj_opaque_p jop)
{
    bool skip_out = false;
    bool evsm_output = false;
    int num, pl, pc;
    uint64_t count;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char str[PCB_STR_LEN];
    char b[128] SG_C_CPP_ZERO_INIT;
    static const char * nmelp = "Non-medium error log page";
    static const char * nmec = "Non-medium error count";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x6]\n", nmelp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, nmelp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                        "non_medium_error_log_parameters");
    }
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0:
            snprintf(b, sizeof(b), "%s", nmec);
            break;
        default:
            if (pc <= 0x7fff)
                snprintf(b, sizeof(b), "  Reserved [0x%x]", pc);
            else {
                if (op->exclude_vendor) {
                    skip_out = true;
                    if ((op->verbose > 0) && (0 == op->do_brief) &&
                        (! evsm_output)) {
                        evsm_output = true;
                        pr2serr("%s:  %s parameter(s) being ignored\n",
                                __func__, vend_spec);
                    }
                } else
                    snprintf(b, sizeof(b), "%s [0x%x]", vend_spec, pc);
            }
            break;
        }
        if (skip_out)
            skip_out = false;
        else {
            count = sg_get_unaligned_be(pl - 4, bp + 4);
            sgj_pr_hr(jsp, "  %s = %" PRIu64 "\n", b, count);
            js_snakenv_ihexstr_nex(jsp, jo3p, param_c, pc, true,
                                   NULL, b, NULL);
            js_snakenv_ihexstr_nex(jsp, jo3p, nmec, count, true, NULL, NULL,
                                   NULL);
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2],
                      str, sizeof(str)));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* PCT_LPAGE [0x1a] <pct>  introduced: SPC-4 */
static bool
show_power_condition_transitions_page(const uint8_t * resp, int len,
                                      struct opts_t * op, sgj_opaque_p jop)
{
    bool partial;
    int num, pl, pc;
    uint64_t count;
    const uint8_t * bp;
    const char * cp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char str[PCB_STR_LEN];
    char b[128];
    char bb[64];
    static const char * pctlp = "Power condition transitions log page";
    static const char * att = "Accumulated transitions to";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x1a]\n", pctlp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, pctlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                        "power_condition_transition_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        cp = NULL;
        partial = true;
        switch (pc) {
        case 1:
            cp = "active";
            break;
        case 2:
            cp = "idle_a";
            break;
        case 3:
            cp = "idle_b";
            break;
        case 4:
            cp = "idle_c";
            break;
        case 8:
            cp = "standby_z";
            break;
        case 9:
            cp = "standby_y";
            break;
        default:
            snprintf(bb, sizeof(bb), "Reserved [0x%x]", pc);
            cp = bb;
            partial = false;
            break;
        }
        if (partial) {
            snprintf(b, sizeof(b), "%s %s", att, cp);
            cp = b;
        }
        count = sg_get_unaligned_be(pl - 4, bp + 4);
        sgj_pr_hr(jsp, "  %s = %" PRIu64 "\n", cp, count);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2],
                      str, sizeof(str)));
        if (jsp->pr_as_json) {
            js_snakenv_ihexstr_nex(jsp, jo3p, cp, count, true,
                                   NULL, NULL, "saturating counter");
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

static char *
temperature_str(int8_t t, bool reporting, char * b, int blen)
{
    if (-128 == t) {
        if (reporting)
            snprintf(b, blen, "%s", not_avail);
        else
            snprintf(b, blen, "no limit");
    } else
        snprintf(b, blen, "%d C", t);
    return b;
}

static char *
humidity_str(uint8_t h, bool reporting, char * b, int blen)
{
    if (255 == h) {
        if (reporting)
            snprintf(b, blen, "%s", not_avail);
        else
            snprintf(b, blen, "no limit");
    } else if (h <= 100)
        snprintf(b, blen, "%u %%", h);
    else
        snprintf(b, blen, "%s value [%u]", rsv_s, h);
    return b;
}

/* ENV_REPORTING_SUBPG [0xd,0x1] <env> introduced: SPC-5 (rev 02). "mounted"
 * changed to "other" in spc5r11 */
static bool
show_environmental_reporting_page(const uint8_t * resp, int len,
                                  struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    bool other_valid;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[32];
    static const int blen = sizeof(b);
    static const char * erlp = "Environmental reporting log page";
    static const char * temp = "Temperature";
    static const char * lmaxt = "Lifetime maximum temperature";
    static const char * lmint = "Lifetime minimum temperature";
    static const char * maxtspo = "Maximum temperature since power on";
    static const char * mintspo = "Minimum temperature since power on";
    static const char * maxot = "Maximum other temperature";
    static const char * minot = "Minimum other temperature";
    static const char * relhum = "Relative humidity";
    static const char * lmaxrh = "Lifetime maximum relative humidity";
    static const char * lminrh = "Lifetime minimum relative humidity";
    static const char * maxrhspo = "Maximum relative humidity since power on";
    static const char * minrhspo = "Minimum relative humidity since power on";
    static const char * maxorh = "Maximum other relative humidity";
    static const char * minorh = "Minimum other relative humidity";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0xd,0x1]\n", erlp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, erlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "environmental_reporting_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        other_valid = !!(bp[4] & 1);
        if (pc < 0x100) {
            if (pl < 12)  {
                pr2serr("%s:  <<expect parameter 0x%x to be at least 12 "
                        "bytes long, got %d, skip>>\n", __func__, pc, pl);
                goto inner;
            }
            sgj_pr_hr(jsp, "  %s=0x%x\n", param_c, pc);
            sgj_js_nv_ihex(jsp, jo3p, param_c_sn, pc);
            sgj_pr_hr(jsp, "    OTV=%d\n", (int)other_valid);
            sgj_js_nv_ihex_nex(jsp, jo3p, "otv",  (int)other_valid,
                               false, "Other Temperature Valid");

            temperature_str(bp[5], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", temp, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, temp, bp[5], false,
                                   NULL, b, "current [Celsius]");
            temperature_str(bp[6], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lmaxt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lmaxt, bp[6], false,
                                   NULL, b, NULL);
            temperature_str(bp[7], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lmint, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lmint, bp[7], false,
                                   NULL, b, NULL);
            temperature_str(bp[8], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", maxtspo, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, maxtspo, bp[8], false,
                                   NULL, b, NULL);
            temperature_str(bp[9], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", mintspo, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, mintspo, bp[9], false,
                                   NULL, b, NULL);
            if (other_valid) {
                temperature_str(bp[10], true, b, blen);
                sgj_pr_hr(jsp, "    %s: %s\n", maxot, b);
                js_snakenv_ihexstr_nex(jsp, jo3p, maxot, bp[10], false,
                                       NULL, b, NULL);
                temperature_str(bp[11], true, b, blen);
                sgj_pr_hr(jsp, "    %s: %s\n", minot, b);
                js_snakenv_ihexstr_nex(jsp, jo3p, minot, bp[11], false,
                                       NULL, b, NULL);
            }
        } else if (pc < 0x200) {
            if (pl < 12)  {
                pr2serr("%s:  <<expect parameter 0x%x to be at least 12 "
                        "bytes long, got %d, skip>>\n", __func__, pc, pl);
                goto inner;
            }
            sgj_pr_hr(jsp, "  %s=0x%x\n", param_c, pc);
            sgj_js_nv_ihex(jsp, jo3p, param_c_sn, pc);
            sgj_pr_hr(jsp, "    ORHV=%d\n", (int)other_valid);
            sgj_js_nv_ihex_nex(jsp, jo3p, "orhv",  (int)other_valid,
                               false, "Other Relative Humidity Valid");

            humidity_str(bp[5], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", relhum, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, relhum, bp[5], false,
                                   NULL, b, NULL);
            humidity_str(bp[6], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lmaxrh, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lmaxrh, bp[6], false,
                                   NULL, b, NULL);
            humidity_str(bp[7], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lminrh, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lminrh, bp[7], false,
                                   NULL, b, NULL);
            humidity_str(bp[8], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", maxrhspo, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, maxrhspo, bp[8], false,
                                   NULL, b, NULL);
            humidity_str(bp[9], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", minrhspo, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, minrhspo, bp[9], false,
                                   NULL, b, NULL);
            if (other_valid) {
                humidity_str(bp[10], true, b, blen);
                sgj_pr_hr(jsp, "    %s: %s\n", maxorh, b);
                js_snakenv_ihexstr_nex(jsp, jo3p, maxorh, bp[10], false,
                                       NULL, b, NULL);
                humidity_str(bp[11], true, b, blen);
                sgj_pr_hr(jsp, "    %s: %s\n", minorh, b);
                js_snakenv_ihexstr_nex(jsp, jo3p, minorh, bp[11], false,
                                       NULL, b, NULL);
            }
        } else
            sgj_pr_hr(jsp, "  <<unexpected %s 0x%x\n", param_c, pc);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
inner:
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* ENV_LIMITS_SUBPG [0xd,0x2] <enl> introduced: SPC-5 (rev 02) */
static bool
show_environmental_limits_page(const uint8_t * resp, int len,
                               struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[32];
    static const int blen = sizeof(b);
    static const char * ellp = "Environmental limits log page";
    static const char * hctlt = "High critical temperature limit trigger";
    static const char * hctlr = "High critical temperature limit reset";
    static const char * lctlr = "High critical temperature limit reset";
    static const char * lctlt = "High critical temperature limit trigger";
    static const char * hotlt = "High operating temperature limit trigger";
    static const char * hotlr = "High operating temperature limit reset";
    static const char * lotlr = "High operating temperature limit reset";
    static const char * lotlt = "High operating temperature limit trigger";
    static const char * hcrhlt =
                "High critical relative humidity limit trigger";
    static const char * hcrhlr =
                "High critical relative humidity limit reset";
    static const char * lcrhlr =
                "High critical relative humidity limit reset";
    static const char * lcrhlt =
                "High critical relative humidity limit trigger";
    static const char * horhlt =
                "High operating relative humidity limit trigger";
    static const char * horhlr =
                "High operating relative humidity limit reset";
    static const char * lorhlr =
                "High operating relative humidity limit reset";
    static const char * lorhlt =
                "High operating relative humidity limit trigger";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0xd,0x2]\n", ellp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, ellp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "environmental_limits_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        if (pc < 0x100) {
            if (pl < 12)  {
                pr2serr("%s:  <<expect parameter 0x%x to be at least 12 "
                        "bytes long, got %d, skip>>\n", __func__, pc, pl);
                goto inner;
            }
            sgj_pr_hr(jsp, "  %s=0x%x\n", param_c, pc);
            sgj_js_nv_ihex(jsp, jo3p, param_c_sn, pc);

            temperature_str(bp[4], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", hctlt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, hctlt, bp[4], false,
                                   NULL, b, "[Celsius]");
            temperature_str(bp[5], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", hctlr, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, hctlr, bp[5], false,
                                   NULL, b, NULL);
            temperature_str(bp[6], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lctlr, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lctlr, bp[6], false,
                                   NULL, b, NULL);
            temperature_str(bp[7], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lctlt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lctlt, bp[7], false,
                                   NULL, b, NULL);
            temperature_str(bp[8], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", hotlt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, hotlt, bp[8], false,
                                   NULL, b, NULL);
            temperature_str(bp[9], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", hotlr, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, hotlr, bp[9], false,
                                   NULL, b, NULL);
            temperature_str(bp[10], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lotlr, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lotlr, bp[10], false,
                                   NULL, b, NULL);
            temperature_str(bp[11], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lotlt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lotlt, bp[11], false,
                                   NULL, b, NULL);
        } else if (pc < 0x200) {
            if (pl < 12)  {
                pr2serr("%s:  <<expect parameter 0x%x to be at least 12 "
                        "bytes long, got %d, skip>>\n", __func__, pc, pl);
                goto inner;
            }
            sgj_pr_hr(jsp, "  %s=0x%x\n", param_c, pc);
            sgj_js_nv_ihex(jsp, jo3p, param_c_sn, pc);

            humidity_str(bp[4], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", hcrhlt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, hcrhlt, bp[4], false,
                                   NULL, b, "[percentage]");
            humidity_str(bp[5], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", hcrhlr, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, hcrhlr, bp[5], false,
                                   NULL, b, NULL);
            humidity_str(bp[6], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lcrhlr, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lcrhlr, bp[6], false,
                                   NULL, b, NULL);
            humidity_str(bp[7], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lcrhlt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lcrhlt, bp[7], false,
                                   NULL, b, NULL);
            humidity_str(bp[8], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", horhlt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, horhlt, bp[8], false,
                                   NULL, b, NULL);
            humidity_str(bp[9], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", horhlr, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, horhlr, bp[9], false,
                                   NULL, b, NULL);
            humidity_str(bp[10], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lorhlr, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lorhlr, bp[10], false,
                                   NULL, b, NULL);
            humidity_str(bp[11], true, b, blen);
            sgj_pr_hr(jsp, "    %s: %s\n", lorhlt, b);
            js_snakenv_ihexstr_nex(jsp, jo3p, lorhlt, bp[11], false,
                                   NULL, b, NULL);
        } else
             sgj_pr_hr(jsp, "  <<unexpected %s 0x%x\n", param_c, pc);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
inner:
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* CMD_DUR_LIMITS_SUBPG [0x19,0x21] <cdl>
 * introduced: SPC-6 rev 1, significantly changed rev 6 */
static bool
show_cmd_dur_limits_page(const uint8_t * resp, int len,
                         struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    uint32_t count, noitmc_v, noatmc_v, noitatmc_v, noc_v;
    const uint8_t * bp;
    const char * cp;
    const char * thp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[144];
    static const int blen = sizeof(b);
    static const char * cdllp = "Command duration limits statistics log page";
    static const char * t2cdld = "T2 command duration limit descriptor";
    static const char * cdlt2amp = "CDL T2A mode page";
    static const char * cdlt2bmp = "CDL T2B mode page";
    static const char * first_7[] = {"First", "Second", "Third", "Fourth",
                                     "Fifth", "Sixth", "Seventh"};
    static const char * noitmc = "Number of inactive target miss commands";
    static const char * noatmc = "Number of active target miss commands";
    static const char * noitatmc =
        "Number of inactive target and active target miss commands";
    static const char * noc = "Number of commands";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x19,0x21]\n", cdllp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, cdllp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                        "command_duration_limits_statistcs_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;         /* parameter length */
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x1:
            /* spc6r06: table 349 name "Number of READ commands" seems to
             * be wrong. Use what surrounding text and table 347 suggest */
            cp = "Achievable latency target";
            count =  sg_get_unaligned_be32(bp + 4);
            sgj_pr_hr(jsp, "  %s = %" PRIu32 "\n", cp, count);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, cp);
                js_snakenv_ihexstr_nex(jsp, jop, cp, count, true, NULL, NULL,
                                       "unit: microsecond");
            }
            break;
        case 0x11:
        case 0x12:
        case 0x13:
        case 0x14:
        case 0x15:
        case 0x16:
        case 0x17:
            sgj_pr_hr(jsp, "  %s code 0x%x restricted\n", param_c, pc);
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, rstrict_s);
            break;
        case 0x21:
        case 0x22:
        case 0x23:
        case 0x24:
        case 0x25:
        case 0x26:
        case 0x27:
            thp = first_7[pc - 0x21];
            sgj_pr_hr(jsp, "  %s %s for %s [pc=0x%x]:\n", thp, t2cdld,
                      cdlt2amp, pc);
            noitmc_v = sg_get_unaligned_be32(bp + 4);
            sgj_pr_hr(jsp, "    %s = %u\n", noitmc, noitmc_v);
            noatmc_v = sg_get_unaligned_be32(bp + 8);
            sgj_pr_hr(jsp, "    %s = %u\n", noatmc, noatmc_v);
            noitatmc_v = sg_get_unaligned_be32(bp + 12);
            sgj_pr_hr(jsp, "    %s = %u\n", noitatmc, noitatmc_v);
            noc_v = sg_get_unaligned_be32(bp + 16);
            sgj_pr_hr(jsp, "    %s = %u\n", noc, noc_v);
            if (jsp->pr_as_json) {
                snprintf(b, blen, "%s %s for %s", thp, t2cdld, cdlt2amp);
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, b);

                js_snakenv_ihexstr_nex(jsp, jop, noitmc, noitmc_v, true, NULL,
                                       NULL, NULL);
                js_snakenv_ihexstr_nex(jsp, jop, noatmc, noatmc_v, true, NULL,
                                       NULL, NULL);
                js_snakenv_ihexstr_nex(jsp, jop, noitatmc, noitatmc_v, true,
                                       NULL, NULL, NULL);
                js_snakenv_ihexstr_nex(jsp, jop, noc, noc_v, true, NULL,
                                       NULL, NULL);
            }
            break;
        case 0x31:
        case 0x32:
        case 0x33:
        case 0x34:
        case 0x35:
        case 0x36:
        case 0x37:
            sgj_pr_hr(jsp, "  %s 0x%x restricted\n", param_c, pc);
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, rstrict_s);
            break;
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
            /* This short form introduced in draft spc6r06 */
            thp = first_7[pc - 0x41];
            sgj_pr_hr(jsp, "  %s %s for %s [pc=0x%x]:\n", thp, t2cdld,
                      cdlt2bmp, pc);
            noitmc_v = sg_get_unaligned_be32(bp + 4);
            sgj_pr_hr(jsp, "    %s = %u\n", noitmc, noitmc_v);
            noatmc_v = sg_get_unaligned_be32(bp + 8);
            sgj_pr_hr(jsp, "    %s = %u\n", noatmc, noatmc_v);
            noitatmc_v = sg_get_unaligned_be32(bp + 12);
            sgj_pr_hr(jsp, "    %s = %u\n", noitatmc, noitatmc_v);
            noc_v = sg_get_unaligned_be32(bp + 16);
            sgj_pr_hr(jsp, "    %s = %u\n", noc, noc_v);
            if (jsp->pr_as_json) {
                snprintf(b, blen, "%s %s for %s", thp, t2cdld, cdlt2amp);
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, b);

                js_snakenv_ihexstr_nex(jsp, jop, noitmc, noitmc_v, true, NULL,
                                       NULL, NULL);
                js_snakenv_ihexstr_nex(jsp, jop, noatmc, noatmc_v, true, NULL,
                                       NULL, NULL);
                js_snakenv_ihexstr_nex(jsp, jop, noitatmc, noitatmc_v, true,
                                       NULL, NULL, NULL);
                js_snakenv_ihexstr_nex(jsp, jop, noc, noc_v, true, NULL,
                                       NULL, NULL);
            }

            break;
        default:
             sgj_pr_hr(jsp, "  <<unexpected %s 0x%x\n", param_c, pc);
            break;
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Tape usage: Vendor specific (LTO-5 and LTO-6): 0x30 */
static bool
show_tape_usage_page(const uint8_t * resp, int len, struct opts_t * op,
                     sgj_opaque_p jop)
{
    int k, num, extra;
    uint32_t u;
    uint64_t ull;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    char b[168];
    static const int blen = sizeof(b);
    static const char * tu_lp = "Tape usage log page";

if (jop) { };
    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, tu_lp);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  (LTO-5 and LTO-6 specific) [0x30]\n", tu_lp);
    for (k = num; k > 0; k -= extra, bp += extra) {
        int pc = sg_get_unaligned_be16(bp + 0);

        extra = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, extra);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            goto skip;
        }
        ull = 0;
        u = 0;
        switch (bp[3]) {
        case 2:
            u = sg_get_unaligned_be16(bp + 4);
            break;
        case 4:
            u = sg_get_unaligned_be32(bp + 4);
            break;
        case 8:
            ull = sg_get_unaligned_be64(bp + 4);
            break;
        }
        switch (pc) {
        case 0x01:
            if (extra == 8)
                snprintf(b, blen, "  Thread count: %u", u);
            break;
        case 0x02:
            if (extra == 12)
                snprintf(b, blen, "  Total data sets written: %" PRIu64, ull);
            break;
        case 0x03:
            if (extra == 8)
                snprintf(b, blen, "  Total write retries: %u", u);
            break;
        case 0x04:
            if (extra == 6)
                snprintf(b, blen, "  Total unrecovered write errors: %u", u);
            break;
        case 0x05:
            if (extra == 6)
                snprintf(b, blen, "  Total suspended writes: %u", u);
            break;
        case 0x06:
            if (extra == 6)
                snprintf(b, blen, "  Total fatal suspended writes: %u", u);
            break;
        case 0x07:
            if (extra == 12)
                snprintf(b, blen, "  Total data sets read: %" PRIu64, ull);
            break;
        case 0x08:
            if (extra == 8)
                snprintf(b, blen, "  Total read retries: %u", u);
            break;
        case 0x09:
            if (extra == 6)
                snprintf(b, blen, "  Total unrecovered read errors: %u", u);
            break;
        case 0x0a:
            if (extra == 6)
                snprintf(b, blen, "  Total suspended reads: %u", u);
            break;
        case 0x0b:
            if (extra == 6)
                snprintf(b, blen, "  Total fatal suspended reads: %u", u);
            break;
        default:
            snprintf(b, blen, "  unknown %s = 0x%x, contents in hex:\n",
                     param_c, pc);
            hex2str(bp,extra, "    ", op->h2s_oformat, blen, b);
            break;
        }
        sgj_pr_hr(jsp, "%s\n", b);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
skip:
        if (op->filter_given)
            break;
    }
    return true;
}

/* 0x30 */
static bool
show_hgst_perf_page(const uint8_t * resp, int len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool valid = false;
    int num, pl;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    char b[128];
    static const int blen = sizeof(b);
    static const char * hwpclp = "HGST/WDC performance counters log page";

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x30]\n", hwpclp);
    num = len - 4;
    if (num < 0x30) {
        pr2serr("%s too short (%d) < 48\n", hwpclp, num);
        return valid;
    }
    bp = &resp[0] + 4;
    while (num > 3) {
        int pc = sg_get_unaligned_be16(bp + 0);

        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        switch (pc) {
        case 0:
            valid = true;
            sgj_pr_hr(jsp, "  Zero Seeks = %u\n",
                      sg_get_unaligned_be16(bp + 4));
            sgj_pr_hr(jsp, "  Seeks >= 2/3 = %u\n",
                      sg_get_unaligned_be16(bp + 6));
            sgj_pr_hr(jsp, "  Seeks >= 1/3 and < 2/3 = %u\n",
                      sg_get_unaligned_be16(bp + 8));
            sgj_pr_hr(jsp, "  Seeks >= 1/6 and < 1/3 = %u\n",
                      sg_get_unaligned_be16(bp + 10));
            sgj_pr_hr(jsp, "  Seeks >= 1/12 and < 1/6 = %u\n",
                      sg_get_unaligned_be16(bp + 12));
            sgj_pr_hr(jsp, "  Seeks > 0 and < 1/12 = %u\n",
                      sg_get_unaligned_be16(bp + 14));
            sgj_pr_hr(jsp, "  Overrun Counter = %u\n",
                      sg_get_unaligned_be16(bp + 20));
            sgj_pr_hr(jsp, "  Underrun Counter = %u\n",
                      sg_get_unaligned_be16(bp + 22));
            sgj_pr_hr(jsp, "  Device Cache Full Read Hits = %u\n",
                      sg_get_unaligned_be32(bp + 24));
            sgj_pr_hr(jsp, "  Device Cache Partial Read Hits = %u\n",
                      sg_get_unaligned_be32(bp + 28));
            sgj_pr_hr(jsp, "  Device Cache Write Hits = %u\n",
                      sg_get_unaligned_be32(bp + 32));
            sgj_pr_hr(jsp, "  Device Cache Fast Writes = %u\n",
                      sg_get_unaligned_be32(bp + 36));
            sgj_pr_hr(jsp, "  Device Cache Read Misses = %u\n",
                      sg_get_unaligned_be32(bp + 40));
            break;
        default:
            valid = false;
            sgj_pr_hr(jsp, "  Unknown HGST/WDC %s = 0x%x\n", param_c, pc);
            break;
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return valid;
}

/* Tape capacity: vendor specific (LTO-5 and LTO-6 ?): 0x31 */
static bool
show_tape_capacity_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    int k, num, extra;
    uint32_t u;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    char b[144];
    static const int blen = sizeof(b);
    static const char * tc_lp = "Tape capacity log page";

if (jop) { };
    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, tc_lp);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  (LTO-5 and LTO-6 specific) [0x31]\n", tc_lp);
    for (k = num; k > 0; k -= extra, bp += extra) {
        int pc = sg_get_unaligned_be16(bp + 0);

        extra = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, extra);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            goto skip;
        }
        if (extra != 8)
            continue;
        u = sg_get_unaligned_be32(bp + 4);
        snprintf(b, blen, "  ");

        switch (pc) {
        case 0x01:
            snprintf(b + 2, blen - 2, "Main partition remaining capacity "
                     "(in MiB): %u", u);
            break;
        case 0x02:
            snprintf(b + 2, blen - 2, "Alternate partition remaining "
                     "capacity (in MiB): %u", u);
            break;
        case 0x03:
            snprintf(b + 2, blen - 2, "Main partition maximum capacity (in "
                     "MiB): %u", u);
            break;
        case 0x04:
            snprintf(b + 2, blen - 2, "Alternate partition maximum capacity "
                     "(in MiB): %u", u);
            break;
        default:
            sgj_pr_hr(jsp, "  unknown %s = 0x%x, contents in hex:\n",
                      param_c, pc);
            hex2str(bp, extra, "    ", op->h2s_oformat, blen, b);
            break;
        }
        sgj_pr_hr(jsp, "%s\n", b);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
skip:
        if (op->filter_given)
            break;
    }
    return true;
}

/* Data compression: originally vendor specific 0x32 (LTO-5), then
 * ssc-4 standardizes it at 0x1b <dc> */
static bool
show_data_compression_page(const uint8_t * resp, int len,
                           struct opts_t * op, sgj_opaque_p jop)
{
    bool is_x100, is_pr;
    int k, pl, num, extra, pc, pg_code;
    uint64_t ull;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * const dc_lp = "Data compression log page";

    pg_code = resp[0] & 0x3f;
    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed data compression page\n", __func__);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (0x1b == pg_code)
            sgj_pr_hr(jsp, "%s  (ssc-4) [0x1b]\n", dc_lp);
        else
            sgj_pr_hr(jsp, "%s  (LTO-5 specific) [0x%x]\n", dc_lp, pg_code);
    }
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, dc_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "data_compression_log_parameters");
    }

    for (k = num; k > 0; k -= extra, bp += extra) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3];
        extra = pl + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, extra);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            break;
        }
        if ((0 == pl) || (pl > 8)) {
            pr2serr("badly formed data compression log parameter\n");
            pr2serr("  %s = 0x%x, contents in hex:\n", param_c, pc);
            hex2stderr(bp, extra, op->dstrhex_no_ascii);
            goto skip_para;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        /* variable length integer, max length 8 bytes */
        ull = sg_get_unaligned_be(pl - 4, bp + 4);
        ccp = NULL;
        is_x100 = false;
        is_pr = false;

        switch (pc) {
        case 0x00:
            ccp = "Read compression ratio";
            is_x100 = true;
            break;
        case 0x01:
            ccp = "Write compression ratio";
            is_x100 = true;
            break;
        case 0x02:
            ccp = "Megabytes transferred to server";
            break;
        case 0x03:
            ccp = "Bytes transferred to server";
            break;
        case 0x04:
            ccp = "Megabytes read from tape";
            break;
        case 0x05:
            ccp = "Bytes read from tape";
            break;
        case 0x06:
            ccp = "Megabytes transferred from server";
            break;
        case 0x07:
            ccp = "Bytes transferred from server";
            break;
        case 0x08:
            ccp = "Megabytes written to tape";
            break;
        case 0x09:
            ccp = "Bytes written to tape";
            break;
        case 0x100:
            ccp = "Data compression enabled";
            break;
        default:
            sgj_pr_hr(jsp, "  unknown %s = 0x%x, contents in hex:\n", param_c,
                      pc);
            hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
            is_pr = true;
            break;
        }
        if (! is_pr)
            sgj_pr_hr(jsp, "  %s%s: %" PRIu64 "\n", ccp,
                      (is_x100 ? " x100" : ""), ull);
        if (jsp->pr_as_json) {
            if (NULL == ccp) {
                if (pc >= 0xf000)
                    ccp = vend_spec;
                else
                    ccp = rsv_s;
            }
            if (is_x100)
                sgj_js_nv_ihexstr_nex(jsp, jo3p, param_c_sn, pc, false,
                                      NULL, ccp, "ratio x 100");
            else
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            sgj_js_nv_i(jsp, jo3p, "data_compression_counter", ull);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
skip_para:
        if (op->filter_given)
            break;
    }
    return true;
}

/* LAST_N_ERR_LPAGE [0x7] <lne>  introduced: SPC-2 */
static bool
show_last_n_error_page(const uint8_t * resp, int len,
                       struct opts_t * op, sgj_opaque_p jop)
{
    int k, num, pl;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[256];
    static const int blen = sizeof(b);
    static const char * lneelp = "Last n error events log page";
    static const char * eed = "error_event_data";

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        sgj_pr_hr(jsp, "No error events logged\n");
        return true;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x7]\n", lneelp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, lneelp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "error_event_log_parameters");
    }

    for (k = num; k > 0; k -= pl, bp += pl) {
        uint16_t pc;

        if (k < 3) {
            pr2serr("%s: short %s\n", __func__, lneelp);
            return false;
        }
        pl = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, NULL);
        }

        sgj_pr_hr(jsp, "  Error event %u [0x%x]:\n", pc, pc);
        if (pl > 4) {
            if ((bp[2] & 0x1) && (bp[2] & 0x2)) {
                sgj_pr_hr(jsp, "    [binary]:\n");
                hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
                if (jsp->pr_as_json)
                    sgj_js_nv_hex_bytes(jsp, jo3p, eed, bp + 4, pl - 4);
            } else if (0x01 == (bp[2] & 0x3)) {  /* ASCII */
                sgj_pr_hr(jsp, "    %.*s\n", pl - 4, (const char *)(bp + 4));
                if (jsp->pr_as_json)
                    sgj_js_nv_s_len_chk(jsp, jo3p, eed, bp + 4, pl - 4);
            } else {
                sgj_pr_hr(jsp, "    [data counter?? (LP bit should be "
                          "set)]:\n");
                hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
                if (jsp->pr_as_json)
                    sgj_js_nv_hex_bytes(jsp, jo3p, eed, bp + 4, pl - 4);
            }
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
    }
    return true;
}

/* LAST_N_DEFERRED_LPAGE [0xb] <lnd>  introduced: SPC-2 */
static bool
show_last_n_deferred_error_page(const uint8_t * resp, int len,
                                struct opts_t * op, sgj_opaque_p jop)
{
    int k, n, num, pl;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p, jo4p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * lndeoaelp =
                "Last n deferred errors or asynchronous events log page";
    static const char * deoae = "Deferred error or asynchronous event";
    static const char * sd = "sense_data";

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: No deferred errors logged\n", __func__);
        return true;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0xb]\n", lndeoaelp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, lndeoaelp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                "deferred_error_or_asynchronous_event_log_parameters");
    }

    for (k = num; k > 0; k -= pl, bp += pl) {
        int pc;

        if (k < 3) {
            pr2serr("%s: short %s\n", __func__, lndeoaelp);
            return false;
        }
        pl = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, deoae);
        }
        sgj_pr_hr(jsp, "  %s [0x%x]:\n", deoae, pc);
        if (op->do_brief > 0) {
            hex2stdout(bp + 4, pl - 4, op->dstrhex_no_ascii);
            hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json)
                sgj_js_nv_hex_bytes(jsp, jo3p, sd, bp + 4, pl - 4);
        } else {

            n = sg_get_sense_str("    ", bp + 4, pl - 4,  false, blen, b);
            sgj_pr_hr(jsp, "%.*s\n", n, b);
            if (jsp->pr_as_json) {
                jo4p = sgj_named_subobject_r(jsp, jo3p, sd);
                sgj_js_sense(jsp, jo4p, bp + 4, pl - 4);
            }
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
    }
    return true;
}

static const char * clgc = "Change list generation code";
static const char * cgn = "Changed generation number";

/* LAST_N_INQUIRY_DATA_CH_SUBPG [0xb,0x1] <lnic> introduced: SPC-5 (rev 17) */
static bool
show_last_n_inq_data_ch_page(const uint8_t * resp, int len,
                             struct opts_t * op, sgj_opaque_p jop)
{
    bool vpd;
    int j, num, pl, vpd_pg;
    uint32_t k, n;
    const uint8_t * bp;
    const char * vpd_pg_name = NULL;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p, jo4p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p;
    char b[128];
    static const int blen = sizeof(b);
    static const char * lnidclp = "Last n inquiry data changed log page";
    static const char * idci = "Inquiry data changed indicator";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0xb,0x1]\n", lnidclp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, lnidclp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "inquiry_data_changed_log_parameters");
    }

    while (num > 3) {
        int pc = sg_get_unaligned_be16(bp + 0);

        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                              0 == pc ? clgc : idci);
        }
        if (0 == pc) {
            if (pl < 8)  {
                pr2serr("%s:  <<expect parameter 0x%x to be at least 8 "
                        "bytes long, got %d, skip>>\n", __func__, pc, pl);
                goto skip;
            }
            sgj_pr_hr(jsp, "  %s [pc=0x0]:\n", clgc);
            for (j = 4, k = 1; j < pl; j +=4, ++k) {
                n = sg_get_unaligned_be32(bp + j);
                sgj_pr_hr(jsp, "    %s [0x%x]: %u\n", cgn, k, n);
            }
            if (jsp->pr_as_json) {
                ja2p = sgj_named_subarray_r(jsp, jo3p,
                                            "changed_generation_numbers");
                for (j = 4, k = 1; j < pl; j +=4, ++k) {
                    jo4p = sgj_new_unattached_object_r(jsp);
                    n = sg_get_unaligned_be32(bp + j);
                    js_snakenv_ihexstr_nex(jsp, jo4p, cgn, n, true, NULL,
                                           NULL, NULL);
                    sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo4p);
                }
            }
        } else {        /* pc > 0x0 */
            int m;
            const int nn = sg_lib_names_mode_len;
            struct sg_lib_simple_value_name_t * nvp = sg_lib_names_vpd_arr;

            snprintf(b, blen, "  %s 0x%x, ", param_c, pc);
            vpd = !! (1 & *(bp + 4));
            vpd_pg = *(bp + 5);
            if (vpd) {
                for (m = 0; m < nn; ++m, ++nvp) {
                    if (nvp->value == vpd_pg)
                        break;
                }
                vpd_pg_name = (m < nn) ? nvp->name : NULL;
            } else
                vpd_pg_name = "Standard INQUIRY";

            if (jsp->pr_as_json) {
                sgj_js_nv_i(jsp, jo3p, "vpd", (int)vpd);
                sgj_js_nv_ihex(jsp, jo3p, "changed_page_code", vpd_pg);
                if (vpd_pg_name)
                    sgj_js_nv_s(jsp, jo3p, "changed_page_name", vpd_pg_name);
            }
            if (vpd) {
                sgj_pr_hr(jsp, "%sVPD page 0x%x changed\n", b, vpd_pg);
                if (0 == op->do_brief) {
                    if (vpd_pg_name)
                        sgj_pr_hr(jsp, "    name: %s\n", vpd_pg_name);
                }
            } else
                sgj_pr_hr(jsp, "%sStandard INQUIRY data changed\n", b);
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
skip:
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
        num -= pl;
        bp += pl;
    }
    return true;
}

/* LAST_N_MODE_PG_DATA_CH_SUBPG [0xb,0x2] <lnmc> introduced: SPC-5 (rev 17) */
static bool
show_last_n_mode_pg_data_ch_page(const uint8_t * resp, int len,
                                 struct opts_t * op, sgj_opaque_p jop)
{
    bool spf;
    int j, k, num, pl, pg_code, spg_code;
    uint32_t n;
    const uint8_t * bp;
    const char * mode_pg_name = NULL;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p, jo4p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p;
    char b[128];
    static const int blen = sizeof(b);
    static const char * lnmpdclp = "Last n mode page data changed log page";
    static const char * mpdci = "Mode page data changed indicator";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0xb,0x2]\n", lnmpdclp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, lnmpdclp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "mode_page_data_changed_log_parameters");
    }

    while (num > 3) {
        int pc = sg_get_unaligned_be16(bp + 0);

        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                              0 == pc ? clgc : mpdci);
        }
        if (0 == pc) {  /* Same as LAST_N_INQUIRY_DATA_CH_SUBPG [0xb,0x1] */
            if (pl < 8)  {
                pr2serr("%s: <<expect parameter 0x%x to be at least 8 bytes "
                        "long, got %d, skip>>\n", __func__, pc, pl);
                goto skip;
            }
            sgj_pr_hr(jsp, "  %s [pc=0x0]:\n", clgc);
            for (j = 4, k = 1; j < pl; j +=4, ++k) {
                n = sg_get_unaligned_be32(bp + j);
                sgj_pr_hr(jsp, "    %s [0x%x]: %u\n", cgn, k, n);
            }
            if (jsp->pr_as_json) {
                ja2p = sgj_named_subarray_r(jsp, jo3p,
                                            "changed_generation_numbers");
                for (j = 4, k = 1; j < pl; j +=4, ++k) {
                    jo4p = sgj_new_unattached_object_r(jsp);
                    n = sg_get_unaligned_be32(bp + j);
                    js_snakenv_ihexstr_nex(jsp, jo4p, cgn, n, true, NULL,
                                           NULL, NULL);
                    sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo4p);
                }
            }
        } else {        /* pc > 0x0 */
            int val;
            const int nn = sg_lib_names_mode_len;
            struct sg_lib_simple_value_name_t * nmp = sg_lib_names_mode_arr;

            snprintf(b, blen, "  %s 0x%x, ", param_c, pc);
            spf = !! (0x40 & *(bp + 4));
            pg_code = 0x3f & *(bp + 4);
            spg_code = *(bp + 5);
            if (spf)       /* SPF bit set */
                sgj_pr_hr(jsp, "%smode page 0x%x,0%x changed\n", b, pg_code,
                          spg_code);
            else
                sgj_pr_hr(jsp, "%smode page 0x%x changed\n", b, pg_code);

            val = (pg_code << 8) | spg_code;
            for (k = 0; k < nn; ++k, ++nmp) {
                if (nmp->value == val)
                    break;
            }
            mode_pg_name = (k < nn) ? nmp->name : NULL;
            if ((0 == op->do_brief) && mode_pg_name)
                sgj_pr_hr(jsp, "    name: %s\n", nmp->name);
            if (jsp->pr_as_json) {
                sgj_js_nv_i(jsp, jo3p, "spf", (int)spf);
                sgj_js_nv_ihex(jsp, jo3p, "mode_page_code", pg_code);
                sgj_js_nv_ihex(jsp, jo3p, spg_c_sn, spg_code);
                if (mode_pg_name)
                    sgj_js_nv_s(jsp, jo3p, "mode_page_name", mode_pg_name);
            }
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
skip:
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
        num -= pl;
        bp += pl;
    }
    return true;
}

static const char * self_test_code[] = {
    "default", "background short", "background extended", "reserved",
    "aborted background", "foreground short", "foreground extended",
    "reserved"};

static const char * self_test_result[] = {
    "completed without error",
    "aborted by SEND DIAGNOSTIC",
    "aborted other than by SEND DIAGNOSTIC",
    "unknown error, unable to complete",
    "self test completed with failure in test segment (which one unknown)",
    "first segment in self test failed",
    "second segment in self test failed",
    "another segment in self test failed",
    "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
    "reserved", "self test in progress"};

/* SELF_TEST_LPAGE [0x10] <str>  introduced: SPC-3 */
static bool
show_self_test_page(const uint8_t * resp, int len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool addr_all_ffs;
    int k, num, res, st_c;
    unsigned int v;
    uint32_t n;
    uint64_t ull;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[80];
    static const int blen = sizeof(b);
    static const char * strlp = "Self-test results log page";
    static const char * stc_s = "Self-test code";
    static const char * str_s = "Self-test result";
    static const char * stn_s = "Self-test number";
    static const char * apoh = "Accumulated power on hours";

    num = len - 4;
    if (num < 0x190) {
        pr2serr("%s: short %s [length 0x%x rather than 0x190 bytes]\n",
                __func__, strlp, num);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x10]\n", strlp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, strlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "self_test_results_log_parameters");
    }

    for (k = 0, bp = resp + 4; k < 20; ++k, bp += 20 ) {
        int pc = sg_get_unaligned_be16(bp + 0);
        int pl = bp[3] + 4;

        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                              "Self-test results");
        }
        n = sg_get_unaligned_be16(bp + 6);
        if ((0 == n) && (0 == bp[4])) {
            if (jsp->pr_as_json)
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
            break;
        }
        sgj_pr_hr(jsp, "  %s = %d, accumulated power-on hours = %d\n",
                  param_c, pc, n);
        st_c = (bp[4] >> 5) & 0x7;
        sgj_pr_hr(jsp, "    %s: %s [%d]\n", stc_s, self_test_code[st_c],
                  st_c);
        res = bp[4] & 0xf;
        sgj_pr_hr(jsp, "    %s: %s [%d]\n", str_s, self_test_result[res],
                  res);
        if (bp[5])
            sgj_pr_hr(jsp, "    %s = %d\n", stn_s, (int)bp[5]);
        ull = sg_get_unaligned_be64(bp + 8);

        addr_all_ffs = sg_all_ffs(bp + 8, 8);
        if (! addr_all_ffs) {
            if ((res > 0) && ( res < 0xf))
                sgj_pr_hr(jsp, "    address of first error = 0x%" PRIx64 "\n",
                          ull);
        }
        v = bp[16] & 0xf;
        if (v) {
            if (op->do_brief)
                sgj_pr_hr(jsp, "    %s = 0x%x , asc = 0x%x, ascq = 0x%x\n",
                          s_key, v, bp[17], bp[18]);
            else {
                sgj_pr_hr(jsp, "    %s = 0x%x [%s]\n", s_key, v,
                          sg_get_sense_key_str(v, blen, b));

                sgj_pr_hr(jsp, "      asc = 0x%x, ascq = 0x%x [%s]\n",
                          bp[17], bp[18], sg_get_asc_ascq_str(bp[17], bp[18],
                          blen, b));
            }
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json) {
            js_snakenv_ihexstr_nex(jsp, jo3p, stc_s, st_c, true, NULL,
                                   self_test_code[st_c], NULL);
            js_snakenv_ihexstr_nex(jsp, jo3p, str_s, res, true, NULL,
                                    self_test_result[res], NULL);
            js_snakenv_ihexstr_nex(jsp, jo3p, stn_s, bp[5], false, NULL,
                                   NULL, "segment number that failed");
            js_snakenv_ihexstr_nex(jsp, jo3p, apoh, n, true, NULL,
                   (0xffff == n ? "65535 hours or more" : NULL), NULL);
            sgj_js_nv_ihexstr(jsp, jo3p, "address_of_first_failure", pc, NULL,
                              addr_all_ffs ? "no errors detected" : NULL);
            sgj_js_nv_ihexstr(jsp, jo3p, "sense_key", v, NULL,
                              sg_get_sense_key_str(v, blen, b));
            sgj_js_nv_ihexstr(jsp, jo3p, "additional_sense_code", bp[17],
                              NULL, NULL);
            sgj_js_nv_ihexstr(jsp, jo3p, "additional_sense_code_qualifier",
                              bp[18], NULL, sg_get_asc_ascq_str(bp[17],
                              bp[18], blen, b));
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
        if (op->filter_given)
            break;
    }
    return true;
}

/* TEMPERATURE_LPAGE [0xd] <temp>  introduced: SPC-3
 * N.B. The ENV_REPORTING_SUBPG [0xd,0x1] and the ENV_LIMITS_SUBPG [0xd,0x2]
 * (both added SPC-5) are a superset of this page. */
static bool
show_temperature_page(const uint8_t * resp, int len, struct opts_t * op,
                      sgj_opaque_p jop)
{
    int k, num, extra;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * tlp = "Temperature log page";
    static const char * ctemp = "Current temperature";
    static const char * rtemp = "Reference temperature";

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, tlp);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (! op->do_temperature)
            sgj_pr_hr(jsp, "%s  [0xd]\n", tlp);
    }
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, tlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "temperature_log_parameters");
    }

    for (k = num; k > 0; k -= extra, bp += extra) {
        int pc;

        if (k < 3) {
            pr2serr("%s: short %s\n", __func__, tlp);
            return true;
        }
        extra = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, extra);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            goto skip;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
            sgj_js_nv_ihex(jsp, jo3p, param_c_sn, pc);
        }

        switch (pc) {
        case 0:
            if ((extra > 5) && (k > 5)) {
                if (0 == bp[5])
                    sgj_pr_hr(jsp, "  %s = 0 C (or less)\n", ctemp);
                else if (bp[5] < 0xff)
                    sgj_pr_hr(jsp, "  %s = %d C\n", ctemp, bp[5]);
                else
                    sgj_pr_hr(jsp, "  %s = <%s>\n", ctemp, not_avail);
                if (jsp->pr_as_json) {
                    const char * cp = NULL;

                    if (0 == bp[5])
                        cp = "0 or less Celsius";
                    else if (0xff == bp[5])
                        cp = "temperature not available";
                    js_snakenv_ihexstr_nex(jsp, jo3p, "temperature", bp[5],
                                           false, NULL, cp,
                                           "current [unit: celsius]");
                }
            }
            break;
        case 1:
            if ((extra > 5) && (k > 5)) {
                if (bp[5] < 0xff)
                    sgj_pr_hr(jsp, "  %s = %d C\n", rtemp, bp[5]);
                else
                    sgj_pr_hr(jsp, "  %s = <%s>\n", rtemp, not_avail);
                if (jsp->pr_as_json) {
                    const char * cp;

                    if (0 == bp[5])
                        cp = "in C (or less)";
                    else if (0xff == bp[5])
                        cp = not_avail;
                    else
                        cp = "in C";
                    sgj_js_nv_ihex_nex(jsp, jo3p, "reference_temperature",
                                       bp[5], true, cp);
                }
            }
            break;
        default:
            if (! op->do_temperature) {
                sgj_pr_hr(jsp, "  unknown %s = 0x%x, contents in hex:\n",
                          param_c, pc);
                hex2stdout(bp, extra, op->dstrhex_no_ascii);
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
                continue;
            }
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
skip:
        if (op->filter_given)
            break;
    }
    return true;
}

/* START_STOP_LPAGE [0xe] <sscc>  introduced: SPC-3 */
static bool
show_start_stop_page(const uint8_t * resp, int len, struct opts_t * op,
                     sgj_opaque_p jop)
{
    int k, num, extra;
    uint32_t val;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char str[PCB_STR_LEN];
    char b[256];
    static const char * sscclp = "Start-stop cycle counter log page";
    static const char * dom = "Date of manufacture";
    static const char * ad = "Accounting date";
    static const char * sccodl = "Specified cycle count over device lifetime";
    static const char * assc = "Accumulated start-stop cycles";
    static const char * slucodl =
                        "Specified load-unload count over device lifetime";
    static const char * aluc = "Accumulated load-unload cycles";

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, sscclp);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0xe]\n", sscclp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, sscclp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "start_stop_cycle_log_parameters");
    }

    for (k = num; k > 0; k -= extra, bp += extra) {
        int pc;

        if (k < 3) {
            pr2serr("%s: short %s\n", __func__, sscclp);
            return false;
        }
        extra = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, extra);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            goto skip;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 1:
            if (10 == extra) {
                 sgj_pr_hr(jsp, "  %s, year: %.4s, week: %.2s\n", dom,
                       bp + 4, bp + 8);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      "Date of manufacture");
                    sgj_js_nv_s_len_chk(jsp, jo3p, "year_of_manufacture",
                                        bp + 4, 4);
                    sgj_js_nv_s_len_chk(jsp, jo3p, "week_of_manufacture",
                                        bp + 8, 2);
                }
            } else if (op->verbose) {
                pr2serr("%s: %s parameter length strange: %d\n", __func__,
                        dom, extra - 4);
                hex2stderr(bp, extra, 1);
            }
            break;
        case 2:
            if (10 == extra) {
                sgj_pr_hr(jsp, "  %s, year: %.4s, week: %.2s\n", ad, bp + 4,
                          bp + 8);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      "Accounting date");
                    sgj_js_nv_s_len_chk(jsp, jo3p, "year_of_manufacture",
                                        bp + 4, 4);
                    sgj_js_nv_s_len_chk(jsp, jo3p, "week_of_manufacture",
                                        bp + 8, 2);
                }
            } else if (op->verbose) {
                pr2serr("%s: %s parameter length strange: %d\n", __func__,
                        ad, extra - 4);
                hex2stderr(bp, extra, 1);
            }
            break;
        case 3:
            if (extra > 7) {
                val = sg_get_unaligned_be32(bp + 4);
                sgj_pr_hr(jsp, "  %s = %u\n", sccodl, val);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      sccodl);
                    js_snakenv_ihexstr_nex(jsp, jo3p, sccodl, val, false,
                                           NULL, NULL, NULL);
                }
            }
            break;
        case 4:
            if (extra > 7) {
                val = sg_get_unaligned_be32(bp + 4);
                sgj_pr_hr(jsp, "  %s = %u\n", assc, val);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      assc);
                    js_snakenv_ihexstr_nex(jsp, jo3p, assc, val, false,
                                           NULL, NULL, NULL);
                }
            }
            break;
        case 5:
            if (extra > 7) {
                val = sg_get_unaligned_be32(bp + 4);
                sgj_pr_hr(jsp, "  %s = %u\n", slucodl, val);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      slucodl);
                    js_snakenv_ihexstr_nex(jsp, jo3p, slucodl, val, false,
                                           NULL, NULL, NULL);
                }
            }
            break;
        case 6:
            if (extra > 7) {
                val = sg_get_unaligned_be32(bp + 4);
                sgj_pr_hr(jsp, "  %s = %u\n", aluc, val);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, aluc);
                    js_snakenv_ihexstr_nex(jsp, jo3p, aluc, val, false,
                                           NULL, NULL, NULL);
                }
            }
            break;
        default:
            sgj_pr_hr(jsp, "  unknown %s = 0x%x, contents in hex:\n",
                      param_c, pc);
            hex2str(bp, extra, "    ", op->h2s_oformat, sizeof(b), b);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, unkn_s);
                sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp, extra);
            }
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], str,
                      sizeof(str)));
skip:
        if (op->filter_given)
            break;
    }
    return true;
}

/* APP_CLIENT_LPAGE [0xf] <ac>  introduced: SPC-3 */
static bool
show_app_client_page(const uint8_t * resp, int len, struct opts_t * op,
                     sgj_opaque_p jop)
{
    int k, n, num, extra;
    char * mp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char str[PCB_STR_LEN];
    static const char * aclp = "Application Client log page";
    static const char * guac = "General Usage Application Client";

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, aclp);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (op->do_hex == 0)))
        sgj_pr_hr(jsp, "%s  [0xf]\n", aclp);
    if (jsp->pr_as_json)
        jo2p = sg_log_js_hdr(jsp, jop, aclp, resp);
    if ((0 == op->filter_given) && (! op->do_full)) {
        if ((len > 128) && (0 == op->do_hex) && (0 == op->undefined_hex)) {
            char d[256];

            hex2str(resp, 64, "  ", op->h2s_oformat, sizeof(d), d);
            sgj_pr_hr(jsp, "%s", d);
            sgj_pr_hr(jsp, "  .....  [truncated after 64 of %d bytes (use "
                      "'-H' to see the rest)]\n", len);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihex(jsp, jo2p, "actual_length", len);
                sgj_js_nv_ihex(jsp, jo2p, "truncated_length", 64);
                sgj_js_nv_hex_bytes(jsp, jo2p, in_hex, resp, 64);
            }
        } else {
            n = len * 4 + 32;
            mp = (char *)malloc(n);
            if (mp) {
                hex2str(resp, len, "  ", op->h2s_oformat, n, mp);
                sgj_pr_hr(jsp, "%s", mp);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihex(jsp, jo2p, "length", len);
                    sgj_js_nv_hex_bytes(jsp, jo2p, in_hex, resp, len);
                }
                free(mp);
            }
        }
        return true;
    }
    if (jsp->pr_as_json)
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "application_client_log_parameters");

    /* here if filter_given set or --full given */
    for (k = num; k > 0; k -= extra, bp += extra) {
        int pc;
        char d[1024];

        if (k < 3) {
            pr2serr("%s: short %s\n", __func__, aclp);
            return true;
        }
        extra = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, extra);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        sgj_pr_hr(jsp, "  %s = %d [0x%x] %s\n", param_c, pc, pc,
                  (pc <= 0xfff) ? guac : "");
        hex2str(bp, extra, "    ", op->h2s_oformat, sizeof(d), d);
        sgj_pr_hr(jsp, "%s", d);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                              (pc <= 0xfff) ? guac : NULL);
            sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp, extra);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], str,
                      sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* IE_LPAGE [0x2f] <ie> "Informational Exceptions"  introduced: SPC-3
 * Previously known as "SMART Status and Temperature Reading" lpage.  */
static bool
show_ie_page(const uint8_t * resp, int len, struct opts_t * op,
             sgj_opaque_p jop)
{
    bool skip = false;
    int k, num, param_len;
    const uint8_t * bp;
    const char * cp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char str[PCB_STR_LEN];
    char b[512];
    char bb[64];
    bool full, decoded;
    static const char * ielp = "Informational exceptions log page";
    static const char * ieasc =
                         "informational_exceptions_additional_sense_code";
    static const char * ct = "Current temperature";
    static const char * tt = "Threshold temperature";
    static const char * mt = "Maximum temperature";
    static const char * ce = "common extension";

    full = ! op->do_temperature;
    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, ielp);
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (full)
            sgj_pr_hr(jsp, "%s  [0x2f]\n", ielp);
    }
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, ielp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                           "informational_exceptions_log_parameters");
    }

    for (k = num; k > 0; k -= param_len, bp += param_len) {
        int pc;

        if (k < 3) {
            pr2serr("%s: short %s\n", __func__, ielp);
            return false;
        }
        param_len = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, param_len);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, param_len, op->dstrhex_no_ascii);
            goto skip;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        decoded = true;
        cp = NULL;

        switch (pc) {
        case 0x0:
            if (param_len > 5) {
                bool na;
                uint8_t t;

                if (full) {
                     sgj_pr_hr(jsp, "  IE asc = 0x%x, ascq = 0x%x\n", bp[4],
                               bp[5]);
                    if (bp[4] || bp[5])
                        if(sg_get_asc_ascq_str(bp[4], bp[5], sizeof(b), b))
                             sgj_pr_hr(jsp, "    [%s]\n", b);
                    if (jsp->pr_as_json) {
                        sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                          "Informational exceptions general");
                        sgj_js_nv_ihexstr(jsp, jo3p, ieasc, bp[4], NULL,
                                          NULL);
                        snprintf(b, sizeof(b), "%s_qualifier", ieasc);
                        sgj_js_nv_ihexstr(jsp, jo3p, b, bp[5], NULL,
                                          sg_get_asc_ascq_str(bp[4], bp[5],
                                          sizeof(bb), bb));
                    }
                }
                if (param_len <= 6)
                    break;
                t = bp[6];
                na = (0xff == t);
                if (na)
                    snprintf(b, sizeof(b), "%u C", t);
                else
                    snprintf(b, sizeof(b), "<%s>", unkn_s);
                sgj_pr_hr(jsp, "    %s = %s\n", ct, b);
                if (jsp->pr_as_json)
                    js_snakenv_ihexstr_nex(jsp, jo3p, ct, t, true,
                                           NULL, na ? unkn_s : NULL,
                                           "[unit: celsius]");
                if (param_len > 7) {
                    t = bp[7];
                    na = (0xff == t);
                    if (na)
                        snprintf(b, sizeof(b), "%u C", t);
                    else
                        snprintf(b, sizeof(b), "<%s>", unkn_s);
                    sgj_pr_hr(jsp, "    %s = %s  [%s]\n", tt, b, ce);
                    if (jsp->pr_as_json)
                        js_snakenv_ihexstr_nex(jsp, jo3p, tt, t, true, NULL,
                                               na ? unkn_s : NULL, ce);
                    t = bp[8];
                    if ((param_len > 8) && (t >= bp[6])) {
                        na = (0xff == t);
                        if (na)
                            snprintf(b, sizeof(b), "%u C", t);
                        else
                            snprintf(b, sizeof(b), "<%s>", unkn_s);
                        sgj_pr_hr(jsp, "    %s = %s  [%s]\n", mt, b, ce);
                        if (jsp->pr_as_json)
                            js_snakenv_ihexstr_nex(jsp, jo3p, mt, t, true,
                                                   NULL,
                                                   na ? unkn_s : NULL, ce);
                    }
                }
            }
            decoded = true;
            break;
        default:
            if (op->do_brief > 0) {
                cp = NULL;
                skip = true;
                break;
            }
            if (VP_HITA == op->vend_prod_num) {
                switch (pc) {
                case 0x1:
                    cp = "Remaining reserve 1";
                    break;
                case 0x2:
                    cp = "Remaining reserve XOR";
                    break;
                case 0x3:
                    cp = "XOR depletion";
                    break;
                case 0x4:
                    cp = "Volatile memory backup failure";
                    break;
                case 0x5:
                    cp = "Wear indicator";
                    break;
                case 0x6:
                    cp = "System area wear indicator";
                    break;
                case 0x7:
                    cp = "Channel hangs";
                    break;
                case 0x8:
                    cp = "Flash scan failure";
                    break;
                default:
                    decoded = false;
                    break;
                }
                if (cp) {
                    sgj_pr_hr(jsp, "  %s:\n", cp);
                    sgj_pr_hr(jsp, "    SMART sense_code=0x%x sense_qualifier"
                              "=0x%x threshold=%d%% trip=%d\n", bp[4], bp[5],
                              bp[6], bp[7]);
                    if (jsp->pr_as_json) {
                        sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                          cp);
                        sgj_js_nv_ihex(jsp, jo3p, "smart_sense_code", bp[4]);
                        sgj_js_nv_ihex(jsp, jo3p, "smart_sense_qualifier",
                                       bp[5]);
                        sgj_js_nv_ihex(jsp, jo3p, "smart_threshold", bp[6]);
                        sgj_js_nv_ihex(jsp, jo3p, "smart_trip", bp[7]);
                    }
                }
            } else {
                decoded = false;
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      unkn_s);
            }
            break;
        }               /* end of switch statement */
        if (skip)
            skip = false;
        else if ((! decoded) && full) {
            hex2str(bp, param_len, "    ", op->h2s_oformat, sizeof(b), b);
            sgj_pr_hr(jsp, "  %s = 0x%x, contents in hex:\n%s", param_c, pc,
                      b);
        }

        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], str,
                      sizeof(str)));
skip:
        if (op->filter_given)
            break;
    }           /* end of for loop */
    return true;
}

/* called for SAS port of PROTO_SPECIFIC_LPAGE [0x18] */
static const char *
show_sas_phy_event_info(int pes, unsigned int val, unsigned int thresh_val,
                        char * b, int blen)
{
    int n = 0;
    unsigned int u;
    const char * cp = "";
    static const char * pvdt = "Peak value detector threshold";

    switch (pes) {
    case 0:
        cp = "No event";
        snprintf(b, blen, "%s", cp);
        break;
    case 0x1:
        cp = "Invalid word count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x2:
        cp = "Running disparity error count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x3:
        cp = "Loss of dword synchronization count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x4:
        cp = "Phy reset problem count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x5:
        cp = "Elasticity buffer overflow count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x6:
        cp = "Received ERROR count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x7:
        cp = "Invalid SPL packet count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x8:
        cp = "Loss of SPL packet synchronization count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x20:
        cp = "Received address frame error count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x21:
        cp = "Transmitted abandon-class OPEN_REJECT count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x22:
        cp =  "Received abandon-class OPEN_REJECT count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x23:
        cp = "Transmitted retry-class OPEN_REJECT count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x24:
        cp = "Received retry-class OPEN_REJECT count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x25:
        cp = "Received AIP (WAITING ON PARTIAL) count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x26:
        cp = "Received AIP (WAITING ON CONNECTION) count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x27:
        cp = "Transmitted BREAK count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x28:
        cp = "Received BREAK count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x29:
        cp = "Break timeout count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x2a:
        cp =  "Connection count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x2b:
        cp = "Peak transmitted pathway blocked count";
        n = sg_scnpr(b, blen, "%s: %u", cp, val & 0xff);
        sg_scnpr(b + n, blen - n, "\t%s: %u", pvdt, thresh_val & 0xff);
        break;
    case 0x2c:
        cp = "Peak transmitted arbitration wait time";
        u = val & 0xffff;
        if (u < 0x8000)
            n = sg_scnpr(b, blen, "%s (us): %u", cp, u);
        else
            n = sg_scnpr(b, blen, "%s (ms): %u", cp, 33 + (u - 0x8000));
        u = thresh_val & 0xffff;
        if (u < 0x8000)
            sg_scnpr(b + n, blen - n, "\t%s (us): %u", pvdt, u);
        else
            sg_scnpr(b + n, blen - n, "\t%s (ms): %u", pvdt,
                     33 + (u - 0x8000));
        break;
    case 0x2d:
        cp = "Peak arbitration time";
        n = sg_scnpr(b, blen, "%s (us): %u", cp, val);
        sg_scnpr(b + n, blen - n, "\t%s: %u", pvdt, thresh_val);
        break;
    case 0x2e:
        cp = "Peak connection time";
        n = sg_scnpr(b, blen, "%s (us): %u", cp, val);
        sg_scnpr(b + n, blen - n, "\t%s: %u", pvdt, thresh_val);
        break;
    case 0x2f:
        cp = "Persistent connection count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x40:
        cp = "Transmitted SSP frame count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x41:
        cp = "Received SSP frame count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x42:
        cp = "Transmitted SSP frame error count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x43:
        cp = "Received SSP frame error count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x44:
        cp = "Transmitted CREDIT_BLOCKED count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x45:
        cp = "Received CREDIT_BLOCKED count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x50:
        cp = "Transmitted SATA frame count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x51:
        cp = "Received SATA frame count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x52:
        cp = "SATA flow control buffer overflow count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x60:
        cp = "Transmitted SMP frame count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x61:
        cp = "Received SMP frame count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    case 0x63:
        cp = "Received SMP frame error count";
        snprintf(b, blen, "%s: %u", cp, val);
        break;
    default:
        cp = "";
        snprintf(b, blen, "Unknown phy event source: %d, val=%u, "
                 "thresh_val=%u", pes, val, thresh_val);
        break;
    }
    return cp;
}

static const char * sas_link_rate_arr[16] = {
    "phy enabled; unknown rate",
    "phy disabled",
    "phy enabled; speed negotiation failed",
    "phy enabled; SATA spinup hold state",
    "phy enabled; port selector",
    "phy enabled; reset in progress",
    "phy enabled; unsupported phy attached",
    "reserved [0x7]",
    "1.5 Gbps",                 /* 0x8 */
    "3 Gbps",
    "6 Gbps",
    "12 Gbps",
    "22.5 Gbps",
    "reserved [0xd]",
    "reserved [0xe]",
    "reserved [0xf]",
};

static char *
sas_negot_link_rate(int lrate, char * b, int blen)
{
    int mask = 0xf;

    if (~mask & lrate)
        snprintf(b, blen, "bad link_rate value=0x%x\n", lrate);
    else
        snprintf(b, blen, "%s", sas_link_rate_arr[lrate]);
    return b;
}

/* helper for SAS port of PROTO_SPECIFIC_LPAGE [0x18] */
static void
show_sas_port_param(const uint8_t * bp, int param_len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    int j, m, nphys, t, spld_len, pi;
    uint64_t ull;
    unsigned int ui, ui2, ui3, ui4;
    char * cp;
    const char * ccp;
    const char * cc2p;
    const char * cc3p;
    const char * cc4p;
    const uint8_t * vcp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;
    char b[160];
    char s[80];
    static const char * rtpi = "Relative target port identifier";
    static const char * psplpfstp =
                "Protocol Specific Port log parameter for SAS target port";
    static const char * at = "attached";
    static const char * ip = "initiator_port";
    static const char * tp = "target_port";
    static const char * pvdt = "peak_value_detector_threshold";
    static const int sz = sizeof(s);
    static const int blen = sizeof(b);

    t = sg_get_unaligned_be16(bp + 0);
    if (op->do_name)
        sgj_pr_hr(jsp, " rel_target_port=%d\n", t);
    else
        sgj_pr_hr(jsp, " %s = %d\n", rtpi, t);
    if (op->do_name)
        sgj_pr_hr(jsp, "  gen_code=%d\n", bp[6]);
    else
        sgj_pr_hr(jsp, "  generation code = %d\n", bp[6]);
    nphys = bp[7];
    if (op->do_name)
        sgj_pr_hr(jsp, "  num_phys=%d\n", nphys);
    else
        sgj_pr_hr(jsp, "  number of phys = %d\n", nphys);
    if (jsp->pr_as_json) {
        js_snakenv_ihexstr_nex(jsp, jop, param_c , t, true,
                               NULL, psplpfstp, rtpi);
        pi = 0xf & bp[4];
        sgj_js_nv_ihexstr(jsp, jop, "protocol_identifier", pi, NULL,
                          sg_get_trans_proto_str(pi, blen, b));
        sgj_js_nv_ihex(jsp, jop, "generation_code", bp[6]);
        sgj_js_nv_ihex(jsp, jop, "number_of_phys", bp[7]);
        jap = sgj_named_subarray_r(jsp, jop, "sas_phy_log_descriptor_list");
    }

    for (j = 0, vcp = bp + 8; j < (param_len - 8);
         vcp += spld_len, j += spld_len) {
        if (jsp->pr_as_json) {
            jo2p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo2p, vcp[2]);
        }
        if (op->do_name)
            sgj_pr_hr(jsp, "    phy_id=%d\n", vcp[1]);
        else
            sgj_haj_vi(jsp, jo2p, 2, "phy identifier", SGJ_SEP_EQUAL_1_SPACE,
                       vcp[1], true);
        spld_len = vcp[3];
        if (spld_len < 44)
            spld_len = 48;      /* in SAS-1 and SAS-1.1 vcp[3]==0 */
        else
            spld_len += 4;
        if (op->do_name) {
            t = ((0x70 & vcp[4]) >> 4);
            sgj_pr_hr(jsp, "      att_dev_type=%d\n", t);
            sgj_pr_hr(jsp, "      att_iport_mask=0x%x\n", vcp[6]);
            sgj_pr_hr(jsp, "      att_phy_id=%d\n", vcp[24]);
            sgj_pr_hr(jsp, "      att_reason=0x%x\n", (vcp[4] & 0xf));
            ull = sg_get_unaligned_be64(vcp + 16);
            sgj_pr_hr(jsp, "      att_sas_addr=0x%" PRIx64 "\n", ull);
            sgj_pr_hr(jsp, "      att_tport_mask=0x%x\n", vcp[7]);
            ui = sg_get_unaligned_be32(vcp + 32);
            sgj_pr_hr(jsp, "      inv_dwords=%u\n", ui);
            ui = sg_get_unaligned_be32(vcp + 40);
            sgj_pr_hr(jsp, "      loss_dword_sync=%u\n", ui);
            sgj_pr_hr(jsp, "      neg_log_lrate=%d\n", 0xf & vcp[5]);
            ui = sg_get_unaligned_be32(vcp + 44);
            sgj_pr_hr(jsp, "      phy_reset_probs=%u\n", ui);
            ui = sg_get_unaligned_be32(vcp + 36);
            sgj_pr_hr(jsp, "      running_disparity=%u\n", ui);
            sgj_pr_hr(jsp, "      reason=0x%x\n", (vcp[5] & 0xf0) >> 4);
            ull = sg_get_unaligned_be64(vcp + 8);
            sgj_pr_hr(jsp, "      sas_addr=0x%" PRIx64 "\n", ull);
        } else {
            t = ((0x70 & vcp[4]) >> 4);
            /* attached SAS device type. In SAS-1.1 case 2 was an edge
             * expander; in SAS-2 case 3 is marked as obsolete. */
            switch (t) {
            case 0: snprintf(s, sz, "no device %s", at); break;
            case 1: snprintf(s, sz, "SAS or SATA device"); break;
            case 2: snprintf(s, sz, "expander device"); break;
            case 3: snprintf(s, sz, "expander device (fanout)"); break;
            default: snprintf(s, sz, "%s [%d]", rsv_s, t); break;
            }
            /* the word 'SAS' in following added in spl4r01 */
            sgj_pr_hr(jsp, "    %s SAS device type: %s\n", at, s);
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo2p, "attached_sas_device_type", t,
                                  NULL, s);
            t = 0xf & vcp[4];
            switch (t) {
            case 0: snprintf(s, sz, "%s", unkn_s); break;
            case 1: snprintf(s, sz, "power on"); break;
            case 2: snprintf(s, sz, "hard reset"); break;
            case 3: snprintf(s, sz, "SMP phy control function"); break;
            case 4: snprintf(s, sz, "loss of dword synchronization"); break;
            case 5: snprintf(s, sz, "mux mix up"); break;
            case 6: snprintf(s, sz, "I_T nexus loss timeout for STP/SATA");
                break;
            case 7: snprintf(s, sz, "break timeout timer expired"); break;
            case 8: snprintf(s, sz, "phy test function stopped"); break;
            case 9: snprintf(s, sz, "expander device reduced functionality");
                 break;
            default: snprintf(s, sz, "%s [0x%x]", rsv_s, t); break;
            }
            sgj_pr_hr(jsp, "    %s reason: %s\n", at, s);
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo2p, "attached_reason", t, NULL, s);
            t = (vcp[5] & 0xf0) >> 4;
            switch (t) {
            case 0: snprintf(s, sz, "%s", unkn_s); break;
            case 1: snprintf(s, sz, "power on"); break;
            case 2: snprintf(s, sz, "hard reset"); break;
            case 3: snprintf(s, sz, "SMP phy control function"); break;
            case 4: snprintf(s, sz, "loss of dword synchronization"); break;
            case 5: snprintf(s, sz, "mux mix up"); break;
            case 6: snprintf(s, sz, "I_T nexus loss timeout for STP/SATA");
                break;
            case 7: snprintf(s, sz, "break timeout timer expired"); break;
            case 8: snprintf(s, sz, "phy test function stopped"); break;
            case 9: snprintf(s, sz, "expander device reduced functionality");
                 break;
            default: snprintf(s, sz, "%s [0x%x]", rsv_s, t); break;
            }
            sgj_pr_hr(jsp, "    reason: %s\n", s);
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo2p, "reason", t, NULL, s);
            t = (0xf & vcp[5]);
            ccp = "negotiated logical link rate";
            cc2p = sas_negot_link_rate(t, s, sz);
            sgj_pr_hr(jsp, "    %s: %s\n", ccp, cc2p);
            if (jsp->pr_as_json) {
                sgj_convert2snake(ccp, b, blen);
                sgj_js_nv_ihexstr(jsp, jo2p, b, t, NULL, cc2p);
            }

            sgj_pr_hr(jsp, "    %s initiator port: ssp=%d stp=%d smp=%d\n",
                      at, !! (vcp[6] & 8), !! (vcp[6] & 4), !! (vcp[6] & 2));
            if (jsp->pr_as_json) {
                snprintf(b, blen, "%s_ssp_%s", at, ip);
                sgj_js_nv_i(jsp, jo2p, b, !! (vcp[6] & 8));
                snprintf(b, blen, "%s_stp_%s", at, ip);
                sgj_js_nv_i(jsp, jo2p, b, !! (vcp[6] & 4));
                snprintf(b, blen, "%s_smp_%s", at, ip);
                sgj_js_nv_i(jsp, jo2p, b, !! (vcp[6] & 2));
            }
            sgj_pr_hr(jsp, "    %s target port: ssp=%d stp=%d smp=%d\n", at,
                      !! (vcp[7] & 8), !! (vcp[7] & 4), !! (vcp[7] & 2));
            if (jsp->pr_as_json) {
                snprintf(b, blen, "%s_ssp_%s", at, tp);
                sgj_js_nv_i(jsp, jo2p, b, !! (vcp[7] & 8));
                snprintf(b, blen, "%s_stp_%s", at, tp);
                sgj_js_nv_i(jsp, jo2p, b, !! (vcp[7] & 4));
                snprintf(b, blen, "%s_smp_%s", at, tp);
                sgj_js_nv_i(jsp, jo2p, b, !! (vcp[7] & 2));
            }
            ull = sg_get_unaligned_be64(vcp + 8);
            sgj_pr_hr(jsp, "    SAS address = 0x%" PRIx64 "\n", ull);
            if (jsp->pr_as_json)
                sgj_js_nv_ihex(jsp, jo2p, "sas_address", ull);
            ull = sg_get_unaligned_be64(vcp + 16);
            sgj_pr_hr(jsp, "    %s SAS address = 0x%" PRIx64 "\n", at, ull);
            if (jsp->pr_as_json)
                sgj_js_nv_ihex(jsp, jo2p, "attached_sas_address", ull);
            ccp = "attached phy identifier";
            sgj_haj_vi(jsp, jo2p, 4, ccp, SGJ_SEP_EQUAL_1_SPACE, vcp[24],
                       true);
            ccp = "Invalid DWORD count";
            ui = sg_get_unaligned_be32(vcp + 32);
            cc2p = "Running disparity error count";
            ui2 = sg_get_unaligned_be32(vcp + 36);
            cc3p = "Loss of DWORD synchronization count";
            ui3 = sg_get_unaligned_be32(vcp + 40);
            cc4p = "Phy reset problem count";
            ui4 = sg_get_unaligned_be32(vcp + 44);
            if (jsp->pr_as_json) {
                sgj_convert2snake(ccp, b, blen);
                sgj_js_nv_ihex(jsp, jo2p, b, ui);
                sgj_convert2snake(cc2p, b, blen);
                sgj_js_nv_ihex(jsp, jo2p, b, ui2);
                sgj_convert2snake(cc3p, b, blen);
                sgj_js_nv_ihex(jsp, jo2p, b, ui3);
                sgj_convert2snake(cc4p, b, blen);
                sgj_js_nv_ihex(jsp, jo2p, b, ui4);
            } else {
                if (0 == op->do_brief) {
                    sgj_pr_hr(jsp, "    %s = %u\n", ccp, ui);
                    sgj_pr_hr(jsp, "    %s = %u\n", cc2p, ui2);
                    sgj_pr_hr(jsp, "    %s = %u\n", cc3p, ui3);
                    sgj_pr_hr(jsp, "    %s = %u\n", cc4p, ui4);
                }
            }
        }
        if (op->do_brief > 0)
            goto skip;
        if (spld_len > 51) {
            int num_ped;
            const uint8_t * xcp;

            num_ped = vcp[51];
            if (op->verbose > 1)
                sgj_pr_hr(jsp, "    <<Phy event descriptors: %d, spld_len: "
                          "%d, calc_ped: %d>>\n", num_ped, spld_len,
                          (spld_len - 52) / 12);
            if (num_ped > 0) {
                if (op->do_name) {
                    sgj_pr_hr(jsp, "      phy_event_desc_num=%d\n", num_ped);
                    return;      /* don't decode at this stage */
                } else
                    sgj_pr_hr(jsp, "    Phy event descriptors:\n");
            }
            if (jsp->pr_as_json) {
                sgj_js_nv_i(jsp, jo2p, "number_of_phy_event_descriptors",
                            num_ped);
                if (num_ped > 0)
                    ja2p = sgj_named_subarray_r(jsp, jo2p,
                                                "phy_event_descriptor_list");
            }
            xcp = vcp + 52;
            for (m = 0; m < (num_ped * 12); m += 12, xcp += 12) {
                int pes = xcp[3];
                unsigned int pvdt_v;

                if (jsp->pr_as_json)
                    jo3p = sgj_new_unattached_object_r(jsp);
                ui = sg_get_unaligned_be32(xcp + 4);
                pvdt_v = sg_get_unaligned_be32(xcp + 8);
                ccp = show_sas_phy_event_info(pes, ui, pvdt_v, b, blen);
                if (0 == strlen(ccp)) {
                    sgj_pr_hr(jsp, "      %s\n", b);    /* unknown pvdt_v */
                    if (jsp->pr_as_json) {
                        int n;

                        snprintf(s, sz, "%s_pes_0x%x", unkn_s, pes);
                        sgj_js_nv_ihex(jsp, jo3p, s, ui);
                        n = strlen(s);
                        sg_scnpr(s + n, sz - n, "_%s", "threshold");
                        sgj_js_nv_ihex(jsp, jo3p, s, pvdt_v);
                    }
                } else {
                    if (jsp->pr_as_json) {
                        sgj_convert2snake(ccp, s, sz);
                        sgj_js_nv_ihex(jsp, jo3p, s, ui);
                        if (0x2b == pes)
                            sgj_js_nv_ihex(jsp, jo3p, pvdt, pvdt_v);
                        else if (0x2c == pes)
                            sgj_js_nv_ihex(jsp, jo3p, pvdt, pvdt_v);
                        else if (0x2d == pes)
                            sgj_js_nv_ihex(jsp, jo3p, pvdt, pvdt_v);
                        else if (0x2e == pes)
                            sgj_js_nv_ihex(jsp, jo3p, pvdt, pvdt_v);
                    } else {
                        cp = strchr(b, '\t');
                        if (cp) {
                            *cp = '\0';
                            sgj_pr_hr(jsp, "      %s\n", b);
                            sgj_pr_hr(jsp, "      %s\n", cp + 1);
                        } else
                            sgj_pr_hr(jsp, "      %s\n", b);
                    }
                }
                if (jsp->pr_as_json)
                    sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
            }
        } else if (op->verbose)
           printf("    <<No phy event descriptors>>\n");
skip:
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }   /* end of for loop over phys with this relative port */
}

/* PROTO_SPECIFIC_LPAGE [0x18] <psp> */
static bool
show_protocol_specific_port_page(const uint8_t * resp, int len,
                                 struct opts_t * op, sgj_opaque_p jop)
{
    int k, num, pl, pid;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const char * psplp = "Protocol specific port log page";
    static const char * fss = "for SAS SSP";

    num = len - 4;
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (op->do_name)
            sgj_pr_hr(jsp, "%s=0x%x\n", lp_sn, PROTO_SPECIFIC_LPAGE);
        else
            sgj_pr_hr(jsp, "%s  [0x18]\n", psplp);
    }
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, psplp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                           "protocol_specific_port_log_parameter_list");
    }

    for (k = 0, bp = resp + 4; k < num; ) {
        int pc = sg_get_unaligned_be16(bp + 0);

        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto skip;
        }
        pid = 0xf & bp[4];
        if (6 != pid) {
            pr2serr("%s: Protocol identifier: %d, only support SAS (SPL) "
                    "which is 6\n", __func__, pid);
            return false;   /* only decode SAS log page */
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        if ((0 == k) && (! op->do_name))
             sgj_pr_hr(jsp, "%s %s  [0x18]\n", psplp, fss);
        /* call helper */
        show_sas_port_param(bp, pl, op, jo3p);
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if ((op->do_pcb) && (! op->do_name))
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b,
                      sizeof(b)));
        if (op->filter_given)
            break;
skip:
        k += pl;
        bp += pl;
    }
    return true;
}

/* Returns true if processed page, false otherwise */
/* STATS_LPAGE [0x19], subpages: 0x0 to 0x1f <gsp,grsp>  introduced: SPC-4 */
static bool
show_stats_perform_pages(const uint8_t * resp, int len,
                         struct opts_t * op, sgj_opaque_p jop)
{
    bool nm = op->do_name;
    bool spf;
    enum sgj_separator_t sep = nm ? SGJ_SEP_EQUAL_NO_SPACE :
                                    SGJ_SEP_SPACE_EQUAL_SPACE;
    int k, num, param_len, param_code, subpg_code, extra;
    uint64_t ull;
    const uint8_t * bp;
    const char * ccp;
    const char * pg_name;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[144];
    static const int blen = sizeof(b);
    static const char * gsaplp =
                "General statistics and performance log page";
    static const char * gr_saplp =
                "Group statistics and performance log page";

    num = len - 4;
    bp = resp + 4;
    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : NOT_SPG_SUBPG;
    if (0 == subpg_code)
        pg_name = gsaplp;
    else if (subpg_code < 0x20)
        pg_name = gr_saplp;
    else
        pg_name = "Unknown subpage";
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (nm) {
             sgj_pr_hr(jsp, "%s=0x%x\n", lp_sn, STATS_LPAGE);
            if (subpg_code > 0)
                sgj_pr_hr(jsp, "log_subpage=0x%x\n", subpg_code);
        } else {
            if (0 == subpg_code)
                sgj_pr_hr(jsp, "%s  [0x19]\n", gsaplp);
            else if (subpg_code < 0x20)
                sgj_pr_hr(jsp, "%s (%d)  [0x19,0x%x]\n", gr_saplp, subpg_code,
                          subpg_code);
            else
                sgj_pr_hr(jsp, "%s: %d  [0x19,0x%x]\n", pg_name, subpg_code,
                          subpg_code);
        }
    }
    if (subpg_code > 31)
        return false;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, pg_name, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, 0 == subpg_code ?
                        "general_statistics_and_performance_log_parameters" :
                        "group_statistics_and_performance_log_parameters");
    }
    if (0 == subpg_code) { /* General statistics and performance log page */
        if (num < 0x5c)
            return false;
        for (k = num; k > 0; k -= extra, bp += extra) {
            unsigned int ui;

            if (k < 3)
                return false;
            param_len = bp[3];
            extra = param_len + 4;
            param_code = sg_get_unaligned_be16(bp + 0);
            if (op->filter_given) {
                if (param_code != op->filter)
                    continue;
            }
            if (op->do_raw) {
                dStrRaw(bp, extra);
                goto skip;
            } else if (op->do_hex) {
                hex2stdout(bp, extra, op->dstrhex_no_ascii);
                goto skip;
            }
            if (jsp->pr_as_json) {
                jo3p = sgj_new_unattached_object_r(jsp);
                if (op->do_pcb)
                    js_pcb(jsp, jo3p, bp[2]);
            }

            switch (param_code) {
            case 1:     /* Statistics and performance log parameter */
                ccp = nm ? "parameter_code=1" :
                           "General access statistics and performance";
                sgj_pr_hr(jsp, "  %s\n", ccp);
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, param_code, NULL,
                                  ccp);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nm ? "read_commands" : "number of read commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 12);
                ccp = nm ? "write_commands" : "number of write commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 20);
                ccp = nm ? "lb_received"
                         : "number of logical blocks received";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 28);
                ccp = nm ? "lb_transmitted"
                         : "number of logical blocks transmitted";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 36);
                ccp = nm ? "read_proc_intervals"
                         : "read command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 44);
                ccp = nm ? "write_proc_intervals"
                         : "write command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 52);
                ccp = nm ? "weighted_rw_commands" :
                    "weighted number of read commands plus write commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 60);
                ccp = nm ? "weighted_rw_processing" : "weighted read "
                        "command processing plus write command processing";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                break;
            case 2:     /* Idle time log parameter */
                ccp = nm ? "parameter_code=2" : "Idle time";
                sgj_pr_hr(jsp, "  %s\n", ccp);
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, param_code, NULL,
                                  ccp);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nm ? "idle_time_intervals" : "idle time intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                break;
            case 3:     /* Time interval log parameter for general stats */
                ccp = nm ? "parameter_code=3" : "Time interval";
                sgj_pr_hr(jsp, "  %s\n", ccp);
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, param_code, NULL,
                                  ccp);
                ui = sg_get_unaligned_be32(bp + 4);
                ccp = nm ? "time_interval_neg_exp" :
                            "time interval negative exponent";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ui, true);
                ui = sg_get_unaligned_be32(bp + 8);
                ccp = nm ? "time_interval_int" : "time interval integer";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ui, true);
                break;
            case 4:     /* FUA statistics and performance log parameter */
                ccp = nm ? "parameter_code=4" : "Force unit access "
                        "statistics and performance";
                sgj_pr_hr(jsp, "  %s\n", ccp);
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, param_code, NULL,
                                  ccp);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nm ? "read_fua_commands" :
                           "number of read FUA commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 12);
                ccp = nm ? "write_fua_commands" :
                           "number of write FUA commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 20);
                ccp = nm ? "read_fua_nv_commands"
                         : "number of read FUA_NV commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 28);
                ccp = nm ? "write_fua_nv_commands"
                         : "number of write FUA_NV commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 36);
                ccp = nm ? "read_fua_proc_intervals"
                         : "read FUA command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 44);
                ccp = nm ? "write_fua_proc_intervals"
                         : "write FUA command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 52);
                ccp = nm ? "read_fua_nv_proc_intervals"
                         : "read FUA_NV command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 60);
                ccp = nm ? "write_fua_nv_proc_intervals"
                         : "write FUA_NV command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                break;
            default:
                if (nm) {
                    sgj_pr_hr(jsp, "  parameter_code=%d\n", param_code);
                    sgj_pr_hr(jsp, "    unknown=1\n");
                } else
                    sgj_haj_vistr(jsp, jo3p, 2, param_c, sep, param_code,
                                  true, unkn_s);
                if (op->verbose)
                    hex2stderr(bp, extra, 1);
                break;
            }
            if (jsp->pr_as_json)
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
            if ((op->do_pcb) && (! nm))
                sgj_pr_hr(jsp, "    <%s>\n", get_pcb_str(bp[2], b, blen));
skip:
            if (op->filter_given)
                break;
        }
    } else {    /* Group statistics and performance (n) log page */
        if (num < 0x34)
            return false;
        for (k = num; k > 0; k -= extra, bp += extra) {
            if (k < 3)
                return false;
            param_len = bp[3];
            extra = param_len + 4;
            param_code = sg_get_unaligned_be16(bp + 0);
            if (op->filter_given) {
                if (param_code != op->filter)
                    continue;
            }
            if (op->do_raw) {
                dStrRaw(bp, extra);
                goto skip2;
            } else if (op->do_hex) {
                hex2stdout(bp, extra, op->dstrhex_no_ascii);
                goto skip2;
            }
            if (jsp->pr_as_json) {
                jo3p = sgj_new_unattached_object_r(jsp);
                if (op->do_pcb)
                    js_pcb(jsp, jo3p, bp[2]);
            }

            switch (param_code) {
            case 1:     /* Group n Statistics and performance log parameter */
                if (nm)
                    sgj_pr_hr(jsp, "  parameter_code=1\n");
                else {
                    snprintf(b, blen, "Group %d Statistics and performance",
                             subpg_code);
                    sgj_pr_hr(jsp, "  %s\n", b);
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, param_code,
                                      NULL, b);
                }
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nm ? "gn_read_commands" : "group n number of read "
                           "commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 12);
                ccp = nm ? "gn_write_commands" : "group n number of write "
                           "commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 20);
                ccp = nm ? "gn_lb_received"
                         : "group n number of logical blocks received";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 28);
                ccp = nm ? "gn_lb_transmitted"
                         : "group n number of logical blocks transmitted";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 36);
                ccp = nm ? "gn_read_proc_intervals"
                         : "group n read command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 44);
                ccp = nm ? "gn_write_proc_intervals"
                         : "group n write command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                break;
            case 4: /* Group n FUA statistics and performance log parameter */
                if (nm)
                    sgj_pr_hr(jsp, "  parameter_code=%d\n", param_code);
                else {
                    snprintf(b, blen, "Group %d force unit access "
                             "statistics and performance", subpg_code);
                    sgj_pr_hr(jsp, "  %s\n", b);
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, param_code,
                                      NULL, b);
                }
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nm ? "gn_read_fua_commands"
                         : "group n number of read FUA commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 12);
                ccp = nm ? "gn_write_fua_commands"
                         : "group n number of write FUA commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 20);
                ccp = nm ? "gn_read_fua_nv_commands"
                         : "group n number of read FUA_NV commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 28);
                ccp = nm ? "gn_write_fua_nv_commands"
                         : "group n number of write FUA_NV commands";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 36);
                ccp = nm ? "gn_read_fua_proc_intervals"
                         : "group n read FUA command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 44);
                ccp = nm ? "gn_write_fua_proc_intervals" : "group n write "
                           "FUA command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 52);
                ccp = nm ? "gn_read_fua_nv_proc_intervals" : "group n "
                           "read FUA_NV command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                ull = sg_get_unaligned_be64(bp + 60);
                ccp = nm ? "gn_write_fua_nv_proc_intervals" : "group n "
                           "write FUA_NV command processing intervals";
                sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
                break;
            default:
                if (nm) {
                    sgj_pr_hr(jsp, "  parameter_code=%d\n", param_code);
                    sgj_pr_hr(jsp, "    unknown=1\n");
                } else
                    sgj_haj_vistr(jsp, jo3p, 2, param_c, sep, param_code,
                                  true, unkn_s);
                if (op->verbose)
                    hex2stderr(bp, extra, 1);
                break;
            }
            if (jsp->pr_as_json)
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
            if ((op->do_pcb) && (! nm))
                sgj_pr_hr(jsp, "    <%s>\n", get_pcb_str(bp[2], b, blen));
skip2:
            if (op->filter_given)
                break;
        }
    }
    return true;
}

/* Returns true if processed page, false otherwise */
/* CACHE_STATS_SUBPG [0x19,0x20] <cms>  introduced: SPC-4 */
static bool
show_cache_stats_page(const uint8_t * resp, int len, struct opts_t * op,
                      sgj_opaque_p jop)
{
    bool nm = op->do_name;
    bool spf;
    enum sgj_separator_t sep = nm ? SGJ_SEP_EQUAL_NO_SPACE :
                                    SGJ_SEP_SPACE_EQUAL_SPACE;
    int k, num, subpg_code, extra;
    unsigned int ui;
    const uint8_t * bp;
    const char * ccp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    uint64_t ull;
    char b[144];
    static const int blen = sizeof(b);
    static const char * cmslp = "Cache memory statistics log page";

    num = len - 4;
    bp = resp + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, cmslp);
        return false;
    }
    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : NOT_SPG_SUBPG;
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (nm) {
            sgj_pr_hr(jsp, "%s=0x%x\n", lp_sn, STATS_LPAGE);
            if (subpg_code > 0)
                sgj_pr_hr(jsp, "log_subpage=0x%x\n", subpg_code);
        } else
            sgj_pr_hr(jsp, "%s  [0x19,0x20]\n", cmslp);
    }
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, cmslp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "cache_memory_statistics_log_parameters");
    }

    for (k = num; k > 0; k -= extra, bp += extra) {
        int pc;

        if (k < 3) {
            pr2serr("%s: short %s\n", __func__, cmslp);
            return false;
        }
        if (8 != bp[3]) {
            pr2serr("%s: %s parameter length not 8\n", __func__, cmslp);
            return false;
        }
        extra = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw) {
            dStrRaw(bp, extra);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            goto skip;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
            js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 1:     /* Read cache memory hits log parameter */
            ccp = nm ? "parameter_code=1" : "Read cache memory hits";
            sgj_pr_hr(jsp, "  %s\n", ccp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nm ? "read_cache_memory_hits" : "read cache memory hits";
            sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
            break;
        case 2:     /* Reads to cache memory log parameter */
            ccp = nm ? "parameter_code=2" : "Reads to cache memory";
            sgj_pr_hr(jsp, "  %s\n", ccp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nm ? "reads_to_cache_memory" : "reads to cache memory";
            sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
            break;
        case 3:     /* Write cache memory hits log parameter */
            ccp = nm ? "parameter_code=3" : "Write cache memory hits";
            sgj_pr_hr(jsp, "  %s\n", ccp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nm ? "write_cache_memory_hits" : "write cache memory hits";
            sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
            break;
        case 4:     /* Writes from cache memory log parameter */
            ccp = nm ? "parameter_code=4" : "Writes from cache memory";
            sgj_pr_hr(jsp, "  %s\n", ccp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nm ? "writes_from_cache_memory" :
                       "writes from cache memory";
            sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
            break;
        case 5:     /* Time from last hard reset log parameter */
            ccp = nm ? "parameter_code=5" : "Time from last hard reset";
            sgj_pr_hr(jsp, "  %s\n", ccp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nm ? "time_from_last_hard_reset" :
                       "time from last hard reset";
            sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ull, true);
            break;
        case 6:     /* Time interval log parameter for cache stats */
            ccp = nm ? "parameter_code=6" : "Time interval";
            sgj_pr_hr(jsp, "  %s\n", ccp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            ui = sg_get_unaligned_be32(bp + 4);
            ccp = nm ? "time_interval_neg_exp" :
                       "time interval negative exponent";
            sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ui, true);
            ui = sg_get_unaligned_be32(bp + 8);
            ccp = nm ? "time_interval_int" : "time interval integer";
            sgj_haj_vi(jsp, jo3p, 4, ccp, sep, ui, true);
            break;
        default:
            if (nm) {
                sgj_pr_hr(jsp, "  parameter_code=%d\n", pc);
                sgj_pr_hr(jsp, "    unknown=1\n");
            } else
                sgj_haj_vistr(jsp, jo3p, 2, param_c, sep, pc, true,
                              unkn_s);
            if (op->verbose)
                hex2stderr(bp, extra, 1);
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if ((op->do_pcb) && (! nm))
            sgj_pr_hr(jsp, "    <%s>\n", get_pcb_str(bp[2], b, blen));
skip:
        if (op->filter_given)
            break;
    }
    return true;
}

/* FORMAT_STATUS_LPAGE [0x8] <fs>  introduced: SBC-2 */
static bool
show_format_status_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    bool is_count, is_not_avail;
    int k, num, pl, pc;
    uint64_t ull;
    const char * cp = "";
    const uint8_t * bp;
    const uint8_t * xp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * fslp = "Format status log page";
    static const char * fso = "Format status out";
    static const char * fso_sn = "format_status_out";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x8]\n", fslp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, fslp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "format_status_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        is_count = true;

        switch (pc) {
        case 0:
            is_not_avail = false;
            if (pl < 5)
                sgj_pr_hr(jsp, "  %s: <empty>\n", fso);
            else {
                if (sg_all_ffs(bp + 4, pl - 4)) {
                    sgj_pr_hr(jsp, "  %s: <%s>\n", fso, not_avail);
                    is_not_avail = true;
                } else {
                    hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat,
                            blen, b);
                    sgj_pr_hr(jsp, "  %s:\n%s", fso, b);


                }
            }
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, fso);
                if (is_not_avail)
                    sgj_js_nv_ihexstr(jsp, jo3p, fso_sn, 0, NULL, not_avail);
                else
                    sgj_js_nv_hex_bytes(jsp, jo3p,  fso_sn, bp + 4, pl - 4);
            }
            is_count = false;
            break;
        case 1:
            cp = "Grown defects during certification";
            break;
        case 2:
            cp = "Total blocks reassigned during format";
            break;
        case 3:
            cp = "Total new blocks reassigned";
            break;
        case 4:
            cp = "Power on minutes since format";
            break;
        default:
            sgj_pr_hr(jsp, "  Unknown Format %s = 0x%x\n", param_c, pc);
            is_count = false;
            hex2fp(bp, pl, "    ", op->h2s_oformat, stdout);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, unkn_s);
                sgj_js_nv_hex_bytes(jsp, jo3p,  in_hex, bp, pl);
            }
            break;
        }
        if (is_count) {
            k = pl - 4;
            xp = bp + 4;
            is_not_avail = false;
            ull = 0;
            if (sg_all_ffs(xp, k)) {
                sgj_pr_hr(jsp, "  %s: <%s>\n", cp, not_avail);
                is_not_avail = true;
            } else {
                if (k > (int)sizeof(ull)) {
                    xp += (k - sizeof(ull));
                    k = sizeof(ull);
                }
                ull = sg_get_unaligned_be(k, xp);
                sgj_pr_hr(jsp, "  %s = %" PRIu64 "\n", cp, ull);
            }
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, cp);
                sgj_convert2snake(cp, b, blen);
                if (is_not_avail)
                    sgj_js_nv_ihexstr(jsp, jo3p, b, 0, NULL, not_avail);
                else
                    sgj_js_nv_ihex(jsp, jo3p, b, ull);
            }
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if ((op->do_pcb) && (! op->do_name))
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Non-volatile cache page [0x17] <nvc>  introduced: SBC-2
 * Standard vacillates between "non-volatile" and "nonvolatile" */
static bool
show_non_volatile_cache_page(const uint8_t * resp, int len,
                             struct opts_t * op, sgj_opaque_p jop)
{
    int j, num, pl, pc;
    const char * cp;
    const char * c2p;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * nvclp = "Non-volatile cache log page";
    static const char * ziinv = "0 (i.e. it is now volatile)";
    static const char * indef = "indefinite";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
         sgj_pr_hr(jsp, "%s  [0x17]\n", nvclp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, nvclp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "nonvolatile_cache_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        cp = NULL;
        switch (pc) {
        case 0:
            cp = "Remaining nonvolatile time";
            c2p = NULL;
            j = sg_get_unaligned_be24(bp + 5);
            switch (j) {
            case 0:
                c2p = ziinv;
                sgj_pr_hr(jsp, "  %s: %s\n", cp, c2p);
                break;
            case 1:
                c2p = unkn_s;
                sgj_pr_hr(jsp, "  %s: <%s>\n", cp, c2p);
                break;
            case 0xffffff:
                c2p = indef;
                sgj_pr_hr(jsp, "  %s: <%s>\n", cp, c2p);
                break;
            default:
                snprintf(b, sizeof(b), "%d minutes [%d:%d]", j, (j / 60),
                         (j % 60));
                c2p = b;
                sgj_pr_hr(jsp, "  %s: %s\n", cp, c2p);
                break;
            }
            break;
        case 1:
            cp = "Maximum non-volatile time";
            c2p = NULL;
            j = sg_get_unaligned_be24(bp + 5);
            switch (j) {
            case 0:
                c2p = ziinv;
                sgj_pr_hr(jsp, "  %s: %s\n", cp, c2p);
                break;
            case 1:
                c2p = rsv_s;
                sgj_pr_hr(jsp, "  %s: <%s>\n", cp, c2p);
                break;
            case 0xffffff:
                c2p = indef;
                sgj_pr_hr(jsp, "  %s: <%s>\n", cp, c2p);
                break;
            default:
                snprintf(b, sizeof(b), "%d minutes [%d:%d]", j, (j / 60),
                         (j % 60));
                c2p = b;
                sgj_pr_hr(jsp, "  %s: %s\n", cp, c2p);
                break;
            }
            break;
        default:
            sgj_pr_hr(jsp, "  Unknown %s = 0x%x\n", param_c, pc);
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                              cp ? cp : unkn_s);
            if (cp)
                js_snakenv_ihexstr_nex(jsp, jo3p, cp , j, true,
                                       NULL, c2p, NULL);
            else if (pl > 4)
                sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, pl - 4);

            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
        if ((op->do_pcb) && (! op->do_name))
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* LB_PROV_LPAGE [0xc] <lbp> introduced: SBC-3 */
static bool
show_lb_provisioning_page(const uint8_t * resp, int len,
                          struct opts_t * op, sgj_opaque_p jop)
{
    bool evsm_output = false;
    int num, pl, pc;
    unsigned int ui;
    const uint8_t * bp;
    const char * cp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * lbplp = "Logical block provisioning log page";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
         sgj_pr_hr(jsp, "%s  [0xc]\n", lbplp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, lbplp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                           "logical_block_provisioning_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x1:
            cp = "Available LBA mapping";
            break;
        case 0x2:
            cp = "Used LBA mapping";
            break;
        case 0x3:
            cp = "Available provisioning";
            break;
        case 0x100:
            cp = "De-duplicated LBA";
            break;
        case 0x101:
            cp = "Compressed LBA";
            break;
        case 0x102:
            cp = "Total efficiency LBA";
            break;
        default:
            cp = NULL;
            break;
        }
        if (cp) {
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("%s: truncated by response length, expected at "
                            "least 8 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 8 expected, got %d\n",
                            __func__, pl);
                break;
            }
            if (0x3 == pc) {    /* resource percentage log parameter */
                ui = sg_get_unaligned_be16(bp + 4);
                snprintf(b, blen, "%s resource percentage", cp);
                printf("  %s: %u %%\n", cp, sg_get_unaligned_be16(bp + 4));
            } else {            /* resource count log parameters */
                ui = sg_get_unaligned_be32(bp + 4);
                snprintf(b, blen, "%s resource count", cp);
                printf("  %s resource count: %u\n", cp,
                       sg_get_unaligned_be32(bp + 4));
            }
            sgj_pr_hr(jsp, "  %s: %u\n", cp, ui);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, b);
                sgj_js_nv_ihex(jsp, jo3p, "resource_count", ui);
            }
            if (pl > 8) {
                ui = bp[8] & 0x3;
                switch (ui) {      /* SCOPE field */
                case 0: cp = not_rep; break;
                case 1: cp = "dedicated to lu"; break;
                case 2: cp = "not dedicated to lu"; break;
                case 3: cp = rsv_s; break;
                }
                sgj_pr_hr(jsp, "    Scope: %s\n", cp);
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, "scope", ui, NULL, cp);
            }
        } else if ((pc >= 0xfff0) && (pc <= 0xffff)) {
            if (op->exclude_vendor) {
                if ((op->verbose > 0) && (0 == op->do_brief) &&
                    (! evsm_output)) {
                    evsm_output = true;
                    sgj_pr_hr(jsp, "  %s parameter(s) being ignored\n",
                              vend_spec);
                }
            } else {
                sgj_pr_hr(jsp, "  %s [0x%x]:", vend_spec, pc);
                hex2stdout(bp, ((pl < num) ? pl : num), op->dstrhex_no_ascii);
            }
        } else {
            sgj_pr_hr(jsp, "  Reserved [%s=0x%x]:\n", param_c_sn, pc);
            hex2stdout(bp, ((pl < num) ? pl : num), op->dstrhex_no_ascii);
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if ((op->do_pcb) && (! op->do_name))
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* UTILIZATION_SUBPG [0xe,0x1] <util>  introduced: SBC-4 */
static bool
show_utilization_page(const uint8_t * resp, int len, struct opts_t * op,
                      sgj_opaque_p jop)
{
    int num, pl, pc;
    unsigned int k;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[144];
    static const int blen = sizeof(b);
    static const char * ulp = "Utilization log page";
    static const char * wu_s = "Workload utilization";
    static const char * uurbodat =
                        "Utilization usage rate based on date and time";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0xe,0x1]\n", ulp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, ulp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "utilitization_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x0:
            if ((pl < 6) || (num < 6)) {
                if (num < 6)
                    pr2serr("%s: truncated by response length, expected "
                            "at least 6 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 6 expected, got %d\n",
                            __func__, pl);
                break;
            }
            k = sg_get_unaligned_be16(bp + 4);
            snprintf(b, blen, "%d.%02d %%", k / 100, k % 100);
            sgj_pr_hr(jsp, "  %s: %s\n", wu_s, b);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, wu_s);
                sgj_convert2snake(wu_s, b, blen);
                sgj_js_nv_ihexstr_nex(jsp, jo3p, b, k, true, NULL, NULL,
                              "1 --> 0.01%, 65535 --> 655.35% or more");
            }
            break;
        case 0x1:
            if ((pl < 6) || (num < 6)) {
                if (num < 6)
                    pr2serr("%s: truncated by response length, expected "
                            "at least 6 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 6 expected, got %d\n",
                            __func__, pl);
                break;
            }
            k = bp[4];
            sgj_pr_hr(jsp, "  %s: %d %%\n", uurbodat, k);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, uurbodat);
                sgj_convert2snake(wu_s, b, blen);
                sgj_js_nv_ihexstr_nex(jsp, jo3p, b, k, true, NULL, NULL,
                                      "1 --> 1%, 255 --> 255% or more");
            }
            break;
        default:
            sgj_pr_hr(jsp, "  Reserved [parameter_code=0x%x]:\n", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if ((op->do_pcb) && (! op->do_name))
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* SOLID_STATE_MEDIA_LPAGE [0x11] <ssm>  introduced: SBC-3 */
static bool
show_solid_state_media_page(const uint8_t * resp, int len,
                            struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * ssmlp = "Solid state media log page";
    static const char * puei = "Percentage used endurance indicator";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x11]\n", ssmlp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, ssmlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "solid_state_media_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x1:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("%s: truncated by response length, expected "
                            "at least 8 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 8 expected, got %d\n",
                            __func__, pl);
                break;
            }
            sgj_pr_hr(jsp, "  %s: %u %%\n", puei, bp[7]);
            if (jsp->pr_as_json) {
                js_snakenv_ihexstr_nex(jsp, jo3p, param_c, pc, true,
                                       NULL, puei, NULL);
                js_snakenv_ihexstr_nex(jsp, jo3p, puei, bp[7], false,
                                       NULL, NULL, NULL);
            }
            break;
        default:
            sgj_pr_hr(jsp, "  Reserved [parameter_code=0x%x]:\n", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

static const char * dt_dev_activity[] = {
    "No DT device activity",
    "Cleaning operation in progress",
    "Volume is being loaded",
    "Volume is being unloaded",
    "Other medium activity",
    "Reading from medium",
    "Writing to medium",
    "Locating medium",
    "Rewinding medium", /* 8 */
    "Erasing volume",
    "Formatting volume",
    "Calibrating",
    "Other DT device activity",
    "Microcode update in progress",
    "Reading encrypted from medium",
    "Writing encrypted to medium",
    "Diagnostic operation in progress", /* 10 */
};

/* DT device status [0x11] <dtds> (ssc, adc) */
static bool
show_dt_device_status_page(const uint8_t * resp, int len,
                           struct opts_t * op, sgj_opaque_p jop)
{
    bool evsm_output = false;
    uint16_t u;
    int num, pl, pc, j, n;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * dds_lp = "DT device status log page";
    static const char * vhfd = "Very high frequency data";
    static const char * vhfpd = "Very high frequency polling delay";
    static const char * ddadecs =
                        "DT device ADC data encryption control status";
    static const char * kmed = "Key management error data";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s (ssc-3, adc-3) [0x11]\n", dds_lp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, dds_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "dt_device_status_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x0:
            sgj_pr_hr(jsp, "  %s:\n", vhfd);
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("%s: truncated by response length, expected at "
                            "least 8 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 8 expected, got %d\n",
                            __func__, pl);
                break;
            }
            snprintf(b, blen, "  PAMR=%d HUI=%d MACC=%d CMPR=%d ",
                     !!(0x80 & bp[4]), !!(0x40 & bp[4]), !!(0x20 & bp[4]),
                     !!(0x10 & bp[4]));
            sgj_pr_hr(jsp, "%sWRTP=%d CRQST=%d CRQRD=%d DINIT=%d\n", b,
                      !!(0x8 & bp[4]), !!(0x4 & bp[4]), !!(0x2 & bp[4]),
                      !!(0x1 & bp[4]));
            snprintf(b, blen, "  INXTN=%d RAA=%d MPRSNT=%d ",
                     !!(0x80 & bp[5]), !!(0x20 & bp[5]), !!(0x10 & bp[5]));
            sgj_pr_hr(jsp, "%sMSTD=%d MTHRD=%d MOUNTED=%d\n", b,
                      !!(0x4 & bp[5]), !!(0x2 & bp[5]), !!(0x1 & bp[5]));
            snprintf(b, blen, "  DT device activity: ");
            j = bp[6];
            if (j < (int)SG_ARRAY_SIZE(dt_dev_activity)) {
                sgj_pr_hr(jsp, "%s%s\n", b, dt_dev_activity[j]);
                ccp = NULL;
            } else if (j < 0x80) {
                sgj_pr_hr(jsp, "%s%s [0x%x]\n", b, rsv_s, j);
                ccp = rsv_s;
            } else {
                sgj_pr_hr(jsp, "%s%s [0x%x]\n", b, vend_spec, j);
                ccp = vend_spec;
            }
            snprintf(b, blen, "  VS=%d TDDEC=%d EPP=%d ", !!(0x80 & bp[7]),
                     !!(0x20 & bp[7]), !!(0x10 & bp[7]));
            sgj_pr_hr(jsp, "%sESR=%d RRQST=%d INTFC=%d TAFC=%d\n", b,
                      !!(0x8 & bp[7]), !!(0x4 & bp[7]), !!(0x2 & bp[7]),
                      !!(0x1 & bp[7]));
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, vhfd);
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "pamr", !!(0x80 & bp[4]),
                                      false, NULL, NULL,
                                      "Prevent/Allow Medium Removal");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "hui", !!(0x40 & bp[4]),
                                      false, NULL, NULL,
                                      "Host Initiated Unload");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "macc", !!(0x20 & bp[4]),
                                      false, NULL, NULL,
                                      "Medium Auxiliary memory aCCessible");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "cmpr", !!(0x10 & bp[4]),
                                      false, NULL, NULL, "CoMPRess");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "wrtp", !!(0x8 & bp[4]),
                                      false, NULL, NULL, "WRiTe Protect");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "crqst", !!(0x4 & bp[4]),
                                      false, NULL, NULL,
                                      "Cleaning ReQueSTed");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "crqrd", !!(0x2 & bp[4]),
                                      false, NULL, NULL,
                                      "Cleaning ReQuiReD");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "dinit", !!(0x1 & bp[4]),
                                      false, NULL, NULL,
                                      "dt Device INITialized");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "inxtn", !!(0x80 & bp[5]),
                                      false, NULL, NULL, "IN TraNsition");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "raa", !!(0x20 & bp[5]),
                                      false, NULL, NULL,
                                      "Robotic Access Allowed");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "mprsnt", !!(0x10 & bp[5]),
                                      false, NULL, NULL, "Medium PReSeNT");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "mstd", !!(0x4 & bp[5]),
                                      false, NULL, NULL, "Medium SeaTeD");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "mthrd", !!(0x2 & bp[5]),
                                      false, NULL, NULL, "Medium THReaDed");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "mounted", !!(0x1 & bp[5]),
                                      false, NULL, NULL, NULL);
                sgj_js_nv_ihexstr(jsp, jo3p, "dt_device_activity", j, NULL,
                                  ccp);
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "vs", !!(0x80 & bp[7]),
                                      false, NULL, NULL, vend_spec);
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "tddec", !!(0x20 & bp[7]),
                                      false, NULL, NULL,
                                      "Tape Diagnostic Data Entry Created");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "epp", !!(0x10 & bp[7]),
                                      false, NULL, NULL,
                                      "Encryption Parameters Present");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "esr", !!(0x8 & bp[7]),
                                      false, NULL, NULL,
                                      "Encryption Service Requested");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "rrqst", !!(0x4 & bp[7]),
                                      false, NULL, NULL, "Recovery ReQueSTed");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "intfc", !!(0x2 & bp[7]),
                                      false, NULL, NULL, "INTerFace Changed");
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "tafc", !!(0x1 & bp[7]),
                                      false, NULL, NULL,
                                      "TapeAlert state Flag Changed");
            }
            break;
        case 0x1:
            snprintf(b, blen, "  %s: ", vhfpd);
            if ((pl < 6) || (num < 6)) {
                sgj_pr_hr(jsp, "%s\n", b);
                if (num < 6)
                    pr2serr("%s: truncated by response length, expected at "
                            "least 6 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 6 expected, got %d\n",
                            __func__, pl);
                break;
            }
            u = sg_get_unaligned_be16(bp + 4);
            sgj_pr_hr(jsp, "%s %d milliseconds\n", b, u);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, vhfpd);
                sgj_js_nv_ihexstr_nex(jsp, jo3p, "vhf_polling_delay", u,
                                      true, NULL, NULL,
                                      "[unit: millisecond]");
            }
            break;
        case 0x2:
            sgj_pr_hr(jsp, "   %s (hex only now):\n", ddadecs);
            if ((pl < 12) || (num < 12)) {
                if (num < 12)
                    pr2serr("%s: truncated by response length, expected at "
                            "least 12 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 12 expected, got %d\n",
                            __func__, pl);
                break;
            }
            hex2str(bp + 4, 8, "      ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ddadecs);
                sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, 8);
            }
            break;
        case 0x3:
            sgj_pr_hr(jsp, "   %s (hex only now):\n", kmed);
            if ((pl < 16) || (num < 16)) {
                if (num < 16)
                    pr2serr("%s: truncated by response length, expected at "
                            "least 16 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 16 expected, got %d\n",
                            __func__, pl);
                break;
            }
            hex2str(bp + 4, 12, "      ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, kmed);
                sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, 12);
            }
            break;
        default:
            if ((pc >= 0x101) && (pc <= 0x1ff)) {
                sgj_pr_hr(jsp, "  Primary port %d status:\n", pc - 0x100);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      "DT device primary port status");
                    sgj_js_nv_ihex(jsp, jo3p, "primary_port_index",
                                   pc - 0x100);
                }
                if (12 == bp[3]) { /* if length of desc is 12, assume SAS */
                    int signal = !!(0x2 & bp[4]);
                    int pic = !!(0x1 & bp[4]);
                    uint32_t b32;
                    uint64_t b64;

                    u = (0xf & (bp[4] >> 4));
                    ccp = sas_negot_link_rate(u, b, blen);
                    b32 = sg_get_unaligned_be24(bp + 5);
                    b64 = sg_get_unaligned_be64(bp + 8);
                    sgj_pr_hr(jsp, "    SAS: negotiated physical link rate: "
                               "%s\n", ccp);
                    snprintf(b, blen, "    signal=%d, pic=%d, ", signal, pic);
                    sgj_pr_hr(jsp, "%shashed SAS addr: 0x%u\n", b, b32);
                    sgj_pr_hr(jsp, "    SAS addr: 0x%" PRIx64 "\n", b64);
                    if (jsp->pr_as_json) {
                        sgj_js_nv_ihexstr(jsp, jo3p,
                                         "negotiated_physical_link_rate", u,
                                         NULL, ccp);
                        sgj_js_nv_ihexstr_nex(jsp, jo3p, "signal", signal,
                                              false, NULL, NULL,
                                              "at least 1 phy detected");
                        sgj_js_nv_ihexstr_nex(jsp, jo3p, "pic", pic, false,
                                              NULL, NULL,
                                              "port initialization complete");
                        sgj_js_nv_ihex(jsp, jo3p, "hashed_sas_address", b32);
                        sgj_js_nv_ihex(jsp, jo3p, "sas_address", b64);
                    }

                } else {
                    sgj_pr_hr(jsp, "    non-SAS transport, in hex:\n");
                    n = ((pl < num) ? pl : num) - 4;
                    hex2str(bp + 4, n, "      ", op->h2s_oformat, blen, b);
                    sgj_pr_hr(jsp, "%s\n", b);
                    if (jsp->pr_as_json)
                        sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, n);
                }
            } else if (pc >= 0x8000) {
                if (op->exclude_vendor) {
                    if ((op->verbose > 0) && (0 == op->do_brief) &&
                        (! evsm_output)) {
                        evsm_output = true;
                        sgj_pr_hr(jsp, "  %s parameter(s) being ignored\n",
                                  vend_spec);
                    }
                } else {
                    sgj_pr_hr(jsp, "  %s [%s=0x%x]:\n", vend_spec,
                              param_c_sn, pc);
                    n = ((pl < num) ? pl : num) - 4;
                    hex2str(bp + 4, n, "      ", op->h2s_oformat, blen, b);
                    sgj_pr_hr(jsp, "%s\n", b);
                    if (jsp->pr_as_json) {
                        sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                          vend_spec);
                        sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, n);
                    }
                }
            } else {
                sgj_pr_hr(jsp, "  Reserved [%s=0x%x]:\n", param_c_sn, pc);
                n = ((pl < num) ? pl : num) - 4;
                hex2str(bp + 4, n, "      ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, rsv_s);
                    sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, n);
                }
            }
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* TapeAlert response [0x12] <tar> (adc,ssc) */
static bool
show_tapealert_response_page(const uint8_t * resp, int len,
                             struct opts_t * op, sgj_opaque_p jop)
{
    bool evsm_output = false;
    int num, pl, pc, k, n, v, mod, div;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    char e[64];
    static const int blen = sizeof(b);
    static const int elen = sizeof(e);
    static const char * tar_lp = "TapeAlert response log page";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s (adc-3, ssc-3) [0x12]\n", tar_lp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, tar_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "tapealert_response_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                              "TapeAlert flags");
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        switch (pc) {
        case 0x0:
            if (pl < 12) {
                pr2serr("%s: parameter_code=0x%x descriptor too short\n",
                        __func__, pc);
                break;
            }
            b[0] = '\0';
            for (k = 1, n = 0; k < 0x41; ++k) {
                mod = ((k - 1) % 8);
                div = (k - 1) / 8;
                v = !! (bp[4 + div] & (1 << (7 - mod)));
                if (0 == mod) {
                    if (div > 0)
                        sgj_pr_hr(jsp, "%s\n", b);
                    n = sg_scnpr(b, blen, "  Flag%02Xh: %d", k, v);
                } else
                    n += sg_scnpr(b + n, blen - n, "  %02Xh: %d", k, v);
                if (jsp->pr_as_json) {
                    snprintf(e, elen, "flag%02x", k);
                    sgj_js_nv_ihex(jsp, jo3p, e, v);
                }
            }
            sgj_pr_hr(jsp, "%s\n", b);
            break;
        default:
            if (pc <= 0x8000) {
                sgj_pr_hr(jsp, "  Reserved [parameter_code=0x%x]:\n", pc);
                hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
            } else {
                if (op->exclude_vendor) {
                    if ((op->verbose > 0) && (0 == op->do_brief) &&
                        (! evsm_output)) {
                        evsm_output = true;
                        sgj_pr_hr(jsp, "  %s parameter(s) being ignored\n",
                                  vend_spec);
                    }
                } else {
                    sgj_pr_hr(jsp, "  %s [%s=0x%x]:\n", vend_spec, param_c_sn,
                              pc);
                    hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen,
                            b);
                    sgj_pr_hr(jsp, "%s\n", b);
                }
            }
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                  (pc <= 0x8000) ? rsv_s : vend_spec);
                sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, pl - 4);
            }
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if ((op->do_pcb) && (! op->do_name))
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

#define NUM_REQ_REC_ARR_ELEMS 16
static const char * req_rec_arr[NUM_REQ_REC_ARR_ELEMS] = {
    "Recovery not requested",
    "Recovery requested, no recovery procedure defined",
    "Instruct operator to push volume",
    "Instruct operator to remove and re-insert volume",
    "Issue UNLOAD command. Instruct operator to remove and re-insert volume",
    "Instruct operator to power cycle target device",
    "Issue LOAD command",
    "Issue UNLOAD command",
    "Issue LOGICAL UNIT RESET task management function",        /* 0x8 */
    "No recovery procedure defined. Contact service organization",
    "Issue UNLOAD command. Instruct operator to remove and quarantine "
        "volume",
    "Instruct operator to not insert a volume. Contact service organization",
    "Issue UNLOAD command. Instruct operator to remove volume. Contact "
        "service organization",
    "Request creation of target device error log",
    "Retrieve a target device error log",
    "Modify configuration to all microcode update and instruct operator to "
        "re-insert volume",     /* 0xf */
};

/* REQ_RECOVERY_LPAGE Requested recovery [0x13] <rr> (ssc) */
static bool
show_requested_recovery_page(const uint8_t * resp, int len,
                             struct opts_t * op, sgj_opaque_p jop)
{
    bool evsm_output = false;
    int num, pl, pc, j, k, n;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jo4p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * rr_lp = "Requested recovery log page";
    static const char * rp_s = "Recovery procedures";
    static const char * rp_sn = "recovery_procedure";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s (ssc-3) [0x13]\n", rr_lp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, rr_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "requested_recovery_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x0:
            sgj_pr_hr(jsp, "  %s:\n", rp_s);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, rp_s);
                ja2p = sgj_named_subarray_r(jsp, jo3p,
                                            "recovery_procedures_list");
            }
            for (k = 4; k < pl; ++ k) {
                j = bp[k];
                if (jsp->pr_as_json)
                    jo4p = sgj_new_unattached_object_r(jsp);
                ccp = NULL;
                if (j < NUM_REQ_REC_ARR_ELEMS)
                    ccp = req_rec_arr[j];
                else if (j < 0x80)
                    sgj_pr_hr(jsp, "    %s [0x%x]\n", rsv_s, j);
                else
                    sgj_pr_hr(jsp, "    %s [0x%x]\n", vend_spec, j);
                if (ccp) {
                    sgj_pr_hr(jsp, "    %s\n", ccp);
                    if (jsp->pr_as_json)
                        sgj_js_nv_ihexstr(jsp, jo4p, rp_sn, j, NULL, ccp);
                } else if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo4p, rp_sn, j, NULL,
                                      (j < 0x80) ? rsv_s : vend_spec);
                if (jsp->pr_as_json)
                    sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo4p);
            }
            break;
        default:
            n = pl - 4;
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                  (pc <= 0x8000) ? rsv_s : vend_spec);
            if (pc <= 0x8000) {
                sgj_pr_hr(jsp, "  %s [%s=0x%x]:\n", rsv_s, param_c_sn, pc);
                hex2str(bp + 4, n, "    ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
                if (jsp->pr_as_json)
                    sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, n);
            } else {
                if (op->exclude_vendor) {
                    if ((op->verbose > 0) && (0 == op->do_brief) &&
                        (! evsm_output)) {
                        evsm_output = true;
                        sgj_pr_hr(jsp, "  %s parameter(s) being ignored\n",
                                  vend_spec);
                    }
                } else {
                    sgj_pr_hr(jsp, "  %s [%s=0x%x]:\n", param_c_sn,
                              vend_spec, pc);
                    hex2str(bp + 4, n, "    ", op->h2s_oformat, blen, b);
                    sgj_pr_hr(jsp, "%s\n", b);
                    if (jsp->pr_as_json)
                        sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, n);
                }
            }
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if ((op->do_pcb) && (! op->do_name))
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* SAT_ATA_RESULTS_LPAGE (SAT-2) [0x16] <aptr> */
static bool
show_ata_pt_results_page(const uint8_t * resp, int len,
                         struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    uint64_t lba;
    const uint8_t * bp;
    const uint8_t * dp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * aptrlp = "ATA pass-through results log page";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x16]\n", aptrlp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, aptrlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "ata_pass_through_results_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihex(jsp, jo3p, param_c_sn, pc);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        if ((pc < 0xf) && (pl > 17)) {
            int extend, count;

            sgj_pr_hr(jsp, "  Log_index=0x%x (parameter_code=0x%x)\n",
                      pc + 1, pc);
            dp = bp + 4;       /* dp is start of ATA Return descriptor
                                 * which is 14 bytes long */
            extend = dp[2] & 1;
            count = dp[5] + (extend ? (dp[4] << 8) : 0);
            sgj_pr_hr(jsp, "    extend=%d  error=0x%x count=0x%x\n", extend,
                      dp[3], count);
            if (extend) {
                lba = dp[10];
                lba <<= dp[8];
                lba <<= dp[6];
                lba <<= dp[11];
                lba <<= dp[9];
                lba <<= dp[7];
                sgj_pr_hr(jsp, "    lba=0x%" PRIx64 "\n", lba);
            } else {
                lba = dp[11];
                lba <<= dp[9];
                lba <<= dp[7];
                sgj_pr_hr(jsp, "    lba=0x%" PRIx64 "\n", lba);
            }
            sgj_pr_hr(jsp, "    device=0x%x  status=0x%x\n", dp[12], dp[13]);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihex(jsp, jo3p, "extend", extend);
                sgj_js_nv_ihex(jsp, jo3p, "error", dp[3]);
                sgj_js_nv_ihex(jsp, jo3p, "count", count);
                sgj_js_nv_ihex(jsp, jo3p, "lba", lba);
                sgj_js_nv_ihex(jsp, jo3p, "device", dp[12]);
                sgj_js_nv_ihex(jsp, jo3p, "status", dp[13]);
            }
        } else if (pl > 17) {
            sgj_pr_hr(jsp, "  Reserved [parameter_code=0x%x]:\n", pc);
            hex2fp(bp, ((pl < num) ? pl : num), "    ",
                   op->h2s_oformat, stdout);
        } else {
            pr2serr("%s: short parameter length: %d [parameter_code=0x%x]:\n",
                    __func__, pl, pc);
            hex2fp(bp, ((pl < num) ? pl : num), "    ",
                   op->h2s_oformat, stderr);
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if ((op->do_pcb) && (! op->do_name))
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

static const char * bms_status[] = {
    "no background scans active",
    "background medium scan is active",
    "background pre-scan is active",
    "background scan halted due to fatal error",
    "background scan halted due to a vendor specific pattern of error",
    "background scan halted due to medium formatted without P-List",
    "background scan halted - vendor specific cause",
    "background scan halted due to temperature out of range",
    ("background scan enabled, none active (waiting for BMS interval timer "
        "to expire)"),  /* clang warns about this, add parens to quieten */
    "background scan halted - scan results list full",
    "background scan halted - pre-scan time limit timer expired" /* 10 */,
};

static const char * reassign_status[] = {
    "Reserved [0x0]",
    "Reassignment pending receipt of Reassign or Write command",
    "Logical block successfully reassigned by device server",
    "Reserved [0x3]",
    "Reassignment by device server failed",
    "Logical block recovered by device server via rewrite",
    "Logical block reassigned by application client, has valid data",
    "Logical block reassigned by application client, contains no valid data",
    "Logical block unsuccessfully reassigned by application client", /* 8 */
};

/* Background scan results [0x15,0] <bsr> for disk  introduced: SBC-3 */
static bool
show_background_scan_results_page(const uint8_t * resp, int len,
                                  struct opts_t * op, sgj_opaque_p jop)
{
    bool skip_out = false;
    bool evsm_output = false;
    bool ok;
    int j, m, n, num, pl, pc;
    double d;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[144];
    char e[80];
    static const int blen = sizeof(b);
    static const int elen = sizeof(e);
    static const char * bsrlp = "Background scan results log page";
    static const char * bss = "Background scan status";
    static const char * bms = "Background medium scan";
    static const char * bsr = "Background scan results";
    static const char * bs = "background scan";
    static const char * ms = "Medium scan";
    static const char * apom = "Accumulated power on minutes";
    static const char * rs = "Reassign status";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x15]\n", bsrlp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, bsrlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "background_scan_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0:
            sgj_pr_hr(jsp, "  Status parameters:\n");
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, bss);
            if ((pl < 16) || (num < 16)) {
                if (num < 16)
                    pr2serr("%s: truncated by response length, expected at "
                            "least 16 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 16 expected, got %d\n",
                            __func__, pl);
                break;
            }
            sg_scnpr(b, blen, "    %s: ", apom);
            j = sg_get_unaligned_be32(bp + 4);
            sgj_pr_hr(jsp, "%s%d [h:m  %d:%d]\n", b, j, (j / 60), (j % 60));
            if (jsp->pr_as_json)
                js_snakenv_ihexstr_nex(jsp, jo3p, apom, j, false, NULL, NULL,
                                       NULL);
            sg_scnpr(b, blen, "    Status: ");
            j = bp[9];
            ok = (j < (int)SG_ARRAY_SIZE(bms_status));
            if (ok)
                sgj_pr_hr(jsp, "%s%s\n", b, bms_status[j]);
            else
                sgj_pr_hr(jsp, "%sunknown [0x%x] %s value\n", b, j, bss);
            if (jsp->pr_as_json)
                js_snakenv_ihexstr_nex(jsp, jo3p, bss, j, true, NULL,
                                       ok ? bms_status[j] : unkn_s, NULL);
            j = sg_get_unaligned_be16(bp + 10);
            snprintf(b, blen, "Number of %ss performed", bs);
            sgj_pr_hr(jsp, "    %s: %d\n", b, j);
            if (jsp->pr_as_json)
                js_snakenv_ihexstr_nex(jsp, jo3p, b, j, true, NULL, NULL,
                                       NULL);
            j = sg_get_unaligned_be16(bp + 12);
            snprintf(b, blen, "%s progress", bms);
            d = (100.0 * j / 65536.0);
#ifdef SG_LIB_MINGW
            snprintf(e, elen, "%g %%", d);
#else
            snprintf(e, elen, "%.2f %%", d);
#endif
            sgj_pr_hr(jsp, "    %s: %s\n", b, e);
            if (jsp->pr_as_json)
                js_snakenv_ihexstr_nex(jsp, jo3p, b, j, true, NULL, e,
                                       NULL);
            j = sg_get_unaligned_be16(bp + 14);
            snprintf(b, blen, "Number of %ss performed", bms);

            ok = (j > 0);
            if (ok)
                sgj_pr_hr(jsp, "    %s: %d\n", b, j);
            else
                sgj_pr_hr(jsp, "    %s: 0 [%s]\n", b, not_rep);
            if (jsp->pr_as_json)
                js_snakenv_ihexstr_nex(jsp, jo3p, b, j, true, NULL,
                                       ok ? NULL : not_rep, NULL);
            break;
        default:
            if (pc > 0x800) {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      (pc >= 0x8000) ? vend_spec : NULL);
                if ((pc >= 0x8000) && (pc <= 0xafff)) {
                    if (op->exclude_vendor) {
                        skip_out = true;
                        if ((op->verbose > 0) && (0 == op->do_brief) &&
                            (! evsm_output)) {
                            evsm_output = true;
                            sgj_pr_hr(jsp, "  %s parameter(s) being "
                                      "ignored\n", vend_spec);
                        }
                    } else
                        sgj_pr_hr(jsp, "  %s parameter # %d [0x%x], %s\n",
                                  ms, pc, pc, vend_spec);
                } else
                    sgj_pr_hr(jsp, "  %s parameter # %d [0x%x], %s\n", ms, pc,
                              pc, rsv_s);
                if (skip_out)
                    skip_out = false;
                else
                    hex2fp(bp, ((pl < num) ? pl : num), "    ",
                           op->h2s_oformat, stdout);
                break;
            } else {
                sgj_pr_hr(jsp, "  %s parameter # %d [0x%x]\n", ms, pc, pc);
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, bsr);
            }
            if ((pl < 24) || (num < 24)) {
                if (num < 24)
                    pr2serr("%s: truncated by response length, expected at "
                            "least 24 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 24 expected, got %d\n",
                            __func__, pl);
                break;
            }
            j = sg_get_unaligned_be32(bp + 4);
            n = (j % 60);
            sgj_pr_hr(jsp, "    %s when error detected: %d [%d:%d]\n", apom,
                      j, (j / 60), n);
            if (jsp->pr_as_json) {
                snprintf(b, blen, "%d hours, %d minute%s", (j / 60), n,
                         n != 1 ? "s" : "");
                js_snakenv_ihexstr_nex(jsp, jo3p, apom, j, true, NULL, b,
                                       "when error detected [unit: minute]");
            }
            j = (bp[8] >> 4) & 0xf;
            ok = (j < (int)SG_ARRAY_SIZE(reassign_status));
            if (ok)
                sgj_pr_hr(jsp, "    %s: %s\n", rs, reassign_status[j]);
            else
                sgj_pr_hr(jsp, "    %s: %s [0x%x]\n", rs, rsv_s, j);
            if (jsp->pr_as_json)
                js_snakenv_ihexstr_nex(jsp, jo3p, rs, j, true, NULL,
                                       ok ? reassign_status[j] : NULL, NULL);
            n = 0xf & bp[8];
            sgj_pr_hr(jsp, "    %s: %s  [sk,asc,ascq: 0x%x,0x%x,0x%x]\n",
                      s_key, sg_get_sense_key_str(n, blen, b), n, bp[9],
                                                  bp[10]);
            if (bp[9] || bp[10])
                sgj_pr_hr(jsp, "      %s\n",
                          sg_get_asc_ascq_str(bp[9], bp[10], blen, b));
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, "sense_key", n, NULL,
                                  sg_get_sense_key_str(n, blen, b));
                sgj_js_nv_ihexstr(jsp, jo3p, "additional_sense_code", bp[9],
                                  NULL, NULL);
                sgj_js_nv_ihexstr(jsp, jo3p, "additional_sense_code_qualifier",
                                  bp[10], NULL, sg_get_asc_ascq_str(bp[9],
                                  bp[10], blen, b));
            }
            if (op->verbose) {
                n = sg_scnpr(b, blen, "    vendor bytes [11 -> 15]: ");
                for (m = 0; m < 5; ++m)
                    n += sg_scnpr(b + n, blen - n, "0x%02x ", bp[11 + m]);
                 sgj_pr_hr(jsp, "%s\n", b);
            }
            n = sg_scnpr(b, blen, "    LBA (associated with medium error): "
                         "0x");
            if (sg_all_zeros(bp + 16, 8))
                sgj_pr_hr(jsp, "%s0\n", b);
            else {
                for (m = 0; m < 8; ++m)
                    n += sg_scnpr(b + n, blen - n, "%02x", bp[16 + m]);
                sgj_pr_hr(jsp, "%s\n", b);
            }
            if (jsp->pr_as_json)
                js_snakenv_ihexstr_nex(jsp, jo3p, lba_sn,
                                       sg_get_unaligned_be64(bp + 16), true,
                                       NULL, NULL, "of medium error");
            break;
        }               /* end of switch statement block */
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* ZONED_BLOCK_DEV_STATS_SUBPG [0x14,0x1] <zbds>  introduced: zbc2r01 */
static bool
show_zoned_block_dev_stats(const uint8_t * resp, int len,
                           struct opts_t * op, sgj_opaque_p jop)
{
    bool trunc, bad_pl;
    int num, pl, pc;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * zbdslp = "Zoned block device statistics log page";
    static const char * mxoz = "Maximum open zones";
    static const char * mxeoz = "Maximum explicitly open zones";
    static const char * mxioz = "Maximum implicitly open zones";
    static const char * mnez = "Minimum empty zones";
    static const char * mxnsz = "Maximum non-sequential zones";
    static const char * ze = "Zones emptied";
    static const char * swc = "Suboptimal write commands";
    static const char * ceol = "Commands exceeding optimal limit";
    static const char * feo = "Failed explicit opens";
    static const char * rrv = "Read rule violations";
    static const char * wrv = "Write rule violations";
    static const char * mxiosobrz =
        "Maximum implicitly open sequential or before required zones";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x14,0x1]\n", zbdslp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, zbdslp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                        "zoned_block_device_statistics_log_parameters");
    }

    while (num > 3) {
        trunc = false;
        bad_pl = false;
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (4 == pl)    /* DC HC560 has empty descriptors */
            goto skip;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x0:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, mxoz);
                sgj_haj_vi(jsp, jo3p, 2, mxoz, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x1:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, mxeoz);
                sgj_haj_vi(jsp, jo3p, 2, mxeoz, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x2:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, mxioz);
                sgj_haj_vi(jsp, jo3p, 2, mxioz, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x3:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, mnez);
                sgj_haj_vi(jsp, jo3p, 2, mnez, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x4:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, mxnsz);
                sgj_haj_vi(jsp, jo3p, 2, mxnsz, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x5:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ze);
                sgj_haj_vi(jsp, jo3p, 2, ze, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x6:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, swc);
                sgj_haj_vi(jsp, jo3p, 2, swc, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x7:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ceol);
                sgj_haj_vi(jsp, jo3p, 2, ceol, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x8:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, feo);
                sgj_haj_vi(jsp, jo3p, 2, feo, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0x9:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, rrv);
                sgj_haj_vi(jsp, jo3p, 2, rrv, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0xa:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, wrv);
                sgj_haj_vi(jsp, jo3p, 2, wrv, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        case 0xb:       /* added zbc2r04 */
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    trunc = true;
                else
                    bad_pl = true;
            } else {
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      mxiosobrz);
                sgj_haj_vi(jsp, jo3p, 2, mxiosobrz, SGJ_SEP_COLON_1_SPACE,
                           sg_get_unaligned_be32(bp + 8), false);
            }
            break;
        default:
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            hex2fp(bp, ((pl < num) ? pl : num), "    ",
                   op->h2s_oformat, stdout);
            break;
        }
        if (trunc)
            pr2serr("%s: truncated by response length, expected at least "
                    "8 bytes\n", __func__);
        if (bad_pl)
            pr2serr("%s: parameter length >= 8 expected, got %d\n",
                    __func__, pl);
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* PENDING_DEFECTS_SUBPG [0x15,0x1] <pd>  introduced: SBC-4 */
static bool
show_pending_defects_page(const uint8_t * resp, int len, struct opts_t * op,
                          sgj_opaque_p jop)
{
    int num, pl, pc;
    uint32_t count;
    uint64_t lba;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * pdlp = "Pending defects log page";
    static const char * pd = "Pending defect";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
         sgj_pr_hr(jsp, "  %s  [0x15,0x1]\n", pdlp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, pdlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "pending_defect_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x0:
            sg_scnpr(b, blen, "%s count:", pd);
            if ((pl < 8) || (num < 8)) {
                sgj_pr_hr(jsp, "  %s: \n", b);
                if (num < 8)
                    pr2serr("%s: truncated by response length, expected "
                            "at least 8 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 8 expected, got %d\n",
                            __func__, pl);
                break;
            }
            count = sg_get_unaligned_be32(bp + 4);
            if (0 == count) {
                sgj_pr_hr(jsp, "  %s 0\n", b);
                break;
            }
            sgj_pr_hr(jsp, "  %s %3u  |     LBA            Accumulated "
                      "power_on\n", b, count);
            sgj_pr_hr(jsp, "-----------------------------|---------------"
                      "-----------hours---------\n");
            if (jsp->pr_as_json) {
                snprintf(b, blen, "%s count", pd);
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, b);
                sgj_js_nv_ihex(jsp, jo3p, "pending_defect_count", count);
            }
            break;
        default:
            if (pc > 0xf000) {
                sgj_pr_hr(jsp, "  %s # %d [0x%x], %s\n", param_s, pc, pc,
                          rsv_s);
                if (jsp->pr_as_json)
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, rsv_s);
                break;
            }
            sg_scnpr(b, blen, "  %s %4d:  ", pd, pc);
            if ((pl < 16) || (num < 16)) {
                sgj_pr_hr(jsp, "  %s: \n", b);
                if (num < 16)
                    pr2serr("%s: truncated by response length, expected "
                            "at least 16 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 16 expected, got %d\n",
                            __func__, pl);
                break;
            }
            count = sg_get_unaligned_be32(bp + 4);
            lba = sg_get_unaligned_be64(bp + 8);
            sgj_pr_hr(jsp, "%s        0x%-16" PRIx64 "      %5u\n", b, lba,
                      count);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, pd);
                sgj_js_nv_ihex(jsp, jo3p, "accumulated_power_on_hours", count);
                sgj_js_nv_ihex(jsp, jo3p, lba_sn, lba);
            }
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* BACKGROUND_OP_SUBPG [0x15,0x2] <bop>  introduced: SBC-4 rev 7 */
static bool
show_background_op_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * bolp = "Background operation log page";
    static const char * bo_s = "Background operation";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x15,0x2]\n", bolp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, bolp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "background_operation_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x0:
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("%s: truncated by response length, expected "
                            "at least 8 bytes\n", __func__);
                else
                    pr2serr("%s: parameter length >= 8 expected, got %d\n",
                            __func__, pl);
                break;
            }
            sgj_pr_hr(jsp, "  %s: BO_STATUS=%d\n", bo_s, bp[4]);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, bo_s);
                sgj_js_nv_ihex(jsp, jo3p, "bo_status", bp[4]);
            }
            break;
        default:
            sgj_pr_hr(jsp, "  %s: %s [%s=0x%x]:\n", bo_s, rsv_s, param_c_sn,
                      pc);
            hex2fp(bp, ((pl < num) ? pl : num), "    ",
                   op->h2s_oformat, stdout);
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* LPS misalignment page [0x15,0x3] <lps>  introduced: SBC-4 rev 10
   LPS: "Long Physical Sector" a term from an ATA feature set */
static bool
show_lps_misalignment_page(const uint8_t * resp, int len,
                           struct opts_t * op, sgj_opaque_p jop)
{
    uint16_t max_lpsm, lm_count;
    int num, pl, pc;
    uint64_t lba;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * lmlp = "LPS misalignment log page";
    static const char * lmc = "LPS misalignment count";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s  [0x15,0x3]\n", lmlp);
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, lmlp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "lps_misalignment_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0x0:
            printf("  LPS misalignment count: ");
            if (4 != bp[3]) {
                sgj_pr_hr(jsp, "  %s: <unexpected pc=0 parameter "
                          "length=%d>\n", lmc, bp[4]);
                break;
            }
            max_lpsm = sg_get_unaligned_be16(bp + 4),
            lm_count = sg_get_unaligned_be16(bp + 6);
            sgj_pr_hr(jsp, "  %s: max lpsm: %" PRIu16 ", count=%" PRIu16
                      "\n", lmc, max_lpsm, lm_count);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr_nex(jsp, jo3p, param_c_sn, pc, true, NULL,
                                      lmc,
                    "Long Physical Sector (LPS); multiple LBs per physical");
                sgj_js_nv_ihex(jsp, jo3p, "max_lpsm", max_lpsm);
                sgj_js_nv_ihex(jsp, jo3p, "lps_misalignment_count", lm_count);
            }
            break;
        default:
            if (pc > 0xf000) {
                sgj_pr_hr(jsp, "  <unexpected pc=0x%x>\n", pc);
                hex2fp(bp, ((pl < num) ? pl : num), "    ",
                       op->h2s_oformat, stdout);
                break;
            }
            /* parameter codes 0x1 to 0xf000 */
            lba = sg_get_unaligned_be64(bp + 4);
            if (8 != bp[3]) {
                sgj_pr_hr(jsp, "  <pc=0x%x, unexpected length: %u>\n", pc,
                          bp[3]);
                hex2fp(bp, ((pl < num) ? pl : num), "    ",
                       op->h2s_oformat, stdout);
                break;
            }
            sgj_pr_hr(jsp, "  LBA of misaligned block: 0x%" PRIx64 "\n", lba);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                  "LPS misalignment");
                sgj_js_nv_ihex(jsp, jo3p, "lba_of_misaligned_block", lba);
            }
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Service buffer information [0x15] <sbi> (adc) */
static bool
show_service_buffer_info_page(const uint8_t * resp, int len,
                              struct opts_t * op, sgj_opaque_p jop)
{
    bool evsm_output = false;
    int num, pl, pc;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    char b[256];
    static const int blen = sizeof(b);

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "Service buffer information page (adc-3) [0x15]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (pc < 0x100) {
            sgj_pr_hr(jsp, "  Service buffer identifier: 0x%x\n", pc);
            sgj_pr_hr(jsp, "    Buffer id: 0x%x, tu=%d, nmp=%d, nmm=%d, "
                      "offline=%d\n", bp[4], !!(0x10 & bp[5]),
                      !!(0x8 & bp[5]), !!(0x4 & bp[5]), !!(0x2 & bp[5]));
            sgj_pr_hr(jsp, "    pd=%d, code_set: %s, Service buffer title:\n",
                      !!(0x1 & bp[5]),
                      sg_get_desig_code_set_str(0xf & bp[6]));
            sgj_pr_hr(jsp, "      %.*s\n", pl - 8, bp + 8);
        } else if (pc < 0x8000) {
            sgj_pr_hr(jsp, "  parameter_code=0x%x, Reserved, parameter in "
                      "hex:\n", pc);
            hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
        } else {
            if (op->exclude_vendor) {
                if ((op->verbose > 0) && (0 == op->do_brief) &&
                    (! evsm_output)) {
                    evsm_output = true;
                    sgj_pr_hr(jsp, "  Vendor specific parameter(s) being "
                              "ignored\n");
                }
            } else {
                sgj_pr_hr(jsp, "  parameter_code=0x%x, Vendor-specific, "
                          "parameter in hex:\n", pc);
                hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
            }
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Sequential access device page [0xc] <sad> for tape */
static bool
show_sequential_access_page(const uint8_t * resp, int len,
                            struct opts_t * op, sgj_opaque_p jop)
{
    bool evsm_output = false;
    bool all_set;
    int num, pl, pc, n;
    uint64_t ull, gbytes;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[168];
    static const int blen = sizeof(b);
    static const char * const sad_lp = "Sequential access device log page";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s (ssc-3)\n", sad_lp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, sad_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "sequential_access_device_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        ull = sg_get_unaligned_be(pl - 4, bp + 4);
        all_set = sg_all_ffs(bp + 4, pl - 4);
        gbytes = ull / 1000000000;
        switch (pc) {
        case 0:
            ccp = "Data bytes received with WRITE operations";
            n = sg_scnpr(b, blen, "  %s: %" PRIu64 " GB", ccp, gbytes);
            if (op->verbose)
                sg_scnpr(b + n, blen - n, " [%" PRIu64 " bytes]", ull);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex(jsp, jo3p, "counter", ull);
            }
            break;
        case 1:
            ccp = "Data bytes written to media by WRITE operations";
            n = sg_scnpr(b, blen, "  %s: %" PRIu64 " GB", ccp, gbytes);
            if (op->verbose)
                sg_scnpr(b + n, blen - n, " [%" PRIu64 " bytes]", ull);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex(jsp, jo3p, "counter", ull);
            }
            break;
        case 2:
            ccp = "Data bytes read from media by READ operations";
            n = sg_scnpr(b, blen, "  %s: %" PRIu64 " GB", ccp, gbytes);
            if (op->verbose)
                sg_scnpr(b + n, blen - n, " [%" PRIu64 " bytes]", ull);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex(jsp, jo3p, "counter", ull);
            }
            break;
        case 3:
            ccp = "Data bytes transferred by READ operations";
            n = sg_scnpr(b, blen, "  %s: %" PRIu64 " GB", ccp, gbytes);
            if (op->verbose)
                sg_scnpr(b + n, blen - n, " [%" PRIu64 " bytes]", ull);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex(jsp, jo3p, "counter", ull);
            }
            break;
        case 4:
            if (all_set)
                break;
            ccp = "Native capacity from BOP to EOD";
            sgj_pr_hr(jsp, "  %s: %" PRIu64 " MB\n", ccp, ull);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex_nex(jsp, jo3p, "counter", ull, true,
                                   "[unit: megabyte]");
            }
            break;
        case 5:
            if (all_set)
                break;
            ccp = "Native capacity from BOP to EW of current partition";
            sgj_pr_hr(jsp, "  %s: %" PRIu64 " MB\n", ccp, ull);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex_nex(jsp, jo3p, "counter", ull, true,
                                   "[unit: megabyte]");
            }
            break;
        case 6:
            if (all_set)
                break;
            ccp = "Minimum native capacity from EW to EOP of current "
                  "partition";
            sgj_pr_hr(jsp, "  %s: %" PRIu64 " MB\n", ccp, ull);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex_nex(jsp, jo3p, "counter", ull, true,
                                   "[unit: megabyte]");
            }
            break;
        case 7:
            if (all_set)
                break;
            ccp = "Native capacity from BOP to current position";
            sgj_pr_hr(jsp, "  %s: %" PRIu64 " MB\n", ccp, ull);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex_nex(jsp, jo3p, "counter", ull, true,
                                   "[unit: megabyte]");
            }
            break;
        case 8:
            if (all_set)
                break;
            ccp = "Maximum native capacity in device object buffer";
            sgj_pr_hr(jsp, "  %s: %" PRIu64 " MB\n", ccp, ull);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex_nex(jsp, jo3p, "counter", ull, true,
                                   "[unit: megabyte]");
            }
            break;
        case 0x100:
            if (ull > 0)
                ccp = "Cleaning action required (or in progress)";
            else
                ccp = "Cleaning action not required (or completed)";
            sgj_pr_hr(jsp, "  %s\n", ccp);
            if (op->verbose)
                sgj_pr_hr(jsp, "    cleaning value: %" PRIu64 "\n", ull);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_ihex_nex(jsp, jo3p, "counter", ull, false,
                                   "only 0 or not zero is significant");
            }
            break;
        default:
            if (pc >= 0x8000) {
                if (op->exclude_vendor) {
                    if ((op->verbose > 0) && (0 == op->do_brief) &&
                        (! evsm_output)) {
                        evsm_output = true;
                        sgj_pr_hr(jsp, "  Vendor specific parameter(s) "
                                  "being ignored\n");
                    }
                } else
                    sgj_pr_hr(jsp, "  Vendor specific parameter [0x%x] "
                              "value: %" PRIu64 "\n", pc, ull);
            } else
                sgj_pr_hr(jsp, "  Reserved parameter [0x%x] value: %"
                          PRIu64 "\n", pc, ull);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                  (pc >= 0x8000) ? vend_spec : rsv_s);
                sgj_js_nv_ihex(jsp, jo3p, "counter", ull);
            }
            break;
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Device statistics 0x14 <ds> for tape and ADC */
static bool
show_device_stats_page(const uint8_t * resp, int len,
                       struct opts_t * op, sgj_opaque_p jop)
{
    bool evsm_output = false;
    int num, pl, pc;
    uint64_t ull;
    const char * ccp;
    const char * cc2p = NULL;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jo4p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;
    char b[196];
    static const int blen = sizeof(b);
    static const char * const ds_lp = "Device statistics log page";

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s (ssc-3 and adc)\n", ds_lp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, ds_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "device_statistics_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
             goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
             goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        if (pc < 0x1000) {
            bool vl_num = true;

            switch (pc) {
            case 0:
                ccp = "Lifetime media loads";
                break;
            case 1:
                ccp = "Lifetime cleaning operations";
                break;
            case 2:
                ccp = "Lifetime power on hours";
                break;
            case 3:
                ccp = "Lifetime media motion (head) hours";
                break;
            case 4:
                ccp = "Lifetime metres of tape processed";
                break;
            case 5:
                ccp = "Lifetime media motion (head) hours when "
                      "incompatible media last loaded";
                break;
            case 6:
                ccp = "Lifetime power on hours when last temperature "
                      "condition occurred";
                break;
            case 7:
                ccp = "Lifetime power on hours when last power "
                      "consumption condition occurred";
                break;
            case 8:
                ccp = "Media motion (head) hours since last successful "
                      "cleaning operation";
                break;
            case 9:
                ccp = "Media motion (head) hours since 2nd to last "
                      "successful cleaning";
                break;
            case 0xa:
                ccp = "Media motion (head) hours since 3rd to last "
                      "successful cleaning";
                break;
            case 0xb:
                ccp = "Lifetime power on hours when last operator initiated "
                      "forced reset";
                cc2p = "and/or emergency eject occurred";
                break;
            case 0xc:
                ccp = "Lifetime power cycles";
                break;
            case 0xd:
                ccp = "Volume loads since last parameter reset";
                break;
            case 0xe:
                ccp = "Hard write errors";
                break;
            case 0xf:
                ccp = "Hard read errors";
                break;
            case 0x10:
                ccp = "Duty cycle sample time (ms)";
                break;
            case 0x11:
                ccp = "Read duty cycle";
                break;
            case 0x12:
                ccp = "Write duty cycle";
                break;
            case 0x13:
                ccp = "Activity duty cycle";
                break;
            case 0x14:
                ccp = "Volume not present duty cycle";
                break;
            case 0x15:
                ccp = "Ready duty cycle";
                break;
            case 0x16:
                ccp = "MBs transferred from app client in duty cycle "
                      "sample time";
                break;
            case 0x17:
                ccp = "MBs transferred to app client in duty cycle "
                       "sample time";
                break;
            case 0x40:
                ccp = "Drive manufacturer's serial number";
                break;
            case 0x41:
                ccp = "Drive serial number";
                break;
            case 0x42:          /* added ssc5r02b */
                vl_num = false;
                ccp = "Manufacturing date (yyyymmdd)";
                sgj_pr_hr(jsp, "  %s: %.*s\n", ccp, pl - 4, bp + 4);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                    sgj_js_nv_s_len_chk(jsp, jo3p, "yyyymmdd", bp + 4,
                                        pl - 4);
                }
                break;
            case 0x43:          /* added ssc5r02b */
                vl_num = false;
                ccp = "Manufacturing date (yyyyww)";
                sgj_pr_hr(jsp, "  %s: %.*s\n", ccp, pl - 4, bp + 4);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                    sgj_js_nv_s_len_chk(jsp, jo3p, "yyyyww", bp + 4, pl - 4);
                }
                break;
            case 0x80:
                ccp = "Medium removal prevented";
                break;
            case 0x81:
                ccp = "Maximum recommended mechanism temperature exceeded";
                break;
            default:
                vl_num = false;
                sgj_pr_hr(jsp, "  Reserved %s [0x%x] data in hex:\n", param_c,
                          pc);
                hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, rsv_s);
                    sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, pl - 4);
                }
                break;
            }
            if (vl_num) {
                ull = sg_get_unaligned_be(pl - 4, bp + 4);
                if (cc2p) {
                    sgj_pr_hr(jsp, "  %s\n    %s: %" PRIu64 "\n", ccp, cc2p,
                              ull);
                    cc2p = NULL;
                } else
                    sgj_pr_hr(jsp, "  %s: %" PRIu64 "\n", ccp, ull);
                if (jsp->pr_as_json) {
                    if (cc2p) {
                        snprintf(b, blen, "%s %s", ccp, cc2p);
                        ccp = b;
                    }
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                    sgj_js_nv_ihex(jsp, jo3p, "counter", ull);
                }
            }
        } else {        /* parameter_code >= 0x1000 */
            int k;
            uint32_t ui;
            const uint8_t * p = bp + 4;

            switch (pc) {
            case 0x1000:
                sgj_pr_hr(jsp, "  Media motion (head) hours for each medium "
                          "type:\n");
                if (jsp->pr_as_json && ((pl - 4) >= 8))
                    ja2p = sgj_named_subarray_r(jsp, jo3p,
                            "device_statistics_medium_type_descriptors");
                for (k = 0; ((pl - 4) - k) >= 8; k += 8, p += 8) {
                    ui = sg_get_unaligned_be32(p + 4);
                    sgj_pr_hr(jsp, "    [%d] Density code: %u, Medium type: "
                              "0x%x, hours: %u\n", ((k / 8) + 1), p[2],
                              p[3], ui);
                    if (jsp->pr_as_json) {
                        jo4p = sgj_new_unattached_object_r(jsp);
                        sgj_js_nv_ihex(jsp, jo4p, "density_code", p[2]);
                        sgj_js_nv_ihex(jsp, jo4p, "medium_type", p[3]);
                        sgj_js_nv_ihex(jsp, jo4p, "medium_motion_hours", ui);
                        sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo4p);
                    }
                }
                break;
            default:
                if (pc >= 0x8000) {
                    if (op->exclude_vendor) {
                        if ((op->verbose > 0) && (0 == op->do_brief) &&
                            (! evsm_output)) {
                            evsm_output = true;
                            sgj_pr_hr(jsp, "  Vendor specific parameter(s) "
                                      "being ignored\n");
                        }
                    } else {
                        sgj_pr_hr(jsp, "  Vendor specific parameter [0x%x], "
                                  "dump in hex:\n", pc);
                        hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat,
                                blen, b);
                        sgj_pr_hr(jsp, "%s\n", b);
                    }
                } else {
                    printf("  Reserved parameter [0x%x], dump in hex:\n", pc);
                    hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat,
                            blen, b);
                    sgj_pr_hr(jsp, "%s\n", b);
                }
                if (jsp->pr_as_json) {
                    sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                      (pc >= 0x8000) ? vend_spec : rsv_s);
                    sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, pl - 4);
                }
                break;
            }
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Media changer statistics 0x14 <mcs> for media changer */
static bool
show_media_stats_page(const uint8_t * resp, int len, struct opts_t * op,
                      sgj_opaque_p jop)
{
    int num, pl, pc;
    const uint8_t * bp;
    uint64_t ull;
    char str[PCB_STR_LEN];

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Media statistics page (smc-3)\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        ull = sg_get_unaligned_be(pl - 4, bp + 4);
        switch (pc) {
        case 0:
            printf("  Number of moves: %" PRIu64 "\n", ull);
            break;
        case 1:
            printf("  Number of picks: %" PRIu64 "\n", ull);
            break;
        case 2:
            printf("  Number of pick retries: %" PRIu64 "\n", ull);
            break;
        case 3:
            printf("  Number of places: %" PRIu64 "\n", ull);
            break;
        case 4:
            printf("  Number of place retries: %" PRIu64 "\n", ull);
            break;
        case 5:
            printf("  Number of volume tags read by volume "
                   "tag reader: %" PRIu64 "\n", ull);
            break;
        case 6:
            printf("  Number of invalid volume tags returned by "
                   "volume tag reader: %" PRIu64 "\n", ull);
            break;
        case 7:
            printf("  Number of library door opens: %" PRIu64 "\n", ull);
            break;
        case 8:
            printf("  Number of import/export door opens: %" PRIu64 "\n",
                   ull);
            break;
        case 9:
            printf("  Number of physical inventory scans: %" PRIu64 "\n",
                   ull);
            break;
        case 0xa:
            printf("  Number of medium transport unrecovered errors: "
                   "%" PRIu64 "\n", ull);
            break;
        case 0xb:
            printf("  Number of medium transport recovered errors: "
                   "%" PRIu64 "\n", ull);
            break;
        case 0xc:
            printf("  Number of medium transport X axis translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0xd:
            printf("  Number of medium transport X axis translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0xe:
            printf("  Number of medium transport Y axis translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0xf:
            printf("  Number of medium transport Y axis translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x10:
            printf("  Number of medium transport Z axis translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x11:
            printf("  Number of medium transport Z axis translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x12:
            printf("  Number of medium transport rotational translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x13:
            printf("  Number of medium transport rotational translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x14:
            printf("  Number of medium transport inversion translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x15:
            printf("  Number of medium transport inversion translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x16:
            printf("  Number of medium transport auxiliary translation "
                   "unrecovered errors: %" PRIu64 "\n", ull);
            break;
        case 0x17:
            printf("  Number of medium transport auxiliary translation "
                   "recovered errors: %" PRIu64 "\n", ull);
            break;
        default:
            printf("  Reserved parameter [0x%x] value: %" PRIu64 "\n",
                   pc, ull);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Element statistics page, 0x15 <els> for SMC */
static bool
show_element_stats_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    unsigned int v;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Element statistics page (smc-3) [0x15]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        printf("  Element address: %d\n", pc);
        v = sg_get_unaligned_be32(bp + 4);
        printf("    Number of places: %u\n", v);
        v = sg_get_unaligned_be32(bp + 8);
        printf("    Number of place retries: %u\n", v);
        v = sg_get_unaligned_be32(bp + 12);
        printf("    Number of picks: %u\n", v);
        v = sg_get_unaligned_be32(bp + 16);
        printf("    Number of pick retries: %u\n", v);
        v = sg_get_unaligned_be32(bp + 20);
        printf("    Number of determined volume identifiers: %u\n", v);
        v = sg_get_unaligned_be32(bp + 24);
        printf("    Number of unreadable volume identifiers: %u\n", v);
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Tape diagnostic data [0x16] <tdd> for tape */
static bool
show_tape_diag_data_page(const uint8_t * resp, int len,
                         struct opts_t * op, sgj_opaque_p jop)
{
    int k, n, num, pl, pc;
    unsigned int v;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    char b[512];
    static const int blen = sizeof(b);

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "Tape diagnostics data page (ssc-3) [0x16]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        sgj_pr_hr(jsp, "  %s: %d\n", param_c, pc);
        sgj_pr_hr(jsp, "    Density code: 0x%x\n", bp[6]);
        sgj_pr_hr(jsp, "    Medium type: 0x%x\n", bp[7]);
        v = sg_get_unaligned_be32(bp + 8);
        sgj_pr_hr(jsp, "    Lifetime media motion hours: %u\n", v);
        sgj_pr_hr(jsp, "    Repeat: %d\n", !!(bp[13] & 0x80));
        v = bp[13] & 0xf;
        sgj_pr_hr(jsp, "    Sense key: 0x%x [%s]\n", v,
                  sg_get_sense_key_str(v, blen, b));
        sgj_pr_hr(jsp, "    Additional sense code: 0x%x\n", bp[14]);
        sgj_pr_hr(jsp, "    Additional sense code qualifier: 0x%x\n", bp[15]);
        if (bp[14] || bp[15])
            sgj_pr_hr(jsp, "      [%s]\n", sg_get_asc_ascq_str(bp[14], bp[15],
                      blen, b));
        v = sg_get_unaligned_be32(bp + 16);
        sgj_pr_hr(jsp, "    Vendor specific code qualifier: 0x%x\n", v);
        v = sg_get_unaligned_be32(bp + 20);
        sgj_pr_hr(jsp, "    Product revision level: %u\n", v);
        v = sg_get_unaligned_be32(bp + 24);
        sgj_pr_hr(jsp, "    Hours since last clean: %u\n", v);
        sgj_pr_hr(jsp, "    Operation code: 0x%x\n", bp[28]);
        sgj_pr_hr(jsp, "    Service action: 0x%x\n", bp[29] & 0xf);
        // Check Medium id number for all zeros
        // ssc4r03.pdf does not define this field, why? xxxxxx
        if (sg_all_zeros(bp + 32, 32))
            sgj_pr_hr(jsp, "    Medium id number is 32 bytes of zero\n");
        else {
            hex2str(bp + 32, 32, "      ", 0 /* with ASCII */, blen, b);
            sgj_pr_hr(jsp, "    Medium id number (in hex):\n%s", b);
        }
        sgj_pr_hr(jsp, "    Timestamp origin: 0x%x\n", bp[64] & 0xf);
        // Check Timestamp for all zeros
        if (sg_all_zeros(bp + 66, 6))
            sgj_pr_hr(jsp, "    Timestamp is all zeros:\n");
        else {
            hex2str(bp + 66, 6, NULL, op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "    Timestamp: %s\n", b);
        }
        if (pl > 72) {
            n = pl - 72;
            k = hex2str(bp + 72, n, "      ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "    Vendor specific:\n");
            if (k >= blen - 1)
                sgj_pr_hr(jsp, "%s      <truncated>\n", b);
            else
                sgj_pr_hr(jsp, "%s\n", b);
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Media changer diagnostic data [0x16] <mcdd> for media changer */
static bool
show_mchanger_diag_data_page(const uint8_t * resp, int len,
                             struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    unsigned int v;
    const uint8_t * bp;
    char str[PCB_STR_LEN];
    char b[512];

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Media changer diagnostics data page (smc-3) [0x16]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        printf("  %s: %d\n", param_c, pc);
        printf("    Repeat: %d\n", !!(bp[5] & 0x80));
        v = bp[5] & 0xf;
        printf("    Sense key: 0x%x [%s]\n", v,
               sg_get_sense_key_str(v, sizeof(b), b));
        printf("    Additional sense code: 0x%x\n", bp[6]);
        printf("    Additional sense code qualifier: 0x%x\n", bp[7]);
        if (bp[6] || bp[7])
            printf("      [%s]\n", sg_get_asc_ascq_str(bp[6], bp[7],
                   sizeof(b), b));
        v = sg_get_unaligned_be32(bp + 8);
        printf("    Vendor specific code qualifier: 0x%x\n", v);
        v = sg_get_unaligned_be32(bp + 12);
        printf("    Product revision level: %u\n", v);
        v = sg_get_unaligned_be32(bp + 16);
        printf("    Number of moves: %u\n", v);
        v = sg_get_unaligned_be32(bp + 20);
        printf("    Number of pick: %u\n", v);
        v = sg_get_unaligned_be32(bp + 24);
        printf("    Number of pick retries: %u\n", v);
        v = sg_get_unaligned_be32(bp + 28);
        printf("    Number of places: %u\n", v);
        v = sg_get_unaligned_be32(bp + 32);
        printf("    Number of place retries: %u\n", v);
        v = sg_get_unaligned_be32(bp + 36);
        printf("    Number of determined volume identifiers: %u\n", v);
        v = sg_get_unaligned_be32(bp + 40);
        printf("    Number of unreadable volume identifiers: %u\n", v);
        printf("    Operation code: 0x%x\n", bp[44]);
        printf("    Service action: 0x%x\n", bp[45] & 0xf);
        printf("    Media changer error type: 0x%x\n", bp[46]);
        printf("    MTAV: %d\n", !!(bp[47] & 0x8));
        printf("    IAV: %d\n", !!(bp[47] & 0x4));
        printf("    LSAV: %d\n", !!(bp[47] & 0x2));
        printf("    DAV: %d\n", !!(bp[47] & 0x1));
        v = sg_get_unaligned_be16(bp + 48);
        printf("    Medium transport address: 0x%x\n", v);
        v = sg_get_unaligned_be16(bp + 50);
        printf("    Initial address: 0x%x\n", v);
        v = sg_get_unaligned_be16(bp + 52);
        printf("    Last successful address: 0x%x\n", v);
        v = sg_get_unaligned_be16(bp + 54);
        printf("    Destination address: 0x%x\n", v);
        if (pl > 91) {
            printf("    Volume tag information:\n");
            hex2fp(bp + 56, 36, "    ", op->h2s_oformat, stdout);
        }
        if (pl > 99) {
            printf("    Timestamp origin: 0x%x\n", bp[92] & 0xf);
            printf("    Timestamp:\n");
            hex2fp(bp + 94, 6, "    ", op->h2s_oformat, stdout);
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Helper for show_volume_stats_pages() */
static void
volume_stats_partition(const char * name, const uint8_t * xp, int len,
                       bool pr_in_hex, bool in_mb, struct opts_t * op,
                       sgj_opaque_p jop)
{
    uint64_t ull;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    const char * mb_s = in_mb ? " [MB]" : "";
    char b[128];
    static const int blen = sizeof(b);

    sgj_pr_hr(jsp, "  %s:\n", name);
    if (jsp->pr_as_json) {
        jap = sgj_named_subarray_r(jsp, jop,
                                   sgj_convert2snake(name, b, blen));
    }
    while (len > 3) {
        bool all_ffs, ffs_last_fe;
        int dl, pn;
        const char * ccp = NULL;

        dl = xp[0] + 1;
        if (dl < 3)
            return;
        if (jsp->pr_as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        pn = sg_get_unaligned_be16(xp + 2);
        ffs_last_fe = false;
        all_ffs = false;
        if (sg_all_ffs(xp + 4, dl - 3)) {
            switch (xp[4 + dl - 3]) {
            case 0xff:
                all_ffs = true;
                break;
            case 0xfe:
                ffs_last_fe = true;
                break;
            default:
                break;
            }
        }
        ull = sg_get_unaligned_be(dl - 4, xp + 4);
        if (! (all_ffs || ffs_last_fe)) {
            if (pr_in_hex)
                sgj_pr_hr(jsp, "    partition number: %d, partition record "
                          "data counter%s: 0x%" PRIx64 "\n", pn, mb_s, ull);
            else
                sgj_pr_hr(jsp, "    partition number: %d, partition record "
                          "data counter%s: %" PRIu64 "\n", pn, mb_s, ull);
        } else if (all_ffs) {
            sgj_pr_hr(jsp, "    partition number: %d, partition record data "
                      "counter is all 0xFFs\n", pn);
            ccp = "no encrypted logical objects";
        } else {    /* ffs_last_fe is true */
            sgj_pr_hr(jsp, "    partition number: %d, partition record data "
                      "counter is all 0xFFs apart\n    from a trailing "
                      "0xFE\n", pn);
            ccp = "unknown number of encrypted logical objects";
        }
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex(jsp, jo2p, "partition_number", pn);
            sgj_js_nv_ihexstr_nex(jsp, jo2p, "partition_record_data_counter",
                                  ull, true, NULL, ccp,
                                  in_mb ? "[unit: megabyte]" : NULL);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
        xp += dl;
        len -= dl;
    }
}

/* Helper for show_volume_stats_pages() */
static void
volume_stats_history(const char * name, const uint8_t * xp, int len,
                     struct opts_t * op, sgj_opaque_p jop)
{
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);

    sgj_pr_hr(jsp, "  %s:\n", name);
    if (jsp->pr_as_json) {
        jap = sgj_named_subarray_r(jsp, jop,
                                   sgj_convert2snake(name, b, blen));
    }

    while (len > 3) {
        int dl, mhi;

        dl = xp[0] + 1;
        if (dl < 4)
            return;
        if (jsp->pr_as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        mhi = sg_get_unaligned_be16(xp + 2);
        if (dl < 12)
            printf("    index: %d\n", mhi);
        else if (12 == dl)
            printf("    index: %d, vendor: %.8s\n", mhi, xp + 4);
        else
            printf("    index: %d, vendor: %.8s, unit serial number: %.*s\n",
                   mhi, xp + 4, dl - 12, xp + 12);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex(jsp, jo2p, "mount_history_index", mhi);
            if (dl >= 12) {
                sgj_js_nv_s_len_chk(jsp, jo2p, "mount_history_vendor_id",
                                    xp + 4, 8);
                if (dl > 12)
                    sgj_js_nv_s_len_chk(jsp, jo2p,
                                        "mount_history_unit_serial_number",
                                        xp + 12, dl - 12);
            }
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
        xp += dl;
        len -= dl;
    }
}

/* Volume Statistics log page and subpages (ssc-4) [0x17, 0x0-0xf] <vs> */
static bool
show_volume_stats_pages(const uint8_t * resp, int len,
                       struct opts_t * op, sgj_opaque_p jop)
{
    bool skip_out = false;
    bool evsm_output = false;
    bool valid, is_count, is_ms, is_mb, is_num_or, is_str;
    int num, pl, pc, subpg_code;
    bool spf;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * const vs_lp = "Volume statistics log page";

    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : NOT_SPG_SUBPG;
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (subpg_code < 0x10)
            sgj_pr_hr(jsp, "%s (ssc-4), subpage=%d\n", vs_lp, subpg_code);
        else {
            sgj_pr_hr(jsp, "%s (ssc-4), subpage=%d; Reserved, skip\n", vs_lp,
                      subpg_code);
            return false;
        }
    }
    if (jsp->pr_as_json) {
        snprintf(b, blen, "%s subpage=0x%x?",  vs_lp, subpg_code);
        jo2p = sg_log_js_hdr(jsp, jop, b, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "volume_statistics_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        is_count = false;
        is_ms = false;
        is_mb = false;
        is_num_or = false;
        is_str = false;

        switch (pc) {
        case 0:
            ccp = "Page valid";
            valid = !!(0x1 & bp[4 + pl - 4 - 1]);
            sgj_pr_hr(jsp, "  %s: %d\n", ccp, (int)valid);
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                sgj_js_nv_i(jsp, jo3p, "page_valid", (int)valid);
            }
            break;
        case 1:
            ccp =  "Thread count";
            is_count = true;
            break;
        case 2:
            ccp =  "Total data sets written";
            is_count = true;
            break;
        case 3:
            ccp =  "Total write retries";
            is_count = true;
            break;
        case 4:
            ccp =  "Total unrecovered write errors";
            is_count = true;
            break;
        case 5:
            ccp =  "Total suspended writes";
            is_count = true;
            break;
        case 6:
            ccp =  "Total fatal suspended writes";
            is_count = true;
            break;
        case 7:
            ccp =  "Total data sets read";
            is_count = true;
            break;
        case 8:
            ccp =  "Total read retries";
            is_count = true;
            break;
        case 9:
            ccp =  "Total unrecovered read errors";
            is_count = true;
            break;
        case 0xa:
            ccp =  "Total suspended reads";
            is_count = true;
            break;
        case 0xb:
            ccp =  "Total fatal suspended reads";
            is_count = true;
            break;
        case 0xc:
            ccp =  "Last mount unrecovered write errors";
            is_count = true;
            break;
        case 0xd:
            ccp =  "Last mount unrecovered read errors";
            is_count = true;
            break;
        case 0xe:
            ccp =  "Last mount megabytes written";
            is_count = true;
            break;
        case 0xf:
            ccp =  "Last mount megabytes read";
            is_count = true;
            break;
        case 0x10:
            ccp =  "Lifetime megabytes written";
            is_count = true;
            break;
        case 0x11:
            ccp =  "Lifetime megabytes read";
            is_count = true;
            break;
        case 0x12:
            ccp =  "Last load write compression ratio";
            is_count = true;
            break;
        case 0x13:
            ccp =  "Last load read compression ratio";
            is_count = true;
            break;
        case 0x14:
            ccp =  "Medium mount time";
            is_count = true;
            is_ms = true;
            break;
        case 0x15:
            ccp =  "Medium ready time";
            is_count = true;
            is_ms = true;
            break;
        case 0x16:
            ccp =  "Total native capacity";
            is_count = true;
            is_mb = true;
            is_num_or = true;
            break;
        case 0x17:
            ccp =  "Total used native capacity";
            is_count = true;
            is_mb = true;
            is_num_or = true;
            break;
        case 0x1a:
            ccp =  "Volume stop writes of forward wraps";
            is_count = true;
            break;
        case 0x1b:
            ccp =  "Volume stop writes of backward wraps";
            is_count = true;
            break;
        case 0x40:
            ccp =  "Volume serial number";
            is_str = true;
            break;
        case 0x41:
            ccp =  "Tape lot identifier";
            is_str = true;
            break;
        case 0x42:
            ccp =  "Volume barcode";
            is_str = true;
            break;
        case 0x43:
            ccp =  "Volume manufacturer";
            is_str = true;
            break;
        case 0x44:
            ccp =  "Volume license code";
            is_str = true;
            break;
        case 0x45:
            ccp =  "Volume personality";
            is_str = true;
            break;
        case 0x80:
            ccp =  "Write protect";
            is_count = true;
            is_num_or = true;
            break;
        case 0x81:
            ccp =  "WORM";
            is_count = true;
            is_num_or = true;
            break;
        case 0x82:
            ccp =  "Maximum recommended tape path temperature exceeded";
            is_count = true;
            is_num_or = true;
            break;
        case 0x100:
            ccp =  "Volume write mounts";
            is_count = true;
            break;
        case 0x101:
            ccp =  "Beginning of medium passes";
            is_count = true;
            break;
        case 0x102:
            ccp =  "Middle of medium passes";
            is_count = true;
            break;
        case 0x200:
            ccp = "Logical position of first encrypted logical object";
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            volume_stats_partition(ccp, bp + 4, pl - 4, true, false, op,
                                  jo3p);
            break;
        case 0x201:
            ccp = "Logical position of first unencrypted logical object "
                  "after first encrypted logical object";
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            volume_stats_partition(ccp, bp + 4, pl - 4, true, false, op,
                                   jo3p);
            break;
        case 0x202:
            ccp = "Native capacity partitions";
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            volume_stats_partition(ccp, bp + 4, pl - 4, false, true, op,
                                  jo3p);
            break;
        case 0x203:
            ccp = "Used native capacity partitions";
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            volume_stats_partition(ccp, bp + 4, pl - 4, false, true, op,
                                   jo3p);
            break;
        case 0x204:
            ccp = "Remaining native capacity partitions";
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            volume_stats_partition(ccp, bp + 4, pl - 4, false, true, op,
                                   jo3p);
            break;
        case 0x300:
            ccp = "Mount history";
            if (jsp->pr_as_json)
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            volume_stats_history(ccp, bp + 4, pl - 4, op, jo3p);
            break;

        default:
            if (pc >= 0xf000) {
                    if (op->exclude_vendor) {
                    skip_out = true;
                    if ((op->verbose > 0) && (0 == op->do_brief) &&
                        (! evsm_output)) {
                        evsm_output = true;
                        sgj_pr_hr(jsp, "  %s parameter(s) being ignored\n",
                                  vend_spec);
                    }
                } else
                    sgj_pr_hr(jsp, "  %s %s (0x%x), payload in hex\n",
                              vend_spec, param_c, pc);
            } else
                sgj_pr_hr(jsp, "  %s %s (0x%x), payload in hex\n", rsv_s,
                          param_c, pc);
            if (skip_out)
                skip_out = false;
            else {
                hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
            }
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL,
                                   (pc >= 0xf000) ? vend_spec : rsv_s);
                sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp + 4, pl - 4);
            }
            break;
        }
        if (is_count || is_str) {
            bool is_unkn = false;
            uint64_t ull;
            const char * cc2p = NULL;

            if (is_str)
                sgj_pr_hr(jsp, "  %s: %.*s\n", ccp, pl - 4, bp + 4);
            else {      /* is_count */
                bool all_ffs = sg_all_ffs(bp + 4, pl - 4);

                if (is_num_or && all_ffs)
                    is_unkn = true;
                ull = sg_get_unaligned_be(pl - 4, bp + 4);
                if (is_ms) {
                    cc2p = "[unit: millisecond]";
                    sgj_pr_hr(jsp, "  %s: %" PRIu64 " milliseconds\n", ccp,
                              ull);
                } else if (is_mb) {
                    cc2p = "[unit: megabyte]";
                    if (is_unkn)
                        sgj_pr_hr(jsp, "  %s: %s\n", ccp, unkn_s);
                    else
                        sgj_pr_hr(jsp, "  %s: %" PRIu64 " megabytes\n", ccp,
                                  ull);
                } else {
                    if (is_unkn)
                        sgj_pr_hr(jsp, "  %s: %s\n", ccp, unkn_s);
                    else
                        sgj_pr_hr(jsp, "  %s: %" PRIu64 "\n", ccp, ull);
                }
            }
            if (jsp->pr_as_json) {
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
                if (is_str)
                    sgj_js_nv_s_len_chk(jsp, jo3p, ccp, bp + 4, pl - 4);
                else
                    sgj_js_nv_ihexstr_nex(jsp, jo3p, "value", ull, true, NULL,
                                          is_unkn ? unkn_s : NULL, cc2p);
            }
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* TAPE_ALERT_LPAGE [0x2e] <ta> */
static bool
show_tape_alert_ssc_page(const uint8_t * resp, int len,
                         struct opts_t * op, sgj_opaque_p jop)
{
    const bool no_ta_strs = (NULL == sg_lib_tapealert_strs[0]);
    int num, pl, pc, flag;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * const ta_lp = "TapeAlert log page";

    /* N.B. the Tape alert log page for smc-3 is different */
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        sgj_pr_hr(jsp, "%s (ssc-3) [0x2e]\n", ta_lp);
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, ta_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "tapealert_log_parameters");
    }
    num = len - 4;
    bp = &resp[0] + 4;

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        flag = bp[4] & 1;
        b[0] = '\0';
        ccp = NULL;
        if (pc > 0x40)
            ccp = rsv_s;
        else if (! no_ta_strs)
            ccp = sg_lib_tapealert_strs[pc];

        if (op->verbose && (0 == op->do_brief) && flag)
            snprintf(b, blen, "  >>>> ");
        if ((0 == op->do_brief) || op->verbose || flag) {
            if (no_ta_strs)
                sgj_pr_hr(jsp, "%s  No string available for code 0x%x, "
                          "flag: %d\n", b, pc, flag);
            else if (pc <= 0x40)
                sgj_pr_hr(jsp, "%s  %s: %d\n", b, ccp, flag);
            else
                sgj_pr_hr(jsp, "%s  Reserved %s 0x%x, flag: %d\n", b,
                          param_c, pc, flag);
        }
        if (jsp->pr_as_json) {
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            sgj_js_nv_i(jsp, jo3p, "flag", flag);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* 0x37 */
static bool
show_seagate_cache_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    bool skip = false;
    int num, pl, pc;
    int bsti = 0;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    char b[128];
    static const int blen = sizeof(b);

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (resp[1] > 0) {
            sgj_pr_hr(jsp, "Suspicious page 0x37, SPF=0 but subpage=0x%x\n",
                      resp[1]);
            if (op->verbose)
                sgj_pr_hr(jsp, "... try vendor=wdc\n");
            if (op->do_brief > 0)
                return true;
        } else
            sgj_pr_hr(jsp, "Seagate cache page [0x37]\n");
    }
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }

        ccp = NULL;
        switch (pc) {
        case 0:
            ++bsti;
            if (bsti < 2)
                ccp = "Blocks sent to initiator";
            else
                skip = true;
            break;
        case 1:
            ccp = "Blocks received from initiator";
            break;
        case 2:
            ccp = "Blocks read from cache and sent to initiator";
            break;
        case 3:
            ccp = "Number of read and write commands whose size "
                  "<= segment size";
            break;
        case 4:
            ccp = "Number of read and write commands whose size "
                  "> segment size";
            break;
        default:
            snprintf(b, blen, "Unknown Seagate %s = 0x%x", param_c, pc);
            ccp = b;
            break;
        }
        if (skip)
            skip = false;
        else {
            sgj_pr_hr(jsp, "  %s = %" PRIu64 "\n", ccp,
                      sg_get_unaligned_be(pl - 4, bp + 4));
            if (op->do_pcb)
                sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        }
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* 0x37 */
static bool
show_hgst_misc_page(const uint8_t * resp, int len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool valid = false;
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("HGST/WDC miscellaneous page [0x37, 0x%x]\n",
               op->decod_subpg_code);
    num = len - 4;
    if (num < 0x30) {
        printf("HGST/WDC miscellaneous page too short (%d) < 48\n", num);
        return valid;
    }
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        switch (pc) {
        case 0:
            valid = true;
            printf("  Power on hours = %u\n", sg_get_unaligned_be32(bp + 4));
            printf("  Total Bytes Read = %" PRIu64 "\n",
                   sg_get_unaligned_be64(bp + 8));
            printf("  Total Bytes Written = %" PRIu64 "\n",
                   sg_get_unaligned_be64(bp + 16));
            printf("  Max Drive Temp (Celsius) = %u\n", bp[24]);
            printf("  GList Size = %u\n", sg_get_unaligned_be16(bp + 25));
            printf("  Number of Information Exceptions = %u\n", bp[27]);
            printf("  MED EXC = %u\n", !! (0x80 & bp[28]));
            printf("  HDW EXC = %u\n", !! (0x40 & bp[28]));
            printf("  Total Read Commands = %" PRIu64 "\n",
                   sg_get_unaligned_be64(bp + 29));
            printf("  Total Write Commands = %" PRIu64 "\n",
                   sg_get_unaligned_be64(bp + 37));
            printf("  Flash Correction Count = %u\n",
                   sg_get_unaligned_be16(bp + 46));
            break;
        default:
            valid = false;
            printf("  Unknown HGST/WDC %s = 0x%x\n", param_c, pc);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return valid;
}

/* 0x3e */
static bool
show_seagate_factory_page(const uint8_t * resp, int len,
                          struct opts_t * op, sgj_opaque_p jop)
{
    bool valid = false;
    int num, pl, pc;
    const uint8_t * bp;
    uint64_t ull;
    char str[PCB_STR_LEN];

if (jop) { };
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Seagate/Hitachi factory page [0x3e]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        valid = true;
        switch (pc) {
        case 0:
            printf("  number of hours powered up");
            break;
        case 8:
            printf("  number of minutes until next internal SMART test");
            break;
        default:
            valid = false;
            printf("  Unknown Seagate/Hitachi %s = 0x%x", param_c, pc);
            break;
        }
        if (valid) {
            ull = sg_get_unaligned_be(pl - 4, bp + 4);
            if (0 == pc)
                printf(" = %.2f", ((double)ull) / 60.0 );
            else
                printf(" = %" PRIu64 "", ull);
        }
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

static void
show_unknown_page(int subpg_code, const uint8_t * resp, int len,
                  struct opts_t * op, sgj_opaque_p jop)
{
    int pg_code, k, n;
    char * cp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * unable_s = "Unable to decode page";

    pg_code = resp[0] & 0x3f;
    if (0 == op->do_hex) {
        if (subpg_code > 0)
            sgj_pr_hr(jsp, "%s = 0x%x, subpage = 0x%x, here is hex:\n",
                      unable_s, pg_code, subpg_code);
        else
            sgj_pr_hr(jsp, "%s = 0x%x, here is hex:\n", unable_s,
                      pg_code);
    }
    if (jsp->pr_as_json) {
        if (subpg_code > 0)
            snprintf(b, blen, "%s_0x%x_0x%x", lp_sn, pg_code, subpg_code);
        else
            snprintf(b, blen, "%s_0x%x", lp_sn, pg_code);
        jop = sgj_named_subobject_r(jsp, jop, b);
        sgj_js_nv_ihex(jsp, jop, pg_c_sn, pg_code);
        sgj_js_nv_ihex(jsp, jop, spg_c_sn, subpg_code);
        sgj_js_nv_ihexstr_nex(jsp, jop, "page_length", len, true,
                              NULL, NULL, "[unit: byte]");
        if (len > 0) {
            bool gt256 = (len > 256);
            const uint8_t * bp = resp;
            int rem;

            if (gt256)
                jap = sgj_named_subarray_r(jsp, jop, "in_hex_list");
            for (k = 0; k < len; bp += 256, k += 256) {
                rem = len - k;
                if (gt256)
                    jo2p = sgj_new_unattached_object_r(jsp);
                else
                    jo2p = jop;
                sgj_js_nv_hex_bytes(jsp, jo2p, "in_hex", bp,
                                    (rem > 256) ? 256 : rem);
                if (gt256)
                    sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
        }
    }
    if ((len > 128) && (0 == op->do_hex)) {
        hex2str(resp, 64, "  ", op->h2s_oformat, blen, b);
        sgj_pr_hr(jsp, "%s\n", b);
        sgj_pr_hr(jsp, "  .....  [truncated after 64 of %d bytes (use "
                  "'-H' to see the rest)]\n", len);
    } else {
        if (0 == op->do_hex) {
            n = len * 4 + 32;
            cp = (char *)malloc(n);
            if (NULL == cp)
                return;
            hex2str(resp, len, "  ", op->h2s_oformat, n, cp);
            sgj_pr_hr(jsp, "%s\n", cp);
            free(cp);
        } else      /* don't care about JSON when do_hex > 0 */
            hex2stdout(resp, len, op->dstrhex_no_ascii);
    }
}

static void
decode_page_contents(const uint8_t * resp, int len, struct opts_t * op,
                     sgj_opaque_p jop)
{
    bool spf;
    bool done = false;
    int pg_code, subpg_code, vpn;
    const struct log_elem * lep;

    if (len < 3) {
        pr2serr("%s: response has bad length: %d\n", __func__, len);
        return;
    }
    spf = !!(resp[0] & 0x40);
    pg_code = resp[0] & 0x3f;
    if ((VP_HITA == op->vend_prod_num) && (pg_code >= 0x30))
        subpg_code = resp[1];   /* Hitachi don't set SPF on VS pages */
    else
        subpg_code = spf ? resp[1] : NOT_SPG_SUBPG;
    op->decod_subpg_code = subpg_code;
    if ((SUPP_SPGS_SUBPG == subpg_code) && (SUPP_PAGES_LPAGE != pg_code)) {
        done = show_supported_pgs_sub_page(resp, len, op, jop);
        if (done)
            return;
    }
    vpn = (op->vend_prod_num >= 0) ? op->vend_prod_num : op->deduced_vpn;
    lep = pg_subpg_pdt_search(pg_code, subpg_code, op->dev_pdt, vpn);

    /* Below is the indirect function call to all the show_* functions */
    if (lep && lep->show_pagep)
        done = (*lep->show_pagep)(resp, len, op, jop);

    if (! done)
        show_unknown_page(subpg_code, resp, len, op, jop);
}

/* Tries to fetch the TEMPERATURE_LPAGE [0xd] page first. If that fails
 * tries to get the Informational Exceptions (IE_LPAGE) page. */
static int
fetchTemperature(int sg_fd, uint8_t * resp, int max_len, struct opts_t * op,
                 sgj_opaque_p jop)
{
    int len;
    int res = 0;

    op->pg_code = TEMPERATURE_LPAGE;
    op->subpg_code = NOT_SPG_SUBPG;
    res = do_logs(sg_fd, resp, max_len, op);
    if (0 == res) {
        len = sg_get_unaligned_be16(resp + 2) + 4;
        if (op->do_raw)
            dStrRaw(resp, len);
        else if (op->do_hex)
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        else
            show_temperature_page(resp, len, op, jop);
    } else if (SG_LIB_CAT_NOT_READY == res)
        pr2serr("%s: Device not ready\n", __func__);
    else {
        op->pg_code = IE_LPAGE;
        res = do_logs(sg_fd, resp, max_len, op);
        if (0 == res) {
            len = sg_get_unaligned_be16(resp + 2) + 4;
            if (op->do_raw)
                dStrRaw(resp, len);
            else if (op->do_hex)
                hex2stdout(resp, len, op->dstrhex_no_ascii);
            else
                show_ie_page(resp, len, op, jop);
        } else
            pr2serr("Unable to find temperature in either Temperature or "
                    "IE log page\n");
    }
    sg_cmds_close_device(sg_fd);
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}

/* Returns 0 if successful else SG_LIB_SYNTAX_ERROR. */
static int
decode_pg_arg(struct opts_t * op)
{
    int nn;
    const struct log_elem * lep;
    char * cp;

    if (isalpha((uint8_t)op->pg_arg[0])) {
        char b[80];

        if (strlen(op->pg_arg) >= (sizeof(b) - 1)) {
            pr2serr("argument to '--page=' is too long\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        strcpy(b, op->pg_arg);
        cp = (char *)strchr(b, ',');
        if (cp)
            *cp = '\0';
        lep = acron_search(b);
        if (NULL == lep) {
            pr2serr("bad argument to '--page=' no acronyn match to "
                    "'%s'\n", b);
            pr2serr("  Try using '-e' or'-ee' to see available "
                    "acronyns\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        op->lep = lep;
        op->pg_code = lep->pg_code;
        if (cp) {
            nn = sg_get_num_nomult(cp + 1);
            if ((nn < 0) || (nn > 255)) {
                pr2serr("Bad second value in argument to "
                        "'--page='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->subpg_code = nn;
        } else
            op->subpg_code = lep->subpg_code;
    } else { /* numeric arg: either 'pg_num' or 'pg_num,subpg_num' */
        int n;

        cp = (char *)strchr(op->pg_arg, ',');
        n = sg_get_num_nomult(op->pg_arg);
        if ((n < 0) || (n > 63)) {
            pr2serr("Bad argument to '--page='\n");
            usage(1);
            return SG_LIB_SYNTAX_ERROR;
        }
        if (cp) {
            nn = sg_get_num_nomult(cp + 1);
            if ((nn < 0) || (nn > 255)) {
                pr2serr("Bad second value in argument to "
                        "'--page='\n");
                usage(1);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else
            nn = 0;
        op->pg_code = n;
        op->subpg_code = nn;
    }
    return 0;
}

/* Since the Supported subpages page is sitting in the rsp_buff which is
 * MX_ALLOC_LEN bytes long (~ 64 KB) then move it (from rsp_buff+0 to
 * rsp_buff+pg_len-1) to the top end of that buffer. Then there is room
 * to merge supp_pgs_rsp with the supported subpages with the result back
 * at the bottom of rsp_buff. The new length of the merged subpages page
 * (excluding its 4 byte header) is returned.
 * Assumes both pages are in ascending order (as required by SPC-4). */
static int
merge_both_supported(const uint8_t * supp_pgs_p, int su_p_pg_len, int pg_len)
{
    uint8_t pg;
    int k, kp, ks;
    int max_blen = (2 * su_p_pg_len) + pg_len;
    uint8_t * m_buff = rsp_buff + (rsp_buff_sz - pg_len);
    uint8_t * r_buff = rsp_buff + 4;

    if (pg_len > 0)
        memmove(m_buff, rsp_buff + 4, pg_len);
    for (k = 0, kp = 0, ks = 0; k < max_blen; k += 2) {
        if (kp < su_p_pg_len)
            pg = supp_pgs_p[kp];
        else
            pg = 0xff;
        if (ks < pg_len) {
            if (m_buff[ks] < pg) {
                r_buff[k] = m_buff[ks];
                r_buff[k + 1] = m_buff[ks + 1];
                ks += 2;
            } else if ((m_buff[ks] == pg) && (m_buff[ks + 1] == 0)) {
                r_buff[k] = m_buff[ks];
                r_buff[k + 1] = m_buff[ks + 1];
                ks += 2;
                ++kp;
            } else {
                r_buff[k] = pg;
                r_buff[k + 1] = 0;
                ++kp;
            }
        } else {
            if (0xff == pg)
                break;
            r_buff[k] = pg;
            r_buff[k + 1] = 0;
            ++kp;
        }
    }
    sg_put_unaligned_be16(k, rsp_buff + 2);
    return k;
}


int
main(int argc, char * argv[])
{
    bool as_json;
    int k, nn, pg_len, res, vb;
    int resp_len = 0;
    int su_p_pg_len = 0;
    int in_len = -1;
    int sg_fd = -1;
    int ret = 0;
    uint8_t * parr;
    uint8_t * free_parr = NULL;
    struct opts_t * op;
    sgj_state * jsp;
    sgj_opaque_p jop = NULL;
    struct sg_simple_inquiry_resp inq_out;
    struct opts_t opts SG_C_CPP_ZERO_INIT;
    uint8_t supp_pgs_rsp[256];
    char b[128];
    static const int blen = sizeof(b);

    op = &opts;
    if (getenv("SG3_UTILS_INVOCATION"))
        sg_rep_invocation(MY_NAME, version_str, argc, argv, NULL);
    /* N.B. some disks only give data for current cumulative */
    op->page_control = 1;
    op->dev_pdt = DEF_DEV_PDT;
    op->vend_prod_num = VP_NONE;
    op->deduced_vpn = VP_NONE;
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (op->do_help) {
        usage_for(op->do_help, op);
        return 0;
    }
    jsp = &op->json_st;
    if (op->do_json) {
        if (! sgj_init_state(jsp, op->json_arg)) {
            int bad_char = jsp->first_bad_char;
            char e[1500];

            if (bad_char) {
                pr2serr("bad argument to --json= option, unrecognized "
                        "character '%c'\n\n", bad_char);
            }
            sg_json_usage(0, e, sizeof(e));
            pr2serr("%s", e);
            return SG_LIB_SYNTAX_ERROR;
        }
        if (op->do_name) {
            pr2serr(">>> The --json option is superior to the --name "
                    "option.\n");
            pr2serr(">>> Ignoring the --name option.\n");
            op->do_name = false;
        }
        jop = sgj_start_r(MY_NAME, version_str, argc, argv, jsp);
    }
    as_json = jsp->pr_as_json;

#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (op->verbose_given && op->version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->verbose = 0;
    } else if (! op->verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (op->verbose_given && op->version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }
    if (op->do_hex > 0) {
        if (op->do_hex > 2) {
            op->dstrhex_no_ascii = -1;
            op->h2s_oformat = 1;
        } else {
            op->dstrhex_no_ascii = (1 == op->do_hex);
            op->h2s_oformat = (1 == op->do_hex);
        }
    } else {
        if (op->undefined_hex > 0) {
            if (op->undefined_hex > 2) {
                op->dstrhex_no_ascii = -1;
                op->h2s_oformat = 1;
            } else {
                op->dstrhex_no_ascii = (1 == op->undefined_hex);
                op->h2s_oformat = (1 == op->undefined_hex);
            }
        } else {       /* default when no --hex nor --undefined */
            op->dstrhex_no_ascii = -1;
            op->h2s_oformat = 1;
        }
    }
    vb = op->verbose;
    if (op->vend_prod) {
        if (0 == memcmp("-1", op->vend_prod,3))
            k = VP_NONE;
        else if (isdigit((uint8_t)op->vend_prod[0]))
            k = sg_get_num_nomult(op->vend_prod);
        else
            k = find_vpn_by_acron(op->vend_prod);
        op->vend_prod_num = k;
        if (VP_ALL == k)
            ;
        else if ((k < 0) || (k > (32 - MVP_OFFSET))) {
            pr2serr("Bad vendor/product acronym after '--vendor=' "
                    " ('-M ') option\n");
            enumerate_vp();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (op->do_enumerate > 0) {
        if (op->device_name && vb)
            pr2serr("Warning: device: %s is being ignored\n",
                    op->device_name);
        enumerate_pages(op);
        return 0;
    }
    if (op->in_fn) {
        if (op->maxlen_given) {
            if (op->maxlen > MX_INLEN_ALLOC_LEN) {
                pr2serr("bad argument to '--maxlen=' when --in= given, from "
                        "2 to %d (inclusive) expected\n", MX_INLEN_ALLOC_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            rsp_buff_sz = op->maxlen;
        } else
            rsp_buff_sz = DEF_INLEN_ALLOC_LEN;
    } else {
        if (op->maxlen_given) {
            if (op->maxlen > MX_ALLOC_LEN) {
                pr2serr("bad argument to '--maxlen=', from 2 to 65535 "
                        "(inclusive) expected\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            rsp_buff_sz = op->maxlen;
        }
    }
    rsp_buff = sg_memalign(rsp_buff_sz, 0 /* page aligned */, &free_rsp_buff,
                           false);
    if (NULL == rsp_buff) {
        pr2serr("Unable to allocate %d bytes on the heap\n", rsp_buff_sz);
        ret = sg_convert_errno(ENOMEM);
        goto err_out;
    }
    if (NULL == op->device_name) {
        if (op->in_fn) {
            bool found = false;
            bool r_spf = false;
            uint16_t u;
            int pg_code, subpg_code, pdt, n;
            const struct log_elem * lep;
            const uint8_t * bp;

            if ((ret = sg_f2hex_arr(op->in_fn, op->do_raw, false, rsp_buff,
                                    &in_len, rsp_buff_sz)))
                goto err_out;
            if (vb > 2)
                pr2serr("Read %d [0x%x] bytes of user supplied data\n",
                        in_len, in_len);
            if (op->do_raw)
                op->do_raw = false;    /* can interfere on decode */
            if (in_len < 4) {
                pr2serr("--in=%s only decoded %d bytes (needs 4 at least)\n",
                        op->in_fn, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
                goto err_out;
            }
            if (op->pg_arg) {
                if (decode_pg_arg(op))
                    return SG_LIB_SYNTAX_ERROR;
                if (op->subpg_code > 0)
                    r_spf = true;
            }

            for (bp = rsp_buff, k = 0; k < in_len; bp += n, k += n) {
                bool spf = !! (bp[0] & 0x40);

                pg_code = bp[0] & 0x3f;
                if ((VP_HITA == op->vend_prod_num) && (pg_code >= 0x30))
                    subpg_code = bp[1];/* Hitachi don't set SPF on VS pages */
                else
                    subpg_code = spf ? bp[1] : NOT_SPG_SUBPG;
                u = sg_get_unaligned_be16(bp + 2);
                n = u + 4;
                if (n > (in_len - k)) {
                    pr2serr("bytes decoded remaining (%d) less than lpage "
                            "length (%d), try decoding anyway\n", in_len - k,
                            n);
                    n = in_len - k;
                }
                if (op->pg_arg) {
                    if ((NOT_SPG_SUBPG == op->subpg_code) && spf) {
                        continue;
                    } else if ((! spf) && (! r_spf)) {
                        if (pg_code != op->pg_code)
                            continue;
                    } else if ((SUPP_SPGS_SUBPG == op->subpg_code) &&
                             (SUPP_PAGES_LPAGE != op->pg_code)) {
                        if (pg_code != op->pg_code)
                            continue;
                    } else if ((SUPP_SPGS_SUBPG != op->subpg_code) &&
                               (SUPP_PAGES_LPAGE == op->pg_code)) {
                        if (subpg_code != op->subpg_code)
                            continue;
                    } else if ((SUPP_SPGS_SUBPG != op->subpg_code) &&
                               (SUPP_PAGES_LPAGE != op->pg_code)) {
                        if ((pg_code != op->pg_code) ||
                            (subpg_code != op->subpg_code))
                            continue;
                    }
                }
                if (op->exclude_vendor && (pg_code >= 0x30))
                    continue;
                found = true;
                if (op->do_hex > 2) {
                     hex2fp(bp, n, NULL, op->h2s_oformat, stdout);
                     continue;
                }
                pdt = op->dev_pdt;
                lep = pg_subpg_pdt_search(pg_code, subpg_code, pdt,
                                          op->vend_prod_num);
                if (lep) {
                    /* Below is the indirect function call to all the
                     * show_* functions */
                    if (lep->show_pagep)
                        (*lep->show_pagep)(bp, n, op, jop);
                    else {
                        sgj_pr_hr(jsp, "Unable to decode %s [%s]\n",
                                  lep->name, lep->acron);
                        show_unknown_page(subpg_code, bp, n, op, jop);
                    }
                } else {
                    nn = sg_scnpr(b, blen, "Unable to decode page=0x%x",
                                  pg_code);
                    if (subpg_code > 0)
                        sg_scnpr(b + nn, blen - nn, ", subpage=0x%x",
                                 subpg_code);
                    if (pdt >= 0)
                        sg_scnpr(b + nn, blen - nn, ", pdt=0x%x\n", pdt);
                    sgj_pr_hr(jsp, "%s\n", b);
                    show_unknown_page(subpg_code, bp, n, op, jop);
                }
            }           /* end of page/subpage search loop */
            if (op->pg_arg && (! found)) {
                nn = sg_scnpr(b, blen, "Unable to find page=0x%x",
                              op->pg_code);
                if (op->subpg_code > 0)
                    sg_scnpr(b + nn, blen - nn, ", subpage=0x%x",
                             op->subpg_code);
                sgj_pr_hr(jsp, "%s\n", b);
                if (jsp->pr_as_json)
                    sgj_js_nv_i(jsp, jop, "page_not_found", 1);
            }
            ret = 0;
            goto err_out;
        }
        if (op->pg_arg) {         /* do this for 'sg_logs -p xxx' */
            ret = decode_pg_arg(op);
            if (ret)
                goto err_out;
        }
        pr2serr("No DEVICE argument given\n\n");
        usage_for(1, op);
        ret = SG_LIB_FILE_ERROR;
        goto err_out;
    }
    if (op->do_select) {
        if (op->do_temperature) {
            pr2serr("--select cannot be used with --temperature\n");
            ret = SG_LIB_CONTRADICT;
            goto err_out;
        }
        if (op->do_transport) {
            pr2serr("--select cannot be used with --transport\n");
            ret = SG_LIB_CONTRADICT;
            goto err_out;
        }
    } else if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
    }
    if (op->do_all) {
        if (op->do_select) {
            pr2serr("--all conflicts with --select\n");
            ret = SG_LIB_CONTRADICT;
            goto err_out;
        }
    }
    if (op->in_fn) {
        if (! op->do_select) {
            pr2serr("--in=FN can only be used with --select when DEVICE "
                    "given\n");
            ret = SG_LIB_CONTRADICT;
            goto err_out;
        }
        if ((ret = sg_f2hex_arr(op->in_fn, op->do_raw, false, rsp_buff,
                                &in_len, rsp_buff_sz)))
            goto err_out;
        if (vb > 2)
            pr2serr("Read %d [0x%x] bytes of user supplied data\n", in_len,
                    in_len);
    }
    if (op->pg_arg) {
        if (op->do_all) {
            if (0 == op->do_brief)
                pr2serr(">>> warning: --page=%s ignored when --all given\n",
                        op->pg_arg);
        } else {
            ret = decode_pg_arg(op);
            if (ret)
                goto err_out;
        }
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    win32_spt_init_state = !! scsi_pt_win32_spt_state();
    if (vb > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                win32_spt_init_state ? "direct" : "indirect");
#endif
#endif
    sg_fd = sg_cmds_open_device(op->device_name, op->o_readonly, vb);
    if ((sg_fd < 0) && (! op->o_readonly))
        sg_fd = sg_cmds_open_device(op->device_name, true /* ro */, vb);
    if (sg_fd < 0) {
        pr2serr("error opening file: %s: %s \n", op->device_name,
                safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto err_out;
    }
    if (op->do_list || op->do_all) {
        op->pg_code = SUPP_PAGES_LPAGE;
        if ((op->do_list > 1) || (op->do_all > 1))
            op->subpg_code = SUPP_SPGS_SUBPG;
    }
    if (op->do_transport) {
        if ((op->pg_code > 0) || (op->subpg_code > 0) ||
            op->do_temperature) {
            pr2serr("'-T' should not be mixed with options implying other "
                    "pages\n");
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        op->pg_code = PROTO_SPECIFIC_LPAGE;
    }

    memset(&inq_out, 0, sizeof(inq_out));
    if (op->no_inq < 2) {
        if (sg_simple_inquiry(sg_fd, &inq_out, true, vb)) {
            pr2serr("%s doesn't respond to a SCSI INQUIRY\n",
                    op->device_name);
            ret = SG_LIB_CAT_OTHER;
            goto err_out;
        }
        op->dev_pdt = inq_out.peripheral_type;
        if ((! op->do_raw) && (0 == op->do_hex) && (! op->do_name) &&
            (0 == op->no_inq) && (0 == op->do_brief))
            sgj_pr_hr(jsp, "    %.8s  %.16s  %.4s\n", inq_out.vendor,
                      inq_out.product, inq_out.revision);
        memcpy(t10_vendor_str, inq_out.vendor, 8);
        memcpy(t10_product_str, inq_out.product, 16);
        if (VP_NONE == op->vend_prod_num)
            op->deduced_vpn = find_vpn_by_inquiry();
    }

    if (op->do_temperature) {
        ret = fetchTemperature(sg_fd, rsp_buff, SHORT_RESP_LEN, op, jop);
        goto err_out;
    }
    if (op->do_select) {
        k = sg_ll_log_select(sg_fd, op->do_pcreset, op->do_sp,
                             op->page_control, op->pg_code, op->subpg_code,
                             rsp_buff, ((in_len > 0) ? in_len : 0), true, vb);
        if (k) {
            if (SG_LIB_CAT_NOT_READY == k)
                pr2serr("log_select: device not ready\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == k)
                pr2serr("log_select: field in cdb illegal\n");
            else if (SG_LIB_CAT_INVALID_OP == k)
                pr2serr("log_select: not supported\n");
            else if (SG_LIB_CAT_UNIT_ATTENTION == k)
                pr2serr("log_select: unit attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == k)
                pr2serr("log_select: aborted command\n");
            else
                pr2serr("log_select: failed (%d), try '-v' for more "
                        "information\n", k);
        }
        ret = (k >= 0) ?  k : SG_LIB_CAT_OTHER;
        goto err_out;
    }
    if (op->do_list > 2) {
        const int supp_pgs_blen = sizeof(supp_pgs_rsp);

        op->subpg_code = NOT_SPG_SUBPG;
        res = do_logs(sg_fd, supp_pgs_rsp, supp_pgs_blen, op);
        if (res != 0)
            goto bad;
        su_p_pg_len = sg_get_unaligned_be16(supp_pgs_rsp + 2);
        if ((su_p_pg_len + 4) > supp_pgs_blen) {
            pr2serr("Supported log pages log page is too long [%d], exit\n",
                    su_p_pg_len);
            res = SG_LIB_CAT_OTHER;
            goto bad;
        }
        op->subpg_code = SUPP_SPGS_SUBPG;
    }
    resp_len = (op->maxlen > 0) ? op->maxlen : MX_ALLOC_LEN;
    res = do_logs(sg_fd, rsp_buff, resp_len, op);
    if (0 == res) {
        pg_len = sg_get_unaligned_be16(rsp_buff + 2);
        if ((pg_len + 4) > resp_len) {
            pr2serr("Only fetched %d bytes of response (available: %d "
                    "bytes)\n    truncate output\n",
                   resp_len, pg_len + 4);
            pg_len = resp_len - 4;
        }
        goto good;
    }
bad:
    if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("%snot supported\n", ls_s);
    else if (SG_LIB_CAT_NOT_READY == res)
        pr2serr("%sdevice not ready\n", ls_s);
    else if (SG_LIB_CAT_ILLEGAL_REQ == res) {
        if ((op->do_list > 2) && (SUPP_SPGS_SUBPG == op->subpg_code)) {
            rsp_buff[0] = 0x40;
            rsp_buff[1] = SUPP_SPGS_SUBPG;
            pg_len = 0;
            res = 0;
            if (op->verbose)
                pr2serr("%sfield in cdb illegal in [0,0xff], "
                        "continue with merge\n", ls_s);
            goto good;
        } else
            pr2serr("%sfield in cdb illegal\n", ls_s);
    } else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        pr2serr("%sunit attention\n", ls_s);
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        pr2serr("%saborted command\n", ls_s);
    else if (SG_LIB_TRANSPORT_ERROR == res)
        pr2serr("%stransport error\n", ls_s);
    else
        pr2serr("%sother error [%d]\n", ls_s, res);
    ret = res;
    goto err_out;

good:
    if (op->do_list > 2)
        pg_len = merge_both_supported(supp_pgs_rsp + 4, su_p_pg_len, pg_len);

    if (0 == op->do_all) {
        if (op->filter_given) {
            if (op->do_hex > 2)
                hex2stdout(rsp_buff, pg_len + 4, op->dstrhex_no_ascii);
            else
                decode_page_contents(rsp_buff, pg_len + 4, op, jop);
        } else if (op->do_raw)
            dStrRaw(rsp_buff, pg_len + 4);
        else if (op->do_hex > 1)
            hex2stdout(rsp_buff, pg_len + 4, op->dstrhex_no_ascii);
        else if (pg_len > 1) {
            if (op->do_hex) {
                if (rsp_buff[0] & 0x40)
                    printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, "
                           "page_len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                           !!(rsp_buff[0] & 0x80), pg_len);
                else
                    printf("Log page code=0x%x, DS=%d, SPF=0, page_len=0x%x\n",
                           rsp_buff[0] & 0x3f, !!(rsp_buff[0] & 0x80), pg_len);
                hex2stdout(rsp_buff, pg_len + 4, op->dstrhex_no_ascii);
            }
            else
                decode_page_contents(rsp_buff, pg_len + 4, op, jop);
        }
    }
    ret = res;

    if (op->do_all && (pg_len > 1)) {
        int my_len = pg_len;
        bool spf;

        parr = sg_memalign(parr_sz, 0, &free_parr, false);
        if (NULL == parr) {
            pr2serr("Unable to allocate heap for parr\n");
            ret = sg_convert_errno(ENOMEM);
            goto err_out;
        }
        spf = !!(rsp_buff[0] & 0x40);
        if (my_len > parr_sz) {
            pr2serr("Unexpectedly large page_len=%d, trim to %d\n", my_len,
                    parr_sz);
            my_len = parr_sz;
        }
        memcpy(parr, rsp_buff + 4, my_len);
        for (k = 0; k < my_len; ++k) {
            op->pg_code = parr[k] & 0x3f;
            if (spf)
                op->subpg_code = parr[++k];
            else
                op->subpg_code = NOT_SPG_SUBPG;

            /* Some devices include [pg_code, 0xff] for all pg_code > 0 */
            if ((op->pg_code > 0) && (SUPP_SPGS_SUBPG == op->subpg_code))
                continue;       /* skip since no new information */
            if ((op->pg_code >= 0x30) && op->exclude_vendor)
                continue;
            if (! op->do_raw)
                sgj_pr_hr(jsp, "\n");
            res = do_logs(sg_fd, rsp_buff, resp_len, op);
            if (0 == res) {
                pg_len = sg_get_unaligned_be16(rsp_buff + 2);
                if ((pg_len + 4) > resp_len) {
                    pr2serr("Only fetched %d bytes of response, truncate "
                            "output\n", resp_len);
                    pg_len = resp_len - 4;
                }
                if (op->do_raw && (! op->filter_given))
                    dStrRaw(rsp_buff, pg_len + 4);
                else if (op->do_hex > 4)
                    decode_page_contents(rsp_buff, pg_len + 4, op, jop);
                else if (op->do_hex > 1)
                    hex2stdout(rsp_buff, pg_len + 4, op->dstrhex_no_ascii);
                else if (1 == op->do_hex) {
                    if (0 == op->do_brief) {
                        if (rsp_buff[0] & 0x40)
                            printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, "
                                   "page_len=0x%x\n", rsp_buff[0] & 0x3f,
                                   rsp_buff[1], !!(rsp_buff[0] & 0x80),
                                   pg_len);
                        else
                            printf("Log page code=0x%x, DS=%d, SPF=0, "
                                   "page_len=0x%x\n", rsp_buff[0] & 0x3f,
                                   !!(rsp_buff[0] & 0x80), pg_len);
                    }
                    hex2stdout(rsp_buff, pg_len + 4, op->dstrhex_no_ascii);
                }
                else
                    decode_page_contents(rsp_buff, pg_len + 4, op, jop);
            } else if (SG_LIB_CAT_INVALID_OP == res)
                pr2serr("%spage=0x%x,0x%x not supported\n", ls_s,
                        op->pg_code, op->subpg_code);
            else if (SG_LIB_CAT_NOT_READY == res)
                pr2serr("%sdevice not ready\n", ls_s);
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                pr2serr("%sfield in cdb illegal [page=0x%x,0x%x]\n", ls_s,
                        op->pg_code, op->subpg_code);
            else if (SG_LIB_CAT_UNIT_ATTENTION == res)
                pr2serr("%sunit attention\n", ls_s);
            else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                pr2serr("%saborted command\n", ls_s);
            else
                pr2serr("%sfailed, try '-v' for more information\n", ls_s);
        }
    }
err_out:
    if (free_rsp_buff)
        free(free_rsp_buff);
    if (free_parr)
        free(free_parr);
    if (sg_fd >= 0)
        sg_cmds_close_device(sg_fd);
    if (0 == vb) {
        if (! sg_if_can2stderr("sg_logs failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    if (as_json) {
        FILE * fp = stdout;

        if (op->js_file) {
            if ((1 != strlen(op->js_file)) || ('-' != op->js_file[0])) {
                fp = fopen(op->js_file, "w");   /* truncate if exists */
                if (NULL == fp) {
                    pr2serr("unable to open file: %s\n", op->js_file);
                    ret = SG_LIB_FILE_ERROR;
                }
            }
            /* '--js-file=-' will send JSON output to stdout */
        }
        if (fp)
            sgj_js2file(jsp, NULL, ret, fp);
        if (op->js_file && fp && (stdout != fp))
            fclose(fp);
        sgj_finish(jsp);
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
