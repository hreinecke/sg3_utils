/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 2000-2020 D. Gilbert
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
#include "sg_cmds_basic.h"
#ifdef SG_LIB_WIN32
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */
#endif
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.81 20200110";    /* spc6r01 + sbc4r17 */

#define MX_ALLOC_LEN (0xfffc)
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
#define BACKGROUND_SCAN_LPAGE 0x15
#define SAT_ATA_RESULTS_LPAGE 0x16
#define PROTO_SPECIFIC_LPAGE 0x18
#define STATS_LPAGE 0x19
#define PCT_LPAGE 0x1a
#define TAPE_ALERT_LPAGE 0x2e
#define IE_LPAGE 0x2f
#define NOT_SPG_SUBPG 0x0                       /* page: any */
#define SUPP_SPGS_SUBPG 0xff                    /* page: any */
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

/* Vendor product identifiers followed by associated mask values */
#define VP_NONE   (-1)
#define VP_SEAG   0
#define VP_HITA   1
#define VP_TOSH   2
#define VP_SMSTR  3
#define VP_LTO5   4
#define VP_LTO6   5
#define VP_ALL    99

#define MVP_OFFSET 8
/* MVO_STD or-ed with MVP_<vendor> is T10 defined lpage with vendor specific
 * parameter codes */
#define MVP_STD    (1 << (MVP_OFFSET - 1))
#define MVP_SEAG   (1 << (VP_SEAG + MVP_OFFSET))
#define MVP_HITA   (1 << (VP_HITA + MVP_OFFSET))
#define MVP_TOSH   (1 << (VP_TOSH + MVP_OFFSET))
#define MVP_SMSTR  (1 << (VP_SMSTR + MVP_OFFSET))
#define MVP_LTO5   (1 << (VP_LTO5 + MVP_OFFSET))
#define MVP_LTO6   (1 << (VP_LTO6 + MVP_OFFSET))

#define OVP_LTO    (MVP_LTO5 | MVP_LTO6)
#define OVP_ALL    (~0)


#define PCB_STR_LEN 128

#define LOG_SENSE_PROBE_ALLOC_LEN 4
#define LOG_SENSE_DEF_TIMEOUT 64        /* seconds */

static uint8_t * rsp_buff;
static uint8_t * free_rsp_buff;
static const int rsp_buff_sz = MX_ALLOC_LEN + 4;
static const int parr_sz = 4096;

static struct option long_options[] = {
        {"All", no_argument, 0, 'A'},   /* equivalent to '-aa' */
        {"all", no_argument, 0, 'a'},
        {"brief", no_argument, 0, 'b'},
        {"control", required_argument, 0, 'c'},
        {"enumerate", no_argument, 0, 'e'},
        {"filter", required_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"in", required_argument, 0, 'i'},
        {"inhex", required_argument, 0, 'i'},
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
        {"vendor", required_argument, 0, 'M'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    bool do_name;
    bool do_pcb;
    bool do_ppc;
    bool do_raw;
    bool do_pcreset;
    bool do_select;
    bool do_sp;
    bool do_temperature;
    bool do_transport;
    bool filter_given;
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
    const char * device_name;
    const char * in_fn;
    const char * pg_arg;
    const char * vend_prod;
    const struct log_elem * lep;
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
                       const struct opts_t * op);
                        /* Returns true if done */
};

struct vp_name_t {
    int vend_prod_num;       /* vendor/product identifier */
    const char * acron;
    const char * name;
    const char * t10_vendorp;
    const char * t10_productp;
};

static bool show_supported_pgs_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_supported_pgs_sub_page(const uint8_t * resp, int len,
                                        const struct opts_t * op);
static bool show_buffer_over_under_run_page(const uint8_t * resp, int len,
                                            const struct opts_t * op);
static bool show_error_counter_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_non_medium_error_page(const uint8_t * resp, int len,
                                       const struct opts_t * op);
static bool show_last_n_error_page(const uint8_t * resp, int len,
                                   const struct opts_t * op);
static bool show_format_status_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_last_n_deferred_error_page(const uint8_t * resp, int len,
                                            const struct opts_t * op);
static bool show_last_n_inq_data_ch_page(const uint8_t * resp, int len,
                                         const struct opts_t * op);
static bool show_last_n_mode_pg_data_ch_page(const uint8_t * resp, int len,
                                             const struct opts_t * op);
static bool show_lb_provisioning_page(const uint8_t * resp, int len,
                                      const struct opts_t * op);
static bool show_sequential_access_page(const uint8_t * resp, int len,
                                        const struct opts_t * op);
static bool show_temperature_page(const uint8_t * resp, int len,
                                  const struct opts_t * op);
static bool show_start_stop_page(const uint8_t * resp, int len,
                                 const struct opts_t * op);
static bool show_utilization_page(const uint8_t * resp, int len,
                                  const struct opts_t * op);
static bool show_app_client_page(const uint8_t * resp, int len,
                                 const struct opts_t * op);
static bool show_self_test_page(const uint8_t * resp, int len,
                                const struct opts_t * op);
static bool show_solid_state_media_page(const uint8_t * resp, int len,
                                        const struct opts_t * op);
static bool show_device_stats_page(const uint8_t * resp, int len,
                                   const struct opts_t * op);
static bool show_media_stats_page(const uint8_t * resp, int len,
                                  const struct opts_t * op);
static bool show_dt_device_status_page(const uint8_t * resp, int len,
                                       const struct opts_t * op);
static bool show_tapealert_response_page(const uint8_t * resp, int len,
                                         const struct opts_t * op);
static bool show_requested_recovery_page(const uint8_t * resp, int len,
                                         const struct opts_t * op);
static bool show_background_scan_results_page(const uint8_t * resp, int len,
                                              const struct opts_t * op);
static bool show_zoned_block_dev_stats(const uint8_t * resp, int len,
                                       const struct opts_t * op);
static bool show_pending_defects_page(const uint8_t * resp, int len,
                                      const struct opts_t * op);
static bool show_background_op_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_lps_misalignment_page(const uint8_t * resp, int len,
                                       const struct opts_t * op);
static bool show_element_stats_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_service_buffer_info_page(const uint8_t * resp, int len,
                                          const struct opts_t * op);
static bool show_ata_pt_results_page(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_tape_diag_data_page(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_mchanger_diag_data_page(const uint8_t * resp, int len,
                                         const struct opts_t * op);
static bool show_non_volatile_cache_page(const uint8_t * resp, int len,
                                         const struct opts_t * op);
static bool show_volume_stats_pages(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_protocol_specific_page(const uint8_t * resp, int len,
                                        const struct opts_t * op);
static bool show_stats_perform_pages(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_cache_stats_page(const uint8_t * resp, int len,
                                  const struct opts_t * op);
static bool show_power_condition_transitions_page(const uint8_t * resp,
                                 int len, const struct opts_t * op);
static bool show_environmental_reporting_page(const uint8_t * resp, int len,
                                              const struct opts_t * op);
static bool show_environmental_limits_page(const uint8_t * resp, int len,
                                           const struct opts_t * op);
static bool show_cmd_dur_limits_page(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_data_compression_page(const uint8_t * resp, int len,
                                       const struct opts_t * op);
static bool show_tape_alert_ssc_page(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_ie_page(const uint8_t * resp, int len,
                         const struct opts_t * op);
static bool show_tape_usage_page(const uint8_t * resp, int len,
                                 const struct opts_t * op);
static bool show_tape_capacity_page(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_seagate_cache_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_seagate_factory_page(const uint8_t * resp, int len,
                                      const struct opts_t * op);
static bool show_hgst_perf_page(const uint8_t * resp, int len,
                                const struct opts_t * op);
static bool show_hgst_misc_page(const uint8_t * resp, int len,
                                const struct opts_t * op);

/* elements in page_number/subpage_number order */
static struct log_elem log_arr[] = {
    {SUPP_PAGES_LPAGE, 0, 0, -1, MVP_STD, "Supported log pages", "sp",
     show_supported_pgs_page},          /* 0, 0 */
    {SUPP_PAGES_LPAGE, SUPP_SPGS_SUBPG, 0, -1, MVP_STD, "Supported log pages "
     "and subpages", "ssp", show_supported_pgs_sub_page}, /* 0, 0xff */
    {BUFF_OVER_UNDER_LPAGE, 0, 0, -1, MVP_STD, "Buffer over-run/under-run",
     "bou", show_buffer_over_under_run_page},  /* 0x1, 0x0 */
    {WRITE_ERR_LPAGE, 0, 0, -1, MVP_STD, "Write error", "we",
     show_error_counter_page},          /* 0x2, 0x0 */
    {READ_ERR_LPAGE, 0, 0, -1, MVP_STD, "Read error", "re",
     show_error_counter_page},          /* 0x3, 0x0 */
    {READ_REV_ERR_LPAGE, 0, 0, -1, MVP_STD, "Read reverse error", "rre",
     show_error_counter_page},          /* 0x4, 0x0 */
    {VERIFY_ERR_LPAGE, 0, 0, -1, MVP_STD, "Verify error", "ve",
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
     show_tapealert_response_page},      /* 0x12, 0x0  SSC,ADC */
    {REQ_RECOVERY_LPAGE, 0, 0, PDT_TAPE, MVP_STD, "Requested recovery", "rr",
     show_requested_recovery_page},     /* 0x13, 0x0  SSC,ADC */
    {0x14, 0, 0, PDT_TAPE, MVP_STD, "Device statistics", "ds",
     show_device_stats_page},           /* 0x14, 0x0  SSC,ADC */
    {0x14, 0, 0, PDT_MCHANGER, MVP_STD, "Media changer statistics", "mcs",
     show_media_stats_page},            /* 0x14, 0x0  SMC */
    {0x14, ZONED_BLOCK_DEV_STATS_SUBPG, 0, 0, MVP_STD,  /* 0x14,0x1 zbc2r01 */
     "Zoned block device statistics", "zbds", show_zoned_block_dev_stats},
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
     "psp", show_protocol_specific_page},  /* 0x18, 0x0  */
    {STATS_LPAGE, 0, 0, -1, MVP_STD, "General Statistics and Performance",
     "gsp", show_stats_perform_pages},  /* 0x19, 0x0  */
    {STATS_LPAGE, 0x1, 0x1f, -1, MVP_STD, "Group Statistics and Performance",
     "grsp", show_stats_perform_pages}, /* 0x19, 0x1...0x1f  */
    {STATS_LPAGE, CACHE_STATS_SUBPG, 0, -1, MVP_STD,    /* 0x19, 0x20  */
     "Cache memory statistics", "cms", show_cache_stats_page},
    {STATS_LPAGE, CMD_DUR_LIMITS_SUBPG, 0, -1, MVP_STD, /* 0x19, 0x21  */
     "Commmand duration limits statistics", "cdl",
     show_cmd_dur_limits_page /* spc6r01 */ },
    {PCT_LPAGE, 0, 0, -1, MVP_STD, "Power condition transitions", "pct",
     show_power_condition_transitions_page}, /* 0x1a, 0  */
    {0x1b, 0, 0, PDT_TAPE, MVP_STD, "Data compression", "dc",
     show_data_compression_page},       /* 0x1b, 0  SSC */
    {0x2d, 0, 0, PDT_TAPE, MVP_STD, "Current service information", "csi",
     NULL},                             /* 0x2d, 0  SSC */
    {TAPE_ALERT_LPAGE, 0, 0, PDT_TAPE, MVP_STD, "Tape alert", "ta",
     show_tape_alert_ssc_page},         /* 0x2e, 0  SSC */
    {IE_LPAGE, 0, 0, -1, (MVP_STD | MVP_SMSTR), "Informational exceptions",
     "ie", show_ie_page},               /* 0x2f, 0  */
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
    {VP_SMSTR, "smstr", "SmrtStor (Sandisk)", "SmrtStor", NULL},
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
           "Usage: sg_logs [-All] [--all] [--brief] [--control=PC] "
           "[--enumerate]\n"
           "               [--filter=FL] [--help] [--hex] [--in=FN] "
           "[--list]\n"
           "               [--no_inq] [--maxlen=LEN] [--name] [--page=PG]\n"
           "               [--paramp=PP] [--pcb] [--ppc] [--pdt=DT] "
           "[--raw]\n"
           "               [--readonly] [--reset] [--select] [--sp] "
           "[--temperature]\n"
           "               [--transport] [--vendor=VP] [--verbose] "
           "[--version]\n"
           "               DEVICE\n"
           "  where the main options are:\n"
           "    --All|-A        fetch and decode all log pages and "
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
           "    --help|-h       print usage message then exit. Use twice "
           "for more help\n"
           "    --hex|-H        output response in hex (default: decode if "
           "known)\n"
           "    --in=FN|-i FN    FN is a filename containing a log page "
           "in ASCII hex\n"
           "                     or binary if --raw also given.\n"
           "    --list|-l       list supported log pages; twice: list log "
           "pages and\n"
           "                    subpages (exclude 0xff subpages); thrice: "
           "all pg+spgs\n"
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
           "    --paramp=PP|-P PP    parameter pointer (decimal) (def: 0)\n"
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
    printf("Usage: sg_logs [-a] [-A] [-b] [-c=PC] [-D=DT] [-e] [-f=FL] "
           "[-h]\n"
           "               [-H] [-i=FN] [-l] [-L] [-m=LEN] [-M=VP] [-n] "
           "[-p=PG]\n"
           "               [-paramp=PP] [-pcb] [-ppc] [-r] [-select] [-sp] "
           "[-t] [-T]\n"
           "               [-v] [-V] [-x] [-X] [-?] DEVICE\n"
           "  where:\n"
           "    -a     fetch and decode all log pages\n"
           "    -A     fetch and decode all log pages and subpages\n"
           "    -b     shorten the output of some log pages\n"
           "    -c=PC    page control(PC) (default: 1)\n"
           "                  0: current threshold, 1: current cumulative\n"
           "                  2: default threshold, 3: default cumulative\n"
           "    -e     enumerate known log pages\n"
           "    -f=FL    filter match parameter code or pdt\n"
           "    -h     output in hex (default: decode if known)\n"
           "    -H     output in hex (same as '-h')\n"
           "    -i=FN    FN is a filename containing a log page "
           "in ASCII hex.\n"
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
        return (vpn > (32 - MVP_OFFSET)) ?  OVP_ALL :
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
    int k, j;
    struct log_elem * lep;
    struct log_elem ** lepp;
    struct log_elem ** lep_arr;

    if (op->do_enumerate < 3) { /* -e, -ee: sort by acronym */
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
    size_t len, k;
    const struct vp_name_t * vpp;

    for (vpp = vp_arr; vpp->acron; ++vpp) {
        len = strlen(vpp->acron);
        for (k = 0; k < len; ++k) {
            if (tolower(vp_ap[k]) != vpp->acron[k])
                break;
        }
        if (k < len)
            continue;
        return vpp->vend_prod_num;
    }
    return VP_NONE;
}

static int
find_vpn_by_inquiry(void)
{
    size_t len;
    size_t t10_v_len = strlen(t10_vendor_str);
    size_t t10_p_len = strlen(t10_product_str);
    bool matched;
    const struct vp_name_t * vpp;

    if ((0 == t10_v_len) && (0 == t10_p_len))
        return VP_NONE;
    for (vpp = vp_arr; vpp->acron; ++vpp) {
        matched = false;
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
    int c, n;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aAbc:D:ef:hHi:lLm:M:nNOp:P:qQrRsStTvV"
                        "xX", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ++op->do_all;
            break;
        case 'A':    /* not documented: compatibility with old interface */
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
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 31)) {
                pr2serr("bad argument to '--pdt='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->dev_pdt = n;
            break;
        case 'e':
            ++op->do_enumerate;
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
        case 'l':
            ++op->do_list;
            break;
        case 'L':
            op->do_list += 2;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (1 == n) || (n > 0xffff)) {
                pr2serr("bad argument to '--maxlen=', from 2 to 65535 "
                        "(inclusive) expected\n");
                usage(2);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->maxlen = n;
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
    int k, plen, num, n;
    unsigned int u, uu;
    const char * cp;

    for (k = 1; k < argc; ++k) {
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
                case 'h':
                case 'H':
                    ++op->do_hex;
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
                if ((1 != num) || (n < 0) || (n > MX_ALLOC_LEN)) {
                    pr2serr("Bad maximum response length after '-m=' "
                            "option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
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
                char * xp;
                const struct log_elem * lep;
                char b[80];

                if (isalpha(ccp[0])) {
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

/* Returns 'xp' with "unknown" if all bits set; otherwise decoded (big endian)
 * number in 'xp'. Number rendered in decimal if in_hex=false otherwise in
 * hex with leading '0x' prepended. */
static char *
num_or_unknown(const uint8_t * xp, int num_bytes /* max is 8 */, bool in_hex,
               char * b, int blen)
{
    if (sg_all_ffs(xp, num_bytes))
        snprintf(b, blen, "unknown");
    else {
        uint64_t num = sg_get_unaligned_be(num_bytes, xp);

        if (in_hex)
            snprintf(b, blen, "0x%" PRIx64, num);
        else
            snprintf(b, blen, "%" PRIu64, num);
    }
    return b;
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

/* SUPP_PAGES_LPAGE [0x0,0x0] */
static bool
show_supported_pgs_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int num, k, pg_code;
    const uint8_t * bp;
    const struct log_elem * lep;
    char b[64];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Supported log pages  [0x0]:\n");  /* introduced: SPC-2 */
    num = len - 4;
    bp = &resp[0] + 4;
    for (k = 0; k < num; ++k) {
        pg_code = bp[k];
        snprintf(b, sizeof(b) - 1, "    0x%02x        ", pg_code);
        lep = pg_subpg_pdt_search(pg_code, 0, op->dev_pdt, -1);
        if (lep) {
            if (op->do_brief > 1)
                printf("    %s\n", lep->name);
            else if (op->do_brief)
                printf("%s%s\n", b, lep->name);
            else
                printf("%s%s [%s]\n", b, lep->name, lep->acron);
        } else
            printf("%s\n", b);
    }
    return true;
}

/* SUPP_PAGES_LPAGE,SUPP_SPGS_SUBPG [0x0,0xff] or all subpages of a given
 * page code: [<pg_code>,0xff] */
static bool
show_supported_pgs_sub_page(const uint8_t * resp, int len,
                            const struct opts_t * op)
{
    int num, k, pg_code, subpg_code;
    const uint8_t * bp;
    const struct log_elem * lep;
    char b[64];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (op->pg_code > 0)
            printf("Supported subpages  [0x%x, 0xff]:\n", op->pg_code);
        else
            printf("Supported log pages and subpages  [0x0, 0xff]:\n");
    }
    num = len - 4;
    bp = &resp[0] + 4;
    for (k = 0; k < num; k += 2) {
        pg_code = bp[k];
        subpg_code = bp[k + 1];
        if ((op->do_list == 2) && (subpg_code == 0xff) && (pg_code > 0))
            continue;
        if (NOT_SPG_SUBPG == subpg_code)
            snprintf(b, sizeof(b) - 1, "    0x%02x        ", pg_code);
        else
            snprintf(b, sizeof(b) - 1, "    0x%02x,0x%02x   ", pg_code,
                     subpg_code);
        lep = pg_subpg_pdt_search(pg_code, subpg_code, op->dev_pdt, -1);
        if (lep) {
            if (op->do_brief > 1)
                printf("    %s\n", lep->name);
            else if (op->do_brief)
                printf("%s%s\n", b, lep->name);
            else
                printf("%s%s [%s]\n", b, lep->name, lep->acron);
        } else
            printf("%s\n", b);
    }
    return true;
}

/* BUFF_OVER_UNDER_LPAGE [0x1]  introduced: SPC-2 */
static bool
show_buffer_over_under_run_page(const uint8_t * resp, int len,
                                const struct opts_t * op)
{
    int num, pl, pc;
    uint64_t count;
    const uint8_t * bp;
    const char * cp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Buffer over-run/under-run page  [0x1]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        cp = NULL;
        pl = bp[3] + 4;
        count = (pl > 4) ? sg_get_unaligned_be(pl - 4, bp + 4) : 0;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
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
            printf("  undefined parameter code [0x%x], count = %" PRIu64 "",
                   pc, count);
            break;
        }
        if (cp)
            printf("  %s = %" PRIu64 "", cp, count);

        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* WRITE_ERR_LPAGE; READ_ERR_LPAGE; READ_REV_ERR_LPAGE; VERIFY_ERR_LPAGE */
/* [0x2, 0x3, 0x4, 0x5]  introduced: SPC-3 */
static bool
show_error_counter_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int num, pl, pc, pg_code;
    uint64_t val;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    pg_code = resp[0] & 0x3f;
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        switch(pg_code) {
        case WRITE_ERR_LPAGE:
            printf("Write error counter page  [0x%x]\n", pg_code);
            break;
        case READ_ERR_LPAGE:
            printf("Read error counter page  [0x%x]\n", pg_code);
            break;
        case READ_REV_ERR_LPAGE:
            printf("Read Reverse error counter page  [0x%x]\n",
                   pg_code);
            break;
        case VERIFY_ERR_LPAGE:
            printf("Verify error counter page  [0x%x]\n", pg_code);
            break;
        default:
            pr2serr("expecting error counter page, got page = 0x%x\n",
                    resp[0]);
            return false;
        }
    }
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0: printf("  Errors corrected without substantial delay"); break;
        case 1: printf("  Errors corrected with possible delays"); break;
        case 2: printf("  Total rewrites or rereads"); break;
        case 3: printf("  Total errors corrected"); break;
        case 4: printf("  Total times correction algorithm processed"); break;
        case 5: printf("  Total bytes processed"); break;
        case 6: printf("  Total uncorrected errors"); break;
        case 0x8009: printf("  Track following errors [Hitachi]"); break;
        case 0x8015: printf("  Positioning errors [Hitachi]"); break;
        default: printf("  Reserved or vendor specific [0x%x]", pc); break;
        }
        val = sg_get_unaligned_be(pl - 4, bp + 4);
        printf(" = %" PRIu64 "", val);
        if (val > ((uint64_t)1 << 40))
            printf(" [%" PRIu64 " TB]\n",
                   (val / (1000UL * 1000 * 1000 * 1000)));
        else
            printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* NON_MEDIUM_LPAGE [0x6]  introduced: SPC-2 */
static bool
show_non_medium_error_page(const uint8_t * resp, int len,
                           const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Non-medium error page  [0x6]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            printf("  Non-medium error count");
            break;
        default:
            if (pc <= 0x7fff)
                printf("  Reserved [0x%x]", pc);
            else
                printf("  Vendor specific [0x%x]", pc);
            break;
        }
        printf(" = %" PRIu64 "", sg_get_unaligned_be(pl - 4, bp + 4));
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* PCT_LPAGE [0x1a]  introduced: SPC-4 */
static bool
show_power_condition_transitions_page(const uint8_t * resp, int len,
                                      const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Power condition transitions page  [0x1a]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 1:
            printf("  Accumulated transitions to active"); break;
        case 2:
            printf("  Accumulated transitions to idle_a"); break;
        case 3:
            printf("  Accumulated transitions to idle_b"); break;
        case 4:
            printf("  Accumulated transitions to idle_c"); break;
        case 8:
            printf("  Accumulated transitions to standby_z"); break;
        case 9:
            printf("  Accumulated transitions to standby_y"); break;
        default:
            printf("  Reserved [0x%x]", pc);
        }
        printf(" = %" PRIu64 "", sg_get_unaligned_be(pl - 4, bp + 4));
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
            snprintf(b, blen, "not available");
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
            snprintf(b, blen, "not available");
        else
            snprintf(b, blen, "no limit");
    } else if (h <= 100)
        snprintf(b, blen, "%u %%", h);
    else
        snprintf(b, blen, "reserved value [%u]", h);
    return b;
}

/* ENV_REPORTING_SUBPG [0xd,0x1]  introduced: SPC-5 (rev 02). "mounted"
 * changed to "other" in spc5r11 */
static bool
show_environmental_reporting_page(const uint8_t * resp, int len,
                                  const struct opts_t * op)
{
    int num, pl, pc, blen;
    bool other_valid;
    const uint8_t * bp;
    char str[PCB_STR_LEN];
    char b[32];

    blen = sizeof(b);
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Environmental reporting page  [0xd,0x1]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        other_valid = !!(bp[4] & 1);
        if (pc < 0x100) {
            if (pl < 12)  {
                printf("  <<expect parameter 0x%x to be at least 12 bytes "
                       "long, got %d, skip>>\n", pc, pl);
                goto skip;
            }
            printf("  parameter code=0x%x\n", pc);
            printf("    OTV=%d\n", (int)other_valid);
            printf("    Temperature: %s\n",
                   temperature_str(bp[5], true, b, blen));
            printf("    Lifetime maximum temperature: %s\n",
                   temperature_str(bp[6], true, b, blen));
            printf("    Lifetime minimum temperature: %s\n",
                   temperature_str(bp[7], true, b, blen));
            printf("    Maximum temperature since power on: %s\n",
                   temperature_str(bp[8], true, b, blen));
            printf("    Minimum temperature since power on: %s\n",
                   temperature_str(bp[9], true, b, blen));
            if (other_valid) {
                printf("    Maximum other temperature: %s\n",
                       temperature_str(bp[10], true, b, blen));
                printf("    Minimum other temperature: %s\n",
                       temperature_str(bp[11], true, b, blen));
            }
        } else if (pc < 0x200) {
            if (pl < 12)  {
                printf("  <<expect parameter 0x%x to be at least 12 bytes "
                       "long, got %d, skip>>\n", pc, pl);
                goto skip;
            }
            printf("  parameter code=0x%x\n", pc);
            printf("    ORHV=%d\n", (int)other_valid);
            printf("    Relative humidity: %s\n",
                   humidity_str(bp[5], true, b, blen));
            printf("    Lifetime maximum relative humidity: %s\n",
                   humidity_str(bp[6], true, b, blen));
            printf("    Lifetime minimum relative humidity: %s\n",
                   humidity_str(bp[7], true, b, blen));
            printf("    Maximum relative humidity since power on: %s\n",
                   humidity_str(bp[8], true, b, blen));
            printf("    Minimum relative humidity since power on: %s\n",
                   humidity_str(bp[9], true, b, blen));
            if (other_valid) {
                printf("    Maximum other relative humidity: %s\n",
                       temperature_str(bp[10], true, b, blen));
                printf("    Minimum other relative humidity: %s\n",
                       temperature_str(bp[11], true, b, blen));
            }
        } else
            printf("  <<unexpected parameter code 0x%x\n", pc);
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* ENV_LIMITS_SUBPG [0xd,0x2]  introduced: SPC-5 (rev 02) */
static bool
show_environmental_limits_page(const uint8_t * resp, int len,
                               const struct opts_t * op)
{
    int num, pl, pc, blen;
    const uint8_t * bp;
    char str[PCB_STR_LEN];
    char b[32];

    blen = sizeof(b);
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Environmental limits page  [0xd,0x2]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if (pc < 0x100) {
            if (pl < 12)  {
                printf("  <<expect parameter 0x%x to be at least 12 bytes "
                       "long, got %d, skip>>\n", pc, pl);
                goto skip;
            }
            printf("  High critical temperature limit trigger: %s\n",
                   temperature_str(bp[4], false, b, blen));
            printf("  High critical temperature limit reset: %s\n",
                   temperature_str(bp[5], false, b, blen));
            printf("  Low critical temperature limit reset: %s\n",
                   temperature_str(bp[6], false, b, blen));
            printf("  Low critical temperature limit trigger: %s\n",
                   temperature_str(bp[7], false, b, blen));
            printf("  High operating temperature limit trigger: %s\n",
                   temperature_str(bp[8], false, b, blen));
            printf("  High operating temperature limit reset: %s\n",
                   temperature_str(bp[9], false, b, blen));
            printf("  Low operating temperature limit reset: %s\n",
                   temperature_str(bp[10], false, b, blen));
            printf("  Low operating temperature limit trigger: %s\n",
                   temperature_str(bp[11], false, b, blen));
        } else if (pc < 0x200) {
            printf("  High critical relative humidity limit trigger: %s\n",
                   humidity_str(bp[4], false, b, blen));
            printf("  High critical relative humidity limit reset: %s\n",
                   humidity_str(bp[5], false, b, blen));
            printf("  Low critical relative humidity limit reset: %s\n",
                   humidity_str(bp[6], false, b, blen));
            printf("  Low critical relative humidity limit trigger: %s\n",
                   humidity_str(bp[7], false, b, blen));
            printf("  High operating relative humidity limit trigger: %s\n",
                   humidity_str(bp[8], false, b, blen));
            printf("  High operating relative humidity limit reset: %s\n",
                   humidity_str(bp[9], false, b, blen));
            printf("  Low operating relative humidity limit reset: %s\n",
                   humidity_str(bp[10], false, b, blen));
            printf("  Low operating relative humidity limit trigger: %s\n",
                   humidity_str(bp[11], false, b, blen));
        } else
            printf("  <<unexpected parameter code 0x%x\n", pc);
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* CMD_DUR_LIMITS_SUBPG [0x19,0x21]  introduced: SPC-6 (rev 01) */
static bool
show_cmd_dur_limits_page(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Command duration limits page  [0x19,0x21]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x1:
            printf("  Number of READ commands = %" PRIu64 "\n",
                   sg_get_unaligned_be64(bp + 4));
            break;
        case 0x11:
        case 0x12:
        case 0x13:
        case 0x14:
        case 0x15:
        case 0x16:
        case 0x17:
        case 0x21:
        case 0x22:
        case 0x23:
        case 0x24:
        case 0x25:
        case 0x26:
        case 0x27:
            printf(" Command duration limit T2%s %d [Parameter code 0x%x]:\n",
                   ((pc > 0x20) ? "B" : "A"),
                   ((pc > 0x20) ? (pc - 0x20) : (pc - 0x10)), pc);
            printf("  Number of inactive target miss commands = %u\n",
                   sg_get_unaligned_be32(bp + 4));
            printf("  Number of active target miss commands = %u\n",
                   sg_get_unaligned_be32(bp + 8));
            printf("  Number of latency miss commands = %u\n",
                   sg_get_unaligned_be32(bp + 12));
            printf("  Number of nonconforming miss commands = %u\n",
                   sg_get_unaligned_be32(bp + 16));
            printf("  Number of predictive latency miss commands = %u\n",
                   sg_get_unaligned_be32(bp + 20));
            printf("  Number of latency misses attributable to errors = %u\n",
                   sg_get_unaligned_be32(bp + 24));
            printf("  Number of latency misses attributable to deferred "
                   "errors = %u\n", sg_get_unaligned_be32(bp + 28));
            printf("  Number of latency misses attributable to background "
                   "operations = %u\n", sg_get_unaligned_be32(bp + 32));
            break;
        default:
            printf("  <<unexpected parameter code 0x%x\n", pc);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
show_tape_usage_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc;
    unsigned int n;
    uint64_t ull;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed tape usage page\n");
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Tape usage page  (LTO-5 and LTO-6 specific) [0x30]\n");
    for (k = num; k > 0; k -= extra, bp += extra) {
        pc = sg_get_unaligned_be16(bp + 0);
        extra = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, extra);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, extra, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        ull = n = 0;
        switch (bp[3]) {
        case 2:
            n = sg_get_unaligned_be16(bp + 4);
            break;
        case 4:
            n = sg_get_unaligned_be32(bp + 4);
            break;
        case 8:
            ull = sg_get_unaligned_be64(bp + 4);
            break;
        }
        switch (pc) {
        case 0x01:
            if (extra == 8)
                printf("  Thread count: %u", n);
            break;
        case 0x02:
            if (extra == 12)
                printf("  Total data sets written: %" PRIu64, ull);
            break;
        case 0x03:
            if (extra == 8)
                printf("  Total write retries: %u", n);
            break;
        case 0x04:
            if (extra == 6)
                printf("  Total unrecovered write errors: %u", n);
            break;
        case 0x05:
            if (extra == 6)
                printf("  Total suspended writes: %u", n);
            break;
        case 0x06:
            if (extra == 6)
                printf("  Total fatal suspended writes: %u", n);
            break;
        case 0x07:
            if (extra == 12)
                printf("  Total data sets read: %" PRIu64, ull);
            break;
        case 0x08:
            if (extra == 8)
                printf("  Total read retries: %u", n);
            break;
        case 0x09:
            if (extra == 6)
                printf("  Total unrecovered read errors: %u", n);
            break;
        case 0x0a:
            if (extra == 6)
                printf("  Total suspended reads: %u", n);
            break;
        case 0x0b:
            if (extra == 6)
                printf("  Total fatal suspended reads: %u", n);
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in "
                   "hex:\n", pc);
            hex2stdout(bp, extra, 1);
            break;
        }
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* 0x30 */
static bool
show_hgst_perf_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    bool valid = false;
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("HGST/WDC performance counters page [0x30]\n");
    num = len - 4;
    if (num < 0x30) {
        printf("HGST/WDC performance counters page too short (%d) < 48\n",
               num);
        return valid;
    }
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            valid = true;
            printf("  Zero Seeks = %u\n", sg_get_unaligned_be16(bp + 4));
            printf("  Seeks >= 2/3 = %u\n", sg_get_unaligned_be16(bp + 6));
            printf("  Seeks >= 1/3 and < 2/3 = %u\n",
                   sg_get_unaligned_be16(bp + 8));
            printf("  Seeks >= 1/6 and < 1/3 = %u\n",
                   sg_get_unaligned_be16(bp + 10));
            printf("  Seeks >= 1/12 and < 1/6 = %u\n",
                   sg_get_unaligned_be16(bp + 12));
            printf("  Seeks > 0 and < 1/12 = %u\n",
                   sg_get_unaligned_be16(bp + 14));
            printf("  Overrun Counter = %u\n",
                   sg_get_unaligned_be16(bp + 20));
            printf("  Underrun Counter = %u\n",
                   sg_get_unaligned_be16(bp + 22));
            printf("  Device Cache Full Read Hits = %u\n",
                   sg_get_unaligned_be32(bp + 24));
            printf("  Device Cache Partial Read Hits = %u\n",
                   sg_get_unaligned_be32(bp + 28));
            printf("  Device Cache Write Hits = %u\n",
                   sg_get_unaligned_be32(bp + 32));
            printf("  Device Cache Fast Writes = %u\n",
                   sg_get_unaligned_be32(bp + 36));
            printf("  Device Cache Read Misses = %u\n",
                   sg_get_unaligned_be32(bp + 40));
            break;
        default:
            valid = false;
            printf("  Unknown HGST/WDC parameter code = 0x%x", pc);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
                        const struct opts_t * op)
{
    int k, num, extra, pc;
    unsigned int n;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed tape capacity page\n");
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Tape capacity page  (LTO-5 and LTO-6 specific) [0x31]\n");
    for (k = num; k > 0; k -= extra, bp += extra) {
        pc = sg_get_unaligned_be16(bp + 0);
        extra = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, extra);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, extra, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if (extra != 8)
            continue;
        n = sg_get_unaligned_be32(bp + 4);
        switch (pc) {
        case 0x01:
            printf("  Main partition remaining capacity (in MiB): %u", n);
            break;
        case 0x02:
            printf("  Alternate partition remaining capacity (in MiB): %u", n);
            break;
        case 0x03:
            printf("  Main partition maximum capacity (in MiB): %u", n);
            break;
        case 0x04:
            printf("  Alternate partition maximum capacity (in MiB): %u", n);
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in "
                    "hex:\n", pc);
            hex2stdout(bp, extra, 1);
            break;
        }
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* Data compression: originally vendor specific 0x32 (LTO-5), then
 * ssc-4 standardizes it at 0x1b */
static bool
show_data_compression_page(const uint8_t * resp, int len,
                           const struct opts_t * op)
{
    int k, j, pl, num, extra, pc, pg_code;
    uint64_t n;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    pg_code = resp[0] & 0x3f;
    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed data compression page\n");
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (0x1b == pg_code)
            printf("Data compression page  (ssc-4) [0x1b]\n");
        else
            printf("Data compression page  (LTO-5 specific) [0x%x]\n",
                   pg_code);
    }
    for (k = num; k > 0; k -= extra, bp += extra) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3];
        extra = pl + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, extra);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, extra, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if ((0 == pl) || (pl > 8)) {
            printf("badly formed data compression log parameter\n");
            printf("  parameter code = 0x%x, contents in hex:\n", pc);
            hex2stdout(bp, extra, 1);
            goto skip_para;
        }
        /* variable length integer, max length 8 bytes */
        for (j = 0, n = 0; j < pl; ++j) {
            if (j > 0)
                n <<= 8;
            n |= bp[4 + j];
        }
        switch (pc) {
        case 0x00:
            printf("  Read compression ratio x100: %" PRIu64 , n);
            break;
        case 0x01:
            printf("  Write compression ratio x100: %" PRIu64 , n);
            break;
        case 0x02:
            printf("  Megabytes transferred to server: %" PRIu64 , n);
            break;
        case 0x03:
            printf("  Bytes transferred to server: %" PRIu64 , n);
            break;
        case 0x04:
            printf("  Megabytes read from tape: %" PRIu64 , n);
            break;
        case 0x05:
            printf("  Bytes read from tape: %" PRIu64 , n);
            break;
        case 0x06:
            printf("  Megabytes transferred from server: %" PRIu64 , n);
            break;
        case 0x07:
            printf("  Bytes transferred from server: %" PRIu64 , n);
            break;
        case 0x08:
            printf("  Megabytes written to tape: %" PRIu64 , n);
            break;
        case 0x09:
            printf("  Bytes written to tape: %" PRIu64 , n);
            break;
        case 0x100:
            printf("  Data compression enabled: 0x%" PRIx64, n);
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in "
                    "hex:\n", pc);
            hex2stdout(bp, extra, 1);
            break;
        }
skip_para:
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* LAST_N_ERR_LPAGE [0x7]  introduced: SPC-2 */
static bool
show_last_n_error_page(const uint8_t * resp, int len,
                       const struct opts_t * op)
{
    int k, num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        printf("No error events logged\n");
        return true;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Last n error events page  [0x7]\n");
    for (k = num; k > 0; k -= pl, bp += pl) {
        if (k < 3) {
            printf("short Last n error events page\n");
            return false;
        }
        pl = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Error event %d:\n", pc);
        if (pl > 4) {
            if ((bp[2] & 0x1) && (bp[2] & 0x2)) {
                printf("    [binary]:\n");
                hex2stdout(bp + 4, pl - 4, 1);
            } else if (bp[2] & 0x1)
                printf("    %.*s\n", pl - 4, (const char *)(bp + 4));
            else {
                printf("    [data counter?? (LP bit should be set)]:\n");
                hex2stdout(bp + 4, pl - 4, 1);
            }
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* LAST_N_DEFERRED_LPAGE [0xb]  introduced: SPC-2 */
static bool
show_last_n_deferred_error_page(const uint8_t * resp, int len,
                                const struct opts_t * op)
{
    int k, num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        printf("No deferred errors logged\n");
        return true;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Last n deferred errors page  [0xb]\n");
    for (k = num; k > 0; k -= pl, bp += pl) {
        if (k < 3) {
            printf("short Last n deferred errors page\n");
            return true;
        }
        pl = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Deferred error %d:\n", pc);
        hex2stdout(bp + 4, pl - 4, 1);
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* LAST_N_INQUIRY_DATA_CH_SUBPG [0xb,0x1]  introduced: SPC-5 (rev 17) */
static bool
show_last_n_inq_data_ch_page(const uint8_t * resp, int len,
                             const struct opts_t * op)
{
    int j, num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Last n Inquiry data changed  [0xb,0x1]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if (0 == pc) {
            if (pl < 8)  {
                printf("  <<expect parameter 0x%x to be at least 8 bytes "
                       "long, got %d, skip>>\n", pc, pl);
                goto skip;
            }
            printf("  Generation number of Inquiry data changed indication: "
                   "%u\n", sg_get_unaligned_be32(bp + 4));
            if (pl > 11)
                printf("  Generation number of Mode page data changed "
                       "indication: %u\n", sg_get_unaligned_be32(bp + 8));
            for (j = 12; j < pl; j +=4)
                printf("  Generation number of indication [0x%x]: %u\n",
                       (j / 4), sg_get_unaligned_be32(bp + j));
        } else {
            printf("  Parameter code 0x%x, ", pc);
            if (1 & *(bp + 4))
                printf("VPD page 0x%x changed\n", *(bp + 5));
            else
                printf("Standard Inquiry data changed\n");
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* LAST_N_MODE_PG_DATA_CH_SUBPG [0xb,0x2]  introduced: SPC-5 (rev 17) */
static bool
show_last_n_mode_pg_data_ch_page(const uint8_t * resp, int len,
                                 const struct opts_t * op)
{
    int j, num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Last n Mode page data changed  [0xb,0x2]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if (0 == pc) {  /* Same as LAST_N_INQUIRY_DATA_CH_SUBPG [0xb,0x1] */
            if (pl < 8)  {
                printf("  <<expect parameter 0x%x to be at least 8 bytes "
                       "long, got %d, skip>>\n", pc, pl);
                goto skip;
            }
            printf("  Generation number of Inquiry data changed indication: "
                   "%u\n", sg_get_unaligned_be32(bp + 4));
            if (pl > 11)
                printf("  Generation number of Mode page data changed "
                       "indication: %u\n", sg_get_unaligned_be32(bp + 8));
            for (j = 12; j < pl; j +=4)
                printf("  Generation number of indication [0x%x]: %u\n",
                       (j / 4), sg_get_unaligned_be32(bp + j));
        } else {
            printf("  Parameter code 0x%x, ", pc);
            if (0x40 & *(bp + 5))       /* SPF bit set */
                printf("Mode page 0x%x,0%x changed\n", (0x3f & *(bp + 5)),
                       *(bp + 6));
            else
                printf("Mode page 0x%x changed\n", (0x3f & *(bp + 5)));
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
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
    "reserved",
    "self test in progress"};

/* SELF_TEST_LPAGE [0x10]  introduced: SPC-3 */
static bool
show_self_test_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, n, res, pc, pl;
    unsigned int v;
    const uint8_t * bp;
    uint64_t ull;
    char str[PCB_STR_LEN];
    char b[80];

    num = len - 4;
    if (num < 0x190) {
        pr2serr("short self-test results page [length 0x%x rather than "
                "0x190 bytes]\n", num);
        return true;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Self-test results page  [0x10]\n");
    for (k = 0, bp = resp + 4; k < 20; ++k, bp += 20 ) {
        pl = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        n = sg_get_unaligned_be16(bp + 6);
        if ((0 == n) && (0 == bp[4]))
            break;
        printf("  Parameter code = %d, accumulated power-on hours = %d\n",
               pc, n);
        printf("    self-test code: %s [%d]\n",
               self_test_code[(bp[4] >> 5) & 0x7], (bp[4] >> 5) & 0x7);
        res = bp[4] & 0xf;
        printf("    self-test result: %s [%d]\n", self_test_result[res], res);
        if (bp[5])
            printf("    self-test number = %d\n", (int)bp[5]);
        if (! sg_all_ffs(bp + 8, 8)) {
            ull = sg_get_unaligned_be64(bp + 8);
            if ((res > 0) && ( res < 0xf))
                printf("    address of first error = 0x%" PRIx64 "\n", ull);
        }
        v = bp[16] & 0xf;
        if (v) {
            printf("    sense key = 0x%x [%s] , asc = 0x%x, ascq = 0x%x",
                   v, sg_get_sense_key_str(v, sizeof(b), b), bp[17],
                   bp[18]);
            if (bp[17] || bp[18])
                printf("      [%s]\n", sg_get_asc_ascq_str(bp[17], bp[18],
                       sizeof(b), b));
            else
                printf("\n");
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* TEMPERATURE_LPAGE [0xd]  introduced: SPC-3 */
static bool
show_temperature_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed Temperature page\n");
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (! op->do_temperature)
            printf("Temperature page  [0xd]\n");
    }
    for (k = num; k > 0; k -= extra, bp += extra) {
        if (k < 3) {
            pr2serr("short Temperature page\n");
            return true;
        }
        extra = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, extra);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, extra, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            if ((extra > 5) && (k > 5)) {
                if (0 == bp[5])
                    printf("  Current temperature = 0 C (or less)\n");
                else if (bp[5] < 0xff)
                    printf("  Current temperature = %d C\n", bp[5]);
                else
                    printf("  Current temperature = <not available>\n");
            }
            break;
        case 1:
            if ((extra > 5) && (k > 5)) {
                if (bp[5] < 0xff)
                    printf("  Reference temperature = %d C\n", bp[5]);
                else
                    printf("  Reference temperature = <not available>\n");
            }
            break;
        default:
            if (! op->do_temperature) {
                printf("  unknown parameter code = 0x%x, contents in "
                       "hex:\n", pc);
                hex2stdout(bp, extra, 1);
            } else
                continue;
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* START_STOP_LPAGE [0xe]  introduced: SPC-3 */
static bool
show_start_stop_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed Start-stop cycle counter page\n");
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Start-stop cycle counter page  [0xe]\n");
    for (k = num; k > 0; k -= extra, bp += extra) {
        if (k < 3) {
            pr2serr("short Start-stop cycle counter page\n");
            return true;
        }
        extra = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, extra);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, extra, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 1:
            if (10 == extra)
                printf("  Date of manufacture, year: %.4s, week: %.2s",
                       &bp[4], &bp[8]);
            else if (op->verbose) {
                pr2serr("  Date of manufacture parameter length strange: "
                        "%d\n", extra - 4);
                hex2stderr(bp, extra, 1);
            }
            break;
        case 2:
            if (10 == extra)
                printf("  Accounting date, year: %.4s, week: %.2s",
                       &bp[4], &bp[8]);
            else if (op->verbose) {
                pr2serr("  Accounting date parameter length strange: %d\n",
                        extra - 4);
                hex2stderr(bp, extra, 1);
            }
            break;
        case 3:
            if (extra > 7) {
                if (sg_all_ffs(bp + 4, 4))
                    printf("  Specified cycle count over device lifetime "
                           "= -1");
                else
                    printf("  Specified cycle count over device lifetime "
                           "= %u", sg_get_unaligned_be32(bp + 4));
            }
            break;
        case 4:
            if (extra > 7) {
                if (sg_all_ffs(bp + 4, 4))
                    printf("  Accumulated start-stop cycles = -1");
                else
                    printf("  Accumulated start-stop cycles = %u",
                           sg_get_unaligned_be32(bp + 4));
            }
            break;
        case 5:
            if (extra > 7) {
                if (sg_all_ffs(bp + 4, 4))
                    printf("  Specified load-unload count over device "
                           "lifetime = -1");
                else
                    printf("  Specified load-unload count over device "
                           "lifetime = %u", sg_get_unaligned_be32(bp + 4));
            }
            break;
        case 6:
            if (extra > 7) {
                if (sg_all_ffs(bp + 4, 4))
                    printf("  Accumulated load-unload cycles = -1");
                else
                    printf("  Accumulated load-unload cycles = %u",
                           sg_get_unaligned_be32(bp + 4));
            }
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in "
                   "hex:\n", pc);
            hex2stdout(bp, extra, 1);
            break;
        }
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* APP_CLIENT_LPAGE [0xf]  introduced: SPC-3 */
static bool
show_app_client_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed Application Client page\n");
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (op->do_hex == 0)))
        printf("Application client page  [0xf]\n");
    if (0 == op->filter_given) {
        if ((len > 128) && (0 == op->do_hex)) {
            hex2stdout(resp, 64, 1);
            printf(" .....  [truncated after 64 of %d bytes (use '-H' to "
                   "see the rest)]\n", len);
        }
        else
            hex2stdout(resp, len, 1);
        return true;
    }
    /* only here if filter_given set */
    for (k = num; k > 0; k -= extra, bp += extra) {
        if (k < 3) {
            pr2serr("short Application client page\n");
            return true;
        }
        extra = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter != pc)
            continue;
        if (op->do_raw)
            dStrRaw(bp, extra);
        else if (0 == op->do_hex)
            hex2stdout(bp, extra, 0);
        else if (1 == op->do_hex)
            hex2stdout(bp, extra, 1);
        else
            hex2stdout(bp, extra, -1);
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        break;
    }
    return true;
}

/* IE_LPAGE [0x2f] "Informational Exceptions"  introduced: SPC-3 */
static bool
show_ie_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, param_len, pc;
    const uint8_t * bp;
    const char * cp;
    char str[PCB_STR_LEN];
    char b[256];
    char bb[32];
    bool full, decoded;
    bool has_header = false;
    bool is_smstr = op->lep ? (MVP_SMSTR & op->lep->flags) :
                              (VP_SMSTR == op->vend_prod_num);

    full = ! op->do_temperature;
    if ('\0' != t10_vendor_str[0]) {
        if (0 != strcmp(vp_arr[VP_SMSTR].t10_vendorp, t10_vendor_str))
            is_smstr = false;  /* Inquiry vendor string says not SmrtStor */
    }
    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed Informational Exceptions page\n");
        return false;
    }
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (full)
            printf("Informational Exceptions page  [0x2f]\n");
    }
    for (k = num; k > 0; k -= param_len, bp += param_len) {
        if (k < 3) {
            printf("short Informational Exceptions page\n");
            return false;
        }
        param_len = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, param_len);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, param_len, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        decoded = true;
        cp = NULL;

        switch (pc) {
        case 0x0:
            if (param_len > 5) {
                if (full) {
                    printf("  IE asc = 0x%x, ascq = 0x%x", bp[4], bp[5]);
                    if (bp[4] || bp[5])
                        if(sg_get_asc_ascq_str(bp[4], bp[5], sizeof(b), b))
                            printf("\n    [%s]", b);
                }
                if (param_len > 6) {
                    if (bp[6] < 0xff)
                        printf("\n    Current temperature = %d C", bp[6]);
                    else
                        printf("\n    Current temperature = <not available>");
                    if (param_len > 7) {
                        if (bp[7] < 0xff)
                            printf("\n    Threshold temperature = %d C  "
                                   "[common extension]", bp[7]);
                        else
                            printf("\n    Threshold temperature = <not "
                                   "available>");
                        if ((param_len > 8) && (bp[8] >= bp[6])) {
                            if (bp[8] < 0xff)
                                printf("\n    Maximum temperature = %d C  "
                                       "[(since new), extension]", bp[8]);
                            else
                                printf("\n    Maximum temperature = <not "
                                       "available>");
                        }
                    }
                }
                decoded = true;
            }
            break;
        default:
            if (is_smstr && (param_len >= 24)) {
                switch (pc) {
                case 0x1:
                    cp = "Read error rate";
                    break;
                case 0x2:
                    cp = "Flash rom check";
                    break;
                case 0x5:
                    cp = "Realloc block count";
                    break;
                case 0x9:
                    cp = "Power on hours";
                    break;
                case 0xc:
                    cp = "Power cycles";
                    break;
                case 0xd:
                    cp = "Ecc rate";
                    break;
                case 0x20:
                    cp = "Write amp";
                    break;
                case 0xb1:      /* 177 */
                    cp = "Percent life remaining";
                    break;
                case 0xb4:      /* 180 */
                    cp = "Unused reserved block count";
                    break;
                case 0xb5:      /* 181 */
                    cp = "Program fail count";
                    break;
                case 0xb6:      /* 182 */
                    cp = "Erase fail count";
                    break;
                case 0xbe:      /* 190 */
                    cp = "Drive temperature warn";
                    break;
                case 0xc2:      /* 194 */
                    cp = "Drive temperature";
                    break;
                case 0xc3:      /* 195 */
                    cp = "Uncorrected error count";
                    break;
                case 0xc6:      /* 198 */
                    cp = "Offline scan uncorrected sector count";
                    break;
                case 0xe9:      /* 233 */
                    cp = "Number of writes";
                    break;
                default:
                    snprintf(bb, sizeof(bb), "parameter_code=0x%x (%d)",
                             pc, pc);
                    cp = bb;
                    break;
                }
                if (cp && (param_len >= 24)) {
                    if (! has_header) {
                        has_header = true;
                        printf("  Has|Ever  %% to  worst %%   Current      "
                               "Worst  Threshold  Attribute\n");
                        printf("   tripped  fail  to fail     "
                               "value      value\n");
                    }
                    printf("   %2d %2d  %4d     %4d  %10u %10u %10u  %s",
                           !!(0x80 & bp[4]), !!(0x40 & bp[4]), bp[5], bp[6],
                           sg_get_unaligned_be32(bp + 8),
                           sg_get_unaligned_be32(bp + 12),
                           sg_get_unaligned_be32(bp + 16),
                           cp);
                    decoded = true;
                }
            } else if (VP_HITA == op->vend_prod_num) {
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
                    printf("  %s:\n", cp);
                    printf("    SMART sense_code=0x%x sense_qualifier=0x%x "
                           "threshold=%d%% trip=%d", bp[4], bp[5], bp[6],
                           bp[7]);
                }
            } else
                decoded = false;
            break;
        }               /* end of switch statement */
        if ((! decoded) && full) {
            printf("  parameter code = 0x%x, contents in hex:\n", pc);
            hex2stdout(bp, param_len, 1);
        } else
            printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }           /* end of for loop */
    return true;
}

/* called for SAS port of PROTO_SPECIFIC_LPAGE [0x18] */
static void
show_sas_phy_event_info(int pes, unsigned int val, unsigned int thresh_val)
{
    unsigned int u;

    switch (pes) {
    case 0:
        printf("     No event\n");
        break;
    case 0x1:
        printf("     Invalid word count: %u\n", val);
        break;
    case 0x2:
        printf("     Running disparity error count: %u\n", val);
        break;
    case 0x3:
        printf("     Loss of dword synchronization count: %u\n", val);
        break;
    case 0x4:
        printf("     Phy reset problem count: %u\n", val);
        break;
    case 0x5:
        printf("     Elasticity buffer overflow count: %u\n", val);
        break;
    case 0x6:
        printf("     Received ERROR  count: %u\n", val);
        break;
    case 0x7:
        printf("     Invalid SPL packet count: %u\n", val);
        break;
    case 0x8:
        printf("     Loss of SPL packet synchronization count: %u\n", val);
        break;
    case 0x20:
        printf("     Received address frame error count: %u\n", val);
        break;
    case 0x21:
        printf("     Transmitted abandon-class OPEN_REJECT count: %u\n", val);
        break;
    case 0x22:
        printf("     Received abandon-class OPEN_REJECT count: %u\n", val);
        break;
    case 0x23:
        printf("     Transmitted retry-class OPEN_REJECT count: %u\n", val);
        break;
    case 0x24:
        printf("     Received retry-class OPEN_REJECT count: %u\n", val);
        break;
    case 0x25:
        printf("     Received AIP (WATING ON PARTIAL) count: %u\n", val);
        break;
    case 0x26:
        printf("     Received AIP (WAITING ON CONNECTION) count: %u\n", val);
        break;
    case 0x27:
        printf("     Transmitted BREAK count: %u\n", val);
        break;
    case 0x28:
        printf("     Received BREAK count: %u\n", val);
        break;
    case 0x29:
        printf("     Break timeout count: %u\n", val);
        break;
    case 0x2a:
        printf("     Connection count: %u\n", val);
        break;
    case 0x2b:
        printf("     Peak transmitted pathway blocked count: %u\n",
               val & 0xff);
        printf("         Peak value detector threshold: %u\n",
               thresh_val & 0xff);
        break;
    case 0x2c:
        u = val & 0xffff;
        if (u < 0x8000)
            printf("     Peak transmitted arbitration wait time (us): "
                   "%u\n", u);
        else
            printf("     Peak transmitted arbitration wait time (ms): "
                   "%u\n", 33 + (u - 0x8000));
        u = thresh_val & 0xffff;
        if (u < 0x8000)
            printf("         Peak value detector threshold (us): %u\n",
                   u);
        else
            printf("         Peak value detector threshold (ms): %u\n",
                   33 + (u - 0x8000));
        break;
    case 0x2d:
        printf("     Peak arbitration time (us): %u\n", val);
        printf("         Peak value detector threshold: %u\n", thresh_val);
        break;
    case 0x2e:
        printf("     Peak connection time (us): %u\n", val);
        printf("         Peak value detector threshold: %u\n", thresh_val);
        break;
    case 0x2f:
        printf("     Persistent connection count: %u\n", val);
        break;
    case 0x40:
        printf("     Transmitted SSP frame count: %u\n", val);
        break;
    case 0x41:
        printf("     Received SSP frame count: %u\n", val);
        break;
    case 0x42:
        printf("     Transmitted SSP frame error count: %u\n", val);
        break;
    case 0x43:
        printf("     Received SSP frame error count: %u\n", val);
        break;
    case 0x44:
        printf("     Transmitted CREDIT_BLOCKED count: %u\n", val);
        break;
    case 0x45:
        printf("     Received CREDIT_BLOCKED count: %u\n", val);
        break;
    case 0x50:
        printf("     Transmitted SATA frame count: %u\n", val);
        break;
    case 0x51:
        printf("     Received SATA frame count: %u\n", val);
        break;
    case 0x52:
        printf("     SATA flow control buffer overflow count: %u\n", val);
        break;
    case 0x60:
        printf("     Transmitted SMP frame count: %u\n", val);
        break;
    case 0x61:
        printf("     Received SMP frame count: %u\n", val);
        break;
    case 0x63:
        printf("     Received SMP frame error count: %u\n", val);
        break;
    default:
        printf("     Unknown phy event source: %d, val=%u, thresh_val=%u\n",
               pes, val, thresh_val);
        break;
    }
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
show_sas_port_param(const uint8_t * bp, int param_len,
                    const struct opts_t * op)
{
    int j, m, nphys, t, sz, spld_len;
    const uint8_t * vcp;
    uint64_t ull;
    unsigned int ui;
    char str[PCB_STR_LEN];
    char s[64];

    sz = sizeof(s);
    t = sg_get_unaligned_be16(bp + 0);
    if (op->do_name)
        printf("rel_target_port=%d\n", t);
    else
        printf("relative target port id = %d\n", t);
    if (op->do_name)
        printf("  gen_code=%d\n", bp[6]);
    else
        printf("  generation code = %d\n", bp[6]);
    nphys = bp[7];
    if (op->do_name)
        printf("  num_phys=%d\n", nphys);
    else {
        printf("  number of phys = %d\n", nphys);
        if ((op->do_pcb) && (! op->do_name))
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
    }

    for (j = 0, vcp = bp + 8; j < (param_len - 8);
         vcp += spld_len, j += spld_len) {
        if (op->do_name)
            printf("    phy_id=%d\n", vcp[1]);
        else
            printf("  phy identifier = %d\n", vcp[1]);
        spld_len = vcp[3];
        if (spld_len < 44)
            spld_len = 48;      /* in SAS-1 and SAS-1.1 vcp[3]==0 */
        else
            spld_len += 4;
        if (op->do_name) {
            t = ((0x70 & vcp[4]) >> 4);
            printf("      att_dev_type=%d\n", t);
            printf("      att_iport_mask=0x%x\n", vcp[6]);
            printf("      att_phy_id=%d\n", vcp[24]);
            printf("      att_reason=0x%x\n", (vcp[4] & 0xf));
            ull = sg_get_unaligned_be64(vcp + 16);
            printf("      att_sas_addr=0x%" PRIx64 "\n", ull);
            printf("      att_tport_mask=0x%x\n", vcp[7]);
            ui = sg_get_unaligned_be32(vcp + 32);
            printf("      inv_dwords=%u\n", ui);
            ui = sg_get_unaligned_be32(vcp + 40);
            printf("      loss_dword_sync=%u\n", ui);
            printf("      neg_log_lrate=%d\n", 0xf & vcp[5]);
            ui = sg_get_unaligned_be32(vcp + 44);
            printf("      phy_reset_probs=%u\n", ui);
            ui = sg_get_unaligned_be32(vcp + 36);
            printf("      running_disparity=%u\n", ui);
            printf("      reason=0x%x\n", (vcp[5] & 0xf0) >> 4);
            ull = sg_get_unaligned_be64(vcp + 8);
            printf("      sas_addr=0x%" PRIx64 "\n", ull);
        } else {
            t = ((0x70 & vcp[4]) >> 4);
            /* attached SAS device type. In SAS-1.1 case 2 was an edge
             * expander; in SAS-2 case 3 is marked as obsolete. */
            switch (t) {
            case 0: snprintf(s, sz, "no device attached"); break;
            case 1: snprintf(s, sz, "SAS or SATA device"); break;
            case 2: snprintf(s, sz, "expander device"); break;
            case 3: snprintf(s, sz, "expander device (fanout)"); break;
            default: snprintf(s, sz, "reserved [%d]", t); break;
            }
            /* the word 'SAS' in following added in spl4r01 */
            printf("    attached SAS device type: %s\n", s);
            t = 0xf & vcp[4];
            switch (t) {
            case 0: snprintf(s, sz, "unknown"); break;
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
            default: snprintf(s, sz, "reserved [0x%x]", t); break;
            }
            printf("    attached reason: %s\n", s);
            t = (vcp[5] & 0xf0) >> 4;
            switch (t) {
            case 0: snprintf(s, sz, "unknown"); break;
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
            default: snprintf(s, sz, "reserved [0x%x]", t); break;
            }
            printf("    reason: %s\n", s);
            printf("    negotiated logical link rate: %s\n",
                   sas_negot_link_rate((0xf & vcp[5]), s, sz));
            printf("    attached initiator port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[6] & 8), !! (vcp[6] & 4), !! (vcp[6] & 2));
            printf("    attached target port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[7] & 8), !! (vcp[7] & 4), !! (vcp[7] & 2));
            ull = sg_get_unaligned_be64(vcp + 8);
            printf("    SAS address = 0x%" PRIx64 "\n", ull);
            ull = sg_get_unaligned_be64(vcp + 16);
            printf("    attached SAS address = 0x%" PRIx64 "\n", ull);
            printf("    attached phy identifier = %d\n", vcp[24]);
            ui = sg_get_unaligned_be32(vcp + 32);
            printf("    Invalid DWORD count = %u\n", ui);
            ui = sg_get_unaligned_be32(vcp + 36);
            printf("    Running disparity error count = %u\n", ui);
            ui = sg_get_unaligned_be32(vcp + 40);
            printf("    Loss of DWORD synchronization count = %u\n", ui);
            ui = sg_get_unaligned_be32(vcp + 44);
            printf("    Phy reset problem count = %u\n", ui);
        }
        if (spld_len > 51) {
            int num_ped, pes;
            const uint8_t * xcp;
            unsigned int pvdt;

            num_ped = vcp[51];
            if (op->verbose > 1)
                printf("    <<Phy event descriptors: %d, spld_len: %d, "
                       "calc_ped: %d>>\n", num_ped, spld_len,
                       (spld_len - 52) / 12);
            if (num_ped > 0) {
                if (op->do_name) {
                   printf("      phy_event_desc_num=%d\n", num_ped);
                   return;      /* don't decode at this stage */
                } else
                   printf("    Phy event descriptors:\n");
            }
            xcp = vcp + 52;
            for (m = 0; m < (num_ped * 12); m += 12, xcp += 12) {
                pes = xcp[3];
                ui = sg_get_unaligned_be32(xcp + 4);
                pvdt = sg_get_unaligned_be32(xcp + 8);
                show_sas_phy_event_info(pes, ui, pvdt);
            }
        } else if (op->verbose)
           printf("    <<No phy event descriptors>>\n");
    }
}

/* PROTO_SPECIFIC_LPAGE [0x18] */
static bool
show_protocol_specific_page(const uint8_t * resp, int len,
                            const struct opts_t * op)
{
    int k, num, pl, pc, pid;
    const uint8_t * bp;

    num = len - 4;
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (op->do_name)
            printf("log_page=0x%x\n", PROTO_SPECIFIC_LPAGE);
    }
    for (k = 0, bp = resp + 4; k < num; ) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        pid = 0xf & bp[4];
        if (6 != pid) {
            pr2serr("Protocol identifier: %d, only support SAS (SPL) which "
                    "is 6\n", pid);
            return false;   /* only decode SAS log page */
        }
        if ((0 == k) && (! op->do_name))
            printf("Protocol Specific port page for SAS SSP  (sas-2) "
                   "[0x18]\n");
        show_sas_port_param(bp, pl, op);
        if (op->filter_given)
            break;
skip:
        k += pl;
        bp += pl;
    }
    return true;
}

/* Returns true if processed page, false otherwise */
/* STATS_LPAGE [0x19], subpages: 0x0 to 0x1f  introduced: SPC-4 */
static bool
show_stats_perform_pages(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    bool nam, spf;
    int k, num, param_len, param_code, subpg_code, extra;
    unsigned int ui;
    uint64_t ull;
    const uint8_t * bp;
    const char * ccp;
    char str[PCB_STR_LEN];

    nam = op->do_name;
    num = len - 4;
    bp = resp + 4;
    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : 0;
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (nam) {
            printf("log_page=0x%x\n", STATS_LPAGE);
            if (subpg_code > 0)
                printf("log_subpage=0x%x\n", subpg_code);
        } else {
            if (0 == subpg_code)
                printf("General Statistics and Performance  [0x19]\n");
            else
                printf("Group Statistics and Performance (%d)  "
                       "[0x19,0x%x]\n", subpg_code, subpg_code);
        }
    }
    if (subpg_code > 31)
        return false;
    if (0 == subpg_code) { /* General statistics and performance log page */
        if (num < 0x5c)
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
                if (op->do_raw) {
                    dStrRaw(bp, extra);
                    break;
                } else if (op->do_hex) {
                    hex2stdout(bp, extra, ((1 == op->do_hex) ? 1 : -1));
                    break;
                }
            }
            switch (param_code) {
            case 1:     /* Statistics and performance log parameter */
                ccp = nam ? "parameter_code=1" : "Statistics and performance "
                        "log parameter";
                printf("%s\n", ccp);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nam ? "read_commands=" : "number of read commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 12);
                ccp = nam ? "write_commands=" : "number of write commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 20);
                ccp = nam ? "lb_received="
                          : "number of logical blocks received = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 28);
                ccp = nam ? "lb_transmitted="
                          : "number of logical blocks transmitted = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 36);
                ccp = nam ? "read_proc_intervals="
                          : "read command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 44);
                ccp = nam ? "write_proc_intervals="
                          : "write command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 52);
                ccp = nam ? "weight_rw_commands=" : "weighted number of "
                                "read commands plus write commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 60);
                ccp = nam ? "weight_rw_processing=" : "weighted read command "
                                "processing plus write command processing = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 2:     /* Idle time log parameter */
                ccp = nam ? "parameter_code=2" : "Idle time log parameter";
                printf("%s\n", ccp);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nam ? "idle_time_intervals=" : "idle time "
                                "intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 3:     /* Time interval log parameter for general stats */
                ccp = nam ? "parameter_code=3" : "Time interval log "
                        "parameter for general stats";
                printf("%s\n", ccp);
                ui = sg_get_unaligned_be32(bp + 4);
                ccp = nam ? "time_interval_neg_exp=" : "time interval "
                                "negative exponent = ";
                printf("  %s%u\n", ccp, ui);
                ui = sg_get_unaligned_be32(bp + 8);
                ccp = nam ? "time_interval_int=" : "time interval "
                                "integer = ";
                printf("  %s%u\n", ccp, ui);
                break;
            case 4:     /* FUA statistics and performance log parameter */
                ccp = nam ? "parameter_code=4" : "Force unit access "
                        "statistics and performance log parameter ";
                printf("%s\n", ccp);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nam ? "read_fua_commands=" : "number of read FUA "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 12);
                ccp = nam ? "write_fua_commands=" : "number of write FUA "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 20);
                ccp = nam ? "read_fua_nv_commands="
                          : "number of read FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 28);
                ccp = nam ? "write_fua_nv_commands="
                          : "number of write FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 36);
                ccp = nam ? "read_fua_proc_intervals="
                          : "read FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 44);
                ccp = nam ? "write_fua_proc_intervals="
                          : "write FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 52);
                ccp = nam ? "read_fua_nv_proc_intervals="
                          : "read FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 60);
                ccp = nam ? "write_fua_nv_proc_intervals="
                          : "write FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 6:     /* Time interval log parameter for cache stats */
                ccp = nam ? "parameter_code=6" : "Time interval log "
                        "parameter for cache stats";
                printf("%s\n", ccp);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nam ? "time_interval_neg_exp=" : "time interval "
                                "negative exponent = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 8);
                ccp = nam ? "time_interval_int=" : "time interval "
                                "integer = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            default:
                if (nam) {
                    printf("parameter_code=%d\n", param_code);
                    printf("  unknown=1\n");
                } else
                    pr2serr("show_performance...  unknown parameter code "
                            "%d\n", param_code);
                if (op->verbose)
                    hex2stderr(bp, extra, 1);
                break;
            }
            if ((op->do_pcb) && (! op->do_name))
                printf("    <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
                if (op->do_raw) {
                    dStrRaw(bp, extra);
                    break;
                } else if (op->do_hex) {
                    hex2stdout(bp, extra, ((1 == op->do_hex) ? 1 : -1));
                    break;
                }
            }
            switch (param_code) {
            case 1:     /* Group n Statistics and performance log parameter */
                if (nam)
                    printf("parameter_code=1\n");
                else
                    printf("Group %d Statistics and performance log "
                           "parameter\n", subpg_code);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nam ? "gn_read_commands=" : "group n number of read "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 12);
                ccp = nam ? "gn_write_commands=" : "group n number of write "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 20);
                ccp = nam ? "gn_lb_received="
                          : "group n number of logical blocks received = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 28);
                ccp = nam ? "gn_lb_transmitted="
                          : "group n number of logical blocks transmitted = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 36);
                ccp = nam ? "gn_read_proc_intervals="
                          : "group n read command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 44);
                ccp = nam ? "gn_write_proc_intervals="
                          : "group n write command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 4: /* Group n FUA statistics and performance log parameter */
                ccp = nam ? "parameter_code=4" : "Group n force unit access "
                        "statistics and performance log parameter";
                printf("%s\n", ccp);
                ull = sg_get_unaligned_be64(bp + 4);
                ccp = nam ? "gn_read_fua_commands="
                          : "group n number of read FUA commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 12);
                ccp = nam ? "gn_write_fua_commands="
                          : "group n number of write FUA commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 20);
                ccp = nam ? "gn_read_fua_nv_commands="
                          : "group n number of read FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 28);
                ccp = nam ? "gn_write_fua_nv_commands="
                          : "group n number of write FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 36);
                ccp = nam ? "gn_read_fua_proc_intervals="
                          : "group n read FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 44);
                ccp = nam ? "gn_write_fua_proc_intervals=" : "group n write "
                            "FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 52);
                ccp = nam ? "gn_read_fua_nv_proc_intervals=" : "group n "
                            "read FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                ull = sg_get_unaligned_be64(bp + 60);
                ccp = nam ? "gn_write_fua_nv_proc_intervals=" : "group n "
                            "write FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            default:
                if (nam) {
                    printf("parameter_code=%d\n", param_code);
                    printf("  unknown=1\n");
                } else
                    pr2serr("show_performance...  unknown parameter code "
                            "%d\n", param_code);
                if (op->verbose)
                    hex2stderr(bp, extra, 1);
                break;
            }
            if ((op->do_pcb) && (! op->do_name))
                printf("    <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
            if (op->filter_given)
                break;
        }
    }
    return true;
}

/* Returns true if processed page, false otherwise */
/* STATS_LPAGE [0x19], CACHE_STATS_SUBPG [0x20]  introduced: SPC-4 */
static bool
show_cache_stats_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, pc, subpg_code, extra;
    bool nam, spf;
    unsigned int ui;
    const uint8_t * bp;
    const char * ccp;
    uint64_t ull;
    char str[PCB_STR_LEN];

    nam = op->do_name;
    num = len - 4;
    bp = resp + 4;
    if (num < 4) {
        pr2serr("badly formed Cache memory statistics page\n");
        return false;
    }
    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : 0;
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (nam) {
            printf("log_page=0x%x\n", STATS_LPAGE);
            if (subpg_code > 0)
                printf("log_subpage=0x%x\n", subpg_code);
        } else
            printf("Cache memory statistics page  [0x19,0x20]\n");
    }

    for (k = num; k > 0; k -= extra, bp += extra) {
        if (k < 3) {
            pr2serr("short Cache memory statistics page\n");
            return false;
        }
        if (8 != bp[3]) {
            printf("Cache memory statistics page parameter length not "
                   "8\n");
            return false;
        }
        extra = bp[3] + 4;
        pc = sg_get_unaligned_be16(bp + 0);
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw(bp, extra);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, extra, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 1:     /* Read cache memory hits log parameter */
            ccp = nam ? "parameter_code=1" :
                        "Read cache memory hits log parameter";
            printf("%s\n", ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nam ? "read_cache_memory_hits=" :
                        "read cache memory hits = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 2:     /* Reads to cache memory log parameter */
            ccp = nam ? "parameter_code=2" :
                        "Reads to cache memory log parameter";
            printf("%s\n", ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nam ? "reads_to_cache_memory=" :
                        "reads to cache memory = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 3:     /* Write cache memory hits log parameter */
            ccp = nam ? "parameter_code=3" :
                        "Write cache memory hits log parameter";
            printf("%s\n", ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nam ? "write_cache_memory_hits=" :
                        "write cache memory hits = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 4:     /* Writes from cache memory log parameter */
            ccp = nam ? "parameter_code=4" :
                        "Writes from cache memory log parameter";
            printf("%s\n", ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nam ? "writes_from_cache_memory=" :
                        "writes from cache memory = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 5:     /* Time from last hard reset log parameter */
            ccp = nam ? "parameter_code=5" :
                        "Time from last hard reset log parameter";
            printf("%s\n", ccp);
            ull = sg_get_unaligned_be64(bp + 4);
            ccp = nam ? "time_from_last_hard_reset=" :
                        "time from last hard reset = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 6:     /* Time interval log parameter for cache stats */
            ccp = nam ? "parameter_code=6" :
                        "Time interval log parameter";
            printf("%s\n", ccp);
            ui = sg_get_unaligned_be32(bp + 4);
            ccp = nam ? "time_interval_neg_exp=" : "time interval "
                            "negative exponent = ";
            printf("  %s%u\n", ccp, ui);
            ui = sg_get_unaligned_be32(bp + 8);
            ccp = nam ? "time_interval_int=" : "time interval "
                            "integer = ";
            printf("  %s%u\n", ccp, ui);
            break;
        default:
            if (nam) {
                printf("parameter_code=%d\n", pc);
                printf("  unknown=1\n");
            } else
                pr2serr("show_performance...  unknown parameter code %d\n",
                        pc);
            if (op->verbose)
                hex2stderr(bp, extra, 1);
            break;
        }
        if ((op->do_pcb) && (! op->do_name))
            printf("    <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
    }
    return true;
}

/* FORMAT_STATUS_LPAGE [0x8]  introduced: SBC-2 */
static bool
show_format_status_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int k, num, pl, pc;
    bool is_count;
    const uint8_t * bp;
    const uint8_t * xp;
    uint64_t ull;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Format status page  [0x8]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        is_count = true;
        switch (pc) {
        case 0:
            if (pl < 5)
                printf("  Format data out: <empty>\n");
            else {
                if (sg_all_ffs(bp + 4, pl - 4))
                    printf("  Format data out: <not available>\n");
                else {
                    printf("  Format data out:\n");
                    hex2stdout(bp + 4, pl - 4, 0);
                }
            }
            is_count = false;
            break;
        case 1:
            printf("  Grown defects during certification");
            break;
        case 2:
            printf("  Total blocks reassigned during format");
            break;
        case 3:
            printf("  Total new blocks reassigned");
            break;
        case 4:
            printf("  Power on minutes since format");
            break;
        default:
            printf("  Unknown Format parameter code = 0x%x\n", pc);
            is_count = false;
            hex2stdout(bp, pl, 0);
            break;
        }
        if (is_count) {
            k = pl - 4;
            xp = bp + 4;
            if (sg_all_ffs(xp, k))
                printf(" <not available>\n");
            else {
                if (k > (int)sizeof(ull)) {
                    xp += (k - sizeof(ull));
                    k = sizeof(ull);
                }
                ull = sg_get_unaligned_be(k, xp);
                printf(" = %" PRIu64 "\n", ull);
            }
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Non-volatile cache page [0x17]  introduced: SBC-2 */
static bool
show_non_volatile_cache_page(const uint8_t * resp, int len,
                             const struct opts_t * op)
{
    int j, num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Non-volatile cache page  [0x17]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            printf("  Remaining non-volatile time: ");
            if (3 == bp[4]) {
                j = sg_get_unaligned_be24(bp + 5);
                switch (j) {
                case 0:
                    printf("0 (i.e. it is now volatile)\n");
                    break;
                case 1:
                    printf("<unknown>\n");
                    break;
                case 0xffffff:
                    printf("<indefinite>\n");
                    break;
                default:
                    printf("%d minutes [%d:%d]\n", j, (j / 60), (j % 60));
                    break;
                }
            } else
                printf("<unexpected parameter length=%d>\n", bp[4]);
            break;
        case 1:
            printf("  Maximum non-volatile time: ");
            if (3 == bp[4]) {
                j = sg_get_unaligned_be24(bp + 5);
                switch (j) {
                case 0:
                    printf("0 (i.e. it is now volatile)\n");
                    break;
                case 1:
                    printf("<reserved>\n");
                    break;
                case 0xffffff:
                    printf("<indefinite>\n");
                    break;
                default:
                    printf("%d minutes [%d:%d]\n", j, (j / 60), (j % 60));
                    break;
                }
            } else
                printf("<unexpected parameter length=%d>\n", bp[4]);
            break;
        default:
            printf("  Unknown parameter code = 0x%x\n", pc);
            hex2stdout(bp, pl, 0);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* LB_PROV_LPAGE [0xc]  introduced: SBC-3 */
static bool
show_lb_provisioning_page(const uint8_t * resp, int len,
                          const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    const char * cp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Logical block provisioning page  [0xc]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x1:
            cp = "  Available LBA mapping threshold";
            break;
        case 0x2:
            cp = "  Used LBA mapping threshold";
            break;
        case 0x3:
            cp = "  Available provisioning resource percentage";
            break;
        case 0x100:
            cp = "  De-duplicated LBA";
            break;
        case 0x101:
            cp = "  Compressed LBA";
            break;
        case 0x102:
            cp = "  Total efficiency LBA";
            break;
        default:
            cp = NULL;
            break;
        }
        if (cp) {
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected at "
                            "least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            if (0x3 == pc)      /* resource percentage log parameter */
                printf("  %s: %u %%\n", cp, sg_get_unaligned_be16(bp + 4));
            else                /* resource count log parameters */
                printf("  %s resource count: %u\n", cp,
                       sg_get_unaligned_be32(bp + 4));
            if (pl > 8) {
                switch (bp[8] & 0x3) {      /* SCOPE field */
                case 0: cp = "not reported"; break;
                case 1: cp = "dedicated to lu"; break;
                case 2: cp = "not dedicated to lu"; break;
                case 3: cp = "reserved"; break;
                }
                printf("    Scope: %s\n", cp);
            }
        } else if ((pc >= 0xfff0) && (pc <= 0xffff)) {
            printf("  Vendor specific [0x%x]:", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), 0);
        } else {
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), 0);
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* UTILIZATION_SUBPG [0xe,0x1]  introduced: SBC-4 */
static bool
show_utilization_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int num, pl, pc, k;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Utilization page  [0xe,0x1]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x0:
            printf("  Workload utilization:");
            if ((pl < 6) || (num < 6)) {
                if (num < 6)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 6 bytes\n");
                else
                    pr2serr("\n    parameter length >= 6 expected, got %d\n",
                            pl);
                break;
            }
            k = sg_get_unaligned_be16(bp + 4);
            printf(" %d.%02d %%\n", k / 100, k % 100);
            break;
        case 0x1:
            printf("  Utilization usage rate based on date and time:");
            if ((pl < 6) || (num < 6)) {
                if (num < 6)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 6 bytes\n");
                else
                    pr2serr("\n    parameter length >= 6 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %d %%\n", bp[4]);
            break;
        default:
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), 0);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* SOLID_STATE_MEDIA_LPAGE [0x11]  introduced: SBC-3 */
static bool
show_solid_state_media_page(const uint8_t * resp, int len,
                            const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Solid state media page  [0x11]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x1:
            printf("  Percentage used endurance indicator:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %u %%\n", bp[7]);
            break;
        default:
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), 0);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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

/* DT device status [0x11] (ssc, adc) */
static bool
show_dt_device_status_page(const uint8_t * resp, int len,
                           const struct opts_t * op)
{
    int num, pl, pc, j;
    const uint8_t * bp;
    char str[PCB_STR_LEN];
    char b[64];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("DT device status page (ssc-3, adc-3) [0x11]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x0:
            printf("  Very high frequency data:\n");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("    truncated by response length, expected at "
                            "least 8 bytes\n");
                else
                    pr2serr("    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf("  PAMR=%d HUI=%d MACC=%d CMPR=%d ", !!(0x80 & bp[4]),
                   !!(0x40 & bp[4]), !!(0x20 & bp[4]), !!(0x10 & bp[4]));
            printf("WRTP=%d CRQST=%d CRQRD=%d DINIT=%d\n", !!(0x8 & bp[4]),
                   !!(0x4 & bp[4]), !!(0x2 & bp[4]), !!(0x1 & bp[4]));
            printf("  INXTN=%d RAA=%d MPRSNT=%d ", !!(0x80 & bp[5]),
                   !!(0x20 & bp[5]), !!(0x10 & bp[5]));
            printf("MSTD=%d MTHRD=%d MOUNTED=%d\n",
                   !!(0x4 & bp[5]), !!(0x2 & bp[5]), !!(0x1 & bp[5]));
            printf("  DT device activity: ");
            j = bp[6];
            if (j < (int)SG_ARRAY_SIZE(dt_dev_activity))
                printf("%s\n", dt_dev_activity[j]);
            else if (j < 0x80)
                printf("Reserved [0x%x]\n", j);
            else
                printf("Vendor specific [0x%x]\n", j);
            printf("  VS=%d TDDEC=%d EPP=%d ", !!(0x80 & bp[7]),
                   !!(0x20 & bp[7]), !!(0x10 & bp[7]));
            printf("ESR=%d RRQST=%d INTFC=%d TAFC=%d\n", !!(0x8 & bp[7]),
                   !!(0x4 & bp[7]), !!(0x2 & bp[7]), !!(0x1 & bp[7]));
            break;
        case 0x1:
            printf("  Very high frequency polling delay: ");
            if ((pl < 6) || (num < 6)) {
                if (num < 6)
                    pr2serr("\n    truncated by response length, expected at "
                            "least 6 bytes\n");
                else
                    pr2serr("\n    parameter length >= 6 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %d milliseconds\n", sg_get_unaligned_be16(bp + 4));
            break;
        case 0x2:
            printf("   DT device ADC data encryption control status (hex "
                   "only now):\n");
            if ((pl < 12) || (num < 12)) {
                if (num < 12)
                    pr2serr("    truncated by response length, expected at "
                            "least 12 bytes\n");
                else
                    pr2serr("    parameter length >= 12 expected, got %d\n",
                            pl);
                break;
            }
            hex2stdout(bp + 4, 8, 1);
            break;
        case 0x3:
            printf("   Key management error data (hex only now):\n");
            if ((pl < 16) || (num < 16)) {
                if (num < 16)
                    pr2serr("    truncated by response length, expected at "
                            "least 16 bytes\n");
                else
                    pr2serr("    parameter length >= 16 expected, got %d\n",
                            pl);
                break;
            }
            hex2stdout(bp + 4, 12, 1);
            break;
        default:
            if ((pc >= 0x101) && (pc <= 0x1ff)) {
                printf("  Primary port %d status:\n", pc - 0x100);
                if (12 == bp[3]) { /* if length of desc is 12, assume SAS */
                    printf("    SAS: negotiated physical link rate: %s\n",
                           sas_negot_link_rate((0xf & (bp[4] >> 4)), b,
                                               sizeof(b)));
                    printf("    signal=%d, pic=%d, ", !!(0x2 & bp[4]),
                           !!(0x1 & bp[4]));
                    printf("hashed SAS addr: 0x%u\n",
                            sg_get_unaligned_be24(bp + 5));
                    printf("    SAS addr: 0x%" PRIx64 "\n",
                            sg_get_unaligned_be64(bp + 8));
                } else {
                    printf("    non-SAS transport, in hex:\n");
                    hex2stdout(bp + 4, ((pl < num) ? pl : num) - 4, 0);
                }
            } else if (pc >= 0x8000) {
                printf("  Vendor specific [parameter_code=0x%x]:\n", pc);
                hex2stdout(bp, ((pl < num) ? pl : num), 0);
            } else {
                printf("  Reserved [parameter_code=0x%x]:\n", pc);
                hex2stdout(bp, ((pl < num) ? pl : num), 0);
            }
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* TapeAlert response [0x12] (adc,ssc) */
static bool
show_tapealert_response_page(const uint8_t * resp, int len,
                             const struct opts_t * op)
{
    int num, pl, pc, k, mod, div;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("TapeAlert response page (ssc-3, adc-3) [0x12]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x0:
            if (pl < 12) {

            }
            for (k = 1; k < 0x41; ++k) {
                mod = ((k - 1) % 8);
                div = (k - 1) / 8;
                if (0 == mod) {
                    if (div > 0)
                        printf("\n");
                    printf("  Flag%02Xh: %d", k, !! (bp[4 + div] & 0x80));
                } else
                    printf("  %02Xh: %d", k,
                           !! (bp[4 + div] & (1 << (7 - mod))));
            }
            printf("\n");
            break;
        default:
            if (pc <= 0x8000) {
                printf("  Reserved [parameter_code=0x%x]:\n", pc);
                hex2stdout(bp, ((pl < num) ? pl : num), 0);
            } else {
                printf("  Vendor specific [parameter_code=0x%x]:\n", pc);
                hex2stdout(bp, ((pl < num) ? pl : num), 0);
            }
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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

/* Requested recovery [0x13] (ssc) */
static bool
show_requested_recovery_page(const uint8_t * resp, int len,
                             const struct opts_t * op)
{
    int num, pl, pc, j, k;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Requested recovery page (ssc-3) [0x13]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x0:
            printf("  Recovery procedures:\n");
            for (k = 4; k < pl; ++ k) {
                j = bp[k];
                if (j < NUM_REQ_REC_ARR_ELEMS)
                    printf("    %s\n", req_rec_arr[j]);
                else if (j < 0x80)
                    printf("    Reserved [0x%x]\n", j);
                else
                    printf("    Vendor specific [0x%x]\n", j);
            }
            break;
        default:
            if (pc <= 0x8000) {
                printf("  Reserved [parameter_code=0x%x]:\n", pc);
                hex2stdout(bp, ((pl < num) ? pl : num), 0);
            } else {
                printf("  Vendor specific [parameter_code=0x%x]:\n", pc);
                hex2stdout(bp, ((pl < num) ? pl : num), 0);
            }
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* SAT_ATA_RESULTS_LPAGE (SAT-2) [0x16] */
static bool
show_ata_pt_results_page(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    const uint8_t * dp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("ATA pass-through results page (sat-2) [0x16]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if ((pc < 0xf) && (pl > 17)) {
            int extend, count;

            printf("  Log_index=0x%x (parameter_code=0x%x)\n", pc + 1, pc);
            dp = bp + 4;       /* dp is start of ATA Return descriptor
                                 * which is 14 bytes long */
            extend = dp[2] & 1;
            count = dp[5] + (extend ? (dp[4] << 8) : 0);
            printf("    extend=%d  error=0x%x count=0x%x\n", extend,
                   dp[3], count);
            if (extend)
                printf("    lba=0x%02x%02x%02x%02x%02x%02x\n", dp[10], dp[8],
                       dp[6], dp[11], dp[9], dp[7]);
            else
                printf("    lba=0x%02x%02x%02x\n", dp[11], dp[9], dp[7]);
            printf("    device=0x%x  status=0x%x\n", dp[12], dp[13]);
        } else if (pl > 17) {
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), 0);
        } else {
            printf("  short parameter length: %d [parameter_code=0x%x]:\n",
                   pl, pc);
            hex2stdout(bp, ((pl < num) ? pl : num), 0);
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
    "background scan enabled, none active (waiting for BMS interval timer "
        "to expire)", /* 8 */
    "background scan halted - scan results list full",
    "background scan halted - pre-scan time limit timer expired" /* 10 */,
};

static const char * reassign_status[] = {
    "Reassign status: Reserved [0x0]",
    "Reassignment pending receipt of Reassign or Write command",
    "Logical block successfully reassigned by device server",
    "Reassign status: Reserved [0x3]",
    "Reassignment by device server failed",
    "Logical block recovered by device server via rewrite",
    "Logical block reassigned by application client, has valid data",
    "Logical block reassigned by application client, contains no valid data",
    "Logical block unsuccessfully reassigned by application client", /* 8 */
};

/* Background scan results [0x15,0] for disk  introduced: SBC-3 */
static bool
show_background_scan_results_page(const uint8_t * resp, int len,
                                  const struct opts_t * op)
{
    int j, m, num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Background scan results page  [0x15]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            printf("  Status parameters:\n");
            if ((pl < 16) || (num < 16)) {
                if (num < 16)
                    pr2serr("    truncated by response length, expected at "
                            "least 16 bytes\n");
                else
                    pr2serr("    parameter length >= 16 expected, got %d\n",
                            pl);
                break;
            }
            printf("    Accumulated power on minutes: ");
            j = sg_get_unaligned_be32(bp + 4);
            printf("%d [h:m  %d:%d]\n", j, (j / 60), (j % 60));
            printf("    Status: ");
            j = bp[9];
            if (j < (int)SG_ARRAY_SIZE(bms_status))
                printf("%s\n", bms_status[j]);
            else
                printf("unknown [0x%x] background scan status value\n", j);
            j = sg_get_unaligned_be16(bp + 10);
            printf("    Number of background scans performed: %d\n", j);
            j = sg_get_unaligned_be16(bp + 12);
#ifdef SG_LIB_MINGW
            printf("    Background medium scan progress: %g %%\n",
                   (double)(j * 100.0 / 65536.0));
#else
            printf("    Background medium scan progress: %.2f %%\n",
                   (double)(j * 100.0 / 65536.0));
#endif
            j = sg_get_unaligned_be16(bp + 14);
            if (0 == j)
                printf("    Number of background medium scans performed: 0 "
                       "[not reported]\n");
            else
                printf("    Number of background medium scans performed: "
                       "%d\n", j);
            break;
        default:
            if (pc > 0x800) {
                if ((pc >= 0x8000) && (pc <= 0xafff))
                    printf("  Medium scan parameter # %d [0x%x], vendor "
                           "specific\n", pc, pc);
                else
                    printf("  Medium scan parameter # %d [0x%x], "
                           "reserved\n", pc, pc);
                hex2stdout(bp, ((pl < num) ? pl : num), 0);
                break;
            } else
                printf("  Medium scan parameter # %d [0x%x]\n", pc, pc);
            if ((pl < 24) || (num < 24)) {
                if (num < 24)
                    pr2serr("    truncated by response length, expected at "
                            "least 24 bytes\n");
                else
                    pr2serr("    parameter length >= 24 expected, got %d\n",
                            pl);
                break;
            }
            printf("    Power on minutes when error detected: ");
            j = sg_get_unaligned_be32(bp + 4);
            printf("%d [%d:%d]\n", j, (j / 60), (j % 60));
            j = (bp[8] >> 4) & 0xf;
            if (j < (int)SG_ARRAY_SIZE(reassign_status))
                printf("    %s\n", reassign_status[j]);
            else
                printf("    Reassign status: reserved [0x%x]\n", j);
            printf("    sense key: %s  [sk,asc,ascq: 0x%x,0x%x,0x%x]\n",
                   sg_get_sense_key_str(bp[8] & 0xf, sizeof(str), str),
                   bp[8] & 0xf, bp[9], bp[10]);
            if (bp[9] || bp[10])
                printf("      %s\n", sg_get_asc_ascq_str(bp[9], bp[10],
                                                         sizeof(str), str));
            if (op->verbose) {
                printf("    vendor bytes [11 -> 15]: ");
                for (m = 0; m < 5; ++m)
                    printf("0x%02x ", bp[11 + m]);
                printf("\n");
            }
            printf("    LBA (associated with medium error): 0x");
            if (sg_all_zeros(bp + 16, 8))
                printf("0\n");
            else {
                for (m = 0; m < 8; ++m)
                    printf("%02x", bp[16 + m]);
                printf("\n");
            }
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* ZONED_BLOCK_DEV_STATS_SUBPG [0x14,0x1]  introduced: zbc2r01 */
static bool
show_zoned_block_dev_stats(const uint8_t * resp, int len,
                           const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Zoned block device statistics page  [0x14,0x1]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x0:
            printf("  Maximum open zones:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x1:
            printf("  Maximum explicitly open zones:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x2:
            printf("  Maximum implicitly open zones:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x3:
            printf("  Minimum empty zones:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x4:
            printf("  Maximum non-sequential zones:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x5:
            printf("  Zones emptied:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x6:
            printf("  Suboptimal write commands:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x7:
            printf("  Commands exceeding optimal limit:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x8:
            printf("  Failed explicit opens:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0x9:
            printf("  Read rule violations:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0xa:
            printf("  Write rule violations:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        case 0xb:       /* added zbc2r04 */
            printf("  Maximum implicitly open or before required zones:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" %" PRIu32 "\n", sg_get_unaligned_be32(bp + 8));
            break;
        default:
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), 0);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* PENDING_DEFECTS_SUBPG [0x15,0x1]  introduced: SBC-4 */
static bool
show_pending_defects_page(const uint8_t * resp, int len,
                          const struct opts_t * op)
{
    int num, pl, pc;
    uint32_t count;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Pending defects page  [0x15,0x1]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x0:
            printf("  Pending defect count: ");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            count = sg_get_unaligned_be32(bp + 4);
            if (0 == count) {
                printf("0\n");
                break;
            }
            printf("%3u  |     LBA            Accumulated power_on\n", count);
            printf("-----------------------------|---------------");
            printf("-----------hours---------\n");
            break;
        default:
            printf("  Pending defect %4d:  ", pc);
            if ((pl < 16) || (num < 16)) {
                if (num < 16)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 16 bytes\n");
                else
                    pr2serr("\n    parameter length >= 16 expected, got %d\n",
                            pl);
                break;
            }
            printf("        0x%-16" PRIx64 "      %5u\n",
                   sg_get_unaligned_be64(bp + 8),
                   sg_get_unaligned_be32(bp + 4));
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* BACKGROUND_OP_SUBPG [0x15,0x2]  introduced: SBC-4 rev 7 */
static bool
show_background_op_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Background operation page  [0x15,0x2]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x0:
            printf("  Background operation:");
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected "
                            "at least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            printf(" BO_STATUS=%d\n", bp[4]);
            break;
        default:
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            hex2stdout(bp, ((pl < num) ? pl : num), 0);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* LPS misalignment page [0x15,0x3]  introduced: SBC-4 rev 10
   LPS: "Long Physical Sector" a term from an ATA feature set */
static bool
show_lps_misalignment_page(const uint8_t * resp, int len,
                           const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("LPS misalignment page  [0x15,0x3]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0x0:
            printf("  LPS misalignment count: ");
            if (4 == bp[3])
                printf("max lpsm: %" PRIu16 ", count=%" PRIu16 "\n",
                       sg_get_unaligned_be16(bp + 4),
                       sg_get_unaligned_be16(bp + 6));
            else
                printf("<unexpected pc=0 parameter length=%d>\n", bp[4]);
            break;
        default:
            if (pc <= 0xf000) {         /* parameter codes 0x1 to 0xf000 */
                if (8 == bp[3])
                    printf("  LBA of misaligned block: 0x%" PRIx64 "\n",
                           sg_get_unaligned_be64(bp + 4));
                else
                    printf("<unexpected pc=0x%x parameter length=%d>\n",
                           pc, bp[4]);
            } else {
                printf("<unexpected pc=0x%x>\n", pc);
                hex2stdout(bp, pl, 0);
            }
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Service buffer information [0x15] (adc) */
static bool
show_service_buffer_info_page(const uint8_t * resp, int len,
                              const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Service buffer information page (adc-3) [0x15]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if (pc < 0x100) {
            printf("  Service buffer identifier: 0x%x\n", pc);
            printf("    Buffer id: 0x%x, tu=%d, nmp=%d, nmm=%d, "
                   "offline=%d\n", bp[4], !!(0x10 & bp[5]),
                   !!(0x8 & bp[5]), !!(0x4 & bp[5]), !!(0x2 & bp[5]));
            printf("    pd=%d, code_set: %s, Service buffer title:\n",
                   !!(0x1 & bp[5]), sg_get_desig_code_set_str(0xf & bp[6]));
            printf("      %.*s\n", pl - 8, bp + 8);
        } else if (pc < 0x8000) {
            printf("  parameter_code=0x%x, Reserved, parameter in hex:\n",
                   pc);
            hex2stdout(bp + 4, pl - 4, 0);
        } else {
            printf("  parameter_code=0x%x, Vendor-specific, parameter in "
                   "hex:\n", pc);
            hex2stdout(bp + 4, pl - 4, 0);
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Sequential access device page [0xc] for tape */
static bool
show_sequential_access_page(const uint8_t * resp, int len,
                            const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    uint64_t ull, gbytes;
    bool all_set;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Sequential access device page (ssc-3)\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        ull = sg_get_unaligned_be(pl - 4, bp + 4);
        all_set = sg_all_ffs(bp + 4, pl - 4);
        gbytes = ull / 1000000000;
        switch (pc) {
        case 0:
            printf("  Data bytes received with WRITE commands: %" PRIu64
                   " GB", gbytes);
            if (op->verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 1:
            printf("  Data bytes written to media by WRITE commands: %" PRIu64
                   " GB", gbytes);
            if (op->verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 2:
            printf("  Data bytes read from media by READ commands: %" PRIu64
                   " GB", gbytes);
            if (op->verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 3:
            printf("  Data bytes transferred by READ commands: %" PRIu64
                   " GB", gbytes);
            if (op->verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 4:
            if (! all_set)
                printf("  Native capacity from BOP to EOD: %" PRIu64 " MB\n",
                       ull);
            break;
        case 5:
            if (! all_set)
                printf("  Native capacity from BOP to EW of current "
                       "partition: %" PRIu64 " MB\n", ull);
            break;
        case 6:
            if (! all_set)
                printf("  Minimum native capacity from EW to EOP of current "
                       "partition: %" PRIu64 " MB\n", ull);
            break;
        case 7:
            if (! all_set)
                printf("  Native capacity from BOP to current position: %"
                       PRIu64 " MB\n", ull);
            break;
        case 8:
            if (! all_set)
                printf("  Maximum native capacity in device object buffer: %"
                       PRIu64 " MB\n", ull);
            break;
        case 0x100:
            if (ull > 0)
                printf("  Cleaning action required\n");
            else
                printf("  Cleaning action not required (or completed)\n");
            if (op->verbose)
                printf("    cleaning value: %" PRIu64 "\n", ull);
            break;
        default:
            if (pc >= 0x8000)
                printf("  Vendor specific parameter [0x%x] value: %" PRIu64
                       "\n", pc, ull);
            else
                printf("  Reserved parameter [0x%x] value: %" PRIu64 "\n",
                       pc, ull);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* 0x14 for tape and ADC */
static bool
show_device_stats_page(const uint8_t * resp, int len,
                       const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Device statistics page (ssc-3 and adc)\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if (pc < 0x1000) {
            bool vl_num = true;

            switch (pc) {
            case 0:
                printf("  Lifetime media loads:");
                break;
            case 1:
                printf("  Lifetime cleaning operations:");
                break;
            case 2:
                printf("  Lifetime power on hours:");
                break;
            case 3:
                printf("  Lifetime media motion (head) hours:");
                break;
            case 4:
                printf("  Lifetime metres of tape processed:");
                break;
            case 5:
                printf("  Lifetime media motion (head) hours when "
                       "incompatible media last loaded:");
                break;
            case 6:
                printf("  Lifetime power on hours when last temperature "
                       "condition occurred:");
                break;
            case 7:
                printf("  Lifetime power on hours when last power "
                       "consumption condition occurred:");
                break;
            case 8:
                printf("  Media motion (head) hours since last successful "
                       "cleaning operation:");
                break;
            case 9:
                printf("  Media motion (head) hours since 2nd to last "
                       "successful cleaning:");
                break;
            case 0xa:
                printf("  Media motion (head) hours since 3rd to last "
                       "successful cleaning:");
                break;
            case 0xb:
                printf("  Lifetime power on hours when last operator "
                       "initiated forced reset\n    and/or emergency "
                       "eject occurred:");
                break;
            case 0xc:
                printf("  Lifetime power cycles:");
                break;
            case 0xd:
                printf("  Volume loads since last parameter reset:");
                break;
            case 0xe:
                printf("  Hard write errors:");
                break;
            case 0xf:
                printf("  Hard read errors:");
                break;
            case 0x10:
                printf("  Duty cycle sample time (ms):");
                break;
            case 0x11:
                printf("  Read duty cycle:");
                break;
            case 0x12:
                printf("  Write duty cycle:");
                break;
            case 0x13:
                printf("  Activity duty cycle:");
                break;
            case 0x14:
                printf("  Volume not present duty cycle:");
                break;
            case 0x15:
                printf("  Ready duty cycle:");
                break;
            case 0x16:
                printf("  MBs transferred from app client in duty cycle "
                       "sample time:");
                break;
            case 0x17:
                printf("  MBs transferred to app client in duty cycle "
                       "sample time:");
                break;
            case 0x40:
                printf("  Drive manufacturer's serial number:");
                break;
            case 0x41:
                printf("  Drive serial number:");
                break;
            case 0x42:          /* added ssc5r02b */
                vl_num = false;
                printf("  Manufacturing date (yyyymmdd): %.*s\n", pl - 4,
                       bp + 4);
                break;
            case 0x43:          /* added ssc5r02b */
                vl_num = false;
                printf("  Manufacturing date (yyyyww): %.*s\n", pl - 4,
                       bp + 4);
                break;
            case 0x80:
                printf("  Medium removal prevented:");
                break;
            case 0x81:
                printf("  Maximum recommended mechanism temperature "
                       "exceeded:");
                break;
            default:
                vl_num = false;
                printf("  Reserved parameter code [0x%x] data in hex:\n", pc);
                hex2stdout(bp + 4, pl - 4, 0);
                break;
            }
            if (vl_num)
                printf(" %" PRIu64 "\n", sg_get_unaligned_be(pl - 4, bp + 4));
        } else {        /* parameter_code >= 0x1000 */
            int k;
            const uint8_t * p = bp + 4;

            switch (pc) {
            case 0x1000:
                printf("  Media motion (head) hours for each medium type:\n");
                for (k = 0; ((pl - 4) - k) >= 8; k += 8, p += 8) {
                    printf("    Density code: 0x%x, Medium type: 0x%x\n",
                           p[2], p[3]);
                    printf("      Medium motion hours: %u\n",
                           sg_get_unaligned_be32(p + 4));
                }
                break;
            default:
                if (pc >= 0x8000)
                    printf("  Vendor specific parameter [0x%x], dump in "
                           "hex:\n", pc);
                else
                    printf("  Reserved parameter [0x%x], dump in hex:\n", pc);
                hex2stdout(bp + 4, pl - 4, 0);
                break;
            }
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* 0x14 for media changer */
static bool
show_media_stats_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    uint64_t ull;
    char str[PCB_STR_LEN];

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
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
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
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* Element statistics page, 0x15 for SMC */
static bool
show_element_stats_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int num, pl, pc;
    unsigned int v;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

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
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
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
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* 0x16 for tape */
static bool
show_tape_diag_data_page(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    int k, num, pl, pc;
    unsigned int v;
    const uint8_t * bp;
    char str[PCB_STR_LEN];
    char b[80];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Tape diagnostics data page (ssc-3) [0x16]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Parameter code: %d\n", pc);
        printf("    Density code: 0x%x\n", bp[6]);
        printf("    Medium type: 0x%x\n", bp[7]);
        v = sg_get_unaligned_be32(bp + 8);
        printf("    Lifetime media motion hours: %u\n", v);
        printf("    Repeat: %d\n", !!(bp[13] & 0x80));
        v = bp[13] & 0xf;
        printf("    Sense key: 0x%x [%s]\n", v,
               sg_get_sense_key_str(v, sizeof(b), b));
        printf("    Additional sense code: 0x%x\n", bp[14]);
        printf("    Additional sense code qualifier: 0x%x\n", bp[15]);
        if (bp[14] || bp[15])
            printf("      [%s]\n", sg_get_asc_ascq_str(bp[14], bp[15],
                   sizeof(b), b));
        v = sg_get_unaligned_be32(bp + 16);
        printf("    Vendor specific code qualifier: 0x%x\n", v);
        v = sg_get_unaligned_be32(bp + 20);
        printf("    Product revision level: %u\n", v);
        v = sg_get_unaligned_be32(bp + 24);
        printf("    Hours since last clean: %u\n", v);
        printf("    Operation code: 0x%x\n", bp[28]);
        printf("    Service action: 0x%x\n", bp[29] & 0xf);
        // Check Medium id number for all zeros
        // ssc4r03.pdf does not define this field, why? xxxxxx
        if (sg_all_zeros(bp + 32, 32))
            printf("    Medium id number is 32 bytes of zero\n");
        else {
            printf("    Medium id number (in hex):\n");
            hex2stdout(bp + 32, 32, 0);
        }
        printf("    Timestamp origin: 0x%x\n", bp[64] & 0xf);
        // Check Timestamp for all zeros
        for (k = 66; k < 72; ++k) {
            if(bp[k])
                break;
        }
        if (72 == k)
            printf("    Timestamp is all zeros:\n");
        else {
            printf("    Timestamp:\n");
            hex2stdout(bp + 66, 6, 1);
        }
        if (pl > 72) {
            printf("    Vendor specific:\n");
            hex2stdout(bp + 72, pl - 72, 0);
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* 0x16 for media changer */
static bool
show_mchanger_diag_data_page(const uint8_t * resp, int len,
                             const struct opts_t * op)
{
    int num, pl, pc;
    unsigned int v;
    const uint8_t * bp;
    char str[PCB_STR_LEN];
    char b[80];

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
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Parameter code: %d\n", pc);
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
            hex2stdout((bp + 56), 36, 0);
        }
        if (pl > 99) {
            printf("    Timestamp origin: 0x%x\n", bp[92] & 0xf);
            printf("    Timestamp:\n");
            hex2stdout((bp + 94), 6, 1);
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
volume_stats_partition(const uint8_t * xp, int len, bool in_hex)
{
    int dl, pn;
    bool all_ffs, ffs_last_fe;
    uint64_t ull;

    while (len > 3) {
        dl = xp[0] + 1;
        if (dl < 3)
            return;
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
        if (! (all_ffs || ffs_last_fe)) {
            ull = sg_get_unaligned_be(dl - 4, xp + 4);
            if (in_hex)
                printf("    partition number: %d, partition record data "
                       "counter: 0x%" PRIx64 "\n", pn, ull);
            else
                printf("    partition number: %d, partition record data "
                       "counter: %" PRIu64 "\n", pn, ull);
        } else if (all_ffs)
            printf("    partition number: %d, partition record data "
                   "counter is all 0xFFs\n", pn);
        else    /* ffs_last_fe is true */
            printf("    partition number: %d, partition record data "
                   "counter is all 0xFFs apart\n    from a trailing "
                   "0xFE\n", pn);
        xp += dl;
        len -= dl;
    }
}

/* Helper for show_volume_stats_pages() */
static void
volume_stats_history(const uint8_t * xp, int len)
{
    int dl, mhi;

    while (len > 3) {
        dl = xp[0] + 1;
        if (dl < 4)
            return;
        mhi = sg_get_unaligned_be16(xp + 2);
        if (dl < 12)
            printf("    index: %d\n", mhi);
        else if (12 == dl)
            printf("    index: %d, vendor: %.8s\n", mhi, xp + 4);
        else
            printf("    index: %d, vendor: %.8s, unit serial number: %.*s\n",
                   mhi, xp + 4, dl - 12, xp + 12);
        xp += dl;
        len -= dl;
    }
}

/* Volume Statistics log page and subpages (ssc-4) [0x17, 0x0-0xf] */
static bool
show_volume_stats_pages(const uint8_t * resp, int len,
                       const struct opts_t * op)
{
    int num, pl, pc, subpg_code;
    bool spf;
    const uint8_t * bp;
    char str[PCB_STR_LEN];
    char b[64];

    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : 0;
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex))) {
        if (subpg_code < 0x10)
            printf("Volume statistics page (ssc-4), subpage=%d\n",
                   subpg_code);
        else {
            printf("Volume statistics page (ssc-4), subpage=%d; Reserved, "
                   "skip\n", subpg_code);
            return false;
        }
    }
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }

        switch (pc) {
        case 0:
            printf("  Page valid: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 1:
            printf("  Thread count: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 2:
            printf("  Total data sets written: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 3:
            printf("  Total write retries: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 4:
            printf("  Total unrecovered write errors: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 5:
            printf("  Total suspended writes: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 6:
            printf("  Total fatal suspended writes: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 7:
            printf("  Total data sets read: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 8:
            printf("  Total read retries: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 9:
            printf("  Total unrecovered read errors: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0xa:
            printf("  Total suspended reads: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0xb:
            printf("  Total fatal suspended reads: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0xc:
            printf("  Last mount unrecovered write errors: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0xd:
            printf("  Last mount unrecovered read errors: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0xe:
            printf("  Last mount megabytes written: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0xf:
            printf("  Last mount megabytes read: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x10:
            printf("  Lifetime megabytes written: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x11:
            printf("  Lifetime megabytes read: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x12:
            printf("  Last load write compression ratio: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x13:
            printf("  Last load read compression ratio: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x14:
            printf("  Medium mount time: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x15:
            printf("  Medium ready time: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x16:
            printf("  Total native capacity [MB]: %s\n",
                   num_or_unknown(bp + 4, pl - 4, false, b, sizeof(b)));
            break;
        case 0x17:
            printf("  Total used native capacity [MB]: %s\n",
                   num_or_unknown(bp + 4, pl - 4, false, b, sizeof(b)));
            break;
        case 0x40:
            printf("  Volume serial number: %.*s\n", pl - 4, bp + 4);
            break;
        case 0x41:
            printf("  Tape lot identifier: %.*s\n", pl - 4, bp + 4);
            break;
        case 0x42:
            printf("  Volume barcode: %.*s\n", pl - 4, bp + 4);
            break;
        case 0x43:
            printf("  Volume manufacturer: %.*s\n", pl - 4, bp + 4);
            break;
        case 0x44:
            printf("  Volume license code: %.*s\n", pl - 4, bp + 4);
            break;
        case 0x45:
            printf("  Volume personality: %.*s\n", pl - 4, bp + 4);
            break;
        case 0x80:
            printf("  Write protect: %s\n",
                   num_or_unknown(bp + 4, pl - 4, false, b, sizeof(b)));
            break;
        case 0x81:
            printf("  WORM: %s\n",
                   num_or_unknown(bp + 4, pl - 4, false, b, sizeof(b)));
            break;
        case 0x82:
            printf("  Maximum recommended tape path temperature exceeded: "
                   "%s\n", num_or_unknown(bp + 4, pl - 4, false, b,
                                          sizeof(b)));
            break;
        case 0x100:
            printf("  Volume write mounts: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x101:
            printf("  Beginning of medium passes: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x102:
            printf("  Middle of medium passes: %" PRIu64 "\n",
                   sg_get_unaligned_be(pl - 4, bp + 4));
            break;
        case 0x200:
            printf("  Logical position of first encrypted logical object:\n");
            volume_stats_partition(bp + 4, pl - 4, true);
            break;
        case 0x201:
            printf("  Logical position of first unencrypted logical object "
                   "after first\n  encrypted logical object:\n");
            volume_stats_partition(bp + 4, pl - 4, true);
            break;
        case 0x202:
            printf("  Native capacity partition(s) [MB]:\n");
            volume_stats_partition(bp + 4, pl - 4, false);
            break;
        case 0x203:
            printf("  Used native capacity partition(s) [MB]:\n");
            volume_stats_partition(bp + 4, pl - 4, false);
            break;
        case 0x204:
            printf("  Remaining native capacity partition(s) [MB]:\n");
            volume_stats_partition(bp + 4, pl - 4, false);
            break;
        case 0x300:
            printf("  Mount history:\n");
            volume_stats_history(bp + 4, pl - 4);
            break;

        default:
            if (pc >= 0xf000)
                printf("  Vendor specific parameter code (0x%x), payload "
                       "in hex\n", pc);
            else
                printf("  Reserved parameter code (0x%x), payload in hex\n",
                       pc);
            hex2stdout(bp + 4, pl - 4, 0);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

static const char * tape_alert_strs[] = {
    "<parameter code 0, unknown>",              /* 0x0 */
    "Read warning",
    "Write warning",
    "Hard error",
    "Media",
    "Read failure",
    "Write failure",
    "Media life",
    "Not data grade",                           /* 0x8 */
    "Write protect",
    "No removal",
    "Cleaning media",
    "Unsupported format",
    "Recoverable mechanical cartridge failure",
    "Unrecoverable mechanical cartridge failure",
    "Memory chip in cartridge failure",
    "Forced eject",                             /* 0x10 */
    "Read only format",
    "Tape directory corrupted on load",
    "Nearing media life",
    "Cleaning required",
    "Cleaning requested",
    "Expired cleaning media",
    "Invalid cleaning tape",
    "Retension requested",                      /* 0x18 */
    "Dual port interface error",
    "Cooling fan failing",
    "Power supply failure",
    "Power consumption",
    "Drive maintenance",
    "Hardware A",
    "Hardware B",
    "Interface",                                /* 0x20 */
    "Eject media",
    "Microcode update fail",
    "Drive humidity",
    "Drive temperature",
    "Drive voltage",
    "Predictive failure",
    "Diagnostics required",
    "Obsolete (28h)",                           /* 0x28 */
    "Obsolete (29h)",
    "Obsolete (2Ah)",
    "Obsolete (2Bh)",
    "Obsolete (2Ch)",
    "Obsolete (2Dh)",
    "Obsolete (2Eh)",
    "Reserved (2Fh)",
    "Reserved (30h)",                           /* 0x30 */
    "Reserved (31h)",
    "Lost statistics",
    "Tape directory invalid at unload",
    "Tape system area write failure",
    "Tape system area read failure",
    "No start of data",
    "Loading failure",
    "Unrecoverable unload failure",             /* 0x38 */
    "Automation interface failure",
    "Firmware failure",
    "WORM medium - integrity check failed",
    "WORM medium - overwrite attempted",
};

/* TAPE_ALERT_LPAGE [0x2e] */
static bool
show_tape_alert_ssc_page(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    int num, pl, pc, flag;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    /* N.B. the Tape alert log page for smc-3 is different */
    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Tape alert page (ssc-3) [0x2e]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        flag = bp[4] & 1;
        if (op->verbose && (0 == op->do_brief) && flag)
            printf("  >>>> ");
        if ((0 == op->do_brief) || op->verbose || flag) {
            if (pc < (int)SG_ARRAY_SIZE(tape_alert_strs))
                printf("  %s: %d\n", tape_alert_strs[pc], flag);
            else
                printf("  Reserved parameter code 0x%x, flag: %d\n", pc,
                       flag);
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
                        const struct opts_t * op)
{
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((! op->do_raw) && (0 == op->do_hex)))
        printf("Seagate cache page [0x37]\n");
    num = len - 4;
    bp = &resp[0] + 4;
    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0: printf("  Blocks sent to initiator"); break;
        case 1: printf("  Blocks received from initiator"); break;
        case 2:
            printf("  Blocks read from cache and sent to initiator");
            break;
        case 3:
            printf("  Number of read and write commands whose size "
                   "<= segment size");
            break;
        case 4:
            printf("  Number of read and write commands whose size "
                   "> segment size"); break;
        default: printf("  Unknown Seagate parameter code = 0x%x", pc); break;
        }
        printf(" = %" PRIu64 "", sg_get_unaligned_be(pl - 4, bp + 4));
        printf("\n");
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
show_hgst_misc_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    bool valid = false;
    int num, pl, pc;
    const uint8_t * bp;
    char str[PCB_STR_LEN];

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
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
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
            printf("  Unknown HGST/WDC parameter code = 0x%x", pc);
            break;
        }
        if (op->do_pcb)
            printf("        <%s>\n", get_pcb_str(bp[2], str, sizeof(str)));
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
                          const struct opts_t * op)
{
    bool valid = false;
    int num, pl, pc;
    const uint8_t * bp;
    uint64_t ull;
    char str[PCB_STR_LEN];

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
            if (op->do_raw) {
                dStrRaw(bp, pl);
                break;
            } else if (op->do_hex) {
                hex2stdout(bp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        valid = true;
        switch (pc) {
        case 0: printf("  number of hours powered up"); break;
        case 8: printf("  number of minutes until next internal SMART test");
            break;
        default:
            valid = false;
            printf("  Unknown Seagate/Hitachi parameter code = 0x%x", pc);
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
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

static void
decode_page_contents(const uint8_t * resp, int len, struct opts_t * op)
{
    int pg_code, subpg_code, vpn;
    bool spf;
    bool done = false;
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
        subpg_code = spf ? resp[1] : 0;
    op->decod_subpg_code = subpg_code;
    if ((SUPP_SPGS_SUBPG == subpg_code) && (SUPP_PAGES_LPAGE != pg_code)) {
        done = show_supported_pgs_sub_page(resp, len, op);
        if (done)
            return;
    }
    vpn = (op->vend_prod_num >= 0) ? op->vend_prod_num : op->deduced_vpn;
    lep = pg_subpg_pdt_search(pg_code, subpg_code, op->dev_pdt, vpn);
    if (lep && lep->show_pagep)
        done = (*lep->show_pagep)(resp, len, op);

 if (! done) {
        if (subpg_code > 0)
            printf("Unable to decode page = 0x%x, subpage = 0x%x, here is "
                   "hex:\n", pg_code, subpg_code);
        else
            printf("Unable to decode page = 0x%x, here is hex:\n", pg_code);
        if (len > 128) {
            hex2stdout(resp, 64, 1);
            printf(" .....  [truncated after 64 of %d bytes (use '-H' to "
                   "see the rest)]\n", len);
        }
        else
            hex2stdout(resp, len, 1);
    }
}

static int
fetchTemperature(int sg_fd, uint8_t * resp, int max_len, struct opts_t * op)
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
            hex2stdout(resp, len, (1 == op->do_hex));
        else
            show_temperature_page(resp, len, op);
    } else if (SG_LIB_CAT_NOT_READY == res)
        pr2serr("Device not ready\n");
    else {
        op->pg_code = IE_LPAGE;
        res = do_logs(sg_fd, resp, max_len, op);
        if (0 == res) {
            len = sg_get_unaligned_be16(resp + 2) + 4;
            if (op->do_raw)
                dStrRaw(resp, len);
            else if (op->do_hex)
                hex2stdout(resp, len, (1 == op->do_hex));
            else
                show_ie_page(resp, len, op);
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
    int n, nn;
    const struct log_elem * lep;
    char * cp;
    char b[80];

    if (isalpha(op->pg_arg[0])) {
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


int
main(int argc, char * argv[])
{
    int k, pg_len, res, resp_len, vb;
    int in_len = -1;
    int sg_fd = -1;
    int ret = 0;
    uint8_t * parr;
    uint8_t * free_parr = NULL;
    struct sg_simple_inquiry_resp inq_out;
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    memset(op, 0, sizeof(opts));
    /* N.B. some disks only give data for current cumulative */
    op->page_control = 1;
    op->dev_pdt = -1;
    op->vend_prod_num = VP_NONE;
    op->deduced_vpn = VP_NONE;
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (op->do_help) {
        usage_for(op->do_help, op);
        return 0;
    }
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
    vb = op->verbose;
    if (op->vend_prod) {
        if (isdigit(op->vend_prod[0]))
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
    rsp_buff = sg_memalign(rsp_buff_sz, 0 /* page aligned */, &free_rsp_buff,
                           false);
    if (NULL == rsp_buff) {
        pr2serr("Unable to allocate %d bytes on the heap\n", rsp_buff_sz);
        ret = sg_convert_errno(ENOMEM);
        goto err_out;
    }
    if (NULL == op->device_name) {
        if (op->in_fn) {
            const struct log_elem * lep;
            const uint8_t * bp;
            int pg_code, subpg_code, pdt, n;
            uint16_t u;

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
            if (op->pg_arg && (0 == op->do_brief))
                pr2serr(">>> --page=%s option is being ignored, using values "
                        "in file: %s\n", op->pg_arg, op->in_fn);
            for (bp = rsp_buff, k = 0; k < in_len; bp += n, k += n) {
                pg_code = bp[0] & 0x3f;
                subpg_code = (bp[0] & 0x40) ? bp[1] : 0;
                u = sg_get_unaligned_be16(bp + 2);
                n = u + 4;
                if (n > (in_len - k)) {
                    pr2serr("bytes decoded remaining (%d) less than lpage "
                            "length (%d), try decoding anyway\n", in_len - k,
                            n);
                    n = in_len - k;
                }
                pdt = op->dev_pdt;
                lep = pg_subpg_pdt_search(pg_code, subpg_code, pdt,
                                          op->vend_prod_num);
                if (lep) {
                    if (lep->show_pagep)
                        (*lep->show_pagep)(bp, n, op);
                    else
                        printf("Unable to decode %s [%s]\n", lep->name,
                               lep->acron);
                } else {
                    printf("Unable to decode page=0x%x", pg_code);
                    if (subpg_code > 0)
                        printf(", subpage=0x%x", subpg_code);
                    if (pdt >= 0)
                        printf(", pdt=0x%x\n", pdt);
                    else
                        printf("\n");
                }
            }
            ret = 0;
            goto err_out;
        }
        if (op->pg_arg) {         /* do this for 'sg_logs -p xxx' */
            ret = decode_pg_arg(op);
            if (ret)
                goto err_out;
        }
        pr2serr("No DEVICE argument given\n");
        usage_for(1, op);
        ret = SG_LIB_SYNTAX_ERROR;
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
        if (op->filter) {
            pr2serr("--all conflicts with --filter\n");
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
    pg_len = 0;

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
            printf("    %.8s  %.16s  %.4s\n", inq_out.vendor,
                   inq_out.product, inq_out.revision);
        memcpy(t10_vendor_str, inq_out.vendor, 8);
        memcpy(t10_product_str, inq_out.product, 16);
        if (VP_NONE == op->vend_prod_num)
            op->deduced_vpn = find_vpn_by_inquiry();
    }

    if (op->do_temperature) {
        ret = fetchTemperature(sg_fd, rsp_buff, SHORT_RESP_LEN, op);
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
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("log_sense: not supported\n");
    else if (SG_LIB_CAT_NOT_READY == res)
        pr2serr("log_sense: device not ready\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        pr2serr("log_sense: field in cdb illegal\n");
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        pr2serr("log_sense: unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        pr2serr("log_sense: aborted command\n");
    if (0 == op->do_all) {
        if (op->filter_given) {
            if (op->do_hex > 2)
                hex2stdout(rsp_buff, pg_len + 4, (op->do_hex < 4));
            else
                decode_page_contents(rsp_buff, pg_len + 4, op);
        } else if (op->do_raw)
            dStrRaw(rsp_buff, pg_len + 4);
        else if (op->do_hex > 1)
            hex2stdout(rsp_buff, pg_len + 4, (2 == op->do_hex) ? 0 : -1);
        else if (pg_len > 1) {
            if (op->do_hex) {
                if (rsp_buff[0] & 0x40)
                    printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, "
                           "page_len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                           !!(rsp_buff[0] & 0x80), pg_len);
                else
                    printf("Log page code=0x%x, DS=%d, SPF=0, page_len=0x%x\n",
                           rsp_buff[0] & 0x3f, !!(rsp_buff[0] & 0x80), pg_len);
                hex2stdout(rsp_buff, pg_len + 4, 1);
            }
            else
                decode_page_contents(rsp_buff, pg_len + 4, op);
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
            if (! op->do_raw)
                printf("\n");
            res = do_logs(sg_fd, rsp_buff, resp_len, op);
            if (0 == res) {
                pg_len = sg_get_unaligned_be16(rsp_buff + 2);
                if ((pg_len + 4) > resp_len) {
                    pr2serr("Only fetched %d bytes of response, truncate "
                            "output\n", resp_len);
                    pg_len = resp_len - 4;
                }
                if (op->do_raw)
                    dStrRaw(rsp_buff, pg_len + 4);
                else if (op->do_hex > 1)
                    hex2stdout(rsp_buff, pg_len + 4,
                               (2 == op->do_hex) ? 0 : -1);
                else if (op->do_hex) {
                    if (rsp_buff[0] & 0x40)
                        printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, page_"
                               "len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                               !!(rsp_buff[0] & 0x80), pg_len);
                    else
                        printf("Log page code=0x%x, DS=%d, SPF=0, page_len="
                               "0x%x\n", rsp_buff[0] & 0x3f,
                               !!(rsp_buff[0] & 0x80), pg_len);
                    hex2stdout(rsp_buff, pg_len + 4, 1);
                }
                else
                    decode_page_contents(rsp_buff, pg_len + 4, op);
            } else if (SG_LIB_CAT_INVALID_OP == res)
                pr2serr("log_sense: page=0x%x,0x%x not supported\n",
                        op->pg_code, op->subpg_code);
            else if (SG_LIB_CAT_NOT_READY == res)
                pr2serr("log_sense: device not ready\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                pr2serr("log_sense: field in cdb illegal "
                        "[page=0x%x,0x%x]\n", op->pg_code, op->subpg_code);
            else if (SG_LIB_CAT_UNIT_ATTENTION == res)
                pr2serr("log_sense: unit attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                pr2serr("log_sense: aborted command\n");
            else
                pr2serr("log_sense: failed, try '-v' for more information\n");
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
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
