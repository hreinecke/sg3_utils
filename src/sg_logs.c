/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 2000-2015 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
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
#include "sg_unaligned.h"
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */

static const char * version_str = "1.29 20150111";    /* spc5r02 + sbc4r04 */

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
#define BACKGROUND_SCAN_LPAGE 0x15
#define SAT_ATA_RESULTS_LPAGE 0x16
#define PROTO_SPECIFIC_LPAGE 0x18
#define STATS_LPAGE 0x19
#define PCT_LPAGE 0x1a
#define TAPE_ALERT_LPAGE 0x2e
#define IE_LPAGE 0x2f
#define NOT_SPG_SUBPG 0x0
#define SUPP_SPGS_SUBPG 0xff
#define LOW_GRP_STATS_SUBPG 0x1
#define HIGH_GRP_STATS_SUBPG 0x1f
#define CACHE_STATS_SUBPG 0x20
#define ENV_REPORTING_SUBPG 0x1
#define ENV_LIMITS_SUBPG 0x2

#define VENDOR_M 0x1000

#define PCB_STR_LEN 128

#define LOG_SENSE_PROBE_ALLOC_LEN 4

static uint8_t rsp_buff[MX_ALLOC_LEN + 4];

static struct option long_options[] = {
        {"all", no_argument, 0, 'a'},
        {"brief", no_argument, 0, 'b'},
        {"control", required_argument, 0, 'c'},
        {"enumerate", no_argument, 0, 'e'},
        {"filter", required_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"in", required_argument, 0, 'i'},
        {"list", no_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"name", no_argument, 0, 'n'},
        {"new", no_argument, 0, 'N'},
        {"no_inq", no_argument, 0, 'x'},
        {"old", no_argument, 0, 'O'},
        {"page", required_argument, 0, 'p'},
        {"paramp", required_argument, 0, 'P'},
        {"pcb", no_argument, 0, 'q'},
        {"ppc", no_argument, 0, 'Q'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'X'},
        {"reset", no_argument, 0, 'R'},
        {"sp", no_argument, 0, 's'},
        {"select", no_argument, 0, 'S'},
        {"temperature", no_argument, 0, 't'},
        {"transport", no_argument, 0, 'T'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_all;
    int do_brief;
    int do_enumerate;
    int do_help;
    int do_hex;
    int do_list;
    int do_name;
    int do_pcb;
    int do_ppc;
    int do_raw;
    int o_readonly;
    int do_pcreset;
    int do_select;
    int do_sp;
    int do_temperature;
    int do_transport;
    int verbose;
    int do_version;
    int filter;
    int filter_given;
    int page_control;
    int maxlen;
    int pg_code;
    int subpg_code;
    int paramp;
    int opt_new;
    int no_inq;
    int dev_pdt;
    const char * device_name;
    const char * in_fn;
    const char * pg_arg;
    const struct log_elem * lep;
};


struct log_elem {
    int pg_code;
    int subpg_code;     /* only unless subpg_high>0 then this is only */
    int subpg_high;     /* when >0 this is high end of subpage range */
    int pdt;            /* -1 for all */
    int flags;          /* bit mask; only VENDOR_M to start with */
    const char * name;
    const char * acron;
    bool (*show_pagep)(const uint8_t * resp, int len,
                       const struct opts_t * op);
                        /* Returns true if done */
};

static bool show_supported_pgs_lpage(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_supported_pgs_sub_lpage(const uint8_t * resp, int len,
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
static bool show_lb_provisioning_page(const uint8_t * resp, int len,
                                      const struct opts_t * op);
static bool show_sequential_access_page(const uint8_t * resp, int len,
                                        const struct opts_t * op);
static bool show_temperature_page(const uint8_t * resp, int len,
                                  const struct opts_t * op);
static bool show_start_stop_page(const uint8_t * resp, int len,
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
static bool show_background_scan_results_page(const uint8_t * resp, int len,
                                              const struct opts_t * op);
static bool show_element_stats_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_ata_pt_results_page(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_tape_diag_data_page(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_mchanger_diag_data_page(const uint8_t * resp, int len,
                                         const struct opts_t * op);
static bool show_non_volatile_cache_page(const uint8_t * resp, int len,
                                         const struct opts_t * op);
static bool show_volume_stats_page(const uint8_t * resp, int len,
                                   const struct opts_t * op);
static bool show_protocol_specific_page(const uint8_t * resp, int len,
                                        const struct opts_t * op);
static bool show_stats_perform_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_cache_stats_page(const uint8_t * resp, int len,
                                  const struct opts_t * op);
static bool show_power_condition_transitions_page(const uint8_t * resp,
                                 int len, const struct opts_t * op);
static bool show_data_compression_lpage(const uint8_t * resp, int len,
                                        const struct opts_t * op);
static bool show_tape_alert_ssc_page(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_ie_page(const uint8_t * resp, int len,
                         const struct opts_t * op);
static bool show_tape_usage_lpage(const uint8_t * resp, int len,
                                  const struct opts_t * op);
static bool show_tape_capacity_lpage(const uint8_t * resp, int len,
                                     const struct opts_t * op);
static bool show_seagate_cache_page(const uint8_t * resp, int len,
                                    const struct opts_t * op);
static bool show_seagate_factory_page(const uint8_t * resp, int len,
                                      const struct opts_t * op);

static struct log_elem log_arr[] = {
    {SUPP_PAGES_LPAGE, 0, 0, -1, 0, "Supported log pages", "sp",
     show_supported_pgs_lpage},         /* 0, 0 */
    {SUPP_PAGES_LPAGE, SUPP_SPGS_SUBPG, 0, -1, 0, "Supported log pages and "
     "subpages", "ssp", show_supported_pgs_sub_lpage}, /* 0, 0xff */
    {BUFF_OVER_UNDER_LPAGE, 0, 0, -1, 0, "Buffer over-run/under-run", "bou",
     show_buffer_over_under_run_page},  /* 0x1, 0x0 */
    {WRITE_ERR_LPAGE, 0, 0, -1, 0, "Write error", "we",
     show_error_counter_page},          /* 0x2, 0x0 */
    {READ_ERR_LPAGE, 0, 0, -1, 0, "Read error", "re",
     show_error_counter_page},          /* 0x3, 0x0 */
    {READ_REV_ERR_LPAGE, 0, 0, -1, 0, "Read reverse error", "rre",
     show_error_counter_page},          /* 0x4, 0x0 */
    {VERIFY_ERR_LPAGE, 0, 0, -1, 0, "Verify error", "ve",
     show_error_counter_page},          /* 0x5, 0x0 */
    {NON_MEDIUM_LPAGE, 0, 0, -1, 0, "Non medium", "nm",
     show_non_medium_error_page},       /* 0x6, 0x0 */
    {LAST_N_ERR_LPAGE, 0, 0, -1, 0, "Last n error", "lne",
     show_last_n_error_page},           /* 0x7, 0x0 */
    {FORMAT_STATUS_LPAGE, 0, 0, 0, 0, "Format status", "fs",
     show_format_status_page},          /* 0x8, 0x0  SBC */
    {LAST_N_DEFERRED_LPAGE, 0, 0, -1, 0, "Last n deferred error", "lnd",
     show_last_n_deferred_error_page},  /* 0xb, 0x0 */
    {LB_PROV_LPAGE, 0, 0, 0, 0, "Logical block provisioning", "lbp",
     show_lb_provisioning_page},        /* 0xc, 0x0  SBC */
    {0xc, 0, 0, PDT_TAPE, 0, "Sequential access device", "sad",
     show_sequential_access_page},      /* 0xc, 0x0  SSC */
    {TEMPERATURE_LPAGE, 0, 0, -1, 0, "Temperature", "temp",
     show_temperature_page},            /* 0xd, 0x0 */
    {TEMPERATURE_LPAGE, 0x1, 0, -1, 0, "Environmental reporting", "enr",
     NULL},                             /* 0xd, 0x1 */
    {TEMPERATURE_LPAGE, 0x2, 0, -1, 0, "Environmental limits", "enl",
     NULL},                             /* 0xd, 0x2 */
    {START_STOP_LPAGE, 0, 0, -1, 0, "Start-stop cycle counter", "sscc",
     show_start_stop_page},             /* 0xe, 0x0 */
    {0xe, 0x1, 0, 0, 0, "Utilization", "util",
     NULL},                             /* 0xe, 0x1 SBC */    /* sbc4r04 */
    {APP_CLIENT_LPAGE, 0, 0, -1, 0, "Application client", "ac",
     show_app_client_page},             /* 0xf, 0x0 */
    {SELF_TEST_LPAGE, 0, 0, -1, 0, "Self test results", "str",
     show_self_test_page},              /* 0x10, 0x0 */
    {SOLID_STATE_MEDIA_LPAGE, 0, 0, 0, 0, "Solid state media", "ssm",
     show_solid_state_media_page},      /* 0x11, 0x0  SBC */
    {0x11, 0, 0, PDT_TAPE, 0, "DT Device status", "dtds",
     show_dt_device_status_page},       /* 0x11, 0x0  SSC,ADC */
    {0x12, 0, 0, PDT_TAPE, 0, "Tape alert response", "tar",
     NULL},                             /* 0x12, 0x0  SSC,ADC */
    {0x13, 0, 0, PDT_TAPE, 0, "Requested recovery", "rr",
     NULL},                             /* 0x13, 0x0  SSC,ADC */
    {0x14, 0, 0, PDT_TAPE, 0, "Device statistics", "ds",
     show_device_stats_page},           /* 0x14, 0x0  SSC,ADC */
    {0x14, 0, 0, PDT_MCHANGER, 0, "Media changer statistics", "mcs",
     show_media_stats_page},            /* 0x14, 0x0  SMC */
    {BACKGROUND_SCAN_LPAGE, 0, 0, 0, 0, "Background scan results", "bsr",
     show_background_scan_results_page}, /* 0x15, 0x0  SBC */
    {0x15, 0, 0, PDT_MCHANGER, 0, "Element statistics", "els",
     show_element_stats_page},           /* 0x15, 0x0  SMC */
    {0x15, 0, 0, PDT_ADC, 0, "Service buffers information", "sbi",
     NULL},                              /* 0x15, 0x0  ADC */
    {BACKGROUND_SCAN_LPAGE, 0x1, 0, 0, 0, "Pending defects", "pd",
     NULL},                             /* 0x15, 0x1  SBC */
    {SAT_ATA_RESULTS_LPAGE, 0, 0, 0, 0, "ATA pass-through results", "aptr",
     show_ata_pt_results_page},         /* 0x16, 0x0  SAT */
    {0x16, 0, 0, PDT_TAPE, 0, "Tape diagnostic data", "tdd",
     show_tape_diag_data_page},         /* 0x16, 0x0  SSC */
    {0x16, 0, 0, PDT_MCHANGER, 0, "Media changer diagnostic data", "mcdd",
     show_mchanger_diag_data_page},     /* 0x16, 0x0  SMC */
    {0x17, 0, 0, 0, 0, "Non volatile cache", "nvc",
     show_non_volatile_cache_page},     /* 0x17, 0x0  SBC */
    {0x17, 0, 0, PDT_TAPE, 0, "Volume statistics", "vs",
     show_volume_stats_page},           /* 0x17, 0x0  SSC */
    {PROTO_SPECIFIC_LPAGE, 0, 0, -1, 0, "Protocol specific port", "psp",
     show_protocol_specific_page},      /* 0x18, 0x0  */
    {STATS_LPAGE, 0, 0, -1, 0, "General Statistics and Performance", "gsp",
     show_stats_perform_page},          /* 0x19, 0x0  */
    {STATS_LPAGE, 0x1, 0x1f, -1, 0, "Group Statistics and Performance", "grsp",
     show_stats_perform_page},          /* 0x19, 0x1...0x1f  */
    {STATS_LPAGE, 0x20, 0, -1, 0, "Cache memory statistics", "cms",
     show_cache_stats_page},            /* 0x19, 0x20  */
    {PCT_LPAGE, 0, 0, -1, 0, "Power condition transitions", "pct",
     show_power_condition_transitions_page}, /* 0x1a, 0  */
    {0x1b, 0, 0, PDT_TAPE, 0, "Data compression", "dc",
     show_data_compression_lpage},      /* 0x1b, 0  SSC */
    {TAPE_ALERT_LPAGE, 0, 0, PDT_TAPE, 0, "Tape alert", "ta",
     show_tape_alert_ssc_page},         /* 0x2e, 0  SSC */
    {IE_LPAGE, 0, 0, -1, 0, "Informational exceptions", "ie",
     show_ie_page},                     /* 0x2f, 0  */
/* vendor specific */
    {0x30, 0, 0, PDT_TAPE, VENDOR_M, "Performance counters (Hitachi)", "pc_hi",
     NULL},                             /* 0x30, 0  SBC */
    {0x30, 0, 0, PDT_TAPE, VENDOR_M, "Tape usage (lto-5, 6)", "ta_",
     show_tape_usage_lpage},            /* 0x30, 0  SSC */
    {0x31, 0, 0, PDT_TAPE, VENDOR_M, "Tape capacity (lto-5, 6)", "tc_",
     show_tape_capacity_lpage},         /* 0x31, 0  SSC */
    {0x32, 0, 0, PDT_TAPE, VENDOR_M, "Data compression (ibm)", "dc_",
     show_data_compression_lpage},      /* 0x32, 0  SSC; redirect to 0x1b */
    {0x33, 0, 0, PDT_TAPE, VENDOR_M, "Write errors (lto-5)", "we_",
     NULL},                             /* 0x33, 0  SSC */
    {0x34, 0, 0, PDT_TAPE, VENDOR_M, "Read forward errors (lto-5)", "rfe_",
     NULL},                             /* 0x34, 0  SSC */
    {0x35, 0, 0, PDT_TAPE, VENDOR_M, "DT Device Error (lto-6)", "dtde_",
     NULL},                             /* 0x35, 0  SSC */
    {0x37, 0, 0, PDT_DISK, VENDOR_M, "Cache (seagate)", "c_se",
     show_seagate_cache_page},          /* 0x37, 0  SBC */
    {0x37, 0, 0, PDT_DISK, VENDOR_M, "Miscellaneous (hitachi)", "mi_hi",
     NULL},                             /* 0x37, 0  SBC */
    {0x37, 0, 0, PDT_TAPE, VENDOR_M, "Performance characteristics (lto-5)",
     "pc_", NULL},                             /* 0x37, 0  SSC */
    {0x38, 0, 0, PDT_TAPE, VENDOR_M, "Blocks/bytes transferred (lto-5)",
     "bbt_", NULL},                             /* 0x38, 0  SSC */
    {0x39, 0, 0, PDT_TAPE, VENDOR_M, "Host port 0 interface errors (lto-5)",
     "hp0_", NULL},                             /* 0x39, 0  SSC */
    {0x3a, 0, 0, PDT_TAPE, VENDOR_M, "Drive control verification (lto-5)",
     "dcv_", NULL},                             /* 0x3a, 0  SSC */
    {0x3b, 0, 0, PDT_TAPE, VENDOR_M, "Host port 1 interface errors (lto-5)",
     "hp1_", NULL},                             /* 0x3b, 0  SSC */
    {0x3c, 0, 0, PDT_TAPE, VENDOR_M, "Drive usage information (lto-5)",
     "dui_", NULL},                             /* 0x3c, 0  SSC */
    {0x3d, 0, 0, PDT_TAPE, VENDOR_M, "Subsystem statistics (lto-5)", "ss_",
     NULL},                             /* 0x3d, 0  SSC */
    {0x3e, 0, 0, PDT_DISK, VENDOR_M, "Factory (seagate)", "f_se",
     show_seagate_factory_page},        /* 0x3e, 0  SBC */
    {0x3e, 0, 0, PDT_DISK, VENDOR_M, "Factory (hitachi)", "f_hi",
     NULL},                             /* 0x3e, 0  SBC */
    {0x3e, 0, 0, PDT_TAPE, VENDOR_M, "Device Status (lto-6)", "ds_",
     NULL},                             /* 0x3e, 0  SSC */

    {-1, -1, -1, -1, -1, NULL, "zzzzz", NULL},           /* end sentinel */
};

#ifdef SG_LIB_WIN32
static int win32_spt_init_state = 0;
static int win32_spt_curr_state = 0;
#endif


#ifdef __GNUC__
static int pr2serr(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
static int pr2serr(const char * fmt, ...);
#endif


static int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

static void
usage(int hval)
{
    if (1 == hval) {
        pr2serr(
           "Usage: sg_logs [--all] [--brief] [--control=PC] [--enumerate] "
           "[--filter=FI]\n"
           "               [--help] [--hex] [--in=FN] [--list] [--no_inq] "
           "[--maxlen=LEN]\n"
           "               [--name] [--page=PG] [--paramp=PP] [--pcb] "
           "[--ppc] [--raw]\n"
           "               [--readonly] [--reset] [--select] [--sp] "
           "[--temperature]\n"
           "               [--transport] [--verbose] [--version] DEVICE\n"
           "  where the main options are:\n"
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
           "    --filter=FI|-f FI    FI is parameter code to display (def: "
           "all); with\n"
           "                         '-e' then FI>=0 enumerate that pdt + "
           "spc\n"
           "                         FI=-1 all (default), FI=-2 spc only\n"
           "    --help|-h       print usage message then exit. Use twice "
           "for more help\n"
           "    --hex|-H        output response in hex (default: decode if "
           "known)\n"
           "    --in=FN|-i FN    FN is a filename containing a log page "
           "in ASCII hex\n"
           "                     or binary if --raw also given.\n"
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
           "    --verbose|-v    increase verbosity\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command and decodes "
           "the response.\nIf only DEVICE is given then '-p sp' (supported "
           "pages) is assumed. Use\n'-e' to see known pages and their "
           "acronyms. For more help use '-hh'.\n");
    } else if (hval > 1) {
        pr2serr(
           "  where sg_logs' lesser used options are:\n"
           "    --control=PC|-c PC    page control(PC) (default: 1)\n"
           "                          0: current threshhold, 1: current "
           "cumulative\n"
           "                          2: default threshhold, 3: default "
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
           "    --no_inq|-x     no initial INQUIRY output (twice: no "
           "INQUIRY call)\n"
           "    --old|-O        use old interface (use as first option)\n"
           "    --paramp=PP|-P PP    parameter pointer (decimal) (def: 0)\n"
           "    --pcb|-q        show parameter control bytes in decoded "
           "output\n"
           "    --ppc|-Q        set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
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
           "issued. If\nDEVICE is not given and '--in=FN' is given then FN "
           "will decoded as if it\nwere a log page. Pages defined in SPC "
           "are common to all device types.\n");
    }
}

static void
usage_old()
{
    printf("Usage:  sg_logs [-a] [-A] [-b] [-c=PC] [-e] [-f=FI] [-h] [-H] "
           "[-i=FN]\n"
           "                [-l] [-L] [-m=LEN] [-n] [-p=PG] "
           "[-paramp=PP]\n"
           "                [-pcb] [-ppc] [-r] [-select] [-sp] [-t] [-T] "
           "[-v] [-V]\n"
           "                [-x] [-X] [-?] DEVICE\n"
           "  where:\n"
           "    -a     fetch and decode all log pages\n"
           "    -A     fetch and decode all log pages and subpages\n"
           "    -b     shorten the output of some log pages\n"
           "    -c=PC    page control(PC) (default: 1)\n"
           "                  0: current threshhold, 1: current cumulative\n"
           "                  2: default threshhold, 3: default cumulative\n"
           "    -e     enumerate known log pages\n"
           "    -f=FI    filter match parameter code or pdt\n"
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
           "    -n       decode some pages into multiple name=value "
           "lines\n"
           "    -p=PG    PG is an acronym (def: 'sp')\n"
           "    -p=PGN    page code in hex (def: 0)\n"
           "    -p=PGN,SPGN    page and subpage codes in hex, (defs: 0,0)\n"
           "    -paramp=PP   (in hex) (def: 0)\n"
           "    -pcb   show parameter control bytes in decoded "
           "output\n");
    printf("    -ppc   set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
           "    -r     reset log parameters (takes PC and SP into "
           "account)\n"
           "           (uses PCR bit in LOG SELECT)\n"
           "    -select  perform LOG SELECT (def: LOG SENSE)\n"
           "    -sp    set the Saving Parameters (SP) bit (def: 0)\n"
           "    -t     outputs temperature log page (0xd)\n"
           "    -T     outputs transport (protocol specific port) log "
           "page (0x18)\n"
           "    -v     increase verbosity\n"
           "    -V     output version string\n"
           "    -x     no initial INQUIRY output (twice: no INQUIRY call)\n"
           "    -X     open DEVICE read-only (def: first read-write then "
           "if fails\n"
           "           try open again with read-only)\n"
           "    -?     output this usage message\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command\n");
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
enumerate_helper(const struct log_elem * lep, int pos,
                 const struct opts_t * op)
{
    char b[80];
    char bb[80];
    const char * cp;

    if (0 == pos) {
        if (1 == op->verbose) {
            printf("acronym   pg[,spg]        name\n");
            printf("===============================================\n");
        } else if (2 == op->verbose) {
            printf("acronym   pg[,spg]        pdt   name\n");
            printf("===================================================\n");
        }
    }
    if ((0 == (op->do_enumerate % 2)) && (VENDOR_M & lep->flags))
        return;     /* if do_enumerate is even then skip vendor pages */
    else if ((! op->filter_given) || (-1 == op->filter))
        ;           /* otherwise enumerate all lpages if no --filter= */
    else if (-2 == op->filter) {   /* skip non-SPC pages */
        if (lep->pdt >= 0)
            return;
    } else if ((op->filter >= 0) && (op->filter <= 0x1f)) {
        if ((lep->pdt >= 0) && (lep->pdt != op->filter) &&
            (lep->pdt != sg_lib_pdt_decay(op->filter)))
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
enumerate_lpages(const struct opts_t * op)
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
            enumerate_helper(*lepp, j, op);
    } else {    /* -eee, -eeee numeric sort (as per table) */
        printf("Known log pages in numerical order:\n");
        for (lep = log_arr, j = 0; lep->pg_code >=0; ++lep, ++j)
            enumerate_helper(lep, j, op);
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

static const struct log_elem *
pg_subpg_pdt_search(int pg_code, int subpg_code, int pdt)
{
    const struct log_elem * lep;
    int d_pdt;

    d_pdt = sg_lib_pdt_decay(pdt);
    for (lep = log_arr; lep->pg_code >=0; ++lep) {
        if (pg_code == lep->pg_code) {
            if (subpg_code == lep->subpg_code) {
                if ((lep->pdt < 0) || (pdt == lep->pdt) || (pdt < 0))
                    return lep;
                else if (d_pdt == lep->pdt)
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
process_cl_new(struct opts_t * op, int argc, char * argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aAbc:ef:hHi:lLm:nNOp:P:qQrRsStTvVxX",
                        long_options, &option_index);
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
            ++op->filter_given;
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
        case 'n':
            ++op->do_name;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = 0;
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
            ++op->do_pcb;
            break;
        case 'Q':       /* N.B. PPC bit obsoleted in SPC-4 rev 18 */
            ++op->do_ppc;
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 'R':
            ++op->do_pcreset;
            ++op->do_select;
            break;
        case 's':
            ++op->do_sp;
            break;
        case 'S':
            ++op->do_select;
            break;
        case 't':
            ++op->do_temperature;
            break;
        case 'T':
            ++op->do_transport;
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            ++op->do_version;
            break;
        case 'x':
            ++op->no_inq;
            break;
        case 'X':
            ++op->o_readonly;
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
process_cl_old(struct opts_t * op, int argc, char * argv[])
{
    int k, jmp_out, plen, num, n;
    unsigned int u, uu;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
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
                    ++op->do_name;
                    break;
                case 'N':
                    op->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'r':
                    op->do_pcreset = 1;
                    op->do_select = 1;
                    break;
                case 't':
                    ++op->do_temperature;
                    break;
                case 'T':
                    ++op->do_transport;
                    break;
                case 'v':
                    ++op->verbose;
                    break;
                case 'V':
                    ++op->do_version;
                    break;
                case 'x':
                    ++op->no_inq;
                    break;
                case 'X':
                    ++op->o_readonly;
                    break;
                case '?':
                    ++op->do_help;
                    break;
                case '-':
                    ++cp;
                    jmp_out = 1;
                    break;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("c=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 3)) {
                    pr2serr("Bad page control after '-c=' option [0..3]\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->page_control = u;
            } else if (0 == strncmp("f=", cp, 2)) {
                n = sg_get_num(cp + 2);
                if ((n < 0) || (n > 0xffff)) {
                    pr2serr("Bad argument after '-f=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->filter = n;
                ++op->filter_given;
            } else if (0 == strncmp("i=", cp, 2))
                op->in_fn = cp + 2;
            else if (0 == strncmp("m=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 0) || (n > MX_ALLOC_LEN)) {
                    pr2serr("Bad maximum response length after '-m=' "
                            "option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->maxlen = n;
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
                        num = sscanf(cp + 2, "%x", &u);
                        if ((1 != num) || (u > 63)) {
                            pr2serr("Bad page code value after '-p=' "
                                    "option\n");
                            usage_old();
                            return SG_LIB_SYNTAX_ERROR;
                        }
                        op->pg_code = u;
                    } else if (2 == sscanf(cp + 2, "%x,%x", &u, &uu)) {
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
                num = sscanf(cp + 7, "%x", &u);
                if ((1 != num) || (u > 0xffff)) {
                    pr2serr("Bad parameter pointer after '-paramp=' "
                            "option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->paramp = u;
            } else if (0 == strncmp("pcb", cp, 3))
                op->do_pcb = 1;
            else if (0 == strncmp("ppc", cp, 3))
                op->do_ppc = 1;
            else if (0 == strncmp("select", cp, 6))
                op->do_select = 1;
            else if (0 == strncmp("sp", cp, 2))
                op->do_sp = 1;
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
process_cl(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = 0;
        res = process_cl_old(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = process_cl_new(op, argc, argv);
    } else {
        op->opt_new = 1;
        res = process_cl_new(op, argc, argv);
        if ((0 == res) && (0 == op->opt_new))
            res = process_cl_old(op, argc, argv);
    }
    return res;
}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

/* Decode counter up to 8 chars long (big endian) into an uint64_t.
 * In the unlikely event that the counter is larger than 8 chars long
 * then take the last 8 chars. */
static uint64_t
decode_count(const uint8_t * xp, int len)
{
    int j;
    uint64_t ull;

    if (len > (int)sizeof(ull)) {
        xp += (len - sizeof(ull));
        len = sizeof(ull);
    }
    ull = 0;
    for (j = 0; j < len; ++j) {
        if (j > 0)
            ull <<= 8;
        ull |= xp[j];
    }
    return ull;
}

/* Read ASCII hex bytes or binary from fname (a file named '-' taken as
 * stdin). If reading ASCII hex then there should be either one entry per
 * line or a comma, space or tab separated list of bytes. If no_space is
 * set then a string of ACSII hex digits is expected, 2 per byte. Everything
 * from and including a '#' on a line is ignored. Returns 0 if ok, or 1 if
 * error. */
static int
f2hex_arr(const char * fname, int as_binary, int no_space,
          uint8_t * mp_arr, int * mp_arr_len, int max_arr_len)
{
    int fn_len, in_len, k, j, m, split_line, fd, has_stdin;
    unsigned int h;
    const char * lcp;
    FILE * fp;
    char line[512];
    char carry_over[4];
    int off = 0;

    if ((NULL == fname) || (NULL == mp_arr) || (NULL == mp_arr_len))
        return 1;
    fn_len = strlen(fname);
    if (0 == fn_len)
        return 1;
    has_stdin = ((1 == fn_len) && ('-' == fname[0]));  /* read from stdin */
    if (as_binary) {
        if (has_stdin) {
            fd = STDIN_FILENO;
                if (sg_set_binary_mode(STDIN_FILENO) < 0)
                    perror("sg_set_binary_mode");
        } else {
            fd = open(fname, O_RDONLY);
            if (fd < 0) {
                pr2serr("unable to open binary file %s: %s\n", fname,
                         safe_strerror(errno));
                return 1;
            } else if (sg_set_binary_mode(fd) < 0)
                perror("sg_set_binary_mode");
        }
        k = read(fd, mp_arr, max_arr_len);
        if (k <= 0) {
            if (0 == k)
                pr2serr("read 0 bytes from binary file %s\n", fname);
            else
                pr2serr("read from binary file %s: %s\n", fname,
                        safe_strerror(errno));
            if (! has_stdin)
                close(fd);
            return 1;
        }
        *mp_arr_len = k;
        if (! has_stdin)
            close(fd);
        return 0;
    } else {    /* So read the file as ASCII hex */
        if (has_stdin)
            fp = stdin;
        else {
            fp = fopen(fname, "r");
            if (NULL == fp) {
                pr2serr("Unable to open %s for reading\n", fname);
                return 1;
            }
        }
    }

    carry_over[0] = 0;
    for (j = 0; j < 512; ++j) {
        if (NULL == fgets(line, sizeof(line), fp))
            break;
        in_len = strlen(line);
        if (in_len > 0) {
            if ('\n' == line[in_len - 1]) {
                --in_len;
                line[in_len] = '\0';
                split_line = 0;
            } else
                split_line = 1;
        }
        if (in_len < 1) {
            carry_over[0] = 0;
            continue;
        }
        if (carry_over[0]) {
            if (isxdigit(line[0])) {
                carry_over[1] = line[0];
                carry_over[2] = '\0';
                if (1 == sscanf(carry_over, "%x", &h))
                    mp_arr[off - 1] = h;       /* back up and overwrite */
                else {
                    pr2serr("f2hex_arr: carry_over error ['%s'] around line "
                            "%d\n", carry_over, j + 1);
                    goto bad;
                }
                lcp = line + 1;
                --in_len;
            } else
                lcp = line;
            carry_over[0] = 0;
        } else
            lcp = line;

        m = strspn(lcp, " \t");
        if (m == in_len)
            continue;
        lcp += m;
        in_len -= m;
        if ('#' == *lcp)
            continue;
        k = strspn(lcp, "0123456789aAbBcCdDeEfF ,\t");
        if ((k < in_len) && ('#' != lcp[k])) {
            pr2serr("f2hex_arr: syntax error at line %d, pos %d\n",
                    j + 1, m + k + 1);
            goto bad;
        }
        if (no_space) {
            for (k = 0; isxdigit(*lcp) && isxdigit(*(lcp + 1));
                 ++k, lcp += 2) {
                if (1 != sscanf(lcp, "%2x", &h)) {
                    pr2serr("f2hex_arr: bad hex number in line %d, "
                            "pos %d\n", j + 1, (int)(lcp - line + 1));
                    goto bad;
                }
                if ((off + k) >= max_arr_len) {
                    pr2serr("f2hex_arr: array length exceeded\n");
                    goto bad;
                }
                mp_arr[off + k] = h;
            }
            if (isxdigit(*lcp) && (! isxdigit(*(lcp + 1))))
                carry_over[0] = *lcp;
            off += k;
        } else {
            for (k = 0; k < 1024; ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        pr2serr("f2hex_arr: hex number larger than "
                                "0xff in line %d, pos %d\n", j + 1,
                                (int)(lcp - line + 1));
                        goto bad;
                    }
                    if (split_line && (1 == strlen(lcp))) {
                        /* single trailing hex digit might be a split pair */
                        carry_over[0] = *lcp;
                    }
                    if ((off + k) >= max_arr_len) {
                        pr2serr("f2hex_arr: array length exceeded\n");
                        goto bad;
                    }
                    mp_arr[off + k] = h;
                    lcp = strpbrk(lcp, " ,\t");
                    if (NULL == lcp)
                        break;
                    lcp += strspn(lcp, " ,\t");
                    if ('\0' == *lcp)
                        break;
                } else {
                    if ('#' == *lcp) {
                        --k;
                        break;
                    }
                    pr2serr("f2hex_arr: error in line %d, at pos %d\n", j + 1,
                            (int)(lcp - line + 1));
                    goto bad;
                }
            }
            off += (k + 1);
        }
    }
    *mp_arr_len = off;
    if (stdin != fp)
        fclose(fp);
    return 0;
bad:
    if (stdin != fp)
        fclose(fp);
    return 1;
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
    int actual_len, res, vb;

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (0 == win32_spt_init_state) {
        if (win32_spt_curr_state) {
            if (mx_resp_len < 16384) {
                scsi_pt_win32_direct(0);
                win32_spt_curr_state = 0;
            }
        } else {
            if (mx_resp_len >= 16384) {
                scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT direct */);
                win32_spt_curr_state = 1;
            }
        }
    }
#endif
#endif
    memset(resp, 0, mx_resp_len);
    vb = op->verbose;
    if (op->maxlen > 1)
        actual_len = mx_resp_len;
    else {
        if ((res = sg_ll_log_sense(sg_fd, op->do_ppc, op->do_sp,
                                   op->page_control, op->pg_code,
                                   op->subpg_code, op->paramp,
                                   resp, LOG_SENSE_PROBE_ALLOC_LEN,
                                   1 /* noisy */, vb)))
            return res;
        actual_len = (resp[2] << 8) + resp[3] + 4;
        if ((0 == op->do_raw) && (vb > 1)) {
            pr2serr("  Log sense (find length) response:\n");
            dStrHexErr((const char *)resp, LOG_SENSE_PROBE_ALLOC_LEN, 1);
            pr2serr("  hence calculated response length=%d\n", actual_len);
        }
        if (op->pg_code != (0x3f & resp[0])) {
            if (vb)
                pr2serr("Page code does not appear in first byte of "
                        "response so it's suspect\n");
            if (actual_len > 0x40) {
                actual_len = 0x40;
                if (vb)
                    pr2serr("Trim response length to 64 bytes due to "
                            "suspect response format\n");
            }
        }
        /* Some HBAs don't like odd transfer lengths */
        if (actual_len % 2)
            actual_len += 1;
        if (actual_len > mx_resp_len)
            actual_len = mx_resp_len;
    }
    if ((res = sg_ll_log_sense(sg_fd, op->do_ppc, op->do_sp,
                               op->page_control, op->pg_code,
                               op->subpg_code, op->paramp,
                               resp, actual_len, 1 /* noisy */, vb)))
        return res;
    if ((0 == op->do_raw) && (vb > 1)) {
        pr2serr("  Log sense response:\n");
        dStrHexErr((const char *)resp, actual_len, 1);
    }
    return 0;
}

static void
get_pcb_str(int pcb, char * outp, int maxoutlen)
{
    char buff[PCB_STR_LEN];
    int n;

    n = sprintf(buff, "du=%d [ds=%d] tsd=%d etc=%d ", ((pcb & 0x80) ? 1 : 0),
                ((pcb & 0x40) ? 1 : 0), ((pcb & 0x20) ? 1 : 0),
                ((pcb & 0x10) ? 1 : 0));
    if (pcb & 0x10)
        n += sprintf(buff + n, "tmc=%d ", ((pcb & 0xc) >> 2));
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
}

/* SUPP_PAGES_LPAGE [0x0,0x0] */
static bool
show_supported_pgs_lpage(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    int num, k, pg_code;
    const uint8_t * ucp;
    const struct log_elem * lep;
    char b[64];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Supported log pages  [0x0]:\n");  /* introduced: SPC-2 */
    num = len - 4;
    ucp = &resp[0] + 4;
    for (k = 0; k < num; ++k) {
        pg_code = ucp[k];
        snprintf(b, sizeof(b) - 1, "    0x%02x        ", pg_code);
        lep = pg_subpg_pdt_search(pg_code, 0, op->dev_pdt);
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
show_supported_pgs_sub_lpage(const uint8_t * resp, int len,
                             const struct opts_t * op)
{
    int num, k, pg_code, subpg_code;
    const uint8_t * ucp;
    const struct log_elem * lep;
    char b[64];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
        if (op->pg_code > 0)
            printf("Supported subpages  [0x%x, 0xff]:\n", op->pg_code);
        else
            printf("Supported log pages and subpages  [0x0, 0xff]:\n");
    }
    num = len - 4;
    ucp = &resp[0] + 4;
    for (k = 0; k < num; k += 2) {
        pg_code = ucp[k];
        subpg_code = ucp[k + 1];
        if (NOT_SPG_SUBPG == subpg_code)
            snprintf(b, sizeof(b) - 1, "    0x%02x        ", pg_code);
        else
            snprintf(b, sizeof(b) - 1, "    0x%02x,0x%02x   ", pg_code,
                     subpg_code);
        lep = pg_subpg_pdt_search(pg_code, subpg_code, op->dev_pdt);
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
    int num, pl, pcb, pc;
    uint64_t count;
    const uint8_t * ucp;
    const char * cp;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Buffer over-run/under-run page  [0x1]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        cp = NULL;
        pl = ucp[3] + 4;
        count = (pl > 4) ? decode_count(ucp + 4, pl - 4) : 0;
        pc = (ucp[0] << 8) + ucp[1];
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
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
            cp = "transport under-run";
            break;
        case 0x3:
            cp = "transport over-run";
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
            cp = "command, transport under-run";
            break;
        case 0x23:
            cp = "command, transport over-run";
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
            cp = "I_T nexus, transport under-run";
            break;
        case 0x43:
            cp = "I_T nexus, transport over-run";
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
            cp = "time, transport under-run";
            break;
        case 0x83:
            cp = "time, transport over-run";
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

        if (op->do_pcb) {
            pcb = ucp[2];
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* WRITE_ERR_LPAGE; READ_ERR_LPAGE; READ_REV_ERR_LPAGE; VERIFY_ERR_LPAGE */
/* [0x2, 0x3, 0x4, 0x5]  introduced: SPC-3 */
static bool
show_error_counter_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int num, pl, pc, pcb, pg_code;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    pg_code = resp[0] & 0x3f;
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
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
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
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
        printf(" = %" PRIu64 "", decode_count(ucp + 4, pl - 4));
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* NON_MEDIUM_LPAGE [0x6]  introduced: SPC-2 */
static bool
show_non_medium_error_page(const uint8_t * resp, int len,
                           const struct opts_t * op)
{
    int num, pl, pc, pcb;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Non-medium error page  [0x6]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
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
        printf(" = %" PRIu64 "", decode_count(ucp + 4, pl - 4));
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* PCT_LPAGE [0x1a]  introduced: SPC-4 */
static bool
show_power_condition_transitions_page(const uint8_t * resp, int len,
                                      const struct opts_t * op)
{
    int num, pl, pc, pcb;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Power condition transitions page  [0x1a]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            printf("  Accumulated transitions to active"); break;
        case 1:
            printf("  Accumulated transitions to idle_a"); break;
        case 2:
            printf("  Accumulated transitions to idle_b"); break;
        case 3:
            printf("  Accumulated transitions to idle_c"); break;
        case 8:
            printf("  Accumulated transitions to standby_z"); break;
        case 9:
            printf("  Accumulated transitions to standby_y"); break;
        default:
            printf("  Reserved [0x%x]", pc);
        }
        printf(" = %" PRIu64 "", decode_count(ucp + 4, pl - 4));
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* Tape usage: Vendor specific (LTO-5 and LTO-6): 0x30 */
static bool
show_tape_usage_lpage(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    uint64_t ull;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed tape usage page\n");
        return false;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Tape usage page  (LTO-5 and LTO-6 specific) [0x30]\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        extra = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, extra);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, extra,
                        ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        ull = n = 0;
        switch (ucp[3]) {
        case 2:
            n = (ucp[4] << 8) | ucp[5];
            break;
        case 4:
            n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
            break;
        case 8:
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
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
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
    }
    return true;
}

/* Tape capacity: vendor specific (IBM): 0x31 */
static bool
show_tape_capacity_lpage(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed tape capacity page\n");
        return false;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Tape capacity page  (IBM specific) [0x31]\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        extra = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, extra);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, extra,
                        ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if (extra != 8)
            continue;
        n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
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
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
    }
    return true;
}

/* Data compression: originally vendor specific 0x32 (IBM), then
 * ssc-4 standardizes it at 0x1b */
static bool
show_data_compression_lpage(const uint8_t * resp, int len,
                            const struct opts_t * op)
{
    int k, j, pl, num, extra, pc, pcb, pg_code;
    uint64_t n;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    pg_code = resp[0] & 0x3f;
    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed data compression page\n");
        return false;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
        if (0x1b == pg_code)
            printf("Data compression page  (ssc-4) [0x1b]\n");
        else
            printf("Data compression page  (IBM specific) [0x%x]\n",
                   pg_code);
    }
    for (k = num; k > 0; k -= extra, ucp += extra) {
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        pl = ucp[3];
        extra = pl + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, extra);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, extra,
                        ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if ((0 == pl) || (pl > 8)) {
            printf("badly formed data compression log parameter\n");
            printf("  parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
            goto skip_para;
        }
        for (j = 0, n = 0; j < pl; ++j) {
            if (j > 0)
                n <<= 8;
            n |= ucp[4 + j];
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
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
skip_para:
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
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
    int k, num, pl, pc, pcb;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("No error events logged\n");
        return true;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Last n error events page  [0x7]\n");
    for (k = num; k > 0; k -= pl, ucp += pl) {
        if (k < 3) {
            printf("short Last n error events page\n");
            return false;
        }
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Error event %d:\n", pc);
        if (pl > 4) {
            if ((pcb & 0x1) && (pcb & 0x2)) {
                printf("    [binary]:\n");
                dStrHex((const char *)ucp + 4, pl - 4, 1);
            } else if (pcb & 0x1)
                printf("    %.*s\n", pl - 4, (const char *)(ucp + 4));
            else {
                printf("    [data counter?? (LP bit should be set)]:\n");
                dStrHex((const char *)ucp + 4, pl - 4, 1);
            }
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
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
    int k, num, pl, pc, pcb;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("No deferred errors logged\n");
        return true;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Last n deferred errors page  [0xb]\n");
    for (k = num; k > 0; k -= pl, ucp += pl) {
        if (k < 3) {
            printf("short Last n deferred errors page\n");
            return true;
        }
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Deferred error %d:\n", pc);
        dStrHex((const char *)ucp + 4, pl - 4, 1);
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
        if (op->filter_given)
            break;
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
    int k, num, n, res, pc, pl, pcb;
    unsigned int v;
    const uint8_t * ucp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];
    char b[80];

    num = len - 4;
    if (num < 0x190) {
        pr2serr("short self-test results page [length 0x%x rather than "
                "0x190 bytes]\n", num);
        return true;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Self-test results page  [0x10]\n");
    for (k = 0, ucp = resp + 4; k < 20; ++k, ucp += 20 ) {
        pcb = ucp[2];
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        n = (ucp[6] << 8) | ucp[7];
        if ((0 == n) && (0 == ucp[4]))
            break;
        printf("  Parameter code = %d, accumulated power-on hours = %d\n",
               pc, n);
        printf("    self-test code: %s [%d]\n",
               self_test_code[(ucp[4] >> 5) & 0x7], (ucp[4] >> 5) & 0x7);
        res = ucp[4] & 0xf;
        printf("    self-test result: %s [%d]\n", self_test_result[res], res);
        if (ucp[5])
            printf("    self-test number = %d\n", (int)ucp[5]);
        ull = ucp[8]; ull <<= 8; ull |= ucp[9]; ull <<= 8; ull |= ucp[10];
        ull <<= 8; ull |= ucp[11]; ull <<= 8; ull |= ucp[12];
        ull <<= 8; ull |= ucp[13]; ull <<= 8; ull |= ucp[14];
        ull <<= 8; ull |= ucp[15];
        if ((0xffffffffffffffffULL != ull) && (res > 0) && ( res < 0xf))
            printf("    address of first error = 0x%" PRIx64 "\n", ull);
        v = ucp[16] & 0xf;
        if (v) {
            printf("    sense key = 0x%x [%s] , asc = 0x%x, ascq = 0x%x",
                   v, sg_get_sense_key_str(v, sizeof(b), b), ucp[17],
                   ucp[18]);
            if (ucp[17] || ucp[18])
                printf("      [%s]\n", sg_get_asc_ascq_str(ucp[17], ucp[18],
                       sizeof(b), b));
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
    }
    return true;
}

/* TEMPERATURE_LPAGE [0xd]  introduced: SPC-3 */
static bool
show_temperature_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc, pcb;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed Temperature page\n");
        return false;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
        if (! op->do_temperature)
            printf("Temperature page  [0xd]\n");
    }
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            pr2serr("short Temperature page\n");
            return true;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, extra);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, extra,
                        ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            if ((extra > 5) && (k > 5)) {
                if (ucp[5] < 0xff)
                    printf("  Current temperature = %d C", ucp[5]);
                else
                    printf("  Current temperature = <not available>");
            }
            break;
        case 1:
            if ((extra > 5) && (k > 5)) {
                if (ucp[5] < 0xff)
                    printf("  Reference temperature = %d C", ucp[5]);
                else
                    printf("  Reference temperature = <not available>");
            }
            break;
        default:
            if (! op->do_temperature) {
                printf("  unknown parameter code = 0x%x, contents in "
                       "hex:\n", pc);
                dStrHex((const char *)ucp, extra, 1);
            } else
                continue;
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
    }
    return true;
}

/* START_STOP_LPAGE [0xe]  introduced: SPC-3 */
static bool
show_start_stop_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed Start-stop cycle counter page\n");
        return false;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Start-stop cycle counter page  [0xe]\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            pr2serr("short Start-stop cycle counter page\n");
            return true;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, extra);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, extra,
                        ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 1:
            if (10 == extra)
                printf("  Date of manufacture, year: %.4s, week: %.2s",
                       &ucp[4], &ucp[8]);
            else if (op->verbose) {
                pr2serr("  Date of manufacture parameter length strange: "
                        "%d\n", extra - 4);
                dStrHexErr((const char *)ucp, extra, 1);
            }
            break;
        case 2:
            if (10 == extra)
                printf("  Accounting date, year: %.4s, week: %.2s",
                       &ucp[4], &ucp[8]);
            else if (op->verbose) {
                pr2serr("  Accounting date parameter length strange: %d\n",
                        extra - 4);
                dStrHexErr((const char *)ucp, extra, 1);
            }
            break;
        case 3:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Specified cycle count over device lifetime "
                           "= -1");
                else
                    printf("  Specified cycle count over device lifetime "
                           "= %u", n);
            }
            break;
        case 4:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Accumulated start-stop cycles = -1");
                else
                    printf("  Accumulated start-stop cycles = %u", n);
            }
            break;
        case 5:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Specified load-unload count over device "
                           "lifetime = -1");
                else
                    printf("  Specified load-unload count over device "
                           "lifetime = %u", n);
            }
            break;
        case 6:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Accumulated load-unload cycles = -1");
                else
                    printf("  Accumulated load-unload cycles = %u", n);
            }
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in "
                   "hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
    }
    return true;
}

/* APP_CLIENT_LPAGE [0xf]  introduced: SPC-3 */
static bool
show_app_client_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc, pcb;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed Application Client page\n");
        return false;
    }
    if (op->verbose || ((op->do_raw == 0) && (op->do_hex == 0)))
        printf("Application client page  [0xf]\n");
    if (0 == op->filter_given) {
        if ((len > 128) && (0 == op->do_hex)) {
            dStrHex((const char *)resp, 64, 1);
            printf(" .....  [truncated after 64 of %d bytes (use '-H' to "
                   "see the rest)]\n", len);
        }
        else
            dStrHex((const char *)resp, len, 1);
        return true;
    }
    /* only here if filter_given set */
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            pr2serr("short Application client page\n");
            return true;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (op->filter != pc)
            continue;
        if (op->do_raw)
            dStrRaw((const char *)ucp, extra);
        else if (0 == op->do_hex)
            dStrHex((const char *)ucp, extra, 0);
        else if (1 == op->do_hex)
            dStrHex((const char *)ucp, extra, 1);
        else
            dStrHex((const char *)ucp, extra, -1);

        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        break;
    }
    return true;
}

/* IE_LPAGE [0x2f]  introduced: SPC-3 */
static bool
show_ie_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, extra, pc, pcb, full;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];
    char b[256];

    full = ! op->do_temperature;
    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("badly formed Informational Exceptions page\n");
        return false;
    }
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
        if (full)
            printf("Informational Exceptions page  [0x2f]\n");
    }
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Informational Exceptions page\n");
            return false;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, extra);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, extra,
                        ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            if (extra > 5) {
                if (full) {
                    printf("  IE asc = 0x%x, ascq = 0x%x", ucp[4], ucp[5]);
                    if (ucp[4] || ucp[5])
                        if(sg_get_asc_ascq_str(ucp[4], ucp[5], sizeof(b), b))
                            printf("\n    [%s]", b);
                }
                if (extra > 6) {
                    if (ucp[6] < 0xff)
                        printf("\n  Current temperature = %d C", ucp[6]);
                    else
                        printf("\n  Current temperature = <not available>");
                    if (extra > 7) {
                        if (ucp[7] < 0xff)
                            printf("\n  Threshold temperature = %d C  [IBM "
                                   "extension]", ucp[7]);
                        else
                            printf("\n  Threshold temperature = <not "
                                   "available>");
                     }
                }
            }
            break;
        default:
            if (full) {
                printf("  parameter code = 0x%x, contents in hex:\n", pc);
                dStrHex((const char *)ucp, extra, 1);
            }
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
    }
    return true;
}

/* helper for SAS port of PROTO_SPECIFIC_LPAGE [0x18] */
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

/* helper for SAS port of PROTO_SPECIFIC_LPAGE [0x18] */
static void
show_sas_port_param(const uint8_t * ucp, int param_len,
                    const struct opts_t * op)
{
    int j, m, n, nphys, pcb, t, sz, spld_len;
    const uint8_t * vcp;
    uint64_t ull;
    unsigned int ui;
    char pcb_str[PCB_STR_LEN];
    char s[64];

    sz = sizeof(s);
    pcb = ucp[2];
    t = (ucp[0] << 8) | ucp[1];
    if (op->do_name)
        printf("rel_target_port=%d\n", t);
    else
        printf("relative target port id = %d\n", t);
    if (op->do_name)
        printf("  gen_code=%d\n", ucp[6]);
    else
        printf("  generation code = %d\n", ucp[6]);
    nphys = ucp[7];
    if (op->do_name)
        printf("  num_phys=%d\n", nphys);
    else {
        printf("  number of phys = %d", nphys);
        if ((op->do_pcb) && (0 == op->do_name)) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }

    for (j = 0, vcp = ucp + 8; j < (param_len - 8);
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
            for (n = 0, ull = vcp[16]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[16 + n];
            }
            printf("      att_sas_addr=0x%" PRIx64 "\n", ull);
            printf("      att_tport_mask=0x%x\n", vcp[7]);
            ui = (vcp[32] << 24) | (vcp[33] << 16) | (vcp[34] << 8) | vcp[35];
            printf("      inv_dwords=%u\n", ui);
            ui = (vcp[40] << 24) | (vcp[41] << 16) | (vcp[42] << 8) | vcp[43];
            printf("      loss_dword_sync=%u\n", ui);
            printf("      neg_log_lrate=%d\n", 0xf & vcp[5]);
            ui = (vcp[44] << 24) | (vcp[45] << 16) | (vcp[46] << 8) | vcp[47];
            printf("      phy_reset_probs=%u\n", ui);
            ui = (vcp[36] << 24) | (vcp[37] << 16) | (vcp[38] << 8) | vcp[39];
            printf("      running_disparity=%u\n", ui);
            printf("      reason=0x%x\n", (vcp[5] & 0xf0) >> 4);
            for (n = 0, ull = vcp[8]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[8 + n];
            }
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
            t = (0xf & vcp[5]);
            switch (t) {
            case 0:
                snprintf(s, sz, "phy enabled; unknown reason");
                break;
            case 1:
                snprintf(s, sz, "phy disabled");
                break;
            case 2:
                snprintf(s, sz, "phy enabled; speed negotiation failed");
                break;
            case 3:
                snprintf(s, sz, "phy enabled; SATA spinup hold state");
                break;
            case 4:
                snprintf(s, sz, "phy enabled; port selector");
                break;
            case 5:
                snprintf(s, sz, "phy enabled; reset in progress");
                break;
            case 6:
                snprintf(s, sz, "phy enabled; unsupported phy attached");
                break;
            case 8:
                snprintf(s, sz, "1.5 Gbps");
                break;
            case 9:
                snprintf(s, sz, "3 Gbps");
                break;
            case 0xa:
                snprintf(s, sz, "6 Gbps");
                break;
            case 0xb:
                snprintf(s, sz, "12 Gbps");
                break;
            default:
                snprintf(s, sz, "reserved [%d]", t);
                break;
            }
            printf("    negotiated logical link rate: %s\n", s);
            printf("    attached initiator port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[6] & 8), !! (vcp[6] & 4), !! (vcp[6] & 2));
            printf("    attached target port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[7] & 8), !! (vcp[7] & 4), !! (vcp[7] & 2));
            for (n = 0, ull = vcp[8]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[8 + n];
            }
            printf("    SAS address = 0x%" PRIx64 "\n", ull);
            for (n = 0, ull = vcp[16]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[16 + n];
            }
            printf("    attached SAS address = 0x%" PRIx64 "\n", ull);
            printf("    attached phy identifier = %d\n", vcp[24]);
            ui = (vcp[32] << 24) | (vcp[33] << 16) | (vcp[34] << 8) | vcp[35];
            printf("    Invalid DWORD count = %u\n", ui);
            ui = (vcp[36] << 24) | (vcp[37] << 16) | (vcp[38] << 8) | vcp[39];
            printf("    Running disparity error count = %u\n", ui);
            ui = (vcp[40] << 24) | (vcp[41] << 16) | (vcp[42] << 8) | vcp[43];
            printf("    Loss of DWORD synchronization = %u\n", ui);
            ui = (vcp[44] << 24) | (vcp[45] << 16) | (vcp[46] << 8) | vcp[47];
            printf("    Phy reset problem = %u\n", ui);
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
                ui = (xcp[4] << 24) | (xcp[5] << 16) | (xcp[6] << 8) |
                     xcp[7];
                pvdt = (xcp[8] << 24) | (xcp[9] << 16) | (xcp[10] << 8) |
                       xcp[11];
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
    const uint8_t * ucp;

    num = len - 4;
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
        if (op->do_name)
            printf("log_page=0x%x\n", PROTO_SPECIFIC_LPAGE);
    }
    for (k = 0, ucp = resp + 4; k < num; ) {
        pc = (ucp[0] << 8) + ucp[1];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        pid = 0xf & ucp[4];
        if (6 != pid) {
            pr2serr("Protocol identifier: %d, only support SAS (SPL) which "
                    "is 6\n", pid);
            return false;   /* only decode SAS log page */
        }
        if ((0 == k) && (0 == op->do_name))
            printf("Protocol Specific port page for SAS SSP  (sas-2) "
                   "[0x18]\n");
        show_sas_port_param(ucp, pl, op);
        if (op->filter_given)
            break;
skip:
        k += pl;
        ucp += pl;
    }
    return true;
}

/* Returns 1 if processed page, 0 otherwise */
/* STATS_LPAGE [0x19], subpages: 0x0 to 0x1f  introduced: SPC-4 */
static bool
show_stats_perform_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int k, num, n, param_len, param_code, spf, subpg_code, extra;
    int pcb, nam;
    const uint8_t * ucp;
    const char * ccp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    nam = op->do_name;
    num = len - 4;
    ucp = resp + 4;
    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : 0;
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
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
        for (k = num; k > 0; k -= extra, ucp += extra) {
            if (k < 3)
                return false;
            param_len = ucp[3];
            extra = param_len + 4;
            param_code = (ucp[0] << 8) + ucp[1];
            pcb = ucp[2];
            if (op->filter_given) {
                if (param_code != op->filter)
                    continue;
                if (op->do_raw) {
                    dStrRaw((const char *)ucp, extra);
                    break;
                } else if (op->do_hex) {
                    dStrHex((const char *)ucp, extra,
                            ((1 == op->do_hex) ? 1 : -1));
                    break;
                }
            }
            switch (param_code) {
            case 1:     /* Statistics and performance log parameter */
                ccp = nam ? "parameter_code=1" : "Statistics and performance "
                        "log parameter";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "read_commands=" : "number of read commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[12]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[12 + n];
                }
                ccp = nam ? "write_commands=" : "number of write commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[20]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[20 + n];
                }
                ccp = nam ? "lb_received="
                          : "number of logical blocks received = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[28]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[28 + n];
                }
                ccp = nam ? "lb_transmitted="
                          : "number of logical blocks transmitted = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[36]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[36 + n];
                }
                ccp = nam ? "read_proc_intervals="
                          : "read command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[44]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[44 + n];
                }
                ccp = nam ? "write_proc_intervals="
                          : "write command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[52]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[52 + n];
                }
                ccp = nam ? "weight_rw_commands=" : "weighted number of "
                                "read commands plus write commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[60]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[60 + n];
                }
                ccp = nam ? "weight_rw_processing=" : "weighted read command "
                                "processing plus write command processing = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 2:     /* Idle time log parameter */
                ccp = nam ? "parameter_code=2" : "Idle time log parameter";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "idle_time_intervals=" : "idle time "
                                "intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 3:     /* Time interval log parameter for general stats */
                ccp = nam ? "parameter_code=3" : "Time interval log "
                        "parameter for general stats";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 4; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "time_interval_neg_exp=" : "time interval "
                                "negative exponent = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[8]; n < 4; ++n) {
                    ull <<= 8; ull |= ucp[8 + n];
                }
                ccp = nam ? "time_interval_int=" : "time interval "
                                "integer = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 4:     /* FUA statistics and performance log parameter */
                ccp = nam ? "parameter_code=4" : "Force unit access "
                        "statistics and performance log parameter ";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "read_fua_commands=" : "number of read FUA "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[12]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[12 + n];
                }
                ccp = nam ? "write_fua_commands=" : "number of write FUA "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[20]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[20 + n];
                }
                ccp = nam ? "read_fua_nv_commands="
                          : "number of read FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[28]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[28 + n];
                }
                ccp = nam ? "write_fua_nv_commands="
                          : "number of write FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[36]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[36 + n];
                }
                ccp = nam ? "read_fua_proc_intervals="
                          : "read FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[44]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[44 + n];
                }
                ccp = nam ? "write_fua_proc_intervals="
                          : "write FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[52]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[52 + n];
                }
                ccp = nam ? "read_fua_nv_proc_intervals="
                          : "read FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[60]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[60 + n];
                }
                ccp = nam ? "write_fua_nv_proc_intervals="
                          : "write FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 6:     /* Time interval log parameter for cache stats */
                ccp = nam ? "parameter_code=6" : "Time interval log "
                        "parameter for cache stats";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 4; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "time_interval_neg_exp=" : "time interval "
                                "negative exponent = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[8]; n < 4; ++n) {
                    ull <<= 8; ull |= ucp[8 + n];
                }
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
                    dStrHexErr((const char *)ucp, extra, 1);
                break;
            }
            if ((op->do_pcb) && (0 == op->do_name)) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("    <%s>\n", pcb_str);
            }
            if (op->filter_given)
                break;
        }
    } else {    /* Group statistics and performance (n) log page */
        if (num < 0x34)
            return false;
        for (k = num; k > 0; k -= extra, ucp += extra) {
            if (k < 3)
                return false;
            param_len = ucp[3];
            extra = param_len + 4;
            param_code = (ucp[0] << 8) + ucp[1];
            pcb = ucp[2];
            if (op->filter_given) {
                if (param_code != op->filter)
                    continue;
                if (op->do_raw) {
                    dStrRaw((const char *)ucp, extra);
                    break;
                } else if (op->do_hex) {
                    dStrHex((const char *)ucp, extra,
                            ((1 == op->do_hex) ? 1 : -1));
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
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "gn_read_commands=" : "group n number of read "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[12]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[12 + n];
                }
                ccp = nam ? "gn_write_commands=" : "group n number of write "
                                "commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[20]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[20 + n];
                }
                ccp = nam ? "gn_lb_received="
                          : "group n number of logical blocks received = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[28]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[28 + n];
                }
                ccp = nam ? "gn_lb_transmitted="
                          : "group n number of logical blocks transmitted = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[36]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[36 + n];
                }
                ccp = nam ? "gn_read_proc_intervals="
                          : "group n read command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[44]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[44 + n];
                }
                ccp = nam ? "gn_write_proc_intervals="
                          : "group n write command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                break;
            case 4: /* Group n FUA statistics and performance log parameter */
                ccp = nam ? "parameter_code=4" : "Group n force unit access "
                        "statistics and performance log parameter";
                printf("%s\n", ccp);
                for (n = 0, ull = ucp[4]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[4 + n];
                }
                ccp = nam ? "gn_read_fua_commands="
                          : "group n number of read FUA commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[12]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[12 + n];
                }
                ccp = nam ? "gn_write_fua_commands="
                          : "group n number of write FUA commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[20]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[20 + n];
                }
                ccp = nam ? "gn_read_fua_nv_commands="
                          : "group n number of read FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[28]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[28 + n];
                }
                ccp = nam ? "gn_write_fua_nv_commands="
                          : "group n number of write FUA_NV commands = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[36]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[36 + n];
                }
                ccp = nam ? "gn_read_fua_proc_intervals="
                          : "group n read FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[44]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[44 + n];
                }
                ccp = nam ? "gn_write_fua_proc_intervals=" : "group n write "
                            "FUA command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[52]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[52 + n];
                }
                ccp = nam ? "gn_read_fua_nv_proc_intervals=" : "group n "
                            "read FUA_NV command processing intervals = ";
                printf("  %s%" PRIu64 "\n", ccp, ull);
                for (n = 0, ull = ucp[60]; n < 8; ++n) {
                    ull <<= 8; ull |= ucp[60 + n];
                }
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
                    dStrHexErr((const char *)ucp, extra, 1);
                break;
            }
            if ((op->do_pcb) && (0 == op->do_name)) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("    <%s>\n", pcb_str);
            }
            if (op->filter_given)
                break;
        }
    }
    return true;
}

/* Returns 1 if processed page, 0 otherwise */
/* STATS_LPAGE [0x19], CACHE_STATS_SUBPG [0x20]  introduced: SPC-4 */
static bool
show_cache_stats_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int k, num, n, pc, spf, subpg_code, extra;
    int pcb, nam;
    const uint8_t * ucp;
    const char * ccp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    nam = op->do_name;
    num = len - 4;
    ucp = resp + 4;
    if (num < 4) {
        pr2serr("badly formed Cache memory statistics page\n");
        return false;
    }
    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : 0;
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
        if (nam) {
            printf("log_page=0x%x\n", STATS_LPAGE);
            if (subpg_code > 0)
                printf("log_subpage=0x%x\n", subpg_code);
        } else
            printf("Cache memory statistics page  [0x19,0x20]\n");
    }

    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            pr2serr("short Cache memory statistics page\n");
            return false;
        }
        if (8 != ucp[3]) {
            printf("Cache memory statistics page parameter length not "
                   "8\n");
            return false;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, extra);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, extra,
                        ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 1:     /* Read cache memory hits log parameter */
            ccp = nam ? "parameter_code=1" :
                        "Read cache memory hits log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "read_cache_memory_hits=" :
                        "read cache memory hits = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 2:     /* Reads to cache memory log parameter */
            ccp = nam ? "parameter_code=2" :
                        "Reads to cache memory log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "reads_to_cache_memory=" :
                        "reads to cache memory = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 3:     /* Write cache memory hits log parameter */
            ccp = nam ? "parameter_code=3" :
                        "Write cache memory hits log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "write_cache_memory_hits=" :
                        "write cache memory hits = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 4:     /* Writes from cache memory log parameter */
            ccp = nam ? "parameter_code=4" :
                        "Writes from cache memory log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "writes_from_cache_memory=" :
                        "writes from cache memory = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 5:     /* Time from last hard reset log parameter */
            ccp = nam ? "parameter_code=5" :
                        "Time from last hard reset log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 8; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "time_from_last_hard_reset=" :
                        "time from last hard reset = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        case 6:     /* Time interval log parameter for cache stats */
            ccp = nam ? "parameter_code=6" :
                        "Time interval log parameter";
            printf("%s\n", ccp);
            for (n = 0, ull = ucp[4]; n < 4; ++n) {
                ull <<= 8; ull |= ucp[4 + n];
            }
            ccp = nam ? "time_interval_neg_exp=" : "time interval "
                            "negative exponent = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            for (n = 0, ull = ucp[8]; n < 4; ++n) {
                ull <<= 8; ull |= ucp[8 + n];
            }
            ccp = nam ? "time_interval_int=" : "time interval "
                            "integer = ";
            printf("  %s%" PRIu64 "\n", ccp, ull);
            break;
        default:
            if (nam) {
                printf("parameter_code=%d\n", pc);
                printf("  unknown=1\n");
            } else
                pr2serr("show_performance...  unknown parameter code %d\n",
                        pc);
            if (op->verbose)
                dStrHexErr((const char *)ucp, extra, 1);
            break;
        }
        if ((op->do_pcb) && (0 == op->do_name)) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("    <%s>\n", pcb_str);
        }
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
    int k, j, num, pl, pc, pcb, all_ff, counter;
    const uint8_t * ucp;
    const uint8_t * xp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Format status page  [0x8]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        counter = 1;
        switch (pc) {
        case 0:
            if (pl < 5)
                printf("  Format data out: <empty>\n");
            else {
                for (all_ff = 1, j = 4; j < pl; ++j) {
                    if (0xff != ucp[j]) {
                        all_ff = 0;
                        break;
                    }
                }
                if (all_ff)
                    printf("  Format data out: <not available>\n");
                else {
                    printf("  Format data out:\n");
                    dStrHex((const char *)ucp + 4, pl - 4, 0);
                }
            }
            counter = 0;
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
            printf("  Unknown Format status code = 0x%x\n", pc);
            counter = 0;
            dStrHex((const char *)ucp, pl, 0);
            break;
        }
        if (counter) {
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (all_ff = 0, j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                else
                    all_ff = 1;
                ull |= xp[j];
                if (0xff != xp[j])
                    all_ff = 0;
            }
            if (all_ff)
                printf(" <not available>");
            else
                printf(" = %" PRIu64 "", ull);
            if (op->do_pcb) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("\n        <%s>\n", pcb_str);
            } else
                printf("\n");
        } else {
            if (op->do_pcb) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("\n        <%s>\n", pcb_str);
            }
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* Non-volatile cache page [0x17]  introduced: SBC-2 */
static bool
show_non_volatile_cache_page(const uint8_t * resp, int len,
                             const struct opts_t * op)
{
    int j, num, pl, pc, pcb;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Non-volatile cache page  [0x17]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        switch (pc) {
        case 0:
            printf("  Remaining non-volatile time: ");
            if (3 == ucp[4]) {
                j = (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
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
                printf("<unexpected parameter length=%d>\n", ucp[4]);
            break;
        case 1:
            printf("  Maximum non-volatile time: ");
            if (3 == ucp[4]) {
                j = (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
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
                printf("<unexpected parameter length=%d>\n", ucp[4]);
            break;
        default:
            printf("  Unknown Format status code = 0x%x\n", pc);
            dStrHex((const char *)ucp, pl, 0);
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* LB_PROV_LPAGE [0xc]  introduced: SBC-3 */
static bool
show_lb_provisioning_page(const uint8_t * resp, int len,
                          const struct opts_t * op)
{
    int j, num, pl, pc, pcb;
    const uint8_t * ucp;
    const char * cp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Logical block provisioning page  [0xc]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
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
            printf("  %s resource count:", cp);
            if ((pl < 8) || (num < 8)) {
                if (num < 8)
                    pr2serr("\n    truncated by response length, expected at "
                            "least 8 bytes\n");
                else
                    pr2serr("\n    parameter length >= 8 expected, got %d\n",
                            pl);
                break;
            }
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf(" %d\n", j);
            if (pl > 8) {
                switch (ucp[8] & 0x3) {
                case 0: cp = "not reported"; break;
                case 1: cp = "dedicated to lu"; break;
                case 2: cp = "not dedicated to lu"; break;
                case 3: cp = "reserved"; break;
                }
                printf("    Scope: %s\n", cp);
            }
        } else if ((pc >= 0xfff0) && (pc <= 0xffff)) {
            printf("  Vendor specific [0x%x]:", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
        } else {
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* SOLID_STATE_MEDIA_LPAGE [0x11]  introduced: SBC-3 */
static bool
show_solid_state_media_page(const uint8_t * resp, int len,
                            const struct opts_t * op)
{
    int num, pl, pc, pcb;
    const uint8_t * ucp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Solid state media page  [0x11]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
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
            printf(" %d%%\n", ucp[7]);
            break;
        default:
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
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
    int num, pl, pc, pcb, j;
    const uint8_t * ucp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("DT device status page (ssc-3, adc-3) [0x11]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
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
            printf("  PAMR=%d HUI=%d MACC=%d CMPR=%d ", !!(0x80 & ucp[4]),
                   !!(0x40 & ucp[4]), !!(0x20 & ucp[4]), !!(0x10 & ucp[4]));
            printf("WRTP=%d CRQST=%d CRQRD=%d DINIT=%d\n", !!(0x8 & ucp[4]),
                   !!(0x4 & ucp[4]), !!(0x2 & ucp[4]), !!(0x1 & ucp[4]));
            printf("  INXTN=%d RAA=%d MPRSNT=%d ", !!(0x80 & ucp[5]),
                   !!(0x20 & ucp[5]), !!(0x10 & ucp[5]));
            printf("MSTD=%d MTHRD=%d MOUNTED=%d\n",
                   !!(0x4 & ucp[5]), !!(0x2 & ucp[5]), !!(0x1 & ucp[5]));
            printf("  DT device activity: ");
            j = ucp[6];
            if (j < (int)(sizeof(dt_dev_activity) /
                          sizeof(dt_dev_activity[0])))
                printf("%s\n", dt_dev_activity[j]);
            else if (j < 0x80)
                printf("Reserved [0x%x]\n", j);
            else
                printf("Vendor specific [0x%x]\n", j);
            printf("  VS=%d TDDEC=%d EPP=%d ", !!(0x80 & ucp[7]),
                   !!(0x20 & ucp[7]), !!(0x10 & ucp[7]));
            printf("ESR=%d RRQST=%d INTFC=%d TAFC=%d\n", !!(0x8 & ucp[7]),
                   !!(0x4 & ucp[7]), !!(0x2 & ucp[7]), !!(0x1 & ucp[7]));
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
            printf(" %d milliseconds\n", (ucp[4] << 8) + ucp[5]);
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
            dStrHex((const char *)ucp + 4, 8, 1);
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
            dStrHex((const char *)ucp + 4, 12, 1);
            break;
        default:
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
            break;
        }
// xxxxxxxxxxxxxxx
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* SAT_ATA_RESULTS_LPAGE (SAT-2) [0x16] */
static bool
show_ata_pt_results_page(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    int num, pl, pc, pcb;
    const uint8_t * ucp;
    const uint8_t * dp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("ATA pass-through results page (sat-2) [0x16]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if ((pc < 0xf) && (pl > 17)) {
            int extend, sector_count;

            dp = ucp + 4;
            printf("  Log_index=0x%x (parameter_code=0x%x)\n", pc + 1, pc);
            extend = dp[2] & 1;
            sector_count = dp[5] + (extend ? (dp[4] << 8) : 0);
            printf("    extend=%d  error=0x%x sector_count=0x%x\n", extend,
                   dp[3], sector_count);
            if (extend)
                printf("    lba=0x%02x%02x%02x%02x%02x%02x\n", dp[10], dp[8],
                       dp[6], dp[11], dp[9], dp[7]);
            else
                printf("    lba=0x%02x%02x%02x\n", dp[11], dp[9], dp[7]);
            printf("    device=0x%x  status=0x%x\n", dp[12], dp[13]);
        } else {
            printf("  Reserved [parameter_code=0x%x]:\n", pc);
            dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
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
    int j, m, num, pl, pc, pcb;
    const uint8_t * ucp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Background scan results page  [0x15]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
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
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf("%d [h:m  %d:%d]\n", j, (j / 60), (j % 60));
            printf("    Status: ");
            j = ucp[9];
            if (j < (int)(sizeof(bms_status) / sizeof(bms_status[0])))
                printf("%s\n", bms_status[j]);
            else
                printf("unknown [0x%x] background scan status value\n", j);
            j = (ucp[10] << 8) + ucp[11];
            printf("    Number of background scans performed: %d\n", j);
            j = (ucp[12] << 8) + ucp[13];
#ifdef SG_LIB_MINGW
            printf("    Background medium scan progress: %g%%\n",
                   (double)(j * 100.0 / 65536.0));
#else
            printf("    Background medium scan progress: %.2f%%\n",
                   (double)(j * 100.0 / 65536.0));
#endif
            j = (ucp[14] << 8) + ucp[15];
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
                dStrHex((const char *)ucp, ((pl < num) ? pl : num), 0);
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
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf("%d [%d:%d]\n", j, (j / 60), (j % 60));
            j = (ucp[8] >> 4) & 0xf;
            if (j <
                (int)(sizeof(reassign_status) / sizeof(reassign_status[0])))
                printf("    %s\n", reassign_status[j]);
            else
                printf("    Reassign status: reserved [0x%x]\n", j);
            printf("    sense key: %s  [sk,asc,ascq: 0x%x,0x%x,0x%x]\n",
                   sg_get_sense_key_str(ucp[8] & 0xf, sizeof(str), str),
                   ucp[8] & 0xf, ucp[9], ucp[10]);
            if (ucp[9] || ucp[10])
                printf("      %s\n", sg_get_asc_ascq_str(ucp[9], ucp[10],
                                                         sizeof(str), str));
            if (op->verbose) {
                printf("    vendor bytes [11 -> 15]: ");
                for (m = 0; m < 5; ++m)
                    printf("0x%02x ", ucp[11 + m]);
                printf("\n");
            }
            printf("    LBA (associated with medium error): 0x");
            for (m = 0; m < 8; ++m)
                printf("%02x", ucp[16 + m]);
            printf("\n");
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* Sequential access device page [0xc] for tape */
static bool
show_sequential_access_page(const uint8_t * resp, int len,
                            const struct opts_t * op)
{
    int num, pl, pc, pcb;
    const uint8_t * ucp;
    uint64_t ull, gbytes;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Sequential access device page (ssc-3)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        ull = decode_count(ucp + 4, pl - 4);
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
            printf("  Native capacity from BOP to EOD: %" PRIu64 " MB\n",
                   ull);
            break;
        case 5:
            printf("  Native capacity from BOP to EW of current partition: "
                   "%" PRIu64 " MB\n", ull);
            break;
        case 6:
            printf("  Minimum native capacity from EW to EOP of current "
                   "partition: %" PRIu64 " MB\n", ull);
            break;
        case 7:
            printf("  Native capacity from BOP to current position: %"
                   PRIu64 " MB\n", ull);
            break;
        case 8:
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
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* 0x14 for tape and ADC */
static bool
show_device_stats_page(const uint8_t * resp, int len,
                       const struct opts_t * op)
{
    int num, pl, pc, pcb;
    const uint8_t * ucp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Device statistics page (ssc-3 and adc)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        if (pc < 0x1000) {
            ull = decode_count(ucp + 4, pl - 4);
            switch (pc) {
            case 0:
                printf("  Lifetime media loads: %" PRIu64 "\n", ull);
                break;
            case 1:
                printf("  Lifetime cleaning operations: %" PRIu64 "\n", ull);
                break;
            case 2:
                printf("  Lifetime power on hours: %" PRIu64 "\n", ull);
                break;
            case 3:
                printf("  Lifetime media motion (head) hours: %" PRIu64 "\n",
                       ull);
                break;
            case 4:
                printf("  Lifetime metres of tape processed: %" PRIu64 "\n",
                       ull);
                break;
            case 5:
                printf("  Lifetime media motion (head) hours when "
                       "incompatible media last loaded: %" PRIu64 "\n", ull);
                break;
            case 6:
                printf("  Lifetime power on hours when last temperature "
                       "condition occurred: %" PRIu64 "\n", ull);
                break;
            case 7:
                printf("  Lifetime power on hours when last power "
                       "consumption condition occurred: %" PRIu64 "\n", ull);
                break;
            case 8:
                printf("  Media motion (head) hours since last successful "
                       "cleaning operation: %" PRIu64 "\n", ull);
                break;
            case 9:
                printf("  Media motion (head) hours since 2nd to last "
                       "successful cleaning: %" PRIu64 "\n", ull);
                break;
            case 0xa:
                printf("  Media motion (head) hours since 3rd to last "
                       "successful cleaning: %" PRIu64 "\n", ull);
                break;
            case 0xb:
                printf("  Lifetime power on hours when last operator "
                       "initiated forced reset\n    and/or emergency "
                       "eject occurred: %" PRIu64 "\n", ull);
                break;
            default:
                printf("  Reserved parameter [0x%x] value: %" PRIu64 "\n",
                       pc, ull);
                break;
            }
        } else {
            switch (pc) {
            case 0x1000:
                printf("  Media motion (head) hours for each medium type:\n");
                printf("      <<to be decoded, dump in hex for now>>:\n");
                dStrHex((const char *)ucp, pl, 0);
                // xxxxxxxxxxx
                break;
            default:
                printf("  Reserved parameter [0x%x], dump in hex:\n", pc);
                dStrHex((const char *)ucp, pl, 0);
                break;
            }
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* 0x14 for media changer */
static bool
show_media_stats_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int num, pl, pc, pcb;
    const uint8_t * ucp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Media statistics page (smc-3)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        ull = decode_count(ucp + 4, pl - 4);
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
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* 0x15 for media changer */
static bool
show_element_stats_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int num, pl, pc, pcb;
    unsigned int v;
    const uint8_t * ucp;
    char str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Element statistics page (smc-3) [0x15]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Element address: %d\n", pc);
        v = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
        printf("    Number of places: %u\n", v);
        v = (ucp[8] << 24) + (ucp[9] << 16) + (ucp[10] << 8) + ucp[11];
        printf("    Number of place retries: %u\n", v);
        v = (ucp[12] << 24) + (ucp[13] << 16) + (ucp[14] << 8) + ucp[15];
        printf("    Number of picks: %u\n", v);
        v = (ucp[16] << 24) + (ucp[17] << 16) + (ucp[18] << 8) + ucp[19];
        printf("    Number of pick retries: %u\n", v);
        v = (ucp[20] << 24) + (ucp[21] << 16) + (ucp[22] << 8) + ucp[23];
        printf("    Number of determined volume identifiers: %u\n", v);
        v = (ucp[24] << 24) + (ucp[25] << 16) + (ucp[26] << 8) + ucp[27];
        printf("    Number of unreadable volume identifiers: %u\n", v);
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* 0x16 for tape */
static bool
show_tape_diag_data_page(const uint8_t * resp, int len,
                         const struct opts_t * op)
{
    int k, num, pl, pc, pcb;
    unsigned int v;
    const uint8_t * ucp;
    char str[PCB_STR_LEN];
    char b[80];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Tape diagnostics data page (ssc-3) [0x16]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Parameter code: %d\n", pc);
        printf("    Density code: 0x%x\n", ucp[6]);
        printf("    Medium type: 0x%x\n", ucp[7]);
        v = (ucp[8] << 24) + (ucp[9] << 16) + (ucp[10] << 8) + ucp[11];
        printf("    Lifetime media motion hours: %u\n", v);
        printf("    Repeat: %d\n", !!(ucp[13] & 0x80));
        v = ucp[13] & 0xf;
        printf("    Sense key: 0x%x [%s]\n", v,
               sg_get_sense_key_str(v, sizeof(b), b));
        printf("    Additional sense code: 0x%x\n", ucp[14]);
        printf("    Additional sense code qualifier: 0x%x\n", ucp[15]);
        if (ucp[14] || ucp[15])
            printf("      [%s]\n", sg_get_asc_ascq_str(ucp[14], ucp[15],
                   sizeof(b), b));
        v = (ucp[16] << 24) + (ucp[17] << 16) + (ucp[18] << 8) + ucp[19];
        printf("    Vendor specific code qualifier: 0x%x\n", v);
        v = (ucp[20] << 24) + (ucp[21] << 16) + (ucp[22] << 8) + ucp[23];
        printf("    Product revision level: %u\n", v);
        v = (ucp[24] << 24) + (ucp[25] << 16) + (ucp[26] << 8) + ucp[27];
        printf("    Hours since last clean: %u\n", v);
        printf("    Operation code: 0x%x\n", ucp[28]);
        printf("    Service action: 0x%x\n", ucp[29] & 0xf);
        // Check Medium id number for all zeros
        // ssc4r03.pdf does not define this field, why? xxxxxx
        for (k = 32; k < 64; ++k) {
            if(ucp[k])
                break;
        }
        if (64 == k)
            printf("    Medium id number is 32 bytes of zero\n");
        else {
            printf("    Medium id number (in hex):\n");
            dStrHex((const char *)(ucp + 32), 32, 0);
        }
        printf("    Timestamp origin: 0x%x\n", ucp[64] & 0xf);
        // Check Timestamp for all zeros
        for (k = 66; k < 72; ++k) {
            if(ucp[k])
                break;
        }
        if (72 == k)
            printf("    Timestamp is all zeros:\n");
        else {
            printf("    Timestamp:\n");
            dStrHex((const char *)(ucp + 66), 6, 1);
        }
        if (pl > 72) {
            printf("    Vendor specific:\n");
            dStrHex((const char *)(ucp + 72), pl - 72, 0);
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* 0x16 for media changer */
static bool
show_mchanger_diag_data_page(const uint8_t * resp, int len,
                             const struct opts_t * op)
{
    int num, pl, pc, pcb;
    unsigned int v;
    const uint8_t * ucp;
    char str[PCB_STR_LEN];
    char b[80];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Media changer diagnostics data page (smc-3) [0x16]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        printf("  Parameter code: %d\n", pc);
        printf("    Repeat: %d\n", !!(ucp[5] & 0x80));
        v = ucp[5] & 0xf;
        printf("    Sense key: 0x%x [%s]\n", v,
               sg_get_sense_key_str(v, sizeof(b), b));
        printf("    Additional sense code: 0x%x\n", ucp[6]);
        printf("    Additional sense code qualifier: 0x%x\n", ucp[7]);
        if (ucp[6] || ucp[7])
            printf("      [%s]\n", sg_get_asc_ascq_str(ucp[6], ucp[7],
                   sizeof(b), b));
        v = (ucp[8] << 24) + (ucp[9] << 16) + (ucp[10] << 8) + ucp[11];
        printf("    Vendor specific code qualifier: 0x%x\n", v);
        v = (ucp[12] << 24) + (ucp[13] << 16) + (ucp[14] << 8) + ucp[15];
        printf("    Product revision level: %u\n", v);
        v = (ucp[16] << 24) + (ucp[17] << 16) + (ucp[18] << 8) + ucp[19];
        printf("    Number of moves: %u\n", v);
        v = (ucp[20] << 24) + (ucp[21] << 16) + (ucp[22] << 8) + ucp[23];
        printf("    Number of pick: %u\n", v);
        v = (ucp[24] << 24) + (ucp[25] << 16) + (ucp[26] << 8) + ucp[27];
        printf("    Number of pick retries: %u\n", v);
        v = (ucp[28] << 24) + (ucp[29] << 16) + (ucp[30] << 8) + ucp[31];
        printf("    Number of places: %u\n", v);
        v = (ucp[32] << 24) + (ucp[33] << 16) + (ucp[34] << 8) + ucp[35];
        printf("    Number of place retries: %u\n", v);
        v = (ucp[36] << 24) + (ucp[37] << 16) + (ucp[38] << 8) + ucp[39];
        printf("    Number of determined volume identifiers: %u\n", v);
        v = (ucp[40] << 24) + (ucp[41] << 16) + (ucp[42] << 8) + ucp[43];
        printf("    Number of unreadable volume identifiers: %u\n", v);
        printf("    Operation code: 0x%x\n", ucp[44]);
        printf("    Service action: 0x%x\n", ucp[45] & 0xf);
        printf("    Media changer error type: 0x%x\n", ucp[46]);
        printf("    MTAV: %d\n", !!(ucp[47] & 0x8));
        printf("    IAV: %d\n", !!(ucp[47] & 0x4));
        printf("    LSAV: %d\n", !!(ucp[47] & 0x2));
        printf("    DAV: %d\n", !!(ucp[47] & 0x1));
        v = (ucp[48] << 8) + ucp[49];
        printf("    Medium transport address: 0x%x\n", v);
        v = (ucp[50] << 8) + ucp[51];
        printf("    Intial address: 0x%x\n", v);
        v = (ucp[52] << 8) + ucp[53];
        printf("    Last successful address: 0x%x\n", v);
        v = (ucp[54] << 8) + ucp[55];
        printf("    Destination address: 0x%x\n", v);
        if (pl > 91) {
            printf("    Volume tag information:\n");
            dStrHex((const char *)(ucp + 56), 36, 0);
        }
        if (pl > 99) {
            printf("    Timestamp origin: 0x%x\n", ucp[92] & 0xf);
            printf("    Timestamp:\n");
            dStrHex((const char *)(ucp + 94), 6, 1);
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* Helper for show_volume_stats_page() */
static void
volume_stats_partition(const uint8_t * xp, int len, int hex)
{
    int dl;

    while (len > 3) {
        dl = xp[0] + 1;
        if (dl < 3)
            return;
        if (hex)
            printf("    partition number: %d, partition record data "
                   "counter: 0x%" PRIx64 "\n", (xp[2] << 8) + xp[3],
                   decode_count(xp + 4, dl - 4));
        else {
            int k;
            int all_ffs = 0;
            int ffs_last_fe = 0;
            uint8_t uc;

            for (k = 0; k < (dl - 4); ++k) {
                uc = xp[4 + k];
                if (uc < 0xfe)
                    break;
                if ((k < (dl - 5)) && (0xfe == uc))
                    break;
                if (k == (dl - 5)) {
                    if (0xff == uc)
                        all_ffs = 1;
                    else if (0xfe == uc)
                        ffs_last_fe = 1;
                }
            }

            if (0 == (all_ffs + ffs_last_fe))
                printf("    partition number: %d, partition record data "
                       "counter: %" PRIu64 "\n", (xp[2] << 8) + xp[3],
                       decode_count(xp + 4, dl - 4));
            else if (all_ffs)
                printf("    partition number: %d, partition record data "
                       "counter is all 0xFFs\n", (xp[2] << 8) + xp[3]);
            else
                printf("    partition number: %d, partition record data "
                       "counter is all 0xFFs apart\n    from a trailing "
                       "0xFE\n", (xp[2] << 8) + xp[3]);
        }
        xp += dl;
        len -= dl;
    }
}

/* Volume Statistics log page (ssc-4) [0x17, 0x1-0xf] */
static bool
show_volume_stats_page(const uint8_t * resp, int len,
                       const struct opts_t * op)
{
    int num, pl, pc, pcb, spf, subpg_code;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    spf = !!(resp[0] & 0x40);
    subpg_code = spf ? resp[1] : 0;
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex))) {
        if (0 == subpg_code)
            printf("Volume statistics page (ssc-4) but subpage=0, abnormal: "
                   "treat like subpage=1\n");
        else if (subpg_code < 0x10)
            printf("Volume statistics page (ssc-4), subpage=%d\n",
                   subpg_code);
        else {
            printf("Volume statistics page (ssc-4), subpage=%d; Reserved, "
                   "skip\n", subpg_code);
            return false;
        }
    }
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }

        switch (pc) {
        case 0:
            printf("  Page valid: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 1:
            printf("  Thread count: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 2:
            printf("  Total data sets written: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 3:
            printf("  Total write retries: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 4:
            printf("  Total unrecovered write errors: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 5:
            printf("  Total suspended writes: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 6:
            printf("  Total fatal suspended writes: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 7:
            printf("  Total data sets read: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 8:
            printf("  Total read retries: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 9:
            printf("  Total unrecovered read errors: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0xa:
            printf("  Total suspended reads: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0xb:
            printf("  Total fatal suspended reads: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0xc:
            printf("  Last mount unrecovered write errors: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0xd:
            printf("  Last mount unrecovered read errors: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0xe:
            printf("  Last mount megabytes written: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0xf:
            printf("  Last mount megabytes read: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x10:
            printf("  Lifetime megabytes written: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x11:
            printf("  Lifetime megabytes read: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x12:
            printf("  Last load write compression ratio: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x13:
            printf("  Last load read compression ratio: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x14:
            printf("  Medium mount time: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x15:
            printf("  Medium ready time: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x16:
            printf("  Total native capacity: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x17:
            printf("  Total used native capacity: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x40:
            printf("  Volume serial number: %.*s\n", pl - 4, ucp + 4);
            break;
        case 0x41:
            printf("  Tape lot identifier: %.*s\n", pl - 4, ucp + 4);
            break;
        case 0x42:
            printf("  Volume barcode: %.*s\n", pl - 4, ucp + 4);
            break;
        case 0x43:
            printf("  Volume manufacturer: %.*s\n", pl - 4, ucp + 4);
            break;
        case 0x44:
            printf("  Volume license code: %.*s\n", pl - 4, ucp + 4);
            break;
        case 0x45:
            printf("  Volume personality: %.*s\n", pl - 4, ucp + 4);
            break;
        case 0x80:
            printf("  Write protect: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x81:
            printf("  WORM: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x82:
            printf("  Maximum recommended tape path temperature exceeded: %"
                   PRIu64 "\n", decode_count(ucp + 4, pl - 4));
            break;
        case 0x100:
            printf("  Volume write mounts: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x101:
            printf("  Beginning of medium passes: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x102:
            printf("  Middle of medium passes: %" PRIu64 "\n",
                   decode_count(ucp + 4, pl - 4));
            break;
        case 0x200:
            printf("  Logical position of first encrypted logical object:\n");
            volume_stats_partition(ucp + 4, pl - 4, 1);
            break;
        case 0x201:
            printf("  Logical position of first unencrypted logical object "
                   "after first\n  encrypted logical object:\n");
            volume_stats_partition(ucp + 4, pl - 4, 1);
            break;
        case 0x202:
            printf("  Native capacity partition(s):\n");
            volume_stats_partition(ucp + 4, pl - 4, 0);
            break;
        case 0x203:
            printf("  Used native capacity partition(s):\n");
            volume_stats_partition(ucp + 4, pl - 4, 0);
            break;
        case 0x204:
            printf("  Remaining native capacity partition(s):\n");
            volume_stats_partition(ucp + 4, pl - 4, 0);
            break;
        case 0x300:
            printf("  Mount history, payload in hex:\n");
            // xxxxxxxx TODO
            dStrHex((const char *)(ucp + 4), pl - 4, 0);
            break;

        default:
            if (pc >= 0xf000)
                printf("  Vendor specific parameter code (0x%x), payload "
                       "in hex\n", pc);
            else
                printf("  Reserved parameter code (0x%x), payload in hex\n",
                       pc);
            dStrHex((const char *)(ucp + 4), pl - 4, 0);
            break;
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
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
    int num, pl, pc, pcb, flag;
    const uint8_t * ucp;
    char str[PCB_STR_LEN];

    /* N.B. the Tape alert log page for smc-3 is different */
    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Tape alert page (ssc-3) [0x2e]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        flag = ucp[4] & 1;
        if (op->verbose && (0 == op->do_brief) && flag)
            printf("  >>>> ");
        if ((0 == op->do_brief) || op->verbose || flag) {
            if (pc < (int)(sizeof(tape_alert_strs) /
                           sizeof(tape_alert_strs[0])))
                printf("  %s: %d\n", tape_alert_strs[pc], flag);
            else
                printf("  Reserved parameter code 0x%x, flag: %d\n", pc,
                       flag);
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("        <%s>\n", str);
        }
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* 0x37 */
static bool
show_seagate_cache_page(const uint8_t * resp, int len,
                        const struct opts_t * op)
{
    int num, pl, pc, pcb;
    const uint8_t * ucp;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Seagate cache page [0x37]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
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
        printf(" = %" PRIu64 "", decode_count(ucp + 4, pl - 4));
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

/* 0x3e */
static bool
show_seagate_factory_page(const uint8_t * resp, int len,
                          const struct opts_t * op)
{
    int num, pl, pc, pcb, valid;
    const uint8_t * ucp;
    uint64_t ull;
    char pcb_str[PCB_STR_LEN];

    if (op->verbose || ((0 == op->do_raw) && (0 == op->do_hex)))
        printf("Seagate/Hitachi factory page [0x3e]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
            if (op->do_raw) {
                dStrRaw((const char *)ucp, pl);
                break;
            } else if (op->do_hex) {
                dStrHex((const char *)ucp, pl, ((1 == op->do_hex) ? 1 : -1));
                break;
            }
        }
        valid = 1;
        switch (pc) {
        case 0: printf("  number of hours powered up"); break;
        case 8: printf("  number of minutes until next internal SMART test");
            break;
        default:
            valid = 0;
            printf("  Unknown Seagate/Hitachi parameter code = 0x%x", pc);
            break;
        }
        if (valid) {
            ull = decode_count(ucp + 4, pl - 4);
            if (0 == pc)
                printf(" = %.2f", ((double)ull) / 60.0 );
            else
                printf(" = %" PRIu64 "", ull);
        }
        if (op->do_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        if (op->filter_given)
            break;
skip:
        num -= pl;
        ucp += pl;
    }
    return true;
}

static void
show_ascii_page(const uint8_t * resp, int len, const struct opts_t * op)
{
    int pg_code, subpg_code, spf;
    bool done = false;
    const struct log_elem * lep;

    if (len < 3) {
        pr2serr("%s: response has bad length: %d\n", __func__, len);
        return;
    }
    spf = !!(resp[0] & 0x40);
    pg_code = resp[0] & 0x3f;
    subpg_code = spf ? resp[1] : 0;
    if ((SUPP_SPGS_SUBPG == subpg_code) && (SUPP_PAGES_LPAGE != pg_code)) {
        done = show_supported_pgs_sub_lpage(resp, len, op);
        if (done)
            return;
    }
    lep = pg_subpg_pdt_search(pg_code, subpg_code, op->dev_pdt);
    if (lep && lep->show_pagep)
        done = (*lep->show_pagep)(resp, len, op);

    if (! done) {
        if (spf)
            printf("No ascii information for page = 0x%x, subpage = 0x%x, "
                   "here is hex:\n", pg_code, subpg_code);
        else
            printf("No ascii information for page = 0x%x, here is hex:\n",
                   pg_code);
        if (len > 128) {
            dStrHex((const char *)resp, 64, 1);
            printf(" .....  [truncated after 64 of %d bytes (use '-H' to "
                   "see the rest)]\n", len);
        }
        else
            dStrHex((const char *)resp, len, 1);
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
        len = (resp[2] << 8) + resp[3] + 4;
        if (op->do_raw)
            dStrRaw((const char *)resp, len);
        else if (op->do_hex)
            dStrHex((const char *)resp, len, (1 == op->do_hex));
        else
            show_temperature_page(resp, len, op);
    }else if (SG_LIB_CAT_NOT_READY == res)
        pr2serr("Device not ready\n");
    else {
        op->pg_code = IE_LPAGE;
        res = do_logs(sg_fd, resp, max_len, op);
        if (0 == res) {
            len = (resp[2] << 8) + resp[3] + 4;
            if (op->do_raw)
                dStrRaw((const char *)resp, len);
            else if (op->do_hex)
                dStrHex((const char *)resp, len, (1 == op->do_hex));
            else
                show_ie_page(resp, len, op);
        } else
            pr2serr("Unable to find temperature in either Temperature or "
                    "IE log page\n");
    }
    sg_cmds_close_device(sg_fd);
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}

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
    int sg_fd, k, pg_len, res, resp_len;
    int in_len = -1;
    int ret = 0;
    struct sg_simple_inquiry_resp inq_out;
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    memset(op, 0, sizeof(opts));
    memset(rsp_buff, 0, sizeof(rsp_buff));
    /* N.B. some disks only give data for current cumulative */
    op->page_control = 1;
    op->dev_pdt = -1;
    res = process_cl(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (op->do_help) {
        usage_for(op->do_help, op);
        return 0;
    }
    if (op->do_version) {
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }
    if (op->do_enumerate > 0) {
        if (op->device_name && op->verbose)
            pr2serr("Warning: device: %s is being ignored\n",
                    op->device_name);
        enumerate_lpages(op);
        return 0;
    }

    if (NULL == op->device_name) {
        if (op->in_fn) {
            const struct log_elem * lep;
            const unsigned char * ucp;
            int pg_code, subpg_code, pdt, n;
            uint16_t u;

            if (f2hex_arr(op->in_fn, op->do_raw, 0, rsp_buff, &in_len,
                          sizeof(rsp_buff)))
                return SG_LIB_FILE_ERROR;
            if (op->do_raw)
                op->do_raw = 0;    /* can interfere on decode */
            if (in_len < 4) {
                pr2serr("--in=%s only decoded %d bytes (needs 4 at least)\n",
                        op->in_fn, in_len);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (op->pg_arg && (0 == op->do_brief))
                pr2serr(">>> --page=%s option is being ignored, using values "
                        "in file: %s\n", op->pg_arg, op->in_fn);
            for (ucp = rsp_buff, k = 0; k < in_len; ucp += n, k += n) {
                pg_code = ucp[0] & 0x3f;
                subpg_code = (ucp[0] & 0x40) ? ucp[1] : 0;
                u = sg_get_unaligned_be16(ucp + 2);
                n = u + 4;
                if (n > (in_len - k)) {
                    pr2serr("bytes decoded remaining (%d) less than lpage "
                            "length (%d), try decoding anyway\n", in_len - k,
                            n);
                    n = in_len - k;
                }
                pdt = (op->filter_given && (op->filter >= 0)) ?
                      op->filter : -1;
                op->dev_pdt = pdt;
                lep = pg_subpg_pdt_search(pg_code, subpg_code, pdt);
                if (lep) {
                    if (lep->show_pagep)
                        (*lep->show_pagep)(ucp, n, op);
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
            return 0;
        }
        pr2serr("No DEVICE argument given\n");
        usage_for(1, op);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_select) {
        if (op->do_temperature) {
            pr2serr("--select cannot be used with --temperature\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (op->do_transport) {
            pr2serr("--select cannot be used with --transport\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    } else if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }
    if (op->do_all) {
        if (op->do_select) {
            pr2serr("--all conflicts with --select\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (op->filter) {
            pr2serr("--all conflicts with --filter\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (op->in_fn) {
        if (! op->do_select) {
            pr2serr("--in=FN can only be used with --select when DEVICE "
                    "given\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (f2hex_arr(op->in_fn, op->do_raw, 0, rsp_buff, &in_len,
                      sizeof(rsp_buff)))
            return SG_LIB_FILE_ERROR;
    }
    if (op->pg_arg) {
        if (op->do_all) {
            if (0 == op->do_brief)
                pr2serr(">>> warning: --page=%s ignored when --all given\n",
                        op->pg_arg);
        } else {
            res = decode_pg_arg(op);
            if (res)
                return res;
        }
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    win32_spt_init_state = scsi_pt_win32_spt_state();
    if (op->verbose > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                win32_spt_init_state ? "direct" : "indirect");
#endif
#endif
    sg_fd = sg_cmds_open_device(op->device_name, op->o_readonly,
                                op->verbose);
    if ((sg_fd < 0) && (0 == op->o_readonly))
        sg_fd = sg_cmds_open_device(op->device_name, 1 /* ro */,
                                    op->verbose);
    if (sg_fd < 0) {
        pr2serr("error opening file: %s: %s \n", op->device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
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
            return SG_LIB_FILE_ERROR;
        }
        op->pg_code = PROTO_SPECIFIC_LPAGE;
    }
    pg_len = 0;

    if (op->no_inq < 2)  {
        if (sg_simple_inquiry(sg_fd, &inq_out, 1, op->verbose)) {
            pr2serr("%s doesn't respond to a SCSI INQUIRY\n",
                    op->device_name);
            sg_cmds_close_device(sg_fd);
            return SG_LIB_CAT_OTHER;
        }
        op->dev_pdt = inq_out.peripheral_type;
        if ((0 == op->do_raw) && (0 == op->do_hex) && (0 == op->do_name) &&
            (0 == op->no_inq) && (0 == op->do_brief))
            printf("    %.8s  %.16s  %.4s\n", inq_out.vendor,
                   inq_out.product, inq_out.revision);
    } else
        memset(&inq_out, 0, sizeof(inq_out));

    if (1 == op->do_temperature)
        return fetchTemperature(sg_fd, rsp_buff, SHORT_RESP_LEN, op);

    if (op->do_select) {
        k = sg_ll_log_select(sg_fd, !!(op->do_pcreset), op->do_sp,
                             op->page_control, op->pg_code, op->subpg_code,
                             rsp_buff, ((in_len > 0) ? in_len : 0),
                             1, op->verbose);
        if (k) {
            if (SG_LIB_CAT_NOT_READY == k)
                pr2serr("log_select: device not ready\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
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
        return (k >= 0) ?  k : SG_LIB_CAT_OTHER;
    }
    resp_len = (op->maxlen > 0) ? op->maxlen : MX_ALLOC_LEN;
    res = do_logs(sg_fd, rsp_buff, resp_len, op);
    if (0 == res) {
        pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
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
                dStrHex((const char *)rsp_buff, pg_len + 4,
                        (op->do_hex < 4));
            else
                show_ascii_page(rsp_buff, pg_len + 4, op);
        } else if (op->do_raw)
            dStrRaw((const char *)rsp_buff, pg_len + 4);
        else if (op->do_hex > 1)
            dStrHex((const char *)rsp_buff, pg_len + 4,
                    (2 == op->do_hex) ? 0 : -1);
        else if (pg_len > 1) {
            if (op->do_hex) {
                if (rsp_buff[0] & 0x40)
                    printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, "
                           "page_len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                           !!(rsp_buff[0] & 0x80), pg_len);
                else
                    printf("Log page code=0x%x, DS=%d, SPF=0, page_len=0x%x\n",
                           rsp_buff[0] & 0x3f, !!(rsp_buff[0] & 0x80), pg_len);
                dStrHex((const char *)rsp_buff, pg_len + 4, 1);
            }
            else
                show_ascii_page(rsp_buff, pg_len + 4, op);
        }
    }
    ret = res;

    if (op->do_all && (pg_len > 1)) {
        int my_len = pg_len;
        int spf;
        uint8_t parr[1024];

        spf = !!(rsp_buff[0] & 0x40);
        if (my_len > (int)sizeof(parr)) {
            pr2serr("Unexpectedly large page_len=%d, trim to %d\n", my_len,
                    (int)sizeof(parr));
            my_len = sizeof(parr);
        }
        memcpy(parr, rsp_buff + 4, my_len);
        for (k = 0; k < my_len; ++k) {
            if (0 == op->do_raw)
                printf("\n");
            op->pg_code = parr[k] & 0x3f;
            if (spf)
                op->subpg_code = parr[++k];
            else
                op->subpg_code = NOT_SPG_SUBPG;

            res = do_logs(sg_fd, rsp_buff, resp_len, op);
            if (0 == res) {
                pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
                if ((pg_len + 4) > resp_len) {
                    pr2serr("Only fetched %d bytes of response, truncate "
                            "output\n", resp_len);
                    pg_len = resp_len - 4;
                }
                if (op->do_raw)
                    dStrRaw((const char *)rsp_buff, pg_len + 4);
                else if (op->do_hex > 1)
                    dStrHex((const char *)rsp_buff, pg_len + 4,
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
                    dStrHex((const char *)rsp_buff, pg_len + 4, 1);
                }
                else
                    show_ascii_page(rsp_buff, pg_len + 4, op);
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
    sg_cmds_close_device(sg_fd);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
