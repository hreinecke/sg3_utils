/*
 * Copyright (c) 2004-2023 Douglas Gilbert.
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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pt.h"
#include "sg_pr2serr.h"

/*
 * This program issues SCSI SEND DIAGNOSTIC and RECEIVE DIAGNOSTIC RESULTS
 * commands tailored for SES (enclosure) devices.
 */

static const char * version_str = "2.73 20230306";    /* ses4r04 */

#define MY_NAME "sg_ses"
#define MX_ALLOC_LEN ((64 * 1024) - 4)  /* max allowable for big enclosures */
#define MX_ELEM_HDR 1024
#define REQUEST_SENSE_RESP_SZ 252
#define DATA_IN_OFF 4
#define MIN_MAXLEN 16
#define MIN_DATA_IN_SZ 8192     /* use max(MIN_DATA_IN_SZ, op->maxlen) for
                                 * the size of data_arr */
#define MX_DATA_IN_LINES (16 * 1024)
#define MX_JOIN_ROWS 520        /* element index fields in dpages are only 8
                                 * bit, and index 0xff (255) is sometimes used
                                 * for 'not applicable'. However this limit
                                 * can bypassed with sub-enclosure numbers.
                                 * So try higher figure. */
#define MX_DATA_IN_DESCS 32
#define NUM_ACTIVE_ET_AESP_ARR 32

#define TEMPERAT_OFF 20         /* 8 bits represents -19 C to +235 C */
                                /* value of 0 (would imply -20 C) reserved */

/* Send Diagnostic and Receive Diagnostic Results page codes */
/* Sometimes referred to as "dpage"s in code comments */
#define SUPPORTED_DPC 0x0
#define CONFIGURATION_DPC 0x1
#define ENC_CONTROL_DPC 0x2
#define ENC_STATUS_DPC 0x2
#define HELP_TEXT_DPC 0x3
#define STRING_DPC 0x4
#define THRESHOLD_DPC 0x5
#define ARRAY_CONTROL_DPC 0x6   /* obsolete, last seen ses-r08b.pdf */
#define ARRAY_STATUS_DPC 0x6    /* obsolete */
#define ELEM_DESC_DPC 0x7       /* names of elements in ENC_STATUS_DPC */
#define SHORT_ENC_STATUS_DPC 0x8
#define ENC_BUSY_DPC 0x9
#define ADD_ELEM_STATUS_DPC 0xa /* Additional Element Status dpage code */
#define SUBENC_HELP_TEXT_DPC 0xb
#define SUBENC_STRING_DPC 0xc
#define SUPPORTED_SES_DPC 0xd   /* should contain 0x1 <= dpc <= 0x2f */
#define DOWNLOAD_MICROCODE_DPC 0xe
#define SUBENC_NICKNAME_DPC 0xf
#define ALL_DPC 0xff

/* Element Type codes */
#define UNSPECIFIED_ETC 0x0
#define DEVICE_ETC 0x1
#define POWER_SUPPLY_ETC 0x2
#define COOLING_ETC 0x3
#define TEMPERATURE_ETC 0x4
#define DOOR_ETC 0x5    /* prior to ses3r05 was DOOR_LOCK_ETC */
#define AUD_ALARM_ETC 0x6
#define ENC_SCELECTR_ETC 0x7 /* Enclosure services controller electronics */
#define SCC_CELECTR_ETC 0x8  /* SCC: SCSI Controller Commands (e.g. RAID
                              * controller). SCC Controller Elecronics */
#define NV_CACHE_ETC 0x9
#define INV_OP_REASON_ETC 0xa
#define UI_POWER_SUPPLY_ETC 0xb
#define DISPLAY_ETC 0xc
#define KEY_PAD_ETC 0xd
#define ENCLOSURE_ETC 0xe
#define SCSI_PORT_TRAN_ETC 0xf
#define LANGUAGE_ETC 0x10
#define COMM_PORT_ETC 0x11
#define VOLT_SENSOR_ETC 0x12
#define CURR_SENSOR_ETC 0x13
#define SCSI_TPORT_ETC 0x14
#define SCSI_IPORT_ETC 0x15
#define SIMPLE_SUBENC_ETC 0x16
#define ARRAY_DEV_ETC 0x17
#define SAS_EXPANDER_ETC 0x18
#define SAS_CONNECTOR_ETC 0x19
#define LAST_ETC SAS_CONNECTOR_ETC      /* adjust as necessary */

#define TPROTO_PCIE_PS_NVME 1   /* NVMe regarded as subset of PCIe */
#define NUM_ETC (LAST_ETC + 1)

#define DEF_CLEAR_VAL 0
#define DEF_SET_VAL 1

#define SG_SES_CALL_ENUMERATE 99999


struct element_type_t {
    int elem_type_code;
    const char * abbrev;
    const char * desc;
};

#define CGS_CL_ARR_MAX_SZ 8
#define CGS_STR_MAX_SZ 80

enum cgs_select_t {CLEAR_OPT, GET_OPT, SET_OPT};

struct cgs_cl_t {
    enum cgs_select_t cgs_sel;
    bool last_cs;       /* true only for last --clear= or --set= */
    char cgs_str[CGS_STR_MAX_SZ];
};

struct opts_t {
    bool do_all;        /* one or more --all options */
    bool byte1_given;   /* true if -b B1 or --byte1=B1 given */
    bool do_control;    /* want to write to DEVICE */
    bool data_or_inhex;
    bool do_json;       /* --json[=JO] option given or implied */
    bool do_list;
    bool do_status;     /* want to read from DEVICE (or user data) */
    bool eiioe_auto;    /* Element Index Includes Overall (status) Element */
    bool eiioe_force;
    bool ind_given;     /* '--index=...' or '-I ...' */
    bool many_dpages;   /* user supplied data has more than one dpage */
    bool mask_ign;      /* element read-mask-modify-write actions */
    bool no_config;     /* -F  (do not depend on config dpage) */
    bool o_readonly;
    bool page_code_given;       /* or suitable abbreviation */
    bool quiet;         /* exit status unaltered by --quiet */
    bool seid_given;
    bool verbose_given;
    bool version_given;
    bool do_warn;
    int byte1;          /* (origin 0 so second byte) in Control dpage */
    int dev_slot_num;
    int do_filter;      /* count of how many times --filter given */
    int do_help;        /* count of how many times --help given */
    int do_hex;         /* count of how many times --hex given */
    int do_hex_inner;   /* when --hex and --inner-hex are both given */
    int do_join;        /* relational join of Enclosure status, Element
                           descriptor and Additional element status dpages.
                           Use twice to add Threshold in dpage to join. */
    int do_raw;
    int enumerate;      /* -e */
    int h2s_oformat;    /* oformat argument for hex2str() */
    int ind_th;    /* type header index, set by build_type_desc_hdr_arr() */
    int ind_indiv;      /* individual element index; -1 for overall */
    int ind_indiv_last; /* if > ind_indiv then [ind_indiv..ind_indiv_last] */
    int ind_et_inst;    /* ETs can have multiple type header instances */
    int inner_hex;      /* -i, incremented if multiple */
    int maxlen;         /* -m LEN */
    int seid;
    int page_code;      /* recognised abbreviations converted to dpage num */
    int verbose;
    int num_cgs;        /* number of --clear-, --get= and --set= options */
    int mx_arr_len;     /* allocated size of data_arr */
    int arr_len;        /* valid bytes in data_arr */
    uint8_t * data_arr;
    uint8_t * free_data_arr;
    const char * desc_name;
    const char * dev_name;
    const struct element_type_t * ind_etp;
    const char * index_str;
    const char * nickname_str;
    const char * json_arg;
    const char * js_file;
    sgj_state json_st;
    struct cgs_cl_t cgs_cl_arr[CGS_CL_ARR_MAX_SZ];
    uint8_t sas_addr[8];  /* Big endian byte sequence */
    char tmp_arr[8];
};

struct diag_page_code {
    int page_code;
    const char * desc;
};

struct diag_page_controllable {
    int page_code;
    bool has_controllable_variant;
};

struct diag_page_abbrev {
    const char * abbrev;
    int page_code;
};

/* The Configuration diagnostic page contains one or more of these. The
 * elements of the Enclosure Control/Status and Threshold In/ Out page follow
 * this format. The additional element status page is closely related to
 * this format (with some element types and all overall elements excluded). */
struct type_desc_hdr_t {
    uint8_t etype;              /* element type code (0: unspecified) */
    uint8_t num_elements;       /* number of possible elements, excluding
                                 * overall element */
    uint8_t se_id;              /* subenclosure id (0 for primary enclosure) */
    uint8_t txt_len;            /* type descriptor text length; (unused) */
};

/* A SQL-like join of the Enclosure Status, Threshold In and Additional
 * Element Status pages based of the format indicated in the Configuration
 * page. Note that the array of these struct instances is built such that
 * the array index is equal to the 'ei_ioe' (element index that includes
 * overall elements). */
struct join_row_t {  /* this struct is 72 bytes long on Intel "64" bit arch */
    int th_i;           /* type header index (origin 0) */
    int indiv_i;        /* individual (element) index, -1 for overall
                         * instance, otherwise origin 0 */
    uint8_t etype;      /* element type */
    uint8_t se_id;      /* subenclosure id (0 for primary enclosure) */
    int ei_eoe;         /* element index referring to Enclosure status dpage
                         * descriptors, origin 0 and excludes overall
                         * elements, -1 for not applicable. As defined by
                         * SES-2 standard for the AES descriptor, EIP=1 */
    int ei_aess;        /* subset of ei_eoe that only includes elements of
                         * these types:  excludes DEVICE_ETC, ARRAY_DEV_ETC,
                         * SAS_EXPANDER_ETC, SCSI_IPORT_ETC, SCSI_TPORT_ETC
                         * and ENC_SCELECTR_ETC. -1 for not applicable */
    /* following point into Element Descriptor, Enclosure Status, Threshold
     * In and Additional element status diagnostic pages. enc_statp only
     * NULL beyond last, other pointers can be NULL . */
    const uint8_t * elem_descp;
    uint8_t * enc_statp;  /* NULL indicates past last */
    uint8_t * thresh_inp;
    const uint8_t * ae_statp;
    int dev_slot_num;           /* if not available, set to -1 */
    uint8_t sas_addr[8];  /* big endian, if not available, set to 0 */
};

enum fj_select_t {FJ_IOE, FJ_EOE, FJ_AESS, FJ_SAS_CON};

/* Instance ('tes' in main() ) holds a type_desc_hdr_t array potentially with
   the matching join array if present. */
struct th_es_t {
    const struct type_desc_hdr_t * th_base;
    int num_ths;        /* items in array pointed to by th_base */
    struct join_row_t * j_base;
    int num_j_rows;
    int num_j_eoe;
};

/* Representation of <acronym>[=<value>] or
 * <start_byte>:<start_bit>[:<num_bits>][=<value>]. Associated with
 * --clear=, --get= or --set= option. */
struct tuple_acronym_val {
    const char * acron;
    const char * val_str;
    enum cgs_select_t cgs_sel;  /* indicates --clear=, --get= or --set= */
    int start_byte;     /* -1 indicates no start_byte */
    int start_bit;
    int num_bits;
    int64_t val;
};

/* Mapping from <acronym> to <start_byte>:<start_bit>:<num_bits> for a
 * given element type. Table of known acronyms made from these elements. */
struct acronym2tuple {
    const char * acron; /* element name or acronym, NULL for past end */
    int etype;          /* -1 for all element types */
    int start_byte;     /* origin 0, normally 0 to 3 */
    int start_bit;      /* 7 (MSbit or leftmost in SES drafts) to 0 (LSbit) */
    int num_bits;       /* usually 1, maximum is 64 */
    const char * info;  /* optional, set to NULL if not used */
};

/* Structure for holding (sub-)enclosure information found in the
 * Configuration diagnostic page. */
struct enclosure_info {
    int have_info;
    int rel_esp_id;     /* relative enclosure services process id (origin 1) */
    int num_esp;        /* number of enclosure services processes */
    uint8_t enc_log_id[8];        /* 8 byte NAA */
    uint8_t enc_vendor_id[8];     /* may differ from INQUIRY response */
    uint8_t product_id[16];       /* may differ from INQUIRY response */
    uint8_t product_rev_level[4]; /* may differ from INQUIRY response */
};

/* When --status is given with --data= the file contents may contain more
 * than one dpage to be decoded. */
struct data_in_desc_t {
    bool in_use;
    int page_code;
    int offset;         /* byte offset from op->data_arr + DATA_IN_OFF */
    int dp_len;         /* byte length of this diagnostic page */
};


/* Join array has four "element index"ing strategies:
 *   [1] based on all descriptors in the Enclosure Status (ES) dpage
 *   [2] based on the non-overall descriptors in the ES dpage
 *   [3] based on the non-overall descriptors of these element types
 *       in the ES dpage: DEVICE_ETC, ARRAY_DEV_ETC, SAS_EXPANDER_ETC,
 *       SCSI_IPORT_ETC, SCSI_TPORT_ETC and ENC_SCELECTR_ETC.
 *   [4] based on the non-overall descriptors of the SAS_CONNECTOR_ETC
 *       element type
 *
 * The indexes are all origin 0 with the maximum index being one less then
 * the number of status descriptors in the ES dpage. Table of supported
 * permutations follows:
 *
 *  ==========|===============================================================
 *  Algorithm |              Indexes                  |    Notes
 *            |Element|Connector element|Other element|
 *  ==========|=======|=================|=============|=======================
 *   [A]      |  [2]  |       [4]       |    [3]      | SES-2, OR
 *   [A]      |  [2]  |       [4]       |    [3]      | SES-3,EIIOE=0
 *  ----------|-------|-----------------|-------------|-----------------------
 *   [B]      |  [1]  |       [1]       |    [1]      | SES-3, EIIOE=1
 *  ----------|-------|-----------------|-------------|-----------------------
 *   [C]      |  [2]  |       [2]       |    [2]      | SES-3, EIIOE=2
 *  ----------|-------|-----------------|-------------|-----------------------
 *   [D]      |  [2]  |       [1]       |    [1]      | SES-3, EIIOE=3
 *  ----------|-------|-----------------|-------------|-----------------------
 *   [E]      |  [1]  |       [4]       |    [3]      | EIIOE=0 and
 *            |       |                 |             | --eiioe=force, OR
 *   [E]      |  [1]  |       [4]       |    [3]      | {HP JBOD} EIIOE=0 and
 *            |       |                 |             | --eiioe=auto and
 *            |       |                 |             | AES[desc_0].ei==1 .
 *  ----------|-------|-----------------|-------------|-----------------------
 *   [F]      | [2->3]|       [4]       |    [3]      | "broken_ei" when any
 *            |       |                 |             | of AES[*].ei invalid
 *            |       |                 |             | using strategy [2]
 *  ----------|-------|-----------------|-------------|-----------------------
 *   [Z]      |  -    |       [4]       |    [3]      | EIP=0, implicit
 *            |       |                 |             | element index of [3]
 *  ==========================================================================
 *
 *
 */
static struct join_row_t join_arr[MX_JOIN_ROWS];
static struct join_row_t * join_arr_lastp = join_arr + MX_JOIN_ROWS - 1;
static bool join_done = false;

static struct type_desc_hdr_t type_desc_hdr_arr[MX_ELEM_HDR];
static int type_desc_hdr_count = 0;
static uint8_t * config_dp_resp = NULL;
static uint8_t * free_config_dp_resp = NULL;
static int config_dp_resp_len;

static struct data_in_desc_t data_in_desc_arr[MX_DATA_IN_DESCS];

/* Large buffers on heap, aligned to page size and zeroed */
static uint8_t * enc_stat_rsp;
static uint8_t * elem_desc_rsp;
static uint8_t * add_elem_rsp;
static uint8_t * threshold_rsp;

static unsigned enc_stat_rsp_sz;
static unsigned elem_desc_rsp_sz;
static unsigned add_elem_rsp_sz;
static unsigned threshold_rsp_sz;

static int enc_stat_rsp_len;
static int elem_desc_rsp_len;
static int add_elem_rsp_len;
static int threshold_rsp_len;

/* The '_sn' suffix is for snake format used in JSON names */
static const char * const not_avail = "not available";
static const char * const not_rep = "not reported";
static const char * const noss_s = "number of secondary subenclosures";
static const char * const gc_s = "generation code";
static const char * const et_s = "Element type";
static const char * const et_sn = "element_type";
static const char * const pc_sn = "page_code";
static const char * const dp_s = "diagnostic page";
static const char * const dp_sn = "diagnostic_page";
static const char * const si_s = "subenclosure identifier";
static const char * const si_ss = "subenclosure id";
static const char * const si_sn = "subenclosure_identifier";
static const char * const es_s = "enclosure status";
static const char * const peli = "Primary enclosure logical identifier";
static const char * const soec =
                 "  <<state of enclosure changed, please try again>>";
static const char * const vs_s = "Vendor specific";
static const char * const rsv_s = "reserved";
static const char * const in_hex_sn = "in_hex";
static const char * const od_s = "Overall descriptor";
static const char * const od_sn = "overall_descriptor";
static const char * const rts_s = "response too short";
static const char * const hct_sn = "high_critical_threshold";
static const char * const hwt_sn = "high_warning_threshold";
static const char * const lwt_sn = "low_warning_threshold";
static const char * const lct_sn = "low_critical_threshold";
static const char * const sdl_s = "Status descriptor list";
static const char * const sdl_sn = "status_descriptor_list";
static const char * const aes_dp =
                "Additional element status diagnostic page";
static const char * const aesd_s = "Additional element status descriptor";
static const char * const aesd_sn = "additional_element_status_descriptor";
static const char * const dwuti = "decoded _without_ using type info";
static const char * const oohm = ">>> Out of heap (memory)";
static const char * const isel_sn = "individual_status_element_list";


/* Diagnostic page names, control and/or status (in and/or out) */
static const struct diag_page_code dpc_arr[] = {
    {SUPPORTED_DPC, "Supported Diagnostic Pages"},  /* 0 */
    {CONFIGURATION_DPC, "Configuration (SES)"},
    {ENC_STATUS_DPC, "Enclosure Status/Control (SES)"},
    {HELP_TEXT_DPC, "Help Text (SES)"},
    {STRING_DPC, "String In/Out (SES)"},
    {THRESHOLD_DPC, "Threshold In/Out (SES)"},
    {ARRAY_STATUS_DPC, "Array Status/Control (SES, obsolete)"},
    {ELEM_DESC_DPC, "Element Descriptor (SES)"},
    {SHORT_ENC_STATUS_DPC, "Short Enclosure Status (SES)"},  /* 8 */
    {ENC_BUSY_DPC, "Enclosure Busy (SES-2)"},
    {ADD_ELEM_STATUS_DPC, "Additional Element Status (SES-2)"},
    {SUBENC_HELP_TEXT_DPC, "Subenclosure Help Text (SES-2)"},
    {SUBENC_STRING_DPC, "Subenclosure String In/Out (SES-2)"},
    {SUPPORTED_SES_DPC, "Supported SES Diagnostic Pages (SES-2)"},
    {DOWNLOAD_MICROCODE_DPC, "Download Microcode (SES-2)"},
    {SUBENC_NICKNAME_DPC, "Subenclosure Nickname (SES-2)"},
    {0x3f, "Protocol Specific (SAS transport)"},
    {0x40, "Translate Address (SBC)"},
    {0x41, "Device Status (SBC)"},
    {0x42, "Rebuild Assist (SBC)"},     /* sbc3r31 */
    {ALL_DPC, ">> All available SES diagnostic pages (sg_ses)"},
    {-1, NULL},
};

/* Diagnostic page names, for status (or in) pages */
static const struct diag_page_code in_dpc_arr[] = {
    {SUPPORTED_DPC, "Supported Diagnostic Pages"},  /* 0 */
    {CONFIGURATION_DPC, "Configuration (SES)"},
    {ENC_STATUS_DPC, "Enclosure Status (SES)"},
    {HELP_TEXT_DPC, "Help Text (SES)"},
    {STRING_DPC, "String In (SES)"},
    {THRESHOLD_DPC, "Threshold In (SES)"},
    {ARRAY_STATUS_DPC, "Array Status (SES, obsolete)"},
    {ELEM_DESC_DPC, "Element Descriptor (SES)"},
    {SHORT_ENC_STATUS_DPC, "Short Enclosure Status (SES)"},  /* 8 */
    {ENC_BUSY_DPC, "Enclosure Busy (SES-2)"},
    {ADD_ELEM_STATUS_DPC, "Additional Element Status (SES-2)"},
    {SUBENC_HELP_TEXT_DPC, "Subenclosure Help Text (SES-2)"},
    {SUBENC_STRING_DPC, "Subenclosure String In (SES-2)"},
    {SUPPORTED_SES_DPC, "Supported SES Diagnostic Pages (SES-2)"},
    {DOWNLOAD_MICROCODE_DPC, "Download Microcode (SES-2)"},
    {SUBENC_NICKNAME_DPC, "Subenclosure Nickname (SES-2)"},
    {0x3f, "Protocol Specific (SAS transport)"},
    {0x40, "Translate Address (SBC)"},
    {0x41, "Device Status (SBC)"},
    {0x42, "Rebuild Assist Input (SBC)"},
    {-1, NULL},
};

/* Diagnostic page names, for control (or out) pages */
static const struct diag_page_code out_dpc_arr[] = {
    {SUPPORTED_DPC, "?? [Supported Diagnostic Pages]"},  /* 0 */
    {CONFIGURATION_DPC, "?? [Configuration (SES)]"},
    {ENC_CONTROL_DPC, "Enclosure Control (SES)"},
    {HELP_TEXT_DPC, "Help Text (SES)"},
    {STRING_DPC, "String Out (SES)"},
    {THRESHOLD_DPC, "Threshold Out (SES)"},
    {ARRAY_CONTROL_DPC, "Array Control (SES, obsolete)"},
    {ELEM_DESC_DPC, "?? [Element Descriptor (SES)]"},
    {SHORT_ENC_STATUS_DPC, "?? [Short Enclosure Status (SES)]"},  /* 8 */
    {ENC_BUSY_DPC, "?? [Enclosure Busy (SES-2)]"},
    {ADD_ELEM_STATUS_DPC, "?? [Additional Element Status (SES-2)]"},
    {SUBENC_HELP_TEXT_DPC, "?? [Subenclosure Help Text (SES-2)]"},
    {SUBENC_STRING_DPC, "Subenclosure String Out (SES-2)"},
    {SUPPORTED_SES_DPC, "?? [Supported SES Diagnostic Pages (SES-2)]"},
    {DOWNLOAD_MICROCODE_DPC, "Download Microcode (SES-2)"},
    {SUBENC_NICKNAME_DPC, "Subenclosure Nickname (SES-2)"},
    {0x3f, "Protocol Specific (SAS transport)"},
    {0x40, "Translate Address (SBC)"},
    {0x41, "Device Status (SBC)"},
    {0x42, "Rebuild Assist Output (SBC)"},
    {-1, NULL},
};

/* Diagnostic page that have control variant have true in second field */
static const struct diag_page_controllable dpctl_arr[] = {
    {SUPPORTED_DPC, false},  /* 0 */
    {CONFIGURATION_DPC, false},
    {ENC_STATUS_DPC, true},
    {HELP_TEXT_DPC, false},
    {STRING_DPC, true},
    {THRESHOLD_DPC, true},
    {ARRAY_STATUS_DPC, true},
    {ELEM_DESC_DPC, false},
    {SHORT_ENC_STATUS_DPC, false},  /* 8 */
    {ENC_BUSY_DPC, false},
    {ADD_ELEM_STATUS_DPC, false},
    {SUBENC_HELP_TEXT_DPC, false},
    {SUBENC_STRING_DPC, true},
    {SUPPORTED_SES_DPC, false},
    {DOWNLOAD_MICROCODE_DPC, true},
    {SUBENC_NICKNAME_DPC, true},
    {ALL_DPC, false},
    {-1, false},
};

static const struct diag_page_abbrev dp_abbrev[] = {
    {"ac", ARRAY_CONTROL_DPC},
    {"aes", ADD_ELEM_STATUS_DPC},
    {"all", ALL_DPC},
    {"as", ARRAY_STATUS_DPC},
    {"cf", CONFIGURATION_DPC},
    {"dm", DOWNLOAD_MICROCODE_DPC},
    {"eb", ENC_BUSY_DPC},
    {"ec", ENC_CONTROL_DPC},
    {"ed", ELEM_DESC_DPC},
    {"es", ENC_STATUS_DPC},
    {"ht", HELP_TEXT_DPC},
    {"sdp", SUPPORTED_DPC},
    {"ses", SHORT_ENC_STATUS_DPC},
    {"sht", SUBENC_HELP_TEXT_DPC},
    {"snic", SUBENC_NICKNAME_DPC},
    {"ssp", SUPPORTED_SES_DPC},
    {"sstr", SUBENC_STRING_DPC},
    {"str", STRING_DPC},
    {"th", THRESHOLD_DPC},
    {NULL, -999},
};

/* Names of element types used by the Enclosure Control/Status diagnostic
 * page. */
static const struct element_type_t element_type_arr[] = {
    {UNSPECIFIED_ETC, "un", "Unspecified"},
    {DEVICE_ETC, "dev", "Device slot"},
    {POWER_SUPPLY_ETC, "ps", "Power supply"},
    {COOLING_ETC, "coo", "Cooling"},
    {TEMPERATURE_ETC, "ts", "Temperature sensor"},
    {DOOR_ETC, "do", "Door"},   /* prior to ses3r05 was 'dl' (for Door Lock)
                                   but the "Lock" has been dropped */
    {AUD_ALARM_ETC, "aa", "Audible alarm"},
    {ENC_SCELECTR_ETC, "esc", "Enclosure services controller electronics"},
    {SCC_CELECTR_ETC, "sce", "SCC controller electronics"},
    {NV_CACHE_ETC, "nc", "Nonvolatile cache"},
    {INV_OP_REASON_ETC, "ior", "Invalid operation reason"},
    {UI_POWER_SUPPLY_ETC, "ups", "Uninterruptible power supply"},
    {DISPLAY_ETC, "dis", "Display"},
    {KEY_PAD_ETC, "kpe", "Key pad entry"},
    {ENCLOSURE_ETC, "enc", "Enclosure"},
    {SCSI_PORT_TRAN_ETC, "sp", "SCSI port/transceiver"},
    {LANGUAGE_ETC, "lan", "Language"},
    {COMM_PORT_ETC, "cp", "Communication port"},
    {VOLT_SENSOR_ETC, "vs", "Voltage sensor"},
    {CURR_SENSOR_ETC, "cs", "Current sensor"},
    {SCSI_TPORT_ETC, "stp", "SCSI target port"},
    {SCSI_IPORT_ETC, "sip", "SCSI initiator port"},
    {SIMPLE_SUBENC_ETC, "ss", "Simple subenclosure"},
    {ARRAY_DEV_ETC, "arr", "Array device slot"},
    {SAS_EXPANDER_ETC, "sse", "SAS expander"},
    {SAS_CONNECTOR_ETC, "ssc", "SAS connector"},
    {-1, NULL, NULL},
};

static struct element_type_t element_type_by_code =
    {0, NULL, "element type code form"};

/* Many control element names below have "RQST" in front in drafts.
   These are for the Enclosure Control/Status diagnostic page */
static const struct acronym2tuple ecs_a2t_arr[] = {
    /* acron   element_type  start_byte  start_bit  num_bits */
    {"ac_fail", UI_POWER_SUPPLY_ETC, 2, 4, 1, NULL},
    {"ac_hi", UI_POWER_SUPPLY_ETC, 2, 6, 1, NULL},
    {"ac_lo", UI_POWER_SUPPLY_ETC, 2, 7, 1, NULL},
    {"ac_qual", UI_POWER_SUPPLY_ETC, 2, 5, 1, NULL},
    {"active", DEVICE_ETC, 2, 7, 1, NULL},     /* for control only */
    {"active", ARRAY_DEV_ETC, 2, 7, 1, NULL},  /* for control only */
    {"batt_fail", UI_POWER_SUPPLY_ETC, 3, 1, 1, NULL},
    {"bpf", UI_POWER_SUPPLY_ETC, 3, 0, 1, NULL},
    {"bypa", DEVICE_ETC, 3, 3, 1, "bypass port A"},
    {"bypa", ARRAY_DEV_ETC, 3, 3, 1, "bypass port A"},
    {"bypb", DEVICE_ETC, 3, 2, 1, "bypass port B"},
    {"bypb", ARRAY_DEV_ETC, 3, 2, 1, "bypass port B"},
    {"conscheck", ARRAY_DEV_ETC, 1, 4, 1, "consistency check"},
    {"ctr_link", SAS_CONNECTOR_ETC, 2, 7, 8, "connector physical link"},
    {"ctr_type", SAS_CONNECTOR_ETC, 1, 6, 7, "connector type"},
    {"current", CURR_SENSOR_ETC, 2, 7, 16, "current in centiamps"},
    {"dc_fail", UI_POWER_SUPPLY_ETC, 2, 3, 1, NULL},
    {"disable", -1, 0, 5, 1, NULL},        /* -1 is for all element types */
    {"disable_elm", SCSI_PORT_TRAN_ETC, 3, 4, 1, "disable port/transceiver"},
    {"disable_elm", COMM_PORT_ETC, 3, 0, 1, "disable communication port"},
    {"devoff", DEVICE_ETC, 3, 4, 1, NULL},     /* device off */
    {"devoff", ARRAY_DEV_ETC, 3, 4, 1, NULL},
    {"disp_mode", DISPLAY_ETC, 1, 1, 2, NULL},
    {"disp_char", DISPLAY_ETC, 2, 7, 16, NULL},
    {"dnr", ARRAY_DEV_ETC, 2, 6, 1, "do not remove"},
    {"dnr", COOLING_ETC, 1, 6, 1, "do not remove"},
    {"dnr", DEVICE_ETC, 2, 6, 1, "do not remove"},
    {"dnr", ENC_SCELECTR_ETC, 1, 5, 1, "do not remove"},
    {"dnr", POWER_SUPPLY_ETC, 1, 6, 1, "do not remove"},
    {"dnr", UI_POWER_SUPPLY_ETC, 3, 3, 1, "do not remove"},
    {"enable", SCSI_IPORT_ETC, 3, 0, 1, NULL},
    {"enable", SCSI_TPORT_ETC, 3, 0, 1, NULL},
    {"fail", AUD_ALARM_ETC, 1, 6, 1, NULL},
    {"fail", COMM_PORT_ETC, 1, 7, 1, NULL},
    {"fail", COOLING_ETC, 3, 6, 1, NULL},
    {"fail", CURR_SENSOR_ETC, 3, 6, 1, NULL},
    {"fail", DISPLAY_ETC, 1, 6, 1, NULL},
    {"fail", DOOR_ETC, 1, 6, 1, NULL},
    {"fail", ENC_SCELECTR_ETC, 1, 6, 1, NULL},
    {"fail", KEY_PAD_ETC, 1, 6, 1, NULL},
    {"fail", NV_CACHE_ETC, 3, 6, 1, NULL},
    {"fail", POWER_SUPPLY_ETC, 3, 6, 1, NULL},
    {"fail", SAS_CONNECTOR_ETC, 3, 6, 1, NULL},
    {"fail", SAS_EXPANDER_ETC, 1, 6, 1, NULL},
    {"fail", SCC_CELECTR_ETC, 3, 6, 1, NULL},
    {"fail", SCSI_IPORT_ETC, 1, 6, 1, NULL},
    {"fail", SCSI_PORT_TRAN_ETC, 1, 6, 1, NULL},
    {"fail", SCSI_TPORT_ETC, 1, 6, 1, NULL},
    {"fail", SIMPLE_SUBENC_ETC, 1, 6, 1, NULL},
    {"fail", TEMPERATURE_ETC, 3, 6, 1, NULL},
    {"fail", UI_POWER_SUPPLY_ETC, 3, 6, 1, NULL},
    {"fail", VOLT_SENSOR_ETC, 1, 6, 1, NULL},
    {"failure_ind", ENCLOSURE_ETC, 2, 1, 1, NULL},
    {"failure", ENCLOSURE_ETC, 3, 1, 1, NULL},
    {"fault", DEVICE_ETC, 3, 5, 1, NULL},
    {"fault", ARRAY_DEV_ETC, 3, 5, 1, NULL},
    {"hotspare", ARRAY_DEV_ETC, 1, 5, 1, NULL},
    {"hotswap", COOLING_ETC, 3, 7, 1, NULL},
    {"hotswap", ENC_SCELECTR_ETC, 3, 7, 1, NULL},       /* status only */
    {"hw_reset", ENC_SCELECTR_ETC, 1, 2, 1, "hardware reset"}, /* 18-047r1 */
    {"ident", DEVICE_ETC, 2, 1, 1, "flash LED"},
    {"ident", ARRAY_DEV_ETC, 2, 1, 1, "flash LED"},
    {"ident", POWER_SUPPLY_ETC, 1, 7, 1, "flash LED"},
    {"ident", COMM_PORT_ETC, 1, 7, 1, "flash LED"},
    {"ident", COOLING_ETC, 1, 7, 1, "flash LED"},
    {"ident", CURR_SENSOR_ETC, 1, 7, 1, "flash LED"},
    {"ident", DISPLAY_ETC, 1, 7, 1, "flash LED"},
    {"ident", DOOR_ETC, 1, 7, 1, "flash LED"},
    {"ident", ENC_SCELECTR_ETC, 1, 7, 1, "flash LED"},
    {"ident", ENCLOSURE_ETC, 1, 7, 1, "flash LED"},
    {"ident", KEY_PAD_ETC, 1, 7, 1, "flash LED"},
    {"ident", LANGUAGE_ETC, 1, 7, 1, "flash LED"},
    {"ident", AUD_ALARM_ETC, 1, 7, 1, NULL},
    {"ident", NV_CACHE_ETC, 1, 7, 1, "flash LED"},
    {"ident", SAS_CONNECTOR_ETC, 1, 7, 1, "flash LED"},
    {"ident", SAS_EXPANDER_ETC, 1, 7, 1, "flash LED"},
    {"ident", SCC_CELECTR_ETC, 1, 7, 1, "flash LED"},
    {"ident", SCSI_IPORT_ETC, 1, 7, 1, "flash LED"},
    {"ident", SCSI_PORT_TRAN_ETC, 1, 7, 1, "flash LED"},
    {"ident", SCSI_TPORT_ETC, 1, 7, 1, "flash LED"},
    {"ident", SIMPLE_SUBENC_ETC, 1, 7, 1, "flash LED"},
    {"ident", TEMPERATURE_ETC, 1, 7, 1, "flash LED"},
    {"ident", UI_POWER_SUPPLY_ETC, 3, 7, 1, "flash LED"},
    {"ident", VOLT_SENSOR_ETC, 1, 7, 1, "flash LED"},
    {"incritarray", ARRAY_DEV_ETC, 1, 3, 1, NULL},
    {"infailedarray", ARRAY_DEV_ETC, 1, 2, 1, NULL},
    {"info", AUD_ALARM_ETC, 3, 3, 1, "emits warning tone when set"},
    {"insert", DEVICE_ETC, 2, 3, 1, NULL},
    {"insert", ARRAY_DEV_ETC, 2, 3, 1, NULL},
    {"intf_fail", UI_POWER_SUPPLY_ETC, 2, 0, 1, NULL},
    {"language", LANGUAGE_ETC, 2, 7, 16, "language code"},
    {"locate", DEVICE_ETC, 2, 1, 1, "flash LED"},
    {"locate", ARRAY_DEV_ETC, 2, 1, 1, "flash LED"},
    {"locate", POWER_SUPPLY_ETC, 1, 7, 1, "flash LED"},
    {"locate", COMM_PORT_ETC, 1, 7, 1, "flash LED"},
    {"locate", COOLING_ETC, 1, 7, 1, "flash LED"},
    {"locate", CURR_SENSOR_ETC, 1, 7, 1, "flash LED"},
    {"locate", DISPLAY_ETC, 1, 7, 1, "flash LED"},
    {"locate", DOOR_ETC, 1, 7, 1, "flash LED"},
    {"locate", ENC_SCELECTR_ETC, 1, 7, 1, "flash LED"},
    {"locate", ENCLOSURE_ETC, 1, 7, 1, "flash LED"},
    {"locate", KEY_PAD_ETC, 1, 7, 1, "flash LED"},
    {"locate", LANGUAGE_ETC, 1, 7, 1, "flash LED"},
    {"locate", AUD_ALARM_ETC, 1, 7, 1, NULL},
    {"locate", NV_CACHE_ETC, 1, 7, 1, "flash LED"},
    {"locate", SAS_CONNECTOR_ETC, 1, 7, 1, "flash LED"},
    {"locate", SAS_EXPANDER_ETC, 1, 7, 1, "flash LED"},
    {"locate", SCC_CELECTR_ETC, 1, 7, 1, "flash LED"},
    {"locate", SCSI_IPORT_ETC, 1, 7, 1, "flash LED"},
    {"locate", SCSI_PORT_TRAN_ETC, 1, 7, 1, "flash LED"},
    {"locate", SCSI_TPORT_ETC, 1, 7, 1, "flash LED"},
    {"locate", SIMPLE_SUBENC_ETC, 1, 7, 1, "flash LED"},
    {"locate", TEMPERATURE_ETC, 1, 7, 1, "flash LED"},
    {"locate", UI_POWER_SUPPLY_ETC, 3, 7, 1, "flash LED"},
    {"locate", VOLT_SENSOR_ETC, 1, 7, 1, "flash LED"},
    {"lol", SCSI_PORT_TRAN_ETC, 3, 1, 1, "Loss of Link"},
    {"mated", SAS_CONNECTOR_ETC, 3, 7, 1, NULL},
    {"missing", DEVICE_ETC, 2, 4, 1, NULL},
    {"missing", ARRAY_DEV_ETC, 2, 4, 1, NULL},
    {"mute", AUD_ALARM_ETC, 3, 6, 1, "control only: mute the alarm"},
    {"muted", AUD_ALARM_ETC, 3, 6, 1, "status only: alarm is muted"},
    {"off", POWER_SUPPLY_ETC, 3, 4, 1, "Not providing power"},
    {"off", COOLING_ETC, 3, 4, 1, "Not providing cooling"},
    {"offset_temp", TEMPERATURE_ETC, 1, 5, 6, "Offset for reference "
     "temperature"},
    {"ok", ARRAY_DEV_ETC, 1, 7, 1, NULL},
    {"on", COOLING_ETC, 3, 5, 1, NULL},
    {"on", POWER_SUPPLY_ETC, 3, 5, 1, "0: turn (remain) off; 1: turn on"},
    {"open", DOOR_ETC, 3, 1, 1, NULL},
    {"overcurrent", CURR_SENSOR_ETC, 1, 1, 1, "overcurrent"},
    {"overcurrent", POWER_SUPPLY_ETC, 2, 1, 1, "DC overcurrent"},
    {"overcurrent", SAS_CONNECTOR_ETC, 3, 5, 1, NULL},  /* added ses3r07 */
    {"overcurrent_warn", CURR_SENSOR_ETC, 1, 3, 1, "overcurrent warning"},
    {"overtemp_fail", TEMPERATURE_ETC, 3, 3, 1, "Overtemperature failure"},
    {"overtemp_warn", TEMPERATURE_ETC, 3, 2, 1, "Overtemperature warning"},
    {"overvoltage", POWER_SUPPLY_ETC, 2, 3, 1, "DC overvoltage"},
    {"overvoltage", VOLT_SENSOR_ETC, 1, 1, 1, "overvoltage"},
    {"overvoltage_warn", POWER_SUPPLY_ETC, 1, 3, 1, "DC overvoltage warning"},
    {"pow_cycle", ENCLOSURE_ETC, 2, 7, 2,
     "0: no; 1: start in pow_c_delay minutes; 2: cancel"},
    {"pow_c_delay", ENCLOSURE_ETC, 2, 5, 6,
     "delay in minutes before starting power cycle (max: 60)"},
    {"pow_c_duration", ENCLOSURE_ETC, 3, 7, 6,
     "0: power off, restore within 1 minute; <=60: restore within that many "
     "minutes; 63: power off, wait for manual power on"},
     /* slightly different in Enclosure status element */
    {"pow_c_time", ENCLOSURE_ETC, 2, 7, 6,
     "time in minutes remaining until starting power cycle; 0: not "
     "scheduled; <=60: scheduled in that many minutes; 63: in zero minutes"},
    {"prdfail", -1, 0, 6, 1, "predict failure"},
    {"rebuildremap", ARRAY_DEV_ETC, 1, 1, 1, NULL},
    {"remove", DEVICE_ETC, 2, 2, 1, NULL},
    {"remove", ARRAY_DEV_ETC, 2, 2, 1, NULL},
    {"remind", AUD_ALARM_ETC, 3, 4, 1, NULL},
    {"report", ENC_SCELECTR_ETC, 2, 0, 1, NULL},        /* status only */
    {"report", SCC_CELECTR_ETC, 2, 0, 1, NULL},
    {"report", SCSI_IPORT_ETC, 2, 0, 1, NULL},
    {"report", SCSI_TPORT_ETC, 2, 0, 1, NULL},
    {"rqst_mute", AUD_ALARM_ETC, 3, 7, 1,
     "status only: alarm was manually muted"},
    {"rqst_override", TEMPERATURE_ETC, 3, 7, 1, "Request(ed) override"},
    {"rrabort", ARRAY_DEV_ETC, 1, 0, 1, "rebuild/remap abort"},
    {"rsvddevice", ARRAY_DEV_ETC, 1, 6, 1, "reserved device"},
    {"select_element", ENC_SCELECTR_ETC, 2, 0, 1, NULL},        /* control */
    {"short_stat", SIMPLE_SUBENC_ETC, 3, 7, 8, "short enclosure status"},
    {"size", NV_CACHE_ETC, 2, 7, 16, NULL},
    {"speed_act", COOLING_ETC, 1, 2, 11, "actual speed (rpm / 10)"},
    {"speed_code", COOLING_ETC, 3, 2, 3,
     "0: leave; 1: lowest... 7: highest"},
    {"size_mult", NV_CACHE_ETC, 1, 1, 2, NULL},
    {"swap", -1, 0, 4, 1, NULL},               /* Reset swap */
    {"sw_reset", ENC_SCELECTR_ETC, 1, 3, 1, "software reset"},/* 18-047r1 */
    {"temp", TEMPERATURE_ETC, 2, 7, 8, "(Requested) temperature"},
    {"unlock", DOOR_ETC, 3, 0, 1, NULL},
    {"undertemp_fail", TEMPERATURE_ETC, 3, 1, 1, "Undertemperature failure"},
    {"undertemp_warn", TEMPERATURE_ETC, 3, 0, 1, "Undertemperature warning"},
    {"undervoltage", POWER_SUPPLY_ETC, 2, 2, 1, "DC undervoltage"},
    {"undervoltage", VOLT_SENSOR_ETC, 1, 0, 1, "undervoltage"},
    {"undervoltage_warn", POWER_SUPPLY_ETC, 1, 2, 1,
     "DC undervoltage warning"},
    {"ups_fail", UI_POWER_SUPPLY_ETC, 2, 2, 1, NULL},
    {"urgency", AUD_ALARM_ETC, 3, 3, 4, NULL},  /* Tone urgency control bits */
    {"voltage", VOLT_SENSOR_ETC, 2, 7, 16, "voltage in centivolts"},
    {"warning", UI_POWER_SUPPLY_ETC, 2, 1, 1, NULL},
    {"warning", ENCLOSURE_ETC, 3, 0, 1, NULL},
    {"warning_ind", ENCLOSURE_ETC, 2, 0, 1, NULL},
    {"xmit_fail", SCSI_PORT_TRAN_ETC, 3, 0, 1, "Transmitter failure"},
    {NULL, 0, 0, 0, 0, NULL},
};

/* These are for the Threshold in/out diagnostic page */
static const struct acronym2tuple th_a2t_arr[] = {
    {"high_crit", -1, 0, 7, 8, NULL},
    {"high_warn", -1, 1, 7, 8, NULL},
    {"low_crit", -1, 2, 7, 8, NULL},
    {"low_warn", -1, 3, 7, 8, NULL},
    {NULL, 0, 0, 0, 0, NULL},
};

/* These are for the Additional element status diagnostic page for SAS with
 * the EIP bit set. First phy only. Index from start of AES descriptor */
static const struct acronym2tuple ae_sas_a2t_arr[] = {
    {"at_sas_addr", -1, 12, 7, 64, NULL},  /* best viewed with --hex --get= */
        /* typically this is the expander's SAS address */
    {"dev_type", -1, 8, 6, 3, "1: SAS/SATA dev, 2: expander"},
    {"dsn", -1, 7, 7, 8, "device slot number (255: none)"},
    {"num_phys", -1, 4, 7, 8, "number of phys"},
    {"phy_id", -1, 28, 7, 8, NULL},
    {"sas_addr", -1, 20, 7, 64, NULL},  /* should be disk or tape ... */
    {"exp_sas_addr", -1, 8, 7, 64, NULL},  /* expander address */
    {"sata_dev", -1, 11, 0, 1, NULL},
    {"sata_port_sel", -1, 11, 7, 1, NULL},
    {"smp_init", -1, 10, 1, 1, NULL},
    {"smp_targ", -1, 11, 1, 1, NULL},
    {"ssp_init", -1, 10, 3, 1, NULL},
    {"ssp_targ", -1, 11, 3, 1, NULL},
    {"stp_init", -1, 10, 2, 1, NULL},
    {"stp_targ", -1, 11, 2, 1, NULL},
    {NULL, 0, 0, 0, 0, NULL},
};

/* Boolean array of element types of interest to the Additional Element
 * Status page. Indexed by element type (0 <= et < 32). The corresponding
 * element_type_arr[] acronym field is shown in the comment. */
static const bool active_et_aesp_arr[NUM_ACTIVE_ET_AESP_ARR] = {
    false, true /* 'dev' */, false, false,
    false, false, false, true /* 'esc', esce */,
    false, false, false, false,
    false, false, false, false,
    false, false, false, false,
    true /* 'stp' */, true /* 'sip' */, false, true /* 'arr' */,
    true /* 'sse' */, false, false, false,
    false, false, false, false,
};      /* 6 of 16 are active, 3 of those are optional */

/* Command line long option names with corresponding short letter. */
static const struct option long_options[] = {
    {"all", no_argument, 0, 'a'},
    {"ALL", no_argument, 0, 'z'},
    {"byte1", required_argument, 0, 'b'},
    {"clear", required_argument, 0, 'C'},
    {"control", no_argument, 0, 'c'},
    {"data", required_argument, 0, 'd'},
    {"descriptor", required_argument, 0, 'D'},
    {"dev-slot-num", required_argument, 0, 'x'},
    {"dev_slot_num", required_argument, 0, 'x'},
    {"device-slot-num", required_argument, 0, 'x'},
    {"device_slot_num", required_argument, 0, 'x'},
    {"device-slot-number", required_argument, 0, 'x'},
    {"device_slot_number", required_argument, 0, 'x'},
    {"dsn", required_argument, 0, 'x'},
    {"eiioe", required_argument, 0, 'E'},
    {"enumerate", no_argument, 0, 'e'},
    {"filter", no_argument, 0, 'f'},
    {"get", required_argument, 0, 'G'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"index", required_argument, 0, 'I'},
    {"inhex", required_argument, 0, 'X'},
    {"inner-hex", no_argument, 0, 'i'},
    {"inner_hex", no_argument, 0, 'i'},
    {"json", optional_argument, 0, 'J'},
    {"js_file", required_argument, 0, 'Q'},
    {"js-file", required_argument, 0, 'Q'},
    {"join", no_argument, 0, 'j'},
    {"list", no_argument, 0, 'l'},
    {"nickid", required_argument, 0, 'N'},
    {"nickname", required_argument, 0, 'n'},
    {"no-config", no_argument, 0, 'F'},
    {"no_config", no_argument, 0, 'F'},
    {"mask", required_argument, 0, 'M'},
    {"maxlen", required_argument, 0, 'm'},
    {"page", required_argument, 0, 'p'},
    {"quiet", no_argument, 0, 'q'},
    {"raw", no_argument, 0, 'r'},
    {"readonly", no_argument, 0, 'R'},
    {"sas-addr", required_argument, 0, 'A'},
    {"sas_addr", required_argument, 0, 'A'},
    {"set", required_argument, 0, 'S'},
    {"status", no_argument, 0, 's'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"warn", no_argument, 0, 'w'},
    {0, 0, 0, 0},
};

/* For overzealous SES device servers that don't like some status elements
 * sent back as control elements. This table is as per ses3r06. */
static const uint8_t ses3_element_cmask_arr[NUM_ETC][4] = {
                                /* Element type code (ETC) names; comment */
    {0x40, 0xff, 0xff, 0xff},   /* [0] unspecified */
    {0x40, 0, 0x4e, 0x3c},      /* DEVICE */
    {0x40, 0x80, 0, 0x60},      /* POWER_SUPPLY */
    {0x40, 0x80, 0, 0x60},      /* COOLING; requested speed as is unless */
    {0x40, 0xc0, 0, 0},         /* TEMPERATURE */
    {0x40, 0xc0, 0, 0x1},       /* DOOR */
    {0x40, 0xc0, 0, 0x5f},      /* AUD_ALARM */
    {0x40, 0xc0, 0x1, 0},       /* ENC_SCELECTR_ETC */
    {0x40, 0xc0, 0, 0},         /* SCC_CELECTR */
    {0x40, 0xc0, 0, 0},         /* NV_CACHE */
    {0x40, 0, 0, 0},            /* [10] INV_OP_REASON */
    {0x40, 0, 0, 0xc0},         /* UI_POWER_SUPPLY */
    {0x40, 0xc0, 0xff, 0xff},   /* DISPLAY */
    {0x40, 0xc3, 0, 0},         /* KEY_PAD */
    {0x40, 0x80, 0, 0xff},      /* ENCLOSURE */
    {0x40, 0xc0, 0, 0x10},      /* SCSI_PORT_TRAN */
    {0x40, 0x80, 0xff, 0xff},   /* LANGUAGE */
    {0x40, 0xc0, 0, 0x1},       /* COMM_PORT */
    {0x40, 0xc0, 0, 0},         /* VOLT_SENSOR */
    {0x40, 0xc0, 0, 0},         /* CURR_SENSOR */
    {0x40, 0xc0, 0, 0x1},       /* [20] SCSI_TPORT */
    {0x40, 0xc0, 0, 0x1},       /* SCSI_IPORT */
    {0x40, 0xc0, 0, 0},         /* SIMPLE_SUBENC */
    {0x40, 0xff, 0x4e, 0x3c},   /* ARRAY */
    {0x40, 0xc0, 0, 0},         /* SAS_EXPANDER */
    {0x40, 0x80, 0, 0x40},      /* SAS_CONNECTOR */
};


static int read_hex(const char * inp, uint8_t * arr, int mx_arr_len,
                    int * arr_len, bool in_hex, bool may_gave_at, int verb);
static int strcase_eq(const char * s1p, const char * s2p);
static void enumerate_diag_pages(void);
static bool saddr_non_zero(const uint8_t * bp);
static const char * find_in_diag_page_desc(int page_num);


static void
usage(int help_num)
{
    if (2 != help_num) {
        pr2serr(
            "Usage: sg_ses [--all] [--ALL] [--descriptor=DES] "
            "[--dev-slot-num=SN]\n"
            "              [--eiioe=A_F] [--filter] [--get=STR] "
            "[--hex]\n"
            "              [--index=IIA | =TIA,II] [--inner-hex] [--join] "
            "[--json[=JO]]\n"
            "              [--js-file=JFN] [--maxlen=LEN] [--no-config] "
            "[--page=PG]\n"
            "              [--quiet] [--raw] [--readonly] [--sas-addr=SA] "
            "[--status]\n"
            "              [--verbose] [--warn] DEVICE\n\n"
            "       sg_ses --control [--byte1=B1] [--clear=STR] "
            "[--data=H,H...]\n"
            "              [--descriptor=DES] [--dev-slot-num=SN] "
            "[--index=IIA | =TIA,II]\n"
            "              [--inhex=FN] [--mask] [--maxlen=LEN] "
            "[--nickid=SEID]\n"
            "              [--nickname=SEN] [--page=PG] [--sas-addr=SA] "
            "[--set=STR]\n"
            "              [--verbose] DEVICE\n\n"
            "       sg_ses --inhex=FN --status [-rr] [<most options from "
            "first form>]\n"
            "       sg_ses --data=@FN --status [-rr] [<most options from "
            "first form>]\n\n"
            "       sg_ses [--enumerate] [--help] [--index=IIA] [--list] "
            "[--version]\n\n"
               );
        if ((help_num < 1) || (help_num > 2)) {
            pr2serr("Or the corresponding short option usage: \n"
                    "  sg_ses [-a] [-D DES] [-x SN] [-E A_F] [-f] [-G STR] "
                    "[-H] [-I IIA|TIA,II]\n"
                    "         [-i] [-j] [-m LEN] [-p PG] [-q] [-r] [-R] "
                    "[-A SA] [-s] [-v] [-w]\n"
                    "         DEVICE\n\n"
                    "  sg_ses [-b B1] [-C STR] [-c] [-d H,H...] [-D DES] "
                    "[-x SN] [-I IIA|TIA,II]\n"
                    "         [-M] [-m LEN] [-N SEID] [-n SEN] [-p PG] "
                    "[-A SA] [-S STR]\n"
                    "         [-v] DEVICE\n\n"
                    "  sg_ses -d @FN -s [-rr] [<most options from first "
                    "form>]\n"
                    "  sg_ses -X FN -s [-rr] [<most options from first "
                    "form>]\n\n"
                    "  sg_ses [-e] [-h] [-I IIA] [-l] [-V]\n"
                   );
            pr2serr("\nFor help use '-h' one or more times.\n");
            return;
        }
        pr2serr(
            "  where the main options are:\n"
            "    --all|-a            --join followed by other SES dpages\n"
            "    --clear=STR|-C STR    clear field by acronym or position\n"
            "    --control|-c        send control information (def: fetch "
            "status)\n"
            "    --descriptor=DES|-D DES    descriptor name (for indexing)\n"
            "    --dev-slot-num=SN|--dsn=SN|-x SN    device slot number "
            "(for indexing)\n"
            "    --filter|-f         filter out enclosure status flags that "
            "are clear\n"
            "                        use twice for status=okay entries "
            "only\n"
            "    --get=STR|-G STR    get value of field by acronym or "
            "position\n"
            "    --help|-h           print out usage message, use twice for "
            "additional\n"
            "    --index=IIA|-I IIA    individual index ('-1' for overall) "
            "or element\n"
            "                          type abbreviation (e.g. 'arr'). A "
            "range may be\n"
            "                          given for the individual index "
            "(e.g. '2:5')\n"
            "    --index=TIA,II|-I TIA,II    comma separated pair: TIA is "
            "type header\n"
            "                                index or element type "
            "abbreviation;\n"
            "                                II is individual index ('-1' "
            "for overall)\n"
            );
        pr2serr(
            "    --inhex=FN|-X FN    read data from file FN, ignore DEVICE "
            "if given\n"
            "    --join|-j           group Enclosure Status, Element "
            "Descriptor\n"
            "                        and Additional Element Status pages. "
            "Use twice\n"
            "                        to add Threshold In page\n"
            "    --json[=JO]|-J[JO]    output in JSON instead of human "
            "readable\n"
            "                          test. Use --json=? for JSON help\n"
            "    --page=PG|-p PG     diagnostic page code (abbreviation "
            "or number)\n"
            "                        (def: 'ssp' [0x0] (supported diagnostic "
            "pages))\n"
            "    --sas-addr=SA|-A SA    SAS address in hex (for indexing)\n"
            "    --set=STR|-S STR    set value of field by acronym or "
            "position\n"
            "    --status|-s         fetch status information (default "
            "action)\n\n"
            "First usage above is for fetching pages or fields from a SCSI "
            "enclosure.\nThe second usage is for changing a page or field in "
            "an enclosure. The\n'--clear=', '--get=' and '--set=' options "
            "can appear multiple times.\nUse '-hh' for more help, including "
            "the options not explained above.\n");
    } else {    /* for '-hh' or '--help --help' */
        pr2serr(
            "  where the remaining sg_ses options are:\n"
            "    --ALL|-z            same as --join twice plus other "
            "SES dpages\n"
            "    --byte1=B1|-b B1    byte 1 (2nd byte) of control page set "
            "to B1\n"
            "    --data=H,H...|-d H,H...    string of ASCII hex bytes to "
            "send as a\n"
            "                               control page or decode as a "
            "status page\n"
            "    --data=- | -d -     fetch string of ASCII hex bytes from "
            "stdin\n"
            "    --data=@FN | -d @FN    fetch string of ASCII hex bytes from "
            "file: FN\n"
            "    --eiioe=A_F|-E A_F    A_F is either 'auto' or 'force'. "
            "'force' acts\n"
            "                          as if EIIOE field is 1, 'auto' tries "
            "to guess\n"
            "    --enumerate|-e      enumerate page names + element types "
            "(ignore\n"
            "                        DEVICE). Use twice for clear,get,set "
            "acronyms\n"
            "    --hex|-H            print page response (or field) in hex\n"
            "    --inner-hex|-i      print innermost level of a"
            " status page in hex\n"
            "    --js-file=JFN|-Q JFN    JFN is a filename to which JSON "
            "output is\n"
            "                            written (def: stdout); truncates "
            "then writes\n"
            "    --list|-l           same as '--enumerate' option\n"
            "    --mask|-M           ignore status element mask in modify "
            "actions\n"
            "                        (e.g.--set= and --clear=) (def: apply "
            "mask)\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "    --nickid=SEID|-N SEID   SEID is subenclosure identifier "
            "(def: 0)\n"
            "                            used to specify which nickname to "
            "change\n"
            "    --nickname=SEN|-n SEN   SEN is new subenclosure nickname\n"
            "    --no-config|-f      output without depending on config "
            "dpage\n"
            "    --quiet|-q          suppress some output messages\n"
            "    --raw|-r            print status page in ASCII hex suitable "
            "for '-d';\n"
            "                        when used twice outputs page in binary "
            "to stdout;\n"
            "                        twice with --inhex= reads input in "
            "binary\n"
            "    --readonly|-R       open DEVICE read-only (def: "
            "read-write)\n"
            "    --verbose|-v        increase verbosity\n"
            "    --version|-V        print version string and exit\n"
            "    --warn|-w           warn about join (and other) issues\n\n"
            "If no options are given then DEVICE's supported diagnostic "
            "pages are\nlisted. STR can be '<start_byte>:<start_bit>"
            "[:<num_bits>][=<val>]'\nor '<acronym>[=val]'. Element type "
            "abbreviations may be followed by a\nnumber (e.g. 'ps1' is "
            "the second power supply element type). Use\n'sg_ses -e' and "
            "'sg_ses -ee' for more information.\n\n"
            );
        pr2serr(
            "Low level indexing can be done with one of the two '--index=' "
            "options.\nAlternatively, medium level indexing can be done "
            "with either the\n'--descriptor=', 'dev-slot-num=' or "
            "'--sas-addr=' options. Support for\nthe medium level options "
            "in the SES device is itself optional.\n"
            );
    }
}

/* Parse argument give to '--index='. Return 0 for okay, else an error. If
 * okay sets op->ind_given, ->ind_indiv, ->ind_indiv_last, ->ind_th,
 * ->ind_et_inst and ->ind_etp  .  */
static int
parse_index(struct opts_t *op)
{
    bool m1;
    int n = 0;
    int n2 = 0;
    const char * cp;
    char * c2p;
    const struct element_type_t * etp;
    char b[80];
    static const int blen = sizeof(b);
    static const char * bati = "bad argument to '--index=',";
    static const char * betc = "bad element type code";
    static const char * beta = "bad element type abbreviation";
    static const char * enf = "expect number from";

    op->ind_given = true;
    op->ind_indiv_last = -1;
    if ((cp = strchr(op->index_str, ','))) {
        /* decode number following comma */
        const char * cc3p;

        if (0 == strncmp("-1", cp + 1, 2))
            n = -1;
        else {

            n = sg_get_num_nomult(cp + 1);
            if ((n < 0) || (n > 255)) {
                pr2serr("%s after comma %s -1 to 255\n", bati, enf);
                return SG_SES_CALL_ENUMERATE;
            }
        }
        cc3p = strchr(cp + 2, ':');     /* preferred range indicator */
        if (NULL == cc3p)
            cc3p = strchr(cp + 2, '-');
        if (cc3p) {
            n2 = sg_get_num_nomult(cc3p + 1);
            if ((n2 < n) || (n2 > 255)) {
                pr2serr("%s after ':' %s %d to 255\n", bati, enf, n);
                return SG_SES_CALL_ENUMERATE;
            }
        }
        op->ind_indiv = n;
        if (n2 >= 0)
            op->ind_indiv_last = n2;
        n = cp - op->index_str;
        if (n >= (blen - 1)) {
            pr2serr("%s string prior to comma too long\n", bati);
            return SG_SES_CALL_ENUMERATE;
        }
    } else {    /* no comma found in index_str */
        n = strlen(op->index_str);
        if (n >= (blen - 1)) {
            pr2serr("%s string too long\n", bati);
            return SG_SES_CALL_ENUMERATE;
        }
    }
    snprintf(b, blen, "%.*s", n, op->index_str);
    m1 = (0 == strncmp("-1", b, 2));
    if (m1 || isdigit((uint8_t)b[0])) {
        if (m1) {
            if (cp) {
                pr2serr("%s unexpected '-1' type header index\n", bati);
                return SG_SES_CALL_ENUMERATE;
            }
            op->ind_th = 0;
            op->ind_indiv = -1;
            n = 0;
        } else {
            n = sg_get_num_nomult(b);
            if ((n < 0) || (n > 255)) {
                pr2serr("%s %s 0 to 255\n", bati, enf);
                return SG_SES_CALL_ENUMERATE;
            }
            if (cp)         /* argument to left of comma */
                op->ind_th = n;
            else {          /* no comma found, so 'n' is ind_indiv */
                op->ind_th = 0;
                op->ind_indiv = n;
            }
        }
        c2p = strchr(b, ':');
        if (NULL == c2p)
            c2p = strchr(b + 1, '-');
        if (c2p) {
            n2 = sg_get_num_nomult(c2p + 1);
            if ((n2 < n) || (n2 > 255)) {
                pr2serr("%s after '-' %s %d to 255\n", bati, enf, n);
                return SG_SES_CALL_ENUMERATE;
            }
            op->ind_indiv_last = n2;
        }
    } else if ('_' == b[0]) {   /* leading "_" prefixes element type code */
        if ((c2p = strchr(b + 1, '_')))
            *c2p = '\0';        /* subsequent "_" prefixes e.t. index */
        n = sg_get_num_nomult(b + 1);
        if ((n < 0) || (n > 255)) {
            pr2serr("%s for '--index', %s 0 to 255\n", betc, enf);
            return SG_SES_CALL_ENUMERATE;
        }
        element_type_by_code.elem_type_code = n;
        op->tmp_arr[0] = '_';
        snprintf(op->tmp_arr + 1, 6, "%d", n);
        element_type_by_code.abbrev = op->tmp_arr;
        if (c2p) {
            n = sg_get_num_nomult(c2p + 1);
            if ((n < 0) || (n > 255)) {
                pr2serr("%s <num> for '--index', %s 0 to 255\n", betc, enf);
                return SG_SES_CALL_ENUMERATE;
            }
            op->ind_et_inst = n;
        }
        op->ind_etp = &element_type_by_code;
        if (NULL == cp)
            op->ind_indiv = -1;
    } else { /* element type abbreviation perhaps followed by <num> */
        int b_len = strlen(b);

        for (etp = element_type_arr; etp->desc; ++etp) {
            n = strlen(etp->abbrev);
            if ((b_len >= n) && (0 == strncmp(b, etp->abbrev, n)))
                break;
        }
        if (NULL == etp->desc) {
            pr2serr("%s [%s] for '--index'\n'--enumerate' output shown to "
                    "see available abbreviations\n", beta, b);
            return SG_SES_CALL_ENUMERATE;
        }
        if (b_len > n) {
            n = sg_get_num_nomult(b + n);
            if ((n < 0) || (n > 255)) {
                pr2serr("%s <num> for '--index', %s 0 to 255\n", beta, enf);
                return SG_SES_CALL_ENUMERATE;
            }
            op->ind_et_inst = n;
        }
        op->ind_etp = etp;
        if (NULL == cp)
            op->ind_indiv = -1;
    }
    if (op->verbose > 1) {
        if (op->ind_etp)
            pr2serr("   %s abbreviation: %s, etp_num=%d, individual "
                    "index=%d, last=%d\n", et_s, op->ind_etp->abbrev,
                    op->ind_et_inst, op->ind_indiv, op->ind_indiv_last);
        else
            pr2serr("   type header index=%d, individual index=%d\n",
                    op->ind_th, op->ind_indiv);
    }
    return 0;
}

static bool
dpage_has_control_variant(int page_num)
{
    const struct diag_page_controllable * dpctlp;

    for (dpctlp = dpctl_arr; dpctlp->page_code >= 0; ++dpctlp) {
        if (page_num == dpctlp->page_code)
            return dpctlp->has_controllable_variant;
        else if (page_num < dpctlp->page_code)
            return false;
    }
    return false;
}

/* command line process, options and arguments. Returns 0 if ok. */
static int
parse_cmd_line(struct opts_t *op, int argc, char *argv[])
{
    int c, n, d_len, ret;
    int res = SG_LIB_SYNTAX_ERROR;
    const char * data_arg = NULL;
    const char * inhex_arg = NULL;
    uint64_t saddr;
    const char * cp;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aA:b:cC:d:D:eE:fFG:hHiI:jJ::ln:N:m:Mp:"
                        "qQ:rRsS:vVwx:X:z", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':       /* --all is synonym for --join */
            ++op->do_join;
            op->do_all = true;
            break;
        case 'A':       /* SAS address, assumed to be hex */
            cp = optarg;
            if ((strlen(optarg) > 2) && ('X' == toupper((uint8_t)optarg[1])))
                cp = optarg + 2;
            if (1 != sscanf(cp, "%" SCNx64 "", &saddr)) {
                pr2serr("bad argument to '--sas-addr=SA'\n");
                goto err_fini;
            }
            sg_put_unaligned_be64(saddr, op->sas_addr + 0);
            if (sg_all_ffs(op->sas_addr, 8)) {
                pr2serr("error decoding '--sas-addr=SA' argument\n");
                goto err_fini;
            }
            break;
        case 'b':
            op->byte1 = sg_get_num_nomult(optarg);
            if ((op->byte1 < 0) || (op->byte1 > 255)) {
                pr2serr("bad argument to '--byte1=B1' (0 to 255 "
                        "inclusive)\n");
                goto err_fini;
            }
            op->byte1_given = true;
            break;
        case 'c':
            op->do_control = true;
            break;
        case 'C':
            if (strlen(optarg) >= CGS_STR_MAX_SZ) {
                pr2serr("--clear= option too long (max %d characters)\n",
                        CGS_STR_MAX_SZ);
                goto err_fini;
            }
            if (op->num_cgs < CGS_CL_ARR_MAX_SZ) {
                op->cgs_cl_arr[op->num_cgs].cgs_sel = CLEAR_OPT;
                strcpy(op->cgs_cl_arr[op->num_cgs].cgs_str, optarg);
                ++op->num_cgs;
            } else {
                pr2serr("Too many --clear=, --get= and --set= options "
                        "(max: %d)\n", CGS_CL_ARR_MAX_SZ);
                res = SG_LIB_CONTRADICT;
                goto err_fini;
            }
            break;
        case 'd':
            data_arg = optarg;
            op->data_or_inhex = true;
            break;
        case 'D':
            op->desc_name = optarg;
            break;
        case 'e':
            ++op->enumerate;
            break;
        case 'E':
            if (0 == strcmp("auto", optarg))
                op->eiioe_auto = true;
            else if (0 == strcmp("force", optarg))
                op->eiioe_force = true;
            else {
                pr2serr("--eiioe option expects 'auto' or 'force' as an "
                        "argument\n");
                res = SG_LIB_CONTRADICT;
                goto err_fini;
            }
            break;
        case 'f':
            ++op->do_filter;
            break;
        case 'F':
            op->no_config = true;
            break;
        case 'G':
            if (strlen(optarg) >= CGS_STR_MAX_SZ) {
                pr2serr("--get= option too long (max %d characters)\n",
                        CGS_STR_MAX_SZ);
                goto err_fini;
            }
            if (op->num_cgs < CGS_CL_ARR_MAX_SZ) {
                op->cgs_cl_arr[op->num_cgs].cgs_sel = GET_OPT;
                strcpy(op->cgs_cl_arr[op->num_cgs].cgs_str, optarg);
                ++op->num_cgs;
            } else {
                pr2serr("Too many --clear=, --get= and --set= options "
                        "(max: %d)\n", CGS_CL_ARR_MAX_SZ);
                res = SG_LIB_CONTRADICT;
                goto err_fini;
            }
            break;
        case 'h':
            ++op->do_help;
            break;
        case '?':
            pr2serr("\n");
            usage(0);
            goto err_fini;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            ++op->inner_hex;
            break;
        case 'I':
            op->index_str = optarg;
            break;
        case 'j':
            ++op->do_join;
            break;
        case 'J':
            op->json_arg = optarg;
            op->do_json = true;
            break;
        case 'l':
            op->do_list = true;
            break;
        case 'n':
            op->nickname_str = optarg;
            break;
        case 'N':
            op->seid = sg_get_num_nomult(optarg);
            if ((op->seid < 0) || (op->seid > 255)) {
                pr2serr("bad argument to '--nickid=SEID' (0 to 255 "
                        "inclusive)\n");
                goto err_fini;
            }
            op->seid_given = true;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 65535)) {
                pr2serr("bad argument to '--maxlen=LEN' (0 to 65535 "
                        "inclusive expected)\n");
                goto err_fini;
            }
            if (0 == n)
                op->maxlen = MX_ALLOC_LEN;
            else if (n < MIN_MAXLEN) {
                pr2serr("Warning: --maxlen=LEN less than %d ignored\n",
                        MIN_MAXLEN);
                op->maxlen = MX_ALLOC_LEN;
            } else
                op->maxlen = n;
            break;
        case 'M':
            op->mask_ign = true;
            break;
        case 'p':
            if (isdigit((uint8_t)optarg[0])) {
                op->page_code = sg_get_num_nomult(optarg);
                if ((op->page_code < 0) || (op->page_code > 255)) {
                    pr2serr("bad argument to '--page=PG' (0 to 255 "
                            "inclusive)\n");
                    goto err_fini;
                }
            } else {
                const struct diag_page_abbrev * ap;

                for (ap = dp_abbrev; ap->abbrev; ++ap) {
                    if (strcase_eq(ap->abbrev, optarg)) {
                        op->page_code = ap->page_code;
                        break;
                    }
                }
                if (NULL == ap->abbrev) {
                    pr2serr("'--page=PG' argument abbreviation \"%s\" not "
                            "found\nHere are the choices:\n", optarg);
                    enumerate_diag_pages();
                    goto err_fini;
                }
            }
            op->page_code_given = true;
            break;
        case 'q':
            op->quiet = true;
            break;
        case 'Q':
            op->js_file = optarg;
            op->do_json = true;
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 'R':
            op->o_readonly = true;
            break;
        case 's':
            op->do_status = true;
            break;
        case 'S':
            if (strlen(optarg) >= CGS_STR_MAX_SZ) {
                pr2serr("--set= option too long (max %d characters)\n",
                        CGS_STR_MAX_SZ);
                goto err_fini;
            }
            if (op->num_cgs < CGS_CL_ARR_MAX_SZ) {
                op->cgs_cl_arr[op->num_cgs].cgs_sel = SET_OPT;
                strcpy(op->cgs_cl_arr[op->num_cgs].cgs_str, optarg);
                ++op->num_cgs;
            } else {
                pr2serr("Too many --clear=, --get= and --set= options "
                        "(max: %d)\n", CGS_CL_ARR_MAX_SZ);
                res = SG_LIB_CONTRADICT;
                goto err_fini;
            }
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'w':
            op->do_warn = true;
            break;
        case 'x':
            op->dev_slot_num = sg_get_num_nomult(optarg);
            if ((op->dev_slot_num < 0) || (op->dev_slot_num > 255)) {
                pr2serr("bad argument to '--dev-slot-num' (0 to 255 "
                        "inclusive)\n");
                goto err_fini;
            }
            break;
        case 'X':       /* --inhex=FN for compatibility with other utils */
            inhex_arg = optarg;
            op->data_or_inhex = true;
            break;
        case 'z':       /* --ALL */
            /* -A already used for --sas-addr=SA shortened form */
            op->do_join += 2;
            op->do_all = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            goto err_help;
        }
    }
    if (op->do_help || op->version_given)
        return 0;
    if (optind < argc) {
        if (NULL == op->dev_name) {
            op->dev_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            goto err_help;
        }
    }
    if (op->no_config && (op->do_join > 0)) {
         pr2serr("Need configuration dpage to do the join operation\n\n");
         goto err_help;
    }
    if (op->inner_hex > 0) {
        if (op->do_hex > 0) {
            if (op->do_hex > 3) {
                pr2serr("-HHHH and --inner-hex not permitted\n");
                res = SG_LIB_CONTRADICT;
                goto err_fini;
            }
            op->h2s_oformat = (1 == op->do_hex);
            op->do_hex_inner = op->do_hex;
            op->do_hex = 0;
        }
    } else if (op->do_hex > 0)
        op->h2s_oformat = (1 == op->do_hex);
    op->mx_arr_len = (op->maxlen > MIN_DATA_IN_SZ) ? op->maxlen :
                                                     MIN_DATA_IN_SZ;
    op->data_arr = sg_memalign(op->mx_arr_len, 0 /* page aligned */,
                               &op->free_data_arr, false);
    if (NULL == op->data_arr) {
        pr2serr("unable to allocate %u bytes on heap\n", op->mx_arr_len);
        res = sg_convert_errno(ENOMEM);
        goto err_fini;
    }
    if (op->data_or_inhex) {
        bool may_have_at = inhex_arg ? false : true;

        if (inhex_arg)
            data_arg = inhex_arg;
        ret = read_hex(data_arg, op->data_arr + DATA_IN_OFF,
                       op->mx_arr_len - DATA_IN_OFF, &op->arr_len,
                       (op->do_raw < 2), may_have_at, op->verbose);
        if (ret) {
            if (inhex_arg)
                pr2serr("bad argument, expect '--inhex=FN' or '--inhex=-'\n");
            else
                pr2serr("bad argument, expect '--data=H,H...', '--data=-' or "
                        "'--data=@FN'\n");
            res = ret;
            goto err_fini;
        }
        if ((! op->do_status) && (! op->do_control)) {
            if ((op->do_join > 0) || op->no_config ||
                (op->inner_hex > 0) ||
                (! op->page_code_given) ||
                ((op->page_code_given &&
                 (! dpage_has_control_variant(op->page_code))))) {
                if (op->verbose > 1)
                    pr2serr("Since --join, --all, --page=all, --no-config, "
                            "or --inner_hex given; assume --status\n");
                op->dev_name = NULL;    /* quash device name */
                op->do_status = true;  /* default to receiving status pages */
            } else {
                pr2serr("require '--control' or '--status' option, if both "
                        "possible\n\n");
                goto err_help;
            }
        }
        op->do_raw = 0;
        /* struct data_in_desc_t stuff does not apply when --control */
        if (op->do_status && (op->arr_len > 3)) {
            int off;
            int pc = 0;
            const uint8_t * bp = op->data_arr + DATA_IN_OFF;
            struct data_in_desc_t * didp = data_in_desc_arr;

            d_len = sg_get_unaligned_be16(bp + 2) + 4;
            for (n = 0, off = 0; n < MX_DATA_IN_DESCS; ++n, ++didp) {
                didp->in_use = true;
                pc = bp[0];
                didp->page_code = pc;
                didp->offset = off;
                didp->dp_len = d_len;
                off += d_len;
                if ((off + 3) < op->arr_len) {
                    bp += d_len;
                    d_len = sg_get_unaligned_be16(bp + 2) + 4;
                } else {
                    ++n;
                    break;
                }
            }
            if (1 == n) {
                op->page_code_given = true;
                op->page_code = pc;
            } else      /* n must be > 1 */
                op->many_dpages = true;

            if (op->verbose > 3) {
                int k;
                char b[128];

                for (didp = data_in_desc_arr, k = 0; k < n; ++k, ++didp) {
                    if ((cp = find_in_diag_page_desc(didp->page_code)))
                        snprintf(b, sizeof(b), "%s %s", cp, dp_s);
                    else
                        snprintf(b, sizeof(b), "%s 0x%x", dp_s,
                                 didp->page_code);
                    pr2serr("%s found, offset %d, dp_len=%d\n", b,
                            didp->offset, didp->dp_len);
                }
            }
        }
    }
    if (op->do_join && op->do_control) {
        pr2serr("cannot have '--join' and '--control'\n");
        goto err_help;
    }
    if (op->index_str) {
        ret = parse_index(op);
        if (ret != 0) {
            if (ret != SG_SES_CALL_ENUMERATE)
                pr2serr("  For more information use '--help'\n");
            return ret;
        }
    }
    if (op->desc_name || (op->dev_slot_num >= 0) ||
        saddr_non_zero(op->sas_addr)) {
        if (op->ind_given) {
            pr2serr("cannot have --index with either --descriptor, "
                    "--dev-slot-num or --sas-addr\n");
            goto err_help;
        }
        if (((!! op->desc_name) + (op->dev_slot_num >= 0) +
             saddr_non_zero(op->sas_addr)) > 1) {
            pr2serr("can only have one of --descriptor, "
                    "--dev-slot-num and --sas-addr\n");
            goto err_help;
        }
        if ((0 == op->do_join) && (! op->do_control) &&
            (0 == op->num_cgs) && (! op->page_code_given)) {
            ++op->do_join;      /* implicit --join */
            if (op->verbose)
                pr2serr("process as if --join option is set\n");
        }
    }
    if (op->ind_given) {
        if ((0 == op->do_join) && (! op->do_control) &&
            (0 == op->num_cgs) && (! op->page_code_given)) {
            op->page_code_given = true;
            op->page_code = ENC_STATUS_DPC;  /* implicit status page */
            if (op->verbose)
                pr2serr("assume --page=2 (es) option is set\n");
        }
    }
    if (op->do_list || op->enumerate)
        return 0;

    if (op->do_control && op->do_status) {
        pr2serr("cannot have both '--control' and '--status'\n");
        goto err_help;
    } else if (op->do_control) {
        if (op->nickname_str || op->seid_given)
            ;
        else if (! op->data_or_inhex) {
            pr2serr("need to give '--data' or '--inhex' in control mode\n");
            goto err_help;
        }
    } else if (! op->do_status) {
        op->do_status = true;  /* default to receiving status pages */
    } else if (op->do_status && op->data_or_inhex && op->dev_name) {
        pr2serr(">>> Warning: device name (%s) will be ignored\n",
                op->dev_name);
        op->dev_name = NULL;    /* quash device name */
    }

    if (op->nickname_str) {
        if (! op->do_control) {
            pr2serr("since '--nickname=' implies control mode, require "
                    "'--control' as well\n");
            goto err_help;
        }
        if (op->page_code_given) {
            if (SUBENC_NICKNAME_DPC != op->page_code) {
                pr2serr("since '--nickname=' assume or expect "
                        "'--page=snic'\n");
                goto err_help;
            }
        } else
            op->page_code = SUBENC_NICKNAME_DPC;
    } else if (op->seid_given) {
        pr2serr("'--nickid=' must be used together with '--nickname='\n");
        goto err_help;

    }
    if ((op->verbose > 4) && saddr_non_zero(op->sas_addr))
        pr2serr("    SAS address (in hex): %" PRIx64 "\n",
                sg_get_unaligned_be64(op->sas_addr + 0));

    if ((! (op->data_or_inhex && op->do_status)) && (NULL == op->dev_name)) {
        if (op->do_control) {
            cp = ">>> when --control is given, ";
            if (NULL == op->dev_name)
                pr2serr("%sa _real_ device name must be supplied\n", cp);
            else
                pr2serr("%seither --data or --inhex must be supplied\n", cp);
        } else {
            pr2serr("missing DEVICE name!\n\n");
            res = SG_LIB_FILE_ERROR;
        }
        goto err_help;
    }
    if (op->do_all && (op->do_hex > 2)) {
        if (op->do_hex < 6) {
            pr2serr("The --all and -HHH (-HHHH, or -HHHHH) options "
                    "contradict\nproducing confusing output. To dump all "
                    "pages in hex try\n'--page=all -HHHH' instead.\nTo "
                    "override this error/warning give '-H' six times!\n");
            res = SG_LIB_CONTRADICT;
            goto err_fini;
        }
    }
    return 0;

err_help:
    if (op->verbose) {
        pr2serr("\n");
        usage(0);
    }
err_fini:
    return res;
}

/* Parse clear/get/set string, writes output to '*tavp'. Uses 'buff' for
 * scratch area. Returns 0 on success, else -1. */
static int
parse_cgs_str(char * buff, struct tuple_acronym_val * tavp)
{
    char * esp;
    char * colp;
    unsigned int ui;

    tavp->acron = NULL;
    tavp->val_str = NULL;
    tavp->start_byte = -1;
    tavp->num_bits = 1;
    if ((esp = strchr(buff, '='))) {
        tavp->val_str = esp + 1;
        *esp = '\0';
        if (0 == strcmp("-1", esp + 1))
            tavp->val = -1;
        else {
            tavp->val = sg_get_llnum_nomult(esp + 1);
            if (-1 == tavp->val) {
                pr2serr("unable to decode: %s value\n", esp + 1);
                pr2serr("    expected: <acronym>[=<val>]\n");
                return -1;
            }
        }
    }
    if (isalpha((uint8_t)buff[0]))
        tavp->acron = buff;
    else {
        char * cp;

        colp = strchr(buff, ':');
        if ((NULL == colp) || (buff == colp))
            return -1;
        *colp = '\0';
        if (('0' == buff[0]) && ('X' == toupper((uint8_t)buff[1]))) {
            if (1 != sscanf(buff + 2, "%x", &ui))
                return -1;
            tavp->start_byte = ui;
        } else if ('H' == toupper((uint8_t)*(colp - 1))) {
            if (1 != sscanf(buff, "%x", &ui))
                return -1;
            tavp->start_byte = ui;
        } else {
            if (1 != sscanf(buff, "%d", &tavp->start_byte))
                return -1;
        }
        if ((tavp->start_byte < 0) || (tavp->start_byte > 127)) {
            pr2serr("<start_byte> needs to be between 0 and 127\n");
            return -1;
        }
        cp = colp + 1;
        colp = strchr(cp, ':');
        if (cp == colp)
            return -1;
        if (colp)
            *colp = '\0';
        if (1 != sscanf(cp, "%d", &tavp->start_bit))
            return -1;
        if ((tavp->start_bit < 0) || (tavp->start_bit > 7)) {
            pr2serr("<start_bit> needs to be between 0 and 7\n");
            return -1;
        }
        if (colp) {
            if (1 != sscanf(colp + 1, "%d", &tavp->num_bits))
                return -1;
        }
        if ((tavp->num_bits < 1) || (tavp->num_bits > 64)) {
            pr2serr("<num_bits> needs to be between 1 and 64\n");
            return -1;
        }
    }
    return 0;
}

static bool
dpage_in_join(int dpage_code, const struct opts_t * op)
{
    switch (dpage_code) {
    case ENC_STATUS_DPC:
    case ELEM_DESC_DPC:
    case ADD_ELEM_STATUS_DPC:
        return true;
    case THRESHOLD_DPC:
        return (op->do_join > 1);
    default:
        return false;
    }
}

/* Fetch diagnostic page name (control or out). Returns NULL if not found. */
static const char *
find_out_diag_page_desc(int page_num)
{
    const struct diag_page_code * pcdp;

    for (pcdp = out_dpc_arr; pcdp->desc; ++pcdp) {
        if (page_num == pcdp->page_code)
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            return NULL;
    }
    return NULL;
}

static bool
match_ind_indiv(int index, const struct opts_t * op)
{
    if (index == op->ind_indiv)
        return true;
    if (op->ind_indiv_last > op->ind_indiv) {
        if ((index > op->ind_indiv) && (index <= op->ind_indiv_last))
            return true;
    }
    return false;
}

/* Return of 0 -> success, SG_LIB_CAT_* positive values or -1 -> other
 * failures */
static int
do_senddiag(struct sg_pt_base * ptvp, void * outgoing_pg, int outgoing_len,
            bool noisy, int verbose)
{
    int ret;

    if (outgoing_pg && (verbose > 2)) {
        int page_num = ((const char *)outgoing_pg)[0];
        const char * cp = find_out_diag_page_desc(page_num);

        if (cp)
            pr2serr("    Send diagnostic page name: %s\n", cp);
        else
            pr2serr("    Send diagnostic page number: 0x%x\n",
                    page_num);
    }
    ret = sg_ll_send_diag_pt(ptvp, 0 /* sf_code */, true /* pf_bit */,
                             false /* sf_bit */, false /* devofl_bit */,
                             false /* unitofl_bit */, 0 /* long_duration */,
                             outgoing_pg, outgoing_len, noisy, verbose);
    clear_scsi_pt_obj(ptvp);
    return ret;
}

/* Fetch diagnostic page name (status and/or control). Returns NULL if not
 * found. */
static const char *
find_diag_page_desc(int page_num)
{
    const struct diag_page_code * pcdp;

    for (pcdp = dpc_arr; pcdp->desc; ++pcdp) {
        if (page_num == pcdp->page_code)
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            return NULL;
    }
    return NULL;
}

/* Always returns valid string */
static const char *
find_dpage_cat_str(int page_code)
{
    if (page_code < 0x10)
        return "unknown";
    else if ((page_code >= 0x10) && (page_code <= 0x1f))
        return vs_s;
    else if (page_code <= 0x3f)
        return rsv_s;
    else if (0x3f == page_code)
        return "SCSI transport";
    else if (page_code >= 0x80)
        return vs_s;
    else
        return rsv_s;
}



/* Fetch diagnostic page name (status or in). Returns NULL if not found. */
static const char *
find_in_diag_page_desc(int page_num)
{
    const struct diag_page_code * pcdp;

    for (pcdp = in_dpc_arr; pcdp->desc; ++pcdp) {
        if (page_num == pcdp->page_code)
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            return NULL;
    }
    return NULL;
}

/* Fetch element type name. Returns NULL if not found. */
static char *
etype_str(int elem_type_code, char * b, int mlen_b)
{
    const struct element_type_t * etp;
    int len;

    if ((NULL == b) || (mlen_b < 1))
        return b;
    for (etp = element_type_arr; etp->desc; ++etp) {
        if (elem_type_code == etp->elem_type_code) {
            len = strlen(etp->desc);
            if (len < mlen_b)
                strcpy(b, etp->desc);
            else {
                strncpy(b, etp->desc, mlen_b - 1);
                b[mlen_b - 1] = '\0';
            }
            return b;
        } else if (elem_type_code < etp->elem_type_code)
            break;
    }
    if (elem_type_code < 0x80)
        snprintf(b, mlen_b - 1, "[0x%x]", elem_type_code);
    else
        snprintf(b, mlen_b - 1, "%s [0x%x]", vs_s, elem_type_code);
    b[mlen_b - 1] = '\0';
    return b;
}

/* Returns true if el_type (element type) is of interest to the Additional
 * Element Status page. Otherwise return false. */
static bool
is_et_used_by_aes(int el_type)
{
    if ((el_type >= 0) && (el_type < NUM_ACTIVE_ET_AESP_ARR))
        return active_et_aesp_arr[el_type];
    else
        return false;
}

/* Returns true if el_type (element type) is optional for the Additional
 * Element Status page. Otherwise return false. Those element types that
 * are active, but not optional, are required (if they appear in the
 * configuration dpage). */
static bool
is_et_optional_for_aes(int el_type)
{
    switch (el_type) {
    case SCSI_TPORT_ETC:
        return true;
    case SCSI_IPORT_ETC:
        return true;
    case ENC_SCELECTR_ETC:
        return true;
    default:
        return false;
    }
}

static const struct join_row_t *
find_join_row_cnst(const struct th_es_t * tesp, int index,
                   enum fj_select_t sel)
{
    int k;
    const struct join_row_t * jrp = tesp->j_base;

    if (index < 0)
        return NULL;
    switch (sel) {
    case FJ_IOE:     /* index includes overall element */
        if (index >= tesp->num_j_rows)
            return NULL;
        return jrp + index;
    case FJ_EOE:     /* index excludes overall element */
        if (index >= tesp->num_j_eoe)
            return NULL;
        for (k = 0; k < tesp->num_j_rows; ++k, ++jrp) {
            if (index == jrp->ei_eoe)
                return jrp;
        }
        return NULL;
    case FJ_AESS:   /* index includes only AES listed element types */
        if (index >= tesp->num_j_eoe)
            return NULL;
        for (k = 0; k < tesp->num_j_rows; ++k, ++jrp) {
            if (index == jrp->ei_aess)
                return jrp;
        }
        return NULL;
    case FJ_SAS_CON: /* index on non-overall SAS connector etype */
        if (index >= tesp->num_j_rows)
            return NULL;
        for (k = 0; k < tesp->num_j_rows; ++k, ++jrp) {
            if (SAS_CONNECTOR_ETC == jrp->etype) {
                if (index == jrp->indiv_i)
                    return jrp;
            }
        }
        return NULL;
    default:
        pr2serr("%s: bad selector: %d\n", __func__, (int)sel);
        return NULL;
    }
}

/* Return of 0 -> success, SG_LIB_CAT_* positive values or -2 if response
 * had bad format, -1 -> other failures */
static int
do_rec_diag(struct sg_pt_base * ptvp, int page_code, uint8_t * rsp_buff,
            int rsp_buff_size, struct opts_t * op, int * rsp_lenp)
{
    int k, d_len, rsp_len, res;
    int resid = 0;
    int vb = op->verbose;
    const char * cp;
    char b[80];
    char bb[120];
    static const char * rdr = "Receive diagnostic results";

    memset(rsp_buff, 0, rsp_buff_size);
    if (rsp_lenp)
        *rsp_lenp = 0;
    if ((cp = find_in_diag_page_desc(page_code)))
        snprintf(bb, sizeof(bb), "%s %s", cp, dp_s);
    else
        snprintf(bb, sizeof(bb), "%s 0x%x", dp_s, page_code);
    cp = bb;

    if (op->data_arr && op->data_or_inhex) {  /* user provided data */
        /* N.B. First 4 bytes in data_arr are not used, user data was read in
         * starting at byte offset 4 */
        bool found = false;
        int off = 0;
        const uint8_t * bp = op->data_arr + DATA_IN_OFF;
        const struct data_in_desc_t * didp = data_in_desc_arr;

        for (k = 0, d_len = 0; k < MX_DATA_IN_DESCS; ++k, ++didp) {
            if (! didp->in_use)
                break;
            if (page_code == didp->page_code) {
                off = didp->offset;
                d_len = didp->dp_len;
                found = true;
                break;
            }
        }
        if (found)
            memcpy(rsp_buff, bp + off, d_len);
        else {
            pr2serr("%s: %s not found in user data\n", __func__, cp);
            return SG_LIB_OK_FALSE;     /* flag dpage not found */
        }

        cp = find_in_diag_page_desc(page_code);
        if (vb > 2) {
            pr2serr("    %s: response data from user", rdr);
            if (3 == vb) {
                pr2serr("%s:\n", (d_len > 256 ? ", first 256 bytes" : ""));
                hex2stderr(rsp_buff, (d_len > 256 ? 256 : d_len), -1);
            } else {
                pr2serr(":\n");
                hex2stderr(rsp_buff, d_len, 0);
            }
        }
        res = 0;
        resid = rsp_buff_size - d_len;
        goto decode;    /* step over the device access */
    }
    if (vb > 1)
        pr2serr("    %s command for %s\n", rdr, cp);
    res = sg_ll_receive_diag_pt(ptvp, true /* pcv */, page_code, rsp_buff,
                                rsp_buff_size, 0 /* default timeout */,
                                &resid, ! op->quiet, vb);
    clear_scsi_pt_obj(ptvp);
decode:
    if (0 == res) {
        rsp_len = sg_get_unaligned_be16(rsp_buff + 2) + 4;
        if (rsp_len > rsp_buff_size) {
            if (rsp_buff_size > 8) /* tried to get more than header */
                pr2serr("<<< warning response buffer too small [was %d but "
                        "need %d]>>>\n", rsp_buff_size, rsp_len);
            if (resid > 0)
                rsp_buff_size -= resid;
        } else if (resid > 0)
            rsp_buff_size -= resid;
        rsp_len = (rsp_len < rsp_buff_size) ? rsp_len : rsp_buff_size;
        if (rsp_len < 0) {
            pr2serr("<<< warning: resid=%d too large, implies negative "
                    "reply length: %d\n", resid, rsp_len);
            rsp_len = 0;
        }
        if (rsp_lenp)
            *rsp_lenp = rsp_len;
        if ((rsp_len > 1) && (page_code != rsp_buff[0])) {
            if ((0x9 == rsp_buff[0]) && (1 & rsp_buff[1])) {
                pr2serr("Enclosure busy, try again later\n");
                if (op->do_hex)
                    hex2stderr(rsp_buff, rsp_len, 0);
            } else if (0x8 == rsp_buff[0]) {
                pr2serr("Enclosure only supports Short %s: 0x%x\n",
                        es_s, rsp_buff[1]);
            } else {
                pr2serr("Invalid response, wanted page code: 0x%x but got "
                        "0x%x\n", page_code, rsp_buff[0]);
                hex2stderr(rsp_buff, rsp_len, 0);
            }
            return -2;
        }
        return 0;
    } else if (vb) {
        pr2serr("Attempt to fetch %s failed\n", cp);
        sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
        pr2serr("    %s\n", b);
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

/* CONFIGURATION_DPC  <"cf"> [0x1]
 * Display Configuration diagnostic page. */
static void
configuration_sdp(const uint8_t * resp, int resp_len, struct opts_t * op,
                  sgj_opaque_p jop)
{
    bool as_json;
    int k, el, num_subs, sum_elem_types;
    uint32_t gen_code;
    uint64_t ull;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const uint8_t * text_bp;
    const uint8_t * type_dh_bp;
    const char * ccp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    char e[80];
    static const int blen = sizeof(b);
    static const int elen = sizeof(e);
    static const char * cf_dp = "Configuration diagnostic page";
    static const char * eli = "enclosure logical identifier";
    static const char * edl = "enclosure descriptor list";
    static const char * tdh_s = "type descriptor header";
    static const char * tt_s = "text";

    sgj_pr_hr(jsp, "%s:\n", cf_dp);
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    sum_elem_types = 0;
    last_bp = resp + resp_len - 1;
    as_json = jsp->pr_as_json;
    if (as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(cf_dp, b, blen));
        sgj_js_nv_ihexstr(jsp, jop, pc_sn, CONFIGURATION_DPC, NULL, cf_dp);
    }
    sgj_haj_vi(jsp, jop, 2, noss_s, SGJ_SEP_COLON_1_SPACE, num_subs - 1,
               false);
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    bp = resp + 8;
    sgj_pr_hr(jsp, "  %s:\n", edl);
    if (as_json)
        jap = sgj_named_subarray_r(jsp, jop,
                                   sgj_convert2snake(edl, b, blen));

    for (k = 0; k < num_subs; ++k, bp += el) {
        bool primary;

        if ((bp + 3) > last_bp)
            goto truncated;
        if (as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        el = bp[3] + 4;
        sum_elem_types += bp[2];
        primary = (0 == bp[1]);
        if (op->inner_hex) {
            hex2str(bp, el, "        ", op->h2s_oformat, blen, b);
            if (as_json && jsp->pr_out_hr)
                sgj_hr_str_out(jsp, b, strlen(b));
            else
                sgj_pr_hr(jsp, "%s\n", b);
            if (as_json) {
                sgj_js_nv_hex_bytes(jsp, jo2p, in_hex_sn, bp, el);
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
            continue;
        }
        sgj_pr_hr(jsp, "    Subenclosure identifier: %d%s\n", bp[1],
                  (primary ? " [primary]" : ""));
        sgj_js_nv_ihexstr(jsp, jo2p, si_sn, bp[1], NULL,
                          primary ? "primary" : NULL);
        sgj_pr_hr(jsp, "      relative ES process id: %d, number of ES "
                  "processes: %d\n", ((bp[0] & 0x70) >> 4), (bp[0] & 0x7));
        sgj_js_nv_ihex(jsp, jo2p,
                       "relative_enclosure_services_process_identifier",
                       (bp[0] & 0x70) >> 4);
        sgj_js_nv_ihex(jsp, jo2p,
                       "number_of_enclosure_services_processes", 0x7 & bp[0]);
        sgj_haj_vi(jsp, jo2p, 6, "number of type descriptor headers",
                   SGJ_SEP_COLON_1_SPACE, bp[2], false);
        if (el < 40) {
            pr2serr("      enc descriptor len=%d ??\n", el);
            if (as_json)
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            continue;
        }
        ull = sg_get_unaligned_be64(bp + 4);
        sgj_pr_hr(jsp, "      %s (hex): %" PRIx64 "\n", eli, ull);
        sgj_js_nv_ihex(jsp, jo2p, sgj_convert2snake(eli, b, blen), ull);
        sgj_pr_hr(jsp, "      enclosure vendor: %.8s  product: %.16s  "
                  "rev: %.4s\n", bp + 12, bp + 20, bp + 36);
        sgj_js_nv_s_len_chk(jsp, jo2p, "enclosure_vendor_identification",
                            bp + 12, 8);
        sgj_js_nv_s_len_chk(jsp, jo2p, "product_identification", bp + 20, 16);
        sgj_js_nv_s_len_chk(jsp, jo2p, "product_revision_level", bp + 36, 4);
        if (el > 40) {
            sgj_pr_hr(jsp, "      %s data:\n", vs_s);
            hex2str(bp + 40, el - 40, "        ", op->h2s_oformat, blen, b);
            if (as_json && jsp->pr_out_hr)
                sgj_hr_str_out(jsp, b, strlen(b));
            else
                sgj_pr_hr(jsp, "%s\n", b);
            if (as_json)
                sgj_js_nv_hex_bytes(jsp, jo2p,
                         "vendor_specific_enclosure_information",
                                    bp + 40, el - 40);
        }
        if (as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    snprintf(e, elen, "%s%s list", tdh_s,
             (op->inner_hex > 0) ? "" : " and text");
    sgj_pr_hr(jsp, "  %s:\n", e);
    if (as_json)
        jap = sgj_named_subarray_r(jsp, jop, sgj_convert2snake(e, b, blen));
    type_dh_bp = bp;
    text_bp = bp + (sum_elem_types * 4);
    for (k = 0; k < sum_elem_types; ++k, bp += 4) {
        if ((bp + 3) > last_bp)
            goto truncated;
        if (as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        ccp = etype_str(bp[0], b, blen);
        sgj_pr_hr(jsp, "    %s: %s, %s: %d\n", et_s, ccp, si_ss, bp[2]);
        sgj_pr_hr(jsp, "      number of possible elements: %d\n", bp[1]);
        if ((op->inner_hex < 2) && as_json) {
            sgj_js_nv_ihexstr(jsp, jo2p, et_sn, bp[0], NULL, ccp);
            sgj_js_nv_ihex(jsp, jo2p, "number_of_possible_elements", bp[1]);
            sgj_js_nv_ihex(jsp, jo2p, si_sn, bp[2]);
        }
        if (op->inner_hex > 0) {
            hex2str(bp, 4, "        ", op->h2s_oformat, blen, b);
            if (as_json && jsp->pr_out_hr)
                sgj_hr_str_out(jsp, b, strlen(b));
            else
                sgj_pr_hr(jsp, "%s\n", b);
            if (as_json) {
                sgj_js_nv_hex_bytes(jsp, jo2p, in_hex_sn, bp, 4);
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
            continue;
        }
        sgj_js_nv_ihex(jsp, jo2p, "type_descriptor_text_length", bp[3]);
        if (bp[3] > 0) {
            if (text_bp > last_bp) {
                if (as_json)
                    sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
                goto truncated;
            }
            sgj_pr_hr(jsp, "      %s: %.*s\n", tt_s, bp[3],
                      (const char *)text_bp);
            if (as_json)
                sgj_js_nv_s_len_chk(jsp, jo2p, tt_s, text_bp, bp[3]);
            text_bp += bp[3];
        }
        if (as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }

    if (op->inner_hex > 0) {
        bp = type_dh_bp;
        text_bp = bp + (sum_elem_types * 4);
        snprintf(e, elen, "type descriptor text list");
        sgj_pr_hr(jsp, "  %s:\n", e);
        if (as_json)
            jap = sgj_named_subarray_r(jsp, jop,
                                       sgj_convert2snake(e, b, blen));
        for (k = 0; k < sum_elem_types; ++k, bp += 4) {
            if (as_json)
                jo2p = sgj_new_unattached_object_r(jsp);
            if (1 == op->inner_hex)
                sgj_pr_hr(jsp, "    %s:\n", tt_s);
            hex2str(text_bp, bp[3], "        ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
            if (as_json) {
                if (1 == op->inner_hex)
                    sgj_js_nv_s_len_chk(jsp, jo2p, tt_s, text_bp, bp[3]);
                else
                    sgj_js_nv_hex_bytes(jsp, jo2p, tt_s, text_bp, bp[3]);
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
            text_bp += bp[3];
        }
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

/* CONFIGURATION_DPC [0x1] read and used to build array pointed to by
 * 'tdhp' with no more than 'max_elems' elements. If 'generationp' is non
 * NULL then writes generation code where it points. if 'primary_ip" is
 * non NULL the writes rimary enclosure info where it points.
 * Returns total number of type descriptor headers written to 'tdhp' or -1
 * if there is a problem */
static int
build_type_desc_hdr_arr(struct sg_pt_base * ptvp,
                         struct type_desc_hdr_t * tdhp, int max_elems,
                        uint32_t * generationp,
                        struct enclosure_info * primary_ip,
                        struct opts_t * op)
{
    int resp_len, k, el, num_subs, sum_type_dheaders, res, n;
    int ret = 0;
    uint32_t gen_code;
    const uint8_t * bp;
    const uint8_t * last_bp;

    if (NULL == config_dp_resp) {
        config_dp_resp = sg_memalign(op->maxlen, 0, &free_config_dp_resp,
                                     false);
        if (NULL == config_dp_resp) {
            pr2serr("%s: unable to allocate %d bytes on heap\n", __func__,
                    op->maxlen);
            ret = -1;
            goto the_end;
        }
        res = do_rec_diag(ptvp, CONFIGURATION_DPC, config_dp_resp, op->maxlen,
                          op, &resp_len);
        if (res) {
            pr2serr("%s: couldn't read config page, res=%d\n", __func__, res);
            ret = -1;
            free(free_config_dp_resp);
            free_config_dp_resp = NULL;
            goto the_end;
        }
        if (resp_len < 4) {
            ret = -1;
            free(free_config_dp_resp);
            free_config_dp_resp = NULL;
            goto the_end;
        }
        config_dp_resp_len = resp_len;
    } else
        resp_len = config_dp_resp_len;

    num_subs = config_dp_resp[1] + 1;
    sum_type_dheaders = 0;
    last_bp = config_dp_resp + resp_len - 1;
    gen_code = sg_get_unaligned_be32(config_dp_resp + 4);
    if (generationp)
        *generationp = gen_code;
    bp = config_dp_resp + 8;
    for (k = 0; k < num_subs; ++k, bp += el) {
        if ((bp + 3) > last_bp)
            goto p_truncated;
        el = bp[3] + 4;
        sum_type_dheaders += bp[2];
        if (el < 40) {
            pr2serr("%s: short enc descriptor len=%d ??\n", __func__, el);
            continue;
        }
        if ((0 == k) && primary_ip) {
            ++primary_ip->have_info;
            primary_ip->rel_esp_id = (bp[0] & 0x70) >> 4;
            primary_ip->num_esp = (bp[0] & 0x7);
            memcpy(primary_ip->enc_log_id, bp + 4, 8);
            memcpy(primary_ip->enc_vendor_id, bp + 12, 8);
            memcpy(primary_ip->product_id, bp + 20, 16);
            memcpy(primary_ip->product_rev_level, bp + 36, 4);
        }
    }
    for (k = 0; k < sum_type_dheaders; ++k, bp += 4) {
        if ((bp + 3) > last_bp)
            goto p_truncated;
        if (k >= max_elems) {
            pr2serr("%s: too many elements\n", __func__);
            ret = -1;
            goto the_end;
        }
        tdhp[k].etype = bp[0];
        tdhp[k].num_elements = bp[1];
        tdhp[k].se_id = bp[2];
        tdhp[k].txt_len = bp[3];
    }
    if (op->ind_given && op->ind_etp) {
        n = op->ind_et_inst;
        for (k = 0; k < sum_type_dheaders; ++k) {
            if (op->ind_etp->elem_type_code == tdhp[k].etype) {
                if (0 == n)
                    break;
                else
                    --n;
            }
        }
        if (k < sum_type_dheaders)
            op->ind_th = k;
        else {
            if (op->ind_et_inst)
                pr2serr("%s: unable to find %s '%s%d'\n", __func__, et_s,
                        op->ind_etp->abbrev, op->ind_et_inst);
            else
                pr2serr("%s: unable to find %s '%s'\n", __func__, et_s,
                        op->ind_etp->abbrev);
            ret = -1;
            goto the_end;
        }
    }
    ret = sum_type_dheaders;
    goto the_end;

p_truncated:
    pr2serr("%s: config too short\n", __func__);
    ret = -1;

the_end:
    if (0 == ret)
        ++type_desc_hdr_count;
    return ret;
}

static char *
find_sas_connector_type(int conn_type, bool abridged, char * buff,
                        int buff_len)
{
    switch (conn_type) {
    case 0x0:
        snprintf(buff, buff_len, "No information");
        break;
    case 0x1:
        if (abridged)
            snprintf(buff, buff_len, "SAS 4x");
        else
            snprintf(buff, buff_len, "SAS 4x receptacle (SFF-8470) "
                     "[max 4 phys]");
        break;
    case 0x2:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS 4x");
        else
            snprintf(buff, buff_len, "Mini SAS 4x receptacle (SFF-8088) "
                     "[max 4 phys]");
        break;
    case 0x3:
        if (abridged)
            snprintf(buff, buff_len, "QSFP+");
        else
            snprintf(buff, buff_len, "QSFP+ receptacle (SFF-8436) "
                     "[max 4 phys]");
        break;
    case 0x4:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS 4x active");
        else
            snprintf(buff, buff_len, "Mini SAS 4x active receptacle "
                     "(SFF-8088) [max 4 phys]");
        break;
    case 0x5:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS HD 4x");
        else
            snprintf(buff, buff_len, "Mini SAS HD 4x receptacle (SFF-8644) "
                     "[max 4 phys]");
        break;
    case 0x6:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS HD 8x");
        else
            snprintf(buff, buff_len, "Mini SAS HD 8x receptacle (SFF-8644) "
                     "[max 8 phys]");
        break;
    case 0x7:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS HD 16x");
        else
            snprintf(buff, buff_len, "Mini SAS HD 16x receptacle (SFF-8644) "
                     "[max 16 phys]");
        break;
    case 0xf:
        snprintf(buff, buff_len, "%s", vs_s);
        break;
    case 0x10:
        if (abridged)
            snprintf(buff, buff_len, "SAS 4i");
        else
            snprintf(buff, buff_len, "SAS 4i plug (SFF-8484) [max 4 phys]");
        break;
    case 0x11:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS 4i");
        else
            snprintf(buff, buff_len, "Mini SAS 4i receptacle (SFF-8087) "
                     "[max 4 phys]");
        break;
    case 0x12:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS HD 4i");
        else
            snprintf(buff, buff_len, "Mini SAS HD 4i receptacle (SFF-8643) "
                     "[max 4 phys]");
        break;
    case 0x13:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS HD 8i");
        else
            snprintf(buff, buff_len, "Mini SAS HD 8i receptacle (SFF-8643) "
                     "[max 8 phys]");
        break;
    case 0x14:
        if (abridged)
            snprintf(buff, buff_len, "Mini SAS HD 16i");
        else
            snprintf(buff, buff_len, "Mini SAS HD 16i receptacle (SFF-8643) "
                     "[max 16 phys]");
        break;
    case 0x15:
        if (abridged)
            snprintf(buff, buff_len, "SlimSAS 4i");  /* was "SAS SlimLine" */
        else
            snprintf(buff, buff_len, "SlimSAS 4i (SFF-8654) [max 4 phys]");
        break;
    case 0x16:
        if (abridged)
            snprintf(buff, buff_len, "SlimSAS 8i");  /* was "SAS SlimLine" */
        else
            snprintf(buff, buff_len, "SlimSAS 8i (SFF-8654) [max 8 phys]");
        break;
    case 0x17:
        if (abridged)
            snprintf(buff, buff_len, "SAS MiniLink 4i");
        else
            snprintf(buff, buff_len, "SAS MiniLink 4i (SFF-8612) "
                     "[max 4 phys]");
        break;
    case 0x18:
        if (abridged)
            snprintf(buff, buff_len, "SAS MiniLink 8i");
        else
            snprintf(buff, buff_len, "SAS MiniLink 8i (SFF-8612) "
                     "[max 8 phys]");
        break;
    case 0x20:
        if (abridged)
            snprintf(buff, buff_len, "SAS Drive backplane");
        else
            snprintf(buff, buff_len, "SAS Drive backplane receptacle "
                     "(SFF-8482) [max 2 phys]");
        break;
    case 0x21:
        if (abridged)
            snprintf(buff, buff_len, "SATA host plug");
        else
            snprintf(buff, buff_len, "SATA host plug [max 1 phy]");
        break;
    case 0x22:
        if (abridged)
            snprintf(buff, buff_len, "SAS Drive plug");
        else
            snprintf(buff, buff_len, "SAS Drive plug (SFF-8482) "
                     "[max 2 phys]");
        break;
    case 0x23:
        if (abridged)
            snprintf(buff, buff_len, "SATA device plug");
        else
            snprintf(buff, buff_len, "SATA device plug [max 1 phy]");
        break;
    case 0x24:
        if (abridged)
            snprintf(buff, buff_len, "Micro SAS receptacle");
        else
            snprintf(buff, buff_len, "Micro SAS receptacle [max 2 phys]");
        break;
    case 0x25:
        if (abridged)
            snprintf(buff, buff_len, "Micro SATA device plug");
        else
            snprintf(buff, buff_len, "Micro SATA device plug [max 1 phy]");
        break;
    case 0x26:
        if (abridged)
            snprintf(buff, buff_len, "Micro SAS plug");
        else
            snprintf(buff, buff_len, "Micro SAS plug (SFF-8486) [max 2 "
                     "phys]");
        break;
    case 0x27:
        if (abridged)
            snprintf(buff, buff_len, "Micro SAS/SATA plug");
        else
            snprintf(buff, buff_len, "Micro SAS/SATA plug (SFF-8486) "
                     "[max 2 phys]");
        break;
    case 0x28:
        if (abridged)
            snprintf(buff, buff_len, "12 Gb/s SAS drive backplane");
        else
            snprintf(buff, buff_len, "12 Gb/s SAS drive backplane receptacle "
                     "(SFF-8680) [max 2 phys]");
        break;
    case 0x29:
        if (abridged)
            snprintf(buff, buff_len, "12 Gb/s SAS drive plug");
        else
            snprintf(buff, buff_len, "12 Gb/s SAS drive plug (SFF-8680) "
                     "[max 2 phys]");
        break;
    case 0x2a:
        if (abridged)
            snprintf(buff, buff_len, "Multifunction 12 Gb/s 6x receptacle");
        else
            snprintf(buff, buff_len, "Multifunction 12 Gb/s 6x unshielded "
                     "receptacle (SFF-8639)");
        break;
    case 0x2b:
        if (abridged)
            snprintf(buff, buff_len, "Multifunction 12 Gb/s 6x plug");
        else
            snprintf(buff, buff_len, "Multifunction 12 Gb/s 6x unshielded "
                     "plug (SFF-8639)");
        break;
    case 0x2c:
        if (abridged)
            snprintf(buff, buff_len, "SAS MultiLink Drive backplane "
                     "receptacle");
        else
            snprintf(buff, buff_len, "SAS MultiLink Drive backplane "
                     "receptacle (SFF-8630)");
        break;
    case 0x2d:
        if (abridged)
            snprintf(buff, buff_len, "SAS MultiLink Drive backplane plug");
        else
            snprintf(buff, buff_len, "SAS MultiLink Drive backplane plug "
                     "(SFF-8630)");
        break;
    case 0x2e:
        if (abridged)
            snprintf(buff, buff_len, "Reserved");
        else
            snprintf(buff, buff_len, "Reserved for internal connectors to "
                     "end device");
        break;
    case 0x2f:
        if (abridged)
            snprintf(buff, buff_len, "SAS virtual connector");
        else
            snprintf(buff, buff_len, "SAS virtual connector [max 1 phy]");
        break;
    case 0x3f:
        if (abridged)
            snprintf(buff, buff_len, "VS internal connector");
        else
            snprintf(buff, buff_len, "%s internal connector", vs_s);
        break;
    case 0x40:
        if (abridged)
            snprintf(buff, buff_len, "SAS high density drive backplane "
                     "receptacle");
        else
            snprintf(buff, buff_len, "SAS high density drive backplane "
                     "receptacle (SFF-8631) [max 8 phys]");
        break;
    case 0x41:
        if (abridged)
            snprintf(buff, buff_len, "SAS high density drive backplane "
                     "plug");
        else
            snprintf(buff, buff_len, "SAS high density drive backplane "
                     "plug (SFF-8631) [max 8 phys]");
        break;
    default:
        if (conn_type < 0x10)
            snprintf(buff, buff_len, "unknown external connector type: 0x%x",
                     conn_type);
        else if (conn_type < 0x20)
            snprintf(buff, buff_len, "unknown internal wide connector type: "
                     "0x%x", conn_type);
        else if (conn_type < 0x3f)
            snprintf(buff, buff_len, "%s for internal connector, type: 0x%x",
                     rsv_s, conn_type);
        else if (conn_type < 0x70)
            snprintf(buff, buff_len, "%s connector type: 0x%x", rsv_s,
                     conn_type);
        else if (conn_type < 0x80)
            snprintf(buff, buff_len, "%s connector type: 0x%x", vs_s,
                     conn_type);
        else    /* conn_type is a 7 bit field, so this is impossible */
            snprintf(buff, buff_len, "unexpected connector type: 0x%x",
                     conn_type);
        break;
    }
    return buff;
}

/* 'Fan speed factor' new in ses4r04 */
static int
calc_fan_speed(int fan_speed_factor, int actual_fan_speed)
{
    switch (fan_speed_factor) {
    case 0:
        return actual_fan_speed * 10;
    case 1:
        return (actual_fan_speed * 10) + 20480;
    case 2:
        return actual_fan_speed * 100;
    default:
        break;
    }
    return -1;        /* something is wrong */
}

static const char * elem_status_code_desc[] = {
    "Unsupported", "OK", "Critical", "Noncritical",
    "Unrecoverable", "Not installed", "Unknown", "Not available",
    "No access allowed", "reserved [9]", "reserved [10]", "reserved [11]",
    "reserved [12]", "reserved [13]", "reserved [14]", "reserved [15]",
};

static const char * actual_speed_desc[] = {
    "stopped", "at lowest speed", "at second lowest speed",
    "at third lowest speed", "at intermediate speed",
    "at third highest speed", "at second highest speed", "at highest speed"
};

static const char * nv_cache_unit[] = {
    "Bytes", "KiB", "MiB", "GiB"
};

static const char * invop_type_desc[] = {
    "SEND DIAGNOSTIC page code error", "SEND DIAGNOSTIC page format error",
    "Reserved", "Vendor specific error"
};

static const char * const display_mode_status[] = {
    "ES process controlling display; display element control of the display "
    "not supported",
    "ES process controlling display; display element control of the display "
    "is supported",
    "The display is being controlled based on the Display element",
    "reserved",
};

static int
enc_status_helper(const char * pad, const uint8_t * statp, int etype,
                  bool abridged, struct opts_t * op, sgj_opaque_p jop,
                  char * a, int alen)
{
    bool nofilter = ! op->do_filter;
    uint8_t s0, s1, s2, s3;
    int res, d, m, n, ct, tpc, fsf, afs, dms, ttpc, voltage, amperage;
    const char * ccp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    char b[144];
    static const int blen = sizeof(b);

    n = 0;
    if (alen > 0)
        a[0] = '\0';
    s0 = statp[0];
    s1 = statp[1];
    s2 = statp[2];
    s3 = statp[3];
    if (op->inner_hex || op->no_config) {
        n += sg_scnpr(a + n, alen - n, "%s%02x %02x %02x %02x\n", pad,
                      s0, s1, s2, s3);
        if (jsp->pr_as_json)
            sgj_js_nv_hex_bytes(jsp, jop, "status_element", statp, 4);
        return n;
    }
    if (! abridged) {
        int status = s0 & 0xf;

        ccp = elem_status_code_desc[status];
        n += sg_scnpr(a + n, alen - n, "%sPredicted failure=%d, Disabled=%d, "
                      "Swap=%d, status: %s\n", pad, !!(s0 & 0x40),
                      !!(s0 & 0x20), !!(s0 & 0x10), ccp);
        sgj_js_nv_ihexstr_nex(jsp, jop, "prdfail", !!(s0 & 0x40), false,
                              NULL, NULL, "PReDicted FAILure");
        sgj_js_nv_i(jsp, jop, "disabled", !!(s0 & 0x20));
        sgj_js_nv_ihexstr_nex(jsp, jop, "swap", !!(s0 & 0x10), false,
                              NULL, NULL, "SWAPped: remove and inserted");
        sgj_js_nv_ihexstr_nex(jsp, jop, "status", status, true, NULL, ccp,
                              NULL);
    }

    switch (etype) { /* element type code */
    case UNSPECIFIED_ETC:
        if (op->verbose)
            n += sg_scnpr(a + n, alen - n, "%sstatus in hex: %02x %02x %02x "
                          "%02x\n", pad, s0, s1, s2, s3);
        break;
    case DEVICE_ETC:
        if (ARRAY_STATUS_DPC == op->page_code) {  /* obsolete after SES-1 */
            if (nofilter || (0xf0 & s1))
                n += sg_scnpr(a + n, alen - n, "%sOK=%d, Reserved device=%d, "
                              "Hot spare=%d, Cons check=%d\n", pad,
                              !!(s1 & 0x80), !!(s1 & 0x40), !!(s1 & 0x20),
                              !!(s1 & 0x10));
            if (nofilter || (0xf & s1))
                n += sg_scnpr(a + n, alen - n, "%sIn crit array=%d, In "
                              "failed array=%d, Rebuild/remap=%d, R/R "
                              "abort=%d\n", pad, !!(s1 & 0x8), !!(s1 & 0x4),
                              !!(s1 & 0x2), !!(s1 & 0x1));
            if (nofilter || ((0x46 & s2) || (0x8 & s3)))
                n += sg_scnpr(a + n, alen - n, "%sDo not remove=%d, RMV=%d, "
                              "Ident=%d, Enable bypass A=%d\n", pad,
                              !!(s2 & 0x40), !!(s2 & 0x4), !!(s2 & 0x2),
                              !!(s3 & 0x8));
            if (nofilter || (0x7 & s3))
                n += sg_scnpr(a + n, alen - n, "%sEnable bypass B=%d, "
                              "Bypass A enabled=%d, Bypass B enabled=%d\n",
                              pad, !!(s3 & 0x4), !!(s3 & 0x2), !!(s3 & 0x1));
            break;
        }
        n += sg_scnpr(a + n, alen - n, "%sSlot address: %d\n", pad, s1);
        if (nofilter || (0xe0 & s2))
            n += sg_scnpr(a + n, alen - n, "%sApp client bypassed A=%d, Do "
                          "not remove=%d, Enc bypassed A=%d\n", pad,
                          !!(s2 & 0x80), !!(s2 & 0x40), !!(s2 & 0x20));
        if (nofilter || (0x1c & s2))
            n += sg_scnpr(a + n, alen - n, "%sEnc bypassed B=%d, Ready to "
                          "insert=%d, RMV=%d, Ident=%d\n", pad, !!(s2 & 0x10),
                          !!(s2 & 0x8), !!(s2 & 0x4), !!(s2 & 0x2));
        if (nofilter || ((1 & s2) || (0xe0 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sReport=%d, App client bypassed "
                          "B=%d, Fault sensed=%d, Fault requested=%d\n", pad,
                          !!(s2 & 0x1), !!(s3 & 0x80), !!(s3 & 0x40),
                          !!(s3 & 0x20));
        if (nofilter || (0x1e & s3))
            n += sg_scnpr(a + n, alen - n, "%sDevice off=%d, Bypassed A=%d, "
                          "Bypassed B=%d, Device bypassed A=%d\n", pad,
                          !!(s3 & 0x10), !!(s3 & 0x8), !!(s3 & 0x4),
                          !!(s3 & 0x2));
        if (nofilter || (0x1 & s3))
            n += sg_scnpr(a + n, alen - n, "%sDevice bypassed B=%d\n", pad,
                          !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex(jsp, jop, "slot_address", s1);
            sgj_js_nv_i(jsp, jop, "app_client_bypassed_a", !!(s2 & 0x80));
            sgj_js_nv_i(jsp, jop, "do_not_remove", !!(s2 & 0x40));
            sgj_js_nv_i(jsp, jop, "enclosure_bypassed_a", !!(s2 & 0x20));
            sgj_js_nv_i(jsp, jop, "enclosure_bypassed_b", !!(s2 & 0x10));
            sgj_js_nv_i(jsp, jop, "ready_to_insert", !!(s2 & 0x8));
            sgj_js_nv_ihex_nex(jsp, jop, "rmv", !!(s2 & 0x4), false,
                               "remove");
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s2 & 0x2), false,
                               "identify (visual indicator)");
            sgj_js_nv_ihex_nex(jsp, jop, "report", !!(s2 & 0x1), false,
                               "es dpage accessed via this device");
            sgj_js_nv_i(jsp, jop, "app_client_bypassed_b", !!(s3 & 0x80));
            sgj_js_nv_ihex_nex(jsp, jop, "fault_sensed", !!(s3 & 0x40), false,
                               "FAULT condition detected (SENSED)");
            sgj_js_nv_ihex_nex(jsp, jop, "fault_reqstd", !!(s3 & 0x20), false,
                       "FAULT REQueSTeD (by rqst_fault in control element)");
            sgj_js_nv_ihex_nex(jsp, jop, "device_off", !!(s3 & 0x10), false,
                               "(0 --> device is ON)");
            sgj_js_nv_i(jsp, jop, "bypassed_a", !!(s3 & 0x8));
            sgj_js_nv_i(jsp, jop, "bypassed_b", !!(s3 & 0x4));
            sgj_js_nv_i(jsp, jop, "device_bypassed_a", !!(s3 & 0x2));
            sgj_js_nv_i(jsp, jop, "device_bypassed_b", !!(s3 & 0x1));
        }
        break;
    case POWER_SUPPLY_ETC:
        if (nofilter || ((0xc0 & s1) || (0xc & s2))) {
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Do not remove=%d, DC "
                          "overvoltage=%d, DC undervoltage=%d\n", pad,
                          !!(s1 & 0x80), !!(s1 & 0x40), !!(s2 & 0x8),
                          !!(s2 & 0x4));
        }
        if (nofilter || ((0x2 & s2) || (0xf0 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sDC overcurrent=%d, Hot "
                          "swap=%d, Fail=%d, Requested on=%d, Off=%d\n", pad,
                          !!(s2 & 0x2), !!(s3 & 0x80), !!(s3 & 0x40),
                          !!(s3 & 0x20), !!(s3 & 0x10));
        if (nofilter || (0xf & s3))
            n += sg_scnpr(a + n, alen - n, "%sOvertmp fail=%d, Temperature "
                          "warn=%d, AC fail=%d, DC fail=%d\n", pad,
                          !!(s3 & 0x8), !!(s3 & 0x4), !!(s3 & 0x2),
                          !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "do_not_remove", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "dc_over_voltage", !!(s2 & 0x8));
            sgj_js_nv_i(jsp, jop, "dc_under_voltage", !!(s2 & 0x4));
            sgj_js_nv_i(jsp, jop, "dc_over_current", !!(s2 & 0x2));
            sgj_js_nv_ihex_nex(jsp, jop, "hot_swap", !!(s3 & 0x80), false,
                               "whether power supply can be hot swapped "
                               "without halting subenclosure");
            sgj_js_nv_i(jsp, jop, "fail", !!(s3 & 0x40));
            sgj_js_nv_i(jsp, jop, "rqsted_on", !!(s3 & 0x20));
            sgj_js_nv_i(jsp, jop, "off", !!(s3 & 0x10));
            sgj_js_nv_i(jsp, jop, "overtmp_fail", !!(s3 & 0x8));
            sgj_js_nv_i(jsp, jop, "temp_warn", !!(s3 & 0x4));
            sgj_js_nv_i(jsp, jop, "ac_fail", !!(s3 & 0x2));
            sgj_js_nv_i(jsp, jop, "dc_fail", !!(s3 & 0x1));

        }
        break;
    case COOLING_ETC:
        if (nofilter || ((0xc0 & s1) || (0xf0 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Do not remove=%d, "
                          "Hot swap=%d, Fail=%d, Requested on=%d\n", pad,
                          !!(s1 & 0x80), !!(s1 & 0x40), !!(s3 & 0x80),
                          !!(s3 & 0x40), !!(s3 & 0x20));
        fsf = (s1 >> 3) & 0x3;
        afs = ((0x7 & s1) << 8) + s2;
        n += sg_scnpr(a + n, alen - n, "%sOff=%d, Actual speed=%d rpm, Fan "
                      "%s\n", pad, !!(s3 & 0x10), calc_fan_speed(fsf, afs),
                      actual_speed_desc[7 & s3]);
        if (op->verbose > 1)    /* show real field values */
            n += sg_scnpr(a + n, alen - n, "%s  [Fan_speed_factor=%d, "
                          "Actual_fan_speed=%d]\n", pad, (s1 >> 3) & 0x3,
                          ((0x7 & s1) << 8) + s2);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "do_not_remove", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "fan_speed_factor", fsf);
            sgj_js_nv_ihex_nex(jsp, jop, "actual_fan_speed", afs, false,
                               "see calculated_fan_speed for actual speed");
            sgj_js_nv_ihex_nex(jsp, jop, "calculated_fan_speed",
                               calc_fan_speed(fsf, afs), false,
                               "[unit: rpm]");
            sgj_js_nv_ihex_nex(jsp, jop, "hot_swap", !!(s3 & 0x80), false,
                               "whether fan can be hot swapped without "
                               "halting subenclosure");
            sgj_js_nv_i(jsp, jop, "fail", !!(s3 & 0x40));
            sgj_js_nv_i(jsp, jop, "rqsted_on", !!(s3 & 0x20));
            sgj_js_nv_i(jsp, jop, "off", !!(s3 & 0x10));
            sgj_js_nv_ihexstr(jsp, jop, "actual_fan_code", 7 & s3, NULL,
                              actual_speed_desc[7 & s3]);
        }
        break;
    case TEMPERATURE_ETC:     /* temperature sensor */
        if (nofilter || ((0xc0 & s1) || (0xf & s3))) {
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, OT "
                          "failure=%d, OT warning=%d, UT failure=%d\n", pad,
                          !!(s1 & 0x80), !!(s1 & 0x40), !!(s3 & 0x8),
                          !!(s3 & 0x4), !!(s3 & 0x2));
            n += sg_scnpr(a + n, alen - n, "%sUT warning=%d\n", pad,
                          !!(s3 & 0x1));
        }
        if (s2)
            n += sg_scnpr(a + n, alen - n, "%sTemperature=%d C\n", pad,
                          (int)s2 - TEMPERAT_OFF);
        else
            n += sg_scnpr(a + n, alen - n, "%sTemperature: <%s>\n", pad,
                          rsv_s);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_ihex_nex(jsp, jop, "offset_for_reference_temperature",
                               s1 & 0x7, false,
                               "offset below high warning threshold");
            snprintf(b, blen, "%d C", (int)s2 - 20);
            sgj_js_nv_ihexstr_nex(jsp, jop, "temperature", s2, false,
                                  NULL, b, "meaning is (value - 20)");
            sgj_js_nv_i(jsp, jop, "rqsted_override", !!(s3 & 0x80));
            sgj_js_nv_i(jsp, jop, "ot_failure", !!(s3 & 0x8));
            sgj_js_nv_i(jsp, jop, "ot_warning", !!(s3 & 0x4));
            sgj_js_nv_i(jsp, jop, "ut_failure", !!(s3 & 0x2));
            sgj_js_nv_i(jsp, jop, "ut_warning", !!(s3 & 0x1));
        }
        break;
    case DOOR_ETC:      /* OPEN field added in ses3r05 */
        if (nofilter || ((0xc0 & s1) || (0x1 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Open=%d, "
                          "Unlock=%d\n", pad, !!(s1 & 0x80), !!(s1 & 0x40),
                          !!(s3 & 0x2), !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "open", !!(s3 & 0x2));
            sgj_js_nv_i(jsp, jop, "unlocked", !!(s3 & 0x1));
        }
        break;
    case AUD_ALARM_ETC:     /* audible alarm */
        if (nofilter || ((0xc0 & s1) || (0xd0 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Request "
                          "mute=%d, Mute=%d, Remind=%d\n", pad, !!(s1 & 0x80),
                          !!(s1 & 0x40), !!(s3 & 0x80), !!(s3 & 0x40),
                          !!(s3 & 0x10));
        if (nofilter || (0xf & s3))
            n += sg_scnpr(a + n, alen - n, "%sTone indicator: Info=%d, "
                          "Non-crit=%d, Crit=%d, Unrecov=%d\n", pad,
                          !!(s3 & 0x8), !!(s3 & 0x4), !!(s3 & 0x2),
                          !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "rqst_mute", !!(s3 & 0x80));
            sgj_js_nv_i(jsp, jop, "muted", !!(s3 & 0x40));
            sgj_js_nv_i(jsp, jop, "remind", !!(s3 & 0x10));
            sgj_js_nv_ihex_nex(jsp, jop, "info", !!(s3 & 0x8), false,
                               "INFOrmation condition tone urgency");
            sgj_js_nv_ihex_nex(jsp, jop, "non_crit", !!(s3 & 0x4), false,
                               "NONCRITical condition tone urgency");
            sgj_js_nv_ihex_nex(jsp, jop, "crit", !!(s3 & 0x2), false,
                               "critical condition tone urgency");
            sgj_js_nv_ihex_nex(jsp, jop, "unrecov", !!(s3 & 0x1), false,
                               "unrecoverable condition tone urgency");
        }
        break;
    case ENC_SCELECTR_ETC: /* enclosure services controller electronics */
        if (nofilter || (0xe0 & s1) || (0x1 & s2) || (0x80 & s3))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Do not "
                          "remove=%d, Report=%d, Hot swap=%d\n", pad,
                          !!(s1 & 0x80), !!(s1 & 0x40), !!(s1 & 0x20),
                          !!(s2 & 0x1), !!(s3 & 0x80));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "do_not_remove", !!(s2 & 0x20));
            sgj_js_nv_ihex_nex(jsp, jop, "rmv", !!(s2 & 0x10), false,
                               "prepared for removal");
            sgj_js_nv_i(jsp, jop, "report", !!(s2 & 0x1));
            sgj_js_nv_ihex_nex(jsp, jop, "hot_swap", !!(s3 & 0x80), false,
                               "whether controller electronics can be hot "
                               "swapped without halting subenclosure");
        }
        break;
    case SCC_CELECTR_ETC:     /* SCC controller electronics */
        if (nofilter || ((0xc0 & s1) || (0x1 & s2)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Report=%d\n",
                          pad, !!(s1 & 0x80), !!(s1 & 0x40), !!(s2 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "report", !!(s2 & 0x1));
        }
        break;
    case NV_CACHE_ETC:     /* Non volatile cache */
        ccp = nv_cache_unit[s1 & 0x3];
        res = sg_get_unaligned_be16(statp + 2);
        n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Size "
                      "multiplier=%d, Non volatile cache size=0x%x\n", pad,
                      !!(s1 & 0x80), !!(s1 & 0x40), (s1 & 0x3), res);
        n += sg_scnpr(a + n, alen - n, "%sHence non volatile cache size: %d "
                      "%s\n", pad, res, ccp);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_ihexstr(jsp, jop, "size_multiplier", 0x3 & s1, NULL,
                              ccp);
            snprintf(b, blen, "%d %s", res, ccp);
            sgj_js_nv_ihexstr(jsp, jop, "nonvolatile_cache_size", res,
                              NULL, b);
        }
        break;
    case INV_OP_REASON_ETC:   /* Invalid operation reason */
        res = ((s1 >> 6) & 3);
        ccp = invop_type_desc[res];
        n += sg_scnpr(a + n, alen - n, "%sInvop type=%d   %s\n", pad, res,
                      ccp);
        if (jsp->pr_as_json)
            sgj_js_nv_ihexstr(jsp, jop, "invop_type", res, NULL, ccp);
        ccp = vs_s;

        switch (res) {
        case 0:
            n += sg_scnpr(a + n, alen - n, "%sPage not supported=%d\n", pad,
                          (s1 & 1));
            if (jsp->pr_as_json)
                sgj_js_nv_i(jsp, jop, "page_not_supported", !!(s1 & 0x1));
            break;
        case 1:
            res = sg_get_unaligned_be16(statp + 2);
            n += sg_scnpr(a + n, alen - n, "%sByte offset=%d, bit "
                          "number=%d\n", pad, res, (s1 & 7));
            if (jsp->pr_as_json) {
                sgj_js_nv_i(jsp, jop, "bit_number", !!(s1 & 0x7));
                sgj_js_nv_i(jsp, jop, "byte_offset", res);
            }
            break;
        case 2:
            ccp = rsv_s;
            /* fallthrough fall-through */
            // [[fallthrough]];
            /* FALLTHRU */
        case 3:
            n += sg_scnpr(a + n, alen - n, "%s%s, last 3 bytes (hex): %02x "
                          "%02x %02x\n", pad, ccp, s1, s2, s3);
            if (jsp->pr_as_json)
                sgj_js_nv_s_len_chk(jsp, jop, "bytes_1_2_3", statp + 1, 3);
            break;
        }
        break;
    case UI_POWER_SUPPLY_ETC:   /* Uninterruptible power supply */
        if (0 == s1)
            n += sg_scnpr(a + n, alen - n, "%sBattery status: discharged or "
                          "unknown\n", pad);
        else if (255 == s1)
            n += sg_scnpr(a + n, alen - n, "%sBattery status: 255 or more "
                          "minutes remaining\n", pad);
        else
            n += sg_scnpr(a + n, alen - n, "%sBattery status: %d minutes "
                          "remaining\n", pad, s1);
        if (nofilter || (0xf8 & s2))
            n += sg_scnpr(a + n, alen - n, "%sAC low=%d, AC high=%d, AC "
                          "qual=%d, AC fail=%d, DC fail=%d\n", pad,
                          !!(s2 & 0x80), !!(s2 & 0x40), !!(s2 & 0x20),
                          !!(s2 & 0x10), !!(s2 & 0x8));
        if (nofilter || ((0x7 & s2) || (0xe3 & s3))) {
            n += sg_scnpr(a + n, alen - n, "%sUPS fail=%d, Warn=%d, Intf "
                          "fail=%d, Ident=%d, Fail=%d, Do not remove=%d\n",
                          pad, !!(s2 & 0x4), !!(s2 & 0x2), !!(s2 & 0x1),
                          !!(s3 & 0x80), !!(s3 & 0x40), !!(s3 & 0x20));
            n += sg_scnpr(a + n, alen - n, "%sBatt fail=%d, BPF=%d\n", pad,
                          !!(s3 & 0x2), !!(s3 & 0x1));
        }
        if (jsp->pr_as_json) {
            sgj_js_nv_ihexstr(jsp, jop, "battery_status", s1, NULL,
                              (0 == s1) ? "discharged or unknown" :
                      "at least this many minutes of capacity remaining");
            sgj_js_nv_i(jsp, jop, "ac_lo", !!(s2 & 0x80));
            sgj_js_nv_i(jsp, jop, "ac_hi", !!(s2 & 0x40));
            sgj_js_nv_i(jsp, jop, "ac_qual", !!(s2 & 0x20));
            sgj_js_nv_i(jsp, jop, "ac_fail", !!(s2 & 0x10));
            sgj_js_nv_i(jsp, jop, "dc_fail", !!(s2 & 0x8));
            sgj_js_nv_i(jsp, jop, "ups_fail", !!(s2 & 0x4));
            sgj_js_nv_i(jsp, jop, "warn", !!(s2 & 0x2));
            sgj_js_nv_ihex_nex(jsp, jop, "intf_fail", !!(s2 & 0x1), false,
                               "interface to UI power supply failure");
        }
        break;
    case DISPLAY_ETC:   /* Display (ses2r15) */
        dms = s1 & 0x3;
        if (nofilter || (0xc0 & s1)) {
            m = sg_scnpr(b, blen, "%sIdent=%d, Fail=%d, Display mode "
                         "status=%d", pad, !!(s1 & 0x80), !!(s1 & 0x40), dms);
            if ((1 == dms) || (2 == dms)) {
                uint16_t dcs = sg_get_unaligned_be16(statp + 2);

                m += sg_scnpr(b + m, blen - m, ", Display character "
                              "status=0x%x", dcs);
                if (s2 && (0 == s3))
                    sg_scnpr(b + m, blen - m, " ['%c']", s2);
            }
            n += sg_scnpr(a + n, alen - n, "%s\n", b);
        }
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_ihexstr(jsp, jop, "display_mode_status", dms, NULL,
                              display_mode_status[dms]);
            sgj_js_nv_s_len_chk(jsp, jop, "display_character_status",
                                statp + 2, 2);
        }
        break;
    case KEY_PAD_ETC:   /* Key pad entry */
        if (nofilter || (0xc0 & s1))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d\n", pad,
                          !!(s1 & 0x80), !!(s1 & 0x40));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
        }
        break;
    case ENCLOSURE_ETC:
        tpc = ((s2 >> 2) & 0x3f);
        if (nofilter || ((0x80 & s1) || tpc || (0x2 & s2)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Time until power "
                          "cycle=%d, Failure indication=%d\n", pad,
                          !!(s1 & 0x80), tpc, !!(s2 & 0x2));
        d = ((s3 >> 2) & 0x3f);
        if (nofilter || (0x1 & s2) || tpc || d)
            n += sg_scnpr(a + n, alen - n, "%sWarning indication=%d, "
                          "Requested power off duration=%d\n", pad,
                          !!(s2 & 0x1), d);
        if (nofilter || (0x3 & s3))
            n += sg_scnpr(a + n, alen - n, "%sFailure requested=%d, Warning "
                          "requested=%d\n", pad, !!(s3 & 0x2), !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            ttpc = s2 >> 2;
            if (0 == ttpc)
                ccp = "No power cycle scheduled";
            else if (0x3f == ttpc)
                ccp = "Power cycle in zero minutes";
            else if (ttpc >= 0x3d)
                ccp = rsv_s;
            else
                ccp = "Power cycle in indicated number of minutes";
            sgj_js_nv_ihexstr(jsp, jop, "time_to_power_cycle", ttpc,
                              NULL, ccp);
            sgj_js_nv_i(jsp, jop, "failure_indication", !!(s2 & 0x2));
            sgj_js_nv_i(jsp, jop, "warning_indication", !!(s2 & 0x1));
            ttpc = s1 >> 2;     /* should be rpod */
            if (0 == ttpc)
                ccp = "No power cycle scheduled";
            else if (0x3f == ttpc)
                ccp = "Power scheduled to be off until manually restored";
            else if (ttpc >= 0x3d)
                ccp = rsv_s;
            else
                ccp = "Power scheduled to be off for indicated number of "
                      "minutes";
            sgj_js_nv_ihexstr(jsp, jop, "requested_power_off_duration",
                              ttpc, NULL, ccp);
            sgj_js_nv_i(jsp, jop, "failure_requested", !!(s3 & 0x2));
            sgj_js_nv_i(jsp, jop, "warning_requested", !!(s3 & 0x1));
        }
        break;
    case SCSI_PORT_TRAN_ETC:   /* SCSI port/transceiver */
        if (nofilter || ((0xc0 & s1) || (0x1 & s2) || (0x13 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Report=%d, "
                          "Disabled=%d, Loss of link=%d, Xmit fail=%d\n",
                          pad, !!(s1 & 0x80), !!(s1 & 0x40), !!(s2 & 0x1),
                          !!(s3 & 0x10), !!(s3 & 0x2), !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "report", !!(s2 & 0x1));
            sgj_js_nv_i(jsp, jop, "disabled", !!(s3 & 0x10));
            sgj_js_nv_ihex_nex(jsp, jop, "lol", !!(s3 & 0x2), false,
                               "Loss Of Link");
            sgj_js_nv_ihex_nex(jsp, jop, "xmit_fail", !!(s3 & 0x1), false,
                               "transmitter failure");
        }
        break;
    case LANGUAGE_ETC:
        m = sg_get_unaligned_be16(statp + 2);
        snprintf(b, blen, "%sIdent=%d, ", pad, !!(s1 & 0x80));
        if (0 == m)
            n += sg_scnpr(a + n, alen - n, "%sLanguage: English\n", b);
        else
            n += sg_scnpr(a + n, alen - n, "%sLanguage code: %.2s\n", b,
                      (const char *)statp + 2);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            if (m > 0) {
                snprintf(b, blen, "%.2s", (const char *)statp + 2);
                ccp = b;
            } else
                ccp = "en";
            sgj_js_nv_ihexstr(jsp, jop, "language_code", m, NULL, ccp);
        }
        break;
    case COMM_PORT_ETC:   /* Communication port */
        if (nofilter || ((0xc0 & s1) || (0x1 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, "
                          "Disabled=%d\n", pad, !!(s1 & 0x80), !!(s1 & 0x40),
                          !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "disabled", !!(s3 & 0x1));
        }
        break;
    case VOLT_SENSOR_ETC:   /* Voltage sensor */
        if (nofilter || (0xcf & s1)) {
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d,  Warn "
                          "Over=%d, Warn Under=%d, Crit Over=%d\n", pad,
                          !!(s1 & 0x80), !!(s1 & 0x40), !!(s1 & 0x8),
                          !!(s1 & 0x4), !!(s1 & 0x2));
            n += sg_scnpr(a + n, alen - n, "%sCrit Under=%d\n", pad,
                          !!(s1 & 0x1));
        }
        voltage = sg_get_unaligned_be16(statp + 2); /* unit: 10 mV */
        n += sg_scnpr(a + n, alen - n, "%sVoltage: %d.%02d Volts\n", pad,
                      voltage / 100, voltage % 100);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "warn_over", !!(s1 & 0x8));
            sgj_js_nv_i(jsp, jop, "warn_under", !!(s1 & 0x4));
            sgj_js_nv_i(jsp, jop, "crit_over", !!(s1 & 0x2));
            sgj_js_nv_i(jsp, jop, "crit_under", !!(s1 & 0x1));
            jo2p = sgj_named_subobject_r(jsp, jop, "voltage");
            sgj_js_nv_ihex_nex(jsp, jo2p, "raw_value", voltage, false,
                               "[unit: 10 milliVolts]");
            snprintf(b, blen, "%d.%02d", voltage / 100, voltage % 100);
            sgj_js_nv_s(jsp, jo2p, "value_in_volts", b);
        }
        break;
    case CURR_SENSOR_ETC:   /* Current sensor */
        if (nofilter || (0xca & s1))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Warn "
                          "Over=%d, Crit Over=%d\n", pad, !!(s1 & 0x80),
                          !!(s1 & 0x40), !!(s1 & 0x8), !!(s1 & 0x2));
        amperage = sg_get_unaligned_be16(statp + 2); /* unit: 10 mV */
        n += sg_scnpr(a + n, alen - n, "%sCurrent: %d.%02d Amps\n", pad,
                      amperage / 100, amperage % 100);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "warn_over", !!(s1 & 0x8));
            sgj_js_nv_i(jsp, jop, "crit_over", !!(s1 & 0x2));
            jo2p = sgj_named_subobject_r(jsp, jop, "current");
            sgj_js_nv_ihex_nex(jsp, jo2p, "raw_value", amperage, false,
                               "[unit: 10 milliAmps]");
            snprintf(b, blen, "%d.%02d", amperage / 100, amperage % 100);
            sgj_js_nv_s(jsp, jo2p, "value_in_amps", b);
        }
        break;
    case SCSI_TPORT_ETC:   /* SCSI target port */
        if (nofilter || ((0xc0 & s1) || (0x1 & s2) || (0x1 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Report=%d, "
                          "Enabled=%d\n", pad, !!(s1 & 0x80), !!(s1 & 0x40),
                          !!(s2 & 0x1), !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "report", !!(s2 & 0x1));
            sgj_js_nv_i(jsp, jop, "enabled", !!(s3 & 0x1));
        }
        break;
    case SCSI_IPORT_ETC:   /* SCSI initiator port */
        if (nofilter || ((0xc0 & s1) || (0x1 & s2) || (0x1 & s3)))
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Report=%d, "
                          "Enabled=%d\n", pad, !!(s1 & 0x80), !!(s1 & 0x40),
                          !!(s2 & 0x1), !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "report", !!(s2 & 0x1));
            sgj_js_nv_i(jsp, jop, "enabled", !!(s3 & 0x1));
        }
        break;
    case SIMPLE_SUBENC_ETC:   /* Simple subenclosure */
        n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d, Short %s: "
                      "0x%x\n", pad, !!(s1 & 0x80), !!(s1 & 0x40), es_s, s3);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
            sgj_js_nv_i(jsp, jop, "short_enclosure_status", s3);
        }
        break;
    case ARRAY_DEV_ETC:   /* Array device */
        if (nofilter || (0xf0 & s1))
            n += sg_scnpr(a + n, alen - n, "%sOK=%d, Reserved device=%d, Hot "
                          "spare=%d, Cons check=%d\n", pad, !!(s1 & 0x80),
                          !!(s1 & 0x40), !!(s1 & 0x20), !!(s1 & 0x10));
        if (nofilter || (0xf & s1))
            n += sg_scnpr(a + n, alen - n, "%sIn crit array=%d, In failed "
                          "array=%d, Rebuild/remap=%d, R/R abort=%d\n", pad,
                          !!(s1 & 0x8), !!(s1 & 0x4), !!(s1 & 0x2),
                          !!(s1 & 0x1));
        if (nofilter || (0xf0 & s2))
            n += sg_scnpr(a + n, alen - n, "%sApp client bypass A=%d, Do not "
                          "remove=%d, Enc bypass A=%d, Enc bypass B=%d\n",
                          pad, !!(s2 & 0x80), !!(s2 & 0x40), !!(s2 & 0x20),
                          !!(s2 & 0x10));
        if (nofilter || (0xf & s2))
            n += sg_scnpr(a + n, alen - n, "%sReady to insert=%d, RMV=%d, "
                          "Ident=%d, Report=%d\n", pad, !!(s2 & 0x8),
                          !!(s2 & 0x4), !!(s2 & 0x2), !!(s2 & 0x1));
        if (nofilter || (0xf0 & s3))
            n += sg_scnpr(a + n, alen - n, "%sApp client bypass B=%d, Fault "
                          "sensed=%d, Fault reqstd=%d, Device off=%d\n", pad,
                          !!(s3 & 0x80), !!(s3 & 0x40), !!(s3 & 0x20),
                          !!(s3 & 0x10));
        if (nofilter || (0xf & s3))
            n += sg_scnpr(a + n, alen - n, "%sBypassed A=%d, Bypassed B=%d, "
                          "Dev bypassed A=%d, Dev bypassed B=%d\n", pad,
                          !!(s3 & 0x8), !!(s3 & 0x4), !!(s3 & 0x2),
                          !!(s3 & 0x1));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_ok", !!(s1 & 0x80), false,
                               "ReQueST OKay, device ok indicator");
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_rsvd_device", !!(s1 & 0x40),
                               false, "ReQueST ReSerVeD device (indicator)");
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_hot_spare", !!(s1 & 0x20),
                               false, "ReQueST HOT SPARE (indicator)");
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_cons_check", !!(s1 & 0x10),
                               false,
                               "ReQueST CONSistency CHECK (in progress)");
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_in_crit_array", !!(s1 & 0x8),
                               false,
                               "ReQueST IN CRITical ARRAY (indicator)");
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_in_failed_array", !!(s1 & 0x4),
                               false, "ReQueST IN FAILED ARRAY (indicator)");
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_rebuild_remap", !!(s1 & 0x2),
                               false, "ReQueST REBUILD/REMAP (indicator)");
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_r_r_abort", !!(s1 & 2), false,
                               "ReQueST rebuild/remap aborted (indicator)");
            sgj_js_nv_ihex_nex(jsp, jop, "rqst_active", !!(s2 & 0x80), false,
                               "ReQueST rebuild/remap aborted (indicator)");
            sgj_js_nv_i(jsp, jop, "app_client_bypassed_a", !!(s2 & 0x80));
            sgj_js_nv_i(jsp, jop, "do_not_remove", !!(s2 & 0x40));
            sgj_js_nv_i(jsp, jop, "enclosure_bypassed_a", !!(s2 & 0x20));
            sgj_js_nv_i(jsp, jop, "enclosure_bypassed_b", !!(s2 & 0x10));
            sgj_js_nv_i(jsp, jop, "ready_to_insert", !!(s2 & 0x8));
            sgj_js_nv_ihex_nex(jsp, jop, "rmv", !!(s2 & 0x4), false,
                               "remove");
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s2 & 0x2), false,
                               "identify (visual indicator)");
            sgj_js_nv_ihex_nex(jsp, jop, "report", !!(s2 & 0x1), false,
                               "es dpage accessed via this device");
            sgj_js_nv_i(jsp, jop, "app_client_bypassed_b", !!(s3 & 0x80));
            sgj_js_nv_ihex_nex(jsp, jop, "fault_sensed", !!(s3 & 0x40), false,
                               "FAULT condition detected (SENSED)");
            sgj_js_nv_ihex_nex(jsp, jop, "fault_reqstd", !!(s3 & 0x20), false,
                       "FAULT REQueSTeD (by rqst_fault in control element)");
            sgj_js_nv_ihex_nex(jsp, jop, "device_off", !!(s3 & 0x10), false,
                               "(0 --> device is ON)");
            sgj_js_nv_i(jsp, jop, "bypassed_a", !!(s3 & 0x8));
            sgj_js_nv_i(jsp, jop, "bypassed_b", !!(s3 & 0x4));
            sgj_js_nv_i(jsp, jop, "device_bypassed_a", !!(s3 & 0x2));
            sgj_js_nv_i(jsp, jop, "device_bypassed_b", !!(s3 & 0x1));
        }
        break;
    case SAS_EXPANDER_ETC:
        n += sg_scnpr(a + n, alen - n, "%sIdent=%d, Fail=%d\n", pad,
                      !!(s1 & 0x80), !!(s1 & 0x40));
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_i(jsp, jop, "fail", !!(s1 & 0x40));
        }
        break;
    case SAS_CONNECTOR_ETC:     /* OC (overcurrent) added in ses3r07 */
        ct = (s1 & 0x7f);
        if (abridged) {
            ccp = find_sas_connector_type(ct, true, b, blen);
            n += sg_scnpr(a + n, alen - n, "%s%s, pl=%u", pad, ccp, s2);
        } else {
            ccp = find_sas_connector_type(ct, false, b, blen);
            n += sg_scnpr(a + n, alen - n, "%sIdent=%d, %s\n", pad,
                          !!(s1 & 0x80), ccp);
            /* Mated added in ses3r10 */
            n += sg_scnpr(a + n, alen - n, "%sConnector physical link=0x%x, "
                          "Mated=%d, Fail=%d, OC=%d\n", pad, s2,
                          !!(s3 & 0x80), !!(s3 & 0x40), !!(s3 & 0x20));
        }
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex_nex(jsp, jop, "ident", !!(s1 & 0x80), false,
                               "identify (visual indicator)");
            sgj_js_nv_ihexstr(jsp, jop, "connector_type", ct, NULL, ccp);
            sgj_js_nv_i(jsp, jop, "connector_physical_link", s2);
            sgj_js_nv_i(jsp, jop, "mated", !!(s3 & 0x80));
            sgj_js_nv_i(jsp, jop, "fail", !!(s3 & 0x40));
            sgj_js_nv_ihex_nex(jsp, jop, "oc", !!(s3 & 0x20), false,
                               "OverCurrent on connector");
        }
        break;
    default:
        if (etype < 0x80)
            n += sg_scnpr(a + n, alen - n, "%sUnknown element type, status "
                          "in hex: %02x %02x %02x %02x\n", pad, s0, s1, s2,
                          s3);
        else
            n += sg_scnpr(a + n, alen - n, "%s%s element type, status in "
                          "hex: %02x %02x %02x %02x\n", pad, vs_s, s0, s1,
                          s2, s3);
        if (jsp->pr_as_json)
            sgj_js_nv_hex_bytes(jsp, jop, "unknown_element_type_bytes",
                                statp, 4);
        break;
    }
    return n;
}

/* ENC_STATUS_DPC  <"es"> [0x2]
 * Display enclosure status diagnostic page. */
static void
enc_status_sdp(const struct th_es_t * tesp, uint32_t ref_gen_code,
               const uint8_t * resp, int resp_len, struct opts_t * op,
               sgj_opaque_p jop)
{
    bool got1, match_ind_th, as_json;
    uint8_t es1, et;
    int j, k;
    uint32_t gen_code;
    const char * se_id_s;
    const uint8_t * bp;
    const uint8_t * last_bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jo4p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;
    const struct type_desc_hdr_t * tdhp = tesp ? tesp->th_base : NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * es_dp = "Enclosure Status diagnostic page";

    sgj_pr_hr(jsp, "%s\n", es_dp);
    if (resp_len < 4)
        goto truncated;
    as_json = jsp->pr_as_json;
    es1 = resp[1];
    sgj_pr_hr(jsp, "  INVOP=%d, INFO=%d, NON-CRIT=%d, CRIT=%d, UNRECOV=%d\n",
              !!(es1 & 0x10), !!(es1 & 0x8), !!(es1 & 0x4), !!(es1 & 0x2),
              !!(es1 & 0x1));
    if (as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(es_dp, b, blen));
        sgj_js_nv_ihexstr_nex(jsp, jop, "invop", !!(es1 & 0x10), false,
                              NULL, NULL, "INvalid Operation requested");
        sgj_js_nv_ihexstr_nex(jsp, jop, "info", !!(es1 & 0x8), false,
                              NULL, NULL, NULL);
        sgj_js_nv_ihexstr_nex(jsp, jop, "non_crit", !!(es1 & 0x4), false,
                              NULL, NULL, "NON-Critical condition");
        sgj_js_nv_ihexstr_nex(jsp, jop, "crit", !!(es1 & 0x4), false,
                              NULL, NULL, "CRITical condition");
        sgj_js_nv_ihexstr_nex(jsp, jop, "unrecov", !!(es1 & 0x4), false,
                              NULL, NULL, "UNRECOVerable condition");
    }
    last_bp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;

    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (tdhp && (ref_gen_code != gen_code)) {
        pr2serr("  <<%s>>\n", soec);
        return;
    }
    bp = resp + 8;
    sgj_pr_hr(jsp, "  %s:\n", sdl_s);
    if (as_json)
        jap = sgj_named_subarray_r(jsp, jop, sdl_sn);
    if (op->no_config) {
        int n = (resp_len - 8) / 4;

        if (op->verbose > 2)
            pr2serr("%s: %s\n", __func__, dwuti);
        for (j = 0; j < n; ++j, bp += 4) {
            if (as_json)
                jo2p = sgj_new_unattached_object_r(jsp);
            enc_status_helper("        ", bp, 0, false, op, jo2p, b, blen);
            sgj_pr_hr(jsp, "%s", b);
            if (as_json)
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
        return;
    }
    if (NULL == tesp) {
        pr2serr("%s: logic error, resp==NULL\n", __func__);
        return;
    }

    for (k = 0, got1 = false; k < tesp->num_ths; ++k, ++tdhp) {
        if ((bp + 3) > last_bp)
            goto truncated;

        jo2p = NULL;
        ja2p = NULL;
        et = tdhp->etype;
        se_id_s = (0 == tdhp->se_id) ? "primary" : NULL;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            sgj_pr_hr(jsp, "    %s: %s, %s: %d [ti=%d]\n", et_s,
                      etype_str(et, b, blen), si_ss, tdhp->se_id, k);
            if (op->inner_hex < 2)
                sgj_pr_hr(jsp, "      %s:\n", od_s);
            if (as_json) {
                jo2p = sgj_new_unattached_object_r(jsp);
                if (op->inner_hex < 2) {
                    sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et,
                                      NULL, etype_str(et, b, blen));
                    sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tdhp->se_id,
                                      NULL, se_id_s);
                } else
                    sgj_js_nv_hex_bytes(jsp, jo2p, "overall_status_element",
                                        bp, 4);
                jo3p = sgj_named_subobject_r(jsp, jo2p, od_sn);
                enc_status_helper("        ", bp, et, false, op,
                              jo3p, b, blen);
            } else {
                enc_status_helper("        ", bp, et, false, op,
                                  jo2p, b, blen);
                sgj_pr_hr(jsp, "%s", b);
            }
            got1 = true;
        }

        for (bp += 4, j = 0; j < tdhp->num_elements; ++j, bp += 4) {
            if (op->ind_given) {
                if ((! match_ind_th) || (! match_ind_indiv(j, op)))
                    continue;
            }
            if (op->inner_hex < 2)
                sgj_pr_hr(jsp, "      Element %d descriptor:\n", j);
            if (as_json) {
                if (NULL == jo2p) {
                    jo2p = sgj_new_unattached_object_r(jsp);
                    if (op->inner_hex < 2) {
                        sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et,
                                          NULL, etype_str(et, b, blen));
                        sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tdhp->se_id,
                                          NULL, se_id_s);
                    }
                }
                if (NULL == ja2p)
                    ja2p = sgj_named_subarray_r(jsp, jo2p, isel_sn);
                jo4p = sgj_new_unattached_object_r(jsp);
            }
            enc_status_helper("        ", bp, et, false, op, jo4p,
                              b, blen);
            sgj_pr_hr(jsp, "%s", b);
            if (as_json)
                sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo4p);
            got1 = true;
        }
        if (as_json && jo2p)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }           /* end of outer for loop */
    if (op->ind_given && (! got1)) {
        snprintf(b, blen, "      >>> no match on --index=%d,%d", op->ind_th,
                 op->ind_indiv);
        if (op->ind_indiv_last > op->ind_indiv)
            sgj_pr_hr(jsp, "%s-%d\n", b, op->ind_indiv_last);
        else
            sgj_pr_hr(jsp, "%s\n", b);
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

/* ARRAY_STATUS_DPC  <"as"> [0x6] obsolete
 * Display array status diagnostic page. */
static void
array_status_sdp(const struct th_es_t * tesp, uint32_t ref_gen_code,
                 const uint8_t * resp, int resp_len,
                 struct opts_t * op, sgj_opaque_p jop)
{
    bool got1, match_ind_th, as_json;
    uint8_t as1, et;
    int j, k, n;
    uint32_t gen_code;
    const char * se_id_s;
    const uint8_t * bp;
    const uint8_t * last_bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jo4p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;
    const struct type_desc_hdr_t * tdhp = tesp ? tesp->th_base : NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * const as_dp = "Array status diagnostic page";

    sgj_pr_hr(jsp, "%s:\n", as_dp);
    if (resp_len < 4)
        goto truncated;
    as1 = resp[1];
    as_json = jsp->pr_as_json;
    sgj_pr_hr(jsp, "  INVOP=%d, INFO=%d, NON-CRIT=%d, CRIT=%d, UNRECOV=%d\n",
              !!(as1 & 0x10), !!(as1 & 0x8), !!(as1 & 0x4), !!(as1 & 0x2),
              !!(as1 & 0x1));
    if (as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(as_dp, b, blen));
        sgj_js_nv_ihexstr_nex(jsp, jop, "invop", !!(as1 & 0x10), false,
                              NULL, NULL, "INvalid Operation requested");
        sgj_js_nv_ihexstr_nex(jsp, jop, "info", !!(as1 & 0x8), false,
                              NULL, NULL, NULL);
        sgj_js_nv_ihexstr_nex(jsp, jop, "non_crit", !!(as1 & 0x4), false,
                              NULL, NULL, "NON-Critical condition");
        sgj_js_nv_ihexstr_nex(jsp, jop, "crit", !!(as1 & 0x4), false,
                              NULL, NULL, "CRITical condition");
        sgj_js_nv_ihexstr_nex(jsp, jop, "unrecov", !!(as1 & 0x4), false,
                              NULL, NULL, "UNRECOVerable condition");
    }
    last_bp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (tesp && (ref_gen_code != gen_code)) {
        pr2serr("  <<%s>>\n", soec);
        return;
    }
    bp = resp + 8;
    sgj_pr_hr(jsp, "  %s:\n", sdl_s);
    if (as_json)
        jap = sgj_named_subarray_r(jsp, jop, sdl_sn);
    if (op->no_config) {
        if (op->verbose > 2)
            pr2serr("%s: %s\n", __func__, dwuti);
        n = (resp_len - 8) / 4;
        for (j = 0; j < n; ++j, bp += 4) {
            if (as_json)
                jo2p = sgj_new_unattached_object_r(jsp);
            enc_status_helper("        ", bp, 0, false, op, jo2p, b, blen);
            sgj_pr_hr(jsp, "%s", b);
            if (as_json)
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
        return;
    }
    if (NULL == tesp) {
        pr2serr("%s: logic error, resp==NULL\n", __func__);
        return;
    }

    for (k = 0, got1 = false; k < tesp->num_ths; ++k, ++tdhp) {
        if ((bp + 3) > last_bp)
            goto truncated;

        jo2p = NULL;
        ja2p = NULL;
        et = tdhp->etype;
        se_id_s = (0 == tdhp->se_id) ? "primary" : NULL;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            sgj_pr_hr(jsp, "    %s: %s, %s: %d [ti=%d]\n", et_s,
                      etype_str(et, b, blen), si_ss, tdhp->se_id, k);
            sgj_pr_hr(jsp, "      %s:\n", od_s);
            if (as_json) {
                jo2p = sgj_new_unattached_object_r(jsp);
                if (op->inner_hex < 2) {
                    sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et,
                                      NULL, etype_str(et, b, blen));
                    sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tdhp->se_id,
                                      NULL, se_id_s);
                } else
                    sgj_js_nv_hex_bytes(jsp, jo2p, "overall_status_element",
                                        bp, 4);
                jo3p = sgj_named_subobject_r(jsp, jo2p, od_sn);
                enc_status_helper("        ", bp, et, false, op,
                              jo3p, b, blen);
            } else {
                enc_status_helper("        ", bp, et, false, op,
                                  jo2p, b, blen);
                sgj_pr_hr(jsp, "%s", b);
            }
            got1 = true;
        }

        for (bp += 4, j = 0; j < tdhp->num_elements; ++j, bp += 4) {
            if (op->ind_given) {
                if ((! match_ind_th) || (! match_ind_indiv(j, op)))
                    continue;
            }
            sgj_pr_hr(jsp, "      Element %d descriptor:\n", j);
            if (as_json ) {
                if (NULL == jo2p) {
                    jo2p = sgj_new_unattached_object_r(jsp);
                    if (op->inner_hex < 2) {
                        sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et,
                                          NULL, etype_str(et, b, blen));
                        sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tdhp->se_id,
                                          NULL, se_id_s);
                    }
                }
                if (NULL == ja2p)
                    ja2p = sgj_named_subarray_r(jsp, jo2p, isel_sn);
                jo4p = sgj_new_unattached_object_r(jsp);
            }
            if (as_json) {
                jo4p = sgj_new_unattached_object_r(jsp);
                if (0 == op->inner_hex)
                    sgj_js_nv_hex_bytes(jsp, jo4p,
                                        "individual_status_element", bp, 4);
            }
            enc_status_helper("        ", bp, et, false, op, jo4p,
                              b, blen);
            sgj_pr_hr(jsp, "%s", b);
            if (as_json)
                sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo4p);
            got1 = true;
        }
        if (as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }           /* end of outer for loop */
    if (op->ind_given && (! got1)) {
        n = sg_scnpr(b, blen, "      >>> no match on --index=%d,%d",
                     op->ind_th, op->ind_indiv);
        if (op->ind_indiv_last > op->ind_indiv)
            sg_scnpr(b + n, blen - n, "-%d\n", op->ind_indiv_last);
        else
            sgj_pr_hr(jsp, "%s\n", b);
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

static char *
reserved_or_num(char * buff, int buff_len, int num, int reserve_num)
{
    if (num == reserve_num)
        snprintf(buff, buff_len, "<%s>", rsv_s);
    else
        snprintf(buff, buff_len, "%d", num);
    if (buff_len > 0)
        buff[buff_len - 1] = '\0';
    return buff;
}

static bool
threshold_used(int etype)
{
    switch (etype) {
    case 0x4:  /*temperature */
    case 0xb:  /* UPS */
    case 0x12: /* voltage */
    case 0x13: /* current */
        return true;
    default:
        return false;
    }
}

static void
threshold_helper(const char * header, const char * pad, const uint8_t *tp,
                 int etype, struct opts_t * op, sgj_opaque_p jop)
{
    bool as_json;
    uint8_t t0, t1, t2, t3;
    const char * cct0p;
    const char * cct1p;
    const char * cct2p;
    const char * cct3p;
    sgj_state * jsp = &op->json_st;
    char b[168];
    char b0[40];
    char b1[40];
    char b2[40];
    char b3[40];
    static const int blen = sizeof(b);
    static const int b0len = sizeof(b0);
    static const int b1len = sizeof(b1);
    static const int b2len = sizeof(b2);
    static const int b3len = sizeof(b3);
    static const char * const an_s = "above nominal";
    static const char * const bn_s = "below nominal";
    static const char * const ru_s = "[raw unit: 0.5%]";
    static const char * const v_s = "voltage";
    static const char * const c_s = "current";
    static const char * const tr_s = "time remaining [unit: minute]";

    t0 = tp[0];
    t1 = tp[1];
    t2 = tp[2];
    t3 = tp[3];
    as_json = jsp->pr_as_json;
    if (op->no_config || (op->inner_hex > 0)) {
        if (header)
            sgj_pr_hr(jsp, "%s", header);
        sgj_pr_hr(jsp, "%s%02x %02x %02x %02x\n", pad, t0, t1, t2, t3);
        if (as_json) {
            if (op->inner_hex < 2) {
                sgj_js_nv_ihex(jsp, jop, hct_sn, t0);
                sgj_js_nv_ihex(jsp, jop, hwt_sn, t1);
                sgj_js_nv_ihex(jsp, jop, lwt_sn, t2);
                sgj_js_nv_ihex(jsp, jop, lct_sn, t3);
            } else
                sgj_js_nv_hex_bytes(jsp, jop, "threshold_element", tp, 4);
        }
        return;
    }
    switch (etype) {
    case 0x4:  /*temperature */
        if (header)
            sgj_pr_hr(jsp, "%s", header);
        cct0p = reserved_or_num(b0, b0len, (int)t0 - TEMPERAT_OFF,
                                -TEMPERAT_OFF);
        cct1p = reserved_or_num(b1, b1len, (int)t1 - TEMPERAT_OFF,
                                -TEMPERAT_OFF);
        cct2p = reserved_or_num(b2, b2len, (int)t2 - TEMPERAT_OFF,
                                -TEMPERAT_OFF);
        cct3p = reserved_or_num(b3, b3len, (int)t3 - TEMPERAT_OFF,
                                -TEMPERAT_OFF);
        snprintf(b, blen, "%shigh critical=%s, high warning=%s", pad, cct0p,
                 cct1p);
        if (op->do_filter && (0 == t2) && (0 == t3))
            sgj_pr_hr(jsp, "%s (in Celsius)\n", b);
        else {
            sgj_pr_hr(jsp, "%s\n", b);
            sgj_pr_hr(jsp, "%slow warning=%s, low critical=%s (in Celsius)\n",
                      pad, cct2p, cct3p);
        }
        if (as_json) {
            sgj_js_nv_ihexstr(jsp, jop, hct_sn, t0, NULL, cct0p);
            sgj_js_nv_ihexstr(jsp, jop, hwt_sn, t1, NULL, cct1p);
            sgj_js_nv_ihexstr(jsp, jop, lwt_sn, t2, NULL, cct2p);
            sgj_js_nv_ihexstr(jsp, jop, lct_sn, t3, NULL, cct3p);
        }
        break;
    case 0xb:  /* UPS */
        if (header)
            sgj_pr_hr(jsp, "%s", header);
        if (0 == t2)
            strcpy(b2, "<vendor>");
        else
            snprintf(b2, b2len, "%d", t2);
        snprintf(b, blen, "%slow warning=%s, ", pad, b2);
        if (0 == t3)
            strcpy(b3, "<vendor>");
        else
            snprintf(b3, b3len, "%d", t3);
        sgj_pr_hr(jsp, "%slow critical=%s (in minutes)\n", b, b3);
        if (as_json) {
            sgj_js_nv_ihexstr_nex(jsp, jop, lwt_sn, t2, true, NULL, b2, tr_s);
            sgj_js_nv_ihexstr_nex(jsp, jop, lct_sn, t3, true, NULL, b3, tr_s);
        }
        break;
    case 0x12: /* voltage */
        if (header)
            sgj_pr_hr(jsp, "%s", header);
        sgj_pr_hr(jsp, "%shigh critical=%d.%d %%, high warning=%d.%d %% "
                  "(above nominal voltage)\n", pad, t0 / 2,
                  (t0 % 2) ? 5 : 0, t1 / 2, (t1 % 2) ? 5 : 0);
        sgj_pr_hr(jsp, "%slow warning=%d.%d %%, low critical=%d.%d %% "
                  "(below nominal voltage)\n", pad, t2 / 2,
                  (t2 % 2) ? 5 : 0, t3 / 2, (t3 % 2) ? 5 : 0);
        if (as_json) {
            snprintf(b0, b0len, "%d.%d %%", t0 / 2, (t0 % 2) ? 5 : 0);
            snprintf(b, blen, "%s %s %s", an_s, v_s, ru_s);
            sgj_js_nv_ihexstr_nex(jsp, jop, hct_sn, t0, true, NULL, b0, b);
            snprintf(b1, b1len, "%d.%d %%", t1 / 2, (t1 % 2) ? 5 : 0);
            sgj_js_nv_ihexstr_nex(jsp, jop, hwt_sn, t1, true, NULL, b1, b);
            snprintf(b2, b2len, "%d.%d %%", t2 / 2, (t2 % 2) ? 5 : 0);
            snprintf(b, blen, "%s %s %s", bn_s, v_s, ru_s);
            sgj_js_nv_ihexstr_nex(jsp, jop, lwt_sn, t2, true, NULL, b2, b);
            snprintf(b3, b3len, "%d.%d %%", t3 / 2, (t3 % 2) ? 5 : 0);
            sgj_js_nv_ihexstr_nex(jsp, jop, lct_sn, t3, true, NULL, b3, b);
        }
        break;
    case 0x13: /* current */
        if (header)
            sgj_pr_hr(jsp, "%s", header);
        sgj_pr_hr(jsp, "%shigh critical=%d.%d %%, high warning=%d.%d %% "
                  "(above nominal current)\n", pad, t0 / 2,
                  (t0 % 2) ? 5 : 0, t1 / 2, (t1 % 2) ? 5 : 0);
        if (as_json) {
            snprintf(b0, b0len, "%d.%d %%", t0 / 2, (t0 % 2) ? 5 : 0);
            snprintf(b, blen, "%s %s %s", an_s, c_s, ru_s);
            sgj_js_nv_ihexstr_nex(jsp, jop, hct_sn, t0, true, NULL, b0, b);
            snprintf(b1, b1len, "%d.%d %%", t1 / 2, (t1 % 2) ? 5 : 0);
            sgj_js_nv_ihexstr_nex(jsp, jop, hwt_sn, t1, true, NULL, b1, b);
        }
        break;
    default:
        if (op->verbose) {
            if (header)
                sgj_pr_hr(jsp, "%s", header);
            sgj_pr_hr(jsp, "%s<< no thresholds for this element type >>\n",
                      pad);
        }
        break;
    }
}

/* THRESHOLD_DPC  <"th"> [0x5] */
static void
threshold_sdp(const struct th_es_t * tesp, uint32_t ref_gen_code,
              const uint8_t * resp, int resp_len, struct opts_t * op,
              sgj_opaque_p jop)
{
    bool got1, match_ind_th, as_json;
    uint8_t et;
    int j, k;
    uint32_t gen_code;
    const char * se_id_s;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const struct type_desc_hdr_t * tdhp = tesp ? tesp->th_base : NULL;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jo4p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;
    char b[144];
    static const int blen = sizeof(b);
    static const char * const ti_dp = "Threshold in diagnostic page";
    static const char * const tsdl = "Threshold status descriptor list";
    static const char * const otse = "Overall threshold status element";
    static const char * const itse = "Individual threshold status element";

    sgj_pr_hr(jsp, "%s:\n", ti_dp);
    if (resp_len < 4)
        goto truncated;
    as_json = jsp->pr_as_json;
    if (as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(ti_dp, b, blen));
        sgj_js_nv_ihexstr(jsp, jop, pc_sn, THRESHOLD_DPC, NULL, ti_dp);
    }
    sgj_haj_vi(jsp, jop, 2, "INVOP", SGJ_SEP_EQUAL_NO_SPACE,
               !!(resp[1] & 0x10), false);
    last_bp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (tesp && (ref_gen_code != gen_code)) {
        pr2serr("  <<%s>>\n", soec);
        return;
    }
    bp = resp + 8;
    sgj_pr_hr(jsp, "  %s\n", tsdl);
    if (as_json) {
        if ((NULL == tesp) || (tesp->num_ths > 0))
            jap = sgj_named_subarray_r(jsp, jop,
                                       sgj_convert2snake(tsdl, b, blen));
    }
    if (op->no_config) {
        int n = (resp_len - 8) / 4;

        if (op->verbose > 2)
            pr2serr("%s: %s\n", __func__, dwuti);
        for (j = 0; j < n; ++j, bp += 4) {
            if (as_json)
                jo2p = sgj_new_unattached_object_r(jsp);
            threshold_helper("    Threshold status element:\n", "      ",
                             bp, 0, op, jo2p);
            if (as_json)
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
        return;
    }
    if (NULL == tesp) {
        pr2serr("%s: logic error, resp==NULL\n", __func__);
        return;
    }

    for (k = 0, got1 = false; k < tesp->num_ths; ++k, ++tdhp) {
        if (bp == (last_bp + 1)) {
            if (op->verbose > 3)
                pr2serr("%s: element types exhausted, k=%d, finished\n",
                        __func__, k);
            return;
        }
        if ((bp + 3) > last_bp)
            goto truncated;

        jo2p = NULL;
        ja2p = NULL;
        et = tdhp->etype;
        se_id_s = (0 == tdhp->se_id) ? "primary" : NULL;
        if (! threshold_used(et)) {
            if (op->verbose > 3)
                pr2serr("%s: skipping %s %u, does not use thresholds\n",
                        __func__, et_s, et);
            continue;
        }
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            sgj_pr_hr(jsp, "    %s: %s, %s: %d [ti=%d]\n", et_s,
                      etype_str(et, b, blen), si_sn, tdhp->se_id, k);
            if (as_json) {
                jo2p = sgj_new_unattached_object_r(jsp);
                if (op->inner_hex < 2) {
                    sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et,
                                      NULL, etype_str(et, b, blen));
                    sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tdhp->se_id,
                                      NULL, se_id_s);
                } else
                    sgj_js_nv_hex_bytes(jsp, jo2p, "overall_descriptor",
                                        bp, 4);
                jo3p = sgj_named_subobject_r(jsp, jo2p, od_sn);
                threshold_helper(otse, "        ", bp, et, op, jo3p);
            } else
                threshold_helper("      Overall descriptor:\n", "        ",
                                 bp, et, op, NULL);
            got1 = true;
        }

        for (bp += 4, j = 0; j < tdhp->num_elements; ++j, bp += 4) {
            if (op->ind_given) {
                if ((! match_ind_th) || (! match_ind_indiv(j, op)))
                    continue;
            }
            snprintf(b, blen, "      Element %d descriptor:\n", j);
            if (as_json) {
                if (NULL == jo2p) {
                    jo2p = sgj_new_unattached_object_r(jsp);
                    if (op->inner_hex < 2) {
                        sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et,
                                          NULL, etype_str(et, b, blen));
                        sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tdhp->se_id,
                                          NULL, se_id_s);
                    }
                }
                if (NULL == ja2p)
                    ja2p = sgj_named_subarray_r(jsp, jo2p, isel_sn);
                jo4p = sgj_new_unattached_object_r(jsp);
                threshold_helper(itse, "        ", bp, et, op, jo4p);
                sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo4p);
            } else
                threshold_helper(b, "        ", bp, et, op, NULL);
            got1 = true;
        }
        if (as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }                                   /* end of outer for loop */
    if (op->ind_given && (! got1)) {
        snprintf(b, blen, "      >>> no match on --index=%d,%d", op->ind_th,
                 op->ind_indiv);
        if (op->ind_indiv_last > op->ind_indiv)
            sgj_pr_hr(jsp, "%s-%d\n", b, op->ind_indiv_last);
        else
            sgj_pr_hr(jsp, "%s\n", b);
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

/* ELEM_DESC_DPC  <"ed"> [0x7]
 * This page contains names of overall and individual elements. */
static void
element_desc_sdp(const struct th_es_t * tesp, uint32_t ref_gen_code,
                 const uint8_t * resp, int resp_len,
                 struct opts_t * op, sgj_opaque_p jop)
{
    bool as_json;
    uint8_t et;
    int j, k, n, desc_len;
    uint32_t gen_code;
    bool got1, match_ind_th;
    const char * se_id_s;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const struct type_desc_hdr_t * tp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo4p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;
    char b[256];
    static const int blen = sizeof(b);
    static const char * const ed_dp = "Element descriptor diagnostic page";
    static const char * const edbtl = "Element descriptor by type list";
    static const char * const d_s = "descriptor";

    sgj_pr_hr(jsp, "%s:\n", ed_dp);
    if (resp_len < 4)
        goto truncated;
    last_bp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    as_json = jsp->pr_as_json;
    if (as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(ed_dp, b, blen));
        sgj_js_nv_ihexstr_nex(jsp, jop, pc_sn, ELEM_DESC_DPC, true, NULL,
                              ed_dp, "names for elements in es dpage");
    }
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (tesp && (ref_gen_code != gen_code)) {
        pr2serr("  <<%s>>\n", soec);
        return;
    }
    sgj_pr_hr(jsp, "  %s:\n", edbtl);
    bp = resp + 8;
    if (as_json)
        jap = sgj_named_subarray_r(jsp, jop,
                                   sgj_convert2snake(edbtl, b, blen));
    if (op->no_config) {
        if (op->verbose > 2)
            pr2serr("%s: %s\n", __func__, dwuti);
        for ( ; bp < last_bp; bp += (n + 4)) {
            n = sg_get_unaligned_be16(bp + 2);
            if (op->inner_hex > 0) {
                hex2str(bp, n + 4, "      ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s\n", b);
            } else
                sgj_pr_hr(jsp, "    %s: %.*s\n", d_s, n, bp + 4);
            jo2p = sgj_new_unattached_object_r(jsp);
            if (op->inner_hex > 1)
                sgj_js_nv_hex_bytes(jsp, jo2p, d_s, bp, n + 4);
            else
                sgj_js_nv_s_len_chk(jsp, jo2p, d_s, bp + 4, n);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
        return;
    }
    got1 = false;
    if (NULL == tesp) {
        pr2serr("%s: logic error, resp==NULL\n", __func__);
        return;
    }

    for (k = 0, tp = tesp->th_base; k < tesp->num_ths; ++k, ++tp) {
        if ((bp + 3) > last_bp)
            goto truncated;

        jo2p = NULL;
        ja2p = NULL;
        et = tp->etype;
        se_id_s = (0 == tp->se_id) ? "primary" : NULL;
        desc_len = sg_get_unaligned_be16(bp + 2) + 4;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            sgj_pr_hr(jsp, "    %s: %s, %s: %d [ti=%d]\n", et_s,
                      etype_str(et, b, blen), si_ss, tp->se_id, k);
            if (desc_len > 4) {
                if (op->inner_hex > 0) {
                    sgj_pr_hr(jsp, "      %s:\n", od_s);
                    hex2str(bp, desc_len, "        ", op->h2s_oformat, blen,
                            b);
                    sgj_pr_hr(jsp, "%s\n", b);
                } else
                    sgj_pr_hr(jsp, "      %s: %.*s\n", od_s, desc_len - 4,
                              bp + 4);
            } else
                sgj_pr_hr(jsp, "      %s: <empty>\n", od_s);
            if (as_json) {
                jo2p = sgj_new_unattached_object_r(jsp);
                if (op->inner_hex < 2) {
                    sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et,
                                      NULL, etype_str(et, b, blen));
                    sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tp->se_id, NULL,
                                      se_id_s);
                    sgj_js_nv_s_len_chk(jsp, jo2p, od_sn, bp + 4,
                                        desc_len - 4);
                } else
                    sgj_js_nv_hex_bytes(jsp, jo2p, od_sn, bp, desc_len);
            }
            got1 = true;
        }

        for (bp += desc_len, j = 0; j < tp->num_elements;
             ++j, bp += desc_len) {
            desc_len = sg_get_unaligned_be16(bp + 2) + 4;
            if (op->ind_given) {
                if ((! match_ind_th) || (! match_ind_indiv(j, op)))
                    continue;
            }
            if (desc_len > 4) {
                if (op->inner_hex > 0) {
                    sgj_pr_hr(jsp, "      Element %d descriptor:\n", j);
                    hex2str(bp, desc_len, "        ", op->h2s_oformat,
                            blen, b);
                    sgj_pr_hr(jsp, "%s\n", b);
                } else
                    sgj_pr_hr(jsp, "      Element %d descriptor: %.*s\n", j,
                              desc_len - 4, bp + 4);
            } else
                sgj_pr_hr(jsp, "      Element %d descriptor: <empty>\n", j);
            got1 = true;
            if (as_json) {
                if (NULL == jo2p) {
                    jo2p = sgj_new_unattached_object_r(jsp);
                    if (op->inner_hex < 2) {
                        sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et, NULL,
                                          etype_str(et, b, blen));
                        sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tp->se_id, NULL,
                                          se_id_s);
                    }
                }
                if (NULL == ja2p)
                    ja2p = sgj_named_subarray_r(jsp, jo2p,
                                                "element_descriptor");
                jo4p = sgj_new_unattached_object_r(jsp);
                if (op->inner_hex > 0)
                    sgj_js_nv_hex_bytes(jsp, jo4p, d_s, bp, desc_len);
                else
                    sgj_js_nv_s_len_chk(jsp, jo4p, d_s, bp + 4, desc_len - 4);
                sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo4p);
            }
        }
        if (as_json && jo2p)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }                                   /* <<< end of outer for loop */
    if (op->ind_given && (! got1)) {
        snprintf(b, blen, "      >>> no match on --index=%d,%d", op->ind_th,
                 op->ind_indiv);
        if (op->ind_indiv_last > op->ind_indiv)
            sgj_pr_hr(jsp, "%s-%d\n", b, op->ind_indiv_last);
        else
            sgj_pr_hr(jsp, "%s\n", b);
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

static bool
saddr_non_zero(const uint8_t * bp)
{
    return ! sg_all_zeros(bp, 8);
}

static const char * sas_device_type[] = {
    "no SAS device attached",   /* but might be SATA device */
    "end device",
    "expander device",  /* in SAS-1.1 this was a "edge expander device */
    "expander device (fanout, SAS-1.1)",  /* marked obsolete in SAS-2 */
    "reserved [4]", "reserved [5]", "reserved [6]", "reserved [7]"
};

static void
additional_elem_sas(const char * pad, const uint8_t * ae_bp, int etype,
                    const struct th_es_t * tesp, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool nofilter = ! op->do_filter;
    bool eip, as_json;
    uint8_t cei, oei;
    int phys, j, n, q, desc_type, eiioe, eip_offset;
    uint64_t sa, asa;
    const struct join_row_t * jrp;
    const uint8_t * aep;
    const uint8_t * ed_bp;
    const char * ccp;
    char * cp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    char e[64];
    static const int blen = sizeof(b);
    static const int elen = sizeof(e);
    static const int m_sz = 4096;
    static const char * pdl_s = "Phy descriptor list";
    static const char * pdl_sn = "phy_descriptor_list";

    eip = !!(0x10 & ae_bp[0]);
    eiioe = eip ? (0x3 & ae_bp[2]) : 0;
    eip_offset = eip ? 2 : 0;
    desc_type = (ae_bp[3 + eip_offset] >> 6) & 0x3;
    as_json = jsp->pr_as_json;
    if (as_json)
        sgj_js_nv_ihex(jsp, jop, "descriptor_type", desc_type);
    if (op->verbose > 1)
        sgj_pr_hr(jsp, "%sdescriptor_type: %d\n", pad, desc_type);

    if (0 == desc_type) {
        phys = ae_bp[2 + eip_offset];
        n = sg_scnpr(b, blen, "%snumber of phys: %d, not all phys: %d", pad,
                     phys, ae_bp[3 + eip_offset] & 1);
        if (eip_offset)
            sg_scnpr(b + n, blen - n, ", device slot number: %d",
                     ae_bp[5 + eip_offset]);
        sgj_pr_hr(jsp, "%s\n", b);
        if (as_json) {
            sgj_js_nv_ihex(jsp, jop, "number_of_phy_descriptors", phys);
            sgj_js_nv_i(jsp, jop, "not_all_phys",
                           ae_bp[3 + eip_offset] & 1);
            if (eip_offset)
                sgj_js_nv_ihex(jsp, jop, "device_slot_number",
                               ae_bp[5 + eip_offset]);
        }
        aep = ae_bp + 4 + eip_offset + eip_offset;
        if (op->inner_hex > 0) {
            cp = (char *)malloc(m_sz);
            if (NULL == cp) {
                pr2serr("%s\n", oohm);
                return;
            }
            j = phys * 28;
            sgj_pr_hr(jsp, "%s%s:\n", pad, pdl_s);
            hex2str(aep, j, "          ", op->h2s_oformat, m_sz, cp);
            sgj_pr_hr(jsp, "%s", cp);
            sgj_js_nv_hex_bytes(jsp, jop, pdl_sn, aep, j);
            free(cp);
            return;
        }
        if (as_json)
            jap = sgj_named_subarray_r(jsp, jop, pdl_sn);

        for (j = 0; j < phys; ++j, aep += 28) {
            bool print_sas_addr = false;
            bool saddr_nz;
            uint8_t ae2 = aep[2];
            uint8_t ae3 = aep[3];
            uint8_t dt = (0x70 & aep[0]) >> 4;

            asa = sg_get_unaligned_be64(aep + 4);
            sa = sg_get_unaligned_be64(aep + 12);
            sgj_pr_hr(jsp, "%sphy index: %d\n", pad, j);
            sgj_pr_hr(jsp, "%s  SAS device type: %s\n", pad,
                      sas_device_type[dt]);
            if (nofilter || (0xe & ae2))
                sgj_pr_hr(jsp, "%s  initiator port for:%s%s%s\n", pad,
                          ((ae2 & 8) ? " SSP" : ""),
                          ((ae2 & 4) ? " STP" : ""),
                          ((ae2 & 2) ? " SMP" : ""));
            if (nofilter || (0x8f & ae3))
                sgj_pr_hr(jsp, "%s  target port for:%s%s%s%s%s\n", pad,
                          ((ae3 & 0x80) ? " SATA_port_selector" : ""),
                          ((ae3 & 8) ? " SSP" : ""),
                          ((ae3 & 4) ? " STP" : ""),
                          ((ae3 & 2) ? " SMP" : ""),
                          ((ae3 & 1) ? " SATA_device" : ""));
            saddr_nz = saddr_non_zero(aep + 4);
            if (nofilter || saddr_nz) {
                print_sas_addr = true;
                sgj_pr_hr(jsp, "%s  attached SAS address: 0x%" PRIx64 "\n",
                          pad, asa);
            }
            saddr_nz = saddr_non_zero(aep + 12);
            if (nofilter || saddr_nz) {
                print_sas_addr = true;
                sgj_pr_hr(jsp, "%s  SAS address: 0x%" PRIx64 "\n", pad, sa);
            }
            if (print_sas_addr)
                sgj_pr_hr(jsp, "%s  phy identifier: 0x%x\n", pad, aep[20]);
            if (as_json) {
                jo2p = sgj_new_unattached_object_r(jsp);
                sgj_js_nv_ihexstr(jsp, jo2p, "device_type", dt, NULL,
                                  sas_device_type[(0x70 & aep[0]) >> 4]);
                sgj_js_nv_i(jsp, jo2p, "ssp_initiator_port", !!(8 & ae2));
                sgj_js_nv_i(jsp, jo2p, "stp_initiator_port", !!(4 & ae2));
                sgj_js_nv_i(jsp, jo2p, "smp_initiator_port", !!(2 & ae2));
                sgj_js_nv_i(jsp, jo2p, "sata_port_selector", !!(0x80 & ae3));
                sgj_js_nv_i(jsp, jo2p, "ssp_target_port", !!(8 & ae3));
                sgj_js_nv_i(jsp, jo2p, "stp_target_port", !!(4 & ae3));
                sgj_js_nv_i(jsp, jo2p, "smp_target_port", !!(2 & ae3));
                sgj_js_nv_i(jsp, jo2p, "sata_device", !!(1 & ae3));
                sgj_js_nv_ihex(jsp, jo2p, "attached_sas_address", asa);
                sgj_js_nv_ihex(jsp, jo2p, "sas_address", sa);
                sgj_js_nv_ihex(jsp, jo2p, "phy_index", aep[20]);
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
        }
    } else if (1 == desc_type) {
        phys = ae_bp[2 + eip_offset];
        if (SAS_EXPANDER_ETC == etype) {
            sgj_pr_hr(jsp, "%snumber of phys: %d\n", pad, phys);
            sa = sg_get_unaligned_be64(ae_bp + 6 + eip_offset);
            sgj_pr_hr(jsp, "%sSAS address: 0x%" PRIx64 "\n", pad, sa);
            sgj_pr_hr(jsp, "%sAttached connector; other_element pairs:\n",
                      pad);
            if (as_json) {
                sgj_js_nv_ihex(jsp, jop,
                               "number_of_expander_phy_descriptors", phys);
                sgj_js_nv_ihex(jsp, jop, "sas_address", sa);
            }
            aep = ae_bp + 14 + eip_offset;
            snprintf(e, elen, "expander_%s", pdl_sn);
            if (op->inner_hex > 0) {
                cp = (char *)malloc(m_sz);
                if (NULL == cp) {
                    pr2serr("%s\n", oohm);
                    return;
                }
                j = phys * 2;
                sgj_pr_hr(jsp, "%sExpander %s:\n", pad, pdl_s);
                hex2str(aep, j, "          ", op->h2s_oformat, m_sz, cp);
                sgj_pr_hr(jsp, "%s", cp);
                sgj_js_nv_hex_bytes(jsp, jop, e, aep, j);
                free(cp);
                return;
            }
            if (as_json)
                jap = sgj_named_subarray_r(jsp, jop, e);

            for (j = 0; j < phys; ++j, aep += 2) {
                cei = aep[0];   /* connector element index */
                oei = aep[1];   /* other element index */
                if (as_json) {
                    jo2p = sgj_new_unattached_object_r(jsp);
                    sgj_js_nv_ihex(jsp, jo2p, "connector_element_index", cei);
                    sgj_js_nv_ihex(jsp, jo2p, "other_element_index", oei);
                }
                n = sg_scnpr(b, blen, "%s  [%d] ", pad, j);
                if (0xff == cei)
                    n += sg_scnpr(b + n, blen - n, "no connector");
                else {
                    if (tesp->j_base) {
                        if (0 == eiioe)
                            jrp = find_join_row_cnst(tesp, cei, FJ_SAS_CON);
                        else if ((1 == eiioe) || (3 == eiioe))
                            jrp = find_join_row_cnst(tesp, cei, FJ_IOE);
                        else
                            jrp = find_join_row_cnst(tesp, cei, FJ_EOE);
                        if ((NULL == jrp) || (NULL == jrp->enc_statp) ||
                            (SAS_CONNECTOR_ETC != jrp->etype))
                            n += sg_scnpr(b + n, blen - n,
                                          "broken [conn_idx=%d]", cei);
                        else {
                            n += enc_status_helper("", jrp->enc_statp,
                                                   jrp->etype, true, op,
                                                   jo2p, b + n, blen - n);
                            n += sg_scnpr(b + n, blen - n, " [%d]",
                                          jrp->indiv_i);
                        }
                    } else
                        n += sg_scnpr(b + n, blen - n, "connector ei: %d",
                                      cei);
                }
                if (0xff != oei) {
                    n += sg_scnpr(b + n, blen - n, "; ");
                    if (tesp->j_base) {
                        if (0 == eiioe)
                            jrp = find_join_row_cnst(tesp, oei, FJ_AESS);
                        else if ((1 == eiioe) || (3 == eiioe))
                            jrp = find_join_row_cnst(tesp, oei, FJ_IOE);
                        else
                            jrp = find_join_row_cnst(tesp, oei, FJ_EOE);
                        if (NULL == jrp)
                            sg_scnpr(b + n, blen - n,
                                     "broken [oth_elem_idx=%d]", oei);
                        else if (jrp->elem_descp) {
                            ccp = etype_str(jrp->etype, e, elen);
                            ed_bp = jrp->elem_descp;
                            q = sg_get_unaligned_be16(ed_bp + 2);
                            if (q > 0)
                                sg_scnpr(b + n, blen - n,
                                         "%.*s [%d,%d] etype: %s", q,
                                         (const char *)(ed_bp + 4),
                                         jrp->th_i, jrp->indiv_i, ccp);
                            else
                                sg_scnpr(b + n, blen - n,
                                         "[%d,%d] etype: %s", jrp->th_i,
                                          jrp->indiv_i, ccp);
                        } else {
                            ccp = etype_str(jrp->etype, e, elen);
                            sg_scnpr(b + n, blen - n,
                                     "[%d,%d] etype: %s", jrp->th_i,
                                     jrp->indiv_i, ccp);
                        }
                    } else
                        sg_scnpr(b + n, blen - n, "other ei: %d", oei);
                }
                sgj_pr_hr(jsp, "%s\n", b);
                if (as_json)
                    sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
        } else if (is_et_optional_for_aes(etype)) {
            sgj_pr_hr(jsp, "%snumber of phys: %d\n", pad, phys);
            if (as_json)
                sgj_js_nv_ihex(jsp, jop,
                               "number_of_phy_descriptors", phys);
            aep = ae_bp + 6 + eip_offset;
            if (op->inner_hex > 0) {
                cp = (char *)malloc(m_sz);
                if (NULL == cp) {
                    pr2serr("%s\n", oohm);
                    return;
                }
                j = phys * 12;
                sgj_pr_hr(jsp, "%s%s:\n", pad, pdl_s);
                hex2str(aep, j, "          ", op->h2s_oformat, m_sz, cp);
                sgj_pr_hr(jsp, "%s", cp);
                sgj_js_nv_hex_bytes(jsp, jop, pdl_sn, aep, j);
                free(cp);
                return;
            }
            if (as_json)
                jap = sgj_named_subarray_r(jsp, jop, pdl_sn);

            for (j = 0; j < phys; ++j, aep += 12) {
                cei = aep[2];   /* connector element index */
                oei = aep[3];   /* other element index */
                if (as_json)
                    jo2p = sgj_new_unattached_object_r(jsp);
                sa = sg_get_unaligned_be64(aep + 4);
                sgj_pr_hr(jsp, "%sphy index: %d\n", pad, j);
                sgj_pr_hr(jsp, "%s  phy_id: 0x%x\n", pad, aep[0]);
                n = sg_scnpr(b, blen, "%s  ", pad);
                if (0xff == cei)
                    n += sg_scnpr(b + n, blen - n, "no connector");
                else {
                    if (tesp->j_base) {
                        if (0 == eiioe)
                            jrp = find_join_row_cnst(tesp, cei, FJ_SAS_CON);
                        else if ((1 == eiioe) || (3 == eiioe))
                            jrp = find_join_row_cnst(tesp, cei, FJ_IOE);
                        else
                            jrp = find_join_row_cnst(tesp, cei, FJ_EOE);
                        if ((NULL == jrp) || (NULL == jrp->enc_statp) ||
                            (SAS_CONNECTOR_ETC != jrp->etype))
                            n += sg_scnpr(b + n, blen - n,
                                          "broken [conn_idx=%d]", cei);
                        else {
                            n += enc_status_helper("", jrp->enc_statp,
                                                   jrp->etype, true, op,
                                                   jo2p, b + n, blen - n);
                            n += sg_scnpr(b + n, blen - n, " [%d]",
                                          jrp->indiv_i);
                        }
                    } else
                        n += sg_scnpr(b + n, blen - n, "connector ei: %d",
                                      cei);
                }
                if (0xff != oei) {
                    n += sg_scnpr(b + n, blen - n, "; ");
                    if (tesp->j_base) {
                        if (0 == eiioe)
                            jrp = find_join_row_cnst(tesp, oei, FJ_AESS);
                        else if ((1 == eiioe) || (3 == eiioe))
                            jrp = find_join_row_cnst(tesp, oei, FJ_IOE);
                        else
                            jrp = find_join_row_cnst(tesp, oei, FJ_EOE);
                        if (NULL == jrp)
                            sg_scnpr(b + n, blen - n,
                                     "broken [oth_elem_idx=%d]", oei);
                        else if (jrp->elem_descp) {
                            ccp = etype_str(jrp->etype, e, elen);
                            ed_bp = jrp->elem_descp;
                            q = sg_get_unaligned_be16(ed_bp + 2);
                            if (q > 0)
                                sg_scnpr(b + n, blen - n,
                                         "%.*s [%d,%d] etype: %s", q,
                                         (const char *)(ed_bp + 4),
                                         jrp->th_i, jrp->indiv_i, ccp);
                            else
                                sg_scnpr(b + n, blen - n,
                                         "[%d,%d] etype: %s", jrp->th_i,
                                         jrp->indiv_i, ccp);
                        } else {
                            ccp = etype_str(jrp->etype, e, elen);
                            sg_scnpr(b + n, blen - n,
                                     "[%d,%d] etype: %s", jrp->th_i,
                                     jrp->indiv_i, ccp);
                        }
                    } else
                        sg_scnpr(b + n, blen - n, "other ei: %d", oei);
                }
                sgj_pr_hr(jsp, "%s\n", b);
                sgj_pr_hr(jsp, "%s  SAS address: 0x%" PRIx64 "\n", pad, sa);
                if (as_json) {
                    sgj_js_nv_ihex(jsp, jo2p, "connector_element_index", cei);
                    sgj_js_nv_ihex(jsp, jo2p, "other_element_index", oei);
                    sgj_js_nv_ihex(jsp, jo2p, "sas_address", sa);
                    sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
                }
            }   /* end_for: loop over phys in SCSI initiator, target */
        } else
            sgj_pr_hr(jsp, "%sunrecognised element type [%d] for desc_type "
                      "1\n", pad, etype);
    } else
        sgj_pr_hr(jsp, "%sunrecognised descriptor type [%d]\n", pad,
                  desc_type);
}

static void
additional_elem_helper(const char * pad, const uint8_t * ae_bp,
                       int len, int etype, const struct th_es_t * tesp,
                       struct opts_t * op, sgj_opaque_p jop)
{
    bool eip, as_json;
    uint16_t pcie_vid;
    int ports, j, m, n, eip_offset, pcie_pt, proto;
    char * cp;
    const uint8_t * aep;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const int m_sz = 4096;

    as_json = jsp->pr_as_json;
    if (1 == op->inner_hex) {
        cp = (char *)malloc(m_sz);
        if (NULL == cp) {
            pr2serr("%s\n", oohm);
            return;
        }
        sgj_pr_hr(jsp, "%s%s:\n", pad, "in hex");
        hex2str(ae_bp, len, pad, op->h2s_oformat, m_sz, cp);
        if (as_json && jsp->pr_out_hr)
            sgj_hr_str_out(jsp, cp, strlen(cp));
        else
            sgj_pr_hr(jsp, "%s\n", cp);
        if (as_json)
            sgj_js_nv_hex_bytes(jsp, jop, in_hex_sn, ae_bp, len);
        free(cp);
        return;
    }
    eip = !!(0x10 & ae_bp[0]);
    eip_offset = eip ? 2 : 0;
    proto = 0xf & ae_bp[0];

    switch (proto) {     /* switch on protocol identifier */
    case TPROTO_FCP:
        sgj_pr_hr(jsp, "%sTransport protocol: FCP\n", pad);
        if (len < (12 + eip_offset))
            break;
        ports = ae_bp[2 + eip_offset];
        sgj_pr_hr(jsp, "%snumber of ports: %d\n", pad, ports);
        n = sg_scnpr(b, blen, "%snode_name: ", pad);
        for (m = 0; m < 8; ++m)
            n += sg_scnpr(b + n, blen - n, "%02x", ae_bp[6 + eip_offset + m]);
        if (eip_offset)
            sg_scnpr(b + n, blen - n, ", device slot number: %d",
                     ae_bp[5 + eip_offset]);
        sgj_pr_hr(jsp, "%s\n", b);
        if (as_json) {
            sgj_js_nv_ihex(jsp, jop, "number_of_ports", ports);
            if (eip_offset)
                sgj_js_nv_ihex(jsp, jop, "device_slot_number",
                               ae_bp[5 + eip_offset]);
            sgj_js_nv_ihex(jsp, jop, "node_name",
                           sg_get_unaligned_be64(ae_bp + eip_offset + 6));
            jap = sgj_named_subarray_r(jsp, jop, "port_descriptor_list");
        }
        aep = ae_bp + 14 + eip_offset;
        for (j = 0; j < ports; ++j, aep += 16) {
            sgj_pr_hr(jsp, "%s  port index: %d, port loop position: %d, port "
                      "bypass reason: 0x%x\n", pad, j, aep[0], aep[1]);
            sgj_pr_hr(jsp, "%srequested hard address: %d, n_port identifier: "
                      "%02x%02x%02x\n", pad, aep[4], aep[5], aep[6], aep[7]);
            n = sg_scnpr(b, blen, "%s  n_port name: ", pad);
            for (m = 0; m < 8; ++m)
                n += sg_scnpr(b + n, blen - n, "%02x", aep[8 + m]);
            sgj_pr_hr(jsp, "%s\n", b);
            if (as_json) {
                jo2p = sgj_new_unattached_object_r(jsp);
                sgj_js_nv_ihex(jsp, jo2p, "port_loop_position", aep[0]);
                sgj_js_nv_ihex(jsp, jo2p, "bypass_reason", aep[1]);
                sgj_js_nv_ihex(jsp, jo2p, "port_requested_hard_address",
                               aep[4]);
                sgj_js_nv_ihex(jsp, jo2p, "n_port_identifier",
                               sg_get_unaligned_be24(aep + 5));
                sgj_js_nv_ihex(jsp, jo2p, "n_port_name",
                               sg_get_unaligned_be64(aep + 8));
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
        }
        break;
    case TPROTO_SAS:
        sgj_pr_hr(jsp, "%sTransport protocol: SAS\n", pad);
        if (len < (4 + eip_offset))
            break;
        additional_elem_sas(pad, ae_bp, etype, tesp, op, jop);
        break;
    case TPROTO_PCIE: /* added in ses3r08; contains little endian fields */
        sgj_pr_hr(jsp, "%sTransport protocol: PCIe\n", pad);
        if (0 == eip_offset) {
            sgj_pr_hr(jsp, "%sfor this protocol EIP must be set (it isn't)\n",
                      pad);
            break;
        }
        if (len < 6)
            break;
        pcie_pt = (ae_bp[5] >> 5) & 0x7;
        if (TPROTO_PCIE_PS_NVME == pcie_pt)
            sgj_pr_hr(jsp, "%sPCIe protocol type: NVMe\n", pad);
        else {  /* no others currently defined */
            sgj_pr_hr(jsp, "%sTransport protocol: PCIe subprotocol=0x%x not "
                      "decoded\n", pad, pcie_pt);
            if (op->verbose)
                hex2stdout(ae_bp, len, 0);
            break;
        }
        ports = ae_bp[4];
        snprintf(b, blen, "%snumber of ports: %d, not all ports: %d", pad,
                 ports, ae_bp[5] & 1);
        sgj_pr_hr(jsp, "%s, device slot number: %d\n", b, ae_bp[7]);

        pcie_vid = sg_get_unaligned_le16(ae_bp + 10);   /* N.B. LE */
        sgj_pr_hr(jsp, "%sPCIe vendor id: 0x%" PRIx16 "%s\n", pad, pcie_vid,
                  (0xffff == pcie_vid) ? not_rep : "");
        sgj_pr_hr(jsp, "%sserial number: %.20s\n", pad, ae_bp + 12);
        sgj_pr_hr(jsp, "%smodel number: %.40s\n", pad, ae_bp + 32);
        if (as_json) {
            sgj_js_nv_ihexstr(jsp, jop, "pcie_protocol_type", pcie_pt, NULL,
                              (TPROTO_PCIE_PS_NVME == pcie_pt) ?
                                 "NVMe" : "unexpected value");
            sgj_js_nv_ihex(jsp, jop, "number_of_ports", ports);
            sgj_js_nv_i(jsp, jop, "not_all_ports", ae_bp[5] & 1);
            sgj_js_nv_ihex(jsp, jop, "device_slot_number", ae_bp[7]);
            sgj_js_nv_ihexstr(jsp, jop, "pcie_vendor_id", pcie_vid, NULL,
                              (0xffff == pcie_vid) ? not_rep : NULL);
            sgj_js_nv_s_len_chk(jsp, jop, "serial_number", ae_bp + 12, 20);
            sgj_js_nv_s_len_chk(jsp, jop, "model_number", ae_bp + 32, 40);
            jap = sgj_named_subarray_r(jsp, jop,
                                       "physical_port_descriptor_list");
        }
        aep = ae_bp + 72;
        for (j = 0; j < ports; ++j, aep += 8) {
            bool psn_valid = !!(0x4 & aep[0]);
            bool bdf_valid = !!(0x2 & aep[0]);
            bool cid_valid = !!(0x1 & aep[0]);
            uint16_t ctrl_id = sg_get_unaligned_le16(aep + 1); /* LEndian */

            sgj_pr_hr(jsp, "%sport index: %d\n", pad, j);
            sgj_pr_hr(jsp, "%s  PSN_VALID=%d, BDF_VALID=%d, CID_VALID=%d\n",
                      pad, (int)psn_valid, (int)bdf_valid, (int)cid_valid);
            if (cid_valid)      /* N.B. little endian */
                sgj_pr_hr(jsp, "%s  controller id: 0x%" PRIx16 "\n", pad,
                          sg_get_unaligned_le16(aep + 1)); /* N.B. LEndian */
            if (bdf_valid)
                sgj_pr_hr(jsp, "%s  bus number: 0x%x, device number: 0x%x, "
                          "function number: 0x%x\n", pad, aep[4],
                          (aep[5] >> 3) & 0x1f, 0x7 & aep[5]);
            if (psn_valid)      /* little endian, top 3 bits assumed zero */
                sgj_pr_hr(jsp, "%s  physical slot number: 0x%" PRIx16 "\n",
                          pad, 0x1fff & sg_get_unaligned_le16(aep + 6));
            if (as_json) {
                jo2p = sgj_new_unattached_object_r(jsp);
                sgj_js_nv_ihex(jsp, jo2p, "psn_valid", (int)psn_valid);
                snprintf(b, blen, "bus number, device number and function "
                         "number field are %svalid", bdf_valid ? "" : "in");
                sgj_js_nv_ihexstr(jsp, jo2p, "bdf_valid", (int)bdf_valid,
                                  NULL,  b);
                sgj_js_nv_ihex(jsp, jo2p, "cid_valid", (int)bdf_valid);
                sgj_js_nv_ihex(jsp, jo2p, "controller_id", ctrl_id);
                sgj_js_nv_ihex(jsp, jo2p, "bus_number", aep[4]);
                sgj_js_nv_ihex(jsp, jo2p, "device_number",
                               (aep[5] >> 3) & 0x1f);
                sgj_js_nv_ihex(jsp, jo2p, "function_number", 0x7 & aep[5]);
                sgj_js_nv_ihex(jsp, jo2p, "physical_slot_number",
                               0x1fff & sg_get_unaligned_le16(aep + 6));
                sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            }
        }
        break;
    default:
        sgj_pr_hr(jsp, "%sTransport protocol: %s not decoded\n", pad,
                  sg_get_trans_proto_str((0xf & ae_bp[0]), blen, b));
        if (op->verbose)
            hex2stdout(ae_bp, len, 0);
        break;
    }
}

/* ADD_ELEM_STATUS_DPC  <"aes"> [0xa] Additional Element Status dpage
 * Previously called "Device element status descriptor". Changed "device"
 * to "additional" to allow for SAS expander and SATA devices */
static void
additional_elem_sdp(const struct th_es_t * tesp, uint32_t ref_gen_code,
                    const uint8_t * resp, int resp_len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool eip, invalid, match_ind_th, local_eiioe_force, skip, as_json;
    uint8_t et;
    int j, k, n, desc_len, el_num, ind, elem_count, ei, eiioe;
    int num_elems, fake_ei, proto;
    uint32_t gen_code;
    const char * ccp;
    const char * se_id_s;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const struct type_desc_hdr_t * tp = tesp ? tesp->th_base : NULL;
    char * b;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jo4p = NULL;
    sgj_opaque_p jap = NULL;
    sgj_opaque_p ja2p = NULL;
    char e[128];
    static const int blen = 4096;
    static const int elen = sizeof(e);
    static const char * aesbetl =
                 "Additional element status by element type list";
    static const char * aesdl = "Additional element status descriptor list";
    static const char * psi_sn = "protocol_specific_information";

    sgj_pr_hr(jsp, "%s:\n", aes_dp);
    b = (char *)malloc(blen);
    if (NULL == b) {
        pr2serr("%s\n", oohm);
        return;
    }
    if (resp_len < 4)
        goto truncated;
    last_bp = resp + resp_len - 1;
    as_json = jsp->pr_as_json;
    if (as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(aes_dp, b, blen));
        sgj_js_nv_ihexstr(jsp, jop, pc_sn, ADD_ELEM_STATUS_DPC, NULL, aes_dp);
    }
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (tesp && (ref_gen_code != gen_code)) {
        pr2serr("  <<%s>>\n", soec);
        goto fini;
    }
    bp = resp + 8;
    if (op->no_config) {
        if (op->verbose > 2)
            pr2serr("%s: %s\n", __func__, dwuti);
        sgj_pr_hr(jsp, "  %s:\n", aesdl);
        if (as_json)
            jap = sgj_named_subarray_r(jsp, jop,
                                       sgj_convert2snake(aesdl, b, blen));
        for ( ; bp < last_bp; bp += n) {
            n = bp[1] + 2;
            jo2p = sgj_new_unattached_object_r(jsp);
            sgj_pr_hr(jsp, "    %s:\n", aesd_s);
            if (op->inner_hex > 1) {
                hex2str(bp, n, "      ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s", b);
                if (as_json)
                    sgj_js_nv_hex_bytes(jsp, jo2p, aesd_sn, bp, n);
            } else {
                invalid = !!(0x80 & bp[0]);
                eip = !!(0x10 & bp[0]);
                if (eip) {
                    eiioe = 0x3 & bp[2];
                    ei = bp[3];
                    j = 4;
                } else
                    j = 2;
                proto = (0xf & bp[0]);
                ccp = sg_get_trans_proto_str(proto, elen, e);
                sgj_pr_hr(jsp, "    invalid=%d\n", (int)invalid);
                sgj_pr_hr(jsp, "    eip=%d\n", (int)eip);
                sgj_pr_hr(jsp, "    proto=%d\n", proto);
                if (eip && (n > 3)) {
                    sgj_pr_hr(jsp, "    eiioe=%d\n", eiioe);
                    sgj_pr_hr(jsp, "    element_index=%d\n", ei);
                }
                hex2str(bp + j, n - j, "      ", op->h2s_oformat, blen, b);
                sgj_pr_hr(jsp, "%s", b);
                if (as_json) {
                    jo3p = sgj_named_subobject_r(jsp, jo2p, aesd_sn);
                    sgj_js_nv_ihex(jsp, jo3p, "invalid", (int)invalid);
                    sgj_js_nv_ihex(jsp, jo3p, "eip", eip);
                    sgj_js_nv_ihexstr(jsp, jo3p, "protocol_identifier", proto,
                                      NULL, ccp);
                    if (eip && (n > 3)) {
                        sgj_js_nv_ihex(jsp, jo3p, "eiioe", 0x3 & bp[2]);
                        sgj_js_nv_ihex(jsp, jo3p, "element_index", bp[3]);
                    }
                    sgj_js_nv_hex_bytes(jsp, jo3p, psi_sn, bp + j, n - j);
                }
            }
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
        goto fini;
    }
    sgj_pr_hr(jsp, "  %s:\n", aesbetl);
    jap = sgj_named_subarray_r(jsp, jop,
                               sgj_convert2snake(aesbetl, b, blen));
    if (NULL == tesp) {
        pr2serr("%s: logic error, resp==NULL\n", __func__);
        goto fini;
    }
    local_eiioe_force = op->eiioe_force;

    for (k = 0, elem_count = 0; k < tesp->num_ths; ++k, ++tp) {
        fake_ei = -1;
        et = tp->etype;
        se_id_s = (0 == tp->se_id) ? "primary" : NULL;
        jo2p = NULL;
        ja2p = NULL;
        num_elems = tp->num_elements;
        if (! is_et_used_by_aes(et)) {
            elem_count += num_elems;
            continue;   /* skip if not element type of interest */
        }
        if ((bp + 1) >= last_bp) {
            if ((bp + 1) == last_bp) {
                if (is_et_optional_for_aes(et))
                    continue;   /* at end of aes dpage but etype optional */
            }
            goto truncated;
        }
        eip = !! (bp[0] & 0x10);
        if (eip) { /* do bounds check on the element index */
            ei = bp[3];
            skip = false;
            if ((0 == k) && op->eiioe_auto && (1 == ei)) {
                /* heuristic: if first AES descriptor has EIP set and its
                 * element index equal to 1, then act as if the EIIOE field
                 * is one. */
                local_eiioe_force = true;
            }
            eiioe = (0x3 & bp[2]);
            if (local_eiioe_force && (0 == eiioe))
                eiioe = 1;
            if (1 == eiioe) {
                if ((ei < (elem_count + k)) ||
                    (ei > (elem_count + k + num_elems))) {
                    elem_count += num_elems;
                    skip = true;
                }
            } else {
                if ((ei < elem_count) || (ei > elem_count + num_elems)) {
                    if ((0 == ei) && (TPROTO_SAS == (0xf & bp[0])) &&
                        (1 == (bp[5] >> 6))) {
                        /* heuristic (hack) for Areca 8028 */
                        fake_ei = elem_count;
                        if (op->verbose > 2)
                            pr2serr("%s: hack, bad ei=%d, fake_ei=%d\n",
                                    __func__, ei, fake_ei);
                        ei = fake_ei;
                    } else {
                        elem_count += num_elems;
                        skip = true;
                    }
                }
            }
            if (skip) {
                if (op->verbose > 2)
                    pr2serr("skipping etype=0x%x, k=%d due to "
                            "element_index=%d bounds\n  effective eiioe=%d, "
                            "elem_count=%d, num_elems=%d\n", et, k,
                            ei, eiioe, elem_count, num_elems);
                continue;
            }
        }
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            sgj_pr_hr(jsp, "    %s: %s, %s: %d [ti=%d]\n", et_s,
                      etype_str(et, b, blen), si_ss, tp->se_id, k);
        }
        el_num = 0;

        for (j = 0; j < num_elems; ++j, bp += desc_len, ++el_num) {
            invalid = !!(bp[0] & 0x80);
            desc_len = bp[1] + 2;
            eip = !!(bp[0] & 0x10);
            eiioe = eip ? (0x3 & bp[2]) : 0;
            if (fake_ei >= 0)
                ind = fake_ei;
            else
                ind = eip ? bp[3] : el_num;
            proto = (0xf & bp[0]);
            if (op->ind_given) {
                if ((! match_ind_th) || (! match_ind_indiv(el_num, op)))
                    continue;
            }
            if (as_json) {
                if (NULL == jo2p) {
                    jo2p = sgj_new_unattached_object_r(jsp);
                    sgj_js_nv_ihexstr(jsp, jo2p, et_sn, et, NULL,
                                      etype_str(et, b, blen));
                    sgj_js_nv_ihexstr(jsp, jo2p, si_sn, tp->se_id, NULL,
                                      se_id_s);
                }
                if (NULL == ja2p)
                    ja2p = sgj_named_subarray_r(jsp, jo2p,
                                         sgj_convert2snake(aesdl, b, blen));
                jo3p = sgj_new_unattached_object_r(jsp);
                jo4p = sgj_named_subobject_r(jsp, jo3p, aesd_sn);
                sgj_js_nv_ihex(jsp, jo4p, "invalid", invalid);
                sgj_js_nv_ihex_nex(jsp, jo4p, "eip", eip, false,
                                   "element index present");
                sgj_js_nv_ihexstr(jsp, jo4p, "protocol_identifier", proto,
                          NULL, sg_get_trans_proto_str(proto, blen, b));
                if (eip)
                    sgj_js_nv_ihex(jsp, jo4p, "element_index", bp[3]);
            }
            if (eip)
                sgj_pr_hr(jsp, "      Element index: %d  eiioe=%d%s\n", ind,
                          eiioe, (((0 != eiioe) && local_eiioe_force) ?
                                                " but overridden" : ""));
            else
                sgj_pr_hr(jsp, "      Element %d descriptor\n", ind);
            if (invalid && (0 == op->inner_hex))
                sgj_pr_hr(jsp, "        flagged as invalid (no further "
                          "information)\n");
            else
                additional_elem_helper("        ", bp, desc_len, et,
                                       tesp, op, jo4p);
            if (as_json && jo3p)
                sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
        }       /* end_for inner loop over each element in current etype */
        elem_count += tp->num_elements;
        if (jsp->pr_as_json && jo2p)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }           /* end_for: loop over type descriptor headers */
    goto fini;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
fini:
    free(b);
    return;
}

/* SUBENC_HELP_TEXT_DPC  <sht> [0xb] */
static void
subenc_help_sdp(const uint8_t * resp, int resp_len, struct opts_t * op,
                sgj_opaque_p jop)
{
    int k, el, num_subs;
    uint32_t gen_code;
    const uint8_t * bp;
    const uint8_t * last_bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[80];
    static const int blen = sizeof(b);
    static const char * sht_dp = "Subenclosure help text diagnostic page";

    sgj_pr_hr(jsp, "%s:\n", sht_dp);
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_bp = resp + resp_len - 1;
    if (jsp->pr_as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(sht_dp, b, blen));
        sgj_js_nv_ihexstr(jsp, jop, pc_sn, SUBENC_NICKNAME_DPC, NULL, sht_dp);
    }
    sgj_haj_vi(jsp, jop, 2, noss_s, SGJ_SEP_COLON_1_SPACE, num_subs - 1,
               false);
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (jsp->pr_as_json)
        jap = sgj_named_subarray_r(jsp, jop, "subenclosure_help_text_list");
    bp = resp + 8;

    for (k = 0; k < num_subs; ++k, bp += el) {
        if ((bp + 3) > last_bp)
            goto truncated;
        if (jsp->pr_as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        el = sg_get_unaligned_be16(bp + 2) + 4;
        sgj_haj_vistr(jsp, jo2p, 4, si_s, SGJ_SEP_COLON_1_SPACE, bp[1], true,
                      (0 == bp[1] ? "primary" : NULL));
        if (el > 4)
            sgj_pr_hr(jsp, "    %.*s\n", el - 4, bp + 4);
        else
            sgj_pr_hr(jsp, "    <empty>\n");
        if (jsp->pr_as_json) {
            if (el > 4)
                sgj_js_nv_s_len_chk(jsp, jo2p, "subenclosure_help_text",
                                    bp + 4, el - 4);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

/* SUBENC_STRING_DPC  <"sstr"> [0xc] */
static void
subenc_string_sdp(const uint8_t * resp, int resp_len, struct opts_t * op,
                  sgj_opaque_p jop)
{
    int k, el, num_subs;
    uint32_t gen_code;
    const uint8_t * bp;
    const uint8_t * last_bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * ssi_dp = "Subenclosure String In diagnostic page";

    sgj_pr_hr(jsp, "%s:\n", ssi_dp);
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_bp = resp + resp_len - 1;
    if (jsp->pr_as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(ssi_dp, b, blen));
        sgj_js_nv_ihexstr(jsp, jop, pc_sn, SUBENC_NICKNAME_DPC, NULL, ssi_dp);
    }
    sgj_haj_vi(jsp, jop, 2, noss_s, SGJ_SEP_COLON_1_SPACE, num_subs - 1,
               false);
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (jsp->pr_as_json)
        jap = sgj_named_subarray_r(jsp, jop,
                                   "subenclosure_string_in_data_list");
    bp = resp + 8;

    for (k = 0; k < num_subs; ++k, bp += el) {
        if ((bp + 3) > last_bp)
            goto truncated;
        if (jsp->pr_as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        sgj_haj_vistr(jsp, jo2p, 4, si_s, SGJ_SEP_COLON_1_SPACE, bp[1], true,
                      (0 == bp[1] ? "primary" : NULL));
        el = sg_get_unaligned_be16(bp + 2) + 4;
        if (el > 4) {
            hex2str(bp + 40, el - 40, "    ", op->h2s_oformat, blen, b);
            if (jsp->pr_as_json && jsp->pr_out_hr)
                sgj_hr_str_out(jsp, b, strlen(b));
            else
                sgj_pr_hr(jsp, "%s\n", b);
        } else
            sgj_pr_hr(jsp, "    <empty>\n");
        if (jsp->pr_as_json) {
            sgj_js_nv_hex_bytes(jsp, jo2p, "subenclosure_string_in_data",
                                bp + 40, el - 40);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

/* SUBENC_NICKNAME_DPC <"snic"> [0xf] */
static void
subenc_nickname_sdp(const uint8_t * resp, int resp_len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool lc_z;
    int k, el, num_subs;
    uint32_t gen_code;
    const char * ccp;
    const uint8_t * bp;
    const uint8_t * last_bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[256];
    static const int blen = sizeof(b);
    static const char * sns_dp =
                "Subenclosure nickname status diagnostic page";
    static const char * snlc = "subenclosure nickname language code";
    static const char * sn_s = "subenclosure nickname";

    sgj_pr_hr(jsp, "%s:\n", sns_dp);
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_bp = resp + resp_len - 1;
    if (jsp->pr_as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(sns_dp, b, blen));
        sgj_js_nv_ihexstr(jsp, jop, pc_sn, SUBENC_NICKNAME_DPC, NULL, sns_dp);
    }
    sgj_haj_vi(jsp, jop, 2, noss_s, SGJ_SEP_COLON_1_SPACE, num_subs - 1,
               false);
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (jsp->pr_as_json)
        jap = sgj_named_subarray_r(jsp, jop,
                        "subenclosure_nickname_status_descriptor_list");
    bp = resp + 8;
    el = 40;
    for (k = 0; k < num_subs; ++k, bp += el) {
        if ((bp + el - 1) > last_bp)
            goto truncated;
        if (jsp->pr_as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        sgj_haj_vistr(jsp, jo2p, 4, si_s, SGJ_SEP_COLON_1_SPACE, bp[1], true,
                      (0 == bp[1] ? "primary" : NULL));
        sgj_haj_vi(jsp, jo2p, 4, "subenclosure nickname status",
                   SGJ_SEP_COLON_1_SPACE, bp[2], true);
        sgj_haj_vi(jsp, jo2p, 4, "subenclosure nickname additional status",
                   SGJ_SEP_COLON_1_SPACE, bp[3], true);

        lc_z = ((0 == bp[6]) && (0 == bp[7]));
        if (lc_z)
            sgj_pr_hr(jsp, "    %s: en\n", snlc);
        else
            sgj_pr_hr(jsp, "    %s: %.2s\n", snlc, bp + 6);
        sgj_pr_hr(jsp, "    %s: %.*s\n", sn_s, 32, bp + 8);
        if (jsp->pr_as_json) {
            ccp = sgj_convert2snake(snlc, b, blen);
            if (lc_z)
                sgj_js_nv_s(jsp, jo2p, ccp, "en");
            else
                sgj_js_nv_s_len_chk(jsp, jo2p, ccp, bp + 6, 2);
            sgj_js_nv_s_len_chk(jsp, jo2p, sgj_convert2snake(sn_s, b, blen),
                                bp + 8, 32);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

/* SUPPORTED_DPC or SUPPORTED_SES_DPC,  <"sdp" or "ssp">, [0x0 or 0xd] */
static void
supported_pages_both_sdp(bool is_ssp, const uint8_t * resp, int resp_len,
                         struct opts_t * op, sgj_opaque_p jop)
{
    bool got1, as_json;
    int k, n, code, prev;
    const char * ccp;
    const struct diag_page_abbrev * ap;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * ssp =
                "Supported SES diagnostic pages diagnostic page";
    static const char * sdp = "Supported diagnostic pages diagnostic page";

    as_json = jsp->pr_as_json;
    ccp = is_ssp ? ssp : sdp;
    sgj_pr_hr(jsp, "%s:\n", ccp);
    if (as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(ccp, b, blen));
        sgj_js_nv_ihexstr(jsp, jop, pc_sn, (is_ssp ? 0xd : 0x0), NULL, ccp);
        jap = sgj_named_subarray_r(jsp, jop, "supported_page_list");
    }
    for (k = 0, prev = 0; k < (resp_len - 4); ++k, prev = code) {
        code = resp[k + 4];
        if (code < prev)
            break;      /* assume to be padding at end */
        if (as_json)
            jo2p = sgj_new_unattached_object_r(jsp);

        ccp = find_diag_page_desc(code);
        if (ccp) {
            n = sg_scnpr(b, blen, "  %s [", ccp);
            for (ap = dp_abbrev, got1 = false; ap->abbrev; ++ap) {
                if (ap->page_code == code) {
                    n += sg_scnpr(b + n, blen - n, "%s%s", (got1 ? "," : ""),
                                  ap->abbrev);
                    got1 = true;
                }
            }
            sgj_pr_hr(jsp, "%s] [0x%x]\n", b, code);
        } else {
            ccp = find_dpage_cat_str(code);
            sgj_pr_hr(jsp, "  <%s> [0x%x]\n", ccp, code);
        }
        if (as_json) {
            sgj_js_nv_ihexstr(jsp, jo2p, pc_sn, code, NULL, ccp);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
    }
}

/* An array of Download microcode status field values and descriptions */
static struct diag_page_code mc_status_arr[] = {
    {0x0, "No download microcode operation in progress"},
    {0x1, "Download in progress, awaiting more"},
    {0x2, "Download complete, updating non-volatile storage"},
    {0x3, "Updating non-volatile storage with deferred microcode"},
    {0x10, "Complete, no error, starting now"},
    {0x11, "Complete, no error, start after hard reset or power cycle"},
    {0x12, "Complete, no error, start after power cycle"},
    {0x13, "Complete, no error, start after activate_mc, hard reset or "
           "power cycle"},
    {0x80, "Error, discarded, see additional status"},
    {0x81, "Error, discarded, image error"},
    {0x82, "Timeout, discarded"},
    {0x83, "Internal error, need new microcode before reset"},
    {0x84, "Internal error, need new microcode, reset safe"},
    {0x85, "Unexpected activate_mc received"},
    {0x1000, NULL},
};

static const char *
get_mc_status(uint8_t status_val)
{
    const struct diag_page_code * mcsp;

    for (mcsp = mc_status_arr; mcsp->desc; ++mcsp) {
        if (status_val == mcsp->page_code)
            return mcsp->desc;
    }
    return "";
}

/* DOWNLOAD_MICROCODE_DPC  <"dm"> [0xe] */
static void
download_code_sdp(const uint8_t * resp, int resp_len, struct opts_t * op,
                  sgj_opaque_p jop)
{
    int k, num_subs;
    uint32_t gen_code, mx_sz, ebo;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const char * cp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * dm_dp = "Download microcode status diagnostic page";
    static const char * dmsdl = "Download microcode status descriptor list";
    static const char * sdm_sn = "subenclosure_download_microcode";

    sgj_pr_hr(jsp, "%s:\n", dm_dp);
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_bp = resp + resp_len - 1;
    if (jsp->pr_as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop,
                                    sgj_convert2snake(dm_dp, b, blen));
        sgj_js_nv_ihexstr(jsp, jop, pc_sn, DOWNLOAD_MICROCODE_DPC, NULL,
                          dm_dp);
    }
    sgj_haj_vi(jsp, jop, 2, noss_s, SGJ_SEP_COLON_1_SPACE, num_subs - 1,
               false);
    gen_code = sg_get_unaligned_be32(resp + 4);
    sgj_haj_vi(jsp, jop, 2, gc_s, SGJ_SEP_COLON_1_SPACE, gen_code, true);
    if (jsp->pr_as_json)
        jap = sgj_named_subarray_r(jsp, jop,
                                   sgj_convert2snake(dmsdl, b, blen));

    sgj_pr_hr(jsp, "  %s:\n", dmsdl);
    bp = resp + 8;

    for (k = 0; k < num_subs; ++k, bp += 16) {
        if ((bp + 3) > last_bp)
            goto truncated;
        if (jsp->pr_as_json)
            jo2p = sgj_new_unattached_object_r(jsp);
        cp = (0 == bp[1]) ? " [primary]" : "";
        sgj_pr_hr(jsp, "   %s: %d%s\n", si_s, bp[1], cp);
        cp = get_mc_status(bp[2]);
        if (strlen(cp) > 0) {
            sgj_pr_hr(jsp, "     download microcode status: %s [0x%x]\n",
                      cp, bp[2]);
            sgj_pr_hr(jsp, "     download microcode additional status: "
                      "0x%x\n", bp[3]);
        } else
            sgj_pr_hr(jsp, "     download microcode status: 0x%x [additional "
                      "status: 0x%x]\n", bp[2], bp[3]);
        mx_sz = sg_get_unaligned_be32(bp + 4);
        sgj_pr_hr(jsp, "     download microcode maximum size: %d bytes\n",
                  mx_sz);
        sgj_pr_hr(jsp, "     download microcode expected buffer id: 0x%x\n",
                   bp[11]);
        ebo = sg_get_unaligned_be32(bp + 12);
        sgj_pr_hr(jsp, "     download microcode expected buffer offset: "
                  "%d\n", ebo);
        if (jsp->pr_as_json) {
            sgj_js_nv_ihex(jsp, jo2p, si_sn, bp[1]);
            snprintf(b, blen, "%s_status", sdm_sn);
            sgj_js_nv_ihexstr(jsp, jo2p, b, bp[2], NULL,
                              get_mc_status(bp[2]));
            snprintf(b, blen, "%s_additional_status", sdm_sn);
            sgj_js_nv_ihex(jsp, jo2p, b, bp[3]);
            snprintf(b, blen, "%s_maximum_size", sdm_sn);
            sgj_js_nv_ihex(jsp, jo2p, b, mx_sz);
            snprintf(b, blen, "%s_expected_buffer_id", sdm_sn);
            sgj_js_nv_ihex(jsp, jo2p, b, bp[11]);
            snprintf(b, blen, "%s_expected_buffer_offset", sdm_sn);
            sgj_js_nv_ihex(jsp, jo2p, b, ebo);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
        }
    }
    return;
truncated:
    pr2serr("    <<<%s: %s>>>\n", __func__, rts_s);
    return;
}

/* Reads hex data from command line, stdin or a file when in_hex is true.
 * Reads binary from stdin or file when in_hex is false. Returns 0 on
 * success. If inp is a file and may_have_at, then the
 * first character is skipped to get filename (since it should be '@'). */
static int
read_hex(const char * inp, uint8_t * arr, int mx_arr_len, int * arr_len,
         bool in_hex, bool may_have_at, int vb)
{
    bool has_stdin, split_line;
    int in_len, e, k, j, m, off, off_fn;
    unsigned int h;
    const char * lcp;
    char * cp;
    char * c2p;
    char line[512];
    char carry_over[4];
    FILE * fp = NULL;

    if ((NULL == inp) || (NULL == arr) || (NULL == arr_len))
        return SG_LIB_LOGIC_ERROR;
    off_fn = may_have_at ? 1 : 0;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len) {
        *arr_len = 0;
        return 0;
    }
    has_stdin = ((1 == in_len) && ('-' == inp[0]));

    if (! in_hex) {     /* binary, assume its not on the command line, */
        int fd;         /* that leaves stdin or a file (pipe) */
        struct stat a_stat;

        if (has_stdin)
            fd = STDIN_FILENO;
        else {
            fd = open(inp + off_fn, O_RDONLY);
            if (fd < 0) {
                e = errno;
                pr2serr("unable to open binary file %s: %s\n", inp + off_fn,
                         safe_strerror(e));
                return sg_convert_errno(e);
            }
        }
        k = read(fd, arr, mx_arr_len);
        if (k <= 0) {
            int res = SG_LIB_SYNTAX_ERROR;

            if (0 == k)
                pr2serr("read 0 bytes from binary file %s\n", inp + off_fn);
            else {
                e = errno;
                pr2serr("read from binary file %s: %s\n", inp + off_fn,
                        safe_strerror(e));
                res = sg_convert_errno(e);
            }
            if (! has_stdin)
                close(fd);
            return res;
        }
        if ((0 == fstat(fd, &a_stat)) && S_ISFIFO(a_stat.st_mode)) {
            /* pipe; keep reading till error or 0 read */
            while (k < mx_arr_len) {
                m = read(fd, arr + k, mx_arr_len - k);
                if (0 == m)
                   break;
                if (m < 0) {
                    e = errno;
                    pr2serr("read from binary pipe %s: %s\n", inp + off_fn,
                            safe_strerror(e));
                    if (! has_stdin)
                        close(fd);
                    return sg_convert_errno(e);
                }
                k += m;
            }
        }
        *arr_len = k;
        if (! has_stdin)
            close(fd);
        return 0;
    }
    if (has_stdin || (! may_have_at) || ('@' == inp[0])) {
        /* read hex from stdin or file */
        if (has_stdin)
            fp = stdin;
        else {
            fp = fopen(inp + off_fn, "r");
            if (NULL == fp) {
                e = errno;
                pr2serr("%s: unable to open file: %s [%s]\n", __func__,
                        inp + off_fn, safe_strerror(e));
                return sg_convert_errno(e);
            }
        }
        carry_over[0] = 0;
        for (j = 0, off = 0; j < MX_DATA_IN_LINES; ++j) {
            if (NULL == fgets(line, sizeof(line), fp))
                break;
            in_len = strlen(line);
            if (in_len > 0) {
                if ('\n' == line[in_len - 1]) {
                    --in_len;
                    line[in_len] = '\0';
                    split_line = false;
                } else
                    split_line = true;
            }
            if (in_len < 1) {
                carry_over[0] = 0;
                continue;
            }
            if (carry_over[0]) {
                if (isxdigit((uint8_t)line[0])) {
                    carry_over[1] = line[0];
                    carry_over[2] = '\0';
                    if (1 == sscanf(carry_over, "%x", &h))
                        arr[off - 1] = h;       /* back up and overwrite */
                    else {
                        pr2serr("%s: carry_over error ['%s'] around line "
                                "%d\n", __func__, carry_over, j + 1);
                        goto err_with_fp;
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
            if (in_len != k) {
                pr2serr("%s: syntax error at line %d, pos %d\n", __func__,
                        j + 1, m + k + 1);
                if (vb > 2)
                    pr2serr("first 40 characters of line: %.40s\n", line);
                goto err_with_fp;
            }
            for (k = 0; k < (mx_arr_len - off); ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        pr2serr("%s: hex number larger than 0xff in line %d, "
                                "pos %d\n", __func__, j + 1,
                                (int)(lcp - line + 1));
                        if (vb > 2)
                            pr2serr("first 40 characters of line: %.40s\n",
                                    line);
                        goto err_with_fp;
                    }
                    if (split_line && (1 == strlen(lcp))) {
                        /* single trailing hex digit might be a split pair */
                        carry_over[0] = *lcp;
                    }
                    arr[off + k] = h;
                    lcp = strpbrk(lcp, " ,\t");
                    if (NULL == lcp)
                        break;
                    lcp += strspn(lcp, " ,\t");
                    if ('\0' == *lcp)
                        break;
                } else {
                    pr2serr("%s: error in line %d, at pos %d\n", __func__,
                            j + 1, (int)(lcp - line + 1));
                    if (vb > 2)
                        pr2serr("first 40 characters of line: %.40s\n", line);
                    goto err_with_fp;
                }
            }
            off += k + 1;
            if (off >= mx_arr_len)
                break;
        }
        *arr_len = off;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF, ");
        if (in_len != k) {
            pr2serr("%s: error at pos %d\n", __func__, k + 1);
            goto err_with_fp;
        }
        for (k = 0; k < mx_arr_len; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    pr2serr("%s: hex number larger than 0xff at pos %d\n",
                            __func__, (int)(lcp - inp + 1));
                    goto err_with_fp;
                }
                arr[k] = h;
                cp = (char *)strchr(lcp, ',');
                c2p = (char *)strchr(lcp, ' ');
                if (NULL == cp)
                    cp = c2p;
                if (NULL == cp)
                    break;
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                pr2serr("%s: error at pos %d\n", __func__,
                        (int)(lcp - inp + 1));
                goto err_with_fp;
            }
        }
        *arr_len = k + 1;
    }
    if (vb > 3) {
        pr2serr("%s: user provided data:\n", __func__);
        hex2stderr(arr, *arr_len, 0);
    }
    if (fp && (fp != stdin))
        fclose(fp);
    return 0;

err_with_fp:
    if (fp && (fp != stdin))
        fclose(fp);
    return SG_LIB_SYNTAX_ERROR;
}

/* Process all status/in diagnostic pages. Return of 0 is good. */
static int
process_status_dpage(struct sg_pt_base * ptvp, int page_code, uint8_t * resp,
                     int resp_len, struct opts_t * op, sgj_opaque_p jop)
{
    int num_ths, k;
    int ret = 0;
    uint32_t ref_gen_code;
    const char * ccp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jap = NULL;
    struct enclosure_info primary_info;
    struct th_es_t tes;
    struct th_es_t * tesp;
    char b[128];
    char e[64];
    static const int blen = sizeof(b);
    static const int elen = sizeof(e);
    static const char * const ht_dp = "Help text diagnostic page";

    tesp = &tes;
    memset(tesp, 0, sizeof(tes));
    if ((ccp = find_in_diag_page_desc(page_code)))
        snprintf(b, blen, "%s %s", ccp, dp_s);
    else
        snprintf(b, blen, "%s 0x%x", dp_s, page_code);
    ccp = b;
    if (op->do_raw) {
        if (1 == op->do_raw)
            hex2stdout(resp + 4, resp_len - 4, -1);
        else {
            if (sg_set_binary_mode(STDOUT_FILENO) < 0)
                perror("sg_set_binary_mode");
            dStrRaw(resp, resp_len);
        }
        goto fini;
    } else if (op->do_hex) {
        if (op->do_hex > 2) {
            if (op->do_hex > 3) {
                if (4 == op->do_hex)
                    printf("\n# %s:\n", ccp);
                else
                    printf("\n# %s [0x%x]:\n", ccp, page_code);
            }
            hex2stdout(resp, resp_len, -1);
         } else {
            printf("# Response in hex for %s:\n", ccp);
            hex2stdout(resp, resp_len, (2 == op->do_hex));
        }
        goto fini;
    }

    memset(&primary_info, 0, sizeof(primary_info));
    switch (page_code) {
    case SUPPORTED_DPC:
        supported_pages_both_sdp(false, resp, resp_len, op, jop);
        break;
    case CONFIGURATION_DPC:
        configuration_sdp(resp, resp_len, op, jop);
        break;
    case ENC_STATUS_DPC:
        if (op->no_config) {
            enc_status_sdp(NULL, 0, resp, resp_len, op, jop);
            break;
        }
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                          MX_ELEM_HDR, &ref_gen_code,
                                          &primary_info, op);
        if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if ((1 == type_desc_hdr_count) && primary_info.have_info)
            sgj_pr_hr(jsp, "  %s (hex): %" PRIx64 "\n", peli,
                      sg_get_unaligned_be64(primary_info.enc_log_id));
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        enc_status_sdp(tesp, ref_gen_code, resp, resp_len, op, jop);
        break;
    case ARRAY_STATUS_DPC:
        if (op->no_config) {
            array_status_sdp(NULL, 0, resp, resp_len, op, jop);
            break;
        }
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                          MX_ELEM_HDR, &ref_gen_code,
                                          &primary_info, op);
        if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if ((1 == type_desc_hdr_count) && primary_info.have_info)
            sgj_pr_hr(jsp, "  %s (hex): %" PRIx64 "\n", peli,
                      sg_get_unaligned_be64(primary_info.enc_log_id));
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        array_status_sdp(tesp, ref_gen_code, resp, resp_len, op, jop);
        break;
    case HELP_TEXT_DPC:         /* <"ht"> */
        sgj_pr_hr(jsp, "%s (for primary subenclosure):\n", ht_dp);
        if (jsp->pr_as_json) {
            /* re-use (overwrite) passed jop argument */
            jop = sgj_named_subobject_r(jsp, jop,
                                        sgj_convert2snake(ht_dp, e, elen));
            sgj_js_nv_ihexstr(jsp, jop, pc_sn, HELP_TEXT_DPC, NULL, ht_dp);
        }
        if (resp_len > 4)
            sgj_pr_hr(jsp, "  %.*s\n", resp_len - 4, resp + 4);
        else
            sgj_pr_hr(jsp, "  <empty>\n");
        if (jsp->pr_as_json)
            sgj_js_nv_s_len_chk(jsp, jop, "primary_subenclosure_help_text",
                                resp + 4, resp_len - 4);
        break;
    case STRING_DPC:    /* <"str"> */
        snprintf(b, blen, "String In %s", dp_s);
        sgj_pr_hr(jsp, "%s (for primary subenclosure):\n", b);
        if (jsp->pr_as_json) {
            /* re-use (overwrite) passed jop argument */
            jop = sgj_named_subobject_r(jsp, jop,
                                        sgj_convert2snake(b, e, elen));
            sgj_js_nv_ihexstr(jsp, jop, pc_sn, STRING_DPC, NULL, b);
        }
        if (resp_len > 4) {
            int n = 6 * (resp_len - 4);
            char * p = (char *)malloc(n);

            if (p) {
                hex2str(resp + 4, resp_len - 4, "", op->h2s_oformat, n, p);
                if (jsp->pr_as_json && jsp->pr_out_hr)
                    sgj_hr_str_out(jsp, p, strlen(p));
                else
                    sgj_pr_hr(jsp, "%s\n", p);
                free(p);
            }
        } else
            sgj_pr_hr(jsp, "  <empty>\n");
        if (jsp->pr_as_json)
            sgj_js_nv_hex_bytes(jsp, jop,
                                "primary_subenclosure_string_in_data",
                                resp + 4, resp_len - 4);
        break;
    case THRESHOLD_DPC:
        if (op->no_config) {
            threshold_sdp(NULL, 0, resp, resp_len, op, jop);
            break;
        }
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                          MX_ELEM_HDR, &ref_gen_code,
                                          &primary_info, op);
        if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if ((1 == type_desc_hdr_count) && primary_info.have_info)
            sgj_pr_hr(jsp, "  %s (hex): %" PRIx64 "\n", peli,
                      sg_get_unaligned_be64(primary_info.enc_log_id));
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        threshold_sdp(tesp, ref_gen_code, resp, resp_len, op, jop);
        break;
    case ELEM_DESC_DPC:
        if (op->no_config) {
            element_desc_sdp(NULL, 0, resp, resp_len, op, jop);
            break;
        }
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                              MX_ELEM_HDR, &ref_gen_code,
                                              &primary_info, op);
            if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if ((1 == type_desc_hdr_count) && primary_info.have_info)
            sgj_pr_hr(jsp, "  %s (hex): %" PRIx64 "\n", peli,
                      sg_get_unaligned_be64(primary_info.enc_log_id));
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        element_desc_sdp(tesp, ref_gen_code, resp, resp_len, op, jop);
        break;
    case SHORT_ENC_STATUS_DPC:  /* <"ses"> */
        sgj_pr_hr(jsp, "Short %s %s, status=0x%x\n", es_s, dp_s, resp[1]);
        break;
    case ENC_BUSY_DPC:
        sgj_pr_hr(jsp, "Enclosure Busy %s, busy=%d [%s=0x%x]\n", dp_s,
                  resp[1] & 1, vs_s, (resp[1] >> 1) & 0xff);
        break;
    case ADD_ELEM_STATUS_DPC:
        if (op->no_config) {
            additional_elem_sdp(NULL, 0, resp, resp_len, op, jop);
            break;
        }
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                          MX_ELEM_HDR, &ref_gen_code,
                                          &primary_info, op);
        if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if (primary_info.have_info)
            sgj_pr_hr(jsp, "  %s (hex): %" PRIx64 "\n", peli,
                      sg_get_unaligned_be64(primary_info.enc_log_id));
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        additional_elem_sdp(tesp, ref_gen_code, resp, resp_len, op, jop);
        break;
    case SUBENC_HELP_TEXT_DPC:
        subenc_help_sdp(resp, resp_len, op, jop);
        break;
    case SUBENC_STRING_DPC:
        subenc_string_sdp(resp, resp_len, op, jop);
        break;
    case SUPPORTED_SES_DPC:
        supported_pages_both_sdp(true, resp, resp_len, op, jop);
        break;
    case DOWNLOAD_MICROCODE_DPC:
        download_code_sdp(resp, resp_len, op, jop);
        break;
    case SUBENC_NICKNAME_DPC:
        subenc_nickname_sdp(resp, resp_len, op, jop);
        break;
    default:
        sgj_pr_hr(jsp, "Cannot decode response from %s: %s\n",
                  dp_s, ccp);
        if (resp_len > 0) {
            int n = resp_len * 4;
            char * p = (char *)malloc(n);

            if (p) {
                hex2str(resp, resp_len, "", op->h2s_oformat, n, p);
                if (jsp->pr_as_json && jsp->pr_out_hr)
                    sgj_hr_str_out(jsp, p, strlen(p));
                else
                    sgj_pr_hr(jsp, "%s\n", p);
                free(p);
            }
        }
        if (jsp->pr_as_json) {
            snprintf(b, blen, "%s_0x%x", dp_sn, page_code);
            jop = sgj_named_subobject_r(jsp, jop, b);
            ccp = find_dpage_cat_str(page_code);
            sgj_js_nv_ihexstr(jsp, jop, pc_sn, page_code, NULL, ccp);
            sgj_js_nv_ihexstr_nex(jsp, jop, "page_length", resp_len, true,
                                  NULL, NULL, "[unit: byte]");
            if (resp_len > 0) {
                bool gt256 = (resp_len > 256);
                uint8_t * bp = resp;
                int rem;

                if (gt256)
                    jap = sgj_named_subarray_r(jsp, jop, "in_hex_list");
                for (k = 0; k < resp_len; bp += 256, k += 256) {
                    rem = resp_len - k;
                    if (gt256)
                        jo2p = sgj_new_unattached_object_r(jsp);
                    else
                        jo2p = jop;
                    sgj_js_nv_hex_bytes(jsp, jo2p, in_hex_sn, bp,
                                        (rem > 256) ? 256 : rem);
                    if (gt256)
                        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
                }
            }
        }
        break;
    }

fini:
    return ret;
}

static int
process_many_status_dpages(struct sg_pt_base * ptvp,  uint8_t * resp,
                           bool with_joinpgs, struct opts_t * op,
                           sgj_opaque_p jop)
{
    int k, n, ret, resp_len, pg_cd;
    int defer_err = 0;
    uint8_t pc, prev;
    uint8_t supp_dpg_arr[256];
    static const int s_arr_sz = sizeof(supp_dpg_arr);

    memset(supp_dpg_arr, 0, s_arr_sz);
    ret = do_rec_diag(ptvp, SUPPORTED_DPC, resp, op->maxlen, op, &resp_len);
    if (ret)        /* SUPPORTED_DPC failed so try SUPPORTED_SES_DPC */
        ret = do_rec_diag(ptvp, SUPPORTED_SES_DPC, resp, op->maxlen, op,
                          &resp_len);
    if (ret)
        return ret;
    /* build list of dpages to visit */
    for (n = 0, pc = 0; (n < s_arr_sz) && (n < (resp_len - 4)); ++n) {
        prev = pc;
        pc = resp[4 + n];
        if (prev > pc) {    /* sanity check */
            if (pc) {       /* could be zero pad at end which is ok */
                pr2serr("%s: Supported (SES) dpage seems corrupt, should "
                        "ascend\n", __func__);
                return SG_LIB_CAT_OTHER;
            }
            break;
        }
        if (pc > 0x2f)  /* non-SES diagnostic pages */
            break;
        supp_dpg_arr[n] = pc;
    }
    for (k = 0; k < n; ++k) {
        pg_cd = supp_dpg_arr[k];
        if ((! with_joinpgs) && dpage_in_join(pg_cd, op))
            continue;
        ret = do_rec_diag(ptvp, pg_cd, resp, op->maxlen, op, &resp_len);
        if (ret) {
            if (SG_LIB_OK_FALSE == ret)
                continue;       /* not found in user data */
            if (op->do_warn || with_joinpgs)
                return ret;
            defer_err = ret;
            if (op->verbose)
                pr2serr("%s: deferring error on page_code=0x%x, continuing\n",
                        __func__, pg_cd);
            continue;
        }
        ret = process_status_dpage(ptvp, pg_cd, resp, resp_len, op, jop);
        if (ret) {
            defer_err = ret;
            if (op->verbose > 2)
                pr2serr("%s: failure decoding page_code=0x%x, ret=%d, "
                        "continuing\n", __func__, pg_cd, ret);
        }
    }
    return defer_err;
}

/* Display "status" page or pages (if op->page_code==0xff) . data-in from
 * SES device or user provided (with --data= option). Return 0 for success */
static int
process_1ormore_status_dpages(struct sg_pt_base * ptvp, struct opts_t * op,
                      sgj_opaque_p jop)
{
    int page_code, ret, resp_len;
    uint8_t * resp = NULL;
    uint8_t * free_resp = NULL;

    resp = sg_memalign(op->maxlen, 0, &free_resp, false);
    if (NULL == resp) {
        pr2serr("%s: unable to allocate %d bytes on heap\n", __func__,
                op->maxlen);
        ret = -1;
        goto fini;
    }
    page_code = op->page_code;
    if (ALL_DPC == page_code) {         /* <"--page=all"> */
        ret = process_many_status_dpages(ptvp, resp, true, op, jop);
    } else {    /* asking for a specific page code */
        ret = do_rec_diag(ptvp, page_code, resp, op->maxlen, op, &resp_len);
        if (ret)
            goto fini;
        ret = process_status_dpage(ptvp, page_code, resp, resp_len, op, jop);
    }

fini:
    if (free_resp)
        free(free_resp);
    return ret;
}

static void
devslotnum_and_sasaddr(struct join_row_t * jrp, const uint8_t * ae_bp)
{
    if ((NULL == jrp) || (NULL == ae_bp) || (0 == (0x10 & ae_bp[0])))
        return; /* sanity and expect EIP=1 */
    switch (0xf & ae_bp[0]) {
    case TPROTO_FCP:
        jrp->dev_slot_num = ae_bp[7];
        break;
    case TPROTO_SAS:
        if (0 == (0xc0 & ae_bp[5])) {
            /* only for device slot and array device slot elements */
            jrp->dev_slot_num = ae_bp[7];
            if (ae_bp[4] > 0) {        /* number of phys */
                int m;

                /* Use the first phy's "SAS ADDRESS" field */
                for (m = 0; m < 8; ++m)
                    jrp->sas_addr[m] = ae_bp[(4 + 4 + 12) + m];
            }
        }
        break;
    case TPROTO_PCIE:
        jrp->dev_slot_num = ae_bp[7];
        break;
    default:
        ;
    }
}

static const char *
offset_str(long offset, bool in_hex, char * b, int blen)
{
    if (in_hex && (offset >= 0))
        snprintf(b, blen, "0x%lx", offset);
    else
        snprintf(b, blen, "%ld", offset);
    return b;
}

/* Returns broken_ei which is only true when EIP=1 and EIIOE=0 is overridden
 * as outlined in join array description near the top of this file. */
static bool
join_aes_helper(const uint8_t * ae_bp, const uint8_t * ae_last_bp,
                const struct th_es_t * tesp, const struct opts_t * op)
{
    int k, j, ei, eiioe, aes_i, hex, blen;
    bool eip, broken_ei;
    struct join_row_t * jrp;
    struct join_row_t * jr2p;
    const struct type_desc_hdr_t * tdhp = tesp->th_base;
    char b[20];

    jrp = tesp->j_base;
    blen = sizeof(b);
    hex = op->do_hex;
    broken_ei = false;
    /* loop over all type descriptor headers in the Configuration dpge */
    for (k = 0, aes_i = 0; k < tesp->num_ths; ++k, ++tdhp) {
        if (is_et_used_by_aes(tdhp->etype)) {
            /* only consider element types that AES element are permiited
             * to refer to, then loop over those number of elements */
            for (j = 0; j < tdhp->num_elements;
                 ++j, ++aes_i, ae_bp += ae_bp[1] + 2) {
                if ((ae_bp + 1) > ae_last_bp) {
                    if (op->verbose || op->do_warn)
                        pr2serr("warning: %s: off end of ae page\n",
                                __func__);
                    return broken_ei;
                }
                eip = !!(ae_bp[0] & 0x10); /* EIP == Element Index Present */
                if (eip) {
                    eiioe = 0x3 & ae_bp[2];
                    if ((0 == eiioe) && op->eiioe_force)
                        eiioe = 1;
                } else
                    eiioe = 0;
                if (eip && (1 == eiioe)) {         /* EIP and EIIOE=1 */
                    ei = ae_bp[3];
                    jr2p = tesp->j_base + ei;
                    if ((ei >= tesp->num_j_eoe) ||
                        (NULL == jr2p->enc_statp)) {
                        pr2serr("%s: oi=%d, ei=%d [num_eoe=%d], eiioe=1 "
                                "not in join_arr\n", __func__, k, ei,
                                tesp->num_j_eoe);
                        return broken_ei;
                    }
                    devslotnum_and_sasaddr(jr2p, ae_bp);
                    if (jr2p->ae_statp) {
                        if (op->do_warn || op->verbose) {
                            pr2serr("warning: aes slot already in use, "
                                    "keep existing AES+%s\n\t",
                                    offset_str(jr2p->ae_statp - add_elem_rsp,
                                               hex, b, blen));
                            pr2serr("dropping AES+%s [length=%d, oi=%d, "
                                    "ei=%d, aes_i=%d]\n",
                                    offset_str(ae_bp - add_elem_rsp, hex, b,
                                               blen),
                                    ae_bp[1] + 2, k, ei, aes_i);
                        }
                    } else
                        jr2p->ae_statp = ae_bp;
                } else if (eip && (0 == eiioe)) {     /* SES-2 so be careful */
                    ei = ae_bp[3];
try_again:
                    /* Check AES dpage descriptor ei is valid */
                    for (jr2p = tesp->j_base; jr2p->enc_statp; ++jr2p) {
                        if (broken_ei) {
                            if (ei == jr2p->ei_aess)
                                break;
                        } else {
                            if (ei == jr2p->ei_eoe)
                                break;
                        }
                    }
                    if (NULL == jr2p->enc_statp) {
                        pr2serr("warning: %s: oi=%d, ei=%d (broken_ei=%d) "
                                "not in join_arr\n", __func__, k, ei,
                                (int)broken_ei);
                        return broken_ei;
                    }
                    if (! is_et_used_by_aes(jr2p->etype)) {
                        /* unexpected element type so  ... */
                        broken_ei = true;
                        goto try_again;
                    }
                    devslotnum_and_sasaddr(jr2p, ae_bp);
                    if (jr2p->ae_statp) {
                        /* 1 to 1 AES to ES mapping assumption violated */
                        if ((0 == ei) && (TPROTO_SAS == (0xf & ae_bp[0])) &&
                            (1 == (ae_bp[5] >> 6))) {
                            /* heuristic for (hack) Areca 8028 */
                            for (jr2p = tesp->j_base; jr2p->enc_statp;
                                 ++jr2p) {
                                if ((-1 == jr2p->indiv_i) ||
                                    (! is_et_used_by_aes(jr2p->etype)) ||
                                    jr2p->ae_statp)
                                    continue;
                                jr2p->ae_statp = ae_bp;
                                break;
                            }
                            if ((NULL == jr2p->enc_statp) &&
                                (op->do_warn || op->verbose))
                                pr2serr("warning2: dropping AES+%s [length="
                                        "%d, oi=%d, ei=%d, aes_i=%d]\n",
                                        offset_str(ae_bp - add_elem_rsp, hex,
                                                   b, blen),
                                        ae_bp[1] + 2, k, ei, aes_i);
                        } else if (op->do_warn || op->verbose) {
                            pr2serr("warning3: aes slot already in use, "
                                    "keep existing AES+%s\n\t",
                                    offset_str(jr2p->ae_statp - add_elem_rsp,
                                               hex, b, blen));
                            pr2serr("dropping AES+%s [length=%d, oi=%d, ei="
                                    "%d, aes_i=%d]\n",
                                    offset_str(ae_bp - add_elem_rsp, hex, b,
                                               blen),
                                    ae_bp[1] + 2, k, ei, aes_i);
                        }
                    } else
                        jr2p->ae_statp = ae_bp;
                } else if (eip) {              /* EIP and EIIOE=2,3 */
                    ei = ae_bp[3];
                    for (jr2p = tesp->j_base; jr2p->enc_statp; ++jr2p) {
                        if (ei == jr2p->ei_eoe)
                            break;  /* good, found match on ei_eoe */
                    }
                    if (NULL == jr2p->enc_statp) {
                        pr2serr("warning: %s: oi=%d, ei=%d, not in "
                                "join_arr\n", __func__, k, ei);
                        return broken_ei;
                    }
                    if (! is_et_used_by_aes(jr2p->etype)) {
                        pr2serr("warning: %s: oi=%d, ei=%d, unexpected "
                                "%s=0x%x\n", __func__, k, ei, et_sn,
                                jr2p->etype);
                        return broken_ei;
                    }
                    devslotnum_and_sasaddr(jr2p, ae_bp);
                    if (jr2p->ae_statp) {
                        if (op->do_warn || op->verbose) {
                            pr2serr("warning3: aes slot already in use, "
                                    "keep existing AES+%s\n\t",
                                    offset_str(jr2p->ae_statp - add_elem_rsp,
                                               hex, b, blen));
                            pr2serr("dropping AES+%s [length=%d, oi=%d, ei="
                                    "%d, aes_i=%d]\n",
                                    offset_str(ae_bp - add_elem_rsp, hex, b,
                                               blen),
                                    ae_bp[1] + 2, k, ei, aes_i);
                        }
                    } else
                        jr2p->ae_statp = ae_bp;
                } else {    /* EIP=0 */
                    /* step jrp over overall elements or those with
                     * jrp->ae_statp already used */
                    while (jrp->enc_statp && ((-1 == jrp->indiv_i) ||
                                              jrp->ae_statp))
                        ++jrp;
                    if (NULL == jrp->enc_statp) {
                        pr2serr("warning: %s: join_arr has no space for "
                                "ae\n", __func__);
                        return broken_ei;
                    }
                    jrp->ae_statp = ae_bp;
                    ++jrp;
                }
            }       /* end_for: loop over non-overall elements of the
                     * current type descriptor header */
        } else {    /* element type _not_ relevant to ae status */
            /* step jrp over overall and individual elements */
            for (j = 0; j <= tdhp->num_elements; ++j, ++jrp) {
                if (NULL == jrp->enc_statp) {
                    pr2serr("warning: %s: join_arr has no space\n",
                            __func__);
                    return broken_ei;
                }
            }
        }
    }       /* end_for: loop over type descriptor headers */
    return broken_ei;
}


/* User output of join array */
static void
join_array_display(struct th_es_t * tesp, struct opts_t * op,
                   sgj_opaque_p jop)
{
    bool got1, need_aes;
    int k, j, n, desc_len, dn_len;
    const uint8_t * ae_bp;
    const char * cp;
    const uint8_t * ed_bp;
    struct join_row_t * jrp;
    uint8_t * t_bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char * b;
    static const int blen = 2048;

    b = (char *)malloc(blen);
    if (NULL == b) {
        pr2serr("%s: heap allocation problem\n", __func__);
        return;
    }
    if (jsp->pr_as_json) {
        /* re-use (overwrite) passed jop argument */
        jop = sgj_named_subobject_r(jsp, jop, "join_of_diagnostic_pages");
        jap = sgj_named_subarray_r(jsp, jop, "element_list");
    }
    need_aes = (op->page_code_given &&
                (ADD_ELEM_STATUS_DPC == op->page_code));
    dn_len = op->desc_name ? (int)strlen(op->desc_name) : 0;
    for (k = 0, jrp = tesp->j_base, got1 = false;
         ((k < MX_JOIN_ROWS) && jrp->enc_statp); ++k, ++jrp) {
        if (op->ind_given) {
            if (op->ind_th != jrp->th_i)
                continue;
            if (! match_ind_indiv(jrp->indiv_i, op))
                continue;
        }
        if (need_aes && (NULL == jrp->ae_statp))
            continue;
        ed_bp = jrp->elem_descp;
        if (op->desc_name) {
            if (NULL == ed_bp)
                continue;
            desc_len = sg_get_unaligned_be16(ed_bp + 2);
            /* some element descriptor strings have trailing NULLs and
             * count them in their length; adjust */
            while (desc_len && ('\0' == ed_bp[4 + desc_len - 1]))
                --desc_len;
            if (desc_len != dn_len)
                continue;
            if (0 != strncmp(op->desc_name, (const char *)(ed_bp + 4),
                             desc_len))
                continue;
        } else if (op->dev_slot_num >= 0) {
            if (op->dev_slot_num != jrp->dev_slot_num)
                continue;
        } else if (saddr_non_zero(op->sas_addr)) {
            for (j = 0; j < 8; ++j) {
                if (op->sas_addr[j] != jrp->sas_addr[j])
                    break;
            }
            if (j < 8)
                continue;
        }
        got1 = true;
        if ((op->do_filter > 1) && (1 != (0xf & jrp->enc_statp[0])))
            continue;   /* when '-ff' and status!=OK, skip */
        cp = etype_str(jrp->etype, b, blen);
        if (ed_bp) {
            desc_len = sg_get_unaligned_be16(ed_bp + 2) + 4;
            if (desc_len > 4)
                sgj_pr_hr(jsp, "%.*s [%d,%d]  %s: %s\n", desc_len - 4,
                          (const char *)(ed_bp + 4), jrp->th_i,
                          jrp->indiv_i, et_s, cp);
            else
                sgj_pr_hr(jsp, "[%d,%d]  %s: %s\n", jrp->th_i, jrp->indiv_i,
                          et_s, cp);
        } else
            sgj_pr_hr(jsp, "[%d,%d]  %s: %s\n", jrp->th_i, jrp->indiv_i,
                      et_s, cp);
        sgj_pr_hr(jsp, "  Enclosure Status:\n");
        if (jsp->pr_as_json) {
            jo2p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihexstr(jsp, jo2p, et_sn, jrp->etype, NULL, cp);
            sgj_js_nv_s(jsp, jo2p, "descriptor", (const char *)(ed_bp + 4));
            sgj_js_nv_i(jsp, jo2p, "element_number", jrp->indiv_i);
            sgj_js_nv_i(jsp, jo2p, "overall", (int)(-1 == jrp->indiv_i));
            sgj_js_nv_b(jsp, jo2p, "individual", (-1 != jrp->indiv_i));
            jo3p = sgj_named_subobject_r(jsp, jo2p, "status_descriptor");
        }
        enc_status_helper("    ", jrp->enc_statp, jrp->etype, false, op, jo3p,
                          b, blen);
        sgj_pr_hr(jsp, "%s", b);
        if (jrp->ae_statp) {
            sgj_pr_hr(jsp, "  Additional Element Status:\n");
            ae_bp = jrp->ae_statp;
            desc_len = ae_bp[1] + 2;
            if (jsp->pr_as_json)
                jo3p = sgj_named_subobject_r(jsp, jo2p, aesd_sn);
            additional_elem_helper("    ",  ae_bp, desc_len, jrp->etype,
                                   tesp, op, jo3p);
        }
        if (jrp->thresh_inp) {
            t_bp = jrp->thresh_inp;
            if (! jsp->pr_as_json)
                threshold_helper("  Threshold In:\n", "    ", t_bp,
                                 jrp->etype, op, NULL);
            else if (threshold_used(jrp->etype)) {
                jo3p = sgj_named_subobject_r(jsp, jo2p,
                                             "threshold_status_descriptor");
                threshold_helper("  Threshold In:\n", "    ", t_bp,
                                 jrp->etype, op, jo3p);
            }
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    if (! got1) {
        if (op->ind_given) {
            n = sg_scnpr(b, blen, "      >>> no match on --index=%d,%d",
                         op->ind_th, op->ind_indiv);
            if (op->ind_indiv_last > op->ind_indiv)
                sg_scnpr(b + n, blen - n, "-%d\n", op->ind_indiv_last);
            else
                sgj_pr_hr(jsp, "%s\n", b);
        } else if (op->desc_name)
            sgj_pr_hr(jsp, "      >>> no match on --descriptor=%s\n",
                      op->desc_name);
        else if (op->dev_slot_num >= 0)
            sgj_pr_hr(jsp, "      >>> no match on --dev-slot-name=%d\n",
                      op->dev_slot_num);
        else if (saddr_non_zero(op->sas_addr))
            sgj_pr_hr(jsp, "      >>> no match on --sas-addr=0x%" PRIx64 "\n",
                      sg_get_unaligned_be64(op->sas_addr + 0));
    }
    free(b);
}

/* This is for debugging, output to stderr */
static void
join_array_dump(struct th_es_t * tesp, int broken_ei, struct opts_t * op)
{
    int k, blen, hex;
    int eiioe_count = 0;
    int eip_count = 0;
    struct join_row_t * jrp;
    char b[64];

    blen = sizeof(b);
    hex = op->do_hex;
    pr2serr("Dump of join array, each line is a row. Lines start with\n");
    pr2serr("[<element_type>: <type_hdr_index>,<elem_ind_within>]\n");
    pr2serr("'-1' indicates overall element or not applicable.\n");
    jrp = tesp->j_base;
    for (k = 0; ((k < MX_JOIN_ROWS) && jrp->enc_statp); ++k, ++jrp) {
        pr2serr("[0x%x: %d,%d] ", jrp->etype, jrp->th_i, jrp->indiv_i);
        if (jrp->se_id > 0)
            pr2serr("se_id=%d ", jrp->se_id);
        pr2serr("ei_ioe,_eoe,_aess=%s", offset_str(k, hex, b, blen));
        pr2serr(",%s", offset_str(jrp->ei_eoe, hex, b, blen));
        pr2serr(",%s", offset_str(jrp->ei_aess, hex, b, blen));
        pr2serr(" dsn=%s", offset_str(jrp->dev_slot_num, hex, b, blen));
        if (op->do_join > 2)
            pr2serr(" sa=0x%" PRIx64 "\n",
                    sg_get_unaligned_be64(jrp->sas_addr + 0));
        if (jrp->enc_statp)
            pr2serr(" ES+%s", offset_str(jrp->enc_statp - enc_stat_rsp,
                                         hex, b, blen));
        if (jrp->elem_descp)
            pr2serr(" ED+%s", offset_str(jrp->elem_descp - elem_desc_rsp,
                                         hex, b, blen));
        if (jrp->ae_statp) {
            pr2serr(" AES+%s", offset_str(jrp->ae_statp - add_elem_rsp,
                                          hex, b, blen));
            if (jrp->ae_statp[0] & 0x10) {
                ++eip_count;
                if (jrp->ae_statp[2] & 0x3)
                    ++eiioe_count;
            }
        }
        if (jrp->thresh_inp)
            pr2serr(" TI+%s", offset_str(jrp->thresh_inp - threshold_rsp,
                                         hex, b, blen));
        pr2serr("\n");
    }
    pr2serr(">> ES len=%s, ", offset_str(enc_stat_rsp_len, hex, b, blen));
    pr2serr("ED len=%s, ", offset_str(elem_desc_rsp_len, hex, b, blen));
    pr2serr("AES len=%s, ", offset_str(add_elem_rsp_len, hex, b, blen));
    pr2serr("TI len=%s\n", offset_str(threshold_rsp_len, hex, b, blen));
    pr2serr(">> join_arr elements=%s, ", offset_str(k, hex, b, blen));
    pr2serr("eip_count=%s, ", offset_str(eip_count, hex, b, blen));
    pr2serr("eiioe_count=%s ", offset_str(eiioe_count, hex, b, blen));
    pr2serr("broken_ei=%d\n", (int)broken_ei);
}

/* EIIOE juggling (standards + heuristics) for join with AES page */
static void
join_juggle_aes(struct th_es_t * tesp, uint8_t * es_bp, const uint8_t * ed_bp,
                uint8_t * t_bp)
{
    int k, j, eoe, ei4aess;
    struct join_row_t * jrp;
    const struct type_desc_hdr_t * tdhp;

    jrp = tesp->j_base;
    tdhp = tesp->th_base;
    for (k = 0, eoe = 0, ei4aess = 0; k < tesp->num_ths; ++k, ++tdhp) {
        bool et_used_by_aes;

        jrp->th_i = k;
        jrp->indiv_i = -1;
        jrp->etype = tdhp->etype;
        jrp->ei_eoe = -1;
        et_used_by_aes = is_et_used_by_aes(tdhp->etype);
        jrp->ei_aess = -1;
        jrp->se_id = tdhp->se_id;
        /* check es_bp < es_last_bp still in range */
        jrp->enc_statp = es_bp;
        es_bp += 4;
        jrp->elem_descp = ed_bp;
        if (ed_bp)
            ed_bp += sg_get_unaligned_be16(ed_bp + 2) + 4;
        jrp->ae_statp = NULL;
        jrp->thresh_inp = t_bp;
        jrp->dev_slot_num = -1;
        /* assume sas_addr[8] zeroed since it's static file scope */
        if (t_bp)
            t_bp += 4;
        ++jrp;
        for (j = 0; j < tdhp->num_elements; ++j, ++jrp) {
            if (jrp >= join_arr_lastp)
                break;
            jrp->th_i = k;
            jrp->indiv_i = j;
            jrp->ei_eoe = eoe++;
            if (et_used_by_aes)
                jrp->ei_aess = ei4aess++;
            else
                jrp->ei_aess = -1;
            jrp->etype = tdhp->etype;
            jrp->se_id = tdhp->se_id;
            jrp->enc_statp = es_bp;
            es_bp += 4;
            jrp->elem_descp = ed_bp;
            if (ed_bp)
                ed_bp += sg_get_unaligned_be16(ed_bp + 2) + 4;
            jrp->thresh_inp = t_bp;
            jrp->dev_slot_num = -1;
            /* assume sas_addr[8] zeroed since it's static file scope */
            if (t_bp)
                t_bp += 4;
            jrp->ae_statp = NULL;
            ++tesp->num_j_eoe;
        }
        if (jrp >= join_arr_lastp) {
            /* ++k; */
            break;      /* leave last row all zeros */
        }
    }
    tesp->num_j_rows = jrp - tesp->j_base;
}

/* Fetch Configuration, Enclosure Status, Element Descriptor, Additional
 * Element Status and optionally Threshold In pages, place in static arrays.
 * Collate (join) overall and individual elements into the static join_arr[].
 * When 'display' is true then the join_arr[]  is output to stdout in a form
 * suitable for end users. For debug purposes the join_arr[] is output to
 * stderr when op->verbose > 3. Returns 0 for success, any other return value
 * is an error. */
static int
join_work(struct sg_pt_base * ptvp, bool display, struct opts_t * op,
          sgj_opaque_p jop)
{
    bool broken_ei;
    int res, n, num_ths, mlen;
    uint32_t ref_gen_code, gen_code;
    const uint8_t * ae_bp;
    const uint8_t * ae_last_bp;
    uint8_t * es_bp;
    const uint8_t * ed_bp;
    uint8_t * t_bp;
    struct th_es_t * tesp;
    sgj_state * jsp = &op->json_st;
    // sgj_opaque_p jo2p;
    // sgj_opaque_p jo3p = NULL;
    // sgj_opaque_p jap = NULL;
    char b[144];
    struct enclosure_info primary_info;
    struct th_es_t tes;
    static const int blen = sizeof(b);

    memset(&primary_info, 0, sizeof(primary_info));
    num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr, MX_ELEM_HDR,
                                      &ref_gen_code, &primary_info, op);
    if (num_ths < 0)
        return num_ths;
    tesp = &tes;
    memset(tesp, 0, sizeof(tes));
    tesp->th_base = type_desc_hdr_arr;
    tesp->num_ths = num_ths;
    if (display && primary_info.have_info) {
        int j;

        n = sg_scnpr(b, blen, "%s (hex): ", peli);
        for (j = 0; j < 8; ++j)
            n += sg_scnpr(b + n, blen - n, "%02x",
                          primary_info.enc_log_id[j]);
        sgj_pr_hr(jsp, "  %s\n", b);
    }
    mlen = enc_stat_rsp_sz;
    if (mlen > op->maxlen)
        mlen = op->maxlen;
    res = do_rec_diag(ptvp, ENC_STATUS_DPC, enc_stat_rsp, mlen, op,
                      &enc_stat_rsp_len);
    if (res)
        return res;
    if (enc_stat_rsp_len < 8) {
        pr2serr("Enclosure Status %s\n", rts_s);
        return -1;
    }
    gen_code = sg_get_unaligned_be32(enc_stat_rsp + 4);
    if (ref_gen_code != gen_code) {
        pr2serr("%s", soec);
        return -1;
    }
    es_bp = enc_stat_rsp + 8;
    /* es_last_bp = enc_stat_rsp + enc_stat_rsp_len - 1; */

    mlen = elem_desc_rsp_sz;
    if (mlen > op->maxlen)
        mlen = op->maxlen;
    res = do_rec_diag(ptvp, ELEM_DESC_DPC, elem_desc_rsp, mlen, op,
                      &elem_desc_rsp_len);
    if (0 == res) {
        if (elem_desc_rsp_len < 8) {
            pr2serr("Element Descriptor %s\n", rts_s);
            return -1;
        }
        gen_code = sg_get_unaligned_be32(elem_desc_rsp + 4);
        if (ref_gen_code != gen_code) {
            pr2serr("%s", soec);
            return -1;
        }
        ed_bp = elem_desc_rsp + 8;
        /* ed_last_bp = elem_desc_rsp + elem_desc_rsp_len - 1; */
    } else {
        elem_desc_rsp_len = 0;
        ed_bp = NULL;
        res = 0;
        if (op->verbose)
            pr2serr("  Element Descriptor page %s\n", not_avail);
    }

    /* check if we want to add the AES page to the join */
    if (display || (ADD_ELEM_STATUS_DPC == op->page_code) ||
        (op->dev_slot_num >= 0) || saddr_non_zero(op->sas_addr)) {
        mlen = add_elem_rsp_sz;
        if (mlen > op->maxlen)
            mlen = op->maxlen;
        res = do_rec_diag(ptvp, ADD_ELEM_STATUS_DPC, add_elem_rsp, mlen, op,
                          &add_elem_rsp_len);
        if (0 == res) {
            if (add_elem_rsp_len < 8) {
                pr2serr("Additional Element Status %s\n", rts_s);
                return -1;
            }
            gen_code = sg_get_unaligned_be32(add_elem_rsp + 4);
            if (ref_gen_code != gen_code) {
                pr2serr("%s", soec);
                return -1;
            }
            ae_bp = add_elem_rsp + 8;
            ae_last_bp = add_elem_rsp + add_elem_rsp_len - 1;
            if (op->eiioe_auto && (add_elem_rsp_len > 11)) {
                /* heuristic: if first AES descriptor has EIP set and its
                 * EI equal to 1, then act as if the EIIOE field is 1. */
                if ((ae_bp[0] & 0x10) && (1 == ae_bp[3]))
                    op->eiioe_force = true;
            }
        } else {        /* unable to read AES dpage */
            add_elem_rsp_len = 0;
            ae_bp = NULL;
            ae_last_bp = NULL;
            res = 0;
            if (op->verbose)
                pr2serr("  %s %s\n", aes_dp, not_avail);
        }
    } else {
        ae_bp = NULL;
        ae_last_bp = NULL;
    }

    if ((op->do_join > 1) ||
        ((! display) && (THRESHOLD_DPC == op->page_code))) {
        mlen = threshold_rsp_sz;
        if (mlen > op->maxlen)
            mlen = op->maxlen;
        res = do_rec_diag(ptvp, THRESHOLD_DPC, threshold_rsp, mlen, op,
                          &threshold_rsp_len);
        if (0 == res) {
            if (threshold_rsp_len < 8) {
                pr2serr("Threshold In %s\n", rts_s);
                return -1;
            }
            gen_code = sg_get_unaligned_be32(threshold_rsp + 4);
            if (ref_gen_code != gen_code) {
                pr2serr("%s", soec);
                return -1;
            }
            t_bp = threshold_rsp + 8;
            /* t_last_bp = threshold_rsp + threshold_rsp_len - 1; */
        } else {
            threshold_rsp_len = 0;
            t_bp = NULL;
            res = 0;
            if (op->verbose)
                pr2serr("  Threshold In page %s\n", not_avail);
        }
    } else {
        threshold_rsp_len = 0;
        t_bp = NULL;
    }

    tesp->j_base = join_arr;
    join_juggle_aes(tesp, es_bp, ed_bp, t_bp);

    broken_ei = false;
    if (ae_bp)
        broken_ei = join_aes_helper(ae_bp, ae_last_bp, tesp, op);

    if (op->verbose > 3)
        join_array_dump(tesp, broken_ei, op);

    join_done = true;
    if (display) {
        join_array_display(tesp, op, jop);
        if (op->do_all) {
            uint8_t * resp = NULL;
            uint8_t * free_resp = NULL;

            resp = sg_memalign(op->maxlen, 0, &free_resp, false);
            if (NULL == resp) {
                pr2serr("%s: unable to allocate %d bytes on heap\n",
                        __func__, op->maxlen);
                res = sg_convert_errno(ENOMEM);
                goto fini;
            }
            sgj_pr_hr(jsp, "Join output completed, now output rest of "
                      "dpages\n\n");
            res = process_many_status_dpages(ptvp, resp, false, op, jop);
            free(free_resp);
        }
    }
fini:
    return res;

}

/* Returns 1 if strings equal (same length, characters same or only differ
 * by case), else returns 0. Assumes 7 bit ASCII (English alphabet). */
static int
strcase_eq(const char * s1p, const char * s2p)
{
    int c1;

    do {
        int c2;

        c1 = *s1p++;
        c2 = *s2p++;
        if (c1 != c2) {
            if (c2 >= 'a')
                c2 = toupper(c2);
            else if (c1 >= 'a')
                c1 = toupper(c1);
            else
                return 0;
            if (c1 != c2)
                return 0;
        }
    } while (c1);
    return 1;
}

static bool
is_acronym_in_status_ctl(const struct tuple_acronym_val * tavp)
{
    const struct acronym2tuple * ap;

    for (ap = ecs_a2t_arr; ap->acron; ++ ap) {
        if (strcase_eq(tavp->acron, ap->acron))
            break;
    }
    return ap->acron;
}

static bool
is_acronym_in_threshold(const struct tuple_acronym_val * tavp)
{
    const struct acronym2tuple * ap;

    for (ap = th_a2t_arr; ap->acron; ++ ap) {
        if (strcase_eq(tavp->acron, ap->acron))
            break;
    }
    return ap->acron;
}

static bool
is_acronym_in_additional(const struct tuple_acronym_val * tavp)
{
    const struct acronym2tuple * ap;

    for (ap = ae_sas_a2t_arr; ap->acron; ++ ap) {
        if (strcase_eq(tavp->acron, ap->acron))
            break;
    }
    return ap->acron;
}

/* ENC_STATUS_DPC  ENC_CONTROL_DPC
 * Do clear/get/set (cgs) on Enclosure Control/Status page. Return 0 for ok
 * -2 for acronym not found, else -1 . */
static int
cgs_enc_ctl_stat(struct sg_pt_base * ptvp, struct join_row_t * jrp,
                 const struct tuple_acronym_val * tavp,
                 const struct opts_t * op, bool last)
{
    int s_byte, s_bit, n_bits;
    const struct acronym2tuple * ap;

    if (NULL == tavp->acron) {
        s_byte = tavp->start_byte;
        s_bit = tavp->start_bit;
        n_bits = tavp->num_bits;
    }
    if (tavp->acron) {
        for (ap = ecs_a2t_arr; ap->acron; ++ ap) {
            if (((jrp->etype == ap->etype) || (-1 == ap->etype)) &&
                strcase_eq(tavp->acron, ap->acron))
                break;
        }
        if (ap->acron) {
            s_byte = ap->start_byte;
            s_bit = ap->start_bit;
            n_bits = ap->num_bits;
        } else {
            if (-1 != ap->etype) {
                for (ap = ecs_a2t_arr; ap->acron; ++ap) {
                    if (0 == strcase_eq(tavp->acron, ap->acron)) {
                        pr2serr(">>> Found %s acronym but not for element "
                                "type %d\n", tavp->acron, jrp->etype);
                        break;
                    }
                }
            }
            return -2;
        }
    }
    if (op->verbose > 1)
        pr2serr("  s_byte=%d, s_bit=%d, n_bits=%d\n", s_byte, s_bit, n_bits);
    if (GET_OPT == tavp->cgs_sel) {
        uint64_t ui = sg_get_big_endian(jrp->enc_statp + s_byte, s_bit,
                                        n_bits);

        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {    /* --set or --clear */
        int len;

        if ((! op->mask_ign) && (jrp->etype < NUM_ETC)) {
            int k;

            if (op->verbose > 2)
                pr2serr("Applying mask to element status [etc=%d] prior to "
                        "modify then write\n", jrp->etype);
            for (k = 0; k < 4; ++k)
                jrp->enc_statp[k] &= ses3_element_cmask_arr[jrp->etype][k];
        } else
            jrp->enc_statp[0] &= 0x40;  /* keep PRDFAIL is set in byte 0 */
        /* next we modify requested bit(s) */
        sg_set_big_endian((uint64_t)tavp->val,
                          jrp->enc_statp + s_byte, s_bit, n_bits);
        jrp->enc_statp[0] |= 0x80;  /* set SELECT bit */
        if (op->byte1_given)
            enc_stat_rsp[1] = op->byte1;
        len = sg_get_unaligned_be16(enc_stat_rsp + 2) + 4;
        if (last) {
            int ret = do_senddiag(ptvp, enc_stat_rsp, len, ! op->quiet,
                                  op->verbose);

            if (ret) {
                pr2serr("couldn't send Enclosure Control page\n");
                return -1;
            }
        }
    }
    return 0;
}

/* THRESHOLD_DPC
 * Do clear/get/set (cgs) on Threshold In/Out page. Return 0 for ok,
 * -2 for acronym not found, else -1 . */
static int
cgs_threshold(struct sg_pt_base * ptvp, const struct join_row_t * jrp,
              const struct tuple_acronym_val * tavp,
              const struct opts_t * op, bool last)
{
    int s_byte, s_bit, n_bits;
    const struct acronym2tuple * ap;

    if (NULL == jrp->thresh_inp) {
        pr2serr("No Threshold In/Out element available\n");
        return -1;
    }
    if (NULL == tavp->acron) {
        s_byte = tavp->start_byte;
        s_bit = tavp->start_bit;
        n_bits = tavp->num_bits;
    }
    if (tavp->acron) {
        for (ap = th_a2t_arr; ap->acron; ++ap) {
            if (((jrp->etype == ap->etype) || (-1 == ap->etype)) &&
                strcase_eq(tavp->acron, ap->acron))
                break;
        }
        if (ap->acron) {
            s_byte = ap->start_byte;
            s_bit = ap->start_bit;
            n_bits = ap->num_bits;
        } else
            return -2;
    }
    if (GET_OPT == tavp->cgs_sel) {
        uint64_t ui = sg_get_big_endian(jrp->thresh_inp + s_byte, s_bit,
                                         n_bits);

        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {
        int len;

        sg_set_big_endian((uint64_t)tavp->val,
                          jrp->thresh_inp + s_byte, s_bit, n_bits);
        if (op->byte1_given)
            threshold_rsp[1] = op->byte1;
        len = sg_get_unaligned_be16(threshold_rsp + 2) + 4;
        if (last) {
            int ret = do_senddiag(ptvp, threshold_rsp, len, ! op->quiet,
                                  op->verbose);

            if (ret) {
                pr2serr("couldn't send Threshold Out page\n");
                return -1;
            }
        }
    }
    return 0;
}

/* ADD_ELEM_STATUS_DPC
 * Do get (cgs) on Additional element status page. Return 0 for ok,
 * -2 for acronym not found, else -1 . */
static int
cgs_additional_el(const struct join_row_t * jrp,
                  const struct tuple_acronym_val * tavp,
                  const struct opts_t * op)
{
    int s_byte, s_bit, n_bits;
    const struct acronym2tuple * ap;

    if (NULL == jrp->ae_statp) {
        pr2serr("No additional element status element available\n");
        return -1;
    }
    if (NULL == tavp->acron) {
        s_byte = tavp->start_byte;
        s_bit = tavp->start_bit;
        n_bits = tavp->num_bits;
    }
    if (tavp->acron) {
        for (ap = ae_sas_a2t_arr; ap->acron; ++ap) {
            if (((jrp->etype == ap->etype) || (-1 == ap->etype)) &&
                strcase_eq(tavp->acron, ap->acron))
                break;
        }
        if (ap->acron) {
            s_byte = ap->start_byte;
            s_bit = ap->start_bit;
            n_bits = ap->num_bits;
        } else
            return -2;
    }
    if (GET_OPT == tavp->cgs_sel) {
        uint64_t ui = sg_get_big_endian(jrp->ae_statp + s_byte, s_bit,
                                         n_bits);

        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {
        pr2serr("--clear and --set %s for %s\n", not_avail, aes_dp);
        return -1;
    }
    return 0;
}

/* Do --clear, --get or --set .
 * Returns 0 for success, any other return value is an error. */
static int
ses_cgs(struct sg_pt_base * ptvp, const struct tuple_acronym_val * tavp,
        bool last, struct opts_t * op, sgj_opaque_p jop)
{
    int ret, k, j, desc_len, dn_len;
    bool found;
    struct join_row_t * jrp;
    const uint8_t * ed_bp;
    char b[64];

    if ((NULL == ptvp) && (GET_OPT != tavp->cgs_sel)) {
        pr2serr("%s: --clear= and --set= only supported when DEVICE is "
                "given\n", __func__);
        return SG_LIB_CONTRADICT;
    }
    found = false;
    if (NULL == tavp->acron) {
        if (! op->page_code_given)
            op->page_code = ENC_CONTROL_DPC;
        found = true;
    } else if (is_acronym_in_status_ctl(tavp)) {
        if (op->page_code > 0) {
            if (ENC_CONTROL_DPC != op->page_code)
                goto inconsistent;
        } else
            op->page_code = ENC_CONTROL_DPC;
        found = true;
    } else if (is_acronym_in_threshold(tavp)) {
        if (op->page_code > 0) {
            if (THRESHOLD_DPC != op->page_code)
                goto inconsistent;
        } else
            op->page_code = THRESHOLD_DPC;
        found = true;
    } else if (is_acronym_in_additional(tavp)) {
        if (op->page_code > 0) {
            if (ADD_ELEM_STATUS_DPC != op->page_code)
                goto inconsistent;
        } else
            op->page_code = ADD_ELEM_STATUS_DPC;
        found = true;
    }
    if (! found) {
        pr2serr("acroynm %s not found (try '-ee' option)\n", tavp->acron);
        return -1;
    }
    if (false == join_done) {
        ret = join_work(ptvp, false, op, jop);
        if (ret)
            return ret;
    }
    dn_len = op->desc_name ? (int)strlen(op->desc_name) : 0;
    for (k = 0, jrp = join_arr; ((k < MX_JOIN_ROWS) && jrp->enc_statp);
         ++k, ++jrp) {
        if (op->ind_given) {
            if (op->ind_th != jrp->th_i)
                continue;
            if (! match_ind_indiv(jrp->indiv_i, op))
                continue;
        } else if (op->desc_name) {
            ed_bp = jrp->elem_descp;
            if (NULL == ed_bp)
                continue;
            desc_len = sg_get_unaligned_be16(ed_bp + 2);
            /* some element descriptor strings have trailing NULLs and
             * count them; adjust */
            while (desc_len && ('\0' == ed_bp[4 + desc_len - 1]))
                --desc_len;
            if (desc_len != dn_len)
                continue;
            if (0 != strncmp(op->desc_name, (const char *)(ed_bp + 4),
                             desc_len))
                continue;
        } else if (op->dev_slot_num >= 0) {
            if (op->dev_slot_num != jrp->dev_slot_num)
                continue;
        } else if (saddr_non_zero(op->sas_addr)) {
            for (j = 0; j < 8; ++j) {
                if (op->sas_addr[j] != jrp->sas_addr[j])
                    break;
            }
            if (j < 8)
                continue;
        }
        if (ENC_CONTROL_DPC == op->page_code)
            ret = cgs_enc_ctl_stat(ptvp, jrp, tavp, op, last);
        else if (THRESHOLD_DPC == op->page_code)
            ret = cgs_threshold(ptvp, jrp, tavp, op, last);
        else if (ADD_ELEM_STATUS_DPC == op->page_code)
            ret = cgs_additional_el(jrp, tavp, op);
        else {
            pr2serr("page %s not supported for cgs\n",
                    etype_str(op->page_code, b, sizeof(b)));
            ret = -1;
        }
        if (ret)
            return ret;
        if (op->ind_indiv_last <= op->ind_indiv)
            break;
    }   /* end of loop over join array */
    if ((k >= MX_JOIN_ROWS || (NULL == jrp->enc_statp))) {
        if (op->desc_name)
            pr2serr("descriptor name: %s not found (check the 'ed' page "
                    "[0x7])\n", op->desc_name);
        else if (op->dev_slot_num >= 0)
            pr2serr("device slot number: %d not found\n", op->dev_slot_num);
        else if (saddr_non_zero(op->sas_addr))
            pr2serr("SAS address not found\n");
        else {
            pr2serr("index: %d,%d", op->ind_th, op->ind_indiv);
            if (op->ind_indiv_last > op->ind_indiv)
                printf("-%d not found\n", op->ind_indiv_last);
            else
                printf(" not found\n");
        }
        return -1;
    }
    return 0;

inconsistent:
    pr2serr("acroynm %s inconsistent with page_code=0x%x\n", tavp->acron,
            op->page_code);
    return -1;
}

/* Called when '--nickname=SEN' given. First calls status page to fetch
 * the generation code. Returns 0 for success, any other return value is
 * an error. */
static int
ses_set_nickname(struct sg_pt_base * ptvp, struct opts_t * op)
{
    int res, len;
    int resp_len = 0;
    uint8_t b[64];
    static const int control_plen = 0x24;

    if (NULL == ptvp) {
        pr2serr("%s: ignored when no device name\n", __func__);
        return 0;
    }
    memset(b, 0, sizeof(b));
    /* Only after the generation code, offset 4 for 4 bytes */
    res = do_rec_diag(ptvp, SUBENC_NICKNAME_DPC, b, 8, op, &resp_len);
    if (res) {
        pr2serr("%s: Subenclosure nickname status page, res=%d\n", __func__,
                res);
        return -1;
    }
    if (resp_len < 8) {
        pr2serr("%s: Subenclosure nickname status page, response length too "
                "short: %d\n", __func__, resp_len);
        return -1;
    }
    if (op->verbose) {
        uint32_t gc;

        gc = sg_get_unaligned_be32(b + 4);
        pr2serr("%s: %s from status page: %" PRIu32 "\n", __func__, gc_s, gc);
    }
    b[0] = (uint8_t)SUBENC_NICKNAME_DPC;  /* just in case */
    b[1] = (uint8_t)op->seid;
    sg_put_unaligned_be16((uint16_t)control_plen, b + 2);
    len = strlen(op->nickname_str);
    if (len > 32)
        len = 32;
    memcpy(b + 8, op->nickname_str, len);
    return do_senddiag(ptvp, b, control_plen + 4, ! op->quiet,
                       op->verbose);
}

static void
enumerate_diag_pages(void)
{
    bool got1;
    const struct diag_page_code * pcdp;
    const struct diag_page_abbrev * ap;

    printf("D%s names, followed by abbreviation(s) then page code:\n",
           dp_s + 1);
    for (pcdp = dpc_arr; pcdp->desc; ++pcdp) {
        printf("    %s  [", pcdp->desc);
        for (ap = dp_abbrev, got1 = false; ap->abbrev; ++ap) {
            if (ap->page_code == pcdp->page_code) {
                printf("%s%s", (got1 ? "," : ""), ap->abbrev);
                got1 = true;
            }
        }
        printf("] [0x%x]\n", pcdp->page_code);
    }
}

/* Output from --enumerate or --list option. Note that the output is
 * different when the option is given twice. */
static void
enumerate_work(const struct opts_t * op)
{
    int num;

    if (op->dev_name)
        printf(">>> DEVICE %s ignored when --%s option given.\n",
               op->dev_name, (op->do_list ? "list" : "enumerate"));
    num = op->enumerate + (int)op->do_list;
    if (num < 2) {
        const struct element_type_t * etp;

        enumerate_diag_pages();
        printf("\nSES element type names, followed by abbreviation and "
               "element type code:\n");
        for (etp = element_type_arr; etp->desc; ++etp)
            printf("    %s  [%s] [0x%x]\n", etp->desc, etp->abbrev,
                   etp->elem_type_code);
    } else {
        bool given_et = false;
        const struct acronym2tuple * ap;
        const char * cp;
        char a[160];
        char b[64];
        char bb[64];

        /* command line has multiple --enumerate and/or --list options */
        printf("--clear, --get, --set acronyms for Enclosure Status/Control "
               "['es' or 'ec'] page");
        if (op->ind_given && op->ind_etp &&
            (cp = etype_str(op->ind_etp->elem_type_code, bb, sizeof(bb)))) {
            printf("\n(element type: %s)", cp);
            given_et = true;
        }
        printf(":\n");
        for (ap = ecs_a2t_arr; ap->acron; ++ap) {
            if (given_et && (op->ind_etp->elem_type_code != ap->etype))
                continue;
            cp = (ap->etype < 0) ?  "*" : etype_str(ap->etype, b, sizeof(b));
            snprintf(a, sizeof(a), "  %s  [%s] [%d:%d:%d]", ap->acron,
                     (cp ? cp : "??"), ap->start_byte, ap->start_bit,
                     ap->num_bits);
            if (ap->info)
                printf("%-44s  %s\n", a, ap->info);
            else
                printf("%s\n", a);
        }
        if (given_et)
            return;
        printf("\n--clear, --get, --set acronyms for Threshold In/Out "
               "['th'] page:\n");
        for (ap = th_a2t_arr; ap->acron; ++ap) {
            cp = (ap->etype < 0) ? "*" : etype_str(ap->etype, b, sizeof(b));
            snprintf(a, sizeof(a), "  %s  [%s] [%d:%d:%d]", ap->acron,
                     (cp ? cp : "??"), ap->start_byte, ap->start_bit,
                     ap->num_bits);
            if (ap->info)
                printf("%-34s  %s\n", a, ap->info);
            else
                printf("%s\n", a);
        }
        printf("\n--get acronyms for %s ['aes'] (SAS EIP=1):\n", aes_dp);
        for (ap = ae_sas_a2t_arr; ap->acron; ++ap) {
            cp = (ap->etype < 0) ? "*" : etype_str(ap->etype, b, sizeof(b));
            snprintf(a, sizeof(a), "  %s  [%s] [%d:%d:%d]", ap->acron,
                     (cp ? cp : "??"), ap->start_byte, ap->start_bit,
                     ap->num_bits);
            if (ap->info)
                printf("%-34s  %s\n", a, ap->info);
            else
                printf("%s\n", a);
        }
    }
}


int
main(int argc, char * argv[])
{
    bool have_cgs = false;
    bool as_json = false;
    int k, n, d_len, res, resid, vb, dhex;
    int sg_fd = -1;
    int pd_type = 0;
    int ret = 0;
    const char * cp;
    struct opts_t opts;
    struct opts_t * op;
    struct tuple_acronym_val * tavp;
    struct cgs_cl_t * cgs_clp;
    uint8_t * free_enc_stat_rsp = NULL;
    uint8_t * free_elem_desc_rsp = NULL;
    uint8_t * free_add_elem_rsp = NULL;
    uint8_t * free_threshold_rsp = NULL;
    struct sg_pt_base * ptvp = NULL;
    sgj_state * jsp;
    sgj_opaque_p jop = NULL;
    struct tuple_acronym_val tav_arr[CGS_CL_ARR_MAX_SZ];
    char buff[128];
    char b[128];

    op = &opts;
    memset(op, 0, sizeof(*op));
    op->dev_slot_num = -1;
    op->ind_indiv_last = -1;
    op->maxlen = MX_ALLOC_LEN;
    if (getenv("SG3_UTILS_INVOCATION"))
        sg_rep_invocation(MY_NAME, version_str, argc, argv, NULL);

    res = parse_cmd_line(op, argc, argv);
    vb = op->verbose;
    jsp = &op->json_st;
    if (res) {
        if (SG_SES_CALL_ENUMERATE == res) {
            pr2serr("\n");
            enumerate_work(op);
            ret = SG_LIB_SYNTAX_ERROR;
            goto early_out;
        }
        ret = res;
        goto early_out;
    }
    /* Swap the meaning of '-H' and '-HH' for compatibility with other
     * sg3_utils where '-H' means hex with no ASCII rendering to the right
     * and '-HH' means that we want ASCII rendering to the right */
    dhex = op->do_hex;
    if (1 == dhex)
        op->do_hex = 2;
    else if (2 == dhex)
        op->do_hex = 1;
    /* end of '-H', '-HH' swap code <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< */

    if (op->do_help) {
        usage(op->do_help);
        goto early_out;
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
        pr2serr("version: %s\n", version_str);
        goto early_out;
    }

    vb = op->verbose;   /* may have changed */
    if (op->enumerate || op->do_list) {
        enumerate_work(op);
        goto early_out;
    }
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
            ret = SG_LIB_SYNTAX_ERROR;
            goto early_out;
        }
        jop = sgj_start_r(MY_NAME, version_str, argc, argv, jsp);
    }
    as_json = jsp->pr_as_json;

    enc_stat_rsp = sg_memalign(op->maxlen, 0, &free_enc_stat_rsp, false);
    if (NULL == enc_stat_rsp) {
        pr2serr("Unable to get heap for enc_stat_rsp\n");
        goto err_out;
    }
    enc_stat_rsp_sz = op->maxlen;
    elem_desc_rsp = sg_memalign(op->maxlen, 0, &free_elem_desc_rsp, false);
    if (NULL == elem_desc_rsp) {
        pr2serr("Unable to get heap for elem_desc_rsp\n");
        goto err_out;
    }
    elem_desc_rsp_sz = op->maxlen;
    add_elem_rsp = sg_memalign(op->maxlen, 0, &free_add_elem_rsp, false);
    if (NULL == add_elem_rsp) {
        pr2serr("Unable to get heap for add_elem_rsp\n");
        goto err_out;
    }
    add_elem_rsp_sz = op->maxlen;
    threshold_rsp = sg_memalign(op->maxlen, 0, &free_threshold_rsp, false);
    if (NULL == threshold_rsp) {
        pr2serr("Unable to get heap for threshold_rsp\n");
        goto err_out;
    }
    threshold_rsp_sz = op->maxlen;

    if (op->num_cgs) {
        have_cgs = true;
        if (op->page_code_given &&
            ! ((ENC_STATUS_DPC == op->page_code) ||
               (THRESHOLD_DPC == op->page_code) ||
               (ADD_ELEM_STATUS_DPC == op->page_code))) {
            pr2serr("--clear, --get or --set options only supported for the "
                    "Enclosure\nControl/Status, Threshold In/Out and "
                    "%ss\n", aes_dp);
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        if (! (op->ind_given || op->desc_name || (op->dev_slot_num >= 0) ||
               saddr_non_zero(op->sas_addr))) {
            pr2serr("with --clear, --get or --set option need either\n   "
                    "--index, --descriptor, --dev-slot-num or --sas-addr\n");
            ret = SG_LIB_CONTRADICT;
            goto err_out;
        }
        for (k = 0, cgs_clp = op->cgs_cl_arr, tavp = tav_arr; k < op->num_cgs;
             ++k, ++cgs_clp, ++tavp) {
            if (parse_cgs_str(cgs_clp->cgs_str, tavp)) {
                pr2serr("unable to decode STR argument to: %s\n",
                        cgs_clp->cgs_str);
                ret = SG_LIB_SYNTAX_ERROR;
                goto err_out;
            }
            if ((GET_OPT == cgs_clp->cgs_sel) && tavp->val_str)
                pr2serr("--get option ignoring =<val> at the end of STR "
                        "argument\n");
            if (NULL == tavp->val_str) {
                if (CLEAR_OPT == cgs_clp->cgs_sel)
                    tavp->val = DEF_CLEAR_VAL;
                if (SET_OPT == cgs_clp->cgs_sel)
                    tavp->val = DEF_SET_VAL;
            }
            if (!strcmp(cgs_clp->cgs_str, "sas_addr") &&
                op->dev_slot_num < 0) {
                pr2serr("--get=sas_addr requires --dev-slot-num.  For "
                        "expander SAS address, use exp_sas_addr instead.\n");
                ret = SG_LIB_SYNTAX_ERROR;
                goto err_out;
            }
            tavp->cgs_sel = cgs_clp->cgs_sel;
        }
        /* keep this descending for loop directly after ascending for loop */
        for (--k, --cgs_clp; k >= 0; --k, --cgs_clp) {
            if ((CLEAR_OPT == cgs_clp->cgs_sel) ||
                (SET_OPT == cgs_clp->cgs_sel)) {
                cgs_clp->last_cs = true;
                break;
            }
        }
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (vb > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    if (op->maxlen >= 16384)
        scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    if (op->dev_name) {
        sg_fd = sg_cmds_open_device(op->dev_name, op->o_readonly, vb);
        if (sg_fd < 0) {
            if (vb)
                pr2serr("open error: %s: %s\n", op->dev_name,
                        safe_strerror(-sg_fd));
            ret = sg_convert_errno(-sg_fd);
            goto early_out;
        }
        ptvp = construct_scsi_pt_obj_with_fd(sg_fd, vb);
        if (NULL == ptvp) {
            pr2serr("construct pt_base failed, probably out of memory\n");
            ret = sg_convert_errno(ENOMEM);
            goto err_out;
        }
        if (! (op->do_raw || have_cgs || (op->do_hex > 2))) {
            uint8_t inq_rsp[36];

            memset(inq_rsp, 0, sizeof(inq_rsp));
            if ((ret = sg_ll_inquiry_pt(ptvp, false, 0, inq_rsp, 36,
                                        0, &resid, ! op->quiet, vb))) {
                pr2serr("%s doesn't respond to a SCSI INQUIRY\n",
                        op->dev_name);
                goto err_out;
            } else {
                if (resid > 0)
                    pr2serr("Short INQUIRY response, not looking good\n");
                 sgj_pr_hr(jsp, "  %.8s  %.16s  %.4s\n", inq_rsp + 8,
                           inq_rsp + 16, inq_rsp + 32);
                pd_type = PDT_MASK & inq_rsp[0];
                cp = sg_get_pdt_str(pd_type, sizeof(buff), buff);
                if (0xd == pd_type) {
                    if (vb)
                        sgj_pr_hr(jsp, "    enclosure services device\n");
                } else if (0x40 & inq_rsp[6])
                    sgj_pr_hr(jsp, "    %s device has EncServ bit set\n", cp);
                else {
                    if (0 != memcmp("NVMe", inq_rsp + 8, 4))
                        sgj_pr_hr(jsp, "    %s device (not an enclosure)\n",
                                  cp);
                }
            }
            clear_scsi_pt_obj(ptvp);
        }
    } else if (op->do_control) {
        pr2serr("Cannot do SCSI Send diagnostic command without a DEVICE\n");
        goto err_out;
    }

#if (HAVE_NVME && (! IGNORE_NVME))
    if (ptvp && pt_device_is_nvme(ptvp) && (enc_stat_rsp_sz > 4095)) {
        /* Fetch VPD 0xde (vendor specific: sg3_utils) for Identify ctl */
        ret = sg_ll_inquiry_pt(ptvp, true, 0xde, enc_stat_rsp, 4096, 0,
                               &resid, ! op->quiet, vb);
        if (ret) {
            if (vb)
                pr2serr("Fetch VPD page 0xde (NVMe Identify ctl) failed, "
                        "continue\n");
        } else if (resid > 0) {
            if (vb)
                pr2serr("VPD page 0xde (NVMe Identify ctl) less than 4096 "
                        "bytes, continue\n");
        } else {
            uint8_t nvmsr;
            uint16_t oacs;

            nvmsr = enc_stat_rsp[253];
            oacs = sg_get_unaligned_le16(enc_stat_rsp + 256);   /* N.B. LE */
            if (vb > 3)
                pr2serr("NVMe Identify ctl response: nvmsr=%u, oacs=0x%x\n",
                        nvmsr, oacs);
            if (! ((0x2 & nvmsr) && (0x40 & oacs))) {
                pr2serr(">>> Warning: A NVMe enclosure needs both the "
                        "enclosure bit and support for\n");
                pr2serr(">>> MI Send+Receive commands bit set; current "
                        "state: %s, %s\n", (0x2 & nvmsr) ? "set" : "clear",
                        (0x40 & oacs) ? "set" : "clear");
            }
        }
        clear_scsi_pt_obj(ptvp);
        memset(enc_stat_rsp, 0, enc_stat_rsp_sz);
    }
#endif

    if (ptvp) {
        n = (enc_stat_rsp_sz < REQUEST_SENSE_RESP_SZ) ? enc_stat_rsp_sz :
                                                        REQUEST_SENSE_RESP_SZ;
        ret = sg_ll_request_sense_pt(ptvp, false, enc_stat_rsp, n,
                                     ! op->quiet, vb);
        if (0 == ret) {
            int sense_len = n - get_scsi_pt_resid(ptvp);
            struct sg_scsi_sense_hdr ssh;

            if ((sense_len > 7) && sg_scsi_normalize_sense(enc_stat_rsp,
                                        sense_len, &ssh)) {
                const char * aa_str = sg_get_asc_ascq_str(ssh.asc, ssh.ascq,
                                                          sizeof(b), b);

                /* Ignore the possibility that multiple UAs queued up */
                if (SPC_SK_UNIT_ATTENTION == ssh.sense_key)
                    pr2serr("Unit attention detected: %s\n  ... continue\n",
                            aa_str);
                else {
                    if (vb) {
                        pr2serr("Request Sense near startup detected "
                                "something:\n");
                        pr2serr("  Sense key: %s, additional: %s\n  ... "
                                "continue\n",
                                sg_get_sense_key_str(ssh.sense_key,
                                         sizeof(buff), buff), aa_str);
                    }
                }
            }
        } else {
            if (vb)
                pr2serr("Request sense failed (res=%d), most likely "
                        " problems ahead\n", ret);
        }
        clear_scsi_pt_obj(ptvp);
        memset(enc_stat_rsp, 0, enc_stat_rsp_sz);
    }

    if (op->nickname_str)
        ret = ses_set_nickname(ptvp, op);
    else if (have_cgs) {
        for (k = 0, tavp = tav_arr, cgs_clp = op->cgs_cl_arr;
             k < op->num_cgs; ++k, ++tavp, ++cgs_clp) {
            ret = ses_cgs(ptvp, tavp, cgs_clp->last_cs, op, jop);
            if (ret)
                break;
        }
    } else if (op->do_join)
        ret = join_work(ptvp, true, op, jop);
    else if (op->do_status)
        ret = process_1ormore_status_dpages(ptvp, op, jop);
    else { /* control page requested */
        op->data_arr[0] = op->page_code;
        op->data_arr[1] = op->byte1;
        d_len = op->arr_len + DATA_IN_OFF;
        sg_put_unaligned_be16((uint16_t)op->arr_len, op->data_arr + 2);
        switch (op->page_code) {
        case ENC_CONTROL_DPC:  /* Enclosure Control diagnostic page [0x2] */
            sgj_pr_hr(jsp, "Sending Enclosure Control [0x%x] page, with page "
                      "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Enclosure Control page\n");
                goto err_out;
            }
            break;
        case STRING_DPC:       /* String Out diagnostic page [0x4] */
            sgj_pr_hr(jsp, "Sending String Out [0x%x] page, with page "
                      "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send String Out page\n");
                goto err_out;
            }
            break;
        case THRESHOLD_DPC:       /* Threshold Out diagnostic page [0x5] */
            sgj_pr_hr(jsp, "Sending Threshold Out [0x%x] page, with page "
                      "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Threshold Out page\n");
                goto err_out;
            }
            break;
        case ARRAY_CONTROL_DPC:   /* Array control diagnostic page [0x6] */
            sgj_pr_hr(jsp, "Sending Array Control [0x%x] page, with page "
                      "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Array Control page\n");
                goto err_out;
            }
            break;
        case SUBENC_STRING_DPC: /* Subenclosure String Out page [0xc] */
            sgj_pr_hr(jsp, "Sending Subenclosure String Out [0x%x] page, "
                      "with page length=%d bytes\n", op->page_code,
                      op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Subenclosure String Out page\n");
                goto err_out;
            }
            break;
        case DOWNLOAD_MICROCODE_DPC: /* Download Microcode Control [0xe] */
            sgj_pr_hr(jsp, "Sending Download Microcode Control [0x%x] page, "
                      "with page length=%d bytes\n", op->page_code, d_len);
            sgj_pr_hr(jsp, "  Perhaps it would be better to use the "
                      "sg_ses_microcode utility\n");
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Download Microcode Control page\n");
                goto err_out;
            }
            break;
        case SUBENC_NICKNAME_DPC: /* Subenclosure Nickname Control [0xf] */
            sgj_pr_hr(jsp, "Sending Subenclosure Nickname Control [0x%x] "
                      "page, with page length=%d bytes\n", op->page_code,
                      d_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Subenclosure Nickname Control page\n");
                goto err_out;
            }
            break;
        default:
            if (! op->page_code_given)
                pr2serr("Must specify --page=PG where PG is modifiable\n");
            else {
                pr2serr("Setting SES control page 0x%x not supported by "
                        "this utility\n", op->page_code);
                pr2serr("If possible, that may be done with the sg_senddiag "
                        "utility with its '--raw=' option\n");
            }
            ret = SG_LIB_SYNTAX_ERROR;
            break;
        }
    }

err_out:
    if (! op->do_status) {
        sg_get_category_sense_str(ret, sizeof(b), b, vb);
        pr2serr("    %s\n", b);
    }
    if (free_enc_stat_rsp)
        free(free_enc_stat_rsp);
    if (free_elem_desc_rsp)
        free(free_elem_desc_rsp);
    if (free_add_elem_rsp)
        free(free_add_elem_rsp);
    if (free_threshold_rsp)
        free(free_threshold_rsp);

early_out:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (ptvp)
        destruct_scsi_pt_obj(ptvp);
    if ((0 == vb) && (! op->quiet)) {
        if (! sg_if_can2stderr("sg_ses failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
        else if ((SG_LIB_SYNTAX_ERROR == ret) && (0 == vb))
            pr2serr("Add '-h' to command line for usage information\n");
    }
    if (op->free_data_arr)
        free(op->free_data_arr);
    if (free_config_dp_resp)
        free(free_config_dp_resp);
    ret = (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
    if (as_json && jop) {
        FILE * fp = stdout;

        if (op->js_file) {
            if ((1 != strlen(op->js_file)) || ('-' != op->js_file[0])) {
                fp = fopen(op->js_file, "w");   /* truncate if exists */
                if (NULL == fp) {
                    int e = errno;

                    pr2serr("unable to open file: %s [%s]\n", op->js_file,
                            safe_strerror(e));
                    ret = sg_convert_errno(e);
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
    return ret;
}
