/*
 * Copyright (c) 2004-2020 Douglas Gilbert.
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

static const char * version_str = "2.48 20200206";    /* ses4r03 + 20-013r1 */

#define MX_ALLOC_LEN ((64 * 1024) - 4)  /* max allowable for big enclosures */
#define MX_ELEM_HDR 1024
#define REQUEST_SENSE_RESP_SZ 252
#define DATA_IN_OFF 4
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
#define ELEM_DESC_DPC 0x7
#define SHORT_ENC_STATUS_DPC 0x8
#define ENC_BUSY_DPC 0x9
#define ADD_ELEM_STATUS_DPC 0xa /* Additional Element Status dpage code */
#define SUBENC_HELP_TEXT_DPC 0xb
#define SUBENC_STRING_DPC 0xc
#define SUPPORTED_SES_DPC 0xd   /* should be 0x1 <= dpc <= 0x2f */
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
    bool byte1_given;   /* true if -b B1 or --byte1=B1 given */
    bool do_control;    /* want to write to DEVICE */
    bool do_data;       /* flag if --data= option has been used */
    bool do_list;
    bool do_status;     /* want to read from DEVICE (or user data) */
    bool eiioe_auto;    /* Element Index Includes Overall (status) Element */
    bool eiioe_force;
    bool ind_given;     /* '--index=...' or '-I ...' */
    bool inner_hex;
    bool many_dpages;   /* user supplied data has more than one dpage */
    bool mask_ign;      /* element read-mask-modify-write actions */
    bool o_readonly;
    bool page_code_given;       /* or suitable abbreviation */
    bool quiet;         /* exit status unaltered by --quiet */
    bool seid_given;
    bool verbose_given;
    bool version_given;
    bool warn;
    int byte1;          /* (origin 0 so second byte) in Control dpage */
    int dev_slot_num;
    int do_filter;
    int do_help;
    int do_hex;
    int do_join;        /* relational join of Enclosure status, Element
                           descriptor and Additional element status dpages.
                           Use twice to add Threshold in dpage to join. */
    int do_raw;
    int enumerate;
    int ind_th;    /* type header index, set by build_type_desc_hdr_arr() */
    int ind_indiv;      /* individual element index; -1 for overall */
    int ind_indiv_last; /* if > ind_indiv then [ind_indiv..ind_indiv_last] */
    int ind_et_inst;    /* ETs can have multiple type header instances */
    int maxlen;
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
    struct cgs_cl_t cgs_cl_arr[CGS_CL_ARR_MAX_SZ];
    uint8_t sas_addr[8];  /* Big endian byte sequence */
};

struct diag_page_code {
    int page_code;
    const char * desc;
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


/* Join array has four "element index"ing stategies:
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


/* Diagnostic page names, control and/or status (in and/or out) */
static struct diag_page_code dpc_arr[] = {
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
    {ALL_DPC, "All SES diagnostic pages output (sg_ses)"},
    {-1, NULL},
};

/* Diagnostic page names, for status (or in) pages */
static struct diag_page_code in_dpc_arr[] = {
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
static struct diag_page_code out_dpc_arr[] = {
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

static struct diag_page_abbrev dp_abbrev[] = {
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
static struct element_type_t element_type_arr[] = {
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
static struct acronym2tuple ecs_a2t_arr[] = {
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
static struct acronym2tuple th_a2t_arr[] = {
    {"high_crit", -1, 0, 7, 8, NULL},
    {"high_warn", -1, 1, 7, 8, NULL},
    {"low_crit", -1, 2, 7, 8, NULL},
    {"low_warn", -1, 3, 7, 8, NULL},
    {NULL, 0, 0, 0, 0, NULL},
};

/* These are for the Additional element status diagnostic page for SAS with
 * the EIP bit set. First phy only. Index from start of AES descriptor */
static struct acronym2tuple ae_sas_a2t_arr[] = {
    {"at_sas_addr", -1, 12, 7, 64, NULL},  /* best viewed with --hex --get= */
        /* typically this is the expander's SAS address */
    {"dev_type", -1, 8, 6, 3, "1: SAS/SATA dev, 2: expander"},
    {"dsn", -1, 7, 7, 8, "device slot number (255: none)"},
    {"num_phys", -1, 4, 7, 8, "number of phys"},
    {"phy_id", -1, 28, 7, 8, NULL},
    {"sas_addr", -1, 20, 7, 64, NULL},  /* should be disk or tape ... */
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
 * Status page. Indexed by element type (0 <= et < 32). */
static bool active_et_aesp_arr[NUM_ACTIVE_ET_AESP_ARR] = {
    false, true /* dev */, false, false,
    false, false, false, true /* esce */,
    false, false, false, false,
    false, false, false, false,
    false, false, false, false,
    true /* starg */, true /* sinit */, false, true /* arr */,
    true /* sas exp */, false, false, false,
    false, false, false, false,
};

/* Command line long option names with corresponding short letter. */
static struct option long_options[] = {
    {"byte1", required_argument, 0, 'b'},
    {"clear", required_argument, 0, 'C'},
    {"control", no_argument, 0, 'c'},
    {"data", required_argument, 0, 'd'},
    {"descriptor", required_argument, 0, 'D'},
    {"dev-slot-num", required_argument, 0, 'x'},
    {"dev_slot_num", required_argument, 0, 'x'},
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
    {"join", no_argument, 0, 'j'},
    {"list", no_argument, 0, 'l'},
    {"nickid", required_argument, 0, 'N'},
    {"nickname", required_argument, 0, 'n'},
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
static uint8_t ses3_element_cmask_arr[NUM_ETC][4] = {
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
            "Usage: sg_ses [--descriptor=DES] [--dev-slot-num=SN] "
            "[--eiioe=A_F]\n"
            "              [--filter] [--get=STR] [--hex] "
            "[--index=IIA | =TIA,II]\n"
            "              [--inner-hex] [--join] [--maxlen=LEN] "
            "[--page=PG] [--quiet]\n"
            "              [--raw] [--readonly] [--sas-addr=SA] [--status] "
            "[--verbose]\n"
            "              [--warn] DEVICE\n\n"
            "       sg_ses --control [--byte1=B1] [--clear=STR] "
            "[--data=H,H...]\n"
            "              [--descriptor=DES] [--dev-slot-num=SN] "
            "[--index=IIA | =TIA,II]\n"
            "              [--inhex=FN] [--mask] [--maxlen=LEN] "
            "[--nickid=SEID]\n"
            "              [--nickname=SEN] [--page=PG] [--sas-addr=SA] "
            "[--set=STR]\n"
            "              [--verbose] DEVICE\n\n"
            "       sg_ses --data=@FN --status [-rr] [<most options from "
            "first form>]\n"
            "       sg_ses --inhex=FN --status [-rr] [<most options from "
            "first form>]\n\n"
            "       sg_ses [--enumerate] [--help] [--index=IIA] [--list] "
            "[--version]\n\n"
               );
        if ((help_num < 1) || (help_num > 2)) {
            pr2serr("Or the corresponding short option usage: \n"
                    "  sg_ses [-D DES] [-x SN] [-E A_F] [-f] [-G STR] [-H] "
                    "[-I IIA|TIA,II] [-i]\n"
                    "         [-j] [-m LEN] [-p PG] [-q] [-r] [-R] [-A SA] "
                    "[-s] [-v] [-w] DEVICE\n\n"
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
            pr2serr("\nFor help use with '-h' one or more times\n");
            return;
        }
        pr2serr(
            "  where the main options are:\n"
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
            "(e.g. '2-5')\n"
            "    --index=TIA,II|-I TIA,II    comma separated pair: TIA is "
            "type header\n"
            "                                index or element type "
            "abbreviation;\n"
            "                                II is individual index ('-1' "
            "for overall)\n"
            );
        pr2serr(
            "    --join|-j           group Enclosure Status, Element "
            "Descriptor\n"
            "                        and Additional Element Status pages. "
            "Use twice\n"
            "                        to add Threshold In page\n"
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
            "    --inhex=FN|-X FN    alternate form of --data=@FN\n"
            "    --inner-hex|-i      print innermost level of a"
            " status page in hex\n"
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
            "    --quiet|-q          suppress some output messages\n"
            "    --raw|-r            print status page in ASCII hex suitable "
            "for '-d';\n"
            "                        when used twice outputs page in binary "
            "to stdout\n"
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

/* Return 0 for okay, else an error */
static int
parse_index(struct opts_t *op)
{
    int n, n2;
    const char * cp;
    char * mallcp;
    char * c2p;
    const char * cc3p;
    const struct element_type_t * etp;
    char b[64];
    const int blen = sizeof(b);

    op->ind_given = true;
    n2 = 0;
    if ((cp = strchr(op->index_str, ','))) {
        /* decode number following comma */
        if (0 == strcmp("-1", cp + 1))
            n = -1;
        else {
            n = sg_get_num_nomult(cp + 1);
            if ((n < 0) || (n > 255)) {
                pr2serr("bad argument to '--index=', after comma expect "
                        "number from -1 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((cc3p = strchr(cp + 1, '-'))) {
                n2 = sg_get_num_nomult(cc3p + 1);
                if ((n2 < n) || (n2 > 255)) {
                    pr2serr("bad argument to '--index', after '-' expect "
                            "number from -%d to 255\n", n);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
        }
        op->ind_indiv = n;
        if (n2 > 0)
            op->ind_indiv_last = n2;
        n = cp - op->index_str;
        if (n >= (blen - 1)) {
            pr2serr("bad argument to '--index', string prior to comma too "
                    "long\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    } else {    /* no comma found in index_str */
        n = strlen(op->index_str);
        if (n >= (blen - 1)) {
            pr2serr("bad argument to '--index', string too long\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    snprintf(b, blen, "%.*s", n, op->index_str);
    if (0 == strcmp("-1", b)) {
        if (cp) {
            pr2serr("bad argument to '--index', unexpected '-1' type header "
                    "index\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        op->ind_th = 0;
        op->ind_indiv = -1;
    } else if (isdigit(b[0])) {
        n = sg_get_num_nomult(b);
        if ((n < 0) || (n > 255)) {
            pr2serr("bad numeric argument to '--index', expect number from 0 "
                    "to 255\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (cp)         /* argument to left of comma */
            op->ind_th = n;
        else {          /* no comma found, so 'n' is ind_indiv */
            op->ind_th = 0;
            op->ind_indiv = n;
            if ((c2p = strchr(b, '-'))) {
                n2 = sg_get_num_nomult(c2p + 1);
                if ((n2 < n) || (n2 > 255)) {
                    pr2serr("bad argument to '--index', after '-' expect "
                            "number from -%d to 255\n", n);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            op->ind_indiv_last = n2;
        }
    } else if ('_' == b[0]) {   /* leading "_" prefixes element type code */
        if ((c2p = strchr(b + 1, '_')))
            *c2p = '\0';        /* subsequent "_" prefixes e.t. index */
        n = sg_get_num_nomult(b + 1);
        if ((n < 0) || (n > 255)) {
            pr2serr("bad element type code for '--index', expect value from "
                    "0 to 255\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        element_type_by_code.elem_type_code = n;
        mallcp = (char *)malloc(8);  /* willfully forget about freeing this */
        mallcp[0] = '_';
        snprintf(mallcp + 1, 6, "%d", n);
        element_type_by_code.abbrev = mallcp;
        if (c2p) {
            n = sg_get_num_nomult(c2p + 1);
            if ((n < 0) || (n > 255)) {
                pr2serr("bad element type code <num> for '--index', expect "
                        "<num> from 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
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
            if ((n == b_len) && (0 == strncmp(b, etp->abbrev, n)))
                break;
        }
        if (NULL == etp->desc) {
            pr2serr("bad element type abbreviation [%s] for '--index'\n"
                    "use '--enumerate' to see possibles\n", b);
            return SG_LIB_SYNTAX_ERROR;
        }
        if (b_len > n) {
            n = sg_get_num_nomult(b + n);
            if ((n < 0) || (n > 255)) {
                pr2serr("bad element type abbreviation <num> for '--index', "
                        "expect <num> from 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->ind_et_inst = n;
        }
        op->ind_etp = etp;
        if (NULL == cp)
            op->ind_indiv = -1;
    }
    if (op->verbose > 1) {
        if (op->ind_etp)
            pr2serr("   element type abbreviation: %s, etp_num=%d, "
                    "individual index=%d\n", op->ind_etp->abbrev,
                    op->ind_et_inst, op->ind_indiv);
        else
            pr2serr("   type header index=%d, individual index=%d\n",
                    op->ind_th, op->ind_indiv);
    }
    return 0;
}


/* command line process, options and arguments. Returns 0 if ok. */
static int
parse_cmd_line(struct opts_t *op, int argc, char *argv[])
{
    int c, j, n, d_len, ret;
    const char * data_arg = NULL;
    const char * inhex_arg = NULL;
    uint64_t saddr;
    const char * cp;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "A:b:cC:d:D:eE:fG:hHiI:jln:N:m:Mp:qrRs"
                        "S:vVwx:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'A':       /* SAS address, assumed to be hex */
            cp = optarg;
            if ((strlen(optarg) > 2) && ('X' == toupper(optarg[1])))
                cp = optarg + 2;
            if (1 != sscanf(cp, "%" SCNx64 "", &saddr)) {
                pr2serr("bad argument to '--sas-addr=SA'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            sg_put_unaligned_be64(saddr, op->sas_addr + 0);
            if (sg_all_ffs(op->sas_addr, 8)) {
                pr2serr("error decoding '--sas-addr=SA' argument\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'b':
            op->byte1 = sg_get_num_nomult(optarg);
            if ((op->byte1 < 0) || (op->byte1 > 255)) {
                pr2serr("bad argument to '--byte1=B1' (0 to 255 "
                        "inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
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
                return SG_LIB_SYNTAX_ERROR;
            }
            if (op->num_cgs < CGS_CL_ARR_MAX_SZ) {
                op->cgs_cl_arr[op->num_cgs].cgs_sel = CLEAR_OPT;
                strcpy(op->cgs_cl_arr[op->num_cgs].cgs_str, optarg);
                ++op->num_cgs;
            } else {
                pr2serr("Too many --clear=, --get= and --set= options "
                        "(max: %d)\n", CGS_CL_ARR_MAX_SZ);
                return SG_LIB_CONTRADICT;
            }
            break;
        case 'd':
            data_arg = optarg;
            op->do_data = true;
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
                return SG_LIB_CONTRADICT;
            }
            break;
        case 'f':
            ++op->do_filter;
            break;
        case 'G':
            if (strlen(optarg) >= CGS_STR_MAX_SZ) {
                pr2serr("--get= option too long (max %d characters)\n",
                        CGS_STR_MAX_SZ);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (op->num_cgs < CGS_CL_ARR_MAX_SZ) {
                op->cgs_cl_arr[op->num_cgs].cgs_sel = GET_OPT;
                strcpy(op->cgs_cl_arr[op->num_cgs].cgs_str, optarg);
                ++op->num_cgs;
            } else {
                pr2serr("Too many --clear=, --get= and --set= options "
                        "(max: %d)\n", CGS_CL_ARR_MAX_SZ);
                return SG_LIB_CONTRADICT;
            }
            break;
        case 'h':
            ++op->do_help;
            break;
        case '?':
            pr2serr("\n");
            usage(0);
            return SG_LIB_SYNTAX_ERROR;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            op->inner_hex = true;
            break;
        case 'I':
            op->index_str = optarg;
            break;
        case 'j':
            ++op->do_join;
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
                return SG_LIB_SYNTAX_ERROR;
            }
            op->seid_given = true;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 65535)) {
                pr2serr("bad argument to '--maxlen=LEN' (0 to 65535 "
                        "inclusive expected)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (0 == n)
                op->maxlen = MX_ALLOC_LEN;
            else if (n < 4)
                pr2serr("Warning: --maxlen=LEN less than 4 ignored\n");
            else
                op->maxlen = n;
            break;
        case 'M':
            op->mask_ign = true;
            break;
        case 'p':
            if (isdigit(optarg[0])) {
                op->page_code = sg_get_num_nomult(optarg);
                if ((op->page_code < 0) || (op->page_code > 255)) {
                    pr2serr("bad argument to '--page=PG' (0 to 255 "
                            "inclusive)\n");
                    return SG_LIB_SYNTAX_ERROR;
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
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            op->page_code_given = true;
            break;
        case 'q':
            op->quiet = true;
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
                return SG_LIB_SYNTAX_ERROR;
            }
            if (op->num_cgs < CGS_CL_ARR_MAX_SZ) {
                op->cgs_cl_arr[op->num_cgs].cgs_sel = SET_OPT;
                strcpy(op->cgs_cl_arr[op->num_cgs].cgs_str, optarg);
                ++op->num_cgs;
            } else {
                pr2serr("Too many --clear=, --get= and --set= options "
                        "(max: %d)\n", CGS_CL_ARR_MAX_SZ);
                return SG_LIB_CONTRADICT;
            }
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            return 0;
        case 'w':
            op->warn = true;
            break;
        case 'x':
            op->dev_slot_num = sg_get_num_nomult(optarg);
            if ((op->dev_slot_num < 0) || (op->dev_slot_num > 255)) {
                pr2serr("bad argument to '--dev-slot-num' (0 to 255 "
                        "inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'X':       /* --inhex=FN for compatibility with other utils */
            inhex_arg = optarg;
            op->do_data = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            goto err_help;
        }
    }
    if (op->do_help)
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
    op->mx_arr_len = (op->maxlen > MIN_DATA_IN_SZ) ? op->maxlen :
                                                     MIN_DATA_IN_SZ;
    op->data_arr = sg_memalign(op->mx_arr_len, 0 /* page aligned */,
                               &op->free_data_arr, false);
    if (NULL == op->data_arr) {
        pr2serr("unable to allocate %u bytes on heap\n", op->mx_arr_len);
        return sg_convert_errno(ENOMEM);
    }
    if (data_arg || inhex_arg) {
        if (inhex_arg) {
            data_arg = inhex_arg;
            if (read_hex(data_arg, op->data_arr + DATA_IN_OFF,
                         op->mx_arr_len - DATA_IN_OFF, &op->arr_len,
                         (op->do_raw < 2), false, op->verbose)) {
                pr2serr("bad argument, expect '--inhex=FN' or '--inhex=-'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else {
            if (read_hex(data_arg, op->data_arr + DATA_IN_OFF,
                         op->mx_arr_len - DATA_IN_OFF, &op->arr_len,
                         (op->do_raw < 2), true, op->verbose)) {
                pr2serr("bad argument, expect '--data=H,H...', '--data=-' or "
                        "'--data=@FN'\n");
                return SG_LIB_SYNTAX_ERROR;
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
                        snprintf(b, sizeof(b), "%s dpage", cp);
                    else
                        snprintf(b, sizeof(b), "dpage 0x%x", didp->page_code);
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
        if (ret) {
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
        else if (! op->do_data) {
            pr2serr("need to give '--data' in control mode\n");
            goto err_help;
        }
    } else if (! op->do_status) {
        if (op->do_data) {
            pr2serr("when user data given, require '--control' or "
                    "'--status' option\n");
            goto err_help;
        }
        op->do_status = true;  /* default to receiving status pages */
    } else if (op->do_status && op->do_data && op->dev_name) {
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
    if ((op->verbose > 4) && saddr_non_zero(op->sas_addr)) {
        pr2serr("    SAS address (in hex): ");
        for (j = 0; j < 8; ++j)
            pr2serr("%02x", op->sas_addr[j]);
        pr2serr("\n");
    }

    if ((! (op->do_data && op->do_status)) && (NULL == op->dev_name)) {
        pr2serr("missing DEVICE name!\n\n");
        goto err_help;
    }
    return 0;

err_help:
    if (op->verbose) {
        pr2serr("\n");
        usage(0);
    }
    return SG_LIB_SYNTAX_ERROR;
}

/* Parse clear/get/set string, writes output to '*tavp'. Uses 'buff' for
 * scratch area. Returns 0 on success, else -1. */
static int
parse_cgs_str(char * buff, struct tuple_acronym_val * tavp)
{
    char * esp;
    char * colp;
    char * cp;
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
    if (isalpha(buff[0]))
        tavp->acron = buff;
    else {
        colp = strchr(buff, ':');
        if ((NULL == colp) || (buff == colp))
            return -1;
        *colp = '\0';
        if (('0' == buff[0]) && ('X' == toupper(buff[1]))) {
            if (1 != sscanf(buff + 2, "%x", &ui))
                return -1;
            tavp->start_byte = ui;
        } else if ('H' == toupper(*(colp - 1))) {
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

#if 0
static bool
match_last_ind_indiv(int index, const struct opts_t * op)
{
    if (op->ind_indiv_last >= op->ind_indiv)
        return (index == op->ind_indiv_last);
    return (index == op->ind_indiv);
}
#endif

/* Return of 0 -> success, SG_LIB_CAT_* positive values or -1 -> other
 * failures */
static int
do_senddiag(struct sg_pt_base * ptvp, void * outgoing_pg, int outgoing_len,
            bool noisy, int verbose)
{
    const bool pf_bit = true;
    int page_num, ret;
    const char * cp;

    if (outgoing_pg && (verbose > 2)) {
        page_num = ((const char *)outgoing_pg)[0];
        cp = find_out_diag_page_desc(page_num);
        if (cp)
            pr2serr("    Send diagnostic command page name: %s\n", cp);
        else
            pr2serr("    Send diagnostic command page number: 0x%x\n",
                    page_num);
    }
    ret = sg_ll_send_diag_pt(ptvp, 0 /* sf_code */, pf_bit,
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
        snprintf(b, mlen_b - 1, "vendor specific [0x%x]", elem_type_code);
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

#if 0
static struct join_row_t *
find_join_row(struct th_es_t * tesp, int index, enum fj_select_t sel)
{
    int k;
    struct join_row_t * jrp = tesp->j_base;

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
    case FJ_AESS:    /* index includes only AES listed element types */
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
#endif

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
        snprintf(bb, sizeof(bb), "%s dpage", cp);
    else
        snprintf(bb, sizeof(bb), "dpage 0x%x", page_code);
    cp = bb;

    if (op->data_arr && op->do_data) {  /* user provided data */
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
            if (vb)
                pr2serr("%s: %s not found in user data\n", __func__, cp);
            return SG_LIB_CAT_OTHER;
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
                pr2serr("Enclosure only supports Short Enclosure Status: "
                        "0x%x\n", rsp_buff[1]);
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

#if 1

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

#else

static void
dStrRaw(const uint8_t * str, int len)
{
    int res, err;

    if (len > 0) {
        res = write(fileno(stdout), str, len);
        if (res < 0) {
            err = errno;
            pr2serr("%s: write to stdout failed: %s [%d]\n", __func__,
                    strerror(err), err);
        }
    }
}

#endif

/* CONFIGURATION_DPC [0x1]
 * Display Configuration diagnostic page. */
static void
configuration_sdg(const uint8_t * resp, int resp_len)
{
    int j, k, el, num_subs, sum_elem_types;
    uint32_t gen_code;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const uint8_t * text_bp;
    char b[64];

    printf("Configuration diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    sum_elem_types = 0;
    last_bp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n",
            num_subs - 1);
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    bp = resp + 8;
    printf("  enclosure descriptor list\n");
    for (k = 0; k < num_subs; ++k, bp += el) {
        if ((bp + 3) > last_bp)
            goto truncated;
        el = bp[3] + 4;
        sum_elem_types += bp[2];
        printf("    Subenclosure identifier: %d%s\n", bp[1],
               (bp[1] ? "" : " [primary]"));
        printf("      relative ES process id: %d, number of ES processes"
               ": %d\n", ((bp[0] & 0x70) >> 4), (bp[0] & 0x7));
        printf("      number of type descriptor headers: %d\n", bp[2]);
        if (el < 40) {
            pr2serr("      enc descriptor len=%d ??\n", el);
            continue;
        }
        printf("      enclosure logical identifier (hex): ");
        for (j = 0; j < 8; ++j)
            printf("%02x", bp[4 + j]);
        printf("\n      enclosure vendor: %.8s  product: %.16s  rev: %.4s\n",
               bp + 12, bp + 20, bp + 36);
        if (el > 40) {
            char bb[1024];

            printf("      vendor-specific data:\n");
            hex2str(bp + 40, el - 40, "        ", 0, sizeof(bb), bb);
            printf("%s\n", bb);
        }
    }
    /* printf("\n"); */
    printf("  type descriptor header and text list\n");
    text_bp = bp + (sum_elem_types * 4);
    for (k = 0; k < sum_elem_types; ++k, bp += 4) {
        if ((bp + 3) > last_bp)
            goto truncated;
        printf("    Element type: %s, subenclosure id: %d\n",
               etype_str(bp[0], b, sizeof(b)), bp[2]);
        printf("      number of possible elements: %d\n", bp[1]);
        if (bp[3] > 0) {
            if (text_bp > last_bp)
                goto truncated;
            printf("      text: %.*s\n", bp[3], text_bp);
            text_bp += bp[3];
        }
    }
    return;
truncated:
    pr2serr("    <<<ses_configuration_sdg: response too short>>>\n");
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
                pr2serr("%s: unable to find element type '%s%d'\n", __func__,
                        op->ind_etp->abbrev, op->ind_et_inst);
            else
                pr2serr("%s: unable to find element type '%s'\n", __func__,
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
        snprintf(buff, buff_len, "Vendor specific");
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
            snprintf(buff, buff_len, "Vendor specific internal connector");
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
            snprintf(buff, buff_len, "reserved for internal connector, "
                     "type: 0x%x", conn_type);
        else if (conn_type < 0x70)
            snprintf(buff, buff_len, "reserved connector type: 0x%x",
                     conn_type);
        else if (conn_type < 0x80)
            snprintf(buff, buff_len, "vendor specific connector type: 0x%x",
                     conn_type);
        else    /* conn_type is a 7 bit field, so this is impossible */
            snprintf(buff, buff_len, "unexpected connector type: 0x%x",
                     conn_type);
        break;
    }
    return buff;
}

/* 'Fan speed factor' new in 20-013r1, probably will be in ses4r04 */
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

static void
enc_status_helper(const char * pad, const uint8_t * statp, int etype,
                  bool abridged, const struct opts_t * op)
{
    int res, a, b, ct, bblen;
    bool nofilter = ! op->do_filter;
    char bb[128];


    if (op->inner_hex) {
        printf("%s%02x %02x %02x %02x\n", pad, statp[0], statp[1], statp[2],
               statp[3]);
        return;
    }
    if (! abridged)
        printf("%sPredicted failure=%d, Disabled=%d, Swap=%d, status: %s\n",
               pad, !!(statp[0] & 0x40), !!(statp[0] & 0x20),
               !!(statp[0] & 0x10), elem_status_code_desc[statp[0] & 0xf]);
    switch (etype) { /* element types */
    case UNSPECIFIED_ETC:
        if (op->verbose)
            printf("%sstatus in hex: %02x %02x %02x %02x\n",
                   pad, statp[0], statp[1], statp[2], statp[3]);
        break;
    case DEVICE_ETC:
        if (ARRAY_STATUS_DPC == op->page_code) {  /* obsolete after SES-1 */
            if (nofilter || (0xf0 & statp[1]))
                printf("%sOK=%d, Reserved device=%d, Hot spare=%d, Cons "
                       "check=%d\n", pad, !!(statp[1] & 0x80),
                       !!(statp[1] & 0x40), !!(statp[1] & 0x20),
                       !!(statp[1] & 0x10));
            if (nofilter || (0xf & statp[1]))
                printf("%sIn crit array=%d, In failed array=%d, Rebuild/"
                       "remap=%d, R/R abort=%d\n", pad, !!(statp[1] & 0x8),
                       !!(statp[1] & 0x4), !!(statp[1] & 0x2),
                       !!(statp[1] & 0x1));
            if (nofilter || ((0x46 & statp[2]) || (0x8 & statp[3])))
                printf("%sDo not remove=%d, RMV=%d, Ident=%d, Enable bypass "
                       "A=%d\n", pad, !!(statp[2] & 0x40), !!(statp[2] & 0x4),
                       !!(statp[2] & 0x2), !!(statp[3] & 0x8));
            if (nofilter || (0x7 & statp[3]))
                printf("%sEnable bypass B=%d, Bypass A enabled=%d, Bypass B "
                        "enabled=%d\n", pad, !!(statp[3] & 0x4),
                       !!(statp[3] & 0x2), !!(statp[3] & 0x1));
            break;
        }
        printf("%sSlot address: %d\n", pad, statp[1]);
        if (nofilter || (0xe0 & statp[2]))
            printf("%sApp client bypassed A=%d, Do not remove=%d, Enc "
                   "bypassed A=%d\n", pad, !!(statp[2] & 0x80),
                   !!(statp[2] & 0x40), !!(statp[2] & 0x20));
        if (nofilter || (0x1c & statp[2]))
            printf("%sEnc bypassed B=%d, Ready to insert=%d, RMV=%d, Ident="
                   "%d\n", pad, !!(statp[2] & 0x10), !!(statp[2] & 0x8),
                   !!(statp[2] & 0x4), !!(statp[2] & 0x2));
        if (nofilter || ((1 & statp[2]) || (0xe0 & statp[3])))
            printf("%sReport=%d, App client bypassed B=%d, Fault sensed=%d, "
                   "Fault requested=%d\n", pad, !!(statp[2] & 0x1),
                   !!(statp[3] & 0x80), !!(statp[3] & 0x40),
                   !!(statp[3] & 0x20));
        if (nofilter || (0x1e & statp[3]))
            printf("%sDevice off=%d, Bypassed A=%d, Bypassed B=%d, Device "
                   "bypassed A=%d\n", pad, !!(statp[3] & 0x10),
                   !!(statp[3] & 0x8), !!(statp[3] & 0x4), !!(statp[3] & 0x2));
        if (nofilter || (0x1 & statp[3]))
            printf("%sDevice bypassed B=%d\n", pad, !!(statp[3] & 0x1));
        break;
    case POWER_SUPPLY_ETC:
        if (nofilter || ((0xc0 & statp[1]) || (0xc & statp[2]))) {
            printf("%sIdent=%d, Do not remove=%d, DC overvoltage=%d, "
                   "DC undervoltage=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[2] & 0x8),
                   !!(statp[2] & 0x4));
        }
        if (nofilter || ((0x2 & statp[2]) || (0xf0 & statp[3])))
            printf("%sDC overcurrent=%d, Hot swap=%d, Fail=%d, Requested "
                   "on=%d, Off=%d\n", pad, !!(statp[2] & 0x2),
                   !!(statp[3] & 0x80), !!(statp[3] & 0x40),
                   !!(statp[3] & 0x20), !!(statp[3] & 0x10));
        if (nofilter || (0xf & statp[3]))
            printf("%sOvertmp fail=%d, Temperature warn=%d, AC fail=%d, "
                   "DC fail=%d\n", pad, !!(statp[3] & 0x8),
                   !!(statp[3] & 0x4), !!(statp[3] & 0x2),
                   !!(statp[3] & 0x1));
        break;
    case COOLING_ETC:
        if (nofilter || ((0xc0 & statp[1]) || (0xf0 & statp[3])))
            printf("%sIdent=%d, Do not remove=%d, Hot swap=%d, Fail=%d, "
                   "Requested on=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x20));
        printf("%sOff=%d, Actual speed=%d rpm, Fan %s\n", pad,
               !!(statp[3] & 0x10),
               calc_fan_speed((statp[1] >> 3) & 0x3,
                              ((0x7 & statp[1]) << 8) + statp[2]),
               actual_speed_desc[7 & statp[3]]);
        if (op->verbose > 1)    /* show real field values */
            printf("%s  [Fan_speed_factor=%d, Actual_fan_speed=%d]\n",
                   pad, (statp[1] >> 3) & 0x3,
                   ((0x7 & statp[1]) << 8) + statp[2]);
        break;
    case TEMPERATURE_ETC:     /* temperature sensor */
        if (nofilter || ((0xc0 & statp[1]) || (0xf & statp[3]))) {
            printf("%sIdent=%d, Fail=%d, OT failure=%d, OT warning=%d, "
                   "UT failure=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[3] & 0x8),
                   !!(statp[3] & 0x4), !!(statp[3] & 0x2));
            printf("%sUT warning=%d\n", pad, !!(statp[3] & 0x1));
        }
        if (statp[2])
            printf("%sTemperature=%d C\n", pad,
                   (int)statp[2] - TEMPERAT_OFF);
        else
            printf("%sTemperature: <reserved>\n", pad);
        break;
    case DOOR_ETC:      /* OPEN field added in ses3r05 */
        if (nofilter || ((0xc0 & statp[1]) || (0x1 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Open=%d, Unlock=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[3] & 0x2), !!(statp[3] & 0x1));
        break;
    case AUD_ALARM_ETC:     /* audible alarm */
        if (nofilter || ((0xc0 & statp[1]) || (0xd0 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Request mute=%d, Mute=%d, "
                   "Remind=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x10));
        if (nofilter || (0xf & statp[3]))
            printf("%sTone indicator: Info=%d, Non-crit=%d, Crit=%d, "
                   "Unrecov=%d\n", pad, !!(statp[3] & 0x8), !!(statp[3] & 0x4),
                   !!(statp[3] & 0x2), !!(statp[3] & 0x1));
        break;
    case ENC_SCELECTR_ETC: /* enclosure services controller electronics */
        if (nofilter || (0xe0 & statp[1]) || (0x1 & statp[2]) ||
            (0x80 & statp[3]))
            printf("%sIdent=%d, Fail=%d, Do not remove=%d, Report=%d, "
                   "Hot swap=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[1] & 0x20),
                   !!(statp[2] & 0x1), !!(statp[3] & 0x80));
        break;
    case SCC_CELECTR_ETC:     /* SCC controller electronics */
        if (nofilter || ((0xc0 & statp[1]) || (0x1 & statp[2])))
            printf("%sIdent=%d, Fail=%d, Report=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[2] & 0x1));
        break;
    case NV_CACHE_ETC:     /* Non volatile cache */
        res = sg_get_unaligned_be16(statp + 2);
        printf("%sIdent=%d, Fail=%d, Size multiplier=%d, Non volatile cache "
               "size=0x%x\n", pad, !!(statp[1] & 0x80), !!(statp[1] & 0x40),
               (statp[1] & 0x3), res);
        printf("%sHence non volatile cache size: %d %s\n", pad, res,
               nv_cache_unit[statp[1] & 0x3]);
        break;
    case INV_OP_REASON_ETC:   /* Invalid operation reason */
        res = ((statp[1] >> 6) & 3);
        printf("%sInvop type=%d   %s\n", pad, res, invop_type_desc[res]);
        switch (res) {
        case 0:
            printf("%sPage not supported=%d\n", pad, (statp[1] & 1));
            break;
        case 1:
            printf("%sByte offset=%d, bit number=%d\n", pad,
                   sg_get_unaligned_be16(statp + 2), (statp[1] & 7));
            break;
        case 2:
        case 3:
            printf("%slast 3 bytes (hex): %02x %02x %02x\n", pad, statp[1],
                   statp[2], statp[3]);
            break;
        }
        break;
    case UI_POWER_SUPPLY_ETC:   /* Uninterruptible power supply */
        if (0 == statp[1])
            printf("%sBattery status: discharged or unknown\n", pad);
        else if (255 == statp[1])
            printf("%sBattery status: 255 or more minutes remaining\n", pad);
        else
            printf("%sBattery status: %d minutes remaining\n", pad, statp[1]);
        if (nofilter || (0xf8 & statp[2]))
            printf("%sAC low=%d, AC high=%d, AC qual=%d, AC fail=%d, DC fail="
                   "%d\n", pad, !!(statp[2] & 0x80), !!(statp[2] & 0x40),
                   !!(statp[2] & 0x20), !!(statp[2] & 0x10),
                   !!(statp[2] & 0x8));
        if (nofilter || ((0x7 & statp[2]) || (0xe3 & statp[3]))) {
            printf("%sUPS fail=%d, Warn=%d, Intf fail=%d, Ident=%d, Fail=%d, "
                   "Do not remove=%d\n", pad, !!(statp[2] & 0x4),
                   !!(statp[2] & 0x2), !!(statp[2] & 0x1),
                   !!(statp[3] & 0x80), !!(statp[3] & 0x40),
                   !!(statp[3] & 0x20));
            printf("%sBatt fail=%d, BPF=%d\n", pad, !!(statp[3] & 0x2),
                   !!(statp[3] & 0x1));
        }
        break;
    case DISPLAY_ETC:   /* Display (ses2r15) */
        if (nofilter || (0xc0 & statp[1])) {
            int dms = statp[1] & 0x3;
            uint16_t dcs;

            printf("%sIdent=%d, Fail=%d, Display mode status=%d", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40), dms);
            if ((1 == dms) || (2 == dms)) {
                dcs = sg_get_unaligned_be16(statp + 2);
                printf(", Display character status=0x%x", dcs);
                if (statp[2] && (0 == statp[3]))
                    printf(" ['%c']", statp[2]);
            }
            printf("\n");
        }
        break;
    case KEY_PAD_ETC:   /* Key pad entry */
        if (nofilter || (0xc0 & statp[1]))
            printf("%sIdent=%d, Fail=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40));
        break;
    case ENCLOSURE_ETC:
        a = ((statp[2] >> 2) & 0x3f);
        if (nofilter || ((0x80 & statp[1]) || a || (0x2 & statp[2])))
            printf("%sIdent=%d, Time until power cycle=%d, "
                   "Failure indication=%d\n", pad, !!(statp[1] & 0x80),
                   a, !!(statp[2] & 0x2));
        b = ((statp[3] >> 2) & 0x3f);
        if (nofilter || (0x1 & statp[2]) || a || b)
            printf("%sWarning indication=%d, Requested power off "
                   "duration=%d\n", pad, !!(statp[2] & 0x1), b);
        if (nofilter || (0x3 & statp[3]))
            printf("%sFailure requested=%d, Warning requested=%d\n",
                   pad, !!(statp[3] & 0x2), !!(statp[3] & 0x1));
        break;
    case SCSI_PORT_TRAN_ETC:   /* SCSI port/transceiver */
        if (nofilter || ((0xc0 & statp[1]) || (0x1 & statp[2]) ||
                           (0x13 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Report=%d, Disabled=%d, Loss of "
                   "link=%d, Xmit fail=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[2] & 0x1),
                   !!(statp[3] & 0x10), !!(statp[3] & 0x2),
                   !!(statp[3] & 0x1));
        break;
    case LANGUAGE_ETC:
        printf("%sIdent=%d, Language code: %.2s\n", pad, !!(statp[1] & 0x80),
               statp + 2);
        break;
    case COMM_PORT_ETC:   /* Communication port */
        if (nofilter || ((0xc0 & statp[1]) || (0x1 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Disabled=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[3] & 0x1));
        break;
    case VOLT_SENSOR_ETC:   /* Voltage sensor */
        if (nofilter || (0xcf & statp[1])) {
            printf("%sIdent=%d, Fail=%d,  Warn Over=%d, Warn Under=%d, "
                   "Crit Over=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[1] & 0x8),
                   !!(statp[1] & 0x4), !!(statp[1] & 0x2));
            printf("%sCrit Under=%d\n", pad, !!(statp[1] & 0x1));
        }
#ifdef SG_LIB_MINGW
        printf("%sVoltage: %g volts\n", pad,
               ((int)(short)sg_get_unaligned_be16(statp + 2) / 100.0));
#else
        printf("%sVoltage: %.2f volts\n", pad,
               ((int)(short)sg_get_unaligned_be16(statp + 2) / 100.0));
#endif
        break;
    case CURR_SENSOR_ETC:   /* Current sensor */
        if (nofilter || (0xca & statp[1]))
            printf("%sIdent=%d, Fail=%d, Warn Over=%d, Crit Over=%d\n",
                    pad, !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                    !!(statp[1] & 0x8), !!(statp[1] & 0x2));
#ifdef SG_LIB_MINGW
        printf("%sCurrent: %g amps\n", pad,
               ((int)(short)sg_get_unaligned_be16(statp + 2) / 100.0));
#else
        printf("%sCurrent: %.2f amps\n", pad,
               ((int)(short)sg_get_unaligned_be16(statp + 2) / 100.0));
#endif
        break;
    case SCSI_TPORT_ETC:   /* SCSI target port */
        if (nofilter || ((0xc0 & statp[1]) || (0x1 & statp[2]) ||
                           (0x1 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Report=%d, Enabled=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[2] & 0x1), !!(statp[3] & 0x1));
        break;
    case SCSI_IPORT_ETC:   /* SCSI initiator port */
        if (nofilter || ((0xc0 & statp[1]) || (0x1 & statp[2]) ||
                           (0x1 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Report=%d, Enabled=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[2] & 0x1), !!(statp[3] & 0x1));
        break;
    case SIMPLE_SUBENC_ETC:   /* Simple subenclosure */
        printf("%sIdent=%d, Fail=%d, Short enclosure status: 0x%x\n", pad,
               !!(statp[1] & 0x80), !!(statp[1] & 0x40), statp[3]);
        break;
    case ARRAY_DEV_ETC:   /* Array device */
        if (nofilter || (0xf0 & statp[1]))
            printf("%sOK=%d, Reserved device=%d, Hot spare=%d, Cons check="
                   "%d\n", pad, !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[1] & 0x20), !!(statp[1] & 0x10));
        if (nofilter || (0xf & statp[1]))
            printf("%sIn crit array=%d, In failed array=%d, Rebuild/remap=%d"
                   ", R/R abort=%d\n", pad, !!(statp[1] & 0x8),
                   !!(statp[1] & 0x4), !!(statp[1] & 0x2),
                   !!(statp[1] & 0x1));
        if (nofilter || (0xf0 & statp[2]))
            printf("%sApp client bypass A=%d, Do not remove=%d, Enc bypass "
                   "A=%d, Enc bypass B=%d\n", pad, !!(statp[2] & 0x80),
                   !!(statp[2] & 0x40), !!(statp[2] & 0x20),
                   !!(statp[2] & 0x10));
        if (nofilter || (0xf & statp[2]))
            printf("%sReady to insert=%d, RMV=%d, Ident=%d, Report=%d\n",
                   pad, !!(statp[2] & 0x8), !!(statp[2] & 0x4),
                   !!(statp[2] & 0x2), !!(statp[2] & 0x1));
        if (nofilter || (0xf0 & statp[3]))
            printf("%sApp client bypass B=%d, Fault sensed=%d, Fault reqstd="
                   "%d, Device off=%d\n", pad, !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x20),
                   !!(statp[3] & 0x10));
        if (nofilter || (0xf & statp[3]))
            printf("%sBypassed A=%d, Bypassed B=%d, Dev bypassed A=%d, "
                   "Dev bypassed B=%d\n",
                   pad, !!(statp[3] & 0x8), !!(statp[3] & 0x4),
                   !!(statp[3] & 0x2), !!(statp[3] & 0x1));
        break;
    case SAS_EXPANDER_ETC:
        printf("%sIdent=%d, Fail=%d\n", pad, !!(statp[1] & 0x80),
               !!(statp[1] & 0x40));
        break;
    case SAS_CONNECTOR_ETC:     /* OC (overcurrent) added in ses3r07 */
        ct = (statp[1] & 0x7f);
        bblen = sizeof(bb);
        if (abridged)
            printf("%s%s, pl=%d", pad,
                   find_sas_connector_type(ct, true, bb, bblen), statp[2]);
        else {
            printf("%sIdent=%d, %s\n", pad, !!(statp[1] & 0x80),
                   find_sas_connector_type(ct, false, bb, bblen));
            /* Mated added in ses3r10 */
            printf("%sConnector physical link=0x%x, Mated=%d, Fail=%d, "
                   "OC=%d\n", pad, statp[2], !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x20));
        }
        break;
    default:
        if (etype < 0x80)
            printf("%sUnknown element type, status in hex: %02x %02x %02x "
                   "%02x\n", pad, statp[0], statp[1], statp[2], statp[3]);
        else
            printf("%sVendor specific element type, status in hex: %02x "
                   "%02x %02x %02x\n", pad, statp[0], statp[1], statp[2],
                   statp[3]);
        break;
    }
}

/* ENC_STATUS_DPC [0x2]
 * Display enclosure status diagnostic page. */
static void
enc_status_dp(const struct th_es_t * tesp, uint32_t ref_gen_code,
              const uint8_t * resp, int resp_len,
              const struct opts_t * op)
{
    int j, k;
    uint32_t gen_code;
    bool got1, match_ind_th;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const struct type_desc_hdr_t * tdhp = tesp->th_base;
    char b[64];

    printf("Enclosure Status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    printf("  INVOP=%d, INFO=%d, NON-CRIT=%d, CRIT=%d, UNRECOV=%d\n",
           !!(resp[1] & 0x10), !!(resp[1] & 0x8), !!(resp[1] & 0x4),
           !!(resp[1] & 0x2), !!(resp[1] & 0x1));
    last_bp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%x\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  status descriptor list\n");
    bp = resp + 8;
    for (k = 0, got1 = false; k < tesp->num_ths; ++k, ++tdhp) {
        if ((bp + 3) > last_bp)
            goto truncated;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   etype_str(tdhp->etype, b, sizeof(b)), tdhp->se_id, k);
            printf("      Overall descriptor:\n");
            enc_status_helper("        ", bp, tdhp->etype, false, op);
            got1 = true;
        }
        for (bp += 4, j = 0; j < tdhp->num_elements; ++j, bp += 4) {
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (! match_ind_indiv(j, op)))
                    continue;
            }
            printf("      Element %d descriptor:\n", j);
            enc_status_helper("        ", bp, tdhp->etype, false, op);
            got1 = true;
        }
    }
    if (op->ind_given && (! got1)) {
        printf("      >>> no match on --index=%d,%d", op->ind_th,
               op->ind_indiv);
        if (op->ind_indiv_last > op->ind_indiv)
            printf("-%d\n", op->ind_indiv_last);
        else
            printf("\n");
    }
    return;
truncated:
    pr2serr("    <<<enc: response too short>>>\n");
    return;
}

/* ARRAY_STATUS_DPC [0x6]
 * Display array status diagnostic page. */
static void
array_status_dp(const struct th_es_t * tesp, uint32_t ref_gen_code,
                const uint8_t * resp, int resp_len,
                const struct opts_t * op)
{
    int j, k;
    uint32_t gen_code;
    bool got1, match_ind_th;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const struct type_desc_hdr_t * tdhp = tesp->th_base;
    char b[64];

    printf("Array Status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    printf("  INVOP=%d, INFO=%d, NON-CRIT=%d, CRIT=%d, UNRECOV=%d\n",
           !!(resp[1] & 0x10), !!(resp[1] & 0x8), !!(resp[1] & 0x4),
           !!(resp[1] & 0x2), !!(resp[1] & 0x1));
    last_bp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%x\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  status descriptor list\n");
    bp = resp + 8;
    for (k = 0, got1 = false; k < tesp->num_ths; ++k, ++tdhp) {
        if ((bp + 3) > last_bp)
            goto truncated;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   etype_str(tdhp->etype, b, sizeof(b)), tdhp->se_id, k);
            printf("      Overall descriptor:\n");
            enc_status_helper("        ", bp, tdhp->etype, false, op);
            got1 = true;
        }
        for (bp += 4, j = 0; j < tdhp->num_elements; ++j, bp += 4) {
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (! match_ind_indiv(j, op)))
                    continue;
            }
            printf("      Element %d descriptor:\n", j);
            enc_status_helper("        ", bp, tdhp->etype, false, op);
            got1 = true;
        }
    }
    if (op->ind_given && (! got1)) {
        printf("      >>> no match on --index=%d,%d", op->ind_th,
               op->ind_indiv);
        if (op->ind_indiv_last > op->ind_indiv)
            printf("-%d\n", op->ind_indiv_last);
        else
            printf("\n");
    }
    return;
truncated:
    pr2serr("    <<<arr: response too short>>>\n");
    return;
}

static char *
reserved_or_num(char * buff, int buff_len, int num, int reserve_num)
{
    if (num == reserve_num)
        strncpy(buff, "<res>", buff_len);
    else
        snprintf(buff, buff_len, "%d", num);
    if (buff_len > 0)
        buff[buff_len - 1] = '\0';
    return buff;
}

static void
threshold_helper(const char * header, const char * pad,
                 const uint8_t *tp, int etype,
                 const struct opts_t * op)
{
    char b[128];
    char b2[128];

    if (op->inner_hex) {
        if (header)
            printf("%s", header);
        printf("%s%02x %02x %02x %02x\n", pad, tp[0], tp[1], tp[2], tp[3]);
        return;
    }
    switch (etype) {
    case 0x4:  /*temperature */
        if (header)
            printf("%s", header);
        printf("%shigh critical=%s, high warning=%s\n", pad,
               reserved_or_num(b, 128, tp[0] - TEMPERAT_OFF, -TEMPERAT_OFF),
               reserved_or_num(b2, 128, tp[1] - TEMPERAT_OFF, -TEMPERAT_OFF));
        printf("%slow warning=%s, low critical=%s (in Celsius)\n", pad,
               reserved_or_num(b, 128, tp[2] - TEMPERAT_OFF, -TEMPERAT_OFF),
               reserved_or_num(b2, 128, tp[3] - TEMPERAT_OFF, -TEMPERAT_OFF));
        break;
    case 0xb:  /* UPS */
        if (header)
            printf("%s", header);
        if (0 == tp[2])
            strcpy(b, "<vendor>");
        else
            snprintf(b, sizeof(b), "%d", tp[2]);
        printf("%slow warning=%s, ", pad, b);
        if (0 == tp[3])
            strcpy(b, "<vendor>");
        else
            snprintf(b, sizeof(b), "%d", tp[3]);
        printf("low critical=%s (in minutes)\n", b);
        break;
    case 0x12: /* voltage */
        if (header)
            printf("%s", header);
#ifdef SG_LIB_MINGW
        printf("%shigh critical=%g %%, high warning=%g %% (above nominal "
               "voltage)\n", pad, 0.5 * tp[0], 0.5 * tp[1]);
        printf("%slow warning=%g %%, low critical=%g %% (below nominal "
               "voltage)\n", pad, 0.5 * tp[2], 0.5 * tp[3]);
#else
        printf("%shigh critical=%.1f %%, high warning=%.1f %% (above nominal "
               "voltage)\n", pad, 0.5 * tp[0], 0.5 * tp[1]);
        printf("%slow warning=%.1f %%, low critical=%.1f %% (below nominal "
               "voltage)\n", pad, 0.5 * tp[2], 0.5 * tp[3]);
#endif
        break;
    case 0x13: /* current */
        if (header)
            printf("%s", header);
#ifdef SG_LIB_MINGW
        printf("%shigh critical=%g %%, high warning=%g %%", pad,
               0.5 * tp[0], 0.5 * tp[1]);
#else
        printf("%shigh critical=%.1f %%, high warning=%.1f %%", pad,
               0.5 * tp[0], 0.5 * tp[1]);
#endif
        printf(" (above nominal current)\n");
        break;
    default:
        if (op->verbose) {
            if (header)
                printf("%s", header);
            printf("%s<< no thresholds for this element type >>\n", pad);
        }
        break;
    }
}

/* THRESHOLD_DPC [0x5] */
static void
threshold_sdg(const struct th_es_t * tesp, uint32_t ref_gen_code,
              const uint8_t * resp, int resp_len,
              const struct opts_t * op)
{
    int j, k;
    uint32_t gen_code;
    bool got1, match_ind_th;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const struct type_desc_hdr_t * tdhp = tesp->th_base;
    char b[64];

    printf("Threshold In diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    printf("  INVOP=%d\n", !!(resp[1] & 0x10));
    last_bp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  Threshold status descriptor list\n");
    bp = resp + 8;
    for (k = 0, got1 = false; k < tesp->num_ths; ++k, ++tdhp) {
        if ((bp + 3) > last_bp)
            goto truncated;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   etype_str(tdhp->etype, b, sizeof(b)), tdhp->se_id, k);
            threshold_helper("      Overall descriptor:\n", "        ", bp,
                             tdhp->etype, op);
            got1 = true;
        }
        for (bp += 4, j = 0; j < tdhp->num_elements; ++j, bp += 4) {
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (! match_ind_indiv(j, op)))
                    continue;
            }
            snprintf(b, sizeof(b), "      Element %d descriptor:\n", j);
            threshold_helper(b, "        ", bp, tdhp->etype, op);
            got1 = true;
        }
    }
    if (op->ind_given && (! got1)) {
        printf("      >>> no match on --index=%d,%d", op->ind_th,
               op->ind_indiv);
        if (op->ind_indiv_last > op->ind_indiv)
            printf("-%d\n", op->ind_indiv_last);
        else
            printf("\n");
    }
    return;
truncated:
    pr2serr("    <<<thresh: response too short>>>\n");
    return;
}

/* ELEM_DESC_DPC [0x7]
 * This page essentially contains names of overall and individual
 * elements. */
static void
element_desc_sdg(const struct th_es_t * tesp, uint32_t ref_gen_code,
                 const uint8_t * resp, int resp_len,
                 const struct opts_t * op)
{
    int j, k, desc_len;
    uint32_t gen_code;
    bool got1, match_ind_th;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const struct type_desc_hdr_t * tp;
    char b[64];

    printf("Element Descriptor In diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    last_bp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  element descriptor list (grouped by type):\n");
    bp = resp + 8;
    got1 = false;
    for (k = 0, tp = tesp->th_base; k < tesp->num_ths; ++k, ++tp) {
        if ((bp + 3) > last_bp)
            goto truncated;
        desc_len = sg_get_unaligned_be16(bp + 2) + 4;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   etype_str(tp->etype, b, sizeof(b)), tp->se_id, k);
            if (desc_len > 4)
                printf("      Overall descriptor: %.*s\n", desc_len - 4,
                       bp + 4);
            else
                printf("      Overall descriptor: <empty>\n");
            got1 = true;
        }
        for (bp += desc_len, j = 0; j < tp->num_elements;
             ++j, bp += desc_len) {
            desc_len = sg_get_unaligned_be16(bp + 2) + 4;
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (! match_ind_indiv(j, op)))
                    continue;
            }
            if (desc_len > 4)
                printf("      Element %d descriptor: %.*s\n", j,
                       desc_len - 4, bp + 4);
            else
                printf("      Element %d descriptor: <empty>\n", j);
            got1 = true;
        }
    }
    if (op->ind_given && (! got1)) {
        printf("      >>> no match on --index=%d,%d", op->ind_th,
               op->ind_indiv);
        if (op->ind_indiv_last > op->ind_indiv)
            printf("-%d\n", op->ind_indiv_last);
        else
            printf("\n");
    }
    return;
truncated:
    pr2serr("    <<<element: response too short>>>\n");
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
                    const struct th_es_t * tesp, const struct opts_t * op)
{
    int phys, j, m, n, desc_type, eiioe, eip_offset;
    bool nofilter = ! op->do_filter;
    bool eip, print_sas_addr, saddr_nz;
    const struct join_row_t * jrp;
    const uint8_t * aep;
    const uint8_t * ed_bp;
    const char * cp;
    char b[64];

    eip = !!(0x10 & ae_bp[0]);
    eiioe = eip ? (0x3 & ae_bp[2]) : 0;
    eip_offset = eip ? 2 : 0;
    desc_type = (ae_bp[3 + eip_offset] >> 6) & 0x3;
    if (op->verbose > 1)
        printf("%sdescriptor_type: %d\n", pad, desc_type);
    if (0 == desc_type) {
        phys = ae_bp[2 + eip_offset];
        printf("%snumber of phys: %d, not all phys: %d", pad, phys,
               ae_bp[3 + eip_offset] & 1);
        if (eip_offset)
            printf(", device slot number: %d", ae_bp[5 + eip_offset]);
        printf("\n");
        aep = ae_bp + 4 + eip_offset + eip_offset;
        for (j = 0; j < phys; ++j, aep += 28) {
            printf("%sphy index: %d\n", pad, j);
            printf("%s  SAS device type: %s\n", pad,
                   sas_device_type[(0x70 & aep[0]) >> 4]);
            if (nofilter || (0xe & aep[2]))
                printf("%s  initiator port for:%s%s%s\n", pad,
                       ((aep[2] & 8) ? " SSP" : ""),
                       ((aep[2] & 4) ? " STP" : ""),
                       ((aep[2] & 2) ? " SMP" : ""));
            if (nofilter || (0x8f & aep[3]))
                printf("%s  target port for:%s%s%s%s%s\n", pad,
                       ((aep[3] & 0x80) ? " SATA_port_selector" : ""),
                       ((aep[3] & 8) ? " SSP" : ""),
                       ((aep[3] & 4) ? " STP" : ""),
                       ((aep[3] & 2) ? " SMP" : ""),
                       ((aep[3] & 1) ? " SATA_device" : ""));
            print_sas_addr = false;
            saddr_nz = saddr_non_zero(aep + 4);
            if (nofilter || saddr_nz) {
                print_sas_addr = true;
                printf("%s  attached SAS address: 0x", pad);
                if (saddr_nz) {
                    for (m = 0; m < 8; ++m)
                        printf("%02x", aep[4 + m]);
                } else
                    printf("0");
            }
            saddr_nz = saddr_non_zero(aep + 12);
            if (nofilter || saddr_nz) {
                print_sas_addr = true;
                printf("\n%s  SAS address: 0x", pad);
                if (saddr_nz) {
                    for (m = 0; m < 8; ++m)
                        printf("%02x", aep[12 + m]);
                } else
                    printf("0");
            }
            if (print_sas_addr)
                printf("\n%s  phy identifier: 0x%x\n", pad, aep[20]);
        }
    } else if (1 == desc_type) {
        phys = ae_bp[2 + eip_offset];
        if (SAS_EXPANDER_ETC == etype) {
            printf("%snumber of phys: %d\n", pad, phys);
            printf("%sSAS address: 0x", pad);
            for (m = 0; m < 8; ++m)
                printf("%02x", ae_bp[6 + eip_offset + m]);
            printf("\n%sAttached connector; other_element pairs:\n", pad);
            aep = ae_bp + 14 + eip_offset;
            for (j = 0; j < phys; ++j, aep += 2) {
                printf("%s  [%d] ", pad, j);
                m = aep[0];     /* connector element index */
                if (0xff == m)
                    printf("no connector");
                else {
                    if (tesp->j_base) {
                        if (0 == eiioe)
                            jrp = find_join_row_cnst(tesp, m, FJ_SAS_CON);
                        else if ((1 == eiioe) || (3 == eiioe))
                            jrp = find_join_row_cnst(tesp, m, FJ_IOE);
                        else
                            jrp = find_join_row_cnst(tesp, m, FJ_EOE);
                        if ((NULL == jrp) || (NULL == jrp->enc_statp) ||
                            (SAS_CONNECTOR_ETC != jrp->etype))
                            printf("broken [conn_idx=%d]", m);
                        else {
                            enc_status_helper("", jrp->enc_statp, jrp->etype,
                                              true, op);
                            printf(" [%d]", jrp->indiv_i);
                        }
                    } else
                        printf("connector ei: %d", m);
                }
                m = aep[1];     /* other element index */
                if (0xff != m) {
                    printf("; ");
                    if (tesp->j_base) {

                        if (0 == eiioe)
                            jrp = find_join_row_cnst(tesp, m, FJ_AESS);
                        else if ((1 == eiioe) || (3 == eiioe))
                            jrp = find_join_row_cnst(tesp, m, FJ_IOE);
                        else
                            jrp = find_join_row_cnst(tesp, m, FJ_EOE);
                        if (NULL == jrp)
                            printf("broken [oth_elem_idx=%d]", m);
                        else if (jrp->elem_descp) {
                            cp = etype_str(jrp->etype, b, sizeof(b));
                            ed_bp = jrp->elem_descp;
                            n = sg_get_unaligned_be16(ed_bp + 2);
                            if (n > 0)
                                printf("%.*s [%d,%d] etype: %s", n,
                                       (const char *)(ed_bp + 4),
                                       jrp->th_i, jrp->indiv_i, cp);
                            else
                                printf("[%d,%d] etype: %s", jrp->th_i,
                                       jrp->indiv_i, cp);
                        } else {
                            cp = etype_str(jrp->etype, b, sizeof(b));
                            printf("[%d,%d] etype: %s", jrp->th_i,
                                   jrp->indiv_i, cp);
                        }
                    } else
                        printf("other ei: %d", m);
                }
                printf("\n");
            }
        } else if ((SCSI_TPORT_ETC == etype) ||
                   (SCSI_IPORT_ETC == etype) ||
                   (ENC_SCELECTR_ETC == etype)) {
            printf("%snumber of phys: %d\n", pad, phys);
            aep = ae_bp + 6 + eip_offset;
            for (j = 0; j < phys; ++j, aep += 12) {
                printf("%sphy index: %d\n", pad, j);
                printf("%s  phy_id: 0x%x\n", pad, aep[0]);
                printf("%s  ", pad);
                m = aep[2];     /* connector element index */
                if (0xff == m)
                    printf("no connector");
                else {
                    if (tesp->j_base) {
                        if (0 == eiioe)
                            jrp = find_join_row_cnst(tesp, m, FJ_SAS_CON);
                        else if ((1 == eiioe) || (3 == eiioe))
                            jrp = find_join_row_cnst(tesp, m, FJ_IOE);
                        else
                            jrp = find_join_row_cnst(tesp, m, FJ_EOE);
                        if ((NULL == jrp) || (NULL == jrp->enc_statp) ||
                            (SAS_CONNECTOR_ETC != jrp->etype))
                            printf("broken [conn_idx=%d]", m);
                        else {
                            enc_status_helper("", jrp->enc_statp, jrp->etype,
                                              true, op);
                            printf(" [%d]", jrp->indiv_i);
                        }
                    } else
                        printf("connector ei: %d", m);
                }
                m = aep[3];     /* other element index */
                if (0xff != m) {
                    printf("; ");
                    if (tesp->j_base) {
                        if (0 == eiioe)
                            jrp = find_join_row_cnst(tesp, m, FJ_AESS);
                        else if ((1 == eiioe) || (3 == eiioe))
                            jrp = find_join_row_cnst(tesp, m, FJ_IOE);
                        else
                            jrp = find_join_row_cnst(tesp, m, FJ_EOE);
                        if (NULL == jrp)
                            printf("broken [oth_elem_idx=%d]", m);
                        else if (jrp->elem_descp) {
                            cp = etype_str(jrp->etype, b, sizeof(b));
                            ed_bp = jrp->elem_descp;
                            n = sg_get_unaligned_be16(ed_bp + 2);
                            if (n > 0)
                                printf("%.*s [%d,%d] etype: %s", n,
                                       (const char *)(ed_bp + 4),
                                       jrp->th_i, jrp->indiv_i, cp);
                            else
                                printf("[%d,%d] etype: %s", jrp->th_i,
                                       jrp->indiv_i, cp);
                        } else {
                            cp = etype_str(jrp->etype, b, sizeof(b));
                            printf("[%d,%d] etype: %s", jrp->th_i,
                                   jrp->indiv_i, cp);
                        }
                    } else
                        printf("other ei: %d", m);
                }
                printf("\n");
                printf("%s  SAS address: 0x", pad);
                for (m = 0; m < 8; ++m)
                    printf("%02x", aep[4 + m]);
                printf("\n");
            }   /* end_for: loop over phys in SCSI initiator, target */
        } else
            printf("%sunrecognised element type [%d] for desc_type "
                   "1\n", pad, etype);
    } else
        printf("%sunrecognised descriptor type [%d]\n", pad, desc_type);
}

static void
additional_elem_helper(const char * pad, const uint8_t * ae_bp,
                       int len, int etype, const struct th_es_t * tesp,
                       const struct opts_t * op)
{
    int ports, phys, j, m, eip_offset, pcie_pt;
    bool cid_valid, psn_valid, bdf_valid, eip;
    uint16_t pcie_vid;
    const uint8_t * aep;
    char b[64];

    if (op->inner_hex) {
        for (j = 0; j < len; ++j) {
            if (0 == (j % 16))
                printf("%s%s", ((0 == j) ? "" : "\n"), pad);
            printf("%02x ", ae_bp[j]);
        }
        printf("\n");
        return;
    }
    eip = !!(0x10 & ae_bp[0]);
    eip_offset = eip ? 2 : 0;
    switch (0xf & ae_bp[0]) {     /* switch on protocol identifier */
    case TPROTO_FCP:
        printf("%sTransport protocol: FCP\n", pad);
        if (len < (12 + eip_offset))
            break;
        ports = ae_bp[2 + eip_offset];
        printf("%snumber of ports: %d\n", pad, ports);
        printf("%snode_name: ", pad);
        for (m = 0; m < 8; ++m)
            printf("%02x", ae_bp[6 + eip_offset + m]);
        if (eip_offset)
            printf(", device slot number: %d", ae_bp[5 + eip_offset]);
        printf("\n");
        aep = ae_bp + 14 + eip_offset;
        for (j = 0; j < ports; ++j, aep += 16) {
            printf("%s  port index: %d, port loop position: %d, port "
                   "bypass reason: 0x%x\n", pad, j, aep[0], aep[1]);
            printf("%srequested hard address: %d, n_port identifier: "
                   "%02x%02x%02x\n", pad, aep[4], aep[5],
                   aep[6], aep[7]);
            printf("%s  n_port name: ", pad);
            for (m = 0; m < 8; ++m)
                printf("%02x", aep[8 + m]);
            printf("\n");
        }
        break;
    case TPROTO_SAS:
        printf("%sTransport protocol: SAS\n", pad);
        if (len < (4 + eip_offset))
            break;
        additional_elem_sas(pad, ae_bp, etype, tesp, op);
        break;
    case TPROTO_PCIE: /* added in ses3r08; contains little endian fields */
        printf("%sTransport protocol: PCIe\n", pad);
        if (0 == eip_offset) {
            printf("%sfor this protocol EIP must be set (it isn't)\n", pad);
            break;
        }
        if (len < 6)
            break;
        pcie_pt = (ae_bp[5] >> 5) & 0x7;
        if (TPROTO_PCIE_PS_NVME == pcie_pt)
            printf("%sPCIe protocol type: NVMe\n", pad);
        else {  /* no others currently defined */
            printf("%sTransport protocol: PCIe subprotocol=0x%x not "
                   "decoded\n", pad, pcie_pt);
            if (op->verbose)
                hex2stdout(ae_bp, len, 0);
            break;
        }
        phys = ae_bp[4];
        printf("%snumber of ports: %d, not all ports: %d", pad, phys,
               ae_bp[5] & 1);
        printf(", device slot number: %d\n", ae_bp[7]);

        pcie_vid = sg_get_unaligned_le16(ae_bp + 10);   /* N.B. LE */
        printf("%sPCIe vendor id: 0x%" PRIx16 "%s\n", pad, pcie_vid,
               (0xffff == pcie_vid) ? " (not reported)" : "");
        printf("%sserial number: %.20s\n", pad, ae_bp + 12);
        printf("%smodel number: %.40s\n", pad, ae_bp + 32);
        aep = ae_bp + 72;
        for (j = 0; j < phys; ++j, aep += 8) {
            printf("%sport index: %d\n", pad, j);
            psn_valid = !!(0x4 & aep[0]);
            bdf_valid = !!(0x2 & aep[0]);
            cid_valid = !!(0x1 & aep[0]);
            printf("%s  PSN_VALID=%d, BDF_VALID=%d, CID_VALID=%d\n", pad,
                   (int)psn_valid, (int)bdf_valid, (int)cid_valid);
            if (cid_valid)      /* N.B. little endian */
                printf("%s  controller id: 0x%" PRIx16 "\n", pad,
                       sg_get_unaligned_le16(aep + 1)); /* N.B. LEndian */
            if (bdf_valid)
                printf("%s  bus number: 0x%x, device number: 0x%x, "
                       "function number: 0x%x\n", pad, aep[4],
                       (aep[5] >> 3) & 0x1f, 0x7 & aep[5]);
            if (psn_valid)      /* little endian, top 3 bits assumed zero */
                printf("%s  physical slot number: 0x%" PRIx16 "\n", pad,
                       0x1fff & sg_get_unaligned_le16(aep + 6)); /* N.B. LE */
        }
        break;
    default:
        printf("%sTransport protocol: %s not decoded\n", pad,
               sg_get_trans_proto_str((0xf & ae_bp[0]), sizeof(b), b));
        if (op->verbose)
            hex2stdout(ae_bp, len, 0);
        break;
    }
}

/* ADD_ELEM_STATUS_DPC [0xa] Additional Element Status dpage
 * Previously called "Device element status descriptor". Changed "device"
 * to "additional" to allow for SAS expander and SATA devices */
static void
additional_elem_sdg(const struct th_es_t * tesp, uint32_t ref_gen_code,
                    const uint8_t * resp, int resp_len,
                    const struct opts_t * op)
{
    int j, k, desc_len, etype, el_num, ind, elem_count, ei, eiioe, num_elems;
    int fake_ei;
    uint32_t gen_code;
    bool eip, invalid, match_ind_th, my_eiioe_force, skip;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const struct type_desc_hdr_t * tp = tesp->th_base;
    char b[64];

    printf("Additional element status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    last_bp = resp + resp_len - 1;
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  additional element status descriptor list\n");
    bp = resp + 8;
    my_eiioe_force = op->eiioe_force;
    for (k = 0, elem_count = 0; k < tesp->num_ths; ++k, ++tp) {
        fake_ei = -1;
        etype = tp->etype;
        num_elems = tp->num_elements;
        if (! is_et_used_by_aes(etype)) {
            elem_count += num_elems;
            continue;   /* skip if not element type of interest */
        }
        if ((bp + 1) > last_bp)
            goto truncated;

        eip = !! (bp[0] & 0x10);
        if (eip) { /* do bounds check on the element index */
            ei = bp[3];
            skip = false;
            if ((0 == k) && op->eiioe_auto && (1 == ei)) {
                /* heuristic: if first AES descriptor has EIP set and its
                 * element index equal to 1, then act as if the EIIOE field
                 * is one. */
                my_eiioe_force = true;
            }
            eiioe = (0x3 & bp[2]);
            if (my_eiioe_force && (0 == eiioe))
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
                            "elem_count=%d, num_elems=%d\n", etype, k,
                            ei, eiioe, elem_count, num_elems);
                continue;
            }
        }
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   etype_str(etype, b, sizeof(b)), tp->se_id, k);
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
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (! match_ind_indiv(el_num, op)))
                    continue;
            }
            if (eip)
                printf("      Element index: %d  eiioe=%d%s\n", ind, eiioe,
                       (((0 != eiioe) && my_eiioe_force) ?
                        " but overridden" : ""));
            else
                printf("      Element %d descriptor\n", ind);
            if (invalid && (! op->inner_hex))
                printf("        flagged as invalid (no further "
                       "information)\n");
            else
                additional_elem_helper("        ", bp, desc_len, etype,
                                       tesp, op);
        }
        elem_count += tp->num_elements;
    }           /* end_for: loop over type descriptor headers */
    return;
truncated:
    pr2serr("    <<<additional: response too short>>>\n");
    return;
}

/* SUBENC_HELP_TEXT_DPC [0xb] */
static void
subenc_help_sdg(const uint8_t * resp, int resp_len)
{
    int k, el, num_subs;
    uint32_t gen_code;
    const uint8_t * bp;
    const uint8_t * last_bp;

    printf("Subenclosure help text diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_bp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n", num_subs - 1);
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    bp = resp + 8;
    for (k = 0; k < num_subs; ++k, bp += el) {
        if ((bp + 3) > last_bp)
            goto truncated;
        el = sg_get_unaligned_be16(bp + 2) + 4;
        printf("   subenclosure identifier: %d\n", bp[1]);
        if (el > 4)
            printf("    %.*s\n", el - 4, bp + 4);
        else
            printf("    <empty>\n");
    }
    return;
truncated:
    pr2serr("    <<<subenc: response too short>>>\n");
    return;
}

/* SUBENC_STRING_DPC [0xc] */
static void
subenc_string_sdg(const uint8_t * resp, int resp_len)
{
    int k, el, num_subs;
    uint32_t gen_code;
    const uint8_t * bp;
    const uint8_t * last_bp;

    printf("Subenclosure string in diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_bp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n", num_subs - 1);
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    bp = resp + 8;
    for (k = 0; k < num_subs; ++k, bp += el) {
        if ((bp + 3) > last_bp)
            goto truncated;
        el = sg_get_unaligned_be16(bp + 2) + 4;
        printf("   subenclosure identifier: %d\n", bp[1]);
        if (el > 4) {
            char bb[1024];

            hex2str(bp + 40, el - 40, "    ", 0, sizeof(bb), bb);
            printf("%s\n", bb);
        } else
            printf("    <empty>\n");
    }
    return;
truncated:
    pr2serr("    <<<subence str: response too short>>>\n");
    return;
}

/* SUBENC_NICKNAME_DPC [0xf] */
static void
subenc_nickname_sdg(const uint8_t * resp, int resp_len)
{
    int k, el, num_subs;
    uint32_t gen_code;
    const uint8_t * bp;
    const uint8_t * last_bp;

    printf("Subenclosure nickname status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_bp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n", num_subs - 1);
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    bp = resp + 8;
    el = 40;
    for (k = 0; k < num_subs; ++k, bp += el) {
        if ((bp + el - 1) > last_bp)
            goto truncated;
        printf("   subenclosure identifier: %d\n", bp[1]);
        printf("   nickname status: 0x%x\n", bp[2]);
        printf("   nickname additional status: 0x%x\n", bp[3]);
        printf("   nickname language code: %.2s\n", bp + 6);
        printf("   nickname: %.*s\n", 32, bp + 8);
    }
    return;
truncated:
    pr2serr("    <<<subence str: response too short>>>\n");
    return;
}

/* SUPPORTED_SES_DPC [0xd] */
static void
supported_pages_sdg(const char * leadin, const uint8_t * resp,
                    int resp_len)
{
    int k, code, prev;
    bool got1;
    const char * cp;
    const struct diag_page_abbrev * ap;

    printf("%s:\n", leadin);
    for (k = 0, prev = 0; k < (resp_len - 4); ++k, prev = code) {
        code = resp[k + 4];
        if (code < prev)
            break;      /* assume to be padding at end */
        cp = find_diag_page_desc(code);
        if (cp) {
            printf("  %s [", cp);
            for (ap = dp_abbrev, got1 = false; ap->abbrev; ++ap) {
                if (ap->page_code == code) {
                    printf("%s%s", (got1 ? "," : ""), ap->abbrev);
                    got1 = true;
                }
            }
            printf("] [0x%x]\n", code);
        } else
            printf("  <unknown> [0x%x]\n", code);
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

/* DOWNLOAD_MICROCODE_DPC [0xe] */
static void
download_code_sdg(const uint8_t * resp, int resp_len)
{
    int k, num_subs;
    uint32_t gen_code;
    const uint8_t * bp;
    const uint8_t * last_bp;
    const char * cp;

    printf("Download microcode status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_bp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n", num_subs - 1);
    gen_code = sg_get_unaligned_be32(resp + 4);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    bp = resp + 8;
    for (k = 0; k < num_subs; ++k, bp += 16) {
        if ((bp + 3) > last_bp)
            goto truncated;
        cp = (0 == bp[1]) ? " [primary]" : "";
        printf("   subenclosure identifier: %d%s\n", bp[1], cp);
        cp = get_mc_status(bp[2]);
        if (strlen(cp) > 0) {
            printf("     download microcode status: %s [0x%x]\n", cp, bp[2]);
            printf("     download microcode additional status: 0x%x\n",
                   bp[3]);
        } else
            printf("     download microcode status: 0x%x [additional "
                   "status: 0x%x]\n", bp[2], bp[3]);
        printf("     download microcode maximum size: %d bytes\n",
               sg_get_unaligned_be32(bp + 4));
        printf("     download microcode expected buffer id: 0x%x\n", bp[11]);
        printf("     download microcode expected buffer id offset: %d\n",
               sg_get_unaligned_be32(bp + 12));
    }
    return;
truncated:
    pr2serr("    <<<download: response too short>>>\n");
    return;
}

/* Reads hex data from command line, stdin or a file when in_hex is true.
 * Reads binary from stdin or file when in_hex is false. Returns 0 on
 * success, 1 otherwise. If inp is a file and may_have_at, then the
 * first character is skipped to get filename (since it should be '@'). */
static int
read_hex(const char * inp, uint8_t * arr, int mx_arr_len, int * arr_len,
         bool in_hex, bool may_have_at, int vb)
{
    bool has_stdin, split_line;
    int in_len, k, j, m, off, off_fn;
    unsigned int h;
    const char * lcp;
    char * cp;
    char * c2p;
    char line[512];
    char carry_over[4];
    FILE * fp = NULL;

    if ((NULL == inp) || (NULL == arr) || (NULL == arr_len))
        return 1;
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
                pr2serr("unable to open binary file %s: %s\n", inp + off_fn,
                         safe_strerror(errno));
                return 1;
            }
        }
        k = read(fd, arr, mx_arr_len);
        if (k <= 0) {
            if (0 == k)
                pr2serr("read 0 bytes from binary file %s\n", inp + off_fn);
            else
                pr2serr("read from binary file %s: %s\n", inp + off_fn,
                        safe_strerror(errno));
            if (! has_stdin)
                close(fd);
            return 1;
        }
        if ((0 == fstat(fd, &a_stat)) && S_ISFIFO(a_stat.st_mode)) {
            /* pipe; keep reading till error or 0 read */
            while (k < mx_arr_len) {
                m = read(fd, arr + k, mx_arr_len - k);
                if (0 == m)
                   break;
                if (m < 0) {
                    pr2serr("read from binary pipe %s: %s\n", inp + off_fn,
                            safe_strerror(errno));
                    if (! has_stdin)
                        close(fd);
                    return 1;
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
                pr2serr("%s: unable to open file: %s\n", __func__,
                        inp + off_fn);
                return 1;
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
                if (isxdigit(line[0])) {
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
    return 1;
}

static int
process_status_dpage(struct sg_pt_base * ptvp, int page_code, uint8_t * resp,
                     int resp_len, struct opts_t * op)
{
    int j, num_ths;
    int ret = 0;
    uint32_t ref_gen_code;
    const char * cp;
    struct enclosure_info primary_info;
    struct th_es_t tes;
    struct th_es_t * tesp;
    char bb[120];

    tesp = &tes;
    memset(tesp, 0, sizeof(tes));
    if ((cp = find_in_diag_page_desc(page_code)))
        snprintf(bb, sizeof(bb), "%s dpage", cp);
    else
        snprintf(bb, sizeof(bb), "dpage 0x%x", page_code);
    cp = bb;
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
                    printf("\n# %s:\n", cp);
                else
                    printf("\n# %s [0x%x]:\n", cp, page_code);
            }
            hex2stdout(resp, resp_len, -1);
         } else {
            printf("# Response in hex for %s:\n", cp);
            hex2stdout(resp, resp_len, (2 == op->do_hex));
        }
        goto fini;
    }

    memset(&primary_info, 0, sizeof(primary_info));
    switch (page_code) {
    case SUPPORTED_DPC:
        supported_pages_sdg("Supported diagnostic pages", resp, resp_len);
        break;
    case CONFIGURATION_DPC:
        configuration_sdg(resp, resp_len);
        break;
    case ENC_STATUS_DPC:
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                          MX_ELEM_HDR, &ref_gen_code,
                                          &primary_info, op);
        if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if ((1 == type_desc_hdr_count) && primary_info.have_info) {
            printf("  Primary enclosure logical identifier (hex): ");
            for (j = 0; j < 8; ++j)
                printf("%02x", primary_info.enc_log_id[j]);
            printf("\n");
        }
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        enc_status_dp(tesp, ref_gen_code, resp, resp_len, op);
        break;
    case ARRAY_STATUS_DPC:
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                          MX_ELEM_HDR, &ref_gen_code,
                                          &primary_info, op);
        if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if ((1 == type_desc_hdr_count) && primary_info.have_info) {
            printf("  Primary enclosure logical identifier (hex): ");
            for (j = 0; j < 8; ++j)
                printf("%02x", primary_info.enc_log_id[j]);
            printf("\n");
        }
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        array_status_dp(tesp, ref_gen_code, resp, resp_len, op);
        break;
    case HELP_TEXT_DPC:
        printf("Help text diagnostic page (for primary "
               "subenclosure):\n");
        if (resp_len > 4)
            printf("  %.*s\n", resp_len - 4, resp + 4);
        else
            printf("  <empty>\n");
        break;
    case STRING_DPC:
        printf("String In diagnostic page (for primary "
               "subenclosure):\n");
        if (resp_len > 4)
            hex2stdout(resp + 4, resp_len - 4, 0);
        else
            printf("  <empty>\n");
        break;
    case THRESHOLD_DPC:
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                          MX_ELEM_HDR, &ref_gen_code,
                                          &primary_info, op);
        if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if ((1 == type_desc_hdr_count) && primary_info.have_info) {
            printf("  Primary enclosure logical identifier (hex): ");
            for (j = 0; j < 8; ++j)
                printf("%02x", primary_info.enc_log_id[j]);
            printf("\n");
        }
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        threshold_sdg(tesp, ref_gen_code, resp, resp_len, op);
        break;
    case ELEM_DESC_DPC:
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                              MX_ELEM_HDR, &ref_gen_code,
                                              &primary_info, op);
            if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if ((1 == type_desc_hdr_count) && primary_info.have_info) {
            printf("  Primary enclosure logical identifier (hex): ");
            for (j = 0; j < 8; ++j)
                printf("%02x", primary_info.enc_log_id[j]);
            printf("\n");
        }
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        element_desc_sdg(tesp, ref_gen_code, resp, resp_len, op);
        break;
    case SHORT_ENC_STATUS_DPC:
        printf("Short enclosure status diagnostic page, "
               "status=0x%x\n", resp[1]);
        break;
    case ENC_BUSY_DPC:
        printf("Enclosure Busy diagnostic page, "
               "busy=%d [vendor specific=0x%x]\n",
               resp[1] & 1, (resp[1] >> 1) & 0xff);
        break;
    case ADD_ELEM_STATUS_DPC:
        num_ths = build_type_desc_hdr_arr(ptvp, type_desc_hdr_arr,
                                          MX_ELEM_HDR, &ref_gen_code,
                                          &primary_info, op);
        if (num_ths < 0) {
            ret = num_ths;
            goto fini;
        }
        if (primary_info.have_info) {
            printf("  Primary enclosure logical identifier (hex): ");
            for (j = 0; j < 8; ++j)
                printf("%02x", primary_info.enc_log_id[j]);
            printf("\n");
        }
        tesp->th_base = type_desc_hdr_arr;
        tesp->num_ths = num_ths;
        additional_elem_sdg(tesp, ref_gen_code, resp, resp_len, op);
        break;
    case SUBENC_HELP_TEXT_DPC:
        subenc_help_sdg(resp, resp_len);
        break;
    case SUBENC_STRING_DPC:
        subenc_string_sdg(resp, resp_len);
        break;
    case SUPPORTED_SES_DPC:
        supported_pages_sdg("Supported SES diagnostic pages", resp,
                            resp_len);
        break;
    case DOWNLOAD_MICROCODE_DPC:
        download_code_sdg(resp, resp_len);
        break;
    case SUBENC_NICKNAME_DPC:
        subenc_nickname_sdg(resp, resp_len);
        break;
    default:
        printf("Cannot decode response from diagnostic page: %s\n", cp);
        hex2stdout(resp, resp_len, 0);
    }

fini:
    return ret;
}

/* Display "status" page or pages (if op->page_code==0xff) . data-in from
 * SES device or user provided (with --data= option). Return 0 for success */
static int
process_status_page_s(struct sg_pt_base * ptvp, struct opts_t * op)
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
    if (ALL_DPC == page_code) {
        int k, n;
        uint8_t pc, prev;
        uint8_t supp_dpg_arr[256];
        const int s_arr_sz = sizeof(supp_dpg_arr);

        memset(supp_dpg_arr, 0, s_arr_sz);
        ret = do_rec_diag(ptvp, SUPPORTED_DPC, resp, op->maxlen, op,
                          &resp_len);
        if (ret)        /* SUPPORTED_DPC failed so try SUPPORTED_SES_DPC */
            ret = do_rec_diag(ptvp, SUPPORTED_SES_DPC, resp, op->maxlen, op,
                              &resp_len);
        if (ret)
            goto fini;
        for (n = 0, pc = 0; (n < s_arr_sz) && (n < (resp_len - 4)); ++n) {
            prev = pc;
            pc = resp[4 + n];
            if (prev > pc) {
                if (pc) {       /* could be zero pad at end which is ok */
                    pr2serr("%s: Supported (SES) dpage seems corrupt, "
                            "should ascend\n", __func__);
                    ret = SG_LIB_CAT_OTHER;
                    goto fini;
                }
                break;
            }
            if (pc > 0x2f)
                break;
            supp_dpg_arr[n] = pc;
        }
        for (k = 0; k < n; ++k) {
            page_code = supp_dpg_arr[k];
            ret = do_rec_diag(ptvp, page_code, resp, op->maxlen, op,
                              &resp_len);
            if (ret)
                goto fini;
            ret = process_status_dpage(ptvp, page_code, resp, resp_len, op);
        }
    } else {    /* asking for a specific page code */
        ret = do_rec_diag(ptvp, page_code, resp, op->maxlen, op, &resp_len);
        if (ret)
            goto fini;
        ret = process_status_dpage(ptvp, page_code, resp, resp_len, op);
    }

fini:
    if (free_resp)
        free(free_resp);
    return ret;
}

static void
devslotnum_and_sasaddr(struct join_row_t * jrp, const uint8_t * ae_bp)
{
    int m;

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
                    if (op->verbose || op->warn)
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
                        if (op->warn || op->verbose) {
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
                                (op->warn || op->verbose))
                                pr2serr("warning2: dropping AES+%s [length="
                                        "%d, oi=%d, ei=%d, aes_i=%d]\n",
                                        offset_str(ae_bp - add_elem_rsp, hex,
                                                   b, blen),
                                        ae_bp[1] + 2, k, ei, aes_i);
                        } else if (op->warn || op->verbose) {
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
                                "element_type=0x%x\n", __func__, k, ei,
                                jr2p->etype);
                        return broken_ei;
                    }
                    devslotnum_and_sasaddr(jr2p, ae_bp);
                    if (jr2p->ae_statp) {
                        if (op->warn || op->verbose) {
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
join_array_display(struct th_es_t * tesp, struct opts_t * op)
{
    bool got1, need_aes;
    int k, j, blen, desc_len, dn_len;
    const uint8_t * ae_bp;
    const char * cp;
    const uint8_t * ed_bp;
    struct join_row_t * jrp;
    uint8_t * t_bp;
    char b[64];

    blen = sizeof(b);
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
                printf("%.*s [%d,%d]  Element type: %s\n", desc_len - 4,
                       (const char *)(ed_bp + 4), jrp->th_i,
                       jrp->indiv_i, cp);
            else
                printf("[%d,%d]  Element type: %s\n", jrp->th_i,
                       jrp->indiv_i, cp);
        } else
            printf("[%d,%d]  Element type: %s\n", jrp->th_i,
                   jrp->indiv_i, cp);
        printf("  Enclosure Status:\n");
        enc_status_helper("    ", jrp->enc_statp, jrp->etype, false, op);
        if (jrp->ae_statp) {
            printf("  Additional Element Status:\n");
            ae_bp = jrp->ae_statp;
            desc_len = ae_bp[1] + 2;
            additional_elem_helper("    ",  ae_bp, desc_len, jrp->etype,
                                   tesp, op);
        }
        if (jrp->thresh_inp) {
            t_bp = jrp->thresh_inp;
            threshold_helper("  Threshold In:\n", "    ", t_bp, jrp->etype,
                             op);
        }
    }
    if (! got1) {
        if (op->ind_given) {
            printf("      >>> no match on --index=%d,%d", op->ind_th,
                   op->ind_indiv);
            if (op->ind_indiv_last > op->ind_indiv)
                printf("-%d\n", op->ind_indiv_last);
            else
                printf("\n");
        } else if (op->desc_name)
            printf("      >>> no match on --descriptor=%s\n", op->desc_name);
        else if (op->dev_slot_num >= 0)
            printf("      >>> no match on --dev-slot-name=%d\n",
                   op->dev_slot_num);
        else if (saddr_non_zero(op->sas_addr)) {
            printf("      >>> no match on --sas-addr=0x");
            for (j = 0; j < 8; ++j)
                printf("%02x", op->sas_addr[j]);
            printf("\n");
        }
    }
}

/* This is for debugging, output to stderr */
static void
join_array_dump(struct th_es_t * tesp, int broken_ei, struct opts_t * op)
{
    int k, j, blen, hex;
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
        if (op->do_join > 2) {
            pr2serr(" sa=0x");
            if (saddr_non_zero(jrp->sas_addr)) {
                for (j = 0; j < 8; ++j)
                    pr2serr("%02x", jrp->sas_addr[j]);
            } else
                pr2serr("0");
        }
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
    bool et_used_by_aes;
    int k, j, eoe, ei4aess;
    struct join_row_t * jrp;
    const struct type_desc_hdr_t * tdhp;

    jrp = tesp->j_base;
    tdhp = tesp->th_base;
    for (k = 0, eoe = 0, ei4aess = 0; k < tesp->num_ths; ++k, ++tdhp) {
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
            ++k;
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
join_work(struct sg_pt_base * ptvp, struct opts_t * op, bool display)
{
    bool broken_ei;
    int j, res, num_ths, mlen;
    uint32_t ref_gen_code, gen_code;
    const uint8_t * ae_bp;
    const uint8_t * ae_last_bp;
    const char * enc_state_changed = "  <<state of enclosure changed, "
                                     "please try again>>\n";
    uint8_t * es_bp;
    const uint8_t * ed_bp;
    uint8_t * t_bp;
    struct th_es_t * tesp;
    struct enclosure_info primary_info;
    struct th_es_t tes;

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
        printf("  Primary enclosure logical identifier (hex): ");
        for (j = 0; j < 8; ++j)
            printf("%02x", primary_info.enc_log_id[j]);
        printf("\n");
    }
    mlen = enc_stat_rsp_sz;
    if (mlen > op->maxlen)
        mlen = op->maxlen;
    res = do_rec_diag(ptvp, ENC_STATUS_DPC, enc_stat_rsp, mlen, op,
                      &enc_stat_rsp_len);
    if (res)
        return res;
    if (enc_stat_rsp_len < 8) {
        pr2serr("Enclosure Status response too short\n");
        return -1;
    }
    gen_code = sg_get_unaligned_be32(enc_stat_rsp + 4);
    if (ref_gen_code != gen_code) {
        pr2serr("%s", enc_state_changed);
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
            pr2serr("Element Descriptor response too short\n");
            return -1;
        }
        gen_code = sg_get_unaligned_be32(elem_desc_rsp + 4);
        if (ref_gen_code != gen_code) {
            pr2serr("%s", enc_state_changed);
            return -1;
        }
        ed_bp = elem_desc_rsp + 8;
        /* ed_last_bp = elem_desc_rsp + elem_desc_rsp_len - 1; */
    } else {
        elem_desc_rsp_len = 0;
        ed_bp = NULL;
        res = 0;
        if (op->verbose)
            pr2serr("  Element Descriptor page not available\n");
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
                pr2serr("Additional Element Status response too short\n");
                return -1;
            }
            gen_code = sg_get_unaligned_be32(add_elem_rsp + 4);
            if (ref_gen_code != gen_code) {
                pr2serr("%s", enc_state_changed);
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
                pr2serr("  Additional Element Status page not available\n");
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
                pr2serr("Threshold In response too short\n");
                return -1;
            }
            gen_code = sg_get_unaligned_be32(threshold_rsp + 4);
            if (ref_gen_code != gen_code) {
                pr2serr("%s", enc_state_changed);
                return -1;
            }
            t_bp = threshold_rsp + 8;
            /* t_last_bp = threshold_rsp + threshold_rsp_len - 1; */
        } else {
            threshold_rsp_len = 0;
            t_bp = NULL;
            res = 0;
            if (op->verbose)
                pr2serr("  Threshold In page not available\n");
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
    if (display)      /* probably wanted join_arr[] built only */
        join_array_display(tesp, op);

    return res;

}

/* Returns 1 if strings equal (same length, characters same or only differ
 * by case), else returns 0. Assumes 7 bit ASCII (English alphabet). */
static int
strcase_eq(const char * s1p, const char * s2p)
{
    int c1, c2;

    do {
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
    int ret, len, s_byte, s_bit, n_bits, k;
    uint64_t ui;
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
        ui = sg_get_big_endian(jrp->enc_statp + s_byte, s_bit, n_bits);
        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {    /* --set or --clear */
        if ((! op->mask_ign) && (jrp->etype < NUM_ETC)) {
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
            ret = do_senddiag(ptvp, enc_stat_rsp, len, ! op->quiet,
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
    int ret, len, s_byte, s_bit, n_bits;
    uint64_t ui;
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
        ui = sg_get_big_endian(jrp->thresh_inp + s_byte, s_bit, n_bits);
        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {
        sg_set_big_endian((uint64_t)tavp->val,
                          jrp->thresh_inp + s_byte, s_bit, n_bits);
        if (op->byte1_given)
            threshold_rsp[1] = op->byte1;
        len = sg_get_unaligned_be16(threshold_rsp + 2) + 4;
        if (last) {
            ret = do_senddiag(ptvp, threshold_rsp, len, ! op->quiet,
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
    uint64_t ui;
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
        ui = sg_get_big_endian(jrp->ae_statp + s_byte, s_bit, n_bits);
        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {
        pr2serr("--clear and --set not available for Additional Element "
                "Status page\n");
        return -1;
    }
    return 0;
}

/* Do --clear, --get or --set .
 * Returns 0 for success, any other return value is an error. */
static int
ses_cgs(struct sg_pt_base * ptvp, const struct tuple_acronym_val * tavp,
        struct opts_t * op, bool last)
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
        ret = join_work(ptvp, op, false);
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
    const int control_plen = 0x24;

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
        pr2serr("%s: generation code from status page: %" PRIu32 "\n",
                __func__, gc);
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

    printf("Diagnostic pages, followed by abbreviation(s) then page code:\n");
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
    const struct element_type_t * etp;
    const struct acronym2tuple * ap;
    char b[64];
    char a[160];
    const char * cp;

    if (op->dev_name)
        printf(">>> DEVICE %s ignored when --%s option given.\n",
               op->dev_name, (op->do_list ? "list" : "enumerate"));
    num = op->enumerate + (int)op->do_list;
    if (num < 2) {
        enumerate_diag_pages();
        printf("\nSES element type names, followed by abbreviation and "
               "element type code:\n");
        for (etp = element_type_arr; etp->desc; ++etp)
            printf("    %s  [%s] [0x%x]\n", etp->desc, etp->abbrev,
                   etp->elem_type_code);
    } else {
        char bb[64];
        bool given_et = false;

        /* command line has multiple --enumerate and/or --list options */
        printf("--clear, --get, --set acronyms for Enclosure Status/Control "
               "['es' or 'ec'] page");
        if (op->ind_given && op->ind_etp &&
            (cp = etype_str(op->ind_etp->elem_type_code, bb, sizeof(bb)))) {
            printf("\n(element type: %s)", bb);
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
        printf("\n--get acronyms for Additional Element Status ['aes'] page "
               "(SAS EIP=1):\n");
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
    int k, d_len, res, resid, vb;
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
    struct tuple_acronym_val tav_arr[CGS_CL_ARR_MAX_SZ];
    char buff[128];
    char b[128];

    op = &opts;
    memset(op, 0, sizeof(*op));
    op->dev_slot_num = -1;
    op->ind_indiv_last = -1;
    op->maxlen = MX_ALLOC_LEN;
    res = parse_cmd_line(op, argc, argv);
    vb = op->verbose;
    if (res) {
        ret = SG_LIB_SYNTAX_ERROR;
        goto early_out;
    }
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
                    "Additional Element Status pages\n");
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

#if 0
    pr2serr("Debug dump of input parameters:\n");
    pr2serr("  index option given: %d, ind_th=%d, ind_indiv=%d, "
            "ind_indiv_last=%d\n", op->ind_given, op->ind_th,
            op->ind_indiv, op->ind_indiv_last);
    pr2serr("  num_cgs=%d, contents:\n", op->num_cgs);
    for (k = 0, tavp = tav_arr, cgs_clp = op->cgs_cl_arr;
         k < op->num_cgs; ++k, ++tavp, ++cgs_clp) {
        pr2serr("  k=%d, cgs_sel=%d, last_cs=%d, tavp=%p str: %s\n",
                k, (int)cgs_clp->cgs_sel, (int)cgs_clp->last_cs, tavp,
                cgs_clp->cgs_str);
    }
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
            if ((ret = sg_ll_inquiry_pt(ptvp, false, 0, enc_stat_rsp, 36,
                                        0, &resid, ! op->quiet, vb))) {
                pr2serr("%s doesn't respond to a SCSI INQUIRY\n",
                        op->dev_name);
                goto err_out;
            } else {
                if (resid > 0)
                    pr2serr("Short INQUIRY response, not looking good\n");
                printf("  %.8s  %.16s  %.4s\n", enc_stat_rsp + 8,
                       enc_stat_rsp + 16, enc_stat_rsp + 32);
                pd_type = 0x1f & enc_stat_rsp[0];
                cp = sg_get_pdt_str(pd_type, sizeof(buff), buff);
                if (0xd == pd_type) {
                    if (vb)
                        printf("    enclosure services device\n");
                } else if (0x40 & enc_stat_rsp[6])
                    printf("    %s device has EncServ bit set\n", cp);
                else {
                    if (0 != memcmp("NVMe", enc_stat_rsp + 8, 4))
                        printf("    %s device (not an enclosure)\n", cp);
                }
            }
            clear_scsi_pt_obj(ptvp);
            /* finished using enc_stat_rsp so clear back to zero */
            memset(enc_stat_rsp, 0, enc_stat_rsp_sz);
        }
    } else if (op->do_control) {
        pr2serr("Cannot do SCSI Send diagnostic command without a DEVICE\n");
        return SG_LIB_SYNTAX_ERROR;
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
        memset(enc_stat_rsp, 0, 4096);
    }
#endif

    if (ptvp) {
        ret = sg_ll_request_sense_pt(ptvp, false, enc_stat_rsp,
                                     REQUEST_SENSE_RESP_SZ, ! op->quiet, vb);
        if (0 == ret) {
            int sense_len = REQUEST_SENSE_RESP_SZ - get_scsi_pt_resid(ptvp);
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
        memset(enc_stat_rsp, 0, REQUEST_SENSE_RESP_SZ);
    }

    if (op->nickname_str)
        ret = ses_set_nickname(ptvp, op);
    else if (have_cgs) {
        for (k = 0, tavp = tav_arr, cgs_clp = op->cgs_cl_arr;
             k < op->num_cgs; ++k, ++tavp, ++cgs_clp) {
            ret = ses_cgs(ptvp, tavp, op,  cgs_clp->last_cs);
            if (ret)
                break;
        }
    } else if (op->do_join)
        ret = join_work(ptvp, op, true);
    else if (op->do_status)
        ret = process_status_page_s(ptvp, op);
    else { /* control page requested */
        op->data_arr[0] = op->page_code;
        op->data_arr[1] = op->byte1;
        d_len = op->arr_len + DATA_IN_OFF;
        sg_put_unaligned_be16((uint16_t)op->arr_len, op->data_arr + 2);
        switch (op->page_code) {
        case ENC_CONTROL_DPC:  /* Enclosure Control diagnostic page [0x2] */
            printf("Sending Enclosure Control [0x%x] page, with page "
                   "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Enclosure Control page\n");
                goto err_out;
            }
            break;
        case STRING_DPC:       /* String Out diagnostic page [0x4] */
            printf("Sending String Out [0x%x] page, with page length=%d "
                   "bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send String Out page\n");
                goto err_out;
            }
            break;
        case THRESHOLD_DPC:       /* Threshold Out diagnostic page [0x5] */
            printf("Sending Threshold Out [0x%x] page, with page length=%d "
                   "bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Threshold Out page\n");
                goto err_out;
            }
            break;
        case ARRAY_CONTROL_DPC:   /* Array control diagnostic page [0x6] */
            printf("Sending Array Control [0x%x] page, with page "
                   "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Array Control page\n");
                goto err_out;
            }
            break;
        case SUBENC_STRING_DPC: /* Subenclosure String Out page [0xc] */
            printf("Sending Subenclosure String Out [0x%x] page, with page "
                   "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Subenclosure String Out page\n");
                goto err_out;
            }
            break;
        case DOWNLOAD_MICROCODE_DPC: /* Download Microcode Control [0xe] */
            printf("Sending Download Microcode Control [0x%x] page, with "
                   "page length=%d bytes\n", op->page_code, d_len);
            printf("  Perhaps it would be better to use the sg_ses_microcode "
                   "utility\n");
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Download Microcode Control page\n");
                goto err_out;
            }
            break;
        case SUBENC_NICKNAME_DPC: /* Subenclosure Nickname Control [0xf] */
            printf("Sending Subenclosure Nickname Control [0x%x] page, with "
                   "page length=%d bytes\n", op->page_code, d_len);
            ret = do_senddiag(ptvp, op->data_arr, d_len, ! op->quiet, vb);
            if (ret) {
                pr2serr("couldn't send Subenclosure Nickname Control page\n");
                goto err_out;
            }
            break;
        default:
            pr2serr("Setting SES control page 0x%x not supported by this "
                    "utility\n", op->page_code);
            pr2serr("That can be done with the sg_senddiag utility with its "
                    "'--raw=' option\n");
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
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
