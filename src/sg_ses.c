/*
 * Copyright (c) 2004-2014 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */

/*
 * This program issues SCSI SEND DIAGNOSTIC and RECEIVE DIAGNOSTIC RESULTS
 * commands tailored for SES (enclosure) devices.
 */

static const char * version_str = "1.97 20141012";    /* ses3r06 */

#define MX_ALLOC_LEN ((64 * 1024) - 4)  /* max allowable for big enclosures */
#define MX_ELEM_HDR 1024
#define MX_DATA_IN 2048
#define MX_JOIN_ROWS 260
#define NUM_ACTIVE_ET_AESP_ARR 32

#define TEMPERAT_OFF 20         /* 8 bits represents -19 C to +235 C */
                                /* value of 0 (would imply -20 C) reserved */

/* Send Diagnostic and Receive Diagnostic Results page codes */
#define DPC_SUPPORTED 0x0
#define DPC_CONFIGURATION 0x1
#define DPC_ENC_CONTROL 0x2
#define DPC_ENC_STATUS 0x2
#define DPC_HELP_TEXT 0x3
#define DPC_STRING 0x4
#define DPC_THRESHOLD 0x5
#define DPC_ARRAY_CONTROL 0x6   /* obsolete */
#define DPC_ARRAY_STATUS 0x6    /* obsolete */
#define DPC_ELEM_DESC 0x7
#define DPC_SHORT_ENC_STATUS 0x8
#define DPC_ENC_BUSY 0x9
#define DPC_ADD_ELEM_STATUS 0xa
#define DPC_SUBENC_HELP_TEXT 0xb
#define DPC_SUBENC_STRING 0xc
#define DPC_SUPPORTED_SES 0xd
#define DPC_DOWNLOAD_MICROCODE 0xe
#define DPC_SUBENC_NICKNAME 0xf

/* Element Type codes */
#define UNSPECIFIED_ETC 0x0
#define DEVICE_ETC 0x1
#define POWER_SUPPLY_ETC 0x2
#define COOLING_ETC 0x3
#define TEMPERATURE_ETC 0x4
#define DOOR_ETC 0x5    /* prior to ses3r05 was DOOR_LOCK_ETC */
#define AUD_ALARM_ETC 0x6
#define ENC_ELECTRONICS_ETC 0x7
#define SCC_CELECTR_ETC 0x8
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

#define NUM_ETC (LAST_ETC + 1)


struct element_type_t {
    int elem_type_code;
    const char * abbrev;
    const char * desc;
};

struct opts_t {
    int byte1;
    int byte1_given;
    int do_control;
    int do_data;
    int dev_slot_num;
    int enumerate;
    int eiioe_auto;
    int eiioe_force;
    int do_filter;
    int do_help;
    int do_hex;
    int ind_given;
    int ind_th;         /* type header index */
    int ind_indiv;      /* individual element index; -1 for overall */
    int ind_et_inst;    /* ETs can have multiple type header instances */
    int inner_hex;
    int do_join;
    int do_list;
    int maxlen;
    int seid;
    int seid_given;
    int page_code;
    int page_code_given;
    int do_raw;
    int o_readonly;
    int do_status;
    int verbose;
    int do_version;
    int warn;
    int num_cgs;
    int arr_len;
    unsigned char sas_addr[8];
    unsigned char data_arr[MX_DATA_IN + 16];
    const char * clear_str;
    const char * desc_name;
    const char * get_str;
    const char * set_str;
    const char * dev_name;
    const char * index_str;
    const char * nickname_str;
    const struct element_type_t * ind_etp;
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
    unsigned char etype;        /* element type code (0: unspecified) */
    unsigned char num_elements; /* number of possible elements, excluding
                                 * overall element */
    unsigned char se_id;        /* subenclosure id (0 for primary enclosure) */
    unsigned char txt_len;      /* type descriptor text length; (unused) */
};

/* A SQL-like join of the Enclosure Status, Threshold In and Additional
 * Element Status pages based of the format indicated in the Configuration
 * page. */
struct join_row_t {
    int el_ind_th;              /* type header index (origin 0) */
    int el_ind_indiv;           /* individual element index, -1 for overall
                                 * instance, otherwise origin 0 */
    unsigned char etype;        /* element type */
    unsigned char se_id;        /* subenclosure id (0 for primary enclosure) */
    int ei_asc;                 /* element index used by Additional Element
                                 * Status page, -1 for not applicable */
    int ei_asc2;                /* some vendors get ei_asc wrong, this is
                                 * their broken version */
    /* following point into Element Descriptor, Enclosure Status, Threshold
     * In and Additional element status diagnostic pages. enc_statp only
     * NULL past last, other pointers can be NULL . */
    unsigned char * elem_descp;
    unsigned char * enc_statp;  /* NULL indicates past last */
    unsigned char * thresh_inp;
    unsigned char * add_elem_statp;
    int dev_slot_num;           /* if not available, set to -1 */
    unsigned char sas_addr[8];  /* if not available, set to 0 */
};

/* Representation of <acronym>[=<value>] or
 * <start_byte>:<start_bit>[:<num_bits>][=<value>]. */
struct tuple_acronym_val {
    const char * acron;
    const char * val_str;
    int start_byte;     /* -1 indicates no start_byte */
    int start_bit;
    int num_bits;
    int64_t val;
};

/* Mapping from <acronym> to <start_byte>:<start_bit>:<num_bits> for a
 * given element type. */
struct acronym2tuple {
    const char * acron; /* element name or acronym, NULL for past end */
    int etype;          /* -1 for all element types */
    int start_byte;     /* origin 0, normally 0 to 3 */
    int start_bit;      /* 7 (MSB or rightmost in SES drafts) to 0 (LSB) */
    int num_bits;       /* usually 1 */
    const char * info;  /* optional, set to NULL if not used */
};

/* Structure for holding (sub-)enclosure information found in the
 * Configuration diagnostic page. */
struct enclosure_info {
    int have_info;
    int rel_esp_id;     /* relative enclosure services process id (origin 1) */
    int num_esp;        /* number of enclosure services processes */
    unsigned char enc_log_id[8];        /* 8 byte NAA */
    unsigned char enc_vendor_id[8];     /* may differ from INQUIRY response */
    unsigned char product_id[16];       /* may differ from INQUIRY response */
    unsigned char product_rev_level[4]; /* may differ from INQUIRY response */
};


static struct type_desc_hdr_t type_desc_hdr_arr[MX_ELEM_HDR];

static struct join_row_t join_arr[MX_JOIN_ROWS];
static struct join_row_t * join_arr_lastp = join_arr + MX_JOIN_ROWS - 1;

#ifdef SG_LIB_FREEBSD

#include <sys/param.h>  /* contains PAGE_SIZE */

static unsigned char enc_stat_rsp[MX_ALLOC_LEN]
        __attribute__ ((aligned (PAGE_SIZE)));
static unsigned char elem_desc_rsp[MX_ALLOC_LEN]
        __attribute__ ((aligned (PAGE_SIZE)));
static unsigned char add_elem_rsp[MX_ALLOC_LEN]
        __attribute__ ((aligned (PAGE_SIZE)));
static unsigned char threshold_rsp[MX_ALLOC_LEN]
        __attribute__ ((aligned (PAGE_SIZE)));

#else

static unsigned char enc_stat_rsp[MX_ALLOC_LEN];
static unsigned char elem_desc_rsp[MX_ALLOC_LEN];
static unsigned char add_elem_rsp[MX_ALLOC_LEN];
static unsigned char threshold_rsp[MX_ALLOC_LEN];

#endif

static int enc_stat_rsp_len;
static int elem_desc_rsp_len;
static int add_elem_rsp_len;
static int threshold_rsp_len;


/* Diagnostic page names, control and/or status (in and/or out) */
static struct diag_page_code dpc_arr[] = {
    {DPC_SUPPORTED, "Supported Diagnostic Pages"},  /* 0 */
    {DPC_CONFIGURATION, "Configuration (SES)"},
    {DPC_ENC_STATUS, "Enclosure Status/Control (SES)"},
    {DPC_HELP_TEXT, "Help Text (SES)"},
    {DPC_STRING, "String In/Out (SES)"},
    {DPC_THRESHOLD, "Threshold In/Out (SES)"},
    {DPC_ARRAY_STATUS, "Array Status/Control (SES, obsolete)"},
    {DPC_ELEM_DESC, "Element Descriptor (SES)"},
    {DPC_SHORT_ENC_STATUS, "Short Enclosure Status (SES)"},  /* 8 */
    {DPC_ENC_BUSY, "Enclosure Busy (SES-2)"},
    {DPC_ADD_ELEM_STATUS, "Additional Element Status (SES-2)"},
    {DPC_SUBENC_HELP_TEXT, "Subenclosure Help Text (SES-2)"},
    {DPC_SUBENC_STRING, "Subenclosure String In/Out (SES-2)"},
    {DPC_SUPPORTED_SES, "Supported SES Diagnostic Pages (SES-2)"},
    {DPC_DOWNLOAD_MICROCODE, "Download Microcode (SES-2)"},
    {DPC_SUBENC_NICKNAME, "Subenclosure Nickname (SES-2)"},
    {0x3f, "Protocol Specific (SAS transport)"},
    {0x40, "Translate Address (SBC)"},
    {0x41, "Device Status (SBC)"},
    {0x42, "Rebuild Assist (SBC)"},     /* sbc3r31 */
    {-1, NULL},
};

/* Diagnostic page names, for status (or in) pages */
static struct diag_page_code in_dpc_arr[] = {
    {DPC_SUPPORTED, "Supported Diagnostic Pages"},  /* 0 */
    {DPC_CONFIGURATION, "Configuration (SES)"},
    {DPC_ENC_STATUS, "Enclosure Status (SES)"},
    {DPC_HELP_TEXT, "Help Text (SES)"},
    {DPC_STRING, "String In (SES)"},
    {DPC_THRESHOLD, "Threshold In (SES)"},
    {DPC_ARRAY_STATUS, "Array Status (SES, obsolete)"},
    {DPC_ELEM_DESC, "Element Descriptor (SES)"},
    {DPC_SHORT_ENC_STATUS, "Short Enclosure Status (SES)"},  /* 8 */
    {DPC_ENC_BUSY, "Enclosure Busy (SES-2)"},
    {DPC_ADD_ELEM_STATUS, "Additional Element Status (SES-2)"},
    {DPC_SUBENC_HELP_TEXT, "Subenclosure Help Text (SES-2)"},
    {DPC_SUBENC_STRING, "Subenclosure String In (SES-2)"},
    {DPC_SUPPORTED_SES, "Supported SES Diagnostic Pages (SES-2)"},
    {DPC_DOWNLOAD_MICROCODE, "Download Microcode (SES-2)"},
    {DPC_SUBENC_NICKNAME, "Subenclosure Nickname (SES-2)"},
    {0x3f, "Protocol Specific (SAS transport)"},
    {0x40, "Translate Address (SBC)"},
    {0x41, "Device Status (SBC)"},
    {0x42, "Rebuild Assist Input (SBC)"},
    {-1, NULL},
};

/* Diagnostic page names, for control (or out) pages */
static struct diag_page_code out_dpc_arr[] = {
    {DPC_SUPPORTED, "?? [Supported Diagnostic Pages]"},  /* 0 */
    {DPC_CONFIGURATION, "?? [Configuration (SES)]"},
    {DPC_ENC_CONTROL, "Enclosure Control (SES)"},
    {DPC_HELP_TEXT, "Help Text (SES)"},
    {DPC_STRING, "String Out (SES)"},
    {DPC_THRESHOLD, "Threshold Out (SES)"},
    {DPC_ARRAY_CONTROL, "Array Control (SES, obsolete)"},
    {DPC_ELEM_DESC, "?? [Element Descriptor (SES)]"},
    {DPC_SHORT_ENC_STATUS, "?? [Short Enclosure Status (SES)]"},  /* 8 */
    {DPC_ENC_BUSY, "?? [Enclosure Busy (SES-2)]"},
    {DPC_ADD_ELEM_STATUS, "?? [Additional Element Status (SES-2)]"},
    {DPC_SUBENC_HELP_TEXT, "?? [Subenclosure Help Text (SES-2)]"},
    {DPC_SUBENC_STRING, "Subenclosure String Out (SES-2)"},
    {DPC_SUPPORTED_SES, "?? [Supported SES Diagnostic Pages (SES-2)]"},
    {DPC_DOWNLOAD_MICROCODE, "Download Microcode (SES-2)"},
    {DPC_SUBENC_NICKNAME, "Subenclosure Nickname (SES-2)"},
    {0x3f, "Protocol Specific (SAS transport)"},
    {0x40, "Translate Address (SBC)"},
    {0x41, "Device Status (SBC)"},
    {0x42, "Rebuild Assist Output (SBC)"},
    {-1, NULL},
};

static struct diag_page_abbrev dp_abbrev[] = {
    {"ac", DPC_ARRAY_CONTROL},
    {"aes", DPC_ADD_ELEM_STATUS},
    {"as", DPC_ARRAY_STATUS},
    {"cf", DPC_CONFIGURATION},
    {"dm", DPC_DOWNLOAD_MICROCODE},
    {"eb", DPC_ENC_BUSY},
    {"ec", DPC_ENC_CONTROL},
    {"ed", DPC_ELEM_DESC},
    {"es", DPC_ENC_STATUS},
    {"ht", DPC_HELP_TEXT},
    {"sdp", DPC_SUPPORTED},
    {"ses", DPC_SHORT_ENC_STATUS},
    {"sht", DPC_SUBENC_HELP_TEXT},
    {"snic", DPC_SUBENC_NICKNAME},
    {"ssp", DPC_SUPPORTED_SES},
    {"sstr", DPC_SUBENC_STRING},
    {"str", DPC_STRING},
    {"th", DPC_THRESHOLD},
    {NULL, -1},
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
    {ENC_ELECTRONICS_ETC, "esc", "Enclosure services controller electronics"},
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
    {"active", DEVICE_ETC, 2, 7, 1, NULL},     /* for control only */
    {"active", ARRAY_DEV_ETC, 2, 7, 1, NULL},  /* for control only */
    {"conscheck", ARRAY_DEV_ETC, 1, 4, 1, "consistency check"},
    {"disable", -1, 0, 5, 1, NULL},        /* -1 is for all element types */
    {"devoff", DEVICE_ETC, 3, 4, 1, NULL},     /* device off */
    {"devoff", ARRAY_DEV_ETC, 3, 4, 1, NULL},
    {"dnr", DEVICE_ETC, 2, 6, 1, "do not remove"},
    {"dnr", ARRAY_DEV_ETC, 2, 6, 1, "do not remove"},
    {"fail", SAS_CONNECTOR_ETC, 3, 6, 1, NULL},
    {"fault", DEVICE_ETC, 3, 5, 1, NULL},
    {"fault", ARRAY_DEV_ETC, 3, 5, 1, NULL},
    {"hotspare", ARRAY_DEV_ETC, 1, 5, 1, NULL},
    {"ident", DEVICE_ETC, 2, 1, 1, "flash LED"},
    {"ident", ARRAY_DEV_ETC, 2, 1, 1, "flash LED"},
    {"ident", POWER_SUPPLY_ETC, 1, 7, 1, "flash LED"},
    {"ident", COOLING_ETC, 1, 7, 1, "flash LED"},
    {"ident", ENCLOSURE_ETC, 1, 7, 1, "flash LED"},
    {"ident", AUD_ALARM_ETC, 1, 7, 1, NULL},
    {"ident", SAS_CONNECTOR_ETC, 1, 7, 1, "flash LED"},
    {"incritarray", ARRAY_DEV_ETC, 1, 3, 1, NULL},
    {"infailedarray", ARRAY_DEV_ETC, 1, 2, 1, NULL},
    {"info", AUD_ALARM_ETC, 3, 3, 1, "emits warning tone when set"},
    {"insert", DEVICE_ETC, 2, 3, 1, NULL},
    {"insert", ARRAY_DEV_ETC, 2, 3, 1, NULL},
    {"locate", DEVICE_ETC, 2, 1, 1, "flash LED"},
    {"locate", ARRAY_DEV_ETC, 2, 1, 1, "flash LED"},
    {"locate", POWER_SUPPLY_ETC, 1, 7, 1, "flash LED"},
    {"locate", COOLING_ETC, 1, 7, 1, "flash LED"},
    {"locate", ENCLOSURE_ETC, 1, 7, 1, "flash LED"},
    {"locate", SAS_CONNECTOR_ETC, 1, 7, 1, "flash LED"},
    {"missing", DEVICE_ETC, 2, 4, 1, NULL},
    {"missing", ARRAY_DEV_ETC, 2, 4, 1, NULL},
    {"ok", ARRAY_DEV_ETC, 1, 7, 1, NULL},
    {"on", POWER_SUPPLY_ETC, 3, 5, 1, "0: turn (remain) off; 1: turn on"},
    {"overcurrent", SAS_CONNECTOR_ETC, 3, 5, 1, NULL},
    {"locate", DEVICE_ETC, 2, 1, 1, NULL},
    {"locate", ARRAY_DEV_ETC, 2, 1, 1, NULL},
    {"pow_cycle", ENCLOSURE_ETC, 2, 7, 2,
     "0: no; 1: start in pow_c_delay minutes; 2: cancel"},
    {"pow_c_delay", ENCLOSURE_ETC, 2, 5, 6,
     "delay in minutes before starting power cycle"},
    {"prdfail", -1, 0, 6, 1, "predict failure"},
    {"rebuildremap", ARRAY_DEV_ETC, 1, 1, 1, NULL},
    {"remove", DEVICE_ETC, 2, 2, 1, NULL},
    {"remove", ARRAY_DEV_ETC, 2, 2, 1, NULL},
    {"rrabort", ARRAY_DEV_ETC, 1, 0, 1, "rebuild/remap abort"},
    {"rsvddevice", ARRAY_DEV_ETC, 1, 6, 1, "reserved device"},
    {"speed_act", COOLING_ETC, 1, 2, 11, "actual speed (rpm / 10)"},
    {"speed_code", COOLING_ETC, 3, 2, 3,
     "0: leave; 1: lowest... 7: highest"},
    {"swap", -1, 0, 4, 1, NULL},               /* Reset swap */
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
 * Status page. Indexed by element type (0 <= et <= 32). */
static int active_et_aesp_arr[NUM_ACTIVE_ET_AESP_ARR] = {
    0, 1 /* dev */, 0, 0,  0, 0, 0, 1 /* esce */,
    0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,  1 /* starg */, 1 /* sinit */, 0, 1 /* arr */,
    1 /* sas exp */, 0, 0, 0,  0, 0, 0, 0,
};

/* Command line long option names with corresponding short letter. */
static struct option long_options[] = {
    {"byte1", required_argument, 0, 'b'},
    {"clear", required_argument, 0, 'C'},
    {"control", no_argument, 0, 'c'},
    {"data", required_argument, 0, 'd'},
    {"descriptor", required_argument, 0, 'D'},
    {"dev-slot-num", required_argument, 0, 'x'},
    {"dsn", required_argument, 0, 'x'},
    {"eiioe", required_argument, 0, 'E'},
    {"enumerate", no_argument, 0, 'e'},
    {"filter", no_argument, 0, 'f'},
    {"get", required_argument, 0, 'G'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"index", required_argument, 0, 'I'},
    {"inner-hex", no_argument, 0, 'i'},
    {"join", no_argument, 0, 'j'},
    {"list", no_argument, 0, 'l'},
    {"nickid", required_argument, 0, 'N'},
    {"nickname", required_argument, 0, 'n'},
    {"maxlen", required_argument, 0, 'm'},
    {"page", required_argument, 0, 'p'},
    {"raw", no_argument, 0, 'r'},
    {"readonly", no_argument, 0, 'R'},
    {"sas-addr", required_argument, 0, 'A'},
    {"set", required_argument, 0, 'S'},
    {"status", no_argument, 0, 's'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

/* For overzealous SES device servers that don't like some status elements
 * sent back as control elements. This table is as per ses3r06. */
static uint8_t ses3_element_cmask_arr[NUM_ETC][4] = {
    {0x40, 0xff, 0xff, 0xff},   /* [0] */
    {0x40, 0, 0xde, 0x3c},      /* DEVICE_ETC */
    {0x40, 0x80, 0, 0x60},      /* POWER_SUPPLY_ETC */
    {0x40, 0x80, 0, 0x67},      /* COOLING_ETC */
    {0x40, 0xc0, 0, 0},         /* TEMPERATURE_ETC */
    {0x40, 0xc0, 0, 0x1},       /* DOOR_ETC */
    {0x40, 0xc0, 0, 0x5f},      /* AUD_ALARM_ETC */
    {0x40, 0xc0, 0x1, 0},       /* ENC_ELECTRONICS_ETC */
    {0x40, 0xc0, 0, 0},         /* SCC_CELECTR_ETC */
    {0x40, 0xc0, 0, 0},         /* NV_CACHE_ETC */
    {0x40, 0, 0, 0},            /* [10] INV_OP_REASON_ETC */
    {0x40, 0, 0, 0xc0},         /* UI_POWER_SUPPLY_ETC */
    {0x40, 0xc3, 0xff, 0xff},   /* DISPLAY_ETC */
    {0x40, 0xc3, 0, 0},         /* KEY_PAD_ETC */
    {0x40, 0x80, 0xff, 0xff},   /* ENCLOSURE_ETC */
    {0x40, 0xc0, 0, 0x1},       /* SCSI_PORT_TRAN_ETC */
    {0x40, 0x80, 0xff, 0xff},   /* LANGUAGE_ETC */
    {0x40, 0xc0, 0, 0x1},       /* COMM_PORT_ETC */
    {0x40, 0xc0, 0, 0},         /* VOLT_SENSOR_ETC */
    {0x40, 0xc0, 0, 0},         /* CURR_SENSOR_ETC */
    {0x40, 0xc0, 0, 0x1},       /* [20] SCSI_TPORT_ETC */
    {0x40, 0xc0, 0, 0x1},       /* SCSI_IPORT_ETC */
    {0x40, 0xc0, 0, 0},         /* SIMPLE_SUBENC_ETC */
    {0x40, 0xff, 0xbe, 0x3c},   /* ARRAY_ETC */
    {0x40, 0xc0, 0, 0},         /* SAS_EXPANDER_ETC */
    {0x40, 0x80, 0, 0xc0},      /* SAS_CONNECTOR_ETC */
};


static int read_hex(const char * inp, unsigned char * arr, int * arr_len,
                    int verb);
static int strcase_eq(const char * s1p, const char * s2p);
static void enumerate_diag_pages(void);
static int saddr_non_zero(const unsigned char * ucp);


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
usage(int help_num)
{
    if (1 == help_num) {
        pr2serr("Usage: "
            "sg_ses [--byte1=B1] [--clear=STR] [--control] [--data=H,H...]\n"
            "              [--descriptor=DN] [--dev-slot-num=SN] "
            "[--eiioe=A_F]\n"
            "              [--enumerate] [--filter] [--get=STR] [--help] "
            "[--hex]\n"
            "              [--index=IIA | =TIA,II] [--inner-hex] "
            "[--join] [--list]\n"
            "              [--maxlen=LEN] [--nickname=SEN] [--nickid=SEID] "
            "[--page=PG]\n"
            "              [--raw] [--sas-addr=SA] [--set=STR] [--status] "
            "[--verbose]\n"
            "              [--version] [--warn] DEVICE\n"
            "  where the main options are:\n"
            "    --clear=STR|-C STR    clear field by acronym or position\n"
            "    --descriptor=DN|-D DN    descriptor name (for indexing)\n"
            "    --dev-slot-num=SN|--dsn=SN|-x SN    device slot number "
            "(for indexing)\n"
            "    --eiioe=A_F|-E A_F    where A_F is either 'auto' or 'force'."
            "'force'\n"
            "                          acts as if EIIOE is set, 'auto' tries "
            "to guess\n"
            "    --enumerate|-e      enumerate page names + element types "
            "(ignore\n"
            "                        DEVICE). Use twice for clear,get,set "
            "acronyms\n"
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
            "                          type abbreviation (e.g. 'arr')\n"
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
            "position\n\n"
            "Fetches status or sends control data to a SCSI enclosure. Use "
            "'-hh' for\nmore help, including the options not shown here.\n");
    } else {    /* for '-hh' or '--help --help' */
        pr2serr(
            "  where the remaining sg_ses options are:\n"
            "    --byte1=B1|-b B1    byte 1 (2nd byte) of control page set "
            "to B1\n"
            "    --control|-c        send control information (def: fetch "
            "status)\n"
            "    --data=H,H...|-d H,H...    string of ASCII hex bytes for "
            "control pages\n"
            "    --data=- | -d -     fetch string of ASCII hex bytes from "
            "stdin\n"
            "    --data=@FN | -d @FN    fetch string of ASCII hex bytes from "
            "file: FN\n"
            "    --hex|-H            print page response (or field) in hex\n"
            "    --inner-hex|-i      print innermost level of a"
            " status page in hex\n"
            "    --list|-l           same as '--enumerate' option\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "    --nickname=SEN|-n SEN   SEN is new subenclosure nickname\n"
            "    --nickid=SEID|-N SEID   SEID is subenclosure identifier "
            "(def: 0)\n"
            "                            used to specify which nickname to "
            "change\n"
            "    --raw|-r            print status page in ASCII hex suitable "
            "for '-d';\n"
            "                        when used twice outputs page in binary "
            "to stdout\n"
            "    --readonly|-R       open DEVICE read-only (def: "
            "read-write)\n"
            "    --status|-s         fetch status information (default "
            "action)\n"
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
            "in the SES device is itself optional. The\nmedium level "
            "options implicitly set '--join'.\n"
            );
    }
}

/* Return 0 for okay, else an error */
static int
parse_index(struct opts_t *op)
{
    int n;
    const char * cp;
    char * mallcp;
    char * c2p;
    const struct element_type_t * etp;
    char b[64];

    op->ind_given = 1;
    if ((cp = strchr(op->index_str, ','))) {
        if (0 == strcmp("-1", cp + 1))
            n = -1;
        else {
            n = sg_get_num(cp + 1);
            if ((n < 0) || (n > 255)) {
                pr2serr("bad argument to '--index', after comma expect "
                        "number from -1 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        }
        op->ind_indiv = n;
        n = cp - op->index_str;
        if (n >= (int)sizeof(b)) {
            pr2serr("bad argument to '--index', string prior to comma too "
                    "long\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    } else {
        n = strlen(op->index_str);
        if (n >= (int)sizeof(b)) {
            pr2serr("bad argument to '--index', string too long\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    strncpy(b, op->index_str, n);
    b[n] = '\0';
    if (0 == strcmp("-1", b)) {
        if (cp) {
            pr2serr("bad argument to '--index', unexpected '-1' type header "
                    "index\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        op->ind_th = 0;
        op->ind_indiv = -1;
    } else if (isdigit(b[0])) {
        n = sg_get_num(b);
        if ((n < 0) || (n > 255)) {
            pr2serr("bad numeric argument to '--index', expect number from 0 "
                    "to 255\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (cp)
            op->ind_th = n;
        else {
            op->ind_th = 0;
            op->ind_indiv = n;
        }
    } else if ('_' == b[0]) {
        if ((c2p = strchr(b + 1, '_')))
            *c2p = '\0';
        n = sg_get_num(b + 1);
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
            n = sg_get_num(c2p + 1);
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
        int blen = strlen(b);

        for (etp = element_type_arr; etp->desc; ++etp) {
            n = strlen(etp->abbrev);
            if ((n == blen) && (0 == strncmp(b, etp->abbrev, n)))
                break;
        }
        if (NULL == etp->desc) {
            pr2serr("bad element type abbreviation [%s] for '--index'\n"
                    "use '--enumerate' to see possibles\n", b);
            return SG_LIB_SYNTAX_ERROR;
        }
        if ((int)strlen(b) > n) {
            n = sg_get_num(b + n);
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


/* process command line options and argument. Returns 0 if ok. */
static int
cl_process(struct opts_t *op, int argc, char *argv[])
{
    int c, j, ret, ff;
    const char * data_arg = NULL;
    uint64_t saddr;
    const char * cp;

    op->dev_slot_num = -1;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "A:b:cC:d:D:eE:fG:hHiI:jln:N:m:p:rRsS:v"
                        "Vwx:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'A':       /* SAS address, assumed to be hex */
            cp = optarg;
            if ((strlen(optarg) > 2) && ('X' == toupper(optarg[1])))
                cp = optarg + 2;
            if (1 != sscanf(cp, "%" SCNx64 "", &saddr)) {
                pr2serr("bad argument to '--sas-addr'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            for (j = 7, ff = 1; j >= 0; --j) {
                if (ff & (0xff != (saddr & 0xff)))
                    ff = 0;
                op->sas_addr[j] = (saddr & 0xff);
                saddr >>= 8;
            }
            if (ff) {
                pr2serr("decode error from argument to '--sas-addr'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'b':
            op->byte1 = sg_get_num(optarg);
            if ((op->byte1 < 0) || (op->byte1 > 255)) {
                pr2serr("bad argument to '--byte1' (0 to 255 inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++op->byte1_given;
            break;
        case 'c':
            ++op->do_control;
            break;
        case 'C':
            op->clear_str = optarg;
            ++op->num_cgs;
            break;
        case 'd':
            data_arg = optarg;
            op->do_data = 1;
            break;
        case 'D':
            op->desc_name = optarg;
            break;
        case 'e':
            ++op->enumerate;
            break;
        case 'E':
            if (0 == strcmp("auto", optarg))
                ++op->eiioe_auto;
            else if (0 == strcmp("force", optarg))
                ++op->eiioe_force;
            else {
                pr2serr("--eiioe option expects 'auto' or 'force' as an "
                        "argument\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'f':
            ++op->do_filter;
            break;
        case 'G':
            op->get_str = optarg;
            ++op->num_cgs;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
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
        case 'l':
            ++op->do_list;
            break;
        case 'n':
            op->nickname_str = optarg;
            break;
        case 'N':
            op->seid = sg_get_num(optarg);
            if ((op->seid < 0) || (op->seid > 255)) {
                pr2serr("bad argument to '--nick_id' (0 to 255 inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++op->seid_given;
            break;
        case 'm':
            op->maxlen = sg_get_num(optarg);
            if ((op->maxlen < 0) || (op->maxlen > 65535)) {
                pr2serr("bad argument to '--maxlen' (0 to 65535 "
                        "inclusive expected)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            if (isdigit(optarg[0])) {
                op->page_code = sg_get_num(optarg);
                if ((op->page_code < 0) || (op->page_code > 255)) {
                    pr2serr("bad argument to '--page' (0 to 255 "
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
                    pr2serr("'--page' abbreviation %s not found\nHere are "
                            "the choices:\n", optarg);
                    enumerate_diag_pages();
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            ++op->page_code_given;
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 'R':
            ++op->o_readonly;
            break;
        case 's':
            ++op->do_status;
            break;
        case 'S':
            op->set_str = optarg;
            ++op->num_cgs;
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            ++op->do_version;
            return 0;
        case 'w':
            ++op->warn;
            break;
        case 'x':
            op->dev_slot_num = sg_get_num(optarg);
            if ((op->dev_slot_num < 0) || (op->dev_slot_num > 255)) {
                pr2serr("bad argument to '--dev-slot-num' (0 to 255 "
                        "inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
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
    if (data_arg) {
        memset(op->data_arr, 0, sizeof(op->data_arr));
        if (read_hex(data_arg, op->data_arr + 4, &op->arr_len, op->verbose)) {
            pr2serr("bad argument to '--data'\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (op->maxlen <= 0)
        op->maxlen = MX_ALLOC_LEN;
    if (op->do_join && (op->do_control)) {
        pr2serr("cannot have '--join' and '--control'\n");
        goto err_help;
    }
    if (op->num_cgs > 1) {
        pr2serr("can only be one of '--clear', '--get' and '--set'\n");
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
            return SG_LIB_SYNTAX_ERROR;
        }
        if ((0 == op->do_join) && (0 == op->do_control) &&
            (0 == op->num_cgs) && (0 == op->page_code_given)) {
            ++op->do_join;      /* implicit --join */
            if (op->verbose)
                pr2serr("assume --join option is set\n");
        }
    }
    if (op->ind_given) {
        if ((0 == op->do_join) && (0 == op->do_control) &&
            (0 == op->num_cgs) && (0 == op->page_code_given)) {
            ++op->page_code_given;
            op->page_code = 2;  /* implicit status page */
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
    } else if (0 == op->do_status)
        op->do_status = 1;  /* default to receiving status pages */

    if (op->nickname_str) {
        if (! op->do_control) {
            pr2serr("since '--nickname=' implies control mode, require "
                    "'--control' as well\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (op->page_code_given) {
            if (DPC_SUBENC_NICKNAME != op->page_code) {
                pr2serr("since '--nickname=' assume or expect "
                        "'--page=snic'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        } else
            op->page_code = DPC_SUBENC_NICKNAME;
    } else if (op->seid_given) {
        pr2serr("'--nickid=' must be used together with '--nickname='\n");
        return SG_LIB_SYNTAX_ERROR;

    }
    if ((op->verbose > 4) && saddr_non_zero(op->sas_addr)) {
        pr2serr("    SAS address (in hex): ");
        for (j = 0; j < 8; ++j)
            pr2serr("%02x", op->sas_addr[j]);
        pr2serr("\n");
    }

    if (NULL == op->dev_name) {
        pr2serr("missing DEVICE name!\n");
        goto err_help;
    }
    return 0;

err_help:
    pr2serr("  For more information use '--help'\n");
    return SG_LIB_SYNTAX_ERROR;
}

/* Returns 64 bit signed integer given in either decimal or in hex. The
 * hex number is either preceded by "0x" or followed by "h". Returns -1
 * on error (so check for "-1" string before using this function). */
static int64_t
get_llnum(const char * buf)
{
    int res, len;
    int64_t num;
    uint64_t unum;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%" SCNx64 "", &unum);
        num = unum;
    } else if ('H' == toupper(buf[len - 1])) {
        res = sscanf(buf, "%" SCNx64 "", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%" SCNd64 "", &num);
    return (1 == res) ? num : -1;
}

/* Parse clear/get/set string. Uses 'buff' for scratch area. Returns 0
 * on success, else -1. */
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
            tavp->val = get_llnum(esp + 1);
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

/* Return of 0 -> success, SG_LIB_CAT_* positive values or -1 -> other
 * failures */
static int
do_senddiag(int sg_fd, int pf_bit, void * outgoing_pg, int outgoing_len,
            int noisy, int verbose)
{
    const char * cp;
    int page_num;

    if (outgoing_pg && (verbose > 2)) {
        page_num = ((const char *)outgoing_pg)[0];
        cp = find_out_diag_page_desc(page_num);
        if (cp)
            pr2serr("    Send diagnostic cmd name: %s\n", cp);
        else
            pr2serr("    Send diagnostic cmd number: 0x%x\n", page_num);
    }
    return sg_ll_send_diag(sg_fd, 0 /* sf_code */, pf_bit, 0 /* sf_bit */,
                           0 /* devofl_bit */, 0 /* unitofl_bit */,
                           0 /* long_duration */, outgoing_pg, outgoing_len,
                           noisy, verbose);
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
find_element_tname(int elem_type_code, char * b, int mlen_b)
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

/* Returns 1 if el_type (element type) is of interest to the Additional
 * Element Status page. Otherwise return 0. */
static int
active_et_aesp(int el_type)
{
    if ((el_type >= 0) && (el_type < NUM_ACTIVE_ET_AESP_ARR))
        return active_et_aesp_arr[el_type];
    else
        return 0;
}

/* Return of 0 -> success, SG_LIB_CAT_* positive values or -1 -> other
 * failures */
static int
do_rec_diag(int sg_fd, int page_code, unsigned char * rsp_buff,
            int rsp_buff_size, const struct opts_t * op, int * rsp_lenp)
{
    int rsp_len, res;
    const char * cp;
    char b[80];

    memset(rsp_buff, 0, rsp_buff_size);
    if (rsp_lenp)
        *rsp_lenp = 0;
    cp = find_in_diag_page_desc(page_code);
    if (op->verbose > 1) {
        if (cp)
            pr2serr("    Receive diagnostic results cmd for %s page\n", cp);
        else
            pr2serr("    Receive diagnostic results cmd for page 0x%x\n",
                    page_code);
    }
    res = sg_ll_receive_diag(sg_fd, 1 /* pcv */, page_code, rsp_buff,
                             rsp_buff_size, 1, op->verbose);
    if (0 == res) {
        rsp_len = (rsp_buff[2] << 8) + rsp_buff[3] + 4;
        if (rsp_len > rsp_buff_size) {
            if (rsp_buff_size > 8) /* tried to get more than header */
                pr2serr("<<< warning response buffer too small [%d but need "
                        "%d]>>>\n", rsp_buff_size, rsp_len);
            rsp_len = rsp_buff_size;
        }
        if (rsp_lenp)
            *rsp_lenp = rsp_len;
        if (page_code != rsp_buff[0]) {
            if ((0x9 == rsp_buff[0]) && (1 & rsp_buff[1])) {
                pr2serr("Enclosure busy, try again later\n");
                if (op->do_hex)
                    dStrHexErr((const char *)rsp_buff, rsp_len, 0);
            } else if (0x8 == rsp_buff[0]) {
                pr2serr("Enclosure only supports Short Enclosure Status: "
                        "0x%x\n", rsp_buff[1]);
            } else {
                pr2serr("Invalid response, wanted page code: 0x%x but got "
                        "0x%x\n", page_code, rsp_buff[0]);
                dStrHexErr((const char *)rsp_buff, rsp_len, 0);
            }
            return -2;
        }
        return 0;
    } else if (op->verbose) {
        if (cp)
            pr2serr("Attempt to fetch %s diagnostic page failed\n", cp);
        else
            pr2serr("Attempt to fetch status diagnostic page [0x%x] failed\n",
                    page_code);
        sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
        pr2serr("    %s\n", b);
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

/* DPC_CONFIGURATION [0x1]
 * Display Configuration diagnostic page. */
static void
ses_configuration_sdg(const unsigned char * resp, int resp_len)
{
    int j, k, el, num_subs, sum_elem_types;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const unsigned char * text_ucp;
    char b[64];

    printf("Configuration diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    sum_elem_types = 0;
    last_ucp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n",
            num_subs - 1);
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    printf("  enclosure descriptor list\n");
    ucp = resp + 8;
    for (k = 0; k < num_subs; ++k, ucp += el) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        el = ucp[3] + 4;
        sum_elem_types += ucp[2];
        printf("    Subenclosure identifier: %d%s\n", ucp[1],
               (ucp[1] ? "" : " [primary]"));
        printf("      relative ES process id: %d, number of ES processes"
               ": %d\n", ((ucp[0] & 0x70) >> 4), (ucp[0] & 0x7));
        printf("      number of type descriptor headers: %d\n", ucp[2]);
        if (el < 40) {
            pr2serr("      enc descriptor len=%d ??\n", el);
            continue;
        }
        printf("      enclosure logical identifier (hex): ");
        for (j = 0; j < 8; ++j)
            printf("%02x", ucp[4 + j]);
        printf("\n      enclosure vendor: %.8s  product: %.16s  rev: %.4s\n",
               ucp + 12, ucp + 20, ucp + 36);
        if (el > 40) {
            printf("      vendor-specific data:\n");
            /* dStrHex((const char *)(ucp + 40), el - 40, 0); */
            printf("        ");
            for (j = 0; j < (el - 40); ++j) {
                if ((j > 0) && (0 == (j % 16)))
                    printf("\n        ");
                printf("%02x ", *(ucp + 40 + j));
            }
            printf("\n");
        }
    }
    /* printf("\n"); */
    printf("  type descriptor header/text list\n");
    text_ucp = ucp + (sum_elem_types * 4);
    for (k = 0; k < sum_elem_types; ++k, ucp += 4) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        printf("    Element type: %s, subenclosure id: %d\n",
               find_element_tname(ucp[0], b, sizeof(b)), ucp[2]);
        printf("      number of possible elements: %d\n", ucp[1]);
        if (ucp[3] > 0) {
            if (text_ucp > last_ucp)
                goto truncated;
            printf("      text: %.*s\n", ucp[3], text_ucp);
            text_ucp += ucp[3];
        }
    }
    return;
truncated:
    pr2serr("    <<<ses_configuration_sdg: response too short>>>\n");
    return;
}

/* DPC_CONFIGURATION
 * Returns total number of type descriptor headers written to 'tdhp' or -1
 * if there is a problem */
static int
populate_type_desc_hdr_arr(int fd, struct type_desc_hdr_t * tdhp,
                           unsigned int * generationp,
                           struct enclosure_info * primary_ip,
                           struct opts_t * op)
{
    int resp_len, k, el, num_subs, sum_type_dheaders, res, n;
    int ret = 0;
    unsigned int gen_code;
    unsigned char * resp;
    const unsigned char * ucp;
    const unsigned char * last_ucp;

    resp = (unsigned char *)calloc(op->maxlen, 1);
    if (NULL == resp) {
        pr2serr("populate: unable to allocate %d bytes on heap\n",
                op->maxlen);
        ret = -1;
        goto the_end;
    }
    res = do_rec_diag(fd, DPC_CONFIGURATION, resp, op->maxlen, op, &resp_len);
    if (res) {
        pr2serr("populate: couldn't read config page, res=%d\n", res);
        ret = -1;
        goto the_end;
    }
    if (resp_len < 4) {
        ret = -1;
        goto the_end;
    }
    num_subs = resp[1] + 1;
    sum_type_dheaders = 0;
    last_ucp = resp + resp_len - 1;
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    if (generationp)
        *generationp = gen_code;
    ucp = resp + 8;
    for (k = 0; k < num_subs; ++k, ucp += el) {
        if ((ucp + 3) > last_ucp)
            goto p_truncated;
        el = ucp[3] + 4;
        sum_type_dheaders += ucp[2];
        if (el < 40) {
            pr2serr("populate: short enc descriptor len=%d ??\n", el);
            continue;
        }
        if ((0 == k) && primary_ip) {
            ++primary_ip->have_info;
            primary_ip->rel_esp_id = (ucp[0] & 0x70) >> 4;
            primary_ip->num_esp = (ucp[0] & 0x7);
            memcpy(primary_ip->enc_log_id, ucp + 4, 8);
            memcpy(primary_ip->enc_vendor_id, ucp + 12, 8);
            memcpy(primary_ip->product_id, ucp + 20, 16);
            memcpy(primary_ip->product_rev_level, ucp + 36, 4);
        }
    }
    for (k = 0; k < sum_type_dheaders; ++k, ucp += 4) {
        if ((ucp + 3) > last_ucp)
            goto p_truncated;
        if (k >= MX_ELEM_HDR) {
            pr2serr("populate: too many elements\n");
            ret = -1;
            goto the_end;
        }
        tdhp[k].etype = ucp[0];
        tdhp[k].num_elements = ucp[1];
        tdhp[k].se_id = ucp[2];
        tdhp[k].txt_len = ucp[3];
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
                pr2serr("populate: unable to find element type '%s%d'\n",
                        op->ind_etp->abbrev, op->ind_et_inst);
            else
                pr2serr("populate: unable to find element type '%s'\n",
                        op->ind_etp->abbrev);
            ret = -1;
            goto the_end;
        }
    }
    ret = sum_type_dheaders;
    goto the_end;

p_truncated:
    pr2serr("populate: config too short\n");
    ret = -1;

the_end:
    if (resp)
        free(resp);
    return ret;
}

static char *
find_sas_connector_type(int conn_type, char * buff, int buff_len)
{
    switch (conn_type) {
    case 0x0:
        snprintf(buff, buff_len, "No information");
        break;
    case 0x1:
        snprintf(buff, buff_len, "SAS 4x receptacle (SFF-8470) "
                 "[max 4 phys]");
        break;
    case 0x2:
        snprintf(buff, buff_len, "Mini SAS 4x receptacle (SFF-8088) "
                 "[max 4 phys]");
        break;
    case 0x3:
        snprintf(buff, buff_len, "QSFP+ receptacle (SFF-8436) "
                 "[max 4 phys]");
        break;
    case 0x4:
        snprintf(buff, buff_len, "Mini SAS 4x active receptacle (SFF-8088) "
                 "[max 4 phys]");
        break;
    case 0x5:
        snprintf(buff, buff_len, "Mini SAS HD 4x receptacle (SFF-8644) "
                 "[max 4 phys]");
        break;
    case 0x6:
        snprintf(buff, buff_len, "Mini SAS HD 8x receptacle (SFF-8644) "
                 "[max 8 phys]");
        break;
    case 0x7:
        snprintf(buff, buff_len, "Mini SAS HD 16x receptacle (SFF-8644) "
                 "[max 16 phys]");
        break;
    case 0xf:
        snprintf(buff, buff_len, "Vendor specific external connector");
        break;
    case 0x10:
        snprintf(buff, buff_len, "SAS 4i plug (SFF-8484) [max 4 phys]");
        break;
    case 0x11:
        snprintf(buff, buff_len, "Mini SAS 4i receptacle (SFF-8087) "
                 "[max 4 phys]");
        break;
    case 0x12:
        snprintf(buff, buff_len, "Mini SAS HD 4i receptacle (SFF-8643) "
                 "[max 4 phys]");
        break;
    case 0x13:
        snprintf(buff, buff_len, "Mini SAS HD 8i receptacle (SFF-8643) "
                 "[max 8 phys]");
        break;
    case 0x20:
        snprintf(buff, buff_len, "SAS Drive backplane receptacle (SFF-8482) "
                 "[max 2 phys]");
        break;
    case 0x21:
        snprintf(buff, buff_len, "SATA host plug [max 1 phy]");
        break;
    case 0x22:
        snprintf(buff, buff_len, "SAS Drive plug (SFF-8482) [max 2 phys]");
        break;
    case 0x23:
        snprintf(buff, buff_len, "SATA device plug [max 1 phy]");
        break;
    case 0x24:
        snprintf(buff, buff_len, "Micro SAS receptacle [max 2 phys]");
        break;
    case 0x25:
        snprintf(buff, buff_len, "Micro SATA device plug [max 1 phy]");
        break;
    case 0x26:
        snprintf(buff, buff_len, "Micro SAS plug (SFF-8486) [max 2 phys]");
        break;
    case 0x27:
        snprintf(buff, buff_len, "Micro SAS/SATA plug (SFF-8486) "
                 "[max 2 phys]");
        break;
    case 0x2f:
        snprintf(buff, buff_len, "SAS virtual connector [max 1 phy]");
        break;
    case 0x3f: snprintf(buff, buff_len, "Vendor specific internal connector");
        break;
    default:
        if (conn_type < 0x10)
            snprintf(buff, buff_len, "unknown external connector type: 0x%x",
                     conn_type);
        else if (conn_type < 0x20)
            snprintf(buff, buff_len, "unknown internal wide connector type: "
                     "0x%x", conn_type);
        else if (conn_type < 0x30)
            snprintf(buff, buff_len, "unknown internal connector to end "
                     "device, type: 0x%x", conn_type);
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
enc_status_helper(const char * pad, const unsigned char * statp, int etype,
                  const struct opts_t * op)
{
    int res, a, b;
    char bb[128];
    int nofilter = ! op->do_filter;


    if (op->inner_hex) {
        printf("%s%02x %02x %02x %02x\n", pad, statp[0], statp[1], statp[2],
               statp[3]);
        return;
    }
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
        if (nofilter || ((0x80 & statp[1]) || (0xe & statp[2])))
            printf("%sIdent=%d, DC overvoltage=%d, DC undervoltage=%d, DC "
                   "overcurrent=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[2] & 0x8), !!(statp[2] & 0x4), !!(statp[2] & 0x2));
        if (nofilter || (0xf8 & statp[3]))
            printf("%sHot swap=%d, Fail=%d, Requested on=%d, Off=%d, "
                   "Overtmp fail=%d\n", pad, !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x20),
                   !!(statp[3] & 0x10), !!(statp[3] & 0x8));
        if (nofilter || (0x7 & statp[3]))
            printf("%sTemperature warn=%d, AC fail=%d, DC fail=%d\n",
                   pad, !!(statp[3] & 0x4), !!(statp[3] & 0x2),
                   !!(statp[3] & 0x1));
        break;
    case COOLING_ETC:
        if (nofilter || ((0xc0 & statp[1]) || (0xf0 & statp[3])))
            printf("%sIdent=%d, Hot swap=%d, Fail=%d, Requested on=%d, "
                   "Off=%d\n", pad, !!(statp[1] & 0x80), !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x20),
                   !!(statp[3] & 0x10));
        printf("%sActual speed=%d rpm, Fan %s\n", pad,
               (((0x7 & statp[1]) << 8) + statp[2]) * 10,
               actual_speed_desc[7 & statp[3]]);
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
    case ENC_ELECTRONICS_ETC: /* enclosure services controller electronics */
        if (nofilter || (0xc0 & statp[1]) || (0x1 & statp[2]) ||
            (0x80 & statp[3]))
            printf("%sIdent=%d, Fail=%d, Report=%d, Hot swap=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[2] & 0x1), !!(statp[3] & 0x80));
        break;
    case SCC_CELECTR_ETC:     /* SCC controller electronics */
        if (nofilter || ((0xc0 & statp[1]) || (0x1 & statp[2])))
            printf("%sIdent=%d, Fail=%d, Report=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[2] & 0x1));
        break;
    case NV_CACHE_ETC:     /* Non volatile cache */
        res = (statp[2] << 8) + statp[3];
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
                   (statp[2] << 8) + statp[3], (statp[1] & 7));
            break;
        case 2:
        case 3:
            printf("%slast 3 bytes (hex): %02x %02x %02x\n", pad, statp[1],
                   statp[2], statp[3]);
            break;
        default:
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
        if (nofilter || ((0x7 & statp[2]) || (0xc3 & statp[3]))) {
            printf("%sUPS fail=%d, Warn=%d, Intf fail=%d, Ident=%d, Fail=%d, "
                   "Batt fail=%d\n", pad, !!(statp[2] & 0x4),
                   !!(statp[2] & 0x2), !!(statp[2] & 0x1),
                   !!(statp[3] & 0x80), !!(statp[3] & 0x40),
                   !!(statp[3] & 0x2));
            printf("%sBPF=%d\n", pad, !!(statp[3] & 0x1));
        }
        break;
    case DISPLAY_ETC:   /* Display (ses2r15) */
        if (nofilter || (0xc0 & statp[1]))
            printf("%sIdent=%d, Fail=%d, Display mode status=%d, Display "
                   "character status=0x%x\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), (statp[1] & 0x3),
                   ((statp[2] << 8) & statp[3]));
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
                   "duration=%d\n", pad, !!(statp[2] & 0x2), b);
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
               ((int)(short)((statp[2] << 8) + statp[3]) / 100.0));
#else
        printf("%sVoltage: %.2f volts\n", pad,
               ((int)(short)((statp[2] << 8) + statp[3]) / 100.0));
#endif
        break;
    case CURR_SENSOR_ETC:   /* Current sensor */
        if (nofilter || (0xca & statp[1]))
            printf("%sIdent=%d, Fail=%d, Warn Over=%d, Crit Over=%d\n",
                    pad, !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                    !!(statp[1] & 0x8), !!(statp[1] & 0x2));
#ifdef SG_LIB_MINGW
        printf("%sCurrent: %g amps\n", pad,
               ((int)(short)((statp[2] << 8) + statp[3]) / 100.0));
#else
        printf("%sCurrent: %.2f amps\n", pad,
               ((int)(short)((statp[2] << 8) + statp[3]) / 100.0));
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
    case SAS_CONNECTOR_ETC:
        printf("%sIdent=%d, %s\n", pad, !!(statp[1] & 0x80),
               find_sas_connector_type((statp[1] & 0x7f), bb, sizeof(bb)));
        printf("%sConnector physical link=0x%x, Fail=%d, OC=%d\n", pad,
               statp[2], !!(statp[3] & 0x40), !!(statp[3] & 0x20));
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

/* DPC_ENC_STATUS [0x2]
 * Display enclosure status diagnostic page. */
static void
ses_enc_status_dp(const struct type_desc_hdr_t * tdhp, int num_telems,
                  unsigned int ref_gen_code, const unsigned char * resp,
                  int resp_len, const struct opts_t * op)
{
    int j, k, elem_ind, match_ind_th, got1;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    char b[64];

    printf("Enclosure Status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    printf("  INVOP=%d, INFO=%d, NON-CRIT=%d, CRIT=%d, UNRECOV=%d\n",
           !!(resp[1] & 0x10), !!(resp[1] & 0x8), !!(resp[1] & 0x4),
           !!(resp[1] & 0x2), !!(resp[1] & 0x1));
    last_ucp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  status descriptor list\n");
    ucp = resp + 8;
    for (k = 0, got1 = 0; k < num_telems; ++k, ++tdhp) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   find_element_tname(tdhp->etype, b, sizeof(b)),
                   tdhp->se_id, k);
            printf("      Overall descriptor:\n");
            enc_status_helper("        ", ucp, tdhp->etype, op);
            ++got1;
        }
        for (ucp += 4, j = 0, elem_ind = 0; j < tdhp->num_elements;
             ++j, ucp += 4, ++elem_ind) {
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (elem_ind != op->ind_indiv))
                    continue;
            }
            printf("      Element %d descriptor:\n", elem_ind);
            enc_status_helper("        ", ucp, tdhp->etype, op);
            ++got1;
        }
    }
    if (op->ind_given && (0 == got1))
        printf("      >>> no match on --index=%d,%d\n", op->ind_th,
               op->ind_indiv);
    return;
truncated:
    pr2serr("    <<<enc: response too short>>>\n");
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
ses_threshold_helper(const char * pad, const unsigned char *tp, int etype,
                     const struct opts_t * op)
{
    char b[128];
    char b2[128];

    if (op->inner_hex) {
        printf("%s%02x %02x %02x %02x\n", pad, tp[0], tp[1], tp[2], tp[3]);
        return;
    }
    switch (etype) {
    case 0x4:  /*temperature */
        printf("%shigh critical=%s, high warning=%s\n", pad,
               reserved_or_num(b, 128, tp[0] - TEMPERAT_OFF, -TEMPERAT_OFF),
               reserved_or_num(b2, 128, tp[1] - TEMPERAT_OFF, -TEMPERAT_OFF));
        printf("%slow warning=%s, low critical=%s (in Celsius)\n", pad,
               reserved_or_num(b, 128, tp[2] - TEMPERAT_OFF, -TEMPERAT_OFF),
               reserved_or_num(b2, 128, tp[3] - TEMPERAT_OFF, -TEMPERAT_OFF));
        break;
    case 0xb:  /* UPS */
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
#ifdef SG_LIB_MINGW
        printf("%shigh critical=%g %%, high warning=%g %%\n", pad,
               0.5 * tp[0], 0.5 * tp[1]);
        printf("%slow warning=%g %%, low critical=%g %% (from nominal "
               "voltage)\n", pad, 0.5 * tp[2], 0.5 * tp[3]);
#else
        printf("%shigh critical=%.1f %%, high warning=%.1f %%\n", pad,
               0.5 * tp[0], 0.5 * tp[1]);
        printf("%slow warning=%.1f %%, low critical=%.1f %% (from nominal "
               "voltage)\n", pad, 0.5 * tp[2], 0.5 * tp[3]);
#endif
        break;
    case 0x13: /* current */
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
        if (op->verbose)
            printf("%s<< no thresholds for this element type >>\n", pad);
        break;
    }
}

/* DPC_THRESHOLD [0x5] */
static void
ses_threshold_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                  unsigned int ref_gen_code, const unsigned char * resp,
                  int resp_len, const struct opts_t * op)
{
    int j, k, elem_ind, match_ind_th, got1;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    char b[64];

    printf("Threshold In diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    printf("  INVOP=%d\n", !!(resp[1] & 0x10));
    last_ucp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  Threshold status descriptor list\n");
    ucp = resp + 8;
    for (k = 0, got1 = 0; k < num_telems; ++k, ++tdhp) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   find_element_tname(tdhp->etype, b, sizeof(b)),
                   tdhp->se_id, k);
            printf("      Overall descriptor:\n");
            ses_threshold_helper("        ", ucp, tdhp->etype, op);
            ++got1;
        }
        for (ucp += 4, j = 0, elem_ind = 0; j < tdhp->num_elements;
             ++j, ucp += 4, ++elem_ind) {
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (elem_ind != op->ind_indiv))
                    continue;
            }
            printf("      Element %d descriptor:\n", elem_ind);
            ses_threshold_helper("        ", ucp, tdhp->etype, op);
            ++got1;
        }
    }
    if (op->ind_given && (0 == got1))
        printf("      >>> no match on --index=%d,%d\n", op->ind_th,
               op->ind_indiv);
    return;
truncated:
    pr2serr("    <<<thresh: response too short>>>\n");
    return;
}

/* DPC_ELEM_DESC [0x7]
 * This page essentially contains names of overall and individual
 * elements. */
static void
ses_element_desc_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                     unsigned int ref_gen_code, const unsigned char * resp,
                     int resp_len, const struct opts_t * op)
{
    int j, k, desc_len, elem_ind, match_ind_th, got1;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const struct type_desc_hdr_t * tp;
    char b[64];

    printf("Element Descriptor In diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    last_ucp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  element descriptor list (grouped by type):\n");
    ucp = resp + 8;
    for (k = 0, got1 = 0, tp = tdhp; k < num_telems; ++k, ++tp) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        desc_len = (ucp[2] << 8) + ucp[3] + 4;
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   find_element_tname(tp->etype, b, sizeof(b)), tp->se_id, k);
            if (desc_len > 4)
                printf("      Overall descriptor: %.*s\n", desc_len - 4,
                       ucp + 4);
            else
                printf("      Overall descriptor: <empty>\n");
            ++got1;
        }
        for (ucp += desc_len, j = 0, elem_ind = 0; j < tp->num_elements;
             ++j, ucp += desc_len, ++elem_ind) {
            desc_len = (ucp[2] << 8) + ucp[3] + 4;
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (elem_ind != op->ind_indiv))
                    continue;
            }
            if (desc_len > 4)
                printf("      Element %d descriptor: %.*s\n", j,
                       desc_len - 4, ucp + 4);
            else
                printf("      Element %d descriptor: <empty>\n", j);
            ++got1;
        }
    }
    if (op->ind_given && (0 == got1))
        printf("      >>> no match on --index=%d,%d\n", op->ind_th,
               op->ind_indiv);
    return;
truncated:
    pr2serr("    <<<element: response too short>>>\n");
    return;
}

static int
saddr_non_zero(const unsigned char * ucp)
{
    int k;

    for (k = 0; k < 8; ++k) {
        if (ucp[k])
            return 1;
    }
    return 0;
}

static const char * sas_device_type[] = {
    "no SAS device attached",   /* but might be SATA device */
    "end device",
    "expander device",  /* in SAS-1.1 this was a "edge expander device */
    "expander device (fanout, SAS-1.1)",  /* marked obsolete in SAS-2 */
    "reserved [4]", "reserved [5]", "reserved [6]", "reserved [7]"
};

static void
additional_elem_helper(const char * pad, const unsigned char * ucp, int len,
                       int elem_type, const struct opts_t * op)
{
    int ports, phys, j, m, desc_type, eip_offset, print_sas_addr, saddr_nz;
    const unsigned char * per_ucp;
    int nofilter = ! op->do_filter;
    char b[64];

    if (op->inner_hex) {
        for (j = 0; j < len; ++j) {
            if (0 == (j % 16))
                printf("%s%s", ((0 == j) ? "" : "\n"), pad);
            printf("%02x ", ucp[j]);
        }
        printf("\n");
        return;
    }
    eip_offset = (0x10 & ucp[0]) ? 2 : 0;
    switch (0xf & ucp[0]) {
    case TPROTO_FCP:
        printf("%sTransport protocol: FCP\n", pad);
        if (len < (12 + eip_offset))
            break;
        ports = ucp[2 + eip_offset];
        printf("%snumber of ports: %d\n", pad, ports);
        printf("%snode_name: ", pad);
        for (m = 0; m < 8; ++m)
            printf("%02x", ucp[6 + eip_offset + m]);
        if (eip_offset)
            printf(", device slot number: %d", ucp[5 + eip_offset]);
        printf("\n");
        per_ucp = ucp + 14 + eip_offset;
        for (j = 0; j < ports; ++j, per_ucp += 16) {
            printf("%s  port index: %d, port loop position: %d, port "
                   "bypass reason: 0x%x\n", pad, j, per_ucp[0], per_ucp[1]);
            printf("%srequested hard address: %d, n_port identifier: "
                   "%02x%02x%02x\n", pad, per_ucp[4], per_ucp[5],
                   per_ucp[6], per_ucp[7]);
            printf("%s  n_port name: ", pad);
            for (m = 0; m < 8; ++m)
                printf("%02x", per_ucp[8 + m]);
            printf("\n");
        }
        break;
    case TPROTO_SAS:
        printf("%sTransport protocol: SAS\n", pad);
        if (len < (4 + eip_offset))
            break;
        desc_type = (ucp[3 + eip_offset] >> 6) & 0x3;
        if (op->verbose > 1)
            printf("%sdescriptor_type: %d\n", pad, desc_type);
        if (0 == desc_type) {
            phys = ucp[2 + eip_offset];
            printf("%snumber of phys: %d, not all phys: %d", pad, phys,
                   ucp[3 + eip_offset] & 1);
            if (eip_offset)
                printf(", device slot number: %d", ucp[5 + eip_offset]);
            printf("\n");
            per_ucp = ucp + 4 + eip_offset + eip_offset;
            for (j = 0; j < phys; ++j, per_ucp += 28) {
                printf("%sphy index: %d\n", pad, j);
                printf("%s  SAS device type: %s\n", pad,
                       sas_device_type[(0x70 & per_ucp[0]) >> 4]);
                if (nofilter || (0xe & per_ucp[2]))
                    printf("%s  initiator port for:%s%s%s\n", pad,
                           ((per_ucp[2] & 8) ? " SSP" : ""),
                           ((per_ucp[2] & 4) ? " STP" : ""),
                           ((per_ucp[2] & 2) ? " SMP" : ""));
                if (nofilter || (0x8f & per_ucp[3]))
                    printf("%s  target port for:%s%s%s%s%s\n", pad,
                           ((per_ucp[3] & 0x80) ? " SATA_port_selector" : ""),
                           ((per_ucp[3] & 8) ? " SSP" : ""),
                           ((per_ucp[3] & 4) ? " STP" : ""),
                           ((per_ucp[3] & 2) ? " SMP" : ""),
                           ((per_ucp[3] & 1) ? " SATA_device" : ""));
                print_sas_addr = 0;
                saddr_nz = saddr_non_zero(per_ucp + 4);
                if (nofilter || saddr_nz) {
                    ++print_sas_addr;
                    printf("%s  attached SAS address: 0x", pad);
                    if (saddr_nz) {
                        for (m = 0; m < 8; ++m)
                            printf("%02x", per_ucp[4 + m]);
                    } else
                        printf("0");
                }
                saddr_nz = saddr_non_zero(per_ucp + 12);
                if (nofilter || saddr_nz) {
                    ++print_sas_addr;
                    printf("\n%s  SAS address: 0x", pad);
                    if (saddr_nz) {
                        for (m = 0; m < 8; ++m)
                            printf("%02x", per_ucp[12 + m]);
                    } else
                        printf("0");
                }
                if (print_sas_addr)
                    printf("\n%s  phy identifier: 0x%x\n", pad, per_ucp[20]);
            }
        } else if (1 == desc_type) {
            phys = ucp[2 + eip_offset];
            if (SAS_EXPANDER_ETC == elem_type) {
                printf("%snumber of phys: %d\n", pad, phys);
                printf("%sSAS address: 0x", pad);
                for (m = 0; m < 8; ++m)
                    printf("%02x", ucp[6 + eip_offset + m]);
                printf("\n");
                per_ucp = ucp + 14 + eip_offset;
                for (j = 0; j < phys; ++j, per_ucp += 2) {
                    printf("%s  [%d] ", pad, j);
                    if (0xff == per_ucp[0])
                        printf("no attached connector");
                    else
                        printf("connector element index: %d", per_ucp[0]);
                    if (0xff != per_ucp[1])
                        printf(", other element index: %d", per_ucp[1]);
                    printf("\n");
                }
            } else if ((SCSI_TPORT_ETC == elem_type) ||
                       (SCSI_IPORT_ETC == elem_type) ||
                       (ENC_ELECTRONICS_ETC == elem_type)) {
                printf("%snumber of phys: %d\n", pad, phys);
                per_ucp = ucp + 6 + eip_offset;
                for (j = 0; j < phys; ++j, per_ucp += 12) {
                    printf("%sphy index: %d\n", pad, j);
                    printf("%s  phy identifier: 0x%x\n", pad, per_ucp[0]);
                    if (0xff == per_ucp[2])
                        printf("%s  no attached connector", pad);
                    else
                        printf("%s  connector element index: %d", pad,
                               per_ucp[2]);
                    if (0xff != per_ucp[3])
                        printf(", other element index: %d", per_ucp[3]);
                    printf("\n");
                    printf("%s  SAS address: 0x", pad);
                    for (m = 0; m < 8; ++m)
                        printf("%02x", per_ucp[4 + m]);
                    printf("\n");
                }
            } else
                printf("%sunrecognised element type [%d] for desc_type "
                       "1\n", pad, elem_type);
        } else
            printf("%sunrecognised descriptor type [%d]\n", pad, desc_type);
        break;
    default:
        printf("%sTransport protocol: %s not decoded\n", pad,
               sg_get_trans_proto_str((0xf & ucp[0]), sizeof(b), b));
        if (op->verbose)
            dStrHex((const char *)ucp, len, 0);
        break;
    }
}

/* DPC_ADD_ELEM_STATUS [0xa]
 * Previously called "Device element status descriptor". Changed "device"
 * to "additional" to allow for SAS expander and SATA devices */
static void
ses_additional_elem_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                        unsigned int ref_gen_code, const unsigned char * resp,
                        int resp_len, const struct opts_t * op)
{
    int j, k, desc_len, elem_type, invalid, el_num, eip, ind, match_ind_th;
    int elem_count, ei, eiioe, my_eiioe_force, num_elems, skip;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const struct type_desc_hdr_t * tp;
    char b[64];

    printf("Additional element status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    last_ucp = resp + resp_len - 1;
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    if (ref_gen_code != gen_code) {
        pr2serr("  <<state of enclosure changed, please try again>>\n");
        return;
    }
    printf("  additional element status descriptor list\n");
    ucp = resp + 8;
    my_eiioe_force = op->eiioe_force;
    for (k = 0, tp = tdhp, elem_count = 0; k < num_telems; ++k, ++tp) {
        elem_type = tp->etype;
        num_elems = tp->num_elements;
        if (! active_et_aesp(elem_type)) {
            elem_count += num_elems;
            continue;   /* skip if not element type of interest */
        }
        if ((ucp + 1) > last_ucp)
            goto truncated;

        /* if eip is 1, do bounds check on the element index */
        if (ucp[0] & 0x10)  /* eip=1 */ {
            ei = ucp[3];
            skip = 0;
            if ((0 == k) && op->eiioe_auto && (1 == ei)) {
                /* heuristic: if first element index in this page is 1
                 * then act as if the EIIOE bit is set. */
                my_eiioe_force = 1;
            }
            eiioe = my_eiioe_force ? 1 : (ucp[2] & 1);
            if (eiioe) {
                if ((ei < (elem_count + k)) ||
                    (ei > (elem_count + k + num_elems))) {
                    elem_count += num_elems;
                    skip = 1;
                }
            } else {
                if ((ei < elem_count) || (ei > elem_count + num_elems)) {
                    elem_count += num_elems;
                    skip = 1;
                }
            }
            if (skip) {
                if (op->verbose > 2)
                    pr2serr("skipping elem_type=0x%x, k=%d due to "
                            "element_index=%d bounds\n  effective eiioe=%d, "
                            "elem_count=%d, num_elems=%d\n", elem_type, k,
                            ei, eiioe, elem_count, num_elems);
                continue;
            }
        }
        match_ind_th = (op->ind_given && (k == op->ind_th));
        if ((! op->ind_given) || (match_ind_th && (-1 == op->ind_indiv))) {
            printf("    Element type: %s, subenclosure id: %d [ti=%d]\n",
                   find_element_tname(elem_type, b, sizeof(b)), tp->se_id, k);
        }
        el_num = 0;
        for (j = 0; j < num_elems; ++j, ucp += desc_len, ++el_num) {
            invalid = !!(ucp[0] & 0x80);
            desc_len = ucp[1] + 2;
            eip = ucp[0] & 0x10;
            eiioe = eip ? (ucp[2] & 1) : 0;
            ind = eip ? ucp[3] : el_num;
            if (op->ind_given) {
                if ((! match_ind_th) || (-1 == op->ind_indiv) ||
                    (el_num != op->ind_indiv))
                    continue;
            }
            if (eip)
                printf("      Element index: %d  eiioe=%d%s\n", ind, eiioe,
                       (((! eiioe) && my_eiioe_force) ?
                        " but overridden" : ""));
            else
                printf("      Element %d descriptor\n", ind);
            if (invalid && (0 == op->inner_hex))
                printf("        flagged as invalid (no further "
                       "information)\n");
            else
                additional_elem_helper("        ", ucp, desc_len, elem_type,
                                       op);
        }
        elem_count += tp->num_elements;
    }
    return;
truncated:
    pr2serr("    <<<additional: response too short>>>\n");
    return;
}

/* DPC_SUBENC_HELP_TEXT [0xb] */
static void
ses_subenc_help_sdg(const unsigned char * resp, int resp_len)
{
    int k, el, num_subs;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;

    printf("Subenclosure help text diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_ucp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n",
            num_subs - 1);
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    ucp = resp + 8;
    for (k = 0; k < num_subs; ++k, ucp += el) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        el = (ucp[2] << 8) + ucp[3] + 4;
        printf("   subenclosure identifier: %d\n", ucp[1]);
        if (el > 4)
            printf("    %.*s\n", el - 4, ucp + 4);
        else
            printf("    <empty>\n");
    }
    return;
truncated:
    pr2serr("    <<<subenc: response too short>>>\n");
    return;
}

/* DPC_SUBENC_STRING [0xc] */
static void
ses_subenc_string_sdg(const unsigned char * resp, int resp_len)
{
    int k, j, el, num_subs;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;

    printf("Subenclosure string in diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_ucp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n",
            num_subs - 1);
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    ucp = resp + 8;
    for (k = 0; k < num_subs; ++k, ucp += el) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        el = (ucp[2] << 8) + ucp[3] + 4;
        printf("   subenclosure identifier: %d\n", ucp[1]);
        if (el > 4) {
            /* dStrHex((const char *)(ucp + 4), el - 4, 0); */
            printf("    ");
            for (j = 0; j < (el - 4); ++j) {
                if ((j > 0) && (0 == (j % 16)))
                    printf("\n    ");
                printf("%02x ", *(ucp + 4 + j));
            }
            printf("\n");
        } else
            printf("    <empty>\n");
    }
    return;
truncated:
    pr2serr("    <<<subence str: response too short>>>\n");
    return;
}

/* DPC_SUBENC_NICKNAME [0xf] */
static void
ses_subenc_nickname_sdg(const unsigned char * resp, int resp_len)
{
    int k, el, num_subs;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;

    printf("Subenclosure nickname status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_ucp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n",
            num_subs - 1);
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    ucp = resp + 8;
    el = 40;
    for (k = 0; k < num_subs; ++k, ucp += el) {
        if ((ucp + el - 1) > last_ucp)
            goto truncated;
        printf("   subenclosure identifier: %d\n", ucp[1]);
        printf("   nickname status: 0x%x\n", ucp[2]);
        printf("   nickname additional status: 0x%x\n", ucp[3]);
        printf("   nickname language code: %.2s\n", ucp + 6);
        printf("   nickname: %.*s\n", 32, ucp + 8);
    }
    return;
truncated:
    pr2serr("    <<<subence str: response too short>>>\n");
    return;
}

/* DPC_SUPPORTED_SES [0xd] */
static void
ses_supported_pages_sdg(const char * leadin, const unsigned char * resp,
                        int resp_len)
{
    int k, code, prev, got1;
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
            for (ap = dp_abbrev, got1 = 0; ap->abbrev; ++ap) {
                if (ap->page_code == code) {
                    printf("%s%s", (got1 ? "," : ""), ap->abbrev);
                    ++got1;
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
    {0x2, "Download complete, updating storage"},
    {0x3, "Updating storage with deferred microcode"},
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
get_mc_status(unsigned char status_val)
{
    const struct diag_page_code * mcsp;

    for (mcsp = mc_status_arr; mcsp->desc; ++mcsp) {
        if (status_val == mcsp->page_code)
            return mcsp->desc;
    }
    return "";
}

/* DPC_DOWNLOAD_MICROCODE [0xe] */
static void
ses_download_code_sdg(const unsigned char * resp, int resp_len)
{
    int k, num_subs;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const char * cp;

    printf("Download microcode status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    num_subs = resp[1] + 1;  /* number of subenclosures (add 1 for primary) */
    last_ucp = resp + resp_len - 1;
    printf("  number of secondary subenclosures: %d\n",
            num_subs - 1);
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    ucp = resp + 8;
    for (k = 0; k < num_subs; ++k, ucp += 16) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        cp = (0 == ucp[1]) ? " [primary]" : "";
        printf("   subenclosure identifier: %d%s\n", ucp[1], cp);
        cp = get_mc_status(ucp[2]);
        if (strlen(cp) > 0) {
            printf("     download microcode status: %s [0x%x]\n", cp, ucp[2]);
            printf("     download microcode additional status: 0x%x\n",
                   ucp[3]);
        } else
            printf("     download microcode status: 0x%x [additional "
                   "status: 0x%x]\n", ucp[2], ucp[3]);
        printf("     download microcode maximum size: %d bytes\n",
               (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7]);
        printf("     download microcode expected buffer id: 0x%x\n", ucp[11]);
        printf("     download microcode expected buffer id offset: %d\n",
               (ucp[12] << 24) + (ucp[13] << 16) + (ucp[14] << 8) + ucp[15]);
    }
    return;
truncated:
    pr2serr("    <<<download: response too short>>>\n");
    return;
}

/* Reads hex data from command line, stdin or a file. Returns 0 on success,
 * 1 otherwise. */
static int
read_hex(const char * inp, unsigned char * arr, int * arr_len, int verb)
{
    int in_len, k, j, m, off, split_line;
    unsigned int h;
    const char * lcp;
    char * cp;
    char * c2p;
    char line[512];
    char carry_over[4];
    FILE * fp = NULL;

    if ((NULL == inp) || (NULL == arr) || (NULL == arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len) {
        *arr_len = 0;
    }
    if (('-' == inp[0]) || ('@' == inp[0])) {    /* read from stdin or file */
        if ('-' == inp[0])
            fp = stdin;
        else {
            fp = fopen(inp + 1, "r");
            if (NULL == fp) {
                pr2serr("read_hex: unable to open file: %s\n", inp + 1);
                return 1;
            }
        }
        carry_over[0] = 0;
        for (j = 0, off = 0; j < MX_DATA_IN; ++j) {
            /* limit lines read to MX_DATA_IN */
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
                        arr[off - 1] = h;       /* back up and overwrite */
                    else {
                        pr2serr("read_hex: carry_over error ['%s'] around "
                                "line %d\n", carry_over, j + 1);
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
                pr2serr("read_hex: syntax error at line %d, pos %d\n", j + 1,
                        m + k + 1);
                goto err_with_fp;
            }
            for (k = 0; k < (MX_DATA_IN - off); ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        pr2serr("read_hex: hex number larger than 0xff in "
                                "line %d, pos %d\n", j + 1,
                                (int)(lcp - line + 1));
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
                    pr2serr("read_hex: error in line %d, at pos %d\n", j + 1,
                            (int)(lcp - line + 1));
                    goto err_with_fp;
                }
            }
            off += k + 1;
            if (off >= MX_DATA_IN)
                break;
        }
        *arr_len = off;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF, ");
        if (in_len != k) {
            pr2serr("read_hex: error at pos %d\n", k + 1);
            return 1;
        }
        for (k = 0; k < MX_DATA_IN; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    pr2serr("read_hex: hex number larger than 0xff at pos "
                            "%d\n", (int)(lcp - inp + 1));
                    return 1;
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
                pr2serr("read_hex: error at pos %d\n", (int)(lcp - inp + 1));
                return 1;
            }
        }
        *arr_len = k + 1;
    }
    if (verb > 3)
        dStrHex((const char *)arr, *arr_len, 0);
    if (fp && (fp != stdin))
        fclose(fp);
    return 0;

err_with_fp:
    if (fp && (fp != stdin))
        fclose(fp);
    return 1;
}

/* Display "status" page (op->page_code). Return 0 for success. */
static int
ses_process_status_page(int sg_fd, struct opts_t * op)
{
    int j, resp_len, res;
    int ret = 0;
    unsigned int ref_gen_code;
    unsigned char *  resp;
    const char * cp;
    struct enclosure_info primary_info;

    resp = (unsigned char *)calloc(op->maxlen, 1);
    if (NULL == resp) {
        pr2serr("process_status_page: unable to allocate %d bytes on heap\n",
                op->maxlen);
        ret = -1;
        goto fini;
    }
    cp = find_in_diag_page_desc(op->page_code);
    ret = do_rec_diag(sg_fd, op->page_code, resp, op->maxlen, op, &resp_len);
    if (ret)
        goto fini;
    if (op->do_raw) {
        if (1 == op->do_raw)
            dStrHex((const char *)resp + 4, resp_len - 4, -1);
        else {
            if (sg_set_binary_mode(STDOUT_FILENO) < 0)
                perror("sg_set_binary_mode");
            dStrRaw((const char *)resp, resp_len);
        }
    } else if (op->do_hex) {
        if (cp)
            printf("Response in hex from diagnostic page: %s\n", cp);
        else
            printf("Response in hex from unknown diagnostic page "
                   "[0x%x]\n", op->page_code);
        dStrHex((const char *)resp, resp_len, 0);
    } else {
        memset(&primary_info, 0, sizeof(primary_info));
        switch (op->page_code) {
        case DPC_SUPPORTED:
            ses_supported_pages_sdg("Supported diagnostic pages",
                                    resp, resp_len);
            break;
        case DPC_CONFIGURATION:
            ses_configuration_sdg(resp, resp_len);
            break;
        case DPC_ENC_STATUS:
            res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                             &ref_gen_code, &primary_info,
                                             op);
            if (res < 0) {
                ret = res;
                goto fini;
            }
            if (primary_info.have_info) {
                printf("  Primary enclosure logical identifier (hex): ");
                for (j = 0; j < 8; ++j)
                    printf("%02x", primary_info.enc_log_id[j]);
                printf("\n");
            }
            ses_enc_status_dp(type_desc_hdr_arr, res, ref_gen_code,
                              resp, resp_len, op);
            break;
        case DPC_HELP_TEXT:
            printf("Help text diagnostic page (for primary "
                   "subenclosure):\n");
            if (resp_len > 4)
                printf("  %.*s\n", resp_len - 4, resp + 4);
            else
                printf("  <empty>\n");
            break;
        case DPC_STRING:
            printf("String In diagnostic page (for primary "
                   "subenclosure):\n");
            if (resp_len > 4)
                dStrHex((const char *)(resp + 4), resp_len - 4, 0);
            else
                printf("  <empty>\n");
            break;
        case DPC_THRESHOLD:
            res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                             &ref_gen_code, &primary_info,
                                             op);
            if (res < 0) {
                ret = res;
                goto fini;
            }
            if (primary_info.have_info) {
                printf("  Primary enclosure logical identifier (hex): ");
                for (j = 0; j < 8; ++j)
                    printf("%02x", primary_info.enc_log_id[j]);
                printf("\n");
            }
            ses_threshold_sdg(type_desc_hdr_arr, res, ref_gen_code,
                              resp, resp_len, op);
            break;
        case DPC_ELEM_DESC:
            res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                             &ref_gen_code, &primary_info,
                                             op);
            if (res < 0) {
                ret = res;
                goto fini;
            }
            if (primary_info.have_info) {
                printf("  Primary enclosure logical identifier (hex): ");
                for (j = 0; j < 8; ++j)
                    printf("%02x", primary_info.enc_log_id[j]);
                printf("\n");
            }
            ses_element_desc_sdg(type_desc_hdr_arr, res, ref_gen_code,
                                 resp, resp_len, op);
            break;
        case DPC_SHORT_ENC_STATUS:
            printf("Short enclosure status diagnostic page, "
                   "status=0x%x\n", resp[1]);
            break;
        case DPC_ENC_BUSY:
            printf("Enclosure Busy diagnostic page, "
                   "busy=%d [vendor specific=0x%x]\n",
                   resp[1] & 1, (resp[1] >> 1) & 0xff);
            break;
        case DPC_ADD_ELEM_STATUS:
            res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                             &ref_gen_code, &primary_info,
                                             op);
            if (res < 0) {
                ret = res;
                goto fini;
            }
            if (primary_info.have_info) {
                printf("  Primary enclosure logical identifier (hex): ");
                for (j = 0; j < 8; ++j)
                    printf("%02x", primary_info.enc_log_id[j]);
                printf("\n");
            }
            ses_additional_elem_sdg(type_desc_hdr_arr, res, ref_gen_code,
                                    resp, resp_len, op);
            break;
        case DPC_SUBENC_HELP_TEXT:
            ses_subenc_help_sdg(resp, resp_len);
            break;
        case DPC_SUBENC_STRING:
            ses_subenc_string_sdg(resp, resp_len);
            break;
        case DPC_SUPPORTED_SES:
            ses_supported_pages_sdg("Supported SES diagnostic pages",
                                    resp, resp_len);
            break;
        case DPC_DOWNLOAD_MICROCODE:
            ses_download_code_sdg(resp, resp_len);
            break;
        case DPC_SUBENC_NICKNAME:
            ses_subenc_nickname_sdg(resp, resp_len);
            break;
        default:
            printf("Cannot decode response from diagnostic "
                   "page: %s\n", (cp ? cp : "<unknown>"));
            dStrHex((const char *)resp, resp_len, 0);
        }
    }
    ret = 0;

fini:
    if (resp)
        free(resp);
    return ret;
}

static void
devslotnum_and_sasaddr(struct join_row_t * jrp, unsigned char * ae_ucp)
{
    int m;

    if ((0 == jrp) || (0 == ae_ucp) || (0 == (0x10 & ae_ucp[0])))
        return; /* sanity and expect EIP=1 */
    switch (0xf & ae_ucp[0]) {
    case TPROTO_FCP:
        jrp->dev_slot_num = ae_ucp[7];
        break;
    case TPROTO_SAS:
        if (0 == (0xc0 & ae_ucp[5])) {
            /* only for device slot and array device slot elements */
            jrp->dev_slot_num = ae_ucp[7];
            if (ae_ucp[4] > 0) {        /* number of phys */
                /* Use the first phy's "SAS ADDRESS" field */
                for (m = 0; m < 8; ++m)
                    jrp->sas_addr[m] = ae_ucp[(4 + 4 + 12) + m];
            }
        }
        break;
    default:
        ;
    }
}

/* Fetch Configuration, Enclosure Status, Element Descriptor, Additional
 * Element Status and optionally Threshold In pages, place in static arrays.
 * Collate (join) overall and individual elements into the static join_arr[].
 * Returns 0 for success, any other return value is an error. */
static int
join_work(int sg_fd, struct opts_t * op, int display)
{
    int k, j, res, num_t_hdrs, elem_ind, ei, desc_len, dn_len;
    int et4aes, broken_ei, ei2, got1, jr_max_ind, mlen;
    unsigned int ref_gen_code, gen_code;
    struct join_row_t * jrp;
    struct join_row_t * jr2p;
    unsigned char * es_ucp;
    unsigned char * ed_ucp;
    unsigned char * ae_ucp;
    unsigned char * t_ucp;
    /* const unsigned char * es_last_ucp; */
    /* const unsigned char * ed_last_ucp; */
    const unsigned char * ae_last_ucp;
    /* const unsigned char * t_last_ucp; */
    const char * cp;
    const char * enc_state_changed = "  <<state of enclosure changed, "
                                     "please try again>>\n";
    const struct type_desc_hdr_t * tdhp;
    struct enclosure_info primary_info;
    char b[64];

    memset(&primary_info, 0, sizeof(primary_info));
    num_t_hdrs = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                            &ref_gen_code, &primary_info,
                                            op);
    if (num_t_hdrs < 0)
        return num_t_hdrs;
    if (display && primary_info.have_info) {
        printf("  Primary enclosure logical identifier (hex): ");
        for (j = 0; j < 8; ++j)
            printf("%02x", primary_info.enc_log_id[j]);
        printf("\n");
    }
    mlen = sizeof(enc_stat_rsp);
    if (mlen > op->maxlen)
        mlen = op->maxlen;
    res = do_rec_diag(sg_fd, DPC_ENC_STATUS, enc_stat_rsp, mlen, op,
                      &enc_stat_rsp_len);
    if (res)
        return res;
    if (enc_stat_rsp_len < 8) {
        pr2serr("Enclosure Status response too short\n");
        return -1;
    }
    gen_code = (enc_stat_rsp[4] << 24) | (enc_stat_rsp[5] << 16) |
               (enc_stat_rsp[6] << 8) | enc_stat_rsp[7];
    if (ref_gen_code != gen_code) {
        pr2serr("%s", enc_state_changed);
        return -1;
    }
    es_ucp = enc_stat_rsp + 8;
    /* es_last_ucp = enc_stat_rsp + enc_stat_rsp_len - 1; */

    mlen = sizeof(elem_desc_rsp);
    if (mlen > op->maxlen)
        mlen = op->maxlen;
    res = do_rec_diag(sg_fd, DPC_ELEM_DESC, elem_desc_rsp, mlen, op,
                      &elem_desc_rsp_len);
    if (0 == res) {
        if (elem_desc_rsp_len < 8) {
            pr2serr("Element Descriptor response too short\n");
            return -1;
        }
        gen_code = (elem_desc_rsp[4] << 24) | (elem_desc_rsp[5] << 16) |
                   (elem_desc_rsp[6] << 8) | elem_desc_rsp[7];
        if (ref_gen_code != gen_code) {
            pr2serr("%s", enc_state_changed);
            return -1;
        }
        ed_ucp = elem_desc_rsp + 8;
        /* ed_last_ucp = elem_desc_rsp + elem_desc_rsp_len - 1; */
    } else {
        elem_desc_rsp_len = 0;
        ed_ucp = NULL;
        res = 0;
        if (op->verbose)
            pr2serr("  Element Descriptor page not available\n");
    }

    if (display || (DPC_ADD_ELEM_STATUS == op->page_code) ||
        (op->dev_slot_num >= 0) || saddr_non_zero(op->sas_addr)) {
        mlen = sizeof(add_elem_rsp);
        if (mlen > op->maxlen)
            mlen = op->maxlen;
        res = do_rec_diag(sg_fd, DPC_ADD_ELEM_STATUS, add_elem_rsp, mlen, op,
                          &add_elem_rsp_len);
        if (0 == res) {
            if (add_elem_rsp_len < 8) {
                pr2serr("Additional Element Status response too short\n");
                return -1;
            }
            gen_code = (add_elem_rsp[4] << 24) | (add_elem_rsp[5] << 16) |
                       (add_elem_rsp[6] << 8) | add_elem_rsp[7];
            if (ref_gen_code != gen_code) {
                pr2serr("%s", enc_state_changed);
                return -1;
            }
            ae_ucp = add_elem_rsp + 8;
            ae_last_ucp = add_elem_rsp + add_elem_rsp_len - 1;
            if (op->eiioe_auto && (add_elem_rsp_len > 11)) {
                /* heuristic: if first element index in this page is 1
                 * then act as if the EIIOE bit is set. */
                if ((ae_ucp[0] & 0x10) && (1 == ae_ucp[3]))
                    op->eiioe_force = 1;
            }
        } else {
            add_elem_rsp_len = 0;
            ae_ucp = NULL;
            ae_last_ucp = NULL;
            res = 0;
            if (op->verbose)
                pr2serr("  Additional Element Status page not available\n");
        }
    } else {
        ae_ucp = NULL;
        ae_last_ucp = NULL;
    }

    if ((op->do_join > 1) ||
        ((0 == display) && (DPC_THRESHOLD == op->page_code))) {
        mlen = sizeof(threshold_rsp);
        if (mlen > op->maxlen)
            mlen = op->maxlen;
        res = do_rec_diag(sg_fd, DPC_THRESHOLD, threshold_rsp, mlen, op,
                          &threshold_rsp_len);
        if (0 == res) {
            if (threshold_rsp_len < 8) {
                pr2serr("Threshold In response too short\n");
                return -1;
            }
            gen_code = (threshold_rsp[4] << 24) | (threshold_rsp[5] << 16) |
                       (threshold_rsp[6] << 8) | threshold_rsp[7];
            if (ref_gen_code != gen_code) {
                pr2serr("%s", enc_state_changed);
                return -1;
            }
            t_ucp = threshold_rsp + 8;
            /* t_last_ucp = threshold_rsp + threshold_rsp_len - 1; */
        } else {
            threshold_rsp_len = 0;
            t_ucp = NULL;
            res = 0;
            if (op->verbose)
                pr2serr("  Threshold In page not available\n");
        }
    } else {
        threshold_rsp_len = 0;
        t_ucp = NULL;
    }

    jrp = join_arr;
    tdhp = type_desc_hdr_arr;
    jr_max_ind = 0;
    for (k = 0, ei = 0, ei2 = 0; k < num_t_hdrs; ++k, ++tdhp) {
        jrp->el_ind_th = k;
        jrp->el_ind_indiv = -1;
        jrp->etype = tdhp->etype;
        jrp->ei_asc = -1;
        et4aes = active_et_aesp(tdhp->etype);
        jrp->ei_asc2 = -1;
        jrp->se_id = tdhp->se_id;
        /* check es_ucp < es_last_ucp still in range */
        jrp->enc_statp = es_ucp;
        es_ucp += 4;
        jrp->elem_descp = ed_ucp;
        if (ed_ucp)
            ed_ucp += (ed_ucp[2] << 8) + ed_ucp[3] + 4;
        jrp->add_elem_statp = NULL;
        jrp->thresh_inp = t_ucp;
        jrp->dev_slot_num = -1;
        /* assume sas_addr[8] zeroed since it's static file scope */
        if (t_ucp)
            t_ucp += 4;
        ++jrp;
        for (j = 0, elem_ind = 0; j < tdhp->num_elements;
             ++j, ++jrp, ++elem_ind) {
            if (jrp >= join_arr_lastp)
                break;
            jrp->el_ind_th = k;
            jrp->el_ind_indiv = elem_ind;
            jrp->ei_asc = ei++;
            if (et4aes)
                jrp->ei_asc2 = ei2++;
            else
                jrp->ei_asc2 = -1;
            jrp->etype = tdhp->etype;
            jrp->se_id = tdhp->se_id;
            jrp->enc_statp = es_ucp;
            es_ucp += 4;
            jrp->elem_descp = ed_ucp;
            if (ed_ucp)
                ed_ucp += (ed_ucp[2] << 8) + ed_ucp[3] + 4;
            jrp->thresh_inp = t_ucp;
            jrp->dev_slot_num = -1;
            /* assume sas_addr[8] zeroed since it's static file scope */
            if (t_ucp)
                t_ucp += 4;
            jrp->add_elem_statp = NULL;
            ++jr_max_ind;
        }
        if (jrp >= join_arr_lastp) {
            ++k;
            break;      /* leave last row all zeros */
        }
    }

    broken_ei = 0;
    if (ae_ucp) {
        int eip, eiioe;
        int aes_i = 0;
        int get_out = 0;

        jrp = join_arr;
        tdhp = type_desc_hdr_arr;
        for (k = 0; k < num_t_hdrs; ++k, ++tdhp) {
            if (active_et_aesp(tdhp->etype)) {
                /* only consider element types that AES element are permiited
                 * to refer to, then loop over those number of elements */
                for (j = 0; j < tdhp->num_elements; ++j) {
                    if ((ae_ucp + 1) > ae_last_ucp) {
                        get_out = 1;
                        if (op->verbose || op->warn)
                            pr2serr("warning: %s: off end of ae page\n",
                                    __func__);
                        break;
                    }
                    eip = !!(ae_ucp[0] & 0x10); /* element index present */
                    if (eip)
                        eiioe = op->eiioe_force ? 1 : (ae_ucp[2] & 1);
                    else
                        eiioe = 0;
                    if (eip && eiioe) {
                        ei = ae_ucp[3];
                        jr2p = join_arr + ei;
                        if ((ei >= jr_max_ind) || (NULL == jr2p->enc_statp)) {
                            get_out = 1;
                            pr2serr("%s: oi=%d, ei=%d [max_ind=%d], eiioe=1 "
                                    "not in join_arr\n", __func__, k, ei,
                                    jr_max_ind);
                            break;
                        }
                        devslotnum_and_sasaddr(jr2p, ae_ucp);
                        if (jr2p->add_elem_statp) {
                            if (op->warn || op->verbose)
                                pr2serr("warning: aes slot busy [oi=%d, "
                                        "ei=%d, aes_i=%d]\n", k, ei, aes_i);
                        } else
                            jr2p->add_elem_statp = ae_ucp;
                    } else if (eip) {     /* and EIIOE=0 */
                        ei = ae_ucp[3];
try_again:
                        for (jr2p = join_arr; jr2p->enc_statp; ++jr2p) {
                            if (broken_ei) {
                                if (ei == jr2p->ei_asc2)
                                    break;
                            } else {
                                if (ei == jr2p->ei_asc)
                                    break;
                            }
                        }
                        if (NULL == jr2p->enc_statp) {
                            get_out = 1;
                            pr2serr("warning: %s: oi=%d, ei=%d (broken_ei=%d) "
                                    "not in join_arr\n", __func__, k, ei,
                                    broken_ei);
                            break;
                        }
                        if (! active_et_aesp(jr2p->etype)) {
                            /* broken_ei must be 0 for that to be false */
                            ++broken_ei;
                            goto try_again;
                        }
                        devslotnum_and_sasaddr(jr2p, ae_ucp);
                        if (jr2p->add_elem_statp) {
                            if (op->warn || op->verbose)
                                pr2serr("warning: aes slot busy [oi=%d, "
                                        "ei=%d, aes_i=%d]\n", k, ei, aes_i);
                        } else
                            jr2p->add_elem_statp = ae_ucp;
                    } else {    /* EIP=0 */
                        while (jrp->enc_statp && ((-1 == jrp->el_ind_indiv) ||
                                                  jrp->add_elem_statp))
                            ++jrp;
                        if (NULL == jrp->enc_statp) {
                            get_out = 1;
                            pr2serr("warning: %s: join_arr has no space for "
                                    "ae\n", __func__);
                            break;
                        }
                        jrp->add_elem_statp = ae_ucp;
                        ++jrp;
                    }
                    ae_ucp += ae_ucp[1] + 2;
                    ++aes_i;
                }
            } else {    /* element type not relevant to ae status */
                /* step over overall and individual elements */
                for (j = 0; j <= tdhp->num_elements; ++j, ++jrp) {
                    if (NULL == jrp->enc_statp) {
                        get_out = 1;
                        pr2serr("warning: %s: join_arr has no space\n",
                                __func__);
                        break;
                    }
                }
            }
            if (get_out)
                break;
        }
    }

    if (op->verbose > 3) {
        jrp = join_arr;
        for (k = 0; ((k < MX_JOIN_ROWS) && jrp->enc_statp); ++k, ++jrp) {
            pr2serr("el_ind_th=%d el_ind_indiv=%d etype=%d se_id=%d ei=%d "
                    "ei2=%d dsn=%d sa=0x", jrp->el_ind_th, jrp->el_ind_indiv,
                    jrp->etype, jrp->se_id, jrp->ei_asc, jrp->ei_asc2,
                    jrp->dev_slot_num);
            if (saddr_non_zero(jrp->sas_addr)) {
                for (j = 0; j < 8; ++j)
                    pr2serr("%02x", jrp->sas_addr[j]);
            } else
                pr2serr("0");
            pr2serr(" %s %s %s %s\n", (jrp->enc_statp ? "ES" : ""),
                    (jrp->elem_descp ? "ED" : ""),
                    (jrp->add_elem_statp ? "AES" : ""),
                    (jrp->thresh_inp ? "TI" : ""));
        }
        pr2serr(">> elements in join_arr: %d, broken_ei=%d\n", k, broken_ei);
    }

    if (! display)      /* probably wanted join_arr[] built only */
        return 0;

    /* Display contents of join_arr */
    dn_len = op->desc_name ? (int)strlen(op->desc_name) : 0;
    for (k = 0, jrp = join_arr, got1 = 0;
         ((k < MX_JOIN_ROWS) && jrp->enc_statp); ++k, ++jrp) {
        if (op->ind_given) {
            if (op->ind_th != jrp->el_ind_th)
                continue;
            if (op->ind_indiv != jrp->el_ind_indiv)
                continue;
        }
        ed_ucp = jrp->elem_descp;
        if (op->desc_name) {
            if (NULL == ed_ucp)
                continue;
            desc_len = (ed_ucp[2] << 8) + ed_ucp[3];
            /* some element descriptor strings have a trailing NULL and
             * count it in their length; adjust */
            if ('\0' == ed_ucp[4 + desc_len - 1])
                --desc_len;
            if (desc_len != dn_len)
                continue;
            if (0 != strncmp(op->desc_name, (const char *)(ed_ucp + 4),
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
        ++got1;
        if ((op->do_filter > 1) && (1 != (0xf & jrp->enc_statp[0])))
            continue;   /* when '-ff' and status!=OK, skip */
        cp = find_element_tname(jrp->etype, b, sizeof(b));
        if (ed_ucp) {
            desc_len = (ed_ucp[2] << 8) + ed_ucp[3] + 4;
            if (desc_len > 4)
                printf("%.*s [%d,%d]  Element type: %s\n", desc_len - 4,
                       (const char *)(ed_ucp + 4), jrp->el_ind_th,
                       jrp->el_ind_indiv, cp);
            else
                printf("[%d,%d]  Element type: %s\n", jrp->el_ind_th,
                       jrp->el_ind_indiv, cp);
        } else
            printf("[%d,%d]  Element type: %s\n", jrp->el_ind_th,
                   jrp->el_ind_indiv, cp);
        printf("  Enclosure Status:\n");
        enc_status_helper("    ", jrp->enc_statp, jrp->etype, op);
        if (jrp->add_elem_statp) {
            printf("  Additional Element Status:\n");
            ae_ucp = jrp->add_elem_statp;
            desc_len = ae_ucp[1] + 2;
            additional_elem_helper("    ",  ae_ucp, desc_len, jrp->etype, op);
        }
        if (jrp->thresh_inp) {
            printf("  Threshold In:\n");
            t_ucp = jrp->thresh_inp;
            ses_threshold_helper("    ", t_ucp, jrp->etype, op);
        }
    }
    if (0 == got1) {
        if (op->ind_given)
            printf("      >>> no match on --index=%d,%d\n", op->ind_th,
                   op->ind_indiv);
        else if (op->desc_name)
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
    return res;
}

static uint64_t
get_big_endian(const unsigned char * from, int start_bit, int num_bits)
{
    uint64_t res;
    int sbit_o1 = start_bit + 1;

    res = (*from++ & ((1 << sbit_o1) - 1));
    num_bits -= sbit_o1;
    while (num_bits > 0) {
        res <<= 8;
        res |= *from++;
        num_bits -= 8;
    }
    if (num_bits < 0)
        res >>= (-num_bits);
    return res;
}

static void
set_big_endian(uint64_t val, unsigned char * to, int start_bit, int num_bits)
{
    int sbit_o1 = start_bit + 1;
    int mask, num, k, x;

    mask = (8 != sbit_o1) ? ((1 << sbit_o1) - 1) : 0xff;
    k = start_bit - ((num_bits - 1) % 8);
    if (0 != k)
        val <<= ((k > 0) ? k : (8 + k));
    num = (num_bits + 15 - sbit_o1) / 8;
    for (k = 0; k < num; ++k) {
        if ((sbit_o1 - num_bits) > 0)
            mask &= ~((1 << (sbit_o1 - num_bits)) - 1);
        if (k < (num - 1))
            x = (val >> ((num - k - 1) * 8)) & 0xff;
        else
            x = val & 0xff;
        to[k] = (to[k] & ~mask) | (x & mask);
        mask = 0xff;
        num_bits -= sbit_o1;
        sbit_o1 = 8;
    }
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

static int
is_acronym_in_status_ctl(const struct tuple_acronym_val * tavp)
{
    const struct acronym2tuple * ap;

    for (ap = ecs_a2t_arr; ap->acron; ++ ap) {
        if (strcase_eq(tavp->acron, ap->acron))
            break;
    }
    return (ap->acron ? 1 : 0);
}

static int
is_acronym_in_threshold(const struct tuple_acronym_val * tavp)
{
    const struct acronym2tuple * ap;

    for (ap = th_a2t_arr; ap->acron; ++ ap) {
        if (strcase_eq(tavp->acron, ap->acron))
            break;
    }
    return (ap->acron ? 1 : 0);
}

static int
is_acronym_in_additional(const struct tuple_acronym_val * tavp)
{
    const struct acronym2tuple * ap;

    for (ap = ae_sas_a2t_arr; ap->acron; ++ ap) {
        if (strcase_eq(tavp->acron, ap->acron))
            break;
    }
    return (ap->acron ? 1 : 0);
}

/* DPC_ENC_STATUS  DPC_ENC_CONTROL
 * Do clear/get/set (cgs) on Enclosure Control/Status page. Return 0 for ok
 * -2 for acronym not found, else -1 . */
static int
cgs_enc_ctl_stat(int sg_fd, const struct join_row_t * jrp,
                 const struct tuple_acronym_val * tavp,
                 const struct opts_t * op)
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
    if (op->get_str) {
        ui = get_big_endian(jrp->enc_statp + s_byte, s_bit, n_bits);
        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {    /* --set or --clear */
        if (jrp->etype < NUM_ETC) {
            for (k = 0; k < 4; ++k)
                jrp->enc_statp[k] &= ses3_element_cmask_arr[jrp->etype][k];
        } else
            jrp->enc_statp[0] &= 0x40;  /* keep PRDFAIL is set in byte 0 */
        set_big_endian((uint64_t)tavp->val,
                       jrp->enc_statp + s_byte, s_bit, n_bits);
        jrp->enc_statp[0] |= 0x80;  /* set SELECT bit */
        if (op->byte1_given)
            enc_stat_rsp[1] = op->byte1;
        len = (enc_stat_rsp[2] << 8) + enc_stat_rsp[3] + 4;
        ret = do_senddiag(sg_fd, 1, enc_stat_rsp, len, 1, op->verbose);
        if (ret) {
            pr2serr("couldn't send Enclosure Control page\n");
            return -1;
        }
    }
    return 0;
}

/* DPC_THRESHOLD
 * Do clear/get/set (cgs) on Threshold In/Out page. Return 0 for ok,
 * -2 for acronym not found, else -1 . */
static int
cgs_threshold(int sg_fd, const struct join_row_t * jrp,
              const struct tuple_acronym_val * tavp,
              const struct opts_t * op)
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
    if (op->get_str) {
        ui = get_big_endian(jrp->thresh_inp + s_byte, s_bit, n_bits);
        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {
        set_big_endian((uint64_t)tavp->val,
                       jrp->thresh_inp + s_byte, s_bit, n_bits);
        if (op->byte1_given)
            threshold_rsp[1] = op->byte1;
        len = (threshold_rsp[2] << 8) + threshold_rsp[3] + 4;
        ret = do_senddiag(sg_fd, 1, threshold_rsp, len, 1, op->verbose);
        if (ret) {
            pr2serr("couldn't send Threshold Out page\n");
            return -1;
        }
    }
    return 0;
}

/* DPC_ADD_ELEM_STATUS
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

    if (NULL == jrp->add_elem_statp) {
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
    if (op->get_str) {
        ui = get_big_endian(jrp->add_elem_statp + s_byte, s_bit, n_bits);
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
ses_cgs(int sg_fd, const struct tuple_acronym_val * tavp,
        struct opts_t * op)
{
    int ret, k, j, desc_len, dn_len, found;
    const struct join_row_t * jrp;
    const unsigned char * ed_ucp;
    char b[64];

    found = 0;
    if (NULL == tavp->acron) {
        if (! op->page_code_given)
            op->page_code = DPC_ENC_CONTROL;
        ++found;
    } else if (is_acronym_in_status_ctl(tavp)) {
        op->page_code = DPC_ENC_CONTROL;
        ++found;
    } else if (is_acronym_in_threshold(tavp)) {
        op->page_code = DPC_THRESHOLD;
        ++found;
    } else if (is_acronym_in_additional(tavp)) {
        op->page_code = DPC_ADD_ELEM_STATUS;
        ++found;
    }
    if (! found) {
        pr2serr("acroynm %s not found (try '-ee' option)\n", tavp->acron);
        return -1;
    }
    ret = join_work(sg_fd, op, 0);
    if (ret)
        return ret;
    dn_len = op->desc_name ? (int)strlen(op->desc_name) : 0;
    for (k = 0, jrp = join_arr; ((k < MX_JOIN_ROWS) && jrp->enc_statp);
         ++k, ++jrp) {
        if (op->ind_given) {
            if (op->ind_th != jrp->el_ind_th)
                continue;
            if (op->ind_indiv != jrp->el_ind_indiv)
                continue;
        } else if (op->desc_name) {
            ed_ucp = jrp->elem_descp;
            if (NULL == ed_ucp)
                continue;
            desc_len = (ed_ucp[2] << 8) + ed_ucp[3];
            /* some element descriptor strings have a trailing NULL and
             * count it; adjust */
            if ('\0' == ed_ucp[4 + desc_len - 1])
                --desc_len;
            if (desc_len != dn_len)
                continue;
            if (0 != strncmp(op->desc_name, (const char *)(ed_ucp + 4),
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
        if (DPC_ENC_CONTROL == op->page_code)
            ret = cgs_enc_ctl_stat(sg_fd, jrp, tavp, op);
        else if (DPC_THRESHOLD == op->page_code)
            ret = cgs_threshold(sg_fd, jrp, tavp, op);
        else if (DPC_ADD_ELEM_STATUS == op->page_code)
            ret = cgs_additional_el(jrp, tavp, op);
        else {
            pr2serr("page %s not supported for cgs\n",
                    find_element_tname(op->page_code, b, sizeof(b)));
            ret = -1;
        }
        if (ret)
            return ret;
        break;
    }
    if ((NULL == jrp->enc_statp) || (k >= MX_JOIN_ROWS)) {
        if (op->desc_name)
            pr2serr("descriptor name: %s not found (check the 'ed' page "
                    "[0x7])\n", op->desc_name);
        else if (op->dev_slot_num >= 0)
            pr2serr("device slot number: %d not found\n", op->dev_slot_num);
        else if (saddr_non_zero(op->sas_addr))
            pr2serr("SAS address not found\n");
        else
            pr2serr("index: %d,%d not found\n", op->ind_th, op->ind_indiv);
        return -1;
    }
    return 0;
}

/* Called when '--nickname=SEN' given. First calls status page to fetch
 * the generation code. Returns 0 for success, any other return value is
 * an error. */
static int
ses_set_nickname(int sg_fd, struct opts_t * op)
{
    int res, len;
    int resp_len = 0;
    unsigned char b[64];
    const int control_plen = 0x24;

    memset(b, 0, sizeof(b));
    /* Only after the generation code, offset 4 for 4 bytes */
    res = do_rec_diag(sg_fd, DPC_SUBENC_NICKNAME, b, 8, op, &resp_len);
    if (res) {
        pr2serr("set_nickname: Subenclosure nickname status page, res=%d\n",
                res);
        return -1;
    }
    if (resp_len < 8) {
        pr2serr("set_nickname: Subenclosure nickname status page, response "
                "length too short: %d\n", resp_len);
        return -1;
    }
    if (op->verbose) {
        unsigned int gc;

        gc = (b[4] << 24) + (b[5] << 16) + (b[6] << 8) + b[7];
        pr2serr("set_nickname: generation code from status page: %u\n", gc);
    }
    b[0] = (unsigned char)DPC_SUBENC_NICKNAME;  /* just in case */
    b[1] = (unsigned char)op->seid;
    b[2] = (unsigned char)(control_plen >> 8);
    b[3] = (unsigned char)control_plen;
    len = strlen(op->nickname_str);
    if (len > 32)
        len = 32;
    memcpy(b + 8, op->nickname_str, len);
    return do_senddiag(sg_fd, 1, b, control_plen + 4, 1, op->verbose);
}

static void
enumerate_diag_pages(void)
{
    const struct diag_page_code * pcdp;
    const struct diag_page_abbrev * ap;
    int got1;

    printf("Diagnostic pages, followed by abbreviation(s) then page code:\n");
    for (pcdp = dpc_arr; pcdp->desc; ++pcdp) {
        printf("    %s  [", pcdp->desc);
        for (ap = dp_abbrev, got1 = 0; ap->abbrev; ++ap) {
            if (ap->page_code == pcdp->page_code) {
                printf("%s%s", (got1 ? "," : ""), ap->abbrev);
                ++got1;
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
    num = op->enumerate + op->do_list;
    if (num < 2) {
        enumerate_diag_pages();
        printf("\nSES element type names, followed by abbreviation and "
               "element type code:\n");
        for (etp = element_type_arr; etp->desc; ++etp)
            printf("    %s  [%s] [0x%x]\n", etp->desc, etp->abbrev,
                   etp->elem_type_code);
    } else {
        /* command line has multiple --enumerate and/or --list options */
        printf("--clear, --get, --set acronyms for Enclosure Status/Control "
               "['es' or 'ec'] page:\n");
        for (ap = ecs_a2t_arr; ap->acron; ++ap) {
            cp = (ap->etype < 0) ?
                         "*" : find_element_tname(ap->etype, b, sizeof(b));
            snprintf(a, sizeof(a), "  %s  [%s] [%d:%d:%d]", ap->acron,
                     (cp ? cp : "??"), ap->start_byte, ap->start_bit,
                     ap->num_bits);
            if (ap->info)
                printf("%-44s  %s\n", a, ap->info);
            else
                printf("%s\n", a);
        }
        printf("\n--clear, --get, --set acronyms for Threshold In/Out "
               "['th'] page:\n");
        for (ap = th_a2t_arr; ap->acron; ++ap) {
            cp = (ap->etype < 0) ? "*" :
                         find_element_tname(ap->etype, b, sizeof(b));
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
            cp = (ap->etype < 0) ? "*" :
                        find_element_tname(ap->etype, b, sizeof(b));
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
    int sg_fd, res;
    char buff[128];
    char b[80];
    int pd_type = 0;
    int have_cgs = 0;
    int ret = 0;
    struct sg_simple_inquiry_resp inq_resp;
    const char * cp;
    struct opts_t opts;
    struct opts_t * op;
    struct tuple_acronym_val tav;

    op = &opts;
    memset(op, 0, sizeof(*op));
    res = cl_process(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (op->do_version) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }
    if (op->do_help) {
        usage(op->do_help);
        return 0;
    }
    if (op->enumerate || op->do_list) {
        enumerate_work(op);
        return 0;
    }
    if (op->num_cgs) {
        have_cgs = 1;
        cp = op->clear_str ? op->clear_str :
             (op->get_str ? op->get_str : op->set_str);
        strncpy(buff, cp, sizeof(buff) - 1);
        buff[sizeof(buff) - 1] = '\0';
        if (parse_cgs_str(buff, &tav)) {
            pr2serr("unable to decode STR argument to --clear, --get or "
                    "--set\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (op->get_str && tav.val_str)
            pr2serr("--get option ignoring =<val> at the end of STR "
                    "argument\n");
        if (! (op->ind_given || op->desc_name || (op->dev_slot_num >= 0) ||
               saddr_non_zero(op->sas_addr))) {
            pr2serr("with --clear, --get or --set option need either\n   "
                    "--index, --descriptor, --dev-slot-num or --sas-addr\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (NULL == tav.val_str) {
            if (op->clear_str)
                tav.val = 0;
            if (op->set_str)
                tav.val = 1;
        }
        if (op->page_code_given && (DPC_ENC_STATUS != op->page_code) &&
            (DPC_THRESHOLD != op->page_code) &&
            (DPC_ADD_ELEM_STATUS != op->page_code)) {
            pr2serr("--clear, --get or --set options only supported for the "
                    "Enclosure\nControl/Status, Threshold In/Out and "
                    "Additional Element Status pages\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (op->verbose > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    if (op->maxlen >= 16384)
        scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif
    sg_fd = sg_cmds_open_device(op->dev_name, op->o_readonly, op->verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", op->dev_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (! (op->do_raw || have_cgs)) {
        if (sg_simple_inquiry(sg_fd, &inq_resp, 1, op->verbose)) {
            pr2serr("%s doesn't respond to a SCSI INQUIRY\n", op->dev_name);
            ret = SG_LIB_CAT_OTHER;
            goto err_out;
        } else {
            printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor,
                   inq_resp.product, inq_resp.revision);
            pd_type = inq_resp.peripheral_type;
            cp = sg_get_pdt_str(pd_type, sizeof(buff), buff);
            if (0xd == pd_type) {
                if (op->verbose)
                    printf("    enclosure services device\n");
            } else if (0x40 & inq_resp.byte_6)
                printf("    %s device has EncServ bit set\n", cp);
            else
                printf("    %s device (not an enclosure)\n", cp);
        }
    }

    if (op->nickname_str)
        ret = ses_set_nickname(sg_fd, op);
    else if (have_cgs)
        ret = ses_cgs(sg_fd, &tav, op);
    else if (op->do_join)
        ret = join_work(sg_fd, op, 1);
    else if (op->do_status)
        ret = ses_process_status_page(sg_fd, op);
    else { /* control page requested */
        op->data_arr[0] = op->page_code;
        op->data_arr[1] = op->byte1;
        op->data_arr[2] = (op->arr_len >> 8) & 0xff;
        op->data_arr[3] = op->arr_len & 0xff;
        switch (op->page_code) {
        case DPC_ENC_CONTROL:  /* Enclosure Control diagnostic page [0x2] */
            printf("Sending Enclosure Control [0x%x] page, with page "
                   "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(sg_fd, 1, op->data_arr, op->arr_len + 4, 1,
                              op->verbose);
            if (ret) {
                pr2serr("couldn't send Enclosure Control page\n");
                goto err_out;
            }
            break;
        case DPC_STRING:       /* String Out diagnostic page [0x4] */
            printf("Sending String Out [0x%x] page, with page length=%d "
                   "bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(sg_fd, 1, op->data_arr, op->arr_len + 4, 1,
                              op->verbose);
            if (ret) {
                pr2serr("couldn't send String Out page\n");
                goto err_out;
            }
            break;
        case DPC_THRESHOLD:       /* Threshold Out diagnostic page [0x5] */
            printf("Sending Threshold Out [0x%x] page, with page length=%d "
                   "bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(sg_fd, 1, op->data_arr, op->arr_len + 4, 1,
                              op->verbose);
            if (ret) {
                pr2serr("couldn't send Threshold Out page\n");
                goto err_out;
            }
            break;
        case DPC_ARRAY_CONTROL:   /* Array control diagnostic page [0x6] */
            printf("Sending Array Control [0x%x] page, with page "
                   "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(sg_fd, 1, op->data_arr, op->arr_len + 4, 1,
                              op->verbose);
            if (ret) {
                pr2serr("couldn't send Array Control page\n");
                goto err_out;
            }
            break;
        case DPC_SUBENC_STRING: /* Subenclosure String Out page [0xc] */
            printf("Sending Subenclosure String Out [0x%x] page, with page "
                   "length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(sg_fd, 1, op->data_arr, op->arr_len + 4, 1,
                              op->verbose);
            if (ret) {
                pr2serr("couldn't send Subenclosure String Out page\n");
                goto err_out;
            }
            break;
        case DPC_DOWNLOAD_MICROCODE: /* Download Microcode Control [0xe] */
            printf("Sending Download Microcode Control [0x%x] page, with "
                   "page length=%d bytes\n", op->page_code, op->arr_len);
            printf("  Perhaps it would be better to use the sg_ses_microcode "
                   "utility\n");
            ret = do_senddiag(sg_fd, 1, op->data_arr, op->arr_len + 4, 1,
                              op->verbose);
            if (ret) {
                pr2serr("couldn't send Download Microcode Control page\n");
                goto err_out;
            }
            break;
        case DPC_SUBENC_NICKNAME: /* Subenclosure Nickname Control [0xf] */
            printf("Sending Subenclosure Nickname Control [0x%x] page, with "
                   "page length=%d bytes\n", op->page_code, op->arr_len);
            ret = do_senddiag(sg_fd, 1, op->data_arr, op->arr_len + 4, 1,
                              op->verbose);
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
    if (0 == op->do_status) {
        sg_get_category_sense_str(ret, sizeof(b), b, op->verbose);
        pr2serr("    %s\n", b);
    }
    if (ret && (0 == op->verbose))
        pr2serr("Problem detected, try again with --verbose option for more "
                "information\n");
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
