/*
 * Copyright (c) 2004-2011 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

/*
 * This program issues SCSI SEND DIAGNOSTIC and RECEIVE DIAGNOSTIC RESULTS
 * commands tailored for SES (enclosure) devices.
 */

static char * version_str = "1.56 20110622";    /* ses3r03 */

#define MX_ALLOC_LEN 4096
#define MX_ELEM_HDR 1024
#define MX_DATA_IN 2048
#define MX_JOIN_ROWS 260

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
#define DOOR_LOCK_ETC 0x5
#define AUD_ALARM_ETC 0x6
#define ESC_ELECTRONICS_ETC 0x7
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


struct opts_t {
    int byte1;
    int byte1_given;
    int do_control;
    int do_data;
    int do_filter;
    int do_help;
    int do_hex;
    int index_given;    /* 1 -> index_elem; 2 -> index_overall */
    int index_elem_ov;
    int inner_hex;
    int do_join;
    int do_list;
    int page_code;
    int page_code_given;
    int do_raw;
    int do_status;
    int verbose;
    int do_version;
    int arr_len;
    unsigned char data_arr[MX_DATA_IN + 16];
    const char * clear_str;
    const char * desc_name;
    const char * get_str;
    const char * set_str;
    const char * device_name;
};

struct diag_page_code {
    int page_code;
    const char * desc;
};

struct element_type_t {
    int elem_type_code;
    const char * desc;
};

/* The Configuration diagnostic page contains one or more of these. The
 * elements of the Enclosure control/status and threshold in/page follow
 * this format. The additional element status page is closely related to
 * this format (with the overall elements excluded). */
struct type_desc_hdr_t {
    unsigned char etype;        /* element type code (0: unspecified) */
    unsigned char num_elements; /* number of possible elements, excluding
                                 * overall element */
    unsigned char se_id;        /* subenclosure id (0 for main enclosure) */
    unsigned char unused;       /* type descriptor text length; not needed */
};

/* A SQL-like join of the Enclosure status, Threshold in and Additional
 * element status pages based of the format indicated in the Configuration
 * page. */
struct join_row_t {
    short el_ov_ind;            /* element index 0 to 999, overall index
                                 * offset by 1000. So 1000 is ov_ind 0 */
    unsigned char etype;        /* element type */
    unsigned char se_id;        /* subenclosure id (0 for main enclosure) */
    /* following point into Element Descriptor, Enclosure Status, Threshold
     * In and Additional element status diagnostic pages. enc_statp only
     * NULL past last, other pointers can be NULL . */
    unsigned char * elem_descp;
    unsigned char * enc_statp;    /* NULL indicates past last */
    unsigned char * thresh_inp;
    unsigned char * add_elem_statp;
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
    int start_byte;
    int start_bit;
    int num_bits;
};


static struct type_desc_hdr_t type_desc_hdr_arr[MX_ELEM_HDR];

static struct join_row_t join_arr[MX_JOIN_ROWS];
static struct join_row_t * join_arr_lastp = join_arr + MX_JOIN_ROWS - 1;

static unsigned char enc_stat_rsp[MX_ALLOC_LEN];
static unsigned char elem_desc_rsp[MX_ALLOC_LEN];
static unsigned char add_elem_rsp[MX_ALLOC_LEN];
static unsigned char threshold_rsp[MX_ALLOC_LEN];
static int enc_stat_rsp_len;
static int elem_desc_rsp_len;
static int add_elem_rsp_len;
static int threshold_rsp_len;

/* Diagnostic page names, control and/or status (in and/or out) */
static struct diag_page_code dpc_arr[] = {
    {DPC_SUPPORTED, "Supported diagnostic pages"},  /* 0 */
    {DPC_CONFIGURATION, "Configuration (SES)"},
    {DPC_ENC_STATUS, "Enclosure status/control (SES)"},
    {DPC_HELP_TEXT, "Help text (SES)"},
    {DPC_STRING, "String In/Out (SES)"},
    {DPC_THRESHOLD, "Threshold In/Out (SES)"},
    {0x6, "Array Status/Control (SES, obsolete)"},
    {DPC_ELEM_DESC, "Element descriptor (SES)"},
    {DPC_SHORT_ENC_STATUS, "Short enclosure status (SES)"},  /* 8 */
    {DPC_ENC_BUSY, "Enclosure busy (SES-2)"},
    {DPC_ADD_ELEM_STATUS, "Additional element status (SES-2)"},
    {DPC_SUBENC_HELP_TEXT, "Subenclosure help text (SES-2)"},
    {DPC_SUBENC_STRING, "Subenclosure string In/Out (SES-2)"},
    {DPC_SUPPORTED_SES, "Supported SES diagnostic pages (SES-2)"},
    {DPC_DOWNLOAD_MICROCODE, "Download microcode (SES-2)"},
    {DPC_SUBENC_NICKNAME, "Subenclosure nickname (SES-2)"},
    {0x3f, "Protocol specific (SAS transport)"},
    {0x40, "Translate address (SBC)"},
    {0x41, "Device status (SBC)"},
    {-1, NULL},
};

/* Diagnostic page names, for status (or in) pages */
static struct diag_page_code in_dpc_arr[] = {
    {DPC_SUPPORTED, "Supported diagnostic pages"},  /* 0 */
    {DPC_CONFIGURATION, "Configuration (SES)"},
    {DPC_ENC_STATUS, "Enclosure status (SES)"},
    {DPC_HELP_TEXT, "Help text (SES)"},
    {DPC_STRING, "String In (SES)"},
    {DPC_THRESHOLD, "Threshold In (SES)"},
    {0x6, "Array Status (SES, obsolete)"},
    {DPC_ELEM_DESC, "Element descriptor (SES)"},
    {DPC_SHORT_ENC_STATUS, "Short enclosure status (SES)"},  /* 8 */
    {DPC_ENC_BUSY, "Enclosure busy (SES-2)"},
    {DPC_ADD_ELEM_STATUS, "Additional element status (SES-2)"},
    {DPC_SUBENC_HELP_TEXT, "Subenclosure help text (SES-2)"},
    {DPC_SUBENC_STRING, "Subenclosure string In (SES-2)"},
    {DPC_SUPPORTED_SES, "Supported SES diagnostic pages (SES-2)"},
    {DPC_DOWNLOAD_MICROCODE, "Download microcode (SES-2)"},
    {DPC_SUBENC_NICKNAME, "Subenclosure nickname (SES-2)"},
    {0x3f, "Protocol specific (SAS transport)"},
    {0x40, "Translate address (SBC)"},
    {0x41, "Device status (SBC)"},
    {-1, NULL},
};

/* Names of element types used by the Enclosure Control/Status diagnostic
 * page. */
static struct element_type_t element_type_arr[] = {
    {UNSPECIFIED_ETC, "Unspecified"},
    {DEVICE_ETC, "Device slot"},
    {POWER_SUPPLY_ETC, "Power supply"},
    {COOLING_ETC, "Cooling"},
    {TEMPERATURE_ETC, "Temperature sensor"},
    {DOOR_LOCK_ETC, "Door lock"},
    {AUD_ALARM_ETC, "Audible alarm"},
    {ESC_ELECTRONICS_ETC, "Enclosure services controller electronics"},
    {SCC_CELECTR_ETC, "SCC controller electronics"},
    {NV_CACHE_ETC, "Nonvolatile cache"},
    {INV_OP_REASON_ETC, "Invalid operation reason"},
    {UI_POWER_SUPPLY_ETC, "Uninterruptible power supply"},
    {DISPLAY_ETC, "Display"},
    {KEY_PAD_ETC, "Key pad entry"},
    {ENCLOSURE_ETC, "Enclosure"},
    {SCSI_PORT_TRAN_ETC, "SCSI port/transceiver"},
    {LANGUAGE_ETC, "Language"},
    {COMM_PORT_ETC, "Communication port"},
    {VOLT_SENSOR_ETC, "Voltage sensor"},
    {CURR_SENSOR_ETC, "Current sensor"},
    {SCSI_TPORT_ETC, "SCSI target port"},
    {SCSI_IPORT_ETC, "SCSI initiator port"},
    {SIMPLE_SUBENC_ETC, "Simple subenclosure"},
    {ARRAY_DEV_ETC, "Array device slot"},
    {SAS_EXPANDER_ETC, "SAS expander"},
    {SAS_CONNECTOR_ETC, "SAS connector"},
    {-1, NULL},
};

/* Many control element names below have "RQST" in front in drafts.
   These are for the Enclosure control/status diagnostic page */
static struct acronym2tuple ecs_a2t_arr[] = {
   {"active", DEVICE_ETC, 2, 7, 1},
   {"active", ARRAY_DEV_ETC, 2, 7, 1},
   {"disable", -1, 0, 5, 1},
   {"devoff", DEVICE_ETC, 3, 4, 1},     /* device off */
   {"devoff", ARRAY_DEV_ETC, 3, 4, 1},
   {"dnr", DEVICE_ETC, 2, 6, 1},        /* do not remove */
   {"dnr", ARRAY_DEV_ETC, 2, 6, 1},
   {"fault", DEVICE_ETC, 3, 5, 1},
   {"fault", ARRAY_DEV_ETC, 3, 5, 1},
   {"ident", DEVICE_ETC, 2, 1, 1},
   {"ident", ARRAY_DEV_ETC, 2, 1, 1},
   {"ident", POWER_SUPPLY_ETC, 1, 7, 1},
   {"ident", COOLING_ETC, 1, 7, 1},
   {"insert", DEVICE_ETC, 2, 3, 1},
   {"insert", ARRAY_DEV_ETC, 2, 3, 1},
   {"locate", DEVICE_ETC, 2, 1, 1},
   {"locate", ARRAY_DEV_ETC, 2, 1, 1},
   {"locate", POWER_SUPPLY_ETC, 1, 7, 1},
   {"locate", COOLING_ETC, 1, 7, 1},
   {"missing", DEVICE_ETC, 2, 4, 1},
   {"missing", ARRAY_DEV_ETC, 2, 4, 1},
   {"locate", DEVICE_ETC, 2, 1, 1},
   {"locate", ARRAY_DEV_ETC, 2, 1, 1},
   {"prdfail", -1, 0, 6, 1},
   {"remove", DEVICE_ETC, 2, 2, 1},
   {"remove", ARRAY_DEV_ETC, 2, 2, 1},
   {"swap", -1, 0, 4, 1},               /* Reset swap */
   {NULL, 0, 0, 0, 0},
};

/* These are for the Threshold in/out diagnostic page */
static struct acronym2tuple th_a2t_arr[] = {
   {"high_crit", -1, 0, 7, 8},
   {"high_warn", -1, 1, 7, 8},
   {"low_crit", -1, 2, 7, 8},
   {"low_warn", -1, 3, 7, 8},
   {NULL, 0, 0, 0, 0},
};

/* These are for the Additional element status diagnostic page for SAS
 * with the EIP bit set. First phy only. */
static struct acronym2tuple ae_sas_a2t_arr[] = {
   {"at_sas_addr", -1, 20, 7, 64},      /* best viewed with --hex --get= */
   {"dev_type", -1, 8, 6, 3},
   {"phy_id", -1, 28, 7, 8},
   {"sas_addr", -1, 12, 7, 64},
   {"sata_dev", -1, 11, 0, 1},
   {"sata_port_sel", -1, 11, 7, 1},
   {"smp_init", -1, 10, 1, 1},
   {"smp_targ", -1, 11, 1, 1},
   {"ssp_init", -1, 10, 3, 1},
   {"ssp_targ", -1, 11, 3, 1},
   {"stp_init", -1, 10, 2, 1},
   {"stp_targ", -1, 11, 2, 1},
   {NULL, 0, 0, 0, 0},
};

/* Command line long option names with corresponding short letter. */
static struct option long_options[] = {
    {"byte1", 1, 0, 'b'},
    {"control", 0, 0, 'c'},
    {"clear", 1, 0, 'C'},
    {"data", 1, 0, 'd'},
    {"descriptor", 1, 0, 'D'},
    {"filter", 0, 0, 'f'},
    {"get", 1, 0, 'G'},
    {"help", 0, 0, 'h'},
    {"hex", 0, 0, 'H'},
    {"inner-hex", 0, 0, 'i'},
    {"index", 1, 0, 'I'},
    {"join", 0, 0, 'j'},
    {"list", 0, 0, 'l'},
    {"page", 1, 0, 'p'},
    {"raw", 0, 0, 'r'},
    {"status", 0, 0, 's'},
    {"set", 1, 0, 'S'},
    {"verbose", 0, 0, 'v'},
    {"version", 0, 0, 'V'},
    {0, 0, 0, 0},
};

static int read_hex(const char * inp, unsigned char * arr, int * arr_len);



static void
usage()
{
    fprintf(stderr, "Usage: "
            "sg_ses [--byte1=B1] [--clear=STR] [--control] [--data=H,H...]\n"
            "              [--descriptor=DN] [--filter] [--get=STR] [--help] "
            "[--hex]\n"
            "              [--index=IND] [--inner-hex] [--join] [--list] "
            "[--page=PG]\n"
            "              [--raw] [--set=STR] [--status] [--verbose] "
            "[--version]\n"
            "              DEVICE\n"
            "  where:\n"
            "    --byte1=B1|-b B1    byte 1 (2nd byte) of control page set "
            "to B1\n"
            "    --clear=STR|-C STR    clear field by acronym or position\n"
            "    --control|-c        send control information (def: fetch "
            "status)\n"
            "    --data=H,H...|-d H,H...    string of ASCII hex bytes for "
            "control pages\n"
            "    --data=- | -d -     fetch string of ASCII hex bytes from "
            "stdin\n"
            "    --descriptor=DN|-D DN    descriptor name, alternative to "
            "--index=IND\n"
            "    --filter|-f         filter out enclosure status clear "
            "flags\n"
            "    --get=STR|-G STR    get value of field by acronym or "
            "position\n"
            "    --help|-h           print out usage message\n"
            "    --hex|-H            print status response in hex\n"
            "    --index=IND|-I IND    only output element index IND, "
            "[0,999] or overall\n"
            "                          index where IND is either preceded by "
            "'ov' or\n"
            "                          offset by 1000. Default: output all "
            "indexes\n"
            );
    fprintf(stderr,
            "    --inner-hex|-i      print innermost level of a"
            " status page in hex\n"
            "    --join|-j           group enclosure status, element "
            "descriptor\n"
            "                        and additional element status pages. "
            "Use twice\n"
            "                        to add threshold in page\n"
            "    --list|-l           list known pages and elements (ignore"
            " DEVICE)\n"
            "                        use twice to list clear,get,set "
            "acronyms\n"
            "    --page=PG|-p PG     SES page code PG (prefix with '0x' "
            "for hex; def: 0)\n"
            "    --raw|-r            print status page in ASCII hex suitable "
            "for '-d';\n"
            "                        when used twice outputs page in binary "
            "to stdout\n"
            "    --set=STR|-G STR    set value of field by acronym or "
            "position\n"
            "    --status|-s         fetch status information (default "
            "action)\n"
            "    --verbose|-v        increase verbosity\n"
            "    --version|-V        print version string and exit\n\n"
            "Fetches status or sends control data to a SCSI enclosure. STR "
            "can be\n'<acronym>[=val]' or '<start_byte>:<start_bit>"
            "[:<num_bits>][=<val>]'.\n"
            );
}


/* process command line options and argument. Returns 0 if ok. */
static int
process_cl(struct opts_t *op, int argc, char *argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:cC:d:D:fG:hHiI:jlp:rsS:vV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            op->byte1 = sg_get_num(optarg);
            if ((op->byte1 < 0) || (op->byte1 > 255)) {
                fprintf(stderr, "bad argument to '--byte1' (0 to 255 "
                        "inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++op->byte1_given;
            break;
        case 'c':
            ++op->do_control;
            break;
        case 'C':
            op->clear_str = optarg;
            break;
        case 'd':
            memset(op->data_arr, 0, sizeof(op->data_arr));
            if (read_hex(optarg, op->data_arr + 4, &op->arr_len)) {
                fprintf(stderr, "bad argument to '--data'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_data = 1;
            break;
        case 'D':
            op->desc_name = optarg;
            break;
        case 'f':
            op->do_filter = 1;
            break;
        case 'G':
            op->get_str = optarg;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            return 0;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            ++op->inner_hex;
            break;
        case 'I':
            if (! isdigit(optarg[0])) {
                if (('O' != toupper(optarg[0])) ||
                    ('V' != toupper(optarg[1]))) {
                    fprintf(stderr, "bad argument to '--index', expect "
                            "number or 'ov' prefix to number\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                n = sg_get_num(optarg + 2);
                if ((n < 0) || (n > 999)) {
                    fprintf(stderr, "bad argument to '--index', after 'ov' "
                            "expect 0 to 999\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->index_elem_ov = n;
                op->index_given = 2;
                break;
            }
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 1999)) {
                fprintf(stderr, "bad argument to '--index' (0 to 1999 "
                        "inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (n > 999) {
                op->index_elem_ov = n - 1000;
                op->index_given = 2;
            } else {
                op->index_elem_ov = n;
                op->index_given = 1;
            }
            break;
        case 'j':
            ++op->do_join;
            break;
        case 'l':
            ++op->do_list;
            break;
        case 'p':
            op->page_code = sg_get_num(optarg);
            if ((op->page_code < 0) || (op->page_code > 255)) {
                fprintf(stderr, "bad argument to '--page' (0 to 255 "
                        "inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++op->page_code_given;
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 's':
            ++op->do_status;
            break;
        case 'S':
            op->set_str = optarg;
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            ++op->do_version;
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
            usage();
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
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (op->do_join && (op->do_control)) {
        fprintf(stderr, "cannot have '--join' and '--control'\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (((!! op->clear_str) + (!! op->get_str) + (!! op->set_str)) > 1) {
        fprintf(stderr, "can only be one of '--clear', '--get' and "
                "'--set'\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->desc_name && op->index_given) {
        fprintf(stderr, "can have either --descriptor or --index but "
                "not both\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_list)
        return 0;
    if (op->do_control && op->do_status) {
        fprintf(stderr, "cannot have both '--control' and '--status'\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    } else if (op->do_control) {
        if (! op->do_data) {
            fprintf(stderr, "need to give '--data' in control mode\n");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    } else if (0 == op->do_status)
        op->do_status = 1;  /* default to receiving status pages */

    if (NULL == op->device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    return 0;
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
                fprintf(stderr, "unable to decode: %s value\n", esp + 1);
                fprintf(stderr, "    expected: <acronym>[=<val>]\n");
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
            fprintf(stderr, "<start_byte> needs to be between 0 and 127\n");
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
            fprintf(stderr, "<start_bit> needs to be between 0 and 7\n");
            return -1;
        }
        if (colp) {
            if (1 != sscanf(colp + 1, "%d", &tavp->num_bits))
                return -1;
        }
        if ((tavp->num_bits < 1) || (tavp->num_bits > 64)) {
            fprintf(stderr, "<num_bits> needs to be between 1 and 64\n");
            return -1;
        }
    }
    return 0;
}
        
/* Return of 0 -> success, SG_LIB_CAT_INVALID_OP -> Send diagnostic not
 * supported, SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_NOT_READY, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_ABORTED_COMMAND, -1 -> other failures */
static int
do_senddiag(int sg_fd, int pf_bit, void * outgoing_pg, int outgoing_len,
            int noisy, int verbose)
{
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
static const char *
find_element_tname(int elem_type_code)
{
    const struct element_type_t * etp;

    for (etp = element_type_arr; etp->desc; ++etp) {
        if (elem_type_code == etp->elem_type_code)
            return etp->desc;
        else if (elem_type_code < etp->elem_type_code)
            return NULL;
    }
    return NULL;
}

/* Return of 0 -> success, SG_LIB_CAT_INVALID_OP -> command not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_NOT_READY -> device not ready, SG_LIB_CAT_ABORTED_COMMAND,
 * -2 -> unexpected response, -1 -> other failure */
static int
do_rec_diag(int sg_fd, int page_code, unsigned char * rsp_buff,
            int rsp_buff_size, const struct opts_t * op, int * rsp_lenp)
{
    int rsp_len, res;
    const char * cp;

    memset(rsp_buff, 0, rsp_buff_size);
    if (rsp_lenp)
        *rsp_lenp = 0;
    cp = find_in_diag_page_desc(page_code);
    if (op->verbose > 1) {
        if (cp)
            fprintf(stderr, "    Receive diagnostic results cmd for %s "
                    "page\n", cp);
        else
            fprintf(stderr, "    Receive diagnostic results cmd for "
                    "page 0x%x\n", page_code);
    }
    res = sg_ll_receive_diag(sg_fd, 1 /* pcv */, page_code, rsp_buff,
                             rsp_buff_size, 1, op->verbose);
    if (0 == res) {
        rsp_len = (rsp_buff[2] << 8) + rsp_buff[3] + 4;
        if (rsp_len > rsp_buff_size) {
            fprintf(stderr, "<<< warning response buffer too small "
                    "[%d but need %d]>>>\n", rsp_buff_size, rsp_len);
            rsp_len = rsp_buff_size;
        }
        if (rsp_lenp)
            *rsp_lenp = rsp_len;
        if (page_code != rsp_buff[0]) {
            if ((0x9 == rsp_buff[0]) && (1 & rsp_buff[1])) {
                fprintf(stderr, "Enclosure busy, try again later\n");
                if (op->do_hex)
                    dStrHex((const char *)rsp_buff, rsp_len, 0);
            } else if (0x8 == rsp_buff[0]) {
                fprintf(stderr, "Enclosure only supports Short Enclosure "
                        "status: 0x%x\n", rsp_buff[1]);
            } else {
                fprintf(stderr, "Invalid response, wanted page code: 0x%x "
                        "but got 0x%x\n", page_code, rsp_buff[0]);
                dStrHex((const char *)rsp_buff, rsp_len, 0);
            }
            return -2;
        }
        return 0;
    } else if (op->verbose) {
        if (cp)
            fprintf(stderr, "Attempt to fetch %s diagnostic page failed\n",
                    cp);
        else
            fprintf(stderr, "Attempt to fetch status diagnostic page "
                    "[0x%x] failed\n", page_code);
        switch (res) {
        case SG_LIB_CAT_NOT_READY:
            fprintf(stderr, "    device no ready\n");
            break;
        case SG_LIB_CAT_ABORTED_COMMAND:
            fprintf(stderr, "    aborted command\n");
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            fprintf(stderr, "    unit attention\n");
            break;
        case SG_LIB_CAT_INVALID_OP:
            fprintf(stderr, "    Receive diagnostic results command not "
                    "supported\n");
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            fprintf(stderr, "    Receive diagnostic results command, "
                    "bad field in cdb\n");
            break;
        }
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

/* Display Configuration diagnostic page [DPC_CONFIGURATION]. */
static void
ses_configuration_sdg(const unsigned char * resp, int resp_len)
{
    int j, k, el, num_subs, sum_elem_types;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const unsigned char * text_ucp;
    const char * cp;

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
               (ucp[1] ? "" : " (primary)"));
        printf("      relative ES process id: %d, number of ES processes"
               ": %d\n", ((ucp[0] & 0x70) >> 4), (ucp[0] & 0x7));
        printf("      number of type descriptor headers: %d\n", ucp[2]);
        if (el < 40) {
            fprintf(stderr, "      enc descriptor len=%d ??\n", el);
            continue;
        }
        printf("      logical identifier (hex): ");
        for (j = 0; j < 8; ++j)
            printf("%02x", ucp[4 + j]);
        printf("\n      vendor: %.8s  product: %.16s  rev: %.4s\n",
               ucp + 12, ucp + 20, ucp + 36);
        if (el > 40) {
            printf("      vendor-specific data:\n");
            dStrHex((const char *)(ucp + 40), el - 40, 0);
        }
    }
    /* printf("\n"); */
    printf("  type descriptor header/text list\n");
    text_ucp = ucp + (sum_elem_types * 4);
    for (k = 0; k < sum_elem_types; ++k, ucp += 4) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        cp = find_element_tname(ucp[0]);
        if (cp)
            printf("    Element type: %s, subenclosure id: %d\n",
                   cp, ucp[2]);
        else
            printf("    Element type: [0x%x], subenclosure id: %d\n",
                   ucp[0], ucp[2]);
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
    fprintf(stderr, "    <<<ses_configuration_sdg: response too short>>>\n");
    return;
}

/* Returns total number of type descriptor headers written to 'tdhp' or -1
 * if there is a problem */
static int
populate_type_desc_hdr_arr(int fd, struct type_desc_hdr_t * tdhp,
                           unsigned int * generationp,
                           const struct opts_t * op)
{
    int resp_len, k, el, num_subs, sum_type_dheaders, res;
    unsigned int gen_code;
    unsigned char resp[MX_ALLOC_LEN];
    const unsigned char * ucp;
    const unsigned char * last_ucp;

    res = do_rec_diag(fd, DPC_CONFIGURATION, resp, sizeof(resp), op,
                      &resp_len);
    if (res) {
        fprintf(stderr, "populate: couldn't read config page, res=%d\n", res);
        return -1;
    }
    if (resp_len < 4)
        return -1;
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
            fprintf(stderr, "populate: short enc descriptor len=%d ??\n",
                    el);
            continue;
        }
    }
    for (k = 0; k < sum_type_dheaders; ++k, ucp += 4) {
        if ((ucp + 3) > last_ucp)
            goto p_truncated;
        if (k >= MX_ELEM_HDR) {
            fprintf(stderr, "populate: too many elements\n");
            return -1;
        }
        tdhp[k].etype = ucp[0];
        tdhp[k].num_elements = ucp[1];
        tdhp[k].se_id = ucp[2];
        tdhp[k].unused = 0;    /* actually type descriptor text length */
    }
    return sum_type_dheaders;

p_truncated:
    fprintf(stderr, "populate: config too short\n");
    return -1;
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
    char buff[128];
    int filter = op->do_filter;

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
        if ((! filter) || (0xe0 & statp[2]))
            printf("%sApp client bypassed A=%d, Do not remove=%d, Enc "
                   "bypassed A=%d\n", pad, !!(statp[2] & 0x80),
                   !!(statp[2] & 0x40), !!(statp[2] & 0x20));
        if ((! filter) || (0x1c & statp[2]))
            printf("%sEnc bypassed B=%d, Ready to insert=%d, RMV=%d, Ident="
                   "%d\n", pad, !!(statp[2] & 0x10), !!(statp[2] & 0x8),
                   !!(statp[2] & 0x4), !!(statp[2] & 0x2));
        if ((! filter) || ((1 & statp[2]) || (0xe0 & statp[3])))
            printf("%sReport=%d, App client bypassed B=%d, Fault sensed=%d, "
                   "Fault requested=%d\n", pad, !!(statp[2] & 0x1),
                   !!(statp[3] & 0x80), !!(statp[3] & 0x40),
                   !!(statp[3] & 0x20));
        if ((! filter) || (0x1e & statp[3]))
            printf("%sDevice off=%d, Bypassed A=%d, Bypassed B=%d, Device "
                   "bypassed A=%d\n", pad, !!(statp[3] & 0x10),
                   !!(statp[3] & 0x8), !!(statp[3] & 0x4), !!(statp[3] & 0x2));
        if ((! filter) || (0x1 & statp[3]))
            printf("%sDevice bypassed B=%d\n", pad, !!(statp[3] & 0x1));
        break;
    case POWER_SUPPLY_ETC:
        if ((! filter) || ((0x80 & statp[1]) || (0xe & statp[2])))
            printf("%sIdent=%d, DC overvoltage=%d, DC undervoltage=%d, DC "
                   "overcurrent=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[2] & 0x8), !!(statp[2] & 0x4), !!(statp[2] & 0x2));
        if ((! filter) || (0xf8 & statp[3]))
            printf("%sHot swap=%d, Fail=%d, Requested on=%d, Off=%d, "
                   "Overtmp fail=%d\n", pad, !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x20),
                   !!(statp[3] & 0x10), !!(statp[3] & 0x8));
        if ((! filter) || (0x7 & statp[3]))
            printf("%sTemperature warn=%d, AC fail=%d, DC fail=%d\n",
                   pad, !!(statp[3] & 0x4), !!(statp[3] & 0x2),
                   !!(statp[3] & 0x1));
        break;
    case COOLING_ETC:
        if ((! filter) || ((0xc0 & statp[1]) || (0xf0 & statp[3])))
            printf("%sIdent=%d, Hot swap=%d, Fail=%d, Requested on=%d, "
                   "Off=%d\n", pad, !!(statp[1] & 0x80), !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x20),
                   !!(statp[3] & 0x10));
        printf("%sActual speed=%d rpm, Fan %s\n", pad,
               (((0x7 & statp[1]) << 8) + statp[2]) * 10,
               actual_speed_desc[7 & statp[3]]);
        break;
    case TEMPERATURE_ETC:     /* temperature sensor */
        if ((! filter) || ((0xc0 & statp[1]) || (0xf & statp[3]))) {
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
    case DOOR_LOCK_ETC:
        if ((! filter) || ((0xc0 & statp[1]) || (0x1 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Unlock=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[3] & 0x1));
        break;
    case AUD_ALARM_ETC:     /* audible alarm */
        if ((! filter) || ((0xc0 & statp[1]) || (0xd0 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Request mute=%d, Mute=%d, "
                   "Remind=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x10));
        if ((! filter) || (0xf & statp[3]))
            printf("%sTone indicator: Info=%d, Non-crit=%d, Crit=%d, "
                   "Unrecov=%d\n", pad, !!(statp[3] & 0x8), !!(statp[3] & 0x4),
                   !!(statp[3] & 0x2), !!(statp[3] & 0x1));
        break;
    case ESC_ELECTRONICS_ETC: /* enclosure services controller electronics */
        if ((! filter) || (0xc0 & statp[1]) || (0x1 & statp[2]) ||
            (0x80 & statp[3]))
            printf("%sIdent=%d, Fail=%d, Report=%d, Hot swap=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[2] & 0x1), !!(statp[3] & 0x80));
        break;
    case SCC_CELECTR_ETC:     /* SCC controller electronics */
        if ((! filter) || ((0xc0 & statp[1]) || (0x1 & statp[2])))
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
        if ((! filter) || (0xf8 & statp[2]))
            printf("%sAC low=%d, AC high=%d, AC qual=%d, AC fail=%d, DC fail="
                   "%d\n", pad, !!(statp[2] & 0x80), !!(statp[2] & 0x40),
                   !!(statp[2] & 0x20), !!(statp[2] & 0x10),
                   !!(statp[2] & 0x8));
        if ((! filter) || ((0x7 & statp[2]) || (0xc3 & statp[3]))) {
            printf("%sUPS fail=%d, Warn=%d, Intf fail=%d, Ident=%d, Fail=%d, "
                   "Batt fail=%d\n", pad, !!(statp[2] & 0x4),
                   !!(statp[2] & 0x2), !!(statp[2] & 0x1),
                   !!(statp[3] & 0x80), !!(statp[3] & 0x40),
                   !!(statp[3] & 0x2));
            printf("%sBPF=%d\n", pad, !!(statp[3] & 0x1));
        }
        break;
    case DISPLAY_ETC:   /* Display (ses2r15) */
        if ((! filter) || (0xc0 & statp[1]))
            printf("%sIdent=%d, Fail=%d, Display mode status=%d, Display "
                   "character status=0x%x\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), (statp[1] & 0x3),
                   ((statp[2] << 8) & statp[3]));
        break;
    case KEY_PAD_ETC:   /* Key pad entry */
        if ((! filter) || (0xc0 & statp[1]))
            printf("%sIdent=%d, Fail=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40));
        break;
    case ENCLOSURE_ETC:
        a = ((statp[2] >> 2) & 0x3f);
        if ((! filter) || ((0x80 & statp[1]) || a || (0x2 & statp[2])))
            printf("%sIdent=%d, Time until power cycle=%d, "
                   "Failure indication=%d\n", pad, !!(statp[1] & 0x80),
                   a, !!(statp[2] & 0x2));
        b = ((statp[3] >> 2) & 0x3f);
        if ((! filter) || (0x1 & statp[2]) || a || b)
            printf("%sWarning indication=%d, Requested power off "
                   "duration=%d\n", pad, !!(statp[2] & 0x2), b);
        if ((! filter) || (0x3 & statp[3]))
            printf("%sFailure requested=%d, Warning requested=%d\n",
                   pad, !!(statp[3] & 0x2), !!(statp[3] & 0x1));
        break;
    case SCSI_PORT_TRAN_ETC:   /* SCSI port/transceiver */
        if ((! filter) || ((0xc0 & statp[1]) || (0x1 & statp[2]) ||
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
        if ((! filter) || ((0xc0 & statp[1]) || (0x1 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Disabled=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[3] & 0x1));
        break;
    case VOLT_SENSOR_ETC:   /* Voltage sensor */
        if ((! filter) || (0xcf & statp[1])) {
            printf("%sIdent=%d, Fail=%d,  Warn Over=%d, Warn Under=%d, "
                   "Crit Over=%d\n", pad, !!(statp[1] & 0x80),
                   !!(statp[1] & 0x40), !!(statp[1] & 0x8),
                   !!(statp[1] & 0x4), !!(statp[1] & 0x2));
            printf("Crit Under=%d\n", !!(statp[1] & 0x1));
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
        if ((! filter) || (0xca & statp[1]))
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
        if ((! filter) || ((0xc0 & statp[1]) || (0x1 & statp[2]) ||
                           (0x1 & statp[3])))
            printf("%sIdent=%d, Fail=%d, Report=%d, Enabled=%d\n", pad,
                   !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[2] & 0x1), !!(statp[3] & 0x1));
        break;
    case SCSI_IPORT_ETC:   /* SCSI initiator port */
        if ((! filter) || ((0xc0 & statp[1]) || (0x1 & statp[2]) ||
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
        if ((! filter) || (0xf0 & statp[1]))
            printf("%sOK=%d, Reserved device=%d, Hot spare=%d, Cons check="
                   "%d\n", pad, !!(statp[1] & 0x80), !!(statp[1] & 0x40),
                   !!(statp[1] & 0x20), !!(statp[1] & 0x10));
        if ((! filter) || (0xf & statp[1]))
            printf("%sIn crit array=%d, In failed array=%d, Rebuild/remap=%d"
                   ", R/R abort=%d\n", pad, !!(statp[1] & 0x8),
                   !!(statp[1] & 0x4), !!(statp[1] & 0x2),
                   !!(statp[1] & 0x1));
        if ((! filter) || (0xf0 & statp[2]))
            printf("%sApp client bypass A=%d, Do not remove=%d, Enc bypass "
                   "A=%d, Enc bypass B=%d\n", pad, !!(statp[2] & 0x80),
                   !!(statp[2] & 0x40), !!(statp[2] & 0x20),
                   !!(statp[2] & 0x10));
        if ((! filter) || (0xf & statp[2]))
            printf("%sReady to insert=%d, RMV=%d, Ident=%d, Report=%d\n",
                   pad, !!(statp[2] & 0x8), !!(statp[2] & 0x4),
                   !!(statp[2] & 0x2), !!(statp[2] & 0x1));
        if ((! filter) || (0xf0 & statp[3]))
            printf("%sApp client bypass B=%d, Fault sensed=%d, Fault reqstd="
                   "%d, Device off=%d\n", pad, !!(statp[3] & 0x80),
                   !!(statp[3] & 0x40), !!(statp[3] & 0x20),
                   !!(statp[3] & 0x10));
        if ((! filter) || (0xf & statp[3]))
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
        printf("%sIdent=%d, %s, Connector physical "
               "link=0x%x\n", pad, !!(statp[1] & 0x80),
               find_sas_connector_type((statp[1] & 0x7f), buff, sizeof(buff)),
               statp[2]);
        printf("%sFail=%d\n", pad, !!(statp[3] & 0x40));
        break;
    default:
        printf("%sUnknown element type, status in hex: %02x %02x %02x %02x\n",
               pad, statp[0], statp[1], statp[2], statp[3]);
        break;
    }
}

/* Display enclosure status [DPC_ENC_STATUS] diagnostic page. */
static void
ses_enc_status_dp(const struct type_desc_hdr_t * tdhp, int num_telems,
                  unsigned int ref_gen_code, const unsigned char * resp,
                  int resp_len, const struct opts_t * op)
{
    int j, k, elem_ind;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const char * cp;

    printf("Enclosure status diagnostic page:\n");
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
        fprintf(stderr, "  <<state of enclosure changed, please try "
                "again>>\n");
        return;
    }
    printf("  status descriptor list\n");
    ucp = resp + 8;
    for (k = 0, elem_ind = 0; k < num_telems; ++k, ++tdhp) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        if ((! op->index_given) ||
            ((2 == op->index_given) && (k == op->index_elem_ov))) {
            cp = find_element_tname(tdhp->etype);
            if (cp)
                printf("    Element type: %s, subenclosure id: %d\n",
                       cp, tdhp->se_id);
            else
                printf("    Element type: [0x%x], subenclosure id: %d\n",
                       tdhp->etype, tdhp->se_id);
            printf("      Overall %d descriptor:\n", k);
            enc_status_helper("        ", ucp, tdhp->etype, op);
        }
        for (ucp += 4, j = 0; j < tdhp->num_elements;
             ++j, ucp += 4, ++elem_ind) {
            if ((2 == op->index_given) ||
                ((1 == op->index_given) && (elem_ind != op->index_elem_ov)))
                continue;
            printf("      Element %d descriptor:\n", elem_ind);
            enc_status_helper("        ", ucp, tdhp->etype, op);
        }
    }
    return;
truncated:
    fprintf(stderr, "    <<<enc: response too short>>>\n");
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

static void
ses_threshold_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                  unsigned int ref_gen_code, const unsigned char * resp,
                  int resp_len, const struct opts_t * op)
{
    int j, k, elem_ind;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const char * cp;

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
        fprintf(stderr, "  <<state of enclosure changed, please try "
                "again>>\n");
        return;
    }
    printf("  threshold status descriptor list\n");
    ucp = resp + 8;
    for (k = 0, elem_ind = 0; k < num_telems; ++k, ++tdhp) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        if ((! op->index_given) ||
            ((2 == op->index_given) && (k == op->index_elem_ov))) {
            cp = find_element_tname(tdhp->etype);
            if (cp)
                printf("    Element type: %s, subenclosure id: %d\n",
                       cp, tdhp->se_id);
            else
                printf("    Element type: [0x%x], subenclosure id: %d\n",
                       tdhp->etype, tdhp->se_id);
            printf("      Overall %d descriptor:\n", k);
            ses_threshold_helper("        ", ucp, tdhp->etype, op);
        }
        for (ucp += 4, j = 0; j < tdhp->num_elements;
             ++j, ucp += 4, ++elem_ind) {
            if ((2 == op->index_given) ||
                ((1 == op->index_given) && (elem_ind != op->index_elem_ov)))
                continue;
            printf("      Element %d descriptor:\n", elem_ind);
            ses_threshold_helper("        ", ucp, tdhp->etype, op);
        }
    }
    return;
truncated:
    fprintf(stderr, "    <<<thresh: response too short>>>\n");
    return;
}

/* This page essentially contains names of overall and individual
 * elements. */
static void
ses_element_desc_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                     unsigned int ref_gen_code, const unsigned char * resp,
                     int resp_len, const struct opts_t * op)
{
    int j, k, desc_len, elem_ind;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const char * cp;
    const struct type_desc_hdr_t * tp;

    printf("Element descriptor In diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    last_ucp = resp + resp_len - 1;
    if (resp_len < 8)
        goto truncated;
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    if (ref_gen_code != gen_code) {
        fprintf(stderr, "  <<state of enclosure changed, please try "
                "again>>\n");
        return;
    }
    printf("  element descriptor by type list\n");
    ucp = resp + 8;
    for (k = 0, tp = tdhp, elem_ind = 0; k < num_telems; ++k, ++tp) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        desc_len = (ucp[2] << 8) + ucp[3] + 4;
        if ((! op->index_given) ||
            ((2 == op->index_given) && (k == op->index_elem_ov))) {
            cp = find_element_tname(tp->etype);
            if (cp)
                printf("    Element type: %s, subenclosure id: %d\n",
                       cp, tp->se_id);
            else
                printf("    Element type: [0x%x], subenclosure id: %d\n",
                       tp->etype, tp->se_id);
            if (desc_len > 4)
                printf("      Overall %d descriptor: %.*s\n", k, desc_len - 4,
                       ucp + 4);
            else
                printf("      Overall %d descriptor: <empty>\n", k);
        }
        for (ucp += desc_len, j = 0; j < tp->num_elements;
             ++j, ucp += desc_len, ++elem_ind) {
            desc_len = (ucp[2] << 8) + ucp[3] + 4;
            if ((2 == op->index_given) ||
                ((1 == op->index_given) && (elem_ind != op->index_elem_ov)))
                continue;
            if (desc_len > 4)
                printf("      Element %d descriptor: %.*s\n", j,
                       desc_len - 4, ucp + 4);
            else
                printf("      Element %d descriptor: <empty>\n", j);
        }
    }
    return;
truncated:
    fprintf(stderr, "    <<<element: response too short>>>\n");
    return;
}

static int
sas_addr_non_zero(const unsigned char * ucp)
{
    int k;

    for (k = 0; k < 8; ++k) {
        if (ucp[k])
            return 1;
    }
    return 0;
}

static char * sas_device_type[] = {
    "no device attached",
    "end device",
    "expander device",  /* in SAS-1.1 this was a "edge expander device */
    "expander device (fanout, SAS-1.1)",  /* marked obsolete in SAS-2 */
    "reserved [4]", "reserved [5]", "reserved [6]", "reserved [7]"
};

static void
additional_elem_helper(const char * pad, const unsigned char * ucp, int len,
                       int elem_type, const struct opts_t * op)
{
    int ports, phys, j, m, desc_type, eip_offset, print_sas_addr;
    const unsigned char * per_ucp;
    int filter = op->do_filter;
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
        ports = ucp[2 + eip_offset];
        printf("%sTransport protocol: FCP\n", pad);
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
        desc_type = (ucp[3 + eip_offset] >> 6) & 0x3;
        printf("%sTransport protocol: SAS\n", pad);
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
                printf("%s  device type: %s\n", pad,
                       sas_device_type[(0x70 & per_ucp[0]) >> 4]);
                if ((! filter) || (0xe & per_ucp[2]))
                    printf("%s  initiator port for:%s%s%s\n", pad,
                           ((per_ucp[2] & 8) ? " SSP" : ""),
                           ((per_ucp[2] & 4) ? " STP" : ""),
                           ((per_ucp[2] & 2) ? " SMP" : ""));
                if ((! filter) || (0x8f & per_ucp[3]))
                    printf("%s  target port for:%s%s%s%s%s\n", pad,
                           ((per_ucp[3] & 0x80) ? " SATA_port_selector" : ""),
                           ((per_ucp[3] & 8) ? " SSP" : ""),
                           ((per_ucp[3] & 4) ? " STP" : ""),
                           ((per_ucp[3] & 2) ? " SMP" : ""),
                           ((per_ucp[3] & 1) ? " SATA_device" : ""));
                print_sas_addr = 0;
                if ((! filter) || sas_addr_non_zero(per_ucp + 4)) {
                    ++print_sas_addr;
                    printf("%s  attached SAS address: 0x", pad);
                    for (m = 0; m < 8; ++m)
                        printf("%02x", per_ucp[4 + m]);
                }
                if ((! filter) || sas_addr_non_zero(per_ucp + 12)) {
                    ++print_sas_addr;
                    printf("\n%s  SAS address: 0x", pad);
                    for (m = 0; m < 8; ++m)
                        printf("%02x", per_ucp[12 + m]);
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
                       (ESC_ELECTRONICS_ETC == elem_type)) {
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

/* Previously called "Device element status descriptor". Changed "device"
   to "additional" to allow for SAS expander and SATA devices */
static void
ses_additional_elem_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                        unsigned int ref_gen_code, const unsigned char * resp,
                        int resp_len, const struct opts_t * op)
{
    int j, k, desc_len, elem_type, invalid, el_num, eip, ind;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const char * cp;
    const struct type_desc_hdr_t * tp;

    printf("Additional element status diagnostic page:\n");
    if (resp_len < 4)
        goto truncated;
    last_ucp = resp + resp_len - 1;
    gen_code = (resp[4] << 24) | (resp[5] << 16) |
               (resp[6] << 8) | resp[7];
    printf("  generation code: 0x%x\n", gen_code);
    if (ref_gen_code != gen_code) {
        fprintf(stderr, "  <<state of enclosure changed, please try "
                "again>>\n");
        return;
    }
    printf("  additional element status descriptor list\n");
    ucp = resp + 8;
    for (k = 0, el_num = 0, tp = tdhp; k < num_telems; ++k, ++tp) {
        elem_type = tp->etype;
        if (! ((DEVICE_ETC == elem_type) ||
               (SCSI_TPORT_ETC == elem_type) ||
               (SCSI_IPORT_ETC == elem_type) ||
               (ARRAY_DEV_ETC == elem_type) ||
               (SAS_EXPANDER_ETC == elem_type) ||
               (ESC_ELECTRONICS_ETC == elem_type)))
            continue;   /* skip if not one of above element types */
        if ((ucp + 1) > last_ucp)
            goto truncated;
        if (op->index_given) {
            cp = find_element_tname(elem_type);
            if (cp)
                printf("    Element type: %s, subenclosure id: %d\n", cp,
                       tp->se_id);
            else
                printf("    Element type: [0x%x], subenclosure id: %d\n",
                       tp->etype, tp->se_id);
        }
        for (j = 0; j < tp->num_elements; ++j, ucp += desc_len, ++el_num) {
            invalid = !!(ucp[0] & 0x80);
            desc_len = ucp[1] + 2;
            eip = ucp[0] & 0x10;
            ind = eip ? ucp[3] : el_num;
            if ((2 == op->index_given) ||
                ((1 == op->index_given) && (ind != op->index_elem_ov)))
                continue;
            if (eip)
                printf("      Element index: %d\n", ind);
            else
                printf("      Element %d descriptor\n", ind);
            if (invalid && (0 == op->inner_hex))
                printf("        flagged as invalid (no further "
                       "information)\n");
            else
                additional_elem_helper("        ", ucp, desc_len, elem_type,
                                       op);
        }
    }
    return;
truncated:
    fprintf(stderr, "    <<<additional: response too short>>>\n");
    return;
}

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
    fprintf(stderr, "    <<<subenc: response too short>>>\n");
    return;
}

static void
ses_subenc_string_sdg(const unsigned char * resp, int resp_len)
{
    int k, el, num_subs;
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
        if (el > 4)
            dStrHex((const char *)(ucp + 4), el - 4, 0);
        else
            printf("    <empty>\n");
    }
    return;
truncated:
    fprintf(stderr, "    <<<subence str: response too short>>>\n");
    return;
}

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
        printf("   nickname: %s\n", ucp + 8);
    }
    return;
truncated:
    fprintf(stderr, "    <<<subence str: response too short>>>\n");
    return;
}

static void
ses_supported_pages_sdg(const char * leadin, const unsigned char * resp,
                        int resp_len)
{
    int k, code, prev;
    const char * cp;

    printf("%s:\n", leadin);
    for (k = 0, prev = 0; k < (resp_len - 4); ++k, prev = code) {
        code = resp[k + 4];
        if (code < prev)
            break;      /* assume to be padding at end */
        cp = find_diag_page_desc(code);
        printf("  %s [0x%x]\n", (cp ? cp : "<unknown>"), code);
    }
}

static void
ses_download_code_sdg(const unsigned char * resp, int resp_len)
{
    int k, num_subs;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;

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
        printf("   subenclosure identifier: %d\n", ucp[1]);
        printf("     download microcode status: 0x%x [additional status: "
               "0x%x]\n", ucp[2], ucp[3]);
        printf("     download microcode maximum size: %d bytes\n",
               (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7]);
        printf("     download microcode expected buffer id: 0x%x\n", ucp[11]);
        printf("     download microcode expected buffer id offset: %d\n",
               (ucp[12] << 24) + (ucp[13] << 16) + (ucp[14] << 8) + ucp[15]);
    }
    return;
truncated:
    fprintf(stderr, "    <<<download: response too short>>>\n");
    return;
}

static int
read_hex(const char * inp, unsigned char * arr, int * arr_len)
{
    int in_len, k, j, m, off;
    unsigned int h;
    const char * lcp;
    char * cp;
    char * c2p;
    char line[512];

    if ((NULL == inp) || (NULL == arr) || (NULL == arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len) {
        *arr_len = 0;
    }
    if ('-' == inp[0]) {        /* read from stdin */
        for (j = 0, off = 0; j < MX_DATA_IN; ++j) {
            /* limit lines read to MX_DATA_IN */
            if (NULL == fgets(line, sizeof(line), stdin))
                break;
            in_len = strlen(line);
            if (in_len > 0) {
                if ('\n' == line[in_len - 1]) {
                    --in_len;
                    line[in_len] = '\0';
                }
            }
            if (0 == in_len)
                continue;
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
                fprintf(stderr, "read_hex: syntax error at "
                        "line %d, pos %d\n", j + 1, m + k + 1);
                return 1;
            }
            for (k = 0; k < (MX_DATA_IN - off); ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        fprintf(stderr, "read_hex: hex number "
                                "larger than 0xff in line %d, pos %d\n",
                                j + 1, (int)(lcp - line + 1));
                        return 1;
                    }
                    arr[off + k] = h;
                    lcp = strpbrk(lcp, " ,\t");
                    if (NULL == lcp)
                        break;
                    lcp += strspn(lcp, " ,\t");
                    if ('\0' == *lcp)
                        break;
                } else {
                    fprintf(stderr, "read_hex: error in "
                            "line %d, at pos %d\n", j + 1,
                            (int)(lcp - line + 1));
                    return 1;
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
            fprintf(stderr, "read_hex: error at pos %d\n",
                    k + 1);
            return 1;
        }
        for (k = 0; k < MX_DATA_IN; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    fprintf(stderr, "read_hex: hex number larger "
                            "than 0xff at pos %d\n", (int)(lcp - inp + 1));
                    return 1;
                }
                arr[k] = h;
                cp = strchr(lcp, ',');
                c2p = strchr(lcp, ' ');
                if (NULL == cp)
                    cp = c2p;
                if (NULL == cp)
                    break;
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                fprintf(stderr, "read_hex: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *arr_len = k + 1;
    }
    return 0;
}

/* Return 0 for success. */
static int
ses_process_status(int sg_fd, const struct opts_t * op)
{
    int rsp_len, res;
    unsigned int ref_gen_code;
    unsigned char rsp_buff[MX_ALLOC_LEN];
    const char * cp;

    cp = find_in_diag_page_desc(op->page_code);
    res = do_rec_diag(sg_fd, op->page_code, rsp_buff, sizeof(rsp_buff),
                      op, &rsp_len);
    if (res)
        return res;
    if (op->do_raw) {
        if (1 == op->do_raw)
            dStrHex((const char *)rsp_buff + 4, rsp_len - 4, -1);
        else {
            if (sg_set_binary_mode(STDOUT_FILENO) < 0)
                perror("sg_set_binary_mode");
            dStrRaw((const char *)rsp_buff, rsp_len);
        }
    } else if (op->do_hex) {
        if (cp)
            printf("Response in hex from diagnostic page: %s\n", cp);
        else
            printf("Response in hex from unknown diagnostic page "
                   "[0x%x]\n", op->page_code);
        dStrHex((const char *)rsp_buff, rsp_len, 0);
    } else {
        switch (op->page_code) {
        case DPC_SUPPORTED:
            ses_supported_pages_sdg("Supported diagnostic pages",
                                    rsp_buff, rsp_len);
            break;
        case DPC_CONFIGURATION:
            ses_configuration_sdg(rsp_buff, rsp_len);
            break;
        case DPC_ENC_STATUS:
            res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                             &ref_gen_code, op);
            if (res < 0)
                return res;
            ses_enc_status_dp(type_desc_hdr_arr, res, ref_gen_code,
                              rsp_buff, rsp_len, op);
            break;
        case DPC_HELP_TEXT:
            printf("Help text diagnostic page (for primary "
                   "subenclosure):\n");
            if (rsp_len > 4)
                printf("  %.*s\n", rsp_len - 4, rsp_buff + 4);
            else
                printf("  <empty>\n");
            break;
        case DPC_STRING:
            printf("String In diagnostic page (for primary "
                   "subenclosure):\n");
            if (rsp_len > 4)
                dStrHex((const char *)(rsp_buff + 4), rsp_len - 4, 0);
            else
                printf("  <empty>\n");
            break;
        case DPC_THRESHOLD:
            res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                             &ref_gen_code, op);
            if (res < 0)
                return res;
            ses_threshold_sdg(type_desc_hdr_arr, res, ref_gen_code,
                              rsp_buff, rsp_len, op);
            break;
        case DPC_ELEM_DESC:
            res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                             &ref_gen_code, op);
            if (res < 0)
                return res;
            ses_element_desc_sdg(type_desc_hdr_arr, res, ref_gen_code,
                                 rsp_buff, rsp_len, op);
            break;
        case DPC_SHORT_ENC_STATUS:
            printf("Short enclosure status diagnostic page, "
                   "status=0x%x\n", rsp_buff[1]);
            break;
        case DPC_ENC_BUSY:
            printf("Enclosure busy diagnostic page, "
                   "busy=%d [vendor specific=0x%x]\n",
                   rsp_buff[1] & 1, (rsp_buff[1] >> 1) & 0xff);
            break;
        case DPC_ADD_ELEM_STATUS:
            res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                             &ref_gen_code, op);
            if (res < 0)
                return res;
            ses_additional_elem_sdg(type_desc_hdr_arr, res, ref_gen_code,
                                    rsp_buff, rsp_len, op);
            break;
        case DPC_SUBENC_HELP_TEXT:
            ses_subenc_help_sdg(rsp_buff, rsp_len);
            break;
        case DPC_SUBENC_STRING:
            ses_subenc_string_sdg(rsp_buff, rsp_len);
            break;
        case DPC_SUPPORTED_SES:
            ses_supported_pages_sdg("Supported SES diagnostic pages",
                                    rsp_buff, rsp_len);
            break;
        case DPC_DOWNLOAD_MICROCODE:
            ses_download_code_sdg(rsp_buff, rsp_len);
            break;
        case DPC_SUBENC_NICKNAME:
            ses_subenc_nickname_sdg(rsp_buff, rsp_len);
            break;
        default:
            printf("Cannot decode response from diagnostic "
                   "page: %s\n", (cp ? cp : "<unknown>"));
            dStrHex((const char *)rsp_buff, rsp_len, 0);
        }
    }
    return 0;
}

/* Fetch configuration, enclosure status, element descriptor, additional
 * element status and optionally threshold in pages, place in static arrays.
 * Collate (join) overall and individual elements into the static join_arr[].
 * Returns 0 for success, any other return value is an error. */
static int
process_join(int sg_fd, const struct opts_t * op, int display)
{
    int k, j, ind, res, num_t_hdrs, elem_ind, ei, get_out, ov, ind_ov;
    int desc_len, dn_len;
    unsigned int ref_gen_code, gen_code;
    struct join_row_t * jrp;
    unsigned char * es_ucp;
    unsigned char * ed_ucp;
    unsigned char * ae_ucp;
    unsigned char * t_ucp;
    const unsigned char * es_last_ucp;
    const unsigned char * ed_last_ucp;
    const unsigned char * ae_last_ucp;
    const unsigned char * t_last_ucp;
    const char * cp;
    const char * enc_state_changed = "  <<state of enclosure changed, "
                                     "please try again>>\n";
    const struct type_desc_hdr_t * tdhp;
    char b[16];

    num_t_hdrs = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                            &ref_gen_code, op);
    if (num_t_hdrs < 0)
        return num_t_hdrs;
    res = do_rec_diag(sg_fd, DPC_ENC_STATUS, enc_stat_rsp,
                      sizeof(enc_stat_rsp), op, &enc_stat_rsp_len);
    if (res)
        return res;
    if (enc_stat_rsp_len < 8) {
        fprintf(stderr, "Enclosure status response too short\n");
        return -1;
    }
    gen_code = (enc_stat_rsp[4] << 24) | (enc_stat_rsp[5] << 16) |
               (enc_stat_rsp[6] << 8) | enc_stat_rsp[7];
    if (ref_gen_code != gen_code) {
        fprintf(stderr, "%s", enc_state_changed);
        return -1;
    }
    es_ucp = enc_stat_rsp + 8;
    es_last_ucp = enc_stat_rsp + enc_stat_rsp_len - 1;

    res = do_rec_diag(sg_fd, DPC_ELEM_DESC, elem_desc_rsp,
                      sizeof(elem_desc_rsp), op, &elem_desc_rsp_len);
    if (0 == res) {
        if (elem_desc_rsp_len < 8) {
            fprintf(stderr, "Element descriptor response too short\n");
            return -1;
        }
        gen_code = (elem_desc_rsp[4] << 24) | (elem_desc_rsp[5] << 16) |
                   (elem_desc_rsp[6] << 8) | elem_desc_rsp[7];
        if (ref_gen_code != gen_code) {
            fprintf(stderr, "%s", enc_state_changed);
            return -1;
        }
        ed_ucp = elem_desc_rsp + 8;
        ed_last_ucp = elem_desc_rsp + elem_desc_rsp_len - 1;
    } else {
        elem_desc_rsp_len = 0;
        ed_ucp = NULL;
        res = 0;
        if (op->verbose)
            fprintf(stderr, "  Element descriptor page not "
                    "available\n");
    }

    if (display || (DPC_ADD_ELEM_STATUS == op->page_code)) {
        res = do_rec_diag(sg_fd, DPC_ADD_ELEM_STATUS, add_elem_rsp,
                          sizeof(add_elem_rsp), op, &add_elem_rsp_len);
        if (0 == res) {
            if (add_elem_rsp_len < 8) {
                fprintf(stderr, "Additional element status response too "
                        "short\n");
                return -1;
            }
            gen_code = (add_elem_rsp[4] << 24) | (add_elem_rsp[5] << 16) |
                       (add_elem_rsp[6] << 8) | add_elem_rsp[7];
            if (ref_gen_code != gen_code) {
                fprintf(stderr, "%s", enc_state_changed);
                return -1;
            }
            ae_ucp = add_elem_rsp + 8;
            ae_last_ucp = add_elem_rsp + add_elem_rsp_len - 1;
        } else {
            add_elem_rsp_len = 0;
            ae_ucp = NULL;
            ae_last_ucp = NULL;
            res = 0;
            if (op->verbose)
                fprintf(stderr, "  Additional element status page not "
                        "available\n");
        }
    } else {
        ae_ucp = NULL;
        ae_last_ucp = NULL;
    }

    if ((op->do_join > 1) ||
        ((0 == display) && (DPC_THRESHOLD == op->page_code))) {
        res = do_rec_diag(sg_fd, DPC_THRESHOLD, threshold_rsp,
                          sizeof(threshold_rsp), op, &threshold_rsp_len);
        if (0 == res) {
            if (threshold_rsp_len < 8) {
                fprintf(stderr, "Additional element status response too "
                        "short\n");
                return -1;
            }
            gen_code = (threshold_rsp[4] << 24) | (threshold_rsp[5] << 16) |
                       (threshold_rsp[6] << 8) | threshold_rsp[7];
            if (ref_gen_code != gen_code) {
                fprintf(stderr, "%s", enc_state_changed);
                return -1;
            }
            t_ucp = threshold_rsp + 8;
            t_last_ucp = threshold_rsp + threshold_rsp_len - 1;
        } else {
            threshold_rsp_len = 0;
            t_ucp = NULL;
            res = 0;
            if (op->verbose)
                fprintf(stderr, "  Threshold in page not available\n");
        }
    } else {
        threshold_rsp_len = 0;
        t_ucp = NULL;
    }

    jrp = join_arr;
    tdhp = type_desc_hdr_arr;
    for (k = 0, elem_ind = 0; k < num_t_hdrs; ++k, ++tdhp) {
        jrp->el_ov_ind = 1000 + k;
        jrp->etype = tdhp->etype;
        jrp->se_id = tdhp->se_id;
        /* check es_ucp < es_last_ucp still in range */
        jrp->enc_statp = es_ucp;
        es_ucp += 4;
        jrp->elem_descp = ed_ucp;
        if (ed_ucp)
            ed_ucp += (ed_ucp[2] << 8) + ed_ucp[3] + 4;
        jrp->add_elem_statp = NULL;
        jrp->thresh_inp = t_ucp;
        if (t_ucp)
            t_ucp += 4;
        ++jrp;
        for (j = 0; j < tdhp->num_elements; ++j, ++jrp, ++elem_ind) {
            if (jrp >= join_arr_lastp)
                break;
            jrp->el_ov_ind = elem_ind;
            jrp->etype = tdhp->etype;
            jrp->se_id = tdhp->se_id;
            jrp->enc_statp = es_ucp;
            es_ucp += 4;
            jrp->elem_descp = ed_ucp;
            if (ed_ucp)
                ed_ucp += (ed_ucp[2] << 8) + ed_ucp[3] + 4;
            jrp->thresh_inp = t_ucp;
            if (t_ucp)
                t_ucp += 4;
            jrp->add_elem_statp = NULL;
        }
        if (jrp >= join_arr_lastp)
            break;      /* leave last row all zeros */
    }

    if (ae_ucp) {
        get_out = 0;
        jrp = join_arr;
        tdhp = type_desc_hdr_arr;
        for (k = 0; k < num_t_hdrs; ++k, ++tdhp) {
            if ((DEVICE_ETC == tdhp->etype) ||
                (SCSI_TPORT_ETC == tdhp->etype) ||
                (SCSI_IPORT_ETC == tdhp->etype) ||
                (ARRAY_DEV_ETC == tdhp->etype) ||
                (SAS_EXPANDER_ETC == tdhp->etype) ||
                (ESC_ELECTRONICS_ETC == tdhp->etype)) {
                for (j = 0; j < tdhp->num_elements; ++j) {
                    if ((ae_ucp + 1) > ae_last_ucp) {
                        get_out = 1;
                        if (op->verbose)
                            fprintf(stderr, "process_join: off end of ae "
                                    "page\n");
                        break;
                    }
                    if (ae_ucp[0] & 0x10) {     /* EIP bit */
                        ei = ae_ucp[3];
                        for (jrp = join_arr; jrp->enc_statp; ++jrp) {
                            if (ei == jrp->el_ov_ind) {
                                jrp->add_elem_statp = ae_ucp;
                                break;
                            }
                        }
                        if (NULL == jrp->enc_statp) {
                            get_out = 1;
                            fprintf(stderr, "process_join: ei=%d not in "
                                    "join_arr\n", ei);
                            break;
                        }
                    } else {
                        while (jrp->enc_statp && ((jrp->el_ov_ind > 999) ||
                                                  jrp->add_elem_statp))
                            ++jrp;
                        if (NULL == jrp->enc_statp) {
                            get_out = 1;
                            fprintf(stderr, "process_join: join_arr has no "
                                    "space for ae\n");
                            break;
                        }
                        jrp->add_elem_statp = ae_ucp;
                    }
                    ae_ucp += ae_ucp[1] + 2;
                }
            }
            if (get_out)
                break;
        }
    }

    if (op->verbose > 3) {
        jrp = join_arr;
        for (k = 0; ((k < MX_JOIN_ROWS) && jrp->enc_statp); ++k, ++jrp) {
            fprintf(stderr, "el_ov_ind=%d etype=%d se_id=%d %s %s %s %s\n",
                    jrp->el_ov_ind, jrp->etype, jrp->se_id,
                    (jrp->enc_statp ? "enc_statp" : ""),
                    (jrp->elem_descp ? "elem_descp" : ""),
                    (jrp->add_elem_statp ? "add_elem_statp" : ""),
                    (jrp->thresh_inp ? "thresh_inp" : ""));
        }
    }
    if (! display)      /* probably wanted join_arr[] built only */
        return 0;

    dn_len = op->desc_name ? (int)strlen(op->desc_name) : 0;
    ind_ov = (2 == op->index_given);
    for (k = 0, jrp = join_arr; ((k < MX_JOIN_ROWS) && jrp->enc_statp);
         ++k, ++jrp) {
        ov = (jrp->el_ov_ind > 999);
        ind = ov ? jrp->el_ov_ind - 1000 : jrp->el_ov_ind;
        if (op->index_given) {
            if (ind_ov != ov)
                continue;
            if (ind != op->index_elem_ov)
                continue;
        }
        ed_ucp = jrp->elem_descp;
        if (op->desc_name) {
            if (NULL == ed_ucp)
                continue;
            desc_len = (ed_ucp[2] << 8) + ed_ucp[3];
            if (desc_len != dn_len)
                continue;
            if (0 != strncmp(op->desc_name, (const char *)(ed_ucp + 4),
                             desc_len))
                continue;
        }
        cp = find_element_tname(jrp->etype);
        if (NULL == cp) {
            snprintf(b, sizeof(b) - 1, "%d", jrp->etype);
            b[sizeof(b) - 1] = '\0';
            cp = b;
        }
        if (ed_ucp) {
            desc_len = (ed_ucp[2] << 8) + ed_ucp[3] + 4;
            if (desc_len > 4)
                printf("%.*s [%s%d]  Element type: %s\n", desc_len - 4,
                       (const char *)(ed_ucp + 4), (ov ? "ov" : ""), ind, cp);
            else
                printf("[%s%d]  Element type: %s\n", (ov ? "ov" : ""), ind,
                       cp);
        } else
            printf("%s index %d  Element type: %s\n",
                   (ov ? "Overall" : "Element"), ind, cp);
        printf("  Enclosure status:\n");
        enc_status_helper("    ", jrp->enc_statp, jrp->etype, op);
        if (jrp->add_elem_statp) {
            printf("  Additional element status:\n");
            ae_ucp = jrp->add_elem_statp;
            desc_len = ae_ucp[1] + 2;
            additional_elem_helper("    ",  ae_ucp, desc_len, jrp->etype, op);
        }
        if (jrp->thresh_inp) {
            printf("  Threshold in:\n");
            t_ucp = jrp->thresh_inp;
            ses_threshold_helper("    ", t_ucp, jrp->etype, op);
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

/* Do clear/get/set (cgs) on Enclosure Control/Status page. Return 0 for ok
 * else -1 . */
static int
cgs_enc_ctl_stat(int sg_fd, const struct join_row_t * jrp,
                 const struct tuple_acronym_val * tavp,
                 const struct opts_t * op)
{
    int ret, len, s_byte, s_bit, n_bits;
    uint64_t ui;
    const struct acronym2tuple * a2tp;

    if (NULL == tavp->acron) {
        s_byte = tavp->start_byte;
        s_bit = tavp->start_bit;
        n_bits = tavp->num_bits;
    }
    if (tavp->acron) {
        for (a2tp = ecs_a2t_arr; a2tp->acron; ++ a2tp) {
            if (((jrp->etype == a2tp->etype) || (-1 == a2tp->etype)) &&
                strcase_eq(tavp->acron, a2tp->acron))
                break;
        }
        if (a2tp->acron) {
            s_byte = a2tp->start_byte;
            s_bit = a2tp->start_bit;
            n_bits = a2tp->num_bits;
        } else {
            fprintf(stderr, "acroynm %s not found for Enclosure "
                    "Control/Status page (try '-ll' option)\n", tavp->acron);
            return -1;
        }
    }
    if (op->get_str) {
        ui = get_big_endian(jrp->enc_statp + s_byte, s_bit, n_bits);
        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {
        jrp->enc_statp[0] &= 0x40;  /* keep PRDFAIL bit in byte 0 */
        set_big_endian((uint64_t)tavp->val,
                       jrp->enc_statp + s_byte, s_bit, n_bits);
        jrp->enc_statp[0] |= 0x80;  /* set SELECT bit */
        if (op->byte1_given)
            enc_stat_rsp[1] = op->byte1;
        len = (enc_stat_rsp[2] << 8) + enc_stat_rsp[3] + 4;
        ret = do_senddiag(sg_fd, 1, enc_stat_rsp, len, 1, op->verbose);
        if (ret) {
            fprintf(stderr, "couldn't send Enclosure control page\n");
            return -1;
        }
    }
    return 0;
}

/* Do clear/get/set (cgs) on Threshold In/Out page. Return 0 for ok else
 * -1 . */
static int
cgs_threshold(int sg_fd, const struct join_row_t * jrp,
              const struct tuple_acronym_val * tavp,
              const struct opts_t * op)
{
    int ret, len, s_byte, s_bit, n_bits;
    uint64_t ui;
    const struct acronym2tuple * a2tp;

    if (NULL == jrp->thresh_inp) {
        fprintf(stderr, "No threshold In/Out element available\n");
        return -1;
    }
    if (NULL == tavp->acron) {
        s_byte = tavp->start_byte;
        s_bit = tavp->start_bit;
        n_bits = tavp->num_bits;
    }
    if (tavp->acron) {
        for (a2tp = th_a2t_arr; a2tp->acron; ++ a2tp) {
            if (((jrp->etype == a2tp->etype) || (-1 == a2tp->etype)) &&
                strcase_eq(tavp->acron, a2tp->acron))
                break;
        }
        if (a2tp->acron) {
            s_byte = a2tp->start_byte;
            s_bit = a2tp->start_bit;
            n_bits = a2tp->num_bits;
        } else {
            fprintf(stderr, "acroynm %s not found for Threshold In/Out "
                    "page (try '-ll' option)\n", tavp->acron);
            return -1;
        }
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
            fprintf(stderr, "couldn't send Threshold Out page\n");
            return -1;
        }
    }
    return 0;
}

/* Do clear/get/set (cgs) on Additional element status page. Return 0 for
 * ok else -1 . */
static int
cgs_additional_el(const struct join_row_t * jrp,
                  const struct tuple_acronym_val * tavp,
                  const struct opts_t * op)
{
    int s_byte, s_bit, n_bits;
    uint64_t ui;
    const struct acronym2tuple * a2tp;

    if (NULL == jrp->add_elem_statp) {
        fprintf(stderr, "No additional element status element available\n");
        return -1;
    }
    if (NULL == tavp->acron) {
        s_byte = tavp->start_byte;
        s_bit = tavp->start_bit;
        n_bits = tavp->num_bits;
    }
    if (tavp->acron) {
        for (a2tp = ae_sas_a2t_arr; a2tp->acron; ++ a2tp) {
            if (((jrp->etype == a2tp->etype) || (-1 == a2tp->etype)) &&
                strcase_eq(tavp->acron, a2tp->acron))
                break;
        }
        if (a2tp->acron) {
            s_byte = a2tp->start_byte;
            s_bit = a2tp->start_bit;
            n_bits = a2tp->num_bits;
        } else {
            fprintf(stderr, "acroynm %s not found for Additional element "
                    "status page (try '-ll' option)\n", tavp->acron);
            return -1;
        }
    }
    if (op->get_str) {
        ui = get_big_endian(jrp->add_elem_statp + s_byte, s_bit, n_bits);
        if (op->do_hex)
            printf("0x%" PRIx64 "\n", ui);
        else
            printf("%" PRId64 "\n", (int64_t)ui);
    } else {
        fprintf(stderr, "--clear and --set not available for Additional "
                "element status page\n");
        return -1;
    }
    return 0;
}

/* Do --clear, --get or --set .
 * Returns 0 for success, any other return value is an error. */
static int
ses_cgs(int sg_fd, const struct tuple_acronym_val * tavp,
        const struct opts_t * op)
{
    int ret, k, ov, ind_ov, ind, desc_len, dn_len;
    const struct join_row_t * jrp;
    const unsigned char * ed_ucp;

    ret = process_join(sg_fd, op, 0);
    if (ret)
        return ret;
    dn_len = op->desc_name ? (int)strlen(op->desc_name) : 0;
    ind_ov = (2 == op->index_given);
    for (k = 0, jrp = join_arr; ((k < MX_JOIN_ROWS) && jrp->enc_statp);
         ++k, ++jrp) {
        ov = (jrp->el_ov_ind > 999);
        ind = ov ? jrp->el_ov_ind - 1000 : jrp->el_ov_ind;
        if (op->index_given) {
            if (ind_ov != ov)
                continue;
            if (ind != op->index_elem_ov)
                continue;
        } else if (op->desc_name) {
            ed_ucp = jrp->elem_descp;
            if (NULL == ed_ucp)
                continue;
            desc_len = (ed_ucp[2] << 8) + ed_ucp[3];
            if (desc_len != dn_len)
                continue;
            if (0 != strncmp(op->desc_name, (const char *)(ed_ucp + 4),
                             desc_len))
                continue;
        }
        if ((0 == op->page_code_given) || (DPC_ENC_CONTROL == op->page_code))
            ret = cgs_enc_ctl_stat(sg_fd, jrp, tavp, op);
        else if (DPC_THRESHOLD == op->page_code)
            ret = cgs_threshold(sg_fd, jrp, tavp, op);
        else if (DPC_ADD_ELEM_STATUS == op->page_code)
            ret = cgs_additional_el(jrp, tavp, op);
        else {
            fprintf(stderr, "page %s not supported for cgs\n",
                    find_element_tname(op->page_code));
            ret = -1;
        }
        if (ret)
            return ret;
        break;
    }
    if ((NULL == jrp->enc_statp) || (k >= MX_JOIN_ROWS)) {
        if (op->desc_name)
            fprintf(stderr, "descriptor name: %s not found (check page "
                    "7)\n", op->desc_name);
        else
            fprintf(stderr, "index: %s%d not found\n", (ind_ov ? "ov" : ""),
                    op->index_elem_ov);
        return -1;
    }
    return 0;
}

/* Output from --list option. Note it is different when given twice. */
static void
process_do_list(const struct opts_t * op)
{
    const struct diag_page_code * pcdp;
    const struct element_type_t * etp;
    const struct acronym2tuple * a2tp;
    const char * cp;

    if (op->device_name)
        printf(">>> DEVICE %s ignored when --list option given.\n",
               op->device_name);
    if (op->do_list < 2) {
        printf("Known diagnostic pages (followed by page code):\n");
        for (pcdp = dpc_arr; pcdp->desc; ++pcdp)
            printf("    %s  [0x%x]\n", pcdp->desc, pcdp->page_code);
        printf("\nKnown SES element type names (followed by element type "
               "code):\n");
        for (etp = element_type_arr; etp->desc; ++etp)
            printf("    %s  [0x%x]\n", etp->desc, etp->elem_type_code);
    } else {
        printf("--clear, --get, --set acronyms for enclosure status/control "
               "page:\n");
        for (a2tp = ecs_a2t_arr; a2tp->acron; ++a2tp) {
            cp = (a2tp->etype < 0) ? "*" : find_element_tname(a2tp->etype);
            printf("    %s  [%s] [%d:%d:%d]\n", a2tp->acron, (cp ? cp : "??"),
                   a2tp->start_byte, a2tp->start_bit, a2tp->num_bits);
        }
        printf("\n--clear, --get, --set acronyms for threshold in/out "
               "page:\n");
        for (a2tp = th_a2t_arr; a2tp->acron; ++a2tp) {
            cp = (a2tp->etype < 0) ? "*" : find_element_tname(a2tp->etype);
            printf("    %s  [%s] [%d:%d:%d]\n", a2tp->acron, (cp ? cp : "??"),
                   a2tp->start_byte, a2tp->start_bit, a2tp->num_bits);
        }
        printf("\n--clear, --get, --set acronyms for additional element "
               "status page (SAS EIP=1):\n");
        for (a2tp = ae_sas_a2t_arr; a2tp->acron; ++a2tp) {
            cp = (a2tp->etype < 0) ? "*" : find_element_tname(a2tp->etype);
            printf("    %s  [%s] [%d:%d:%d]\n", a2tp->acron, (cp ? cp : "??"),
                   a2tp->start_byte, a2tp->start_bit, a2tp->num_bits);
        }
    }
}


int
main(int argc, char * argv[])
{
    int sg_fd, res;
    char buff[128];
    int pd_type = 0;
    int have_cgs = 0;
    int ret = 0;
    struct sg_simple_inquiry_resp inq_resp;
    const char * cp;
    struct opts_t opts;
    struct tuple_acronym_val tav;

    memset(&opts, 0, sizeof(opts));
    res = process_cl(&opts, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (opts.do_version) {
        fprintf(stderr, "version: %s\n", version_str);
        return 0;
    }
    if (opts.do_help) {
        usage();
        return 0;
    }
    if (opts.do_list) {
        process_do_list(&opts);
        return 0;
    }
    if (opts.clear_str || opts.get_str || opts.set_str) {
        have_cgs = 1;
        cp = opts.clear_str ? opts.clear_str :
             (opts.get_str ? opts.get_str : opts.set_str);
        strncpy(buff, cp, sizeof(buff) - 1);
        buff[sizeof(buff) - 1] = '\0';
        if (parse_cgs_str(buff, &tav)) {
            fprintf(stderr, "unable to decode STR argument to --clear, "
                    "--get or --set\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (opts.get_str && tav.val_str)
            fprintf(stderr, "eith --get option ignoring =<val> at the end "
                    "of STR argument\n");
        if ((0 == opts.index_given) && (! opts.desc_name)) {
            fprintf(stderr, "with --clear, --get or --set option need "
                    "either --index or --descriptor\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (NULL == tav.val_str) {
            if (opts.clear_str)
                tav.val = 0;
            if (opts.set_str)
                tav.val = 1;
        }
        if (opts.page_code_given && (DPC_ENC_STATUS != opts.page_code) &&
            (DPC_THRESHOLD != opts.page_code) &&
            (DPC_ADD_ELEM_STATUS != opts.page_code)) {
            fprintf(stderr, "--clear, --get or --set options only supported "
                            "for the Enclosure\nControl/Status, Threshold "
                            "In/Out and Additional Element Status pages\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(opts.device_name, 0 /* rw */, opts.verbose);
    if (sg_fd < 0) {
        fprintf(stderr, "open error: %s: %s\n", opts.device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (! (opts.do_raw || have_cgs)) {
        if (sg_simple_inquiry(sg_fd, &inq_resp, 1, opts.verbose)) {
            fprintf(stderr, "%s doesn't respond to a SCSI INQUIRY\n",
                    opts.device_name);
            ret = SG_LIB_CAT_OTHER;
            goto err_out;
        } else {
            printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor,
                   inq_resp.product, inq_resp.revision);
            pd_type = inq_resp.peripheral_type;
            cp = sg_get_pdt_str(pd_type, sizeof(buff), buff);
            if (0xd == pd_type)
                printf("    enclosure services device\n");
            else if (0x40 & inq_resp.byte_6)
                printf("    %s device has EncServ bit set\n", cp);
            else
                printf("    %s device (not an enclosure)\n", cp);
        }
    }
    if (have_cgs)
        ret = ses_cgs(sg_fd, &tav, &opts);
    else if (opts.do_join)
        ret = process_join(sg_fd, &opts, 1);
    else if (opts.do_status)
        ret = ses_process_status(sg_fd, &opts);
    else { /* control page requested */
        opts.data_arr[0] = opts.page_code;
        opts.data_arr[1] = opts.byte1;
        opts.data_arr[2] = (opts.arr_len >> 8) & 0xff;
        opts.data_arr[3] = opts.arr_len & 0xff;
        switch (opts.page_code) {
        case 0x2:       /* Enclosure control diagnostic page */
            printf("Sending Enclosure control [0x%x] page, with page "
                   "length=%d bytes\n", opts.page_code, opts.arr_len);
            ret = do_senddiag(sg_fd, 1, opts.data_arr, opts.arr_len + 4, 1,
                              opts.verbose);
            if (ret) {
                fprintf(stderr, "couldn't send Enclosure control page\n");
                goto err_out;
            }
            break;
        case 0x4:       /* String Out diagnostic page */
            printf("Sending String Out [0x%x] page, with page length=%d "
                   "bytes\n", opts.page_code, opts.arr_len);
            ret = do_senddiag(sg_fd, 1, opts.data_arr, opts.arr_len + 4, 1,
                              opts.verbose);
            if (ret) {
                fprintf(stderr, "couldn't send String Out page\n");
                goto err_out;
            }
            break;
        case 0x5:       /* Threshold Out diagnostic page */
            printf("Sending Threshold Out [0x%x] page, with page length=%d "
                   "bytes\n", opts.page_code, opts.arr_len);
            ret = do_senddiag(sg_fd, 1, opts.data_arr, opts.arr_len + 4, 1,
                              opts.verbose);
            if (ret) {
                fprintf(stderr, "couldn't send Threshold Out page\n");
                goto err_out;
            }
            break;
        case 0x6:       /* Array control diagnostic page (obsolete) */
            printf("Sending Array control [0x%x] page, with page "
                   "length=%d bytes\n", opts.page_code, opts.arr_len);
            ret = do_senddiag(sg_fd, 1, opts.data_arr, opts.arr_len + 4, 1,
                              opts.verbose);
            if (ret) {
                fprintf(stderr, "couldn't send Array control page\n");
                goto err_out;
            }
            break;
        case 0xc:       /* Subenclosure String Out diagnostic page */
            printf("Sending Subenclosure String Out [0x%x] page, with page "
                   "length=%d bytes\n", opts.page_code, opts.arr_len);
            ret = do_senddiag(sg_fd, 1, opts.data_arr, opts.arr_len + 4, 1,
                              opts.verbose);
            if (ret) {
                fprintf(stderr, "couldn't send Subenclosure String Out "
                        "page\n");
                goto err_out;
            }
            break;
        default:
            fprintf(stderr, "Setting SES control page 0x%x not supported "
                    "by this utility\n", opts.page_code);
            fprintf(stderr, "That can be done with the sg_senddiag utility "
                    "with its '--raw=' option\n");
            ret = SG_LIB_SYNTAX_ERROR;
            break;
        }
    }

err_out:
    if (0 == opts.do_status) {
        switch (ret) {
        case SG_LIB_CAT_NOT_READY:
            fprintf(stderr, "    device no ready\n");
            break;
        case SG_LIB_CAT_ABORTED_COMMAND:
            fprintf(stderr, "    aborted command\n");
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            fprintf(stderr, "    unit attention\n");
            break;
        case SG_LIB_CAT_INVALID_OP:
            fprintf(stderr, "    Send diagnostics command not supported\n");
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            fprintf(stderr, "    Send diagnostics command, bad field in "
                    "cdb\n");
            break;
        }
    }
    if (ret && (0 == opts.verbose))
        fprintf(stderr, "Problem detected, try again with --verbose option "
                "for more information\n");
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
