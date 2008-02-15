/*
 * Copyright (c) 2004-2008 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

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

static char * version_str = "1.42 20080214";    /* ses2r19b */

#define MX_ALLOC_LEN 4096
#define MX_ELEM_HDR 1024

#define TEMPERATURE_OFFSET 20   /* 8 bits represents -19 C to +235 C */
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


static struct option long_options[] = {
        {"byte1", 1, 0, 'b'},
        {"control", 0, 0, 'c'},
        {"data", 1, 0, 'd'},
        {"filter", 0, 0, 'f'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"inner-hex", 0, 0, 'i'},
        {"list", 0, 0, 'l'},
        {"page", 1, 0, 'p'},
        {"raw", 0, 0, 'r'},
        {"status", 0, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    fprintf(stderr, "Usage: "
          "sg_ses [--byte1=B1] [--control] [--data=H,H...] [--filter] "
          "[--help]\n"
          "              [--hex] [--inner-hex] [--list] [--page=PG] [--raw] "
          "[--status]\n"
          "              [--verbose] [--version] DEVICE\n"
          "  where:\n"
          "    --byte1=B1|-b B1  byte 1 (2nd byte) for some control "
          "pages\n"
          "    --control|-c        send control information (def: fetch "
          "status)\n"
          "    --data=H,H...|-d H,H...    string of ASCII hex bytes for "
          "control pages\n"
          "    --data=- | -d -     fetch string of ASCII hex bytes from "
          "stdin\n"
          "    --filter|-f         filter out enclosure status clear "
          "flags\n"
          "    --help|-h           print out usage message\n"
          "    --hex|-H            print status response in hex\n"
          "    --inner-hex|-i      print innermost level of a"
          " status page in hex\n"
          "    --list|-l           list known pages and elements (ignore"
          " DEVICE)\n"
          "    --page=PG|-p PG     SES page code PG (prefix with '0x' "
          "for hex; def: 0)\n"
          "    --raw|-r            print status page in ASCII hex suitable "
          "for '-d';\n"
          "                        when used twice outputs page in binary "
          "to stdout\n"
          "    --status|-s         fetch status information\n"
          "    --verbose|-v        increase verbosity\n"
          "    --version|-V        print version string and exit\n\n"
          "Fetches status or sends control data to a SCSI enclosure\n"
          );
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

struct diag_page_code {
        int page_code;
        const char * desc;
};

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
        {DPC_ADD_ELEM_STATUS, "Additional (device) element status (SES-2)"},
        {DPC_SUBENC_HELP_TEXT, "Subenclosure help text (SES-2)"},
        {DPC_SUBENC_STRING, "Subenclosure string In/Out (SES-2)"},
        {DPC_SUPPORTED_SES, "Supported SES diagnostic pages (SES-2)"},
        {DPC_DOWNLOAD_MICROCODE, "Download microcode (SES-2)"},
        {DPC_SUBENC_NICKNAME, "Subenclosure nickname (SES-2)"},
        {0x3f, "Protocol specific SAS (SAS-1)"},
        {0x40, "Translate address (SBC)"},
        {0x41, "Device status (SBC)"},
};
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
        {DPC_ADD_ELEM_STATUS, "Additional (device) element status (SES-2)"},
        {DPC_SUBENC_HELP_TEXT, "Subenclosure help text (SES-2)"},
        {DPC_SUBENC_STRING, "Subenclosure string In (SES-2)"},
        {DPC_SUPPORTED_SES, "Supported SES diagnostic pages (SES-2)"},
        {DPC_DOWNLOAD_MICROCODE, "Download microcode (SES-2)"},
        {DPC_SUBENC_NICKNAME, "Subenclosure nickname (SES-2)"},
        {0x3f, "Protocol specific SAS (SAS-1)"},
        {0x40, "Translate address (SBC)"},
        {0x41, "Device status (SBC)"},
};

static const char *
find_diag_page_desc(int page_num)
{
    int k;
    int num = sizeof(dpc_arr) / sizeof(dpc_arr[0]);
    const struct diag_page_code * pcdp = &dpc_arr[0];

    for (k = 0; k < num; ++k, ++pcdp) {
        if (page_num == pcdp->page_code)
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            return NULL;
    }
    return NULL;
}

static const char *
find_in_diag_page_desc(int page_num)
{
    int k;
    int num = sizeof(in_dpc_arr) / sizeof(in_dpc_arr[0]);
    const struct diag_page_code * pcdp = &in_dpc_arr[0];

    for (k = 0; k < num; ++k, ++pcdp) {
        if (page_num == pcdp->page_code)
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            return NULL;
    }
    return NULL;
}

struct element_type_t {
        int elem_type_code;
        const char * desc;
};
static struct element_type_t element_type_arr[] = {
        {0x0, "Unspecified"},
        {DEVICE_ETC, "Device"},
        {POWER_SUPPLY_ETC, "Power supply"},
        {COOLING_ETC, "Cooling"},
        {TEMPERATURE_ETC, "Temperature sense"},
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
        {ARRAY_DEV_ETC, "Array device"},
        {SAS_EXPANDER_ETC, "SAS expander"},
        {SAS_CONNECTOR_ETC, "SAS connector"},
};

static const char *
find_element_desc(int elem_type_code)
{
    int k;
    int num = sizeof(element_type_arr) / sizeof(element_type_arr[0]);
    const struct element_type_t * etp = &element_type_arr[0];

    for (k = 0; k < num; ++k, ++etp) {
        if (elem_type_code == etp->elem_type_code)
            return etp->desc;
        else if (elem_type_code < etp->elem_type_code)
            return NULL;
    }
    return NULL;
}

#if 0
static const char *
get_element_type_desc(int elem_type_code, int b_len, char * b)
{
    const char * elem_desc;

    if (b_len > 0)
        b[b_len - 1] = '\0';
    elem_desc = find_element_desc(elem_type_code);
    if (elem_desc)
        snprintf(b, b_len - 1, "%s", elem_desc);
    else
        snprintf(b, b_len - 1, "unknown element type code=0x%x", elem_type_code);
    return b;
}
#endif

struct type_desc_hdr_t {
    unsigned char etype;
    unsigned char num_elements;
    unsigned char se_id;
    unsigned char unused;       /* type descriptor text length; not needed */
};

static struct type_desc_hdr_t type_desc_hdr_arr[MX_ELEM_HDR];

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

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
    ucp = resp + 8;
    for (k = 0; k < num_subs; ++k, ucp += el) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        el = ucp[3] + 4;
        sum_elem_types += ucp[2];
        printf("    Subenclosure identifier: %d\n", ucp[1]);
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
    text_ucp = ucp + (sum_elem_types * 4);
    for (k = 0; k < sum_elem_types; ++k, ucp += 4) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        cp = find_element_desc(ucp[0]);
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
            printf("      Description: %.*s\n", ucp[3], text_ucp);
            text_ucp += ucp[3];
        }
    }
    return;
truncated:
    fprintf(stderr, "    <<<ses_configuration_sdg: response too short>>>\n");
    return;
}

/* Returns number of elements written to 'tdhp' or -1 if there is
   a problem */ 
static int
populate_type_desc_hdr_arr(int fd, struct type_desc_hdr_t * tdhp,
                         unsigned int * generationp, int verbose)
{
    int resp_len, k, el, num_subs, sum_elem_types, res;
    unsigned int gen_code;
    unsigned char resp[MX_ALLOC_LEN];
    int rsp_buff_size = MX_ALLOC_LEN;
    const unsigned char * ucp;
    const unsigned char * last_ucp;

    res = sg_ll_receive_diag(fd, 1 /* pcv */, DPC_ENC_STATUS, resp,
                             rsp_buff_size, 1, verbose);
    if (0 == res) {
        resp_len = (resp[2] << 8) + resp[3] + 4;
        if (resp_len > rsp_buff_size) {
            fprintf(stderr, "<<< warning: response buffer too small "
                    "[%d but need %d]>>>\n", rsp_buff_size, resp_len);
            resp_len = rsp_buff_size;
        }
        if (1 != resp[0]) {
            if ((0x9 == resp[0]) && (1 & resp[1]))
                printf("Enclosure busy, try again later\n");
            else if (0x8 == resp[0])
                printf("Enclosure only supports Short Enclosure status: "
                       "0x%x\n", resp[1]);
            else
                printf("Invalid response, wanted page code: 0x%x but got "
                       "0x%x\n", 1, resp[0]);
            return -1;
        }
        if (resp_len < 4)
            return -1;
        num_subs = resp[1] + 1;
        sum_elem_types = 0;
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
            sum_elem_types += ucp[2];
            if (el < 40) {
                fprintf(stderr, "populate: short enc descriptor len=%d ??\n",
                        el);
                continue;
            }
        }
        for (k = 0; k < sum_elem_types; ++k, ucp += 4) {
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
        return sum_elem_types;
    } else {
        fprintf(stderr, "populate: couldn't read config page, res=%d\n", res);
        return -1;
    }
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
    case 0x2f:
        snprintf(buff, buff_len, "SAS virtual connector [max 1 phy]");
        break;
    case 0x3f:
        snprintf(buff, buff_len, "Vendor specific internal connector");
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
print_element_status(const char * pad, const unsigned char * statp, int etype,
                     int filter)
{
    int res, a, b;
    char buff[128];

    printf("%sPredicted failure=%d, Disabled=%d, Swap=%d, status: %s\n",
           pad, !!(statp[0] & 0x40), !!(statp[0] & 0x20),
           !!(statp[0] & 0x10), elem_status_code_desc[statp[0] & 0xf]);
    switch (etype) { /* element types */
    case 0:     /* unspecified */
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
                   (int)statp[2] - TEMPERATURE_OFFSET);
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
    case ESC_ELECTRONICS_ETC:     /* enclosure services controller electronics */
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
#ifdef SG3_UTILS_MINGW
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
#ifdef SG3_UTILS_MINGW
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
            printf("%sApp client bypass A=%d, Don't remove=%d, Enc bypass "
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

static void
ses_enc_status_dp(const struct type_desc_hdr_t * tdhp, int num_telems,
                  unsigned int ref_gen_code, const unsigned char * resp,
                  int resp_len, int inner_hex, int filter)
{
    int j, k;
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
    ucp = resp + 8;
    for (k = 0; k < num_telems; ++k) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        cp = find_element_desc(tdhp[k].etype);
        if (cp)
            printf("    Element type: %s, subenclosure id: %d\n",
                   cp, tdhp[k].se_id);
        else
            printf("    Element type: [0x%x], subenclosure id: %d\n",
                   tdhp[k].etype, tdhp[k].se_id);
        if (inner_hex)
            printf("    Overall status(hex): %02x %02x %02x %02x\n", ucp[0],
                   ucp[1], ucp[2], ucp[3]);
        else {
            printf("    Overall status:\n");
            print_element_status("     ", ucp, tdhp[k].etype, filter);
        }
        for (ucp += 4, j = 0; j < tdhp[k].num_elements; ++j, ucp += 4) {
            if (inner_hex)
                printf("      Individual element %d status(hex): %02x %02x "
                       "%02x %02x\n", j + 1, ucp[0], ucp[1], ucp[2], ucp[3]);
            else {
                printf("      Individual element %d status:\n", j + 1);
                print_element_status("       ", ucp, tdhp[k].etype, filter);
            }
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
                     int p_num, int inner_hex, int verbose)
{
    char buff[128];
    char b[128];
    char b2[128];

    if (p_num < 0)
        strcpy (buff, "Overall threshold");
    else
        snprintf(buff, sizeof(buff) - 1, "Individual threshold status "
                 "element %d", p_num + 1);
    if (inner_hex) {
        printf("%s%s (in hex): %02x %02x %02x %02x\n", pad, buff,
               tp[0], tp[1], tp[2], tp[3]);
        return;
    }
    switch (etype) {
    case 0x4:  /*temperature */
        printf("%s%s: high critical=%s, high warning=%s\n", pad,
               buff, reserved_or_num(b, 128, tp[0] - TEMPERATURE_OFFSET,
                                     -TEMPERATURE_OFFSET),
               reserved_or_num(b2, 128, tp[1] - TEMPERATURE_OFFSET,
                               -TEMPERATURE_OFFSET));
        printf("%s  low warning=%s, low critical=%s (in degrees Celsius)\n", pad,
               reserved_or_num(b, 128, tp[2] - TEMPERATURE_OFFSET,
                               -TEMPERATURE_OFFSET),
               reserved_or_num(b2, 128, tp[3] - TEMPERATURE_OFFSET, 
                               -TEMPERATURE_OFFSET));
        break;
    case 0xb:  /* UPS */
        if (0 == tp[2])
            strcpy(b, "<vendor>");
        else
            snprintf(b, sizeof(b), "%d", tp[2]);
        printf("%s%s: low warning=%s, ", pad, buff, b);
        if (0 == tp[3])
            strcpy(b, "<vendor>");
        else
            snprintf(b, sizeof(b), "%d", tp[3]);
        printf("low critical=%s (in minutes)\n", b);
        break;
    case 0x12: /* voltage */
#ifdef SG3_UTILS_MINGW
        printf("%s%s: high critical=%g %%, high warning=%g %%\n", pad,
               buff, 0.5 * tp[0], 0.5 * tp[1]);
        printf("%s  low warning=%g %%, low critical=%g %% (from nominal "
               "voltage)\n", pad, 0.5 * tp[2], 0.5 * tp[3]);
#else
        printf("%s%s: high critical=%.1f %%, high warning=%.1f %%\n", pad,
               buff, 0.5 * tp[0], 0.5 * tp[1]);
        printf("%s  low warning=%.1f %%, low critical=%.1f %% (from nominal "
               "voltage)\n", pad, 0.5 * tp[2], 0.5 * tp[3]);
#endif
        break;
    case 0x13: /* current */
#ifdef SG3_UTILS_MINGW
        printf("%s%s: high critical=%g %%, high warning=%g %%\n", pad,
               buff, 0.5 * tp[0], 0.5 * tp[1]);
#else
        printf("%s%s: high critical=%.1f %%, high warning=%.1f %%\n", pad,
               buff, 0.5 * tp[0], 0.5 * tp[1]);
#endif
        printf("%s  (above nominal current)\n", pad);
        break;
    default:
        if (verbose)
            printf("%s<< no thresholds for this element type >>\n", pad);
        break;
    }
}

static void
ses_threshold_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                  unsigned int ref_gen_code, const unsigned char * resp,
                  int resp_len, int inner_hex, int verbose)
{
    int j, k;
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
    ucp = resp + 8;
    for (k = 0; k < num_telems; ++k) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        cp = find_element_desc(tdhp[k].etype);
        if (cp)
            printf("    Element type: %s, subenclosure id: %d\n",
                   cp, tdhp[k].se_id);
        else
            printf("    Element type: [0x%x], subenclosure id: %d\n",
                   tdhp[k].etype, tdhp[k].se_id);
        ses_threshold_helper("    ", ucp, tdhp[k].etype, -1, inner_hex,
                             verbose);
        for (ucp += 4, j = 0; j < tdhp[k].num_elements; ++j, ucp += 4) {
            ses_threshold_helper("      ", ucp, tdhp[k].etype, j, inner_hex,
                                 verbose);
        }
    }
    return;
truncated:
    fprintf(stderr, "    <<<thresh: response too short>>>\n");
    return;
}

static void
ses_element_desc_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                     unsigned int ref_gen_code, const unsigned char * resp,
                     int resp_len)
{
    int j, k, desc_len;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const char * cp;

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
    ucp = resp + 8;
    for (k = 0; k < num_telems; ++k) {
        if ((ucp + 3) > last_ucp)
            goto truncated;
        cp = find_element_desc(tdhp[k].etype);
        if (cp)
            printf("    Element type: %s, subenclosure id: %d\n",
                   cp, tdhp[k].se_id);
        else
            printf("    Element type: [0x%x], subenclosure id: %d\n",
                   tdhp[k].etype, tdhp[k].se_id);
        desc_len = (ucp[2] << 8) + ucp[3] + 4;
        if (desc_len > 4)
            printf("    Overall descriptor: %.*s\n", desc_len - 4, ucp + 4);
        else
            printf("    Overall descriptor: <empty>\n");
        for (ucp += desc_len, j = 0; j < tdhp[k].num_elements; ++j, ucp += desc_len) {
            desc_len = (ucp[2] << 8) + ucp[3] + 4;
            if (desc_len > 4)
                printf("      Element %d descriptor: %.*s\n", j + 1,
                       desc_len - 4, ucp + 4);
            else
                printf("      Element %d descriptor: <empty>\n", j + 1);
        }
    }
    return;
truncated:
    fprintf(stderr, "    <<<element: response too short>>>\n");
    return;
}


static char * sas_device_type[] = {
    "no device attached",
    "end device",
    "edge expander device",
    "fanout expander device",
    "reserved [4]", "reserved [5]", "reserved [6]", "reserved [7]"
};

static void
ses_additional_elem_each(const unsigned char * ucp, int len, int elem_num,
                         int elem_type)
{
    int ports, phys, j, m, desc_type, eip_offset;
    const unsigned char * per_ucp;
    char b[64];

    eip_offset = (0x10 & ucp[0]) ? 2 : 0;
    switch (0xf & ucp[0]) {
    case TPROTO_FCP:
        ports = ucp[2 + eip_offset];
        printf("    Transport protocol: FCP\n");
#if 0
        printf("%s element\n", get_element_desc(elem_type, sizeof(b), b));
#endif
        printf("    number of ports: %d\n", ports);
        printf("    node_name: ");
        for (m = 0; m < 8; ++m)
            printf("%02x", ucp[6 + eip_offset + m]);
        if (eip_offset)
            printf(", bay number: %d", ucp[5 + eip_offset]);
        printf("\n");
        per_ucp = ucp + 14 + eip_offset;
        for (j = 0; j < ports; ++j, per_ucp += 16) {
            printf("    port index: %d, port loop position: %d, port "
                   "bypass reason: 0x%x\n", j, per_ucp[0], per_ucp[1]);
            printf("      requested hard address: %d, n_port "
                   "identifier: %02x%02x%02x\n", per_ucp[4], per_ucp[5],
                   per_ucp[6], per_ucp[7]);
            printf("      n_port name: ");
            for (m = 0; m < 8; ++m)
                printf("%02x", per_ucp[8 + m]);
            printf("\n");
        }
        break;
    case TPROTO_SAS:
        desc_type = (ucp[3 + eip_offset] >> 6) & 0x3;
        printf("    Transport protocol: SAS\n");
#if 0
        printf("%s element\n", get_element_desc(elem_type, sizeof(b), b));
#endif
        if (0 == desc_type) {
            phys = ucp[2 + eip_offset];
            printf("    number of phys: %d, not all phys: %d", phys,
                   ucp[3 + eip_offset] & 1);
            if (eip_offset)
                printf(", bay number: %d", ucp[5 + eip_offset]);
            printf("\n");
            per_ucp = ucp + 4 + eip_offset + eip_offset;
            for (j = 0; j < phys; ++j, per_ucp += 28) {
                printf("    phy index: %d\n", j);
                printf("      device type: %s\n",
                       sas_device_type[(0x70 & per_ucp[0]) >> 4]);
                printf("      initiator port for:%s%s%s\n",
                       ((per_ucp[2] & 8) ? " SSP" : ""),
                       ((per_ucp[2] & 4) ? " STP" : ""),
                       ((per_ucp[2] & 2) ? " SMP" : ""));
                printf("      target port for:%s%s%s%s%s\n",
                       ((per_ucp[3] & 0x80) ? " SATA_port_selector" : ""),
                       ((per_ucp[3] & 8) ? " SSP" : ""),
                       ((per_ucp[3] & 4) ? " STP" : ""),
                       ((per_ucp[3] & 2) ? " SMP" : ""),
                       ((per_ucp[3] & 1) ? " SATA_device" : ""));
                printf("      attached SAS address: 0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", per_ucp[4 + m]);
                printf("\n      SAS address: 0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", per_ucp[12 + m]);
                printf("\n      phy identifier: 0x%x\n", per_ucp[20]);
            }
        } else if (1 == desc_type) {
            phys = ucp[2 + eip_offset];
            if (SAS_EXPANDER_ETC == elem_type) {
                printf("    number of phys: %d\n", phys);
                printf("    SAS address: 0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", ucp[6 + eip_offset + m]);
                printf("\n");
                per_ucp = ucp + 14 + eip_offset;
                for (j = 0; j < phys; ++j, per_ucp += 2) {
                    printf("      [%d] ", j);
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
                printf("    number of phys: %d\n", phys);
                per_ucp = ucp + 6 + eip_offset;
                for (j = 0; j < phys; ++j, per_ucp += 12) {
                    printf("    phy index: %d\n", j);
                    printf("      phy identifier: 0x%x\n", per_ucp[0]);
                    if (0xff == per_ucp[2])
                        printf("      no attached connector");
                    else
                        printf("      connector element index: %d",
                               per_ucp[2]);
                    if (0xff != per_ucp[3])
                        printf(", other element index: %d", per_ucp[3]);
                    printf("\n");
                    printf("      SAS address: 0x");
                    for (m = 0; m < 8; ++m)
                        printf("%02x", per_ucp[4 + m]);
                    printf("\n");
                }
            } else
                printf("    unrecognised element type [%d] for desc_type 1\n",
                       elem_type);
        } else
            printf("    unrecognised descriptor type [%d]\n", desc_type);
        break;
    default:
        printf("   [%d] Transport protocol: %s not decoded, in hex:\n",
               elem_num + 1,
               sg_get_trans_proto_str((0xf & ucp[0]), sizeof(b), b));
        dStrHex((const char *)ucp, len, 0);
        break;
    }
}

/* Previously called "Device element status descriptor". Changed "device"
   to "additional" to allow for SAS expander and SATA devices */
static void
ses_additional_elem_sdg(const struct type_desc_hdr_t * tdhp, int num_telems,
                        unsigned int ref_gen_code, const unsigned char * resp,
                        int resp_len, int inner_hex)
{
    int j, k, desc_len, elem_type, invalid;
    unsigned int gen_code;
    const unsigned char * ucp;
    const unsigned char * last_ucp;
    const char * cp;

    printf("Additional (device) element status diagnostic page:\n");
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
    ucp = resp + 8;
    for (k = 0; k < num_telems; ++k) {
        elem_type = tdhp[k].etype;
        if (! ((DEVICE_ETC == elem_type) ||
               (SCSI_TPORT_ETC == elem_type) ||
               (SCSI_IPORT_ETC == elem_type) ||
               (ARRAY_DEV_ETC == elem_type) ||
               (SAS_EXPANDER_ETC == elem_type) ||
               (ESC_ELECTRONICS_ETC == elem_type)))
            continue;   /* skip if not one of above element types */
        if ((ucp + 1) > last_ucp)
            goto truncated;
        cp = find_element_desc(elem_type);
        if (cp)
            printf("  Element type: %s, subenclosure id: %d\n",
                   cp, tdhp[k].se_id);
        else
            printf("  Element type: [0x%x], subenclosure id: %d\n",
                   tdhp[k].etype, tdhp[k].se_id);
        for (j = 0; j < tdhp[k].num_elements; ++j, ucp += desc_len) {
            invalid = !!(ucp[0] & 0x80);
            if (ucp[0] & 0x10)  /* eip=1 */
                printf("    element index: %d [0x%x]\n", ucp[3], ucp[3]);
            desc_len = ucp[1] + 2;
            if (inner_hex)
                dStrHex((const char *)ucp + 4, desc_len, 0);
            else if (invalid)
                printf("      flagged as invalid (no further information)\n");
            else
                ses_additional_elem_each(ucp, desc_len, j, elem_type);
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
    char line[512];

    if ((NULL == inp) || (NULL == arr) || (NULL == arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len) {
        *arr_len = 0;
    }
    if ('-' == inp[0]) {        /* read from stdin */
        for (j = 0, off = 0; j < 512; ++j) {
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
            for (k = 0; k < 1024; ++k) {
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
        }
        *arr_len = off;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF,");
        if (in_len != k) {
            fprintf(stderr, "read_hex: error at pos %d\n",
                    k + 1);
            return 1;
        }
        for (k = 0; k < 1024; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    fprintf(stderr, "read_hex: hex number larger "
                            "than 0xff at pos %d\n", (int)(lcp - inp + 1));
                    return 1;
                }
                arr[k] = h;
                cp = strchr(lcp, ',');
                if (NULL == cp)
                    break;
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

static int
ses_process_status(int sg_fd, int page_code, int do_raw, int do_hex,
                   int inner_hex, int filter, int verbose)
{
    int rsp_len, res;
    unsigned int ref_gen_code;
    unsigned char rsp_buff[MX_ALLOC_LEN];
    int rsp_buff_size = MX_ALLOC_LEN;
    const char * cp;

    memset(rsp_buff, 0, rsp_buff_size);
    cp = find_in_diag_page_desc(page_code);
    res = sg_ll_receive_diag(sg_fd, 1, page_code, rsp_buff,
                             rsp_buff_size, 1, verbose);
    if (0 == res) {
        rsp_len = (rsp_buff[2] << 8) + rsp_buff[3] + 4;
        if (rsp_len > rsp_buff_size) {
            fprintf(stderr, "<<< warning response buffer too small "
                    "[%d but need %d]>>>\n", rsp_buff_size, rsp_len);
            rsp_len = rsp_buff_size;
        }
        if (page_code != rsp_buff[0]) {
            if ((0x9 == rsp_buff[0]) && (1 & rsp_buff[1])) {
                fprintf(stderr, "Enclosure busy, try again later\n");
                if (do_hex)
                    dStrHex((const char *)rsp_buff, rsp_len, 0);
            } else if (0x8 == rsp_buff[0]) {
                fprintf(stderr, "Enclosure only supports Short Enclosure "
                        "status: 0x%x\n", rsp_buff[1]);
            } else {
                fprintf(stderr, "Invalid response, wanted page code: 0x%x "
                        "but got 0x%x\n", page_code, rsp_buff[0]);
                dStrHex((const char *)rsp_buff, rsp_len, 0);
            }
        } else if (do_raw) {
            if (1 == do_raw)
                dStrHex((const char *)rsp_buff + 4, rsp_len - 4, -1);
            else
                dStrRaw((const char *)rsp_buff, rsp_len);
        } else if (do_hex) {
            if (cp)
                printf("Response in hex from diagnostic page: %s\n", cp);
            else
                printf("Response in hex from unknown diagnostic page "
                       "[0x%x]\n", page_code);
            dStrHex((const char *)rsp_buff, rsp_len, 0);
        } else {
            switch (page_code) {
            case DPC_SUPPORTED: 
                ses_supported_pages_sdg("Supported diagnostic pages",
                                        rsp_buff, rsp_len);
                break;
            case DPC_CONFIGURATION: 
                ses_configuration_sdg(rsp_buff, rsp_len);
                break;
            case DPC_ENC_STATUS: 
                res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                               &ref_gen_code, verbose);
                if (res < 0)
                    break;
                ses_enc_status_dp(type_desc_hdr_arr, res, ref_gen_code,
                                  rsp_buff, rsp_len, inner_hex, filter);
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
                                               &ref_gen_code, verbose);
                if (res < 0)
                    break;
                ses_threshold_sdg(type_desc_hdr_arr, res, ref_gen_code,
                                  rsp_buff, rsp_len, inner_hex, verbose);
                break;
            case DPC_ELEM_DESC: 
                res = populate_type_desc_hdr_arr(sg_fd, type_desc_hdr_arr,
                                               &ref_gen_code, verbose);
                if (res < 0)
                    break;
                ses_element_desc_sdg(type_desc_hdr_arr, res, ref_gen_code,
                                     rsp_buff, rsp_len);
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
                                               &ref_gen_code, verbose);
                if (res < 0)
                    break;
                ses_additional_elem_sdg(type_desc_hdr_arr, res, ref_gen_code,
                                        rsp_buff, rsp_len, inner_hex);
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
    } else {
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


int
main(int argc, char * argv[])
{
    int sg_fd, res, c;
    int do_control = 0;
    int do_data = 0;
    int do_filter = 0;
    int do_hex = 0;
    int do_raw = 0;
    int do_list = 0;
    int do_status = 0;
    int page_code = 0;
    int verbose = 0;
    int inner_hex = 0;
    int byte1 = 0;
    const char * device_name = NULL;
    char buff[48];
    unsigned char data_arr[1024];
    int arr_len = 0;
    int pd_type = 0;
    int ret = 0;
    struct sg_simple_inquiry_resp inq_resp;
    const char * cp;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:cd:fhHilp:rsvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            byte1 = sg_get_num(optarg);
            if ((byte1 < 0) || (byte1 > 255)) {
                fprintf(stderr, "bad argument to '--byte1' (0 to 255 "
                        "inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'c':
            ++do_control;
            break;
        case 'd':
            memset(data_arr, 0, sizeof(data_arr));
            if (read_hex(optarg, data_arr + 4, &arr_len)) {
                fprintf(stderr, "bad argument to '--data'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            do_data = 1;
            break;
        case 'f':
            do_filter = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'i':
            ++inner_hex;
            break;
        case 'l':
            ++do_list;
            break;
        case 'p':
            page_code = sg_get_num(optarg);
            if ((page_code < 0) || (page_code > 255)) {
                fprintf(stderr, "bad argument to '--page' (0 to 255 "
                        "inclusive)\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            ++do_raw;
            break;
        case 's':
            ++do_status;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
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
    if (do_list) {
        int k;
        int num = sizeof(dpc_arr) / sizeof(dpc_arr[0]);
        const struct diag_page_code * pcdp = &dpc_arr[0];
        const struct element_type_t * etp = &element_type_arr[0];

    
        printf("Known diagnostic pages (followed by page code):\n");
        for (k = 0; k < num; ++k, ++pcdp)
            printf("    %s  [0x%x]\n", pcdp->desc, pcdp->page_code);
        printf("\nKnown SES element type names (followed by element type "
               "code):\n");
        num = sizeof(element_type_arr) / sizeof(element_type_arr[0]);
        for (k = 0; k < num; ++k, ++etp)
            printf("    %s  [0x%x]\n", etp->desc, etp->elem_type_code);
        return 0;
    }
    if (do_control && do_status) {
        fprintf(stderr, "cannot have both '--control' and '--status'\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    } else if (do_control) {
        if (! do_data) {
            fprintf(stderr, "need to give '--data' in control mode\n");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    } else if (0 == do_status)
        do_status = 1;  /* default to receiving status pages */

    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (! do_raw) {
        if (sg_simple_inquiry(sg_fd, &inq_resp, 1, verbose)) {
            fprintf(stderr, "%s doesn't respond to a SCSI INQUIRY\n",
                    device_name);
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
    if (do_status) {
        ret = ses_process_status(sg_fd, page_code, do_raw, do_hex,
                                 inner_hex, do_filter, verbose);
    } else { /* control page requested */
        data_arr[0] = page_code;
        data_arr[1] = byte1;
        data_arr[2] = (arr_len >> 8) & 0xff;
        data_arr[3] = arr_len & 0xff;
        switch (page_code) {
        case 0x2:       /* Enclosure control diagnostic page */
            printf("Sending Enclosure control [0x%x] page, with page "
                   "length=%d bytes\n", page_code, arr_len);
            ret = do_senddiag(sg_fd, 1, data_arr, arr_len + 4, 1, verbose);
            if (ret) {
                fprintf(stderr, "couldn't send Enclosure control page\n");
                goto err_out;
            }
            break;
        case 0x4:       /* String Out diagnostic page */
            printf("Sending String Out [0x%x] page, with page length=%d "
                   "bytes\n", page_code, arr_len);
            ret = do_senddiag(sg_fd, 1, data_arr, arr_len + 4, 1, verbose);
            if (ret) {
                fprintf(stderr, "couldn't send String Out page\n");
                goto err_out;
            }
            break;
        case 0x5:       /* Threshold Out diagnostic page */
            printf("Sending Threshold Out [0x%x] page, with page length=%d "
                   "bytes\n", page_code, arr_len);
            ret = do_senddiag(sg_fd, 1, data_arr, arr_len + 4, 1, verbose);
            if (ret) {
                fprintf(stderr, "couldn't send Threshold Out page\n");
                goto err_out;
            }
            break;
        case 0x6:       /* Array control diagnostic page (obsolete) */
            printf("Sending Array control [0x%x] page, with page "
                   "length=%d bytes\n", page_code, arr_len);
            ret = do_senddiag(sg_fd, 1, data_arr, arr_len + 4, 1, verbose);
            if (ret) {
                fprintf(stderr, "couldn't send Array control page\n");
                goto err_out;
            }
            break;
        case 0xc:       /* Subenclosure String Out diagnostic page */
            printf("Sending Subenclosure String Out [0x%x] page, with page "
                   "length=%d bytes\n", page_code, arr_len);
            ret = do_senddiag(sg_fd, 1, data_arr, arr_len + 4, 1, verbose);
            if (ret) {
                fprintf(stderr, "couldn't send Subenclosure String Out "
                        "page\n");
                goto err_out;
            }
            break;
        default:
            fprintf(stderr, "Setting SES control page 0x%x not supported "
                    "yet\n", page_code);
            ret = SG_LIB_SYNTAX_ERROR;
            break;
        }
    }

err_out:
    if (0 == do_status) {
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
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
