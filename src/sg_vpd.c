/*
 * Copyright (c) 2006-2013 Douglas Gilbert.
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

/* This utility program was originally written for the Linux OS SCSI subsystem.

   This program fetches Vital Product Data (VPD) pages from the given
   device and outputs it as directed. VPD pages are obtained via a
   SCSI INQUIRY command. Most of the data in this program is obtained
   from the SCSI SPC-4 document at http://www.t10.org .

*/

static char * version_str = "0.66 20130301";    /* spc4r36 + sbc3r35 */
        /* And with sbc3r35, vale Mark Evans */

extern void svpd_enumerate_vendor(void);
extern int svpd_decode_vendor(int sg_fd, int num_vpd, int subvalue,
                              int maxlen, int do_hex, int do_raw,
                              int do_long, int do_quiet, int verbose);
extern const struct svpd_values_name_t *
                svpd_find_vendor_by_acron(const char * ap);


/* standard VPD pages, in ascending page number order */
#define VPD_SUPPORTED_VPDS 0x0
#define VPD_UNIT_SERIAL_NUM 0x80
#define VPD_IMP_OP_DEF 0x81     /* obsolete in SPC-2 */
#define VPD_ASCII_OP_DEF 0x82   /* obsolete in SPC-2 */
#define VPD_DEVICE_ID 0x83
#define VPD_SOFTW_INF_ID 0x84
#define VPD_MAN_NET_ADDR 0x85
#define VPD_EXT_INQ 0x86
#define VPD_MODE_PG_POLICY 0x87
#define VPD_SCSI_PORTS 0x88
#define VPD_ATA_INFO 0x89
#define VPD_POWER_CONDITION 0x8a
#define VPD_DEVICE_CONSTITUENTS 0x8b
#define VPD_CFA_PROFILE_INFO 0x8c
#define VPD_POWER_CONSUMPTION  0x8d
#define VPD_3PARTY_COPY 0x8f
#define VPD_PROTO_LU 0x90
#define VPD_PROTO_PORT 0x91
#define VPD_BLOCK_LIMITS 0xb0   /* SBC-3 */
#define VPD_SA_DEV_CAP 0xb0     /* SSC-3 */
#define VPD_OSD_INFO 0xb0       /* OSD */
#define VPD_BLOCK_DEV_CHARS 0xb1 /* SBC-3 */
#define VPD_MAN_ASS_SN 0xb1     /* SSC-3, ADC-2 */
#define VPD_SECURITY_TOKEN 0xb1 /* OSD */
#define VPD_TA_SUPPORTED 0xb2   /* SSC-3 */
#define VPD_LB_PROVISIONING 0xb2   /* SBC-3 */
#define VPD_REFERRALS 0xb3   /* SBC-3 */
#define VPD_AUTOMATION_DEV_SN 0xb3   /* SSC-3 */
#define VPD_DTDE_ADDRESS 0xb4   /* SSC-4 */
#define VPD_NOT_STD_INQ -2      /* request for standard inquiry */

/* Device identification VPD page associations */
#define VPD_ASSOC_LU 0
#define VPD_ASSOC_TPORT 1
#define VPD_ASSOC_TDEVICE 2

/* values for selection one or more associations (2**vpd_assoc),
   except _AS_IS */
#define VPD_DI_SEL_LU 1
#define VPD_DI_SEL_TPORT 2
#define VPD_DI_SEL_TARGET 4
#define VPD_DI_SEL_AS_IS 32


#define DEF_ALLOC_LEN 252
#define MX_ALLOC_LEN (0xc000 + 0x80)
#define VPD_ATA_INFO_LEN  572


/* This structure is a duplicate of one of the same name in sg_vpd_vendor.c .
   Take care that both have the same fields (and types). */
struct svpd_values_name_t {
    int value;
    int subvalue;
    int pdt;         /* peripheral device type id, -1 is the default */
                     /* (all or not applicable) value */
    int vendor;      /* vendor flag */
    const char * acron;
    const char * name;
};


static unsigned char rsp_buff[MX_ALLOC_LEN + 2];

static int decode_dev_ids(const char * print_if_found, unsigned char * buff,
                          int len, int m_assoc, int m_desig_type,
                          int m_code_set, int long_out, int quiet);
static void decode_transport_id(const char * leadin, unsigned char * ucp,
                                int len);

static struct option long_options[] = {
        {"enumerate", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"ident", no_argument, 0, 'i'},
        {"long", no_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"page", required_argument, 0, 'p'},
        {"quiet", no_argument, 0, 'q'},
        {"raw", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


/* arranged in alphabetical order by acronym */
static struct svpd_values_name_t standard_vpd_pg[] = {
    {VPD_ATA_INFO, 0, -1, 0, "ai", "ATA information (SAT)"},
    {VPD_ASCII_OP_DEF, 0, -1, 0, "aod",
     "ASCII implemented operating definition (obsolete)"},
    {VPD_AUTOMATION_DEV_SN, 0, 1, 0, "adsn", "Automation device serial "
     "number (SSC)"},
    {VPD_BLOCK_LIMITS, 0, 0, 0, "bl", "Block limits (SBC)"},
    {VPD_BLOCK_DEV_CHARS, 0, 0, 0, "bdc", "Block device characteristics "
     "(SBC)"},
    {VPD_CFA_PROFILE_INFO, 0, 0, 0, "cfa", "CFA profile information"},
    {VPD_DEVICE_CONSTITUENTS, 0, 1, 0, "dc", "Device constituents"},
    {VPD_DEVICE_ID, 0, -1, 0, "di", "Device identification"},
    {VPD_DEVICE_ID, VPD_DI_SEL_AS_IS, -1, 0, "di_asis", "Like 'di' "
     "but designators ordered as found"},
    {VPD_DEVICE_ID, VPD_DI_SEL_LU, -1, 0, "di_lu", "Device identification, "
     "lu only"},
    {VPD_DEVICE_ID, VPD_DI_SEL_TPORT, -1, 0, "di_port", "Device "
     "identification, target port only"},
    {VPD_DEVICE_ID, VPD_DI_SEL_TARGET, -1, 0, "di_target", "Device "
     "identification, target device only"},
    {VPD_DTDE_ADDRESS, 0, 1, 0, "dtde",
     "Data transfer device element address (SSC)"},
    {VPD_EXT_INQ, 0, -1, 0, "ei", "Extended inquiry data"},
    {VPD_IMP_OP_DEF, 0, -1, 0, "iod",
     "Implemented operating definition (obsolete)"},
    {VPD_LB_PROVISIONING, 0, 0, 0, "lbpv",
     "Logical block provisioning (SBC)"},
    {VPD_MAN_ASS_SN, 0, 1, 0, "mas",
     "Manufacturer assigned serial number (SSC)"},
    {VPD_MAN_ASS_SN, 0, 0x12, 0, "masa",
     "Manufacturer assigned serial number (ADC)"},
    {VPD_MAN_NET_ADDR, 0, -1, 0, "mna", "Management network addresses"},
    {VPD_MODE_PG_POLICY, 0, -1, 0, "mpp", "Mode page policy"},
    {VPD_OSD_INFO, 0, 0x11, 0, "oi", "OSD information"},
    {VPD_POWER_CONDITION, 0, -1, 0, "pc", "Power condition"},
    {VPD_POWER_CONSUMPTION, 0, -1, 0, "psm", "Power consumption"},
    {VPD_PROTO_LU, 0, 0x0, 0, "pslu", "Protocol-specific logical unit "
     "information"},
    {VPD_PROTO_PORT, 0, 0x0, 0, "pspo", "Protocol-specific port information"},
    {VPD_REFERRALS, 0, 0, 0, "ref", "Referrals (SBC)"},
    {VPD_SA_DEV_CAP, 0, 1, 0, "sad",
     "Sequential access device capabilities (SSC)"},
    {VPD_SOFTW_INF_ID, 0, -1, 0, "sii", "Software interface identification"},
    {VPD_NOT_STD_INQ, 0, -1, 0, "sinq", "Standard inquiry response"},
    {VPD_UNIT_SERIAL_NUM, 0, -1, 0, "sn", "Unit serial number"},
    {VPD_SCSI_PORTS, 0, -1, 0, "sp", "SCSI ports"},
    {VPD_SECURITY_TOKEN, 0, 0x11, 0, "st", "Security token (OSD)"},
    {VPD_SUPPORTED_VPDS, 0, -1, 0, "sv", "Supported VPD pages"},
    {VPD_TA_SUPPORTED, 0, 1, 0, "tas", "TapeAlert supported flags (SSC)"},
    {VPD_3PARTY_COPY, 0, -1, 0, "tpc", "Third party copy"},
    {0, 0, 0, 0, NULL, NULL},
};

static void
usage()
{
    fprintf(stderr,
            "Usage: sg_vpd  [--enumerate] [--help] [--hex] [--ident] "
            "[--long]\n"
            "               [--maxlen=LEN] [--page=PG] [--quiet] [--raw] "
            "[--verbose]\n"
            "               [--version] DEVICE\n");
    fprintf(stderr,
            "  where:\n"
            "    --enumerate|-e    enumerate known VPD pages names (ignore "
            "DEVICE)\n"
            "    --help|-h       output this usage message then exit\n"
            "    --hex|-H        output page in ASCII hexadecimal\n"
            "    --ident|-i      output device identification VPD page, "
            "twice for\n"
            "                    short logical unit designator (equiv: "
            "'-qp di_lu')\n"
            "    --long|-l       perform extra decoding\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> 252 bytes)\n"
            "    --page=PG|-p PG    fetch VPD page where PG is an "
            "acronym, or a decimal\n"
            "                       number unless hex indicator "
            "is given (e.g. '0x83')\n"
            "    --quiet|-q      suppress some output when decoding\n"
            "    --raw|-r        output page in binary\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version string and exit\n\n"
            "Fetch Vital Product Data (VPD) page using SCSI INQUIRY\n");
}

static const struct svpd_values_name_t *
sdp_get_vpd_detail(int page_num, int subvalue, int pdt)
{
    const struct svpd_values_name_t * vnp;
    int sv, ty;

    sv = (subvalue < 0) ? 1 : 0;
    ty = (pdt < 0) ? 1 : 0;
    for (vnp = standard_vpd_pg; vnp->acron; ++vnp) {
        if ((page_num == vnp->value) &&
            (sv || (subvalue == vnp->subvalue)) &&
            (ty || (pdt == vnp->pdt)))
            return vnp;
    }
    if (! ty)
        return sdp_get_vpd_detail(page_num, subvalue, -1);
    if (! sv)
        return sdp_get_vpd_detail(page_num, -1, -1);
    return NULL;
}

static const struct svpd_values_name_t *
sdp_find_vpd_by_acron(const char * ap)
{
    const struct svpd_values_name_t * vnp;

    for (vnp = standard_vpd_pg; vnp->acron; ++vnp) {
        if (0 == strcmp(vnp->acron, ap))
            return vnp;
    }
    return NULL;
}

static void
enumerate_vpds(int standard, int vendor)
{
    const struct svpd_values_name_t * vnp;

    if (standard) {
        for (vnp = standard_vpd_pg; vnp->acron; ++vnp) {
            if (vnp->name && (0 == vnp->vendor)) {
                if (vnp->value < 0)
                    printf("  %-10s -1        %s\n", vnp->acron, vnp->name);
                else
                    printf("  %-10s 0x%02x      %s\n", vnp->acron, vnp->value,
                       vnp->name);
            }
        }
    }
    if (vendor)
        svpd_enumerate_vendor();
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

/* Assume index is less than 16 */
const char * sg_ansi_version_arr[] =
{
    "no conformance claimed",
    "SCSI-1",           /* obsolete, ANSI X3.131-1986 */
    "SCSI-2",           /* obsolete, ANSI X3.131-1994 */
    "SPC",              /* withdrawn */
    "SPC-2",
    "SPC-3",
    "SPC-4",
    "reserved [7h]",
    "ecma=1, [8h]",
    "ecma=1, [9h]",
    "ecma=1, [Ah]",
    "ecma=1, [Bh]",
    "reserved [Ch]",
    "reserved [Dh]",
    "reserved [Eh]",
    "reserved [Fh]",
};

static void
decode_std_inq(unsigned char * b, int len, int verbose)
{
    int pqual, n;

    if (len < 4)
        return;
    pqual = (b[0] & 0xe0) >> 5;
    if (0 == pqual)
        printf("standard INQUIRY:\n");
    else if (1 == pqual)
        printf("standard INQUIRY: [qualifier indicates no connected "
               "LU]\n");
    else if (3 == pqual)
        printf("standard INQUIRY: [qualifier indicates not capable "
               "of supporting LU]\n");
    else
        printf("standard INQUIRY: [reserved or vendor specific "
                       "qualifier [%d]]\n", pqual);
    printf("  PQual=%d  Device_type=%d  RMB=%d  version=0x%02x ",
           pqual, b[0] & 0x1f, !!(b[1] & 0x80), (unsigned int)b[2]);
    printf(" [%s]\n", sg_ansi_version_arr[b[2] & 0xf]);
    printf("  [AERC=%d]  [TrmTsk=%d]  NormACA=%d  HiSUP=%d "
           " Resp_data_format=%d\n",
           !!(b[3] & 0x80), !!(b[3] & 0x40), !!(b[3] & 0x20),
           !!(b[3] & 0x10), b[3] & 0x0f);
    if (len < 5)
        return;
    n = b[4] + 5;
    if (verbose)
        fprintf(stderr, ">> requested %d bytes, %d bytes available\n",
                len, n);
    printf("  SCCS=%d  ACC=%d  TPGS=%d  3PC=%d  Protect=%d ",
           !!(b[5] & 0x80), !!(b[5] & 0x40), ((b[5] & 0x30) >> 4),
           !!(b[5] & 0x08), !!(b[5] & 0x01));
    printf(" [BQue=%d]\n  EncServ=%d  ", !!(b[6] & 0x80), !!(b[6] & 0x40));
    if (b[6] & 0x10)
        printf("MultiP=1 (VS=%d)  ", !!(b[6] & 0x20));
    else
        printf("MultiP=0  ");
    printf("[MChngr=%d]  [ACKREQQ=%d]  Addr16=%d\n  [RelAdr=%d]  ",
           !!(b[6] & 0x08), !!(b[6] & 0x04), !!(b[6] & 0x01),
           !!(b[7] & 0x80));
    printf("WBus16=%d  Sync=%d  Linked=%d  [TranDis=%d]  ",
           !!(b[7] & 0x20), !!(b[7] & 0x10), !!(b[7] & 0x08),
           !!(b[7] & 0x04));
    printf("CmdQue=%d\n", !!(b[7] & 0x02));
    if (len < 36)
        return;
    printf("  Vendor_identification: %.8s\n", b + 8);
    printf("  Product_identification: %.16s\n", b + 16);
    printf("  Product_revision_level: %.4s\n", b + 32);
}

static const char * assoc_arr[] =
{
    "Addressed logical unit",
    "Target port",      /* that received request; unless SCSI ports VPD */
    "Target device that contains addressed lu",
    "Reserved [0x3]",
};

static void
decode_id_vpd(unsigned char * buff, int len, int subvalue, int do_long,
              int do_quiet)
{
    int m_a, m_d, m_cs;

    if (len < 4) {
        fprintf(stderr, "Device identification VPD page length too "
                "short=%d\n", len);
        return;
    }
    m_a = -1;
    m_d = -1;
    m_cs = -1;
    if (0 == subvalue) {
        decode_dev_ids(assoc_arr[VPD_ASSOC_LU], buff + 4, len - 4,
                       VPD_ASSOC_LU, m_d, m_cs, do_long, do_quiet);
        decode_dev_ids(assoc_arr[VPD_ASSOC_TPORT], buff + 4, len - 4,
                       VPD_ASSOC_TPORT, m_d, m_cs, do_long, do_quiet);
        decode_dev_ids(assoc_arr[VPD_ASSOC_TDEVICE], buff + 4, len - 4,
                       VPD_ASSOC_TDEVICE, m_d, m_cs, do_long, do_quiet);
    } else if (VPD_DI_SEL_AS_IS == subvalue)
        decode_dev_ids(NULL, buff + 4, len - 4, m_a, m_d, m_cs, do_long,
                       do_quiet);
    else {
        if (VPD_DI_SEL_LU & subvalue)
            decode_dev_ids(assoc_arr[VPD_ASSOC_LU], buff + 4, len - 4,
                           VPD_ASSOC_LU, m_d, m_cs, do_long, do_quiet);
        if (VPD_DI_SEL_TPORT & subvalue)
            decode_dev_ids(assoc_arr[VPD_ASSOC_TPORT], buff + 4, len - 4,
                           VPD_ASSOC_TPORT, m_d, m_cs, do_long, do_quiet);
        if (VPD_DI_SEL_TARGET & subvalue)
            decode_dev_ids(assoc_arr[VPD_ASSOC_TDEVICE], buff + 4, len - 4,
                           VPD_ASSOC_TDEVICE, m_d, m_cs, do_long, do_quiet);
    }
}

static const char * network_service_type_arr[] =
{
    "unspecified",
    "storage configuration service",
    "diagnostics",
    "status",
    "logging",
    "code download",
    "administrative configuration service",
    "reserved[0x7]", "reserved[0x8]", "reserved[0x9]",
    "reserved[0xa]", "reserved[0xb]", "reserved[0xc]", "reserved[0xd]",
    "reserved[0xe]", "reserved[0xf]", "reserved[0x10]", "reserved[0x11]",
    "reserved[0x12]", "reserved[0x13]", "reserved[0x14]", "reserved[0x15]",
    "reserved[0x16]", "reserved[0x17]", "reserved[0x18]", "reserved[0x19]",
    "reserved[0x1a]", "reserved[0x1b]", "reserved[0x1c]", "reserved[0x1d]",
    "reserved[0x1e]", "reserved[0x1f]",
};

/* VPD_MAN_NET_ADDR */
static void
decode_net_man_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, na_len;
    unsigned char * ucp;

    if (1 == do_hex) {
        dStrHex((const char *)buff, len, 1);
        return;
    }
    if (len < 4) {
        fprintf(stderr, "Management network addresses VPD page length too "
                "short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        printf("  %s, Service type: %s\n",
               assoc_arr[(ucp[0] >> 5) & 0x3],
               network_service_type_arr[ucp[0] & 0x1f]);
        na_len = (ucp[2] << 8) + ucp[3];
        bump = 4 + na_len;
        if ((k + bump) > len) {
            fprintf(stderr, "Management network addresses VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (na_len > 0) {
            if (do_hex > 1) {
                printf("    Network address:\n");
                dStrHex((const char *)(ucp + 4), na_len, 0);
            } else
                printf("    %s\n", ucp + 4);
        }
    }
}

static const char * mode_page_policy_arr[] =
{
    "shared",
    "per target port",
    "per initiator port",
    "per I_T nexus",
};

/* VPD_MODE_PG_POLICY */
static void
decode_mode_policy_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump;
    unsigned char * ucp;

    if (1 == do_hex) {
        dStrHex((const char *)buff, len, 1);
        return;
    }
    if (len < 4) {
        fprintf(stderr, "Mode page policy VPD page length too short=%d\n",
                len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            fprintf(stderr, "Mode page policy VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (do_hex > 1)
            dStrHex((const char *)ucp, 4, 1);
        else {
            printf("  Policy page code: 0x%x", (ucp[0] & 0x3f));
            if (ucp[1])
                printf(",  subpage code: 0x%x\n", ucp[1]);
            else
                printf("\n");
            printf("    MLUS=%d,  Policy: %s\n", !!(ucp[2] & 0x80),
                   mode_page_policy_arr[ucp[2] & 0x3]);
        }
    }
}

/* VPD_SCSI_PORTS */
static void
decode_scsi_ports_vpd(unsigned char * buff, int len, int do_hex, int do_long,
                      int do_quiet)
{
    int k, bump, rel_port, ip_tid_len, tpd_len;
    unsigned char * ucp;

    if (1 == do_hex) {
        dStrHex((const char *)buff, len, 1);
        return;
    }
    if (len < 4) {
        fprintf(stderr, "SCSI Ports VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        rel_port = (ucp[2] << 8) + ucp[3];
        printf("Relative port=%d\n", rel_port);
        ip_tid_len = (ucp[6] << 8) + ucp[7];
        bump = 8 + ip_tid_len;
        if ((k + bump) > len) {
            fprintf(stderr, "SCSI Ports VPD page, short descriptor "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (ip_tid_len > 0) {
            if (do_hex > 1) {
                printf(" Initiator port transport id:\n");
                dStrHex((const char *)(ucp + 8), ip_tid_len, 1);
            } else
                decode_transport_id(" ", ucp + 8, ip_tid_len);
        }
        tpd_len = (ucp[bump + 2] << 8) + ucp[bump + 3];
        if ((k + bump + tpd_len + 4) > len) {
            fprintf(stderr, "SCSI Ports VPD page, short descriptor(tgt) "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (tpd_len > 0) {
            if (do_hex > 1) {
                printf(" Target port descriptor(s):\n");
                dStrHex((const char *)(ucp + bump + 4), tpd_len, 1);
            } else {
                if ((0 == do_quiet) || (ip_tid_len > 0))
                    printf(" Target port descriptor(s):\n");
                decode_dev_ids("SCSI Ports", ucp + bump + 4, tpd_len,
                               VPD_ASSOC_TPORT, -1, -1, do_long, do_quiet);
            }
        }
        bump += tpd_len + 4;
    }
}

static const char * code_set_arr[] =
{
    "Reserved [0x0]",
    "Binary",
    "ASCII",
    "UTF-8",
    "Reserved [0x4]", "Reserved [0x5]", "Reserved [0x6]", "Reserved [0x7]",
    "Reserved [0x8]", "Reserved [0x9]", "Reserved [0xa]", "Reserved [0xb]",
    "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};

static const char * desig_type_arr[] =
{
    "vendor specific [0x0]",
    "T10 vendor identification",
    "EUI-64 based",
    "NAA",
    "Relative target port",
    "Target port group",        /* spc4r09: _primary_ target port group */
    "Logical unit group",
    "MD5 logical unit identifier",
    "SCSI name string",
    "Protocol specific port identifier",  /* spc4r36 */
    "Reserved [0xa]", "Reserved [0xb]",
    "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};


/* Prints outs an abridged set of device identification designators
   selected by association, designator type and/or code set. */
static int
decode_dev_ids_quiet(unsigned char * buff, int len, int m_assoc,
                     int m_desig_type, int m_code_set)
{
    int m, p_id, c_set, piv, desig_type, i_len, naa, off, u;
    int assoc, is_sas, rtp;
    const unsigned char * ucp;
    const unsigned char * ip;
    unsigned char sas_tport_addr[8];

    rtp = 0;
    memset(sas_tport_addr, 0, sizeof(sas_tport_addr));
    off = -1;
    if (buff[2] != 0) {
        if (m_assoc != VPD_ASSOC_LU)
            return 0;
        ip = buff;
        p_id = 0;
        c_set = 1;
        assoc = VPD_ASSOC_LU;
        piv = 0;
        is_sas = 0;
        desig_type = 3;
        i_len = 16;
        off = 16;
        goto decode;
    }
    while ((u = sg_vpd_dev_id_iter(buff, len, &off, m_assoc, m_desig_type,
                                   m_code_set)) == 0) {
        ucp = buff + off;
        i_len = ucp[3];
        if ((off + i_len + 4) > len) {
            fprintf(stderr, "    VPD page error: designator length longer "
                    "than\n     remaining response length=%d\n", (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        ip = ucp + 4;
        p_id = ((ucp[0] >> 4) & 0xf);
        c_set = (ucp[0] & 0xf);
        piv = ((ucp[1] & 0x80) ? 1 : 0);
        is_sas = (piv && (6 == p_id)) ? 1 : 0;
        assoc = ((ucp[1] >> 4) & 0x3);
        desig_type = (ucp[1] & 0xf);
 decode:
        switch (desig_type) {
        case 0: /* vendor specific */
            break;
        case 1: /* T10 vendor identification */
            break;
        case 2: /* EUI-64 based */
            if ((8 != i_len) && (12 != i_len) && (16 != i_len))
                fprintf(stderr, "      << expect 8, 12 and 16 byte "
                        "EUI, got %d>>\n", i_len);
            printf("0x");
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        case 3: /* NAA */
            if (1 != c_set) {
                fprintf(stderr, "      << unexpected code set %d for "
                        "NAA>>\n", c_set);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            naa = (ip[0] >> 4) & 0xff;
            if ((naa < 2) || (naa > 6) || (4 == naa)) {
                fprintf(stderr, "      << unexpected NAA [0x%x]>>\n", naa);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            if (2 == naa) {             /* NAA IEEE extended */
                if (8 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 2 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, 0);
                    break;
                }
                printf("0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            } else if ((3 == naa) || (5 == naa)) {
                /* NAA=3 Locally assigned; NAA=5 IEEE Registered */
                if (8 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 3 or 5 "
                            "identifier length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, 0);
                    break;
                }
                if ((0 == is_sas) || (1 != assoc)) {
                    printf("0x");
                    for (m = 0; m < 8; ++m)
                        printf("%02x", (unsigned int)ip[m]);
                    printf("\n");
                } else if (rtp) {
                    printf("0x");
                    for (m = 0; m < 8; ++m)
                        printf("%02x", (unsigned int)ip[m]);
                    printf(",0x%x\n", rtp);
                    rtp = 0;
                } else {
                    if (sas_tport_addr[0]) {
                        printf("0x");
                        for (m = 0; m < 8; ++m)
                            printf("%02x", (unsigned int)sas_tport_addr[m]);
                        printf("\n");
                    }
                    memcpy(sas_tport_addr, ip, sizeof(sas_tport_addr));
                }
            } else if (6 == naa) {      /* NAA IEEE registered extended */
                if (16 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 6 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, 0);
                    break;
                }
                printf("0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
            break;
        case 4: /* Relative target port */
            if ((0 == is_sas) || (1 != c_set) || (1 != assoc) || (4 != i_len))
                break;
            rtp = ((ip[2] << 8) | ip[3]);
            if (sas_tport_addr[0]) {
                printf("0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)sas_tport_addr[m]);
                printf(",0x%x\n", rtp);
                memset(sas_tport_addr, 0, sizeof(sas_tport_addr));
                rtp = 0;
            }
            break;
        case 5: /* (primary) Target port group */
            break;
        case 6: /* Logical unit group */
            break;
        case 7: /* MD5 logical unit identifier */
            break;
        case 8: /* SCSI name string */
            if (3 != c_set) {
                fprintf(stderr, "      << expected UTF-8 code_set>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            /* does %s print out UTF-8 ok??
             * Seems to depend on the locale. Looks ok here with my
             * locale setting: en_AU.UTF-8
             */
            printf("%s\n", (const char *)ip);
            break;
        case 9: /* PCIe routing ID */
            break;
        default: /* reserved */
            break;
        }
    }
    if (sas_tport_addr[0]) {
        printf("0x");
        for (m = 0; m < 8; ++m)
            printf("%02x", (unsigned int)sas_tport_addr[m]);
        printf("\n");
    }
    if (-2 == u) {
        fprintf(stderr, "VPD page error: short designator around "
                "offset %d\n", off);
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
}

static void
decode_designation_descriptor(const unsigned char * ip, int i_len,
                              int p_id, int c_set, int piv, int assoc,
                              int desig_type, int long_out, int print_assoc)
{
    int m, ci_off, c_id, d_id, naa;
    int vsi, k;
    uint64_t vsei;
    uint64_t id_ext;
    char b[64];

    if (print_assoc)
        printf("  %s:\n", assoc_arr[assoc]);
    printf("    designator type: %s,  code set: %s\n",
           desig_type_arr[desig_type], code_set_arr[c_set]);
    if (piv && ((1 == assoc) || (2 == assoc)))
        printf("     transport: %s\n",
               sg_get_trans_proto_str(p_id, sizeof(b), b));
    /* printf("    associated with the %s\n", assoc_arr[assoc]); */
    switch (desig_type) {
    case 0: /* vendor specific */
        k = 0;
        if ((1 == c_set) || (2 == c_set)) { /* ASCII or UTF-8 */
            for (k = 0; (k < i_len) && isprint(ip[k]); ++k)
                ;
            if (k >= i_len)
                k = 1;
        }
        if (k)
            printf("      vendor specific: %.*s\n", i_len, ip);
        else
            dStrHex((const char *)ip, i_len, 0);
        break;
    case 1: /* T10 vendor identification */
        printf("      vendor id: %.8s\n", ip);
        if (i_len > 8)
            printf("      vendor specific: %.*s\n", i_len - 8, ip + 8);
        break;
    case 2: /* EUI-64 based */
        if (! long_out) {
            if ((8 != i_len) && (12 != i_len) && (16 != i_len)) {
                fprintf(stderr, "      << expect 8, 12 and 16 byte "
                        "EUI, got %d>>\n", i_len);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            printf("      0x");
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        }
        printf("      EUI-64 based %d byte identifier\n", i_len);
        if (1 != c_set) {
            fprintf(stderr, "      << expected binary code_set (1)>>\n");
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        ci_off = 0;
        if (16 == i_len) {
            ci_off = 8;
            id_ext = 0;
            for (m = 0; m < 8; ++m) {
                if (m > 0)
                    id_ext <<= 8;
                id_ext |= ip[m];
            }
            printf("      Identifier extension: 0x%" PRIx64 "\n", id_ext);
        } else if ((8 != i_len) && (12 != i_len)) {
            fprintf(stderr, "      << can only decode 8, 12 and 16 "
                    "byte ids>>\n");
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        c_id = ((ip[ci_off] << 16) | (ip[ci_off + 1] << 8) |
                ip[ci_off + 2]);
        printf("      IEEE Company_id: 0x%x\n", c_id);
        vsei = 0;
        for (m = 0; m < 5; ++m) {
            if (m > 0)
                vsei <<= 8;
            vsei |= ip[ci_off + 3 + m];
        }
        printf("      Vendor Specific Extension Identifier: 0x%" PRIx64
               "\n", vsei);
        if (12 == i_len) {
            d_id = (((unsigned int)ip[8] << 24) | (ip[9] << 16) |
                    (ip[10] << 8) | ip[11]);
            printf("      Directory ID: 0x%x\n", d_id);
        }
        break;
    case 3: /* NAA */
        if (1 != c_set) {
            fprintf(stderr, "      << unexpected code set %d for "
                    "NAA>>\n", c_set);
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        naa = (ip[0] >> 4) & 0xff;
        if (! ((2 == naa) || (5 == naa) || (6 == naa))) {
            fprintf(stderr, "      << unexpected NAA [0x%x]>>\n", naa);
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        if (2 == naa) {
            if (8 != i_len) {
                fprintf(stderr, "      << unexpected NAA 2 identifier "
                        "length: 0x%x>>\n", i_len);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            d_id = (((ip[0] & 0xf) << 8) | ip[1]);
            c_id = ((ip[2] << 16) | (ip[3] << 8) | ip[4]);
            vsi = ((ip[5] << 16) | (ip[6] << 8) | ip[7]);
            if (long_out) {
                printf("      NAA 2, vendor specific identifier A: "
                       "0x%x\n", d_id);
                printf("      IEEE Company_id: 0x%x\n", c_id);
                printf("      vendor specific identifier B: 0x%x\n", vsi);
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            }
            printf("      0x");
            for (m = 0; m < 8; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
        } else if (5 == naa) {
            if (8 != i_len) {
                fprintf(stderr, "      << unexpected NAA 5 identifier "
                        "length: 0x%x>>\n", i_len);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            c_id = (((ip[0] & 0xf) << 20) | (ip[1] << 12) |
                    (ip[2] << 4) | ((ip[3] & 0xf0) >> 4));
            vsei = ip[3] & 0xf;
            for (m = 1; m < 5; ++m) {
                vsei <<= 8;
                vsei |= ip[3 + m];
            }
            if (long_out) {
                printf("      NAA 5, IEEE Company_id: 0x%x\n", c_id);
                printf("      Vendor Specific Identifier: 0x%" PRIx64
                       "\n", vsei);
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            } else {
                printf("      0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
        } else if (6 == naa) {
            if (16 != i_len) {
                fprintf(stderr, "      << unexpected NAA 6 identifier "
                        "length: 0x%x>>\n", i_len);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            c_id = (((ip[0] & 0xf) << 20) | (ip[1] << 12) |
                    (ip[2] << 4) | ((ip[3] & 0xf0) >> 4));
            vsei = ip[3] & 0xf;
            for (m = 1; m < 5; ++m) {
                vsei <<= 8;
                vsei |= ip[3 + m];
            }
            if (long_out) {
                printf("      NAA 6, IEEE Company_id: 0x%x\n", c_id);
                printf("      Vendor Specific Identifier: 0x%" PRIx64
                       "\n", vsei);
                vsei = 0;
                for (m = 0; m < 8; ++m) {
                    if (m > 0)
                        vsei <<= 8;
                    vsei |= ip[8 + m];
                }
                printf("      Vendor Specific Identifier Extension: "
                       "0x%" PRIx64 "\n", vsei);
                printf("      [0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            } else {
                printf("      0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
        }
        break;
    case 4: /* Relative target port */
        if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
            fprintf(stderr, "      << expected binary code_set, target "
                    "port association, length 4>>\n");
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        d_id = ((ip[2] << 8) | ip[3]);
        printf("      Relative target port: 0x%x\n", d_id);
        break;
    case 5: /* (primary) Target port group */
        if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
            fprintf(stderr, "      << expected binary code_set, target "
                    "port association, length 4>>\n");
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        d_id = ((ip[2] << 8) | ip[3]);
        printf("      Target port group: 0x%x\n", d_id);
        break;
    case 6: /* Logical unit group */
        if ((1 != c_set) || (0 != assoc) || (4 != i_len)) {
            fprintf(stderr, "      << expected binary code_set, logical "
                    "unit association, length 4>>\n");
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        d_id = ((ip[2] << 8) | ip[3]);
        printf("      Logical unit group: 0x%x\n", d_id);
        break;
    case 7: /* MD5 logical unit identifier */
        if ((1 != c_set) || (0 != assoc)) {
            printf("      << expected binary code_set, logical "
                   "unit association>>\n");
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        printf("      MD5 logical unit identifier:\n");
        dStrHex((const char *)ip, i_len, 0);
        break;
    case 8: /* SCSI name string */
        if (3 != c_set) {
            fprintf(stderr, "      << expected UTF-8 code_set>>\n");
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
        printf("      SCSI name string:\n");
        /* does %s print out UTF-8 ok??
         * Seems to depend on the locale. Looks ok here with my
         * locale setting: en_AU.UTF-8
         */
        printf("      %s\n", (const char *)ip);
        break;
    case 9: /* Protocol specific port identifier */
        /* added in spc4r36, PIV must be set, proto_id indicates */
        /* whether UAS (USB) or SOP (PCIe) or ... */
        if (! piv)
            printf("      >>>> Protocol specific port identifier "
                   "expects protocol\n"
                   "           identifier to be valid and it is not\n");
        if (TPROTO_UAS == p_id) {
            printf("      USB device address: 0x%x\n", 0x7f & ip[0]);
            printf("      USB interface number: 0x%x\n", ip[2]);
        } else if (TPROTO_SOP == p_id) {
            printf("      PCIe routing ID, bus number: 0x%x\n", ip[0]);
            printf("          function number: 0x%x\n", ip[1]);
            printf("          [or device number: 0x%x, function number: "
                   "0x%x]\n", (0x1f & (ip[1] >> 3)), 0x7 & ip[1]);
        } else
            printf("      >>>> unexpected protocol indentifier: %s\n"
                   "           with Protocol specific port "
                   "identifier\n",
                   sg_get_trans_proto_str(p_id, sizeof(b), b));
        break;
    default: /* reserved */
        dStrHex((const char *)ip, i_len, 0);
        break;
    }
}

/* Prints outs device identification designators selected by association,
   designator type and/or code set. */
static int
decode_dev_ids(const char * print_if_found, unsigned char * buff, int len,
               int m_assoc, int m_desig_type, int m_code_set, int long_out,
               int quiet)
{
    int assoc, i_len, c_set, piv, p_id, desig_type;
    int printed, off, u;
    const unsigned char * ucp;

    if (quiet)
        return decode_dev_ids_quiet(buff, len, m_assoc, m_desig_type,
                                    m_code_set);
    if ( buff[2] != 0 ) {
        if (m_assoc == VPD_ASSOC_LU)
            decode_designation_descriptor( buff, 16, 0, 1, 0, m_assoc, 3,
                                           long_out, 0);
        return 0;
    }
    off = -1;
    printed = 0;
    while ((u = sg_vpd_dev_id_iter(buff, len, &off, m_assoc, m_desig_type,
                                   m_code_set)) == 0) {
        ucp = buff + off;
        i_len = ucp[3];
        if ((off + i_len + 4) > len) {
            fprintf(stderr, "    VPD page error: designator length longer "
                    "than\n     remaining response length=%d\n", (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        assoc = ((ucp[1] >> 4) & 0x3);
        if (print_if_found && (0 == printed)) {
            printed = 1;
            printf("  %s:\n", print_if_found);
        }
        if (NULL == print_if_found)
            printf("  %s:\n", assoc_arr[assoc]);
        p_id = ((ucp[0] >> 4) & 0xf);
        c_set = (ucp[0] & 0xf);
        piv = ((ucp[1] & 0x80) ? 1 : 0);
        desig_type = (ucp[1] & 0xf);
        decode_designation_descriptor(ucp + 4, i_len, p_id, c_set, piv, assoc,
                                      desig_type, long_out, 0);
    }
    if (-2 == u) {
        fprintf(stderr, "VPD page error: short designator around "
                "offset %d\n", off);
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
}

/* Transport IDs are initiator port identifiers, typically other than the
   initiator port issuing a SCSI command. */
static void
decode_transport_id(const char * leadin, unsigned char * ucp, int len)
{
    int format_code, proto_id, num, j, k;
    uint64_t ull;
    int bump;

    for (k = 0, bump= 24; k < len; k += bump, ucp += bump) {
        if ((len < 24) || (0 != (len % 4)))
            printf("%sTransport Id short or not multiple of 4 "
                   "[length=%d]:\n", leadin, len);
        else
            printf("%sTransport Id of initiator:\n", leadin);
        format_code = ((ucp[0] >> 6) & 0x3);
        proto_id = (ucp[0] & 0xf);
        switch (proto_id) {
        case TPROTO_FCP: /* Fibre channel */
            printf("%s  FCP-2 World Wide Name:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, -1);
            bump = 24;
            break;
        case TPROTO_SPI:        /* Scsi Parallel Interface */
            printf("%s  Parallel SCSI initiator SCSI address: 0x%x\n",
                   leadin, ((ucp[2] << 8) | ucp[3]));
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            printf("%s  relative port number (of corresponding target): "
                   "0x%x\n", leadin, ((ucp[6] << 8) | ucp[7]));
            bump = 24;
            break;
        case TPROTO_SSA:
            printf("%s  SSA (transport id not defined):\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case TPROTO_1394: /* IEEE 1394 */
            printf("%s  IEEE 1394 EUI-64 name:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, -1);
            bump = 24;
            break;
        case TPROTO_SRP:
            printf("%s  RDMA initiator port identifier:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 16, -1);
            bump = 24;
            break;
        case TPROTO_ISCSI:
            printf("%s  iSCSI ", leadin);
            num = ((ucp[2] << 8) | ucp[3]);
            if (0 == format_code)
                printf("name: %.*s\n", num, &ucp[4]);
            else if (1 == format_code)
                printf("world wide unique port id: %.*s\n", num, &ucp[4]);
            else {
                printf("  [Unexpected format code: %d]\n", format_code);
                dStrHex((const char *)ucp, num + 4, 0);
            }
            bump = (((num + 4) < 24) ? 24 : num + 4);
            break;
        case TPROTO_SAS:
            ull = 0;
            for (j = 0; j < 8; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= ucp[4 + j];
            }
            printf("%s  SAS address: 0x%" PRIx64 "\n", leadin, ull);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            bump = 24;
            break;
        case TPROTO_ADT:
            printf("%s  ADT:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case TPROTO_ATA: /* ATA/ATAPI */
            printf("%s  ATAPI:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case TPROTO_UAS:
            printf("%s  UAS:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case TPROTO_SOP:
            printf("%s  SOP ", leadin);
            num = ((ucp[2] << 8) | ucp[3]);
            if (0 == format_code)
                printf("Routing ID: 0x%x\n", num);
            else {
                printf("  [Unexpected format code: %d]\n", format_code);
                dStrHex((const char *)ucp, 24, 0);
            }
            bump = 24;
            break;
        case TPROTO_NONE:
            fprintf(stderr, "%s  No specified protocol\n", leadin);
            /* dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0); */
            bump = 24;
            break;
        default:
            fprintf(stderr, "%s  unknown protocol id=0x%x  "
                    "format_code=%d\n", leadin, proto_id, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        }
    }
}

/* VPD_EXT_INQ    Extended Inquiry VPD */
static void
decode_x_inq_vpd(unsigned char * b, int len, int do_hex, int do_long,
                 int protect)
{
    int n;

    if (len < 7) {
        fprintf(stderr, "Extended INQUIRY data VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)b, len, 0);
        return;
    }
    if (do_long) {
        n = (b[4] >> 6) & 0x3;
        printf("  ACTIVATE_MICROCODE=%d", n);
        if (1 == n)
            printf(" [before final WRITE BUFFER]\n");
        else if (2 == n)
            printf(" [after power on or hard reset]\n");
        else
            printf("\n");
        n = (b[4] >> 3) & 0x7;
        printf("  SPT=%d", n);
        if (protect) {
            switch (n)
            {
            case 0:
                printf(" [protection type 1 supported]\n");
                break;
            case 1:
                printf(" [protection types 1 and 2 supported]\n");
                break;
            case 2:
                printf(" [protection type 2 supported]\n");
                break;
            case 3:
                printf(" [protection types 1 and 3 supported]\n");
                break;
            case 4:
                printf(" [protection type 3 supported]\n");
                break;
            case 5:
                printf(" [protection types 2 and 3 supported]\n");
                break;
            case 7:
                printf(" [protection types 1, 2 and 3 supported]\n");
                break;
            default:
                printf("\n");
                break;
            }
        } else
            printf("\n");
        printf("  GRD_CHK=%d\n", !!(b[4] & 0x4));
        printf("  APP_CHK=%d\n", !!(b[4] & 0x2));
        printf("  REF_CHK=%d\n", !!(b[4] & 0x1));
        printf("  UASK_SUP=%d\n", !!(b[5] & 0x20));
        printf("  GROUP_SUP=%d\n", !!(b[5] & 0x10));
        printf("  PRIOR_SUP=%d\n", !!(b[5] & 0x8));
        printf("  HEADSUP=%d\n", !!(b[5] & 0x4));
        printf("  ORDSUP=%d\n", !!(b[5] & 0x2));
        printf("  SIMPSUP=%d\n", !!(b[5] & 0x1));
        printf("  WU_SUP=%d\n", !!(b[6] & 0x8));
        printf("  CRD_SUP=%d\n", !!(b[6] & 0x4));
        printf("  NV_SUP=%d\n", !!(b[6] & 0x2));
        printf("  V_SUP=%d\n", !!(b[6] & 0x1));
        printf("  P_I_I_SUP=%d\n", !!(b[7] & 0x10));
        printf("  LUICLR=%d\n", !!(b[7] & 0x1));
        printf("  R_SUP=%d\n", !!(b[8] & 0x10));
        printf("  CBCS=%d\n", !!(b[8] & 0x1));
        printf("  Multi I_T nexus microcode download=%d\n", b[9] & 0xf);
        printf("  Extended self-test completion minutes=%d\n",
               (b[10] << 8) + b[11]);
        printf("  POA_SUP=%d\n", !!(b[12] & 0x80));     /* spc4r32 */
        printf("  HRA_SUP=%d\n", !!(b[12] & 0x40));     /* spc4r32 */
        printf("  VSA_SUP=%d\n", !!(b[12] & 0x20));     /* spc4r32 */
        printf("  Maximum supported sense data length=%d\n",
               b[13]); /* spc4r34 */
        return;
    }
    printf("  ACTIVATE_MICROCODE=%d SPT=%d GRD_CHK=%d APP_CHK=%d "
           "REF_CHK=%d\n", ((b[4] >> 6) & 0x3), ((b[4] >> 3) & 0x7),
           !!(b[4] & 0x4), !!(b[4] & 0x2), !!(b[4] & 0x1));
    printf("  UASK_SUP=%d GROUP_SUP=%d PRIOR_SUP=%d HEADSUP=%d ORDSUP=%d "
           "SIMPSUP=%d\n", !!(b[5] & 0x20), !!(b[5] & 0x10), !!(b[5] & 0x8),
           !!(b[5] & 0x4), !!(b[5] & 0x2), !!(b[5] & 0x1));
    printf("  WU_SUP=%d CRD_SUP=%d NV_SUP=%d V_SUP=%d\n",
           !!(b[6] & 0x8), !!(b[6] & 0x4), !!(b[6] & 0x2), !!(b[6] & 0x1));
    printf("  P_I_I_SUP=%d LUICLR=%d R_SUP=%d CBCS=%d\n",
           !!(b[7] & 0x10), !!(b[7] & 0x1), !!(b[8] & 0x10), !!(b[8] & 0x1));
    printf("  Multi I_T nexus microcode download=%d\n", b[9] & 0xf);
    printf("  Extended self-test completion minutes=%d\n",
           (b[10] << 8) + b[11]);    /* spc4r27 */
    printf("  POA_SUP=%d HRA_SUP=%d VSA_SUP=%d\n",      /* spc4r32 */
           !!(b[12] & 0x80), !!(b[12] & 0x40), !!(b[12] & 0x20));
    printf("  Maximum supported sense data length=%d\n", b[13]); /* spc4r34 */
}

/* VPD_SOFTW_INF_ID */
static void
decode_softw_inf_id(unsigned char * buff, int len, int do_hex)
{
    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    len -= 4;
    buff += 4;
    for ( ; len > 5; len -= 6, buff += 6) {
        printf("    IEEE Company_id: 0x%06x, vendor specific extension "
               "id: 0x%06x\n", (buff[0] << 16) | (buff[1] << 8) | buff[2],
               (buff[3] << 16) | (buff[4] << 8) | buff[5]);
    }
}

/* VPD_ATA_INFO */
static void
decode_ata_info_vpd(unsigned char * buff, int len, int do_long, int do_hex)
{
    char b[80];
    int num, is_be;
    const char * cp;

    if (len < 36) {
        fprintf(stderr, "ATA information VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (do_hex && (2 != do_hex)) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    memcpy(b, buff + 8, 8);
    b[8] = '\0';
    printf("  SAT Vendor identification: %s\n", b);
    memcpy(b, buff + 16, 16);
    b[16] = '\0';
    printf("  SAT Product identification: %s\n", b);
    memcpy(b, buff + 32, 4);
    b[4] = '\0';
    printf("  SAT Product revision level: %s\n", b);
    if (len < 56)
        return;
    if (do_long) {
        printf("  Signature (Device to host FIS):\n");
        dStrHex((const char *)buff + 36, 20, 0);
    }
    if (len < 60)
        return;
    is_be = sg_is_big_endian();
    if ((0xec == buff[56]) || (0xa1 == buff[56])) {
        cp = (0xa1 == buff[56]) ? "PACKET " : "";
        printf("  ATA command IDENTIFY %sDEVICE response summary:\n", cp);
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 27, 20,
                               is_be, b);
        b[num] = '\0';
        printf("    model: %s\n", b);
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 10, 10,
                               is_be, b);
        b[num] = '\0';
        printf("    serial number: %s\n", b);
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 23, 4,
                               is_be, b);
        b[num] = '\0';
        printf("    firmware revision: %s\n", b);
        if (do_long)
            printf("  ATA command IDENTIFY %sDEVICE response in hex:\n", cp);
    } else if (do_long)
        printf("  ATA command 0x%x got following response:\n",
               (unsigned int)buff[56]);
    if (len < 572)
        return;
    if (2 == do_hex)
        dStrHex((const char *)(buff + 60), 512, 0);
    else if (do_long)
        dWordHex((const unsigned short *)(buff + 60), 256, 0, is_be);
}

/* VPD_POWER_CONDITION */
static void
decode_power_condition(unsigned char * buff, int len, int do_hex)
{
    if (len < 18) {
        fprintf(stderr, "Power condition VPD page length too short=%d\n",
                len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    printf("  Standby_y=%d Standby_z=%d Idle_c=%d Idle_b=%d Idle_a=%d\n",
           !!(buff[4] & 0x2), !!(buff[4] & 0x1),
           !!(buff[5] & 0x4), !!(buff[5] & 0x2), !!(buff[5] & 0x1));
    printf("  Stopped condition recovery time (ms) %d\n",
            (buff[6] << 8) + buff[7]);
    printf("  Standby_z condition recovery time (ms) %d\n",
            (buff[8] << 8) + buff[9]);
    printf("  Standby_y condition recovery time (ms) %d\n",
            (buff[10] << 8) + buff[11]);
    printf("  Idle_a condition recovery time (ms) %d\n",
            (buff[12] << 8) + buff[13]);
    printf("  Idle_b condition recovery time (ms) %d\n",
            (buff[14] << 8) + buff[15]);
    printf("  Idle_c condition recovery time (ms) %d\n",
            (buff[16] << 8) + buff[17]);
}

static const char * power_unit_arr[] =
{
    "Gigawatts",
    "Megawatts",
    "Kilowatts",
    "Watts",
    "Milliwatts",
    "Microwatts",
    "Unit reserved",
    "Unit reserved",
};

/* VPD_POWER_CONSUMPTION */
static void
decode_power_consumption_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump;
    unsigned char * ucp;
    unsigned int value;

    if (1 == do_hex) {
        dStrHex((const char *)buff, len, 1);
        return;
    }
    if (len < 4) {
        fprintf(stderr, "Power consumption VPD page length too short=%d\n",
                len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            fprintf(stderr, "Power consumption VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (do_hex > 1)
            dStrHex((const char *)ucp, 4, 1);
        else {
            value = (ucp[2] << 8) + ucp[3];
            printf("  Power consumption identifier: 0x%x", ucp[0]);
            if (value >= 1000 && (ucp[1] & 0x7) > 0)
                printf("    Maximum power consumption: %d.%03d %s\n",
                       value / 1000, value % 1000,
                       power_unit_arr[(ucp[1] & 0x7) - 1]);
            else
                printf("    Maximum power consumption: %d %s\n",
                       value, power_unit_arr[ucp[1] & 0x7]);
        }
    }
}

/* VPD_PROTO_LU */
static void
decode_proto_lu_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, rel_port, desc_len, proto;
    unsigned char * ucp;

    if (1 == do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    if (len < 4) {
        fprintf(stderr, "Protocol-specific logical unit information VPD "
                "page length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        rel_port = (ucp[0] << 8) + ucp[1];
        printf("Relative port=%d\n", rel_port);
        proto = ucp[2] & 0xf;
        desc_len = (ucp[6] << 8) + ucp[7];
        bump = 8 + desc_len;
        if ((k + bump) > len) {
            fprintf(stderr, "Protocol-specific logical unit information VPD "
                    "page, short descriptor length=%d, left=%d\n", bump,
                    (len - k));
            return;
        }
        if (0 == desc_len)
            continue;
        if (2 == do_hex)
            dStrHex((const char *)ucp + 8, desc_len, 1);
        else if (do_hex > 2)
            dStrHex((const char *)ucp, bump, 1);
        else {
            switch (proto) {
            case TPROTO_SAS:
                printf(" Protocol identifier: SAS\n");
                printf(" TLR control supported: %d\n", !!(ucp[8] & 0x1));
                break;
            default:
                fprintf(stderr, "Unexpected proto=%d\n", proto);
                dStrHex((const char *)ucp, bump, 1);
                break;
            }
        }
    }
}

/* VPD_PROTO_PORT */
static void
decode_proto_port_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, j, bump, rel_port, desc_len, proto;
    unsigned char * ucp;
    unsigned char * pidp;

    if (1 == do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    if (len < 4) {
        fprintf(stderr, "Protocol-specific port information VPD "
                "page length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        rel_port = (ucp[0] << 8) + ucp[1];
        printf("Relative port=%d\n", rel_port);
        proto = ucp[2] & 0xf;
        desc_len = (ucp[6] << 8) + ucp[7];
        bump = 8 + desc_len;
        if ((k + bump) > len) {
            fprintf(stderr, "Protocol-specific port VPD "
                    "page, short descriptor length=%d, left=%d\n", bump,
                    (len - k));
            return;
        }
        if (0 == desc_len)
            continue;
        if (2 == do_hex)
            dStrHex((const char *)ucp + 8, desc_len, 1);
        else if (do_hex > 2)
            dStrHex((const char *)ucp, bump, 1);
        else {
            switch (proto) {
            case TPROTO_SAS:    /* for SSP, added spl3r2 */
                pidp = ucp + 8;
                for (j = 0; j < desc_len; j += 4, pidp += 4)
                    printf("  phy id=%d, ssp persistent capable=%d\n",
                           pidp[1], (0x1 & pidp[2]));
                break;
            default:
                fprintf(stderr, "Unexpected proto=%d\n", proto);
                dStrHex((const char *)ucp, bump, 1);
                break;
            }
        }
    }
}

/* VPD_BLOCK_LIMITS sbc */
/* VPD_SA_DEV_CAP ssc */
/* VPD_OSD_INFO osd */
static void
decode_b0_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    switch (pdt) {
    case 0: case 4: case 7: /* Block limits */
        if (len < 16) {
            fprintf(stderr, "Block limits VPD page length too "
                    "short=%d\n", len);
            return;
        }
        printf("  Write same no zero (WSNZ): %d\n", !!(buff[4] & 0x1));
        printf("  Maximum compare and write length: %u blocks\n",
               buff[5]);
        u = (buff[6] << 8) | buff[7];
        printf("  Optimal transfer length granularity: %u blocks\n", u);
        u = (buff[8] << 24) | (buff[9] << 16) | (buff[10] << 8) |
            buff[11];
        printf("  Maximum transfer length: %u blocks\n", u);
        u = (buff[12] << 24) | (buff[13] << 16) | (buff[14] << 8) |
            buff[15];
        printf("  Optimal transfer length: %u blocks\n", u);
        if (len > 19) {     /* added in sbc3r09 */
            u = (buff[16] << 24) | (buff[17] << 16) | (buff[18] << 8) |
                buff[19];
            printf("  Maximum prefetch length: %u blocks\n", u);
            /* was 'Maximum prefetch transfer length' prior to sbc3r33 */
        }
        if (len > 27) {     /* added in sbc3r18 */
            u = ((unsigned int)buff[20] << 24) | (buff[21] << 16) |
                (buff[22] << 8) | buff[23];
            printf("  Maximum unmap LBA count: %u\n", u);
            u = ((unsigned int)buff[24] << 24) | (buff[25] << 16) |
                (buff[26] << 8) | buff[27];
            printf("  Maximum unmap block descriptor count: %u\n", u);
        }
        if (len > 35) {     /* added in sbc3r19 */
            int m;
            uint64_t mwsl;

            u = ((unsigned int)buff[28] << 24) | (buff[29] << 16) |
                (buff[30] << 8) | buff[31];
            printf("  Optimal unmap granularity: %u\n", u);
            printf("  Unmap granularity alignment valid: %u\n",
                   !!(buff[32] & 0x80));
            u = ((unsigned int)(buff[32] & 0x7f) << 24) | (buff[33] << 16) |
                (buff[34] << 8) | buff[35];
            printf("  Unmap granularity alignment: %u\n", u);
            /* added in sbc3r26 */
            mwsl = 0;
            for (m = 0; m < 8; ++m) {
                if (m > 0)
                    mwsl <<= 8;
                mwsl |= buff[36 + m];
            }
            printf("  Maximum write same length: 0x%" PRIx64 " blocks\n",
                   mwsl);
        }
        break;
    case 1: case 8:
        printf("  WORM=%d\n", !!(buff[4] & 0x1));
        break;
    case 0x11:
    default:
        printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHex((const char *)buff, len, 0);
        break;
    }
}

/* VPD_BLOCK_DEV_CHARS sbc */
/* VPD_MAN_ASS_SN ssc */
/* VPD_SECURITY_TOKEN osd */
static void
decode_b1_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
        if (len < 64) {
            fprintf(stderr, "Block device characteristics VPD page length "
                    "too short=%d\n", len);
            return;
        }
        u = (buff[4] << 8) | buff[5];
        if (0 == u)
            printf("  Medium rotation rate is not reported\n");
        else if (1 == u)
            printf("  Non-rotating medium (e.g. solid state)\n");
        else if ((u < 0x401) || (0xffff == u))
            printf("  Reserved [0x%x]\n", u);
        else
            printf("  Nominal rotation rate: %d rpm\n", u);
        printf("  Product type=%d\n", buff[6]);
        printf("  WABEREQ=%d\n", (buff[7] >> 6) & 0x3);
        printf("  WACEREQ=%d\n", (buff[7] >> 4) & 0x3);
        u = buff[7] & 0xf;
        printf("  Nominal form factor");
        switch (u) {
        case 0:
            printf(" not reported\n");
            break;
        case 1:
            printf(": 5.25 inch\n");
            break;
        case 2:
            printf(": 3.5 inch\n");
            break;
        case 3:
            printf(": 2.5 inch\n");
            break;
        case 4:
            printf(": 1.8 inch\n");
            break;
        case 5:
            printf(": less then 1.8 inch\n");
            break;
        default:
            printf(": reserved\n");
            break;
        }
        printf("  VBULS=%d\n", buff[8] & 0x1);
        break;
    case PDT_TAPE: case PDT_MCHANGER: case PDT_ADC:
        printf("  Manufacturer-assigned serial number: %.*s\n",
               len - 4, buff + 4);
        break;
    default:
        printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHex((const char *)buff, len, 0);
        break;
    }
}

/* VPD_LB_PROVISIONING */
static int
decode_block_lb_prov_vpd(unsigned char * b, int len)
{
    int dp;

    if (len < 4) {
        fprintf(stderr, "Logical block provisioning page too short=%d\n",
                len);
        return SG_LIB_CAT_MALFORMED;
    }
    printf("  Unmap command supported (LBPU): %d\n", !!(0x80 & b[5]));
    printf("  Write same (16) with unmap bit supported (LBWS): %d\n",
           !!(0x40 & b[5]));
    printf("  Write same (10) with unmap bit supported (LBWS10): %d\n",
           !!(0x20 & b[5]));
    printf("  Logical block provisioning read zeros (LBPRZ): %d\n",
           !!(0x4 & b[5]));
    printf("  Anchored LBAs supported (ANC_SUP): %d\n", !!(0x2 & b[5]));
    dp = !!(b[5] & 0x1);
    printf("  Threshold exponent: %d\n", b[4]);
    printf("  Descriptor present (DP): %d\n", dp);
    printf("  Provisioning type: %d\n", b[6] & 0x7);
    if (dp) {
        const unsigned char * ucp;
        int i_len, p_id, c_set, piv, assoc, desig_type;

        ucp = b + 8;
        i_len = ucp[3];
        if (0 == i_len) {
            fprintf(stderr, "Logical block provisioning page provisioning "
                    "group descriptor too short=%d\n", i_len);
            return 0;
        }
        printf("  Provisioning group descriptor\n");
        p_id = ((ucp[0] >> 4) & 0xf);
        c_set = (ucp[0] & 0xf);
        piv = ((ucp[1] & 0x80) ? 1 : 0);
        assoc = ((ucp[1] >> 4) & 0x3);
        desig_type = (ucp[1] & 0xf);
        decode_designation_descriptor(ucp, i_len, p_id, c_set, piv, assoc,
                                      desig_type, 0, 1);
    }
    return 0;
}

/* VPD_TA_SUPPORTED */
static int
decode_tapealert_supported_vpd(unsigned char * b, int len)
{
    if (len < 12) {
        fprintf(stderr, "TapeAlert supported flags length too short=%d\n",
                len);
        return SG_LIB_CAT_MALFORMED;
    }
    printf("  Flag01h: %d  02h: %d  03h: %d  04h: %d  05h: %d  06h: %d  "
           "07h: %d  08h: %d\n", !!(b[4] & 0x80), !!(b[4] & 0x40),
           !!(b[4] & 0x20), !!(b[4] & 0x10), !!(b[4] & 0x8), !!(b[4] & 0x4),
           !!(b[4] & 0x2), !!(b[4] & 0x1));
    printf("  Flag09h: %d  0ah: %d  0bh: %d  0ch: %d  0dh: %d  0eh: %d  "
           "0fh: %d  10h: %d\n", !!(b[5] & 0x80), !!(b[5] & 0x40),
           !!(b[5] & 0x20), !!(b[5] & 0x10), !!(b[5] & 0x8), !!(b[5] & 0x4),
           !!(b[5] & 0x2), !!(b[5] & 0x1));
    printf("  Flag11h: %d  12h: %d  13h: %d  14h: %d  15h: %d  16h: %d  "
           "17h: %d  18h: %d\n", !!(b[6] & 0x80), !!(b[6] & 0x40),
           !!(b[6] & 0x20), !!(b[6] & 0x10), !!(b[6] & 0x8), !!(b[6] & 0x4),
           !!(b[6] & 0x2), !!(b[6] & 0x1));
    printf("  Flag19h: %d  1ah: %d  1bh: %d  1ch: %d  1dh: %d  1eh: %d  "
           "1fh: %d  20h: %d\n", !!(b[7] & 0x80), !!(b[7] & 0x40),
           !!(b[7] & 0x20), !!(b[7] & 0x10), !!(b[7] & 0x8), !!(b[7] & 0x4),
           !!(b[7] & 0x2), !!(b[7] & 0x1));
    printf("  Flag21h: %d  22h: %d  23h: %d  24h: %d  25h: %d  26h: %d  "
           "27h: %d  28h: %d\n", !!(b[8] & 0x80), !!(b[8] & 0x40),
           !!(b[8] & 0x20), !!(b[8] & 0x10), !!(b[8] & 0x8), !!(b[8] & 0x4),
           !!(b[8] & 0x2), !!(b[8] & 0x1));
    printf("  Flag29h: %d  2ah: %d  2bh: %d  2ch: %d  2dh: %d  2eh: %d  "
           "2fh: %d  30h: %d\n", !!(b[9] & 0x80), !!(b[9] & 0x40),
           !!(b[9] & 0x20), !!(b[9] & 0x10), !!(b[9] & 0x8), !!(b[9] & 0x4),
           !!(b[9] & 0x2), !!(b[9] & 0x1));
    printf("  Flag31h: %d  32h: %d  33h: %d  34h: %d  35h: %d  36h: %d  "
           "37h: %d  38h: %d\n", !!(b[10] & 0x80), !!(b[10] & 0x40),
           !!(b[10] & 0x20), !!(b[10] & 0x10), !!(b[10] & 0x8),
           !!(b[10] & 0x4), !!(b[10] & 0x2), !!(b[10] & 0x1));
    printf("  Flag39h: %d  3ah: %d  3bh: %d  3ch: %d  3dh: %d  3eh: %d  "
           "3fh: %d  40h: %d\n", !!(b[11] & 0x80), !!(b[11] & 0x40),
           !!(b[11] & 0x20), !!(b[11] & 0x10), !!(b[11] & 0x8),
           !!(b[11] & 0x4), !!(b[11] & 0x2), !!(b[11] & 0x1));
    return 0;
}

/* VPD_LB_PROVISIONING sbc */
/* VPD_TA_SUPPORTED ssc */
static void
decode_b2_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
        decode_block_lb_prov_vpd(buff, len);
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        decode_tapealert_supported_vpd(buff, len);
        break;
    default:
        printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHex((const char *)buff, len, 0);
        break;
    }
}

/* VPD_REFERRALS sbc */
/* VPD_AUTOMATION_DEV_SN ssc */
static void
decode_b3_vpd(unsigned char * b, int len, int do_hex, int pdt)
{
    char obuff[DEF_ALLOC_LEN];
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)b, len, 0);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
        if (len < 16) {
            fprintf(stderr, "Referrals VPD page length too short=%d\n", len);
            break;
        }
        u = ((unsigned int)b[8] << 24) | (b[9] << 16) | (b[10] << 8) | b[11];
        printf("  User data segment size: %u\n", u);
        u = ((unsigned int)b[12] << 24) | (b[13] << 16) |
            (b[14] << 8) | b[15];
        printf("  User data segment multiplier: %u\n", u);
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        memset(obuff, 0, sizeof(obuff));
        len -= 4;
        if (len >= (int)sizeof(obuff))
            len = sizeof(obuff) - 1;
        memcpy(obuff, b + 4, len);
        printf("  Automation device serial number: %s\n", obuff);
        break;
    default:
        printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHex((const char *)b, len, 0);
        break;
    }
}

/* Returns 0 if successful */
static int
svpd_unable_to_decode(int sg_fd, int num_vpd, int subvalue, int maxlen,
                      int do_hex, int do_raw, int do_long, int do_quiet,
                      int verbose)
{
    int len, res;
    int alloc_len = maxlen;

    do_quiet = do_quiet;       /* suppress warning */
    if ((! do_hex) && (! do_raw))
        printf("Only hex output supported\n");
    if (!do_raw) {
        if (subvalue)
            printf("VPD page code=0x%.2x, subvalue=0x%.2x:\n", num_vpd,
                   subvalue);
        else if (num_vpd >= 0)
            printf("VPD page code=0x%.2x:\n", num_vpd);
        else
            printf("VPD page code=%d:\n", num_vpd);
    }
    if (0 == alloc_len)
        alloc_len = DEF_ALLOC_LEN;
    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len,
                        1, verbose);
    if (0 == res) {
        len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
        if (num_vpd != rsp_buff[1]) {
            fprintf(stderr, "invalid VPD response; probably a STANDARD "
                    "INQUIRY response\n");
            if (verbose) {
                fprintf(stderr, "First 32 bytes of bad response\n");
                    dStrHex((const char *)rsp_buff, 32, 0);
            }
            return SG_LIB_CAT_MALFORMED;
        }
        if (len > alloc_len) {
            if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len, 1,
                                    verbose);
                if (res) {
                    fprintf(stderr, "fetching VPD page (2) code=0x%.2x "
                            " (alloc_len=%d) failed\n", num_vpd, len);
                    return res;
                }
            } else {
                fprintf(stderr, "warning: response length (%d) longer than "
                        "requested (%d)\n", len, maxlen);
                len = alloc_len;
            }
        }
        if (do_raw)
            dStrRaw((const char *)rsp_buff, len);
        else {
            if (VPD_ASCII_OP_DEF == num_vpd)
                dStrHex((const char *)rsp_buff, len, 0);
            else
                dStrHex((const char *)rsp_buff, len, (do_long ? 0 : 1));
        }
        return 0;
    } else {
        if (num_vpd >= 0)
            fprintf(stderr, "fetching VPD page code=0x%.2x: failed\n",
                    num_vpd);
        else
            fprintf(stderr, "fetching VPD page code=%d: failed\n", num_vpd);
        return res;
    }
}

/* Returns 0 if successful, else see sg_ll_inquiry() */
static int
svpd_decode_t10(int sg_fd, int num_vpd, int subvalue, int maxlen, int do_hex,
                int do_raw, int do_long, int do_quiet, int verbose)
{
    int len, pdt, num, k, pn;
    char buff[48];
    const struct svpd_values_name_t * vnp;
    int res = 0;
    int alloc_len = maxlen;
    char obuff[DEF_ALLOC_LEN];


    if (0 == alloc_len)
        alloc_len = (VPD_ATA_INFO == num_vpd) ?
                    VPD_ATA_INFO_LEN : DEF_ALLOC_LEN;
    switch(num_vpd) {
    case VPD_NOT_STD_INQ:         /* -2 (want standard inquiry response) */
        if (do_long)
            alloc_len = DEF_ALLOC_LEN;
        else if (0 == maxlen)
            alloc_len = 36;
        res = sg_ll_inquiry(sg_fd, 0, 0, 0, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            if (do_raw)
                dStrRaw((const char *)rsp_buff, alloc_len);
            else if (do_hex) {
                if (! do_quiet)
                    printf("Standard Inquiry reponse:\n");
                dStrHex((const char *)rsp_buff, alloc_len, 0);
            } else
                decode_std_inq(rsp_buff, alloc_len, verbose);
            return 0;
        }
        break;
    case VPD_SUPPORTED_VPDS:    /* 0x0 */
        if ((! do_raw) && (! do_quiet))
            printf("Supported VPD pages VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4; /* spc4r25 */
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Supported VPD pages "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                num = rsp_buff[3];
                if (num > (len - 4))
                    num = (len - 4);
                for (k = 0; k < num; ++k) {
                    pn = rsp_buff[4 + k];
                    vnp = sdp_get_vpd_detail(pn, -1, pdt);
                    if (vnp) {
                        if (do_long)
                            printf("  0x%02x  %s [%s]\n", pn, vnp->name,
                                   vnp->acron);
                        else
                            printf("  %s [%s]\n", vnp->name, vnp->acron);
                    } else
                        printf("  0x%x\n", pn);
                }
            }
            return 0;
        }
        break;
    case VPD_UNIT_SERIAL_NUM:   /* 0x80 */
        if ((! do_raw) && (! do_quiet))
            printf("Unit serial number VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4; /* spc4r25 */
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Unit serial number page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                memset(obuff, 0, sizeof(obuff));
                len -= 4;
                if (len >= (int)sizeof(obuff))
                    len = sizeof(obuff) - 1;
                memcpy(obuff, rsp_buff + 4, len);
                printf("  Unit serial number: %s\n", obuff);
            }
            return 0;
        }
        break;
    case VPD_DEVICE_ID:         /* 0x83 */
        if ((! do_raw) && (! do_quiet))
            printf("Device Identification VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Device Identification page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_id_vpd(rsp_buff, len, subvalue, do_long, do_quiet);
            }
            return 0;
        }
        break;
    case VPD_SOFTW_INF_ID:      /* 0x84 */
        if ((! do_raw) && (! do_quiet))
            printf("Software interface identification VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4; /* spc4r25 */
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Software interface id page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_softw_inf_id(rsp_buff, len, do_hex);
            }
            return 0;
        }
        break;
    case VPD_MAN_NET_ADDR:      /* 0x85 */
        if ((! do_raw) && (! do_quiet))
            printf("Management network addresses VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Management network "
                                "addresses page (alloc_len=%d) failed\n",
                                len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_net_man_vpd(rsp_buff, len, do_hex);
            return 0;
        }
        break;
    case VPD_EXT_INQ:           /* 0x86 */
        if ((! do_raw) && (! do_quiet))
            printf("extended INQUIRY data VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;   /* spc4r25 */
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Extended INQUIRY data page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                int protect = 0;
                struct sg_simple_inquiry_resp sir;

                if (do_long) {
                    res = sg_simple_inquiry(sg_fd, &sir, 0, verbose);
                    if (res)
                        break;
                    protect = sir.byte_5 & 0x1;     /* SPC-3 and later */
                }
                pdt = rsp_buff[0] & 0x1f;
                if (verbose)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_x_inq_vpd(rsp_buff, len, do_hex, do_long, protect);
            }
            return 0;
        }
        break;
    case VPD_MODE_PG_POLICY:    /* 0x87 */
        if ((! do_raw) && (! do_quiet))
            printf("Mode page policy VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Mode page policy page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_mode_policy_vpd(rsp_buff, len, do_hex);
            }
            return 0;
        }
        break;
    case VPD_SCSI_PORTS:        /* 0x88 */
        if ((! do_raw) && (! do_quiet))
            printf("SCSI Ports VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching SCSI ports page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_scsi_ports_vpd(rsp_buff, len, do_hex, do_long,
                                      do_quiet);
            }
            return 0;
        }
        break;
    case VPD_ATA_INFO:          /* 0x89 */
        if ((! do_raw) && (3 != do_hex) && (! do_quiet))
            printf("ATA information VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching ATA info page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if ((2 == do_raw) || (3 == do_hex))  /* special for hdparm */
                dWordHex((const unsigned short *)(rsp_buff + 60),
                         256, -2, sg_is_big_endian());
            else if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_ata_info_vpd(rsp_buff, len, do_long, do_hex);
            }
            return 0;
        }
        break;
    case VPD_POWER_CONDITION:          /* 0x8a */
        if ((! do_raw) && (! do_quiet))
            printf("Power condition VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching ATA info page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_power_condition(rsp_buff, len, do_hex);
            }
            return 0;
        }
        break;
    case VPD_POWER_CONSUMPTION:    /* 0x8d */
        if ((! do_raw) && (! do_quiet))
            printf("Power consumption VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Power consumption page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_power_consumption_vpd(rsp_buff, len, do_hex);
            }
            return 0;
        }
        break;
    case VPD_3PARTY_COPY:   /* 0x8f */
        if ((! do_raw) && (! do_quiet))
            printf("Third party copy VPD page:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4; /* spc4r25 */
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Third party copy page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else {
                printf("   Leave decoding of this page until it is wanted, "
                       "in hex:\n");
                dStrHex((const char *)rsp_buff, len, 0);
            }
            return 0;
        }
        break;
    case VPD_PROTO_LU:          /* 0x90 */
        if ((! do_raw) && (! do_quiet))
            printf("Protocol-specific logical unit information:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Protocol-specific LU page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_proto_lu_vpd(rsp_buff, len, do_hex);
            }
            return 0;
        }
        break;
    case VPD_PROTO_PORT:        /* 0x91 */
        if ((! do_raw) && (! do_quiet))
            printf("Protocol-specific port information:\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Protocol-specific port page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_proto_port_vpd(rsp_buff, len, do_hex);
            }
            return 0;
        }
        break;
    case 0xb0:  /* depends on pdt */
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            pdt = rsp_buff[0] & 0x1f;
            if ((! do_raw) && (! do_quiet)) {
                switch (pdt) {
                case 0: case 4: case 7:
                    printf("Block limits VPD page (SBC):\n");
                    break;
                case 1: case 8:
                    printf("Sequential access device capabilities VPD page "
                           "(SSC):\n");
                    break;
                case 0x11:
                    printf("OSD information VPD page (OSD):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", 0xb0, pdt);
                    break;
                }
            }
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xb0 page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_b0_vpd(rsp_buff, len, do_hex, pdt);
            }
            return 0;
        } else if (! do_raw)
            printf("VPD page=0xb0\n");
        break;
    case 0xb1:  /* depends on pdt */
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            pdt = rsp_buff[0] & 0x1f;
            if ((! do_raw) && (! do_quiet)) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
                    printf("Block device characteristics VPD page (SBC):\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("Manufactured assigned serial number VPD page "
                           "(SSC):\n");
                    break;
                case PDT_OSD:
                    printf("Security token VPD page (OSD):\n");
                    break;
                case PDT_ADC:
                    printf("Manufactured assigned serial number VPD page "
                           "(ADC):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", 0xb1, pdt);
                    break;
                }
            }
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xb1 page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_b1_vpd(rsp_buff, len, do_hex, pdt);
            }
            return 0;
        } else if (! do_raw)
            printf("VPD page=0xb1\n");
        break;
    case 0xb2:          /* VPD page depends on pdt */
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            pdt = rsp_buff[0] & 0x1f;
            if ((! do_raw) && (! do_quiet)) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
                    printf("Logical block provisioning VPD page (SBC):\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("TapeAlert supported flags VPD page (SSC):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", 0xb2, pdt);
                    break;
                }
            }
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xb2 page "
                                "(alloc_len=%d) failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_b2_vpd(rsp_buff, len, do_hex, pdt);
            }
            return 0;
        } else if (! do_raw)
            printf("VPD page=0xb2\n");
        break;
    case 0xb3:          /* VPD page depends on pdt */
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            pdt = rsp_buff[0] & 0x1f;
            if ((! do_raw) && (! do_quiet)) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
                    printf("Referrals VPD page (SBC):\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("Automation device serial number VPD page "
                           "(SSC):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", 0xb3, pdt);
                    break;
                }
            }
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching VPD page 0x%x "
                                "(alloc_len=%d) failed\n", num_vpd, len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                decode_b3_vpd(rsp_buff, len, do_hex, pdt);
            }
            return 0;
        } else if (! do_raw)
            printf("VPD page=0xb3\n");
        break;
    case VPD_DTDE_ADDRESS:      /* 0xb4 */
        if ((! do_raw) && (! do_quiet))
            printf("Data transfer device element address (SSC):\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                if (verbose) {
                    fprintf(stderr, "First 32 bytes of bad response\n");
                        dStrHex((const char *)rsp_buff, 32, 0);
                }
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching Data transfer device "
                                "element address page (alloc_len=%d) "
                                "failed\n", len);
                        return res;
                    }
                } else {
                    fprintf(stderr, ">>> warning: response length (%d) "
                            "longer than requested (%d)\n", len, alloc_len);
                    len = alloc_len;
                }
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (verbose || do_long)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rsp_buff[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(buff), buff));
                printf("  Data transfer device element address: 0x");
                for (k = 4; k < len; ++k)
                    printf("%02x", (unsigned int)rsp_buff[k]);
                printf("\n");
            }
            return 0;
        }
        break;
    default:
        return SG_LIB_SYNTAX_ERROR;
    }
    return res;
}


int
main(int argc, char * argv[])
{
    int sg_fd, c, res;
    const char * device_name = NULL;
    const struct svpd_values_name_t * vnp;
    const char * page_str = NULL;
    const char * cp;
    int num_vpd = 0;
    int do_hex = 0;
    int do_ident = 0;
    int do_long = 0;
    int maxlen = 0;
    int do_quiet = 0;
    int do_raw = 0;
    int do_verbose = 0;
    int ret = 0;
    int subvalue = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ehHilm:p:qrvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'e':
            printf("Standard VPD pages:\n");
            enumerate_vpds(1, 1);
            return 0;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'i':
            ++do_ident;
            break;
        case 'l':
            ++do_long;
            break;
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MX_ALLOC_LEN)) {
                fprintf(stderr, "argument to '--maxlen' should be %d or "
                        "less\n", MX_ALLOC_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
            if (page_str) {
                fprintf(stderr, "only one '--page=' option permitted\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            } else
                page_str = optarg;
            break;
        case 'q':
            ++do_quiet;
            break;
        case 'r':
            ++do_raw;
            break;
        case 'v':
            ++do_verbose;
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
    if (page_str) {
        if ((0 == strcmp("-1", page_str)) || (0 == strcmp("-2", page_str)))
            num_vpd = VPD_NOT_STD_INQ;
        else if (isalpha(page_str[0])) {
            vnp = sdp_find_vpd_by_acron(page_str);
            if (NULL == vnp) {
                vnp = svpd_find_vendor_by_acron(page_str);
                if (NULL == vnp) {
                    fprintf(stderr, "abbreviation doesn't match a VPD "
                            "page\n");
                    printf("available VPD pages:\n");
                    enumerate_vpds(1, 1);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            num_vpd = vnp->value;
            subvalue = vnp->subvalue;
        } else {
            cp = strchr(page_str, ',');
            num_vpd = sg_get_num_nomult(page_str);
            if ((num_vpd < 0) || (num_vpd > 255)) {
                fprintf(stderr, "Bad page code value after '-p' "
                        "option\n");
                printf("available VPD pages:\n");
                enumerate_vpds(1, 1);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (cp) {
                subvalue = sg_get_num_nomult(cp + 1);
                if ((subvalue < 0) || (subvalue > 255)) {
                    fprintf(stderr, "Bad subvalue code value after "
                            "'-p' option\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
        }
    }

    if (do_raw && do_hex) {
        fprintf(stderr, "Can't do hex and raw at the same time\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (do_ident) {
        num_vpd = VPD_DEVICE_ID;
        if (do_ident > 1) {
            if (0 == do_long)
                ++do_quiet;
            subvalue = VPD_DI_SEL_LU;
        }
    }
    if (NULL == device_name) {
        fprintf(stderr, "No DEVICE argument given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = sg_cmds_open_device(device_name, 1 /* ro */,
                                     do_verbose)) < 0) {
        fprintf(stderr, "error opening file: %s: %s\n",
                device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    memset(rsp_buff, 0, sizeof(rsp_buff));

    res = svpd_decode_t10(sg_fd, num_vpd, subvalue, maxlen, do_hex, do_raw,
                          do_long, do_quiet, do_verbose);
    if (SG_LIB_SYNTAX_ERROR == res) {
        res = svpd_decode_vendor(sg_fd, num_vpd, subvalue, maxlen, do_hex,
                                 do_raw, do_long, do_quiet, do_verbose);
        if (SG_LIB_SYNTAX_ERROR == res)
            res = svpd_unable_to_decode(sg_fd, num_vpd, subvalue, maxlen,
                                        do_hex, do_raw, do_long, do_quiet,
                                        do_verbose);
    }
    if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "fetching VPD page failed, aborted command\n");
    else if (res)
        fprintf(stderr, "fetching VPD page failed\n");
    ret = res;
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
