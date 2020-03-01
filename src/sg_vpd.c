/*
 * Copyright (c) 2006-2020 Douglas Gilbert.
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
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* This utility program was originally written for the Linux OS SCSI subsystem.

   This program fetches Vital Product Data (VPD) pages from the given
   device and outputs it as directed. VPD pages are obtained via a
   SCSI INQUIRY command. Most of the data in this program is obtained
   from the SCSI SPC-4 document at http://www.t10.org .

*/

static const char * version_str = "1.58 20200223";  /* spc6r01 + sbc4r18 */

/* standard VPD pages, in ascending page number order */
#define VPD_SUPPORTED_VPDS 0x0
#define VPD_UNIT_SERIAL_NUM 0x80
#define VPD_IMP_OP_DEF 0x81             /* obsolete in SPC-2 */
#define VPD_ASCII_OP_DEF 0x82           /* obsolete in SPC-2 */
#define VPD_DEVICE_ID 0x83
#define VPD_SOFTW_INF_ID 0x84
#define VPD_MAN_NET_ADDR 0x85
#define VPD_EXT_INQ 0x86                /* Extended Inquiry */
#define VPD_MODE_PG_POLICY 0x87
#define VPD_SCSI_PORTS 0x88
#define VPD_ATA_INFO 0x89
#define VPD_POWER_CONDITION 0x8a
#define VPD_DEVICE_CONSTITUENTS 0x8b
#define VPD_CFA_PROFILE_INFO 0x8c
#define VPD_POWER_CONSUMPTION  0x8d
#define VPD_3PARTY_COPY 0x8f            /* 3PC, XCOPY, SPC-4, SBC-3 */
#define VPD_PROTO_LU 0x90
#define VPD_PROTO_PORT 0x91
#define VPD_SCSI_FEATURE_SETS 0x92      /* spc5r11 */
#define VPD_BLOCK_LIMITS 0xb0           /* SBC-3 */
#define VPD_SA_DEV_CAP 0xb0             /* SSC-3 */
#define VPD_OSD_INFO 0xb0               /* OSD */
#define VPD_BLOCK_DEV_CHARS 0xb1        /* SBC-3 */
#define VPD_MAN_ASS_SN 0xb1             /* SSC-3, ADC-2 */
#define VPD_SECURITY_TOKEN 0xb1         /* OSD */
#define VPD_TA_SUPPORTED 0xb2           /* SSC-3 */
#define VPD_LB_PROVISIONING 0xb2        /* SBC-3 */
#define VPD_REFERRALS 0xb3              /* SBC-3 */
#define VPD_AUTOMATION_DEV_SN 0xb3      /* SSC-3 */
#define VPD_SUP_BLOCK_LENS 0xb4         /* sbc4r01 */
#define VPD_DTDE_ADDRESS 0xb4           /* SSC-4 */
#define VPD_BLOCK_DEV_C_EXTENS 0xb5     /* sbc4r02 */
#define VPD_LB_PROTECTION 0xb5          /* SSC-5 */
#define VPD_ZBC_DEV_CHARS 0xb6          /* zbc-r01b */
#define VPD_BLOCK_LIMITS_EXT 0xb7       /* sbc4r08 */
#define VPD_FORMAT_PRESETS 0xb8         /* sbc4r18 */
#define VPD_NOPE_WANT_STD_INQ -2        /* request for standard inquiry */

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

#define SENSE_BUFF_LEN  64       /* Arbitrary, could be larger */
#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define DEF_PT_TIMEOUT  60       /* 60 seconds */


/* These structures are duplicates of those of the same name in
 * sg_vpd_vendor.c . Take care that both are the same. */
struct opts_t {
    bool do_all;
    bool do_enum;
    bool do_force;
    bool do_long;
    bool do_quiet;
    bool verbose_given;
    bool version_given;
    int do_hex;
    int do_ident;
    int do_raw;
    int examine;
    int maxlen;
    int vend_prod_num;
    int verbose;
    int vpd_pn;
    const char * device_name;
    const char * page_str;
    const char * inhex_fn;
    const char * vend_prod;
};

struct svpd_values_name_t {
    int value;       /* VPD page number */
    int subvalue;    /* to differentiate if value+pdt are not unique */
    int pdt;         /* peripheral device type id, -1 is the default */
                     /* (all or not applicable) value */
    const char * acron;
    const char * name;
};


/* Following functions also used by sg_vpd_vendor.c hence extern */
void svpd_enumerate_vendor(int vend_prod_num);
int svpd_count_vendor_vpds(int vpd_pn, int vend_prod_num);
int svpd_decode_vendor(int sg_fd, struct opts_t * op, int off);
const struct svpd_values_name_t * svpd_find_vendor_by_acron(const char * ap);
int svpd_find_vp_num_by_acron(const char * vp_ap);
const struct svpd_values_name_t * svpd_find_vendor_by_num(int page_num,
                                                          int vend_prod_num);
int vpd_fetch_page(int sg_fd, uint8_t * rp, int page, int mxlen,
                   bool qt, int vb, int * rlenp);
void dup_sanity_chk(int sz_opts_t, int sz_values_name_t);

static int svpd_decode_t10(int sg_fd, struct opts_t * op, int subvalue,
                           int off, const char * prefix);
static int svpd_unable_to_decode(int sg_fd, struct opts_t * op, int subvalue,
                                 int off);

static int decode_dev_ids(const char * print_if_found, int num_leading,
                          uint8_t * buff, int len, int m_assoc,
                          int m_desig_type, int m_code_set,
                          const struct opts_t * op);

uint8_t * rsp_buff;
const int rsp_buff_sz = MX_ALLOC_LEN + 2;
static uint8_t * free_rsp_buff;

static struct option long_options[] = {
        {"all", no_argument, 0, 'a'},
        {"enumerate", no_argument, 0, 'e'},
        {"examine", no_argument, 0, 'E'},
        {"force", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"ident", no_argument, 0, 'i'},
        {"inhex", required_argument, 0, 'I'},
        {"long", no_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"page", required_argument, 0, 'p'},
        {"quiet", no_argument, 0, 'q'},
        {"raw", no_argument, 0, 'r'},
        {"vendor", required_argument, 0, 'M'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


/* arranged in alphabetical order by acronym */
static struct svpd_values_name_t standard_vpd_pg[] = {
    {VPD_ATA_INFO, 0, -1, "ai", "ATA information (SAT)"},
    {VPD_ASCII_OP_DEF, 0, -1, "aod",
     "ASCII implemented operating definition (obsolete)"},
    {VPD_AUTOMATION_DEV_SN, 0, 1, "adsn", "Automation device serial "
     "number (SSC)"},
    {VPD_BLOCK_LIMITS, 0, 0, "bl", "Block limits (SBC)"},
    {VPD_BLOCK_LIMITS_EXT, 0, 0, "ble", "Block limits extension (SBC)"},
    {VPD_BLOCK_DEV_CHARS, 0, 0, "bdc", "Block device characteristics "
     "(SBC)"},
    {VPD_BLOCK_DEV_C_EXTENS, 0, 0, "bdce", "Block device characteristics "
     "extension (SBC)"},
    {VPD_CFA_PROFILE_INFO, 0, 0, "cfa", "CFA profile information"},
    {VPD_DEVICE_CONSTITUENTS, 0, -1, "dc", "Device constituents"},
    {VPD_DEVICE_ID, 0, -1, "di", "Device identification"},
    {VPD_DEVICE_ID, VPD_DI_SEL_AS_IS, -1, "di_asis", "Like 'di' "
     "but designators ordered as found"},
    {VPD_DEVICE_ID, VPD_DI_SEL_LU, -1, "di_lu", "Device identification, "
     "lu only"},
    {VPD_DEVICE_ID, VPD_DI_SEL_TPORT, -1, "di_port", "Device "
     "identification, target port only"},
    {VPD_DEVICE_ID, VPD_DI_SEL_TARGET, -1, "di_target", "Device "
     "identification, target device only"},
    {VPD_DTDE_ADDRESS, 0, 1, "dtde",
     "Data transfer device element address (SSC)"},
    {VPD_EXT_INQ, 0, -1, "ei", "Extended inquiry data"},
    {VPD_FORMAT_PRESETS, 0, 0, "fp", "Format presets"},
    {VPD_IMP_OP_DEF, 0, -1, "iod",
     "Implemented operating definition (obsolete)"},
    {VPD_LB_PROTECTION, 0, 0, "lbpro", "Logical block protection (SSC)"},
    {VPD_LB_PROVISIONING, 0, 0, "lbpv", "Logical block provisioning (SBC)"},
    {VPD_MAN_ASS_SN, 0, 1, "mas", "Manufacturer assigned serial number (SSC)"},
    {VPD_MAN_ASS_SN, 0, 0x12, "masa",
     "Manufacturer assigned serial number (ADC)"},
    {VPD_MAN_NET_ADDR, 0, -1, "mna", "Management network addresses"},
    {VPD_MODE_PG_POLICY, 0, -1, "mpp", "Mode page policy"},
    {VPD_OSD_INFO, 0, 0x11, "oi", "OSD information"},
    {VPD_POWER_CONDITION, 0, -1, "pc", "Power condition"},
    {VPD_POWER_CONSUMPTION, 0, -1, "psm", "Power consumption"},
    {VPD_PROTO_LU, 0, -1, "pslu", "Protocol-specific logical unit "
     "information"},
    {VPD_PROTO_PORT, 0, -1, "pspo", "Protocol-specific port information"},
    {VPD_REFERRALS, 0, 0, "ref", "Referrals (SBC)"},
    {VPD_SA_DEV_CAP, 0, 1, "sad",
     "Sequential access device capabilities (SSC)"},
    {VPD_SUP_BLOCK_LENS, 0, 0, "sbl", "Supported block lengths and "
     "protection types (SBC)"},
    {VPD_SCSI_FEATURE_SETS, 0, -1, "sfs", "SCSI feature sets"},
    {VPD_SOFTW_INF_ID, 0, -1, "sii", "Software interface identification"},
    {VPD_NOPE_WANT_STD_INQ, 0, -1, "sinq", "Standard inquiry response"},
    {VPD_UNIT_SERIAL_NUM, 0, -1, "sn", "Unit serial number"},
    {VPD_SCSI_PORTS, 0, -1, "sp", "SCSI ports"},
    {VPD_SECURITY_TOKEN, 0, 0x11, "st", "Security token (OSD)"},
    {VPD_SUPPORTED_VPDS, 0, -1, "sv", "Supported VPD pages"},
    {VPD_TA_SUPPORTED, 0, 1, "tas", "TapeAlert supported flags (SSC)"},
    {VPD_3PARTY_COPY, 0, -1, "tpc", "Third party copy"},
    {VPD_ZBC_DEV_CHARS, 0, -1, "zbdch", "Zoned block device characteristics"},
        /* Use pdt of -1 since this page both for pdt=0 and pdt=0x14 */
    {0, 0, 0, NULL, NULL},
};


static void
usage()
{
    pr2serr("Usage: sg_vpd  [--all] [--enumerate] [--examine] [--force] "
            "[--help] [--hex]\n"
            "               [--ident] [--inhex=FN] [--long] [--maxlen=LEN] "
            "[--page=PG]\n"
            "               [--quiet] [--raw] [--vendor=VP] [--verbose] "
            "[--version]\n"
            "               DEVICE\n");
    pr2serr("  where:\n"
            "    --all|-a        output all pages listed in the supported "
            "pages VPD\n"
            "                    page\n"
            "    --enumerate|-e    enumerate known VPD pages names (ignore "
            "DEVICE),\n"
            "                      can be used with --page=num to search\n"
            "    --examine|-E    starting at 0x80 scan pages code to 0xff\n"
            "    --force|-f      skip VPD page 0 (supported VPD pages) "
            "checking\n"
            "    --help|-h       output this usage message then exit\n"
            "    --hex|-H        output page in ASCII hexadecimal\n"
            "    --ident|-i      output device identification VPD page, "
            "twice for\n"
            "                    short logical unit designator (equiv: "
            "'-qp di_lu')\n"
            "    --inhex=FN|-I FN    read ASCII hex from file FN instead of "
            "DEVICE;\n"
            "                        if used with --raw then read binary "
            "from FN\n"
            "    --long|-l       perform extra decoding\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> 252 bytes)\n"
            "    --page=PG|-p PG    fetch VPD page where PG is an "
            "acronym, or a decimal\n"
            "                       number unless hex indicator "
            "is given (e.g. '0x83');\n"
            "                       can also take PG,VP as an "
            "operand\n"
            "    --quiet|-q      suppress some output when decoding\n"
            "    --raw|-r        output page in binary; if --inhex=FN is "
            "also\n"
            "                    given, FN is in binary (else FN is in "
            "hex)\n"
            "    --vendor=VP|-M VP    vendor/product abbreviation [or "
            "number]\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version string and exit\n\n"
            "Fetch Vital Product Data (VPD) page using SCSI INQUIRY or "
            "decodes VPD\npage response held in file FN. To list available "
            "pages use '-e'. Also\n'-p -1' or '-p sinq' yields the standard "
            "INQUIRY response.\n");
}

/* mxlen is command line --maxlen=LEN option (def: 0) or -1 for a VPD page
 * with a short length (1 byte). Returns 0 for success. */
int     /* global: use by sg_vpd_vendor.c */
vpd_fetch_page(int sg_fd, uint8_t * rp, int page, int mxlen, bool qt,
               int vb, int * rlenp)
{
    int res, resid, rlen, len, n;

    if (sg_fd < 0) {
        len = sg_get_unaligned_be16(rp + 2) + 4;
        if (vb && (len > mxlen))
            pr2serr("warning: VPD page's length (%d) > bytes in --inhex=FN "
                    "file (%d)\n",  len , mxlen);
        if (rlenp)
            *rlenp = (len < mxlen) ? len : mxlen;
        return 0;
    }
    if (mxlen > MX_ALLOC_LEN) {
        pr2serr("--maxlen=LEN too long: %d > %d\n", mxlen, MX_ALLOC_LEN);
        return SG_LIB_SYNTAX_ERROR;
    }
    n = (mxlen > 0) ? mxlen : DEF_ALLOC_LEN;
    res = sg_ll_inquiry_v2(sg_fd, true, page, rp, n, DEF_PT_TIMEOUT, &resid,
                           ! qt, vb);
    if (res)
        return res;
    rlen = n - resid;
    if (rlen < 4) {
        pr2serr("VPD response too short (len=%d)\n", rlen);
        return SG_LIB_CAT_MALFORMED;
    }
    if (page != rp[1]) {
        pr2serr("invalid VPD response; probably a STANDARD INQUIRY "
                "response\n");
        n = (rlen < 32) ? rlen : 32;
        if (vb) {
            pr2serr("First %d bytes of bad response\n", n);
            hex2stderr(rp, n, 0);
        }
        return SG_LIB_CAT_MALFORMED;
    } else if ((0x80 == page) && (0x2 == rp[2]) && (0x2 == rp[3])) {
        /* could be a Unit Serial number VPD page with a very long
         * length of 4+514 bytes; more likely standard response for
         * SCSI-2, RMB=1 and a response_data_format of 0x2. */
        pr2serr("invalid Unit Serial Number VPD response; probably a "
                "STANDARD INQUIRY response\n");
        return SG_LIB_CAT_MALFORMED;
    }
    if (mxlen < 0)
        len = rp[3] + 4;
    else
        len = sg_get_unaligned_be16(rp + 2) + 4;
    if (len <= rlen) {
        if (rlenp)
            *rlenp = len;
        return 0;
    } else if (mxlen) {
        if (rlenp)
            *rlenp = rlen;
        return 0;
    }
    if (len > MX_ALLOC_LEN) {
        pr2serr("response length too long: %d > %d\n", len, MX_ALLOC_LEN);
        return SG_LIB_CAT_MALFORMED;
    } else {
        res = sg_ll_inquiry_v2(sg_fd, true, page, rp, len, DEF_PT_TIMEOUT,
                               &resid, ! qt, vb);
        if (res)
            return res;
        rlen = len - resid;
        /* assume it is well behaved: hence page and len still same */
        if (rlenp)
            *rlenp = rlen;
        return 0;
    }
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
            if (vnp->name) {
                if (vnp->value < 0)
                    printf("  %-10s -1        %s\n", vnp->acron, vnp->name);
                else
                    printf("  %-10s 0x%02x      %s\n", vnp->acron, vnp->value,
                       vnp->name);
            }
        }
    }
    if (vendor)
        svpd_enumerate_vendor(-2);
}

static int
count_standard_vpds(int vpd_pn)
{
    const struct svpd_values_name_t * vnp;
    int matches;

    for (vnp = standard_vpd_pg, matches = 0; vnp->acron; ++vnp) {
        if ((vpd_pn == vnp->value) && vnp->name) {
            if (0 == matches)
                printf("Matching standard VPD pages:\n");
            ++matches;
            if (vnp->value < 0)
                printf("  %-10s -1        %s\n", vnp->acron, vnp->name);
            else
                printf("  %-10s 0x%02x      %s\n", vnp->acron, vnp->value,
                   vnp->name);
        }
    }
    return matches;
}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Assume index is less than 16 */
static const char * sg_ansi_version_arr[16] =
{
    "no conformance claimed",
    "SCSI-1",           /* obsolete, ANSI X3.131-1986 */
    "SCSI-2",           /* obsolete, ANSI X3.131-1994 */
    "SPC",              /* withdrawn, ANSI INCITS 301-1997 */
    "SPC-2",            /* ANSI INCITS 351-2001, ISO/IEC 14776-452 */
    "SPC-3",            /* ANSI INCITS 408-2005, ISO/IEC 14776-453 */
    "SPC-4",            /* ANSI INCITS 513-2015 */
    "SPC-5",
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
std_inq_decode(uint8_t * b, int len, int verbose)
{
    int pqual, n;

    if (len < 4)
        return;
    pqual = (b[0] & 0xe0) >> 5;
    printf("standard INQUIRY:");
    if (0 == pqual)
        printf("\n");
    else if (1 == pqual)
        printf(" [PQ indicates LU temporarily unavailable]\n");
    else if (3 == pqual)
        printf(" [PQ indicates LU not accessible via this port]\n");
    else
        printf(" [reserved or vendor specific qualifier [%d]]\n", pqual);
    printf("  PQual=%d  Device_type=%d  RMB=%d  LU_CONG=%d  version=0x%02x ",
           pqual, b[0] & 0x1f, !!(b[1] & 0x80), !!(b[1] & 0x40),
           (unsigned int)b[2]);
    printf(" [%s]\n", sg_ansi_version_arr[b[2] & 0xf]);
    printf("  [AERC=%d]  [TrmTsk=%d]  NormACA=%d  HiSUP=%d "
           " Resp_data_format=%d\n",
           !!(b[3] & 0x80), !!(b[3] & 0x40), !!(b[3] & 0x20),
           !!(b[3] & 0x10), b[3] & 0x0f);
    if (len < 5)
        return;
    n = b[4] + 5;
    if (verbose)
        pr2serr(">> requested %d bytes, %d bytes available\n", len, n);
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
    printf("WBus16=%d  Sync=%d  [Linked=%d]  [TranDis=%d]  ",
           !!(b[7] & 0x20), !!(b[7] & 0x10), !!(b[7] & 0x08),
           !!(b[7] & 0x04));
    printf("CmdQue=%d\n", !!(b[7] & 0x02));
    if (len < 36)
        return;
    printf("  Vendor_identification: %.8s\n", b + 8);
    printf("  Product_identification: %.16s\n", b + 16);
    printf("  Product_revision_level: %.4s\n", b + 32);
}

static void
decode_id_vpd(uint8_t * buff, int len, int subvalue,
              const struct opts_t * op)
{
    int m_a, m_d, m_cs, blen;
    uint8_t * b;

    if (len < 4) {
        pr2serr("Device identification VPD page length too short=%d\n", len);
        return;
    }
    blen = len - 4;
    b = buff + 4;
    m_a = -1;
    m_d = -1;
    m_cs = -1;
    if (0 == subvalue) {
        decode_dev_ids(sg_get_desig_assoc_str(VPD_ASSOC_LU), 0, b, blen,
                       VPD_ASSOC_LU, m_d, m_cs, op);
        decode_dev_ids(sg_get_desig_assoc_str(VPD_ASSOC_TPORT), 0, b, blen,
                       VPD_ASSOC_TPORT, m_d, m_cs, op);
        decode_dev_ids(sg_get_desig_assoc_str(VPD_ASSOC_TDEVICE), 0, b, blen,
                       VPD_ASSOC_TDEVICE, m_d, m_cs, op);
    } else if (VPD_DI_SEL_AS_IS == subvalue)
        decode_dev_ids(NULL, 0, b, blen, m_a, m_d, m_cs, op);
    else {
        if (VPD_DI_SEL_LU & subvalue)
            decode_dev_ids(sg_get_desig_assoc_str(VPD_ASSOC_LU), 0, b, blen,
                           VPD_ASSOC_LU, m_d, m_cs, op);
        if (VPD_DI_SEL_TPORT & subvalue)
            decode_dev_ids(sg_get_desig_assoc_str(VPD_ASSOC_TPORT), 0, b,
                           blen, VPD_ASSOC_TPORT, m_d, m_cs, op);
        if (VPD_DI_SEL_TARGET & subvalue)
            decode_dev_ids(sg_get_desig_assoc_str(VPD_ASSOC_TDEVICE), 0,
                           b, blen, VPD_ASSOC_TDEVICE, m_d, m_cs, op);
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
    "copy service",
    "administrative configuration service",
    "reserved[0x8]", "reserved[0x9]",
    "reserved[0xa]", "reserved[0xb]", "reserved[0xc]", "reserved[0xd]",
    "reserved[0xe]", "reserved[0xf]", "reserved[0x10]", "reserved[0x11]",
    "reserved[0x12]", "reserved[0x13]", "reserved[0x14]", "reserved[0x15]",
    "reserved[0x16]", "reserved[0x17]", "reserved[0x18]", "reserved[0x19]",
    "reserved[0x1a]", "reserved[0x1b]", "reserved[0x1c]", "reserved[0x1d]",
    "reserved[0x1e]", "reserved[0x1f]",
};

/* VPD_MAN_NET_ADDR */
static void
decode_net_man_vpd(uint8_t * buff, int len, int do_hex)
{
    int k, bump, na_len;
    uint8_t * bp;

    if ((1 == do_hex) || (do_hex > 2)) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Management network addresses VPD page length too short=%d\n",
                len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        printf("  %s, Service type: %s\n",
               sg_get_desig_assoc_str((bp[0] >> 5) & 0x3),
               network_service_type_arr[bp[0] & 0x1f]);
        na_len = sg_get_unaligned_be16(bp + 2);
        bump = 4 + na_len;
        if ((k + bump) > len) {
            pr2serr("Management network addresses VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (na_len > 0) {
            if (do_hex > 1) {
                printf("    Network address:\n");
                hex2stdout((bp + 4), na_len, 0);
            } else
                printf("    %s\n", bp + 4);
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
decode_mode_policy_vpd(uint8_t * buff, int len, int do_hex)
{
    int k, bump;
    uint8_t * bp;

    if ((1 == do_hex) || (do_hex > 2)) {
        hex2stdout(buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Mode page policy VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            pr2serr("Mode page policy VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (do_hex > 1)
            hex2stdout(bp, 4, 1);
        else {
            printf("  Policy page code: 0x%x", (bp[0] & 0x3f));
            if (bp[1])
                printf(",  subpage code: 0x%x\n", bp[1]);
            else
                printf("\n");
            if ((0 == k) && (0x3f == (0x3f & bp[0])) && (0xff == bp[1]))
                printf("  therefore the policy applies to all modes pages "
                       "and subpages\n");
            printf("    MLUS=%d,  Policy: %s\n", !!(bp[2] & 0x80),
                   mode_page_policy_arr[bp[2] & 0x3]);
        }
    }
}

/* VPD_SCSI_PORTS */
static void
decode_scsi_ports_vpd(uint8_t * buff, int len, const struct opts_t * op)
{
    int k, bump, rel_port, ip_tid_len, tpd_len;
    uint8_t * bp;

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("SCSI Ports VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        rel_port = sg_get_unaligned_be16(bp + 2);
        printf("  Relative port=%d\n", rel_port);
        ip_tid_len = sg_get_unaligned_be16(bp + 6);
        bump = 8 + ip_tid_len;
        if ((k + bump) > len) {
            pr2serr("SCSI Ports VPD page, short descriptor "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (ip_tid_len > 0) {
            if (op->do_hex > 1) {
                printf("    Initiator port transport id:\n");
                hex2stdout((bp + 8), ip_tid_len, 1);
            } else {
                char b[1024];

                printf("%s", sg_decode_transportid_str("    ", bp + 8,
                                         ip_tid_len, true, sizeof(b), b));
            }
        }
        tpd_len = sg_get_unaligned_be16(bp + bump + 2);
        if ((k + bump + tpd_len + 4) > len) {
            pr2serr("SCSI Ports VPD page, short descriptor(tgt) "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (tpd_len > 0) {
            if (op->do_hex > 1) {
                printf("    Target port descriptor(s):\n");
                hex2stdout(bp + bump + 4, tpd_len, 1);
            } else {
                if ((0 == op->do_quiet) || (ip_tid_len > 0))
                    printf("    Target port descriptor(s):\n");
                decode_dev_ids("", 2 /* leading spaces */, bp + bump + 4,
                               tpd_len, VPD_ASSOC_TPORT, -1, -1, op);
            }
        }
        bump += tpd_len + 4;
    }
}

/* Prints outs an abridged set of device identification designators
   selected by association, designator type and/or code set. */
static int
decode_dev_ids_quiet(uint8_t * buff, int len, int m_assoc,
                     int m_desig_type, int m_code_set)
{
    int k, m, p_id, c_set, piv, desig_type, i_len, naa, off, u;
    int assoc, is_sas, rtp;
    const uint8_t * bp;
    const uint8_t * ip;
    uint8_t sas_tport_addr[8];

    rtp = 0;
    memset(sas_tport_addr, 0, sizeof(sas_tport_addr));
    for (k = 0, off = -1; true; ++k) {
        if ((0 == k) && (0 != buff[2])) {
            /* first already in buff */
            if (m_assoc != VPD_ASSOC_LU)
                return 0;
            ip = buff;
            c_set = 1;
            assoc = VPD_ASSOC_LU;
            is_sas = 0;
            desig_type = 3;
            i_len = 16;
        } else {
            u = sg_vpd_dev_id_iter(buff, len, &off, m_assoc, m_desig_type,
                                   m_code_set);
            if (0 != u)
                break;
            bp = buff + off;
            i_len = bp[3];
            if ((off + i_len + 4) > len) {
                pr2serr("    VPD page error: designator length longer than\n"
                        "     remaining response length=%d\n", (len - off));
                return SG_LIB_CAT_MALFORMED;
            }
            ip = bp + 4;
            p_id = ((bp[0] >> 4) & 0xf);
            c_set = (bp[0] & 0xf);
            piv = ((bp[1] & 0x80) ? 1 : 0);
            is_sas = (piv && (6 == p_id)) ? 1 : 0;
            assoc = ((bp[1] >> 4) & 0x3);
            desig_type = (bp[1] & 0xf);
        }
        switch (desig_type) {
        case 0: /* vendor specific */
            break;
        case 1: /* T10 vendor identification */
            break;
        case 2: /* EUI-64 based */
            if ((8 != i_len) && (12 != i_len) && (16 != i_len))
                pr2serr("      << expect 8, 12 and 16 byte "
                        "EUI, got %d>>\n", i_len);
            printf("  0x");
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        case 3: /* NAA */
            naa = (ip[0] >> 4) & 0xff;
            if (1 != c_set) {
                pr2serr("      << expected binary code_set (1), got %d for "
                        "NAA=%d>>\n", c_set, naa);
                hex2stderr(ip, i_len, 0);
                break;
            }
            switch (naa) {
            case 2:             /* NAA IEEE extended */
                if (8 != i_len) {
                    pr2serr("      << unexpected NAA 2 identifier "
                            "length: 0x%x>>\n", i_len);
                    hex2stderr(ip, i_len, 0);
                    break;
                }
                printf("  0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
                break;
            case 3:             /* Locally assigned */
            case 5:             /* IEEE Registered */
                if (8 != i_len) {
                    pr2serr("      << unexpected NAA 3 or 5 "
                            "identifier length: 0x%x>>\n", i_len);
                    hex2stderr(ip, i_len, 0);
                    break;
                }
                if ((0 == is_sas) || (1 != assoc)) {
                    printf("  0x");
                    for (m = 0; m < 8; ++m)
                        printf("%02x", (unsigned int)ip[m]);
                    printf("\n");
                } else if (rtp) {
                    printf("  0x");
                    for (m = 0; m < 8; ++m)
                        printf("%02x", (unsigned int)ip[m]);
                    printf(",0x%x\n", rtp);
                    rtp = 0;
                } else {
                    if (sas_tport_addr[0]) {
                        printf("  0x");
                        for (m = 0; m < 8; ++m)
                            printf("%02x", (unsigned int)sas_tport_addr[m]);
                        printf("\n");
                    }
                    memcpy(sas_tport_addr, ip, sizeof(sas_tport_addr));
                }
                break;
            case 6:             /* NAA IEEE registered extended */
                if (16 != i_len) {
                    pr2serr("      << unexpected NAA 6 identifier length: "
                            "0x%x>>\n", i_len);
                    hex2stderr(ip, i_len, 0);
                    break;
                }
                printf("  0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
                break;
            default:
                pr2serr("      << bad NAA nibble, expected 2, 3, 5 or 6, got "
                        "%d>>\n", naa);
                hex2stderr(ip, i_len, 0);
                break;
            }
            break;
        case 4: /* Relative target port */
            if ((0 == is_sas) || (1 != c_set) || (1 != assoc) || (4 != i_len))
                break;
            rtp = sg_get_unaligned_be16(ip + 2);
            if (sas_tport_addr[0]) {
                printf("  0x");
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
            if (c_set < 2) {    /* quietly accept ASCII for UTF-8 */
                pr2serr("      << expected UTF-8 code_set>>\n");
                hex2stderr(ip, i_len, 0);
                break;
            }
            if (! (strncmp((const char *)ip, "eui.", 4) ||
                   strncmp((const char *)ip, "EUI.", 4) ||
                   strncmp((const char *)ip, "naa.", 4) ||
                   strncmp((const char *)ip, "NAA.", 4) ||
                   strncmp((const char *)ip, "iqn.", 4))) {
                pr2serr("      << expected name string prefix>>\n");
                hex2stderr(ip, i_len, -1);
                break;
            }
            /* does %s print out UTF-8 ok??
             * Seems to depend on the locale. Looks ok here with my
             * locale setting: en_AU.UTF-8
             */
            printf("  %.*s\n", i_len, (const char *)ip);
            break;
        case 9: /* Protocol specific port identifier */
            break;
        case 0xa: /* UUID identifier [spc5r08] RFC 4122 */
            if ((1 != c_set) || (18 != i_len) || (1 != ((ip[0] >> 4) & 0xf)))
                break;
            for (m = 0; m < 16; ++m) {
                if ((4 == m) || (6 == m) || (8 == m) || (10 == m))
                    printf("-");
                printf("%02x", (unsigned int)ip[2 + m]);
            }
            printf("\n");
            break;
        default: /* reserved */
            break;
        }
    }
    if (sas_tport_addr[0]) {
        printf("  0x");
        for (m = 0; m < 8; ++m)
            printf("%02x", (unsigned int)sas_tport_addr[m]);
        printf("\n");
    }
    if (-2 == u) {
        pr2serr("VPD page error: short designator around offset %d\n", off);
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
}

/* Prints outs designation descriptors (dd_s)selected by association,
   designator type and/or code set. */
static int
decode_dev_ids(const char * print_if_found, int num_leading, uint8_t * buff,
               int len, int m_assoc, int m_desig_type, int m_code_set,
               const struct opts_t * op)
{
    int assoc, off, u, i_len;
    bool printed;
    const uint8_t * bp;
    char b[1024];
    char sp[82];

    if (op->do_quiet)
        return decode_dev_ids_quiet(buff, len, m_assoc, m_desig_type,
                                    m_code_set);
    if (num_leading > (int)(sizeof(sp) - 2))
        num_leading = sizeof(sp) - 2;
    if (num_leading > 0)
        snprintf(sp, sizeof(sp), "%*c", num_leading, ' ');
    else
        sp[0] = '\0';
    if (buff[2] != 0) { /* all valid dd_s should have 0 in this byte */
        if (op->verbose)
            pr2serr("%s: designation descriptors byte 2 should be 0\n"
                    "perhaps this is a standard inquiry response, ignore\n",
                    __func__);
        return 0;
    }
    off = -1;
    printed = false;
    while ((u = sg_vpd_dev_id_iter(buff, len, &off, m_assoc, m_desig_type,
                                   m_code_set)) == 0) {
        bp = buff + off;
        i_len = bp[3];
        if ((off + i_len + 4) > len) {
            pr2serr("    VPD page error: designator length longer than\n"
                    "     remaining response length=%d\n", (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        assoc = ((bp[1] >> 4) & 0x3);
        if (print_if_found && (! printed)) {
            printed = true;
            if (strlen(print_if_found) > 0)
                printf("  %s:\n", print_if_found);
        }
        if (NULL == print_if_found)
            printf("  %s%s:\n", sp, sg_get_desig_assoc_str(assoc));
        sg_get_designation_descriptor_str(sp, bp, i_len + 4, false,
                                          op->do_long, sizeof(b), b);
        printf("%s", b);
    }
    if (-2 == u) {
        pr2serr("VPD page error: short designator around offset %d\n", off);
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
}

/* VPD_EXT_INQ    Extended Inquiry VPD */
static void
decode_x_inq_vpd(uint8_t * b, int len, int do_hex, bool do_long,
                 bool protect)
{
    int n;

    if (len < 7) {
        pr2serr("Extended INQUIRY data VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        hex2stdout(b, len, (1 == do_hex) ? 0 : -1);
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
            case 6:
                printf(" [see Supported block lengths and protection types "
                       "VPD page]\n");
                break;
            case 7:
                printf(" [protection types 1, 2 and 3 supported]\n");
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
        printf("  NO_PI_CHK=%d\n", !!(b[7] & 0x10));    /* spc5r02 */
        printf("  P_I_I_SUP=%d\n", !!(b[7] & 0x10));
        printf("  LUICLR=%d\n", !!(b[7] & 0x1));
        printf("  LU_COLL_TYPE=%d\n", (b[8] >> 5) & 0x7); /* spc5r09 */
        printf("  R_SUP=%d\n", !!(b[8] & 0x10));
        printf("  RTD_SUP=%d\n", !!(b[8] & 0x8));       /* spc5r11 */
        printf("  HSSRELEF=%d\n", !!(b[8] & 0x2));      /* spc5r02 */
        printf("  CBCS=%d\n", !!(b[8] & 0x1));  /* obsolete in spc5r01 */
        printf("  Multi I_T nexus microcode download=%d\n", b[9] & 0xf);
        printf("  Extended self-test completion minutes=%d\n",
               sg_get_unaligned_be16(b + 10));
        printf("  POA_SUP=%d\n", !!(b[12] & 0x80));     /* spc4r32 */
        printf("  HRA_SUP=%d\n", !!(b[12] & 0x40));     /* spc4r32 */
        printf("  VSA_SUP=%d\n", !!(b[12] & 0x20));     /* spc4r32 */
        printf("  DMS_VALID=%d\n", !!(b[12] & 0x10));   /* spc5r20 */
        printf("  Maximum supported sense data length=%d\n",
               b[13]); /* spc4r34 */
        printf("  IBS=%d\n", !!(b[14] & 0x80));     /* spc5r09 */
        printf("  IAS=%d\n", !!(b[14] & 0x40));     /* spc5r09 */
        printf("  SAC=%d\n", !!(b[14] & 0x4));      /* spc5r09 */
        printf("  NRD1=%d\n", !!(b[14] & 0x2));     /* spc5r09 */
        printf("  NRD0=%d\n", !!(b[14] & 0x1));     /* spc5r09 */
        printf("  Maximum inquiry change logs=%u\n",
               sg_get_unaligned_be16(b + 15));      /* spc5r17 */
        printf("  Maximum mode page change logs=%u\n",
               sg_get_unaligned_be16(b + 17));      /* spc5r17 */
        printf("  DM_MD_4=%d\n", !!(b[19] & 0x80)); /* spc5r20 */
        printf("  DM_MD_5=%d\n", !!(b[19] & 0x40)); /* spc5r20 */
        printf("  DM_MD_6=%d\n", !!(b[19] & 0x20)); /* spc5r20 */
        printf("  DM_MD_7=%d\n", !!(b[19] & 0x10)); /* spc5r20 */
        printf("  DM_MD_D=%d\n", !!(b[19] & 0x8));  /* spc5r20 */
        printf("  DM_MD_E=%d\n", !!(b[19] & 0x4));  /* spc5r20 */
        printf("  DM_MD_F=%d\n", !!(b[19] & 0x2));  /* spc5r20 */
        return;
    }
    printf("  ACTIVATE_MICROCODE=%d SPT=%d GRD_CHK=%d APP_CHK=%d "
           "REF_CHK=%d\n", ((b[4] >> 6) & 0x3), ((b[4] >> 3) & 0x7),
           !!(b[4] & 0x4), !!(b[4] & 0x2), !!(b[4] & 0x1));
    printf("  UASK_SUP=%d GROUP_SUP=%d PRIOR_SUP=%d HEADSUP=%d ORDSUP=%d "
           "SIMPSUP=%d\n", !!(b[5] & 0x20), !!(b[5] & 0x10), !!(b[5] & 0x8),
           !!(b[5] & 0x4), !!(b[5] & 0x2), !!(b[5] & 0x1));
    printf("  WU_SUP=%d [CRD_SUP=%d] NV_SUP=%d V_SUP=%d\n",
           !!(b[6] & 0x8), !!(b[6] & 0x4), !!(b[6] & 0x2), !!(b[6] & 0x1));
    printf("  NO_PI_CHK=%d P_I_I_SUP=%d LUICLR=%d\n", !!(b[7] & 0x20),
           !!(b[7] & 0x10), !!(b[7] & 0x1));
    /* RTD_SUP added in spc5r11, LU_COLL_TYPE added in spc5r09,
     * HSSRELEF added in spc5r02; CBCS obsolete in spc5r01 */
    printf("  LU_COLL_TYPE=%d R_SUP=%d RTD_SUP=%d HSSRELEF=%d [CBCS=%d]\n",
           (b[8] >> 5) & 0x7, !!(b[8] & 0x10), !!(b[8] & 0x8),
           !!(b[8] & 0x2), !!(b[8] & 0x1));
    printf("  Multi I_T nexus microcode download=%d\n", b[9] & 0xf);
    printf("  Extended self-test completion minutes=%d\n",
           sg_get_unaligned_be16(b + 10));    /* spc4r27 */
    printf("  POA_SUP=%d HRA_SUP=%d VSA_SUP=%d DMS_VALID=%d\n",
           !!(b[12] & 0x80), !!(b[12] & 0x40), !!(b[12] & 0x20),
           !!(b[12] & 0x10));                   /* spc5r20 */
    printf("  Maximum supported sense data length=%d\n", b[13]); /* spc4r34 */
    printf("  IBS=%d IAS=%d SAC=%d NRD1=%d NRD0=%d\n", !!(b[14] & 0x80),
           !!(b[14] & 0x40), !!(b[14] & 0x4), !!(b[14] & 0x2),
           !!(b[14] & 0x1));  /* added in spc5r09 */
    printf("  Maximum inquiry change logs=%u\n",
           sg_get_unaligned_be16(b + 15));        /* spc5r17 */
    printf("  Maximum mode page change logs=%u\n",
           sg_get_unaligned_be16(b + 17));        /* spc5r17 */
    printf("  DM_MD_4=%d DM_MD_5=%d DM_MD_6=%d DM_MD_7=%d\n",
           !!(b[19] & 0x80), !!(b[19] & 0x40), !!(b[19] & 0x20),
           !!(b[19] & 0x10));                     /* spc5r20 */
    printf("  DM_MD_D=%d DM_MD_E=%d DM_MD_F=%d\n",
           !!(b[19] & 0x8), !!(b[19] & 0x4), !!(b[19] & 0x2));
}

/* VPD_SOFTW_INF_ID */
static void
decode_softw_inf_id(uint8_t * buff, int len, int do_hex)
{
    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    len -= 4;
    buff += 4;
    for ( ; len > 5; len -= 6, buff += 6) {
        printf("    IEEE Company_id: 0x%06x, vendor specific extension "
               "id: 0x%06x\n", sg_get_unaligned_be24(buff),
               sg_get_unaligned_be24(buff + 3));
    }
}

/* VPD_ATA_INFO */
static void
decode_ata_info_vpd(uint8_t * buff, int len, int do_long, int do_hex)
{
    char b[80];
    int num, is_be, cc;
    const char * cp;
    const char * ata_transp;

    if (len < 36) {
        pr2serr("ATA information VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex && (2 != do_hex)) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
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
    ata_transp = (0x34 == buff[36]) ? "SATA" : "PATA";
    if (do_long) {
        printf("  Device signature [%s] (in hex):\n", ata_transp);
        hex2stdout(buff + 36, 20, 0);
    } else
        printf("  Device signature indicates %s transport\n", ata_transp);
    cc = buff[56];      /* 0xec for IDENTIFY DEVICE and 0xa1 for IDENTIFY
                         * PACKET DEVICE (obsolete) */
    printf("  Command code: 0x%x\n", cc);
    if (len < 60)
        return;
    if (0xec == cc)
        cp = "";
    else if (0xa1 == cc)
        cp = "PACKET ";
    else
        cp = NULL;
    is_be = sg_is_big_endian();
    if (cp) {
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
               (unsigned int)cc);
    if (len < 572)
        return;
    if (2 == do_hex)
        hex2stdout((buff + 60), 512, 0);
    else if (do_long)
        dWordHex((const unsigned short *)(buff + 60), 256, 0, is_be);
}


/* VPD_POWER_CONDITION 0x8a */
static void
decode_power_condition(uint8_t * buff, int len, int do_hex)
{
    if (len < 18) {
        pr2serr("Power condition VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    printf("  Standby_y=%d Standby_z=%d Idle_c=%d Idle_b=%d Idle_a=%d\n",
           !!(buff[4] & 0x2), !!(buff[4] & 0x1),
           !!(buff[5] & 0x4), !!(buff[5] & 0x2), !!(buff[5] & 0x1));
    printf("  Stopped condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 6));
    printf("  Standby_z condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 8));
    printf("  Standby_y condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 10));
    printf("  Idle_a condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 12));
    printf("  Idle_b condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 14));
    printf("  Idle_c condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 16));
}

static const char * constituent_type_arr[] = {
    "Reserved",
    "Virtual tape library",
    "Virtual tape drive",
    "Direct access block device",
};

/* VPD_DEVICE_CONSTITUENTS 0x8b */
static void
decode_dev_constit_vpd(const uint8_t * buff, int len, struct opts_t * op)
{
    int k, j, res, bump, csd_len;
    uint16_t constit_type;
    const uint8_t * bp;
    const char * dcp = "Device constituents VPD page";
    char b[64];

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("%s length too short=%d\n", dcp, len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0, j = 0; k < len; k += bump, bp += bump, ++j) {
        if (j > 0)
            printf("\n");
        printf("  Constituent descriptor %d:\n", j + 1);
        if ((k + 36) > len) {
            pr2serr("%s, short descriptor length=36, left=%d\n", dcp,
                    (len - k));
            return;
        }
        constit_type = sg_get_unaligned_be16(bp + 0);
        if (constit_type >= SG_ARRAY_SIZE(constituent_type_arr))
            printf("    Constituent type: unknown [0x%x]\n", constit_type);
        else
            printf("    Constituent type: %s [0x%x]\n",
                   constituent_type_arr[constit_type], constit_type);
        printf("    Constituent device type: ");
        if (0xff == bp[2])
            printf("Unknown [0xff]\n");
        else if (bp[2] >= 0x20)
            printf("Reserved [0x%x]\n", bp[2]);
        else
            printf("%s [0x%x]\n", sg_get_pdt_str(0x1f & bp[2], sizeof(b), b),
                   bp[2]);
        printf("    Vendor_identification: %.8s\n", bp + 4);
        printf("    Product_identification: %.16s\n", bp + 12);
        printf("    Product_revision_level: %.4s\n", bp + 28);
        csd_len = sg_get_unaligned_be16(bp + 34);
        bump = 36 + csd_len;
        if ((k + bump) > len) {
            pr2serr("%s, short descriptor length=%d, left=%d\n", dcp, bump,
                    (len - k));
            return;
        }
        if (csd_len > 0) {
            int m, q, cs_bump;
            uint8_t cs_type;
            uint8_t cs_len;
            const uint8_t * cs_bp;

            printf("    Constituent specific descriptors:\n");
            for (m = 0, q = 0, cs_bp = bp + 36; m < csd_len;
                 m += cs_bump, ++q, cs_bp += cs_bump) {
                cs_type = cs_bp[0];
                cs_len = sg_get_unaligned_be16(cs_bp + 2);
                cs_bump = cs_len + 4;
                if (1 == cs_type) {     /* VPD page */
                    int off = cs_bp + 4 - buff;

                    printf("      Constituent VPD page %d:\n", q + 1);
                    /* SPC-5 says these shall _not_ themselves be Device
                     *  Constituent VPD pages. So no infinite recursion. */
                    res = svpd_decode_t10(-1, op, 0, off, NULL);
                    if (SG_LIB_CAT_OTHER == res) {
                        res = svpd_decode_vendor(-1, op, off);
                        if (SG_LIB_CAT_OTHER == res)
                            svpd_unable_to_decode(-1, op, 0, off);
                    }
                } else {
                    if (0xff == cs_type)
                        printf("      Vendor specific data (in hex):\n");
                    else
                        printf("      Reserved [0x%x] specific data (in "
                               "hex):\n", cs_type);
                    hex2stdout(cs_bp + 4, cs_len, 0 /* plus ASCII */);
                }
            }   /* end of Constituent specific descriptor loop */
        }
    }   /* end Constituent descriptor loop */
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
decode_power_consumption_vpd(uint8_t * buff, int len, int do_hex)
{
    int k, bump;
    uint8_t * bp;
    unsigned int value;
    const char * pcp = "Power consumption VPD page";

    if ((1 == do_hex) || (do_hex > 2)) {
        hex2stdout(buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("%s length too short=%d\n", pcp,len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            pr2serr("%s, short descriptor length=%d, left=%d\n", pcp, bump,
                    (len - k));
            return;
        }
        if (do_hex > 1)
            hex2stdout(bp, 4, 1);
        else {
            value = sg_get_unaligned_be16(bp + 2);
            printf("  Power consumption identifier: 0x%x", bp[0]);
            if (value >= 1000 && (bp[1] & 0x7) > 0)
                printf("    Maximum power consumption: %d.%03d %s\n",
                       value / 1000, value % 1000,
                       power_unit_arr[(bp[1] & 0x7) - 1]);
            else
                printf("    Maximum power consumption: %u %s\n",
                       value, power_unit_arr[bp[1] & 0x7]);
        }
    }
}

/* This is xcopy(LID4) related: "ROD" == Representation Of Data
 * Used by VPD_3PARTY_COPY */
static void
decode_rod_descriptor(const uint8_t * buff, int len)
{
    const uint8_t * bp = buff;
    int k, bump;
    uint64_t ul;

    for (k = 0; k < len; k += bump, bp += bump) {
        bump = sg_get_unaligned_be16(bp + 2) + 4;
        switch (bp[0]) {
            case 0:
                /* Block ROD device type specific descriptor */
                printf("  Optimal block ROD length granularity: %d\n",
                       sg_get_unaligned_be16(bp + 6));
                printf("  Maximum Bytes in block ROD: %" PRIu64 "\n",
                       sg_get_unaligned_be64(bp + 8));
                ul = sg_get_unaligned_be64(bp + 16);
                printf("  Optimal Bytes in block ROD transfer: ");
                if (SG_LIB_UNBOUNDED_64BIT == ul)
                    printf("-1 [no limit]\n");
                else
                    printf("%" PRIu64 "\n", ul);
                ul = sg_get_unaligned_be64(bp + 24);
                printf("  Optimal Bytes to token per segment: ");
                if (SG_LIB_UNBOUNDED_64BIT == ul)
                    printf("-1 [no limit]\n");
                else
                    printf("%" PRIu64 "\n", ul);
                ul = sg_get_unaligned_be64(bp + 32);
                printf("  Optimal Bytes from token per segment: ");
                if (SG_LIB_UNBOUNDED_64BIT == ul)
                    printf("-1 [no limit]\n");
                else
                    printf("%" PRIu64 "\n", ul);
                break;
            case 1:
                /* Stream ROD device type specific descriptor */
                printf("  Maximum Bytes in stream ROD: %" PRIu64 "\n",
                       sg_get_unaligned_be64(bp + 8));
                ul = sg_get_unaligned_be64(bp + 16);
                printf("  Optimal Bytes in stream ROD transfer: ");
                if (SG_LIB_UNBOUNDED_64BIT == ul)
                    printf("-1 [no limit]\n");
                else
                    printf("%" PRIu64 "\n", ul);
                break;
            case 3:
                /* Copy manager ROD device type specific descriptor */
                printf("  Maximum Bytes in processor ROD: %" PRIu64 "\n",
                       sg_get_unaligned_be64(bp + 8));
                ul = sg_get_unaligned_be64(bp + 16);
                printf("  Optimal Bytes in processor ROD transfer: ");
                if (SG_LIB_UNBOUNDED_64BIT == ul)
                    printf("-1 [no limit]\n");
                else
                    printf("%" PRIu64 "\n", ul);
                break;
            default:
                printf("  Unhandled descriptor (format %d, device type %d)\n",
                       bp[0] >> 5, bp[0] & 0x1F);
                break;
        }
    }
}

struct tpc_desc_type {
    uint8_t code;
    const char * name;
};

static struct tpc_desc_type tpc_desc_arr[] = {
    {0x0, "block -> stream"},
    {0x1, "stream -> block"},
    {0x2, "block -> block"},
    {0x3, "stream -> stream"},
    {0x4, "inline -> stream"},
    {0x5, "embedded -> stream"},
    {0x6, "stream -> discard"},
    {0x7, "verify CSCD"},
    {0x8, "block<o> -> stream"},
    {0x9, "stream -> block<o>"},
    {0xa, "block<o> -> block<o>"},
    {0xb, "block -> stream & application_client"},
    {0xc, "stream -> block & application_client"},
    {0xd, "block -> block & application_client"},
    {0xe, "stream -> stream&application_client"},
    {0xf, "stream -> discard&application_client"},
    {0x10, "filemark -> tape"},
    {0x11, "space -> tape"},            /* obsolete: spc5r02 */
    {0x12, "locate -> tape"},           /* obsolete: spc5r02 */
    {0x13, "<i>tape -> <i>tape"},
    {0x14, "register persistent reservation key"},
    {0x15, "third party persistent reservation source I_T nexus"},
    {0x16, "<i>block -> <i>block"},
    {0x17, "positioning -> tape"},      /* this and next added spc5r02 */
    {0x18, "<loi>tape -> <loi>tape"},   /* loi: logical object identifier */
    {0xbe, "ROD <- block range(n)"},
    {0xbf, "ROD <- block range(1)"},
    {0xe0, "CSCD: FC N_Port_Name"},
    {0xe1, "CSCD: FC N_Port_ID"},
    {0xe2, "CSCD: FC N_Port_ID with N_Port_Name, checking"},
    {0xe3, "CSCD: Parallel interface: I_T"},
    {0xe4, "CSCD: Identification Descriptor"},
    {0xe5, "CSCD: IPv4"},
    {0xe6, "CSCD: Alias"},
    {0xe7, "CSCD: RDMA"},
    {0xe8, "CSCD: IEEE 1394 EUI-64"},
    {0xe9, "CSCD: SAS SSP"},
    {0xea, "CSCD: IPv6"},
    {0xeb, "CSCD: IP copy service"},
    {0xfe, "CSCD: ROD"},
    {0xff, "CSCD: extension"},
    {0x0, NULL},
};

static const char *
get_tpc_desc_name(uint8_t code)
{
    const struct tpc_desc_type * dtp;

    for (dtp = tpc_desc_arr; dtp->name; ++dtp) {
        if (code == dtp->code)
            return dtp->name;
    }
    return "";
}

struct tpc_rod_type {
    uint32_t type;
    const char * name;
};

static struct tpc_rod_type tpc_rod_arr[] = {
    {0x0, "copy manager internal"},
    {0x10000, "access upon reference"},
    {0x800000, "point in time copy - default"},
    {0x800001, "point in time copy - change vulnerable"},
    {0x800002, "point in time copy - persistent"},
    {0x80ffff, "point in time copy - any"},
    {0xffff0001, "block device zero"},
    {0x0, NULL},
};

static const char *
get_tpc_rod_name(uint32_t rod_type)
{
    const struct tpc_rod_type * rtp;

    for (rtp = tpc_rod_arr; rtp->name; ++rtp) {
        if (rod_type == rtp->type)
            return rtp->name;
    }
    return "";
}

struct cscd_desc_id_t {
    uint16_t id;
    const char * name;
};

static struct cscd_desc_id_t cscd_desc_id_arr[] = {
    /* only values higher than 0x7ff are listed */
    {0xc000, "copy src or dst null LU, pdt=0"},
    {0xc001, "copy src or dst null LU, pdt=1"},
    {0xf800, "copy src or dst in ROD token"},
    {0xffff, "copy src or dst is copy manager LU"},
    {0x0, NULL},
};

static const char *
get_cscd_desc_id_name(uint16_t cscd_desc_id)
{
    const struct cscd_desc_id_t * cdip;

    for (cdip = cscd_desc_id_arr; cdip->name; ++cdip) {
        if (cscd_desc_id == cdip->id)
            return cdip->name;
    }
    return "";
}

/* VPD_3PARTY_COPY [3PC, third party copy] */
static void
decode_3party_copy_vpd(uint8_t * buff, int len, int do_hex, int pdt,
                       int verbose)
{
    int j, k, m, bump, desc_type, desc_len, sa_len, blen;
    unsigned int u;
    const uint8_t * bp;
    const char * cp;
    uint64_t ull;
    char b[120];

    if (len < 4) {
        pr2serr("Third-party Copy VPD page length too short=%d\n", len);
        return;
    }
    if (3 == do_hex) {
        hex2stdout(buff, len, -1);
        return;
    }
    blen = sizeof(b);
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        desc_type = sg_get_unaligned_be16(bp);
        desc_len = sg_get_unaligned_be16(bp + 2);
        if (verbose)
            printf("Descriptor type=%d [0x%x] , len %d\n", desc_type,
                   desc_type, desc_len);
        bump = 4 + desc_len;
        if ((k + bump) > len) {
            pr2serr("Third-party Copy VPD page, short descriptor length=%d, "
                    "left=%d\n", bump, (len - k));
            return;
        }
        if (0 == desc_len)
            continue;
        if (2 == do_hex)
            hex2stdout(bp + 4, desc_len, 1);
        else if (do_hex > 2)
            hex2stdout(bp, bump, 1);
        else {
            int csll;

            switch (desc_type) {
            case 0x0000:    /* Required if POPULATE TOKEN (or friend) used */
                printf(" Block Device ROD Token Limits:\n");
                u = sg_get_unaligned_be16(bp + 10);
                printf("  Maximum range descriptors: ");
                if (0 == u)
                    printf("0 [not reported]\n");
                else
                    printf("%u\n", u);
                u = sg_get_unaligned_be32(bp + 12);
                printf("  Maximum inactivity timeout: ");
                if (0 == u)
                    printf("0 [not reported]\n");
                else if (SG_LIB_UNBOUNDED_32BIT == u)
                    printf("-1 [no maximum given]\n");
                else
                    printf("%u seconds\n", u);
                u = sg_get_unaligned_be32(bp + 16);
                printf("  Default inactivity timeout: ");
                if (0 == u)
                    printf("0 [not reported]\n");
                else
                    printf("%u seconds\n", u);
                ull = sg_get_unaligned_be64(bp + 20);
                printf("  Maximum token transfer size: ");
                if (0 == ull)
                    printf("0 [not reported]\n");
                else
                    printf("%" PRIu64 "\n", ull);
                ull = sg_get_unaligned_be64(bp + 28);
                printf("  Optimal transfer count: ");
                if (0 == ull)
                    printf("0 [not reported]\n");
                else
                    printf("%" PRIu64 "\n", ull);
                break;
            case 0x0001:    /* Mandatory (SPC-4) */
                printf(" Supported commands:\n");
                j = 0;
                csll = bp[4];
                if (csll >= desc_len) {
                    pr2serr("Command supported list length (%d) >= "
                            "descriptor length (%d), wrong so trim\n",
                            csll, desc_len);
                    csll = desc_len - 1;
                }
                while (j < csll) {
                    sa_len = bp[6 + j];
                    for (m = 0; (m < sa_len) && ((j + m) < csll); ++m) {
                        sg_get_opcode_sa_name(bp[5 + j], bp[7 + j + m],
                                              pdt, blen, b);
                        printf("  %s\n", b);
                    }
                    if (0 == sa_len) {
                        sg_get_opcode_name(bp[5 + j], pdt, blen, b);
                        printf("  %s\n",  b);
                    } else if (m < sa_len)
                        pr2serr("Supported service actions list length (%d) "
                                "is too large\n", sa_len);
                    j += m + 2;
                }
                break;
            case 0x0004:
                printf(" Parameter data:\n");
                printf("  Maximum CSCD descriptor count: %d\n",
                       sg_get_unaligned_be16(bp + 8));
                printf("  Maximum segment descriptor count: %d\n",
                       sg_get_unaligned_be16(bp + 10));
                u = sg_get_unaligned_be32(bp + 12);
                printf("  Maximum descriptor list length: %u\n", u);
                u = sg_get_unaligned_be32(bp + 16);
                printf("  Maximum inline data length: %u\n", u);
                break;
            case 0x0008:
                printf(" Supported descriptors:\n");
                for (j = 0; j < bp[4]; j++) {
                    cp = get_tpc_desc_name(bp[5 + j]);
                    if (strlen(cp) > 0)
                        printf("  %s [0x%x]\n", cp, bp[5 + j]);
                    else
                        printf("  0x%x\n", bp[5 + j]);
                }
                break;
            case 0x000C:
                printf(" Supported CSCD IDs (above 0x7ff):\n");
                for (j = 0; j < sg_get_unaligned_be16(bp + 4); j += 2) {
                    u = sg_get_unaligned_be16(bp + 6 + j);
                    cp = get_cscd_desc_id_name(u);
                    if (strlen(cp) > 0)
                        printf("  %s [0x%04x]\n", cp, u);
                    else
                        printf("  0x%04x\n", u);
                }
                break;
            case 0x000D:
                printf(" Copy group identifier:\n");
                u = bp[4];
                sg_t10_uuid_desig2str(bp + 5, u, 1 /* c_set */, false,
                                      false, NULL, blen, b);
                printf("%s", b);
                break;
            case 0x0106:
                printf(" ROD token features:\n");
                printf("  Remote tokens: %d\n", bp[4] & 0x0f);
                u = sg_get_unaligned_be32(bp + 16);
                printf("  Minimum token lifetime: %u seconds\n", u);
                u = sg_get_unaligned_be32(bp + 20);
                printf("  Maximum token lifetime: %u seconds\n", u);
                u = sg_get_unaligned_be32(bp + 24);
                printf("  Maximum token inactivity timeout: %u\n", u);
                decode_rod_descriptor(bp + 48,
                                      sg_get_unaligned_be16(bp + 46));
                break;
            case 0x0108:
                printf(" Supported ROD token and ROD types:\n");
                for (j = 0; j < sg_get_unaligned_be16(bp + 6); j+= 64) {
                    u = sg_get_unaligned_be32(bp + 8 + j);
                    cp = get_tpc_rod_name(u);
                    if (strlen(cp) > 0)
                        printf("  ROD type: %s [0x%x]\n", cp, u);
                    else
                        printf("  ROD type: 0x%x\n", u);
                    printf("    Internal: %s\n",
                           (bp[8 + j + 4] & 0x80) ? "yes" : "no");
                    printf("    Token in: %s\n",
                           (bp[8 + j + 4] & 0x02) ? "yes" : "no");
                    printf("    Token out: %s\n",
                           (bp[8 + j + 4] & 0x01) ? "yes" : "no");
                    printf("    Preference: %d\n",
                           sg_get_unaligned_be16(bp + 8 + j + 6));
                }
                break;
            case 0x8001:    /* Mandatory (SPC-4) */
                printf(" General copy operations:\n");
                u = sg_get_unaligned_be32(bp + 4);
                printf("  Total concurrent copies: %u\n", u);
                u = sg_get_unaligned_be32(bp + 8);
                printf("  Maximum identified concurrent copies: %u\n", u);
                u = sg_get_unaligned_be32(bp + 12);
                printf("  Maximum segment length: %u\n", u);
                printf("  Data segment granularity: ");
                u = bp[16];     /* field is power of 2 */
                if (u < 64)
                    printf("%" PRIu64 "\n", (uint64_t)1 << u);
                else
                    printf("too large [2^%u]\n", u);
                printf("  Inline data granularity: ");
                u = bp[17];     /* field is power of 2 */
                if (u < 64)
                    printf("%" PRIu64 "\n", (uint64_t)1 << u);
                else
                    printf("too large [2^%u]\n", u);
                break;
            case 0x9101:
                printf(" Stream copy operations:\n");
                u = sg_get_unaligned_be32(bp + 4);
                printf("  Maximum stream device transfer size: %u\n", u);
                break;
            case 0xC001:
                printf(" Held data:\n");
                u = sg_get_unaligned_be32(bp + 4);
                printf("  Held data limit: %u\n", u);
                ull = (1 << bp[8]);
                printf("  Held data granularity: %" PRIu64 "\n", ull);
                break;
            default:
                pr2serr("Unexpected type=%d\n", desc_type);
                hex2stderr(bp, bump, 1);
                break;
            }
        }
    }
}

/* VPD_PROTO_LU */
static void
decode_proto_lu_vpd(uint8_t * buff, int len, int do_hex)
{
    int k, bump, rel_port, desc_len, proto;
    uint8_t * bp;

    if ((1 == do_hex) || (do_hex > 2)) {
        hex2stdout(buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Protocol-specific logical unit information VPD page length "
                "too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        rel_port = sg_get_unaligned_be16(bp);
        printf("  Relative port=%d\n", rel_port);
        proto = bp[2] & 0xf;
        desc_len = sg_get_unaligned_be16(bp + 6);
        bump = 8 + desc_len;
        if ((k + bump) > len) {
            pr2serr("Protocol-specific logical unit information VPD page, "
                    "short descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (0 == desc_len)
            continue;
        if (2 == do_hex) {
            hex2stdout(bp + 8, desc_len, 1);
            continue;
        }
        switch (proto) {
        case TPROTO_SAS:
            printf("    Protocol identifier: SAS\n");
            printf("    TLR control supported: %d\n", !!(bp[8] & 0x1));
            break;
        default:
            pr2serr("Unexpected proto=%d\n", proto);
            hex2stderr(bp, bump, 1);
            break;
        }
    }
}

/* VPD_PROTO_PORT */
static void
decode_proto_port_vpd(uint8_t * buff, int len, int do_hex)
{
    int k, j, bump, rel_port, desc_len, proto;
    uint8_t * bp;
    uint8_t * pidp;

    if ((1 == do_hex) || (do_hex > 2)) {
        hex2stdout(buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Protocol-specific port information VPD page length too "
                "short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        rel_port = sg_get_unaligned_be16(bp);
        printf("  Relative port=%d\n", rel_port);
        proto = bp[2] & 0xf;
        desc_len = sg_get_unaligned_be16(bp + 6);
        bump = 8 + desc_len;
        if ((k + bump) > len) {
            pr2serr("Protocol-specific port VPD page, short descriptor "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (0 == desc_len)
            continue;
        if (2 == do_hex) {
            hex2stdout(bp + 8, desc_len, 1);
            continue;
        }
        switch (proto) {
        case TPROTO_SAS:    /* page added in spl3r02 */
            printf("    power disable supported (pwr_d_s)=%d\n",
                   !!(bp[3] & 0x1));       /* added spl3r03 */
            pidp = bp + 8;
            for (j = 0; j < desc_len; j += 4, pidp += 4)
                printf("      phy id=%d, SSP persistent capable=%d\n",
                       pidp[1], (0x1 & pidp[2]));
            break;
        default:
            pr2serr("Unexpected proto=%d\n", proto);
            hex2stderr(bp, bump, 1);
            break;
        }
    }
}

/* VPD_SCSI_FEATURE_SETS [0x92] (sfs) */
static void
decode_feature_sets_vpd(uint8_t * buff, int len, const struct opts_t * op)
{
    int k, bump;
    uint16_t sf_code;
    bool found;
    uint8_t * bp;
    char b[64];

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("SCSI Feature sets VPD page length too short=%d\n", len);
        return;
    }
    len -= 8;
    bp = buff + 8;
    for (k = 0; k < len; k += bump, bp += bump) {
        sf_code = sg_get_unaligned_be16(bp);
        bump = 2;
        if ((k + bump) > len) {
            pr2serr("SCSI Feature sets, short descriptor length=%d, "
                    "left=%d\n", bump, (len - k));
            return;
        }
        if (2 == op->do_hex)
            hex2stdout(bp + 8, 2, 1);
        else if (op->do_hex > 2)
            hex2stdout(bp, 2, 1);
        else {
            printf("    %s", sg_get_sfs_str(sf_code, -2, sizeof(b), b,
                   &found, op->verbose));
            if (op->verbose == 1)
                printf(" [0x%x]\n", (unsigned int)sf_code);
            else if (op->verbose > 1)
                printf(" [0x%x] found=%s\n", (unsigned int)sf_code,
                       found ? "true" : "false");
            else
                printf("\n");
        }
    }
}


/* VPD_BLOCK_LIMITS sbc */
/* VPD_SA_DEV_CAP ssc */
/* VPD_OSD_INFO osd */
static void
decode_b0_vpd(uint8_t * buff, int len, int do_hex, int pdt)
{
    unsigned int u;
    uint64_t ull;
    bool ugavalid;

    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        if (len < 16) {
            pr2serr("Block limits VPD page length too short=%d\n", len);
            return;
        }
        printf("  Write same non-zero (WSNZ): %d\n", !!(buff[4] & 0x1));
        u = buff[5];
        printf("  Maximum compare and write length: ");
        if (0 == u)
            printf("0 blocks [Command not implemented]\n");
        else
            printf("%u blocks\n", buff[5]);
        u = sg_get_unaligned_be16(buff + 6);
        printf("  Optimal transfer length granularity: ");
        if (0 == u)
            printf("0 blocks [not reported]\n");
        else
            printf("%u blocks\n", u);
        u = sg_get_unaligned_be32(buff + 8);
        printf("  Maximum transfer length: ");
        if (0 == u)
            printf("0 blocks [not reported]\n");
        else
            printf("%u blocks\n", u);
        u = sg_get_unaligned_be32(buff + 12);
        printf("  Optimal transfer length: ");
        if (0 == u)
            printf("0 blocks [not reported]\n");
        else
            printf("%u blocks\n", u);
        if (len > 19) {     /* added in sbc3r09 */
            u = sg_get_unaligned_be32(buff + 16);
            printf("  Maximum prefetch transfer length: ");
            if (0 == u)
                printf("0 blocks [ignored]\n");
            else
                printf("%u blocks\n", u);
        }
        if (len > 27) {     /* added in sbc3r18 */
            u = sg_get_unaligned_be32(buff + 20);
            printf("  Maximum unmap LBA count: ");
            if (0 == u)
                printf("0 [Unmap command not implemented]\n");
            else if (SG_LIB_UNBOUNDED_32BIT == u)
                printf("-1 [unbounded]\n");
            else
                printf("%u\n", u);
            u = sg_get_unaligned_be32(buff + 24);
            printf("  Maximum unmap block descriptor count: ");
            if (0 == u)
                printf("0 [Unmap command not implemented]\n");
            else if (SG_LIB_UNBOUNDED_32BIT == u)
                printf("-1 [unbounded]\n");
            else
                printf("%u\n", u);
        }
        if (len > 35) {     /* added in sbc3r19 */
            u = sg_get_unaligned_be32(buff + 28);
            printf("  Optimal unmap granularity: ");
            if (0 == u)
                printf("0 blocks [not reported]\n");
            else
                printf("%u blocks\n", u);

            ugavalid = !!(buff[32] & 0x80);
            printf("  Unmap granularity alignment valid: %s\n",
                   ugavalid ? "true" : "false");
            u = 0x7fffffff & sg_get_unaligned_be32(buff + 32);
            printf("  Unmap granularity alignment: %u%s\n", u,
                   ugavalid ? "" : " [invalid]");
        }
        if (len > 43) {     /* added in sbc3r26 */
            ull = sg_get_unaligned_be64(buff + 36);
            printf("  Maximum write same length: ");
            if (0 == ull)
                printf("0 blocks [not reported]\n");
            else
                printf("0x%" PRIx64 " blocks\n", ull);
        }
        if (len > 44) {     /* added in sbc4r02 */
            u = sg_get_unaligned_be32(buff + 44);
            printf("  Maximum atomic transfer length: ");
            if (0 == u)
                printf("0 blocks [not reported]\n");
            else
                printf("%u blocks\n", u);
            u = sg_get_unaligned_be32(buff + 48);
            printf("  Atomic alignment: ");
            if (0 == u)
                printf("0 [unaligned atomic writes permitted]\n");
            else
                printf("%u\n", u);
            u = sg_get_unaligned_be32(buff + 52);
            printf("  Atomic transfer length granularity: ");
            if (0 == u)
                printf("0 [no granularity requirement\n");
            else
                printf("%u\n", u);
        }
        if (len > 56) {
            u = sg_get_unaligned_be32(buff + 56);
            printf("  Maximum atomic transfer length with atomic "
                   "boundary: ");
            if (0 == u)
                printf("0 blocks [not reported]\n");
            else
                printf("%u blocks\n", u);
            u = sg_get_unaligned_be32(buff + 60);
            printf("  Maximum atomic boundary size: ");
            if (0 == u)
                printf("0 blocks [can only write atomic 1 block]\n");
            else
                printf("%u blocks\n", u);
        }
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        printf("  WORM=%d\n", !!(buff[4] & 0x1));
        break;
    case PDT_OSD:
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        hex2stderr(buff, len, 0);
        break;
    }
}

static const char * product_type_arr[] =
{
    "Not specified",
    "CFast",
    "CompactFlash",
    "MemoryStick",
    "MultiMediaCard",
    "Secure Digital Card (SD)",
    "XQD",
    "Universal Flash Storage Card (UFS)",
};

/* VPD_BLOCK_DEV_CHARS sbc */
/* VPD_MAN_ASS_SN ssc */
/* VPD_SECURITY_TOKEN osd */
/* VPD_ES_DEV_CHARS ses-4 */
static void
decode_b1_vpd(uint8_t * buff, int len, int do_hex, int pdt)
{
    unsigned int u, k;

    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        if (len < 64) {
            pr2serr("Block device characteristics VPD page length too "
                    "short=%d\n", len);
            return;
        }
        u = sg_get_unaligned_be16(buff + 4);
        if (0 == u)
            printf("  Medium rotation rate is not reported\n");
        else if (1 == u)
            printf("  Non-rotating medium (e.g. solid state)\n");
        else if ((u < 0x401) || (0xffff == u))
            printf("  Reserved [0x%x]\n", u);
        else
            printf("  Nominal rotation rate: %u rpm\n", u);
        u = buff[6];
        k = SG_ARRAY_SIZE(product_type_arr);
        printf("  Product type: ");
        if (u < k)
            printf("%s\n", product_type_arr[u]);
        else if (u < 0xf0)
            printf("Reserved [0x%x]\n", u);
        else
            printf("Vendor specific [0x%x]\n", u);
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
        printf("  ZONED=%d\n", (buff[8] >> 4) & 0x3);   /* sbc4r04 */
        printf("  RBWZ=%d\n", !!(buff[8] & 0x8));       /* sbc4r12 */
        printf("  BOCS=%d\n", !!(buff[8] & 0x4));       /* sbc4r07 */
        printf("  FUAB=%d\n", !!(buff[8] & 0x2));
        printf("  VBULS=%d\n", !!(buff[8] & 0x1));
        printf("  DEPOPULATION_TIME=%u (seconds)\n",
               sg_get_unaligned_be32(buff + 12));       /* added sbc4r14 */
        break;
    case PDT_TAPE: case PDT_MCHANGER: case PDT_ADC:
        printf("  Manufacturer-assigned serial number: %.*s\n",
               len - 4, buff + 4);
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        hex2stderr(buff, len, 0);
        break;
    }
}

static const char * prov_type_arr[8] = {
    "not known or fully provisioned",
    "resource provisioned",
    "thin provisioned",
    "reserved [0x3]",
    "reserved [0x4]",
    "reserved [0x5]",
    "reserved [0x6]",
    "reserved [0x7]",
};

/* VPD_LB_PROVISIONING 0xb2 */
static int
decode_block_lb_prov_vpd(uint8_t * b, int len, const struct opts_t * op)
{
    int dp, pt;
    unsigned int u;

    if (len < 4) {
        pr2serr("Logical block provisioning page too short=%d\n", len);
        return SG_LIB_CAT_MALFORMED;
    }
    pt = b[6] & 0x7;
    printf("  Unmap command supported (LBPU): %d\n", !!(0x80 & b[5]));
    printf("  Write same (16) with unmap bit supported (LBPWS): %d\n",
           !!(0x40 & b[5]));
    printf("  Write same (10) with unmap bit supported (LBPWS10): %d\n",
           !!(0x20 & b[5]));
    printf("  Logical block provisioning read zeros (LBPRZ): %d\n",
           (0x7 & (b[5] >> 2)));  /* expanded from 1 to 3 bits in sbc4r07 */
    printf("  Anchored LBAs supported (ANC_SUP): %d\n", !!(0x2 & b[5]));
    dp = !!(b[5] & 0x1);
    u = b[4];
    printf("  Threshold exponent: ");
    if (0 == u)
        printf("0 [threshold sets not supported]\n");
    else
        printf("%u\n", u);
    printf("  Descriptor present (DP): %d\n", dp);
    printf("  Minimum percentage: ");
    u = 0x1f & (b[6] >> 3);
    if (0 == u)
        printf("0 [not reported]\n");
    else
        printf("%d\n", u);
    printf("  Provisioning type: %d (%s)\n", pt, prov_type_arr[pt]);
    printf("  Threshold percentage: ");
    if (0 == b[7])
        printf("0 [percentages not supported]\n");
    else
        printf("%u\n", b[7]);
    if (dp && (len > 11)) {
        int i_len;
        const uint8_t * bp;
        char bb[1024];

        bp = b + 8;
        i_len = bp[3];
        if (0 == i_len) {
            pr2serr("LB provisioning page provisioning group descriptor too "
                    "short=%d\n", i_len);
            return 0;
        }
        printf("  Provisioning group descriptor:\n");
        sg_get_designation_descriptor_str("    ", bp, i_len + 4, 0,
                                          op->do_long, sizeof(bb), bb);
        printf("%s", bb);
    }
    return 0;
}

/* VPD_SUP_BLOCK_LENS  0xb4 (added sbc4r01) */
static void
decode_sup_block_lens_vpd(uint8_t * buff, int len)
{
    int k;
    unsigned int u;
    uint8_t * bp;

    if (len < 4) {
        pr2serr("Supported block lengths and protection types VPD page "
                "length too short=%d\n", len);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += 8, bp += 8) {
        u = sg_get_unaligned_be32(bp);
        printf("  Logical block length: %u\n", u);
        printf("    P_I_I_SUP: %d\n", !!(bp[4] & 0x40));
        printf("    NO_PI_CHK: %d\n", !!(bp[4] & 0x8));  /* sbc4r05 */
        printf("    GRD_CHK: %d\n", !!(bp[4] & 0x4));
        printf("    APP_CHK: %d\n", !!(bp[4] & 0x2));
        printf("    REF_CHK: %d\n", !!(bp[4] & 0x1));
        printf("    T3PS: %d\n", !!(bp[5] & 0x8));
        printf("    T2PS: %d\n", !!(bp[5] & 0x4));
        printf("    T1PS: %d\n", !!(bp[5] & 0x2));
        printf("    T0PS: %d\n", !!(bp[5] & 0x1));
    }
}

/* VPD_BLOCK_DEV_C_EXTENS  0xb5 (added sbc4r02) */
static void
decode_block_dev_char_ext_vpd(uint8_t * b, int len)
{
    if (len < 16) {
        pr2serr("Block device characteristics extension VPD page "
                "length too short=%d\n", len);
        return;
    }
    printf("  Utilization type: ");
    switch (b[5]) {
    case 1:
        printf("Combined writes and reads");
        break;
    case 2:
        printf("Writes only");
        break;
    case 3:
        printf("Separate writes and reads");
        break;
    default:
        printf("Reserved");
        break;
    }
    printf(" [0x%x]\n", b[5]);
    printf("  Utilization units: ");
    switch (b[6]) {
    case 2:
        printf("megabytes");
        break;
    case 3:
        printf("gigabytes");
        break;
    case 4:
        printf("terabytes");
        break;
    case 5:
        printf("petabytes");
        break;
    case 6:
        printf("exabytes");
        break;
    default:
        printf("Reserved");
        break;
    }
    printf(" [0x%x]\n", b[6]);
    printf("  Utilization interval: ");
    switch (b[7]) {
    case 0xa:
        printf("per day");
        break;
    case 0xe:
        printf("per year");
        break;
    default:
        printf("Reserved");
        break;
    }
    printf(" [0x%x]\n", b[7]);
    printf("  Utilization B: %u\n", sg_get_unaligned_be32(b + 8));
    printf("  Utilization A: %u\n", sg_get_unaligned_be32(b + 12));
}

/* VPD_LB_PROTECTION 0xb5 (SSC)  [added in ssc5r02a] */
static void
decode_lb_protection_vpd(uint8_t * buff, int len, int do_hex)
{
    int k, bump;
    uint8_t * bp;

    if ((1 == do_hex) || (do_hex > 2)) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    if (len < 8) {
        pr2serr("Logical block protection VPD page length too short=%d\n",
                len);
        return;
    }
    len -= 8;
    bp = buff + 8;
    for (k = 0; k < len; k += bump, bp += bump) {
        bump = 1 + bp[0];
        printf("  method: %d, info_len: %d, LBP_W_C=%d, LBP_R_C=%d, "
               "RBDP_C=%d\n", bp[1], 0x3f & bp[2], !!(0x80 & bp[3]),
               !!(0x40 & bp[3]), !!(0x20 & bp[3]));
        if ((k + bump) > len) {
            pr2serr("Logical block protection VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
    }
}

/* VPD_TA_SUPPORTED 0xb2 */
static int
decode_tapealert_supported_vpd(uint8_t * b, int len)
{
    int k, mod, div;

    if (len < 12) {
        pr2serr("TapeAlert supported flags length too short=%d\n", len);
        return SG_LIB_CAT_MALFORMED;
    }
    for (k = 1; k < 0x41; ++k) {
        mod = ((k - 1) % 8);
        div = (k - 1) / 8;
        if (0 == mod) {
            if (div > 0)
                printf("\n");
            printf("  Flag%02Xh: %d", k, !! (b[4 + div] & 0x80));
        } else
            printf("  %02Xh: %d", k, !! (b[4 + div] & (1 << (7 - mod))));
    }
    printf("\n");
    return 0;
}

/* VPD_LB_PROVISIONING sbc */
/* VPD_TA_SUPPORTED ssc */
static void
decode_b2_vpd(uint8_t * buff, int len, int pdt, const struct opts_t * op)
{
    if (op->do_hex) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        decode_block_lb_prov_vpd(buff, len, op);
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        decode_tapealert_supported_vpd(buff, len);
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        hex2stderr(buff, len, 0);
        break;
    }
}

/* VPD_REFERRALS sbc */
/* VPD_AUTOMATION_DEV_SN ssc */
static void
decode_b3_vpd(uint8_t * b, int len, int do_hex, int pdt)
{
    char obuff[DEF_ALLOC_LEN];
    unsigned int u;

    if (do_hex) {
        hex2stdout(b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        if (len < 16) {
            pr2serr("Referrals VPD page length too short=%d\n", len);
            break;
        }
        u = sg_get_unaligned_be32(b + 8);
        printf("  User data segment size: ");
        if (0 == u)
            printf("0 [per sense descriptor]\n");
        else
            printf("%u\n", u);
        u = sg_get_unaligned_be32(b + 12);
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
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        hex2stderr(b, len, 0);
        break;
    }
}

/* VPD_SUP_BLOCK_LENS sbc */
/* VPD_DTDE_ADDRESS ssc */
static void
decode_b4_vpd(uint8_t * b, int len, int do_hex, int pdt)
{
    int k;

    if (do_hex) {
        hex2stdout(b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        decode_sup_block_lens_vpd(b, len);
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        printf("  Data transfer device element address: 0x");
        for (k = 4; k < len; ++k)
            printf("%02x", (unsigned int)b[k]);
        printf("\n");
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        hex2stderr(b, len, 0);
        break;
    }
}

/* VPD_BLOCK_DEV_C_EXTENS sbc */
static void
decode_b5_vpd(uint8_t * b, int len, int do_hex, int pdt)
{
    if (do_hex) {
        hex2stdout(b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        decode_block_dev_char_ext_vpd(b, len);
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        decode_lb_protection_vpd(b, len, do_hex);
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        hex2stderr(b, len, 0);
        break;
    }
}

/* VPD_ZBC_DEV_CHARS 0xb6  sbc or zbc [zbc2r04] */
static void
decode_zbdch_vpd(uint8_t * b, int len, int do_hex)
{
    uint32_t u;

    if (do_hex) {
        hex2stdout(b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    if (len < 64) {
        pr2serr("Zoned block device characteristics VPD page length too "
                "short=%d\n", len);
        return;
    }
    printf("  Zoned block device extension: ");
    switch ((b[4] >> 4) & 0xf) {
    case 0:
        printf("not reported\n");
        break;
    case 1:
        printf("host aware zone block device model\n");
        break;
    case 2:
        printf("Domains and realms zone block device model\n");
        break;
    default:
        printf("Unknown [0x%x]\n", (b[4] >> 4) & 0xf);
        break;
    }
    /* activation aligned on realm boundaries */
    printf("  AAORB: %d\n", !!(b[4] & 0x2));
    printf("  URSWRZ: %d\n", !!(b[4] & 0x1));
    u = sg_get_unaligned_be32(b + 8);
    printf("  Optimal number of open sequential write preferred zones: ");
    if (SG_LIB_UNBOUNDED_32BIT == u)
        printf("not reported\n");
    else
        printf("%" PRIu32 "\n", u);
    u = sg_get_unaligned_be32(b + 12);
    printf("  Optimal number of non-sequentially written sequential write "
           "preferred zones: ");
    if (SG_LIB_UNBOUNDED_32BIT == u)
        printf("not reported\n");
    else
        printf("%" PRIu32 "\n", u);
    u = sg_get_unaligned_be32(b + 16);
    printf("  Maximum number of open sequential write required zones: ");
    if (SG_LIB_UNBOUNDED_32BIT == u)
        printf("no limit\n");
    else
        printf("%" PRIu32 "\n", u);
}

/* VPD_BLOCK_LIMITS_EXT [0xb7] sbc */
static void
decode_b7_vpd(uint8_t * buff, int len, int do_hex, int pdt)
{
    unsigned int u;

    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        if (len < 12) {
            pr2serr("Block limits extension VPD page length too short=%d\n",
                    len);
            return;
        }
        u = sg_get_unaligned_be16(buff + 6);
        printf("  Maximum number of streams: ");
        if (0 == u)
            printf("0 [Stream control not supported]\n");
        else
            printf("%u\n", u);
        u = sg_get_unaligned_be16(buff + 8);
        printf("  Optimal stream write size: %u blocks\n", u);
        u = sg_get_unaligned_be32(buff + 10);
        printf("  Stream granularity size: %u\n", u);
        if (len > 27) {
            u = sg_get_unaligned_be32(buff + 16);
            printf("  Maximum scattered LBA range transfer length: ");
            if (0 == u)
                printf("0 blocks [not reported]\n");
            else
                printf("%u blocks\n", u);
            u = sg_get_unaligned_be16(buff + 22);
            printf("  Maximum scattered LBA range descriptor count: ");
            if (0 == u)
                printf("0 [not reported]\n");
            else
                printf("%u\n", u);
            u = sg_get_unaligned_be32(buff + 24);
            printf("  Maximum scattered transfer length: ");
            if (0 == u)
                printf("0 blocks [not reported]\n");
            else
                printf("%u blocks\n", u);
        }
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        hex2stderr(buff, len, 0);
        break;
    }
}

/* Returns 0 if successful */
static int
svpd_unable_to_decode(int sg_fd, struct opts_t * op, int subvalue, int off)
{
    int len, res;
    uint8_t * rp;

    rp = rsp_buff + off;
    if ((! op->do_hex) && (! op->do_raw) && (0 == op->examine))
        printf("Only hex output supported\n");
    if ((!op->do_raw) && (op->do_hex < 2) && (0 == op->examine)) {
        if (subvalue)
            printf("VPD page code=0x%.2x, subvalue=0x%.2x:\n", op->vpd_pn,
                   subvalue);
        else if (op->vpd_pn >= 0)
            printf("VPD page code=0x%.2x:\n", op->vpd_pn);
        else
            printf("VPD page code=%d:\n", op->vpd_pn);
    }

    res = vpd_fetch_page(sg_fd, rp, op->vpd_pn, op->maxlen, op->do_quiet,
                         op->verbose, &len);
    if (0 == res) {
        if (op->do_raw)
            dStrRaw(rp, len);
        else {
            if (op->do_hex > 1)
                hex2stdout(rp, len, -1);
            else if (VPD_ASCII_OP_DEF == op->vpd_pn)
                hex2stdout(rp, len, 0);
            else if (1 == op->do_hex)
                hex2stdout(rp, len, (op->do_long ? 0 : 1));
            else
                hex2stdout(rp, len, 0);
        }
    } else if ((! op->do_quiet) && (0 == op->examine)) {
        if (op->vpd_pn >= 0)
            pr2serr("fetching VPD page code=0x%.2x: failed\n", op->vpd_pn);
        else
            pr2serr("fetching VPD page code=%d: failed\n", op->vpd_pn);
    }
    return res;
}

/* Returns 0 if successful. If don't know how to decode, returns
 * SG_LIB_CAT_OTHER else see sg_ll_inquiry(). */
static int
svpd_decode_t10(int sg_fd, struct opts_t * op, int subvalue, int off,
                const char * prefix)
{
    bool allow_name, allow_if_found, long_notquiet, qt;
    bool vpd_supported = false;
    int len, pdt, num, k, resid, alloc_len, pn, vb;
    int res = 0;
    const struct svpd_values_name_t * vnp;
    uint8_t * rp;
    const char * np;
    const char * pre = (prefix ? prefix : "");;
    char obuff[DEF_ALLOC_LEN];
    char b[48];

    vb = op->verbose;
    qt = op->do_quiet;
    long_notquiet = op->do_long && (! op->do_quiet);
    if (op->do_raw || (op->do_quiet && (! op->do_long) && (! op->do_all)) ||
        (op->do_hex >= 3) || (op->examine > 0))
        allow_name = false;
    else
        allow_name = true;
    allow_if_found = (op->examine > 0) && (! op->do_quiet);
    rp = rsp_buff + off;
    pn = (-1 == sg_fd) ? rp[1] : op->vpd_pn;
    if (sg_fd != -1 && !op->do_force &&
        0 == op->examine &&
        pn != VPD_NOPE_WANT_STD_INQ &&
        pn != VPD_SUPPORTED_VPDS) {
        res = vpd_fetch_page(sg_fd, rp, VPD_SUPPORTED_VPDS, op->maxlen, qt,
                             vb, &len);
        if (res)
            return res;

        num = rp[3];
        if (num > (len - 4))
            num = (len - 4);
        if (vb > 1) {
            pr2serr("Supported VPD pages, hex list: ");
            hex2stderr(rp + 4, num, -1);
        }
        for (k = 0; k < num; ++k) {
            if (pn == rp[4 + k]) {
                vpd_supported = true;
                break;
            }
        }
        if (! vpd_supported) { /* get creative, was SG_LIB_CAT_ILLEGAL_REQ */
            if (vb)
                pr2serr("Given VPD page not in supported list, use --force "
                        "to override this check\n");
            return sg_convert_errno(EDOM);
        }
    }
    switch(pn) {
    case VPD_NOPE_WANT_STD_INQ:    /* -2 (want standard inquiry response) */
        if (sg_fd >= 0) {
            if (op->maxlen > 0)
                alloc_len = op->maxlen;
            else if (op->do_long)
                alloc_len = DEF_ALLOC_LEN;
            else
                alloc_len = 36;
            res = sg_ll_inquiry_v2(sg_fd, false, 0, rp, alloc_len,
                                   DEF_PT_TIMEOUT, &resid, ! op->do_quiet, vb);
        } else {
            alloc_len = op->maxlen;
            resid = 0;
            res = 0;
        }
        if (0 == res) {
            alloc_len -= resid;
            if (op->do_raw)
                dStrRaw(rp, alloc_len);
            else if (op->do_hex) {
                if (! op->do_quiet && (op->do_hex < 3))
                    printf("Standard Inquiry response:\n");
                hex2stdout(rp, alloc_len, (1 == op->do_hex) ? 0 : -1);
            } else
                std_inq_decode(rp, alloc_len, vb);
            return 0;
        }
        break;
    case VPD_SUPPORTED_VPDS:    /* 0x0 */
        np = "Supported VPD pages VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else if (op->do_hex)
                hex2stdout(rp, len, (1 == op->do_hex) ? 0 : -1);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                num = rp[3];
                if (num > (len - 4))
                    num = (len - 4);
                for (k = 0; k < num; ++k) {
                    pn = rp[4 + k];
                    vnp = sdp_get_vpd_detail(pn, -1, pdt);
                    if (vnp) {
                        if (op->do_long)
                            printf("  0x%02x  %s [%s]\n", pn, vnp->name,
                                   vnp->acron);
                        else
                            printf("  %s [%s]\n", vnp->name, vnp->acron);
                    } else if (op->vend_prod_num >= 0) {
                        vnp = svpd_find_vendor_by_num(pn, op->vend_prod_num);
                        if (vnp) {
                            if (op->do_long)
                                printf("  0x%02x  %s [%s]\n", pn, vnp->name,
                                       vnp->acron);
                            else
                                printf("  %s [%s]\n", vnp->name, vnp->acron);
                        } else
                            printf("  0x%x\n", pn);
                    } else
                        printf("  0x%x\n", pn);
                }
            }
            return 0;
        }
        break;
    case VPD_UNIT_SERIAL_NUM:   /* 0x80 */
        np = "Unit serial number VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else if (op->do_hex)
                hex2stdout(rp, len, (1 == op->do_hex) ? 0 : -1);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                memset(obuff, 0, sizeof(obuff));
                len -= 4;
                if (len >= (int)sizeof(obuff))
                    len = sizeof(obuff) - 1;
                memcpy(obuff, rp + 4, len);
                printf("  Unit serial number: %s\n", obuff);
            }
            return 0;
        }
        break;
    case VPD_DEVICE_ID:         /* 0x83 */
        np = "Device Identification VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else if (op->do_hex)
                hex2stdout(rp, len, (1 == op->do_hex) ? 0 : -1);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_id_vpd(rp, len, subvalue, op);
            }
            return 0;
        }
        break;
    case VPD_SOFTW_INF_ID:      /* 0x84 */
        np = "Software interface identification VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_softw_inf_id(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_MAN_NET_ADDR:      /* 0x85 */
        np= "Management network addresses VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else
                decode_net_man_vpd(rp, len, op->do_hex);
            return 0;
        }
        break;
    case VPD_EXT_INQ:           /* 0x86 */
        np = "extended INQUIRY data VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                bool protect = false;
                struct sg_simple_inquiry_resp sir;

                if ((sg_fd >= 0) && long_notquiet) {
                    res = sg_simple_inquiry(sg_fd, &sir, false, vb);
                    if (res) {
                        if (op->verbose)
                            pr2serr("%s: sg_simple_inquiry() failed, "
                                    "res=%d\n", __func__, res);
                    } else
                        protect = !!(sir.byte_5 & 0x1); /* SPC-3 and later */
                }
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_x_inq_vpd(rp, len, op->do_hex, long_notquiet, protect);
            }
            return 0;
        }
        break;
    case VPD_MODE_PG_POLICY:    /* 0x87 */
        np = "Mode page policy VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", (prefix ? prefix : ""), np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_mode_policy_vpd(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_SCSI_PORTS:        /* 0x88 */
        np = "SCSI Ports VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_scsi_ports_vpd(rp, len, op);
            }
            return 0;
        }
        break;
    case VPD_ATA_INFO:          /* 0x89 */
        np = "ATA information VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        alloc_len = op->maxlen ? op->maxlen : VPD_ATA_INFO_LEN;
        res = vpd_fetch_page(sg_fd, rp, pn, alloc_len, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", (prefix ? prefix : ""), np);
            if ((2 == op->do_raw) || (3 == op->do_hex)) {  /* for hdparm */
                if (len < (60 + 512))
                    pr2serr("ATA_INFO VPD page len (%d) less than expected "
                            "572\n", len);
                else
                    dWordHex((const unsigned short *)(rp + 60), 256, -2,
                             sg_is_big_endian());
            }
            else if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_ata_info_vpd(rp, len, long_notquiet, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_POWER_CONDITION:          /* 0x8a */
        np = "Power condition VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_power_condition(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_DEVICE_CONSTITUENTS:      /* 0x8b */
        np = "Device constituents VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else
                decode_dev_constit_vpd(rp, len, op);
            return 0;
        }
        break;
    case VPD_POWER_CONSUMPTION:    /* 0x8d */
        np = "Power consumption VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_power_consumption_vpd(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_3PARTY_COPY:   /* 0x8f */
        np = "Third party copy VPD page:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else if (1 == op->do_hex)
                hex2stdout(rp, len, 0);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_3party_copy_vpd(rp, len, op->do_hex, pdt, vb);
            }
            return 0;
        }
        break;
    case VPD_PROTO_LU:          /* 0x90 */
        np = "Protocol-specific logical unit information:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_proto_lu_vpd(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_PROTO_PORT:        /* 0x91 */
        np = "Protocol-specific port information:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_proto_port_vpd(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_SCSI_FEATURE_SETS:         /* 0x92 */
        np = "SCSI Feature sets:";
        if (allow_name)
            printf("%s%s\n", pre, np);
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            if (! allow_name && allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_feature_sets_vpd(rp, len, op);
            }
            return 0;
        }
        break;
    case 0xb0:  /* depends on pdt */
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            switch (pdt) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                np = "Block limits VPD page (SBC):";
                break;
            case PDT_TAPE: case PDT_MCHANGER:
                np = "Sequential-access device capabilities VPD page (SSC):";
                break;
            case PDT_OSD:
                np = "OSD information VPD page (OSD):";
                break;
            default:
                np = NULL;
                break;
            }
            if (NULL == np)
                printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
            else if (allow_name || allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b0_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3) &&
                   (0 == op->examine))
            printf("%sVPD page=0xb0\n", pre);
        break;
    case 0xb1:  /* depends on pdt */
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            switch (pdt) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                np = "Block device characteristics VPD page (SBC):";
                break;
            case PDT_TAPE: case PDT_MCHANGER:
                np = "Manufactured-assigned serial number VPD page (SSC):";
                break;
            case PDT_OSD:
                np = "Security token VPD page (OSD):";
                break;
            case PDT_ADC:
                np = "Manufactured-assigned serial number VPD page (ADC):";
                break;
            default:
                np = NULL;
                break;
            }
            if (NULL == np)
                printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
            else if (allow_name || allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b1_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3) &&
                   (0 == op->examine))
            printf("%sVPD page=0xb1\n", pre);
        break;
    case 0xb2:          /* VPD page depends on pdt */
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            switch (pdt) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                np = "Logical block provisioning VPD page (SBC):";
                break;
            case PDT_TAPE: case PDT_MCHANGER:
                np = "TapeAlert supported flags VPD page (SSC):";
                break;
            default:
                np = NULL;
                break;
            }
            if (NULL == np)
                printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
            else if (allow_name || allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b2_vpd(rp, len, pdt, op);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3) &&
                   (0 == op->examine))
            printf("%sVPD page=0xb2\n", pre);
        break;
    case 0xb3:          /* VPD page depends on pdt */
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            switch (pdt) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                np = "Referrals VPD page (SBC):";
                break;
            case PDT_TAPE: case PDT_MCHANGER:
                np = "Automation device serial number VPD page SSC):";
                break;
            default:
                np = NULL;
                break;
            }
            if (NULL == np)
                printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
            else if (allow_name || allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b3_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3) &&
                   (0 == op->examine))
            printf("%sVPD page=0xb3\n", pre);
        break;
    case 0xb4:          /* VPD page depends on pdt */
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            switch (pdt) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                np = "Supported block lengths and protection types VPD page "
                     "(SBC):";
                break;
            case PDT_TAPE: case PDT_MCHANGER:
                np = "Data transfer device element address (SSC):";
                break;
            default:
                np = NULL;
                break;
            }
            if (NULL == np)
                printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
            else if (allow_name || allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b4_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3) &&
                   (0 == op->examine))
            printf("%sVPD page=0xb4\n", pre);
        break;
    case 0xb5:          /* VPD page depends on pdt */
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            switch (pdt) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                np = "Block device characteristics extension VPD page (SBC):";
                break;
            case PDT_TAPE: case PDT_MCHANGER:
                np = "Logical block protection VPD page (SSC):";
                break;
            default:
                np = NULL;
                break;
            }
            if (NULL == np)
                printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
            else if (allow_name || allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b5_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3) &&
                   (0 == op->examine))
            printf("%sVPD page=0xb4\n", pre);
        break;
    case VPD_ZBC_DEV_CHARS:       /* 0xb6 for both pdt=0 and pdt=0x14 */
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            switch (pdt) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                np = "Zoned block device characteristics VPD page (SBC, "
                     "ZBC):";
                break;
            default:
                np = NULL;
                break;
            }
            if (NULL == np)
                printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
            else if (allow_name || allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_zbdch_vpd(rp, len, op->do_hex);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3) &&
                   (0 == op->examine))
            printf("%sVPD page=0xb5\n", pre);
        break;
    case 0xb7:
        res = vpd_fetch_page(sg_fd, rp, pn, op->maxlen, qt, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            switch (pdt) {
            case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                np = "Block limits extension VPD page (SBC):";
                break;
            default:
                np = NULL;
                break;
            }
            if (NULL == np)
                printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
            else if (allow_name || allow_if_found)
                printf("%s%s\n", pre, np);
            if (op->do_raw)
                dStrRaw(rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b7_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3) &&
                   (0 == op->examine))
            printf("%sVPD page=0xb7\n", pre);
        break;
    default:
        return SG_LIB_CAT_OTHER;
    }
    return res;
}

static int
svpd_decode_all(int sg_fd, struct opts_t * op)
{
    int k, res, rlen, n, pn;
    int max_pn = 255;
    int any_err = 0;
    uint8_t vpd0_buff[512];
    uint8_t * rp = vpd0_buff;

    if (op->vpd_pn > 0)
        max_pn = op->vpd_pn;
    if (sg_fd >= 0) {   /* have valid open file descriptor (handle) */
        res = vpd_fetch_page(sg_fd, rp, VPD_SUPPORTED_VPDS, op->maxlen,
                             op->do_quiet, op->verbose, &rlen);
        if (res) {
            if (! op->do_quiet) {
                if (SG_LIB_CAT_ABORTED_COMMAND == res)
                    pr2serr("%s: VPD page 0, aborted command\n", __func__);
                else if (res) {
                    char b[80];

                    sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
                    pr2serr("%s: fetching VPD page 0 failed: %s\n", __func__,
                            b);
                }
            }
            return res;
        }
        n = sg_get_unaligned_be16(rp + 2);
        if (n > (rlen - 4)) {
            if (op->verbose)
                pr2serr("%s: rlen=%d > page0 size=%d\n", __func__, rlen,
                        n + 4);
            n = (rlen - 4);
        }
        for (k = 0; k < n; ++k) {
            pn = rp[4 + k];
            if (pn > max_pn)
                continue;
            op->vpd_pn = pn;
            if (k > 0)
                printf("\n");
            if (op->do_long)
                printf("[0x%x] ", pn);

            res = svpd_decode_t10(sg_fd, op, 0, 0, NULL);
            if (SG_LIB_CAT_OTHER == res) {
                res = svpd_decode_vendor(sg_fd, op, 0);
                if (SG_LIB_CAT_OTHER == res)
                    res = svpd_unable_to_decode(sg_fd, op, 0, 0);
            }
            if (! op->do_quiet) {
                if (SG_LIB_CAT_ABORTED_COMMAND == res)
                    pr2serr("fetching VPD page failed, aborted command\n");
                else if (res) {
                    char b[80];

                    sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
                    pr2serr("fetching VPD page failed: %s\n", b);
                }
            }
            if (res)
                any_err = res;
        }
        res = any_err;
    } else {    /* input is coming from --inhex=FN */
        int bump, off;
        int in_len = op->maxlen;
        int prev_pn = -1;

        res = 0;
        for (k = 0, off = 0; off < in_len; ++k, off += bump) {
            rp = rsp_buff + off;
            pn = rp[1];
            bump = sg_get_unaligned_be16(rp + 2) + 4;
            if ((off + bump) > in_len) {
                pr2serr("%s: page 0x%x size (%d) exceeds buffer\n", __func__,
                        pn, bump);
                bump = in_len - off;
            }
            if (pn <= prev_pn) {
                pr2serr("%s: prev_pn=0x%x, this pn=0x%x, not ascending so "
                        "exit\n", __func__, prev_pn, pn);
                break;
            }
            prev_pn = pn;
            op->vpd_pn = pn;
            if (pn > max_pn) {
                if (op->verbose > 2)
                    pr2serr("%s: skipping as this pn=0x%x exceeds "
                            "max_pn=0x%x\n", __func__, pn, max_pn);
                continue;
            }
            if (op->do_long)
                printf("[0x%x] ", pn);

            res = svpd_decode_t10(-1, op, 0, off, NULL);
            if (SG_LIB_CAT_OTHER == res) {
                res = svpd_decode_vendor(-1, op, off);
                if (SG_LIB_CAT_OTHER == res)
                    res = svpd_unable_to_decode(-1, op, 0, off);
            }
        }
    }
    return res;
}

static int
svpd_examine_all(int sg_fd, struct opts_t * op)
{
    bool first = true;
    bool got_one = false;
    int k, res;
    int max_pn = 255;
    int any_err = 0;
    char b[64];

    if (op->vpd_pn > 0)
        max_pn = op->vpd_pn;
    for (k = op->examine > 1 ? 0 : 0x80; k <= max_pn; ++k) {
        op->vpd_pn = k;
        if (first)
            first = false;
        else if (got_one) {
            printf("\n");
            got_one = false;
        }
        if (op->do_long)
            snprintf(b, sizeof(b), "[0x%x] ", k);

        res = svpd_decode_t10(sg_fd, op, 0, 0, b);
        if (SG_LIB_CAT_OTHER == res) {
            res = svpd_decode_vendor(sg_fd, op, 0);
            if (SG_LIB_CAT_OTHER == res)
                res = svpd_unable_to_decode(sg_fd, op, 0, 0);
        }
        if (! op->do_quiet) {
            if (SG_LIB_CAT_ABORTED_COMMAND == res)
                pr2serr("fetching VPD page failed, aborted command\n");
            else if (res && (SG_LIB_CAT_ILLEGAL_REQ != res)) {
                char b[80];

                /* SG_LIB_CAT_ILLEGAL_REQ expected as well examine all */
                sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
                pr2serr("fetching VPD page failed: %s\n", b);
            }
        }
        if (res && (SG_LIB_CAT_ILLEGAL_REQ != res))
            any_err = res;
        if (0 == res)
            got_one = true;
    }
    return any_err;
}


int
main(int argc, char * argv[])
{
    int c, res, matches;
    int sg_fd = -1;
    int inhex_len = 0;
    int ret = 0;
    int subvalue = 0;
    const char * cp;
    struct opts_t * op;
    const struct svpd_values_name_t * vnp;
    struct opts_t opts;

    op = &opts;
    memset(&opts, 0, sizeof(opts));
    dup_sanity_chk((int)sizeof(opts), (int)sizeof(*vnp));
    op->vend_prod_num = -1;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aeEfhHiI:lm:M:p:qrvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            op->do_all = true;
            break;
        case 'e':
            op->do_enum = true;
            break;
        case 'E':
            ++op->examine;
            break;
        case 'f':
            op->do_force = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            ++op->do_ident;
            break;
        case 'I':
            if (op->inhex_fn) {
                pr2serr("only one '--inhex=' option permitted\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            } else
                op->inhex_fn = optarg;
            break;
        case 'l':
            op->do_long = true;
            break;
        case 'm':
            op->maxlen = sg_get_num(optarg);
            if ((op->maxlen < 0) || (op->maxlen > MX_ALLOC_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MX_ALLOC_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'M':
            if (op->vend_prod) {
                pr2serr("only one '--vendor=' option permitted\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            } else
                op->vend_prod = optarg;
            break;
        case 'p':
            if (op->page_str) {
                pr2serr("only one '--page=' option permitted\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            } else
                op->page_str = optarg;
            break;
        case 'q':
            op->do_quiet = true;
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
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
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
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
        return 0;
    }

    if (op->do_enum) {
        if (op->device_name)
            pr2serr("Device name %s ignored when --enumerate given\n",
                    op->device_name);
        if (op->vend_prod) {
            if (isdigit(op->vend_prod[0])) {
                op->vend_prod_num = sg_get_num_nomult(op->vend_prod);
                if ((op->vend_prod_num < 0) || (op->vend_prod_num > 10)) {
                    pr2serr("Bad vendor/product number after '--vendor=' "
                            "option\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                op->vend_prod_num = svpd_find_vp_num_by_acron(op->vend_prod);
                if (op->vend_prod_num < 0) {
                    pr2serr("Bad vendor/product acronym after '--vendor=' "
                            "option\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            svpd_enumerate_vendor(op->vend_prod_num);
            return 0;
        }
        if (op->page_str) {
            if ((0 == strcmp("-1", op->page_str)) ||
                (0 == strcmp("-2", op->page_str)))
                op->vpd_pn = VPD_NOPE_WANT_STD_INQ;
            else if (isdigit(op->page_str[0])) {
                op->vpd_pn = sg_get_num_nomult(op->page_str);
                if ((op->vpd_pn < 0) || (op->vpd_pn > 255)) {
                    pr2serr("Bad page code value after '-p' option\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                pr2serr("with --enumerate only search using VPD page "
                        "numbers\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            matches = count_standard_vpds(op->vpd_pn);
            if (0 == matches)
                matches = svpd_count_vendor_vpds(op->vpd_pn,
                                                 op->vend_prod_num);
            if (0 == matches)
                printf("No matches found for VPD page number 0x%x\n",
                       op->vpd_pn);
        } else {        /* enumerate standard then vendor VPD pages */
            printf("Standard VPD pages:\n");
            enumerate_vpds(1, 1);
        }
        return 0;
    }
    if (op->page_str) {
        if ((0 == strcmp("-1", op->page_str)) ||
            (0 == strcmp("-2", op->page_str)))
            op->vpd_pn = VPD_NOPE_WANT_STD_INQ;
        else if (isalpha(op->page_str[0])) {
            vnp = sdp_find_vpd_by_acron(op->page_str);
            if (NULL == vnp) {
                vnp = svpd_find_vendor_by_acron(op->page_str);
                if (NULL == vnp) {
                    pr2serr("abbreviation doesn't match a VPD page\n");
                    printf("Available standard VPD pages:\n");
                    enumerate_vpds(1, 1);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            op->vpd_pn = vnp->value;
            subvalue = vnp->subvalue;
            op->vend_prod_num = subvalue;
        } else {
            cp = strchr(op->page_str, ',');
            if (cp && op->vend_prod) {
                pr2serr("the --page=pg,vp and the --vendor=vp forms overlap, "
                        "choose one or the other\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->vpd_pn = sg_get_num_nomult(op->page_str);
            if ((op->vpd_pn < 0) || (op->vpd_pn > 255)) {
                pr2serr("Bad page code value after '-p' option\n");
                printf("Available standard VPD pages:\n");
                enumerate_vpds(1, 1);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (cp) {
                if (isdigit(*(cp + 1)))
                    op->vend_prod_num = sg_get_num_nomult(cp + 1);
                else
                    op->vend_prod_num = svpd_find_vp_num_by_acron(cp + 1);
                if ((op->vend_prod_num < 0) || (op->vend_prod_num > 255)) {
                    pr2serr("Bad vendor/product acronym after comma in '-p' "
                            "option\n");
                    if (op->vend_prod_num < 0)
                        svpd_enumerate_vendor(-1);
                    return SG_LIB_SYNTAX_ERROR;
                }
                subvalue = op->vend_prod_num;
            } else if (op->vend_prod) {
                if (isdigit(op->vend_prod[0]))
                    op->vend_prod_num = sg_get_num_nomult(op->vend_prod);
                else
                    op->vend_prod_num =
                        svpd_find_vp_num_by_acron(op->vend_prod);
                if ((op->vend_prod_num < 0) || (op->vend_prod_num > 255)) {
                    pr2serr("Bad vendor/product acronym after '--vendor=' "
                            "option\n");
                    svpd_enumerate_vendor(-1);
                    return SG_LIB_SYNTAX_ERROR;
                }
                subvalue = op->vend_prod_num;
            }
        }
    } else if (op->vend_prod) {
        if (isdigit(op->vend_prod[0]))
            op->vend_prod_num = sg_get_num_nomult(op->vend_prod);
        else
            op->vend_prod_num = svpd_find_vp_num_by_acron(op->vend_prod);
        if ((op->vend_prod_num < 0) || (op->vend_prod_num > 255)) {
            pr2serr("Bad vendor/product acronym after '--vendor=' "
                    "option\n");
            svpd_enumerate_vendor(-1);
            return SG_LIB_SYNTAX_ERROR;
        }
        subvalue = op->vend_prod_num;
    }

    rsp_buff = sg_memalign(rsp_buff_sz, 0 /* page align */, &free_rsp_buff,
                           false);
    if (NULL == rsp_buff) {
        pr2serr("Unable to allocate %d bytes on heap\n", rsp_buff_sz);
        return sg_convert_errno(ENOMEM);
    }
    if (op->inhex_fn) {
        if (op->device_name) {
            pr2serr("Cannot have both a DEVICE and --inhex= option\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        if ((ret = sg_f2hex_arr(op->inhex_fn, !!op->do_raw, false, rsp_buff,
                                &inhex_len, rsp_buff_sz))) {
            goto err_out;
        }
        if (op->verbose > 2)
            pr2serr("Read %d [0x%x] bytes of user supplied data\n", inhex_len,
                    inhex_len);
        if (op->verbose > 3)
            hex2stderr(rsp_buff, inhex_len, 0);
        op->do_raw = 0;         /* don't want raw on output with --inhex= */
        if ((NULL == op->page_str) && (! op->do_all)) {
            /* may be able to deduce VPD page */
            if ((0x2 == (0xf & rsp_buff[3])) && (rsp_buff[2] > 2)) {
                if (op->verbose)
                    pr2serr("Guessing from --inhex= this is a standard "
                            "INQUIRY\n");
            } else if (rsp_buff[2] <= 2) {
                if (op->verbose)
                    pr2serr("Guessing from --inhex this is VPD page 0x%x\n",
                            rsp_buff[1]);
                op->vpd_pn = rsp_buff[1];
            } else {
                if (op->vpd_pn > 0x80) {
                    op->vpd_pn = rsp_buff[1];
                    if (op->verbose)
                        pr2serr("Guessing from --inhex this is VPD page "
                                "0x%x\n", rsp_buff[1]);
                } else {
                    op->vpd_pn = VPD_NOPE_WANT_STD_INQ;
                    if (op->verbose)
                        pr2serr("page number unclear from --inhex, hope "
                                "it's a standard INQUIRY response\n");
                }
            }
        }
    } else if (NULL == op->device_name) {
        pr2serr("No DEVICE argument given\n\n");
        usage();
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }

    if (op->do_raw && op->do_hex) {
        pr2serr("Can't do hex and raw at the same time\n");
        usage();
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }
    if (op->do_ident) {
        op->vpd_pn = VPD_DEVICE_ID;
        if (op->do_ident > 1) {
            if (! op->do_long)
                op->do_quiet = true;
            subvalue = VPD_DI_SEL_LU;
        }
    }
    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
    }

    if (op->inhex_fn) {
        if ((0 == op->maxlen) || (inhex_len < op->maxlen))
            op->maxlen = inhex_len;
        if (op->do_all)
            res = svpd_decode_all(-1, op);
        else {
            res = svpd_decode_t10(-1, op, subvalue, 0, NULL);
            if (SG_LIB_CAT_OTHER == res) {
                res = svpd_decode_vendor(-1, op, 0);
                if (SG_LIB_CAT_OTHER == res)
                    res = svpd_unable_to_decode(-1, op, subvalue, 0);
            }
        }
        ret = res;
        goto err_out;
    }

    if ((sg_fd = sg_cmds_open_device(op->device_name, true /* ro */,
                                     op->verbose)) < 0) {
        if (op->verbose > 0)
            pr2serr("error opening file: %s: %s\n", op->device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        if (ret < 0)
            ret = SG_LIB_FILE_ERROR;
        goto err_out;
    }

    if (op->examine > 0) {
        ret = svpd_examine_all(sg_fd, op);
    } else if (op->do_all)
        ret = svpd_decode_all(sg_fd, op);
    else {
        memset(rsp_buff, 0, rsp_buff_sz);

        res = svpd_decode_t10(sg_fd, op, subvalue, 0, NULL);
        if (SG_LIB_CAT_OTHER == res) {
            res = svpd_decode_vendor(sg_fd, op, 0);
            if (SG_LIB_CAT_OTHER == res)
                res = svpd_unable_to_decode(sg_fd, op, subvalue, 0);
        }
        if (! op->do_quiet) {
            if (SG_LIB_CAT_ABORTED_COMMAND == res)
                pr2serr("fetching VPD page failed, aborted command\n");
            else if (res) {
                char b[80];

                sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
                pr2serr("fetching VPD page failed: %s\n", b);
            }
        }
        ret = res;
    }
err_out:
    if (free_rsp_buff)
        free(free_rsp_buff);
    if ((0 == op->verbose) && (! op->do_quiet)) {
        if (! sg_if_can2stderr("sg_vpd failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    res = (sg_fd >= 0) ? sg_cmds_close_device(sg_fd) : 0;

    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return sg_convert_errno(-res);
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
