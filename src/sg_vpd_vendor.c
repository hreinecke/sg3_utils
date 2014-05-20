/*
 * Copyright (c) 2006-2014 Douglas Gilbert.
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
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifndef SG_LIB_MINGW
#include <time.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"

/* This is a companion file to sg_vpd.c . It contains logic to output and
   decode vendor specific VPD pages

   This program fetches Vital Product Data (VPD) pages from the given
   device and outputs it as directed. VPD pages are obtained via a
   SCSI INQUIRY command. Most of the data in this program is obtained
   from the SCSI SPC-4 document at http://www.t10.org .

   Acknowledgments:
      - Lars Marowsky-Bree <lmb at suse dot de> contributed Unit Path Report
        VPD page decoding for EMC CLARiiON devices [20041016]
      - Hannes Reinecke <hare at suse dot de> contributed RDAC vendor
        specific VPD pages [20060421]
      - Jonathan McDowell <noodles at hp dot com> contributed HP/3PAR InServ
        VPD page [0xc0] containing volume information [20110922]

*/

/* vendor/product identifiers */
#define VPD_VP_SEAGATE 0
#define VPD_VP_RDAC 1
#define VPD_VP_EMC 2
#define VPD_VP_DDS 3
#define VPD_VP_LTO 4
#define VPD_VP_HP3PAR 5


/* vendor VPD pages */
#define VPD_V_HP3PAR 0xc0
#define VPD_V_FIRM_SEA  0xc0
#define VPD_V_UPR_EMC  0xc0
#define VPD_V_HVER_RDAC  0xc0
#define VPD_V_FVER_DDS 0xc0
#define VPD_V_FVER_LTO 0xc0
#define VPD_V_DATC_SEA  0xc1
#define VPD_V_FVER_RDAC  0xc1
#define VPD_V_HVER_LTO 0xc1
#define VPD_V_JUMP_SEA 0xc2
#define VPD_V_SVER_RDAC 0xc2
#define VPD_V_PCA_LTO 0xc2
#define VPD_V_DEV_BEH_SEA 0xc3
#define VPD_V_FEAT_RDAC 0xc3
#define VPD_V_MECH_LTO 0xc3
#define VPD_V_SUBS_RDAC 0xc4
#define VPD_V_HEAD_LTO 0xc4
#define VPD_V_ACI_LTO 0xc5
#define VPD_V_EDID_RDAC 0xc8
#define VPD_V_VAC_RDAC 0xc9
#define VPD_V_RVSI_RDAC 0xca
#define VPD_V_SAID_RDAC 0xd0


#define DEF_ALLOC_LEN 252
#define MX_ALLOC_LEN (0xc000 + 0x80)

struct svpd_vp_name_t {
    int vp_num;       /* vendor/product identifier */
    const char * acron;
    const char * name;
};

/* This structure is a duplicate of one of the same name in sg_vpd.c .
   Take care that both have the same fields (and types). */
struct svpd_values_name_t {
    int value;       /* VPD number */
    int subvalue;    /* vendor/product identifier used to disambiguate */
                     /* shared VPD numbers */
    int pdt;         /* peripheral device type id, -1 is the default */
                     /* (all or not applicable) value */
    const char * acron;
    const char * name;
};


int vpd_fetch_page_from_dev(int sg_fd, unsigned char * rp, int page,
                            int mxlen, int vb, int * rlenp);

/* Size of this array must match the array of the same name in sg_vpd.c */
static unsigned char rsp_buff[MX_ALLOC_LEN + 2];


/* Supported vendor specific VPD pages */
/* Arrange in alphabetical order by acronym */
static struct svpd_vp_name_t vp_arr[] = {
    {VPD_VP_DDS, "dds", "DDS tape family from IBM"},
    {VPD_VP_EMC, "emc", "EMC (company)"},
    {VPD_VP_HP3PAR, "hp3par", "3PAR array (HP was Left Hand)"},
    {VPD_VP_LTO, "lto", "LTO tape drive/system (IBM and others)"},
    {VPD_VP_RDAC, "rdac", "RDAC array (EMC Clariion)"},
    {VPD_VP_SEAGATE, "sea", "Seagate disk"},
    {0, NULL, NULL},
};


/* Supported vendor specific VPD pages */
/* 'subvalue' holds vendor/product number to disambiguate */
/* Arrange in alphabetical order by acronym */
static struct svpd_values_name_t vendor_vpd_pg[] = {
    {VPD_V_ACI_LTO, VPD_VP_LTO, -1, "aci", "ACI revision level (LTO)"},
    {VPD_V_DATC_SEA, VPD_VP_SEAGATE, -1, "datc", "Date code (Seagate)"},
    {VPD_V_FVER_DDS, VPD_VP_DDS, -1, "ddsver", "Firmware revision (DDS)"},
    {VPD_V_DEV_BEH_SEA, VPD_VP_SEAGATE, -1, "devb", "Device behavior "
     "(Seagate)"},
    {VPD_V_EDID_RDAC, VPD_VP_RDAC, -1, "edid", "Extended device "
     "identification (RDAC)"},
    {VPD_V_FEAT_RDAC, VPD_VP_RDAC, -1, "feat", "Feature Parameters (RDAC)"},
    {VPD_V_FIRM_SEA, VPD_VP_SEAGATE, -1, "firm", "Firmware numbers "
     "(Seagate)"},
    {VPD_V_FVER_LTO, VPD_VP_LTO, -1, "frl" , "Firmware revision level (LTO)"},
    {VPD_V_FVER_RDAC, VPD_VP_RDAC, -1, "fver", "Firmware version (RDAC)"},
    {VPD_V_HEAD_LTO, VPD_VP_LTO, -1, "head", "Head Assy revision level "
     "(LTO)"},
    {VPD_V_HP3PAR, VPD_VP_HP3PAR, -1, "hp3par", "Volume information "
     "(HP/3PAR)"},
    {VPD_V_HVER_LTO, VPD_VP_LTO, -1, "hrl", "Hardware revision level (LTO)"},
    {VPD_V_HVER_RDAC, VPD_VP_RDAC, -1, "hver", "Hardware version (RDAC)"},
    {VPD_V_JUMP_SEA, VPD_VP_SEAGATE, -1, "jump", "Jump setting (Seagate)"},
    {VPD_V_MECH_LTO, VPD_VP_LTO, -1, "mech", "Mechanism revision level "
     "(LTO)"},
    {VPD_V_PCA_LTO, VPD_VP_LTO, -1, "pca", "PCA revision level (LTO)"},
    {VPD_V_RVSI_RDAC, VPD_VP_RDAC, -1, "rvsi", "Replicated volume source "
     "identifier (RDAC)"},
    {VPD_V_SAID_RDAC, VPD_VP_RDAC, -1, "said", "Storage array world wide "
     "name (RDAC)"},
    {VPD_V_SUBS_RDAC, VPD_VP_RDAC, -1, "sub", "Subsystem identifier (RDAC)"},
    {VPD_V_SVER_RDAC, VPD_VP_RDAC, -1, "sver", "Software version (RDAC)"},
    {VPD_V_UPR_EMC, VPD_VP_EMC, -1, "upr", "Unit path report (EMC)"},
    {VPD_V_VAC_RDAC, VPD_VP_RDAC, -1, "vac", "Volume access control (RDAC)"},
    {0, 0, 0, NULL, NULL},
};


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

static const struct svpd_values_name_t *
svpd_get_v_detail(int page_num, int vp_num, int pdt)
{
    const struct svpd_values_name_t * vnp;
    int vp, ty;

    vp = (vp_num < 0) ? 1 : 0;
    ty = (pdt < 0) ? 1 : 0;
    for (vnp = vendor_vpd_pg; vnp->acron; ++vnp) {
        if ((page_num == vnp->value) &&
            (vp || (vp_num == vnp->subvalue)) &&
            (ty || (pdt == vnp->pdt)))
            return vnp;
    }
    if (! ty)
        return svpd_get_v_detail(page_num, vp_num, -1);
    if (! vp)
        return svpd_get_v_detail(page_num, -1, -1);
    return NULL;
}

const struct svpd_values_name_t *
svpd_find_vendor_by_num(int page_num, int vp_num)
{
    const struct svpd_values_name_t * vnp;

    for (vnp = vendor_vpd_pg; vnp->acron; ++vnp) {
        if ((page_num == vnp->value) &&
            ((vp_num < 0) || (vp_num == vnp->subvalue)))
            return vnp;
    }
    return NULL;
}


int
svpd_find_vp_num_by_acron(const char * vp_ap)
{
    size_t len;
    const struct svpd_vp_name_t * vpp;

    for (vpp = vp_arr; vpp->acron; ++vpp) {
        len = strlen(vpp->acron);
        if (0 == strncmp(vpp->acron, vp_ap, len))
            return vpp->vp_num;
    }
    return -1;
}


const struct svpd_values_name_t *
svpd_find_vendor_by_acron(const char * ap)
{
    const struct svpd_values_name_t * vnp;

    for (vnp = vendor_vpd_pg; vnp->acron; ++vnp) {
        if (0 == strcmp(vnp->acron, ap))
            return vnp;
    }
    return NULL;
}

/* vp_num=-2 everthing, =-1 only vendor_product, else just that vp_num */
void
svpd_enumerate_vendor(int vp_num)
{
    const struct svpd_vp_name_t * vpp;
    const struct svpd_values_name_t * vnp;
    int seen;

    if (vp_num < 0) {
        for (seen = 0, vpp = vp_arr; vpp->acron; ++vpp) {
            if (vpp->name) {
                if (! seen) {
                    printf("\nVendor/product identifiers:\n");
                    seen = 1;
                }
                printf("  %-10s %d      %s\n", vpp->acron,
                       vpp->vp_num, vpp->name);
            }
        }
    }
    if (-1 == vp_num)
        return;
    for (seen = 0, vnp = vendor_vpd_pg; vnp->acron; ++vnp) {
	if ((vp_num >= 0) && (vp_num != vnp->subvalue))
            continue;
        if (vnp->name) {
            if (! seen) {
                printf("\nVendor specific VPD pages:\n");
                seen = 1;
            }
            printf("  %-10s 0x%02x,%d      %s\n", vnp->acron,
                   vnp->value, vnp->subvalue, vnp->name);
        }
    }
}

int
svpd_count_vendor_vpds(int num_vpd, int vp_num)
{
    const struct svpd_values_name_t * vnp;
    int matches;

    for (vnp = vendor_vpd_pg, matches = 0; vnp->acron; ++vnp) {
        if ((num_vpd == vnp->value) && vnp->name) {
            if ((vp_num < 0) || (vp_num == vnp->subvalue)) {
                if (0 == matches)
                    printf("Matching vendor specific VPD pages:\n");
                ++matches;
                printf("  %-10s 0x%02x,%d      %s\n", vnp->acron,
                       vnp->value, vnp->subvalue, vnp->name);
            }
        }
    }
    return matches;
}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

static void
decode_vpd_c0_hp3par(unsigned char * buff, int len)
{
    int rev;
    long offset;

    if (len < 24) {
        pr2serr("HP/3PAR vendor specific VPD page length too short=%d\n",
                len);
        return;
    }

    rev = buff[4];
    printf("  Page revision: %d\n", rev);

    printf("  Volume type: %s\n", (buff[5] & 0x01) ? "tpvv" :
            (buff[5] & 0x02) ? "snap" : "base");
    printf("  Reclaim supported: %s\n", (buff[5] & 0x04) ? "yes" : "no");
    printf("  ATS supported: %s\n", (buff[5] & 0x10) ? "yes" : "no");
    printf("  XCopy supported: %s\n", (buff[5] & 0x20) ? "yes" : "no");

    if (rev > 3) {
        printf("  VV ID: %" PRIu64 "\n", ((uint64_t) buff[28] << 56) +
                ((uint64_t) buff[29] << 48) + ((uint64_t) buff[30] << 40) +
                ((uint64_t) buff[31] << 32) + ((uint64_t) buff[32] << 24) +
                (buff[33] << 16) + (buff[34] << 8) + buff[35]);

        offset = 44;
        printf("  Volume name: %s\n", &buff[offset]);

        printf("  Domain ID: %d\n", (buff[36] << 24) +  (buff[37] << 16) +
                (buff[38] << 8) + buff[39]);

        offset += (buff[offset - 4] << 24) + (buff[offset - 3] << 16) +
                (buff[offset - 2] << 8) + buff[offset - 1] + 4;
        printf("  Domain Name: %s\n", &buff[offset]);

        offset += (buff[offset - 4] << 24) + (buff[offset - 3] << 16) +
                (buff[offset - 2] << 8) + buff[offset - 1] + 4;
        printf("  User CPG: %s\n", &buff[offset]);

        offset += (buff[offset - 4] << 24) + (buff[offset - 3] << 16) +
                (buff[offset - 2] << 8) + buff[offset - 1] + 4;
        printf("  Snap CPG: %s\n", &buff[offset]);

        offset += (buff[offset - 4] << 24) + (buff[offset - 3] << 16) +
                (buff[offset - 2] << 8) + buff[offset - 1];

        printf("  VV policies: %s,%s,%s,%s\n",
                (buff[offset + 3] & 0x01) ? "stale_ss" : "no_stale_ss",
                (buff[offset + 3] & 0x02) ? "one_host" : "no_one_host",
                (buff[offset + 3] & 0x04) ? "tp_bzero" : "no_tp_bzero",
                (buff[offset + 3] & 0x08) ? "zero_detect" : "no_zero_detect");

    }

    if (buff[5] & 0x04) {
        printf("  Allocation unit: %d\n", (buff[8] << 24) +  (buff[9] << 16) +
                (buff[10] << 8) + buff[11]);

        printf("  Data pool size: %" PRIu64 "\n",
               (((uint64_t)buff[12]) << 56) + (((uint64_t)buff[13]) << 48) +
               (((uint64_t)buff[14]) << 40) + (((uint64_t)buff[15]) << 32) +
               (((uint64_t)buff[16]) << 24) + (buff[17] << 16) +
               (buff[18] << 8) + buff[19]);

        printf("  Space allocated: %" PRIu64 "\n",
               (((uint64_t)buff[20]) << 56) + (((uint64_t)buff[21]) << 48) +
               (((uint64_t)buff[22]) << 40) + (((uint64_t)buff[23]) << 32) +
               (((uint64_t)buff[24]) << 24) + (buff[25] << 16) +
               (buff[26] << 8) + buff[27]);
    }
    return;
}


static void
decode_firm_vpd_c0_sea(unsigned char * buff, int len)
{
    if (len < 28) {
        pr2serr("Seagate firmware numbers VPD page length too short=%d\n",
                len);
        return;
    }
    if (28 == len) {
        printf("  SCSI firmware release number: %.8s\n", buff + 4);
        printf("  Servo ROM release number: %.8s\n", buff + 20);
    } else {
        printf("  SCSI firmware release number: %.8s\n", buff + 4);
        printf("  Servo ROM release number: %.8s\n", buff + 12);
        printf("  SAP block point numbers (major/minor): %.8s\n", buff + 20);
        if (len < 36)
            return;
        printf("  Servo firmware release date: %.4s\n", buff + 28);
        printf("  Servo ROM release date: %.4s\n", buff + 32);
        if (len < 44)
            return;
        printf("  SAP firmware release number: %.8s\n", buff + 36);
        if (len < 52)
            return;
        printf("  SAP firmware release date: %.4s\n", buff + 44);
        printf("  SAP firmware release year: %.4s\n", buff + 48);
        if (len < 60)
            return;
        printf("  SAP manufacturing key: %.4s\n", buff + 52);
        printf("  Servo firmware product family and product family "
               "member: %.4s\n", buff + 56);
    }
}

static void
decode_date_code_vpd_c1_sea(unsigned char * buff, int len)
{
    if (len < 20) {
        pr2serr("Seagate Data code VPD page length too short=%d\n",
                len);
        return;
    }
    printf("  ETF log (mmddyyyy): %.8s\n", buff + 4);
    printf("  Compile date code (mmddyyyy): %.8s\n", buff + 12);
}

static void
decode_dev_beh_vpd_c3_sea(unsigned char * buff, int len)
{
    if (len < 25) {
        pr2serr("Seagate Device behaviour VPD page length too short=%d\n",
                len);
        return;
    }
    printf("  Version number: %d\n", buff[4]);
    printf("  Behaviour code: %d\n", buff[5]);
    printf("  Behaviour code version number: %d\n", buff[6]);
    printf("  ASCII family number: %.16s\n", buff + 7);
    printf("  Number of interleaves: %d\n", buff[23]);
    printf("  Default number of cache segments: %d\n", buff[24]);
}

static const char * lun_state_arr[] =
{
    "LUN not bound or LUN_Z report",
    "LUN bound, but not owned by this SP",
    "LUN bound and owned by this SP",
};

static const char * ip_mgmt_arr[] =
{
    "No IP access",
    "Reserved (undefined)",
    "via IPv4",
    "via IPv6",
};

static const char * sp_arr[] =
{
    "SP A",
    "SP B",
};

static const char * lun_op_arr[] =
{
    "Normal operations",
    "I/O Operations being rejected, SP reboot or NDU in progress",
};

static const char * failover_mode_arr[] =
{
    "Legacy mode 0",
    "Unknown mode (1)",
    "Unknown mode (2)",
    "Unknown mode (3)",
    "Active/Passive (PNR) mode 1",
    "Unknown mode (5)",
    "Active/Active (ALUA) mode 4",
    "Unknown mode (7)",
    "Legacy mode 2",
    "Unknown mode (9)",
    "Unknown mode (10)",
    "Unknown mode (11)",
    "Unknown mode (12)",
    "Unknown mode (13)",
    "AIX Active/Passive (PAR) mode 3",
    "Unknown mode (15)",
};

static void
decode_upr_vpd_c0_emc(unsigned char * buff, int len)
{
    int k, ip_mgmt, vpp80, lun_z;

    if (len < 3) {
        pr2serr("EMC upr VPD page [0xc0]: length too short=%d\n", len);
        return;
    }
    if (buff[9] != 0x00) {
        pr2serr("Unsupported page revision %d, decoding not possible.\n",
                buff[9]);
        return;
    }
    printf("  LUN WWN: ");
    for (k = 0; k < 16; ++k)
        printf("%02x", buff[10 + k]);
    printf("\n");
    printf("  Array Serial Number: ");
    dStrRaw((const char *)&buff[50], buff[49]);
    printf("\n");

    printf("  LUN State: ");
    if (buff[4] > 0x02)
           printf("Unknown (%x)\n", buff[4]);
    else
           printf("%s\n", lun_state_arr[buff[4]]);

    printf("  This path connects to: ");
    if (buff[8] > 0x01)
           printf("Unknown SP (%x)", buff[8]);
    else
           printf("%s", sp_arr[buff[8]]);
    printf(", Port Number: %u\n", buff[7]);

    printf("  Default Owner: ");
    if (buff[5] > 0x01)
           printf("Unknown (%x)\n", buff[5]);
    else
           printf("%s\n", sp_arr[buff[5]]);

    printf("  NO_ATF: %s, Access Logix: %s\n",
                   buff[6] & 0x80 ? "set" : "not set",
                   buff[6] & 0x40 ? "supported" : "not supported");

    ip_mgmt = (buff[6] >> 4) & 0x3;

    printf("  SP IP Management Mode: %s\n", ip_mgmt_arr[ip_mgmt]);
    if (ip_mgmt == 2)
        printf("  SP IPv4 address: %u.%u.%u.%u\n",
               buff[44], buff[45], buff[46], buff[47]);
    else {
        printf("  SP IPv6 address: ");
        for (k = 0; k < 16; ++k)
            printf("%02x", buff[32 + k]);
        printf("\n");
    }

    vpp80 = buff[30] & 0x08;
    lun_z = buff[30] & 0x04;

    printf("  System Type: %x, Failover mode: %s\n",
           buff[27], failover_mode_arr[buff[28] & 0x0f]);

    printf("  Inquiry VPP 0x80 returns: %s, Arraycommpath: %s\n",
                   vpp80 ? "array serial#" : "LUN serial#",
                   lun_z ? "Set to 1" : "Unknown");

    printf("  Lun operations: %s\n",
               buff[48] > 1 ? "undefined" : lun_op_arr[buff[48]]);

    return;
}

static void
decode_rdac_vpd_c0(unsigned char * buff, int len)
{
    int memsize;
    char name[65];

    if (len < 3) {
        pr2serr("Hardware Version VPD page length too short=%d\n", len);
        return;
    }
    if (buff[4] != 'h' && buff[5] != 'w' && buff[6] != 'r') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    printf("  Number of channels: %x\n", buff[8]);
    memsize = buff[10] << 8 | buff[11];
    printf("  Processor Memory Size: %d\n", memsize);
    memset(name, 0, 65);
    memcpy(name, buff + 16, 64);
    printf("  Board Name: %s\n", name);
    memset(name, 0, 65);
    memcpy(name, buff + 80, 16);
    printf("  Board Part Number: %s\n", name);
    memset(name, 0, 65);
    memcpy(name, buff + 96, 12);
    printf("  Schematic Number: %s\n", name);
    memset(name, 0, 65);
    memcpy(name, buff + 108, 4);
    printf("  Schematic Revision Number: %s\n", name);
    memset(name, 0, 65);
    memcpy(name, buff + 112, 16);
    printf("  Board Serial Number: %s\n", name);
    memset(name, 0, 65);
    memcpy(name, buff + 144, 8);
    printf("  Date of Manufacture: %s\n", name);
    memset(name, 0, 65);
    memcpy(name, buff + 152, 2);
    printf("  Board Revision: %s\n", name);
    memset(name, 0, 65);
    memcpy(name, buff + 154, 2);
    printf("  Board Identifier: %s\n", name);

    return;
}

static void
decode_rdac_vpd_c1(unsigned char * buff, int len)
{
    int i, n, v, r, m, p, d, y, num_part;
    char part[5];

    if (len < 3) {
        pr2serr("Firmware Version VPD page length too short=%d\n", len);
        return;
    }
    if (buff[4] != 'f' && buff[5] != 'w' && buff[6] != 'r') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    printf("  Firmware Version: %x.%x.%x\n", buff[8], buff[9], buff[10]);
    printf("  Firmware Date: %02d/%02d/%02d\n", buff[11], buff[12], buff[13]);

    num_part = (len - 12) / 16;
    n = 16;
    printf("  Partitions: %d\n", num_part);
    for (i = 0; i < num_part; i++) {
        memset(part,0, 5);
        memcpy(part, &buff[n], 4);
        printf("    Name: %s\n", part);
        n += 4;
        v = buff[n++];
        r = buff[n++];
        m = buff[n++];
        p = buff[n++];
        printf("    Version: %d.%d.%d.%d\n", v, r, m, p);
        m = buff[n++];
        d = buff[n++];
        y = buff[n++];
        printf("    Date: %d/%d/%d\n", m, d, y);

        n += 5;
    }

    return;
}

static void
decode_rdac_vpd_c2(unsigned char * buff, int len)
{
    int i, n, v, r, m, p, d, y, num_part;
    char part[5];

    if (len < 3) {
        pr2serr("Software Version VPD page length too short=%d\n", len);
        return;
    }
    if (buff[4] != 's' && buff[5] != 'w' && buff[6] != 'r') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    printf("  Software Version: %x.%x.%x\n", buff[8], buff[9], buff[10]);
    printf("  Software Date: %02d/%02d/%02d\n", buff[11], buff[12], buff[13]);
    printf("  Features:");
    if (buff[14] & 0x01)
        printf(" Dual Active,");
    if (buff[14] & 0x02)
        printf(" Series 3,");
    if (buff[14] & 0x04)
        printf(" Multiple Sub-enclosures,");
    if (buff[14] & 0x08)
        printf(" DCE/DRM,");
    if (buff[14] & 0x10)
        printf(" AVT,");
    printf("\n");
    printf("  Max. #of LUNS: %d\n", buff[15]);

    num_part = (len - 12) / 16;
    n = 16;
    printf("  Partitions: %d\n", num_part);
    for (i = 0; i < num_part; i++) {
        memset(part,0, 5);
        memcpy(part, &buff[n], 4);
        printf("    Name: %s\n", part);
        n += 4;
        v = buff[n++];
        r = buff[n++];
        m = buff[n++];
        p = buff[n++];
        printf("    Version: %d.%d.%d.%d\n", v, r, m, p);
        m = buff[n++];
        d = buff[n++];
        y = buff[n++];
        printf("    Date: %d/%d/%d\n", m, d, y);

        n += 5;
    }

    return;
}

static void
decode_rdac_vpd_c3(unsigned char * buff, int len)
{
    if (len < 0x2c) {
        pr2serr("Feature parameters VPD page length too short=%d\n", len);
        return;
    }
    if (buff[4] != 'p' && buff[5] != 'r' && buff[6] != 'm') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    printf("  Maximum number of drives per LUN: %d\n", buff[8]);
    printf("  Maximum number of hot spare drives: %d\n", buff[9]);
    printf("  UTM: %s\n", buff[11] & 0x80?"enabled":"disabled");
    if ((buff[11] & 0x80))
        printf("    UTM LUN: %02x\n", buff[11] & 0x7f);

    return;
}

static void
decode_rdac_vpd_c4(unsigned char * buff, int len)
{
    char subsystem_id[17];
    char subsystem_rev[5];
    char slot_id[3];

    if (len < 0x1c) {
        pr2serr("Subsystem identifier VPD page length too short=%d\n", len);
        return;
    }
    if (buff[4] != 's' && buff[5] != 'u' && buff[6] != 'b') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    memset(subsystem_id, 0, 17);
    memcpy(subsystem_id, &buff[8], 16);
    memset(subsystem_rev, 0, 5);
    memcpy(subsystem_rev, &buff[24], 4);
    slot_id[0] = buff[28];
    slot_id[1] = buff[29];
    slot_id[2] = 0;

    printf("  Subsystem ID: %s\n  Subsystem Revision: %s",
           subsystem_id, subsystem_rev);
    if (!strcmp(subsystem_rev, "10.0"))
        printf(" (Board ID 4884)\n");
    else if (!strcmp(subsystem_rev, "12.0"))
        printf(" (Board ID 5884)\n");
    else if (!strcmp(subsystem_rev, "13.0"))
        printf(" (Board ID 2882)\n");
    else if (!strcmp(subsystem_rev, "13.1"))
        printf(" (Board ID 2880)\n");
    else if (!strcmp(subsystem_rev, "14.0"))
        printf(" (Board ID 2822)\n");
    else
        printf(" (Board ID unknown)\n");

    printf("  Slot ID: %s\n", slot_id);

    return;
}

static void
decode_rdac_vpd_c8(unsigned char * buff, int len)
{
    int i;
#ifndef SG_LIB_MINGW
    time_t tstamp;
#endif
    char *c;
    char label[61];
    int label_len;
    char uuid[33];
    int uuid_len;

    if (len < 0xab) {
        pr2serr("Extended Device Identification VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 'e' && buff[5] != 'd' && buff[6] != 'i') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }

    uuid_len = buff[11];

    for (i = 0, c = uuid; i < uuid_len; i++) {
        sprintf(c,"%02x",buff[12 + i]);
        c += 2;
    }

    printf("  Volume Unique Identifier: %s\n", uuid);
#ifndef SG_LIB_MINGW
    tstamp = (buff[24] << 24) + (buff[25] << 16) + (buff[26] << 8) + buff[27];
    printf("    Creation Number: %d, Timestamp: %s",
           (buff[22] << 8) + buff[23], ctime(&tstamp));
#else
    printf("    Creation Number: %d, Timestamp value: %u",
           (buff[22] << 8) + buff[23],
           (buff[24] << 24) + (buff[25] << 16) + (buff[26] << 8) + buff[27]);
#endif
    memset(label, 0, 61);
    label_len = buff[28];
    for(i = 0; i < (label_len - 1); ++i)
        *(label + i) = buff[29 + (2 * i) + 1];
    printf("  Volume User Label: %s\n", label);

    uuid_len = buff[89];

    for (i = 0, c = uuid; i < uuid_len; i++) {
        sprintf(c,"%02x",buff[90 + i]);
        c += 2;
    }

    printf("  Storage Array Unique Identifier: %s\n", uuid);
    memset(label, 0, 61);
    label_len = buff[106];
    for(i = 0; i < (label_len - 1); ++i)
        *(label + i) = buff[107 + (2 * i) + 1];
    printf("  Storage Array User Label: %s\n", label);

    for (i = 0, c = uuid; i < 8; i++) {
        sprintf(c,"%02x",buff[167 + i]);
        c += 2;
    }

    printf("  Logical Unit Number: %s\n", uuid);

    return;
}

static void
decode_rdac_vpd_c9(unsigned char * buff, int len)
{
    if (len < 3) {
        pr2serr("Volume Access Control VPD page length too short=%d\n", len);
        return;
    }
    if (buff[4] != 'v' && buff[5] != 'a' && buff[6] != 'c') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    if (buff[7] != '1') {
        pr2serr("Invalid page version '%c' (should be 1)\n", buff[7]);
    }
    printf("  AVT:");
    if (buff[8] & 0x80) {
        printf(" Enabled");
        if (buff[8] & 0x40)
            printf(" (Allow reads on sector 0)");
        printf("\n");
    } else {
        printf(" Disabled\n");
    }
    printf("  Volume Access via: ");
    if (buff[8] & 0x01)
        printf("primary controller\n");
    else
        printf("alternate controller\n");

    printf("  Path priority: %d ", buff[9] & 0xf);
    switch(buff[9] & 0xf) {
        case 0x1:
            printf("(preferred path)\n");
            break;
        case 0x2:
            printf("(secondary path)\n");
            break;
        default:
            printf("(unknown)\n");
            break;
    }

    return;
}

static void
decode_rdac_vpd_ca(unsigned char * buff, int len)
{
    int i;

    if (len < 16) {
        pr2serr("Replicated Volume Source Identifier VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 'r' && buff[5] != 'v' && buff[6] != 's') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding not possible.\n",
                buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    if (buff[8] & 0x01) {
        printf("  Snapshot Volume\n");
        printf("  Base Volume WWID: ");
        for (i = 0; i < 16; i++)
            printf("%02x", buff[10 + i]);
        printf("\n");
    } else if (buff[8] & 0x02) {
        printf("  Copy Target Volume\n");
        printf("  Source Volume WWID: ");
        for (i = 0; i < 16; i++)
            printf("%02x", buff[10 + i]);
        printf("\n");
    } else
        printf(" Neither a snapshot nor a copy target volume\n");

    return;
}

static void
decode_rdac_vpd_d0(unsigned char * buff, int len)
{
    int i;

    if (len < 20) {
        pr2serr("Storage Array World Wide Name VPD page length too "
                "short=%d\n", len);
        return;
    }
    printf("  Storage Array WWN: ");
    for (i = 0; i < 16; i++)
        printf("%02x", buff[8 + i]);
    printf("\n");

    return;
}


static void
decode_dds_vpd_c0(unsigned char * buff, int len)
{
    char firmware_rev[25];
    char build_date[43];
    char hw_conf[21];
    char fw_conf[21];

    if (len < 0xb3) {
        pr2serr("Vendor-Unique Firmware revision page invalid length=%d\n",
                len);
        return;
    }
    memset(firmware_rev, 0x0, 25);
    memcpy(firmware_rev, &buff[5], 24);

    printf("  %s\n", firmware_rev);

    memset(build_date, 0x0, 43);
    memcpy(build_date, &buff[30], 42);

    printf("  %s\n", build_date);

    memset(hw_conf, 0x0, 21);
    memcpy(hw_conf, &buff[73], 20);
    printf("  %s\n", hw_conf);

    memset(fw_conf, 0x0, 21);
    memcpy(fw_conf, &buff[94], 20);
    printf("  %s\n", fw_conf);
    return;
}

static void
decode_lto_vpd_cx(unsigned char * buff, int len, int page)
{
    char str[32];
    const char *comp = NULL;

    if (len < 0x5c) {
        pr2serr("Driver Component Revision Levels page invalid length=%d\n",
                len);
        return;
    }
    switch (page) {
        case 0xc0:
            comp = "Firmware";
            break;
        case 0xc1:
            comp = "Hardware";
            break;
        case 0xc2:
            comp = "PCA";
            break;
        case 0xc3:
            comp = "Mechanism";
            break;
        case 0xc4:
            comp = "Head Assy";
            break;
        case 0xc5:
            comp = "ACI";
            break;
    }
    if (!comp) {
        pr2serr("Driver Component Revision Level invalid page=0x%02x\n",
                page);
        return;
    }

    memset(str, 0x0, 32);
    memcpy(str, &buff[4], 26);
    printf("  %s\n", str);

    memset(str, 0x0, 32);
    memcpy(str, &buff[30], 19);
    printf("  %s\n", str);

    memset(str, 0x0, 32);
    memcpy(str, &buff[49], 24);
    printf("  %s\n", str);

    memset(str, 0x0, 32);
    memcpy(str, &buff[73], 23);
    printf("  %s\n", str);
    return;
}

/* Returns 0 if successful, see sg_ll_inquiry() plus SG_LIB_SYNTAX_ERROR for
   unsupported page */
int
svpd_decode_vendor(int sg_fd, int num_vpd, int vp_num, int maxlen,
                   int do_hex, int do_raw, int do_long, int do_quiet,
                   int verbose)
{
    int len, res;
    char name[64];
    const struct svpd_values_name_t * vnp;
    int alloc_len = maxlen;

    if (do_long) { ; }  /* unused, dummy to suppress warning */
    vnp = svpd_get_v_detail(num_vpd, vp_num, -1);
    if (vnp && vnp->name)
        strcpy(name, vnp->name);
    else
        snprintf(name, sizeof(name) - 1, "Vendor VPD page=0x%x", num_vpd);
    if (sg_fd >= 0) {
        if (0 == alloc_len)
            alloc_len = DEF_ALLOC_LEN;
    }
    if ((! do_raw) && (! do_quiet) && (do_hex < 2))
        printf("%s VPD Page:\n", name);
    res = vpd_fetch_page_from_dev(sg_fd, rsp_buff, num_vpd, alloc_len,
                                  verbose, &len);
    if (0 == res) {
        if (do_raw)
            dStrRaw((const char *)rsp_buff, len);
        else if (do_hex)
            dStrHex((const char *)rsp_buff, len, ((1 == do_hex) ? 0 : -1));
        else {
            switch(num_vpd) {
                case 0xc0:
                    if (VPD_VP_SEAGATE == vp_num)
                        decode_firm_vpd_c0_sea(rsp_buff, len);
                    else if (VPD_VP_EMC == vp_num)
                        decode_upr_vpd_c0_emc(rsp_buff, len);
                    else if (VPD_VP_HP3PAR == vp_num)
                        decode_vpd_c0_hp3par(rsp_buff, len);
                    else if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_c0(rsp_buff, len);
                    else if (VPD_VP_DDS == vp_num)
                        decode_dds_vpd_c0(rsp_buff, len);
                    else if (VPD_VP_LTO == vp_num)
                        decode_lto_vpd_cx(rsp_buff, len, num_vpd);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xc1:
                    if (VPD_VP_SEAGATE == vp_num)
                        decode_date_code_vpd_c1_sea(rsp_buff, len);
                    else if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_c1(rsp_buff, len);
                    else if (VPD_VP_LTO == vp_num)
                        decode_lto_vpd_cx(rsp_buff, len, num_vpd);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xc2:
                    if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_c2(rsp_buff, len);
                    else if (VPD_VP_LTO == vp_num)
                        decode_lto_vpd_cx(rsp_buff, len, num_vpd);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xc3:
                    if (VPD_VP_SEAGATE == vp_num)
                        decode_dev_beh_vpd_c3_sea(rsp_buff, len);
                    else if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_c3(rsp_buff, len);
                    else if (VPD_VP_LTO == vp_num)
                        decode_lto_vpd_cx(rsp_buff, len, num_vpd);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xc4:
                    if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_c4(rsp_buff, len);
                    else if (VPD_VP_LTO == vp_num)
                        decode_lto_vpd_cx(rsp_buff, len, num_vpd);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xc5:
                    if (VPD_VP_LTO == vp_num)
                        decode_lto_vpd_cx(rsp_buff, len, num_vpd);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xc8:
                    if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_c8(rsp_buff, len);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xc9:
                    if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_c9(rsp_buff, len);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xca:
                    if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_ca(rsp_buff, len);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                case 0xd0:
                    if (VPD_VP_RDAC == vp_num)
                        decode_rdac_vpd_d0(rsp_buff, len);
                    else
                        dStrHex((const char *)rsp_buff, len, 0);
                    break;
                default:
                    return SG_LIB_SYNTAX_ERROR;
            }
            return 0;
        }
    }
    return res;
}
