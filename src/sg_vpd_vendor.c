/*
 * Copyright (c) 2006-2011 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
*/


/* vendor VPD pages */
#define VPD_V_FIRM_SEA  0xc0
#define VPD_V_UPR_EMC  0xc0
#define VPD_V_DATC_SEA  0xc1
#define VPD_V_JUMP_SEA 0xc2
#define VPD_V_SVER_RDAC 0xc2
#define VPD_V_DEV_BEH_SEA 0xc3
#define VPD_V_FEAT_RDAC 0xc3
#define VPD_V_SUBS_RDAC 0xc4
#define VPD_V_EDID_RDAC 0xc8
#define VPD_V_VAC_RDAC 0xc9


#define DEF_ALLOC_LEN 252
#define MX_ALLOC_LEN (0xc000 + 0x80)

/* This structure is a duplicate of one of the same name in sg_vpd.c .
   Take care that both have the same fields (and types). */
struct svpd_values_name_t {
    int value;       /* VPD number */
    int subvalue;    /* used to disambiguate when different vendors use */
                     /* the same VPD number */
    int pdt;         /* peripheral device type id, -1 is the default */
                     /* (all or not applicable) value */
    int vendor;      /* vendor flag */
    const char * acron;
    const char * name;
};


/* Size of this array must match the array of the same name in sg_vpd.c */
static unsigned char rsp_buff[MX_ALLOC_LEN + 2];


/* Supported vendor specific VPD pages */
/* 'subvalue' used to disambiguate, 'vendor' should be set */
/* Arrange in alphabetical order by acronym */
static struct svpd_values_name_t vendor_vpd_pg[] = {
    {VPD_V_DATC_SEA, 0, -1, 1, "datc", "Date code (Seagate)"},
    {VPD_V_DEV_BEH_SEA, 0, -1, 1, "devb", "Device behavior (Seagate)"},
    {VPD_V_EDID_RDAC, 0, -1, 1, "edid", "Extended device identification "
     "(RDAC)"},
    {VPD_V_FEAT_RDAC, 1, -1, 1, "feat", "Feature Parameters (RDAC)"},
    {VPD_V_FIRM_SEA, 0, -1, 1, "firm", "Firmware numbers (Seagate)"},
    {VPD_V_JUMP_SEA, 0, -1, 1, "jump", "Jump setting (Seagate)"},
    {VPD_V_SUBS_RDAC, 0, -1, 1, "sub", "Subsystem identifier (RDAC)"},
    {VPD_V_SVER_RDAC, 1, -1, 1, "sver", "Software version (RDAC)"},
    {VPD_V_UPR_EMC, 1, -1, 1, "upr", "Unit path report (EMC)"},
    {VPD_V_VAC_RDAC, 0, -1, 1, "vac", "Volume access control (RDAC)"},
    {0, 0, 0, 0, NULL, NULL},
};

static const struct svpd_values_name_t *
svpd_get_v_detail(int page_num, int subvalue, int pdt)
{
    const struct svpd_values_name_t * vnp;
    int sv, ty;

    sv = (subvalue < 0) ? 1 : 0;
    ty = (pdt < 0) ? 1 : 0;
    for (vnp = vendor_vpd_pg; vnp->acron; ++vnp) {
        if ((page_num == vnp->value) &&
            (sv || (subvalue == vnp->subvalue)) &&
            (ty || (pdt == vnp->pdt)))
            return vnp;
    }
    if (! ty)
        return svpd_get_v_detail(page_num, subvalue, -1);
    if (! sv)
        return svpd_get_v_detail(page_num, -1, -1);
    return NULL;
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

void
svpd_enumerate_vendor()
{
    const struct svpd_values_name_t * vnp;
    int seen;

    for (seen = 0, vnp = vendor_vpd_pg; vnp->acron; ++vnp) {
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

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
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

static void
decode_firm_vpd_c0_sea(unsigned char * buff, int len)
{
    if (len < 28) {
        fprintf(stderr, "Seagate firmware numbers VPD page length too "
                "short=%d\n", len);
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
decode_upr_vpd_c0_emc(unsigned char * buff, int len)
{
    int k, ip_mgmt, failover_mode, vpp80, lun_z;

    if (len < 3) {
        fprintf(stderr, "EMC upr VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[9] != 0x00) {
        fprintf(stderr, "Unsupported page revision %d, decoding not "
                "possible.\n" , buff[9]);
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

    failover_mode = buff[28] & 0x0f;
    vpp80 = buff[30] & 0x08;
    lun_z = buff[30] & 0x04;

    printf("  System Type: %x, ", buff[27]);
    switch (failover_mode) {
        case 4:
            printf("Failover mode: 1 (Linux)\n");
            break;
        case 6:
            printf("Failover mode: 4 (ALUA)\n");
            break;
        default:
            printf("Failover mode: Unknown (%d)\n", failover_mode);
            break;
    }

    printf("  Inquiry VPP 0x80 returns: %s, Arraycommpath: %s\n",
                   vpp80 ? "array serial#" : "LUN serial#",
                   lun_z ? "Set to 1" : "Unknown");

    printf("  Lun operations: %s\n",
               buff[48] > 1 ? "undefined" : lun_op_arr[buff[48]]);

    return;
}

static void
decode_rdac_vpd_c2(unsigned char * buff, int len)
{
    int i, n, v, r, m, p, num_part;
    char part[5];

    if (len < 3) {
        fprintf(stderr, "Software Version VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 's' && buff[5] != 'w' && buff[6] != 'r') {
        fprintf(stderr, "Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
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

        /*
         * These three bytes are actually the partition date,
         * but I've no idea how it's encoded.
         */
        n += 3;

        n += 5;
    }

    return;
}

static void
decode_rdac_vpd_c3(unsigned char * buff, int len)
{
    if (len < 0x2c) {
        fprintf(stderr, "Feature parameters VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 'p' && buff[5] != 'r' && buff[6] != 'm') {
        fprintf(stderr, "Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
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
        fprintf(stderr, "Subsystem identifier VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 's' && buff[5] != 'u' && buff[6] != 'b') {
        fprintf(stderr, "Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
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
        printf(" {Board ID unknown)\n");

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
        fprintf(stderr, "Extended Device Identification VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 'e' && buff[5] != 'd' && buff[6] != 'i') {
        fprintf(stderr, "Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
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
        fprintf(stderr, "Volume Access Control VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 'v' && buff[5] != 'a' && buff[6] != 'c') {
        fprintf(stderr, "Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    if (buff[7] != '1') {
        fprintf(stderr, "Invalid page version '%c' (should be 1)\n",
                buff[7]);
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

/* Returns 0 if successful, see sg_ll_inquiry() plus SG_LIB_SYNTAX_ERROR for
   unsupported page */
int
svpd_decode_vendor(int sg_fd, int num_vpd, int subvalue, int maxlen,
                   int do_hex, int do_raw, int do_long, int do_quiet,
                   int verbose)
{
    int len, t, res;
    char name[64];
    const struct svpd_values_name_t * vnp;
    int alloc_len = maxlen;

    t = do_long;        /* suppress warning */
    vnp = svpd_get_v_detail(num_vpd, subvalue, -1);
    if (vnp && vnp->name)
        strcpy(name, vnp->name);
    else
        snprintf(name, sizeof(name) - 1, "Vendor VPD page=0x%x", num_vpd);
    if (0 == alloc_len)
        alloc_len = DEF_ALLOC_LEN;
    switch(num_vpd) {
    case VPD_V_UPR_EMC:
        if ((! do_raw) && (! do_quiet))
            printf("%s VPD Page:\n", name);
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xc0 page "
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
            else if (0 == subvalue)
                decode_firm_vpd_c0_sea(rsp_buff, len);
            else if (1 == subvalue)
                decode_upr_vpd_c0_emc(rsp_buff, len);
            else
                dStrHex((const char *)rsp_buff, len, 0);
            return 0;
        }
        break;
    case VPD_V_SVER_RDAC:
        if ((! do_raw) && (! do_quiet))
            printf("%s VPD Page:\n", name);
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xc2 page "
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
            else if (1 == subvalue)
                decode_rdac_vpd_c2(rsp_buff, len);
            else
                dStrHex((const char *)rsp_buff, len, 0);
            return 0;
        }
        break;
    case VPD_V_FEAT_RDAC:
        if ((! do_raw) && (! do_quiet))
            printf("%s VPD Page:\n", name);
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xc3 page "
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
            else if (1 == subvalue)
                decode_rdac_vpd_c3(rsp_buff, len);
            else
                dStrHex((const char *)rsp_buff, len, 0);
            return 0;
        }
        break;
    case VPD_V_SUBS_RDAC:
        if ((! do_raw) && (! do_quiet))
            printf("%s VPD Page:\n", name);
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xc4 page "
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
            else if (0 == subvalue)
                decode_rdac_vpd_c4(rsp_buff, len);
            else
                dStrHex((const char *)rsp_buff, len, 0);
            return 0;
        }
        break;
    case VPD_V_EDID_RDAC:
        if ((! do_raw) && (! do_quiet))
            printf("%s VPD Page:\n", name);
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xc8 page "
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
            else if (0 == subvalue)
                decode_rdac_vpd_c8(rsp_buff, len);
            else
                dStrHex((const char *)rsp_buff, len, 0);
            return 0;
        }
        break;
    case VPD_V_VAC_RDAC:
        if ((! do_raw) && (! do_quiet))
            printf("%s VPD Page:\n", name);
        res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, alloc_len, 1,
                            verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (num_vpd != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > alloc_len) {
                if ((0 == maxlen) && (len < MX_ALLOC_LEN)) {
                    res = sg_ll_inquiry(sg_fd, 0, 1, num_vpd, rsp_buff, len,
                                        1, verbose);
                    if (res) {
                        fprintf(stderr, "fetching 0xc9 page "
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
            else if (0 == subvalue)
                decode_rdac_vpd_c9(rsp_buff, len);
            else
                dStrHex((const char *)rsp_buff, len, 0);
            return 0;
        }
        break;
    default:
        return SG_LIB_SYNTAX_ERROR;
    }
    return res;
}
