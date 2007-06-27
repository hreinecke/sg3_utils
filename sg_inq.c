#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
*  Copyright (C) 2000-2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI INQUIRY command.
   It is mainly based on the SCSI SPC-3 document at http://www.t10.org .

   Acknowledgment:
      - Martin Schwenke <martin at meltin dot net> added the raw switch and 
        other improvements [20020814]
      - Lars Marowsky-Bree <lmb at suse dot de> contributed Unit Path Report
        VPD page decoding for EMC CLARiiON devices [20041016]

From SPC-3 revision 16 the CmdDt bit in an INQUIRY is obsolete. There is
now a REPORT SUPPORTED OPERATION CODES command that yields similar
information [MAINTENANCE IN, service action = 0xc]. Support will be added
in the future.
   
*/

static char * version_str = "0.42 20041126";


#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define SUPPORTED_VPDS_VPD 0x0
#define UNIT_SERIAL_NUM_VPD 0x80
#define DEV_ID_VPD  0x83
#define X_INQ_VPD  0x86
#define SCSI_PORTS_VPD  0x88
#define UPR_EMC_VPD  0xc0
#define DEF_ALLOC_LEN 252
#define MX_ALLOC_LEN 4096

#define EBUFF_SZ 256


static unsigned char rsp_buff[MX_ALLOC_LEN + 1];
static char xtra_buff[MX_ALLOC_LEN + 1];

static int try_ata_identity(int ata_fd, int do_raw);
static const char * find_version_descriptor_str(int value);
static void decode_dev_ids(const char * leadin, unsigned char * buff,
                           int len, int do_hex);
static void decode_transport_id(const char * leadin, unsigned char * ucp,
                                int len);


static void usage()
{
    fprintf(stderr,
            "Usage: 'sg_inq [-c] [-cl] [-d] [-e] [-h|-r] [-i] "
            "[-o=<opcode_page>]\n"
            "               [-p=<vpd_page>] [-P] [-s] [-v] [-V] [-x] [-36]"
            " [-?]\n"
            "               <scsi_device>'\n"
            " where -c   set CmdDt mode (use -o for opcode) [obsolete]\n"
            "       -cl  list supported commands using CmdDt mode [obsolete]\n"
            "       -d   list version descriptors\n"
            "       -e   set VPD mode (use -p for page code)\n"
            "       -h   output in hex (ASCII to the right)\n"
            "       -i   decode device identification VPD page (0x83)\n"
            "       -o=<opcode_page> opcode or page code in hex (def: 0)\n"
            "       -p=<vpd_page> vpd page code in hex (def: 0)\n"
            "       -P   decode Unit Path Report VPD page (0xc0) (EMC)\n"
            "       -r   output raw binary data\n"
            "       -s   decode SCSI Ports VPD page (0x88)\n"
            "       -v   verbose (output cdb and, if non-zero, resid)\n"
            "       -V   output version string\n"
            "       -x   decode extented INQUIRY VPD page (0x86)\n"
            "       -36  only perform a 36 byte INQUIRY\n"
            "       -?   output this usage message\n"
            "   If no optional switches given then does"
            " a standard INQUIRY\n");
}


static void dStrRaw(const char* str, int len)
{
    int k;
    
    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

static const char * scsi_ptype_strs[] = {
    /* 0 */ "disk",
    "tape",
    "printer",
    "processor",
    "write once optical disk",
    /* 5 */ "cd/dvd",
    "scanner",
    "optical memory device",
    "medium changer",
    "communications",
    /* 0xa */ "graphics",
    "graphics",
    "storage array controller",
    "enclosure services device",
    "simplified direct access device",
    "optical card reader/writer device",
    /* 0x10 */ "bridging expander",
    "object based storage",
    "automation/driver interface",
};

static const char * get_ptype_str(int scsi_ptype)
{
    int num = sizeof(scsi_ptype_strs) / sizeof(scsi_ptype_strs[0]);

    if (0x1f == scsi_ptype)
        return "no physical device on this lu";
    else if (0x1e == scsi_ptype)
        return "well known logical unit";
    else
        return (scsi_ptype < num) ? scsi_ptype_strs[scsi_ptype] : "";
}

struct vpd_name {
    int number;
    int peri_type;
    char * name;
};

static struct vpd_name vpd_name_arr[] = {
    {0x0, 0, "Supported VPD pages"},
    {0x80, 0, "Unit serial number"},
    {0x81, 0, "Implemented operating definitions"},
    {0x82, 0, "ASCII implemented operating definition"},
    {0x83, 0, "Device identification"},
    {0x84, 0, "Software interface identification"},
    {0x85, 0, "Management network addresses"},
    {0x86, 0, "Extended INQUIRY data"},
    {0x87, 0, "Mode page policy"},
    {0x88, 0, "SCSI ports"},
    {0x89, 0, "ATA information"},
    {0xb0, 0, "Block limits (sbc2)"}, 
    {0xb0, 0x1, "SSC device capabilities (ssc3)"},
    {0xb0, 0x11, "OSD information (osd)"},
    {0xb1, 0x11, "Security token (osd)"},
    {0xc0, 0, "vendor: Firmware numbers (seagate); Unit path report (EMC)"},
    {0xc1, 0, "vendor: Date code (seagate)"},
    {0xc2, 0, "vendor: Jumper settings (seagate)"},
    {0xc3, 0, "vendor: Device behavior (seagate)"},
};

const char * get_vpd_page_str(int vpd_page_num, int scsi_ptype)
{
    int k;
    int vpd_name_arr_sz = 
        (int)(sizeof(vpd_name_arr) / sizeof(vpd_name_arr[0]));

    if ((vpd_page_num >= 0xb0) && (vpd_page_num < 0xc0)) {
        /* peripheral device type relevent for 0xb0..0xbf range */
        for (k = 0; k < vpd_name_arr_sz; ++k) {
            if ((vpd_name_arr[k].number == vpd_page_num) &&
                (vpd_name_arr[k].peri_type == scsi_ptype))
                break;
        }
        if (k < vpd_name_arr_sz)
            return vpd_name_arr[k].name;
        for (k = 0; k < vpd_name_arr_sz; ++k) {
            if ((vpd_name_arr[k].number == vpd_page_num) &&
                (vpd_name_arr[k].peri_type == 0))
                break;
        }
        if (k < vpd_name_arr_sz)
            return vpd_name_arr[k].name;
        else
            return NULL;
    } else {
        /* rest of 0x0..0xff range doesn't depend on peripheral type */
        for (k = 0; k < vpd_name_arr_sz; ++k) {
            if (vpd_name_arr[k].number == vpd_page_num)
                break;
        }
        if (k < vpd_name_arr_sz)
            return vpd_name_arr[k].name;
        else
            return NULL;
    }
}

static void decode_id_vpd(unsigned char * buff, int len, int do_hex)
{
    if (len < 4) {
        fprintf(stderr, "Device identification VPD page length too "
                "short=%d\n", len);
        return;
    }
    decode_dev_ids("Device identification", buff + 4, len - 4, do_hex);
}

static void decode_scsi_ports_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, rel_port, ip_tid_len, tpd_len;
    unsigned char * ucp;

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
            if (do_hex) {
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
            printf(" Target ports:\n");
            if (do_hex)
                dStrHex((const char *)(ucp + bump + 4), tpd_len, 1);
            else
                decode_dev_ids("SCSI Ports", ucp + bump + 4, tpd_len,
                               do_hex);
        }
        bump += tpd_len + 4;
    }
}
        
static const char * transport_proto_arr[] =
{
    "Fibre Channel (FCP-2)",
    "Parallel SCSI (SPI-5)",
    "SSA (SSA-S3P)",
    "IEEE 1394 (SBP-3)",
    "Remote Direct Memory Access (RDMA)",
    "Internet SCSI (iSCSI)",
    "Serial Attached SCSI (SAS)",
    "Automation/Drive Interface Transport Protocol (ADT)",
    "ATA Packet Interface (ATA/ATAPI-7)",
    "Ox9", "Oxa", "Oxb", "Oxc", "Oxd", "Oxe",
    "No specific protocol"
};

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

static const char * assoc_arr[] =
{
    "addressed logical unit",
    "SCSI target port",
    "SCSI target device",
    "reserved [0x3]",
};

static const char * id_type_arr[] =
{
    "vendor specific [0x0]",
    "T10 vendor identication",
    "EUI-64 based",
    "NAA",
    "Relative target port",
    "Target port group",
    "Logical unit group",
    "MD5 logical unit identifier",
    "SCSI name string",
    "Reserved [0x9]", "Reserved [0xa]", "Reserved [0xb]",
    "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};

/* These are target port, device server (i.e. target) and lu identifiers */
static void decode_dev_ids(const char * leadin, unsigned char * buff,
                           int len, int do_hex)
{
    int k, j, m, id_len, p_id, c_set, piv, assoc, id_type, i_len;
    int ci_off, c_id, d_id, naa, vsi;
    unsigned long long vsei;
    unsigned long long id_ext;
    const unsigned char * ucp;
    const unsigned char * ip;

    ucp = buff;
    for (k = 0, j = 1; k < len; k += id_len, ucp += id_len, ++j) {
        i_len = ucp[3];
        id_len = i_len + 4;
        if ((k + id_len) > len) {
            fprintf(stderr, "%s VPD page, short descriptor length=%d, "
                    "left=%d\n", leadin, id_len, (len - k));
            return;
        }
        printf("  Identification descriptor number %d, "
               "descriptor length: %d\n", j, id_len);
        ip = ucp + 4;
        p_id = ((ucp[0] >> 4) & 0xf);
        c_set = (ucp[0] & 0xf);
        piv = ((ucp[1] & 0x80) ? 1 : 0);
        assoc = ((ucp[1] >> 4) & 0x3);
        id_type = (ucp[1] & 0xf);
        if (piv && ((1 == assoc) || (2 == assoc)))
            printf("    transport: %s\n", transport_proto_arr[p_id]);
        printf("    id_type: %s,  code_set: %s\n", id_type_arr[id_type],
               code_set_arr[c_set]);
        printf("    associated with the %s\n", assoc_arr[assoc]);
        if (do_hex) {
            printf("    descriptor header(hex): %.2x %.2x %.2x %.2x\n",
                   ucp[0], ucp[1], ucp[2], ucp[3]);
            printf("    identifier:\n");
            dStrHex((const char *)ip, i_len, 0);
            continue;
        }
        switch (id_type) {
        case 0: /* vendor specific */
            dStrHex((const char *)ip, i_len, 0);
            break;
        case 1: /* T10 vendor identication */
            printf("      vendor id: %.8s\n", ip);
            if (i_len > 8)
                printf("      vendor specific: %.*s\n", i_len - 8, ip + 8);
            break;
        case 2: /* EUI-64 based */
            printf("      EUI-64 based %d byte identifier\n", i_len);
            if (1 != c_set) {
                printf("      << expected binary code_set (1)>>\n");
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
                printf("      Identifier extension: 0x%llx\n", id_ext);
            } else if ((8 != i_len) && (12 != i_len)) {
                printf("      << can only decode 8, 12 and 16 byte ids>>\n");
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
            printf("      Vendor Specific Extension Identifier: 0x%llx\n",
                   vsei);
            if (12 == i_len) {
                d_id = ((ip[8] << 24) | (ip[9] << 16) | (ip[10] << 8) |
                        ip[11]);
                printf("      Directory ID: 0x%x\n", d_id);
            }
            break;
        case 3: /* NAA */
            if (1 != c_set) {
                printf("      << expected binary code_set (1)>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            naa = (ip[0] >> 4) & 0xff;
            if (! ((2 == naa) || (5 == naa) || (6 == naa))) {
                printf("      << expected naa [0x%x]>>\n", naa);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            if (2 == naa) {
                if (8 != i_len) {
                    printf("      << expected NAA 2 identifier length: "
                           "0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, 0);
                    break;
                }
                d_id = (((ip[0] & 0xf) << 8) | ip[1]);
                c_id = ((ip[2] << 16) | (ip[3] << 8) | ip[4]);
                vsi = ((ip[5] << 16) | (ip[6] << 8) | ip[7]);
                printf("      NAA 2, vendor specific identifier A: 0x%x\n",
                       d_id);
                printf("      IEEE Company_id: 0x%x\n", c_id);
                printf("      vendor specific identifier B: 0x%x\n", vsi);
            } else if (5 == naa) {
                if (8 != i_len) {
                    printf("      << expected NAA 5 identifier length: "
                           "0x%x>>\n", i_len);
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
                printf("      NAA 5, IEEE Company_id: 0x%x\n", c_id);
                printf("      Vendor Specific Identifier: 0x%llx\n",
                       vsei);
            } else if (6 == naa) {
                if (16 != i_len) {
                    printf("      << expected NAA 6 identifier length: "
                           "0x%x>>\n", i_len);
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
                printf("      NAA 6, IEEE Company_id: 0x%x\n", c_id);
                printf("      Vendor Specific Identifier: 0x%llx\n",
                       vsei);
                vsei = 0;
                for (m = 0; m < 8; ++m) {
                    if (m > 0)
                        vsei <<= 8;
                    vsei |= ip[8 + m];
                }
                printf("      Vendor Specific Identifier Extension: "
                       "0x%llx\n", vsei);
            }
            break;
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                printf("      << expected binary code_set, target "
                       "port association, length 4>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            d_id = ((ip[2] << 8) | ip[3]);
            printf("      Relative target port: 0x%x\n", d_id);
            break;
        case 5: /* Target port group */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                printf("      << expected binary code_set, target "
                       "port association, length 4>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            d_id = ((ip[2] << 8) | ip[3]);
            printf("      Target port group: 0x%x\n", d_id);
            break;
        case 6: /* Logical unit group */
            if ((1 != c_set) || (0 != assoc) || (4 != i_len)) {
                printf("      << expected binary code_set, logical "
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
                printf("      << expected UTF-8 code_set>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            printf("      MD5 logical unit identifier:\n");
            // does %s print out UTF-8 ok??
            // Seems to depend on the locale. Looks ok here with my
            // locale setting: en_AU.UTF-8
            printf("      %s\n", (const char *)ip);
            break;
        default: /* reserved */
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
    }
}

/* Transport IDs are initiator port identifiers, typically other than the
   initiator port issuing a SCSI command. Borrowed from sg_persist.c */
static void decode_transport_id(const char * leadin, unsigned char * ucp,
                                int len)
{
    int format_code, proto_id, num, j, k;
    unsigned long long ull;
    int bump;

    for (k = 0, bump; k < len; k += bump, ucp += bump) {
        if ((len < 24) || (0 != (len % 4)))
            printf("%sTransport Id short or not multiple of 4 "
                   "[length=%d]:\n", leadin, len);
        else
            printf("%sTransport Id of initiator:\n", leadin);
        format_code = ((ucp[0] >> 6) & 0x3);
        proto_id = (ucp[0] & 0xf);
        switch (proto_id) {
        case 0: /* Fibre channel */
            printf("%s  FCP-2 World Wide Name:\n", leadin);
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, 0);
            bump = 24;
            break;
        case 1: /* Parallel SCSI */
            printf("%s  Parallel SCSI initiator SCSI address: 0x%x\n",
                   leadin, ((ucp[2] << 8) | ucp[3]));
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            printf("%s  relative port number (of corresponding target): "
                   "0x%x\n", leadin, ((ucp[6] << 8) | ucp[7]));
            bump = 24;
            break;
        case 2: /* SSA */
            printf("%s  SSA (transport id not defined):\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case 3: /* IEEE 1394 */
            printf("%s  IEEE 1394 EUI-64 name:\n", leadin);
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, 0);
            bump = 24;
            break;
        case 4: /* Remote Direct Memory Access (RDMA) */
            printf("%s  RDMA initiator port identifier:\n", leadin);
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 16, 0);
            bump = 24;
            break;
        case 5: /* iSCSI */
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
        case 6: /* SAS */
            ull = 0;
            for (j = 0; j < 8; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= ucp[4 + j];
            }
            printf("%s  SAS address: 0x%llx\n", leadin, ull);
            if (0 != format_code) 
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            bump = 24;
            break;
        case 7: /* Automation/Drive Interface Transport Protocol */
            printf("%s  ADT:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case 8: /* ATAPI */
            printf("%s  ATAPI:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
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

static void decode_x_inq_vpd(unsigned char * buff, int len, int do_hex)
{
    if (len < 7) {
        fprintf(stderr, "Extended INQUIRY VPD page length too short=%d\n",
                len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    printf("  RTO=%d GRD_CHK=%d APP_CHK=%d REF_CHK=%d\n", !!(buff[4] & 0x8),
           !!(buff[4] & 0x4), !!(buff[4] & 0x2), !!(buff[4] & 0x1));
    printf("  GRP_SUP=%d PRIOR_SUP=%d HEADSUP=%d ORDSUP=%d SIMPSUP=%d\n",
           !!(buff[5] & 0x10), !!(buff[5] & 0x8), !!(buff[5] & 0x4),
           !!(buff[5] & 0x2), !!(buff[5] & 0x1));
    printf("  NV_SUP=%d V_SUP=%d", !!(buff[6] & 0x2), !!(buff[6] & 0x1));
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

static void decode_upr_vpd_c0_emc(unsigned char * buff, int len)
{
    int k, ip_mgmt, failover_mode, vpp80, lun_z;

    if (len < 3) {
        fprintf(stderr, "Device identification VPD page length too "
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
        printf("%hhx", buff[10 + k]);
    printf("\n");
    printf("  Array Serial Number: ");
    dStrRaw((const char *)&buff[50], buff[49]);
    printf("\n");

    printf("  LUN State: ");
    if (buff[4] > 0x02)
           printf("Unknown (%hhx)\n", buff[4]);
    else
           printf("%s\n", lun_state_arr[buff[4]]);

    printf("  This path connects to: ");
    if (buff[8] > 0x01)
           printf("Unknown SP (%hhx)", buff[8]);
    else
           printf("%s", sp_arr[buff[8]]);
    printf(", Port Number: %u\n", buff[7]);

    printf("  Default Owner: ");
    if (buff[5] > 0x01)
           printf("Unknown (%hhx)\n", buff[5]);
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
            printf("%hhx", buff[32 + k]);
        printf("\n");
    }

    failover_mode = buff[28] & 0x0f;
    vpp80 = buff[30] & 0x08;
    lun_z = buff[30] & 0x04;

    printf("  System Type: %hhx, Failover mode: %s\n",
                   buff[27],
                   failover_mode == 4 ? "Set to 1" : "Unknown");

    printf("  Inquiry VPP 0x80 returns: %s, Arraycommpath: %s\n",
                   vpp80 ? "array serial#" : "LUN serial#",
                   lun_z ? "Set to 1" : "Unknown");

    printf("  Lun operations: %s\n",
               buff[48] > 1 ? "undefined" : lun_op_arr[buff[48]]);

    return;
}

/* Returns 0 if Unit Serial Number VPD page contents found, else -1 */
static int fetch_unit_serial_num(int sg_fd, char * obuff, int obuff_len,
                                 int verbose)
{
    int sz, len, k;
    unsigned char b[DEF_ALLOC_LEN];

    sz = sizeof(b);
    memset(b, 0xff, 4); /* guard against empty response */
    /* first check if unit serial number VPD page is supported */
    if ((0 == sg_ll_inquiry(sg_fd, 0, 1, SUPPORTED_VPDS_VPD, b, sz, 0,
                            verbose)) &&
        (SUPPORTED_VPDS_VPD == b[1]) && (0x0 == b[2])) {
        len = b[3];
        for (k = 0; k < len; ++k) {
            if (UNIT_SERIAL_NUM_VPD == b[k + 4])
                break;
        }
        if ((k < len) &&
            (0 == sg_ll_inquiry(sg_fd, 0, 1, UNIT_SERIAL_NUM_VPD,
                                b, sz, 0, verbose))) {
            len = b[3];
            len = (len < (obuff_len - 1)) ? len : (obuff_len - 1);
            if ((UNIT_SERIAL_NUM_VPD == b[1]) && (len > 0)) {
                memcpy(obuff, b + 4, len);
                obuff[len] = '\0';
                return 0;
            }
        }
    }
    return -1;
}

static const char * ansi_version_arr[] =
{
    "no conformance claimed",
    "SCSI-1",
    "SCSI-2",
    "SPC",
    "SPC-2",
    "SPC-3",
    "SPC-4",
    "ANSI version: 7",
};

static const char * get_ansi_version_str(int version, char * buff,
                                         int buff_len)
{
    version &= 0x7;
    buff[buff_len - 1] = '\0';
    strncpy(buff, ansi_version_arr[version], buff_len - 1);
    return buff;
}


/* Returns 0 if successful */
static int process_std_inq(int sg_fd, const char * file_name, int do_36,
                           int peri_type, int do_vdescriptors, int do_hex,
                           int do_raw, int do_verbose)
{
    int res, len, act_len, ansi_version, ret, k, j;
    const char * cp;
    int vdesc_arr[8];
    char buff[32];

    memset(vdesc_arr, 0, sizeof(vdesc_arr));
    res = sg_ll_inquiry(sg_fd, 0, 0, 0, rsp_buff, 36, 0, do_verbose);
    if (0 == res) {
        if (!do_raw)
            printf("standard INQUIRY:\n");
        len = rsp_buff[4] + 5;
        ansi_version = rsp_buff[2] & 0x7;
        peri_type = rsp_buff[0] & 0x1f;
        if ((len > 36) && (len < 256) && (! do_36)) {
            if (sg_ll_inquiry(sg_fd, 0, 0, 0, rsp_buff, len, 1, do_verbose)) {
                fprintf(stderr, "second INQUIRY (%d byte) failed\n", len);
                return 1;
            }
            if (len != (rsp_buff[4] + 5)) {
                fprintf(stderr,
                        "strange, twin INQUIRYs yield different "
                        "'additional length'\n");
                ret = 2;
            }
        }
        if (do_36) {
            act_len = len;
            len = 36;
        }
        else
            act_len = len;
        if (do_hex)
            dStrHex((const char *)rsp_buff, len, 0);
        else if (do_raw)
            dStrRaw((const char *)rsp_buff, len);
        else {
            printf("  PQual=%d  Device_type=%d  RMB=%d  version=0x%02x ",
                   (rsp_buff[0] & 0xe0) >> 5, peri_type,
                   !!(rsp_buff[1] & 0x80), (unsigned int)rsp_buff[2]);
            printf(" [%s]\n", get_ansi_version_str(ansi_version, buff,
                                                   sizeof(buff)));
            printf("  [AERC=%d]  [TrmTsk=%d]  NormACA=%d  HiSUP=%d "
                   " Resp_data_format=%d\n  SCCS=%d  ",
                   !!(rsp_buff[3] & 0x80), !!(rsp_buff[3] & 0x40),
                   !!(rsp_buff[3] & 0x20), !!(rsp_buff[3] & 0x10),
                   rsp_buff[3] & 0x0f, !!(rsp_buff[5] & 0x80));
            printf("ACC=%d  TGPS=%d  3PC=%d  Protect=%d\n",
                   !!(rsp_buff[5] & 0x40), ((rsp_buff[5] & 0x30) >> 4),
                   !!(rsp_buff[5] & 0x08), !!(rsp_buff[5] & 0x01));
            printf("  BQue=%d  EncServ=%d  MultiP=%d  MChngr=%d  "
                   "[ACKREQQ=%d]  ",
                   !!(rsp_buff[6] & 0x80), !!(rsp_buff[6] & 0x40), 
                   !!(rsp_buff[6] & 0x10), !!(rsp_buff[6] & 0x08), 
                   !!(rsp_buff[6] & 0x04));
            printf("Addr16=%d\n  [RelAdr=%d]  ",
                   !!(rsp_buff[6] & 0x01),
                   !!(rsp_buff[7] & 0x80));
            printf("WBus16=%d  Sync=%d  Linked=%d  [TranDis=%d]  ",
                   !!(rsp_buff[7] & 0x20), !!(rsp_buff[7] & 0x10),
                   !!(rsp_buff[7] & 0x08), !!(rsp_buff[7] & 0x04));
            printf("CmdQue=%d\n", !!(rsp_buff[7] & 0x02));
            if (len > 56)
                printf("  Clocking=0x%x  QAS=%d  IUS=%d\n",
                       (rsp_buff[56] & 0x0c) >> 2, !!(rsp_buff[56] & 0x2),
                       !!(rsp_buff[56] & 0x1));
            if (act_len == len)
                printf("    length=%d (0x%x)", len, len);
            else
                printf("    length=%d (0x%x), but only read 36 bytes", 
                       len, len);
            if ((ansi_version >= 2) && (len < 36))
                printf("  [for SCSI>=2, len>=36 is expected]");
            cp = get_ptype_str(peri_type);
            if (strlen(cp) > 0)
                printf("   Peripheral device type: %s\n", cp);

            if (len <= 8)
                printf(" Inquiry response length=%d, no vendor, "
                       "product or revision data\n", len);
            else {
                if (len < 36)
                    rsp_buff[len] = '\0';
                memcpy(xtra_buff, &rsp_buff[8], 8);
                xtra_buff[8] = '\0';
                printf(" Vendor identification: %s\n", xtra_buff);
                if (len <= 16)
                    printf(" Product identification: <none>\n");
                else {
                    memcpy(xtra_buff, &rsp_buff[16], 16);
                    xtra_buff[16] = '\0';
                    printf(" Product identification: %s\n", xtra_buff);
                }
                if (len <= 32)
                    printf(" Product revision level: <none>\n");
                else {
                    memcpy(xtra_buff, &rsp_buff[32], 4);
                    xtra_buff[4] = '\0';
                    printf(" Product revision level: %s\n", xtra_buff);
                }
                if (do_vdescriptors) {
                    for (j = 0, k = 58; ((j < 8) && ((k + 1) < len));
                         k +=2, ++j) 
                        vdesc_arr[j] = ((rsp_buff[k] << 8) +
                                         rsp_buff[k + 1]);
                }
            }
        }
        if (! (do_raw || do_hex)) {
            if (0 == fetch_unit_serial_num(sg_fd, xtra_buff,
                                           sizeof(xtra_buff), do_verbose))
                printf(" Unit serial number: %s\n", xtra_buff);
            if (do_vdescriptors) {
                if (0 == vdesc_arr[0])
                    printf("\n  No version descriptors available\n");
                else {
                    printf("\n  Version descriptors:\n");
                    for (k = 0; k < 8; ++k) {
                        if (0 == vdesc_arr[k])
                            break;
                        cp = find_version_descriptor_str(vdesc_arr[k]);
                        if (cp)
                            printf("    %s\n", cp);
                        else
                            printf("    [unrecognised version descriptor "
                                   "code: 0x%x]\n", vdesc_arr[k]);
                    }
                }
            }
        }
    }
    else if (-1 == res) { /* could be an ATA device */
        /* Try an ATA Identity command */
        res = try_ata_identity(sg_fd, do_raw);
        if (0 != res) {
            fprintf(stderr, "Both SCSI INQUIRY and ATA IDENTITY failed "
                    "on %s with this error:\n\t%s\n", file_name, 
                    safe_strerror(res));
            return 1;
        }
    } else {        /* SCSI device not supporting 36 byte INQUIRY?? */
        printf("36 byte INQUIRY failed\n");
        return 1;
    }
    return 0;
}

/* Returns 0 if successful */
static int process_cmddt(int sg_fd, int do_cmdlst, int num_opcode,
                         int peri_type, int do_hex, int do_raw,
                         int do_verbose)
{
    int k, j, num, len, reserved_cmddt, support_num;
    char op_name[128];

    if (do_cmdlst) {
        printf("Supported command list:\n");
        for (k = 0; k < 256; ++k) {
            if (0 == sg_ll_inquiry(sg_fd, 1, 0, k, rsp_buff, DEF_ALLOC_LEN,
                                   1, do_verbose)) {
                support_num = rsp_buff[1] & 7;
                reserved_cmddt = rsp_buff[4];
                if ((3 == support_num) || (5 == support_num)) {
                    num = rsp_buff[5];
                    for (j = 0; j < num; ++j)
                        printf(" %.2x", (int)rsp_buff[6 + j]);
                    if (5 == support_num)
                        printf("  [vendor specific manner (5)]");
                    sg_get_opcode_name((unsigned char)k, peri_type,
                                       sizeof(op_name) - 1, op_name);
                    op_name[sizeof(op_name) - 1] = '\0';
                    printf("  %s\n", op_name);
                } else if ((4 == support_num) || (6 == support_num))
                    printf("  opcode=0x%.2x vendor specific (%d)\n",
                           k, support_num);
                else if ((0 == support_num) && (reserved_cmddt > 0)) {
                    printf("  opcode=0x%.2x ignored cmddt bit, "
                           "given standard INQUIRY response, stop\n", k);
                    break;
                }
            }
            else {
                fprintf(stderr,
                        "CmdDt INQUIRY on opcode=0x%.2x: failed\n", k);
                break;
            }
        }
    }
    else {
        if (! do_raw) {
            printf("CmdDt INQUIRY, opcode=0x%.2x:  [", num_opcode);
            sg_get_opcode_name((unsigned char)num_opcode, peri_type, 
                               sizeof(op_name) - 1, op_name);
            op_name[sizeof(op_name) - 1] = '\0';
            printf("%s]\n", op_name);
        }
        if (0 == sg_ll_inquiry(sg_fd, 1, 0, num_opcode, rsp_buff, 
                               DEF_ALLOC_LEN, 1, do_verbose)) {
            len = rsp_buff[5] + 6;
            reserved_cmddt = rsp_buff[4];
            if (do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                const char * desc_p;
                int prnt_cmd = 0;

                support_num = rsp_buff[1] & 7;
                num = rsp_buff[5];
                switch (support_num) {
                case 0: 
                    if (0 == reserved_cmddt)
                        desc_p = "no data available"; 
                    else
                        desc_p = "ignored cmddt bit, standard INQUIRY "
                                 "response";
                    break;
                case 1: desc_p = "not supported"; break;
                case 2: desc_p = "reserved (2)"; break;
                case 3: desc_p = "supported as per standard"; 
                        prnt_cmd = 1;
                        break;
                case 4: desc_p = "vendor specific (4)"; break;
                case 5: desc_p = "supported in vendor specific way";
                        prnt_cmd = 1; 
                        break;
                case 6: desc_p = "vendor specific (6)"; break;
                case 7: desc_p = "reserved (7)"; break;
                default: desc_p = "impossible value > 7"; break;
                }
                if (prnt_cmd) {
                    printf("  Support field: %s [", desc_p);
                    for (j = 0; j < num; ++j)
                        printf(" %.2x", (int)rsp_buff[6 + j]);
                    printf(" ]\n");
                } else
                    printf("  Support field: %s\n", desc_p);
            }
        }
        else {
            fprintf(stderr,
                    "CmdDt INQUIRY on opcode=0x%.2x: failed\n",
                    num_opcode);
            return 1;
        }
    }
    return 0;
}

/* Returns 0 if successful */
static int process_evpd(int sg_fd, int num_opcode, int peri_type,
                        int do_hex, int do_raw, int do_verbose)
{
    int ret, len, num, k, vpd;
    const char * cp;

    if (!do_raw)
        printf("VPD INQUIRY, page code=0x%.2x:\n", num_opcode);
    if (0 == sg_ll_inquiry(sg_fd, 0, 1, num_opcode, rsp_buff, DEF_ALLOC_LEN,
                           1, do_verbose)) {
        len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
        ret = 3;
        if (num_opcode != rsp_buff[1]) {
            fprintf(stderr, "invalid VPD response; probably a STANDARD "
                    "INQUIRY response\n");
            return 1;
        }
        if (len > MX_ALLOC_LEN) {
            fprintf(stderr, "response length too long: %d > %d\n", len,
                   MX_ALLOC_LEN);
            return 1;
        } else if (len > DEF_ALLOC_LEN) {
            if (sg_ll_inquiry(sg_fd, 0, 1, num_opcode, rsp_buff, len, 1, 
                              do_verbose))
                return 1;
        }
        ret = 0;
        if (do_raw)
            dStrRaw((const char *)rsp_buff, len);
        else {
            if (do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else if (0 == num_opcode) { /* decode this mandatory page */
                peri_type = rsp_buff[0] & 0x1f;
                printf("   [PQual=%d  Peripheral device type: %s]\n",
                       (rsp_buff[0] & 0xe0) >> 5, 
                       get_ptype_str(peri_type));
                printf("   Supported VPD pages:\n");
                num = rsp_buff[3];
                for (k = 0; k < num; ++k) {
                    vpd = rsp_buff[4 + k];
                    cp = get_vpd_page_str(vpd, peri_type);
                    if (cp)
                        printf("     0x%x\t%s\n", vpd, cp);
                    else
                        printf("     0x%x\n", vpd);
                }
            } else {
                printf(" Only hex output supported\n");
                dStrHex((const char *)rsp_buff, len, 0);
            }
        }
    }
    else {
        fprintf(stderr,
                "VPD INQUIRY, page code=0x%.2x: failed\n", num_opcode);
        return 1;
    }
    return 0;
}


int main(int argc, char * argv[])
{
    int sg_fd, k, num, len;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned int num_opcode = 0; /* SUPPORTED_VPDS_VPD == 0 */
    int num_opcode_given = 0;
    int p_switch_given = 0;
    int do_evpd = 0;
    int do_cmddt = 0;
    int do_cmdlst = 0;
    int do_di_vpd = 0;
    int do_hex = 0;
    int do_raw = 0;
    int do_scsi_ports_vpd = 0;
    int do_xtended = 0;
    int do_upr_c0_emc = 0;
    int do_36 = 0;
    int do_vdescriptors = 0;
    int do_verbose = 0;
    int decode = 0;
    int oflags = O_RDONLY | O_NONBLOCK;
    int ret = 0;
    int peri_type = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-36", argv[k]))
            do_36 = 1;
        else if (0 == strcmp("-c", argv[k]))
            do_cmddt = 1;
        else if (0 == strcmp("-cl", argv[k])) {
            do_cmdlst = 1;
            do_cmddt = 1;
        } else if (0 == strcmp("-d", argv[k]))
            do_vdescriptors = 1;
        else if (0 == strcmp("-e", argv[k]))
            do_evpd = 1;
        else if (0 == strcmp("-h", argv[k]))
            do_hex = 1;
        else if (0 == strcmp("-i", argv[k]))
            do_di_vpd = 1;
        else if (0 == strncmp("-o=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &num_opcode);
            if ((1 != num) || (num_opcode > 255)) {
                fprintf(stderr, "Bad number after '-p' or '-o' switch\n");
                file_name = 0;
                break;
            }
            num_opcode_given = 1;
        }
        else if (0 == strncmp("-p=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &num_opcode);
            if ((1 != num) || (num_opcode > 255)) {
                fprintf(stderr, "Bad number after '-p' switch\n");
                file_name = 0;
                break;
            }
            num_opcode_given = 1;
            p_switch_given = 1;
        } else if (0 == strcmp("-P", argv[k]))
            do_upr_c0_emc = 1;
        else if (0 == strcmp("-r", argv[k]))
            do_raw = 1;
        else if (0 == strcmp("-s", argv[k]))
            do_scsi_ports_vpd = 1;
        else if (0 == strcmp("-v", argv[k]))
            ++do_verbose;
        else if (0 == strcmp("-x", argv[k]))
            do_xtended = 1;
        else if (0 == strcmp("-?", argv[k])) {
            file_name = 0;
            break;
        }
        else if (0 == strcmp("-V", argv[k])) {
            fprintf(stderr, "Version string: %s\n", version_str);
            exit(0);
        }
        else if (*argv[k] == '-') {
            fprintf(stderr, "Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            fprintf(stderr, "too many arguments\n");
            file_name = 0;
            break;
        }
    }
    
    decode = do_di_vpd + do_xtended + do_upr_c0_emc + do_scsi_ports_vpd;
    if (do_raw && do_hex) {
        fprintf(stderr, "Can't do hex and raw at the same time\n");
        file_name = 0;
    }
    if (decode > 1) {
        fprintf(stderr, "Can only have one of '-i', '-P', '-s' or '-x'\n");
        file_name = 0;
    } else if (decode && (do_cmddt || do_evpd || num_opcode_given)) {
        fprintf(stderr, "Can't use '-i', '-P', '-s' or '-x' with other VPD "
                "or CmdDt flags\n");
        file_name = 0;
    }
    if (0 == file_name) {
        usage();
        return 1;
    }
    if ((! (decode || do_cmddt || do_evpd)) &&
        num_opcode_given) {
        do_evpd = 1;    /* '-o' implies '-e' unless explicitly overridden */
        if (! (do_raw || p_switch_given))
            printf(" <<given page_code so assumed EVPD selected>>\n");
    }
    if (do_vdescriptors) {
        if (do_cmddt || do_evpd || do_36) {
            if (do_36)
                fprintf(stderr, "Can't use '-d' with 36 byte INQUIRY\n");
            else
                fprintf(stderr, "Can't use '-d' with VPD or CmdDt flags\n");
            usage();
            return 1;
        }
    }

    if ((sg_fd = open(file_name, oflags)) < 0) {
        snprintf(ebuff, EBUFF_SZ, "sg_inq: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    memset(rsp_buff, 0, MX_ALLOC_LEN + 1);

    if (! (do_cmddt || do_evpd || decode)) {
        /* So it's a Standard INQUIRY */
        if (process_std_inq(sg_fd, file_name, do_36, peri_type,
                            do_vdescriptors, do_hex, do_raw, do_verbose))
            return 1;
    } else if (do_cmddt) {
        if (process_cmddt(sg_fd, do_cmdlst, num_opcode, peri_type,
                          do_hex, do_raw, do_verbose))
            return 1;
    } else if (do_evpd) {
        if (process_evpd(sg_fd, num_opcode, peri_type,
                          do_hex, do_raw, do_verbose))
            return 1;
    } else if (do_di_vpd) {
        if (!do_raw)
            printf("VPD INQUIRY: Device Identification page\n");
        if (0 == sg_ll_inquiry(sg_fd, 0, 1, DEV_ID_VPD, rsp_buff,
                               DEF_ALLOC_LEN, 1, do_verbose)) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            ret = 3;
            if (DEV_ID_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                goto err_out;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                goto err_out;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, DEV_ID_VPD, rsp_buff, len,
                                  1, do_verbose))
                    goto err_out;
            }
            ret = 0;
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_id_vpd(rsp_buff, len, do_hex);
        }
    } else if (do_xtended) {
        if (!do_raw)
            printf("VPD INQUIRY: extended INQUIRY page\n");
        if (0 == sg_ll_inquiry(sg_fd, 0, 1, X_INQ_VPD, rsp_buff,
                               DEF_ALLOC_LEN, 1, do_verbose)) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            ret = 3;
            if (X_INQ_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                goto err_out;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                goto err_out;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, X_INQ_VPD, rsp_buff, len,
                                  1, do_verbose))
                    goto err_out;
            }
            ret = 0;
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_x_inq_vpd(rsp_buff, len, do_hex);
        }
    } else if (do_upr_c0_emc) {
        if (!do_raw)
            printf("VPD INQUIRY: Unit Path Report Page (EMC)\n");
        if (0 == sg_ll_inquiry(sg_fd, 0, 1, UPR_EMC_VPD, rsp_buff,
                               DEF_ALLOC_LEN, 1, do_verbose)) {
            len = rsp_buff[3] + 3;
            ret = 3;
            if (UPR_EMC_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                goto err_out;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                goto err_out;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, UPR_EMC_VPD, rsp_buff, len, 1,
                           do_verbose))
                    goto err_out;
            }
            ret = 0;
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (do_hex)
                dStrHex((const char *)rsp_buff, len, 1);
            else
                decode_upr_vpd_c0_emc(rsp_buff, len);
        }
    } else if (do_scsi_ports_vpd) {
        if (!do_raw)
            printf("VPD INQUIRY: SCSI Ports page\n");
        if (0 == sg_ll_inquiry(sg_fd, 0, 1, SCSI_PORTS_VPD, rsp_buff,
                               DEF_ALLOC_LEN, 1, do_verbose)) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            ret = 3;
            if (SCSI_PORTS_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                goto err_out;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                goto err_out;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, SCSI_PORTS_VPD, rsp_buff, len,
                                  1, do_verbose))
                    goto err_out;
            }
            ret = 0;
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_scsi_ports_vpd(rsp_buff, len, do_hex);
        }
    }

err_out:
    close(sg_fd);
    return ret;
}


/* Following code permits ATA IDENTITY commands to be performed on
   ATA non "Packet Interface" devices (e.g. ATA disks).
   GPL-ed code borrowed from smartmontools (smartmontools.sf.net).
   Copyright (C) 2002-4 Bruce Allen 
                <smartmontools-support@lists.sourceforge.net>
 */
#ifndef ATA_IDENTIFY_DEVICE
#define ATA_IDENTIFY_DEVICE 0xec
#endif
#ifndef HDIO_DRIVE_CMD
#define HDIO_DRIVE_CMD    0x031f
#endif

/* Needed parts of the ATA DRIVE IDENTIFY Structure. Those labeled
 * word* are NOT used.
 */
struct ata_identify_device {
  unsigned short words000_009[10];
  unsigned char  serial_no[20];
  unsigned short words020_022[3];
  unsigned char  fw_rev[8];
  unsigned char  model[40];
  unsigned short words047_079[33];
  unsigned short major_rev_num;
  unsigned short minor_rev_num;
  unsigned short command_set_1;
  unsigned short command_set_2;
  unsigned short command_set_extension;
  unsigned short cfs_enable_1;
  unsigned short word086;
  unsigned short csf_default;
  unsigned short words088_255[168];
};

/* Copies n bytes (or n-1 if n is odd) from in to out, but swaps adjacents
 * bytes.
 */
static void swapbytes(char *out, const char *in, size_t n)
{
    size_t k;

    if (n > 1) {
        for (k = 0; k < (n - 1); k += 2) {
            out[k] = in[k + 1];
            out[k + 1] = in[k];
        }
    }
}

/* Copies in to out, but removes leading and trailing whitespace. */
static void trim(char *out, const char *in)
{
    int k, first, last;

    /* Find the first non-space character (maybe none). */
    first = -1;
    for (k = 0; in[k]; k++) {
        if (! isspace((int)in[k])) {
            first = k;
            break;
        }
    }

    if (first == -1) {
        /* There are no non-space characters. */
        out[0] = '\0';
        return;
    }

    /* Find the last non-space character. */
    for (k = strlen(in) - 1; k >= first && isspace((int)in[k]); k--)
        ;
    last = k;
    strncpy(out, in + first, last - first + 1);
    out[last - first + 1] = '\0';
}

/* Convenience function for formatting strings from ata_identify_device */
static void formatdriveidstring(char *out, const char *in, int n)
{
    char tmp[65];

    n = n > 64 ? 64 : n;
    swapbytes(tmp, in, n);
    tmp[n] = '\0';
    trim(out, tmp);
}

/* Function for printing ASCII byte-swapped strings, skipping white
 * space. Please note that this is needed on both big- and
 * little-endian hardware.
 */
static void printswap(char *output, char *in, unsigned int n)
{
    formatdriveidstring(output, in, n);
    if (*output)
        printf("%.*s   ", (int)n, output);
    else
        printf("%.*s   ", (int)n, "[No Information Found]\n");
}

#define ATA_IDENTITY_BUFF_SZ  sizeof(struct ata_identify_device)

static int ata_command_interface(int device, char *data)
{
    const int HDIO_DRIVE_CMD_OFFSET = 4;
    unsigned char buff[ATA_IDENTITY_BUFF_SZ + HDIO_DRIVE_CMD_OFFSET];
    int retval; 

    buff[0] = ATA_IDENTIFY_DEVICE;
    buff[3] = 1;
    /* We are now doing the HDIO_DRIVE_CMD type ioctl. */
    if ((retval = ioctl(device, HDIO_DRIVE_CMD, buff)))
        return errno;

    /* if the command returns data, copy it back */
    memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTITY_BUFF_SZ);
    return 0;
}

/* Returns 0 if successful, else errno of error */
static int try_ata_identity(int ata_fd, int do_raw)
{
    struct ata_identify_device ata_ident;
    char model[64];
    char serial[64];
    char firm[64];
    int res;

    res = ata_command_interface(ata_fd, (char *)&ata_ident);
    if (res)
        return res;
    if (do_raw)
        dStrRaw((const char *)&ata_ident, 256);
    else {
        printf("ATA device (probably a disk):\n");
        printf("    ");
        printswap(model, (char *)ata_ident.model, 40);
        printswap(serial, (char *)ata_ident.serial_no, 20);
        printswap(firm, (char *)ata_ident.fw_rev, 8);
        printf("\n");
    }
    return 0;
}

struct version_descriptor {
    int value;
    const char * name;
};

/* table from SPC-3 revision 21 [sorted numerically (Annex D listing)] */
static struct version_descriptor version_descriptor_arr[] = {
    {0x0, "Version Descriptor not supported or No standard identified"},
    {0x20, "SAM (no version claimed)"},
    {0x3b, "SAM T10/0994-D revision 18"},
    {0x3c, "SAM ANSI X3.270:1996"},
    {0x40, "SAM-2 (no version claimed)"},
    {0x54, "SAM-2 T10/1157-D revision 23"},
    {0x55, "SAM-2 T10/1157-D revision 24"},
    {0x5c, "SAM-2 ANSI INCITS.366:2003"},
    {0x60, "SAM-3 (no version claimed)"},
    {0x62, "SAM-3 T10/1561-D revision 7"},
    {0x75, "SAM-3 T10/1561-D revision 13"},
    {0x76, "SAM-3 T10/1561-D revision 14"},
    {0x80, "SAM-4 (no version claimed)"},
    {0x120, "SPC (no version claimed)"},
    {0x13b, "SPC T10/0995-D revision 11a"},
    {0x13c, "SPC ANSI X3.301:1997"},
    {0x140, "MMC (no version claimed)"},
    {0x15b, "MMC T10/1048-D revision 10a"},
    {0x15c, "MMC ANSI X3.304:1997"},
    {0x160, "SCC (no version claimed)"},
    {0x17b, "SCC T10/1047-D revision 06c"},
    {0x17c, "SCC ANSI X3.276:1997"},
    {0x180, "SBC (no version claimed)"},
    {0x19b, "SBC T10/0996-D revision 08c"},
    {0x19c, "SBC ANSI X3.306:1998"},
    {0x1a0, "SMC (no version claimed)"},
    {0x1bb, "SMC T10/0999-D revision 10a"},
    {0x1bc, "SMC ANSI NCITS.314:1998"},
    {0x1c0, "SES (no version claimed)"},
    {0x1db, "SES T10/1212-D revision 08b"},
    {0x1dc, "SES ANSI NCITS.305:1998"},
    {0x1dd, "SES T10/1212-D revision 08b w/ Amendment ANSI "
            "NCITS.305/AM1:2000"},
    {0x1de, "SES ANSI NCITS.305:1998 w/ Amendment ANSI "
            "NCITS.305/AM1:2000"},
    {0x1e0, "SCC-2 (no version claimed}"},
    {0x1fb, "SCC-2 T10/1125-D revision 04"},
    {0x1fc, "SCC-2 ANSI NCITS.318:1998"},
    {0x200, "SSC (no version claimed)"},
    {0x201, "SSC T10/0997-D revision 17"},
    {0x207, "SSC T10/0997-D revision 22"},
    {0x21c, "SSC ANSI NCITS.335:2000"},
    {0x220, "RBC (no version claimed)"},
    {0x238, "RBC T10/1240-D revision 10a"},
    {0x23c, "RBC ANSI NCITS.330:2000"},
    {0x240, "MMC-2 (no version claimed)"},
    {0x255, "MMC-2 T10/1228-D revision 11"},
    {0x25b, "MMC-2 T10/1228-D revision 11a"},
    {0x25c, "MMC-2 ANSI NCITS.333:2000"},
    {0x260, "SPC-2 (no version claimed)"},
    {0x267, "SPC-2 T10/1236-D revision 12"},
    {0x269, "SPC-2 T10/1236-D revision 18"},
    {0x275, "SPC-2 T10/1236-D revision 19"},
    {0x276, "SPC-2 T10/1236-D revision 20"},
    {0x277, "SPC-2 ANSI NCITS.351:2001"},
    {0x280, "OCRW (no version claimed)"},
    {0x29e, "OCRW ISI/IEC 14776-382"},
    {0x2a0, "MMC-3 (no version claimed)"},
    {0x2b5, "MMC-3 T10/1363-D revision 9"},
    {0x2b6, "MMC-3 T10/1363-D revision 10g"},
    {0x2b8, "MMC-3 ANSI NCITS.360:2002"},
    {0x2e0, "SMC-2 (no version claimed)"},
    {0x2f5, "SMC-2 T10/1383-D revision 5"},
    {0x2fc, "SMC-2 T10/1383-D revision 6"},
    {0x2fd, "SMC-2 T10/1383-D revision 7"},
    {0x300, "SPC-3 (no version claimed)"},
    {0x301, "SPC-3 T10/1416-D revision 7"},
    {0x307, "SPC-3 T10/1416-D revision 21"},
    {0x320, "SBC-2 (no version claimed)"},
    {0x322, "SBC-2 T10/1417-D revision 5a"},
    {0x324, "SBC-2 T10/1417-D revision 15"},
    {0x340, "OSD (no version claimed)"},
    {0x341, "OSD T10/1355-D revision 0"},
    {0x342, "OSD T10/1355-D revision 7a"},
    {0x343, "OSD T10/1355-D revision 8"},
    {0x344, "OSD T10/1355-D revision 9"},
    {0x355, "OSD T10/1355-D revision 10"},
    {0x360, "SSC-2 (no version claimed)"},
    {0x374, "SSC-2 T10/1434-D revision 7"},
    {0x375, "SSC-2 T10/1434-D revision 9"},
    {0x37d, "SSC-2 ANSI NCITS.380:2003"},
    {0x380, "BCC (no version claimed)"},
    {0x3a0, "MMC-4 (no version claimed)"},
    {0x3bd, "MMC-4 T10/1545-D revision 3"},
    {0x3be, "MMC-4 T10/1545-D revision 3d"},
    {0x3c0, "ADC (no version claimed)"},
    {0x3d5, "ADC T10/1558-D revision 6"},
    {0x3d6, "ADC T10/1558-D revision 7"},
    {0x3e0, "SES-2 (no version claimed)"},
    {0x400, "SSC-3 (no version claimed)"},
    {0x420, "MMC-5 (no version claimed)"},
    {0x440, "OSD-2 (no version claimed)"},
    {0x460, "SPC-4 (no version claimed)"},
    {0x480, "SMC-3 (no version claimed)"},
    {0x820, "SSA-TL2 (no version claimed)"},
    {0x83b, "SSA-TL2 T10/1147-D revision 05b"},
    {0x83c, "SSA-TL2 ANSI NCITS.308:1998"},
    {0x840, "SSA-TL1 (no version claimed)"},
    {0x85b, "SSA-TL1 T10/0989-D revision 10b"},
    {0x85c, "SSA-TL1 ANSI X3.295:1996"},
    {0x860, "SSA-S3P (no version claimed)"},
    {0x87b, "SSA-S3P T10/1051-D revision 05b"},
    {0x87c, "SSA-S3P ANSI NCITS.309:1998"},
    {0x880, "SSA-S2P (no version claimed)"},
    {0x89b, "SSA-S2P T10/1121-D revision 07b"},
    {0x89c, "SSA-S2P ANSI X3.294:1996"},
    {0x8a0, "SIP (no version claimed)"},
    {0x8bb, "SIP T10/0856-D revision 10"},
    {0x8bc, "SIP ANSI X3.292:1997"},
    {0x8c0, "FCP (no version claimed)"},
    {0x8db, "FCP T10/0856-D revision 12"},
    {0x8dc, "FCP ANSI X3.269:1996"},
    {0x8e0, "SBP-2 (no version claimed)"},
    {0x8fb, "SBP-2 T10/1155-D revision 04"},
    {0x8fc, "SBP-2 ANSI NCITS.325:1999"},
    {0x900, "FCP-2 (no version claimed)"},
    {0x901, "FCP-2 T10/1144-D revision 4"},
    {0x915, "FCP-2 T10/1144-D revision 7"},
    {0x916, "FCP-2 T10/1144-D revision 7a"},
    {0x917, "FCP-2 ANSI INCITS.350:2003"},
    {0x918, "FCP-2 T10/1144-D revision 8"},
    {0x920, "SST (no version claimed)"},
    {0x935, "SST T10/1380-D revision 8b"},
    {0x940, "SRP (no version claimed)"},
    {0x954, "SRP T10/1415-D revision 10"},
    {0x955, "SRP T10/1415-D revision 16a"},
    {0x95c, "SRP ANSI INCITS.365:2002"},
    {0x960, "iSCSI (no version claimed)"},
    {0x980, "SBP-3 (no version claimed)"},
    {0x982, "SBP-3 T10/1467-D revision 1f"},
    {0x994, "SBP-3 T10/1467-D revision 3"},
    {0x99a, "SBP-3 T10/1467-D revision 4"},
    {0x99b, "SBP-3 T10/1467-D revision 5"},
    {0x99c, "SBP-3 ANSI INCITS.375:2004"},
    {0x9a0, "SRP-2 (no version claimed)"},
    {0x9c0, "ADP (no version claimed)"},
    {0x9e0, "ADT (no version claimed)"},
    {0x9f9, "ADT T10/1557-D revision 11"},
    {0xa00, "FCP-3 (no version claimed)"},
    {0xaa0, "SPI (no version claimed)"},
    {0xab9, "SPI T10/0855-D revision 15a"},
    {0xaba, "SPI ANSI X3.253:1995"},
    {0xabb, "SPI T10/0855-D revision 15a with SPI Amnd revision 3a"},
    {0xabc, "SPI ANSI X3.253:1995 with SPI Amnd ANSI X3.253/AM1:1998"},
    {0xac0, "Fast-20 (no version claimed)"},
    {0xadb, "Fast-20 T10/1071-D revision 06"},
    {0xadc, "Fast-20 ANSI X3.277:1996"},
    {0xae0, "SPI-2 (no version claimed)"},
    {0xafb, "SPI-2 T10/1142-D revision 20b"},
    {0xafc, "SPI-2 ANSI X3.302:1999"},
    {0xb00, "SPI-3 (no version claimed)"},
    {0xb18, "SPI-3 T10/1302-D revision 10"},
    {0xb19, "SPI-3 T10/1302-D revision 13a"},
    {0xb1a, "SPI-3 T10/1302-D revision 14"},
    {0xb1c, "SPI-3 ANSI NCITS.336:2000"},
    {0xb20, "EPI (no version claimed)"},
    {0xb3b, "EPI T10/1134-D revision 16"},
    {0xb3c, "EPI ANSI NCITS TR-23:1999"},
    {0xb40, "SPI-4 (no version claimed)"},
    {0xb54, "SPI-4 T10/1365-D revision 7"},
    {0xb55, "SPI-4 T10/1365-D revision 9"},
    {0xb56, "SPI-4 ANSI INCITS.362:2002"},
    {0xb59, "SPI-4 T10/1365-D revision 10"},
    {0xb60, "SPI-5 (no version claimed)"},
    {0xb79, "SPI-5 T10/1525-D revision 3"},
    {0xb7a, "SPI-5 T10/1525-D revision 5"},
    {0xb7b, "SPI-5 T10/1525-D revision 6"},
    {0xb7c, "SPI-5 ANSI INCITS.367:2004"},
    {0xbe0, "SAS (no version claimed)"},
    {0xbe1, "SAS T10/1562-D revision 01"},
    {0xbf5, "SAS T10/1562-D revision 03"},
    {0xbfa, "SAS T10/1562-D revision 04"},
    {0xbfb, "SAS T10/1562-D revision 04"},
    {0xbfc, "SAS T10/1562-D revision 05"},
    {0xbfd, "SAS ANSI INCITS.376:2003"},
    {0xc00, "SAS-1.1 (no version claimed)"},
    {0xd20, "FC-PH (no version claimed)"},
    {0xd3b, "FC-PH ANSI X3.230:1994"},
    {0xd3c, "FC-PH ANSI X3.230:1994 with Amnd 1 ANSI X3.230/AM1:1996"},
    {0xd40, "FC-AL (no version claimed)"},
    {0xd5c, "FC-AL ANSI X3.272:1996"},
    {0xd60, "FC-AL-2 (no version claimed)"},
    {0xd61, "FC-AL-2 T11/1133-D revision 7.0"},
    {0xd7c, "FC-AL-2 ANSI NCITS.332:1999"},
    {0xd7d, "FC-AL-2 ANSI NCITS.332:1999 with Amnd 1 AM1:2002"},
    {0xd80, "FC-PH-3 (no version claimed)"},
    {0xd9c, "FC-PH-3 ANSI X3.303:1998"},
    {0xda0, "FC-FS (no version claimed)"},
    {0xdb7, "FC-FS T11/1331-D revision 1.2"},
    {0xdb8, "FC-FS T11/1331-D revision 1.7"},
    {0xdbc, "FC-FS ANSI INCITS.373:2003"},
    {0xdc0, "FC-PI (no version claimed)"},
    {0xddc, "FC-PI ANSI INCITS.352:2002"},
    {0xde0, "FC-PI-2 (no version claimed)"},
    {0xde2, "FC-PI-2 T11/1506-D revision 5.0"},
    {0xe00, "FC-FS-2 (no version claimed)"},
    {0xe20, "FC-LS (no version claimed)"},
    {0xe40, "FC-SP (no version claimed)"},
    {0xe42, "FC-SP T11/1570-D revision 1.6"},
    {0x12e0, "FC-DA (no version claimed)"},
    {0x12e2, "FC-DA T11/1513-DT revision 3.1"},
    {0x1300, "FC-Tape (no version claimed)"},
    {0x1301, "FC-Tape T11/1315-D revision 1.16"},
    {0x131b, "FC-Tape T11/1315-D revision 1.17"},
    {0x131c, "FC-Tape ANSI NCITS TR-24:1999"},
    {0x1320, "FC-FLA (no version claimed)"},
    {0x133b, "FC-FLA T11/1235-D revision 7"},
    {0x133c, "FC-FLA ANSI NCITS TR-20:1998"},
    {0x1340, "FC-PLDA (no version claimed)"},
    {0x135b, "FC-PLDA T11/1162-D revision 2.1"},
    {0x135c, "FC-PLDA ANSI NCITS TR-19:1998"},
    {0x1360, "SSA-PH2 (no version claimed)"},
    {0x137b, "SSA-PH2 T10/1145-D revision 09c"},
    {0x137c, "SSA-PH2 ANSI X3.293:1996"},
    {0x1380, "SSA-PH3 (no version claimed)"},
    {0x139b, "SSA-PH3 T10/1146-D revision 05b"},
    {0x139c, "SSA-PH3 ANSI NCITS.307:1998"},
    {0x14a0, "IEEE 1394 (no version claimed)"},
    {0x14bd, "ANSI IEEE 1394:1995"},
    {0x14c0, "IEEE 1394a (no version claimed)"},
    {0x14e0, "IEEE 1394b (no version claimed)"},
    {0x15e0, "ATA/ATAPI-6 (no version claimed)"},
    {0x15fd, "ATA/ATAPI-6 ANSI INCITS.361:2002"},
    {0x1600, "ATA/ATAPI-7 (no version claimed)"},
    {0x1602, "ATA/ATAPI-7 T13/1532-D revision 3"},
    {0x1728, "Universal Serial Bus Specification, Revision 1.1"},
    {0x1729, "Universal Serial Bus Specification, Revision 2.0"},
    {0x1730, "USB Mass Storage Class Bulk-Only Transport, Revision 1.0"},
    {0x1ea0, "SAT (no version claimed)"},
};

static int version_descriptor_arr_sz = (sizeof(version_descriptor_arr) /
                                        sizeof(version_descriptor_arr[0]));

static const char * find_version_descriptor_str(int value)
{
    int k;

    for (k = 0; k < version_descriptor_arr_sz; ++k) {
        if (value == version_descriptor_arr[k].value)
            return version_descriptor_arr[k].name;
        if (value < version_descriptor_arr[k].value)
            break;
    }
    return NULL;
}
