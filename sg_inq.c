#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef SG3_UTILS_LINUX
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/hdreg.h>
#endif

#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
*  Copyright (C) 2000-2006 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI INQUIRY command.
   It is mainly based on the SCSI SPC-4 document at http://www.t10.org .

   Acknowledgment:
      - Martin Schwenke <martin at meltin dot net> added the raw switch and 
        other improvements [20020814]
      - Lars Marowsky-Bree <lmb at suse dot de> contributed Unit Path Report
        VPD page decoding for EMC CLARiiON devices [20041016]
*/

/* INQUIRY notes:
 * It is recommended that the initial allocation length given to a
 * standard INQUIRY is 36 (bytes), especially if this is the first
 * SCSI command sent to a logical unit. This is compliant with SCSI-2
 * and another major operating system. There are devices out there
 * that use one of the SCSI commands sets and lock up if they receive
 * an allocation length other than 36. This technique is sometimes
 * referred to as a "36 byte INQUIRY".
 *
 * A "standard" INQUIRY is one that has the EVPD and the CmdDt bits
 * clear.
 *
 * When doing device discovery on a SCSI transport (e.g. bus scanning)
 * the first SCSI command sent to a device should be a standard (36
 * byte) INQUIRY.
 *
 * The allocation length field in the INQUIRY command was changed
 * from 1 to 2 bytes in SPC-3, revision 9, 17 September 2002.
 * Be careful using allocation lengths greater than 252 bytes, especially
 * if the lower byte is 0x0 (e.g. a 512 byte allocation length may
 * not be a good arbitrary choice (as 512 == 0x200) ).
 *
 * From SPC-3 revision 16 the CmdDt bit in an INQUIRY is obsolete. There
 * is now a REPORT SUPPORTED OPERATION CODES command that yields similar
 * information [MAINTENANCE IN, service action = 0xc]; see sg_opcodes.
 */

static char * version_str = "0.61 20050622";    /* spc-4 rev 05 */


#define SUPPORTED_VPDS_VPD 0x0
#define UNIT_SERIAL_NUM_VPD 0x80
#define DEV_ID_VPD  0x83
#define SOFTW_INF_ID_VPD 0x84
#define MAN_NET_ADDR_VPD  0x85
#define X_INQ_VPD  0x86
#define MODE_PG_POLICY_VPD  0x87
#define SCSI_PORTS_VPD  0x88
#define ATA_INFO_VPD  0x89
#define BLOCK_LIMITS_VPD  0xb0
#define UPR_EMC_VPD  0xc0
#define RDAC_VERS_VPD 0xc2
#define RDAC_VAC_VPD 0xc9

#define DEF_ALLOC_LEN 252
#define SAFE_STD_INQ_RESP_LEN 36
#define MX_ALLOC_LEN (0xc000 + 0x80)
#define ATA_INFO_VPD_LEN  572


static unsigned char rsp_buff[MX_ALLOC_LEN + 1];
static char xtra_buff[MX_ALLOC_LEN + 1];

static const char * find_version_descriptor_str(int value);
static void decode_dev_ids(const char * leadin, unsigned char * buff,
                           int len, int do_hex);
static void decode_transport_id(const char * leadin, unsigned char * ucp,
                                int len);

#ifdef SG3_UTILS_LINUX
static int try_ata_identify(int ata_fd, int do_hex, int do_raw,
                            int do_verbose);
#endif


static void usage()
{
#ifdef SG3_UTILS_LINUX
    fprintf(stderr,
            "Usage:  sg_inq [-a] [-A] [-b] [-c] [-cl] [-d] [-e] [-h] [-H] "
            "[-i] [-m] [-M]\n"
            "               [-o=<opcode_page>] [-p=<vpd_page>] [-P] [-r] "
            "[-s] [-v]\n"
            "               [-V] [-x] [-36] [-?] <device>\n"
            " where -a   decode ATA information VPD page (0x89)\n"
            "       -A   treat <device> as (directly attached) ATA device\n");
#else
    fprintf(stderr,
            "Usage:  sg_inq [-a] [-b] [-c] [-cl] [-d] [-e] [-h] [-H] "
            "[-i] [-m] [-M]\n"
            "               [-o=<opcode_page>] [-p=<vpd_page>] [-P] [-r] "
            "[-s] [-v]\n"
            "               [-V] [-x] [-36] [-?] <device>\n"
            " where -a   decode ATA information VPD page (0x89)\n");

#endif
    fprintf(stderr,
            "       -b   decode Block limits VPD page (0xb0) (SBC)\n"
            "       -c   set CmdDt mode (use -o for opcode) [obsolete]\n"
            "       -cl  list supported commands using CmdDt mode [obsolete]\n"
            "       -d   decode; version descriptors or VPD page\n"
            "       -e   set VPD mode (use -p for page code)\n"
            "       -h   output in hex (ASCII to the right)\n"
            "       -H   output in hex (ASCII to the right) [same as '-h']\n"
            "       -i   decode device identification VPD page (0x83)\n"
            "       -m   decode management network addresses VPD page "
            "(0x85)\n"
            "       -M   decode mode page policy VPD page (0x87)\n"
            "       -o=<opcode_page> opcode or page code in hex (def: 0)\n"
            "       -p=<vpd_page> vpd page code in hex (def: 0)\n"
            "       -P   decode Unit Path Report VPD page (0xc0) (EMC)\n"
            "       -r   output raw binary data ('-rr': output for hdparm)\n"
            "       -s   decode SCSI Ports VPD page (0x88)\n"
            "       -v   verbose (output cdb and, if non-zero, resid)\n"
            "       -V   output version string\n"
            "       -x   decode extended INQUIRY data VPD page (0x86)\n"
            "       -36  perform standard INQUIRY with a 36 byte response\n"
            "       -?   output this usage message\n"
            "   If no options given then does a standard SCSI INQUIRY\n");
}


static void dStrRaw(const char* str, int len)
{
    int k;
    
    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

struct vpd_name {
    int number;
    int peri_type;
    char * name;
};

static struct vpd_name vpd_name_arr[] = {
    {SUPPORTED_VPDS_VPD, 0, "Supported VPD pages"},
    {UNIT_SERIAL_NUM_VPD, 0, "Unit serial number"},
    {0x81, 0, "Implemented operating definitions (obsolete)"},
    {0x82, 0, "ASCII implemented operating definition (obsolete)"},
    {DEV_ID_VPD, 0, "Device identification"},
    {SOFTW_INF_ID_VPD, 0, "Software interface identification"},
    {MAN_NET_ADDR_VPD, 0, "Management network addresses"},
    {X_INQ_VPD, 0, "Extended INQUIRY data"},
    {MODE_PG_POLICY_VPD, 0, "Mode page policy"},
    {SCSI_PORTS_VPD, 0, "SCSI ports"},
    {ATA_INFO_VPD, 0, "ATA information"},
    {BLOCK_LIMITS_VPD, 0, "Block limits (sbc2)"}, 
    {0xb0, 0x1, "Sequential access device capabilities (ssc3)"},
    {0xb2, 0x1, "TapeAlert supported flags (ssc3)"},
    {0xb0, 0x11, "OSD information (osd)"},
    {0xb1, 0x11, "Security token (osd)"},
    {0xc0, 0, "vendor: Firmware numbers (seagate); Unit path report (EMC)"},
    {0xc1, 0, "vendor: Date code (seagate)"},
    {0xc2, 0, "vendor: Jumper settings (seagate); Software version (RDAC)"},
    {0xc3, 0, "vendor: Device behavior (seagate)"},
    {0xc9, 0, "Volume Access Control (RDAC)"},
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

static const char * assoc_arr[] =
{
    "addressed logical unit",
    "target port",      /* that received request; unless SCSI ports VPD */
    "target device that contains addressed lu",
    "reserved [0x3]",
};
        
static const char * network_service_type_arr[] =
{
    "unspecified",
    "storage configuration service",
    "diagnostics",
    "status",
    "logging",
    "code download",
    "reserved[0x6]", "reserved[0x7]", "reserved[0x8]", "reserved[0x9]",
    "reserved[0xa]", "reserved[0xb]", "reserved[0xc]", "reserved[0xd]",
    "reserved[0xe]", "reserved[0xf]", "reserved[0x10]", "reserved[0x11]",
    "reserved[0x12]", "reserved[0x13]", "reserved[0x14]", "reserved[0x15]",
    "reserved[0x16]", "reserved[0x17]", "reserved[0x18]", "reserved[0x19]",
    "reserved[0x1a]", "reserved[0x1b]", "reserved[0x1c]", "reserved[0x1d]",
    "reserved[0x1e]", "reserved[0x1f]",
};

static void decode_net_man_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, na_len;
    unsigned char * ucp;

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
            if (do_hex) {
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

static void decode_mode_policy_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump;
    unsigned char * ucp;

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
        if (do_hex)
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
            printf(" Target port descriptor(s):\n");
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
    "Parallel SCSI (SPI-4)",
    "SSA (SSA-S3P)",
    "IEEE 1394 (SBP-3)",
    "Remote Direct Memory Access (RDMA)",
    "Internet SCSI (iSCSI)",
    "Serial Attached SCSI (SAS)",
    "Automation/Drive Interface (ADT)",
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

static const char * id_type_arr[] =
{
    "vendor specific [0x0]",
    "T10 vendor identification",
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

extern int sg_vpd_dev_id_iter(const unsigned char * initial_desig_desc,
                              int page_len, int * off, int m_assoc,
                              int m_desig_type, int m_code_set);

/* These are target port, device server (i.e. target) and lu identifiers */
static void decode_dev_ids(const char * leadin, unsigned char * buff,
                           int len, int do_hex)
{
    int u, j, m, id_len, p_id, c_set, piv, assoc, id_type, i_len;
    int off, ci_off, c_id, d_id, naa, vsi;
    unsigned long long vsei;
    unsigned long long id_ext;
    const unsigned char * ucp;
    const unsigned char * ip;

    for (j = 1, off = -1;
         (u = sg_vpd_dev_id_iter(buff, len, &off, -1, -1, -1)) == 0;
         ++j) {
        ucp = buff + off;
        i_len = ucp[3];
        id_len = i_len + 4;
        printf("  Designation descriptor number %d, "
               "descriptor length: %d\n", j, id_len);
        if ((off + id_len) > len) {
            fprintf(stderr, "%s VPD page error: designator length longer "
                    "than\n     remaining response length=%d\n", leadin,
                    (len - off));
            return;
        }
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
            printf("    designator header(hex): %.2x %.2x %.2x %.2x\n",
                   ucp[0], ucp[1], ucp[2], ucp[3]);
            printf("    designator:\n");
            dStrHex((const char *)ip, i_len, 0);
            continue;
        }
        switch (id_type) {
        case 0: /* vendor specific */
            dStrHex((const char *)ip, i_len, 0);
            break;
        case 1: /* T10 vendor identification */
            printf("      vendor id: %.8s\n", ip);
            if (i_len > 8)
                printf("      vendor specific: %.*s\n", i_len - 8, ip + 8);
            break;
        case 2: /* EUI-64 based */
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
                printf("      Identifier extension: 0x%llx\n", id_ext);
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
            printf("      Vendor Specific Extension Identifier: 0x%llx\n",
                   vsei);
            if (12 == i_len) {
                d_id = ((ip[8] << 24) | (ip[9] << 16) | (ip[10] << 8) |
                        ip[11]);
                printf("      Directory ID: 0x%x\n", d_id);
            }
            printf("      [0x");
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("]\n");
            break;
        case 3: /* NAA */
            if (1 != c_set) {
                fprintf(stderr, "      << expected binary code_set (1)>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            naa = (ip[0] >> 4) & 0xff;
            if (! ((2 == naa) || (5 == naa) || (6 == naa))) {
                fprintf(stderr, "      << expected naa [0x%x]>>\n", naa);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            if (2 == naa) {
                if (8 != i_len) {
                    fprintf(stderr, "      << expected NAA 2 identifier "
                            "length: 0x%x>>\n", i_len);
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
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            } else if (5 == naa) {
                if (8 != i_len) {
                    fprintf(stderr, "      << expected NAA 5 identifier "
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
                printf("      NAA 5, IEEE Company_id: 0x%x\n", c_id);
                printf("      Vendor Specific Identifier: 0x%llx\n",
                       vsei);
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            } else if (6 == naa) {
                if (16 != i_len) {
                    fprintf(stderr, "      << expected NAA 6 identifier "
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
                printf("      [0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
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
        case 5: /* Target port group */
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
                fprintf(stderr, "      << expected binary code_set, logical "
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
        default: /* reserved */
            dStrHex((const char *)ip, i_len, 0);
            break;
        }
    }
    if (-2 == u)
        fprintf(stderr, "%s VPD page error: around offset=%d\n", leadin, off);
}

/* Transport IDs are initiator port identifiers, typically other than the
   initiator port issuing a SCSI command. Code borrowed from sg_persist.c */
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
        fprintf(stderr, "Extended INQUIRY data VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    printf("  SPT=%d GRD_CHK=%d APP_CHK=%d REF_CHK=%d\n",
           ((buff[4] >> 3) & 0x7), !!(buff[4] & 0x4), !!(buff[4] & 0x2),
           !!(buff[4] & 0x1));
    printf("  GRP_SUP=%d PRIOR_SUP=%d HEADSUP=%d ORDSUP=%d SIMPSUP=%d\n",
           !!(buff[5] & 0x10), !!(buff[5] & 0x8), !!(buff[5] & 0x4),
           !!(buff[5] & 0x2), !!(buff[5] & 0x1));
    printf("  CORR_D_SUP=%d NV_SUP=%d V_SUP=%d\n", !!(buff[6] & 0x80),
           !!(buff[6] & 0x2), !!(buff[6] & 0x1));
}

static void decode_softw_inf_id(unsigned char * buff, int len, int do_hex)
{
    int k;

    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    len -= 4;
    buff += 4;
    for ( ; len > 5; len -= 6, buff += 6) {
        printf("    ");
        for (k = 0; k < 6; ++k)
            printf("%02x", (unsigned int)buff[k]);
        printf("\n");
    }
}

static void decode_ata_info_vpd(unsigned char * buff, int len, int do_hex)
{
    char b[80];
    int is_be, num;

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
    printf("  Signature (Device to host FIS):\n");
    dStrHex((const char *)buff + 36, 20, 1);
    if (len < 60)
        return;
    is_be = sg_is_big_endian();
    if ((0xec == buff[56]) || (0xa1 == buff[56])) {
        printf("  ATA command IDENTIFY %sDEVICE response summary:\n",
               ((0xa1 == buff[56]) ? "PACKET " : ""));
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
        printf("  response in hex:\n");
    } else
        printf("  ATA command 0x%x got following response:\n",
               (unsigned int)buff[56]);
    if (len < 572)
        return;
    if (2 == do_hex)
        dStrHex((const char *)(buff + 60), 512, 0);
    else
        dWordHex((const unsigned short *)(buff + 60), 256, 0,
                 sg_is_big_endian());
}

static void decode_b0_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    switch (pdt) {
       case 0: case 4: case 7:
            if (len < 16) {
                fprintf(stderr, "Block limits VPD page length too "
                        "short=%d\n", len);
                return;
            }
            u = (buff[6] << 8) | buff[7];
            printf("  Optimal transfer length granularity: %u blocks\n", u);
            u = (buff[8] << 24) | (buff[9] << 16) | (buff[10] << 8) |
                buff[11];
            printf("  Maximum transfer length: %u blocks\n", u);
            u = (buff[12] << 24) | (buff[13] << 16) | (buff[14] << 8) |
                buff[15];
            printf("  Optimal transfer length: %u blocks\n", u);
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
        printf("%02hhx", buff[10 + k]);
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
            printf("%02hhx", buff[32 + k]);
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

static void decode_rdac_vpd_c2(unsigned char * buff, int len)
{
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
    printf("  Software Version: %d.%d.%d\n", buff[8], buff[9], buff[10]);
    printf("  Software Date: %02x/%02x/%02x\n", buff[11], buff[12], buff[13]);
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
    return;
}

static void decode_rdac_vpd_c9(unsigned char * buff, int len)
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

/* Returns 0 if Unit Serial Number VPD page contents found, else see
   sg_ll_inquiry() */
static int fetch_unit_serial_num(int sg_fd, char * obuff, int obuff_len,
                                 int verbose)
{
    int sz, len, k, res;
    unsigned char b[DEF_ALLOC_LEN];

    res = 0;
    sz = sizeof(b);
    memset(b, 0xff, 4); /* guard against empty response */
    /* first check if unit serial number VPD page is supported */
    res = sg_ll_inquiry(sg_fd, 0, 1, SUPPORTED_VPDS_VPD, b, sz, 0,
                        verbose);
    if (0 == res) {
        if ((SUPPORTED_VPDS_VPD != b[1]) || (0x0 != b[2]))
            return SG_LIB_CAT_MALFORMED;
        len = b[3];
        for (k = 0; k < len; ++k) {
            if (UNIT_SERIAL_NUM_VPD == b[k + 4])
                break;
        }
        if (k < len) {
            res = sg_ll_inquiry(sg_fd, 0, 1, UNIT_SERIAL_NUM_VPD,
                                b, sz, 0, verbose);
            if (0 == res) {
                len = b[3];
                len = (len < (obuff_len - 1)) ? len : (obuff_len - 1);
                if ((UNIT_SERIAL_NUM_VPD == b[1]) && (len > 0)) {
                    memcpy(obuff, b + 4, len);
                    obuff[len] = '\0';
                    return 0;
                } else
                    return SG_LIB_CAT_MALFORMED;
            }
        } else
            return SG_LIB_CAT_MALFORMED;
    }
    return res;
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
                           int do_vdescriptors, int do_hex, int do_raw,
                           int do_verbose)
{
    int res, len, act_len, pqual, peri_type, ansi_version, k, j;
    const char * cp;
    int vdesc_arr[8];
    char buff[48];

    memset(vdesc_arr, 0, sizeof(vdesc_arr));
    res = sg_ll_inquiry(sg_fd, 0, 0, 0, rsp_buff,
                        SAFE_STD_INQ_RESP_LEN, 0, do_verbose);
    if (0 == res) {
        pqual = (rsp_buff[0] & 0xe0) >> 5;
        if (! do_raw) {
            if (0 == pqual)
                printf("standard INQUIRY:\n");
            else if (1 == pqual)
                printf("standard INQUIRY: [qualifier indicates no connected "
                       "lu]\n");
            else if (3 == pqual)
                printf("standard INQUIRY: [qualifier indicates not capable "
                       "of supporting lu]\n");
            else
                printf("standard INQUIRY: [reserved or vendor specific "
                       "qualifier [%d]\n", pqual);
        }
        len = rsp_buff[4] + 5;
        ansi_version = rsp_buff[2] & 0x7;
        peri_type = rsp_buff[0] & 0x1f;
        if ((len > SAFE_STD_INQ_RESP_LEN) && (len < 256) && (! do_36)) {
            if (sg_ll_inquiry(sg_fd, 0, 0, 0, rsp_buff, len, 1, do_verbose)) {
                fprintf(stderr, "second INQUIRY (%d byte) failed\n", len);
                return SG_LIB_CAT_OTHER;
            }
            if (len != (rsp_buff[4] + 5)) {
                fprintf(stderr,
                        "strange, twin INQUIRYs yield different "
                        "'additional length'\n");
                res = SG_LIB_CAT_MALFORMED;
            }
        }
        if (do_36) {
            act_len = len;
            len = SAFE_STD_INQ_RESP_LEN;
        } else
            act_len = len;
        if (do_hex)
            dStrHex((const char *)rsp_buff, len, 0);
        else if (do_raw)
            dStrRaw((const char *)rsp_buff, len);
        else {
            printf("  PQual=%d  Device_type=%d  RMB=%d  version=0x%02x ",
                   pqual, peri_type, !!(rsp_buff[1] & 0x80),
                   (unsigned int)rsp_buff[2]);
            printf(" [%s]\n", get_ansi_version_str(ansi_version, buff,
                                                   sizeof(buff)));
            printf("  [AERC=%d]  [TrmTsk=%d]  NormACA=%d  HiSUP=%d "
                   " Resp_data_format=%d\n  SCCS=%d  ",
                   !!(rsp_buff[3] & 0x80), !!(rsp_buff[3] & 0x40),
                   !!(rsp_buff[3] & 0x20), !!(rsp_buff[3] & 0x10),
                   rsp_buff[3] & 0x0f, !!(rsp_buff[5] & 0x80));
            printf("ACC=%d  TGPS=%d  3PC=%d  Protect=%d ",
                   !!(rsp_buff[5] & 0x40), ((rsp_buff[5] & 0x30) >> 4),
                   !!(rsp_buff[5] & 0x08), !!(rsp_buff[5] & 0x01));
            printf(" BQue=%d\n  EncServ=%d  ", !!(rsp_buff[6] & 0x80),
                   !!(rsp_buff[6] & 0x40));
            if (rsp_buff[6] & 0x10)
                printf("MultiP=1 (VS=%d)  ", !!(rsp_buff[6] & 0x20));
            else
                printf("MultiP=0  "); 
            printf("[MChngr=%d]  [ACKREQQ=%d]  Addr16=%d\n  [RelAdr=%d]  ",
                   !!(rsp_buff[6] & 0x08), !!(rsp_buff[6] & 0x04),
                   !!(rsp_buff[6] & 0x01), !!(rsp_buff[7] & 0x80));
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
            if ((ansi_version >= 2) && (len < SAFE_STD_INQ_RESP_LEN))
                printf("  [for SCSI>=2, len>=36 is expected]");
            cp = sg_get_pdt_str(peri_type, sizeof(buff), buff);
            if (strlen(cp) > 0)
                printf("   Peripheral device type: %s\n", cp);

            if (len <= 8)
                printf(" Inquiry response length=%d, no vendor, "
                       "product or revision data\n", len);
            else {
                if (len < SAFE_STD_INQ_RESP_LEN)
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
        if (! (do_raw || do_hex || do_36)) {
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
    } else if (res < 0) { /* could be an ATA device */
#ifdef SG3_UTILS_LINUX
        /* Try an ATA Identify Device command */
        res = try_ata_identify(sg_fd, do_hex, do_raw, do_verbose);
        if (0 != res) {
            fprintf(stderr, "Both SCSI INQUIRY and fetching ATA information "
                    "failed on %s\n", file_name);
            return SG_LIB_CAT_OTHER;
        }
#else
        fprintf(stderr, "SCSI INQUIRY failed on %s\n", file_name);
        return res;
#endif
    } else {        /* SCSI device not supporting 36 byte INQUIRY?? */
        printf("36 byte INQUIRY failed\n");
        return res;
    }
    return 0;
}

/* Returns 0 if successful */
static int process_cmddt(int sg_fd, int do_cmdlst, int num_opcode,
                         int do_hex, int do_raw, int do_verbose)
{
    int k, j, num, len, peri_type, reserved_cmddt, support_num, res;
    char op_name[128];

    memset(rsp_buff, 0, DEF_ALLOC_LEN);
    if (do_cmdlst) {
        printf("Supported command list:\n");
        for (k = 0; k < 256; ++k) {
            res = sg_ll_inquiry(sg_fd, 1, 0, k, rsp_buff, DEF_ALLOC_LEN,
                                1, do_verbose);
            if (0 == res) {
                peri_type = rsp_buff[0] & 0x1f;
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
        res = sg_ll_inquiry(sg_fd, 1, 0, num_opcode, rsp_buff, 
                            DEF_ALLOC_LEN, 1, do_verbose);
        if (0 == res) {
            peri_type = rsp_buff[0] & 0x1f;
            if (! do_raw) {
                printf("CmdDt INQUIRY, opcode=0x%.2x:  [", num_opcode);
                sg_get_opcode_name((unsigned char)num_opcode, peri_type, 
                                   sizeof(op_name) - 1, op_name);
                op_name[sizeof(op_name) - 1] = '\0';
                printf("%s]\n", op_name);
            }
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
            if (! do_raw) {
                printf("CmdDt INQUIRY, opcode=0x%.2x:  [", num_opcode);
                sg_get_opcode_name((unsigned char)num_opcode, 0, 
                                   sizeof(op_name) - 1, op_name);
                op_name[sizeof(op_name) - 1] = '\0';
                printf("%s]\n", op_name);
            }
            fprintf(stderr, "CmdDt INQUIRY on opcode=0x%.2x: failed\n",
                    num_opcode);
        }
    }
    return res;
}

/* Returns 0 if successful */
static int process_evpd(int sg_fd, int num_opcode, int do_hex,
                        int do_raw, int verbose)
{
    int res, len, num, k, peri_type, vpd;
    const char * cp;
    char buff[48];

    memset(rsp_buff, 0, DEF_ALLOC_LEN);
    if (!do_raw)
        printf("VPD INQUIRY, page code=0x%.2x:\n", num_opcode);
    res = sg_ll_inquiry(sg_fd, 0, 1, num_opcode, rsp_buff, DEF_ALLOC_LEN,
                        1, verbose);
    if (0 == res) {
        len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
        if (num_opcode != rsp_buff[1]) {
            fprintf(stderr, "invalid VPD response; probably a STANDARD "
                    "INQUIRY response\n");
            return SG_LIB_CAT_MALFORMED;
        }
        if (len > MX_ALLOC_LEN) {
            fprintf(stderr, "response length too long: %d > %d\n", len,
                   MX_ALLOC_LEN);
            return SG_LIB_CAT_MALFORMED;
        } else if (len > DEF_ALLOC_LEN) {
            if (sg_ll_inquiry(sg_fd, 0, 1, num_opcode, rsp_buff, len, 1, 
                              verbose))
                return SG_LIB_CAT_OTHER;
        }
        if (do_raw)
            dStrRaw((const char *)rsp_buff, len);
        else {
            if (do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else if (0 == num_opcode) { /* decode this mandatory page */
                peri_type = rsp_buff[0] & 0x1f;
                printf("   [PQual=%d  Peripheral device type: %s]\n",
                       (rsp_buff[0] & 0xe0) >> 5, 
                       sg_get_pdt_str(peri_type, sizeof(buff), buff));
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
            } else
                dStrHex((const char *)rsp_buff, len, 0);
        }
    } else {
        fprintf(stderr,
                "VPD INQUIRY, page code=0x%.2x: failed\n", num_opcode);
    }
    return res;
}

/* Returns 0 if successful */
static int decode_vpd(int sg_fd, int num_opcode, int do_hex,
                      int do_raw, int verbose)
{
    int len, pdt;
    int res = 0;

    switch(num_opcode) {
    case UNIT_SERIAL_NUM_VPD:
        if (! do_raw)
            printf("VPD INQUIRY: Unit serial number page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, UNIT_SERIAL_NUM_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (UNIT_SERIAL_NUM_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                char obuff[DEF_ALLOC_LEN];

                memset(obuff, 0, sizeof(obuff));
                len -= 4;
                if (len >= (int)sizeof(obuff))
                    len = sizeof(obuff) - 1;
                memcpy(obuff, rsp_buff + 4, len);
                printf("  Unit serial number: %s\n", obuff);
            }
        }
        break;
    case DEV_ID_VPD:
        if (! do_raw)
            printf("VPD INQUIRY: Device Identification page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, DEV_ID_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (DEV_ID_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, DEV_ID_VPD, rsp_buff, len,
                                  1, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_id_vpd(rsp_buff, len, do_hex);
        }
        break;
    case SOFTW_INF_ID_VPD:
        if (! do_raw)
            printf("VPD INQUIRY: Software interface identification page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, SOFTW_INF_ID_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (SOFTW_INF_ID_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_softw_inf_id(rsp_buff, len, do_hex);
        }
        break;
    case MAN_NET_ADDR_VPD:
        if (!do_raw)
            printf("VPD INQUIRY: Management network addresses page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, MAN_NET_ADDR_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (MAN_NET_ADDR_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, MAN_NET_ADDR_VPD, rsp_buff,
                                  len, 1, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_net_man_vpd(rsp_buff, len, do_hex);
        }
        break;
    case MODE_PG_POLICY_VPD:
        if (!do_raw)
            printf("VPD INQUIRY: Mode page policy\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, MODE_PG_POLICY_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (MODE_PG_POLICY_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, MODE_PG_POLICY_VPD, rsp_buff,
                                  len, 1, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_mode_policy_vpd(rsp_buff, len, do_hex);
        }
        break;
    case X_INQ_VPD:
        if (!do_raw)
            printf("VPD INQUIRY: extended INQUIRY data page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, X_INQ_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (X_INQ_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, X_INQ_VPD, rsp_buff, len,
                                  1, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_x_inq_vpd(rsp_buff, len, do_hex);
        }
        break;
    case ATA_INFO_VPD:
        if (!do_raw)
            printf("VPD INQUIRY: ATA information page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, ATA_INFO_VPD, rsp_buff,
                            ATA_INFO_VPD_LEN, 1, verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (ATA_INFO_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > ATA_INFO_VPD_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, ATA_INFO_VPD, rsp_buff, len,
                                  1, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw) {
                if (2 == do_raw)
                    dWordHex((const unsigned short *)(rsp_buff + 60),
                             256, -2, sg_is_big_endian());
                else
                    dStrRaw((const char *)rsp_buff, len);
            } else
                decode_ata_info_vpd(rsp_buff, len, do_hex);
        }
        break;
    case 0xb0:  /* could be BLOCK LIMITS but need to know pdt to find out */
        res = sg_ll_inquiry(sg_fd, 0, 1, 0xb0, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            pdt = rsp_buff[0] & 0x1f;
            if (! do_raw) {
                switch (pdt) {
                case 0: case 4: case 7:
                    printf("VPD INQUIRY: Block limits page (SBC)\n");
                    break;
                case 1: case 8:
                    printf("VPD INQUIRY: Sequential access device "
                           "capabilities (SSC)\n");
                    break;
                case 0x11:
                    printf("VPD INQUIRY: OSD information (OSD)\n");
                    break;
                default:
                    printf("VPD INQUIRY: page=0x%x, pdt=0x%x\n", 0xb0, pdt);
                    break;
                }
            }
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (0xb0 != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, 0xb0, rsp_buff,
                                  len, 1, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_b0_vpd(rsp_buff, len, do_hex, pdt);
        } else if (! do_raw)
            printf("VPD INQUIRY: page=0xb0\n");
        break;
    case UPR_EMC_VPD:   /* 0xc0 */
        if (!do_raw)
            printf("VPD INQUIRY: Unit Path Report Page (EMC)\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, UPR_EMC_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (UPR_EMC_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, UPR_EMC_VPD, rsp_buff, len, 1,
                           verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (do_hex)
                dStrHex((const char *)rsp_buff, len, 1);
            else
                decode_upr_vpd_c0_emc(rsp_buff, len);
        }
        break;
    case RDAC_VERS_VPD:         /* 0xc2 */
        if (!do_raw)
            printf("VPD INQUIRY: Software Version (RDAC)\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, RDAC_VERS_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (RDAC_VERS_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, RDAC_VERS_VPD, rsp_buff, len, 1,
                           verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (do_hex)
                dStrHex((const char *)rsp_buff, len, 1);
            else
                decode_rdac_vpd_c2(rsp_buff, len);
        }
        break;
    case RDAC_VAC_VPD:          /* 0xc9 */
        if (!do_raw)
            printf("VPD INQUIRY: Volume Access Control (RDAC)\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, RDAC_VAC_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (RDAC_VAC_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, RDAC_VAC_VPD, rsp_buff, len, 1,
                           verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (do_hex)
                dStrHex((const char *)rsp_buff, len, 1);
            else
                decode_rdac_vpd_c9(rsp_buff, len);
        }
        break;
    case SCSI_PORTS_VPD:
        if (!do_raw)
            printf("VPD INQUIRY: SCSI Ports page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, SCSI_PORTS_VPD, rsp_buff,
                            DEF_ALLOC_LEN, 1, verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (SCSI_PORTS_VPD != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, SCSI_PORTS_VPD, rsp_buff, len,
                                  1, verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_scsi_ports_vpd(rsp_buff, len, do_hex);
        }
        break;
    default:
        printf(" Only hex output supported\n");
        return process_evpd(sg_fd, num_opcode, do_hex, do_raw, verbose);
    }
    return res;
}


int main(int argc, char * argv[])
{
    int sg_fd, k, num, plen, jmp_out, res;
    const char * file_name = 0;
    const char * cp;
    unsigned int num_opcode = 0; /* SUPPORTED_VPDS_VPD == 0 */
    int num_opcode_given = 0;
    int p_switch_given = 0;
    int do_ata_device = 0;
    int do_decode = 0;
    int do_evpd = 0;
    int do_cmddt = 0;
    int do_cmdlst = 0;
    int do_hex = 0;
    int do_raw = 0;
    int do_36 = 0;
    int do_vdescriptors = 0;
    int do_verbose = 0;
    int num_pages = 0;
    int ret = 0;


    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '3':
                    if ('6' == *(cp + 1)) {
                        do_36 = 1;
                        --plen;
                        ++cp;
                    } else
                        jmp_out = 1;
                    break;
                case 'a':
                    num_opcode = ATA_INFO_VPD;
                    do_evpd = 1;
                    ++num_pages;
                    break;
#ifdef SG3_UTILS_LINUX
                case 'A':
                    do_ata_device = 1;
                    break;
#endif
                case 'b':
                    num_opcode = BLOCK_LIMITS_VPD;
                    do_evpd = 1;
                    ++num_pages;
                    break;
                case 'c':
                    do_cmddt = 1;
                    if ('l' == *(cp + 1)) {
                        do_cmdlst = 1;
                        --plen;
                        ++cp;
                    }
                    break;
                case 'd':
                    do_decode = 1;
                    break;
                case 'e':
                    do_evpd = 1;
                    break;
                case 'h':
                case 'H':
                    ++do_hex;
                    break;
                case 'i':
                    num_opcode = DEV_ID_VPD;
                    do_evpd = 1;
                    ++num_pages;
                    break;
                case 'm':
                    num_opcode = MAN_NET_ADDR_VPD;
                    do_evpd = 1;
                    ++num_pages;
                    break;
                case 'M':
                    num_opcode = MODE_PG_POLICY_VPD;
                    do_evpd = 1;
                    ++num_pages;
                    break;
                case 'P':
                    num_opcode = UPR_EMC_VPD;
                    do_evpd = 1;
                    ++num_pages;
                    break;
                case 'r':
                    ++do_raw;
                    break;
                case 's':
                    num_opcode = SCSI_PORTS_VPD;
                    do_evpd = 1;
                    ++num_pages;
                    break;
                case 'v':
                    ++do_verbose;
                    break;
                case 'V':
                    fprintf(stderr, "Version string: %s\n", version_str);
                    exit(0);
                case 'x':
                    num_opcode = X_INQ_VPD;
                    do_evpd = 1;
                    ++num_pages;
                    break;
                case '?':
                    usage();
                    return 0;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            else if (0 == strncmp("o=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &num_opcode);
                if ((1 != num) || (num_opcode > 255)) {
                    fprintf(stderr, "Bad number after 'o=' option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                num_opcode_given = 1;
                ++num_pages;
            } else if (0 == strncmp("p=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &num_opcode);
                if ((1 != num) || (num_opcode > 255)) {
                    fprintf(stderr, "Bad number after '-p' switch\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                num_opcode_given = 1;
                p_switch_given = 1;
                ++num_pages;
            } else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == file_name)
            file_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", file_name, cp);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (do_raw && do_hex) {
        fprintf(stderr, "Can't do hex and raw at the same time\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (do_evpd && do_cmddt) {
        fprintf(stderr, "Can't have both '-e' and '-c' (or '-cl')\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (num_pages > 1) {
        fprintf(stderr, "Can only fetch one page (VPD or Cmd) at a time\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (do_decode) {
        if (num_pages)
            num_opcode_given = 0;
        else {
            do_vdescriptors = 1;
            if (do_36) {
                fprintf(stderr, "version descriptors need > 36 byte "
                        "INQUIRY\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            if (do_cmddt || do_evpd) {
                fprintf(stderr, "version descriptors require standard"
                        "INQUIRY\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        }
    }
    if (num_pages && do_ata_device) {
        fprintf(stderr, "Can't use '-A' with an explicit decode VPD "
                "page option\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (0 == file_name) {
        fprintf(stderr, "No <device> argument given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (num_pages && (! do_cmddt) && (! do_evpd)) {
        do_evpd = 1;    /* '-o=' and '-p=' implies '-e' unless overridden */
        if (! (do_raw || p_switch_given))
            printf(" <<given page_code so assumed EVPD selected>>\n");
    }

    if ((sg_fd = sg_cmds_open_device(file_name, 1 /* ro */, do_verbose)) < 0) {
        fprintf(stderr, "sg_inq: error opening file: %s: %s\n",
                file_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    memset(rsp_buff, 0, MX_ALLOC_LEN + 1);

#ifdef SG3_UTILS_LINUX
    if (do_ata_device) {
        res = try_ata_identify(sg_fd, do_hex, do_raw, do_verbose);
        if (0 != res) {
            fprintf(stderr, "fetching ATA information failed on %s\n",
                    file_name);
            ret = SG_LIB_CAT_OTHER;
        } else
            ret = 0;
        goto err_out;
    }
#endif

    if ((! do_cmddt) && (! do_evpd)) {
        /* So it's a Standard INQUIRY, try ATA IDENTIFY if that fails */
        ret = process_std_inq(sg_fd, file_name, do_36, do_vdescriptors,
                             do_hex, do_raw, do_verbose);
        if (ret)
            goto err_out;
    } else if (do_cmddt) {
        ret = process_cmddt(sg_fd, do_cmdlst, num_opcode, do_hex, do_raw,
                            do_verbose);
        if (ret)
            goto err_out;
    } else if (do_evpd) {
        if (num_opcode_given) {
            ret = process_evpd(sg_fd, num_opcode, do_hex, do_raw, do_verbose);
            if (ret)
                goto err_out;
        } else {
            ret = decode_vpd(sg_fd, num_opcode, do_hex, do_raw, do_verbose);
            if (ret)
                goto err_out;
        }
    }

err_out:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}


#ifdef SG3_UTILS_LINUX
/* Following code permits ATA IDENTIFY commands to be performed on
   ATA non "Packet Interface" devices (e.g. ATA disks).
   GPL-ed code borrowed from smartmontools (smartmontools.sf.net).
   Copyright (C) 2002-4 Bruce Allen 
                <smartmontools-support@lists.sourceforge.net>
 */
#ifndef ATA_IDENTIFY_DEVICE
#define ATA_IDENTIFY_DEVICE 0xec
#define ATA_IDENTIFY_PACKET_DEVICE 0xa1
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

#define ATA_IDENTIFY_BUFF_SZ  sizeof(struct ata_identify_device)
#define HDIO_DRIVE_CMD_OFFSET 4

static int ata_command_interface(int device, char *data, int * atapi_flag,
                                 int verbose)
{
    unsigned char buff[ATA_IDENTIFY_BUFF_SZ + HDIO_DRIVE_CMD_OFFSET];
    unsigned short get_ident[256];

    if (atapi_flag)
        *atapi_flag = 0;
    memset(buff, 0, sizeof(buff));
    if (ioctl(device, HDIO_GET_IDENTITY, &get_ident) < 0) {
        if (ENOTTY == errno) {
            if (verbose > 1)
                fprintf(stderr, "HDIO_GET_IDENTITY failed with ENOTTY, "
                        "try HDIO_DRIVE_CMD ioctl ...\n");
            buff[0] = ATA_IDENTIFY_DEVICE;
            buff[3] = 1;
            if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
                if (verbose)
                    fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                            "ioctl failed:\n\t%s [%d]\n",
                            safe_strerror(errno), errno);
                return errno;
            }
            memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTIFY_BUFF_SZ);
            return 0;
        } else {
            if (verbose)
                fprintf(stderr, "HDIO_GET_IDENTITY ioctl failed:\n"
                        "\t%s [%d]\n", safe_strerror(errno), errno);
            return errno;
        }
    }
    if (0x2 == ((get_ident[0] >> 14) &0x3)) {   /* ATAPI device */
        if (verbose > 1)
            fprintf(stderr, "assume ATAPI device from HDIO_GET_IDENTITY "
                    "response\n");
        memset(buff, 0, sizeof(buff));
        buff[0] = ATA_IDENTIFY_PACKET_DEVICE;
        buff[3] = 1;
        if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
            if (verbose)
                fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_PACKET_DEVICE) "
                        "ioctl failed:\n\t%s [%d]\n", safe_strerror(errno),
                        errno);
            buff[0] = ATA_IDENTIFY_DEVICE;
            buff[3] = 1;
            if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
                if (verbose)
                    fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                            "ioctl failed:\n\t%s [%d]\n", safe_strerror(errno),
                            errno);
                return errno;
            }
        } else if (atapi_flag)
            *atapi_flag = 1;
    } else {    /* assume non-packet device */
        buff[0] = ATA_IDENTIFY_DEVICE;
        buff[3] = 1;
        if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
            if (verbose)
                fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                        "ioctl failed:\n\t%s [%d]\n", safe_strerror(errno),
                        errno);
            return errno;
        }
    }
    /* if the command returns data, copy it back */
    memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTIFY_BUFF_SZ);
    return 0;
}

/* Returns 0 if successful, else errno of error */
static int try_ata_identify(int ata_fd, int do_hex, int do_raw,
                            int verbose)
{
    struct ata_identify_device ata_ident;
    char model[64];
    char serial[64];
    char firm[64];
    int res, atapi;

    memset(&ata_ident, 0, sizeof(ata_ident));
    res = ata_command_interface(ata_fd, (char *)&ata_ident, &atapi, verbose);
    if (res)
        return res;
    if (do_raw) {
        if (2 == do_raw)
            dWordHex((const unsigned short *)&ata_ident, 256, -2,
                     sg_is_big_endian());
        else
            dStrRaw((const char *)&ata_ident, 512);
    } else {
        if (do_hex) {
            if (atapi)
                printf("ATA IDENTIFY PACKET DEVICE response ");
            else
                printf("ATA IDENTIFY DEVICE response ");
            if (do_hex > 1) {
                printf("(512 bytes):\n");
                dStrHex((const char *)&ata_ident, 512, 0);
            } else {
                printf("(256 words):\n");
                dWordHex((const unsigned short *)&ata_ident, 256, 0,
                         sg_is_big_endian());
            }
        } else {
            printf("%s device: model, serial number and firmware revision:\n",
                   (atapi ? "ATAPI" : "ATA"));
            res = sg_ata_get_chars((const unsigned short *)ata_ident.model,
                                   0, 20, sg_is_big_endian(), model);
            model[res] = '\0';
            res = sg_ata_get_chars((const unsigned short *)ata_ident.serial_no,
                                   0, 10, sg_is_big_endian(), serial);
            serial[res] = '\0';
            res = sg_ata_get_chars((const unsigned short *)ata_ident.fw_rev,
                                   0, 4, sg_is_big_endian(), firm);
            firm[res] = '\0';
            printf("  %s %s %s\n", model, serial, firm);
            if (verbose) {
                if (atapi)
                    printf("ATA IDENTIFY PACKET DEVICE response "
                           "(256 words):\n");
                else
                    printf("ATA IDENTIFY DEVICE response (256 words):\n");
                dWordHex((const unsigned short *)&ata_ident, 256, 0,
                         sg_is_big_endian());
            }
        }
    }
    return 0;
}
#endif

struct version_descriptor {
    int value;
    const char * name;
};

/* table from SPC-4 revision 3 [sorted numerically (Annex D listing)] */
static struct version_descriptor version_descriptor_arr[] = {
    {0x0, "Version Descriptor not supported or No standard identified"},
    {0x20, "SAM (no version claimed)"},
    {0x3b, "SAM T10/0994-D revision 18"},
    {0x3c, "SAM ANSI INCITS 270-1996"},
    {0x40, "SAM-2 (no version claimed)"},
    {0x54, "SAM-2 T10/1157-D revision 23"},
    {0x55, "SAM-2 T10/1157-D revision 24"},
    {0x5c, "SAM-2 ANSI INCITS 366-2003"},
    {0x60, "SAM-3 (no version claimed)"},
    {0x62, "SAM-3 T10/1561-D revision 7"},
    {0x75, "SAM-3 T10/1561-D revision 13"},
    {0x76, "SAM-3 T10/1561-D revision 14"},
    {0x77, "SAM-3 ANSI INCITS 402-2005"},
    {0x80, "SAM-4 (no version claimed)"},
    {0x120, "SPC (no version claimed)"},
    {0x13b, "SPC T10/0995-D revision 11a"},
    {0x13c, "SPC ANSI INCITS 301-1997"},
    {0x140, "MMC (no version claimed)"},
    {0x15b, "MMC T10/1048-D revision 10a"},
    {0x15c, "MMC ANSI INCITS 304-1997"},
    {0x160, "SCC (no version claimed)"},
    {0x17b, "SCC T10/1047-D revision 06c"},
    {0x17c, "SCC ANSI INCITS 276-1997"},
    {0x180, "SBC (no version claimed)"},
    {0x19b, "SBC T10/0996-D revision 08c"},
    {0x19c, "SBC ANSI INCITS 306-1998"},
    {0x1a0, "SMC (no version claimed)"},
    {0x1bb, "SMC T10/0999-D revision 10a"},
    {0x1bc, "SMC ANSI INCITS 314-1998"},
    {0x1c0, "SES (no version claimed)"},
    {0x1db, "SES T10/1212-D revision 08b"},
    {0x1dc, "SES ANSI INCITS 305-1998"},
    {0x1dd, "SES T10/1212-D revision 08b w/ Amendment ANSI "
            "INCITS.305/AM1:2000"},
    {0x1de, "SES ANSI INCITS 305-1998 w/ Amendment ANSI "
            "INCITS.305/AM1:2000"},
    {0x1e0, "SCC-2 (no version claimed}"},
    {0x1fb, "SCC-2 T10/1125-D revision 04"},
    {0x1fc, "SCC-2 ANSI INCITS 318-1998"},
    {0x200, "SSC (no version claimed)"},
    {0x201, "SSC T10/0997-D revision 17"},
    {0x207, "SSC T10/0997-D revision 22"},
    {0x21c, "SSC ANSI INCITS 335-2000"},
    {0x220, "RBC (no version claimed)"},
    {0x238, "RBC T10/1240-D revision 10a"},
    {0x23c, "RBC ANSI INCITS 330-2000"},
    {0x240, "MMC-2 (no version claimed)"},
    {0x255, "MMC-2 T10/1228-D revision 11"},
    {0x25b, "MMC-2 T10/1228-D revision 11a"},
    {0x25c, "MMC-2 ANSI INCITS 333-2000"},
    {0x260, "SPC-2 (no version claimed)"},
    {0x267, "SPC-2 T10/1236-D revision 12"},
    {0x269, "SPC-2 T10/1236-D revision 18"},
    {0x275, "SPC-2 T10/1236-D revision 19"},
    {0x276, "SPC-2 T10/1236-D revision 20"},
    {0x277, "SPC-2 ANSI INCITS 351-2001"},
    {0x280, "OCRW (no version claimed)"},
    {0x29e, "OCRW ISO/IEC 14776-381"},
    {0x2a0, "MMC-3 (no version claimed)"},
    {0x2b5, "MMC-3 T10/1363-D revision 9"},
    {0x2b6, "MMC-3 T10/1363-D revision 10g"},
    {0x2b8, "MMC-3 ANSI INCITS 360-2002"},
    {0x2e0, "SMC-2 (no version claimed)"},
    {0x2f5, "SMC-2 T10/1383-D revision 5"},
    {0x2fc, "SMC-2 T10/1383-D revision 6"},
    {0x2fd, "SMC-2 T10/1383-D revision 7"},
    {0x2fe, "SMC-2 ANSI INCITS 382-2004"},
    {0x300, "SPC-3 (no version claimed)"},
    {0x301, "SPC-3 T10/1416-D revision 7"},
    {0x307, "SPC-3 T10/1416-D revision 21"},
    {0x30f, "SPC-3 T10/1416-D revision 22"},
    {0x312, "SPC-3 T10/1416-D revision 23"},
    {0x314, "SPC-3 ANSI INCITS 408-2005"},
    {0x320, "SBC-2 (no version claimed)"},
    {0x322, "SBC-2 T10/1417-D revision 5a"},
    {0x324, "SBC-2 T10/1417-D revision 15"},
    {0x33b, "SBC-2 T10/1417-D revision 16"},
    {0x33d, "SBC-2 ANSI INCITS 405-2005"},
    {0x340, "OSD (no version claimed)"},
    {0x341, "OSD T10/1355-D revision 0"},
    {0x342, "OSD T10/1355-D revision 7a"},
    {0x343, "OSD T10/1355-D revision 8"},
    {0x344, "OSD T10/1355-D revision 9"},
    {0x355, "OSD T10/1355-D revision 10"},
    {0x356, "OSD ANSI INCITS 400-2004"},
    {0x360, "SSC-2 (no version claimed)"},
    {0x374, "SSC-2 T10/1434-D revision 7"},
    {0x375, "SSC-2 T10/1434-D revision 9"},
    {0x37d, "SSC-2 ANSI INCITS 380-2003"},
    {0x380, "BCC (no version claimed)"},
    {0x3a0, "MMC-4 (no version claimed)"},
    {0x3b0, "MMC-4 T10/1545-D revision 5"},
    {0x3b1, "MMC-4 T10/1545-D revision 5a"},
    {0x3bd, "MMC-4 T10/1545-D revision 3"},
    {0x3be, "MMC-4 T10/1545-D revision 3d"},
    {0x3bf, "MMC-4 ANSI INCITS 401-2005"},
    {0x3c0, "ADC (no version claimed)"},
    {0x3d5, "ADC T10/1558-D revision 6"},
    {0x3d6, "ADC T10/1558-D revision 7"},
    {0x3d7, "ADC ANSI INCITS 403-2005"},
    {0x3e0, "SES-2 (no version claimed)"},
    {0x400, "SSC-3 (no version claimed)"},
    {0x420, "MMC-5 (no version claimed)"},
    {0x440, "OSD-2 (no version claimed)"},
    {0x460, "SPC-4 (no version claimed)"},
    {0x480, "SMC-3 (no version claimed)"},
    {0x4a0, "ADC-2 (no version claimed)"},
    {0x4c0, "SBC-3 (no version claimed)"},
    {0x4e0, "MMC-6 (no version claimed)"},
    {0x820, "SSA-TL2 (no version claimed)"},
    {0x83b, "SSA-TL2 T10/1147-D revision 05b"},
    {0x83c, "SSA-TL2 ANSI INCITS 308-1998"},
    {0x840, "SSA-TL1 (no version claimed)"},
    {0x85b, "SSA-TL1 T10/0989-D revision 10b"},
    {0x85c, "SSA-TL1 ANSI INCITS 295-1996"},
    {0x860, "SSA-S3P (no version claimed)"},
    {0x87b, "SSA-S3P T10/1051-D revision 05b"},
    {0x87c, "SSA-S3P ANSI INCITS 309-1998"},
    {0x880, "SSA-S2P (no version claimed)"},
    {0x89b, "SSA-S2P T10/1121-D revision 07b"},
    {0x89c, "SSA-S2P ANSI INCITS 294-1996"},
    {0x8a0, "SIP (no version claimed)"},
    {0x8bb, "SIP T10/0856-D revision 10"},
    {0x8bc, "SIP ANSI INCITS 292-1997"},
    {0x8c0, "FCP (no version claimed)"},
    {0x8db, "FCP T10/0856-D revision 12"},
    {0x8dc, "FCP ANSI INCITS 269-1996"},
    {0x8e0, "SBP-2 (no version claimed)"},
    {0x8fb, "SBP-2 T10/1155-D revision 04"},
    {0x8fc, "SBP-2 ANSI INCITS 325-1999"},
    {0x900, "FCP-2 (no version claimed)"},
    {0x901, "FCP-2 T10/1144-D revision 4"},
    {0x915, "FCP-2 T10/1144-D revision 7"},
    {0x916, "FCP-2 T10/1144-D revision 7a"},
    {0x917, "FCP-2 ANSI INCITS 350-2003"},
    {0x918, "FCP-2 T10/1144-D revision 8"},
    {0x920, "SST (no version claimed)"},
    {0x935, "SST T10/1380-D revision 8b"},
    {0x940, "SRP (no version claimed)"},
    {0x954, "SRP T10/1415-D revision 10"},
    {0x955, "SRP T10/1415-D revision 16a"},
    {0x95c, "SRP ANSI INCITS 365-2002"},
    {0x960, "iSCSI (no version claimed)"},
    {0x980, "SBP-3 (no version claimed)"},
    {0x982, "SBP-3 T10/1467-D revision 1f"},
    {0x994, "SBP-3 T10/1467-D revision 3"},
    {0x99a, "SBP-3 T10/1467-D revision 4"},
    {0x99b, "SBP-3 T10/1467-D revision 5"},
    {0x99c, "SBP-3 ANSI INCITS 375-2004"},
    /* {0x9a0, "SRP-2 (no version claimed)"}, */
    {0x9c0, "ADP (no version claimed)"},
    {0x9e0, "ADT (no version claimed)"},
    {0x9f9, "ADT T10/1557-D revision 11"},
    {0x9fa, "ADT T10/1557-D revision 14"},
    {0x9fd, "ADT ANSI INCITS 406-2005"},
    {0xa00, "FCP-3 (no version claimed)"},
    {0xa07, "FCP-3 T10/1560-D revision 3f"},
    {0xa0f, "FCP-3 T10/1560-D revision 4"},
    {0xa20, "ADT-2 (no version claimed)"},
    {0xa40, "FCP-4 (no version claimed)"},
    {0xaa0, "SPI (no version claimed)"},
    {0xab9, "SPI T10/0855-D revision 15a"},
    {0xaba, "SPI ANSI INCITS 253-1995"},
    {0xabb, "SPI T10/0855-D revision 15a with SPI Amnd revision 3a"},
    {0xabc, "SPI ANSI INCITS 253-1995 with SPI Amnd ANSI INCITS "
            "253/AM1:1998"},
    {0xac0, "Fast-20 (no version claimed)"},
    {0xadb, "Fast-20 T10/1071-D revision 06"},
    {0xadc, "Fast-20 ANSI INCITS 277-1996"},
    {0xae0, "SPI-2 (no version claimed)"},
    {0xafb, "SPI-2 T10/1142-D revision 20b"},
    {0xafc, "SPI-2 ANSI INCITS 302-1999"},
    {0xb00, "SPI-3 (no version claimed)"},
    {0xb18, "SPI-3 T10/1302-D revision 10"},
    {0xb19, "SPI-3 T10/1302-D revision 13a"},
    {0xb1a, "SPI-3 T10/1302-D revision 14"},
    {0xb1c, "SPI-3 ANSI INCITS 336-2000"},
    {0xb20, "EPI (no version claimed)"},
    {0xb3b, "EPI T10/1134-D revision 16"},
    {0xb3c, "EPI ANSI INCITS TR-23 1999"},
    {0xb40, "SPI-4 (no version claimed)"},
    {0xb54, "SPI-4 T10/1365-D revision 7"},
    {0xb55, "SPI-4 T10/1365-D revision 9"},
    {0xb56, "SPI-4 ANSI INCITS 362-2002"},
    {0xb59, "SPI-4 T10/1365-D revision 10"},
    {0xb60, "SPI-5 (no version claimed)"},
    {0xb79, "SPI-5 T10/1525-D revision 3"},
    {0xb7a, "SPI-5 T10/1525-D revision 5"},
    {0xb7b, "SPI-5 T10/1525-D revision 6"},
    {0xb7c, "SPI-5 ANSI INCITS 367-2004"},
    {0xbe0, "SAS (no version claimed)"},
    {0xbe1, "SAS T10/1562-D revision 01"},
    {0xbf5, "SAS T10/1562-D revision 03"},
    {0xbfa, "SAS T10/1562-D revision 04"},
    {0xbfb, "SAS T10/1562-D revision 04"},
    {0xbfc, "SAS T10/1562-D revision 05"},
    {0xbfd, "SAS ANSI INCITS 376-2003"},
    {0xc00, "SAS-1.1 (no version claimed)"},
    {0xc07, "SAS-1.1 T10/1602-D revision 9"},
    {0xc0f, "SAS-1.1 T10/1602-D revision 10"},
    {0xc11, "SAS-1.1 ANSI INCITS 417-2006"},
    {0xc20, "SAS-2 (no version claimed)"},
    {0xd20, "FC-PH (no version claimed)"},
    {0xd3b, "FC-PH ANSI INCITS 230-1994"},
    {0xd3c, "FC-PH ANSI INCITS 230-1994 with Amnd 1 ANSI INCITS "
            "230/AM1:1996"},
    {0xd40, "FC-AL (no version claimed)"},
    {0xd5c, "FC-AL ANSI INCITS 272-1996"},
    {0xd60, "FC-AL-2 (no version claimed)"},
    {0xd61, "FC-AL-2 T11/1133-D revision 7.0"},
    {0xd7c, "FC-AL-2 ANSI INCITS 332-1999"},
    {0xd7d, "FC-AL-2 ANSI INCITS 332-1999 with Amnd 1 AM1:2002"},
    {0xd80, "FC-PH-3 (no version claimed)"},
    {0xd9c, "FC-PH-3 ANSI INCITS 303-1998"},
    {0xda0, "FC-FS (no version claimed)"},
    {0xdb7, "FC-FS T11/1331-D revision 1.2"},
    {0xdb8, "FC-FS T11/1331-D revision 1.7"},
    {0xdbc, "FC-FS ANSI INCITS 373-2003"},
    {0xdc0, "FC-PI (no version claimed)"},
    {0xddc, "FC-PI ANSI INCITS 352-2002"},
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
    {0x131c, "FC-Tape ANSI INCITS TR-24 1999"},
    {0x1320, "FC-FLA (no version claimed)"},
    {0x133b, "FC-FLA T11/1235-D revision 7"},
    {0x133c, "FC-FLA ANSI INCITS TR-20 1998"},
    {0x1340, "FC-PLDA (no version claimed)"},
    {0x135b, "FC-PLDA T11/1162-D revision 2.1"},
    {0x135c, "FC-PLDA ANSI INCITS TR-19 1998"},
    {0x1360, "SSA-PH2 (no version claimed)"},
    {0x137b, "SSA-PH2 T10/1145-D revision 09c"},
    {0x137c, "SSA-PH2 ANSI INCITS 293-1996"},
    {0x1380, "SSA-PH3 (no version claimed)"},
    {0x139b, "SSA-PH3 T10/1146-D revision 05b"},
    {0x139c, "SSA-PH3 ANSI INCITS 307-1998"},
    {0x14a0, "IEEE 1394 (no version claimed)"},
    {0x14bd, "ANSI IEEE 1394:1995"},
    {0x14c0, "IEEE 1394a (no version claimed)"},
    {0x14e0, "IEEE 1394b (no version claimed)"},
    {0x15e0, "ATA/ATAPI-6 (no version claimed)"},
    {0x15fd, "ATA/ATAPI-6 ANSI INCITS 361-2002"},
    {0x1600, "ATA/ATAPI-7 (no version claimed)"},
    {0x1602, "ATA/ATAPI-7 T13/1532-D revision 3"},
    {0x161c, "ATA/ATAPI-7 ANSI INCITS 397-2005"},
    {0x1620, "ATA/ATAPI-8 ATA-AAM Architecture model (no version claimed)"},
    {0x1621, "ATA/ATAPI-8 ATA-PT Parallel transport (no version claimed)"},
    {0x1622, "ATA/ATAPI-8 ATA-AST Serial transport (no version claimed)"},
    {0x1623, "ATA/ATAPI-8 ATA-ACS ATA/ATAPI command set (no version "
             "claimed)"},
    {0x1728, "Universal Serial Bus Specification, Revision 1.1"},
    {0x1729, "Universal Serial Bus Specification, Revision 2.0"},
    {0x1730, "USB Mass Storage Class Bulk-Only Transport, Revision 1.0"},
    {0x1ea0, "SAT (no version claimed)"},
    {0x1ea7, "SAT T10/1711-d rev 8"},
    {0x1ec0, "SAT-2 (no version claimed)"},
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
