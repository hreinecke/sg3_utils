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
#include "sg_err.h"

/* A utility program for the Linux OS SCSI subsystem.
*  Copyright (C) 2000-2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI INQUIRY command.
   It is mainly based on the SCSI SPC-3 document.

   Acknowledgment:
      - Martin Schwenke <martin at meltin dot net> added the raw switch and 
        other improvements [20020814]

From SPC-3 revision 16 the CmdDt bit in an INQUIRY is obsolete. There is
now a REPORT SUPPORTED OPERATION CODES command that yields similar
information [MAINTENANCE IN, service action = 0xc]. Support will be added
in the future.
   
*/

static char * version_str = "0.32 20040622";


#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define DEV_ID_VPD  0x83
#define DEF_ALLOC_LEN 252
#define MX_ALLOC_LEN 4096

#define EBUFF_SZ 256


static unsigned char rsp_buff[MX_ALLOC_LEN + 1];
static char xtra_buff[MX_ALLOC_LEN + 1];

static void dStrHex(const char* str, int len, int no_ascii);

static int try_ata_identity(int ata_fd, int do_raw);

/* Returns 0 when successful, -1 -> SG_IO ioctl failed, -2 -> bad response */
static int do_inq(int sg_fd, int cmddt, int evpd, unsigned int pg_op, 
                  void * resp, int mx_resp_len, int noisy, int verbose)
{
    int res, k;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (cmddt)
        inqCmdBlk[1] |= 2;
    if (evpd)
        inqCmdBlk[1] |= 1;
    inqCmdBlk[2] = (unsigned char)pg_op;
    inqCmdBlk[3] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    inqCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
    if (verbose) {
        fprintf(stderr, "    inquiry cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            fprintf(stderr, "%02x ", inqCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
	if (noisy || verbose)
            perror("SG_IO (inquiry) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        return 0;
    default:
        if (noisy || verbose) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, "Inquiry error, CmdDt=%d, "
                     "VPD=%d, page_opcode=%x ", cmddt, evpd, pg_op);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -2;
    }
}

static void usage()
{
    fprintf(stderr,
            "Usage: 'sg_inq [-c] [-cl] [-e] [-h|-r] [-i] [-o=<opcode_page>]"
            " [-v] [-V]\n               [-36] [-?] <scsi_device>'\n"
            " where -c   set CmdDt mode (use -o for opcode) [obsolete]\n"
            "       -cl  list supported commands using CmdDt mode [obsolete]\n"
            "       -e   set VPD mode (use -o for page code)\n"
            "       -h   output in hex (ASCII to the right)\n"
            "       -i   decode device identification VPD page (0x83)\n"
            "       -o=<opcode_page> opcode or page code in hex\n"
            "       -r   output raw binary data\n"
            "       -v   verbose\n"
            "       -V   output version string\n"
            "       -36  only perform a 36 byte INQUIRY\n"
            "       -?   output this usage message\n"
            " If no optional switches given (or '-h') then does"
            " a standard INQUIRY\n");
}


static void dStrRaw(const char* str, int len)
{
    int i;
    
    for (i = 0 ; i < len; i++) {
        printf("%c", str[i]);
    }
}

static void dStrHex(const char* str, int len, int no_ascii)
{
    const char* p = str;
    unsigned char c;
    char buff[82];
    int a = 0;
    const int bpstart = 5;
    const int cpstart = 60;
    int cpos = cpstart;
    int bpos = bpstart;
    int i, k;
    
    if (len <= 0) return;
    memset(buff,' ',80);
    buff[80]='\0';
    k = sprintf(buff + 1, "%.2x", a);
    buff[k + 1] = ' ';
    if (bpos >= ((bpstart + (9 * 3))))
        bpos++;

    for(i = 0; i < len; i++)
    {
        c = *p++;
        bpos += 3;
        if (bpos == (bpstart + (9 * 3)))
            bpos++;
        sprintf(&buff[bpos], "%.2x", (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if (no_ascii)
            buff[cpos++] = ' ';
        else {
            if ((c < ' ') || (c >= 0x7f))
                c='.';
            buff[cpos++] = c;
        }
        if (cpos > (cpstart+15))
        {
            printf("%s\n", buff);
            bpos = bpstart;
            cpos = cpstart;
            a += 16;
            memset(buff,' ',80);
            k = sprintf(buff + 1, "%.2x", a);
            buff[k + 1] = ' ';
        }
    }
    if (cpos > cpstart)
    {
        printf("%s\n", buff);
    }
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

const char * get_ptype_str(int scsi_ptype)
{
    int num = sizeof(scsi_ptype_strs) / sizeof(scsi_ptype_strs[0]);

    if (0x1f == scsi_ptype)
        return "no physical device on this lu";
    else if (0x1e == scsi_ptype)
        return "well known logical unit";
    else
        return (scsi_ptype < num) ? scsi_ptype_strs[scsi_ptype] : "";
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


static void decode_id_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, j, m, id_len, p_id, c_set, piv, assoc, id_type, i_len;
    int ci_off, c_id, d_id, naa, vsi;
    unsigned long long vsei;
    unsigned long long id_ext;
    unsigned char * ucp;
    unsigned char * ip;

    if (len < 4) {
        fprintf(stderr, "Device identification VPD page length too "
                "short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0, j = 1; k < len; k += id_len, ucp += id_len, ++j) {
        i_len = ucp[3];
        id_len = i_len + 4;
        if ((k + id_len) > len) {
            fprintf(stderr, "Device id VPD page, short descriptor "
                    "length=%d, left=%d\n", id_len, (len - k));
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


int main(int argc, char * argv[])
{
    int sg_fd, k, j, num, len, act_len, res;
    int support_num;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    const char * cp;
    unsigned int num_opcode = 0;
    int do_evpd = 0;
    int do_cmddt = 0;
    int do_cmdlst = 0;
    int do_di_vpd = 0;
    int do_hex = 0;
    int do_raw = 0;
    int do_36 = 0;
    int do_verbose = 0;
    int oflags = O_RDONLY | O_NONBLOCK;
    int ansi_version = 0;
    int ret = 0;
    int peri_type = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-o=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &num_opcode);
            if ((1 != num) || (num_opcode > 255)) {
                fprintf(stderr, "Bad number after '-o' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strcmp("-e", argv[k]))
            do_evpd = 1;
        else if (0 == strcmp("-h", argv[k]))
            do_hex = 1;
        else if (0 == strcmp("-i", argv[k]))
            do_di_vpd = 1;
        else if (0 == strcmp("-r", argv[k]))
            do_raw = 1;
        else if (0 == strcmp("-cl", argv[k])) {
            do_cmdlst = 1;
            do_cmddt = 1;
        }
        else if (0 == strcmp("-c", argv[k]))
            do_cmddt = 1;
        else if (0 == strcmp("-36", argv[k]))
            do_36 = 1;
        else if (0 == strcmp("-v", argv[k]))
            ++do_verbose;
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
    
    if (do_raw && do_hex) {
        fprintf(stderr, "Can't do hex and raw at the same time\n");
        file_name = 0;
    }
    if (do_di_vpd && (do_cmddt || do_evpd || (0 != num_opcode))) {
        fprintf(stderr, "Can't use '-i' with other VPD or CmdDt flags\n");
        file_name = 0;
    }
    if (0 == file_name) {
        usage();
        return 1;
    }

    if ((sg_fd = open(file_name, oflags)) < 0) {
        snprintf(ebuff, EBUFF_SZ, "sg_inq: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    memset(rsp_buff, 0, MX_ALLOC_LEN + 1);

    if (num_opcode > 0) {
        printf(" <<given page_code so assumed EVPD selected>>\n");
        do_evpd = 1;
    }

    if (! (do_cmddt || do_evpd || do_di_vpd)) {
	res = do_inq(sg_fd, 0, 0, 0, rsp_buff, 36, 0, do_verbose);
        if (0 == res) {
            if (!do_raw)
                printf("standard INQUIRY:\n");
            len = rsp_buff[4] + 5;
            ansi_version = rsp_buff[2] & 0x7;
            peri_type = rsp_buff[0] & 0x1f;
            if ((len > 36) && (len < 256) && (! do_36)) {
                if (do_inq(sg_fd, 0, 0, 0, rsp_buff, len, 1, do_verbose)) {
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
                printf("  PQual=%d  Device_type=%d  RMB=%d  [ANSI_version=%d] ",
                       (rsp_buff[0] & 0xe0) >> 5, peri_type,
                       !!(rsp_buff[1] & 0x80), ansi_version);
                printf(" version=0x%02x\n", (unsigned int)rsp_buff[2]);
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
                printf("   Peripheral device type: %s\n", cp);

                if (len <= 8)
                    printf(" Inquiry response length=%d\n, no vendor, "
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
                }
            }
            if (!do_raw &&
                (0 == do_inq(sg_fd, 0, 1, 0x80, rsp_buff, DEF_ALLOC_LEN, 0, 
                             do_verbose))) {
                len = rsp_buff[3];
                if (len > 0) {
                    memcpy(xtra_buff, rsp_buff + 4, len);
                    xtra_buff[len] = '\0';
                    printf(" Product serial number: %s\n", xtra_buff);
                }
            }
        }
        else if (-1 == res) { /* could be an ATA device */
	    /* Try an ATA Identity command */
	    res = try_ata_identity(sg_fd, do_raw);
	    if (0 != res) {
		fprintf(stderr, "Both SCSI INQUIRY and ATA IDENTITY failed "
			"on %s with this error:\n\t%s\n", file_name, 
			strerror(res));
		return 1;
	    }
        } else {	/* SCSI device not supporting 36 byte INQUIRY?? */
            printf("36 byte INQUIRY failed\n");
            return 1;
        }
    } else if (do_cmddt) {
        int reserved_cmddt;
        char op_name[128];

        if (do_cmdlst) {
            printf("Supported command list:\n");
            for (k = 0; k < 256; ++k) {
                if (0 == do_inq(sg_fd, 1, 0, k, rsp_buff, DEF_ALLOC_LEN, 1,
                                do_verbose)) {
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
                    }
                    else if ((4 == support_num) || (6 == support_num))
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
            if (0 == do_inq(sg_fd, 1, 0, num_opcode, rsp_buff, 
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
    } else if (do_evpd) {
        if (!do_raw)
            printf("VPD INQUIRY, page code=0x%.2x:\n", num_opcode);
        if (0 == do_inq(sg_fd, 0, 1, num_opcode, rsp_buff, DEF_ALLOC_LEN, 1,
                        do_verbose)) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            ret = 3;
            if (num_opcode != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                goto err_out;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                goto err_out;
            } else if (len > DEF_ALLOC_LEN) {
                if (do_inq(sg_fd, 0, 1, num_opcode, rsp_buff, len, 1, 
                           do_verbose))
                    goto err_out;
            }
            ret = 0;
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                if (do_hex)
                    dStrHex((const char *)rsp_buff, len, 0);
                else if (0 == num_opcode) { /* decode this mandatory page */
                    printf(" Supported VPD pages\n");
                    peri_type = rsp_buff[0] & 0x1f;
                    printf("   PQual=%d  Peripheral device type: %s\n",
                           (rsp_buff[0] & 0xe0) >> 5, 
                           get_ptype_str(peri_type));
                    num = rsp_buff[3];
                    for (k = 0; k < num; ++k)
                        printf("     0x%x\n", rsp_buff[4 + k]);
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
    } else if (do_di_vpd) {
        if (!do_raw)
            printf("VPD INQUIRY: Device Identification page\n");
        if (0 == do_inq(sg_fd, 0, 1, DEV_ID_VPD, rsp_buff, DEF_ALLOC_LEN, 1,
                        do_verbose)) {
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
                if (do_inq(sg_fd, 0, 1, DEV_ID_VPD, rsp_buff, len, 1, 
                           do_verbose))
                    goto err_out;
            }
            ret = 0;
            if (do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_id_vpd(rsp_buff, len, do_hex);
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
