#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2000-2005 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI MODE SENSE command.
   Does 10 byte MODE SENSE commands by default, Trent Piepho added a "-6"
   switch for force 6 byte mode sense commands.
   
*/

static char * version_str = "0.34 20050223";

#define ME "sg_modes: "

#define MX_ALLOC_LEN (1024 * 4)
#define PG_CODE_ALL 0x3f
#define PG_CODE_MASK 0x3f
#define PG_CODE_MAX 0x3f
#define SPG_CODE_ALL 0xff
#define PROTO_SPECIFIC_1 0x18
#define PROTO_SPECIFIC_2 0x19

#define EBUFF_SZ 256


static const char * scsi_ptype_strs[] = {
    "disk",                             /* 0x0 */
    "tape",
    "printer",
    "processor",
    "write once optical disk",
    "cd/dvd",
    "scanner",
    "optical memory device",
    "medium changer",                   /* 0x8 */
    "communications",
    "graphics [0xa]",
    "graphics [0xb]",
    "storage array controller",
    "enclosure services device",
    "simplified direct access device",
    "optical card reader/writer device",
    "bridge controller commands",       /* 0x10 */
    "object storage device",
    "automation/drive interface",
    "0x13", "0x14", "0x15", "0x16", "0x17", "0x18",
    "0x19", "0x1a", "0x1b", "0x1c", "0x1d",
    "well known logical unit",
    "no physical device on this lu",
};

static const char * get_ptype_str(int scsi_ptype)
{
    int num = sizeof(scsi_ptype_strs) / sizeof(scsi_ptype_strs[0]);

    return (scsi_ptype < num) ? scsi_ptype_strs[scsi_ptype] : "";
}

static const char * transport_proto_arr[] =
{
    "Fibre Channel (FCP-2)",
    "Parallel SCSI (SPI-4)",
    "SSA (SSA-S3P)",
    "IEEE 1394 (SBP-3)",
    "Remote Direct Memory Access (SRP)",
    "Internet SCSI (iSCSI)",
    "Serial Attached SCSI (SAS)",
    "Automation/Drive Interface (ADT)",
    "ATA Packet Interface (ATA/ATAPI-7)",
    "Ox9", "Oxa", "Oxb", "Oxc", "Oxd", "Oxe",
    "No specific protocol"
};

struct page_code_desc {
    int page_code;
    int subpage_code;
    const char * desc;
};

static struct page_code_desc pc_desc_common[] = {
    {0x0, 0x0, "Unit Attention condition [vendor: page format optional]"},
    {0x2, 0x0, "Disconnect-Reconnect"},
    {0x9, 0x0, "Peripheral device (obsolete)"},
    {0xa, 0x0, "Control"},
    {0xa, 0x1, "Control extension"},
    {0x15, 0x0, "Extended"},
    {0x16, 0x0, "Extended device-type specific"},
    {0x18, 0x0, "Protocol specific lu"},
    {0x19, 0x0, "Protocol specific port"},
    {0x1a, 0x0, "Power condition"},
    {0x1c, 0x0, "Informational exceptions control"},
    {PG_CODE_ALL, 0x0, "[yields all supported pages]"},
    {PG_CODE_ALL, SPG_CODE_ALL, "[yields all supported pages and subpages]"},
};

static struct page_code_desc pc_desc_disk[] = {
    {0x1, 0x0, "Read-Write error recovery"},
    {0x3, 0x0, "Format (obsolete)"},
    {0x4, 0x0, "Rigid disk geometry (obsolete)"},
    {0x5, 0x0, "Flexible geometry (obsolete)"},
    {0x7, 0x0, "Verify error recovery"},
    {0x8, 0x0, "Caching"},
    {0xb, 0x0, "Medium types supported (obsolete)"},
    {0xc, 0x0, "Notch and partition (obsolete)"},
    {0xd, 0x0, "Power condition (obsolete)"},
    {0x10, 0x0, "XOR control"},
    {0x1c, 0x1, "Background control"},
};

static struct page_code_desc pc_desc_tape[] = {
    {0xf, 0x0, "Data Compression"},
    {0x10, 0x0, "Device config"},
    {0x11, 0x0, "Medium Partition [1]"},
    {0x12, 0x0, "Medium Partition [2]"},
    {0x13, 0x0, "Medium Partition [3]"},
    {0x14, 0x0, "Medium Partition [4]"},
    {0x1c, 0x0, "Informational exceptions control (tape version)"},
    {0x1d, 0x0, "Medium configuration"},
};

static struct page_code_desc pc_desc_cddvd[] = {
    {0x1, 0x0, "Read-Write error recovery"},
    {0x3, 0x0, "MRW"},
    {0x5, 0x0, "Write parameters"},
    {0x7, 0x0, "Verify error recovery"},
    {0x8, 0x0, "Caching"},
    {0xd, 0x0, "CD device parameters (obsolete)"},
    {0xe, 0x0, "CD audio"},
    {0x1a, 0x0, "Power condition (mmc)"},
    {0x1c, 0x0, "Fault/failure reporting control (mmc)"},
    {0x1d, 0x0, "Timeout and protect"},
    {0x2a, 0x0, "MM capabilities and mechanical status (obsolete)"},
};

static struct page_code_desc pc_desc_smc[] = {
    {0x1d, 0x0, "Element address assignment"},
    {0x1e, 0x0, "Transport geometry parameters"},
    {0x1f, 0x0, "Device capabilities"},
    {0x1f, 0x1, "Extended device capabilities"},
};

static struct page_code_desc pc_desc_scc[] = {
    {0x1b, 0x0, "LUN mapping"},
};

static struct page_code_desc pc_desc_ses[] = {
    {0x14, 0x0, "Enclosure services management"},
};

static struct page_code_desc pc_desc_rbc[] = {
    {0x6, 0x0, "RBC device parameters"},
};

static struct page_code_desc pc_desc_adt[] = {
    {0xe, 0x0, "ADC device configuration"},
};

static struct page_code_desc * mode_page_cs_table(int scsi_ptype,
                                                  int * size)
{
    switch (scsi_ptype)
    {
        case -1:        /* common list */
            *size = sizeof(pc_desc_common) / sizeof(pc_desc_common[0]);
            return &pc_desc_common[0];
        case 0:         /* disk (direct access) type devices */
        case 4:
        case 7:
            *size = sizeof(pc_desc_disk) / sizeof(pc_desc_disk[0]);
            return &pc_desc_disk[0];
        case 1:         /* tape devices */
        case 2:
            *size = sizeof(pc_desc_tape) / sizeof(pc_desc_tape[0]);
            return &pc_desc_tape[0];
        case 5:         /* cd/dvd devices */
            *size = sizeof(pc_desc_cddvd) / sizeof(pc_desc_cddvd[0]);
            return &pc_desc_cddvd[0];
        case 8:         /* medium changer devices */
            *size = sizeof(pc_desc_smc) / sizeof(pc_desc_smc[0]);
            return &pc_desc_smc[0];
        case 0xc:       /* storage array devices */
            *size = sizeof(pc_desc_scc) / sizeof(pc_desc_scc[0]);
            return &pc_desc_scc[0];
        case 0xd:       /* enclosure services devices */
            *size = sizeof(pc_desc_ses) / sizeof(pc_desc_ses[0]);
            return &pc_desc_ses[0];
        case 0xe:       /* simplified direct access device */
            *size = sizeof(pc_desc_rbc) / sizeof(pc_desc_rbc[0]);
            return &pc_desc_rbc[0];
        case 0x12:       /* automation device/interface */
            *size = sizeof(pc_desc_adt) / sizeof(pc_desc_adt[0]);
            return &pc_desc_adt[0];
    }
    *size = 0;
    return NULL;
}

static struct page_code_desc pc_desc_t_fcp[] = {
    {0x18, 0x0, "LU control"},
    {0x19, 0x0, "Port control"},
};

static struct page_code_desc pc_desc_t_spi4[] = {
    {0x18, 0x0, "LU control"},
    {0x19, 0x0, "Port control short format"},
    {0x19, 0x1, "Margin control"},
    {0x19, 0x2, "Saved training configuration value"},
    {0x19, 0x3, "Negotiated settings"},
    {0x19, 0x4, "Report transfer capabilities"},
};

static struct page_code_desc pc_desc_t_sas[] = {
    {0x18, 0x0, "LU SSP, short format"},
    {0x19, 0x0, "Port SSP, short format"},
    {0x19, 0x1, "Port SSP, phy control and discover"},
};

static struct page_code_desc pc_desc_t_adt[] = {
    {0xe, 0x1, "Target device"},
    {0xe, 0x2, "DT device primary port"},
    {0xe, 0x3, "Logical unit"},
    {0x18, 0x0, "Protocol specific lu"},
    {0x19, 0x0, "Protocol specific port"},
};

static struct page_code_desc * mode_page_transp_table(int t_proto,
                                                      int * size)
{
    switch (t_proto)
    {
        case 0:         /* Fibre channel */
            *size = sizeof(pc_desc_t_fcp) / sizeof(pc_desc_t_fcp[0]);
            return &pc_desc_t_fcp[0];
        case 1:         /* SPI-4 */
            *size = sizeof(pc_desc_t_spi4) / sizeof(pc_desc_t_spi4[0]);
            return &pc_desc_t_spi4[0];
        case 6:         /* SAS-1.1 */
            *size = sizeof(pc_desc_t_sas) / sizeof(pc_desc_t_sas[0]);
            return &pc_desc_t_sas[0];
        case 7:         /* ADT/ADC */
            *size = sizeof(pc_desc_t_adt) / sizeof(pc_desc_t_adt[0]);
            return &pc_desc_t_adt[0];
    }
    *size = 0;
    return NULL;
}

static const char * find_page_code_desc(int page_num, int subpage_num,
                                        int scsi_ptype, int t_proto)
{
    int k;
    int num;
    const struct page_code_desc * pcdp;

    if (t_proto >= 0) {
        pcdp = mode_page_transp_table(t_proto, &num);
        if (pcdp) {
            for (k = 0; k < num; ++k, ++pcdp) {
                if ((page_num == pcdp->page_code) &&
                    (subpage_num == pcdp->subpage_code))
                    return pcdp->desc;
                else if (page_num < pcdp->page_code)
                    break;
            }
        }
    }
    pcdp = mode_page_cs_table(scsi_ptype, &num);
    if (pcdp) {
        for (k = 0; k < num; ++k, ++pcdp) {
            if ((page_num == pcdp->page_code) &&
                (subpage_num == pcdp->subpage_code))
                return pcdp->desc;
            else if (page_num < pcdp->page_code)
                break;
        }
    }
    pcdp = mode_page_cs_table(-1, &num);
    for (k = 0; k < num; ++k, ++pcdp) {
        if ((page_num == pcdp->page_code) &&
            (subpage_num == pcdp->subpage_code))
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            break;
    }
    return NULL;
}

static void list_page_codes(int scsi_ptype, int t_proto)
{
    int num, num_ptype, pg, spg, c, d, valid_transport;
    const struct page_code_desc * dp;
    const struct page_code_desc * pe_dp;

    valid_transport = ((t_proto >= 0) && (t_proto <= 0xf)) ? 1 : 0;
    printf("Page[,subpage]   Name\n");
    printf("=====================\n");
    dp = mode_page_cs_table(-1, &num);
    pe_dp = mode_page_cs_table(scsi_ptype, &num_ptype);
    while (1) {
        pg = dp ? dp->page_code : PG_CODE_ALL + 1; 
        spg = dp ? dp->subpage_code : SPG_CODE_ALL; 
        c = (pg << 8) + spg;
        pg = pe_dp ? pe_dp->page_code : PG_CODE_ALL + 1; 
        spg = pe_dp ? pe_dp->subpage_code : SPG_CODE_ALL;
        d = (pg << 8) + spg;
        if (valid_transport &&
            ((PROTO_SPECIFIC_1 == c) || (PROTO_SPECIFIC_2 == c)))
            dp = (--num <= 0) ? NULL : (dp + 1); /* skip protocol specific */
        else if (c == d) { 
            if (pe_dp->subpage_code)
                printf(" 0x%02x,0x%02x    *  %s\n", pe_dp->page_code,
                       pe_dp->subpage_code, pe_dp->desc);   
            else
                printf(" 0x%02x         *  %s\n", pe_dp->page_code,
                       pe_dp->desc);   
            dp = (--num <= 0) ? NULL : (dp + 1);
            pe_dp = (--num_ptype <= 0) ? NULL : (pe_dp + 1);
        } else if (c < d) { 
            if (dp->subpage_code)
                printf(" 0x%02x,0x%02x       %s\n", dp->page_code,
                       dp->subpage_code, dp->desc);   
            else
                printf(" 0x%02x            %s\n", dp->page_code,
                       dp->desc);
            dp = (--num <= 0) ? NULL : (dp + 1);
        } else {
            if (pe_dp->subpage_code)
                printf(" 0x%02x,0x%02x       %s\n", pe_dp->page_code,
                       pe_dp->subpage_code, pe_dp->desc);   
            else
                printf(" 0x%02x            %s\n", pe_dp->page_code,
                       pe_dp->desc);   
            pe_dp = (--num_ptype <= 0) ? NULL : (pe_dp + 1);
        }
        if ((NULL == dp) && (NULL == pe_dp))
            break;
    }
    if (valid_transport) {
        printf("\n    Transport protocol: %s\n",
               transport_proto_arr[t_proto]);
        dp = mode_page_transp_table(t_proto, &num);
        while (dp) {
            if (dp->subpage_code)
                printf(" 0x%02x,0x%02x       %s\n", dp->page_code,
                       dp->subpage_code, dp->desc);   
            else
                printf(" 0x%02x            %s\n", dp->page_code,
                       dp->desc);
            dp = (--num <= 0) ? NULL : (dp + 1);
        }
    }
}

static const char * pg_control_str_arr[] = {
    "current",
    "changeable",
    "default",
    "saved",
};

static void usage()
{
    printf("Usage: 'sg_modes [-a] [-A] [-c=<page_control] [-d] [-D] [-h] "
           "[-l]\n\t\t"
           " [-p=<page_number>[,<sub_page_code>]] [-r]"
           "\n\t\t [-subp=<sub_page_code>] [-v] [-V] [-6] [<scsi_device>]'\n"
           " where -a   get all mode pages supported by device\n"
           "       -A   get all mode pages and subpages supported by device\n"
           "       -c=<page_control> page control (def: 0 [current],"
           " 1 [changeable],\n            2 [default], 3 [saved])\n"
           "       -d   disable block descriptors (field in cdb)\n"
           "       -D   disable block descriptor output\n"
           "       -h   output in hex\n"
           "       -l   list common page codes for device peripheral type,\n"
           "            if no device given then assume disk type\n"
           "       -p=<page_code> page code in hex (def: 0)\n"
           "       -p=<page_code>,<sub_page_code> both in hex, (defs: 0)\n"
           "       -r   mode page output to stdout, a byte per line in "
           "ASCII hex\n"
           "       -subp=<sub_page_code> (in hex, def: 0)\n"
           "       -v   verbose\n"
           "       -V   output version string\n"
           "       -6   Use MODE SENSE(6) instead of MODE SENSE(10)\n"
           "       -?   output this usage message\n");
}


int main(int argc, char * argv[])
{
    int sg_fd, k, num, len, res, md_len, bd_len, longlba, page_num, spf;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    const char * descp;
    unsigned char rsp_buff[MX_ALLOC_LEN];
    int rsp_buff_size = MX_ALLOC_LEN;
    unsigned int u, uu;
    int pg_code = -1;
    int sub_pg_code = 0;
    int sub_pg_code_set = 0;
    int pc = 0;
    int do_all = 0;
    int do_all_sub = 0;
    int do_dbd = 0;
    int no_desc_out = 0;
    int do_hex = 0;
    int do_mode6 = 0;  /* Use MODE SENSE(6) instead of MODE SENSE(10) */
    int do_list = 0;
    int do_raw = 0;
    int do_verbose = 0;
    int oflags = O_RDONLY | O_NONBLOCK;
    int density_code_off, t_proto;
    unsigned char * ucp;
    unsigned char uc;
    struct sg_simple_inquiry_resp inq_out;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-a", argv[k]))
            do_all = 1;
        else if (0 == strcmp("-A", argv[k])) {
            do_all = 1;
            do_all_sub = 1;
        } else if (0 == strncmp("-c=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 3)) {
                fprintf(stderr, "Bad page control after '-c' switch\n");
                file_name = 0;
                break;
            }
            pc = u;
        } else if (0 == strcmp("-d", argv[k]))
            do_dbd = 1;
        else if (0 == strcmp("-D", argv[k]))
            no_desc_out = 1;
        else if (0 == strcmp("-h", argv[k]))
            do_hex = 1;
        else if (0 == strcmp("-l", argv[k]))
            do_list = 1;
        else if (0 == strncmp("-p=", argv[k], 3)) {
            if (NULL == strchr(argv[k] + 3, ',')) {
                num = sscanf(argv[k] + 3, "%x", &u);
                if ((1 != num) || (u > 63)) {
                    fprintf(stderr, "Bad page code value after '-p' switch\n");
                    file_name = 0;
                    break;
                }
                pg_code = u;
            } else if (2 == sscanf(argv[k] + 3, "%x,%x", &u, &uu)) {
                if (uu > 255) {
                    fprintf(stderr, "Bad sub page code value after '-p' "
                            "switch\n");
                    file_name = 0;
                    break;
                }
                pg_code = u;
                sub_pg_code = uu;
                sub_pg_code_set = 1;
            } else {
                fprintf(stderr, "Bad page code, subpage code sequence after "
                        "'-p' switch\n");
                file_name = 0;
                break;
            }
        } else if (0 == strcmp("-r", argv[k]))
            do_raw = 1;
        else if (0 == strncmp("-subp=", argv[k], 6)) {
            num = sscanf(argv[k] + 6, "%x", &u);
            if ((1 != num) || (u > 255)) {
                fprintf(stderr, "Bad sub page code after '-subp' switch\n");
                file_name = 0;
                break;
            }
            sub_pg_code = u;
            sub_pg_code_set = 1;
            if (-1 == pg_code)
                pg_code = 0;
        } else if (0 == strcmp("-v", argv[k]))
            ++do_verbose;
        else if (0 == strcmp("-V", argv[k])) {
            printf("Version string: %s\n", version_str);
            exit(0);
        } else if (0 == strcmp("-6", argv[k]))
            do_mode6 = 1;
        else if (0 == strcmp("-?", argv[k])) {
            usage();
            return 0;
        } else if (*argv[k] == '-') {
            fprintf(stderr, "Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        } else if (0 == file_name)
            file_name = argv[k];
        else {
            fprintf(stderr, "too many arguments\n");
            file_name = 0;
            break;
        }
    }
    if (0 == file_name) {
        if (do_list) {
            if ((pg_code < 0) || (pg_code > 0x1f)) {
                printf("    Assume peripheral device type: disk\n");
                list_page_codes(0, -1);
            } else {
                printf("    peripheral device type: %s\n",
                       get_ptype_str(pg_code));
                if (sub_pg_code_set)
                    list_page_codes(pg_code, sub_pg_code);
                else
                    list_page_codes(pg_code, -1);
            }
            return 0;
        }
        usage();
        return 1;
    }

    /* The 6 bytes command only allows up to 252 bytes of response data */
    if (do_mode6) 
        rsp_buff_size = 252;
    /* If no pages or list selected than treat as 'a' */
    if (! ((pg_code >= 0) || do_all || do_list))
        do_all = 1;

    if ((sg_fd = open(file_name, oflags)) < 0) {
        snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }

    if (sg_simple_inquiry(sg_fd, &inq_out, 1, do_verbose)) {
        fprintf(stderr, ME "%s doesn't respond to a SCSI INQUIRY\n",
                file_name);
        close(sg_fd);
        return 1;
    }
    if (0 == do_raw)
        printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n", 
               inq_out.vendor, inq_out.product, inq_out.revision,
               get_ptype_str(inq_out.peripheral_type),
               inq_out.peripheral_type);

    if (do_list) {
        if (sub_pg_code_set)
            list_page_codes(inq_out.peripheral_type, sub_pg_code);
        else
            list_page_codes(inq_out.peripheral_type, -1);
        return 0;
    }
    if (PG_CODE_ALL == pg_code)
        do_all = 1;
    else if (do_all)
        pg_code = PG_CODE_ALL;
    if (do_all && do_all_sub)
        sub_pg_code = SPG_CODE_ALL;

    if (do_raw) {
        if (do_all) {
            fprintf(stderr, "'-r' requires a given (sub)page (not all)\n");
            usage();
            return 1;
        }
        if (do_hex) {
            fprintf(stderr, "'-r' and '-h' clash");
            usage();
            return 1;
        }
    }

    if (do_mode6) {
        res = sg_ll_mode_sense6(sg_fd, do_dbd, pc, pg_code, sub_pg_code,
                                rsp_buff, rsp_buff_size, 1, do_verbose);
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, ">>>>>> try again without the '-6' "
                    "switch for a 10 byte MODE SENSE command\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in cdb (perhaps subpages "
                    "not supported\n");
    } else {
        res = sg_ll_mode_sense10(sg_fd, 0 /* llbaa */, do_dbd, pc, pg_code,
                         sub_pg_code, rsp_buff, rsp_buff_size, 1, do_verbose);
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, ">>>>>> try again with a '-6' "
                    "switch for a 6 byte MODE SENSE command\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in cdb (perhaps subpages "
                    "not supported\n");
    }
    if (0 == res) {
        int medium_type, specific, headerlen;

        if (! do_raw)
            printf("Mode parameter header from %s byte MODE SENSE:\n",
                   (do_mode6 ? "6" : "10"));
        if (do_mode6) {
            headerlen = 4;
            md_len = rsp_buff[0] + 1;
            bd_len = rsp_buff[3];
            medium_type = rsp_buff[1];
            specific = rsp_buff[2];
            longlba = 0;
        } else {
            headerlen = 8;
            md_len = (rsp_buff[0] << 8) + rsp_buff[1] + 2;
            bd_len = (rsp_buff[6] << 8) + rsp_buff[7];
            medium_type = rsp_buff[2];
            specific = rsp_buff[3];
            longlba = rsp_buff[4] & 1;
        }
        if (do_raw) {
            ucp = rsp_buff + bd_len + headerlen; 
            md_len -= bd_len + headerlen;
            spf = ((ucp[0] & 0x40) ? 1 : 0);
            len = (spf ? ((ucp[2] << 8) + ucp[3] + 4) : (ucp[1] + 2));
            len = (len < md_len) ? len : md_len;
            for (k = 0; k < len; ++k)
                printf("%02x\n", ucp[k]);
            close(sg_fd);
            return 0;
        }
        if (do_hex)
            dStrHex((const char *)rsp_buff, headerlen, 1);
        if (0 == inq_out.peripheral_type)
            printf("  Mode data length=%d, medium type=0x%.2x, WP=%d,"
                   " DpoFua=%d, longlba=%d\n", md_len, medium_type, 
                   !!(specific & 0x80), !!(specific & 0x10), longlba);
        else
            printf("  Mode data length=%d, medium type=0x%.2x, specific"
                   " param=0x%.2x, longlba=%d\n", md_len, medium_type, 
                   specific, longlba);
        if (md_len > rsp_buff_size) {
            printf("Only fetched %d bytes of response, truncate output\n",
                   rsp_buff_size);
            md_len = rsp_buff_size;
            if (bd_len + headerlen > rsp_buff_size)
                bd_len = rsp_buff_size - headerlen;
        }
        if (! no_desc_out) {
            printf("  Block descriptor length=%d\n", bd_len);
            if (bd_len > 0) {
                len = 8;
                density_code_off = 0;
                num = bd_len;
                if (longlba) {
                    printf("> longlba block descriptors:\n");
                    len = 16;
                    density_code_off = 8;
                }
                else if (0 == inq_out.peripheral_type) { 
                    printf("> Direct access device block descriptors:\n");
                    density_code_off = 4;
                }
                else
                    printf("> General mode parameter block descriptors:\n");
    
                ucp = rsp_buff + headerlen;
                while (num > 0) {
                    printf("   Density code=0x%x\n", *(ucp + density_code_off));
                    dStrHex((const char *)ucp, len, 1);
                    ucp += len;
                    num -= len;
                }
                printf("\n");
            }
        }
        ucp = rsp_buff + bd_len + headerlen;    /* start of mode page(s) */
        md_len -= bd_len + headerlen;           /* length of mode page(s) */
        for (k = 0; md_len > 0; ++k) { /* got mode page(s) */
            if ((k > 0) && (! do_all) && (SPG_CODE_ALL != sub_pg_code)) {
                fprintf(stderr, "Unexpectedly received extra mode page "
                                "responses, ignore\n");
                break;
            }
            uc = *ucp;
            spf = ((uc & 0x40) ? 1 : 0);
            len = (spf ? ((ucp[2] << 8) + ucp[3] + 4) : (ucp[1] + 2));
            page_num = ucp[0] & PG_CODE_MASK;
            if (do_hex) {
                if (spf)
                    printf(">> page_code=0x%x, subpage_code=0x%x, "
                           "page_control=%d\n", page_num, ucp[1], pc);
                else
                    printf(">> page_code=0x%x, page_control=%d\n", page_num,
                           pc);
            } else {
                descp = NULL;
                if ((0x18 == page_num) || (0x19 == page_num)) {
                    t_proto = (spf ? ucp[5] : ucp[2]) & 0xf;
                    descp = find_page_code_desc(page_num, (spf ? ucp[1] : 0),
                                                inq_out.peripheral_type,
                                                t_proto);
                } else
                    descp = find_page_code_desc(page_num, (spf ? ucp[1] : 0),
                                                inq_out.peripheral_type, -1);
                if (NULL == descp) {
                    if (spf)
                        snprintf(ebuff, EBUFF_SZ, "0x%x, subpage_code: 0x%x",
                                 page_num, ucp[1]);
                    else
                        snprintf(ebuff, EBUFF_SZ, "0x%x", page_num);
                }
                if (descp)
                    printf(">> %s, page_control: %s\n", descp,
                           pg_control_str_arr[pc]);
                else
                    printf(">> page_code: %s, page_control: %s\n", ebuff,
                           pg_control_str_arr[pc]);
            }
            dStrHex((const char *)ucp, ((len > md_len) ? md_len : len) , 1);
            ucp += len;
            md_len -= len;
        }
    }
    close(sg_fd);
    return 0;
}
