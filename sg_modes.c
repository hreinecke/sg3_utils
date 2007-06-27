#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "sg_lib.h"
#include "sg_cmds_basic.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2000-2006 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI MODE SENSE command.
   Does 10 byte MODE SENSE commands by default, Trent Piepho added a "-6"
   switch for force 6 byte mode sense commands.
   
*/

static char * version_str = "1.20 20061012";

#define ME "sg_modes: "

#define MX_ALLOC_LEN (1024 * 4)
#define PG_CODE_ALL 0x3f
#define PG_CODE_MASK 0x3f
#define PG_CODE_MAX 0x3f
#define SPG_CODE_ALL 0xff
#define PROTO_SPECIFIC_1 0x18
#define PROTO_SPECIFIC_2 0x19

#define EBUFF_SZ 256


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
    {0x0, 0x0, "Unit Attention condition [vendor specific format]"},
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
    {0xa, 0xf1, "Parallel ATA control (SAT)"},
    {0xa, 0xf2, "Reserved (SATA control) (SAT)"},
    {0xb, 0x0, "Medium types supported (obsolete)"},
    {0xc, 0x0, "Notch and partition (obsolete)"},
    {0xd, 0x0, "Power condition (obsolete, moved to 0x1a)"},
    {0x10, 0x0, "XOR control"},
    {0x1c, 0x1, "Background control"},
};

static struct page_code_desc pc_desc_tape[] = {
    {0xf, 0x0, "Data Compression"},
    {0x10, 0x0, "Device configuration"},
    {0x10, 0x1, "Device configuration extension"},
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
    {0x1f, 0x41, "Extended device capabilities"},
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
    /* {0xe, 0x0, "ADC device configuration"}, */
    {0xe, 0x1, "Target device"},
    {0xe, 0x2, "DT device primary port"},
    {0xe, 0x3, "Logical unit"},
    {0xe, 0x4, "Target device serial number"},
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
    {0x19, 0x2, "Port SSP, shared"},
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
                                        int scsi_ptype, int inq_byte6,
                                        int t_proto)
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
    if ((0xd != scsi_ptype) && (inq_byte6 & 0x40)) {
        /* check for attached enclosure services processor */
        pcdp = mode_page_cs_table(0xd, &num);
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
    if ((0x8 != scsi_ptype) && (inq_byte6 & 0x8)) {
        /* check for attached medium changer device */
        pcdp = mode_page_cs_table(0x8, &num);
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

static void list_page_codes(int scsi_ptype, int inq_byte6, int t_proto)
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
    if ((0xd != scsi_ptype) && (inq_byte6 & 0x40)) {
        /* check for attached enclosure services processor */
        printf("\n    Attached enclosure services processor\n");
        dp = mode_page_cs_table(0xd, &num);
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
    if ((0x8 != scsi_ptype) && (inq_byte6 & 0x8)) {
        /* check for attached medium changer device */
        printf("\n    Attached medium changer device\n");
        dp = mode_page_cs_table(0x8, &num);
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

static int examine_pages(int sg_fd, int do_mode6, int inq_pdt, int inq_byte6,
                         int verbose)
{
    int k, res, header;
    unsigned char rbuf[4];
    const char * cp;

    for (header = 0, k = 0; k < 0x3f; ++k) {
        if (do_mode6) {
            res = sg_ll_mode_sense6(sg_fd, 0, 0, k, 0,
                                    rbuf, sizeof(rbuf), 0, verbose);
            if (SG_LIB_CAT_INVALID_OP == res) {
                fprintf(stderr, ">>>>>> try again without the '-6' "
                        "switch for a 10 byte MODE SENSE command\n");
                return res;
            } else if (SG_LIB_CAT_NOT_READY == res) {
                fprintf(stderr, "MODE SENSE (6) failed, device not ready\n");
                return res;
            }
        } else {
            res = sg_ll_mode_sense10(sg_fd, 0, 0, 0, k,
                                     0, rbuf, sizeof(rbuf), 1, verbose);
            if (SG_LIB_CAT_INVALID_OP == res) {
                fprintf(stderr, ">>>>>> try again with a '-6' "
                        "switch for a 6 byte MODE SENSE command\n");
                return res;
            } else if (SG_LIB_CAT_NOT_READY == res) {
                fprintf(stderr, "MODE SENSE (10) failed, device not ready\n");
                return res;
            }
        }
        if (0 == res) {
            if (0 == header) {
                printf("Discovered mode pages:\n");
                header = 1;
            }
            cp = find_page_code_desc(k, 0, inq_pdt, inq_byte6, -1);
            if (cp)
                printf("    %s\n", cp);
            else
                printf("    [0x%x]\n", k);
        }
    }
    return res;
}

static const char * pg_control_str_arr[] = {
    "current",
    "changeable",
    "default",
    "saved",
};

static void usage()
{
    printf("Usage:  sg_modes [-a] [-A] [-c=<page_control] [-d] [-D] [-f] "
           "[-e] [-h] [-H]\n\t\t"
           " [-l] [-L] [-p=<page_number>[,<sub_page_code>]] [-r]"
           "\n\t\t [-subp=<sub_page_code>] [-v] [-V] [-6] [<scsi_device>]\n"
           " where:\n"
           "   -a    get all mode pages supported by device\n"
           "   -A    get all mode pages and subpages supported by device\n"
           "   -c=<page_control>    page control (def: 0 [current],"
           " 1 [changeable],\n"
           "                                           2 [default], "
           "3 [saved])\n"
           "   -d    disable block descriptors (DBD field in cdb)\n"
           "   -e    examine pages # 0 through to 0x3e, note if found\n"
           "   -D    disable block descriptor output\n"
           "   -f    be flexible, cope with MODE SENSE 6/10 response "
           "mixup\n");
    printf("   -h    output page number and header in hex\n"
           "   -H    output page number and header in hex (same as '-h')\n"
           "   -l    list common page codes for device peripheral type,\n"
           "         if no device given then assume disk type\n"
           "   -L    set Long LBA Accepted (LLBAA field in mode sense "
           "10 cdb)\n"
           "   -p=<page_code>    page code in hex (def: 0)\n"
           "   -p=<page_code>,<sub_page_code>    both in hex, (defs: 0)\n"
           "   -r    mode page output to stdout, a byte per line in "
           "ASCII hex\n"
           "   -subp=<sub_page_code>    sub page code (in hex, def: 0)\n"
           "   -v    verbose\n"
           "   -V    output version string\n"
           "   -6    Use MODE SENSE(6), by default uses MODE SENSE(10)\n"
           "   -?    output this usage message\n\n"
           "Performs a SCSI MODE SENSE (6 or 10) command\n");
}


int main(int argc, char * argv[])
{
    int sg_fd, k, num, len, res, md_len, bd_len, longlba, page_num, spf;
    const char * file_name = 0;
    char ebuff[EBUFF_SZ];
    const char * descp;
    const char * cp;
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
    int do_examine = 0;
    int flexible = 0;
    int do_hex = 0;
    int do_llbaa = 0;
    int do_mode6 = 0;  /* Use MODE SENSE(6) instead of MODE SENSE(10) */
    int do_list = 0;
    int do_raw = 0;
    int do_verbose = 0;
    int ret = 0;
    int density_code_off, t_proto, inq_pdt, inq_byte6, resp_mode6;
    int num_ua_pages, plen, jmp_out;
    unsigned char * ucp;
    unsigned char uc;
    struct sg_simple_inquiry_resp inq_out;
    char pdt_name[64];

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '6':
                    do_mode6 = 1;
                    break;
                case 'a':
                    do_all = 1;
                    break;
                case 'A':
                    do_all = 1;
                    do_all_sub = 1;
                    break;
                case 'd':
                    do_dbd = 1;
                    break;
                case 'D':
                    no_desc_out = 1;
                    break;
                case 'e':
                    do_examine = 1;
                    break;
                case 'f':
                    flexible = 1;
                    break;
                case 'h':
                case 'H':
                    do_hex = 1;
                    break;
                case 'l':
                    do_list = 1;
                    break;
                case 'L':
                    do_llbaa = 1;
                    break;
                case 'r':
                    do_raw = 1;
                    break;
                case 'v':
                    ++do_verbose;
                    break;
                case 'V':
                    fprintf(stderr, "Version string: %s\n", version_str);
                    exit(0);
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
            if (0 == strncmp("c=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 3)) {
                    fprintf(stderr, "Bad page control after 'c=' option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                pc = u;
            } else if (0 == strncmp("p=", cp, 2)) {
                if (NULL == strchr(cp + 2, ',')) {
                    num = sscanf(cp + 2, "%x", &u);
                    if ((1 != num) || (u > 63)) {
                        fprintf(stderr, "Bad page code value after 'p=' "
                                "option\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    pg_code = u;
                } else if (2 == sscanf(cp + 2, "%x,%x", &u, &uu)) {
                    if (uu > 255) {
                        fprintf(stderr, "Bad sub page code value after 'p=' "
                                "option\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    pg_code = u;
                    sub_pg_code = uu;
                    sub_pg_code_set = 1;
                } else {
                    fprintf(stderr, "Bad page code, subpage code sequence "
                            "after 'p=' option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else if (0 == strncmp("subp=", cp, 5)) {
                num = sscanf(cp + 5, "%x", &u);
                if ((1 != num) || (u > 255)) {
                    fprintf(stderr, "Bad sub page code after 'subp=' "
                            "option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                sub_pg_code = u;
                sub_pg_code_set = 1;
                if (-1 == pg_code)
                    pg_code = 0;
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
    
    if (0 == file_name) {
        if (do_list) {
            if ((pg_code < 0) || (pg_code > 0x1f)) {
                printf("    Assume peripheral device type: disk\n");
                list_page_codes(0, 0, -1);
            } else {
                printf("    peripheral device type: %s\n",
                       sg_get_pdt_str(pg_code, sizeof(pdt_name), pdt_name));
                if (sub_pg_code_set)
                    list_page_codes(pg_code, 0, sub_pg_code);
                else
                    list_page_codes(pg_code, 0, -1);
            }
            return 0;
        }
        fprintf(stderr, "No <scsi_device> argument given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (do_examine && (pg_code >= 0)) {
        fprintf(stderr, "can't give '-e' and a page number\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    /* The 6 bytes command only allows up to 252 bytes of response data */
    if (do_mode6) { 
        if (do_llbaa) {
            fprintf(stderr, "LLBAA not defined for MODE SENSE 6, try "
                    "without '-L'\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        rsp_buff_size = 252;
    }
    /* If no pages or list selected than treat as 'a' */
    if (! ((pg_code >= 0) || do_all || do_list || do_examine))
        do_all = 1;

    if ((sg_fd = sg_cmds_open_device(file_name, 1 /* ro */, do_verbose)) < 0) {
        fprintf(stderr, ME "error opening file: %s: %s\n", file_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (sg_simple_inquiry(sg_fd, &inq_out, 1, do_verbose)) {
        fprintf(stderr, ME "%s doesn't respond to a SCSI INQUIRY\n",
                file_name);
        sg_cmds_close_device(sg_fd);
        return SG_LIB_CAT_OTHER;
    }
    inq_pdt = inq_out.peripheral_type;
    inq_byte6 = inq_out.byte_6;
    if (0 == do_raw)
        printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n", 
               inq_out.vendor, inq_out.product, inq_out.revision,
               sg_get_pdt_str(inq_pdt, sizeof(pdt_name), pdt_name), inq_pdt);
    if (do_list) {
        if (sub_pg_code_set)
            list_page_codes(inq_pdt, inq_byte6, sub_pg_code);
        else
            list_page_codes(inq_pdt, inq_byte6, -1);
        return 0;
    }
    if (do_examine) {
        ret = examine_pages(sg_fd, do_mode6, inq_pdt, inq_byte6, do_verbose);
        goto finish;
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
            return SG_LIB_SYNTAX_ERROR;
        }
        if (do_hex) {
            fprintf(stderr, "'-r' and '-h' clash");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    memset(rsp_buff, 0, sizeof(rsp_buff));
    if (do_mode6) {
        res = sg_ll_mode_sense6(sg_fd, do_dbd, pc, pg_code, sub_pg_code,
                                rsp_buff, rsp_buff_size, 1, do_verbose);
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, ">>>>>> try again without the '-6' "
                    "switch for a 10 byte MODE SENSE command\n");
    } else {
        res = sg_ll_mode_sense10(sg_fd, do_llbaa, do_dbd, pc, pg_code,
                                 sub_pg_code, rsp_buff, rsp_buff_size, 1,
                                 do_verbose);
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, ">>>>>> try again with a '-6' "
                    "switch for a 6 byte MODE SENSE command\n");
    }
    if (SG_LIB_CAT_ILLEGAL_REQ == res) {
        if (sub_pg_code > 0)
            fprintf(stderr, "invalid field in cdb (perhaps subpages "
                    "not supported)\n");
        else if (pc > 0)
            fprintf(stderr, "invalid field in cdb (perhaps "
                    "page control (PC) not supported)\n");
        else
            fprintf(stderr, "invalid field in cdb (perhaps "
                "page 0x%x not supported)\n", pg_code);
    } else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "device not ready\n");
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "aborted command\n");
    ret = res;
    if (0 == res) {
        int medium_type, specific, headerlen;

        ret = 0;
        resp_mode6 = do_mode6;
        if (flexible) {
            num = rsp_buff[0];
            if (do_mode6 && (num < 3))
                resp_mode6 = 0;
            if ((0 == do_mode6) && (num > 5)) {
                if ((num > 11) && (0 == (num % 2)) && (0 == rsp_buff[4]) &&
                    (0 == rsp_buff[5]) && (0 == rsp_buff[6])) {
                    rsp_buff[1] = num;
                    rsp_buff[0] = 0;
                    fprintf(stderr, ">>> msense(10) but resp[0]=%d and "
                            "not msense(6) response so fix length\n", num);
                } else
                    resp_mode6 = 1;
            }
        }
        if (! do_raw) {
            if (resp_mode6 == do_mode6)
                printf("Mode parameter header from %s byte MODE SENSE:\n",
                       (do_mode6 ? "6" : "10"));
            else
                printf(" >>> Mode parameter header from %s byte MODE "
                       "SENSE,\n     decoded as %s byte response:\n",
                       (do_mode6 ? "6" : "10"), (resp_mode6 ? "6" : "10"));
        }
        if (resp_mode6) {
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
            sg_cmds_close_device(sg_fd);
            return 0;
        }
        if (do_hex)
            dStrHex((const char *)rsp_buff, headerlen, 1);
        if (0 == inq_pdt)
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
                    printf("> longlba direct access device block "
                           "descriptors:\n");
                    len = 16;
                    density_code_off = 8;
                }
                else if (0 == inq_pdt) { 
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
        num_ua_pages = 0;
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
            if (0x0 == page_num) {
                ++num_ua_pages;
                if((num_ua_pages > 3) && (md_len > 0xa00)) {
                    fprintf(stderr, ">>> Seen 3 unit attention pages "
                            "(only one should be at end)\n     and mpage "
                            "length=%d, looks malformed, try '-f' option\n",
                            md_len);
                    break;
                }
            }
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
                                                inq_pdt, inq_byte6, t_proto);
                } else
                    descp = find_page_code_desc(page_num, (spf ? ucp[1] : 0),
                                                inq_pdt, inq_byte6, -1);
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
            num = (len > md_len) ? md_len : len;
            if ((k > 0) && (num > 256)) {
                num = 256;
                fprintf(stderr, ">>> page length (%d) > 256 bytes, unlikely "
                                "trim\n    Try '-f' option\n", len);
            }
            dStrHex((const char *)ucp, num , 1);
            ucp += len;
            md_len -= len;
        }
    }
finish:
    sg_cmds_close_device(sg_fd);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
