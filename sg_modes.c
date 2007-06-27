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
*  Copyright (C) 2000-2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI MODE SENSE command.
   Does 10 byte MODE SENSE commands by default, Trent Piepho added a "-6"
   switch for force 6 byte mode sense commands.
   
*/

static char * version_str = "0.28 20041012";

#define ME "sg_modes: "

#define MX_ALLOC_LEN (1024 * 4)
#define PG_CODE_ALL 0x3f
#define PG_CODE_MASK 0x3f
#define PG_CODE_MAX 0x3f
#define SPG_CODE_ALL 0xff

#define EBUFF_SZ 256


const char * scsi_ptype_strs[] = {
    "disk",
    "tape",
    "printer",
    "processor",
    "write once optical disk",
    "cd/dvd",
    "scanner",
    "optical memory device",
    "medium changer",
    "communications",
    "graphics",
    "graphics",
    "storage array controller",
    "enclosure services device",
    "simplified direct access device",
    "optical card reader/writer device",
};

const char * get_ptype_str(int scsi_ptype)
{
    int num = sizeof(scsi_ptype_strs) / sizeof(scsi_ptype_strs[0]);

    return (scsi_ptype < num) ? scsi_ptype_strs[scsi_ptype] : "";
}

struct page_code_desc {
    int page_code;
    int subpage_code;
    const char * desc;
};

static struct page_code_desc pc_desc_all[] = {
    {0x0, 0x0, "Unit Attention condition [vendor: page format not required]"},
    {0x2, 0x0, "Disconnect-Reconnect"},
    {0xa, 0x0, "Control"},
    {0xa, 0x1, "Control extension"},
    {0x15, 0x0, "Extended"},
    {0x16, 0x0, "Extended device-type specific"},
    {0x18, 0x0, "Protocol specific LUN"},
    {0x19, 0x0, "Protocol specific port"},
    {0x1a, 0x0, "Power condition"},
    {0x1c, 0x0, "Informational exceptions control"},
    {PG_CODE_ALL, 0x0, "[yields all supported pages]"},
};

static struct page_code_desc pc_desc_disk[] = {
    {0x1, 0x0, "Read-Write error recovery"},
    {0x3, 0x0, "Format"},
    {0x4, 0x0, "Rigid disk geometry"},
    {0x5, 0x0, "Flexible geometry"},
    {0x7, 0x0, "Verify error recovery"},
    {0x8, 0x0, "Caching"},
    {0x9, 0x0, "Peripheral device (spc-2 ?)"},
    {0xb, 0x0, "Medium types supported"},
    {0xc, 0x0, "Notch and partition"},
    {0xd, 0x0, "Power condition (obsolete)"},
    {0x10, 0x0, "XOR control"},
};

static struct page_code_desc pc_desc_tape[] = {
    {0xf, 0x0, "Data Compression"},
    {0x10, 0x0, "Device config"},
    {0x11, 0x0, "Medium Partition [1]"},
    {0x12, 0x0, "Medium Partition [2]"},
    {0x13, 0x0, "Medium Partition [3]"},
    {0x14, 0x0, "Medium Partition [4]"},
    {0x1c, 0x0, "Informational exceptions control (tape version)"},
};

static struct page_code_desc pc_desc_cddvd[] = {
    {0x1, 0x0, "Read-Write error recovery"},
    {0x3, 0x0, "MRW"},
    {0x5, 0x0, "Write parameters"},
    {0x7, 0x0, "Verify error recovery"},
    {0x8, 0x0, "Caching"},
    {0xd, 0x0, "CD device parameters (obsolete)"},
    {0xe, 0x0, "CD audio"},
    {0x1a, 0x0, "Power condition"},
    {0x1c, 0x0, "Fault/failure reporting control"},
    {0x1d, 0x0, "Timeout and protect"},
    {0x2a, 0x0, "MM capabilities and mechanical status (obsolete)"},
};

static struct page_code_desc pc_desc_smc[] = {
    {0x1d, 0x0, "Element address assignment"},
    {0x1e, 0x0, "Transport geometry parameters"},
    {0x1f, 0x0, "Device capabilities"},
};

static struct page_code_desc pc_desc_scc[] = {
    {0x1b, 0x0, "LUN mapping"},
};

static struct page_code_desc pc_desc_ses[] = {
    {0x14, 0x0, "Enclosure services management"},
};

struct page_code_desc * find_mode_page_table(int scsi_ptype, int * size)
{
    switch (scsi_ptype)
    {
        case 0:         /* disk (direct access) type devices */
        case 4:
        case 7:
        case 0xe:
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
    }
    *size = 0;
    return NULL;
}

const char * find_page_code_desc(int page_num, int subpage_num,
                                 int scsi_ptype)
{
    int k;
    int num;
    const struct page_code_desc * pcdp;

    pcdp = find_mode_page_table(scsi_ptype, &num);
    if (pcdp) {
        for (k = 0; k < num; ++k, ++pcdp) {
            if ((page_num == pcdp->page_code) &&
                (subpage_num == pcdp->subpage_code))
                return pcdp->desc;
            else if (page_num < pcdp->page_code)
                break;
        }
    }
    pcdp = &pc_desc_all[0];
    num = sizeof(pc_desc_all) / sizeof(pc_desc_all[0]);
    for (k = 0; k < num; ++k, ++pcdp) {
        if ((page_num == pcdp->page_code) &&
            (subpage_num == pcdp->subpage_code))
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            break;
    }
    return NULL;
}

static void list_page_codes(int scsi_ptype)
{
    int k;
    int num = sizeof(pc_desc_all) / sizeof(pc_desc_all[0]);
    const struct page_code_desc * pcdp = &pc_desc_all[0];
    int num_ptype;
    const struct page_code_desc * pcd_ptypep;

    pcd_ptypep = find_mode_page_table(scsi_ptype, &num_ptype);
    printf("Page_Code  Description\n");
    for (k = 0; k <= PG_CODE_MAX; ++k) {
        if (pcd_ptypep && (num_ptype > 0)) {
            if (k == pcd_ptypep->page_code) {
                printf(" 0x%02x      %s\n", pcd_ptypep->page_code, 
                       pcd_ptypep->desc);   
                ++pcd_ptypep;
                --num_ptype;
                continue;
            } else if (k > pcd_ptypep->page_code) {
                pcd_ptypep++;
                --num_ptype;
            }
        }
        if (pcdp && (num > 0)) {
            if (k == pcdp->page_code) {
                printf(" 0x%02x      %s\n", pcdp->page_code, pcdp->desc);   
                ++pcdp;
                --num;
                continue;
            } else if (k > pcdp->page_code) {
                pcdp++;
                --num;
            }
        }
    }
}

static const char * pg_control_str_arr[] = {
    "current",
    "changeable",
    "default",
    "saved"};

static void usage()
{
    printf("Usage: 'sg_modes [-a] [-c=<page_control] [-d] [-h] [-l] "
           "[-p=<page_number>]\n\t\t [-subp=<sub_page_code>] [-v] [-V] "
           "[-6] [<sg_device>]'\n"
           " where -a   get all mode pages\n"
           "       -c=<page_control> page control (def: 0 [current],"
           " 1 [changeable],\n            2 [default], 3 [saved])\n"
           "       -d   disable block descriptors\n"
           "       -h   output in hex\n"
           "       -l   list common page codes\n"
           "       -p=<page_code> page code (in hex, def: 0)\n"
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
    unsigned int u;
    int pg_code = -1;
    int sub_pg_code = 0;
    int pc = 0;
    int do_all = 0;
    int do_dbd = 0;
    int do_hex = 0;
    int do_mode6 = 0;  /* Use MODE SENSE(6) instead of MODE SENSE(10) */
    int do_list = 0;
    int do_verbose = 0;
    int oflags = O_RDONLY | O_NONBLOCK;
    int density_code_off;
    unsigned char * ucp;
    unsigned char uc;
    struct sg_simple_inquiry_resp inq_out;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-p=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 63)) {
                printf("Bad page code after '-p' switch\n");
                file_name = 0;
                break;
            }
            pg_code = u;
        }
        else if (0 == strncmp("-subp=", argv[k], 6)) {
            num = sscanf(argv[k] + 6, "%x", &u);
            if ((1 != num) || (u > 255)) {
                printf("Bad sub page code after '-subp' switch\n");
                file_name = 0;
                break;
            }
            sub_pg_code = u;
            if (-1 == pg_code)
                pg_code = 0;
        }
        else if (0 == strncmp("-c=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 3)) {
                printf("Bad page control after '-c' switch\n");
                file_name = 0;
                break;
            }
            pc = u;
        }
        else if (0 == strcmp("-d", argv[k]))
            do_dbd = 1;
        else if (0 == strcmp("-a", argv[k]))
            do_all = 1;
        else if (0 == strcmp("-h", argv[k]))
            do_hex = 1;
        else if (0 == strcmp("-6", argv[k]))
            do_mode6 = 1;
        else if (0 == strcmp("-l", argv[k]))
            do_list = 1;
        else if (0 == strcmp("-v", argv[k]))
            ++do_verbose;
        else if (0 == strcmp("-?", argv[k])) {
            usage();
            return 0;
        }
        else if (0 == strcmp("-V", argv[k])) {
            printf("Version string: %s\n", version_str);
            exit(0);
        }
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            printf("too many arguments\n");
            file_name = 0;
            break;
        }
    }
    if (0 == file_name) {
        if (do_list) {
            printf("Assume 'disk' device type\n");
            list_page_codes(0);
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
        printf(ME "%s doesn't respond to a SCSI INQUIRY\n", file_name);
        close(sg_fd);
        return 1;
    }
    printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n", 
           inq_out.vendor, inq_out.product, inq_out.revision,
           get_ptype_str(inq_out.peripheral_type), inq_out.peripheral_type);

    if (do_list) {
        list_page_codes(inq_out.peripheral_type);
        return 0;
    }
    if (PG_CODE_ALL == pg_code)
        do_all = 1;
    else if (do_all)
        pg_code = PG_CODE_ALL;

    if (do_mode6) {
        res = sg_ll_mode_sense6(sg_fd, do_dbd, pc, pg_code, sub_pg_code,
				rsp_buff, rsp_buff_size, 1, do_verbose);
	if (SG_LIB_CAT_INVALID_OP == res)
	    fprintf(stderr, ">>>>>> try again without the '-6' "
		    "switch for a 10 byte MODE SENSE command\n");
    } else {
        res = sg_ll_mode_sense10(sg_fd, do_dbd, pc, pg_code, sub_pg_code,
				 rsp_buff, rsp_buff_size, 1, do_verbose);
	if (SG_LIB_CAT_INVALID_OP == res)
	    fprintf(stderr, ">>>>>> try again with a '-6' "
		    "switch for a 6 byte MODE SENSE command\n");
    }
    if (0 == res) {
        int medium_type, specific, headerlen;

        printf("Mode parameter header from %s byte MODE SENSE:\n",
               (do_mode6 ? "6" : "10"));
        if (do_mode6) {
            headerlen = 4;
            md_len = rsp_buff[0]+1;
            bd_len = rsp_buff[3];
            medium_type = rsp_buff[1];
            specific = rsp_buff[2];
            longlba = 0; /* what is this field? */
        } else {
            headerlen = 8;
            md_len = (rsp_buff[0] << 8) + rsp_buff[1] + 2;
            bd_len = (rsp_buff[6] << 8) + rsp_buff[7];
            medium_type = rsp_buff[2];
            specific = rsp_buff[3];
            longlba = rsp_buff[4] & 1;
        }
        if (do_hex)
            dStrHex((const char *)rsp_buff, headerlen, 1);
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
                descp = find_page_code_desc(page_num, (spf ? ucp[1] : 0),
                                            inq_out.peripheral_type);
                if (NULL == descp) {
                    if (spf)
                        snprintf(ebuff, EBUFF_SZ, "0x%x, subpage_code: 0x%x",
                                 page_num, ucp[1]);
                    else
                        snprintf(ebuff, EBUFF_SZ, "0x%x", page_num);
                }
                printf(">> page_code: %s, page_control: %s\n", 
                       (descp ? descp: ebuff), pg_control_str_arr[pc]);
            }
            dStrHex((const char *)ucp, ((len > md_len) ? md_len : len) , 1);
            ucp += len;
            md_len -= len;
        }
    }
    close(sg_fd);
    return 0;
}
