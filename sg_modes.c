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
#include "sg_err.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2000-2003 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI MODE SENSE command.
   Does 10 byte MODE SENSE commands by default, Trent Piepho added a "-6"
   switch for force 6 byte mode sense commands.
   
*/

static char * version_str = "0.18 20030507";

#define ME "sg_modes: "

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define MODE_SENSE6_CMD      0x1a
#define MODE_SENSE6_CMDLEN   6
#define MODE_SENSE10_CMD     0x5a
#define MODE_SENSE10_CMDLEN  10
#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define MX_ALLOC_LEN (1024 * 4)

#define PG_CODE_ALL 0x3f

#define EBUFF_SZ 256


/* Returns 0 when successful, else -1 */
static int do_simple_inq(int sg_fd, void * resp, int mx_resp_len, int noisy)
{
    int res;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;

    inqCmdBlk[4] = (unsigned char)mx_resp_len;
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
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
        perror("SG_IO (inquiry) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
	return 0;
    default:
	if (noisy) {
	    char ebuff[EBUFF_SZ];
	    snprintf(ebuff, EBUFF_SZ, "Inquiry error ");
            sg_chk_n_print3(ebuff, &io_hdr);
	}
	return -1;
    }
}

static int do_modes(int sg_fd, int dbd, int pc, int pg_code, int sub_pg_code,
		  void * resp, int mx_resp_len, int noisy, int mode6)
{
    int res;
    unsigned char modesCmdBlk[MODE_SENSE10_CMDLEN] = 
    	{MODE_SENSE10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;

    modesCmdBlk[1] = (unsigned char)(dbd ? 0x8 : 0);
    modesCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    modesCmdBlk[3] = (unsigned char)(sub_pg_code & 0xff);
    if (mx_resp_len > (mode6?0xff:0xffff)) {
    	printf( ME "mx_resp_len too big\n");
	return -1;
    }
    if(mode6) {
	modesCmdBlk[0] = MODE_SENSE6_CMD;
	modesCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
    } else {
	modesCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
	modesCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);
    }

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    memset(sense_b, 0, sizeof(sense_b));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = mode6 ? MODE_SENSE6_CMDLEN : MODE_SENSE10_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = modesCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (mode sense) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
	return 0;
    default:
	if (noisy) {
	    char ebuff[EBUFF_SZ];
	    snprintf(ebuff, EBUFF_SZ, "Mode sense error, dbd=%d "
	    	     "pc=%d page_code=%x sub_page_code=%x\n     ", dbd, pc, 
		     pg_code, sub_pg_code);
            sg_chk_n_print3(ebuff, &io_hdr);
	}
	if ((0x70 == (0x7f & sense_b[0])) && (0x20 == sense_b[12]) &&
	    (0x0 == sense_b[13])) {
	    if (mode6)
	        fprintf(stderr, ">>>>>> drop '-6' switch and try again with "
			        "a 10 byte MODE SENSE\n");
	    else
	        fprintf(stderr, ">>>>>> add '-6' switch and try again with "
				"a 6 byte MODE SENSE\n");
	}
	return -1;
    }
}

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
    const char * desc;
};

static struct page_code_desc pc_desc_all[] = {
    {0x0, "Unit Attention condition [vendor: page format not required]"},
    {0x2, "Disconnect-Reconnect"},
    {0xa, "Control"},
    {0x15, "Extended"},
    {0x16, "Extended device-type specific"},
    {0x18, "Protocol specific LUN"},
    {0x19, "Protocol specific port"},
    {0x1a, "Power condition"},
    {0x1c, "Informational exceptions control"},
    {0x3f, "[yields all supported pages]"},
};

static struct page_code_desc pc_desc_disk[] = {
    {0x1, "Read-Write error recovery"},
    {0x3, "Format"},
    {0x4, "Rigid disk geometry"},
    {0x5, "Flexible geometry"},
    {0x7, "Verify error recovery"},
    {0x8, "Caching"},
    {0x9, "Peripheral device (spc-2 ?)"},
    {0xb, "Medium types supported"},
    {0xc, "Notch and partition"},
    {0xd, "Power condition (obsolete)"},
    {0x10, "XOR control"},
};

static struct page_code_desc pc_desc_tape[] = {
    {0xf, "Data Compression"},
    {0x10, "Device config"},
    {0x11, "Medium Partition [1]"},
    {0x12, "Medium Partition [2]"},
    {0x13, "Medium Partition [3]"},
    {0x14, "Medium Partition [4]"},
    {0x1c, "Informational exceptions control (tape version)"},
};

static struct page_code_desc pc_desc_cddvd[] = {
    {0x1, "Read-Write error recovery"},
    {0x3, "MRW"},
    {0x5, "Write parameters"},
    {0xd, "CD device parameters (obsolete)"},
    {0xe, "CD audio"},
    {0x1a, "Power condition"},
    {0x1c, "Fault/failure reporting control"},
    {0x1d, "Timeout and protect"},
    {0x2a, "MM capabilities and mechanical status (obsolete)"},
};

static struct page_code_desc pc_desc_smc[] = {
    {0x1d, "Element address assignment"},
    {0x1e, "Transport geometry parameters"},
    {0x1f, "Device capabilities"},
};

static struct page_code_desc pc_desc_scc[] = {
    {0x1b, "LUN mapping"},
};

static struct page_code_desc pc_desc_ses[] = {
    {0x14, "Enclosure services management"},
};

struct page_code_desc * find_mode_page_table(int scsi_ptype, int * size)
{
    switch (scsi_ptype)
    {
	case 0:		/* disk (direct access) type devices */
	case 4:
	case 7:
	case 0xe:
	    *size = sizeof(pc_desc_disk) / sizeof(pc_desc_disk[0]);
	    return &pc_desc_disk[0];
	case 1:		/* tape devices */
	case 2:
	    *size = sizeof(pc_desc_tape) / sizeof(pc_desc_tape[0]);
	    return &pc_desc_tape[0];
	case 5:		/* cd/dvd devices */
	    *size = sizeof(pc_desc_cddvd) / sizeof(pc_desc_cddvd[0]);
	    return &pc_desc_cddvd[0];
	case 8:		/* medium changer devices */
	    *size = sizeof(pc_desc_smc) / sizeof(pc_desc_smc[0]);
	    return &pc_desc_smc[0];
	case 0xc:	/* storage array devices */
	    *size = sizeof(pc_desc_scc) / sizeof(pc_desc_scc[0]);
	    return &pc_desc_scc[0];
	case 0xd:	/* enclosure services devices */
	    *size = sizeof(pc_desc_ses) / sizeof(pc_desc_ses[0]);
	    return &pc_desc_ses[0];
    }
    *size = 0;
    return NULL;
}

const char * find_page_code_desc(int page_num, int scsi_ptype)
{
    int k;
    int num;
    const struct page_code_desc * pcdp;

    pcdp = find_mode_page_table(scsi_ptype, &num);
    if (pcdp) {
        for (k = 0; k < num; ++k, ++pcdp) {
	    if (page_num == pcdp->page_code)
	        return pcdp->desc;
	    else if (page_num < pcdp->page_code)
	        break;
	}
    }
    pcdp = &pc_desc_all[0];
    num = sizeof(pc_desc_all) / sizeof(pc_desc_all[0]);
    for (k = 0; k < num; ++k, ++pcdp) {
	if (page_num == pcdp->page_code)
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
    for (k = 0; k < 0x3f; ++k) {
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
    printf("Usage: 'sg_modes [-a] [-c=<page_control] [-d] [-h]"
	   " [-l] [-p=<page_number>]\n\t\t [-subp=<sub_page_code>] [-V] "
	   "[-6] [<sg_device>]'\n"
	   " where -a   get all mode pages\n"
	   "       -c=<page_control> page control (def: 0 [current],"
	   " 1 [changeable],\n            2 [default], 3 [saved])\n"
	   "       -d   disable block descriptors\n"
	   "       -h   output in hex\n"
	   "       -l   list common page codes\n"
	   "       -p=<page_code> page code (in hex, def: 0)\n"
	   "       -subp=<sub_page_code> (in hex, def: 0)\n"
	   "       -V   output version string\n"
	   "       -6   Use MODE SENSE(6) instead of MODE SENSE(10)\n"
	   "       -?   output this usage message\n");
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



int main(int argc, char * argv[])
{
    int sg_fd, k, num, len, md_len, bd_len, longlba, page_num;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    const char * descp;
    unsigned char rsp_buff[MX_ALLOC_LEN];
    int rsp_buff_size = MX_ALLOC_LEN;
    unsigned int u;
    int pg_code = 0;
    int sub_pg_code = 0;
    int pc = 0;
    int do_all = 0;
    int do_dbd = 0;
    int do_hex = 0;
    int do_mode6 = 0;  /* Use MODE SENSE(6) instead of MODE SENSE(10) */
    int do_list = 0;
    int oflags = O_RDONLY | O_NONBLOCK;
    struct sg_scsi_id a_sid;
    int scsi_ptype, density_code_off;
    unsigned char * ucp;
    unsigned char uc;

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

    /* The 6 bytes command only allows up to 255 bytes of response data */
    if(do_mode6) rsp_buff_size = 255;

    if ((sg_fd = open(file_name, oflags)) < 0) {
        snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Just to be safe, check we have a new sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        printf(ME "%s doesn't seem to be a version 3 sg device\n",
               file_name);
        close(sg_fd);
        return 1;
    }
    if (ioctl(sg_fd, SG_GET_SCSI_ID, &a_sid) < 0) {
	unsigned char inqBuff[36];

	if (do_simple_inq(sg_fd, inqBuff, sizeof(inqBuff), 1)) {
            printf(ME "%s doesn't respond to a SCSI INQUIRY\n", file_name);
            close(sg_fd);
            return 1;
	}
	scsi_ptype = inqBuff[0] & 0x1f; /* fetch peripheral device type */
    }
    else
	scsi_ptype = a_sid.scsi_type;
    printf("  SCSI peripheral type: %s [0x%x] (from INQUIRY)\n", 
	   get_ptype_str(scsi_ptype), scsi_ptype);
    if (do_list) {
	list_page_codes(scsi_ptype);
	return 0;
    }
    if (do_all)
    	pg_code = PG_CODE_ALL;

    if (0 == do_modes(sg_fd, do_dbd, pc, pg_code, sub_pg_code, 
		      rsp_buff, rsp_buff_size, 1, do_mode6))
    {
	int medium_type, specific, headerlen;

    	printf("Mode parameter header from %s byte MODE SENSE:\n",
	       (do_mode6 ? "6" : "10"));
	if(do_mode6) {
	    headerlen = 4;
	    if (do_hex)
		dStrHex((const char *)rsp_buff, headerlen, 1);
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
	    else if (0 == scsi_ptype) { 
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
	ucp = rsp_buff + bd_len + headerlen;	/* start of mode page(s) */
	md_len -= bd_len + headerlen;		/* length of mode page(s) */
	while (md_len > 0) { /* got mode page(s) */
	    uc = *ucp;
	    page_num = ucp[0] & 0x3f;
	    if (do_hex)
	        descp = NULL;
	    else {
	        descp = find_page_code_desc(page_num, scsi_ptype);
		if (NULL == descp)
		    snprintf(ebuff, EBUFF_SZ, "vendor[0x%x]", page_num);
	    }
	    if (uc & 0x40) {
		len = (ucp[2] << 8) + ucp[3] + 4;
		if (do_hex)
		    printf(">> page_code=0x%x, subpage_code=0x%x, "
			   "page_control=%d\n", page_num, ucp[1], pc);
		else
		    printf(">> page_code: %s, subpage_code=0x%x, "
			   "page_control: %s\n",
			   (descp ? descp: ebuff), ucp[1],
			   pg_control_str_arr[pc]);
	    }
	    else {
		len = ucp[1] + 2;
		if (do_hex)
		    printf(">> page_code=0x%x, page_control=%d\n", page_num,
			   pc);
		else
		    printf(">> page_code: %s, page_control: %s\n", 
		           (descp ? descp: ebuff), pg_control_str_arr[pc]);
	    }
	    dStrHex((const char *)ucp, len, 1);
	    ucp += len;
	    md_len -= len;
	}
    }

    close(sg_fd);
    return 0;
}
