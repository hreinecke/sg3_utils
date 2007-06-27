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

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2000-2002 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI MODE SENSE command.
   
*/

static char * version_str = "0.11 20020227";

#define ME "sg_modes: "

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define MODE_SENSE10_CMD     0x5a
#define MODE_SENSE10_CMDLEN  10
#define MX_ALLOC_LEN (1024 * 4)

#define PG_CODE_ALL 0x3f

#define EBUFF_SZ 256


static int do_modes(int sg_fd, int dbd, int pc, int pg_code, 
		  void * resp, int mx_resp_len, int noisy)
{
    int res;
    unsigned char modesCmdBlk[MODE_SENSE10_CMDLEN] = 
    	{MODE_SENSE10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;

    modesCmdBlk[1] = (unsigned char)(dbd ? 0x8 : 0);
    modesCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    if (mx_resp_len > 0xffff) {
    	printf( ME "mx_resp_len too big\n");
	return -1;
    }
    modesCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    modesCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(modesCmdBlk);
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
	    snprintf(ebuff, EBUFF_SZ, "Mode sense error, dbd=%d, "
	    	     "pc=%d, page_code=%x ", dbd, pc, pg_code);
            sg_chk_n_print3(ebuff, &io_hdr);
	}
	return -1;
    }
}

static void usage()
{
    printf("Usage: 'sg_modes [-a] [-h] [-p=<page_number>]"
	   " [-c=<page_control] [-d] [-V]\n\t\t<sg_device>'\n"
	   " where -a   get all mode pages\n"
	   "       -h   output in hex\n"
	   "       -p=<page_code> page code (in hex, def: 0)\n"
	   "       -c=<page_control> page control (def: 0 (current))\n"
	   "       -d   disable block descriptors\n"
	   "       -V   output version string\n"
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
    int sg_fd, k, num, len, md_len, bd_len, longlba;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char rsp_buff[MX_ALLOC_LEN];
    unsigned int u;
    int pg_code = 0;
    int pc = 0;
    int do_all = 0;
    int do_dbd = 0;
    int do_hex = 0;
    int oflags = O_RDONLY;
    struct sg_scsi_id a_sid;
    int scsi_ptype, density_code_off;
    unsigned char * ucp;
    unsigned char uc;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-p=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (pg_code > 63)) {
                printf("Bad page code after '-p' switch\n");
                file_name = 0;
                break;
            }
	    pg_code = u;
        }
        else if (0 == strncmp("-c=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (pc > 3)) {
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
        else if (0 == strcmp("-?", argv[k])) {
	    file_name = 0;
	    break;
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
        usage();
        return 1;
    }

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
        printf(ME "ioctl(SG_GET_SCSI_ID) failed, errno=%d\n", errno);
        close(sg_fd);
        return 1;
    }
    scsi_ptype = a_sid.scsi_type;
    if (do_all)
    	pg_code = PG_CODE_ALL;

    if (0 == do_modes(sg_fd, do_dbd, pc, pg_code, rsp_buff, MX_ALLOC_LEN, 1))
    {
    	printf("Mode parameter header:\n");
	md_len = (rsp_buff[0] << 8) + rsp_buff[1];
	bd_len = (rsp_buff[6] << 8) + rsp_buff[7];
	longlba = rsp_buff[4] & 1;
    	printf("  Mode data length=%d, medium type=0x%.2x, specific"
	       " param=0x%.2x, longlba=%d\n", md_len, rsp_buff[2], 
	       rsp_buff[3], longlba);
        if ((md_len + 2) > MX_ALLOC_LEN) {
            printf("Only fetched %d bytes of response, truncate output\n",
                   MX_ALLOC_LEN);
            md_len = MX_ALLOC_LEN - 2;
	    if ((md_len + 6) > bd_len);
		bd_len = MX_ALLOC_LEN - 8;
        }
    	printf("  Block descriptor length=%d,  SCSI peripheral type=0x%x\n", 
	       bd_len, scsi_ptype);
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

	    ucp = rsp_buff + 8;
	    while (num > 0) {
		printf("   Density code=0x%x\n", *(ucp + density_code_off));
		dStrHex((const char *)ucp, len, 1);
		ucp += len;
		num -= len;
	    }
	    printf("\n");
	}
	ucp = rsp_buff + bd_len + 8;
	md_len -= bd_len + 6;
	while (md_len > 0) { /* got mode page(s) */
	    uc = *ucp;
	    if (uc & 0x40) {
		len = (ucp[2] << 8) + ucp[3] + 4;
		printf(">> page_code=0x%x, subpage code=0x%x\n", 
		       ucp[0] & 0x3f, ucp[1]);
	    }
	    else {
		len = ucp[1] + 2;
		printf(">> page_code=0x%x\n", ucp[0] & 0x3f);
	    }
	    dStrHex((const char *)ucp, len, 1);
	    ucp += len;
	    md_len -= len;
	}
    }

    close(sg_fd);
    return 0;
}
