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

   This program outputs information provided by a SCSI LOG SENSE command.
   
*/

static char * version_str = "0.10 20020228";

#define ME "sg_logs: "

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define LOG_SENSE_CMD     0x4d
#define LOG_SENSE_CMDLEN  10
#define MX_ALLOC_LEN (1024 * 17)

#define PG_CODE_ALL 0x00

#define EBUFF_SZ 256


static int do_logs(int sg_fd, int ppc, int sp, int pc, int pg_code, 
		   int paramp, void * resp, int mx_resp_len, int noisy)
{
    int res;
    unsigned char logsCmdBlk[LOG_SENSE_CMDLEN] = 
    	{LOG_SENSE_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;

    logsCmdBlk[1] = (unsigned char)((ppc ? 2 : 0) | (sp ? 1 : 0));
    logsCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    logsCmdBlk[5] = (unsigned char)((paramp >> 8) & 0xff);
    logsCmdBlk[6] = (unsigned char)(paramp & 0xff);
    if (mx_resp_len > 0xffff) {
    	printf( ME "mx_resp_len too big\n");
	return -1;
    }
    logsCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    logsCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(logsCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = logsCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (log sense) error");
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
	    snprintf(ebuff, EBUFF_SZ, ME "ppc=%d, sp=%d, "
	    	     "pc=%d, page_code=%x, paramp=%x ", ppc, sp, pc, 
		     pg_code, paramp);
            sg_chk_n_print3(ebuff, &io_hdr);
	}
	return -1;
    }
}

static void usage()
{
    printf("Usage: 'sg_logs [-l] [-h] [-ppc] [-sp] [-p=<page_number>] "
    	   " [-c=<page_control] [-paramp=<parameter_pointer> [-V]"
	   " <sg_device>'\n"
	   " where -l   list supported log pages\n"
	   "       -h   output in hex\n"
	   "       -ppc set the PPC bit (def: 0)\n"
	   "       -sp  set the PPC bit (def: 0)\n"
	   "       -p=<page_code> page code (in hex)\n"
	   "       -c=<page_control> page control (def: 0 (current))\n"
	   "       -paramp=<parameter_pointer> (def: 0)\n"
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
    int sg_fd, k, num, pg_len;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char rsp_buff[MX_ALLOC_LEN];
    unsigned int u;
    int pg_code = 0;
    int pc = 0;
    int paramp = 0;
    int do_list = 0;
    int do_ppc = 0;
    int do_sp = 0;
    int do_hex = 0;
    int oflags = O_RDWR;
    struct sg_scsi_id a_sid;
    int scsi_ptype;

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
        else if (0 == strncmp("-c=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 3)) {
                printf("Bad page control after '-c' switch\n");
                file_name = 0;
                break;
            }
	    pc = u;
        }
        else if (0 == strncmp("-paramp=", argv[k], 8)) {
            num = sscanf(argv[k] + 8, "%x", &u);
            if ((1 != num) || (u > 0xffff)) {
                printf("Bad parameter pointer after '-paramp' switch\n");
                file_name = 0;
                break;
            }
	    paramp = u;
        }
        else if (0 == strcmp("-l", argv[k]))
	    do_list = 1;
        else if (0 == strcmp("-ppc", argv[k]))
	    do_ppc = 1;
        else if (0 == strcmp("-sp", argv[k]))
	    do_sp = 1;
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
    if (do_list)
    	pg_code = PG_CODE_ALL;

    if (0 == do_logs(sg_fd, do_ppc, do_sp, pc, pg_code, paramp,
    		     rsp_buff, MX_ALLOC_LEN, 1))
    {
    	pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
    	printf("Returned log page code=0x%x,  page len=0x%x\n", 
	       rsp_buff[0], pg_len);
	if ((pg_len + 4) > MX_ALLOC_LEN) {
	    printf("Only fetched %d bytes of response, truncate output\n",
	    	   MX_ALLOC_LEN);
	    pg_len = MX_ALLOC_LEN - 4;
	}
	dStrHex((const char *)rsp_buff, pg_len + 4, 1);
#if 0
	{
	    int para_len;
	    unsigned char * ucp;

	    ucp = rsp_buff + 4;
	    while (pg_len > 0) {
		para_len = *(ucp + 3) + 4;
		printf(">> parameter code=0x%x\n", (ucp[0] << 8) + ucp[1]); 
		dStrHex((const char *)ucp, para_len, 1);
		ucp += para_len;
		pg_len -= para_len;
	    }
	}
#endif
    }

    close(sg_fd);
    return 0;
}
