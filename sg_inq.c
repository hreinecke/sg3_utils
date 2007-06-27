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

   This program outputs information provided by a SCSI INQUIRY command.
   It is mainly based on the SCSI-3 SPC-1 document with some additions
   from SPC-2 (draft revision 18).
   
*/

static char * version_str = "0.16 20020114";


/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define MX_ALLOC_LEN 255

#define EBUFF_SZ 256

#ifndef SCSI_IOCTL_GET_PCI
#define SCSI_IOCTL_GET_PCI 0x5387
#endif


static int do_inq(int sg_fd, int cmddt, int evpd, unsigned int pg_op, 
		  void * resp, int mx_resp_len, int noisy)
{
    int res;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;

    if (cmddt)
    	inqCmdBlk[1] |= 2;
    if (evpd)
    	inqCmdBlk[1] |= 1;
    inqCmdBlk[2] = (unsigned char)pg_op;
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
	    snprintf(ebuff, EBUFF_SZ, "Inquiry error, CmdDt=%d, "
	    	     "EVPD=%d, page_opcode=%x ", cmddt, evpd, pg_op);
            sg_chk_n_print3(ebuff, &io_hdr);
	}
	return -1;
    }
}

static void usage()
{
    printf("Usage: 'sg_inq [-e] [-h] [-o=<opcode_page>] [-V]"
	   " <sg_device>'\n"
	   " where -e   set EVPD mode\n"
	   "       -c   set CmdDt mode\n"
	   "       -h   output in hex (ASCII to the right)\n"
	   "       -o=<opcode_page> opcode or page code in hex\n"
	   "       -p   output SCSI adapter PCI information\n"
	   "       -V   output version string\n"
	   "       -?   output this usage message\n"
	   " If no optional switches given (or '-h') then does"
	   " a standard INQUIRY\n");
}


static void dStrHex(const char* str, int len)
{
    const char* p = str;
    unsigned char c;
    char buff[82];
    int a = 0;
    const int bpstart = 5;
    const int cpstart = 60;
    int cpos = cpstart;
    int bpos = bpstart;
    int i;
    
    if (len <= 0) return;
    memset(buff,' ',80);
    buff[80]='\0';
    sprintf(buff + 1, "%.2x", a);
    buff[3] = ' ';
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
	if ((c < ' ') || (c >= 0x7f))
	    c='.';
	buff[cpos++] = c;
	if (cpos > (cpstart+15))
	{
	    printf("%s\n", buff);
	    bpos = bpstart;
	    cpos = cpstart;
	    a += 16;
	    memset(buff,' ',80);
	    sprintf(buff + 1, "%.2x", a);
	    buff[3] = ' ';
	}
    }
    if (cpos > cpstart)
    {
	printf("%s\n", buff);
    }
}



int main(int argc, char * argv[])
{
    int sg_fd, k, num, len;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    char buff[MX_ALLOC_LEN + 1];
    unsigned char rsp_buff[MX_ALLOC_LEN + 1];
    unsigned int num_opcode = 0;
    int do_evpd = 0;
    int do_cmddt = 0;
    int do_hex = 0;
    int do_pci = 0;
    int oflags = O_RDONLY;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-o=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &num_opcode);
            if ((1 != num) || (num_opcode > 255)) {
                printf("Bad number after '-o' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strcmp("-e", argv[k]))
	    do_evpd = 1;
        else if (0 == strcmp("-h", argv[k]))
	    do_hex = 1;
        else if (0 == strcmp("-c", argv[k]))
	    do_cmddt = 1;
	else if (0 == strcmp("-p", argv[k]))
            do_pci = 1;
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

    if (do_pci)
    	oflags = O_RDWR;
    if ((sg_fd = open(file_name, oflags)) < 0) {
        snprintf(ebuff, EBUFF_SZ, "sg_inq: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Just to be safe, check we have a new sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        printf("sg_inq: %s doesn't seem to be a version 3 sg device\n",
               file_name);
        close(sg_fd);
        return 1;
    }

    if (! (do_cmddt || do_evpd)) {
	printf("standard INQUIRY:\n");
        if (0 == do_inq(sg_fd, 0, 0, 0, rsp_buff, MX_ALLOC_LEN, 1)) {
	    len = rsp_buff[4] + 5;
	    if (do_hex)
		dStrHex((const char *)rsp_buff, len);
	    else {
	        printf("  PQual=%d, Device type=%d, RMB=%d, ANSI version=%d, ",
	               (rsp_buff[0] & 0xe0) >> 5, rsp_buff[0] & 0x1f,
	               !!(rsp_buff[1] & 0x80), rsp_buff[2] & 0x7);
	        printf("[full version=0x%02x]\n", (unsigned int)rsp_buff[2]);
	        printf("  AERC=%d, TrmTsk=%d, NormACA=%d, HiSUP=%d, "
		       "Resp data format=%d, SCCS=%d\n",
	               !!(rsp_buff[3] & 0x80), !!(rsp_buff[3] & 0x40),
	               !!(rsp_buff[3] & 0x20), !!(rsp_buff[3] & 0x10),
		       rsp_buff[3] & 0x0f, !!(rsp_buff[5] & 0x80));
	        printf("  BQue=%d, EncServ=%d, MultiP=%d, MChngr=%d, "
		       "ACKREQQ=%d, ",
	               !!(rsp_buff[6] & 0x80), !!(rsp_buff[6] & 0x40), 
		       !!(rsp_buff[6] & 0x10), !!(rsp_buff[6] & 0x08), 
		       !!(rsp_buff[6] & 0x04));
	        printf("Addr16=%d\n  RelAdr=%d, ",
	               !!(rsp_buff[6] & 0x01),
	               !!(rsp_buff[7] & 0x80));
	        printf("WBus16=%d, Sync=%d, Linked=%d, TranDis=%d, ",
	               !!(rsp_buff[7] & 0x20), !!(rsp_buff[7] & 0x10),
	               !!(rsp_buff[7] & 0x08), !!(rsp_buff[7] & 0x04));
	        printf("CmdQue=%d\n", !!(rsp_buff[7] & 0x02));
		if (len > 56)
		    printf("  Clocking=0x%x, QAS=%d, IUS=%d\n",
		           (rsp_buff[56] & 0x0c) >> 2, !!(rsp_buff[56] & 0x2),
			   !!(rsp_buff[56] & 0x1));
		printf("    length=%d (0x%x)\n", len, len);
	        if (len >= 36) {
	            memcpy(buff, &rsp_buff[8], 8);
	            buff[8] = '\0';
	            printf(" Vendor identification: %s\n", buff);
	            memcpy(buff, &rsp_buff[16], 16);
	            buff[16] = '\0';
	            printf(" Product identification: %s\n", buff);
	            memcpy(buff, &rsp_buff[32], 4);
	            buff[4] = '\0';
	            printf(" Product revision level: %s\n", buff);
	        }
	        else
	            printf(" Inquiry response length shorter than expected\n");
            }
	    if (0 == do_inq(sg_fd, 0, 1, 0x80, rsp_buff, MX_ALLOC_LEN, 0)) {
	        len = rsp_buff[3];
		if (len > 0) {
		    memcpy(buff, rsp_buff + 4, len);
		    buff[len] = '\0';
		    printf(" Product serial number: %s\n", buff);
		}
	    }
	}
    }
    else if (do_cmddt) {
	printf("CmdDt INQUIRY, opcode=0x%.2x:\n", num_opcode);
        if (0 == do_inq(sg_fd, 1, 0, num_opcode, rsp_buff, MX_ALLOC_LEN, 1)) {
	    len = rsp_buff[5] + 6;
	    if (do_hex)
		dStrHex((const char *)rsp_buff, len);
	    else {
	    	printf("  Support=%d\n", rsp_buff[1] & 7);
	    }
	}
    }
    else if (do_evpd) {
	printf("EVPD INQUIRY, page code=0x%.2x:\n", num_opcode);
        if (0 == do_inq(sg_fd, 0, 1, num_opcode, rsp_buff, MX_ALLOC_LEN, 1)) {
	    len = rsp_buff[3] + 4;
	    if (! do_hex)
	    	printf(" Only hex output supported\n");
	    dStrHex((const char *)rsp_buff, len);
	}
    }

    if (do_pci) {
        unsigned char slot_name[16];

	printf("\n");
        memset(slot_name, '\0', sizeof(slot_name));
        if (ioctl(sg_fd, SCSI_IOCTL_GET_PCI, slot_name) < 0) {
            if (EINVAL == errno)
                printf("ioctl(SCSI_IOCTL_GET_PCI) not supported by this "
                       "kernel\n");
            else if (ENXIO == errno)
                printf("associated adapter not a PCI device?\n");
            else
                perror("ioctl(SCSI_IOCTL_GET_PCI) failed");
        }
        else
            printf("PCI:slot_name: %s\n", slot_name);
    }

    close(sg_fd);
    return 0;
}
