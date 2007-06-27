#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"

/* This is a program that periodically executes a TEST UNIT READY
   SCSI command using the SCSI generic (sg) driver.

*  Copyright (C) 2001 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   Invocation: sg_hold [-t<secs>] [-d] <sg_device>

   Version 1.00 (20010312)

6 byte TEST UNIT READY command:
[0x00][   |lu][res   ][res   ][res   ][res   ]

*/
#define TUR_CMD_LEN 6


int main(int argc, char * argv[])
{
    int sg_fd, k, j, res;
    unsigned char turCmdBlk [TUR_CMD_LEN] =
                                {0x00, 0, 0, 0, 0, 0};
    sg_io_hdr_t io_hdr;
    char * file_name = 0;
    char ebuff[128];
    unsigned char sense_buffer[32];
    int sleep_period = 1;
    int debug = 0;
    size_t len;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-t", argv[k], 2)) {
	    len = strlen(argv[k]);
	    if (len > 2) 
	    	res = sscanf(argv[k] + 2, "%d", &sleep_period);
	    else if (++k < argc)
	    	res = sscanf(argv[k], "%d", &sleep_period);
	    else
	    	res = 0;
	    if ((1 != res) || (sleep_period < 1)) {
	    	file_name = 0;
		printf("Bad '-t' argument\n");
		break;
	    }
	}
        else if (0 == memcmp("-d", argv[k], 2))
	    debug = 1;
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
        printf("Usage: 'sg_hold [-t<secs>] [-d] <sg_device>'\n");
	printf("    where: -t<secs>  time in seconds between TURs "
	       "(default: 1 sec)\n");
	printf("           -d  output message with each TUR\n");
        return 1;
    }
    
    if ((sg_fd = open(file_name, O_RDONLY)) < 0) {
        sprintf(ebuff, "sg_hold: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Just to be safe, check we have a new sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        printf("sg_hold: %s doesn't seem to be an new sg device\n", 
               file_name);
        close(sg_fd);
        return 1;
    }

    for (j = 1; ; ++j) {
	/* Prepare TEST UNIT READY command */
	memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof(turCmdBlk);
	io_hdr.mx_sb_len = sizeof(sense_buffer);
	io_hdr.dxfer_direction = SG_DXFER_NONE;
	io_hdr.cmdp = turCmdBlk;
	io_hdr.sbp = sense_buffer;
	io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
	io_hdr.pack_id = j;	/* marching pack_id starting at 1 */

	if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
	    perror("sg_hold: Test Unit Ready SG_IO ioctl error");
	    close(sg_fd);
	    return 1;
	}

	/* now for the error processing */
	if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
	    if (io_hdr.sb_len_wr > 0) {
		printf("TEST UNIT READY sense data: ");
		for (k = 0; k < io_hdr.sb_len_wr; ++k) {
		    if ((k > 0) && (0 == (k % 10)))
			printf("\n  ");
		    printf("0x%02x ", sense_buffer[k]);
		}
		printf("\n");
	    }
	    else if (io_hdr.masked_status)
		printf("TEST UNIT READY SCSI status=0x%x\n", io_hdr.status);
	    else if (io_hdr.host_status)
		printf("TEST UNIT READY host_status=0x%x\n", 
		       io_hdr.host_status);
	    else if (io_hdr.driver_status)
		printf("TEST UNIT READY driver_status=0x%x\n", 
		       io_hdr.driver_status);
	    else
		printf("TEST UNIT READY unexpected error\n");
	    printf("Test Unit Ready failed so unit may _not_ be ready!\n");
	}
	else if (debug)
	    printf("Test Unit Ready successful so unit is ready!\n");
	
	sleep(sleep_period);
    }
    close(sg_fd);
    return 0;
}
