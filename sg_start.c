#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "sg_include.h"
#include "sg_err.h"

/* This program is modeled on the example code in the SCSI Programming
   HOWTO V1.5 by Heiko Eissfeldt dated 7 May 1996.
*
*  Copyright (C) 1999 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   Since this code has been used in the past to form the backbone of
   some Linux apps based on the "sg" device driver, it has been
   strengthened.

   Version 0.32 (990728)
 
   Start/Stop parameter by Kurt Garloff <garloff@suse.de>, 6/2000
   Sync cache parameter by Kurt Garloff <garloff@suse.de>, 1/2001
 
*/

#define SCSI_OFF sizeof(struct sg_header)

int debug = 0;
int fd; 					/* SCSI device/file descriptor */
char* fn;
static unsigned char cmd[SCSI_OFF + 18];	/* SCSI command buffer */

/* process a complete SCSI cmd. Use the generic SCSI interface. */
static int handle_SCSI_cmd(int cmd_len,		/* SCSI command length */
                           int in_size,		/* sg_hd + cmd [+ in_data] */
                           unsigned char * i_buff, 
                           int out_size,	/* sg_hd [+ out_data] */
                           unsigned char * o_buff,	/* if == 0 use i_buff */
			   int ign_err		/* ignore errors? */
                           )
{
	int status = 0;
	struct sg_header * sg_hd;
	
	/* safety checks */
	if (cmd_len < 6) return -1;            /* need a cmd_len != 0 */
	if (! i_buff) return -1;             /* need an input buffer != NULL */
	
	if (!o_buff) out_size = 0;      /* no output buffer, no output size */
	
	/* generic SCSI device header construction */
	sg_hd = (struct sg_header *)i_buff;
	sg_hd->reply_len   = SCSI_OFF + out_size;
	sg_hd->twelve_byte = (cmd_len == 12);
	sg_hd->result = 0;
	sg_hd->pack_len = SCSI_OFF + cmd_len + in_size; /* not necessary */
	sg_hd->pack_id = 0;     /* not used internally, but passed back */
	sg_hd->other_flags = 0; /* not used */
	
	if (debug) {
		for (status = 0; status < cmd_len; status++)
			printf (" %02x", i_buff[SCSI_OFF + status]);
		//printf ("\n");
	}
	
	/* send command */
	status = write( fd, i_buff, SCSI_OFF + cmd_len + in_size );
	if ( status < 0 || status != SCSI_OFF + cmd_len + in_size || 
	    sg_hd->result ) {
		/* some error happened */
		fprintf( stderr, "write(generic) result = 0x%x cmd = 0x%x\n",
			sg_hd->result, i_buff[SCSI_OFF] );
		perror("");
		return status;
	}
	
	if (!o_buff) o_buff = i_buff;       /* buffer pointer check */
	
	/* retrieve result */
	status = read( fd, o_buff, SCSI_OFF + out_size);
	if ( status < 0 || status != SCSI_OFF + out_size || (!ign_err && sg_hd->result) ) {
		/* some error happened */
		fprintf( stderr, "read(generic) status = 0x%x, result = 0x%x, "
			"cmd = 0x%x\n", 
			status, sg_hd->result, o_buff[SCSI_OFF] );
        fprintf( stderr, "read(generic) sense "
                "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n", 
                sg_hd->sense_buffer[0],         sg_hd->sense_buffer[1],
                sg_hd->sense_buffer[2],         sg_hd->sense_buffer[3],
                sg_hd->sense_buffer[4],         sg_hd->sense_buffer[5],
                sg_hd->sense_buffer[6],         sg_hd->sense_buffer[7],
                sg_hd->sense_buffer[8],         sg_hd->sense_buffer[9],
                sg_hd->sense_buffer[10],        sg_hd->sense_buffer[11],
                sg_hd->sense_buffer[12],        sg_hd->sense_buffer[13],
                sg_hd->sense_buffer[14],        sg_hd->sense_buffer[15]);
		if (status < 0)
			perror("");
	}
	/* Look if we got what we expected to get */
	if (status == SCSI_OFF + out_size) status = 0; /* got them all */
	
	return status;  /* 0 means no error */
}


#define START_STOP		0x1b
#define SYNCHRONIZE_CACHE	0x35

static unsigned char cmdbuffer[ SCSI_OFF ];


/* request vendor brand and model */
static unsigned char *StartStop ( int start )
{
	unsigned char cmdblk [ 6 ] = { 
		START_STOP,	/* Command */
		1,		/* Resvd/Immed */
		0,		/* Reserved */
		0,		/* Reserved */
		0,		/* PowCond/Resvd/LoEj/Start */
		0 };		/* Reserved/Flag/Link */
	
	if (start) cmdblk[4] |= 1;
	//cmdblk[1] &= ~1;
	memcpy( cmd + SCSI_OFF, cmdblk, sizeof(cmdblk) );
	
	/*
	 * +------------------+
	 * | struct sg_header | <- cmd
	 * +------------------+
	 * | copy of cmdblk   | <- cmd + SCSI_OFF
	 * +------------------+
	 */
	if (debug)
		printf ("%s device %s ... ", (start? "Start": "Stop"), fn);
	if (handle_SCSI_cmd (sizeof(cmdblk), 0, cmd,
			     sizeof(cmdbuffer) - SCSI_OFF, cmdbuffer, 0) ) {
		fprintf( stderr, "Start/Stop failed\n" );
		exit(2);
	}
	if (debug)
		printf ("\n");
	return (cmdbuffer + SCSI_OFF);
}

static unsigned char *SyncCache (int ign_err)
{
	unsigned char cmdblk [ 10 ] = {
		SYNCHRONIZE_CACHE,	/* Command */
		0,			/* Immed (2) */
		0, 0, 0, 0,		/* LBA */
		0,			/* Reserved */
		0, 0,			/* No of blocks */
		0 };			/* Reserved/Flag/Link */
	
	memcpy( cmd + SCSI_OFF, cmdblk, sizeof(cmdblk) );
	
	/*
	 * +------------------+
	 * | struct sg_header | <- cmd
	 * +------------------+
	 * | copy of cmdblk   | <- cmd + SCSI_OFF
	 * +------------------+
	 */

	if (debug) 
		printf ("Sync cache %s ... ", fn);
	if (handle_SCSI_cmd (sizeof(cmdblk), 0, cmd, 
			     sizeof(cmdbuffer) - SCSI_OFF, cmdbuffer, ign_err) ) {
		fprintf( stderr, "Synchronize_Cache failed\n" );
		exit(2);
	}
	if (debug)
		printf ("\n");
	return (cmdbuffer + SCSI_OFF);
}

void usage ()
{
	printf("Usage:  sg_start <sg_device> [-s] [-d] [0/1]\n"
	       "    -s: send the synchronize cache command before start/stop\n"
	       "    -d: output debug\n"
	       "     1: start (spin-up)\n"
	       "     0: stop (spin-down)\n"
	       "        Example: sg_start /dev/sgb 1\n");
	exit (1);
}

int main(int argc, char * argv[])
{
	char **argptr = argv + 2;
	int startstop = -1, synccache = 0;
	
	if (argc < 3) 
		usage ();

	fn = argv[1];
	if (!strcmp (*argptr, "-d")) {
		debug = 1;
		argptr++;
	}
	
	if (*argptr && !strcmp (*argptr, "-s")) {
		synccache = 1;
		argptr++;
	}
	
	if (*argptr) {
		if (!strcmp (*argptr, "0"))
			startstop = 0;
		else if (!strcmp (*argptr, "1"))
			startstop = 1;
	}
	if (!synccache && startstop == -1)
		usage ();
		
	fd = open(fn, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error trying to open %s\n", fn);
		perror("");
		return 2;
	}
	if (ioctl (fd, SG_GET_TIMEOUT, 0) < 0) {
		fprintf( stderr, "Given file not a SCSI generic device\n" );
		close(fd);
		return 3;
	}
	
	if (synccache)
		SyncCache ((startstop == -1? 0: 1));
	
	if (startstop != -1)
		StartStop (startstop);
	
	close (fd);
	return 0;
}
