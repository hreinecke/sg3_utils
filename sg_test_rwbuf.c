/* sg_test_rwbuf.c */
/*
 * Program to test the SCSI host adapter by issueing 
 * write and read operations on a device's buffer
 * and calculating checksums.
 * NOTE: If you can not reserve the buffer of the device 
 * for this purpose (SG_GET_RESERVED_SIZE), you risk
 * serious data corruption, if the device is accessed by
 * somebody else in the meantime.
 * (c) 2000 Kurt Garloff <garloff@suse.de>
 * heavily based on Doug Gilbert's sg_rbuf program.
 * (c) 1999 Doug Gilbert
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 * 
 * $Id: sg_test_rwbuf.c,v 1.1 2000/03/02 13:50:03 garloff Exp $
 */

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "sg_include.h"
#include "sg_err.h"

#define BPI (signed)(sizeof(int))

#define OFF sizeof(struct sg_header)
#define RB_MODE_DESC 3
#define RB_MODE_DATA 2
#define RB_DESC_LEN 4

int base = 0x12345678;
int buf_capacity = 0;
int buf_granul = 255;
const unsigned char rbCmdBlk [10] = {READ_BUFFER, 0, 0, 0, 0, 0, 0, 0, 0, 0};
int ln; 
char *file_name = 0;
unsigned char *cmpbuf = 0;


/* Options */
char do_quick = 0;
int addwrite  = 0;
int addread   = 0;

int find_out_about_buffer (int sg_fd)
{
    int res;
    unsigned char * rbBuff = malloc(OFF + sizeof(rbCmdBlk) + 512);
    struct sg_header * rsghp = (struct sg_header *)rbBuff;
    int rbInLen = OFF + RB_DESC_LEN;
    int rbOutLen = OFF + sizeof(rbCmdBlk);
    unsigned char * buffp = rbBuff + OFF;
    rsghp->pack_len = 0;                /* don't care */
    rsghp->pack_id = 0;
    rsghp->reply_len = rbInLen;
    rsghp->twelve_byte = 0;
    rsghp->result = 0;
#ifndef SG_GET_RESERVED_SIZE
    rsghp->sense_buffer[0] = 0;
#endif
    memcpy(rbBuff + OFF, rbCmdBlk, sizeof(rbCmdBlk));
    rbBuff[OFF + 1] = RB_MODE_DESC;
    rbBuff[OFF + 8] = RB_DESC_LEN;

    res = write(sg_fd, rbBuff, rbOutLen);
    if (res < 0) {
        perror("sg_test_rwbuf: write (desc) error");
        if (rbBuff) free(rbBuff);
        return 1;
    }
    if (res < rbOutLen) {
        printf("sg_test_rwbuf: wrote less (desc), ask=%d, got=%d\n", rbOutLen, res);
        if (rbBuff) free(rbBuff);
        return 1;
    }
    
    memset(rbBuff + OFF, 0, RB_DESC_LEN);
    res = read(sg_fd, rbBuff, rbInLen);
    if (res < 0) {
        perror("sg_test_rwbuf: read (desc) error");
        if (rbBuff) free(rbBuff);
        return 1;
    }
    if (res < rbInLen) {
        printf("sg_test_rwbuf: read less (desc), ask=%d, got=%d\n", rbInLen, res);
        if (rbBuff) free(rbBuff);
        return 1;
    }
#ifdef SG_GET_RESERVED_SIZE
    if (! sg_chk_n_print("sg_test_rwbuf: desc", rsghp->target_status, 
                         rsghp->host_status, rsghp->driver_status, 
                         rsghp->sense_buffer, SG_MAX_SENSE)) {
        printf("sg_test_rwbuf: perhaps %s doesn't support READ BUFFER\n",
               file_name);
        if (rbBuff) free(rbBuff);
        return 1;
    }
#else
    if ((rsghp->result != 0) || (0 != rsghp->sense_buffer[0])) {
        printf("sg_test_rwbuf: read(desc) result=%d\n", rsghp->result);
        if (0 != rsghp->sense_buffer[0])
            sg_print_sense("sg_test_rwbuf: desc", rsghp->sense_buffer, 
                           SG_MAX_SENSE);
        printf("sg_test_rwbuf: perhaps %s doesn't support READ BUFFER\n",
               file_name);
        if (rbBuff) free(rbBuff);
        return 1;
    }
#endif
    buf_capacity = ((buffp[1] << 16) | (buffp[2] << 8) | buffp[3]);
    buf_granul = (unsigned char)buffp[0];
#if 0	
    printf("READ BUFFER reports: %02x %02x %02x %02x %02x %02x %02x %02x\n",
	   buffp[0], buffp[1], buffp[2], buffp[3],
	   buffp[4], buffp[5], buffp[6], buffp[7]);
#endif
	   
    printf("READ BUFFER reports: buffer capacity=%d, offset boundary=%d\n", 
           buf_capacity, buf_granul);
#ifdef SG_DEF_RESERVED_SIZE
    res = ioctl(sg_fd, SG_SET_RESERVED_SIZE, &buf_capacity);
    if (res < 0)
        perror("sg_test_rwbuf: SG_SET_RESERVED_SIZE error");
#endif
    return 0;
}

int mymemcmp (unsigned char *bf1, unsigned char *bf2, int len)
{
	int df;
	for (df = 0; df < len; df++)
		if (bf1[df] != bf2[df]) return df;
	return 0;
}

int do_checksum (int *buf, int len, int quiet)
{
	int sum = base;
	int i; int rln = len;
	for (i = 0; i < len/BPI; i++)
		sum += buf[i];
	while (rln%BPI) sum += ((char*)buf)[--rln];
	if (sum != 0x12345678) {
		if (!quiet) printf ("sg_test_rwbuf: Checksum error (sz=%i): %08x\n",
			len, sum);
		if (cmpbuf && !quiet) {
			int diff = mymemcmp (cmpbuf, (unsigned char*)buf, len);
			printf ("Differ at pos %i/%i:\n", diff, len);
			for (i = 0; i < 24 && i+diff < len; i++)
				printf (" %02x", cmpbuf[i+diff]);
			printf ("\n");
			for (i = 0; i < 24 && i+diff < len; i++)
				printf (" %02x", ((unsigned char*)buf)[i+diff]);
			printf ("\n");
		}
		return 2;
	}
	else return 0;
}

void do_fill_buffer (int *buf, int len)
{
	int sum; 
	int i; int rln = len;
	srand (time (0));
    retry:
	if (len >= BPI) 
		base = 0x12345678 + rand ();
	else 
		base = 0x12345678 + (char) rand ();
	sum = base;
	for (i = 0; i < len/BPI - 1; i++)
	{
		/* we rely on rand() giving full range of int */
		buf[i] = rand ();	
		sum += buf[i];
	}
	while (rln%BPI) 
	{
		((char*)buf)[--rln] = rand ();
		sum += ((char*)buf)[rln];
	}
	if (len >= BPI) buf[len/BPI - 1] = 0x12345678 - sum;
	else ((char*)buf)[0] = 0x12345678 + ((char*)buf)[0] - sum;
	if (do_checksum (buf, len, 1)) {
		if (len < BPI) goto retry;
		printf ("sg_test_rwbuf: Memory corruption?\n");
		exit (1);
	}
	if (cmpbuf) memcpy (cmpbuf, (char*)buf, len);
}


int read_buffer (int sg_fd, unsigned size)
{
	int res;
	unsigned char * rbBuff = malloc(OFF + sizeof(rbCmdBlk) + size + addread);
	struct sg_header * rsghp = (struct sg_header *)rbBuff;
	
        int rbInLen = OFF + size + addread;
	int rbOutLen = OFF + sizeof (rbCmdBlk);
	memset(rbBuff, 0, OFF + sizeof(rbCmdBlk) + size + addread);
        rsghp->pack_len = 0;                /* don't care */
        rsghp->reply_len = rbInLen;
        rsghp->twelve_byte = 0;
        rsghp->result = 0;
        memcpy(rbBuff + OFF, rbCmdBlk, sizeof(rbCmdBlk));
        rbBuff[OFF + 1] = RB_MODE_DATA;
        rbBuff[OFF + 6] = 0xff & ((size+addread) >> 16);
        rbBuff[OFF + 7] = 0xff & ((size+addread) >> 8);
        rbBuff[OFF + 8] = 0xff & (size+addread);

        rsghp->pack_id = 2;
        res = write(sg_fd, rbBuff, rbOutLen);
        if (res < 0) {
            perror("sg_test_rwbuf: write (data) error");
            if (rbBuff) free(rbBuff);
            return 1;
        }
        if (res < rbOutLen) {
            printf("sg_test_rwbuf: wrote less (data), ask=%d, got=%d\n", 
                   rbOutLen, res);
            if (rbBuff) free(rbBuff);
            return 1;
        }
        
        res = read(sg_fd, rbBuff, rbInLen);
        if (res < 0) {
            perror("sg_test_rwbuf: read (data) error");
            if (rbBuff) free(rbBuff);
            return 1;
        }
        if (res < rbInLen) {
            printf("sg_test_rwbuf: read less (data), ask=%d, got=%d\n", 
                   rbInLen, res);
            if (rbBuff) free(rbBuff);
            return 1;
        }
	res = do_checksum ((int*)(rbBuff + OFF), size, 0);
	if (rbBuff) free(rbBuff);
	return res;
}

int write_buffer (int sg_fd, unsigned size)
{
	int res;
	unsigned char * rbBuff = malloc(OFF + sizeof(rbCmdBlk) + size + addwrite);
	struct sg_header * rsghp = (struct sg_header *)rbBuff;
	//unsigned char * buffp = rbBuff + OFF;
    
        int rbInLen = OFF;
	int rbOutLen = OFF + sizeof (rbCmdBlk) + size + addwrite;
	if (addwrite) memset(rbBuff + OFF + sizeof(rbCmdBlk) + size, 0x5a, addwrite);
	do_fill_buffer ((int*)(rbBuff + OFF + sizeof(rbCmdBlk)), size);
        rsghp->pack_len = 0;                /* don't care */
        rsghp->reply_len = rbInLen;
        rsghp->twelve_byte = 0;
        rsghp->result = 0;
        memcpy(rbBuff + OFF, rbCmdBlk, sizeof(rbCmdBlk));
	rbBuff[OFF + 0] = WRITE_BUFFER;
        rbBuff[OFF + 1] = RB_MODE_DATA;
        rbBuff[OFF + 6] = 0xff & ((size+addwrite) >> 16);
        rbBuff[OFF + 7] = 0xff & ((size+addwrite) >> 8);
        rbBuff[OFF + 8] = 0xff & (size+addwrite);

        rsghp->pack_id = 1;
        res = write(sg_fd, rbBuff, rbOutLen);
        if (res < 0) {
            perror("sg_test_rwbuf: write (data) error");
            if (rbBuff) free(rbBuff);
            return 1;
        }
        if (res < rbOutLen) {
            printf("sg_test_rwbuf: wrote less (data), ask=%d, got=%d\n", 
                   rbOutLen, res);
            if (rbBuff) free(rbBuff);
            return 1;
        }
        
        res = read(sg_fd, rbBuff, rbInLen);
        if (res < 0) {
            perror("sg_test_rwbuf: read (status) error");
            if (rbBuff) free(rbBuff);
            return 1;
        }
	if (rbBuff) free(rbBuff);
	return 0;
}


void usage ()
{
	printf ("Usage: sg_test_rwbuf /dev/sgX sz [addwr] [addrd]\n");
	printf ("sg_test_rwbuf writes and reads back sz bytes to the internal buffer of\n");
	printf (" device /dev/sgX. For testing purposes, you can ask it to write\n");
	printf (" (addwr) or read (addrd) some more bytes.\n");
	printf ("WARNING: If you access the device at the same time, e.g. because it's a\n");
	printf (" mounted hard disk, the device's buffer may be used by the device itself\n");
	printf (" for other data at the same time, and overwriting it may or may not\n");
	printf (" cause data corruption!\n");
	printf ("(c) Douglas Gilbert, Kurt Garloff, 2000, GNU GPL\n");
	exit (1);
}

void parseargs (int argc, char *argv[])
{
	if (argc < 3) usage ();
	file_name = argv[1];
	ln = atol (argv[2]);
	if (argc > 3) addwrite = atol (argv[3]);
	if (argc > 4) addread  = atol (argv[4]);
}


int main (int argc, char * argv[])
{
	int sg_fd; int res;
   
	parseargs (argc, argv);
	sg_fd = open(file_name, O_RDWR);
	if (sg_fd < 0) {
		perror("sg_test_rwbuf: open error");
        return 1;
	}
	/* Don't worry, being very careful not to write to a none-sg file ... */
	res = ioctl(sg_fd, SG_GET_TIMEOUT, 0);
	if (res < 0) {
		/* perror("ioctl on generic device, error"); */
		printf("sg_test_rwbuf: not a sg device, or wrong driver\n");
		return 1;
	}
	if (find_out_about_buffer (sg_fd)) return 1;
	if (ln > buf_capacity) {
		printf ("sg_test_rwbuf: sz=%i > buf_capacity=%i!\n",
			ln, buf_capacity);
		exit (2);
	}
	
	cmpbuf = malloc (ln);
	if (write_buffer (sg_fd, ln)) return 3;
	res = read_buffer (sg_fd, ln);
	if (res) return (res + 4);

	res = close(sg_fd);
	if (res < 0) {
		perror("sg_test_rwbuf: close error");
		return 6;
	}
	printf ("Success\n");
	return 0;
}
	
