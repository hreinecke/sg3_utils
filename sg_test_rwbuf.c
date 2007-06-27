/* sg_test_rwbuf.c */
/*
 * Program to test the SCSI host adapter by issueing 
 * write and read operations on a device's buffer
 * and calculating checksums.
 * NOTE: If you can not reserve the buffer of the device 
 * for this purpose (SG_GET_RESERVED_SIZE), you risk
 * serious data corruption, if the device is accessed by
 * somebody else in the meantime.
 * (c) 2000 Kurt Garloff <garloff at suse dot de>
 * heavily based on Doug Gilbert's sg_rbuf program.
 * (c) 1999-2004 Doug Gilbert
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 * 
 * $Id: sg_test_rwbuf.c,v 1.1 2000/03/02 13:50:03 garloff Exp $
 *
 *   2003/11/11  switch sg3_utils version to use SG_IO ioctl [dpg]
 *   2004/06/08  remove SG_GET_VERSION_NUM check [dpg]
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <time.h>
#include "sg_include.h"
#include "sg_lib.h"

#define BPI (signed)(sizeof(int))

#define RB_MODE_DESC 3
#define RWB_MODE_DATA 2 
#define RB_DESC_LEN 4

/*  The microcode in a SCSI device is _not_ modified by doing a WRITE BUFFER
 *  with mode set to "data" (0x2) as done by this utility. Therefore this 
 *  utility is safe in that respect. [Mode values 0x4, 0x5, 0x6 and 0x7 are
 *  the dangerous ones :-)]
 */

#define ME "sg_test_rwbuf: "

int base = 0x12345678;
int buf_capacity = 0;
int buf_granul = 255;
int ln; 
char *file_name = 0;
unsigned char *cmpbuf = 0;


/* Options */
char do_quick = 0;
int addwrite  = 0;
int addread   = 0;

int find_out_about_buffer (int sg_fd)
{
        unsigned char rbCmdBlk[] = {READ_BUFFER, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        unsigned char rbBuff[RB_DESC_LEN];
        unsigned char sense_buffer[32];
        struct sg_io_hdr io_hdr;

        rbCmdBlk[1] = RB_MODE_DESC;
        rbCmdBlk[8] = RB_DESC_LEN;
        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = RB_DESC_LEN;
        io_hdr.dxferp = rbBuff;
        io_hdr.cmdp = rbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
                perror(ME "SG_IO READ BUFFER descriptor error");
                return 1;
        }
        /* now for the error processing */
        switch (sg_err_category3(&io_hdr)) {
        case SG_LIB_CAT_CLEAN:
                break;
        case SG_LIB_CAT_RECOVERED:
                printf("Recovered error on READ BUFFER descriptor, "
                       "continuing\n");
                break;
        default: /* won't bother decoding other categories */
                sg_chk_n_print3("READ BUFFER descriptor error", &io_hdr);
                return 1;
        }
    
        buf_capacity = ((rbBuff[1] << 16) | (rbBuff[2] << 8) | rbBuff[3]);
        buf_granul = (unsigned char)rbBuff[0];
#if 0   
        printf("READ BUFFER reports: %02x %02x %02x %02x\n",
               rbBuff[0], rbBuff[1], rbBuff[2], rbBuff[3]);
#endif
        printf("READ BUFFER reports: buffer capacity=%d, offset boundary=%d\n", 
               buf_capacity, buf_granul);
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
                if (!quiet) printf ("sg_test_rwbuf: Checksum error (sz=%i):"
                                    " %08x\n", len, sum);
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
        unsigned char rbCmdBlk[] = {READ_BUFFER, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int bufSize = size + addread;
        unsigned char * rbBuff = malloc(bufSize);
        unsigned char sense_buffer[32];
        struct sg_io_hdr io_hdr;

        if (NULL == rbBuff)
                return 1;
        rbCmdBlk[1] = RWB_MODE_DATA;
        rbCmdBlk[6] = 0xff & (bufSize >> 16);
        rbCmdBlk[7] = 0xff & (bufSize >> 8);
        rbCmdBlk[8] = 0xff & bufSize;
        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = bufSize;
        io_hdr.dxferp = rbBuff;
        io_hdr.cmdp = rbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.pack_id = 2;
        io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
                perror(ME "SG_IO READ BUFFER read data error");
                free(rbBuff);
                return 1;
        }
        /* now for the error processing */
        switch (sg_err_category3(&io_hdr)) {
        case SG_LIB_CAT_CLEAN:
                break;
        case SG_LIB_CAT_RECOVERED:
                printf("Recovered error in READ BUFFER read data, "
                       "continuing\n");
                break;
        default: /* won't bother decoding other categories */
                sg_chk_n_print3("READ BUFFER read data error", &io_hdr);
                free(rbBuff);
                return 1;
        }

        res = do_checksum ((int*)rbBuff, size, 0);
        free(rbBuff);
        return res;
}

int write_buffer (int sg_fd, unsigned size)
{
        unsigned char wbCmdBlk[] = {WRITE_BUFFER, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int bufSize = size + addwrite;
        unsigned char * wbBuff = malloc(bufSize);
        unsigned char sense_buffer[32];
        struct sg_io_hdr io_hdr;

        if (NULL == wbBuff)
                return 1;
        memset(wbBuff, 0, bufSize);
        do_fill_buffer ((int*)wbBuff, size);
        wbCmdBlk[1] = RWB_MODE_DATA;
        wbCmdBlk[6] = 0xff & (bufSize >> 16);
        wbCmdBlk[7] = 0xff & (bufSize >> 8);
        wbCmdBlk[8] = 0xff & bufSize;
        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(wbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
        io_hdr.dxfer_len = bufSize;
        io_hdr.dxferp = wbBuff;
        io_hdr.cmdp = wbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.pack_id = 1;
        io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
                perror(ME "SG_IO READ BUFFER write data error");
                free(wbBuff);
                return 1;
        }
        /* now for the error processing */
        switch (sg_err_category3(&io_hdr)) {
        case SG_LIB_CAT_CLEAN:
                break;
        case SG_LIB_CAT_RECOVERED:
                printf("Recovered error in READ BUFFER write data, continuing\n");
                break;
        default: /* won't bother decoding other categories */
                sg_chk_n_print3("READ BUFFER write data error", &io_hdr);
                free(wbBuff);
                return 1;
        }
        free(wbBuff);
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
        printf ("(c) Douglas Gilbert, Kurt Garloff, 2000-2004, GNU GPL\n");
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
        int sg_fd, res;
   
        parseargs (argc, argv);
        sg_fd = open(file_name, O_RDWR);
        if (sg_fd < 0) {
                perror("sg_test_rwbuf: open error");
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
        
