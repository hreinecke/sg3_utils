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
#include "sg_err.h"

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999 - 2001 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program scans the "sg" device space (ie actual + simulated SCSI
   generic devices).
   Options: -w   open writable (new driver opens readable unless -i)
            -n   numeric scan: scan /dev/sg0,1,2, ....
            -a   alpha scan: scan /dev/sga,b,c, ....
            -i   do SCSI inquiry on device (implies -w)
            -x   extra information output

   By default this program will look for /dev/sg0 first (i.e. numeric scan)

   Note: This program is written to work under both the original and
   the new sg driver.

   Version 3.92 20010119

   F. Jansen - minor modification to extend beyond 26 sg devices.

6 byte INQUIRY command:
[0x12][   |lu][pg cde][res   ][al len][cntrl ]
*/

#define NUMERIC_SCAN_DEF 1   /* change to 0 to make alpha scan default */

#define OFF sizeof(struct sg_header)
#define INQ_REPLY_LEN 96        /* logic assumes >= sizeof(inqCmdBlk) */
#define INQ_CMD_LEN 6
#define MAX_ERRORS 4


#ifdef SG_GET_RESERVED_SIZE
#define OPEN_FLAG O_RDONLY
#else
#define OPEN_FLAG O_RDWR
#endif

#ifndef SG_MAX_SENSE
#define SG_MAX_SENSE 16
#endif

typedef struct my_scsi_idlun {
/* why can't userland see this structure ??? */
    int dev_id;
    int host_unique_id;
} My_scsi_idlun;

typedef struct my_sg_scsi_id {
    int host_no;        /* as in "scsi<n>" where 'n' is one of 0, 1, 2 etc */
    int channel;
    int scsi_id;        /* scsi id of target device */
    int lun;
    int scsi_type;      /* TYPE_... defined in scsi/scsi.h */
    short h_cmd_per_lun;/* host (adapter) maximum commands per lun */
    short d_queue_depth;/* device (or adapter) maximum queue length */
    int unused1;        /* probably find a good use, set 0 for now */
    int unused2;        /* ditto */
} My_sg_scsi_id;

#ifdef SG_IO
int sg3_inq(int sg_fd, unsigned char * inqBuff, int do_extra);
#endif

#define EBUFF_LEN 256
static unsigned char inqCmdBlk [INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};


void usage()
{
    printf("Usage: 'sg_scan [-a] [-n] [-w] [-i] [-x]'\n");
    printf("    where: -a   do alpha scan (ie sga, sgb, sgc)\n");
    printf("           -n   do numeric scan (ie sg0, sg1...) [default]\n");
    printf("           -w   force open with read/write flag\n");
    printf("           -i   do SCSI INQUIRY, output results\n");
    printf("           -x   extra information output about queuing\n");
}

void make_dev_name(char * fname, int k, int do_numeric)
{
    char buff[64];
    int  big,little;

    strcpy(fname, "/dev/sg");
    if (do_numeric) {
        sprintf(buff, "%d", k);
        strcat(fname, buff);
    }
    else {
        if (k < 26) {
            buff[0] = 'a' + (char)k;
            buff[1] = '\0';
            strcat(fname, buff);
        }
        else if (k <= 255) { /* assumes sequence goes x,y,z,aa,ab,ac etc */
            big    = k/26;
            little = k - (26 * big);
            big    = big - 1;

            buff[0] = 'a' + (char)big;
            buff[1] = 'a' + (char)little;
            buff[2] = '\0';
            strcat(fname, buff);
        }
        else
            strcat(fname, "xxxx");
    }
}


int main(int argc, char * argv[])
{
    int sg_fd, res, k, f;
    unsigned char inqBuff[OFF + INQ_REPLY_LEN];
    int inqInLen = OFF + sizeof(inqCmdBlk);
    int inqOutLen = OFF + INQ_REPLY_LEN;
    unsigned char * buffp = inqBuff + OFF;
    struct sg_header * isghp = (struct sg_header *)inqBuff;
    int do_numeric = NUMERIC_SCAN_DEF;
    int do_inquiry = 0;
    int do_extra = 0;
    int writeable = 0;
    int num_errors = 0;
    int num_silent = 0;
    int eacces_err = 0;
    char fname[64];
    char ebuff[EBUFF_LEN];
    My_scsi_idlun my_idlun;
    int host_no;
    int flags;
    int emul;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-n", argv[k]))
            do_numeric = 1;
        else if (0 == strcmp("-a", argv[k]))
            do_numeric = 0;
        else if (0 == strcmp("-w", argv[k]))
            writeable = 1;
        else if (0 == strcmp("-i", argv[k])) {
#ifndef SG_IO
            writeable = 1;
#endif
            do_inquiry = 1;
        }
        else if (0 == strcmp("-x", argv[k]))
            do_extra = 1;
        else if ((0 == strcmp("-?", argv[k])) ||
                 (0 == strncmp("-h", argv[k], 2))) {
            printf("Scan sg device names and optionally do an INQUIRY\n\n");
            usage();
            return 1;
        }
        else if (*argv[k] == '-') {
            printf("Unknown switch: %s\n", argv[k]);
            usage();
            return 1;
        }
        else if (*argv[k] != '-') {
            printf("Unknown argument\n");
            usage();
            return 1;
        }
    }

    flags = writeable ? O_RDWR : OPEN_FLAG;

    for (k = 0, res = 0; (k < 1000)  && (num_errors < MAX_ERRORS);
         ++k, res = (sg_fd >= 0) ? close(sg_fd) : 0) {
        if (res < 0) {
            sprintf(ebuff, "Error closing %s ", fname);
            perror("sg_scan: close error");
            return 1;
        }
        make_dev_name(fname, k, do_numeric);

        sg_fd = open(fname, flags | O_NONBLOCK);
        if (sg_fd < 0) {
            if (EBUSY == errno) {
                printf("%s: device busy (O_EXCL lock), skipping\n", fname);
                continue;
            }
            else if ((ENODEV == errno) || (ENOENT == errno) ||
                     (ENXIO == errno)) {
                ++num_errors;
                ++num_silent;
                continue;
            }
            else {
                if (EACCES == errno)
                    eacces_err = 1;
                sprintf(ebuff, "Error opening %s ", fname);
                perror(ebuff);
                ++num_errors;
                continue;
            }
        }
        res = ioctl(sg_fd, SCSI_IOCTL_GET_IDLUN, &my_idlun);
        if (res < 0) {
            sprintf(ebuff, "device %s failed on scsi ioctl, skip", fname);
            perror(ebuff);
            ++num_errors;
            continue;
        }
        res = ioctl(sg_fd, SCSI_IOCTL_GET_BUS_NUMBER, &host_no);
        if (res < 0) {
            sprintf(ebuff, "device %s failed on scsi ioctl(2), skip",
                    fname);
            perror(ebuff);
            ++num_errors;
            continue;
        }
#ifdef SG_EMULATED_HOST
        res = ioctl(sg_fd, SG_EMULATED_HOST, &emul);
        if (res < 0) {
            sprintf(ebuff, "device %s failed on sg ioctl(3), skip", fname);
            perror(ebuff);
            ++num_errors;
            continue;
        }
#else
        emul = 0;
#endif
        printf("%s: scsi%d channel=%d id=%d lun=%d", fname, host_no,
               (my_idlun.dev_id >> 16) & 0xff, my_idlun.dev_id & 0xff,
               (my_idlun.dev_id >> 8) & 0xff);
        if (emul)
            printf(" [em]");
#if 0
        printf(", huid=%d", my_idlun.host_unique_id);
#endif
#ifdef SG_GET_RESERVED_SIZE
        {
            My_sg_scsi_id m_id; /* compatible with sg_scsi_id_t in sg.h */

            res = ioctl(sg_fd, SG_GET_SCSI_ID, &m_id);
            if (res < 0) {
                sprintf(ebuff, "device %s ioctls(4), skip", fname);
                perror(ebuff);
                ++num_errors;
                continue;
            }
            printf("  type=%d", m_id.scsi_type);
            if (do_extra)
                printf(" cmd_per_lun=%hd queue_depth=%hd\n",
                       m_id.h_cmd_per_lun, m_id.d_queue_depth);
            else
                printf("\n");
        }
#else
        printf("\n");
#endif
        if (! do_inquiry)
            continue;

#ifdef SG_IO
        if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &f) >= 0) && (f >= 30000)) {
            res = sg3_inq(sg_fd, inqBuff, do_extra);
            continue;
        }
#endif
        memset(isghp, 0, sizeof(struct sg_header));
        isghp->reply_len = inqOutLen;
        memcpy(inqBuff + OFF, inqCmdBlk, INQ_CMD_LEN);
        
        if (O_RDWR == (flags & O_ACCMODE)) { /* turn on blocking */
        f = fcntl(sg_fd, F_GETFL);
            fcntl(sg_fd, F_SETFL, f & (~ O_NONBLOCK)); 
        }
        else {
            close(sg_fd);
            sg_fd = open(fname, O_RDWR);
        }

        res = write(sg_fd, inqBuff, inqInLen);
        if (res < 0) {
            sprintf(ebuff, "device %s writing, skip", fname);
            perror(ebuff);
            ++num_errors;
            continue;
        }
        res = read(sg_fd, inqBuff, inqOutLen);
        if (res < 0) {
            sprintf(ebuff, "device %s reading, skip", fname);
            perror(ebuff);
            ++num_errors;
            continue;
        }
#ifdef SG_GET_RESERVED_SIZE
        if (! sg_chk_n_print("Error from Inquiry", isghp->target_status,
                             isghp->host_status, isghp->driver_status,
                             isghp->sense_buffer, SG_MAX_SENSE))
            continue;
#else
        if ((isghp->result != 0) || (0 != isghp->sense_buffer[0])) {
            printf("Error from Inquiry: result=%d\n", isghp->result);
            if (0 != isghp->sense_buffer[0])
                sg_print_sense("Error from Inquiry", isghp->sense_buffer,
			       SG_MAX_SENSE);
            continue;
        }
#endif
        f = (int)*(buffp + 7);
        printf("    %.8s  %.16s  %.4s ", buffp + 8, buffp + 16,
               buffp + 32);
        printf("[wide=%d sync=%d cmdq=%d sftre=%d pq=0x%x]\n",
               !!(f & 0x20), !!(f & 0x10), !!(f & 2), !!(f & 1),
               (*buffp & 0xe0) >> 5);
    }
    if ((num_errors >= MAX_ERRORS) && (num_silent < num_errors)) {
        printf("Stopping because there are too many error\n");
        if (eacces_err)
            printf("    root access may be required\n");
    }
    return 0;
}

#ifdef SG_IO
int sg3_inq(int sg_fd, unsigned char * inqBuff, int do_extra)
{
    sg_io_hdr_t io_hdr;
    unsigned char sense_buffer[32];
    int ok;

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = INQ_REPLY_LEN;
    io_hdr.dxferp = inqBuff;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_scan: Inquiry SG_IO ioctl error");
        return 1;
    }

    /* now for the error processing */
    ok = 0;
    switch (sg_err_category3(&io_hdr)) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("INQUIRY command error", &io_hdr);
        break;
    }

    if (ok) { /* output result if it is available */
        char * p = (char *)inqBuff;
        int f = (int)*(p + 7);
        printf("    %.8s  %.16s  %.4s ", p + 8, p + 16, p + 32);
        printf("[wide=%d sync=%d cmdq=%d sftre=%d pq=0x%x] ",
               !!(f & 0x20), !!(f & 0x10), !!(f & 2), !!(f & 1),
               (*p & 0xe0) >> 5);
        if (do_extra)
            printf("dur=%ums\n", io_hdr.duration);
        else
            printf("\n");
    }
    return 0;
}
#endif
