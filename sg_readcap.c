#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/../scsi/sg.h>  /* cope with silly includes */
#include "sg_err.h"  /* alternatively include <linux/../scsi/scsi.h> */

/* This code is does a SCSI READ CAPACITY command on the given device
   and outputs the result.

*  Copyright (C) 1999,2000 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program is program should work on the 2.0, 2.2 and 2.4 series
   of Linux kernels no matter which of those environments it was
   compiled and built under.

   Version 3.55 (20000827)

10 byte READ CAPACITY command:
[0x25][  |lu][    ][    ][    ][    ][    ][    ][cntrl] {ignore PMI mode}

*/

#ifndef SG_GET_RESERVED_SIZE
#define SG_GET_RESERVED_SIZE 0x2272
#endif

#ifndef SG_SET_RESERVED_SIZE
#define SG_SET_RESERVED_SIZE 0x2275
#endif

#ifndef SG_GET_VERSION_NUM
#define SG_GET_VERSION_NUM 0x2282
#endif

#ifndef SG_NEXT_CMD_LEN
#define SG_NEXT_CMD_LEN 0x2283
#endif

#ifndef SG_MAX_SENSE
#define SG_MAX_SENSE 16
#endif

#ifndef SG_IO
#define SG_IO 0x2285
#endif

#ifndef SG_DXFER_FROM_DEV
#define SG_DXFER_FROM_DEV -3
#endif


#define SG_RT_UNKN (-1)
#define SG_RT_ORIG 0    /* original driver as found in 2.0.* kernels */
#define SG_RT_NEW32 1   /* driver version 2.1.31 + 2.1.32 */
#define SG_RT_NEW34 2   /* version >= 2.1.34 and < 3.0.0 */
#define SG_RT_NEW_V3 3  /* version >= 3.0.0 */

typedef struct sg_h_n  /* for "forward" compatibility case */
{
    int pack_len;    /* [o] reply_len (ie useless), ignored as input */
    int reply_len;   /* [i] max length of expected reply (inc. sg_header) */
    int pack_id;     /* [io] id number of packet (use ints >= 0) */
    int result;      /* [o] 0==ok, else (+ve) Unix errno (best ignored) */
    unsigned int twelve_byte:1;
        /* [i] Force 12 byte command length for group 6 & 7 commands  */
    unsigned int target_status:5;   /* [o] scsi status from target */
    unsigned int host_status:8;     /* [o] host status (see "DID" codes) */
    unsigned int driver_status:8;   /* [o] driver status+suggestion */
    unsigned int other_flags:10;    /* unused */
    unsigned char sense_buffer[SG_MAX_SENSE]; /* [o] Output in 3 cases:
           when target_status is CHECK_CONDITION or
           when target_status is COMMAND_TERMINATED or
           when (driver_status & DRIVER_SENSE) is true. */
} sg_h_n_t;      /* This structure is 36 bytes long on i386 */


typedef struct m_sg_iovec /* same structure as used by readv() Linux system */
{                         /* call. It defines one scatter-gather element. */
    void * iov_base;            /* Starting address  */
    size_t iov_len;             /* Length in bytes  */
} M_sg_iovec_t;


typedef struct m_sg_io_hdr
{
    int interface_id;           /* [i] 'S' for SCSI generic */
    int dxfer_direction;        /* [i] data transfer direction  */
    unsigned char cmd_len;      /* [i] SCSI command length ( <= 16 bytes) */
    unsigned char mx_sb_len;    /* [i] max length to write to sbp */
    unsigned short iovec_count; /* [i] 0 implies no scatter gather */
    unsigned int dxfer_len;     /* [i] byte count of data transfer */
    void * dxferp;              /* [i], [*io] points to data transfer memory
                                              or scatter gather list */
    unsigned char * cmdp;       /* [i], [*i] points to command to perform */
    unsigned char * sbp;        /* [i], [*o] points to sense_buffer memory */
    unsigned int timeout;       /* [i] MAX_UINT->no timeout (unit: millisec) */
    unsigned int flags;         /* [i] 0 -> default, see SG_FLAG... */
    int pack_id;                /* [i->o] unused internally */
    void * usr_ptr;             /* [i->o] unused internally */
    unsigned char status;       /* [o] scsi status */
    unsigned char masked_status;/* [o] shifted, masked scsi status */
    unsigned char msg_status;   /* [o] messaging level data (optional) */
    unsigned char sb_len_wr;    /* [o] byte count actually written to sbp */
    unsigned short host_status; /* [o] errors from host adapter */
    unsigned short driver_status;/* [o] errors from software driver */
    int resid;                  /* [o] dxfer_len - actual_transferred */
    unsigned int duration;      /* [o] 0 -> time taken (unit: millisec) */
    unsigned int info;          /* [o] auxiliary information */
} M_sg_io_hdr_t;  /* 64 bytes long (on i386) */

/* Use negative values to flag difference from original sg_header structure */

static int open_scsi_dev_as_sg(const char * devname);

#define OFF sizeof(struct sg_header)
#define RCAP_REPLY_LEN 8
#define RCAP_CMD_LEN 10
#define MY_PACK_ID 1234


static void usage()
{
    printf("Usage: 'sg_readcap <scsi_device>'\n");
}


/* Return of 0 -> success, -1 -> failure */
int readcap_sg_header(int sg_fd, int sg_which, int * last_sect, int * sect_sz)
{
    int cmd_len, ok;
    unsigned char rcapCmdBlk [RCAP_CMD_LEN] =
                                {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char rcapBuff[OFF + OFF + RCAP_REPLY_LEN]; /* Overkill */
    int rcapInLen = OFF + sizeof(rcapCmdBlk);
    int rcapOutLen = OFF + RCAP_REPLY_LEN;
    unsigned char * buffp = rcapBuff + OFF;
    struct sg_header * sghp = (struct sg_header *)rcapBuff;
    sg_h_n_t * n_sghp = (sg_h_n_t *)rcapBuff;

    sghp->reply_len = rcapOutLen;
    sghp->pack_id = MY_PACK_ID;
    sghp->twelve_byte = 0;
    sghp->other_flags = 0;     /* some apps assume this is done ?!? */

    switch (sg_which) {
    case SG_RT_ORIG:
        sghp->sense_buffer[0] = 0;
        break;
    case SG_RT_NEW32:
        break;
    case SG_RT_NEW34: /* this is optional, explicitly setting cmd length */
        cmd_len = RCAP_CMD_LEN;
        if (ioctl(sg_fd, SG_NEXT_CMD_LEN, &cmd_len) < 0) {
            perror("sg_readcap: SG_NEXT_CMD_LEN error");
            close(sg_fd);
            return 1;
        }
        break;
    default:
        printf("Illegal state for sg_which=%d\n", sg_which);
        return 1;
    }
    memcpy(rcapBuff + OFF, rcapCmdBlk, RCAP_CMD_LEN);

    if (write(sg_fd, rcapBuff, rcapInLen) < 0) {
        perror("sg_readcap: write error");
        close(sg_fd);
        return 1;
    }

    if (read(sg_fd, rcapBuff, rcapOutLen) < 0) {
        perror("sg_readcap: read error");
        close(sg_fd);
        return 1;
    }

    /* now for the error processing */
    ok = 0;
    switch (sg_which) {
    case SG_RT_ORIG:
        if ((0 == sghp->result) && (0 == sghp->sense_buffer[0]))
            ok = 1;
        else if (sghp->sense_buffer[0])
            sg_print_sense("READ CAPACITY command error", sghp->sense_buffer,
                           SG_MAX_SENSE);
        else /* sghp->result is != 0 */
            printf("READ CAPACITY failed, sghp->result=%d\n", sghp->result);
        break;
    case SG_RT_NEW32:
    case SG_RT_NEW34:
        switch (sg_err_category(n_sghp->target_status, n_sghp->host_status,
                n_sghp->driver_status, n_sghp->sense_buffer, SG_MAX_SENSE)) {
        case SG_ERR_CAT_CLEAN:
            ok = 1;
            break;
        case SG_ERR_CAT_RECOVERED:
            printf("Recovered error on READ CAPACITY, continuing\n");
            ok = 1;
            break;
        default: /* won't bother decoding other categories */
            sg_chk_n_print("READ CAPACITY command error",
                           n_sghp->target_status,
                           n_sghp->host_status, n_sghp->driver_status,
                           n_sghp->sense_buffer, SG_MAX_SENSE);
            break;
        }
        break;
    default:
        break;
    }

    if (ok) { /* get result if it is available */
        *last_sect = ((buffp[0] << 24) | (buffp[1] << 16) |
                      (buffp[2] << 8) | buffp[3]);
        *sect_sz = (buffp[4] << 24) | (buffp[5] << 16) |
                   (buffp[6] << 8) | buffp[7];
    }
    return 0;
}

/* Return of 0 -> success, -1 -> failure */
int readcap_sg_io_hdr(int sg_fd, int * last_sect, int * sect_sz)
{
    int res;
    unsigned char rcCmdBlk [10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char rcBuff[RCAP_REPLY_LEN];
    unsigned char sense_b[64];
    M_sg_io_hdr_t io_hdr;

    memset(&io_hdr, 0, sizeof(M_sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = sizeof(rcBuff);
    io_hdr.dxferp = rcBuff;
    io_hdr.cmdp = rcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = 60000;

    while (1) {
        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
            perror("read_capacity (SG_IO) error");
            return -1;
        }
        res = sg_err_category(io_hdr.masked_status, io_hdr.host_status,
                io_hdr.driver_status, io_hdr.sbp, io_hdr.sb_len_wr);
        if (SG_ERR_CAT_MEDIA_CHANGED == res)
            continue;
        else if (SG_ERR_CAT_CLEAN != res) {
            sg_chk_n_print("READ CAPACITY command error",
                           io_hdr.masked_status,
                           io_hdr.host_status, io_hdr.driver_status,
                           io_hdr.sbp, io_hdr.sb_len_wr);
            return -1;
        }
        else
            break;
    }
    *last_sect = ((rcBuff[0] << 24) | (rcBuff[1] << 16) |
                 (rcBuff[2] << 8) | rcBuff[3]);
    *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
               (rcBuff[6] << 8) | rcBuff[7];
    // printf("last sector=%d, sector size=%d\n", *last_sect, *sect_sz);
    return 0;
}


int main(int argc, char * argv[])
{
    int sg_fd, k, res;
    int reserved_size;
    int sg_which = SG_RT_UNKN;
    int sg_version = 0;
    int last_blk_addr, block_size;
    const char * file_name = 0;

    for (k = 1; k < argc; ++k) {
        if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            break;
        }
        else
            file_name = argv[k];
    }
    if (0 == file_name) {
        usage();
        return 1;
    }

    sg_fd = open_scsi_dev_as_sg(file_name);
    if (sg_fd < 0) {
        if (-9999 == sg_fd)
            printf("Failed trying to open SCSI device as an sg device\n");
        else
            perror("sg_readcap: open error");
        return 1;
    }

    /* Run time selection code follows */
    if (ioctl(sg_fd, SG_GET_RESERVED_SIZE, &reserved_size) < 0) {
        reserved_size = SG_BIG_BUFF;
        sg_which = SG_RT_ORIG;
    }
    else if (ioctl(sg_fd, SG_GET_VERSION_NUM, &sg_version) < 0)
        sg_which = SG_RT_NEW32;
    else if (sg_version >= 30000)
        sg_which = SG_RT_NEW_V3;
    else
        sg_which = SG_RT_NEW34;

    if (SG_RT_NEW_V3 == sg_which)
        res = readcap_sg_io_hdr(sg_fd, &last_blk_addr, &block_size);
    else
        res = readcap_sg_header(sg_fd, sg_which, &last_blk_addr, &block_size);

   if (! res) {
        printf("Read Capacity results:\n");
        printf("   Last block address = %u (0x%x), Number of blocks = %u\n",
               last_blk_addr, (int)last_blk_addr, last_blk_addr + 1);
        printf("   Block size = %u bytes\n", block_size);
    }
    close(sg_fd);
    return 0;
}


#define MAX_SG_DEVS 26
#define MAX_FILENAME_LEN 128

#define SCAN_ALPHA 0
#define SCAN_NUMERIC 1
#define DEF_SCAN SCAN_ALPHA

static void make_dev_name(char * fname, int k, int do_numeric)
{
    char buff[MAX_FILENAME_LEN];

    strcpy(fname, "/dev/sg");
    if (do_numeric) {
        sprintf(buff, "%d", k);
        strcat(fname, buff);
    }
    else {
        if (k <= 26) {
            buff[0] = 'a' + (char)k;
            buff[1] = '\0';
            strcat(fname, buff);
        }
        else
            strcat(fname, "xxxx");
    }
}

typedef struct my_scsi_idlun
{
    int mux4;
    int host_unique_id;

} My_scsi_idlun;

static int open_scsi_dev_as_sg(const char * devname)
{
    int fd, bus, bbus, k;
    My_scsi_idlun m_idlun, mm_idlun;
    int do_numeric = DEF_SCAN;
    char name[MAX_FILENAME_LEN];

    strcpy(name, devname);
    if ((fd = open(name, O_RDONLY | O_NONBLOCK)) < 0) {
        if (EACCES == errno) {
            if ((fd = open(name, O_RDWR | O_NONBLOCK)) < 0)
                return fd;
        }
    }
    if (ioctl(fd, SG_GET_TIMEOUT, 0) < 0) { /* not sg device ? */
        if (ioctl(fd, SCSI_IOCTL_GET_BUS_NUMBER, &bus) < 0) {
            printf("Need a filename that resolves to a SCSI device\n");
            close(fd);
            return -9999;
        }
        if (ioctl(fd, SCSI_IOCTL_GET_IDLUN, &m_idlun) < 0) {
            printf("Need a filename that resolves to a SCSI device (2)\n");
            close(fd);
            return -9999;
        }
        close(fd);

        for (k = 0; k < MAX_SG_DEVS; k++) {
            make_dev_name(name, k, do_numeric);
            if ((fd = open(name, O_RDONLY | O_NONBLOCK)) < 0) {
                if (EACCES == errno)
                    fd = open(name, O_RDWR | O_NONBLOCK);
                if (fd < 0) {
                    if ((ENOENT == errno) && (0 == k) &&
                        (do_numeric == DEF_SCAN)) {
                        do_numeric = ! DEF_SCAN;
                        make_dev_name(name, k, do_numeric);
                        if ((fd = open(name, O_RDONLY | O_NONBLOCK)) < 0) {
                            if (EACCES == errno)
                                fd = open(name, O_RDWR | O_NONBLOCK);
                        }
                    }
                    if (fd < 0) {
                        if (EBUSY == errno)
                            continue;  /* step over if O_EXCL already on it */
                        else
                            break;
                    }
                }
            }
            if (ioctl(fd, SCSI_IOCTL_GET_BUS_NUMBER, &bbus) < 0) {
                perror("sg ioctl failed");
                close(fd);
                fd = -9999;
            }
            if (ioctl(fd, SCSI_IOCTL_GET_IDLUN, &mm_idlun) < 0) {
                perror("sg ioctl failed (2)");
                close(fd);
                fd = -9999;
            }
            if ((bus == bbus) &&
                ((m_idlun.mux4 & 0xff) == (mm_idlun.mux4 & 0xff)) &&
                (((m_idlun.mux4 >> 8) & 0xff) ==
                                        ((mm_idlun.mux4 >> 8) & 0xff)) &&
                (((m_idlun.mux4 >> 16) & 0xff) ==
                                        ((mm_idlun.mux4 >> 16) & 0xff))) {
                printf("  >>> Mapping %s to sg device: %s\n", devname, name);
                break;
            }
            else {
                close(fd);
                fd = -9999;
            }
        }
    }
    if (fd >= 0) { /* everything ok, close and re-open read-write */
        close(fd);
        if ((fd = open(name, O_RDWR)) < 0) {
            if (EACCES == errno)
                fd = open(name, O_RDONLY);
        }
    }
    return fd;
}
