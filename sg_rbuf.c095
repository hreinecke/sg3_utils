#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_err.h"

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program uses the SCSI command READ BUFFER on the given sg
   device, first to find out how big it is and then to read that
   buffer. The '-q' option skips the data transfer from the kernel
   DMA buffers to the user space. The '-b=num' option allows the
   buffer size (in KBytes) to be specified (default is to use the
   number obtained from READ BUFFER (descriptor) SCSI command).
   The '-s=num' option allows the total size of the transfer to be
   set (in megabytes, the default is 200 MB). The '-d' option requests
   direct io (and is overridden by '-q').

   Version 3.70 (20010321)
*/


#define RB_MODE_DESC 3
#define RB_MODE_DATA 2
#define RB_DESC_LEN 4
#define RB_MB_TO_READ 200
#define RB_OPCODE 0x3C
#define RB_CMD_LEN 10

/* #define SG_DEBUG */


int main(int argc, char * argv[])
{
    int sg_fd, res, j, m;
    unsigned int k, num;
    unsigned char rbCmdBlk [RB_CMD_LEN];
    unsigned char * rbBuff = NULL;
    void * rawp = NULL;
    unsigned char sense_buffer[32];
    int buf_capacity = 0;
    int do_quick = 0;
    int do_dio = 0;
    int buf_size = 0;
    unsigned int total_size_mb = RB_MB_TO_READ;
    char * file_name = 0;
    size_t psz = 0;
    int dio_incomplete = 0;
    sg_io_hdr_t io_hdr;
#ifdef SG_DEBUG
    int clear = 1;
#endif

    for (j = 1; j < argc; ++j) {
        if (0 == strncmp("-b=", argv[j], 3)) {
            m = 3;
            num = sscanf(argv[j] + m, "%d", &buf_size);
            if ((1 != num) || (buf_size <= 0)) {
                printf("Couldn't decode number after '-b' switch\n");
                file_name = 0;
                break;
            }
            buf_size *= 1024;
        }
        else if (0 == strncmp("-s=", argv[j], 3)) {
            m = 3;
            num = sscanf(argv[j] + m, "%u", &total_size_mb);
            if (1 != num) {
                printf("Couldn't decode number after '-s' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strcmp("-q", argv[j]))
            do_quick = 1;
        else if (0 == strcmp("-d", argv[j]))
            do_dio = 1;
        else if (*argv[j] == '-') {
            printf("Unrecognized switch: %s\n", argv[j]);
            file_name = 0;
            break;
        }
        else
            file_name = argv[j];
    }
    if (0 == file_name) {
        printf(
        "Usage: 'sg_rbuf [-q] [-d] [-b=num] [-s=num] <generic_device>'\n");
        printf("  where: -q       quick, don't xfer to user space\n");
        printf("         -d       requests dio ('-q' overrides it)\n");
        printf("         -b=num   num is buff size to use (in KBytes)\n");
        printf("         -s=num   num is total size to read (in MBytes)\n");
        printf("                    default total size is 200 MBytes\n");
        printf("                    max total size is 4000 MBytes\n");
        return 1;
    }

    sg_fd = open(file_name, O_RDONLY);
    if (sg_fd < 0) {
        perror("sg_rbuf: open error");
        return 1;
    }
    /* Don't worry, being very careful not to write to a none-sg file ... */
    res = ioctl(sg_fd, SG_GET_VERSION_NUM, &k);
    if ((res < 0) || (k < 30000)) {
        printf("sg_rbuf: not a sg device, or driver prior to 3.x\n");
        return 1;
    }
    if (NULL == (rbBuff = malloc(512))) {
        printf("sg_rbuf: out of memory (query)\n");
        return 1;
    }

    memset(rbCmdBlk, 0, RB_CMD_LEN);
    rbCmdBlk[0] = RB_OPCODE;
    rbCmdBlk[1] = RB_MODE_DESC;
    rbCmdBlk[8] = RB_DESC_LEN;
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
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
        perror("sg_rbuf: SG_IO READ BUFF descriptor error");
        if (rbBuff) free(rbBuff);
        return 1;
    }

    /* now for the error processing */
    switch (sg_err_category3(&io_hdr)) {
    case SG_ERR_CAT_CLEAN:
        break;
    case SG_ERR_CAT_RECOVERED:
        printf("Recovered error on READ BUFF descriptor, continuing\n");
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("READ BUFF descriptor error", &io_hdr);
        if (rbBuff) free(rbBuff);
        return 1;
    }

    buf_capacity = ((rbBuff[1] << 16) | (rbBuff[2] << 8) | rbBuff[3]);
    printf("READ BUFFER reports: buffer capacity=%d, offset boundary=%d\n",
           buf_capacity, (int)rbBuff[0]);

    if (0 == buf_size)
        buf_size = buf_capacity;
    else if (buf_size > buf_capacity) {
        printf("Requested buffer size=%d exceeds reported capacity=%d\n",
               buf_size, buf_capacity);
        if (rbBuff) free(rbBuff);
        return 1;
    }
    if (! do_dio) {
        res = ioctl(sg_fd, SG_SET_RESERVED_SIZE, &buf_size);
        if (res < 0)
            perror("sg_rbuf: SG_SET_RESERVED_SIZE error");
    }
    if (rbBuff) free(rbBuff);

    psz = getpagesize();
    rawp = malloc(buf_size + (do_dio ? psz : 0));
    if (NULL == rawp) {
        printf("sg_rbuf: out of memory (data)\n");
        return 1;
    }
    if (do_dio)    /* align to page boundary */
    	rbBuff= (unsigned char *)(((unsigned long)rawp + psz - 1) &
			          (~(psz - 1)));
    else
	rbBuff = rawp;

    num = (total_size_mb * 1024U * 1024U) / (unsigned int)buf_size;
    for (k = 0; k < num; ++k) {
        memset(rbCmdBlk, 0, RB_CMD_LEN);
        rbCmdBlk[0] = RB_OPCODE;
        rbCmdBlk[1] = RB_MODE_DATA;
        rbCmdBlk[6] = 0xff & (buf_size >> 16);
        rbCmdBlk[7] = 0xff & (buf_size >> 8);
        rbCmdBlk[8] = 0xff & buf_size;
        memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
#ifdef SG_DEBUG
        memset(rbBuff, 0, buf_size);
#endif

        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = buf_size;
        io_hdr.dxferp = rbBuff;
        io_hdr.cmdp = rbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
        io_hdr.pack_id = k;
        if (do_dio)
            io_hdr.flags |= SG_FLAG_DIRECT_IO;
        if (do_quick)
            io_hdr.flags |= SG_FLAG_NO_DXFER;

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
            perror("sg_rbuf: SG_IO READ BUFF data error");
            if (rbBuff) free(rawp);
            return 1;
        }

        /* now for the error processing */
        switch (sg_err_category3(&io_hdr)) {
        case SG_ERR_CAT_CLEAN:
            break;
        case SG_ERR_CAT_RECOVERED:
            printf("Recovered error on READ BUFF data, continuing\n");
            break;
        default: /* won't bother decoding other categories */
            sg_chk_n_print3("READ BUFF data error", &io_hdr);
            if (rbBuff) free(rawp);
            return 1;
        }
        if (do_dio &&  
            ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
            dio_incomplete = 1;    /* flag that dio not done (completely) */
        
#ifdef SG_DEBUG
        if (clear) {
            for (j = 0; j < buf_size; ++j) {
                if (rbBuff[j] != 0) {
                    clear = 0;
                    break;
                }
            }
        }
#endif
    }
    if (dio_incomplete)
        printf(">> direct IO requested but not done\n");
    printf("Read %u MBytes (actual %u MB, %u bytes), buffer size=%d KBytes\n",
	   total_size_mb, (num * buf_size) / 1048576, num * buf_size,
	   buf_size / 1024);

    if (rbBuff) free(rawp);
    res = close(sg_fd);
    if (res < 0) {
        perror("sg_rbuf: close error");
        return 1;
    }
#ifdef SG_DEBUG
    if (clear)
        printf("read buffer always zero\n");
    else
        printf("read buffer non-zero\n");
#endif
    return 0;
}
