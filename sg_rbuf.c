#define _XOPEN_SOURCE 500
#define _GNU_SOURCE  

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include "sg_include.h"
#include "sg_lib.h"

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999-2005 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program uses the SCSI command READ BUFFER on the given sg
   device, first to find out how big it is and then to read that
   buffer. The '-q' option skips the data transfer from the kernel
   DMA buffers to the user space. The '-b=num' option allows the
   buffer size (in KiB) to be specified (default is to use the
   number obtained from READ BUFFER (descriptor) SCSI command).
   The '-s=num' option allows the total size of the transfer to be
   set (in megabytes, the default is 200 MiB). The '-d' option requests
   direct io (and is overridden by '-q').
   The '-m' option request mmap-ed IO (and overrides the '-q' and '-d'
   options if they are also given).
   The ability to time transfers internally (based on gettimeofday()) has
   been added with the '-t' option.
*/


#define RB_MODE_DESC 3
#define RB_MODE_DATA 2
#define RB_DESC_LEN 4
#define RB_MIB_TO_READ 200
#define RB_OPCODE 0x3C
#define RB_CMD_LEN 10

/* #define SG_DEBUG */

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif

#define ME "sg_rbuf: "

static char * version_str = "4.79 20050309";

static void usage()
{
    printf("Usage: sg_rbuf [-b=num] [[-q] | [-d] | [-m]] [-s=num] [-t] "
           "[-v] [-V]\n               <generic_device>\n");
    printf("  where  -b=num   num is buffer size to use (in KiB)\n");
    printf("         -d       requests dio ('-q' overrides it)\n");
    printf("         -m       requests mmap-ed IO (overrides -q, -d)\n");
    printf("         -q       quick, don't xfer to user space\n");
    printf("         -s=num   num is total size to read (in MiB)\n");
    printf("                    default total size is 200 MiB\n");
    printf("                    max total size is 4000 MiB\n");
    printf("         -t       time the data transfer\n");
    printf("         -v       increase verbosity (more debug)\n");
    printf("         -V       print version string then exit\n");
}

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
    int do_mmap = 0;
    int do_time = 0;
    int verbose = 0;
    int buf_size = 0;
    unsigned int total_size_mib = RB_MIB_TO_READ;
    char * file_name = 0;
    size_t psz = getpagesize();
    int dio_incomplete = 0;
    struct sg_io_hdr io_hdr;
    struct timeval start_tm, end_tm;
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
            num = sscanf(argv[j] + m, "%u", &total_size_mib);
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
        else if (0 == strcmp("-m", argv[j]))
            do_mmap = 1;
        else if (0 == strcmp("-t", argv[j]))
            do_time = 1;
        else if (0 == strcmp("-v", argv[j]))
            ++verbose;
        else if (0 == strcmp("-V", argv[j])) {
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        } else if (*argv[j] == '-') {
            printf("Unrecognized switch: %s\n", argv[j]);
            file_name = 0;
            break;
        }
        else
            file_name = argv[j];
    }
    if (0 == file_name) {
        usage();
        return 1;
    }

    sg_fd = open(file_name, O_RDONLY);
    if (sg_fd < 0) {
        perror(ME "open error");
        return 1;
    }
    /* Don't worry, being very careful not to write to a none-sg file ... */
    if (do_mmap) {
        do_dio = 0;
        do_quick = 0;
    }
    if (NULL == (rawp = malloc(512))) {
        printf(ME "out of memory (query)\n");
        return 1;
    }
    rbBuff = rawp;

    memset(rbCmdBlk, 0, RB_CMD_LEN);
    rbCmdBlk[0] = RB_OPCODE;
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
    /* do normal IO to find RB size (not dio or mmap-ed at this stage) */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror(ME "SG_IO READ BUFFER descriptor error");
        if (rawp) free(rawp);
        return 1;
    }

    /* now for the error processing */
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("READ BUFFER descriptor, continuing", &io_hdr);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("READ BUFFER descriptor error", &io_hdr);
        if (rawp) free(rawp);
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
        if (rawp) free(rawp);
        return 1;
    }
    if (rawp) {
        free(rawp);
        rawp = NULL;
    }

    if (! do_dio) {
        k = buf_size;
        if (do_mmap && (0 != (k % psz)))
            k = ((k / psz) + 1) * psz;  /* round up to page size */
        res = ioctl(sg_fd, SG_SET_RESERVED_SIZE, &k);
        if (res < 0)
            perror(ME "SG_SET_RESERVED_SIZE error");
    }

    if (do_mmap) {
        rbBuff = mmap(NULL, buf_size, PROT_READ, MAP_SHARED, sg_fd, 0);
        if (MAP_FAILED == rbBuff) {
            if (ENOMEM == errno)
                printf(ME "mmap() out of memory, try a smaller "
                       "buffer size than %d KiB\n", buf_size / 1024);
            else
                perror(ME "error using mmap()");
            return 1;
        }
    }
    else { /* non mmap-ed IO */
        rawp = malloc(buf_size + (do_dio ? psz : 0));
        if (NULL == rawp) {
            printf(ME "out of memory (data)\n");
            return 1;
        }
        if (do_dio)    /* align to page boundary */
            rbBuff= (unsigned char *)(((unsigned long)rawp + psz - 1) &
                                      (~(psz - 1)));
        else
            rbBuff = rawp;
    }

    num = (total_size_mib * 1024U * 1024U) / (unsigned int)buf_size;
    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }
    /* main data reading loop */
    for (k = 0; k < num; ++k) {
        memset(rbCmdBlk, 0, RB_CMD_LEN);
        rbCmdBlk[0] = RB_OPCODE;
        rbCmdBlk[1] = RB_MODE_DATA;
        rbCmdBlk[6] = 0xff & (buf_size >> 16);
        rbCmdBlk[7] = 0xff & (buf_size >> 8);
        rbCmdBlk[8] = 0xff & buf_size;
#ifdef SG_DEBUG
        memset(rbBuff, 0, buf_size);
#endif

        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = buf_size;
        if (! do_mmap)
            io_hdr.dxferp = rbBuff;
        io_hdr.cmdp = rbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
        io_hdr.pack_id = k;
        if (do_mmap)
            io_hdr.flags |= SG_FLAG_MMAP_IO;
        else if (do_dio)
            io_hdr.flags |= SG_FLAG_DIRECT_IO;
        else if (do_quick)
            io_hdr.flags |= SG_FLAG_NO_DXFER;

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
            if (ENOMEM == errno)
                printf(ME "SG_IO data; out of memory, try a smaller "
                       "buffer size than %d KiB\n", buf_size / 1024);
            else
                perror(ME "SG_IO READ BUFFER data error");
            if (rawp) free(rawp);
            return 1;
        }

        /* now for the error processing */
        switch (sg_err_category3(&io_hdr)) {
        case SG_LIB_CAT_CLEAN:
            break;
        case SG_LIB_CAT_RECOVERED:
            sg_chk_n_print3("READ BUFFER data, continuing", &io_hdr);
            break;
        default: /* won't bother decoding other categories */
            sg_chk_n_print3("READ BUFFER data error", &io_hdr);
            if (rawp) free(rawp);
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
    if ((do_time) && (start_tm.tv_sec || start_tm.tv_usec)) {
        struct timeval res_tm;
        double a, b;

        gettimeofday(&end_tm, NULL);
        res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
        if (res_tm.tv_usec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        a = res_tm.tv_sec;
        a += (0.000001 * res_tm.tv_usec);
        b = (double)buf_size * num;
        printf("time to read data from buffer was %d.%06d secs", 
               (int)res_tm.tv_sec, (int)res_tm.tv_usec);
        if ((a > 0.00001) && (b > 511))
            printf(", %.2f MB/sec\n", b / (a * 1000000.0));
        else
            printf("\n");
    }
    if (dio_incomplete)
        printf(">> direct IO requested but not done\n");
    printf("Read %u MiB (actual %u MiB, %u bytes), buffer size=%d KiB\n",
           total_size_mib, (num * buf_size) / 1048576, num * buf_size,
           buf_size / 1024);

    if (rawp) free(rawp);
    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
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
