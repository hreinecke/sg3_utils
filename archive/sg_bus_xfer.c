#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_err.h"

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 2001 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program tests the SG_FLAG_BUS_ADDR capability.
   It is for moving data to and from fixed memory addresses (e.g. memory
   mapped io used by video frame buffers) directly to a SCSI device via
   the sg driver. The given address is passed straight through by sg to the
   scsi adapter driver. The adapter typically does a "virtual to bus"
   address transformation and gives the new address to its DMA engine.
   Large amounts of data (in physically contiguous memory) can be moved
   (quickly) in a single SCSI command.

   This will probably only work on i386 architecture with PCI cards that
   memory map their IO area (e.g. video frame buffer). On i386 the
   "virt_to_bus" transformation involves subtracting 0xC0000000 from the
   given address. So from the addresses seen in the lspci command,
   subtracting 0x40000000 would be an appropriate correction (due to
   32 bit wrap around).

   The SG_FLAG_BUS_ADDR logic is not in normal sg drivers, you need a
   patch, see the sg web site.

   Version 0.11 (20010210)
*/

#ifndef SG_FLAG_BUS_ADDR
#define SG_FLAG_BUS_ADDR 0x10
#endif


#define S_RW_LEN 10             /* Use SCSI READ(10) and WRITE(10) */

#define SGP_READ10 0x28
#define SGP_WRITE10 0x2a

/* #define SG_DEBUG */


int get_num(char * buf)
{
    int res, num;
    char c;

    res = sscanf(buf, "%d%c", &num, &c);
    if (0 == res)
        return -1;
    else if (1 == res)
        return num;
    else {
        switch (c) {
        case 'c':
        case 'C':
            return num;
        case 'b':
        case 'B':
            return num * 512;
        case 'k':
            return num * 1024;
        case 'K':
            return num * 1000;
        case 'm':
            return num * 1024 * 1024;
        case 'M':
            return num * 1000000;
        case 'g':
            return num * 1024 * 1024 * 1024;
        case 'G':
            return num * 1000000000;
        default:
            fprintf(stderr, "unrecognized multiplier\n");
            return -1;
        }
    }
}

int main(int argc, char * argv[])
{
    int sg_fd, res, j, m;
    unsigned int k, num;
    unsigned char rwCmdBlk[S_RW_LEN];
    unsigned char sense_buffer[32];
    int do_wr = -1; /* 1 -> write, 0 -> read */
    unsigned long addr = ULONG_MAX;
    int bs = 512;
    int skip = -1;
    int count = -1;
    char * file_name = 0;
    sg_io_hdr_t io_hdr;

    for (j = 1; j < argc; ++j) {
        if (0 == strncmp("-a=", argv[j], 3)) {
            m = 3;
            num = sscanf(argv[j] + m, "%lx", &addr);
            if (1 != num) {
                printf("Couldn't decode number after '-a=' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strncmp("-bs=", argv[j], 4)) {
            m = 4;
            bs = get_num(argv[j] + m);
            if (-1 == bs) {
                printf("Couldn't decode number after '-bs=' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strncmp("-skip=", argv[j], 6)) {
            m = 6;
            skip = get_num(argv[j] + m);
            if (-1 == skip) {
                printf("Couldn't decode number after '-skip=' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strncmp("-count=", argv[j], 7)) {
            m = 7;
            count = get_num(argv[j] + m);
            if (-1 == count) {
                printf("Couldn't decode number after '-count=' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strcmp("-r", argv[j]))
            do_wr = 0;
        else if (0 == strcmp("-w", argv[j]))
            do_wr = 1;
        else if (*argv[j] == '-') {
            printf("Unrecognized switch: %s\n", argv[j]);
            file_name = 0;
            break;
        }
        else
            file_name = argv[j];
    }
    if ((0 == file_name) || (count < 0) || (do_wr < 0) || (addr == ULONG_MAX)
    	|| (skip < 0)) {
	printf("Probabably missing parameter\n\n");
        printf(
        "Usage: 'sg_bus_xfer -r|w -a=hex_num [-bs=num] -skip=num"
	" <sg_device>'\n");
        printf("  where: -r|w         read from (or write to) sg device\n");
        printf("         -a=hex_num   memory address (virtual ?)\n");
        printf("         -bs=num      blocks size in bytes (default 512)\n");
        printf("         -skip=num    num is blocks to skip/seek on sg dev\n");
        printf("         -count=num   num of blocks to xfer\n");
        printf("\n BEWARE you could do damage with this command "
	       "(needs root access)\n");
        printf("\n bs, skip and count may take k,K,m,M etc multipliers\n");
        return 1;
    }

    sg_fd = open(file_name, O_RDWR);
    if (sg_fd < 0) {
        perror("sg_bus_xfer: open error");
        return 1;
    }
    /* Don't worry, being very careful not to write to a none-sg file ... */
    res = ioctl(sg_fd, SG_GET_VERSION_NUM, &k);
    if ((res < 0) || (k < 30000)) {
        printf("sg_bus_xfer: not a sg device, or driver prior to 3.x\n");
        return 1;
    }

    memset(rwCmdBlk, 0, S_RW_LEN);
    rwCmdBlk[0] = do_wr ? SGP_WRITE10 : SGP_READ10;
    rwCmdBlk[2] = (unsigned char)((skip >> 24) & 0xFF);
    rwCmdBlk[3] = (unsigned char)((skip >> 16) & 0xFF);
    rwCmdBlk[4] = (unsigned char)((skip >> 8) & 0xFF);
    rwCmdBlk[5] = (unsigned char)(skip & 0xFF);
    rwCmdBlk[6] = (unsigned char)((count >> 16) & 0xff);
    rwCmdBlk[7] = (unsigned char)((count >> 8) & 0xff);
    rwCmdBlk[8] = (unsigned char)(count & 0xff);
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rwCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = do_wr ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = bs * count;
    // io_hdr.dxferp = malloc(1024 * 1024);	/* <<<<<<<<<<<<<<<< */
    io_hdr.dxferp = (void *)addr;
    io_hdr.cmdp = rwCmdBlk;
    io_hdr.flags = SG_FLAG_BUS_ADDR;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 10000;     /* 10000 millisecs == 10 seconds */

    printf("  dxferp=%p len=%d\n", io_hdr.dxferp, bs * count);
#ifdef SG_DEBUG
    sg_print_command(rwCmdBlk);
    printf("  dxferp=%p len=%d\n", io_hdr.dxferp, bs * count);
    return 0;
#endif
    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_bus_xfer: SG_IO failed");
        return 1;
    }

    /* now for the error processing */
    switch (sg_err_category3(&io_hdr)) {
    case SG_ERR_CAT_CLEAN:
        break;
    case SG_ERR_CAT_RECOVERED:
        printf("Recovered error, continuing\n");
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("SG_IO error", &io_hdr);
        return 1;
    }
    return 0;
}
