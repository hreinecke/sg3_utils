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
#include "sg_lib.h"
#include "sg_io_linux.h"

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 2003-2007 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program will read a certain number of blocks of a given block size
   from a given sg device node and write what is retrieved out to a
   normal file. The purpose is to test the sg_iovec mechanism within the
   sg_io_hdr structure.

   Version 0.12 (20070121)
*/


#define ME "sg_iovec_tst: "

#define A_PRIME 509
#define IOVEC_ELEMS 2048

#define SENSE_BUFF_LEN 32
#define DEF_TIMEOUT 40000       /* 40,000 milliseconds */

struct sg_iovec iovec[IOVEC_ELEMS];

/* Returns 0 if everything ok */
int sg_read(int sg_fd, unsigned char * buff, int num_blocks, int from_block,
            int bs)
{
    unsigned char rdCmd[10] = {READ_10, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int dxfer_len = bs * num_blocks;
    int k, pos, rem;

    rdCmd[2] = (unsigned char)((from_block >> 24) & 0xff);
    rdCmd[3] = (unsigned char)((from_block >> 16) & 0xff);
    rdCmd[4] = (unsigned char)((from_block >> 8) & 0xff);
    rdCmd[5] = (unsigned char)(from_block & 0xff);
    rdCmd[7] = (unsigned char)((num_blocks >> 8) & 0xff);
    rdCmd[8] = (unsigned char)(num_blocks & 0xff);

    for (k = 0, pos = 0, rem = dxfer_len; k < IOVEC_ELEMS; ++k) {
        iovec[k].iov_base = buff + pos;
        iovec[k].iov_len = (rem > A_PRIME) ? A_PRIME : rem;
        if (rem <= A_PRIME)
            break;
        pos += A_PRIME;
        rem -= A_PRIME;
    }
    if (k >= IOVEC_ELEMS) {
        fprintf(stderr, "Can't fit dxfer_len=%d bytes in iovec\n", dxfer_len);
        return -1;
    }
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rdCmd);
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = dxfer_len;
    io_hdr.iovec_count = k + 1;
    io_hdr.dxferp = iovec;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = from_block;

    if (ioctl(sg_fd, SG_IO, &io_hdr)) {
        perror("reading (SG_IO) on sg device, error");
        return -1;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        fprintf(stderr, "Recovered error while reading block=%d, num=%d\n",
               from_block, num_blocks);
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:
        fprintf(stderr, "Unit attention\n");
        return -1;
    default:
        sg_chk_n_print3("reading", &io_hdr, 1);
        return -1;
    }
    return 0;
}


int main(int argc, char * argv[])
{
    int sg_fd, fd, res, j, m, dxfer_len;
    unsigned int k, num;
    int do_help = 0;
    int blk_size = 512;
    int count = 0;
    char * sg_file_name = 0;
    char * out_file_name = 0;
    unsigned char * buffp;

    for (j = 1; j < argc; ++j) {
        if (0 == strncmp("-b=", argv[j], 3)) {
            m = 3;
            num = sscanf(argv[j] + m, "%d", &blk_size);
            if ((1 != num) || (blk_size <= 0)) {
                printf("Couldn't decode number after '-b' switch\n");
                sg_file_name = 0;
                break;
            }
        }
        else if (0 == strncmp("-c=", argv[j], 3)) {
            m = 3;
            num = sscanf(argv[j] + m, "%d", &count);
            if (1 != num) {
                printf("Couldn't decode number after '-c' switch\n");
                sg_file_name = 0;
                break;
            }
        }
        else if (0 == strcmp("-h", argv[j]))
            do_help = 1;
        else if (*argv[j] == '-') {
            printf("Unrecognized switch: %s\n", argv[j]);
            sg_file_name = 0;
            break;
        }
        else if (NULL == sg_file_name)
            sg_file_name = argv[j];
        else
            out_file_name = argv[j];
    }
    if ((NULL == sg_file_name) || (NULL == out_file_name) || (0 == count)) {
        printf("Usage: sg_iovec_tst [-h] [-b=num] -c=num <generic_device> "
               "<output_filename>\n");
        printf("  where: -h       this usage message\n");
        printf("         -b=num   block size (default 512 Bytes)\n");
        printf("         -c=num   count of blocks to transfer\n");
        printf(" reads from <generic_device> and sends to <output_filename>\n");
        return 1;
    }

    sg_fd = open(sg_file_name, O_RDONLY);
    if (sg_fd < 0) {
        perror(ME "sg device node open error");
        return 1;
    }
    /* Don't worry, being very careful not to write to a none-sg file ... */
    res = ioctl(sg_fd, SG_GET_VERSION_NUM, &k);
    if ((res < 0) || (k < 30000)) {
        printf(ME "not a sg device, or driver prior to 3.x\n");
        return 1;
    }
    fd = open(out_file_name, O_WRONLY | O_CREAT, 0666);
    if (fd < 0) {
        perror(ME "output file open error");
        return 1;
    }
    dxfer_len = count * blk_size;
    buffp = (unsigned char *)malloc(dxfer_len);
    if (buffp) {
        if (0 == sg_read(sg_fd, buffp, count, 0, blk_size)) {
            if (write(fd, buffp, dxfer_len) < 0)
                perror(ME "output write failed");
        }
        free(buffp);
    }
    res = close(fd);
    if (res < 0) {
        perror(ME "output file close error");
        close(sg_fd);
        return 1;
    }
    res = close(sg_fd);
    if (res < 0) {
        perror(ME "sg device close error");
        return 1;
    }
    return 0;
}
