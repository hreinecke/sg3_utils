/*
 * Copyright (C) 2003-2019 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
 * device driver.
 * This program will read a certain number of blocks of a given block size
 * from a given sg device node and write what is retrieved out to a
 * normal file. The purpose is to test the sg_iovec mechanism within the
 * sg_io_hdr structure.
 *
 * Version 0.17 (20181207)
 */

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sg_lib.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"



#define ME "sg_iovec_tst: "

#define A_PRIME 509
#define IOVEC_ELEMS 2048

#define SENSE_BUFF_LEN 32
#define DEF_TIMEOUT 40000       /* 40,000 milliseconds */

struct sg_iovec iovec[IOVEC_ELEMS];


static void
usage(void)
{
    printf("Usage: sg_iovec_tst [-a] [-b=bs] -c=num [-e=es] [-h]\n"
           "                    <generic_device> <output_filename>\n");
    printf("  where: -a       async sg use (def: use ioctl(SGIO) )\n");
    printf("         -b=bs    block size (default 512 Bytes)\n");
    printf("         -c=num   count of blocks to transfer\n");
    printf("         -e=es    iovec element size (def: 509)\n");
    printf("         -h       this usage message\n");
    printf(" reads from <generic_device> and sends to "
           "<output_filename>\nUses iovec (a scatter list) in linear "
           "mode\n");
}

/* Returns 0 if everything ok */
static int sg_read(int sg_fd, uint8_t * buff, int num_blocks,
                   int from_block, int bs, int elem_size, int async)
{
    uint8_t rdCmd[10] = {READ_10, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    struct pollfd a_poll;
    int dxfer_len = bs * num_blocks;
    int k, pos, rem, res;

    sg_put_unaligned_be32((uint32_t)from_block, rdCmd + 2);
    sg_put_unaligned_be16((uint16_t)from_block, rdCmd + 7);

    for (k = 0, pos = 0, rem = dxfer_len; k < IOVEC_ELEMS; ++k) {
        iovec[k].iov_base = buff + pos;
        iovec[k].iov_len = (rem > elem_size) ? elem_size : rem;
        if (rem <= elem_size)
            break;
        pos += elem_size;
        rem -= elem_size;
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

    if (async) {
        res = write(sg_fd, &io_hdr, sizeof(io_hdr));
        if (res < 0) {
            perror("write(<sg_device>), error");
            return -1;
        } else if (res < (int)sizeof(io_hdr)) {
            fprintf(stderr, "write(<sg_device>) returned %d, expected %d\n",
                    res, (int)sizeof(io_hdr));
            return -1;
        }
        a_poll.fd = sg_fd;
        a_poll.events = POLLIN;
        a_poll.revents = 0;
        res = poll(&a_poll, 1, 2000 /* millisecs */ );
        if (res < 0) {
            perror("poll error on <sg_device>");
            return -1;
        }
        if (0 == (POLLIN & a_poll.revents)) {
            fprintf(stderr, "strange, poll() completed without data to "
                    "read\n");
            return -1;
        }
        res = read(sg_fd, &io_hdr, sizeof(io_hdr));
        if (res < 0) {
            perror("read(<sg_device>), error");
            return -1;
        } else if (res < (int)sizeof(io_hdr)) {
            fprintf(stderr, "read(<sg_device>) returned %d, expected %d\n",
                    res, (int)sizeof(io_hdr));
            return -1;
        }
    } else if (ioctl(sg_fd, SG_IO, &io_hdr)) {
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
    int do_async = 0;
    int do_help = 0;
    int blk_size = 512;
    int elem_size = A_PRIME;
    int count = 0;
    char * sg_file_name = 0;
    char * out_file_name = 0;
    uint8_t * buffp;

    for (j = 1; j < argc; ++j) {
        if (0 == strcmp("-a", argv[j]))
            do_async = 1;
        else if (0 == strncmp("-b=", argv[j], 3)) {
            m = 3;
            num = sscanf(argv[j] + m, "%d", &blk_size);
            if ((1 != num) || (blk_size <= 0)) {
                printf("Couldn't decode number after '-b' switch\n");
                sg_file_name = 0;
                break;
            }
        } else if (0 == strncmp("-c=", argv[j], 3)) {
            m = 3;
            num = sscanf(argv[j] + m, "%d", &count);
            if (1 != num) {
                printf("Couldn't decode number after '-c' switch\n");
                sg_file_name = 0;
                break;
            }
        } else if (0 == strncmp("-e=", argv[j], 3)) {
            m = 3;
            num = sscanf(argv[j] + m, "%d", &elem_size);
            if (1 != num) {
                printf("Couldn't decode number after '-e' switch\n");
                sg_file_name = 0;
                break;
            }
        } else if (0 == strcmp("-h", argv[j]))
            do_help = 1;
        else if (*argv[j] == '-') {
            printf("Unrecognized switch: %s\n", argv[j]);
            sg_file_name = 0;
            break;
        } else if (NULL == sg_file_name)
            sg_file_name = argv[j];
        else
            out_file_name = argv[j];
    }
    if (do_help) {
        usage();
        return 0;
    }
    if (NULL == sg_file_name) {
        printf(">>> need sg node name (e.g. /dev/sg3)\n\n");
        usage();
        return 1;
    }
    if (NULL == out_file_name) {
        printf(">>> need out filename (to place what is fetched by READ\n\n");
        usage();
        return 1;
    }
    if (0 == count) {
        printf(">>> need count of blocks to READ\n\n");
        usage();
        return 1;
    }

    if (do_async)
        sg_fd = open(sg_file_name, O_RDWR);
    else
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
    buffp = (uint8_t *)calloc(count, blk_size);
    if (buffp) {
        if (0 == sg_read(sg_fd, buffp, count, 0, blk_size, elem_size,
                         do_async)) {
            if (write(fd, buffp, dxfer_len) < 0)
                perror(ME "output write failed");
        }
        free(buffp);
    } else
        fprintf(stderr, "user space calloc for %d bytes failed\n",
                dxfer_len);
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
