#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_err.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 1999 D. Gilbert and P. Allworth
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program is a specialization of the Unix "dd" command in which
   one or both of the given files is a scsi generic device. A block size
   ('bs') is assumed to be 512 if not given. This program complains if
   'ibs' or 'obs' are given with some other value.
   If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
   not given or 'of=-' then stdout assumed. The multipliers "c, b, k, m"
   are recognized on numeric arguments.

   A non-standard argument "bpt" (blocks per transfer) is added to control
   the maximum number of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16KB
   in this case) are transferred to or from the sg device in a single SCSI
   command.

   This version should compile with Linux sg drivers with version numbers
   >= 30000 .

   Version 3.992 20000823
*/

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128

// #define SG_DEBUG

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define READ_CAP_REPLY_LEN 8
#define DEF_TIMEOUT 40000       /* 40,000 millisecs == 40 seconds */

static int sum_of_resids = 0;


void usage()
{
    printf("Usage: "
           "sg_dd  [if=<infile>] [skip=<n>] [of=<ofile>] [seek=<n>]\n"
           "              [bs=<num>] [bpt=<num>] [count=<n>]"
           " [dio=<n>]\n"
           "            either 'if' or 'of' must be a scsi generic device\n"
           " 'bpt' is blocks_per_transfer (default is 128)\n"
           " 'dio' is direct IO, 1->attempt, 0->indirect IO (def)\n");
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
int read_capacity(int sg_fd, int * num_sect, int * sect_sz)
{
    int res;
    unsigned char rcCmdBlk [10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char rcBuff[READ_CAP_REPLY_LEN];
    unsigned char sense_b[64];
    sg_io_hdr_t io_hdr;

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = sizeof(rcBuff);
    io_hdr.dxferp = rcBuff;
    io_hdr.cmdp = rcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("read_capacity (SG_IO) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    if (SG_ERR_CAT_MEDIA_CHANGED == res)
        return 2; /* probably have another go ... */
    else if (SG_ERR_CAT_CLEAN != res) {
        sg_chk_n_print3("read capacity", &io_hdr);
        return -1;
    }
    *num_sect = 1 + ((rcBuff[0] << 24) | (rcBuff[1] << 16) |
                (rcBuff[2] << 8) | rcBuff[3]);
    *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
               (rcBuff[6] << 8) | rcBuff[7];
#ifdef SG_DEBUG
    printf("number of sectors=%d, sector size=%d\n", *num_sect, *sect_sz);
#endif
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
int sg_read(int sg_fd, unsigned char * buff, int blocks, int from_block,
            int bs, int * diop)
{
    unsigned char rdCmd[10] = {0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char senseBuff[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;
    int res;

    rdCmd[2] = (unsigned char)((from_block >> 24) & 0xFF);
    rdCmd[3] = (unsigned char)((from_block >> 16) & 0xFF);
    rdCmd[4] = (unsigned char)((from_block >> 8) & 0xFF);
    rdCmd[5] = (unsigned char)(from_block & 0xFF);
    rdCmd[7] = (unsigned char)((blocks >> 8) & 0xff);
    rdCmd[8] = (unsigned char)(blocks & 0xff);

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rdCmd);
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = from_block;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    while (((res = write(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("reading (wr) on sg device, error");
        return -1;
    }

    while (((res = read(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        perror("reading (rd) on sg device, error");
        return -1;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_ERR_CAT_CLEAN:
        break;
    case SG_ERR_CAT_RECOVERED:
        printf("Recovered error while reading block=%d, num=%d\n",
               from_block, blocks);
        break;
    case SG_ERR_CAT_MEDIA_CHANGED:
        return 2;
    default:
        sg_chk_n_print3("reading", &io_hdr);
        return -1;
    }
    if (diop && *diop && 
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0;      /* flag that dio not done (completely) */
    sum_of_resids += io_hdr.resid;
#if SG_DEBUG
    printf("duration=%u ms\n", io_hdr.duration);
#endif
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
int sg_write(int sg_fd, unsigned char * buff, int blocks, int to_block,
             int bs, int * diop)
{
    unsigned char wrCmd[10] = {0x2a, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char senseBuff[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;
    int res;

    wrCmd[2] = (unsigned char)((to_block >> 24) & 0xFF);
    wrCmd[3] = (unsigned char)((to_block >> 16) & 0xFF);
    wrCmd[4] = (unsigned char)((to_block >> 8) & 0xFF);
    wrCmd[5] = (unsigned char)(to_block & 0xFF);
    wrCmd[7] = (unsigned char)((blocks >> 8) & 0xff);
    wrCmd[8] = (unsigned char)(blocks & 0xff);

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(wrCmd);
    io_hdr.cmdp = wrCmd;
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = to_block;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    while (((res = write(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("writing (wr) on sg device, error");
        return -1;
    }

    while (((res = read(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        perror("writing (rd) on sg device, error");
        return -1;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_ERR_CAT_CLEAN:
        break;
    case SG_ERR_CAT_RECOVERED:
        printf("Recovered error while writing block=%d, num=%d\n",
               to_block, blocks);
        break;
    case SG_ERR_CAT_MEDIA_CHANGED:
        return 2;
    default:
        sg_chk_n_print3("writing", &io_hdr);
        return -1;
    }
    if (diop && *diop && 
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0;      /* flag that dio not done (completely) */
    return 0;
}

int get_num(char * buf)
{
    int res, num;
    char c, cc;

    res = sscanf(buf, "%d%c", &num, &c);
    if (0 == res)
        return -1;
    else if (1 == res)
        return num;
    else {
        cc = (char)toupper(c);
        if ('B' == cc)
            return num * 512;
        else if ('C' == cc)
            return num;
        else if ('K' == cc)
            return num * 1024;
        else if ('M' == cc)
            return num * 1024 * 1024;
        else {
            printf("unrecognized multiplier\n");
            return -1;
        }
    }
}


int main(int argc, char * argv[])
{
    int skip = 0;
    int seek = 0;
    int bs = 0;
    int ibs = 0;
    int obs = 0;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    int count = -1;
    char str[512];
    char * key;
    char * buf;
    char inf[512];
    int in_is_sg = 0;
    char outf[512];
    int out_is_sg = 0;
    int dio = 0;
    int dio_incomplete = 0;
    int res, k, t, buf_sz, dio_tmp;
    int infd, outfd, blocks;
    unsigned char * wrkBuff;
    unsigned char * wrkPos;
    int in_num_sect = 0;
    int out_num_sect = 0;
    int in_sect_sz, out_sect_sz;
    int in_full = 0;
    int in_partial = 0;
    int out_full = 0;
    int out_partial = 0;
    char ebuff[256];
    int blocks_per;

    inf[0] = '\0';
    outf[0] = '\0';
    if (argc < 2) {
        usage();
        return 1;
    }

    for(k = 1; k < argc; k++) {
        if (argv[k])
            strcpy(str, argv[k]);
        else
            continue;
        for(key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        if (strcmp(key,"if") == 0)
            strcpy(inf, buf);
        else if (strcmp(key,"of") == 0)
            strcpy(outf, buf);
        else if (0 == strcmp(key,"ibs"))
            ibs = get_num(buf);
        else if (0 == strcmp(key,"obs"))
            obs = get_num(buf);
        else if (0 == strcmp(key,"bs"))
            bs = get_num(buf);
        else if (0 == strcmp(key,"bpt"))
            bpt = get_num(buf);
        else if (0 == strcmp(key,"skip"))
            skip = get_num(buf);
        else if (0 == strcmp(key,"seek"))
            seek = get_num(buf);
        else if (0 == strcmp(key,"count"))
            count = get_num(buf);
        else if (0 == strcmp(key,"dio"))
            dio = get_num(buf);
        else {
            printf("Unrecognized argument '%s'\n", key);
            usage();
            return 1;
        }
    }
    if (bs <= 0) {
        bs = DEF_BLOCK_SIZE;
        printf("Assume default 'bs' (block size) of %d bytes\n", bs);
    }
    if ((ibs && (ibs != bs)) || (obs && (obs != bs))) {
        printf("If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return 1;
    }
    if ((skip < 0) || (seek < 0)) {
        printf("skip and seek cannot be negative\n");
        return 1;
    }
#ifdef SG_DEBUG
    printf("sg_dd: if=%s skip=%d of=%s seek=%d count=%d\n",
           inf, skip, outf, seek, count);
#endif
    infd = STDIN_FILENO;
    outfd = STDOUT_FILENO;
    if (inf[0] && ('-' != inf[0])) {
        if ((infd = open(inf, O_RDWR)) >= 0) {
            if (ioctl(infd, SG_GET_TIMEOUT, 0) < 0) {
                /* not a scsi generic device so now try and open RDONLY */
                close(infd);
            }
            else {
                in_is_sg = 1;
                res = 0;
                t = bs * bpt;
                res = ioctl(infd, SG_SET_RESERVED_SIZE, &t);
                if (res < 0)
                    perror("sg_dd: SG_SET_RESERVED_SIZE error");
                res = ioctl(infd, SG_GET_VERSION_NUM, &t);
                if ((res < 0) || (t < 30000)) {
                    printf("sg_dd: sg driver prior to 3.x.y\n");
                    return 1;
                }
            }
        }
        if (! in_is_sg) {
            if ((infd = open(inf, O_RDONLY)) < 0) {
                sprintf(ebuff, "sg_dd: could not open %s for reading", inf);
                perror(ebuff);
                return 1;
            }
            else if (skip > 0) {
                off_t offset = skip;

                offset *= bs;       /* could overflow here! */
                if (lseek(infd, offset, SEEK_SET) < 0) {
                    sprintf(ebuff,
                "sg_dd: couldn't skip to required position on %s", inf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
    }
    if (outf[0] && ('-' != outf[0])) {
        if ((outfd = open(outf, O_RDWR)) >= 0) {
            if (ioctl(outfd, SG_GET_TIMEOUT, 0) < 0) {
                /* not a scsi generic device so now try and open RDONLY */
                close(outfd);
            }
            else {
                out_is_sg = 1;
                res = 0;
                t = bs * bpt;
                res = ioctl(outfd, SG_SET_RESERVED_SIZE, &t);
                if (res < 0)
                    perror("sg_dd: SG_SET_RESERVED_SIZE error");
                res = ioctl(outfd, SG_GET_VERSION_NUM, &t);
                if ((res < 0) || (t < 30000)) {
                    printf("sg_dd: sg driver prior to 3.x.y\n");
                    return 1;
                }
            }
        }
        if (! out_is_sg) {
            if ((outfd = open(outf, O_WRONLY | O_CREAT, 0666)) < 0) {
                sprintf(ebuff,
                        "sg_dd: could not open %s for writing", outf);
                perror(ebuff);
                return 1;
            }
            else if (seek > 0) {
                off_t offset = seek;

                offset *= bs;       /* could overflow here! */
                if (lseek(outfd, offset, SEEK_SET) < 0) {
                    sprintf(ebuff,
                "sg_dd: couldn't seek to required position on %s", outf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
    }
    if ((STDIN_FILENO == infd) && (STDOUT_FILENO == outfd)) {
        printf("Can't have both 'if' as stdin _and_ 'of' as stdout\n");
        return 1;
    }
#if 1
    if (! (in_is_sg || out_is_sg)) {
        printf("Either 'if' or 'of' must be a scsi generic device\n");
        return 1;
    }
#endif
    if (0 == count)
        return 0;
    else if (count < 0) {
        if (in_is_sg) {
            res = read_capacity(infd, &in_num_sect, &in_sect_sz);
            if (2 == res) {
                printf("Unit attention, media changed(in), try again\n");
                res = read_capacity(infd, &in_num_sect, &in_sect_sz);
            }
            if (0 != res) {
                printf("Unable to read capacity on %s\n", inf);
                in_num_sect = -1;
            }
            else {
#if 0
                if (0 == in_sect_sz)
                    in_sect_sz = bs;
                else if (in_sect_sz > bs)
                    in_num_sect *=  (in_sect_sz / bs);
                else if (in_sect_sz < bs)
                    in_num_sect /=  (bs / in_sect_sz);
#endif
                if (in_num_sect > skip)
                    in_num_sect -= skip;
            }
        }
        if (out_is_sg) {
            res = read_capacity(outfd, &out_num_sect, &out_sect_sz);
            if (2 == res) {
                printf("Unit attention, media changed(out), try again\n");
                res = read_capacity(outfd, &out_num_sect, &out_sect_sz);
            }
            if (0 != res) {
                printf("Unable to read capacity on %s\n", outf);
                out_num_sect = -1;
            }
            else {
                if (out_num_sect > seek)
                    out_num_sect -= seek;
            }
        }
#ifdef SG_DEBUG
    printf("Start of loop, count=%d, in_num_sect=%d, out_num_sect=%d\n", 
           count, in_num_sect, out_num_sect);
#endif
        if (in_num_sect > 0) {
            if (out_num_sect > 0)
                count = (in_num_sect > out_num_sect) ? out_num_sect :
                                                       in_num_sect;
            else
                count = in_num_sect;
        }
        else
            count = out_num_sect;
    }

    wrkBuff= malloc(bs * bpt);
    if (0 == wrkBuff) {
        printf("Not enough user memory\n");
        return 1;
    }
    wrkPos = wrkBuff;

    blocks_per = bpt;
#ifdef SG_DEBUG
    printf("Start of loop, count=%d, blocks_per=%d\n", count, blocks_per);
#endif
    while (count) {
        blocks = (count > blocks_per) ? blocks_per : count;
        if (in_is_sg) {
            dio_tmp = dio;
            res = sg_read(infd, wrkBuff, blocks, skip, bs, &dio_tmp);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + bs - 1) / bs;
                blocks = blocks_per;
                printf("Reducing read to %d blocks per loop\n", blocks_per);
                res = sg_read(infd, wrkBuff, blocks, skip, bs, &dio_tmp);
            }
            else if (2 == res) {
                printf("Unit attention, media changed, try again (r)\n");
                res = sg_read(infd, wrkBuff, blocks, skip, bs, &dio_tmp);
            }
            if (0 != res) {
                printf("sg_read failed, skip=%d\n", skip);
                break;
            }
            else {
                in_full += blocks;
                if (dio && (0 == dio_tmp))
                    dio_incomplete++;
            }
        }
        else {
            while (((res = read(infd, wrkPos, blocks * bs)) < 0) &&
                   (EINTR == errno))
                ;
            if (res < 0) {
                sprintf(ebuff, "sg_dd: reading, skip=%d ", skip);
                perror(ebuff);
                break;
            }
            else if (res < blocks * bs) {
                count = 0;
                blocks = res / bs;
                if ((res % bs) > 0) {
                    blocks++;
                    in_partial++;
                }
            }
            in_full += blocks;
        }

        if (out_is_sg) {
            dio_tmp = dio;
            res = sg_write(outfd, wrkBuff, blocks, seek, bs, &dio_tmp);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(outfd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + bs - 1) / bs;
                blocks = blocks_per;
                printf("Reducing write to %d blocks per loop\n", blocks);
                res = sg_write(outfd, wrkBuff, blocks, seek, bs, &dio_tmp);
            }
            else if (2 == res) {
                printf("Unit attention, media changed, try again (w)\n");
                res = sg_write(outfd, wrkBuff, blocks, seek, bs, &dio_tmp);
            }
            else if (0 != res) {
                printf("sg_write failed, seek=%d\n", seek);
                break;
            }
            else {
                out_full += blocks;
                if (dio && (0 == dio_tmp))
                    dio_incomplete++;
            }
        }
        else {
            while (((res = write(outfd, wrkPos, blocks * bs)) < 0)
                   && (EINTR == errno))
                ;
            if (res < 0) {
                sprintf(ebuff, "sg_ddd512: writing, seek=%d ", seek);
                perror(ebuff);
                break;
            }
            else if (res < blocks * bs) {
                printf("output file probably full, seek=%d ", seek);
                blocks = res / bs;
                out_full += blocks;
                if ((res % bs) > 0)
                    out_partial++;
                break;
            }
            else
                out_full += blocks;
        }
        if (count > 0)
            count -= blocks;
        skip += blocks;
        seek += blocks;
    }

    free(wrkBuff);
    if (STDIN_FILENO != infd)
        close(infd);
    if (STDOUT_FILENO != outfd)
        close(outfd);
    if (0 != count) {
        printf("Some error occurred, count=%d\n", count);
        return 1;
    }
    printf("%d+%d records in\n", in_full, in_partial);
    printf("%d+%d records out\n", out_full, out_partial);
    if (dio_incomplete)
        printf(">> Direct IO requested but incomplete %d times\n", 
               dio_incomplete);
    if (sum_of_resids)
        printf(">> Non-zero sum of residual counts=%d\n", sum_of_resids);
    return 0;
}
