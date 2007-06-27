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

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999 D. Gilbert and P. Allworth
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program is a specialization of the Unix "dd" command in which
   one or both of the given files is a scsi generic device. It assumes
   a 'bs' (block size) of 512 and complains if 'bs' ('ibs' or 'obs') is
   given with some other value.
   If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
   not given of 'of=-' then stdout assumed. The multipliers "c, b, k, m"
   are recognized on numeric arguments.
   As an experiment added an argument "tq" to allow 'tagged queuing' to
   be enabled (1), disabled(0) or left as is (-1) which is the default.
   BEWARE: If the 'of' file is a 'sg' device (eg a disk) then it _will_
   be written to, potentially destroying its previous contents.

   This version should compile with Linux sg drivers with version numbers
   >= 30000 .

   Version 3.96 991208


6 byte commands [READ: 0x08, WRITE: 0x0a]:
[cmd ][had|lu][midAdd][lowAdd][count ][flags ]
10 byte commands [EREAD: 0x28, EWRITE: 0x2a, READ_CAPACITY 0x25]:
[cmd ][   |lu][hiAddr][hmAddr][lmAddr][lowAdd][      ][hiCnt ][lowCnt][flags ]
12 byte commands [LREAD: 0xd8, LWRITE: 0xda]:
[cmd ][   |lu][hiAddr][hmAddr][lmAddr][lowAdd][hiCnt ][hmCnt ][lmCnt ][lowCnt]
 ... [      ][flags ]
*/

#define BLOCK_SIZE 512

#define BLOCKS_PER_WBUFF 128    /* this implies 64 KByte working buffer */

// #define SG_DEBUG

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 40000       /* 40,000 millisecs == 40 seconds */


void usage()
{
    printf("Usage: "
           "sg_dd512 [if=<infile>] [skip=<n>] [of=<ofile>] [seek=<n>]\n"
           "       [count=<n>] [tq=<n>]      {512 byte 'bs' assumed}\n"
           "            either 'if' or 'of' must be a scsi generic device\n"
           " 'tq' is tagged queuing, 1->enable, 0->disable, -1->leave(def)\n");
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
int read_capacity(int sg_fd, int * num_sect, int * sect_sz)
{
    int res;
    unsigned char rcCmdBlk [10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char rcBuff[64];
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
/* printf("number of sectors=%d, sector size=%d\n", *num_sect, *sect_sz); */
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
int sg_read(int sg_fd, unsigned char * buff, int blocks, int from_block)
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
    io_hdr.dxfer_len = BLOCK_SIZE * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = from_block;

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
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
int sg_write(int sg_fd, unsigned char * buff, int blocks, int to_block)
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
    io_hdr.dxfer_len = BLOCK_SIZE * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = to_block;

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
    int count = -1;
    char str[512];
    char * key;
    char * buf;
    char inf[512];
    int in_is_sg = 0;
    char outf[512];
    int out_is_sg = 0;
    int bs_bad = 0;
    int tq = -1;
    int res, k, t, buf_sz;
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
        else if (0 == strcmp(key,"ibs")) {
            if (BLOCK_SIZE != get_num(buf))
                bs_bad = 1;
        }
        else if (0 == strcmp(key,"obs")) {
            if (BLOCK_SIZE != get_num(buf))
                bs_bad = 1;
        }
        else if (0 == strcmp(key,"bs")) {
            if (BLOCK_SIZE != get_num(buf))
                bs_bad = 1;
        }
        else if (0 == strcmp(key,"skip"))
            skip = get_num(buf);
        else if (0 == strcmp(key,"seek"))
            seek = get_num(buf);
        else if (0 == strcmp(key,"count"))
            count = get_num(buf);
        else if (0 == strcmp(key,"tq"))
            tq = get_num(buf);
        else {
            printf("Unrecognized argument '%s'\n", key);
            usage();
            return 1;
        }
    }
    if (bs_bad) {
        printf("If bs/ibs/obs given, must=%d\n", BLOCK_SIZE);
        usage();
        return 1;
    }
    if ((skip < 0) || (seek < 0)) {
        printf("skip and seek cannot be negative\n");
        return 1;
    }
#ifdef SG_DEBUG
    printf("sg_dd512: if=%s skip=%d of=%s seek=%d count=%d\n",
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
                if (0 == tq)
                    res = ioctl(infd, SCSI_IOCTL_TAGGED_DISABLE, &t);
                if (1 == tq)
                    res = ioctl(infd, SCSI_IOCTL_TAGGED_ENABLE, &t);
                if (res < 0)
                    perror("sg_dd512: SCSI_IOCTL_TAGGED error");
                t = BLOCK_SIZE * BLOCKS_PER_WBUFF;
                res = ioctl(infd, SG_SET_RESERVED_SIZE, &t);
                if (res < 0)
                    perror("sg_dd512: SG_SET_RESERVED_SIZE error");
                res = ioctl(infd, SG_GET_VERSION_NUM, &t);
                if ((res < 0) || (t < 30000)) {
                    printf("sg_dd512: sg driver prior to 3.x.y\n");
                    return 1;
                }
            }
        }
        if (! in_is_sg) {
            if ((infd = open(inf, O_RDONLY)) < 0) {
                sprintf(ebuff, "sg_dd512: could not open %s for reading", inf);
                perror(ebuff);
                return 1;
            }
            else if (skip > 0) {
                off_t offset = skip;

                offset *= BLOCK_SIZE;       /* could overflow here! */
                if (lseek(infd, offset, SEEK_SET) < 0) {
                    sprintf(ebuff,
                "sg_dd512: couldn't skip to required position on %s", inf);
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
                if (0 == tq)
                    res = ioctl(outfd, SCSI_IOCTL_TAGGED_DISABLE, &t);
                if (1 == tq)
                    res = ioctl(outfd, SCSI_IOCTL_TAGGED_ENABLE, &t);
                if (res < 0)
                    perror("sg_dd512: SCSI_IOCTL_TAGGED(o) error");
                t = BLOCK_SIZE * BLOCKS_PER_WBUFF;
                res = ioctl(outfd, SG_SET_RESERVED_SIZE, &t);
                if (res < 0)
                    perror("sg_dd512: SG_SET_RESERVED_SIZE error");
                res = ioctl(infd, SG_GET_VERSION_NUM, &t);
                if ((res < 0) || (t < 30000)) {
                    printf("sg_dd512: sg driver prior to 3.x.y\n");
                    return 1;
                }
            }
        }
        if (! out_is_sg) {
            if ((outfd = open(outf, O_WRONLY | O_CREAT, 0666)) < 0) {
                sprintf(ebuff,
                        "sg_dd512: could not open %s for writing", outf);
                perror(ebuff);
                return 1;
            }
            else if (seek > 0) {
                off_t offset = seek;

                offset *= BLOCK_SIZE;       /* could overflow here! */
                if (lseek(outfd, offset, SEEK_SET) < 0) {
                    sprintf(ebuff,
                "sg_dd512: couldn't seek to required position on %s", outf);
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
                    in_sect_sz = BLOCK_SIZE;
                else if (in_sect_sz > BLOCK_SIZE)
                    in_num_sect *=  (in_sect_sz / BLOCK_SIZE);
                else if (in_sect_sz < BLOCK_SIZE)
                    in_num_sect /=  (BLOCK_SIZE / in_sect_sz);
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

    wrkBuff= malloc(BLOCK_SIZE * BLOCKS_PER_WBUFF);
    if (0 == wrkBuff) {
        printf("Not enough user memory\n");
        return 1;
    }
    wrkPos = wrkBuff;

    blocks_per = BLOCKS_PER_WBUFF;
    while (count) {
        blocks = (count > blocks_per) ? blocks_per : count;
        if (in_is_sg) {
            res = sg_read(infd, wrkBuff, blocks, skip);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + BLOCK_SIZE - 1) / BLOCK_SIZE;
                blocks = blocks_per;
                printf("Reducing read to %d blocks per loop\n", blocks_per);
                res = sg_read(infd, wrkBuff, blocks, skip);
            }
            else if (2 == res) {
                printf("Unit attention, media changed, try again (r)\n");
                res = sg_read(infd, wrkBuff, blocks, skip);
            }
            if (0 != res) {
                printf("sg_read failed, skip=%d\n", skip);
                break;
            }
            else
                in_full += blocks;
        }
        else {
            while (((res = read(infd, wrkPos, blocks * BLOCK_SIZE)) < 0) &&
                   (EINTR == errno))
                ;
            if (res < 0) {
                sprintf(ebuff, "sg_dd512: reading, skip=%d ", skip);
                perror(ebuff);
                break;
            }
            else if (res < blocks * BLOCK_SIZE) {
                count = 0;
                blocks = res / BLOCK_SIZE;
                if ((res % BLOCK_SIZE) > 0) {
                    blocks++;
                    in_partial++;
                }
            }
            in_full += blocks;
        }

        if (out_is_sg) {
            res = sg_write(outfd, wrkBuff, blocks, seek);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(outfd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + BLOCK_SIZE - 1) / BLOCK_SIZE;
                blocks = blocks_per;
                printf("Reducing write to %d blocks per loop\n", blocks);
                res = sg_write(outfd, wrkBuff, blocks, seek);
            }
            else if (2 == res) {
                printf("Unit attention, media changed, try again (w)\n");
                res = sg_write(outfd, wrkBuff, blocks, seek);
            }
            else if (0 != res) {
                printf("sg_write failed, seek=%d\n", seek);
                break;
            }
            else
                out_full += blocks;
        }
        else {
            while (((res = write(outfd, wrkPos, blocks * BLOCK_SIZE)) < 0)
                   && (EINTR == errno))
                ;
            if (res < 0) {
                sprintf(ebuff, "sg_ddd512: writing, seek=%d ", seek);
                perror(ebuff);
                break;
            }
            else if (res < blocks * BLOCK_SIZE) {
                printf("output file probably full, seek=%d ", seek);
                blocks = res / BLOCK_SIZE;
                out_full += blocks;
                if ((res % BLOCK_SIZE) > 0)
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
    return 0;
}
