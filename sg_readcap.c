#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "sg_include.h"
#include "sg_err.h"

/* This code is does a SCSI READ CAPACITY command on the given device
   and outputs the result.

*  Copyright (C) 1999 - 2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program will only work with Linux 2.4 and 2.6 kernels (i.e.
   those that support the SG_IO ioctl). Another version of this program
   that should work on the 2.0, 2.2 and 2.4 series of Linux kernels no 
   matter which of those environments it was compiled and built under
   can be found in the sg_utils package (e.g. sg_utils-1.02).

*/

static char * version_str = "3.65 20040608";

#define ME "sg_readcap: "

#define READCAP_TIMEOUT 60000   /* 60,000 milliseconds == 1 minute */
#define SENSE_BUFF_SZ 32
#define RCAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 12

#ifndef SERVICE_ACTION_IN
#define SERVICE_ACTION_IN     0x9e
#endif
#ifndef SAI_READ_CAPACITY_16
#define SAI_READ_CAPACITY_16  0x10
#endif

#define EBUFF_SZ 256


/* Performs a 16 byte READ CAPACITY command and fetches response.
 * Return of 0 -> success, -1 -> failure */
int do_readcap_16(int sg_fd, int pmi, unsigned long long llba, 
                  unsigned long long * llast_sect, unsigned int * sect_sz)
{
    int k, res;
    unsigned char rcCmdBlk[16] = {SERVICE_ACTION_IN, SAI_READ_CAPACITY_16, 
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char rcBuff[RCAP16_REPLY_LEN];
    unsigned char sense_b[SENSE_BUFF_SZ];
    struct sg_io_hdr io_hdr;
    unsigned long long ls;

    if (pmi) { /* lbs only valid when pmi set */
        rcCmdBlk[14] |= 1;
        rcCmdBlk[2] = (llba >> 56) & 0xff;
        rcCmdBlk[3] = (llba >> 48) & 0xff;
        rcCmdBlk[4] = (llba >> 40) & 0xff;
        rcCmdBlk[5] = (llba >> 32) & 0xff;
        rcCmdBlk[6] = (llba >> 24) & 0xff;
        rcCmdBlk[7] = (llba >> 16) & 0xff;
        rcCmdBlk[8] = (llba >> 8) & 0xff;
        rcCmdBlk[9] = llba & 0xff;
    }
    rcCmdBlk[13] = 12;  /* Allocation length */
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
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
            perror("read_capacity16 (SG_IO) error");
            return -1;
        }
        res = sg_err_category3(&io_hdr);
        if (SG_ERR_CAT_MEDIA_CHANGED == res)
            continue;
        else if (SG_ERR_CAT_CLEAN != res) {
            sg_chk_n_print3("READ CAPACITY 16 command error", &io_hdr);
            return -1;
        }
        else
            break;
    }
    for (k = 0, ls = 0; k < 8; ++k) {
        ls <<= 8;
        ls |= rcBuff[k];
    }
    *llast_sect = ls;
    *sect_sz = (rcBuff[8] << 24) | (rcBuff[9] << 16) |
               (rcBuff[10] << 8) | rcBuff[11];
    return 0;
}


/* Performs a 10 byte READ CAPACITY command and fetches response.
 * Return of 0 -> success, -1 -> failure */
int do_readcap_10(int sg_fd, int pmi, unsigned int lba, 
                  unsigned int * last_sect, unsigned int * sect_sz)
{
    int res;
    unsigned char rcCmdBlk[10] = {READ_CAPACITY, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char rcBuff[RCAP_REPLY_LEN];
    unsigned char sense_b[SENSE_BUFF_SZ];
    struct sg_io_hdr io_hdr;

    if (pmi) { /* lbs only valid when pmi set */
        rcCmdBlk[8] |= 1;
        rcCmdBlk[2] = (lba >> 24) & 0xff;
        rcCmdBlk[3] = (lba >> 16) & 0xff;
        rcCmdBlk[4] = (lba >> 8) & 0xff;
        rcCmdBlk[5] = lba & 0xff;
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
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
        res = sg_err_category3(&io_hdr);
        if (SG_ERR_CAT_MEDIA_CHANGED == res)
            continue;
        else if (SG_ERR_CAT_CLEAN != res) {
            sg_chk_n_print3("READ CAPACITY command error", &io_hdr);
            return -1;
        }
        else
            break;
    }
    *last_sect = ((rcBuff[0] << 24) | (rcBuff[1] << 16) |
                 (rcBuff[2] << 8) | rcBuff[3]);
    *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
               (rcBuff[6] << 8) | rcBuff[7];
    return 0;
}

void usage ()
{
    fprintf(stderr, "Usage:  sg_readcap [-h] [-lba=<block>] [-pmi] [-V] "
            "[-?] <device>\n"
            " where    -16: use 16 byte read capacity command\n"
            "          -h: output this usage message and exit\n"
            "          -lba=<block>: yields the last block prior to (head "
            "movement) delay\n"
            "                        after <block> [in hex (def: 0) "
            "valid with -pmi]\n"
            "          -pmi: partial medium indicator (without this switch "
            "shows total\n"
            "                disk capacity\n"
            "          -V: output version string and exit\n"
            "          -?: output this usage message and exit\n"
            "          <device>: sg device (or block device in lk 2.6)\n"
            "                    with no other arguments reads device "
            "capacity\n");
}

int main(int argc, char * argv[])
{
    int sg_fd, k, res, num;
    unsigned int lba = 0;
    unsigned long long llba = 0;
    unsigned long long u, llast_blk_addr;
    int pmi = 0;
    int do16 = 0;
    unsigned int last_blk_addr, block_size;
    char ebuff[EBUFF_SZ];
    const char * file_name = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-pmi", argv[k]))
            pmi = 1;
        else if (0 == strcmp("-16", argv[k]))
            do16 = 1;
        else if (0 == strncmp("-lba=", argv[k], 5)) {
            num = sscanf(argv[k] + 5, "%llx", &u);
            if (1 != num) {
                printf("Bad value after '-lba' switch\n");
                file_name = 0;
                break;
            }
            llba = u;
            if (llba > 0xfffffffeULL)
                do16 = 1;       /* force READ_CAPACITY16 for large lbas */
            lba = (unsigned int)llba;
        }
        else if (0 == strcmp("-V", argv[k])) {
            printf("Version string: %s\n", version_str);
            exit(0);
        }
        else if (0 == strcmp("-h", argv[k])) {
            usage();
            exit(0);
        }
        else if (0 == strcmp("-?", argv[k])) {
            usage();
            exit(0);
        }
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else
            file_name = argv[k];
    }
    if (0 == file_name) {
        usage();
        return 1;
    }
    if ((0 == pmi) && (lba > 0)) {
        fprintf(stderr, ME "lba can only be non-zero when pmi is set\n");
        usage();
        return 1;
    }
    if ((sg_fd = open(file_name, do16 ? O_RDWR : O_RDONLY)) < 0) {
        snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    if (! do16) {
        res = do_readcap_10(sg_fd, pmi, lba, &last_blk_addr, &block_size);
        if ((0 == res) && (0xffffffff != last_blk_addr)) {
            printf("Read Capacity results:\n");
            if (pmi)
                printf("   PMI mode: given lba=0x%x, last block before "
                       "delay=0x%x\n", lba, last_blk_addr);
            else
                printf("   Last block address=%u (0x%x), Number of blocks=%u\n",
                       last_blk_addr, last_blk_addr, last_blk_addr + 1);
            printf("   Block size = %u bytes\n", block_size);
            if (! pmi) {
                unsigned long long total_sz = last_blk_addr + 1;
                double sz_mb, sz_gb;

                total_sz *= block_size;
                sz_mb = ((double)(last_blk_addr + 1) * block_size) / 
                        (double)(1048576);
                sz_gb = ((double)(last_blk_addr + 1) * block_size) / 
                        (double)(1000000000L);
                printf("Hence:\n");
                printf("   Device size: %llu bytes, %.1f MB, %.2f GB\n",
                       total_sz, sz_mb, sz_gb);
            }
        }
        else if (0 == res) {
            do16 = 1;
            close(sg_fd);
            if ((sg_fd = open(file_name, O_RDWR)) < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "error re-opening file: %s "
                         "RDWR", file_name);
                perror(ebuff);
                return 1;
            }
        }
    }
    if (do16) {
        res = do_readcap_16(sg_fd, pmi, llba, &llast_blk_addr, &block_size);
        if (0 == res) {
            printf("Read Capacity results:\n");
            if (pmi)
                printf("   PMI mode: given lba=0x%llx, last block before "
                       "delay=0x%llx\n", llba, llast_blk_addr);
            else
                printf("   Last block address=%llu (0x%llx), Number of "
                       "blocks=%llu\n", llast_blk_addr, llast_blk_addr, 
                       llast_blk_addr + 1);
            printf("   Block size = %u bytes\n", block_size);
            if (! pmi) {
                unsigned long long total_sz = llast_blk_addr + 1;
                double sz_mb, sz_gb;

                total_sz *= block_size;
                sz_mb = ((double)(llast_blk_addr + 1) * block_size) / 
                        (double)(1048576);
                sz_gb = ((double)(llast_blk_addr + 1) * block_size) / 
                        (double)(1000000000L);
                printf("Hence:\n");
                printf("   Device size: %llu bytes, %.1f MB, %.2f GB\n",
                       total_sz, sz_mb, sz_gb);
            }
        }
    }
    close(sg_fd);
    return 0;
}
