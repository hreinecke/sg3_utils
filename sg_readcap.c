#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* This code is does a SCSI READ CAPACITY command on the given device
   and outputs the result.

*  Copyright (C) 1999 - 2005 D. Gilbert
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

static char * version_str = "3.69 20050211";

#define ME "sg_readcap: "

#define RCAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

#define EBUFF_SZ 256


void usage ()
{
    fprintf(stderr, "Usage:  sg_readcap [-h] [-lba=<block>] [-pmi] [-v] [-V]"
            " [-?] <device>\n"
            " where    -16: use 16 byte read capacity command\n"
            "          -h: output this usage message and exit\n"
            "          -lba=<block>: yields the last block prior to (head "
            "movement) delay\n"
            "                        after <block> [in hex (def: 0) "
            "valid with -pmi]\n"
            "          -pmi: partial medium indicator (without this switch "
            "shows total\n"
            "                disk capacity\n"
            "          -v: increase verbosity\n"
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
    int verbose = 0;
    unsigned int last_blk_addr, block_size;
    char ebuff[EBUFF_SZ];
    const char * file_name = 0;
    unsigned char resp_buff[RCAP16_REPLY_LEN];

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
        else if (0 == strcmp("-v", argv[k]))
            ++verbose;
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
    if ((sg_fd = open(file_name, (do16 ? O_RDWR : O_RDONLY) | O_NONBLOCK))
        < 0) {
        snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }

    if (! do16) {
        res = sg_ll_readcap_10(sg_fd, pmi, lba, resp_buff, RCAP_REPLY_LEN,
                               verbose);
        if (0 == res) {
            last_blk_addr = ((resp_buff[0] << 24) | (resp_buff[1] << 16) |
                             (resp_buff[2] << 8) | resp_buff[3]);
            if (0xffffffff != last_blk_addr) {
                block_size = ((resp_buff[4] << 24) | (resp_buff[5] << 16) |
                             (resp_buff[6] << 8) | resp_buff[7]);
                printf("Read Capacity results:\n");
                if (pmi)
                    printf("   PMI mode: given lba=0x%x, last block before "
                           "delay=0x%x\n", lba, last_blk_addr);
                else
                    printf("   Last block address=%u (0x%x), Number of "
                           "blocks=%u\n", last_blk_addr, last_blk_addr,
                           last_blk_addr + 1);
                printf("   Block size=%u bytes\n", block_size);
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
        } else if (SG_LIB_CAT_INVALID_OP == res) {
            do16 = 1;
            close(sg_fd);
            if ((sg_fd = open(file_name, O_RDWR | O_NONBLOCK)) < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "error re-opening file: %s "
                         "RDWR", file_name);
                perror(ebuff);
                return 1;
            }
            if (verbose)
                fprintf(stderr, "READ CAPACITY (10) not supported, trying "
                        "READ CAPACITY (16)\n");
        } else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in READ CAPACITY (10) cdb\n");
        else if (verbose)
            fprintf(stderr, "READ CAPACITY (10) failed [res=%d]\n", res);
    }
    if (do16) {
        res = sg_ll_readcap_16(sg_fd, pmi, llba, resp_buff, RCAP16_REPLY_LEN,
                               verbose);
        if (0 == res) {
            for (k = 0, llast_blk_addr = 0; k < 8; ++k) {
                llast_blk_addr <<= 8;
                llast_blk_addr |= resp_buff[k];
            }
            block_size = ((resp_buff[8] << 24) | (resp_buff[9] << 16) |
                          (resp_buff[10] << 8) | resp_buff[11]);
            printf("Read Capacity results:\n");
            printf("   Protection: prot_en=%d, rto_en=%d\n",
                   !!(resp_buff[12] & 0x1), !!(resp_buff[12] & 0x2));
            if (pmi)
                printf("   PMI mode: given lba=0x%llx, last block before "
                       "delay=0x%llx\n", llba, llast_blk_addr);
            else
                printf("   Last block address=%llu (0x%llx), Number of "
                       "blocks=%llu\n", llast_blk_addr, llast_blk_addr, 
                       llast_blk_addr + 1);
            printf("   Block size=%u bytes\n", block_size);
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
        else if (SG_LIB_CAT_INVALID_OP == res) 
            fprintf(stderr, "READ CAPACITY (16) not supported\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in READ CAPACITY (10) cdb\n");
        else if (verbose)
            fprintf(stderr, "READ CAPACITY (16) failed [res=%d]\n", res);
    }
    close(sg_fd);
    return 0;
}
