#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "sg_lib.h"
#include "sg_cmds_basic.h"

/* This code is does a SCSI READ CAPACITY command on the given device
   and outputs the result.

*  Copyright (C) 1999 - 2006 D. Gilbert
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

static char * version_str = "3.79 20061015";

#define ME "sg_readcap: "

#define RCAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32


void usage ()
{
    fprintf(stderr, "Usage:  sg_readcap [-16] [-b] [-h] [-H] [-lba=<block>] "
            "[-pmi] [-r] [-v] [-V]\n"
            "                   <device>\n"
            "  where:\n"
            "    -16    use READ CAPACITY (16) cdb (def: use "
            "10 byte cdb)\n"
            "    -b     brief, two hex numbers: number of blocks "
            "and block size\n"
            "    -h     output this usage message and exit\n"
            "    -H     output response in hexadecimal to stdout\n"
            "    -lba=<block>  yields the last block prior to (head "
            "movement) delay\n"
            "                  after <block> [in hex (def: 0) "
            "valid with -pmi]\n"
            "    -pmi   partial medium indicator (without this switch "
            "shows total\n"
            "           disk capacity)\n"
            "    -r     output response in binary to stdout\n"
            "    -v     increase verbosity\n"
            "    -V     output version string and exit\n\n"
            "Perform a READ CAPACITY SCSI command\n");
}

static void dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

int main(int argc, char * argv[])
{
    int sg_fd, k, res, num, plen, jmp_out;
    unsigned int lba = 0;
    unsigned long long llba = 0;
    unsigned long long u, llast_blk_addr;
    int brief = 0;
    int do_hex = 0;
    int pmi = 0;
    int do16 = 0;
    int do_raw = 0;
    int verbose = 0;
    int ret = 0;
    unsigned int last_blk_addr, block_size;
    const char * file_name = 0;
    const char * cp;
    unsigned char resp_buff[RCAP16_REPLY_LEN];

    memset(resp_buff, 0, sizeof(resp_buff));
    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '1':
                    if ('6' == *(cp + 1)) {
                        do16 = 1;
                        ++cp;
                        --plen;
                    } else
                        jmp_out = 1;
                    break;
                case 'b':
                    brief = 1;
                    break;
                case 'h':
                case '?':
                    usage();
                    return 0;
                case 'H':
                    ++do_hex;
                    break;
                case 'p':
                    if (0 == strncmp("pmi", cp, 3)) {
                        pmi = 1;
                        cp += 2;
                        plen -= 2;
                    } else
                        jmp_out = 1;
                    break;
                case 'r':
                    ++do_raw;
                    break;
                case 'v':
                    ++verbose;
                    break;
                case 'V':
                    fprintf(stderr, "Version string: %s\n", version_str);
                    exit(0);
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("lba=", cp, 4)) {
                num = sscanf(cp + 4, "%llx", &u);
                if (1 != num) {
                    printf("Bad value after 'lba=' option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                llba = u;
                if (llba > 0xfffffffeULL)
                    do16 = 1;       /* force READ_CAPACITY16 for large lbas */
                lba = (unsigned int)llba;
            } else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == file_name)
            file_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", file_name, cp);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    
    if (0 == file_name) {
        fprintf(stderr, "No <device> argument given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((0 == pmi) && (lba > 0)) {
        fprintf(stderr, ME "lba can only be non-zero when pmi is set\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((sg_fd = sg_cmds_open_device(file_name, 
                                     (do16 ? 0 /* rw */ : 1), verbose)) < 0) {
        fprintf(stderr, ME "error opening file: %s: %s\n", file_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (! do16) {
        res = sg_ll_readcap_10(sg_fd, pmi, lba, resp_buff, RCAP_REPLY_LEN,
                               0, verbose);
        ret = res;
        if (0 == res) {
            if (do_hex || do_raw) {
                if (do_hex)
                    dStrHex((const char *)resp_buff, RCAP_REPLY_LEN, 1);
                else
                    dStrRaw((const char *)resp_buff, RCAP_REPLY_LEN);
                goto good;
            }
            last_blk_addr = ((resp_buff[0] << 24) | (resp_buff[1] << 16) |
                             (resp_buff[2] << 8) | resp_buff[3]);
            if (0xffffffff != last_blk_addr) {
                block_size = ((resp_buff[4] << 24) | (resp_buff[5] << 16) |
                             (resp_buff[6] << 8) | resp_buff[7]);
                if (brief) {
                    printf("0x%x 0x%x\n", last_blk_addr + 1, block_size);
                    goto good;
                }
                printf("Read Capacity results:\n");
                if (pmi)
                    printf("   PMI mode: given lba=0x%x, last lba before "
                           "delay=0x%x\n", lba, last_blk_addr);
                else
                    printf("   Last logical block address=%u (0x%x), Number "
                           "of blocks=%u\n", last_blk_addr, last_blk_addr,
                           last_blk_addr + 1);
                printf("   Logical block length=%u bytes\n", block_size);
                if (! pmi) {
                    unsigned long long total_sz = last_blk_addr + 1;
                    double sz_mb, sz_gb;

                    total_sz *= block_size;
                    sz_mb = ((double)(last_blk_addr + 1) * block_size) / 
                            (double)(1048576);
                    sz_gb = ((double)(last_blk_addr + 1) * block_size) / 
                            (double)(1000000000L);
                    printf("Hence:\n");
                    printf("   Device size: %llu bytes, %.1f MiB, %.2f GB\n",
                           total_sz, sz_mb, sz_gb);
                }
                goto good;
            } else {
                printf("READ CAPACITY (10) indicates device capacity too "
                       "large\n  now trying 16 byte cdb variant\n");
                do16 = 1;
            }
        } else if (SG_LIB_CAT_INVALID_OP == res) {
            do16 = 1;
            sg_cmds_close_device(sg_fd);
            if ((sg_fd = sg_cmds_open_device(file_name, 0 /*rw */, verbose))
                < 0) {
                fprintf(stderr, ME "error re-opening file: %s (rw): %s\n",
                        file_name, safe_strerror(-sg_fd));
                return SG_LIB_FILE_ERROR;
            }
            if (verbose)
                fprintf(stderr, "READ CAPACITY (10) not supported, trying "
                        "READ CAPACITY (16)\n");
        } else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in READ CAPACITY (10) cdb\n");
        else if (SG_LIB_CAT_NOT_READY == res)
            fprintf(stderr, "READ CAPACITY (10) failed, device not ready\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "READ CAPACITY (10) failed, aborted command\n");
        else if (! verbose)
            fprintf(stderr, "READ CAPACITY (10) failed [res=%d], try "
                    "with '-v'\n", res);
    }
    if (do16) {
        res = sg_ll_readcap_16(sg_fd, pmi, llba, resp_buff, RCAP16_REPLY_LEN,
                               0, verbose);
        ret = res;
        if (0 == res) {
            if (do_hex || do_raw) {
                if (do_hex)
                    dStrHex((const char *)resp_buff, RCAP16_REPLY_LEN, 1);
                else
                    dStrRaw((const char *)resp_buff, RCAP16_REPLY_LEN);
                goto good;
            }
            for (k = 0, llast_blk_addr = 0; k < 8; ++k) {
                llast_blk_addr <<= 8;
                llast_blk_addr |= resp_buff[k];
            }
            block_size = ((resp_buff[8] << 24) | (resp_buff[9] << 16) |
                          (resp_buff[10] << 8) | resp_buff[11]);
            if (brief) {
                printf("0x%llx 0x%x\n", llast_blk_addr + 1, block_size);
                goto good;
            }
            printf("Read Capacity results:\n");
            printf("   Protection: prot_en=%d, p_type=%d\n",
                   !!(resp_buff[12] & 0x1), ((resp_buff[12] >> 1) & 0x7));
            if (pmi)
                printf("   PMI mode: given lba=0x%llx, last lba before "
                       "delay=0x%llx\n", llba, llast_blk_addr);
            else
                printf("   Last logical block address=%llu (0x%llx), Number "
                       "of logical blocks=%llu\n", llast_blk_addr,
                       llast_blk_addr, llast_blk_addr + 1);
            printf("   Logical block length=%u bytes\n", block_size);
            printf("   Logical blocks per physical block=%d (log base 2) "
                   "[actual=%d]\n", (resp_buff[13] & 0xf),
                   (1 << (resp_buff[13] & 0xf)));
            printf("   Lowest aligned logical block address=%d\n",
                   ((resp_buff[14] & 0x3f) << 8) + resp_buff[15]);
            if (! pmi) {
                unsigned long long total_sz = llast_blk_addr + 1;
                double sz_mb, sz_gb;

                total_sz *= block_size;
                sz_mb = ((double)(llast_blk_addr + 1) * block_size) / 
                        (double)(1048576);
                sz_gb = ((double)(llast_blk_addr + 1) * block_size) / 
                        (double)(1000000000L);
                printf("Hence:\n");
                printf("   Device size: %llu bytes, %.1f MiB, %.2f GB\n",
                       total_sz, sz_mb, sz_gb);
            }
            goto good;
        }
        else if (SG_LIB_CAT_INVALID_OP == res) 
            fprintf(stderr, "READ CAPACITY (16) not supported\n");
        else if (SG_LIB_CAT_NOT_READY == res) 
            fprintf(stderr, "READ CAPACITY (16) failed, device not ready\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res) 
            fprintf(stderr, "READ CAPACITY (16) failed, aborted command\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in READ CAPACITY (10) cdb\n");
        else if (! verbose)
            fprintf(stderr, "READ CAPACITY (16) failed [res=%d], try "
                    "with '-v'\n", res);
    }
    if (brief)
        printf("0x0 0x0\n");

good:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
