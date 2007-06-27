/*
 * Copyright (c) 2004-2005 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This program issues the SCSI VERIFY command to the given SCSI block device.
 */

static char * version_str = "1.02 20050309";

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define VERIFY10_CMD      0x2f
#define VERIFY10_CMDLEN   10

#define ME "sg_verify: "


static struct option long_options[] = {
        {"bpc", 1, 0, 'b'},
        {"count", 1, 0, 'c'},
        {"dpo", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"lba", 1, 0, 'l'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_verify [--bpc=<n>] [--count=<n>] [--dpo] [--help] [--lba=<n>]\n"
          "                   [--verbose] [--version] <scsi_device>\n"
          "  where: --bpc=<n>|-b <n>   max blocks per verify command "
          "(def 128)\n"
          "         --count=<n>|-c <n> count of blocks to verify (def 1)\n"
          "         --dpo|-d           disable page out (cache retension "
          "priority)\n"
          "         --help|-h          print out usage message\n"
          "         --lba=<n>|-l <n>   logical block address to start "
          "verify (def 0)\n"
          "         --verbose|-v       increase verbosity\n"
          "         --version|-V       print version string and exit\n"
          );

}

/* Invokes a SCSI VERIFY (10) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Verify(10) not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
int sg_ll_verify10(int sg_fd, int dpo, int bytechk, unsigned long lba,
                   int veri_len, void * data_out, int data_out_len,
                   int verbose)
{
    int k, res;
    unsigned char vCmdBlk[VERIFY10_CMDLEN] = 
                {VERIFY10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if ((0 == bytechk) && (data_out && (data_out_len > 0))) {
        fprintf(stderr, "Verify(10): data_out buffer given but "
                "'bytechk'==0??\n");
        return -1;
    }
    if (bytechk && (! (data_out && (data_out_len > 0)))) {
        fprintf(stderr, "Verify(10): invalid data_out buffer given but "
                "'bytechk'==1??\n");
        return -1;
    }
    if (dpo)
        vCmdBlk[1] |= 0x10;
    if (bytechk)
        vCmdBlk[1] |= 0x2;
    vCmdBlk[2] = (unsigned char)((lba >> 24) & 0xff);
    vCmdBlk[3] = (unsigned char)((lba >> 16) & 0xff);
    vCmdBlk[4] = (unsigned char)((lba >> 8) & 0xff);
    vCmdBlk[5] = (unsigned char)(lba & 0xff);
    vCmdBlk[7] = (unsigned char)((veri_len >> 8) & 0xff);
    vCmdBlk[8] = (unsigned char)(veri_len & 0xff);
    if (verbose) {
        fprintf(stderr, "    Verify(10) cdb: ");
        for (k = 0; k < VERIFY10_CMDLEN; ++k)
            fprintf(stderr, "%02x ", vCmdBlk[k]);
        fprintf(stderr, "\n");
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = VERIFY10_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = bytechk ? SG_DXFER_TO_DEV : SG_DXFER_NONE;
    io_hdr.dxfer_len = bytechk ? data_out_len : 0;
    io_hdr.dxferp = bytechk ? data_out : NULL;
    io_hdr.cmdp = vCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.pack_id = (int)lba;  /* aid debugging with progress indication */
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(stderr, "verify(10) SG_IO error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("VERIFY(10), continuing", &io_hdr);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        return 0;
    case SG_LIB_CAT_INVALID_OP:
    case SG_LIB_CAT_ILLEGAL_REQ:
        if (verbose > 1)
            sg_chk_n_print3("VERIFY(10) command problem", &io_hdr);
        return res;
    default:
        sg_chk_n_print3("VERIFY(10) command problem", &io_hdr);
        return -1;
    }
}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, num;
    long long ll;
    int dpo = 0;
    int bytechk = 0;
    long long count = 1;
    int bpc = 128;
    unsigned long long lba = 0;
    int verbose = 0;
    char device_name[256];
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:c:dhl:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
           bpc = sg_get_num(optarg);
           if (bpc < 1) {
                fprintf(stderr, "bad argument to '--bpc'\n");
                return 1;
            }
            break;
        case 'c':
           count = sg_get_llnum(optarg);
           if (count < 0) {
                fprintf(stderr, "bad argument to '--count'\n");
                return 1;
            }
            break;
        case 'd':
            dpo = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
           ll = sg_get_llnum(optarg);
           if (-1 == ll) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return 1;
            }
            lba = (unsigned long long)ll;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if ('\0' == device_name[0]) {
            strncpy(device_name, argv[optind], sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }
    if (bpc > 0xffff) {
        fprintf(stderr, "'bpc' cannot exceed 65535\n");
        usage();
        return 1;
    }
    if (lba > 0xffffffffLLU) {
        fprintf(stderr, "'lba' cannot exceed 32 bits\n");
        usage();
        return 1;
    }

    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", device_name);
        perror("");
        return 1;
    }

    for (; count > 0; count -= bpc, lba +=bpc) {
        num = (count > bpc) ? bpc : count;
        res = sg_ll_verify10(sg_fd, dpo, bytechk, (unsigned long)lba, num,
                             NULL, 0, verbose);
        if (0 != res) {
            if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, "Verify(10) command not supported\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "bad field in Verify(10) cdb\n");
            else
                fprintf(stderr, "Verify(10) failed near lba=%llu [0x%llx]\n",
                        lba, lba);
            break;
        }
    }
    if (count <= 0)
        ret = 0;

    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}
