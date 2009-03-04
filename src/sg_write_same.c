/*
 * Copyright (c) 2009 Douglas Gilbert.
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
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"

static char * version_str = "0.90 20090303";


#define MAX_XFER_LEN 10000


#define ME "sg_write_same: "

#define EBUFF_SZ 256

static struct option long_options[] = {
        {"16", no_argument, 0, 'S'},
        {"32", no_argument, 0, 'T'},
        {"help", no_argument, 0, 'h'},
        {"in", required_argument, 0, 'i'},
        {"lba", required_argument, 0, 'l'},
        {"lbdata", no_argument, 0, 'L'},
        {"num", required_argument, 0, 'n'},
        {"pbdata", no_argument, 0, 'P'},
        {"unmap", no_argument, 0, 'U'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wrprotect", required_argument, 0, 'w'},
        {"xfer_len", required_argument, 0, 'x'},
        {0, 0, 0, 0},
};

static void usage()
{
  fprintf(stderr, "Usage: "
          "sg_write_same [--16] [--32] [--grpnum=GP] [--help] [--in=IF]\n"
          "                     [--lba=LBA] [--lbdata] [--num=NUM] "
          "[--pbdata] [--unmap]\n"
          "                     [--verbose] [--version] [--wrprotect=WRP] "
          "[xferlen=LEN]\n"
          "                     DEVICE\n"
          "  where:\n"
          "    --16|-S              do WRITE SAME(16) (def: 10 unless "
          "'--unmap' given\n"
          "                         or LBA+NUM needs more than 32 bits)\n"
          "    --32|-T              do WRITE SAME(32) (def: 10 or 16)\n"
          "    --grpnum=GN|-g GN    GN is group number field (def: 0)\n"
          "    --help|-h            print out usage message\n"
          "    --in=IF|-i IF        IF is file to fetch one block of data "
          "from (use LEN\n"
          "                         bytes or whole file)\n"
          "    --lba=LBA|-l LBA     LBA is the logical block address to "
          "start (def: 0)\n"
          "    --lbdata|-L          set LBDATA bit\n"
          "    --num=NUM|-n NUM     NUM is number of logical blocks to write "
          "(def: 1)\n"
          "                         [Beware NUM==0 means rest of device]\n"
          "    --pbdata|-P          set PBDATA bit\n"
          "    --unmap|-U           set UNMAP bit\n"
          "    --verbose|-v         increase verbosity\n"
          "    --version|-V         print version string then exit\n"
          "    --wrprotect=WPR|-w WPR    WPR is the WRPROTECT field value "
          "(def: 0)\n"
          "    --xferlen=LEN|-x LEN    LEN is number of bytes from IF to "
          "send to\n"
          "                            DEVICE (def: IF file length)\n\n"
          "Performs a SCSI WRITE SAME (10, 16 or 32) command\n"
          );
}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, infd, offset;
    unsigned char * writeLongBuff = NULL;
    void * rawp = NULL;
    int xfer_len = 520;
    int cor_dis = 0;
    int pblock = 0;
    int wr_uncor = 0;
    int do_16 = 0;
    uint64_t llba = 0;
    int verbose = 0;
    int64_t ll;
    int got_stdin;
    const char * device_name = NULL;
    char file_name[256];
    char ebuff[EBUFF_SZ];
    const char * ten_or;
    int ret = 1;

    memset(file_name, 0, sizeof file_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "chi:l:pSvVwx:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            cor_dis = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            strncpy(file_name, optarg, sizeof(file_name));
            break;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            llba = (uint64_t)ll;
            break;
        case 'p':
            pblock = 1;
            break;
        case 'S':
            do_16 = 1;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        case 'w':
            wr_uncor = 1;
            break;
        case 'x':
            xfer_len = sg_get_num(optarg);
           if (-1 == xfer_len) {
                fprintf(stderr, "bad argument to '--xfer_len'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (wr_uncor)
        xfer_len = 0;
    else if (xfer_len >= MAX_XFER_LEN) {
        fprintf(stderr, "xfer_len (%d) is out of range ( < %d)\n",
                xfer_len, MAX_XFER_LEN);
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (wr_uncor) {
        if ('\0' != file_name[0])
            fprintf(stderr, ">>> warning: when '--wr_uncor' given "
                    "'-in=' is ignored\n");
    } else {
        if (NULL == (rawp = malloc(MAX_XFER_LEN))) {
            fprintf(stderr, ME "out of memory\n");
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        writeLongBuff = (unsigned char *)rawp;
        memset(rawp, 0xff, MAX_XFER_LEN);
        if (file_name[0]) {
            got_stdin = (0 == strcmp(file_name, "-")) ? 1 : 0;
            if (got_stdin)
                infd = 0;
            else {
                if ((infd = open(file_name, O_RDONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for reading", file_name);
                    perror(ebuff);
                    goto err_out;
                }
            }
            res = read(infd, writeLongBuff, xfer_len);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s",
                         file_name);
                perror(ebuff);
                if (! got_stdin)
                    close(infd);
                goto err_out;
            }
            if (res < xfer_len) {
                fprintf(stderr, "tried to read %d bytes from %s, got %d "
                        "bytes\n", xfer_len, file_name, res);
                fprintf(stderr, "pad with 0xff bytes and continue\n");
            }
            if (! got_stdin)
                close(infd);
        }
    }
    if (verbose)
        fprintf(stderr, ME "issue write long to device %s\n\t\txfer_len= %d "
                "(0x%x), lba=%" PRIu64 " (0x%" PRIx64 ")\n    cor_dis=%d, "
                "wr_uncor=%d, pblock=%d\n", device_name, xfer_len, xfer_len,
                llba, llba, cor_dis, wr_uncor, pblock);

    ten_or = do_16 ? "16" : "10";
    if (do_16)
        res = sg_ll_write_long16(sg_fd, cor_dis, wr_uncor, pblock, llba,
                                 writeLongBuff, xfer_len, &offset, 1, verbose);
    else
        res = sg_ll_write_long10(sg_fd, cor_dis, wr_uncor, pblock,
                                 (unsigned int)llba, writeLongBuff, xfer_len,
                                 &offset, 1, verbose);
    ret = res;
    switch (res) {
    case 0:
        break;
    case SG_LIB_CAT_NOT_READY:
        fprintf(stderr, "  SCSI WRITE LONG (%s) failed, device not ready\n",
                ten_or);
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:
        fprintf(stderr, "  SCSI WRITE LONG (%s), unit attention\n",
                ten_or);
        break;
    case SG_LIB_CAT_ABORTED_COMMAND:
        fprintf(stderr, "  SCSI WRITE LONG (%s), aborted command\n",
                ten_or);
        break;
    case SG_LIB_CAT_INVALID_OP:
        fprintf(stderr, "  SCSI WRITE LONG (%s) command not supported\n",
                ten_or);
        break;
    case SG_LIB_CAT_ILLEGAL_REQ:
        fprintf(stderr, "  SCSI WRITE LONG (%s) command, bad field in cdb\n",
                ten_or);
        break;
    case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:
        fprintf(stderr, "<<< device indicates 'xfer_len' should be %d "
                ">>>\n", xfer_len - offset);
        break;
    default:
        fprintf(stderr, "  SCSI WRITE LONG (%s) command error\n", ten_or);
        break;
    }

err_out:
    if (rawp)
        free(rawp);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
