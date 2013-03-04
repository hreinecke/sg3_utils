#define _XOPEN_SOURCE 500
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*
*  Copyright (c) 2012-2013, Kaminario Technologies LTD
*  All rights reserved.
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions are met:
*    * Redistributions of source code must retain the above copyright
*        notice, this list of conditions and the following disclaimer.
*    * Redistributions in binary form must reproduce the above copyright
*        notice, this list of conditions and the following disclaimer in the
*        documentation and/or other materials provided with the distribution.
*    * Neither the name of the <organization> nor the
*        names of its contributors may be used to endorse or promote products
*        derived from this software without specific prior written permission.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
*  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
*  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
*  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
*  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
*  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
*  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
*  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
*  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*  This command performs a SCSI COMPARE AND WRITE on the given lba.
*
*/

static const char * version_str = "1.02 20130117";

#define DEF_BLOCK_SIZE 512
#define DEF_NUM_BLOCKS (1)
#define DEF_BLOCKS_PER_TRANSFER 8
#define DEF_TIMEOUT_SECS 60

#define COMPARE_AND_WRITE_OPCODE (0x89)
#define COMPARE_AND_WRITE_CDB_SIZE (16)

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */

#define ME "sg_compare_and_write: "

static struct option long_options[] = {
        {"dpo", no_argument, 0, 'd'},
        {"fua", no_argument, 0, 'f'},
        {"fua_nv", no_argument, 0, 'F'},
        {"group", required_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"in", required_argument, 0, 'i'},
        {"lba", required_argument, 0, 'l'},
        {"num", required_argument, 0, 'n'},
        {"timeout", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wrprotect", required_argument, 0, 'w'},
        {"xferlen", required_argument, 0, 'x'},
        {0, 0, 0, 0},
};

struct opts_t {
        char ifilename[256];
        uint64_t lba;
        int numblocks;
        int verbose;
        int timeout;
        int xfer_len;
        const char * device_name;
        struct caw_flags {
                int dpo;
                int fua;
                int fua_nv;
                int group;
                int wrprotect;
        } flags;
} opts;

static void
usage()
{
        fprintf(stderr, "Usage: "
                "sg_compare_and_write [--dpo] [--fua] [--fua_nv] "
                "[--group=GN] [--help]\n"
                "                            --in=IF --lba=LBA [--num=NUM] "
                "[--timeout=TO]\n"
                "                            [--verbose] [--version] "
                "[--wrpotect=w]\n"
                "                            [--xferlen=LEN] DEVICE\n"
                "  where:\n"
                "    --dpo|-d            set the dpo bit in cdb (def: "
                "clear)\n"
                "    --fua|-f            set the fua bit in cdb (def: "
                "clear)\n"
                "    --fua_nv|-F         set the fua_nv bit in cdb (def: "
                "clear)\n"
                "    --group=GN|-g GN    GN is GROUP NUMBER to set in "
                "cdb (def: 0)\n"
                "    --help|-h           print out usage message\n"
                "    --in=IF|-i IF       IF is input file, read the compare "
                "and write buffer\n"
                "                        from this file\n"
                "    --lba=LBA|-l LBA    LBA of the first block of the "
                "compare and write\n"
                "    --num=NUM|-n NUM    number of blocks to "
                "compare/write (def: 1)\n"
                "    --timeout=TO|-t TO    timeout for the command "
                "(def: 60 secs)\n"
                "    --verbose|-v        increase verbosity (use '-vv' for "
                "more)\n"
                "    --version|-V        print version string then exit\n"
                "    --wrprotect=WP|-w WP    write protect information "
                "(def: 0)\n"
                "    --xferlen=LEN|-x LEN    number of bytes to transfer "
                "(def: 1024)\n"
                "                            default is "
                "(NUM * default_block_size * 2)\n"
                "\n"
                "Performs a SCSI COMPARE AND WRITE operation.\n");
}

static int
parse_args(int argc, char* argv[])
{
        int c;
        int lba_given = 0;
        int if_given = 0;
        int64_t ll;

        memset(&opts, 0, sizeof(opts));
        opts.numblocks = DEF_NUM_BLOCKS;
        /* COMPARE AND WRITE defines 2*buffers compare + write */
        opts.xfer_len = 2*DEF_NUM_BLOCKS*DEF_BLOCK_SIZE;
        opts.timeout = DEF_TIMEOUT_SECS;
        opts.device_name = NULL;
        while (1) {
                int option_index = 0;

                c = getopt_long(argc, argv, "dfFg:hi:l:n:t:vVw:x:",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'd':
                        opts.flags.dpo = 1;
                        break;
                case 'F':
                        opts.flags.fua_nv = 1;
                        break;
                case 'f':
                        opts.flags.fua = 1;
                        break;
                case 'g':
                        opts.flags.group = sg_get_num(optarg);
                        if ((opts.flags.group < 0) ||
                            (opts.flags.group > 31))  {
                                fprintf(stderr, "argument to '--group' "
                                        "expected to be 0 to 31\n");
                                goto out_err_no_usage;
                        }
                        break;
                case 'h':
                case '?':
                        usage();
                        exit(0);
                case 'i':
                        strncpy(opts.ifilename, optarg,
                                sizeof(opts.ifilename));
                        if_given = 1;
                        break;
                case 'l':
                        ll = sg_get_llnum(optarg);
                        if (-1 == ll) {
                                fprintf(stderr, "bad argument to '--lba'\n");
                                goto out_err_no_usage;
                        }
                        opts.lba = (uint64_t)ll;
                        lba_given = 1;
                        break;
                case 'n':
                        opts.numblocks = sg_get_num(optarg);
                        if (opts.numblocks < 0)  {
                                fprintf(stderr, "bad argument to '--num'\n");
                                goto out_err_no_usage;
                        }
                        break;
                case 't':
                        opts.timeout = sg_get_num(optarg);
                        if (opts.timeout < 0)  {
                                fprintf(stderr, "bad argument to "
                                        "'--timeout'\n");
                                goto out_err_no_usage;
                        }
                        break;
                case 'v':
                        ++opts.verbose;
                        break;
                case 'V':
                        fprintf(stderr, ME "version: %s\n", version_str);
                        exit(0);
                case 'w':
                        opts.flags.wrprotect = sg_get_num(optarg);
                        if (opts.flags.wrprotect >> 3) {
                                fprintf(stderr, "bad argument to "
                                        "'--wrprotect' not in range 0-7\n");
                                goto out_err_no_usage;
                        }
                        break;
                case 'x':
                        opts.xfer_len = sg_get_num(optarg);
                        if (opts.xfer_len < 0) {
                                fprintf(stderr, "bad argument to "
                                        "'--xferlen'\n");
                                goto out_err_no_usage;
                        }
                        break;
                default:
                        fprintf(stderr, "unrecognised option code 0x%x ??\n",
                                c);
                        goto out_err;
                }
        }
        if (optind < argc) {
                if (NULL == opts.device_name) {
                        opts.device_name = argv[optind];
                        ++optind;
                }
                if (optind < argc) {
                        for (; optind < argc; ++optind)
                                fprintf(stderr, "Unexpected extra argument: "
                                        "%s\n", argv[optind]);
                        goto out_err;
                }
        }
        if (NULL == opts.device_name) {
                fprintf(stderr, "missing device name!\n");
                goto out_err;
        }
        if (!if_given) {
                fprintf(stderr, "missing input file\n");
                goto out_err;
        }
        if (!lba_given) {
                fprintf(stderr, "missing lba\n");
                goto out_err;
        }
        return 0;

out_err:
        usage();

out_err_no_usage:
        exit(1);
}

#define FLAG_FUA        (0x8)
#define FLAG_FUA_NV     (0x2)
#define FLAG_DPO        (0x10)
#define WRPROTECT_MASK  (0x7)
#define WRPROTECT_SHIFT (5)

static int
sg_build_scsi_cdb(unsigned char * cdbp, unsigned int blocks,
                  int64_t start_block, struct caw_flags flags)
{
        memset(cdbp, 0, COMPARE_AND_WRITE_CDB_SIZE);
        cdbp[0] = COMPARE_AND_WRITE_OPCODE;
        cdbp[1] = (flags.wrprotect && WRPROTECT_MASK) << WRPROTECT_SHIFT;
        if (flags.dpo)
                cdbp[1] |= FLAG_DPO;
        if (flags.fua)
                cdbp[1] |= FLAG_FUA;
        if (flags.fua_nv)
                cdbp[1] |= FLAG_FUA_NV;
        cdbp[2] = (unsigned char)((start_block >> 56) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 48) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 40) & 0xff);
        cdbp[5] = (unsigned char)((start_block >> 32) & 0xff);
        cdbp[6] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[7] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[8] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[9] = (unsigned char)(start_block & 0xff);
        /* cdbp[10-12] are reserved */
        cdbp[13] = (unsigned char)(blocks & 0xff);
        cdbp[14] = (unsigned char)(flags.group & 0x1f);
        return 0;
}

static int
sg_compare_and_write(int sg_fd, unsigned char * buff, int blocks,
                     int64_t lba, int xfer_len, struct caw_flags flags,
                     int verbose)
{
        int k, sense_cat;
        unsigned char cawCmd[COMPARE_AND_WRITE_CDB_SIZE];
        unsigned char senseBuff[SENSE_BUFF_LEN];
        struct sg_pt_base * ptvp;
        int res, ret;

        if (sg_build_scsi_cdb(cawCmd, blocks, lba, flags)) {
                fprintf(stderr, ME "bad cdb build, lba=0x%"PRIx64", "
                        "blocks=%d\n", lba, blocks);
                return -1;
        }
        ptvp = construct_scsi_pt_obj();
        if (NULL == ptvp) {
                fprintf(sg_warnings_strm, "Could not construct scsit_pt_obj, "
                        "out of " "memory\n");
                return -1;
        }

        set_scsi_pt_cdb(ptvp, cawCmd, COMPARE_AND_WRITE_CDB_SIZE);
        set_scsi_pt_sense(ptvp, senseBuff, sizeof(senseBuff));
        set_scsi_pt_data_out(ptvp, buff, xfer_len);
        if (verbose > 1) {
                fprintf(stderr, "    Compare and write cdb: ");
                for (k = 0; k < COMPARE_AND_WRITE_CDB_SIZE; ++k)
                        fprintf(stderr, "%02x ", cawCmd[k]);
                fprintf(stderr, "\n");
        }
        if ((verbose > 2) && (xfer_len > 0)) {
                fprintf(stderr, "    Data-out buffer contents:\n");
                dStrHex((const char *)buff, xfer_len, 1);
        }
        res = do_scsi_pt(ptvp, sg_fd, DEF_TIMEOUT_SECS, verbose);
        ret = sg_cmds_process_resp(ptvp, "COMPARE AND WRITE", res, 0,
                                   senseBuff, 1 /* noisy */, verbose,
                                   &sense_cat);
        if (-1 == ret)
                ;
        else if (-2 == ret) {
                switch (sense_cat) {
                case SG_LIB_CAT_NOT_READY:
                case SG_LIB_CAT_INVALID_OP:
                case SG_LIB_CAT_UNIT_ATTENTION:
                case SG_LIB_CAT_ILLEGAL_REQ:
                case SG_LIB_CAT_ABORTED_COMMAND:
                        ret = sense_cat;
                        break;
                case SG_LIB_CAT_RECOVERED:
                case SG_LIB_CAT_NO_SENSE:
                        ret = 0;
                        break;
                case SG_LIB_CAT_MEDIUM_HARD:
                        {
                                int valid, slen;
                                uint64_t ull = 0;

                                slen = get_scsi_pt_sense_len(ptvp);
                                valid = sg_get_sense_info_fld(senseBuff, slen,
                                                              &ull);
                                if (valid)
                                        fprintf(stderr, "Medium or hardware "
                                                "error starting at lba=%"
                                                PRIu64" [0x%"PRIx64"]\n", ull,
                                                ull);
                        }
                        ret = sense_cat;
                        break;
                default:
                        ret = -1;
                        break;
                }
        } else
                ret = 0;

        destruct_scsi_pt_obj(ptvp);
        return ret;
}


static int
open_if(const char * inf)
{
        int fd = open(inf, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, ME "open error: %s: %s\n", inf,
                        safe_strerror(-fd));
                return -1*SG_LIB_FILE_ERROR;
        }
        return fd;
}

static int
open_of(const char * outf, int verbose)
{
        int sg_fd = sg_cmds_open_device(outf, 0 /* rw */, verbose);
        if (sg_fd < 0) {
                fprintf(stderr, ME "open error: %s: %s\n", outf,
                        safe_strerror(-sg_fd));
                return -1*SG_LIB_FILE_ERROR;
        }

        return sg_fd;
}

#define STR_SZ 1024
#define INF_SZ 512

int
main(int argc, char * argv[])
{
        int res;
        int infd = 0;
        int outfd = 0;
        unsigned char * wrkBuff = NULL;

        res = parse_args(argc, argv);
        if (res != 0) {
                fprintf(stderr, "Failed parsing args\n");
                goto out;
        }

        if (opts.verbose)
                fprintf(stderr, "Running COMPARE AND WRITE command with the "
                        "following options:\n  in=%s device=%s lba=0x%"
                        PRIx64 " num_blocks=%d xfer_len=%d timeout=%d\n",
                        opts.ifilename, opts.device_name, opts.lba,
                        opts.numblocks, opts.xfer_len, opts.timeout);

        infd = open_if(opts.ifilename);
        if (infd <=0) {
                res = -1*infd;
                goto out;
        }

        outfd = open_of(opts.device_name, opts.verbose);
        if (outfd <=0) {
                res = -1*outfd;
                goto out;
        }

        wrkBuff = (unsigned char *)malloc(opts.xfer_len);
        if (0 == wrkBuff) {
                fprintf(stderr, "Not enough user memory\n");
                res = SG_LIB_CAT_OTHER;
                goto out;
        }

        res = read(infd, wrkBuff, opts.xfer_len);
        if (res < 0) {
                fprintf(stderr, "Could not read from %s", opts.ifilename);
                goto out;
        } else if (res < opts.xfer_len) {
                fprintf(stderr, "Read only %d bytes (expected %d) from  %s\n",
                        res, opts.xfer_len, opts.ifilename);
                goto out;
        }
        res = sg_compare_and_write(outfd, wrkBuff, opts.numblocks, opts.lba,
                opts.xfer_len, opts.flags, opts.verbose);

out:
        if (0 != res) {
                switch (res) {
                case SG_LIB_CAT_MEDIUM_HARD:
                        fprintf(stderr, ME "SCSI COMPARE AND WRITE "
                                "medium/hardware error\n");
                        break;
                case SG_LIB_CAT_NOT_READY:
                        fprintf(stderr, ME "device not compare_and_writey\n");
                        break;
                case SG_LIB_CAT_UNIT_ATTENTION:
                        fprintf(stderr, ME "SCSI COMPARE AND WRITE unit "
                                "attention\n");
                        break;
                case SG_LIB_CAT_ABORTED_COMMAND:
                        fprintf(stderr, ME "SCSI READ aborted command\n");
                        break;
                default:
                        res = SG_LIB_CAT_OTHER;
                        fprintf(stderr, ME "SCSI COMPARE AND WRITE failed\n");
                        break;
                }
        }

        if (wrkBuff)
                free(wrkBuff);
        if (infd > 0)
                close(infd);
        if (outfd > 0)
                close(outfd);
        return res;
}
