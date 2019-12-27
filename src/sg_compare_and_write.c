/*
*  Copyright (c) 2012-2019, Kaminario Technologies LTD
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
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This command performs a SCSI COMPARE AND WRITE. See SBC-3 at
 * http://www.t10.org
 *
 */

#ifndef __sun
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.27 20191220";

#define DEF_BLOCK_SIZE 512
#define DEF_NUM_BLOCKS (1)
#define DEF_BLOCKS_PER_TRANSFER 8
#define DEF_TIMEOUT_SECS 60

#define COMPARE_AND_WRITE_OPCODE (0x89)
#define COMPARE_AND_WRITE_CDB_SIZE (16)

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */

#define ME "sg_compare_and_write: "

static struct option long_options[] = {
        {"dpo", no_argument, 0, 'd'},
        {"fua", no_argument, 0, 'f'},
        {"fua_nv", no_argument, 0, 'F'},
        {"fua-nv", no_argument, 0, 'F'},
        {"group", required_argument, 0, 'g'},
        {"grpnum", required_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"in", required_argument, 0, 'i'},
        {"inc", required_argument, 0, 'C'},
        {"inw", required_argument, 0, 'D'},
        {"lba", required_argument, 0, 'l'},
        {"num", required_argument, 0, 'n'},
        {"quiet", no_argument, 0, 'q'},
        {"timeout", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wrprotect", required_argument, 0, 'w'},
        {"xferlen", required_argument, 0, 'x'},
        {0, 0, 0, 0},
};

struct caw_flags {
        bool dpo;
        bool fua;
        bool fua_nv;
        int group;
        int wrprotect;
};

struct opts_t {
        bool quiet;
        bool verbose_given;
        bool version_given;
        bool wfn_given;
        int numblocks;
        int verbose;
        int timeout;
        int xfer_len;
        uint64_t lba;
        const char * ifn;
        const char * wfn;
        const char * device_name;
        struct caw_flags flags;
};


static void
usage()
{
        pr2serr("Usage: sg_compare_and_write [--dpo] [--fua] [--fua_nv] "
                "[--grpnum=GN] [--help]\n"
                "                            --in=IF|--inc=IF [--inw=WF] "
                "--lba=LBA "
                "[--num=NUM]\n"
                "                            [--quiet] [--timeout=TO] "
                "[--verbose] [--version]\n"
                "                            [--wrprotect=WP] [--xferlen=LEN] "
                "DEVICE\n"
                "  where:\n"
                "    --dpo|-d            set the dpo bit in cdb (def: "
                "clear)\n"
                "    --fua|-f            set the fua bit in cdb (def: "
                "clear)\n"
                "    --fua_nv|-F         set the fua_nv bit in cdb (def: "
                "clear)\n"
                "    --grpnum=GN|-g GN    GN is GROUP NUMBER to set in "
                "cdb (def: 0)\n"
                "    --help|-h           print out usage message\n"
                "    --in=IF|-i IF       IF is a file containing a compare "
                "buffer and\n"
                "                        optionally a write buffer (when "
                "--inw=WF is\n"
                "                        not given)\n"
                "    --inc=IF|-C IF      The same as the --in option\n"
                "    --inw=WF|-D WF      WF is a file containing a write "
                "buffer\n"
                "    --lba=LBA|-l LBA    LBA of the first block to compare "
                "and write\n"
                "    --num=NUM|-n NUM    number of blocks to "
                "compare/write (def: 1)\n"
                "    --quiet|-q          suppress MISCOMPARE report to "
                "stderr,\n"
                "                        still sets exit status of 14\n"
                "    --timeout=TO|-t TO    timeout for the command "
                "(def: 60 secs)\n"
                "    --verbose|-v        increase verbosity (use '-vv' for "
                "more)\n"
                "    --version|-V        print version string then exit\n"
                "    --wrprotect=WP|-w WP    write protect information "
                "(def: 0)\n"
                "    --xferlen=LEN|-x LEN    number of bytes to transfer. "
                "Default is\n"
                "                            (2 * NUM * 512) or 1024 when "
                "NUM is 1\n"
                "\n"
                "Performs a SCSI COMPARE AND WRITE operation. Sends a double "
                "size\nbuffer, the first half is used to compare what is at "
                "LBA for NUM\nblocks. If and only if the comparison is "
                "equal, then the second\nhalf of the buffer is written to "
                "LBA for NUM blocks.\n");
}

static int
parse_args(int argc, char* argv[], struct opts_t * op)
{
        bool lba_given = false;
        bool if_given = false;
        int c;
        int64_t ll;

        op->numblocks = DEF_NUM_BLOCKS;
        /* COMPARE AND WRITE defines 2*buffers compare + write */
        op->xfer_len = 0;
        op->timeout = DEF_TIMEOUT_SECS;
        op->device_name = NULL;
        while (1) {
                int option_index = 0;

                c = getopt_long(argc, argv, "C:dD:fFg:hi:l:n:qt:vVw:x:",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'C':
                case 'i':
                        op->ifn = optarg;
                        if_given = true;
                        break;
                case 'd':
                        op->flags.dpo = true;
                        break;
                case 'D':
                        op->wfn = optarg;
                        op->wfn_given = true;
                        break;
                case 'F':
                        op->flags.fua_nv = true;
                        break;
                case 'f':
                        op->flags.fua = true;
                        break;
                case 'g':
                        op->flags.group = sg_get_num(optarg);
                        if ((op->flags.group < 0) ||
                            (op->flags.group > 63))  {
                                pr2serr("argument to '--grpnum=' expected to "
                                        "be 0 to 63\n");
                                goto out_err_no_usage;
                        }
                        break;
                case 'h':
                case '?':
                        usage();
                        exit(0);
                case 'l':
                        ll = sg_get_llnum(optarg);
                        if (-1 == ll) {
                                pr2serr("bad argument to '--lba'\n");
                                goto out_err_no_usage;
                        }
                        op->lba = (uint64_t)ll;
                        lba_given = true;
                        break;
                case 'n':
                        op->numblocks = sg_get_num(optarg);
                        if ((op->numblocks < 0) || (op->numblocks > 255))  {
                                pr2serr("bad argument to '--num', expect 0 "
                                        "to 255\n");
                                goto out_err_no_usage;
                        }
                        break;
                case 'q':
                        op->quiet = true;
                        break;
                case 't':
                        op->timeout = sg_get_num(optarg);
                        if (op->timeout < 0)  {
                                pr2serr("bad argument to '--timeout'\n");
                                goto out_err_no_usage;
                        }
                        break;
                case 'v':
                        op->verbose_given = true;
                        ++op->verbose;
                        break;
                case 'V':
                        op->version_given = true;
                        break;
                case 'w':
                        op->flags.wrprotect = sg_get_num(optarg);
                        if (op->flags.wrprotect >> 3) {
                                pr2serr("bad argument to '--wrprotect' not "
                                        "in range 0-7\n");
                                goto out_err_no_usage;
                        }
                        break;
                case 'x':
                        op->xfer_len = sg_get_num(optarg);
                        if (op->xfer_len < 0) {
                                pr2serr("bad argument to '--xferlen'\n");
                                goto out_err_no_usage;
                        }
                        break;
                default:
                        pr2serr("unrecognised option code 0x%x ??\n", c);
                        goto out_err;
                }
        }
        if (optind < argc) {
                if (NULL == op->device_name) {
                        op->device_name = argv[optind];
                        ++optind;
                }
                if (optind < argc) {
                        for (; optind < argc; ++optind)
                                pr2serr("Unexpected extra argument: %s\n",
                                        argv[optind]);
                        goto out_err;
                }
        }
        if (NULL == op->device_name) {
                pr2serr("missing device name!\n");
                goto out_err;
        }
        if (! if_given) {
                pr2serr("missing input file\n");
                goto out_err;
        }
        if (! lba_given) {
                pr2serr("missing lba\n");
                goto out_err;
        }
        if (0 == op->xfer_len)
            op->xfer_len = 2 * op->numblocks * DEF_BLOCK_SIZE;
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
sg_build_scsi_cdb(uint8_t * cdbp, unsigned int blocks,
                  int64_t start_block, struct caw_flags flags)
{
        memset(cdbp, 0, COMPARE_AND_WRITE_CDB_SIZE);
        cdbp[0] = COMPARE_AND_WRITE_OPCODE;
        cdbp[1] = (flags.wrprotect & WRPROTECT_MASK) << WRPROTECT_SHIFT;
        if (flags.dpo)
                cdbp[1] |= FLAG_DPO;
        if (flags.fua)
                cdbp[1] |= FLAG_FUA;
        if (flags.fua_nv)
                cdbp[1] |= FLAG_FUA_NV;
        sg_put_unaligned_be64((uint64_t)start_block, cdbp + 2);
        /* cdbp[10-12] are reserved */
        cdbp[13] = (uint8_t)(blocks & 0xff);
        cdbp[14] = (uint8_t)(flags.group & 0x1f);
        return 0;
}

/* Returns 0 for success, SG_LIB_CAT_MISCOMPARE if compare fails,
 * various other SG_LIB_CAT_*, otherwise -1 . */
static int
sg_ll_compare_and_write(int sg_fd, uint8_t * buff, int blocks,
                        int64_t lba, int xfer_len, struct caw_flags flags,
                        bool noisy, int verbose)
{
        bool valid;
        int sense_cat, slen, res, ret;
        uint64_t ull = 0;
        struct sg_pt_base * ptvp;
        uint8_t cawCmd[COMPARE_AND_WRITE_CDB_SIZE];
        uint8_t sense_b[SENSE_BUFF_LEN];

        if (sg_build_scsi_cdb(cawCmd, blocks, lba, flags)) {
                pr2serr(ME "bad cdb build, lba=0x%" PRIx64 ", blocks=%d\n",
                        lba, blocks);
                return -1;
        }
        ptvp = construct_scsi_pt_obj();
        if (NULL == ptvp) {
                pr2serr("Could not construct scsit_pt_obj, out of memory\n");
                return -1;
        }

        set_scsi_pt_cdb(ptvp, cawCmd, COMPARE_AND_WRITE_CDB_SIZE);
        set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
        set_scsi_pt_data_out(ptvp, buff, xfer_len);
        if (verbose > 1) {
                char b[128];

                pr2serr("    Compare and write cdb: %s\n",
                sg_get_command_str(cawCmd, COMPARE_AND_WRITE_CDB_SIZE, false,
                                   sizeof(b), b));
        }
        if ((verbose > 2) && (xfer_len > 0)) {
                pr2serr("    Data-out buffer contents:\n");
                hex2stderr(buff, xfer_len, 1);
        }
        res = do_scsi_pt(ptvp, sg_fd, DEF_TIMEOUT_SECS, verbose);
        ret = sg_cmds_process_resp(ptvp, "COMPARE AND WRITE", res,
                                   noisy, verbose, &sense_cat);
        if (-1 == ret)
                ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
        else if (-2 == ret) {
                switch (sense_cat) {
                case SG_LIB_CAT_RECOVERED:
                case SG_LIB_CAT_NO_SENSE:
                        ret = 0;
                        break;
                case SG_LIB_CAT_MEDIUM_HARD:
                        slen = get_scsi_pt_sense_len(ptvp);
                        valid = sg_get_sense_info_fld(sense_b, slen,
                                                      &ull);
                        if (valid)
                                pr2serr("Medium or hardware error starting "
                                        "at lba=%" PRIu64 " [0x%" PRIx64
                                        "]\n", ull, ull);
                        else
                                pr2serr("Medium or hardware error\n");
                        ret = sense_cat;
                        break;
                case SG_LIB_CAT_MISCOMPARE:
                        ret = sense_cat;
                        if (! (noisy || verbose))
                                break;
                        slen = get_scsi_pt_sense_len(ptvp);
                        valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                        if (valid)
                                pr2serr("Miscompare at byte offset: %" PRIu64
                                        " [0x%" PRIx64 "]\n", ull, ull);
                        else
                                pr2serr("Miscompare reported\n");
                        break;
                default:
                        ret = sense_cat;
                        break;
                }
        } else
                ret = 0;

        destruct_scsi_pt_obj(ptvp);
        return ret;
}

static int
open_if(const char * fn, bool got_stdin)
{
        int fd;

        if (got_stdin)
                fd = STDIN_FILENO;
        else {
                fd = open(fn, O_RDONLY);
                if (fd < 0) {
                        pr2serr(ME "open error: %s: %s\n", fn,
                                safe_strerror(errno));
                        return -SG_LIB_FILE_ERROR;
                }
        }
        if (sg_set_binary_mode(fd) < 0) {
                perror("sg_set_binary_mode");
                return -SG_LIB_FILE_ERROR;
        }
        return fd;
}

static int
open_dev(const char * outf, int verbose)
{
        int sg_fd = sg_cmds_open_device(outf, false /* rw */, verbose);

        if ((sg_fd < 0) && verbose)
                pr2serr(ME "open error: %s: %s\n", outf,
                        safe_strerror(-sg_fd));
        return sg_fd;
}


int
main(int argc, char * argv[])
{
        bool ifn_stdin;
        int res, half_xlen, vb;
        int infd = -1;
        int wfd = -1;
        int devfd = -1;
        uint8_t * wrkBuff = NULL;
        uint8_t * free_wrkBuff = NULL;
        struct opts_t * op;
        struct opts_t opts;

        op = &opts;
        memset(op, 0, sizeof(opts));
        res = parse_args(argc, argv, op);
        if (res != 0) {
                pr2serr("Failed parsing args\n");
                goto out;
        }

#ifdef DEBUG
        pr2serr("In DEBUG mode, ");
        if (op->verbose_given && op->version_given) {
                pr2serr("but override: '-vV' given, zero verbose and "
                        "continue\n");
                op->verbose_given = false;
                op->version_given = false;
                op->verbose = 0;
        } else if (! op->verbose_given) {
                pr2serr("set '-vv'\n");
                op->verbose = 2;
        } else
                pr2serr("keep verbose=%d\n", op->verbose);
#else
        if (op->verbose_given && op->version_given)
                pr2serr("Not in DEBUG mode, so '-vV' has no special "
                        "action\n");
#endif
        if (op->version_given) {
                pr2serr(ME "version: %s\n", version_str);
                return 0;
        }
        vb = op->verbose;

        if (vb) {
                pr2serr("Running COMPARE AND WRITE command with the "
                        "following options:\n  in=%s ", op->ifn);
                if (op->wfn_given)
                        pr2serr("inw=%s ", op->wfn);
                pr2serr("device=%s\n  lba=0x%" PRIx64 " num_blocks=%d "
                        "xfer_len=%d timeout=%d\n", op->device_name,
                        op->lba, op->numblocks, op->xfer_len, op->timeout);
        }
        ifn_stdin = ((1 == strlen(op->ifn)) && ('-' == op->ifn[0]));
        infd = open_if(op->ifn, ifn_stdin);
        if (infd < 0) {
                res = -infd;
                goto out;
        }
        if (op->wfn_given) {
                if ((1 == strlen(op->wfn)) && ('-' == op->wfn[0])) {
                        pr2serr(ME "don't allow stdin for write file\n");
                        res = SG_LIB_FILE_ERROR;
                        goto out;
                }
                wfd = open_if(op->wfn, false);
                if (wfd < 0) {
                        res = -wfd;
                        goto out;
                }
        }

        devfd = open_dev(op->device_name, vb);
        if (devfd < 0) {
                res = sg_convert_errno(-devfd);
                goto out;
        }

        wrkBuff = (uint8_t *)sg_memalign(op->xfer_len, 0, &free_wrkBuff,
                                         vb > 3);
        if (NULL == wrkBuff) {
                pr2serr("Not enough user memory\n");
                res = sg_convert_errno(ENOMEM);
                goto out;
        }

        if (op->wfn_given) {
                half_xlen = op->xfer_len / 2;
                res = read(infd, wrkBuff, half_xlen);
                if (res < 0) {
                        pr2serr("Could not read from %s", op->ifn);
                        goto out;
                } else if (res < half_xlen) {
                        pr2serr("Read only %d bytes (expected %d) from %s\n",
                                res, half_xlen, op->ifn);
                        goto out;
                }
                res = read(wfd, wrkBuff + half_xlen, half_xlen);
                if (res < 0) {
                        pr2serr("Could not read from %s", op->wfn);
                        goto out;
                } else if (res < half_xlen) {
                        pr2serr("Read only %d bytes (expected %d) from %s\n",
                                res, half_xlen, op->wfn);
                        goto out;
                }
        } else {
                res = read(infd, wrkBuff, op->xfer_len);
                if (res < 0) {
                        pr2serr("Could not read from %s", op->ifn);
                        goto out;
                } else if (res < op->xfer_len) {
                        pr2serr("Read only %d bytes (expected %d) from %s\n",
                                res, op->xfer_len, op->ifn);
                        goto out;
                }
        }
        res = sg_ll_compare_and_write(devfd, wrkBuff, op->numblocks, op->lba,
                                      op->xfer_len, op->flags, ! op->quiet,
                                      vb);
        if (0 != res) {
                char b[80];

                switch (res) {
                case SG_LIB_CAT_MEDIUM_HARD:
                case SG_LIB_CAT_MISCOMPARE:
                case SG_LIB_FILE_ERROR:
                        break;  /* already reported */
                default:
                        sg_get_category_sense_str(res, sizeof(b), b, vb);
                        pr2serr(ME "SCSI COMPARE AND WRITE: %s\n", b);
                        break;
                }
        }
out:
        if (free_wrkBuff)
                free(free_wrkBuff);
        if ((infd >= 0) && (! ifn_stdin))
                close(infd);
        if (wfd >= 0)
                close(wfd);
        if (devfd >= 0)
                close(devfd);
        if (0 == op->verbose) {
                if (! sg_if_can2stderr("sg_compare_and_write failed: ", res))
                        pr2serr("Some error occurred, try again with '-v' "
                                "or '-vv' for more information\n");
        }
        return res;
}
