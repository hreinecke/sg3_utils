/*
 * Copyright (c) 2014-2016 Douglas Gilbert
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * This program issues the SCSI command WRITE AND VERIFY to a given SCSI
 * device. It sends the command with the logical block address passed as the
 * LBA argument, for the given number of blocks. The number of bytes sent is
 * supplied separately, either by the size of the given file (IF) or
 * explicitly with ILEN.
 *
 * This code was contributed by Bruno Goncalves
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.09 20160531";


#define ME "sg_write_verify: "

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */

#define WRITE_VERIFY10_CMD      0x2e
#define WRITE_VERIFY10_CMDLEN   10
#define WRITE_VERIFY16_CMD      0x8e
#define WRITE_VERIFY16_CMDLEN   16

#define WRPROTECT_MASK  (0x7)
#define WRPROTECT_SHIFT (5)

#define DEF_TIMEOUT_SECS 60


static struct option long_options[] = {
    {"16", no_argument, 0, 'S'},
    {"bytchk", required_argument, 0, 'b'},
    {"dpo", no_argument, 0, 'd'},
    {"group", required_argument, 0, 'g'},
    {"help", no_argument, 0, 'h'},
    {"ilen", required_argument, 0, 'I'},
    {"in", required_argument, 0, 'i'},
    {"lba", required_argument, 0, 'l'},
    {"num", required_argument, 0, 'n'},
    {"repeat", no_argument, 0, 'R'},
    {"timeout", required_argument, 0, 't'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"wrprotect", required_argument, 0, 'w'},
    {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_write_verify [--16] [--bytchk=BC] [--dpo] [--group=GN] "
            "[--help]\n"
            "                       [--ilen=IL] [--in=IF] --lba=LBA "
            "[--num=NUM]\n"
            "                       [--repeat] [--timeout=TO] [--verbose] "
            "[--version]\n"
            "                       [--wrprotect=WPR] DEVICE\n"
            "  where:\n"
            "    --16|-S              do WRITE AND VERIFY(16) (default: 10)\n"
            "    --bytchk=BC|-b BC    set BYTCHK field (default: 0)\n"
            "    --dpo|-d             set DPO bit (default: 0)\n"
            "    --group=GN|-g GN     GN is group number (default: 0)\n"
            "    --help|-h            print out usage message\n"
            "    --ilen=IL| -I IL     input (file) length in bytes, becomes "
            "data-out\n"
            "                         buffer length (def: deduced from IF "
            "size)\n"
            "    --in=IF|-i IF        IF is a file containing the data to "
            "be written\n"
            "    --lba=LBA|-l LBA     LBA of the first block to write "
            "and verify;\n"
            "                         no default, must be given\n"
            "    --num=NUM|-n NUM     logical blocks to write and verify "
            "(def: 1)\n"
            "    --repeat|-R          while IF still has data to read, send "
            "another\n"
            "                         command, bumping LBA with up to NUM "
            "blocks again\n"
            "    --timeout=TO|-t TO   command timeout in seconds (def: 60)\n"
            "    --verbose|-v         increase verbosity\n"
            "    --version|-V         print version string then exit\n"
            "    --wrprotect|-w WPR   WPR is the WRPROTECT field value "
            "(def: 0)\n\n"
            "Performs a SCSI WRITE AND VERIFY (10 or 16) command on DEVICE, "
            "startings\nat LBA for NUM logical blocks. More commands "
            "performed only if '--repeat'\noption given. Data to be written "
            "is fetched from the IF file.\n"
         );
}

/* Invokes a SCSI WRITE AND VERIFY according with CDB. Returns 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
run_scsi_transaction(int sg_fd, const unsigned char *cdbp, int cdb_len,
                     unsigned char *dop, int do_len, int timeout, int verbose)
{
    int res, k, sense_cat, ret;
    unsigned char sense_b[SENSE_BUFF_LEN];
    int noisy = 1;
    struct sg_pt_base * ptvp;
    char b[32];

    snprintf(b, sizeof(b), "Write and verify(%d)", cdb_len);
    if (verbose) {
       pr2serr("    %s cdb: ", b);
       for (k = 0; k < cdb_len; ++k)
           pr2serr("%02x ", cdbp[k]);
       pr2serr("\n");
       if ((verbose > 2) && dop && do_len) {
            pr2serr("    Data out buffer [%d bytes]:\n", do_len);
            dStrHexErr((const char *)dop, do_len, -1);
        }
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", b);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, cdbp, cdb_len);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, dop, do_len);
    res = do_scsi_pt(ptvp, sg_fd, timeout, verbose);
    ret = sg_cmds_process_resp(ptvp, b, res, 0, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_MEDIUM_HARD:    /* write or verify failed */
            {
                int valid, slen;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                if (valid)
                    pr2serr("Medium or hardware error starting at lba=%"
                            PRIu64 " [0x%" PRIx64 "]\n", ull, ull);
            }
            ret = sense_cat;
            break;
        case SG_LIB_CAT_PROTECTION:     /* PI failure */
        case SG_LIB_CAT_MISCOMPARE:     /* only in bytchk=1 case */
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI WRITE AND VERIFY (10) command (SBC). Returns 0 -> success,
* various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_write_verify10(int sg_fd, int wrprotect, int dpo, int bytchk,
                     unsigned int lba, int num_lb, int group,
                     unsigned char *dop, int do_len, int timeout, int verbose)
{
    int ret;
    unsigned char wv_cdb[WRITE_VERIFY10_CMDLEN];

    memset(wv_cdb, 0, WRITE_VERIFY10_CMDLEN);
    wv_cdb[0] = WRITE_VERIFY10_CMD;
    wv_cdb[1] = ((wrprotect & WRPROTECT_MASK) << WRPROTECT_SHIFT);
    if (dpo)
        wv_cdb[1] |= 0x10;
    if (bytchk)
       wv_cdb[1] |= ((bytchk & 0x3) << 1);

    sg_put_unaligned_be32((uint32_t)lba, wv_cdb + 2);
    wv_cdb[6] = group & 0x1f;
    sg_put_unaligned_be16((uint16_t)num_lb, wv_cdb + 7);
    ret = run_scsi_transaction(sg_fd, wv_cdb, sizeof(wv_cdb), dop, do_len,
                               timeout, verbose);
    return ret;
}

/* Invokes a SCSI WRITE AND VERIFY (16) command (SBC). Returns 0 -> success,
* various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_write_verify16(int sg_fd, int wrprotect, int dpo, int bytchk,
                     uint64_t llba, int num_lb, int group, unsigned char *dop,
                     int do_len, int timeout, int verbose)
{
    int ret;
    unsigned char wv_cdb[WRITE_VERIFY16_CMDLEN];


    memset(wv_cdb, 0, sizeof(wv_cdb));
    wv_cdb[0] = WRITE_VERIFY16_CMD;
    wv_cdb[1] = ((wrprotect & WRPROTECT_MASK) << WRPROTECT_SHIFT);
    if (dpo)
        wv_cdb[1] |= 0x10;
    if (bytchk)
        wv_cdb[1] |= ((bytchk & 0x3) << 1);

    sg_put_unaligned_be64(llba, wv_cdb + 2);
    sg_put_unaligned_be32((uint32_t)num_lb, wv_cdb + 10);
    wv_cdb[14] = group & 0x1f;
    ret = run_scsi_transaction(sg_fd, wv_cdb, sizeof(wv_cdb), dop, do_len,
                               timeout, verbose);
    return ret;
}

static int
open_if(const char * fn, int got_stdin)
{
    int fd;

    if (got_stdin)
        fd = STDIN_FILENO;
    else {
        fd = open(fn, O_RDONLY);
        if (fd < 0) {
            pr2serr(ME "open error: %s: %s\n", fn, safe_strerror(errno));
            return -SG_LIB_FILE_ERROR;
        }
    }
    if (sg_set_binary_mode(fd) < 0) {
        perror("sg_set_binary_mode");
        return -SG_LIB_FILE_ERROR;
    }
    return fd;
}

int
main(int argc, char * argv[])
{
    int sg_fd, res, c, n, first_time;
    unsigned char * wvb = NULL;
    void * wrkBuff = NULL;
    int dpo = 0;
    int bytchk = 0;
    int group = 0;
    int do_16 = 0;
    int given_do_16 = 0;
    uint64_t llba = 0;
    int lba_given = 0;
    uint32_t num_lb = 1;
    uint32_t snum_lb = 1;
    int repeat = 0;
    int timeout = DEF_TIMEOUT_SECS;
    int verbose = 0;
    int64_t ll;
    int wrprotect = 0;
    const char * device_name = NULL;
    const char * ifnp;
    int has_filename = 0;
    int ilen = -1;
    int ifd = -1;
    int ret = 1;
    int b_p_lb = 512;
    int tnum_lb_wr = 0;
    char cmd_name[32];

    ifnp = "";          /* keep MinGW quiet */
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:dg:hi:I:l:n:RSt:w:vV", long_options,
                       &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            /* Only bytchk=0 and =1 are meaningful for this command in
             * sbc4r02 (not =2 nor =3) but that may change in the future. */
            bytchk = sg_get_num(optarg);
            if ((bytchk < 0) || (bytchk > 3))  {
                pr2serr("argument to '--bytchk' expected to be 0 to 3\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'd':
            dpo = 1;
            break;
        case 'g':
            group = sg_get_num(optarg);
            if ((group < 0) || (group > 31))  {
                pr2serr("argument to '--group' expected to be 0 to 31\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            ifnp = optarg;
            has_filename = 1;
            break;
        case 'I':
            ilen = sg_get_num(optarg);
            if (-1 == ilen) {
                pr2serr("bad argument to '--ilen'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'l':
            if (lba_given) {
                pr2serr("must have one and only one '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ll = sg_get_llnum(optarg);
            if (ll < 0) {
                pr2serr("bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            llba = (uint64_t)ll;
            ++lba_given;
            break;
        case 'n':
            n = sg_get_num(optarg);
            if (-1 == n) {
                pr2serr("bad argument to '--num'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            num_lb = (uint32_t)n;
            break;
        case 'R':
            ++repeat;
            break;
        case 'S':
            do_16 = 1;
            given_do_16 = 1;
            break;
        case 't':
            timeout = sg_get_num(optarg);
            if (timeout < 1) {
                pr2serr("bad argument to '--timeout'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
        case 'w':
            wrprotect = sg_get_num(optarg);
            if ((wrprotect < 0) || (wrprotect > 7))  {
                pr2serr("wrprotect (%d) is out of range ( < %d)\n", wrprotect,
                        7);
                return SG_LIB_SYNTAX_ERROR;
            }

            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
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
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
       }
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (! lba_given) {
        pr2serr("need a --lba=LBA option\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (repeat) {
        if (! has_filename) {
            pr2serr("with '--repeat' need '--in=IF' option\n");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
        if (ilen < 1) {
            pr2serr("with '--repeat' need '--ilen=ILEN' option\n");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        } else {
            b_p_lb = ilen / num_lb;
            if (b_p_lb < 64) {
                pr2serr("calculated %d bytes per logical block, too small\n",
                        b_p_lb);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        }
    }

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if ((0 == do_16) && (llba > UINT_MAX))
        do_16 = 1;
    if ((0 == do_16) && (num_lb > 0xffff))
        do_16 = 1;
    snprintf(cmd_name, sizeof(cmd_name), "Write and verify(%d)",
             (do_16 ? 16 : 10));
    if (verbose && (0 == given_do_16) && do_16)
        pr2serr("Switching to %s because LBA or NUM too large\n", cmd_name);
    if (verbose) {
        pr2serr("Issue %s to device %s\n\tilen=%d", cmd_name, device_name,
                ilen);
        if (ilen > 0)
            pr2serr(" [0x%x]", ilen);
        pr2serr(", lba=%" PRIu64 " [0x%" PRIx64 "]\n\twrprotect=%d, dpo=%d, "
                "bytchk=%d, group=%d, repeat=%d\n", llba, llba, wrprotect,
                dpo, bytchk, group, repeat);
    }

    first_time = 1;
    do {
        if (first_time) {
            //If a file with data to write has been provided
            if (has_filename) {
                struct stat a_stat;

                if ((1 == strlen(ifnp)) && ('-' == ifnp[0])) {
                    ifd = STDIN_FILENO;
                    ifnp = "<stdin>";
                    if (verbose > 1)
                        pr2serr("Reading input data from stdin\n");
                } else {
                    ifd = open_if(ifnp, 0);
                    if (ifd < 0) {
                        ret = -ifd;
                        goto err_out;
                    }
                }
                if (ilen < 1) {
                    if (fstat(ifd, &a_stat) < 0) {
                        pr2serr("Could not fstat(%s)\n", ifnp);
                        goto err_out;
                    }
                    if (! S_ISREG(a_stat.st_mode)) {
                        pr2serr("Cannot determine IF size, please give "
                                "'--ilen='\n");
                        goto err_out;
                    }
                    ilen = (int)a_stat.st_size;
                    if (ilen < 1) {
                        pr2serr("%s file size too small\n", ifnp);
                        goto err_out;
                    } else if (verbose)
                        pr2serr("Using file size of %d bytes\n", ilen);
                }
                if (NULL == (wrkBuff = malloc(ilen))) {
                    pr2serr(ME "out of memory\n");
                    ret = SG_LIB_CAT_OTHER;
                    goto err_out;
                }
                wvb = (unsigned char *)wrkBuff;
                res = read(ifd, wvb, ilen);
                if (res < 0) {
                    pr2serr("Could not read from %s", ifnp);
                    goto err_out;
                }
                if (res < ilen) {
                    pr2serr("Read only %d bytes (expected %d) from %s\n", res,
                            ilen, ifnp);
                    if (repeat)
                        pr2serr("Will scale subsequent pieces when repeat=1, "
                                "but this is first\n");
                    goto err_out;
                }
            } else {
                if (ilen < 1) {
                    if (verbose)
                        pr2serr("Default write length to %d*%d=%d bytes\n",
                                num_lb, 512, 512 * num_lb);
                    ilen = 512 * num_lb;
                }
                if (NULL == (wrkBuff = malloc(ilen))) {
                    pr2serr(ME "out of memory\n");
                    ret = SG_LIB_CAT_OTHER;
                    goto err_out;
                }
                wvb = (unsigned char *)wrkBuff;
                /* Not sure about this: default contents to 0xff bytes */
                memset(wrkBuff, 0xff, ilen);
            }
            first_time = 0;
            snum_lb = num_lb;
        } else {        /* repeat=1, first_time=0, must be reading file */
            llba += snum_lb;
            res = read(ifd, wvb, ilen);
            if (res < 0) {
                pr2serr("Could not read from %s", ifnp);
                goto err_out;
            } else {
                if (verbose > 1)
                pr2serr("Subsequent read from %s got %d bytes\n", ifnp, res);
                if (0 == res)
                    break;
                if (res < ilen) {
                    snum_lb = (uint32_t)(res / b_p_lb);
                    n = res % b_p_lb;
                    if (0 != n)
                        pr2serr(">>> warning: ignoring last %d bytes of %s\n",
                                n, ifnp);
                    if (snum_lb < 1)
                        break;
                }
            }
        }
        if (do_16)
            res = sg_ll_write_verify16(sg_fd, wrprotect, dpo, bytchk, llba,
                                       snum_lb, group, wvb, ilen, timeout,
                                       verbose);
        else
            res = sg_ll_write_verify10(sg_fd, wrprotect, dpo, bytchk,
                                       (unsigned int)llba, snum_lb, group,
                                       wvb, ilen, timeout, verbose);
        ret = res;
        if (repeat && (0 == ret))
            tnum_lb_wr += snum_lb;
        if (ret || (snum_lb != num_lb))
            break;
    } while (repeat);

err_out:
    if (repeat)
        pr2serr("%d [0x%x] logical blocks written, in total\n", tnum_lb_wr,
                tnum_lb_wr);
    if (wrkBuff)
        free(wrkBuff);
    if ((ifd >= 0) && (STDIN_FILENO != ifd))
        close(ifd);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    if (ret && (0 == verbose)) {
        if (SG_LIB_CAT_INVALID_OP == ret)
            pr2serr("%s command not supported\n", cmd_name);
        else if (ret > 0)
            pr2serr("%s, exit status %d\n", cmd_name, ret);
        else if (ret < 0)
            pr2serr("Some error occurred\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
