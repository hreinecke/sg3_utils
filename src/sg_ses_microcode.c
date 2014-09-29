/*
 * Copyright (c) 2014 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */
#endif
#endif
#include "sg_unaligned.h"

/*
 * This utility issues the SCSI SEND DIAGNOSTIC and RECEIVE DIAGNOSTIC
 * RESULTS commands in order to send microcode to the given SES device.
 */

static const char * version_str = "1.00 20140829";    /* ses3r06 */

#define ME "sg_ses_microcode: "
#define MAX_XFER_LEN (128 * 1024 * 1024)
#define DEF_XFER_LEN (8 * 1024 * 1024)
#define DEF_DI_LEN (8 * 1024)
#define EBUFF_SZ 256

#define DPC_DOWNLOAD_MICROCODE 0xe

struct opts_t {
    int bpw;
    int bpw_then_activate;
    int mc_id;
    int mc_len;
    int mc_len_given;
    int mc_mode;
    int mc_offset;
    int mc_skip;
    int mc_subenc;
    int mc_tlen;
    int verbose;
};

static struct option long_options[] = {
    {"bpw", required_argument, 0, 'b'},
    {"help", no_argument, 0, 'h'},
    {"id", required_argument, 0, 'i'},
    {"in", required_argument, 0, 'I'},
    {"length", required_argument, 0, 'l'},
    {"mode", required_argument, 0, 'm'},
    {"offset", required_argument, 0, 'o'},
    {"skip", required_argument, 0, 's'},
    {"subenc", required_argument, 0, 'S'},
    {"tlength", required_argument, 0, 't'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};


#ifdef __GNUC__
static int pr2serr(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
static int pr2serr(const char * fmt, ...);
#endif


static int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

static void
usage()
{
    pr2serr("Usage: "
            "sg_ses_microcode [--bpw=CS] [--help] [--id=ID] [--in=FILE]\n"
            "                        [--length=LEN] [--mode=MO] "
            "[--offset=OFF]\n"
            "                        [--skip=SKIP] [--subenc=SEID] "
            "[--tlength=TLEN]\n"
            "                        [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --bpw=CS|-b CS         CS is chunk size: bytes per send "
            "diagnostic\n"
            "                           command (def: 0 -> as many as "
            "possible)\n"
            "    --help|-h              print out usage message then exit\n"
            "    --id=ID|-i ID          buffer identifier (0 (default) to "
            "255)\n"
            "    --in=FILE|-I FILE      read from FILE ('-I -' read "
            "from stdin)\n"
            "    --length=LEN|-l LEN    length in bytes to send; may be "
            "deduced from\n"
            "                           FILE\n"
            "    --mode=MO|-m MO        download microcode mode, MO is "
            "number or\n"
            "                           acronym (def: 0 -> 'dmc_status')\n"
            "    --offset=OFF|-o OFF    buffer offset (unit: bytes, def: "
            "0);\n"
            "                           ignored if --bpw=CS given\n"
            "    --skip=SKIP|-s SKIP    bytes in file FILE to skip before "
            "reading\n"
            "    --subenc=SEID|-S SEID     subenclosure identifier (def: 0 "
            "(primary))\n"
            "    --tlength=TLEN|-t TLEN    total length of firmware in "
            "bytes\n"
            "                              (def: 0). Only needed if "
            "TLEN>LEN\n"
            "    --verbose|-v           increase verbosity\n"
            "    --version|-V           print version string and exit\n\n"
            "Does one or more SCSI SEND DIAGNOSTIC followed by RECEIVE "
            "DIAGNOSTIC\nRESULTS command sequences in order to download "
            "microcode. Use '-m xxx'\nto list available modes. With only "
            "DEVICE given, the Download Microcode\nStatus dpage is output.\n"
          );
}

#define MODE_DNLD_STATUS        0
#define MODE_DNLD_MC_OFFS       6
#define MODE_DNLD_MC_OFFS_SAVE  7
#define MODE_DNLD_MC_OFFS_DEFER 0x0E
#define MODE_ACTIVATE_MC        0x0F

struct mode_s {
        const char *mode_string;
        int   mode;
        const char *comment;
};

static struct mode_s mode_arr[] = {
    {"dmc_status", MODE_DNLD_STATUS, "report status of microcode "
     "download"},
    {"dmc_offs", MODE_DNLD_MC_OFFS, "download microcode with offsets "
     "and activate"},
    {"dmc_offs_save", MODE_DNLD_MC_OFFS_SAVE, "download microcode with "
     "offsets, save and\n\t\t\t\tactivate"},
    {"dmc_offs_defer", MODE_DNLD_MC_OFFS_DEFER, "download microcode "
     "with offsets, save and\n\t\t\t\tdefer activation"},
    {"activate_mc", MODE_ACTIVATE_MC, "activate deferred microcode"},
    {NULL, 0, NULL},
};


static void
print_modes(void)
{
    const struct mode_s * mp;

    pr2serr("The modes parameter argument can be numeric (hex or decimal)\n"
            "or symbolic:\n");
    for (mp = mode_arr; mp->mode_string; ++mp) {
        pr2serr(" %2d (0x%02x)  %-18s%s\n", mp->mode, mp->mode,
                mp->mode_string, mp->comment);
    }
    pr2serr("\nAdditionally '--bpw=<val>,act' does a activate deferred "
            "microcode after a\nsuccessful multipart dmc_offs_defer mode "
            "download.\n");
}

struct diag_page_code {
    int page_code;
    const char * desc;
};

/* An array of Download microcode status field values and descriptions */
static struct diag_page_code mc_status_arr[] = {
    {0x0, "No download microcode operation in progress"},
    {0x1, "Download in progress, awaiting more"},
    {0x2, "Download complete, updating storage"},
    {0x3, "Updating storage with deferred microcode"},
    {0x10, "Complete, no error, starting now"},
    {0x11, "Complete, no error, start after hard reset or power cycle"},
    {0x12, "Complete, no error, start after power cycle"},
    {0x13, "Complete, no error, start after activate_mc, hard reset or "
           "power cycle"},
    {0x80, "Error, discarded, see additional status"},
    {0x81, "Error, discarded, image error"},
    {0x82, "Timeout, discarded"},
    {0x83, "Internal error, need new microcode before reset"},
    {0x84, "Internal error, need new microcode, reset safe"},
    {0x85, "Unexpected activate_mc received"},
    {0x1000, NULL},
};

static const char *
get_mc_status_str(unsigned char status_val)
{
    const struct diag_page_code * mcsp;

    for (mcsp = mc_status_arr; mcsp->desc; ++mcsp) {
        if (status_val == mcsp->page_code)
            return mcsp->desc;
    }
    return "";
}

/* DPC_DOWNLOAD_MICROCODE [0xe] */
static void
ses_download_code_sdg(const unsigned char * resp, int resp_len,
                      uint32_t gen_code)
{
    int k, num_subs, num;
    const unsigned char * ucp;
    const char * cp;

    printf("Download microcode status diagnostic page:\n");
    if (resp_len < 8)
        goto truncated;
    num_subs = resp[1];  /* primary is additional one) */
    num = (resp_len - 8) / 16;
    if ((resp_len - 8) % 16)
        pr2serr("Found %d Download microcode status descriptors, but there "
                "is residual\n", num);
    printf("  number of secondary subenclosures: %d\n", num_subs);
    printf("  generation code: 0x%" PRIx32 "\n", gen_code);
    ucp = resp + 8;
    for (k = 0; k < num; ++k, ucp += 16) {
        cp = (0 == ucp[1]) ? " [primary]" : "";
        printf("   subenclosure identifier: %d%s\n", ucp[1], cp);
        cp = get_mc_status_str(ucp[2]);
        if (strlen(cp) > 0) {
            printf("     download microcode status: %s [0x%x]\n", cp, ucp[2]);
            printf("     download microcode additional status: 0x%x\n",
                   ucp[3]);
        } else
            printf("     download microcode status: 0x%x [additional "
                   "status: 0x%x]\n", ucp[2], ucp[3]);
        printf("     download microcode maximum size: %" PRIu32 " bytes\n",
               sg_get_unaligned_be32(ucp + 4));
        printf("     download microcode expected buffer id: 0x%x\n", ucp[11]);
        printf("     download microcode expected buffer id offset: %" PRIu32
               "\n", sg_get_unaligned_be32(ucp + 12));
    }
    return;
truncated:
    pr2serr("    <<<download status: response too short>>>\n");
    return;
}

struct dout_buff_t {
    unsigned char * doutp;
    int dout_len;
};

static int
send_then_receive(int sg_fd, uint32_t gen_code, int off_off,
                  const unsigned char * dmp, int dmp_len,
                  struct dout_buff_t * wp, unsigned char * dip,
                  const struct opts_t * op)
{
    int do_len, rem, res, rsp_len, k, num, mc_status;
    int send_data = 0;
    int ret = 0;
    uint32_t rec_gen_code;
    const unsigned char * ucp;
    const char * cp;

    switch (op->mc_mode) {
    case MODE_DNLD_MC_OFFS:
    case MODE_DNLD_MC_OFFS_SAVE:
    case MODE_DNLD_MC_OFFS_DEFER:
        send_data = 1;
        do_len = 24 + dmp_len;
        rem = do_len % 4;
        if (rem)
            do_len += (4 - rem);
        break;
    case MODE_ACTIVATE_MC:
        do_len = 24;
        break;
    default:
        pr2serr("send_then_receive: unexpected mc_mode=0x%x\n", op->mc_mode);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (do_len > wp->dout_len) {
        if (wp->doutp)
            free(wp->doutp);
        wp->doutp = (unsigned char *)malloc(do_len);
        if (! wp->doutp) {
            pr2serr("send_then_receive: unable to malloc %d bytes\n", do_len);
            return SG_LIB_CAT_OTHER;
        }
        wp->dout_len = do_len;
    }
    memset(wp->doutp, 0, do_len);
    wp->doutp[0] = DPC_DOWNLOAD_MICROCODE;
    wp->doutp[1] = op->mc_subenc;
    sg_put_unaligned_be16(do_len - 4, wp->doutp + 2);
    sg_put_unaligned_be32(gen_code, wp->doutp + 4);
    wp->doutp[8] = op->mc_mode;
    wp->doutp[11] = op->mc_id;
    if (send_data)
        sg_put_unaligned_be32(op->mc_offset + off_off, wp->doutp + 12);
    sg_put_unaligned_be32(op->mc_tlen, wp->doutp + 16);
    sg_put_unaligned_be32(dmp_len, wp->doutp + 20);
    if (send_data && (dmp_len > 0))
        memcpy(wp->doutp + 24, dmp, dmp_len);
    /* select long duration timeout (7200 seconds) */
    res = sg_ll_send_diag(sg_fd, 0 /* sf_code */, 1 /* pf */, 0 /* sf */,
                          0 /* devofl */, 0 /* unitofl */,
                          1 /* long_duration */, wp->doutp, do_len,
                          1 /* noisy */, op->verbose);
    if (res)
        return res;
    res = sg_ll_receive_diag(sg_fd, 1 /* pcv */, DPC_DOWNLOAD_MICROCODE, dip,
                             DEF_DI_LEN, 1, op->verbose);
    if (res)
        return res;
    rsp_len = sg_get_unaligned_be16(dip + 2) + 4;
    if (rsp_len > DEF_DI_LEN) {
        pr2serr("<<< warning response buffer too small [%d but need "
                "%d]>>>\n", DEF_DI_LEN, rsp_len);
        rsp_len = DEF_DI_LEN;
    }
    if (rsp_len < 8) {
        pr2serr("Download microcode status dpage too short\n");
        return SG_LIB_CAT_OTHER;
    }
    rec_gen_code = sg_get_unaligned_be32(dip + 4);
    if (rec_gen_code != gen_code)
        pr2serr("gen_code changed from %" PRIu32 " to %" PRIu32
                ", continuing but may fail\n", gen_code, rec_gen_code);
    num = (rsp_len - 8) / 16;
    if ((rsp_len - 8) % 16)
        pr2serr("Found %d Download microcode status descriptors, but there "
                "is residual\n", num);
    ucp = dip + 8;
    for (k = 0; k < num; ++k, ucp += 16) {
        if ((unsigned int)op->mc_subenc == (unsigned int)ucp[1]) {
            mc_status = ucp[2];
            cp = get_mc_status_str(mc_status);
            if ((mc_status >= 0x80) || op->verbose)
                pr2serr("mc offset=%d: status: %s [0x%x, additional=0x%x]\n",
                        off_off, cp, mc_status, ucp[3]);
            if (mc_status >= 0x80)
                ret = SG_LIB_CAT_OTHER;
        }
    }
    return ret;
}


int
main(int argc, char * argv[])
{
    int sg_fd, res, c, len, k, n, got_stdin, is_reg, rsp_len;
    int infd = -1;
    int do_help = 0;
    const char * device_name = NULL;
    const char * file_name = NULL;
    unsigned char * dmp = NULL;
    unsigned char * dip = NULL;
    char * cp;
    char ebuff[EBUFF_SZ];
    struct stat a_stat;
    struct dout_buff_t dout;
    struct opts_t opts;
    struct opts_t * op;
    const struct mode_s * mp;
    uint32_t gen_code;
    int ret = 0;

    op = &opts;
    memset(op, 0, sizeof(opts));
    memset(&dout, 0, sizeof(dout));
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:hi:I:l:m:o:s:S:t:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            op->bpw = sg_get_num(optarg);
            if (op->bpw < 0) {
                pr2serr("argument to '--bpw' should be in a positive "
                        "number\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((cp = strchr(optarg, ','))) {
                if (0 == strncmp("act", cp + 1, 3))
                    ++op->bpw_then_activate;
            }
            break;
        case 'h':
        case '?':
            ++do_help;
            break;
        case 'i':
            op->mc_id = sg_get_num(optarg);
            if ((op->mc_id < 0) || (op->mc_id > 255)) {
                pr2serr("argument to '--id' should be in the range 0 to "
                        "255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'I':
            file_name = optarg;
            break;
        case 'l':
            op->mc_len = sg_get_num(optarg);
            if (op->mc_len < 0) {
                pr2serr("bad argument to '--length'\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             op->mc_len_given = 1;
             break;
        case 'm':
            if (isdigit(*optarg)) {
                op->mc_mode = sg_get_num(optarg);
                if ((op->mc_mode < 0) || (op->mc_mode > 255)) {
                    pr2serr("argument to '--mode' should be in the range 0 "
                            "to 255\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                len = strlen(optarg);
                for (mp = mode_arr; mp->mode_string; ++mp) {
                    if (0 == strncmp(mp->mode_string, optarg, len)) {
                        op->mc_mode = mp->mode;
                        break;
                    }
                }
                if (! mp->mode_string) {
                    print_modes();
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            break;
        case 'o':
           op->mc_offset = sg_get_num(optarg);
           if (op->mc_offset < 0) {
                pr2serr("bad argument to '--offset'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (0 != (op->mc_offset % 4)) {
                pr2serr("'--offset' value needs to be a multiple of 4\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 's':
           op->mc_skip = sg_get_num(optarg);
           if (op->mc_skip < 0) {
                pr2serr("bad argument to '--skip'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'S':
           op->mc_subenc = sg_get_num(optarg);
           if ((op->mc_subenc < 0) || (op->mc_subenc > 255)) {
                pr2serr("expected argument to '--subenc' to be 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 't':
           op->mc_tlen = sg_get_num(optarg);
           if (op->mc_tlen < 0) {
                pr2serr("bad argument to '--tlength'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (do_help) {
        if (do_help > 1) {
            usage();
            pr2serr("\n");
            print_modes();
        } else
            usage();
        return 0;
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

    if ((op->mc_len > 0) && (op->bpw > op->mc_len)) {
        pr2serr("trim chunk size (CS) to be the same as LEN\n");
        op->bpw = op->mc_len;
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (op->verbose > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, op->verbose);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (file_name && ((MODE_DNLD_STATUS == op->mc_mode) ||
                      (MODE_ACTIVATE_MC == op->mc_mode)))
        pr2serr("ignoring --in=FILE option\n");
    else if (file_name) {
        got_stdin = (0 == strcmp(file_name, "-")) ? 1 : 0;
        if (got_stdin)
            infd = STDIN_FILENO;
        else {
            if ((infd = open(file_name, O_RDONLY)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", file_name);
                perror(ebuff);
                ret = SG_LIB_FILE_ERROR;
                goto fini;
            } else if (sg_set_binary_mode(infd) < 0)
                perror("sg_set_binary_mode");
        }
        if ((0 == fstat(infd, &a_stat)) && S_ISREG(a_stat.st_mode)) {
            is_reg = 1;
            if (0 == op->mc_len) {
                if (op->mc_skip >= a_stat.st_size) {
                    pr2serr("skip exceeds file size of %d bytes\n",
                            (int)a_stat.st_size);
                    ret = SG_LIB_FILE_ERROR;
                    goto fini;
                }
                op->mc_len = (int)(a_stat.st_size) - op->mc_skip;
            }
        } else {
            is_reg = 0;
            if (0 == op->mc_len)
                op->mc_len = DEF_XFER_LEN;
        }
        if (op->mc_len > MAX_XFER_LEN) {
            pr2serr("file size or requested length (%d) exceeds "
                    "MAX_XFER_LEN of %d bytes\n", op->mc_len,
                    MAX_XFER_LEN);
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
        if (NULL == (dmp = (unsigned char *)malloc(op->mc_len))) {
            pr2serr(ME "out of memory (to hold microcode)\n");
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
        /* Don't remember why this is preset to 0xff, from write_buffer */
        memset(dmp, 0xff, op->mc_len);
        if (op->mc_skip > 0) {
            if (! is_reg) {
                if (got_stdin)
                    pr2serr("Can't skip on stdin\n");
                else
                    pr2serr(ME "not a 'regular' file so can't apply skip\n");
                ret = SG_LIB_FILE_ERROR;
                goto fini;
            }
            if (lseek(infd, op->mc_skip, SEEK_SET) < 0) {
                snprintf(ebuff,  EBUFF_SZ, ME "couldn't skip to "
                         "required position on %s", file_name);
                perror(ebuff);
                ret = SG_LIB_FILE_ERROR;
                goto fini;
            }
        }
        res = read(infd, dmp, op->mc_len);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s",
                     file_name);
            perror(ebuff);
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
        if (res < op->mc_len) {
            if (op->mc_len_given) {
                pr2serr("tried to read %d bytes from %s, got %d bytes\n",
                        op->mc_len, file_name, res);
                pr2serr("pad with 0xff bytes and continue\n");
            } else {
                if (op->verbose) {
                    pr2serr("tried to read %d bytes from %s, got %d "
                            "bytes\n", op->mc_len, file_name, res);
                    pr2serr("will send %d bytes", res);
                    if ((op->bpw > 0) && (op->bpw < op->mc_len))
                        pr2serr(", %d bytes per WRITE BUFFER command\n",
                                op->bpw);
                    else
                        pr2serr("\n");
                }
                op->mc_len = res;
            }
        }
        if (! got_stdin)
            close(infd);
        infd = -1;
    } else if (! ((MODE_DNLD_STATUS == op->mc_mode) ||
                  (MODE_ACTIVATE_MC == op->mc_mode))) {
        pr2serr("need --in=FILE option with given mode\n");
        ret = SG_LIB_SYNTAX_ERROR;
        goto fini;
    }
    if (op->mc_tlen < op->mc_len)
        op->mc_tlen = op->mc_len;

    if (NULL == (dip = (unsigned char *)malloc(DEF_DI_LEN))) {
        pr2serr(ME "out of memory (data-in buffer)\n");
        ret = SG_LIB_CAT_OTHER;
        goto fini;
    }
    memset(dip, 0, DEF_DI_LEN);
    /* Fetch Download microde status dpage for generation code ++ */
    res = sg_ll_receive_diag(sg_fd, 1 /* pcv */, DPC_DOWNLOAD_MICROCODE, dip,
                             DEF_DI_LEN, 1, op->verbose);
    if (0 == res) {
        rsp_len = sg_get_unaligned_be16(dip + 2) + 4;
        if (rsp_len > DEF_DI_LEN) {
            pr2serr("<<< warning response buffer too small [%d but need "
                    "%d]>>>\n", DEF_DI_LEN, rsp_len);
            rsp_len = DEF_DI_LEN;
        }
        if (rsp_len < 8) {
            pr2serr("Download microcode status dpage too short\n");
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
    } else {
        ret = res;
        goto fini;
    }
    gen_code = sg_get_unaligned_be32(dip + 4);

    if (MODE_DNLD_STATUS == op->mc_mode) {
        ses_download_code_sdg(dip, rsp_len, gen_code);
        goto fini;
    } else if (MODE_ACTIVATE_MC == op->mc_mode) {
        res = send_then_receive(sg_fd, gen_code, 0, NULL, 0, &dout, dip, op);
        ret = res;
        goto fini;
    }

    res = 0;
    if (op->bpw > 0) {
        for (k = 0; k < op->mc_len; k += n) {
            n = op->mc_len - k;
            if (n > op->bpw)
                n = op->bpw;
            if (op->verbose)
                pr2serr("send_then_receive: mode=0x%x, id=%d, off_off=%d, "
                        "len=%d\n", op->mc_mode, op->mc_id, k, n);
            res = send_then_receive(sg_fd, gen_code, k, dmp + k, n, &dout,
                                    dip, op);
            if (res)
                break;
        }
        if (op->bpw_then_activate && (0 == res)) {
            op->mc_mode = MODE_ACTIVATE_MC;
            if (op->verbose)
                pr2serr("sending Activate deferred microcode [0xf]\n");
            res = send_then_receive(sg_fd, gen_code, 0, NULL, 0, &dout,
                                    dip, op);
        }
    } else {
        if (op->verbose)
            pr2serr("single send_then_receive: mode=0x%x, id=%d, offset=%d, "
                    "len=%d\n", op->mc_mode, op->mc_id,
                    op->mc_offset, op->mc_len);
        res = send_then_receive(sg_fd, gen_code, 0, dmp, op->mc_len, &dout,
                                dip, op);
    }
    if (res)
        ret = res;

fini:
    if ((infd >= 0) && (! got_stdin))
        close(infd);
    if (dmp)
        free(dmp);
    if (dout.doutp)
        free(dout.doutp);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    if (ret && (0 == op->verbose)) {
        if (SG_LIB_CAT_INVALID_OP == ret)
            pr2serr("%sRECEIVE DIAGNOSTIC RESULTS command not supported\n",
                    ((MODE_DNLD_STATUS == op->mc_mode) ?
                     "" : "SEND DIAGNOSTIC or "));
        else if (ret > 0)
            fprintf(stderr, "Failed, exit status %d\n", ret);
        else if (ret < 0)
            fprintf(stderr, "Some error occurred\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
