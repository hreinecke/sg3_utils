/*
 * Copyright (c) 2014-2019 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */
#endif
#endif

/*
 * This utility issues the SCSI SEND DIAGNOSTIC and RECEIVE DIAGNOSTIC
 * RESULTS commands in order to send microcode to the given SES device.
 */

static const char * version_str = "1.18 20190513";    /* ses4r02 */

#define ME "sg_ses_microcode: "
#define MAX_XFER_LEN (128 * 1024 * 1024)
#define DEF_XFER_LEN (8 * 1024 * 1024)
#define DEF_DIN_LEN (8 * 1024)
#define EBUFF_SZ 256

#define DPC_DOWNLOAD_MICROCODE 0xe

struct opts_t {
    bool dry_run;
    bool ealsd;
    bool mc_non;
    bool bpw_then_activate;
    bool mc_len_given;
    int bpw;            /* bytes per write, chunk size */
    int mc_id;
    int mc_len;         /* --length=LEN */
    int mc_mode;
    int mc_offset;      /* Buffer offset in SCSI commands */
    int mc_skip;        /* on FILE */
    int mc_subenc;
    int mc_tlen;        /* --tlength=TLEN */
    int verbose;
};

static struct option long_options[] = {
    {"bpw", required_argument, 0, 'b'},
    {"dry-run", no_argument, 0, 'd'},
    {"dry_run", no_argument, 0, 'd'},
    {"ealsd", no_argument, 0, 'e'},
    {"help", no_argument, 0, 'h'},
    {"id", required_argument, 0, 'i'},
    {"in", required_argument, 0, 'I'},
    {"length", required_argument, 0, 'l'},
    {"mode", required_argument, 0, 'm'},
    {"non", no_argument, 0, 'N'},
    {"offset", required_argument, 0, 'o'},
    {"skip", required_argument, 0, 's'},
    {"subenc", required_argument, 0, 'S'},
    {"tlength", required_argument, 0, 't'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

#define MODE_DNLD_STATUS        0
#define MODE_DNLD_MC_OFFS       6
#define MODE_DNLD_MC_OFFS_SAVE  7
#define MODE_DNLD_MC_OFFS_DEFER 0x0E
#define MODE_ACTIVATE_MC        0x0F
#define MODE_ABORT_MC           0xFF    /* actually reserved; any reserved
                                         * value aborts a microcode download
                                         * in progress */

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
    {"dmc_abort", MODE_ABORT_MC, "abort download microcode in progress"},
    {NULL, 0, NULL},
};

/* An array of Download microcode status field values and descriptions.
 * This table is a subset of one in sg_read_buffer for the read microcode
 * status page. */
static struct sg_lib_simple_value_name_t mc_status_arr[] = {
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

struct dout_buff_t {
    uint8_t * doutp;
    uint8_t * free_doutp;
    int dout_len;
};

/* This dummy response is used when --dry-run skips the RECEIVE DIAGNOSTICS
 * RESULTS command. Say maximum download MC size is 4 MB. Set generation
 * code to 0 . */
uint8_t dummy_rd_resp[] = {
    0xe,  3,  0, 68,  0, 0, 0, 0,
    0,  0,  0,  0,  0x0, 0x40, 0x0, 0x0,  0, 0, 0,  0,  0x0, 0x0, 0x0, 0x0,
    0,  1,  0,  0,  0x0, 0x40, 0x0, 0x0,  0, 0, 0,  0,  0x0, 0x0, 0x0, 0x0,
    0,  2,  0,  0,  0x0, 0x40, 0x0, 0x0,  0, 0, 0,  0,  0x0, 0x0, 0x0, 0x0,
    0,  3,  0,  0,  0x0, 0x40, 0x0, 0x0,  0, 0, 0,  0,  0x0, 0x0, 0x0, 0x0,
};


static void
usage()
{
    pr2serr("Usage: "
            "sg_ses_microcode [--bpw=CS] [--dry-run] [--ealsd] [--help] "
            "[--id=ID]\n"
            "                        [--in=FILE] [--length=LEN] [--mode=MO] "
            "[--non]\n"
            "                        [--offset=OFF] [--skip=SKIP] "
            "[--subenc=SEID]\n"
            "                        [--tlength=TLEN] [--verbose] "
            "[--version]\n"
            "                        DEVICE\n"
            "  where:\n"
            "    --bpw=CS|-b CS         CS is chunk size: bytes per send "
            "diagnostic\n"
            "                           command (def: 0 -> as many as "
            "possible)\n"
            "                           can append ',act' to do activate "
            "after last\n"
            "    --dry-run|-d           skip SCSI commands, do everything "
            "else\n"
            "    --ealsd|-e             exit after last Send Diagnostic "
            "command\n"
            "    --help|-h              print out usage message then exit\n"
            "    --id=ID|-i ID          buffer identifier (0 (default) to "
            "255)\n"
            "    --in=FILE|-I FILE      read from FILE ('-I -' read "
            "from stdin)\n"
            "    --length=LEN|-l LEN    length in bytes to send (def: "
            "deduced from\n"
            "                           FILE taking SKIP into account)\n"
            "    --mode=MO|-m MO        download microcode mode, MO is "
            "number or\n"
            "                           acronym (def: 0 -> 'dmc_status')\n"
            "    --non|-N               non-standard: bypass all receive "
            "diagnostic\n"
            "                           results commands except after check "
            "condition\n"
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

static void
print_modes(void)
{
    const struct mode_s * mp;

    pr2serr("The modes parameter argument can be numeric (hex or decimal)\n"
            "or symbolic:\n");
    for (mp = mode_arr; mp->mode_string; ++mp) {
        pr2serr(" %3d [0x%02x]  %-18s%s\n", mp->mode, mp->mode,
                mp->mode_string, mp->comment);
    }
    pr2serr("\nAdditionally '--bpw=<val>,act' does a activate deferred "
            "microcode after a\nsuccessful multipart dmc_offs_defer mode "
            "download.\n");
}

static const char *
get_mc_status_str(uint8_t status_val)
{
    const struct sg_lib_simple_value_name_t * mcsp;

    for (mcsp = mc_status_arr; mcsp->name; ++mcsp) {
        if (status_val == mcsp->value)
            return mcsp->name;
    }
    return "";
}

/* display DPC_DOWNLOAD_MICROCODE status dpage [0xe] */
static void
show_download_mc_sdg(const uint8_t * resp, int resp_len,
                     uint32_t gen_code)
{
    int k, num_subs, num;
    const uint8_t * bp;
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
    bp = resp + 8;
    for (k = 0; k < num; ++k, bp += 16) {
        cp = (0 == bp[1]) ? " [primary]" : "";
        printf("   subenclosure identifier: %d%s\n", bp[1], cp);
        cp = get_mc_status_str(bp[2]);
        if (strlen(cp) > 0) {
            printf("     download microcode status: %s [0x%x]\n", cp, bp[2]);
            printf("     download microcode additional status: 0x%x\n",
                   bp[3]);
        } else
            printf("     download microcode status: 0x%x [additional "
                   "status: 0x%x]\n", bp[2], bp[3]);
        printf("     download microcode maximum size: %" PRIu32 " bytes\n",
               sg_get_unaligned_be32(bp + 4));
        printf("     download microcode expected buffer id: 0x%x\n", bp[11]);
        printf("     download microcode expected buffer id offset: %" PRIu32
               "\n", sg_get_unaligned_be32(bp + 12));
    }
    return;
truncated:
    pr2serr("    <<<download status: response too short>>>\n");
    return;
}

static int
send_then_receive(int sg_fd, uint32_t gen_code, int off_off,
                  const uint8_t * dmp, int dmp_len,
                  struct dout_buff_t * wp, uint8_t * dip,
                  int din_len, bool last, const struct opts_t * op)
{
    bool send_data = false;
    int do_len, rem, res, rsp_len, k, n, num, mc_status, resid, act_len, verb;
    int ret = 0;
    uint32_t rec_gen_code;
    const uint8_t * bp;
    const char * cp;

    verb = (op->verbose > 1) ? op->verbose - 1 : 0;
    switch (op->mc_mode) {
    case MODE_DNLD_MC_OFFS:
    case MODE_DNLD_MC_OFFS_SAVE:
    case MODE_DNLD_MC_OFFS_DEFER:
        send_data = true;
        do_len = 24 + dmp_len;
        rem = do_len % 4;
        if (rem)
            do_len += (4 - rem);
        break;
    case MODE_ACTIVATE_MC:
    case MODE_ABORT_MC:
        do_len = 24;
        break;
    default:
        pr2serr("%s: unexpected mc_mode=0x%x\n", __func__, op->mc_mode);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (do_len > wp->dout_len) {
        if (wp->doutp)
            free(wp->doutp);
        wp->doutp = sg_memalign(do_len, 0, &wp->free_doutp, op->verbose > 3);
        if (! wp->doutp) {
            pr2serr("%s: unable to alloc %d bytes\n", __func__, do_len);
            return SG_LIB_CAT_OTHER;
        }
        wp->dout_len = do_len;
    } else
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
    if ((op->verbose > 2) || (op->dry_run && op->verbose)) {
        pr2serr("send diag: sub-enc id=%u exp_gen=%u download_mc_code=%u "
                "buff_id=%u\n", op->mc_subenc, gen_code, op->mc_mode,
                op->mc_id);
        pr2serr("    buff_off=%u image_len=%u this_mc_data_len=%u "
                "dout_len=%u\n", op->mc_offset + off_off, op->mc_tlen,
                dmp_len, do_len);
    }
    /* select long duration timeout (7200 seconds) */
    if (op->dry_run) {
        if (op->mc_subenc < 4) {
            int s = op->mc_offset + off_off + dmp_len;

            n = 8 + (op->mc_subenc * 16);
            dummy_rd_resp[n + 11] = op->mc_id;
            sg_put_unaligned_be32(((send_data && (! last)) ? s : 0),
                                  dummy_rd_resp + n + 12);
            if (MODE_ABORT_MC == op->mc_mode)
                dummy_rd_resp[n + 2] = 0x80;
            else if (MODE_ACTIVATE_MC == op->mc_mode)
                dummy_rd_resp[n + 2] = 0x0;     /* done */
            else
                dummy_rd_resp[n + 2] = (s >= op->mc_tlen) ? 0x13 : 0x1;
        }
        res = 0;
    } else
        res = sg_ll_send_diag(sg_fd, 0 /* st_code */, true /* pf */,
                              false /* st */, false /* devofl */,
                              false /* unitofl */, 1 /* long_duration */,
                              wp->doutp, do_len, true /* noisy */, verb);
    if (op->mc_non) {
        /* If non-standard, only call RDR after failed SD */
        if (0 == res)
            return 0;
        /* If RDR error after SD error, prefer reporting SD error */
        ret = res;
    } else {
        switch (op->mc_mode) {
        case MODE_DNLD_MC_OFFS:
        case MODE_DNLD_MC_OFFS_SAVE:
            if (res)
                return res;
            else if (last) {
                if (op->ealsd)
                    return 0;   /* RDR after last may hit a device reset */
            }
            break;
        case MODE_DNLD_MC_OFFS_DEFER:
            if (res)
                return res;
            break;
        case MODE_ACTIVATE_MC:
        case MODE_ABORT_MC:
            if (0 == res) {
                if (op->ealsd)
                    return 0;   /* RDR after this may hit a device reset */
            }
            /* SD has failed, so do a RDR but return SD's error */
            ret = res;
            break;
        default:
            pr2serr("%s: mc_mode=0x%x\n", __func__, op->mc_mode);
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (op->dry_run) {
        n = sizeof(dummy_rd_resp);
        n = (n < din_len) ? n : din_len;
        memcpy(dip, dummy_rd_resp, n);
        resid = din_len - n;
        res = 0;
    } else
        res = sg_ll_receive_diag_v2(sg_fd, true /* pcv */,
                                    DPC_DOWNLOAD_MICROCODE, dip, din_len,
                                    0 /* default timeout */, &resid, true,
                                    verb);
    if (res)
        return ret ? ret : res;
    rsp_len = sg_get_unaligned_be16(dip + 2) + 4;
    act_len = din_len - resid;
    if (rsp_len > din_len) {
        pr2serr("<<< warning response buffer too small [%d but need "
                "%d]>>>\n", din_len, rsp_len);
        rsp_len = din_len;
    }
    if (rsp_len > act_len) {
        pr2serr("<<< warning response too short [actually got %d but need "
                "%d]>>>\n", act_len, rsp_len);
        rsp_len = act_len;
    }
    if (rsp_len < 8) {
        pr2serr("Download microcode status dpage too short [%d]\n", rsp_len);
        return ret ? ret : SG_LIB_CAT_OTHER;
    }
    rec_gen_code = sg_get_unaligned_be32(dip + 4);
    if ((op->verbose > 2) || (op->dry_run && op->verbose)) {
        n = 8 + (op->mc_subenc * 16);
        pr2serr("rec diag: rsp_len=%d, num_sub-enc=%u rec_gen_code=%u "
                "exp_buff_off=%u\n", rsp_len, dip[1],
                sg_get_unaligned_be32(dip + 4),
                sg_get_unaligned_be32(dip + n + 12));
    }
    if (rec_gen_code != gen_code)
        pr2serr("gen_code changed from %" PRIu32 " to %" PRIu32
                ", continuing but may fail\n", gen_code, rec_gen_code);
    num = (rsp_len - 8) / 16;
    if ((rsp_len - 8) % 16)
        pr2serr("Found %d Download microcode status descriptors, but there "
                "is residual\n", num);
    bp = dip + 8;
    for (k = 0; k < num; ++k, bp += 16) {
        if ((unsigned int)op->mc_subenc == (unsigned int)bp[1]) {
            mc_status = bp[2];
            cp = get_mc_status_str(mc_status);
            if ((mc_status >= 0x80) || op->verbose)
                pr2serr("mc offset=%u: status: %s [0x%x, additional=0x%x]\n",
                        sg_get_unaligned_be32(bp + 12), cp, mc_status, bp[3]);
            if (op->verbose > 1)
                pr2serr("  subenc_id=%d, expected_buffer_id=%d, "
                        "expected_offset=0x%" PRIx32 "\n", bp[1], bp[11],
                        sg_get_unaligned_be32(bp + 12));
            if (mc_status >= 0x80)
                ret = ret ? ret : SG_LIB_CAT_OTHER;
        }
    }
    return ret;
}


int
main(int argc, char * argv[])
{
    bool last, got_stdin, is_reg;
    bool want_file = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c, len, k, n, rsp_len, resid, act_len, din_len, verb;
    int sg_fd = -1;
    int infd = -1;
    int do_help = 0;
    int ret = 0;
    uint32_t gen_code = 0;
    const char * device_name = NULL;
    const char * file_name = NULL;
    uint8_t * dmp = NULL;
    uint8_t * dip = NULL;
    uint8_t * free_dip = NULL;
    char * cp;
    char ebuff[EBUFF_SZ];
    struct stat a_stat;
    struct dout_buff_t dout;
    struct opts_t opts;
    struct opts_t * op;
    const struct mode_s * mp;

    op = &opts;
    memset(op, 0, sizeof(opts));
    memset(&dout, 0, sizeof(dout));
    din_len = DEF_DIN_LEN;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:dehi:I:l:m:No:s:S:t:vV", long_options,
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
                    op->bpw_then_activate = true;
            }
            break;
        case 'd':
            op->dry_run = true;
            break;
        case 'e':
            op->ealsd = true;
            break;
        case 'h':
        case '?':
            ++do_help;
            break;
        case 'i':
            op->mc_id = sg_get_num_nomult(optarg);
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
             op->mc_len_given = true;
             break;
        case 'm':
            if (isdigit(*optarg)) {
                op->mc_mode = sg_get_num_nomult(optarg);
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
        case 'N':
            op->mc_non = true;
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
           op->mc_subenc = sg_get_num_nomult(optarg);
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
            verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            version_given = true;
            break;
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

#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        verbose_given = false;
        version_given = false;
        op->verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr(ME "version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    switch (op->mc_mode) {
    case MODE_DNLD_MC_OFFS:
    case MODE_DNLD_MC_OFFS_SAVE:
    case MODE_DNLD_MC_OFFS_DEFER:
        want_file = true;
        break;
    case MODE_DNLD_STATUS:
    case MODE_ACTIVATE_MC:
    case MODE_ABORT_MC:
        want_file = false;
        break;
    default:
        pr2serr("%s: mc_mode=0x%x, continue for now\n", __func__,
                op->mc_mode);
        break;
    }

    if ((op->mc_len > 0) && (op->bpw > op->mc_len)) {
        pr2serr("trim chunk size (CS) to be the same as LEN\n");
        op->bpw = op->mc_len;
    }
    if ((op->mc_offset > 0) && (op->bpw > 0)) {
        op->mc_offset = 0;
        pr2serr("WARNING: --offset= ignored (set back to 0) when --bpw= "
                "argument given (and > 0)\n");
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (op->verbose > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    sg_fd = sg_cmds_open_device(device_name, false /* rw */, op->verbose);
    if (sg_fd < 0) {
        if (op->verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    if (file_name && (! want_file))
        pr2serr("ignoring --in=FILE option\n");
    else if (file_name) {
        got_stdin = (0 == strcmp(file_name, "-"));
        if (got_stdin)
            infd = STDIN_FILENO;
        else {
            if ((infd = open(file_name, O_RDONLY)) < 0) {
                ret = sg_convert_errno(errno);
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", file_name);
                perror(ebuff);
                goto fini;
            } else if (sg_set_binary_mode(infd) < 0)
                perror("sg_set_binary_mode");
        }
        if ((0 == fstat(infd, &a_stat)) && S_ISREG(a_stat.st_mode)) {
            is_reg = true;
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
            is_reg = false;
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
        if (NULL == (dmp = (uint8_t *)malloc(op->mc_len))) {
            pr2serr(ME "out of memory to hold microcode read from FILE\n");
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
                ret = sg_convert_errno(errno);
                snprintf(ebuff,  EBUFF_SZ, ME "couldn't skip to "
                         "required position on %s", file_name);
                perror(ebuff);
                goto fini;
            }
        }
        res = read(infd, dmp, op->mc_len);
        if (res < 0) {
            ret = sg_convert_errno(errno);
            snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s",
                     file_name);
            perror(ebuff);
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
    } else if (want_file) {
        pr2serr("need --in=FILE option with given mode\n");
        ret = SG_LIB_CONTRADICT;
        goto fini;
    }
    if (op->mc_tlen < op->mc_len)
        op->mc_tlen = op->mc_len;
    if (op->mc_non && (MODE_DNLD_STATUS == op->mc_mode)) {
        pr2serr("Do nothing because '--non' given so fetching the Download "
                "microcode status\ndpage might be dangerous\n");
        goto fini;
    }

    dip = sg_memalign(din_len, 0, &free_dip, op->verbose > 3);
    if (NULL == dip) {
        pr2serr(ME "out of memory (data-in buffer)\n");
        ret = SG_LIB_CAT_OTHER;
        goto fini;
    }
    verb = (op->verbose > 1) ? op->verbose - 1 : 0;
    /* Fetch Download microcode status dpage for generation code ++ */
    if (op->dry_run) {
        n = sizeof(dummy_rd_resp);
        n = (n < din_len) ? n : din_len;
        memcpy(dip, dummy_rd_resp, n);
        resid = din_len - n;
        res = 0;
    } else
        res = sg_ll_receive_diag_v2(sg_fd, true /* pcv */,
                                    DPC_DOWNLOAD_MICROCODE, dip, din_len,
                                    0 /*default timeout */, &resid, true,
                                    verb);
    if (0 == res) {
        rsp_len = sg_get_unaligned_be16(dip + 2) + 4;
        act_len = din_len - resid;
        if (rsp_len > din_len) {
            pr2serr("<<< warning response buffer too small [%d but need "
                    "%d]>>>\n", din_len, rsp_len);
            rsp_len = din_len;
        }
        if (rsp_len > act_len) {
            pr2serr("<<< warning response too short [actually got %d but "
                    "need %d]>>>\n", act_len, rsp_len);
            rsp_len = act_len;
        }
        if (rsp_len < 8) {
            pr2serr("Download microcode status dpage too short\n");
            ret = SG_LIB_CAT_OTHER;
            goto fini;
        }
        if ((op->verbose > 2) || (op->dry_run && op->verbose))
            pr2serr("rec diag(ini): rsp_len=%d, num_sub-enc=%u "
                    "rec_gen_code=%u\n", rsp_len, dip[1],
                    sg_get_unaligned_be32(dip + 4));
    } else {
        ret = res;
        goto fini;
    }
    gen_code = sg_get_unaligned_be32(dip + 4);

    if (MODE_DNLD_STATUS == op->mc_mode) {
        show_download_mc_sdg(dip, rsp_len, gen_code);
        goto fini;
    } else if (! want_file) {   /* ACTIVATE and ABORT */
        res = send_then_receive(sg_fd, gen_code, 0, NULL, 0, &dout, dip,
                                din_len, true, op);
        ret = res;
        goto fini;
    }

    res = 0;
    if (op->bpw > 0) {
        for (k = 0, last = false; k < op->mc_len; k += n) {
            n = op->mc_len - k;
            if (n > op->bpw)
                n = op->bpw;
            else
                last = true;
            if (op->verbose)
                pr2serr("bpw loop: mode=0x%x, id=%d, off_off=%d, len=%d, "
                        "last=%d\n", op->mc_mode, op->mc_id, k, n, last);
            res = send_then_receive(sg_fd, gen_code, k, dmp + k, n, &dout,
                                    dip, din_len, last, op);
            if (res)
                break;
        }
        if (op->bpw_then_activate && (0 == res)) {
            op->mc_mode = MODE_ACTIVATE_MC;
            if (op->verbose)
                pr2serr("sending Activate deferred microcode [0xf]\n");
            res = send_then_receive(sg_fd, gen_code, 0, NULL, 0, &dout,
                                    dip, din_len, true, op);
        }
    } else {
        if (op->verbose)
            pr2serr("single: mode=0x%x, id=%d, offset=%d, len=%d\n",
                    op->mc_mode, op->mc_id, op->mc_offset, op->mc_len);
        res = send_then_receive(sg_fd, gen_code, 0, dmp, op->mc_len, &dout,
                                dip, din_len, true, op);
    }
    if (res)
        ret = res;

fini:
    if ((infd >= 0) && (! got_stdin))
        close(infd);
    if (dmp)
        free(dmp);
    if (dout.free_doutp)
        free(dout.free_doutp);
    if (free_dip)
        free(free_dip);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_ses_microcode failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
