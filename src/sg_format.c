/*
 * sg_format : format a SCSI disk
 *             potentially with a different number of blocks and block size
 *
 * formerly called blk512-linux.c (v0.4)
 *
 * Copyright (C) 2003  Grant Grundler    grundler at parisc-linux dot org
 * Copyright (C) 2003  James Bottomley       jejb at parisc-linux dot org
 * Copyright (C) 2005-2020  Douglas Gilbert   dgilbert at interlog dot com
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2, or (at your option)
 *   any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * See http://www.t10.org for relevant standards and drafts. The most recent
 * draft is SBC-4 revision 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"
#include "sg_pt.h"

static const char * version_str = "1.61 20200123";


#define RW_ERROR_RECOVERY_PAGE 1  /* can give alternate with --mode=MP */

#define SHORT_TIMEOUT           20   /* 20 seconds unless --wait given */
#define FORMAT_TIMEOUT          (20 * 3600)       /* 20 hours ! */
#define FOUR_TBYTE      (4LL * 1000 * 1000 * 1000 * 1000)
#define LONG_FORMAT_TIMEOUT     (40 * 3600)       /* 40 hours */
#define EIGHT_TBYTE     (FOUR_TBYTE * 2)
#define VLONG_FORMAT_TIMEOUT    (80 * 3600)       /* 3 days, 8 hours */

#define POLL_DURATION_SECS 60
#define POLL_DURATION_FFMT_SECS 10
#define DEF_POLL_TYPE_RS false     /* false -> test unit ready;
                                      true -> request sense */
#define MAX_BUFF_SZ     252

#if defined(MSC_VER) || defined(__MINGW32__)
#define HAVE_MS_SLEEP
#endif

#ifdef HAVE_MS_SLEEP
#include <windows.h>
#define sleep_for(seconds)    Sleep( (seconds) * 1000)
#else
#define sleep_for(seconds)    sleep(seconds)
#endif

/* FORMAT UNIT (SBC) and FORMAT MEDIUM (SSC) share the same opcode */
#define SG_FORMAT_MEDIUM_CMD 0x4
#define SG_FORMAT_MEDIUM_CMDLEN 6

/* FORMAT WITH PRESET (new in sbc4r18) */
#define SG_FORMAT_WITH_PRESET_CMD 0x38
#define SG_FORMAT_WITH_PRESET_CMDLEN 10

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */

struct opts_t {
        bool cmplst;            /* -C value */
        bool cmplst_given;
        bool dry_run;           /* -d */
        bool early;             /* -e */
        bool fmtmaxlba;         /* -b (only with F_WITH_PRESET) */
        bool fwait;             /* -w (negated form IMMED) */
        bool ip_def;            /* -I */
        bool long_lba;          /* -l */
        bool mode6;             /* -6 */
        bool pinfo;             /* -p, deprecated, prefer fmtpinfo */
        bool poll_type;         /* -x 0|1 */
        bool poll_type_given;
        bool preset;            /* -E */
        bool quick;             /* -Q */
        bool do_rcap16;         /* -l */
        bool resize;            /* -r */
        bool rto_req;           /* -R, deprecated, prefer fmtpinfo */
        bool verbose_given;
        bool verify;            /* -y */
        bool version_given;
        int dcrt;              /* -D (can be given once or twice) */
        int lblk_sz;            /* -s value */
        int ffmt;               /* -t value; fast_format if > 0 */
        int fmtpinfo;
        int format;             /* -F */
        uint32_t p_id;          /* set by argument of --preset=id  */
        int mode_page;          /* -M value */
        int pfu;                /* -P value */
        int pie;                /* -q value */
        int sec_init;           /* -S */
        int tape;               /* -T <format>, def: -1 */
        int timeout;            /* -m SECS, def: depends on IMMED bit */
        int verbose;            /* -v */
        int64_t blk_count;      /* -c value */
        int64_t total_byte_count;      /* from READ CAPACITY command */
        const char * device_name;
};



static struct option long_options[] = {
        {"count", required_argument, 0, 'c'},
        {"cmplst", required_argument, 0, 'C'},
        {"dcrt", no_argument, 0, 'D'},
        {"dry-run", no_argument, 0, 'd'},
        {"dry_run", no_argument, 0, 'd'},
        {"early", no_argument, 0, 'e'},
        {"ffmt", required_argument, 0, 't'},
        {"fmtmaxlba", no_argument, 0, 'b'},
        {"fmtpinfo", required_argument, 0, 'f'},
        {"format", no_argument, 0, 'F'},
        {"help", no_argument, 0, 'h'},
        {"ip-def", no_argument, 0, 'I'},
        {"ip_def", no_argument, 0, 'I'},
        {"long", no_argument, 0, 'l'},
        {"mode", required_argument, 0, 'M'},
        {"pinfo", no_argument, 0, 'p'},
        {"pfu", required_argument, 0, 'P'},
        {"pie", required_argument, 0, 'q'},
        {"poll", required_argument, 0, 'x'},
        {"preset", required_argument, 0, 'E'},
        {"quick", no_argument, 0, 'Q'},
        {"resize", no_argument, 0, 'r'},
        {"rto_req", no_argument, 0, 'R'},
        {"security", no_argument, 0, 'S'},
        {"six", no_argument, 0, '6'},
        {"size", required_argument, 0, 's'},
        {"tape", required_argument, 0, 'T'},
        {"timeout", required_argument, 0, 'm'},
        {"verbose", no_argument, 0, 'v'},
        {"verify", no_argument, 0, 'y'},
        {"version", no_argument, 0, 'V'},
        {"wait", no_argument, 0, 'w'},
        {0, 0, 0, 0},
};


static void
usage()
{
        printf("Usage:\n"
               "  sg_format [--cmplst=0|1] [--count=COUNT] [--dcrt] "
               "[--dry-run] [--early]\n"
               "            [--ffmt=FFMT] [--fmtmaxlba] [--fmtpinfo=FPI] "
               "[--format] [--help]\n"
               "            [--ip-def] [--long] [--mode=MP] [--pfu=PFU] "
               "[--pie=PIE]\n"
               "            [--pinfo] [--poll=PT] [--preset=ID] [--quick] "
               "[--resize]\n"
               "            [--rto_req] [--security] [--six] [--size=LB_SZ] "
               "[--tape=FM]\n"
               "            [--timeout=SECS] [--verbose] [--verify] "
               "[--version] [--wait]\n"
               "            DEVICE\n"
               "  where:\n"
               "    --cmplst=0|1\n"
               "      -C 0|1        sets CMPLST bit in format cdb "
               "(def: 1; if FFMT: 0)\n"
               "    --count=COUNT|-c COUNT    number of blocks to report "
               "after format or\n"
               "                              resize. Format default is "
               "same as current\n"
               "    --dcrt|-D       disable certification (doesn't "
               "verify media)\n"
               "                    use twice to enable certification and "
               "set FOV bit\n"
               "    --dry-run|-d    bypass device modifying commands (i.e. "
               "don't format)\n"
               "    --early|-e      exit once format started (user can "
               "monitor progress)\n"
               "    --ffmt=FFMT|-t FFMT    fast format (def: 0 -> slow, "
               "may visit every\n"
               "                           block). 1 and 2 are fast formats; "
               "1: after\n"
               "                           format, unwritten data read "
               "without error\n"
               "    --fmtpinfo=FPI|-f FPI    FMTPINFO field value "
               "(default: 0)\n"
               "    --format|-F     do FORMAT UNIT (default: report current "
               "count and size)\n"
               "                    use thrice for FORMAT UNIT command "
               "only\n"
               "    --fmtmaxlba|-b    sets FMTMAXLBA field in FORMAT WITH "
               "PRESET\n"
               "    --help|-h       prints out this usage message\n"
               "    --ip-def|-I     use default initialization pattern\n"
               "    --long|-l       allow for 64 bit lbas (default: assume "
               "32 bit lbas)\n"
               "    --mode=MP|-M MP     mode page (def: 1 -> RW error "
               "recovery mpage)\n"
               "    --pie=PIE|-q PIE    Protection Information Exponent "
               "(default: 0)\n"
               "    --pinfo|-p      set upper bit of FMTPINFO field\n"
               "                    (deprecated, use '--fmtpinfo=FPI' "
               "instead)\n"
               "    --poll=PT|-x PT    PT is poll type, 0 for test unit "
               "ready\n"
               "                       1 for request sense (def: 0 (1 "
               "for tape and\n"
               "                       format with preset))\n");
        printf("    --preset=ID|-E ID    do FORMAT WITH PRESET command "
               "with PRESET\n"
               "                         IDENTIFIER field set to ID\n"
               "    --quick|-Q      start format without pause for user "
               "intervention\n"
               "                    (i.e. no time to reconsider)\n"
               "    --resize|-r     resize (rather than format) to COUNT "
               "value\n"
               "    --rto_req|-R    set lower bit of FMTPINFO field\n"
               "                    (deprecated use '--fmtpinfo=FPI' "
               "instead)\n"
               "    --security|-S    set security initialization (SI) bit\n"
               "    --six|-6        use 6 byte MODE SENSE/SELECT to probe "
               "disk\n"
               "                    (def: use 10 byte MODE SENSE/SELECT)\n"
               "    --size=LB_SZ|-s LB_SZ    bytes per logical block, "
               "defaults to DEVICE's\n"
               "                           current logical block size. Only "
               "needed to\n"
               "                           change current logical block "
               "size\n"
               "    --tape=FM|-T FM    request FORMAT MEDIUM with FORMAT "
               "field set\n"
               "                       to FM (def: 0 --> default format)\n"
               "    --timeout=SECS|-m SECS    FORMAT UNIT/MEDIUM command "
               "timeout in seconds\n"
               "    --verbose|-v    increase verbosity\n"
               "    --verify|-y     sets VERIFY bit in FORMAT MEDIUM (tape)\n"
               "    --version|-V    print version details and exit\n"
               "    --wait|-w       format commands wait until format "
               "operations complete\n"
               "                    (default: set IMMED=1 and poll with "
               "Test Unit Ready)\n\n"
               "\tExample: sg_format --format /dev/sdc\n\n"
               "This utility formats a SCSI disk [FORMAT UNIT] or resizes "
               "it. Alternatively\nif '--tape=FM' is given formats a tape "
               "[FORMAT MEDIUM]. Another alternative\nis doing the FORMAT "
               "WITH PRESET command when '--preset=ID' is given.\n\n");
        printf("WARNING: This utility will destroy all the data on the "
               "DEVICE when\n\t '--format', '--tape=FM' or '--preset=ID' "
               "is given. Double check\n\t that you have specified the "
               "correct DEVICE.\n");
}

/* Invokes a SCSI FORMAT MEDIUM command (SSC).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_format_medium(int sg_fd, bool verify, bool immed, int format,
                    void * paramp, int transfer_len, int timeout, bool noisy,
                    int verbose)
{
        int ret, res, sense_cat;
        uint8_t fm_cdb[SG_FORMAT_MEDIUM_CMDLEN] =
                                  {SG_FORMAT_MEDIUM_CMD, 0, 0, 0, 0, 0};
        uint8_t sense_b[SENSE_BUFF_LEN];
        struct sg_pt_base * ptvp;

        if (verify)
                fm_cdb[1] |= 0x2;
        if (immed)
                fm_cdb[1] |= 0x1;
        if (format)
                fm_cdb[2] |= (0xf & format);
        if (transfer_len > 0)
                sg_put_unaligned_be16(transfer_len, fm_cdb + 3);
        if (verbose) {
                char b[128];

                pr2serr("    Format medium cdb: %s\n",
                        sg_get_command_str(fm_cdb, SG_FORMAT_MEDIUM_CMDLEN,
                                           false, sizeof(b), b));
        }

        ptvp = construct_scsi_pt_obj();
        if (NULL == ptvp) {
                pr2serr("%s: out of memory\n", __func__);
                return sg_convert_errno(ENOMEM);
        }
        set_scsi_pt_cdb(ptvp, fm_cdb, sizeof(fm_cdb));
        set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
        set_scsi_pt_data_out(ptvp, (uint8_t *)paramp, transfer_len);
        res = do_scsi_pt(ptvp, sg_fd, timeout, verbose);
        ret = sg_cmds_process_resp(ptvp, "format medium", res, noisy,
                                   verbose, &sense_cat);
        if (-1 == ret)
                ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
        else if (-2 == ret) {
                switch (sense_cat) {
                case SG_LIB_CAT_RECOVERED:
                case SG_LIB_CAT_NO_SENSE:
                        ret = 0;
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

/* Invokes a SCSI FORMAT WITH PRESET command (SBC).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_format_with_preset(int sg_fd, bool immed, bool fmtmaxlba,
                         uint32_t preset_id, int timeout, bool noisy,
                         int verbose)
{
        int ret, res, sense_cat;
        uint8_t fwp_cdb[SG_FORMAT_WITH_PRESET_CMDLEN] =
                     {SG_FORMAT_WITH_PRESET_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        uint8_t sense_b[SENSE_BUFF_LEN];
        struct sg_pt_base * ptvp;

        if (immed)
                fwp_cdb[1] |= 0x80;
        if (fmtmaxlba)
                fwp_cdb[1] |= 0x40;
        if (preset_id > 0)
                sg_put_unaligned_be32(preset_id, fwp_cdb + 2);
        if (verbose) {
                char b[128];

                pr2serr("    Format with preset cdb: %s\n",
                        sg_get_command_str(fwp_cdb,
                                           SG_FORMAT_WITH_PRESET_CMDLEN,
                                           false, sizeof(b), b));
        }
        ptvp = construct_scsi_pt_obj();
        if (NULL == ptvp) {
                pr2serr("%s: out of memory\n", __func__);
                return sg_convert_errno(ENOMEM);
        }
        set_scsi_pt_cdb(ptvp, fwp_cdb, sizeof(fwp_cdb));
        set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
        res = do_scsi_pt(ptvp, sg_fd, timeout, verbose);
        ret = sg_cmds_process_resp(ptvp, "format with preset", res, noisy,
                                   verbose, &sense_cat);
        if (-1 == ret)
                ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
        else if (-2 == ret) {
                switch (sense_cat) {
                case SG_LIB_CAT_RECOVERED:
                case SG_LIB_CAT_NO_SENSE:
                        ret = 0;
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

/* Return 0 on success, else see sg_ll_format_unit_v2() */
static int
scsi_format_unit(int fd, const struct opts_t * op)
{
        bool need_param_lst, longlist, ip_desc;
        bool immed = ! op->fwait;
        int res, progress, pr, rem, param_sz, off, resp_len, tmout;
        int poll_wait_secs;
        int vb = op->verbose;
        const int SH_FORMAT_HEADER_SZ = 4;
        const int LONG_FORMAT_HEADER_SZ = 8;
        const int INIT_PATTERN_DESC_SZ = 4;
        const int max_param_sz = LONG_FORMAT_HEADER_SZ + INIT_PATTERN_DESC_SZ;
        uint8_t * param;
        uint8_t * free_param = NULL;
        char b[80];

        param = sg_memalign(max_param_sz, 0, &free_param, false);
        if (NULL == param) {
                pr2serr("%s: unable to obtain heap for parameter list\n",
                        __func__);
                return sg_convert_errno(ENOMEM);
        }
        if (immed)
                tmout = SHORT_TIMEOUT;
        else {
                if (op->total_byte_count > EIGHT_TBYTE)
                        tmout = VLONG_FORMAT_TIMEOUT;
                else if (op->total_byte_count > FOUR_TBYTE)
                        tmout = LONG_FORMAT_TIMEOUT;
                else
                        tmout = FORMAT_TIMEOUT;
        }
        if (op->timeout > tmout)
                tmout = op->timeout;
        longlist = (op->pie > 0);  /* only set LONGLIST if PI_EXPONENT>0 */
        ip_desc = (op->ip_def || op->sec_init);
        off = longlist ? LONG_FORMAT_HEADER_SZ : SH_FORMAT_HEADER_SZ;
        param[0] = op->pfu & 0x7;  /* PROTECTION_FIELD_USAGE (bits 2-0) */
        param[1] = (immed ? 0x2 : 0); /* FOV=0, [DPRY,DCRT,STPF,IP=0] */
        if (1 == op->dcrt)
                param[1] |= 0xa0;     /* FOV=1, DCRT=1 */
        else if (op->dcrt > 1)
                param[1] |= 0x80;     /* FOV=1, DCRT=0 */
        if (ip_desc) {
                param[1] |= 0x88;     /* FOV=1, IP=1 */
                if (op->sec_init)
                        param[off + 0] = 0x20; /* SI=1 in IP desc */
        }
        if (longlist)
                param[3] = (op->pie & 0xf);/* PROTECTION_INTERVAL_EXPONENT */
        /* with the long parameter list header, P_I_INFORMATION is always 0 */

        need_param_lst = (immed || op->cmplst || (op->dcrt > 0) || ip_desc ||
                          (op->pfu > 0) || (op->pie > 0));
        param_sz = need_param_lst ?
                    (off + (ip_desc ? INIT_PATTERN_DESC_SZ : 0)) : 0;

        if (op->dry_run) {
                res = 0;
                pr2serr("Due to --dry-run option bypassing FORMAT UNIT "
                        "command\n");
                if (vb) {
                        if (need_param_lst) {
                                pr2serr("  FU would have received parameter "
                                        "list: ");
                                hex2stderr(param, max_param_sz, -1);
                        } else
                                pr2serr("  FU would not have received a "
                                        "parameter list\n");
                        pr2serr("  FU cdb fields: fmtpinfo=0x%x, "
                                "longlist=%d, fmtdata=%d, cmplst=%d, "
                                "ffmt=%d [timeout=%d secs]\n",
                                op->fmtpinfo, longlist, need_param_lst,
                                op->cmplst, op->ffmt, tmout);
                }
        } else
                res = sg_ll_format_unit_v2(fd, op->fmtpinfo, longlist,
                                           need_param_lst, op->cmplst, 0,
                                           op->ffmt, tmout, param, param_sz,
                                           true, vb);
        if (free_param)
            free(free_param);

        if (res) {
                sg_get_category_sense_str(res, sizeof(b), b, vb);
                pr2serr("Format unit command: %s\n", b);
                return res;
        }
        if (! immed)
                return 0;

        if (! op->dry_run)
                printf("\nFormat unit has started\n");

        if (op->early) {
                if (immed)
                        printf("Format continuing,\n    request sense or "
                               "test unit ready can be used to monitor "
                               "progress\n");
                return 0;
        }

        if (op->dry_run) {
                printf("No point in polling for progress, so exit\n");
                return 0;
        }
        poll_wait_secs = op->ffmt ? POLL_DURATION_FFMT_SECS :
                                    POLL_DURATION_SECS;
        if (! op->poll_type) {
                for(;;) {
                        sleep_for(poll_wait_secs);
                        progress = -1;
                        res = sg_ll_test_unit_ready_progress(fd, 0, &progress,
                                             true, (vb > 1) ? (vb - 1) : 0);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 656;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
        }
        if (op->poll_type || (SG_LIB_CAT_NOT_READY == res)) {
                uint8_t * reqSense;
                uint8_t * free_reqSense = NULL;

                reqSense = sg_memalign(MAX_BUFF_SZ, 0, &free_reqSense, false);
                if (NULL == reqSense) {
                        pr2serr("%s: unable to obtain heap for Request "
                                "Sense\n", __func__);
                        return sg_convert_errno(ENOMEM);
                }
                for(;;) {
                        sleep_for(poll_wait_secs);
                        memset(reqSense, 0x0, MAX_BUFF_SZ);
                        res = sg_ll_request_sense(fd, false, reqSense,
                                                  MAX_BUFF_SZ, false,
                                                  (vb > 1) ? (vb - 1) : 0);
                        if (res) {
                                pr2serr("polling with Request Sense command "
                                        "failed [res=%d]\n", res);
                                break;
                        }
                        resp_len = reqSense[7] + 8;
                        if (vb > 1) {
                                pr2serr("Parameter data in hex:\n");
                                hex2stderr(reqSense, resp_len, 1);
                        }
                        progress = -1;
                        sg_get_sense_progress_fld(reqSense, resp_len,
                                                  &progress);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 656;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
                if (free_reqSense)
                        free(free_reqSense);
        }
        printf("FORMAT UNIT Complete\n");
        return 0;
}

/* Return 0 on success, else see sg_ll_format_medium() above */
static int
scsi_format_medium(int fd, const struct opts_t * op)
{
        int res, progress, pr, rem, resp_len, tmout;
        int vb = op->verbose;
        bool immed = ! op->fwait;
        char b[80];

        if (immed)
                tmout = SHORT_TIMEOUT;
        else {
                if (op->total_byte_count > EIGHT_TBYTE)
                        tmout = VLONG_FORMAT_TIMEOUT;
                else if (op->total_byte_count > FOUR_TBYTE)
                        tmout = LONG_FORMAT_TIMEOUT;
                else
                        tmout = FORMAT_TIMEOUT;
        }
        if (op->timeout > tmout)
                tmout = op->timeout;
        if (op->dry_run) {
                res = 0;
                pr2serr("Due to --dry-run option bypassing FORMAT MEDIUM "
                        "command\n");
        } else
                res = sg_ll_format_medium(fd, op->verify, immed,
                                          0xf & op->tape, NULL, 0, tmout,
                                          true, vb);
        if (res) {
                sg_get_category_sense_str(res, sizeof(b), b, vb);
                pr2serr("Format medium command: %s\n", b);
                return res;
        }
        if (! immed)
                return 0;

        if (! op->dry_run)
                printf("\nFormat medium has started\n");
        if (op->early) {
                if (immed)
                        printf("Format continuing,\n    request sense or "
                               "test unit ready can be used to monitor "
                               "progress\n");
                return 0;
        }

        if (op->dry_run) {
                printf("No point in polling for progress, so exit\n");
                return 0;
        }
        if (! op->poll_type) {
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        progress = -1;
                        res = sg_ll_test_unit_ready_progress(fd, 0, &progress,
                                             true, (vb > 1) ? (vb - 1) : 0);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 656;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
        }
        if (op->poll_type || (SG_LIB_CAT_NOT_READY == res)) {
                uint8_t * reqSense;
                uint8_t * free_reqSense = NULL;

                reqSense = sg_memalign(MAX_BUFF_SZ, 0, &free_reqSense, false);
                if (NULL == reqSense) {
                        pr2serr("%s: unable to obtain heap for Request "
                                "Sense\n", __func__);
                        return sg_convert_errno(ENOMEM);
                }
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        memset(reqSense, 0x0, MAX_BUFF_SZ);
                        res = sg_ll_request_sense(fd, false, reqSense,
                                                  MAX_BUFF_SZ, false,
                                                  (vb > 1) ? (vb - 1) : 0);
                        if (res) {
                                pr2serr("polling with Request Sense command "
                                        "failed [res=%d]\n", res);
                                break;
                        }
                        resp_len = reqSense[7] + 8;
                        if (vb > 1) {
                                pr2serr("Parameter data in hex:\n");
                                hex2stderr(reqSense, resp_len, 1);
                        }
                        progress = -1;
                        sg_get_sense_progress_fld(reqSense, resp_len,
                                                  &progress);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 656;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
                if (free_reqSense)
                        free(free_reqSense);
        }
        printf("FORMAT MEDIUM Complete\n");
        return 0;
}

/* Return 0 on success, else see sg_ll_format_medium() above */
static int
scsi_format_with_preset(int fd, const struct opts_t * op)
{
        int res, progress, pr, rem, resp_len, tmout;
        int vb = op->verbose;
        bool immed = ! op->fwait;
        char b[80];

        if (immed)
                tmout = SHORT_TIMEOUT;
        else {
                if (op->total_byte_count > EIGHT_TBYTE)
                        tmout = VLONG_FORMAT_TIMEOUT;
                else if (op->total_byte_count > FOUR_TBYTE)
                        tmout = LONG_FORMAT_TIMEOUT;
                else
                        tmout = FORMAT_TIMEOUT;
        }
        if (op->timeout > tmout)
                tmout = op->timeout;
        if (op->dry_run) {
                res = 0;
                pr2serr("Due to --dry-run option bypassing FORMAT WITH "
                        "PRESET command\n");
        } else
                res = sg_ll_format_with_preset(fd, immed, op->fmtmaxlba,
                                               op->p_id, tmout, true, vb);
        if (res) {
                sg_get_category_sense_str(res, sizeof(b), b, vb);
                pr2serr("Format with preset command: %s\n", b);
                return res;
        }
        if (! immed)
                return 0;

        if (! op->dry_run)
                printf("\nFormat with preset has started\n");
        if (op->early) {
                if (immed)
                        printf("Format continuing,\n    Request sense can "
                               "be used to monitor progress\n");
                return 0;
        }

        if (op->dry_run) {
                printf("No point in polling for progress, so exit\n");
                return 0;
        }
        if (! op->poll_type) {
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        progress = -1;
                        res = sg_ll_test_unit_ready_progress(fd, 0, &progress,
                                             true, (vb > 1) ? (vb - 1) : 0);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 656;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
        }
        if (op->poll_type || (SG_LIB_CAT_NOT_READY == res)) {
                uint8_t * reqSense;
                uint8_t * free_reqSense = NULL;

                reqSense = sg_memalign(MAX_BUFF_SZ, 0, &free_reqSense, false);
                if (NULL == reqSense) {
                        pr2serr("%s: unable to obtain heap for Request "
                                "Sense\n", __func__);
                        return sg_convert_errno(ENOMEM);
                }
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        memset(reqSense, 0x0, MAX_BUFF_SZ);
                        res = sg_ll_request_sense(fd, false, reqSense,
                                                  MAX_BUFF_SZ, false,
                                                  (vb > 1) ? (vb - 1) : 0);
                        if (res) {
                                pr2serr("polling with Request Sense command "
                                        "failed [res=%d]\n", res);
                                break;
                        }
                        resp_len = reqSense[7] + 8;
                        if (vb > 1) {
                                pr2serr("Parameter data in hex:\n");
                                hex2stderr(reqSense, resp_len, 1);
                        }
                        progress = -1;
                        sg_get_sense_progress_fld(reqSense, resp_len,
                                                  &progress);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 656;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
                if (free_reqSense)
                        free(free_reqSense);
        }
        printf("FORMAT WITH PRESET Complete\n");
        return 0;
}

#define VPD_DEVICE_ID 0x83
#define VPD_ASSOC_LU 0
#define VPD_ASSOC_TPORT 1
#define TPROTO_ISCSI 5

static char *
get_lu_name(const uint8_t * bp, int u_len, char * b, int b_len)
{
        int len, off, sns_dlen, dlen, k;
        uint8_t u_sns[512];
        char * cp;

        len = u_len - 4;
        bp += 4;
        off = -1;
        if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                    8 /* SCSI name string (sns) */,
                                    3 /* UTF-8 */)) {
                sns_dlen = bp[off + 3];
                memcpy(u_sns, bp + off + 4, sns_dlen);
                /* now want to check if this is iSCSI */
                off = -1;
                if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_TPORT,
                                            8 /* SCSI name string (sns) */,
                                            3 /* UTF-8 */)) {
                        if ((0x80 & bp[1]) &&
                            (TPROTO_ISCSI == (bp[0] >> 4))) {
                                snprintf(b, b_len, "%.*s", sns_dlen, u_sns);
                                return b;
                        }
                }
        } else
                sns_dlen = 0;
        if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                    3 /* NAA */, 1 /* binary */)) {
                dlen = bp[off + 3];
                if (! ((8 == dlen) || (16 ==dlen)))
                        return b;
                cp = b;
                for (k = 0; ((k < dlen) && (b_len > 1)); ++k) {
                        snprintf(cp, b_len, "%02x", bp[off + 4 + k]);
                        cp += 2;
                        b_len -= 2;
                }
        } else if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                           2 /* EUI */, 1 /* binary */)) {
                dlen = bp[off + 3];
                if (! ((8 == dlen) || (12 == dlen) || (16 ==dlen)))
                        return b;
                cp = b;
                for (k = 0; ((k < dlen) && (b_len > 1)); ++k) {
                        snprintf(cp, b_len, "%02x", bp[off + 4 + k]);
                        cp += 2;
                        b_len -= 2;
                }
        } else if (sns_dlen > 0)
                snprintf(b, b_len, "%.*s", sns_dlen, u_sns);
        return b;
}

#define SAFE_STD_INQ_RESP_LEN 36
#define VPD_SUPPORTED_VPDS 0x0
#define VPD_UNIT_SERIAL_NUM 0x80
#define VPD_DEVICE_ID 0x83
#define MAX_VPD_RESP_LEN 256

static int
print_dev_id(int fd, uint8_t * sinq_resp, int max_rlen,
             const struct opts_t * op)
{
        int k, n, verb, pdt, has_sn, has_di;
        int res = 0;
        uint8_t  * b;
        uint8_t  * free_b = NULL;
        char a[MAX_VPD_RESP_LEN];
        char pdt_name[64];

        verb = (op->verbose > 1) ? op->verbose - 1 : 0;
        memset(sinq_resp, 0, max_rlen);
        b = sg_memalign(MAX_VPD_RESP_LEN, 0, &free_b, false);
        if (NULL == b) {
                res = sg_convert_errno(ENOMEM);
                goto out;
        }
        /* Standard INQUIRY */
        res = sg_ll_inquiry(fd, false, false, 0, b, SAFE_STD_INQ_RESP_LEN,
                            true, verb);
        if (res)
                goto out;
        n = b[4] + 5;
        if (n > SAFE_STD_INQ_RESP_LEN)
                n = SAFE_STD_INQ_RESP_LEN;
        memcpy(sinq_resp, b, (n < max_rlen) ? n : max_rlen);
        if (n == SAFE_STD_INQ_RESP_LEN) {
                pdt = b[0] & 0x1f;
                printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n",
                       (const char *)(b + 8), (const char *)(b + 16),
                       (const char *)(b + 32),
                       sg_get_pdt_str(pdt, sizeof(pdt_name), pdt_name), pdt);
                if (op->verbose)
                        printf("      PROTECT=%d\n", !!(b[5] & 1));
                if (b[5] & 1)
                        printf("      << supports protection information>>"
                               "\n");
        } else {
                pr2serr("Short INQUIRY response: %d bytes, expect at least "
                        "36\n", n);
                res = SG_LIB_CAT_OTHER;
                goto out;
        }
        res = sg_ll_inquiry(fd, false, true, VPD_SUPPORTED_VPDS, b,
                            SAFE_STD_INQ_RESP_LEN, true, verb);
        if (res) {
                if (op->verbose)
                        pr2serr("VPD_SUPPORTED_VPDS gave res=%d\n", res);
                res = 0;
                goto out;
        }
        if (VPD_SUPPORTED_VPDS != b[1]) {
                if (op->verbose)
                        pr2serr("VPD_SUPPORTED_VPDS corrupted\n");
                goto out;
        }
        n = sg_get_unaligned_be16(b + 2);
        if (n > (SAFE_STD_INQ_RESP_LEN - 4))
                n = (SAFE_STD_INQ_RESP_LEN - 4);
        for (k = 0, has_sn = 0, has_di = 0; k < n; ++k) {
                if (VPD_UNIT_SERIAL_NUM == b[4 + k])
                        ++has_sn;
                else if (VPD_DEVICE_ID == b[4 + k]) {
                        ++has_di;
                        break;
                }
        }
        if (has_sn) {
                res = sg_ll_inquiry(fd, false, true /* evpd */,
                                    VPD_UNIT_SERIAL_NUM, b, MAX_VPD_RESP_LEN,
                                    true, verb);
                if (res) {
                        if (op->verbose)
                                pr2serr("VPD_UNIT_SERIAL_NUM gave res=%d\n",
                                        res);
                        res = 0;
                        goto out;
                }
                if (VPD_UNIT_SERIAL_NUM != b[1]) {
                        if (op->verbose)
                                pr2serr("VPD_UNIT_SERIAL_NUM corrupted\n");
                        goto out;
                }
                n = sg_get_unaligned_be16(b + 2);
                if (n > (int)(MAX_VPD_RESP_LEN - 4))
                        n = (MAX_VPD_RESP_LEN - 4);
                printf("      Unit serial number: %.*s\n", n,
                       (const char *)(b + 4));
        }
        if (has_di) {
                res = sg_ll_inquiry(fd, false, true /* evpd */, VPD_DEVICE_ID,
                                    b, MAX_VPD_RESP_LEN, true, verb);
                if (res) {
                        if (op->verbose)
                                pr2serr("VPD_DEVICE_ID gave res=%d\n", res);
                        res = 0;
                        goto out;
                }
                if (VPD_DEVICE_ID != b[1]) {
                        if (op->verbose)
                                pr2serr("VPD_DEVICE_ID corrupted\n");
                        goto out;
                }
                n = sg_get_unaligned_be16(b + 2);
                if (n > (int)(MAX_VPD_RESP_LEN - 4))
                        n = (MAX_VPD_RESP_LEN - 4);
                n = strlen(get_lu_name(b, n + 4, a, sizeof(a)));
                if (n > 0)
                        printf("      LU name: %.*s\n", n, a);
        }
out:
        if (free_b)
                free(free_b);
        return res;
}

#define RCAP_REPLY_LEN 32

/* Returns block size or -2 if do_16==0 and the number of blocks is too
 * big, or returns -1 for other error. */
static int
print_read_cap(int fd, struct opts_t * op)
{
        int res = 0;
        uint8_t * resp_buff;
        uint8_t * free_resp_buff = NULL;
        unsigned int last_blk_addr, block_size;
        uint64_t llast_blk_addr;
        int64_t ll;
        char b[80];

        resp_buff = sg_memalign(RCAP_REPLY_LEN, 0, &free_resp_buff, false);
        if (NULL == resp_buff) {
                pr2serr("%s: unable to obtain heap\n", __func__);
                res = -1;
                goto out;
        }
        if (op->do_rcap16) {
                res = sg_ll_readcap_16(fd, false /* pmi */, 0 /* llba */,
                                       resp_buff, RCAP_REPLY_LEN, true,
                                       op->verbose);
                if (0 == res) {
                        llast_blk_addr = sg_get_unaligned_be64(resp_buff + 0);
                        block_size = sg_get_unaligned_be32(resp_buff + 8);
                        printf("Read Capacity (16) results:\n");
                        printf("   Protection: prot_en=%d, p_type=%d, "
                               "p_i_exponent=%d\n",
                               !!(resp_buff[12] & 0x1),
                               ((resp_buff[12] >> 1) & 0x7),
                               ((resp_buff[13] >> 4) & 0xf));
                        printf("   Logical block provisioning: lbpme=%d, "
                               "lbprz=%d\n", !!(resp_buff[14] & 0x80),
                               !!(resp_buff[14] & 0x40));
                        printf("   Logical blocks per physical block "
                               "exponent=%d\n", resp_buff[13] & 0xf);
                        printf("   Lowest aligned logical block address=%d\n",
                               0x3fff & sg_get_unaligned_be16(resp_buff +
                                                              14));
                        printf("   Number of logical blocks=%" PRIu64 "\n",
                               llast_blk_addr + 1);
                        printf("   Logical block size=%u bytes\n",
                               block_size);
                        ll = (int64_t)(llast_blk_addr + 1) * block_size;
                        if (ll > op->total_byte_count)
                                op->total_byte_count = ll;
                        res = (int)block_size;
                        goto out;
                }
        } else {
                res = sg_ll_readcap_10(fd, false /* pmi */, 0 /* lba */,
                                       resp_buff, 8, true, op->verbose);
                if (0 == res) {
                        last_blk_addr = sg_get_unaligned_be32(resp_buff + 0);
                        block_size = sg_get_unaligned_be32(resp_buff + 4);
                        if (0xffffffff == last_blk_addr) {
                                if (op->verbose)
                                        printf("Read Capacity (10) response "
                                               "indicates that Read Capacity "
                                               "(16) is required\n");
                                res = -2;
                                goto out;
                        }
                        printf("Read Capacity (10) results:\n");
                        printf("   Number of logical blocks=%u\n",
                               last_blk_addr + 1);
                        printf("   Logical block size=%u bytes\n",
                               block_size);
                        ll = (int64_t)(last_blk_addr + 1) * block_size;
                        if (ll > op->total_byte_count)
                                op->total_byte_count = ll;
                        res = (int)block_size;
                        goto out;
                }
        }
        sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
        pr2serr("READ CAPACITY (%d): %s\n", (op->do_rcap16 ? 16 : 10), b);
        res = -1;
out:
        if (free_resp_buff)
                free(free_resp_buff);
        return res;
}

/* Use MODE SENSE(6 or 10) to fetch blocks descriptor(s), if any. Analyze
 * the first block descriptor and if required, start preparing for a
 * MODE SELECT(6 or 10). Returns 0 on success. */
static int
fetch_block_desc(int fd, uint8_t * dbuff, int * calc_lenp, int * bd_lb_szp,
                 struct opts_t * op)
{
        bool first = true;
        bool prob;
        int bd_lbsz, bd_len, dev_specific_param, offset, res, rq_lb_sz;
        int rsp_len;
        int resid = 0;
        int vb = op->verbose;
        uint64_t ull;
        int64_t ll;
        char b[80];

again_with_long_lba:
        memset(dbuff, 0, MAX_BUFF_SZ);
        if (op->mode6)
                res = sg_ll_mode_sense6(fd, false /* DBD */, 0 /* current */,
                                        op->mode_page, 0 /* subpage */, dbuff,
                                        MAX_BUFF_SZ, true, vb);
        else
                res = sg_ll_mode_sense10_v2(fd, op->long_lba, false /* DBD */,
                                            0 /* current */, op->mode_page,
                                            0 /* subpage */, dbuff,
                                            MAX_BUFF_SZ, 0, &resid, true,
                                            vb);
        if (res) {
                if (SG_LIB_CAT_ILLEGAL_REQ == res) {
                        if (op->long_lba && (! op->mode6))
                                pr2serr("bad field in MODE SENSE (%d) "
                                        "[longlba flag not supported?]\n",
                                        (op->mode6 ? 6 : 10));
                        else
                                pr2serr("bad field in MODE SENSE (%d) "
                                        "[mode_page %d not supported?]\n",
                                        (op->mode6 ? 6 : 10), op->mode_page);
                } else {
                        sg_get_category_sense_str(res, sizeof(b), b, vb);
                        pr2serr("MODE SENSE (%d) command: %s\n",
                                (op->mode6 ? 6 : 10), b);
                }
                if (0 == vb)
                        pr2serr("    try '-v' for more information\n");
                return res;
        }
        rsp_len = (resid > 0) ? (MAX_BUFF_SZ - resid) : MAX_BUFF_SZ;
        if (rsp_len < 0) {
                pr2serr("%s: resid=%d implies negative response "
                        "length of %d\n", __func__, resid, rsp_len);
                return SG_LIB_WILD_RESID;
        }
        *calc_lenp = sg_msense_calc_length(dbuff, rsp_len, op->mode6, &bd_len);
        if (op->mode6) {
                if (rsp_len < 4) {
                        pr2serr("%s: MS(6) response length too short (%d)\n",
                                __func__, rsp_len);
                        return SG_LIB_CAT_MALFORMED;
                }
                dev_specific_param = dbuff[2];
                op->long_lba = false;
                offset = 4;
                /* prepare for mode select */
                dbuff[0] = 0;
                dbuff[1] = 0;
                dbuff[2] = 0;
        } else {        /* MODE SENSE(10) */
                if (rsp_len < 8) {
                        pr2serr("%s: MS(10) response length too short (%d)\n",
                                __func__, rsp_len);
                        return SG_LIB_CAT_MALFORMED;
                }
                dev_specific_param = dbuff[3];
                op->long_lba = !! (dbuff[4] & 1);
                offset = 8;
                /* prepare for mode select */
                dbuff[0] = 0;
                dbuff[1] = 0;
                dbuff[2] = 0;
                dbuff[3] = 0;
        }
        if (rsp_len < *calc_lenp) {
                pr2serr("%s: MS response length truncated (%d < %d)\n",
                        __func__, rsp_len, *calc_lenp);
                return SG_LIB_CAT_MALFORMED;
        }
        if ((offset + bd_len) < *calc_lenp)
                dbuff[offset + bd_len] &= 0x7f;  /* clear PS bit in mpage */
        prob = false;
        bd_lbsz = 0;
        *bd_lb_szp = bd_lbsz;
        rq_lb_sz = op->lblk_sz;
        if (first) {
                first = false;
                printf("Mode Sense (block descriptor) data, prior to "
                       "changes:\n");
        }
        if (dev_specific_param & 0x40)
                printf("  <<< Write Protect (WP) bit set >>>\n");
        if (bd_len > 0) {
                ull = op->long_lba ? sg_get_unaligned_be64(dbuff + offset) :
                                 sg_get_unaligned_be32(dbuff + offset);
                bd_lbsz = op->long_lba ?
                                 sg_get_unaligned_be32(dbuff + offset + 12) :
                                 sg_get_unaligned_be24(dbuff + offset + 5);
                *bd_lb_szp = bd_lbsz;
                if (! op->long_lba) {
                        if (0xffffffff == ull) {
                                if (vb)
                                        pr2serr("block count maxed out, set "
                                                "<<longlba>>\n");
                                op->long_lba = true;
                                op->mode6 = false;
                                op->do_rcap16 = true;
                                goto again_with_long_lba;
                        } else if ((rq_lb_sz > 0) && (rq_lb_sz < bd_lbsz) &&
                                   (((ull * bd_lbsz) / rq_lb_sz) >=
                                    0xffffffff)) {
                                if (vb)
                                        pr2serr("number of blocks will max "
                                                "out, set <<longlba>>\n");
                                op->long_lba = true;
                                op->mode6 = false;
                                op->do_rcap16 = true;
                                goto again_with_long_lba;
                        }
                }
                if (op->long_lba) {
                        printf("  <<< longlba flag set (64 bit lba) >>>\n");
                        if (bd_len != 16)
                                prob = true;
                } else if (bd_len != 8)
                        prob = true;
                printf("  Number of blocks=%" PRIu64 " [0x%" PRIx64 "]\n",
                       ull, ull);
                printf("  Block size=%d [0x%x]\n", bd_lbsz, bd_lbsz);
                ll = (int64_t)ull * bd_lbsz;
                if (ll > op->total_byte_count)
                        op->total_byte_count = ll;
        } else {
                printf("  No block descriptors present\n");
                prob = true;
        }
        if (op->resize || (op->format && ((op->blk_count != 0) ||
              ((rq_lb_sz > 0) && (rq_lb_sz != bd_lbsz))))) {
                /* want to run MODE SELECT, prepare now */

                if (prob) {
                        pr2serr("Need to perform MODE SELECT (to change "
                                "number or blocks or block length)\n");
                        pr2serr("but (single) block descriptor not found "
                                "in earlier MODE SENSE\n");
                        return SG_LIB_CAT_MALFORMED;
                }
                if (op->blk_count != 0)  { /* user supplied blk count */
                        if (op->long_lba)
                                sg_put_unaligned_be64(op->blk_count,
                                                      dbuff + offset);
                        else
                                sg_put_unaligned_be32(op->blk_count,
                                                      dbuff + offset);
                } else if ((rq_lb_sz > 0) && (rq_lb_sz != bd_lbsz))
                        /* 0 implies max capacity with new LB size */
                        memset(dbuff + offset, 0, op->long_lba ? 8 : 4);

                if ((rq_lb_sz > 0) && (rq_lb_sz != bd_lbsz)) {
                        if (op->long_lba)
                                sg_put_unaligned_be32((uint32_t)rq_lb_sz,
                                                      dbuff + offset + 12);
                        else
                                sg_put_unaligned_be24((uint32_t)rq_lb_sz,
                                                      dbuff + offset + 5);
                }
        }
        return 0;
}

static int
parse_cmd_line(struct opts_t * op, int argc, char **argv)
{
        int j;
        int64_t ll;

        op->cmplst = true;      /* will be set false if FFMT > 0 */
        op->mode_page = RW_ERROR_RECOVERY_PAGE;
        op->poll_type = DEF_POLL_TYPE_RS;
        op->tape = -1;
        while (1) {
                int option_index = 0;
                int c;

                c = getopt_long(argc, argv,
                                "bc:C:dDeE:f:FhIlm:M:pP:q:QrRs:St:T:vVwx:y6",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'b':
                        op->fmtmaxlba = true;
                        break;
                case 'c':
                        if (0 == strcmp("-1", optarg))
                                op->blk_count = -1;
                        else {
                                op->blk_count = sg_get_llnum(optarg);
                                if (-1 == op->blk_count) {
                                        pr2serr("bad argument to '--count'\n");
                                        return SG_LIB_SYNTAX_ERROR;
                                }
                        }
                        break;
                case 'C':
                        j = sg_get_num(optarg);
                        if ((j < 0) || (j > 1)) {
                                pr2serr("bad argument to '--cmplst', want 0 "
                                        "or 1\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        op->cmplst_given = true;
                        op->cmplst = !! j;
                        break;
                case 'd':
                        op->dry_run = true;
                        break;
                case 'D':
                        ++op->dcrt;
                        break;
                case 'e':
                        op->early = true;
                        break;
                case 'E':
                        ll = sg_get_llnum(optarg);
                        if ((ll < 0) || (ll > UINT32_MAX)) {
                                pr2serr("bad argument to '--preset', need 32 "
                                        "bit integer\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        op->p_id = (uint32_t)ll;
                        op->preset = true;
                        op->poll_type = 1;      /* poll with REQUEST SENSE */
                        break;
                case 'f':
                        op->fmtpinfo = sg_get_num(optarg);
                        if ((op->fmtpinfo < 0) || ( op->fmtpinfo > 3)) {
                                pr2serr("bad argument to '--fmtpinfo', "
                                        "accepts 0 to 3 inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'F':
                        ++op->format;
                        break;
                case 'h':
                        usage();
                        return SG_LIB_OK_FALSE;
                case 'I':
                        op->ip_def = true;
                        break;
                case 'l':
                        op->long_lba = true;
                        op->do_rcap16 = true;
                        break;
                case 'm':
                        op->timeout = sg_get_num(optarg);
                        if (op->timeout < 0) {
                                pr2serr("bad argument to '--timeout=', "
                                        "accepts 0 or more\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'M':
                        op->mode_page = sg_get_num(optarg);
                        if ((op->mode_page < 0) || ( op->mode_page > 62)) {
                                pr2serr("bad argument to '--mode', accepts "
                                        "0 to 62 inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'p':
                        op->pinfo = true;
                        break;
                case 'P':
                        op->pfu = sg_get_num(optarg);
                        if ((op->pfu < 0) || ( op->pfu > 7)) {
                                pr2serr("bad argument to '--pfu', accepts 0 "
                                        "to 7 inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'q':
                        op->pie = sg_get_num(optarg);
                        if ((op->pie < 0) || (op->pie > 15)) {
                                pr2serr("bad argument to '--pie', accepts 0 "
                                        "to 15 inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'Q':
                        op->quick = true;
                        break;
                case 'r':
                        op->resize = true;
                        break;
                case 'R':
                        op->rto_req = true;
                        break;
                case 's':
                        op->lblk_sz = sg_get_num(optarg);
                        if (op->lblk_sz <= 0) {
                                pr2serr("bad argument to '--size', want arg "
                                        "> 0\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'S':
                        op->sec_init = true;
                        break;
                case 't':
                        op->ffmt = sg_get_num(optarg);
                        if ((op->ffmt < 0) || ( op->ffmt > 3)) {
                                pr2serr("bad argument to '--ffmt', "
                                        "accepts 0 to 3 inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'T':
                        if (('-' == optarg[0]) && ('1' == optarg[1]) &&
                            ('\0' == optarg[2])) {
                                op->tape = -1;
                                break;
                        }
                        op->tape = sg_get_num(optarg);
                        if ((op->tape < 0) || ( op->tape > 15)) {
                                pr2serr("bad argument to '--tape', accepts "
                                        "0 to 15 inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'v':
                        op->verbose_given = true;
                        op->verbose++;
                        break;
                case 'V':
                        op->version_given = true;
                        break;
                case 'w':
                        op->fwait = true;
                        break;
                case 'x':       /* false: TUR; true: request sense */
                        op->poll_type = !! sg_get_num(optarg);
                        op->poll_type_given = true;
                        break;
                case 'y':
                        op->verify = true;
                        break;
                case '6':
                        op->mode6 = true;
                        break;
                default:
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
        }
        if (optind < argc) {
                if (NULL == op->device_name) {
                        op->device_name = argv[optind];
                        ++optind;
                }
        }
        if (optind < argc) {
                for (; optind < argc; ++optind)
                        pr2serr("Unexpected extra argument: %s\n",
                                argv[optind]);
                usage();
                return SG_LIB_SYNTAX_ERROR;
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
                pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
        if (op->version_given) {
                pr2serr("sg_format version: %s\n", version_str);
                return SG_LIB_OK_FALSE;
        }
        if (NULL == op->device_name) {
                pr2serr("no DEVICE name given\n\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }
        if (((int)(op->format > 0) + (int)(op->tape >= 0) + (int)op->preset)
            > 1) {
                pr2serr("Can choose only one of: '--format', '--tape=' and "
                        "'--preset='\n");
                return SG_LIB_CONTRADICT;
        }
        if (op->ip_def && op->sec_init) {
                pr2serr("'--ip_def' and '--security' contradict, choose "
                        "one\n");
                return SG_LIB_CONTRADICT;
        }
        if (op->resize) {
                if (op->format) {
                        pr2serr("both '--format' and '--resize' not "
                                "permitted\n");
                        usage();
                        return SG_LIB_CONTRADICT;
                } else if (0 == op->blk_count) {
                        pr2serr("'--resize' needs a '--count' (other than "
                                "0)\n");
                        usage();
                        return SG_LIB_CONTRADICT;
                } else if (0 != op->lblk_sz) {
                        pr2serr("'--resize' not compatible with '--size'\n");
                        usage();
                        return SG_LIB_CONTRADICT;
                }
        }
        if ((op->pinfo > 0) || (op->rto_req > 0) || (op->fmtpinfo > 0)) {
                if ((op->pinfo || op->rto_req) && op->fmtpinfo) {
                        pr2serr("confusing with both '--pinfo' or "
                                "'--rto_req' together with\n'--fmtpinfo', "
                                "best use '--fmtpinfo' only\n");
                        usage();
                        return SG_LIB_CONTRADICT;
                }
                if (op->pinfo)
                        op->fmtpinfo |= 2;
                if (op->rto_req)
                        op->fmtpinfo |= 1;
        }
        if ((op->ffmt > 0) && (! op->cmplst_given))
                op->cmplst = false; /* SBC-4 silent; FFMT&&CMPLST unlikely */
        return 0;
}


int
main(int argc, char **argv)
{
        int bd_lb_sz, calc_len, pdt, res, rq_lb_sz, vb;
        int fd = -1;
        int ret = 0;
        const int dbuff_sz = MAX_BUFF_SZ;
        const int inq_resp_sz = SAFE_STD_INQ_RESP_LEN;
        struct opts_t * op;
        uint8_t * dbuff;
        uint8_t * free_dbuff = NULL;
        uint8_t * inq_resp;
        uint8_t * free_inq_resp = NULL;
        struct opts_t opts;
        char b[80];

        op = &opts;
        memset(op, 0, sizeof(opts));
        ret = parse_cmd_line(op, argc, argv);
        if (ret)
                return (SG_LIB_OK_FALSE == ret) ? 0 : ret;
        vb = op->verbose;

        dbuff = sg_memalign(dbuff_sz, 0, &free_dbuff, false);
        inq_resp = sg_memalign(inq_resp_sz, 0, &free_inq_resp, false);
        if ((NULL == dbuff) || (NULL == inq_resp)) {
                pr2serr("Unable to allocate heap\n");
                ret = sg_convert_errno(ENOMEM);
                goto out;
        }

        if ((fd = sg_cmds_open_device(op->device_name, false, vb)) < 0) {
                pr2serr("error opening device file: %s: %s\n",
                        op->device_name, safe_strerror(-fd));
                ret = sg_convert_errno(-fd);
                goto out;
        }

        if (op->format > 2)
                goto format_only;

        ret = print_dev_id(fd, inq_resp, inq_resp_sz, op);
        if (ret) {
                if (op->dry_run) {
                        pr2serr("INQUIRY failed, assume device is a disk\n");
                        pdt = 0;
                } else
                        goto out;
        } else
                pdt = 0x1f & inq_resp[0];
        if (op->format) {
                if ((PDT_DISK != pdt) && (PDT_OPTICAL != pdt) &&
                    (PDT_RBC != pdt)) {
                        pr2serr("This format is only defined for disks "
                                "(using SBC-2 or RBC) and MO media\n");
                        ret = SG_LIB_CAT_MALFORMED;
                        goto out;
                }
        } else if (op->tape >= 0) {
                if (! ((PDT_TAPE == pdt) || (PDT_MCHANGER == pdt) ||
                       (PDT_ADC == pdt))) {
                        pr2serr("This format is only defined for tapes\n");
                        ret = SG_LIB_CAT_MALFORMED;
                        goto out;
                }
                goto format_med;
        } else if (op->preset)
                goto format_with_pre;

        ret = fetch_block_desc(fd, dbuff, &calc_len, &bd_lb_sz, op);
        if (ret) {
                if (op->dry_run) {
                        /* pick some numbers ... */
                        calc_len = 1024 * 1024 * 1024;
                        bd_lb_sz = 512;
                } else
                        goto out;
        }
        rq_lb_sz = op->lblk_sz;
        if (op->resize || (op->format && ((op->blk_count != 0) ||
              ((rq_lb_sz > 0) && (rq_lb_sz != bd_lb_sz))))) {
                /* want to run MODE SELECT */
                if (op->dry_run) {
                        pr2serr("Due to --dry-run option bypass MODE "
                                "SELECT(%d) command\n", (op->mode6 ? 6 : 10));
                        res = 0;
                } else {
                        bool sp = true;   /* may not be able to save pages */

again_sp_false:
                        if (op->mode6)
                                res = sg_ll_mode_select6(fd, true /* PF */,
                                                         sp, dbuff, calc_len,
                                                         true, vb);
                        else
                                res = sg_ll_mode_select10(fd, true /* PF */,
                                                          sp, dbuff, calc_len,
                                                          true, vb);
                        if ((SG_LIB_CAT_ILLEGAL_REQ == res) && sp) {
                                pr2serr("Try MODE SELECT again with SP=0 "
                                        "this time\n");
                                sp = false;
                                goto again_sp_false;
                        }
                }
                ret = res;
                if (res) {
                        sg_get_category_sense_str(res, sizeof(b), b, vb);
                        pr2serr("MODE SELECT command: %s\n", b);
                        if (0 == vb)
                                pr2serr("    try '-v' for more information\n");
                        goto out;
                }
        }
        if (op->resize) {
                printf("Resize operation seems to have been successful\n");
                goto out;
        } else if (! op->format) {
                res = print_read_cap(fd, op);
                if (-2 == res) {
                        op->do_rcap16 = true;
                        res = print_read_cap(fd, op);
                }
                if (res < 0)
                        ret = -1;
                if ((res > 0) && (bd_lb_sz > 0) &&
                    (res != (int)bd_lb_sz)) {
                        printf("  Warning: mode sense and read capacity "
                               "report different block sizes [%d,%d]\n",
                               bd_lb_sz, res);
                        printf("           Probably needs format\n");
                }
                if ((PDT_TAPE == pdt) || (PDT_MCHANGER == pdt) ||
                    (PDT_ADC == pdt))
                        printf("No changes made. To format use '--tape='.\n");
                else
                        printf("No changes made. To format use '--format'. "
                               "To resize use '--resize'\n");
                goto out;
        }

        if (op->format) {
format_only:
                if (op->quick)
                        goto skip_f_unit_reconsider;
                printf("\nA FORMAT UNIT will commence in 15 seconds\n");
                printf("    ALL data on %s will be DESTROYED\n",
                       op->device_name);
                printf("        Press control-C to abort\n");
                sleep_for(5);
                printf("\nA FORMAT UNIT will commence in 10 seconds\n");
                printf("    ALL data on %s will be DESTROYED\n",
                       op->device_name);
                printf("        Press control-C to abort\n");
                sleep_for(5);
                printf("\nA FORMAT UNIT will commence in 5 seconds\n");
                printf("    ALL data on %s will be DESTROYED\n",
                       op->device_name);
                printf("        Press control-C to abort\n");
                sleep_for(5);
skip_f_unit_reconsider:
                res = scsi_format_unit(fd, op);
                ret = res;
                if (res) {
                        pr2serr("FORMAT UNIT failed\n");
                        if (0 == vb)
                                pr2serr("    try '-v' for more "
                                        "information\n");
                }
        }
        goto out;

format_med:
        if (! op->poll_type_given) /* SSC-5 specifies REQUEST SENSE polling */
                op->poll_type = true;
        if (op->quick)
                goto skip_f_med_reconsider;
        printf("\nA FORMAT MEDIUM will commence in 15 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n",
               op->device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
        printf("\nA FORMAT MEDIUM will commence in 10 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n",
               op->device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
        printf("\nA FORMAT MEDIUM will commence in 5 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n",
               op->device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
skip_f_med_reconsider:
        res = scsi_format_medium(fd, op);
        ret = res;
        if (res) {
                pr2serr("FORMAT MEDIUM failed\n");
                if (0 == vb)
                        pr2serr("    try '-v' for more information\n");
        }
        goto out;

format_with_pre:
        if (op->quick)
                goto skip_f_with_pre_reconsider;
        printf("\nA FORMAT WITH PRESET will commence in 15 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n",
               op->device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
        printf("\nA FORMAT WITH PRESET will commence in 10 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n",
               op->device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
        printf("\nA FORMAT WITH PRESET will commence in 5 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n",
               op->device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
skip_f_with_pre_reconsider:
        res = scsi_format_with_preset(fd, op);
        ret = res;
        if (res) {
                pr2serr("FORMAT WITH PRESET failed\n");
                if (0 == vb)
                        pr2serr("    try '-v' for more information\n");
        }

out:
        if (free_dbuff)
                free(free_dbuff);
        if (free_inq_resp)
                free(free_inq_resp);
        if (fd >= 0) {
            res = sg_cmds_close_device(fd);
            if (res < 0) {
                    pr2serr("close error: %s\n", safe_strerror(-res));
                    if (0 == ret)
                            ret = sg_convert_errno(-res);
            }
        }
        if (0 == vb) {
                if (! sg_if_can2stderr("sg_format failed: ", ret))
                        pr2serr("Some error occurred, try again with '-v' "
                                "or '-vv' for more information\n");
        }
        return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
