/*
 * sg_format : format a SCSI disk
 *             potentially with a different number of blocks and block size
 *
 * formerly called blk512-linux.c (v0.4)
 *
 * Copyright (C) 2003  Grant Grundler    grundler at parisc-linux dot org
 * Copyright (C) 2003  James Bottomley       jejb at parisc-linux dot org
 * Copyright (C) 2005-2016  Douglas Gilbert   dgilbert at interlog dot com
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2, or (at your option)
 *   any later version.
 *
 * See http://www.t10.org for relevant standards and drafts. The most recent
 * draft is SBC-4 revision 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
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

static const char * version_str = "1.36 20160423";


#define RW_ERROR_RECOVERY_PAGE 1  /* can give alternate with --mode=MP */

#define SHORT_TIMEOUT           20   /* 20 seconds unless --wait given */
#define FORMAT_TIMEOUT          (20 * 3600)       /* 20 hours ! */
/* Seagate ST32000444SS 2TB disk takes 9.5 hours, now there are 4TB disks */

#define POLL_DURATION_SECS 60
#define DEF_POLL_TYPE 0

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
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */

struct opts_t {
        int64_t blk_count;      /* -c value */
        int blk_size;           /* -s value */
        int cmplst;             /* -C value */
        bool dcrt;              /* -D */
        bool early;             /* -e */
        int ffmt;               /* -t value */
        int fmtpinfo;
        int format;             /* -F */
        bool fwait;             /* -w (negate for immed) */
        bool ip_def;            /* -I */
        bool long_lba;          /* -l */
        int mode_page;          /* -M value */
        bool mode6;             /* -6 */
        int pfu;                /* -P value */
        int pie;                /* -q value */
        bool pinfo;             /* -p, deprecated, prefer fmtpinfo */
        int pollt;              /* -x value */
        bool pollt_given;
        bool do_rcap16;         /* -l */
        bool resize;            /* -r */
        bool rto_req;           /* -R, deprecated, prefer fmtpinfo */
        int sec_init;           /* -S */
        int tape;               /* -T <format>, def: -1 */
        int timeout;            /* -m SEC, def: depends on IMMED bit */
        int verbose;            /* -v */
        int verify;             /* -y */
        const char * device_name;
};

#define MAX_BUFF_SZ     252
static unsigned char dbuff[MAX_BUFF_SZ];


static struct option long_options[] = {
        {"count", required_argument, 0, 'c'},
        {"cmplst", required_argument, 0, 'C'},
        {"dcrt", no_argument, 0, 'D'},
        {"early", no_argument, 0, 'e'},
        {"ffmt", required_argument, 0, 't'},
        {"fmtpinfo", required_argument, 0, 'f'},
        {"format", no_argument, 0, 'F'},
        {"help", no_argument, 0, 'h'},
        {"ip_def", no_argument, 0, 'I'},
        {"long", no_argument, 0, 'l'},
        {"mode", required_argument, 0, 'M'},
        {"pinfo", no_argument, 0, 'p'},
        {"pfu", required_argument, 0, 'P'},
        {"pie", required_argument, 0, 'q'},
        {"poll", required_argument, 0, 'x'},
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
        printf("usage: sg_format [--cmplst=0|1] [--count=COUNT] [--dcrt] "
               "[--early]\n"
               "                 [--ffmt] [--fmtpinfo=FPI] [--format] "
               "[--help] [--ip_def]\n"
               "                 [--long] [--mode=MP] [--pfu=PFU] "
               "[--pie=PIE] [--pinfo]\n"
               "                 [--poll=PT] [--resize] [--rto_req] "
               "[--security] [--six]\n"
               "                 [--size=SIZE] [--tape=FM] [--timeout=SEC] "
               "[--verbose]\n"
               "                 [--verify] [--version] [--wait] DEVICE\n"
               "  where:\n"
               "    --cmplst=0|1\n"
               "      -C 0|1        sets CMPLST bit in format cdb "
               "(default: 1)\n"
               "    --count=COUNT|-c COUNT    number of blocks to report "
               "after format or\n"
               "                              resize. Format default is "
               "same as current\n"
               "    --dcrt|-D       disable certification (doesn't "
               "verify media)\n"
               "    --early|-e      exit once format started (user can "
               "monitor progress)\n"
               "    --ffmt=FFMT|-t FFMT      fast format (def: 0 -> "
               "possibly write\n"
               "                             to whole medium\n"
               "    --fmtpinfo=FPI|-f FPI    FMTPINFO field value "
               "(default: 0)\n"
               "    --format|-F     do FORMAT UNIT (default: report current "
               "count and size)\n"
               "                    use thrice for FORMAT UNIT command "
               "only\n"
               "    --help|-h       prints out this usage message\n"
               "    --ip_def|-I     initialization pattern: default\n"
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
               "for tape))\n");
        printf("    --resize|-r     resize (rather than format) to COUNT "
               "value\n"
               "    --rto_req|-R    set lower bit of FMTPINFO field\n"
               "                    (deprecated use '--fmtpinfo=FPI' "
               "instead)\n"
               "    --security|-S    set security initialization (SI) bit\n"
               "    --six|-6        use 6 byte MODE SENSE/SELECT to probe "
               "disk\n"
               "                    (def: use 10 byte MODE SENSE/SELECT)\n"
               "    --size=SIZE|-s SIZE    bytes per logical block, "
               "defaults to DEVICE's\n"
               "                           current logical block size. Only "
               "needed to\n"
               "                           change current logical block "
               "size\n"
               "    --tape=FM|-T FM    request FORMAT MEDIUM with FORMAT "
               "field set\n"
               "                       to FM (def: 0 --> default format)\n"
               "    --timeout=SEC|-m SEC    FORMAT UNIT/MEDIUM command "
               "timeout in seconds\n"
               "    --verbose|-v    increase verbosity\n"
               "    --verify|-y     sets VERIFY bit in FORMAT MEDIUM (tape)\n"
               "    --version|-V    print version details and exit\n"
               "    --wait|-w       format command waits until format "
               "operation completes\n"
               "                    (default: set IMMED=1 and poll with "
               "Test Unit Ready)\n\n"
               "\tExample: sg_format --format /dev/sdc\n\n"
               "This utility formats a SCSI disk [FORMAT UNIT] or resizes "
               "it. Alternatively\nif '--tape=FM' is given formats a tape "
               "[FORMAT MEDIUM].\n");
        printf("WARNING: This utility will destroy all the data on "
               "DEVICE when '--format'\n\t or '--tape' is given. Check that "
               "you have specified the correct\n\t DEVICE.\n");
}

/* Invokes a SCSI FORMAT MEDIUM command (SSC).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_format_medium(int sg_fd, int verify, int immed, int format,
                    void * paramp, int transfer_len, int timeout, int noisy,
                    int verbose)
{
        int k, ret, res, sense_cat;
        unsigned char fmCmdBlk[SG_FORMAT_MEDIUM_CMDLEN] =
                                  {SG_FORMAT_MEDIUM_CMD, 0, 0, 0, 0, 0};
        unsigned char sense_b[SENSE_BUFF_LEN];
        struct sg_pt_base * ptvp;

        if (verify)
                fmCmdBlk[1] |= 0x2;
        if (immed)
                fmCmdBlk[1] |= 0x1;
        if (format)
                fmCmdBlk[2] |= (0xf & format);
        if (transfer_len > 0)
                sg_put_unaligned_be16(transfer_len, fmCmdBlk + 3);
        if (verbose) {
                pr2serr("    Format medium cdb: ");
                for (k = 0; k < SG_FORMAT_MEDIUM_CMDLEN; ++k)
                        pr2serr("%02x ", fmCmdBlk[k]);
                pr2serr("\n");
        }

        ptvp = construct_scsi_pt_obj();
        if (NULL == ptvp) {
                pr2serr("%s: out of memory\n", __func__);
                return -1;
        }
        set_scsi_pt_cdb(ptvp, fmCmdBlk, sizeof(fmCmdBlk));
        set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
        set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, transfer_len);
        res = do_scsi_pt(ptvp, sg_fd, timeout, verbose);
        ret = sg_cmds_process_resp(ptvp, "format medium", res, transfer_len,
                                   sense_b, noisy, verbose, &sense_cat);
        if (-1 == ret)
                ;
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

/* Return 0 on success, else see sg_ll_format_unit2() */
static int
scsi_format_unit(int fd, const struct opts_t * op)
{
        int res, need_hdr, progress, pr, rem, verb, fmt_pl_sz, longlist, off;
        int resp_len, ip_desc, timeout;
        int immed = ! op->fwait;
        const int SH_FORMAT_HEADER_SZ = 4;
        const int LO_FORMAT_HEADER_SZ = 8;
        const char INIT_PATTERN_DESC_SZ = 4;
        unsigned char fmt_pl[LO_FORMAT_HEADER_SZ + INIT_PATTERN_DESC_SZ];
        unsigned char reqSense[MAX_BUFF_SZ];
        char b[80];

        memset(fmt_pl, 0, sizeof(fmt_pl));
        timeout = (immed ? SHORT_TIMEOUT : FORMAT_TIMEOUT);
        if (op->timeout > timeout)
                timeout = op->timeout;
        longlist = (op->pie > 0);
        ip_desc = (op->ip_def || op->sec_init);
        off = longlist ? LO_FORMAT_HEADER_SZ : SH_FORMAT_HEADER_SZ;
        fmt_pl[0] = op->pfu & 0x7;  /* PROTECTION_FIELD_USAGE (bits 2-0) */
        fmt_pl[1] = (immed ? 0x2 : 0); /* FOV=0, [DPRY,DCRT,STPF,IP=0] */
        if (op->dcrt)
                fmt_pl[1] |= 0xa0;     /* FOV=1, DCRT=1 */
        if (ip_desc) {
                fmt_pl[1] |= 0x88;     /* FOV=1, IP=1 */
                if (op->sec_init)
                        fmt_pl[off + 0] = 0x20; /* SI=1 in IP desc */
        }
        if (longlist)
                fmt_pl[3] = (op->pie & 0xf);/* PROTECTION_INTERVAL_EXPONENT */
        /* with the long parameter list header, P_I_INFORMATION is always 0 */

        need_hdr = (immed || op->cmplst || op->dcrt || ip_desc ||
                    (op->pfu > 0) || (op->pie > 0));
        fmt_pl_sz = 0;
        if (need_hdr)
                fmt_pl_sz = off + (ip_desc ? INIT_PATTERN_DESC_SZ : 0);

        res = sg_ll_format_unit2(fd, op->fmtpinfo, longlist,
                                 need_hdr/* FMTDATA*/, op->cmplst,
                                 0 /* DEFECT_LIST_FORMAT */, op->ffmt,
                                 timeout, fmt_pl, fmt_pl_sz, 1, op->verbose);
        if (res) {
                sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
                pr2serr("Format unit command: %s\n", b);
                return res;
        }
        if (! immed)
                return 0;

        printf("\nFormat unit has started\n");
        if (op->early) {
                if (immed)
                        printf("Format continuing,\n    request sense or "
                               "test unit ready can be used to monitor "
                               "progress\n");
                return 0;
        }

        verb = (op->verbose > 1) ? (op->verbose - 1) : 0;
        if (0 == op->pollt) {
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        progress = -1;
                        res = sg_ll_test_unit_ready_progress(fd, 0, &progress,
                                                             1, verb);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 656;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
        }
        if (op->pollt || (SG_LIB_CAT_NOT_READY == res)) {
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        memset(reqSense, 0x0, sizeof(reqSense));
                        res = sg_ll_request_sense(fd, 0, reqSense,
                                                  sizeof(reqSense), 0, verb);
                        if (res) {
                                pr2serr("polling with Request Sense command "
                                        "failed [res=%d]\n", res);
                                break;
                        }
                        resp_len = reqSense[7] + 8;
                        if (verb) {
                                pr2serr("Parameter data in hex:\n");
                                dStrHexErr((const char *)reqSense, resp_len,
                                           1);
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
        }
#if 0
        for (k = 0; k < num_rs; ++k) {
                if (k > 0)
                        sleep_for(30);
                memset(requestSenseBuff, 0x0, sizeof(requestSenseBuff));
                res = sg_ll_request_sense(sg_fd, desc, requestSenseBuff,
                                          maxlen, 1, op->verbose);
                if (res) {
                        ret = res;
                        sg_get_category_sense_str(res, sizeof(b), b,
                                                  op->verbose);
                        pr2serr("Request Sense command: %s\n", b);
                        break;
                }
                /* "Additional sense length" same in descriptor and fixed */
                resp_len = requestSenseBuff[7] + 8;
                if (op->verbose > 1) {
                        pr2serr("Parameter data in hex\n");
                        dStrHexErr((const char *)requestSenseBuff, resp_len,
                                   1);
                }
                progress = -1;
                sg_get_sense_progress_fld(requestSenseBuff, resp_len,
                                          &progress);
                if (progress < 0) {
                        ret = res;
                        if (op->verbose > 1)
                                pr2serr("No progress indication found, "
                                        "iteration %d\n", k + 1);
                                /* N.B. exits first time there isn't a
                                 * progress indication */
                        break;
                } else
                        printf("Progress indication: %d.%02d%% done\n",
                               (progress * 100) / 65536,
                               ((progress * 100) % 65536) / 656);
        }
#endif
        printf("FORMAT UNIT Complete\n");
        return 0;
}

/* Return 0 on success, else see sg_ll_format_medium() above */
static int
scsi_format_medium(int fd, const struct opts_t * op)
{
        int res, progress, pr, rem, verb, resp_len, timeout;
        int immed = ! op->fwait;
        unsigned char reqSense[MAX_BUFF_SZ];
        char b[80];

        timeout = (immed ? SHORT_TIMEOUT : FORMAT_TIMEOUT);
        if (op->timeout > timeout)
                timeout = op->timeout;
        res = sg_ll_format_medium(fd, op->verify, immed, 0xf & op->tape, NULL,
                                  0, timeout, 1, op->verbose);
        if (res) {
                sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
                pr2serr("Format medium command: %s\n", b);
                return res;
        }
        if (! immed)
                return 0;

        printf("\nFormat medium has started\n");
        if (op->early) {
                if (immed)
                        printf("Format continuing,\n    request sense or "
                               "test unit ready can be used to monitor "
                               "progress\n");
                return 0;
        }

        verb = (op->verbose > 1) ? (op->verbose - 1) : 0;
        if (0 == op->pollt) {
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        progress = -1;
                        res = sg_ll_test_unit_ready_progress(fd, 0, &progress,
                                                             1, verb);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 656;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
        }
        if (op->pollt || (SG_LIB_CAT_NOT_READY == res)) {
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        memset(reqSense, 0x0, sizeof(reqSense));
                        res = sg_ll_request_sense(fd, 0, reqSense,
                                                  sizeof(reqSense), 0, verb);
                        if (res) {
                                pr2serr("polling with Request Sense command "
                                        "failed [res=%d]\n", res);
                                break;
                        }
                        resp_len = reqSense[7] + 8;
                        if (verb) {
                                pr2serr("Parameter data in hex:\n");
                                dStrHexErr((const char *)reqSense, resp_len,
                                           1);
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
        }
        printf("FORMAT MEDIUM Complete\n");
        return 0;
}

#define VPD_DEVICE_ID 0x83
#define VPD_ASSOC_LU 0
#define VPD_ASSOC_TPORT 1
#define TPROTO_ISCSI 5

static char *
get_lu_name(const unsigned char * bp, int u_len, char * b, int b_len)
{
        int len, off, sns_dlen, dlen, k;
        unsigned char u_sns[512];
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

static int
print_dev_id(int fd, unsigned char * sinq_resp, int max_rlen,
             const struct opts_t * op)
{
        int res, k, n, verb, pdt, has_sn, has_di;
        unsigned char b[256];
        char a[256];
        char pdt_name[64];

        verb = (op->verbose > 1) ? op->verbose - 1 : 0;
        memset(sinq_resp, 0, max_rlen);
        res = sg_ll_inquiry(fd, 0, 0 /* evpd */, 0 /* pg_op */, b,
                            SAFE_STD_INQ_RESP_LEN, 1, verb);
        if (res)
                return res;
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
                return SG_LIB_CAT_OTHER;
        }
        res = sg_ll_inquiry(fd, 0, 1 /* evpd */, VPD_SUPPORTED_VPDS, b,
                            SAFE_STD_INQ_RESP_LEN, 1, verb);
        if (res) {
                if (op->verbose)
                        pr2serr("VPD_SUPPORTED_VPDS gave res=%d\n", res);
                return 0;
        }
        if (VPD_SUPPORTED_VPDS != b[1]) {
                if (op->verbose)
                        pr2serr("VPD_SUPPORTED_VPDS corrupted\n");
                return 0;
        }
        n = sg_get_unaligned_be16(b + 2);
        if (n > (SAFE_STD_INQ_RESP_LEN - 4))
                n = (SAFE_STD_INQ_RESP_LEN - 4);
        for (k = 0, has_sn = 0, has_di = 0; k < n; ++k) {
                if (VPD_UNIT_SERIAL_NUM == b[4 + k]) {
                        if (has_di) {
                                if (op->verbose)
                                        pr2serr("VPD_SUPPORTED_VPDS "
                                                "dis-ordered\n");
                                return 0;
                        }
                        ++has_sn;
                } else if (VPD_DEVICE_ID == b[4 + k]) {
                        ++has_di;
                        break;
                }
        }
        if (has_sn) {
                res = sg_ll_inquiry(fd, 0, 1 /* evpd */, VPD_UNIT_SERIAL_NUM,
                                    b, sizeof(b), 1, verb);
                if (res) {
                        if (op->verbose)
                                pr2serr("VPD_UNIT_SERIAL_NUM gave res=%d\n",
                                        res);
                        return 0;
                }
                if (VPD_UNIT_SERIAL_NUM != b[1]) {
                        if (op->verbose)
                                pr2serr("VPD_UNIT_SERIAL_NUM corrupted\n");
                        return 0;
                }
                n = sg_get_unaligned_be16(b + 2);
                if (n > (int)(sizeof(b) - 4))
                        n = (sizeof(b) - 4);
                printf("      Unit serial number: %.*s\n", n,
                       (const char *)(b + 4));
        }
        if (has_di) {
                res = sg_ll_inquiry(fd, 0, 1 /* evpd */, VPD_DEVICE_ID, b,
                                    sizeof(b), 1, verb);
                if (res) {
                        if (op->verbose)
                                pr2serr("VPD_DEVICE_ID gave res=%d\n", res);
                        return 0;
                }
                if (VPD_DEVICE_ID != b[1]) {
                        if (op->verbose)
                                pr2serr("VPD_DEVICE_ID corrupted\n");
                        return 0;
                }
                n = sg_get_unaligned_be16(b + 2);
                if (n > (int)(sizeof(b) - 4))
                        n = (sizeof(b) - 4);
                n = strlen(get_lu_name(b, n + 4, a, sizeof(a)));
                if (n > 0)
                        printf("      LU name: %.*s\n", n, a);
        }
        return 0;
}

#define RCAP_REPLY_LEN 32

/* Returns block size or -2 if do_16==0 and the number of blocks is too
 * big, or returns -1 for other error. */
static int
print_read_cap(int fd, const struct opts_t * op)
{
        int res;
        unsigned char resp_buff[RCAP_REPLY_LEN];
        unsigned int last_blk_addr, block_size;
        uint64_t llast_blk_addr;
        char b[80];

        if (op->do_rcap16) {
                res = sg_ll_readcap_16(fd, 0 /* pmi */, 0 /* llba */,
                                       resp_buff, 32, 1, op->verbose);
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
                        return (int)block_size;
                }
        } else {
                res = sg_ll_readcap_10(fd, 0 /* pmi */, 0 /* lba */,
                                       resp_buff, 8, 1, op->verbose);
                if (0 == res) {
                        last_blk_addr = sg_get_unaligned_be32(resp_buff + 0);
                        block_size = sg_get_unaligned_be32(resp_buff + 4);
                        if (0xffffffff == last_blk_addr) {
                                if (op->verbose)
                                        printf("Read Capacity (10) reponse "
                                               "indicates that Read Capacity "
                                               "(16) is required\n");
                                return -2;
                        }
                        printf("Read Capacity (10) results:\n");
                        printf("   Number of logical blocks=%u\n",
                               last_blk_addr + 1);
                        printf("   Logical block size=%u bytes\n",
                               block_size);
                        return (int)block_size;
                }
        }
        sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
        pr2serr("READ CAPACITY (%d): %s\n", (op->do_rcap16 ? 16 : 10), b);
        return -1;
}


int
main(int argc, char **argv)
{
        int fd, res, calc_len, bd_len, dev_specific_param;
        int offset, j, n, bd_blk_len, prob, len, pdt;
        uint64_t ull;
        char b[80];
        unsigned char inq_resp[SAFE_STD_INQ_RESP_LEN];
        int ret = 0;
        struct opts_t opts;
        struct opts_t * op;

        op = &opts;
        memset(op, 0, sizeof(opts));
        op->cmplst = 1;
        op->mode_page = RW_ERROR_RECOVERY_PAGE;
        op->pollt = DEF_POLL_TYPE;
        op->tape = -1;
        while (1) {
                int option_index = 0;
                int c;

                c = getopt_long(argc, argv,
                                "c:C:Def:FhIlm:M:pP:q:rRs:St:T:vVwx:y6",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
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
                        op->cmplst = sg_get_num(optarg);
                        if ((op->cmplst < 0) || (op->cmplst > 1)) {
                                pr2serr("bad argument to '--cmplst', want 0 "
                                        "or 1\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'D':
                        op->dcrt = 1;
                        break;
                case 'e':
                        op->early = true;
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
                        return 0;
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
                case 'r':
                        op->resize = true;
                        break;
                case 'R':
                        op->rto_req = true;
                        break;
                case 's':
                        op->blk_size = sg_get_num(optarg);
                        if (op->blk_size <= 0) {
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
                        op->verbose++;
                        break;
                case 'V':
                        pr2serr("sg_format version: %s\n", version_str);
                        return 0;
                case 'w':
                        op->fwait = true;
                        break;
                case 'x':
                        op->pollt = !!sg_get_num(optarg);
                        op->pollt_given = true;
                        break;
                case 'y':
                        op->verify++;
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
        if (NULL == op->device_name) {
                pr2serr("no DEVICE name given\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }
        if (op->format && (op->tape >= 0)) {
                pr2serr("Cannot choose both '--format' and '--tape='; disk "
                        "or tape, choose one only\n");
                return SG_LIB_SYNTAX_ERROR;
        }
        if (op->ip_def && op->sec_init) {
                pr2serr("'--ip_def' and '--security' contradict, choose "
                        "one\n");
                return SG_LIB_SYNTAX_ERROR;
        }
        if (op->resize) {
                if (op->format) {
                        pr2serr("both '--format' and '--resize' not "
                                "permitted\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                } else if (0 == op->blk_count) {
                        pr2serr("'--resize' needs a '--count' (other than "
                                "0)\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                } else if (0 != op->blk_size) {
                        pr2serr("'--resize' not compatible with '--size'\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
        }
        if ((op->pinfo > 0) || (op->rto_req > 0) || (op->fmtpinfo > 0)) {
                if ((op->pinfo || op->rto_req) && op->fmtpinfo) {
                        pr2serr("confusing with both '--pinfo' or "
                                "'--rto_req' together with\n'--fmtpinfo', "
                                "best use '--fmtpinfo' only\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
                if (op->pinfo)
                        op->fmtpinfo |= 2;
                if (op->rto_req)
                        op->fmtpinfo |= 1;
        }

        if ((fd = sg_cmds_open_device(op->device_name, 0 /* read write */,
                                      op->verbose)) < 0) {
                pr2serr("error opening device file: %s: %s\n",
                        op->device_name, safe_strerror(-fd));
                return SG_LIB_FILE_ERROR;
        }

        if (op->format > 2)
                goto format_only;

        ret = print_dev_id(fd, inq_resp, sizeof(inq_resp), op);
        if (ret)
                goto out;
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
        }

again_with_long_lba:
        memset(dbuff, 0, MAX_BUFF_SZ);
        if (op->mode6)
                res = sg_ll_mode_sense6(fd, 0 /* DBD */, 0 /* current */,
                                        op->mode_page, 0 /* subpage */, dbuff,
                                        MAX_BUFF_SZ, 1, op->verbose);
        else
                res = sg_ll_mode_sense10(fd, op->long_lba, 0 /* DBD */,
                                         0 /* current */, op->mode_page,
                                         0 /* subpage */, dbuff,
                                         MAX_BUFF_SZ, 1, op->verbose);
        ret = res;
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
                        sg_get_category_sense_str(res, sizeof(b), b,
                                                  op->verbose);
                        pr2serr("MODE SENSE (%d) command: %s\n",
                                (op->mode6 ? 6 : 10), b);
                }
                if (0 == op->verbose)
                        pr2serr("    try '-v' for more information\n");
                goto out;
        }
        if (op->mode6) {
                calc_len = dbuff[0] + 1;
                dev_specific_param = dbuff[2];
                bd_len = dbuff[3];
                op->long_lba = 0;
                offset = 4;
                /* prepare for mode select */
                dbuff[0] = 0;
                dbuff[1] = 0;
                dbuff[2] = 0;
        } else {
                calc_len = sg_get_unaligned_be16(dbuff + 0);
                dev_specific_param = dbuff[3];
                bd_len = sg_get_unaligned_be16(dbuff + 6);
                op->long_lba = (dbuff[4] & 1);
                offset = 8;
                /* prepare for mode select */
                dbuff[0] = 0;
                dbuff[1] = 0;
                dbuff[2] = 0;
                dbuff[3] = 0;
        }
        if ((offset + bd_len) < calc_len)
                dbuff[offset + bd_len] &= 0x7f;  /* clear PS bit in mpage */
        prob = 0;
        bd_blk_len = 0;
        printf("Mode Sense (block descriptor) data, prior to changes:\n");
        if (dev_specific_param & 0x40)
                printf("  <<< Write Protect (WP) bit set >>>\n");
        if (bd_len > 0) {
                ull = op->long_lba ? sg_get_unaligned_be64(dbuff + offset) :
                                 sg_get_unaligned_be32(dbuff + offset);
                if ((0 == op->long_lba) && (0xffffffff == ull)) {
                        if (op->verbose)
                                pr2serr("Mode sense number of blocks maxed "
                                        "out, set longlba\n");
                        op->long_lba = 1;
                        op->mode6 = 0;
                        op->do_rcap16 = 1;
                        goto again_with_long_lba;
                }
                bd_blk_len = op->long_lba ?
                                 sg_get_unaligned_be32(dbuff + offset + 12) :
                                 sg_get_unaligned_be24(dbuff + offset + 5);
                if (op->long_lba) {
                        printf("  <<< longlba flag set (64 bit lba) >>>\n");
                        if (bd_len != 16)
                                prob = 1;
                } else if (bd_len != 8)
                        prob = 1;
                printf("  Number of blocks=%" PRIu64 " [0x%" PRIx64 "]\n",
                       ull, ull);
                printf("  Block size=%d [0x%x]\n", bd_blk_len, bd_blk_len);
        } else {
                printf("  No block descriptors present\n");
                prob = 1;
        }
        if (op->resize || (op->format && ((op->blk_count != 0) ||
              ((op->blk_size > 0) && (op->blk_size != bd_blk_len))))) {
                /* want to run MODE SELECT */

/* Working Draft SCSI Primary Commands - 3 (SPC-3)    pg 255
**
** If the SCSI device doesn't support changing its capacity by changing
** the NUMBER OF BLOCKS field using the MODE SELECT command, the value
** in the NUMBER OF BLOCKS field is ignored. If the device supports changing
** its capacity by changing the NUMBER OF BLOCKS field, then the
** NUMBER OF BLOCKS field is interpreted as follows:
**      a) If the number of blocks is set to zero, the device shall retain
**         its current capacity if the block size has not changed. If the
**         number of blocks is set to zero and the block size has changed,
**         the device shall be set to its maximum capacity when the new
**         block size takes effect;
**
**      b) If the number of blocks is greater than zero and less than or
**         equal to its maximum capacity, the device shall be set to that
**         number of blocks. If the block size has not changed, the device
**         shall not become format corrupted. This capacity setting shall be
**         retained through power cycles, hard resets, logical unit resets,
**         and I_T nexus losses;
**
**      c) If the number of blocks field is set to a value greater than the
**         maximum capacity of the device and less than FFFF FFFFh, then the
**         command is terminated with a CHECK CONDITION status. The sense key
**         is set to ILLEGAL REQUEST. The device shall retain its previous
**         block descriptor settings; or
**
**      d) If the number of blocks is set to FFFF FFFFh, the device shall be
**         set to its maximum capacity. If the block size has not changed,
**         the device shall not become format corrupted. This capacity setting
**         shall be retained through power cycles, hard resets, logical unit
**         resets, and I_T nexus losses.
*/

                if (prob) {
                        pr2serr("Need to perform MODE SELECT (to change "
                                "number or blocks or block length)\n");
                        pr2serr("but (single) block descriptor not found "
                                "in earlier MODE SENSE\n");
                        ret = SG_LIB_CAT_MALFORMED;
                        goto out;
                }
                if (op->blk_count != 0)  {
                        len = (op->long_lba ? 8 : 4);
                        for (j = 0; j < len; ++j) {
                                n = (len - j - 1) * 8;
                                dbuff[offset + j] =
                                            (op->blk_count >> n) & 0xff;
                        }
                } else if ((op->blk_size > 0) &&
                           (op->blk_size != bd_blk_len)) {
                        len = (op->long_lba ? 8 : 4);
                        for (j = 0; j < len; ++j)
                                dbuff[offset + j] = 0;
                }
                if ((op->blk_size > 0) && (op->blk_size != bd_blk_len)) {
                        if (op->long_lba)
                                sg_put_unaligned_be32((uint32_t)op->blk_size,
                                                      dbuff + offset + 12);
                        else
                                sg_put_unaligned_be24((uint32_t)op->blk_size,
                                                      dbuff + offset + 5);
                }
                if (op->mode6)
                        res = sg_ll_mode_select6(fd, 1 /* PF */, 1 /* SP */,
                                         dbuff, calc_len, 1, op->verbose);
                else
                        res = sg_ll_mode_select10(fd, 1 /* PF */, 1 /* SP */,
                                          dbuff, calc_len, 1, op->verbose);
                ret = res;
                if (res) {
                        sg_get_category_sense_str(res, sizeof(b), b,
                                                  op->verbose);
                        pr2serr("MODE SELECT command: %s\n", b);
                        if (0 == op->verbose)
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
                        op->do_rcap16 = 1;
                        res = print_read_cap(fd, op);
                }
                if (res < 0)
                        ret = -1;
                if ((res > 0) && (bd_blk_len > 0) &&
                    (res != (int)bd_blk_len)) {
                        printf("  Warning: mode sense and read capacity "
                               "report different block sizes [%d,%d]\n",
                               bd_blk_len, res);
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
#if 1
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
                res = scsi_format_unit(fd, op);
                ret = res;
                if (res) {
                        pr2serr("FORMAT UNIT failed\n");
                        if (0 == op->verbose)
                                pr2serr("    try '-v' for more "
                                        "information\n");
                }
#else
                pr2serr("FORMAT UNIT ignored, testing\n");
#endif
        }
        goto out;

format_med:
        if (! op->pollt_given)
                op->pollt = 1;  /* SSC-5 specifies REQUEST SENSE polling */
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
        res = scsi_format_medium(fd, op);
        ret = res;
        if (res) {
                pr2serr("FORMAT MEDIUM failed\n");
                if (0 == op->verbose)
                        pr2serr("    try '-v' for more "
                                "information\n");
        }

out:
        res = sg_cmds_close_device(fd);
        if (res < 0) {
                pr2serr("close error: %s\n", safe_strerror(-res));
                if (0 == ret)
                        return SG_LIB_FILE_ERROR;
        }
        return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
