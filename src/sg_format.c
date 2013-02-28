/*
 * sg_format : format a SCSI disk
 *             potentially with a different number of blocks and block size
 *
 * formerly called blk512-linux.c (v0.4)
 *
 * Copyright (C) 2003  Grant Grundler    grundler at parisc-linux dot org
 * Copyright (C) 2003  James Bottomley       jejb at parisc-linux dot org
 * Copyright (C) 2005-2013  Douglas Gilbert   dgilbert at interlog dot com
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2, or (at your option)
 *   any later version.
 *
 * http://www.t10.org/scsi-3.htm
 * http://www.tldp.org/HOWTO/SCSI-Generic-HOWTO
 *
 *
 *  List of some (older) disk manufacturers' block counts.
 *  These are not needed in newer disks which will automatically use
 *  the manufacturers' recommended block count if a count of -1 is given.
 *      Inquiry         Block Count (@512 byte blocks)
 *      ST150150N       8388315
 *      IBM_DCHS04F     8888543
 *      IBM_DGHS09Y     17916240
 *      ST336704FC      71132960
 *      ST318304FC      35145034  (Factory spec is 35885167 sectors)
 *      ST336605FC      ???
 *      ST336753FC      71132960  (Factory spec is 71687372 sectors)
 *  and a newer one:
 *      ST33000650SS    5860533168 (3 TB SAS disk)
 */

#include <stdio.h>
#include <stdlib.h>
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

static char * version_str = "1.21 20130228";

#define RW_ERROR_RECOVERY_PAGE 1  /* every disk should have one */
#define FORMAT_DEV_PAGE 3         /* Format Device Mode Page [now obsolete] */
#define CONTROL_MODE_PAGE 0xa     /* alternative page all devices have?? */

#define THIS_MPAGE_EXISTS RW_ERROR_RECOVERY_PAGE

#define SHORT_TIMEOUT           20   /* 20 seconds unless immed=0 ... */
#define FORMAT_TIMEOUT          (15 * 3600)       /* 15 hours ! */
                        /* Seagate ST32000444SS 2TB disk takes 9.5 hours */

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


#define MAX_BUFF_SZ     252
static unsigned char dbuff[MAX_BUFF_SZ];


static struct option long_options[] = {
        {"count", required_argument, 0, 'c'},
        {"cmplst", required_argument, 0, 'C'},
        {"dcrt", no_argument, 0, 'D'},
        {"early", no_argument, 0, 'e'},
        {"fmtpinfo", required_argument, 0, 'f'},
        {"format", no_argument, 0, 'F'},
        {"help", no_argument, 0, 'h'},
        {"long", no_argument, 0, 'l'},
        {"pinfo", no_argument, 0, 'p'},
        {"pfu", required_argument, 0, 'P'},
        {"pie", required_argument, 0, 'q'},
        {"poll", required_argument, 0, 'x'},
        {"resize", no_argument, 0, 'r'},
        {"rto_req", no_argument, 0, 'R'},
        {"security", no_argument, 0, 'S'},
        {"six", no_argument, 0, '6'},
        {"size", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wait", no_argument, 0, 'w'},
        {0, 0, 0, 0},
};


static void
usage()
{
        printf("usage: sg_format [--cmplst=0|1] [--count=COUNT] [--dcrt] "
               "[--early]\n"
               "                 [--fmtpinfo=FPI] [--format] [--help] "
               "[--long] [--pfu=PFU]\n"
               "                 [--pie=PIE] [--pinfo] [--poll=PT] "
               "[--resize] [--rto_req]\n"
               "                 [--security] [--six] [--size=SIZE] "
               "[--verbose] [--version]\n"
               "                 [--wait] DEVICE\n"
               "  where:\n"
               "    --cmplst=0|1\n"
               "      -C 0|1        sets CMPLST bit in format cdb "
               "(default: 1)\n"
               "    --count=COUNT|-c COUNT    number of blocks to "
               "report after format or\n"
               "                              resize. With format "
               "defaults to same as current\n"
               "    --dcrt|-D       disable certification (doesn't "
               "verify media)\n"
               "    --early|-e      exit once format started (user can "
               "monitor progress)\n"
               "    --fmtpinfo=FPI|-f FPI    FMTPINFO field value "
               "(default: 0)\n"
               "    --format|-F     format unit (default: report current "
               "count and size)\n"
               "    --help|-h       prints out this usage message\n"
               "    --long|-l       allow for 64 bit lbas (default: assume "
               "32 bit lbas)\n"
               "    --pfu=PFU|-P PFU    Protection Field Usage value "
               "(default: 0)\n"
               "    --pie=PIE|-q PIE    Protection Information Exponent "
               "(default: 0)\n"
               "    --pinfo|-p      set upper bit of FMTPINFO field\n"
               "                    (deprecated, use '--fmtpinfo=FPI' "
               "instead)\n"
               "    --poll=PT|-x PT    PT is poll type, 0 for test unit "
               "ready\n"
               "                       1 for request sense (def: 0 (in "
               "future will be 1))\n");
        printf("    --resize|-r     resize (rather than format) to COUNT "
               "value\n"
               "    --rto_req|-R    set lower bit of FMTPINFO field\n"
               "                    (deprecated use '--fmtpinfo=FPI' "
               "instead)\n"
               "    --security|-S    set security initialization (SI) bit\n"
               "    --six|-6        use 6 byte MODE SENSE/SELECT to probe "
               "disk\n"
               "                    (def: use 10 byte MODE SENSE/SELECT)\n"
               "    --size=SIZE|-s SIZE    bytes per block, defaults to "
               "DEVICE's current\n"
               "                           block size. Only needed to "
               "change current block\n"
               "                           size\n"
               "    --verbose|-v    increase verbosity\n"
               "    --version|-V    print version details and exit\n"
               "    --wait|-w       format command waits until format "
               "operation completes\n"
               "                    (default: set IMMED=1 and poll with "
               "Test Unit Ready)\n\n"
               "\tExample: sg_format --format /dev/sdc\n\n"
               "This utility formats or resizes a SCSI disk.\n");
        printf("WARNING: This utility will destroy all the data on "
               "DEVICE when\n\t '--format' is given. Check that you "
               "have the correct DEVICE.\n");
}

/* Return 0 on success, else see sg_ll_format_unit() */
static int
scsi_format(int fd, int fmtpinfo, int cmplst, int pf_usage, int immed,
            int dcrt, int pie, int si, int early, int pt, int verbose)
{
        int res, need_hdr, progress, pr, rem, verb, fmt_pl_sz, longlist, off;
        int resp_len;
        const int SH_FORMAT_HEADER_SZ = 4;
        const int LO_FORMAT_HEADER_SZ = 8;
        const char INIT_PATTERN_DESC_SZ = 4;
        unsigned char fmt_pl[LO_FORMAT_HEADER_SZ + INIT_PATTERN_DESC_SZ];
        unsigned char reqSense[MAX_BUFF_SZ];

        memset(fmt_pl, 0, sizeof(fmt_pl));
        longlist = (pie > 0);
        off = longlist ? LO_FORMAT_HEADER_SZ : SH_FORMAT_HEADER_SZ;
        fmt_pl[0] = pf_usage & 0x7;  /* protection_field_usage (bits 2-0) */
        fmt_pl[1] = (immed ? 0x2 : 0); /* fov=0, [dpry,dcrt,stpf,ip=0] */
        if (dcrt)
                fmt_pl[1] |= 0xa0;     /* fov=1, dcrt=1 */
        if (si) {
                fmt_pl[1] |= 0x88;     /* fov=1, ip=1 */
                fmt_pl[off + 0] = 0x20;     /* si=1 in init. pattern desc */
        }
        if (longlist)
                fmt_pl[3] = (pie & 0xf);    /* protection interval exponent */

        need_hdr = (immed || cmplst || dcrt || si || (pf_usage > 0) ||
                    (pie > 0));
        fmt_pl_sz = 0;
        if (need_hdr)
                fmt_pl_sz = off + (si ? INIT_PATTERN_DESC_SZ : 0);

        res = sg_ll_format_unit(fd, fmtpinfo, longlist, need_hdr /*fmtdata*/,
                                cmplst, 0 /* dlist_format */,
                                (immed ? SHORT_TIMEOUT : FORMAT_TIMEOUT),
                                fmt_pl, fmt_pl_sz, 1, verbose);
        switch (res) {
        case 0:
                break;
        case SG_LIB_CAT_NOT_READY:
                fprintf(stderr, "Format command, device not ready\n");
                break;
        case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, "Format command not supported\n");
                break;
        case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, "Format command, illegal parameter\n");
                break;
        case SG_LIB_CAT_UNIT_ATTENTION:
                fprintf(stderr, "Format command, unit attention\n");
                break;
        case SG_LIB_CAT_ABORTED_COMMAND:
                fprintf(stderr, "Format command, aborted command\n");
                break;
        default:
                fprintf(stderr, "Format command failed\n");
                break;
        }
        if (res)
                return res;

        if (! immed)
                return 0;

        printf("\nFormat has started\n");
        if (early) {
                if (immed)
                        printf("Format continuing,\n    request sense or "
                               "test unit ready can be used to monitor "
                               "progress\n");
                return 0;
        }

        verb = (verbose > 1) ? (verbose - 1) : 0;
        if (0 == pt) {
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        progress = -1;
                        res = sg_ll_test_unit_ready_progress(fd, 0, &progress,
                                                             1, verb);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 655;
                                printf("Format in progress, %d.%02d%% done\n",
                                       pr, rem);
                        } else
                                break;
                }
        }
        if (pt || (SG_LIB_CAT_NOT_READY == res)) {
                for(;;) {
                        sleep_for(POLL_DURATION_SECS);
                        memset(reqSense, 0x0, sizeof(reqSense));
                        res = sg_ll_request_sense(fd, 0, reqSense,
                                                  sizeof(reqSense), 0, verb);
                        if (res) {
                                fprintf(stderr, "polling with Request Sense "
                                        "command failed [res=%d]\n", res);
                                break;
                        }
                        resp_len = reqSense[7] + 8;
                        if (verb) {
                                fprintf(stderr, "Parameter data in hex:\n");
                                dStrHex((const char *)reqSense, resp_len, 1);
                        }
                        progress = -1;
                        sg_get_sense_progress_fld(reqSense, resp_len,
                                                  &progress);
                        if (progress >= 0) {
                                pr = (progress * 100) / 65536;
                                rem = ((progress * 100) % 65536) / 655;
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
            res = sg_ll_request_sense(sg_fd, desc, requestSenseBuff, maxlen,
                                      1, verbose);
            if (res) {
                ret = res;
                if (SG_LIB_CAT_INVALID_OP == res)
                    fprintf(stderr, "Request Sense command not supported\n");
                else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                    fprintf(stderr, "bad field in Request Sense cdb\n");
                else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                    fprintf(stderr, "Request Sense, aborted command\n");
                else {
                    fprintf(stderr, "Request Sense command unexpectedly "
                            "failed\n");
                    if (0 == verbose)
                        fprintf(stderr, "    try the '-v' option for "
                                "more information\n");
                }
                break;
            }
            /* "Additional sense length" same in descriptor and fixed */
            resp_len = requestSenseBuff[7] + 8;
            if (verbose > 1) {
                fprintf(stderr, "Parameter data in hex\n");
                dStrHex((const char *)requestSenseBuff, resp_len, 1);
            }
            progress = -1;
            sg_get_sense_progress_fld(requestSenseBuff, resp_len,
                                      &progress);
            if (progress < 0) {
                ret = res;
                if (verbose > 1)
                     fprintf(stderr, "No progress indication found, "
                             "iteration %d\n", k + 1);
                /* N.B. exits first time there isn't a progress indication */
                break;
            } else
                printf("Progress indication: %d.%02d%% done\n",
                       (progress * 100) / 65536,
                       ((progress * 100) % 65536) / 655);
        }
#endif
        printf("FORMAT Complete\n");
        return 0;
}

#define RCAP_REPLY_LEN 32

/* Returns block size or -2 if do_16==0 and the number of blocks is too
 * big, or returns -1 for other error. */
static int
print_read_cap(int fd, int do_16, int verbose)
{
        int res, k;
        unsigned char resp_buff[RCAP_REPLY_LEN];
        unsigned int last_blk_addr, block_size;
        uint64_t llast_blk_addr;

        if (do_16) {
                res = sg_ll_readcap_16(fd, 0 /* pmi */, 0 /* llba */,
                                       resp_buff, 32, 1, verbose);
                if (0 == res) {
                        for (k = 0, llast_blk_addr = 0; k < 8; ++k) {
                                llast_blk_addr <<= 8;
                                llast_blk_addr |= resp_buff[k];
                        }
                        block_size = ((resp_buff[8] << 24) |
                                      (resp_buff[9] << 16) |
                                      (resp_buff[10] << 8) |
                                      resp_buff[11]);
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
                               ((resp_buff[14] & 0x3f) << 8) + resp_buff[15]);
                        printf("   Number of logical blocks=%" PRIu64 "\n",
                               llast_blk_addr + 1);
                        printf("   Logical block size=%u bytes\n",
                               block_size);
                        return (int)block_size;
                }
        } else {
                res = sg_ll_readcap_10(fd, 0 /* pmi */, 0 /* lba */,
                                       resp_buff, 8, 1, verbose);
                if (0 == res) {
                        last_blk_addr = ((resp_buff[0] << 24) |
                                         (resp_buff[1] << 16) |
                                         (resp_buff[2] << 8) |
                                         resp_buff[3]);
                        block_size = ((resp_buff[4] << 24) |
                                      (resp_buff[5] << 16) |
                                      (resp_buff[6] << 8) |
                                      resp_buff[7]);
                        if (0xffffffff == last_blk_addr) {
                            if (verbose)
                                printf("Read Capacity (10) reponse "
                                       "indicates that Read Capacity (16) "
                                       "is required\n");
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
        if (SG_LIB_CAT_NOT_READY == res)
                fprintf(stderr, "READ CAPACITY (%d): device not ready\n",
                        (do_16 ? 16 : 10));
        else if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, "READ CAPACITY (%d) not supported\n",
                        (do_16 ? 16 : 10));
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "bad field in READ CAPACITY (%d) "
                        "cdb\n", (do_16 ? 16 : 10));
        else if (verbose)
                fprintf(stderr, "READ CAPACITY (%d) failed "
                        "[res=%d]\n", (do_16 ? 16 : 10), res);
        return -1;
}


int
main(int argc, char **argv)
{
        const int mode_page = THIS_MPAGE_EXISTS;        /* hopefully */
        int fd, res, calc_len, bd_len, dev_specific_param;
        int offset, j, bd_blk_len, prob, len;
        uint64_t ull;
        int64_t blk_count = 0;  /* -c value */
        int blk_size = 0;     /* -s value */
        int format = 0;         /* -F */
        int resize = 0;         /* -r */
        int verbose = 0;        /* -v */
        int fwait = 0;          /* -w */
        int mode6 = 0;
        int fmtpinfo = 0;
        int pinfo = 0;          /* deprecated, prefer fmtpinfo */
        int pie = 0;
        int pfu = 0;
        int pt = DEF_POLL_TYPE;
        int rto_req = 0;        /* deprecated, prefer fmtpinfo */
        int cmplst = 1;
        int do_rcap16 = 0;
        int long_lba = 0;
        int dcrt = 0;
        int do_si = 0;
        int early = 0;
        const char * device_name = NULL;
        char pdt_name[64];
        struct sg_simple_inquiry_resp inq_out;
        int ret = 0;

        while (1) {
                int option_index = 0;
                int c;

                c = getopt_long(argc, argv, "c:C:Def:FhlpP:q:rRs:SvVwx:6",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'c':
                        if (0 == strcmp("-1", optarg))
                                blk_count = -1;
                        else {
                                blk_count = sg_get_llnum(optarg);
                                if (-1 == blk_count) {
                                        fprintf(stderr, "bad argument to "
                                                "'--count'\n");
                                        return SG_LIB_SYNTAX_ERROR;
                                }
                        }
                        break;
                case 'C':
                        cmplst = sg_get_num(optarg);
                        if ((cmplst < 0) || ( cmplst > 1)) {
                                fprintf(stderr, "bad argument to '--cmplst', "
                                        "want 0 or 1\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'D':
                        dcrt = 1;
                        break;
                case 'e':
                        early = 1;
                        break;
                case 'f':
                        fmtpinfo = sg_get_num(optarg);
                        if ((fmtpinfo < 0) || ( fmtpinfo > 3)) {
                                fprintf(stderr, "bad argument to "
                                        "'--fmtpinfo', accepts 0 to 3 "
                                        "inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'F':
                        format = 1;
                        break;
                case 'h':
                        usage();
                        return 0;
                case 'l':
                        long_lba = 1;
                        do_rcap16 = 1;
                        break;
                case 'p':
                        pinfo = 1;
                        break;
                case 'P':
                        pfu = sg_get_num(optarg);
                        if ((pfu < 0) || ( pfu > 7)) {
                                fprintf(stderr, "bad argument to '--pfu', "
                                        "accepts 0 to 7 inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'q':
                        pie = sg_get_num(optarg);
                        if ((pie < 0) || ( pie > 15)) {
                                fprintf(stderr, "bad argument to '--pie', "
                                        "accepts 0 to 15 inclusive\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'r':
                        resize = 1;
                        break;
                case 'R':
                        rto_req = 1;
                        break;
                case 's':
                        blk_size = sg_get_num(optarg);
                        if (blk_size <= 0) {
                                fprintf(stderr, "bad argument to '--size', "
                                        "want arg > 0\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'S':
                        do_si = 1;
                        break;
                case 'v':
                        verbose++;
                        break;
                case 'V':
                        fprintf(stderr, "sg_format version: %s\n",
                                version_str);
                        return 0;
                case 'w':
                        fwait = 1;
                        break;
                case 'x':
                        pt = !!sg_get_num(optarg);
                        break;
                case '6':
                        mode6 = 1;
                        break;
                default:
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
        }
        if (optind < argc) {
                if (NULL == device_name) {
                        device_name = argv[optind];
                        ++optind;
                }
        }
        if (optind < argc) {
                for (; optind < argc; ++optind)
                        fprintf(stderr, "Unexpected extra argument: %s\n",
                                argv[optind]);
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }
        if (NULL == device_name) {
                fprintf(stderr, "no DEVICE name given\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }
        if (resize) {
                if (format) {
                        fprintf(stderr, "both '--format' and '--resize'"
                                "not permitted\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                } else if (0 == blk_count) {
                        fprintf(stderr, "'--resize' needs a '--count' (other"
                                " than 0)\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                } else if (0 != blk_size) {
                        fprintf(stderr, "'--resize' not compatible with "
                                "'--size'\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
        }
        if ((pinfo > 0) || (rto_req > 0) || (fmtpinfo > 0)) {
                if ((pinfo || rto_req) && fmtpinfo) {
                        fprintf(stderr, "confusing with both '--pinfo' or "
                                "'--rto_req' together with\n'--fmtpinfo', "
                                "best use '--fmtpinfo' only\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
                if (pinfo)
                        fmtpinfo |= 2;
                if (rto_req)
                        fmtpinfo |= 1;
        }

        if ((fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose)) < 0) {
                fprintf(stderr, "error opening device file: %s: %s\n",
                        device_name, safe_strerror(-fd));
                return SG_LIB_FILE_ERROR;
        }

        if (sg_simple_inquiry(fd, &inq_out, 1, verbose)) {
                fprintf(stderr, "%s doesn't respond to a SCSI INQUIRY\n",
                        device_name);
                ret = SG_LIB_CAT_OTHER;
                goto out;
        }
        printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n",
               inq_out.vendor, inq_out.product, inq_out.revision,
               sg_get_pdt_str(inq_out.peripheral_type, sizeof(pdt_name),
                              pdt_name),
               inq_out.peripheral_type);
        if (verbose)
                printf("      PROTECT=%d\n", !!(inq_out.byte_5 & 1));
        if (inq_out.byte_5 & 1)
                printf("      << supports protection information>>\n");

        if ((0 != inq_out.peripheral_type) &&
            (7 != inq_out.peripheral_type) &&
            (0xe != inq_out.peripheral_type)) {
                fprintf(stderr, "This format is only defined for disks "
                        "(using SBC-2 or RBC) and MO media\n");
                ret = SG_LIB_CAT_MALFORMED;
                goto out;
        }

again_with_long_lba:
        memset(dbuff, 0, MAX_BUFF_SZ);
        if (mode6)
                res = sg_ll_mode_sense6(fd, 0 /* DBD */, 0 /* current */,
                                        mode_page, 0 /* subpage */, dbuff,
                                        MAX_BUFF_SZ, 1, verbose);
        else
                res = sg_ll_mode_sense10(fd, long_lba, 0 /* DBD */,
                                         0 /* current */, mode_page,
                                         0 /* subpage */, dbuff,
                                         MAX_BUFF_SZ, 1, verbose);
        ret = res;
        if (res) {
                if (SG_LIB_CAT_NOT_READY == res)
                        fprintf(stderr, "MODE SENSE (%d) command, device "
                                "not ready\n", (mode6 ? 6 : 10));
                else if (SG_LIB_CAT_UNIT_ATTENTION == res)
                        fprintf(stderr, "MODE SENSE (%d) command, unit "
                                "attention\n", (mode6 ? 6 : 10));
                else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                        fprintf(stderr, "MODE SENSE (%d) command, aborted "
                                "command\n", (mode6 ? 6 : 10));
                else if (SG_LIB_CAT_INVALID_OP == res) {
                        fprintf(stderr, "MODE SENSE (%d) command is not "
                                "supported\n", (mode6 ? 6 : 10));
                        fprintf(stderr, "    try again %s the '--six' "
                                "option\n", (mode6 ? "without" : "with"));

                } else if (SG_LIB_CAT_ILLEGAL_REQ == res) {
                        if (long_lba && (! mode6))
                                fprintf(stderr, "bad field in MODE SENSE "
                                        "(%d) [longlba flag not supported?]"
                                        "\n", (mode6 ? 6 : 10));
                        else
                                fprintf(stderr, "bad field in MODE SENSE "
                                        "(%d) [mode_page %d not supported?]"
                                        "\n", (mode6 ? 6 : 10), mode_page);
                } else
                        fprintf(stderr, "MODE SENSE (%d) command failed\n",
                                (mode6 ? 6 : 10));
                        if (0 == verbose)
                                fprintf(stderr, "    try '-v' for more "
                                        "information\n");
                goto out;
        }
        if (mode6) {
                calc_len = dbuff[0] + 1;
                dev_specific_param = dbuff[2];
                bd_len = dbuff[3];
                long_lba = 0;
                offset = 4;
                /* prepare for mode select */
                dbuff[0] = 0;
                dbuff[1] = 0;
                dbuff[2] = 0;
        } else {
                calc_len = (dbuff[0] << 8) + dbuff[1] + 2;
                dev_specific_param = dbuff[3];
                bd_len = (dbuff[6] << 8) + dbuff[7];
                long_lba = (dbuff[4] & 1);
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
                ull = 0;
                for (j = 0; j < (long_lba ? 8 : 4); ++j) {
                        if (j > 0)
                                ull <<= 8;
                        ull |= dbuff[offset + j];
                }
                if ((0 == long_lba) && (0xffffffff == ull)) {
                        if (verbose)
                                fprintf(stderr, "Mode sense number of "
                                        "blocks maxed out, set longlba\n");
                        long_lba = 1;
                        mode6 = 0;
                        do_rcap16 = 1;
                        goto again_with_long_lba;
                }
                if (long_lba)
                        bd_blk_len = (dbuff[offset + 12] << 24) +
                                     (dbuff[offset + 13] << 16) +
                                     (dbuff[offset + 14] << 8) +
                                     dbuff[offset + 15];
                else
                        bd_blk_len = (dbuff[offset + 5] << 16) +
                                     (dbuff[offset + 6] << 8) +
                                     dbuff[offset + 7];
                if (long_lba) {
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
        if (resize ||
            (format && ((blk_count != 0) ||
                        ((blk_size > 0) && (blk_size != bd_blk_len))))) {
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
                        fprintf(stderr, "Need to perform MODE SELECT (to "
                                "change number or blocks or block length)\n");
                        fprintf(stderr, "but (single) block descriptor not "
                                "found in earlier MODE SENSE\n");
                        ret = SG_LIB_CAT_MALFORMED;
                        goto out;
                }
                if (blk_count != 0)  {
                        len = (long_lba ? 8 : 4);
                        for (j = 0; j < len; ++j)
                                dbuff[offset + j] =
                                    (blk_count >> ((len - j - 1) * 8)) & 0xff;
                } else if ((blk_size > 0) && (blk_size != bd_blk_len)) {
                        len = (long_lba ? 8 : 4);
                        for (j = 0; j < len; ++j)
                                dbuff[offset + j] = 0;
                }
                if ((blk_size > 0) && (blk_size != bd_blk_len)) {
                        if (long_lba) {
                                dbuff[offset + 12] = (blk_size >> 24) & 0xff;
                                dbuff[offset + 13] = (blk_size >> 16) & 0xff;
                                dbuff[offset + 14] = (blk_size >> 8) & 0xff;
                                dbuff[offset + 15] = blk_size & 0xff;
                        } else {
                                dbuff[offset + 5] = (blk_size >> 16) & 0xff;
                                dbuff[offset + 6] = (blk_size >> 8) & 0xff;
                                dbuff[offset + 7] = blk_size & 0xff;
                        }
                }
                if (mode6)
                        res = sg_ll_mode_select6(fd, 1 /* PF */, 1 /* SP */,
                                                 dbuff, calc_len, 1, verbose);
                else
                        res = sg_ll_mode_select10(fd, 1 /* PF */, 1 /* SP */,
                                                  dbuff, calc_len, 1, verbose);
                ret = res;
                if (res) {
                        if (SG_LIB_CAT_NOT_READY == res)
                                fprintf(stderr, "MODE SELECT command, "
                                        "device not ready\n");
                        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
                                fprintf(stderr, "MODE SELECT command, "
                                        "unit attention\n");
                        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                                fprintf(stderr, "MODE SELECT command, "
                                        "aborted command\n");
                        else if (SG_LIB_CAT_INVALID_OP == res)
                                fprintf(stderr, "MODE SELECT (%d) command is "
                                        "not supported\n", (mode6 ? 6 : 10));
                        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                                fprintf(stderr, "bad field in MODE SELECT "
                                        "(%d)\n", (mode6 ? 6 : 10));
                        else
                                fprintf(stderr, "MODE SELECT (%d) command "
                                        "failed\n", (mode6 ? 6 : 10));
                        if (0 == verbose)
                                fprintf(stderr, "    try '-v' for "
                                        "more information\n");
                        goto out;
                }
        }
        if (resize) {
                printf("Resize operation seems to have been successful\n");
                goto out;
        }
        else if (! format) {
                res = print_read_cap(fd, do_rcap16, verbose);
                if (-2 == res) {
                        do_rcap16 = 1;
                        res = print_read_cap(fd, do_rcap16, verbose);
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
                printf("No changes made. To format use '--format'. To "
                       "resize use '--resize'\n");
                goto out;
        }

        if (format)
#if 1
                printf("\nA FORMAT will commence in 10 seconds\n");
                printf("    ALL data on %s will be DESTROYED\n", device_name);
                printf("        Press control-C to abort\n");
                sleep_for(5);
                printf("A FORMAT will commence in 5 seconds\n");
                printf("    ALL data on %s will be DESTROYED\n", device_name);
                printf("        Press control-C to abort\n");
                sleep_for(5);
                res = scsi_format(fd, fmtpinfo, cmplst, pfu, ! fwait, dcrt,
                                  pie, do_si, early, pt, verbose);
                ret = res;
                if (res) {
                        fprintf(stderr, "FORMAT failed\n");
                        if (0 == verbose)
                                fprintf(stderr, "    try '-v' for more "
                                        "information\n");
                }
#else
                fprintf(stderr, "FORMAT ignored, testing\n");
#endif

out:
        res = sg_cmds_close_device(fd);
        if (res < 0) {
                fprintf(stderr, "close error: %s\n", safe_strerror(-res));
                if (0 == ret)
                        return SG_LIB_FILE_ERROR;
        }
        return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
