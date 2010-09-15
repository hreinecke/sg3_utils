/*
 * Copyright (c) 2010 Hannes Reinecke.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"

/*
 * A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI REPORT REFERRALS command to the given
 * SCSI device.
 */

static char * version_str = "1.03 20100813";    /* sbc3r24 */

#define MAX_REFER_BUFF_LEN (1024 * 1024)
#define DEF_REFER_BUFF_LEN 256

#define TPGS_STATE_OPTIMIZED 0x0
#define TPGS_STATE_NONOPTIMIZED 0x1
#define TPGS_STATE_STANDBY 0x2
#define TPGS_STATE_UNAVAILABLE 0x3
#define TPGS_STATE_LB_DEPENDENT 0x4
#define TPGS_STATE_OFFLINE 0xe          /* SPC-4 rev 9 */
#define TPGS_STATE_TRANSITIONING 0xf

static unsigned char referralBuff[DEF_REFER_BUFF_LEN];
static unsigned char * referralBuffp = referralBuff;

static const char *decode_tpgs_state(const int st)
{
    switch (st) {
    case TPGS_STATE_OPTIMIZED:
        return "active/optimized";
        break;
    case TPGS_STATE_NONOPTIMIZED:
        return "active/non optimized";
        break;
    case TPGS_STATE_STANDBY:
        return "standby";
        break;
    case TPGS_STATE_UNAVAILABLE:
        return "unavailable";
        break;
    case TPGS_STATE_LB_DEPENDENT:
        return "logical block dependent";
        break;
    case TPGS_STATE_OFFLINE:
        return "offline";
        break;
    case TPGS_STATE_TRANSITIONING:
        return "transitioning between states";
        break;
    default:
        return "unknown";
        break;
    }
}

static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"lba", required_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"one-segment", no_argument, 0, 's'},
        {"raw", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
    fprintf(stderr, "Usage: "
            "sg_referrals  [--help] [--hex] [--lba=LBA] [--maxlen=LEN]\n"
            "                     [--one-segment] [--raw] [--verbose] "
            "[--version]\n"
            "                     DEVICE\n"
            "  where:\n"
            "    --help|-h         print out usage message\n"
            "    --hex|-H          output in hexadecimal\n"
            "    --lba=LBA|-l LBA    starting LBA (logical block address) "
            "(def: 0)\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n",
            DEF_REFER_BUFF_LEN );
    fprintf(stderr,
            "    --one-segment|-s    return information about the specified "
            "segment only\n"
            "    --raw|-r          output in binary\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Performs a SCSI REPORT REFERRALS command (SBC-3)\n"
            );
}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

/* Decodes given user data referral segment descriptor
 * the number of blocks and returns the number of bytes processed,
 * -1 for error.
 */
static int
decode_referral_desc(const unsigned char * ucp, int bytes)
{
    int j, n;
    uint64_t first, last;

    if (NULL == ucp)
        return -1;

    if (bytes < 20)
        return -1;

    first = ((uint64_t)ucp[4] << 56) | ((uint64_t)ucp[5] << 48) |
        ((uint64_t)ucp[6] << 40) | ((uint64_t)ucp[7] << 32) |
        ((uint64_t)ucp[8] << 24) | ((uint64_t)ucp[9] << 16) |
        ((uint64_t)ucp[10] << 8) | (uint64_t)ucp[11];
    last = ((uint64_t)ucp[12] << 56) | ((uint64_t)ucp[13] << 48) |
        ((uint64_t)ucp[14] << 40) | ((uint64_t)ucp[15] << 32) |
        ((uint64_t)ucp[16] << 24) | ((uint64_t)ucp[17] << 16) |
        ((uint64_t)ucp[18] << 8) | (uint64_t)ucp[19];

    printf("    target port descriptors: %d\n", ucp[3]);
    printf("    user data segment: first lba %" PRIu64 ", last lba %"
          PRIu64 "\n", first, last);
    n = 20;
    bytes -= n;
    for (j = 0; j < ucp[3]; j++) {
        if (bytes < 4)
            return -1;
        printf("      target port descriptor %d:\n", j);
        printf("        port group %x state (%s)\n",
               (ucp[n+2] << 8) | (ucp[n+3]), decode_tpgs_state(ucp[n] & 0xf));
        n += 4;
        bytes -= 4;
    }
    return n;
}


int
main(int argc, char * argv[])
{
    int sg_fd, k, res, c, rlen;
    int do_hex = 0;
    int do_one_segment = 0;
    int64_t ll;
    uint64_t lba = 0;
    int maxlen = DEF_REFER_BUFF_LEN;
    int do_raw = 0;
    int verbose = 0;
    int desc = 0;
    const char * device_name = NULL;
    const unsigned char * ucp;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHl:m:rsvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'l':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                fprintf(stderr, "bad argument to '--lba'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            lba = (uint64_t)ll;
            break;
        case 'm':
            maxlen = sg_get_num(optarg);
            if ((maxlen < 0) || (maxlen > MAX_REFER_BUFF_LEN)) {
                fprintf(stderr, "argument to '--maxlen' should be %d or "
                        "less\n", MAX_REFER_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 's':
            ++do_one_segment;
            break;
        case 'r':
            ++do_raw;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
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
        fprintf(stderr, "No DEVICE argument given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (maxlen > DEF_REFER_BUFF_LEN) {
        referralBuffp = (unsigned char *)calloc(maxlen, 1);
        if (NULL == referralBuffp) {
            fprintf(stderr, "unable to allocate %d bytes on heap\n", maxlen);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto free_buff;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        ret = SG_LIB_FILE_ERROR;
        goto free_buff;
    }

    res = sg_ll_report_referrals(sg_fd, lba, do_one_segment, referralBuffp,
                                 maxlen, 1, verbose);
    ret = res;
    if (0 == res) {
        if (maxlen >= 4)
            /*
             * This is strictly speaking incorrect. However, the
             * spec reserved bytes 0 and 1, so some implementations
             * might want to use them to increase the number of
             * possible user segments.
             * And maybe someone takes a pity and updates the spec ...
             */
            rlen = (referralBuffp[0] << 24) + (referralBuffp[1] << 16) +
                   (referralBuffp[2] << 8) + referralBuffp[3] + 4;
        else
            rlen = maxlen;
        k = (rlen > maxlen) ? maxlen : rlen;
        if (do_raw) {
            dStrRaw((const char *)referralBuffp, k);
            goto the_end;
        }
        if (do_hex) {
            dStrHex((const char *)referralBuffp, k, 1);
            goto the_end;
        }
        if (maxlen < 4) {
            if (verbose)
                fprintf(stderr, "Exiting because allocation length (maxlen) "
                        " less than 4\n");
            goto the_end;
        }
        if ((verbose > 1) || (verbose && (rlen > maxlen))) {
            fprintf(stderr, "response length %d bytes\n", rlen);
            if (rlen > maxlen)
                fprintf(stderr, "  ... which is greater than maxlen "
                        "(allocation length %d), truncation\n", maxlen);
        }
        if (rlen > maxlen)
            rlen = maxlen;

        ucp = referralBuffp + 4;
        k = 0;
        printf("Report referrals:\n");
        while (k < rlen - 4) {
            printf("  descriptor %d:\n", desc);
            res = decode_referral_desc(ucp + k, rlen - 4 - k);
            if (res < 0) {
                fprintf(stderr, "bad user data segment referral descriptor\n");
                k = rlen - 4;
                break;
            }
            k += res;
            desc++;
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Report Referrals command not supported\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "Report Referrals, aborted command\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "Report Referrals command has bad field in cdb\n");
    else {
        fprintf(stderr, "Report Referrals command failed\n");
        if (0 == verbose)
            fprintf(stderr, "    try '-v' option for more information\n");
    }

the_end:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            ret = SG_LIB_FILE_ERROR;
    }
free_buff:
    if (referralBuffp && (referralBuffp != referralBuff))
        free(referralBuffp);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
