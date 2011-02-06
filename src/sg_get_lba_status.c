/*
 * Copyright (c) 2009-2011 Douglas Gilbert.
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

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI GET LBA STATUS command to the given SCSI device.
 */

static char * version_str = "1.03 20110204";    /* sbc2r22 */

#define MAX_GLBAS_BUFF_LEN (1024 * 1024)
#define DEF_GLBAS_BUFF_LEN 24

static unsigned char glbasBuff[DEF_GLBAS_BUFF_LEN];
static unsigned char * glbasBuffp = glbasBuff;


static struct option long_options[] = {
        {"brief", no_argument, 0, 'b'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"lba", required_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"raw", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
usage()
{
    fprintf(stderr, "Usage: "
            "sg_get_lba_status  [--brief] [--help] [--hex] [--lba=LBA]\n"
            "                          [--maxlen=LEN] [--raw] [--verbose] "
            "[--version]\n"
            "                          DEVICE\n"
            "  where:\n"
            "    --brief|-b        a descriptor per line: "
            "<lba_hex blocks_hex p_status>\n"
            "                      use twice ('-bb') for given LBA "
            "provisioning status\n"
            "    --help|-h         print out usage message\n"
            "    --hex|-H          output in hexadecimal\n"
            "    --lba=LBA|-l LBA    starting LBA (logical block address) "
            "(def: 0)\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> %d bytes)\n",
            DEF_GLBAS_BUFF_LEN );
    fprintf(stderr,
            "    --raw|-r          output in binary\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Performs a SCSI GET LBA STATUS command (SBC-3)\n"
            );
}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

/* Decodes given LBA status descriptor passing back the starting LBA,
 * the number of blocks and returns the provisioning status, -1 for error.
 */
static int
decode_lba_status_desc(const unsigned char * ucp, uint64_t * slbap,
                       uint32_t * blocksp)
{
    int j;
    uint32_t blocks;
    uint64_t ull;

    if (NULL == ucp)
        return -1;
    ull = 0;
    for (j = 0; j < 8; ++j) {
        if (j > 0)
            ull <<= 8;
        ull |= ucp[j];
    }
    blocks = 0;
    for (j = 0; j < 4; ++j) {
        if (j > 0)
            blocks <<= 8;
        blocks |= ucp[8 + j];
    }
    if (slbap)
        *slbap = ull;
    if (blocksp)
        *blocksp = blocks;
    return ucp[12] & 0xf;
}


int
main(int argc, char * argv[])
{
    int sg_fd, k, j, res, c, rlen, num_descs;
    int do_brief = 0;
    int do_hex = 0;
    int64_t ll;
    uint64_t lba = 0;
    uint64_t d_lba = 0;
    uint32_t d_blocks = 0;
    int maxlen = DEF_GLBAS_BUFF_LEN;
    int do_raw = 0;
    int verbose = 0;
    const char * device_name = NULL;
    const unsigned char * ucp;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "bhHl:m:rvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            ++do_brief;
            break;
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
            if ((maxlen < 0) || (maxlen > MAX_GLBAS_BUFF_LEN)) {
                fprintf(stderr, "argument to '--maxlen' should be %d or "
                        "less\n", MAX_GLBAS_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
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
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (maxlen > DEF_GLBAS_BUFF_LEN) {
        glbasBuffp = (unsigned char *)calloc(maxlen, 1);
        if (NULL == glbasBuffp) {
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

    res = sg_ll_get_lba_status(sg_fd, lba, glbasBuffp, maxlen, 1,
                               verbose);
    ret = res;
    if (0 == res) {
        if (maxlen >= 4)
            rlen = (glbasBuffp[0] << 24) + (glbasBuffp[1] << 16) +
                   (glbasBuffp[2] << 8) + glbasBuffp[3] + 8;
        else
            rlen = maxlen;
        k = (rlen > maxlen) ? maxlen : rlen;
        if (do_raw) {
            dStrRaw((const char *)glbasBuffp, k);
            goto the_end;
        }
        if (do_hex) {
            dStrHex((const char *)glbasBuffp, k, 1);
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
        
        if (do_brief > 1) {
            if (rlen < 24) {
                fprintf(stderr, "Need maxlen and response length to "
                        " be at least 24, have %d bytes\n", rlen);
                ret = SG_LIB_CAT_OTHER;
                goto the_end;
            }
            res = decode_lba_status_desc(glbasBuffp + 8, &d_lba, &d_blocks);
            if ((res < 0) || (res > 15)) {
                fprintf(stderr, "first LBA status descriptor returned %d "
                        "??\n", res);
                ret = SG_LIB_CAT_OTHER;
                goto the_end;
            }
            if ((lba < d_lba) || (lba >= (d_lba + d_blocks))) {
                fprintf(stderr, "given LBA not in range of first "
                        "descriptor:\n" "  descriptor LBA: 0x");
                for (j = 0; j < 8; ++j)
                    fprintf(stderr, "%02x", glbasBuffp[8 + j]);
                fprintf(stderr, "  blocks: 0x%x  p_status: %d\n",
                        (unsigned int)d_blocks, res);
                ret = SG_LIB_CAT_OTHER;
                goto the_end;
            }
            printf("%d\n", res);
            goto the_end;
        }

        if (rlen < 24) {
            printf("No complete LBA status descriptors available\n");
            goto the_end;
        }
        num_descs = (rlen - 8) / 16;
        if (verbose)
            fprintf(stderr, "%d complete LBA status descriptors found\n",
                    num_descs);
        for (ucp = glbasBuffp + 8, k = 0; k < num_descs; ucp += 16, ++k) {
            res = decode_lba_status_desc(ucp, &d_lba, &d_blocks);
            if ((res < 0) || (res > 15))
                fprintf(stderr, "descriptor %d: bad LBA status descriptor "
                        "returned %d\n", k + 1, res);
            if (do_brief) {
                printf("0x");
                for (j = 0; j < 8; ++j)
                    printf("%02x", ucp[j]);
                printf("  0x%x  %d\n", (unsigned int)d_blocks, res);
            } else {
                printf("descriptor LBA: 0x");
                for (j = 0; j < 8; ++j)
                    printf("%02x", ucp[j]);
                printf("  blocks: %u", (unsigned int)d_blocks);
                switch (res) {
                case 0:
                    printf("  mapped\n");
                    break;
                case 1:
                    printf("  deallocated\n");
                    break;
                case 2:
                    printf("  anchored\n");
                    break;
                default:
                    printf("  Provisioning status: %d\n", res);
                    break;
                }
            }
        }
        if ((num_descs * 16) + 8 < rlen)
            fprintf(stderr, "incomplete trailing LBA status descriptors "
                    "found\n");
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Get LBA Status command not supported\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "Get LBA Status, aborted command\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "Get LBA Status command has bad field in cdb\n");
    else {
        fprintf(stderr, "Get LBA Status command failed\n");
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
    if (glbasBuffp && (glbasBuffp != glbasBuff))
        free(glbasBuffp);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
