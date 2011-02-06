/*
 * Copyright (c) 2005-2011 Douglas Gilbert.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"

/* A utility program was originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI command READ MEDIA SERIAL NUMBER
 * to the given SCSI device.
 */

static char * version_str = "1.09 20110206";

#define SERIAL_NUM_SANITY_LEN (16 * 1024)


static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"raw", 0, 0, 'r'},
        {"readonly", 0, 0, 'R'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_rmsn   [--help] [--raw] [--readonly] [--verbose] [--version]\n"
          "                 DEVICE\n"
          "  where:\n"
          "    --help|-h       print out usage message\n"
          "    --raw|-r        output serial number to stdout "
          "(potentially binary)\n"
          "    --readonly|-R    open DEVICE read-only (def: open it "
          "read-write)\n"
          "    --verbose|-v    increase verbosity\n"
          "    --version|-V    print version string and exit\n\n"
          "Performs a SCSI READ MEDIA SERIAL NUMBER command\n"
          );
}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, sn_len, n;
    unsigned char rmsn_buff[4];
    unsigned char * ucp = NULL;
    int raw = 0;
    int readonly = 0;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hrRvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'r':
            ++raw;
            break;
        case 'R':
            ++readonly;
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
    if (raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    memset(rmsn_buff, 0x0, sizeof(rmsn_buff));

    res = sg_ll_read_media_serial_num(sg_fd, rmsn_buff, sizeof(rmsn_buff),
                                      1, verbose);
    ret = res;
    if (0 == res) {
        sn_len = (rmsn_buff[0] << 24) + (rmsn_buff[1] << 16) +
                     (rmsn_buff[2] << 8) + rmsn_buff[3];
        if (! raw)
            printf("Reported serial number length = %d\n", sn_len);
        if (0 == sn_len) {
            fprintf(stderr, "    This implies the media has no serial "
                    "number\n");
            goto err_out;
        }
        if (sn_len > SERIAL_NUM_SANITY_LEN) {
            fprintf(stderr, "    That length (%d) seems too long for a "
                    "serial number\n", sn_len);
            goto err_out;
        }
        sn_len += 4;
        ucp = (unsigned char *)malloc(sn_len);
        if (NULL == ucp) {
            fprintf(stderr, "    Out of memory (ram)\n");
            goto err_out;
        }
        res = sg_ll_read_media_serial_num(sg_fd, ucp, sn_len, 1, verbose);
        if (0 == res) {
            sn_len = (ucp[0] << 24) + (ucp[1] << 16) + (ucp[2] << 8) +
                     ucp[3];
            if (raw) {
                if (sn_len > 0)
                    n = fwrite(ucp + 4, 1, sn_len, stdout);
            } else {
                printf("Serial number:\n");
                if (sn_len > 0)
                    dStrHex((const char *)ucp + 4, sn_len, 0);
            }
        }
    }
    if (0 != res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "Read Media Serial Number command not "
                    "supported\n");
        else if (SG_LIB_CAT_NOT_READY == res)
            fprintf(stderr, "Read Media Serial Number failed, device not "
                    "ready\n");
        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
            fprintf(stderr, "Read Media Serial Number failed, unit "
                    "attention\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "Read Media Serial Number failed, aborted "
                    "command\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in Read Media Serial Number cdb "
                    "including unsupported service action\n");
        else {
            fprintf(stderr, "Read Media Serial Number failed\n");
            if (0 == verbose)
                fprintf(stderr, "    try '-v' for more information\n");
        }
    }

err_out:
    if (ucp)
        free(ucp);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
