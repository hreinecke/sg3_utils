/*
 * Copyright (c) 2005 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program issues these SCSI commands: REPORT DEVICE IDENTIFIER,
 * SET DEVICE IDENTIFIER and/or INQUIRY (VPD=0x83 [device identifier]).
 */

static char * version_str = "1.00 20050808";

#define ME "sg_ident: "

#define REPORT_DEV_ID_SANITY_LEN 512


static struct option long_options[] = {
        {"ascii", 0, 0, 'A'},
        {"clear", 0, 0, 'C'},
        {"help", 0, 0, 'h'},
        {"raw", 0, 0, 'r'},
        {"set", 0, 0, 'S'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_ident   [--ascii] [--clear] [--help] [--raw] [--set] "
          "[--verbose]\n"
          "                  [--version] <scsi_device>\n"
          "  where: --ascii|-A      report device identifier as ASCII "
          "string\n"
          "         --clear|-C      clear (set to zero length) device "
          "identifier\n"
          "         --help|-h       print out usage message\n"
          "         --raw|-r        output device identifier to stdout\n"
          "                         fetch from stdin (when '--set')\n"
          "         --set|-S        invoke set device identifier with data "
          "from stdin\n"
          "         --verbose|-v    set device identifier\n"
          "         --version|-V    print version string and exit\n\n"
          "Performs a REPORT or SET DEVICE IDENTIFIER SCSI command\n"
          );
}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, di_len, n;
    unsigned char rdi_buff[REPORT_DEV_ID_SANITY_LEN + 4];
    unsigned char * ucp = NULL;
    int ascii = 0;
    int do_clear = 0;
    int raw = 0;
    int do_set = 0;
    int verbose = 0;
    char device_name[512];
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "AChrSvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'A':
            ascii = 1;
            break;
        case 'C':
            do_clear = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'r':
            raw = 1;
            break;
        case 'S':
            do_set = 1;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if ('\0' == device_name[0]) {
            strncpy(device_name, argv[optind], sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }

    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    if (do_set && do_clear) {
        fprintf(stderr, "only one of '--clear' and '--set' can be given\n");
        usage();
        return 1;
    }
    if (ascii && raw) {
        fprintf(stderr, "only one of '--ascii' and '--raw' can be given\n");
        usage();
        return 1;
    }
    if ((do_set || do_clear) && (raw || ascii)) {
        fprintf(stderr, "'--set' cannot be used with either '--ascii' or "
                "'--raw'\n");
        usage();
        return 1;
    }
    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", device_name);
        perror("");
        return 1;
    }

    memset(rdi_buff, 0x0, sizeof(rdi_buff));
    if (do_set || do_clear) {
        if (do_set) {
            res = fread(rdi_buff, 1, REPORT_DEV_ID_SANITY_LEN + 2, stdin); 
            if (res <= 0) {
                fprintf(stderr, "no data read from stdin; to clear "
                        "identifier use '--clear' instead\n");
                goto err_out;
            } else if (res > REPORT_DEV_ID_SANITY_LEN) {
                fprintf(stderr, "SPC-3 limits identifier length to 512 "
                        "bytes\n");
                goto err_out;
            }
            di_len = res;
            res = sg_ll_set_dev_id(sg_fd, rdi_buff, di_len, 1, verbose);
        } else    /* do_clear */
            res = sg_ll_set_dev_id(sg_fd, rdi_buff, 0, 1, verbose);
        if (0 == res)
            ret = 0;
        else {
            if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, "Set Device Identifier command not "
                        "supported\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "bad field in Set Device Identifier "
                        "cdb\n");
            else {
                fprintf(stderr, "Set Device Identifier command failed\n");
                if (0 == verbose)
                    fprintf(stderr, "    try '-v' for more information\n");
            }
        }
    } else {    /* do report device identifier */
        res = sg_ll_report_dev_id(sg_fd, rdi_buff, 4, 1, verbose);
        if (0 == res) {
            di_len = (rdi_buff[0] << 24) + (rdi_buff[1] << 16) + 
                         (rdi_buff[2] << 8) + rdi_buff[3];
            if (! raw)
                printf("Reported device identifier length = %d\n", di_len);
            if (0 == di_len) {
                fprintf(stderr, "    This implies the device has an empty "
                        "identifier\n");
                goto err_out;
            }
            if (di_len > REPORT_DEV_ID_SANITY_LEN) {
                fprintf(stderr, "    That length (%d) seems too long for a "
                        "device identifier\n", di_len);
                goto err_out;
            }
            ucp = rdi_buff;
            res = sg_ll_report_dev_id(sg_fd, ucp, di_len + 4, 1, verbose);
            if (0 == res) {
                di_len = (ucp[0] << 24) + (ucp[1] << 16) + (ucp[2] << 8) +
                         ucp[3];
                if (raw) {
                    if (di_len > 0)
                        n = fwrite(ucp + 4, 1, di_len, stdout);
                } else {
                    printf("Device identifier:\n");
                    if (di_len > 0) {
                        if (ascii)
                            printf("%.*s\n", di_len, (const char *)ucp + 4);
                        else
                            dStrHex((const char *)ucp + 4, di_len, 0); 
                    }
                }
                ret = 0;
            }
        }
        if (0 != res) {
            if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, "Report Device Identifier command not "
                        "supported\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "bad field in Report Device Identifier "
                        "cdb\n");
            else {
                fprintf(stderr, "Report Device Identifier command failed\n");
                if (0 == verbose)
                    fprintf(stderr, "    try '-v' for more information\n");
            }
        }
    }

err_out:
    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}
