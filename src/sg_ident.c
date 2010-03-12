/*
 * Copyright (c) 2005-2010 Douglas Gilbert.
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

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues these SCSI commands: REPORT IDENTIFYING INFORMATION
 * and SET IDENTIFYING INFORMATION. These commands were called REPORT
 * DEVICE IDENTIFIER and SET DEVICE IDENTIFIER prior to spc4r07.
 */

static char * version_str = "1.08 20100312";

#define ME "sg_ident: "

#define REPORT_ID_INFO_SANITY_LEN 512


static struct option long_options[] = {
        {"ascii", 0, 0, 'A'},
        {"clear", 0, 0, 'C'},
        {"help", 0, 0, 'h'},
        {"itype", 1, 0, 'i'},
        {"raw", 0, 0, 'r'},
        {"set", 0, 0, 'S'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void decode_ii(const unsigned char * iip, int ii_len, int itype,
                      int ascii, int raw, int verbose)
{
    int k, n;

    if (raw) {
        if (ii_len > 0) {
            if (sg_set_binary_mode(STDOUT_FILENO) < 0)
                perror("sg_set_binary_mode");
#if 0
            n = fwrite(iip, 1, ii_len, stdout);
#else
            n = write(STDOUT_FILENO, iip, ii_len);
#endif
        }
        return;
    }
    if (0x7f == itype) {  /* list of available information types */
        for (k = 0; k < (ii_len - 3); k += 4)
            printf("  Information type: %d, Maximum information length: "
                   "%d bytes\n", iip[k], ((iip[k + 2] << 8) + iip[k + 3]));
    } else {        /* single element */
        if (verbose)
            printf("Information:\n");
        if (ii_len > 0) {
            if (ascii)
                printf("%.*s\n", ii_len, (const char *)iip);
            else
                dStrHex((const char *)iip, ii_len, 0);
        }
    }
}

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_ident   [--ascii] [--clear] [--help] [--itype=IT] [--raw] "
          "[--set]\n"
          "                  [--verbose] [--version] DEVICE\n"
          "  where:\n"
          "    --ascii|-A      report identifying information as ASCII "
          "(or UTF8) string\n"
          "    --clear|-C      clear (set to zero length) identifying "
          "information\n"
          "    --help|-h       print out usage message\n"
          "    --itype=IT|-i IT    specify information type\n"
          "    --raw|-r        output identifying information to "
          "stdout\n"
          "    --set|-S        invoke set identifying information with "
          "data from stdin\n"
          "    --verbose|-v    increase verbosity of output\n"
          "    --version|-V    print version string and exit\n\n"
          "Performs a SCSI REPORT (or SET) IDENTIFYING INFORMATION command\n"
          );
}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, ii_len;
    unsigned char rdi_buff[REPORT_ID_INFO_SANITY_LEN + 4];
    unsigned char * ucp = NULL;
    int ascii = 0;
    int do_clear = 0;
    int itype = 0;
    int raw = 0;
    int do_set = 0;
    int verbose = 0;
    const char * device_name = NULL;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "AChi:rSvV", long_options,
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
        case 'i':
           itype = sg_get_num(optarg);
           if ((itype < 0) || (itype > 127)) {
                fprintf(stderr, "argument to '--itype' should be in range "
                        "0 to 127\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
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
    if (do_set && do_clear) {
        fprintf(stderr, "only one of '--clear' and '--set' can be given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (ascii && raw) {
        fprintf(stderr, "only one of '--ascii' and '--raw' can be given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((do_set || do_clear) && (raw || ascii)) {
        fprintf(stderr, "'--set' cannot be used with either '--ascii' or "
                "'--raw'\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    memset(rdi_buff, 0x0, sizeof(rdi_buff));
    if (do_set || do_clear) {
        if (do_set) {
            res = fread(rdi_buff, 1, REPORT_ID_INFO_SANITY_LEN + 2, stdin);
            if (res <= 0) {
                fprintf(stderr, "no data read from stdin; to clear "
                        "identifying information use '--clear' instead\n");
                ret = -1;
                goto err_out;
            } else if (res > REPORT_ID_INFO_SANITY_LEN) {
                fprintf(stderr, "SPC-4 limits information length to 512 "
                        "bytes\n");
                ret = -1;
                goto err_out;
            }
            ii_len = res;
            res = sg_ll_set_id_info(sg_fd, itype, rdi_buff, ii_len, 1,
                                    verbose);
        } else    /* do_clear */
            res = sg_ll_set_id_info(sg_fd, itype, rdi_buff, 0, 1, verbose);
        if (res) {
            ret = res;
            if (SG_LIB_CAT_NOT_READY == res)
                fprintf(stderr, "Set identifying information command, device "
                        "not ready\n");
            else if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, "Set identifying information command not "
                        "supported\n");
            else if (SG_LIB_CAT_UNIT_ATTENTION == res)
                fprintf(stderr, "Set identifying information, unit "
                        "attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                fprintf(stderr, "Set identifying information, aborted "
                        "command\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "bad field in Set identifying information "
                        "cdb including unsupported service action\n");
            else {
                fprintf(stderr, "Set identifying information command "
                        "failed\n");
                if (0 == verbose)
                    fprintf(stderr, "    try '-v' for more information\n");
            }
        }
    } else {    /* do report identifying information */
        res = sg_ll_report_id_info(sg_fd, itype, rdi_buff, 4, 1, verbose);
        if (0 == res) {
            ii_len = (rdi_buff[0] << 24) + (rdi_buff[1] << 16) +
                         (rdi_buff[2] << 8) + rdi_buff[3];
            if ((! raw) && (verbose > 0))
                printf("Reported identifying information length = %d\n",
                       ii_len);
            if (0 == ii_len) {
                if (verbose > 1)
                    fprintf(stderr, "    This implies the device has an "
                            "empty information field\n");
                goto err_out;
            }
            if (ii_len > REPORT_ID_INFO_SANITY_LEN) {
                fprintf(stderr, "    That length (%d) seems too long for an "
                        "information\n", ii_len);
                ret = -1;
                goto err_out;
            }
            ucp = rdi_buff;
            res = sg_ll_report_id_info(sg_fd, itype, ucp, ii_len + 4, 1,
                                       verbose);
            if (0 == res) {
                ii_len = (ucp[0] << 24) + (ucp[1] << 16) + (ucp[2] << 8) +
                         ucp[3];
                decode_ii(ucp + 4, ii_len, itype, ascii, raw, verbose);
            } else
                ret = res;
        } else
            ret = res;
        if (ret) {
            if (SG_LIB_CAT_NOT_READY == ret)
                fprintf(stderr, "Report identifying information command, "
                        "device not ready\n");
            else if (SG_LIB_CAT_UNIT_ATTENTION == ret)
                fprintf(stderr, "Report identifying information, unit "
                        "attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == ret)
                fprintf(stderr, "Report identifying information, aborted "
                        "command\n");
            else if (SG_LIB_CAT_INVALID_OP == ret)
                fprintf(stderr, "Report identifying information command "
                        "not supported\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == ret)
                fprintf(stderr, "bad field in Report identifying "
                        "information cdb including unsupported service "
                        "action\n");
            else {
                fprintf(stderr, "Report identifying information command "
                        "failed\n");
                if (0 == verbose)
                    fprintf(stderr, "    try '-v' for more "
                            "information\n");
            }
        }
    }

err_out:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
