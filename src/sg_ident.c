/*
 * Copyright (c) 2005-2018 Douglas Gilbert.
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
#include <string.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues these SCSI commands: REPORT IDENTIFYING INFORMATION
 * and SET IDENTIFYING INFORMATION. These commands were called REPORT
 * DEVICE IDENTIFIER and SET DEVICE IDENTIFIER prior to spc4r07.
 */

static const char * version_str = "1.23 20180814";

#define ME "sg_ident: "

#define REPORT_ID_INFO_SANITY_LEN 512


static struct option long_options[] = {
        {"ascii", no_argument, 0, 'A'},
        {"clear", no_argument, 0, 'C'},
        {"help", no_argument, 0, 'h'},
        {"itype", required_argument, 0, 'i'},
        {"raw", no_argument, 0, 'r'},
        {"set", no_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void
decode_ii(const uint8_t * iip, int ii_len, int itype, bool ascii,
          bool raw, int verbose)
{
    int k;

    if (raw) {
        if (ii_len > 0) {
            int n;

            if (sg_set_binary_mode(STDOUT_FILENO) < 0)
                perror("sg_set_binary_mode");
#if 0
            n = fwrite(iip, 1, ii_len, stdout);
#else
            n = write(STDOUT_FILENO, iip, ii_len);
#endif
            if (verbose && (n < 1))
                pr2serr("unable to write to stdout\n");
        }
        return;
    }
    if (0x7f == itype) {  /* list of available information types */
        for (k = 0; k < (ii_len - 3); k += 4)
            printf("  Information type: %d, Maximum information length: "
                   "%d bytes\n", iip[k], sg_get_unaligned_be16(iip + 2));
    } else {        /* single element */
        if (verbose)
            printf("Information:\n");
        if (ii_len > 0) {
            if (ascii)
                printf("%.*s\n", ii_len, (const char *)iip);
            else
                hex2stdout(iip, ii_len, 0);
        }
    }
}

static void
usage(void)
{
    pr2serr("Usage: sg_ident   [--ascii] [--clear] [--help] [--itype=IT] "
            "[--raw] [--set]\n"
            "                  [--verbose] [--version] DEVICE\n"
            "  where:\n"
            "    --ascii|-A      report identifying information as ASCII "
            "(or UTF8) string\n"
            "    --clear|-C      clear (set to zero length) identifying "
            "information\n"
            "    --help|-h       print out usage message\n"
            "    --itype=IT|-i IT    specify identifying information type "
            "(def: 0)\n"
            "    --raw|-r        output identifying information to "
            "stdout\n"
            "    --set|-S        invoke set identifying information with "
            "data from stdin\n"
            "    --verbose|-v    increase verbosity of output\n"
            "    --version|-V    print version string and exit\n\n"
            "Performs a SCSI REPORT (or SET) IDENTIFYING INFORMATION "
            "command. When no\noptions are given then REPORT IDENTIFYING "
            "INFORMATION is sent and the\nresponse is output in "
            "hexadecimal with ASCII to the right.\n");
}

int
main(int argc, char * argv[])
{
    bool ascii = false;
    bool do_clear = false;
    bool raw = false;
    bool do_set = false;
    bool verbose_given = false;
    bool version_given = false;
    int sg_fd, res, c, ii_len;
    uint8_t rdi_buff[REPORT_ID_INFO_SANITY_LEN + 4];
    char b[80];
    uint8_t * bp = NULL;
    int itype = 0;
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
            ascii = true;
            break;
        case 'C':
            do_clear = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
           itype = sg_get_num(optarg);
           if ((itype < 0) || (itype > 127)) {
                pr2serr("argument to '--itype' should be in range 0 to 127\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            raw = true;
            break;
        case 'S':
            do_set = true;
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
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
        verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", verbose);
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
    if (do_set && do_clear) {
        pr2serr("only one of '--clear' and '--set' can be given\n");
        usage();
        return SG_LIB_CONTRADICT;
    }
    if (ascii && raw) {
        pr2serr("only one of '--ascii' and '--raw' can be given\n");
        usage();
        return SG_LIB_CONTRADICT;
    }
    if ((do_set || do_clear) && (raw || ascii)) {
        pr2serr("'--set' cannot be used with either '--ascii' or '--raw'\n");
        usage();
        return SG_LIB_CONTRADICT;
    }
    sg_fd = sg_cmds_open_device(device_name, false /* rw=false */, verbose);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        return sg_convert_errno(-sg_fd);
    }

    memset(rdi_buff, 0x0, sizeof(rdi_buff));
    if (do_set || do_clear) {
        if (do_set) {
            res = fread(rdi_buff, 1, REPORT_ID_INFO_SANITY_LEN + 2, stdin);
            if (res <= 0) {
                pr2serr("no data read from stdin; to clear identifying "
                        "information use '--clear' instead\n");
                ret = -1;
                goto err_out;
            } else if (res > REPORT_ID_INFO_SANITY_LEN) {
                pr2serr("SPC-4 limits information length to 512 bytes\n");
                ret = -1;
                goto err_out;
            }
            ii_len = res;
            res = sg_ll_set_id_info(sg_fd, itype, rdi_buff, ii_len, true,
                                    verbose);
        } else    /* do_clear */
            res = sg_ll_set_id_info(sg_fd, itype, rdi_buff, 0, true, verbose);
        if (res) {
            ret = res;
            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("Set identifying information: %s\n", b);
            if (0 == verbose)
                pr2serr("    try '-v' for more information\n");
        }
    } else {    /* do report identifying information */
        res = sg_ll_report_id_info(sg_fd, itype, rdi_buff, 4, true, verbose);
        if (0 == res) {
            ii_len = sg_get_unaligned_be32(rdi_buff + 0);
            if ((! raw) && (verbose > 0))
                printf("Reported identifying information length = %d\n",
                       ii_len);
            if (0 == ii_len) {
                if (verbose > 1)
                    pr2serr("    This implies the device has an empty "
                            "information field\n");
                goto err_out;
            }
            if (ii_len > REPORT_ID_INFO_SANITY_LEN) {
                pr2serr("    That length (%d) seems too long for an "
                        "information\n", ii_len);
                ret = -1;
                goto err_out;
            }
            bp = rdi_buff;
            res = sg_ll_report_id_info(sg_fd, itype, bp, ii_len + 4, true,
                                       verbose);
            if (0 == res) {
                ii_len = sg_get_unaligned_be32(bp + 0);
                decode_ii(bp + 4, ii_len, itype, ascii, raw, verbose);
            } else
                ret = res;
        } else
            ret = res;
        if (ret) {
            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("Report identifying information: %s\n", b);
            if (0 == verbose)
                pr2serr("    try '-v' for more information\n");
        }
    }

err_out:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            ret = sg_convert_errno(-res);
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_ident failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
