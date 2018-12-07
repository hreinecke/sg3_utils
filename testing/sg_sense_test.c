/*
 *  Copyright (C) 2004-2018 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This is a simple program that tests the sense data descriptor format
 * printout function in sg_lib.c . */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include "sg_lib.h"


#define EBUFF_SZ 256

#define ME "sg_sense_test: "

static const char * version_str = "2.04 20181207";

static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"leadin",  required_argument, 0, 'l'},
        {"stdout",  no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},   /* sentinel */
};


static void
usage()
{
    fprintf(stderr,
            "Usage: %s [--help] [--leadin=STR] [--stdout] [--verbose] "
            "[--version]\n"
            "  where: --help|-h          print out usage message\n"
            "         --leadin=STR|-l STR    every line output by --sense "
            "should\n"
            "                                be prefixed by STR\n"
            "         --stdout|-s        send output to stdout (def: "
            "stderr)\n"
            "         --verbose|-v       increase verbosity\n"
            "         --version|-V       print version string and exit\n\n"
            "Test sense data handling of sg_lib. Overlaps somewhat with "
            "tst_sg_lib\n", ME
           );

}

int
main(int argc, char * argv[])
{
    bool to_stdout = false;
    int c, k, prev_len;
    int verbose = 0;
    const char * leadin = NULL;
    FILE * outfp = stderr;
    uint8_t err1[] = {0x72, 0x5, 0x24, 0x0, 0, 0, 0, 32,
                      0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                      0, 0xa, 0x80, 0, 1, 2, 3, 4,
                      0xaa, 0xbb, 0xcc, 0xdd,
                      1, 0xa, 0, 0, 1, 2, 3, 4,
                      0xaa, 0xbb, 0xee, 0xff};
    uint8_t err2[] = {0x72, SPC_SK_MEDIUM_ERROR, 0x11, 0xb, 0x80, 0, 0,
                      32,
                      0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                      0, 0xa, 0x80, 0, 1, 2, 3, 4,
                      0xaa, 0xbb, 0xcc, 0xdd,
                      1, 0xa, 0, 0, 1, 2, 3, 4,
                      0xaa, 0xbb, 0xee, 0xff};
                     /* Set SDAT_OVFL */
    uint8_t err3[] = {0x72, SPC_SK_NO_SENSE, 0x4, 0x4, 0, 0, 0, 8,
                      0x2, 0x6, 0, 0, 0xc8, 0x12, 0x34, 0};
    uint8_t err4[] = {0x73, SPC_SK_COPY_ABORTED, 0x8, 0x4, 0, 0, 0, 22,
                      0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                      0x3, 0x2, 0, 0x55,
                      0x5, 0x2, 0, 0x20,
                      0x85, 0x4, 0, 0x20, 0x33, 0x44};
                     /* Set Filemark, EOM, ILI and SDAT_OVFL */
    uint8_t err5[] = {0xf1, 0, (0xf0 | SPC_SK_ILLEGAL_REQUEST), 0x11,
                      0x22, 0x33, 0x44, 0xa,
                      0x0, 0x0, 0, 0, 0x4, 0x1, 0, 0xcf, 0, 5,};
    uint8_t err6[] = {0x72, SPC_SK_NO_SENSE, 0x4, 0x1, 0, 0, 0, 14,
                      0x9, 0xc, 1, 0, 0x11, 0x22, 0x66, 0x33,
                      0x77, 0x44, 0x88, 0x55, 0x1, 0x2};
    uint8_t err7[] = {0xf1, 0, 0xe5, 0x11, 0x22, 0x33, 0x44, 0xa,
                      0x0, 0x0, 0x0, 0x0, 0x24, 0x1, 0xbb,
                      0xc9, 0x0, 0x2};
                     /* Vendor specific, with "valid" bit set */
    uint8_t err8[] = {0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc,
                      0xd, 0xe, 0xf, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
                      0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0};
    char b[2048];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hl:svV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            leadin = optarg;
            break;
        case 's':
            to_stdout = true;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }
    if (to_stdout) {
        outfp = stdout;
        sg_set_warnings_strm(outfp);
    }

    fprintf(outfp, "err1 test:\n");
    sg_print_sense(leadin, err1, sizeof(err1), verbose /* raw_info */);
    fprintf(outfp, "\n");
    fprintf(outfp, "err2 test:\n");
    sg_print_sense(leadin, err2, sizeof(err2), verbose);
    fprintf(outfp, "\n");
    fprintf(outfp, "err3 test:\n");
    sg_print_sense(leadin, err3, sizeof(err3), verbose);
    fprintf(outfp, "\n");
    fprintf(outfp, "err4 test:\n");
    sg_print_sense(leadin, err4, sizeof(err4), verbose);
    fprintf(outfp, "\n");
    fprintf(outfp, "err5 test: Set Filemark, EOM, ILI and SDAT_OVFL\n");
    sg_print_sense(leadin, err5, sizeof(err5), verbose);
    fprintf(outfp, "\n");
    fprintf(outfp, "err6 test:\n");
    sg_print_sense(leadin, err6, sizeof(err6), verbose);
    fprintf(outfp, "\n");
    fprintf(outfp, "err7 test:\n");
    sg_print_sense(leadin, err7, sizeof(err7), verbose);
    fprintf(outfp, "\n");
    fprintf(outfp, "err8 test (vendor specific):\n");
    sg_print_sense(leadin, err8, sizeof(err8), verbose);
    fprintf(outfp, "\n");

    if (verbose > 1) {
        fprintf(outfp, "\n\nTry different output string sizes with "
               "sg_get_sense_str(err2):\n");
        for (k = 1, prev_len = -1; k < 512; ++k) {
            /* snprintf(leadin, sizeof(leadin), "blen=%d", k); */
            sg_get_sense_str(NULL, err2, sizeof(err2), 0, k, b);
            fprintf(outfp, "%s\n", b);
            if (prev_len == (int)strlen(b))
                break;
            else
                prev_len = strlen(b);
        }
    }

    if (verbose > 2) {
        fprintf(outfp, "\n\nTry different output string sizes with "
               "sg_get_sense_str(err4):\n");
        for (k = 1, prev_len = -1; k < 512; ++k) {
            /* snprintf(leadin, sizeof(leadin), "blen=%d", k); */
            sg_get_sense_str(NULL, err4, sizeof(err4), 0, k, b);
            fprintf(outfp, "%s\n", b);
            if (prev_len == (int)strlen(b))
                break;
            else
                prev_len = strlen(b);
        }
    }
    return 0;
}
