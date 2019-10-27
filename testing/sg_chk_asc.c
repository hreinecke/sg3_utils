/*
 * Copyright (c) 2006-2019 Douglas Gilbert.
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
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>

#include "sg_lib.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This program takes a asc_ascq.txt file from www.t10.org and
 * checks it against the additional sense codes held in the
 * sg_lib.c file.
 * The online version of the asc_ascq codes can be found at:
 * http://www.t10.org/lists/asc-num.txt
 */

static const char * version_str = "1.08 20191014";


#define MAX_LINE_LEN 1024


static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
            "sg_chk_asc [--help] [--offset=POS] [--verbose] [--version]\n"
            "                  <asc_ascq_file>\n"
            "  where:\n"
            "    --help|-h          print out usage message\n"
            "    --offset=POS|-o POS    line position in file where "
            "text starts\n"
            "                           origin 0 (def: 24 (was 25))\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Checks asc/ascq codes in <asc_ascq_file> against the sg3_utils "
            "library.\nThe additional sense code (asc_ascq) can be found at\n"
            "www.t10.org/lists/asc-num.txt .\n"
           );

}

int main(int argc, char * argv[])
{
    int k, j, res, c, num, len;
    unsigned int asc, ascq;
    FILE * fp;
    int offset = 24;
    int verbose = 0;
    char file_name[256];
    char line[MAX_LINE_LEN];
    char b[MAX_LINE_LEN];
    char bb[MAX_LINE_LEN];
    char * cp;
    int ret = 1;

    memset(file_name, 0, sizeof file_name);
    memset(line, 0, sizeof file_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ho:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'o':
            offset = sg_get_num(optarg);
            if (offset < 0) {
                fprintf(stderr, "bad argument to --offset\n");
                return 1;
            }
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
        if ('\0' == file_name[0]) {
            strncpy(file_name, argv[optind], sizeof(file_name) - 1);
            file_name[sizeof(file_name) - 1] = '\0';
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

    if (0 == file_name[0]) {
        fprintf(stderr, "missing file name!\n");
        usage();
        return 1;
    }
    fp = fopen(file_name, "r");
    if (NULL == fp) {
        fprintf(stderr, "open error: %s: %s\n", file_name,
                safe_strerror(errno));
        return 1;
    }
    for (k = 0; (cp = fgets(line, sizeof(line) - 1, fp)); ++k) {
        len = strlen(line);
        if (len < 1)
            continue;
        if (! isdigit(line[0]))
            continue;
        num = sscanf(line, "%xh/%xh", &asc, &ascq);
        if (1 == num)
            ascq = 999;
        if (num < 1) {
            if (verbose)
                fprintf(stderr, "Badly formed line number %d (num=%d)\n",
                        k + 1, num);
            continue;
        }
        if (len < 26)
            continue;
#if 0
strncpy(b , line, sizeof(b) - 1);
b[sizeof(b) - 1] = '\0';
num = strlen(b);
if (0xd == b[num - 2]) {
    b[num - 2] = '\0';
    b[num - 1] = '\0';
}
printf("\"%s\",\n", b);
#endif
        strncpy(b , line + offset, sizeof(b) - 1);
        b[sizeof(b) - 1] = '\0';
        num = strlen(b);
        if (0xd == b[num - 2])
            b[num - 2] = '\0';
        b[num - 1] = '\0';
        num = strlen(b);
        for (j = 0; j < num; ++j)
            b[j] = toupper(b[j]);

        bb[0] = '\0';
        if (ascq < 999) {
            cp = sg_get_asc_ascq_str(asc, ascq, sizeof(bb) - 1, bb);
            if (NULL == cp) {
                fprintf(stderr, "no entry for %x,%x : %s\n", asc, ascq, b);
                continue;
            }
            num = strlen(cp);
// fprintf(stderr, "file: asc=%x  acsq=%x  strlen=%d %s\n", asc, ascq, num,
//         cp);
//            if (num < 20)
//                continue;
            if ((num > 6) &&
                ((0 == memcmp("ASC", cp, 3)) ||
                 (0 == memcmp("vendor", cp, 6)))) {
                fprintf(stderr, "%x,%x differ, ref: %s, sg_lib_data: "
                        "<missing>\n", asc, ascq, b);
                continue;
            }
            if (num > 20) {
                cp += 18;
                num -= 18;
                for (j = 0; j < num; ++j)
                    cp[j] = toupper(cp[j]);
            }
            if (0 != strcmp(b, cp))
                fprintf(stderr, "%x,%x differ, ref: %s, sg_lib_data: "
                        "%s\n", asc, ascq, b, cp);
        }
    }
    if (NULL == cp) {
        if (feof(fp)) {
            if (verbose > 2)
                fprintf(stderr, "EOF detected\n");
        } else
            fprintf(stderr, "fgets: %s\n", safe_strerror(errno));
    } else
        fprintf(stderr, "%s\n", line);

    res = fclose(fp);
    if (EOF == res) {
        fprintf(stderr, "close error: %s\n", safe_strerror(errno));
        return 1;
    }
    return ret;
}
