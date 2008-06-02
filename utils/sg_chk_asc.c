/*
 * Copyright (c) 2006-2008 Douglas Gilbert.
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

static char * version_str = "1.03 20080313";

#define ME "sg_chk_asc: "

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
          "sg_chk_asc [--help] [--verbose] [--version] <asc_ascq_file>\n"
          "  where: --help|-h          print out usage message\n"
          "         --verbose|-v       increase verbosity\n"
          "         --version|-V       print version string and exit\n\n"
          "Checks asc/ascq codes < www.t10.org/lists/asc-num.txt > against "
          "sg_lib.c\n"
          );

}

int main(int argc, char * argv[])
{
    int k, j, res, c, num, len, asc, ascq;
    FILE * fp;
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

        c = getopt_long(argc, argv, "hvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
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
        fprintf(stderr, ME "open error: %s: %s\n", file_name,
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
            ascq = -1;
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
        strncpy(b , line + 25, sizeof(b) - 1);
        b[sizeof(b) - 1] = '\0';
        num = strlen(b);
        if (0xd == b[num - 2]) {
            b[num - 2] = '\0';
            b[num - 1] = '\0';
        }
        num = strlen(b);
        for (j = 0; j < num; ++j)
            b[j] = toupper(b[j]);

        bb[0] = '\0';
        if (ascq >= 0) {
            cp = sg_get_asc_ascq_str(asc, ascq, sizeof(bb) - 1, bb);
            if (NULL == cp) {
                fprintf(stderr, "no entry for %x,%x : %s\n", asc, ascq, b);
                continue;
            }
            num = strlen(cp);
// fprintf(stderr, "file: asc=%x  acsq=%x  strlen=%d %s\n", asc, ascq, num, cp);
//            if (num < 20)
//                continue;
            if (num > 20) {
                cp += 18;
                num -= 18;
                for (j = 0; j < num; ++j)
                    cp[j] = toupper(cp[j]);
            }
            if (0 != strcmp(b, cp))
                fprintf(stderr, "%x,%x differ, ref: %s, sg_lib: "
                        "%s\n", asc, ascq, b, cp);
        }
    }
    if (NULL == cp) {
        if (feof(fp)) {
            if (verbose > 2)
                fprintf(stderr, "EOF detected\n");
        } else
            fprintf(stderr, ME "fgets: %s\n", safe_strerror(errno));
    } else
        fprintf(stderr, "%s\n", line);

    res = fclose(fp);
    if (EOF == res) {
        fprintf(stderr, ME "close error: %s\n", safe_strerror(errno));
        return 1;
    }
    return ret;
}
