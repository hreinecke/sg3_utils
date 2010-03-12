/*
 * Copyright (c) 2004-2010 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define DEF_BYTES_PER_LINE 16

static int bytes_per_line = DEF_BYTES_PER_LINE;

static const char * version_str = "1.13 20100312";

#define CHARS_PER_HEX_BYTE 3
#define BINARY_START_COL 6
#define MAX_LINE_LENGTH 257


#ifdef SG_LIB_MINGW
/* Non Unix OSes distinguish between text and binary files.
   Set text mode on fd. Does nothing in Unix. Returns negative number on
   failure. */
int
sg_set_text_mode(int fd)
{
    return setmode(fd, O_TEXT);
}

/* Set binary mode on fd. Does nothing in Unix. Returns negative number on
   failure. */
int
sg_set_binary_mode(int fd)
{
    return setmode(fd, O_BINARY);
}

#else
/* For Unix the following functions are dummies. */
int
sg_set_text_mode(int fd)
{
    return fd;  /* fd should be >= 0 */
}

int
sg_set_binary_mode(int fd)
{
    return fd;
}
#endif


static void
dStrHex(const char* str, int len, long start)
{
    const char* p = str;
    unsigned char c;
    char buff[MAX_LINE_LENGTH];
    long a = start;
    const int bpstart = BINARY_START_COL;
    const int cpstart = BINARY_START_COL +
                        ((CHARS_PER_HEX_BYTE * bytes_per_line) + 1) + 5;
    int cpos = cpstart;
    int bpos = bpstart;
    int midline_space = (bytes_per_line / 2) + 1;
    int i, k, line_length;

    if (len <= 0)
        return;
    line_length = BINARY_START_COL +
                  (bytes_per_line * (1 + CHARS_PER_HEX_BYTE)) + 7;
    if (line_length >= MAX_LINE_LENGTH) {
        fprintf(stderr, "bytes_per_line causes maximum line length of %d "
                        "to be exceeded\n", MAX_LINE_LENGTH);
        return;
    }
    memset(buff, ' ', line_length);
    buff[line_length] = '\0';
    k = sprintf(buff + 1, "%.2lx", a);
    buff[k + 1] = ' ';
    if (bpos >= ((bpstart + (midline_space * CHARS_PER_HEX_BYTE))))
        bpos++;

    for(i = 0; i < len; i++) {
        c = *p++;
        bpos += CHARS_PER_HEX_BYTE;
        if (bpos == (bpstart + (midline_space * CHARS_PER_HEX_BYTE)))
            bpos++;
        sprintf(&buff[bpos], "%.2x", (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if ((c < ' ') || (c >= 0x7f))
            c='.';
        buff[cpos++] = c;
        if (cpos >= (cpstart + bytes_per_line)) {
            printf("%s\n", buff);
            bpos = bpstart;
            cpos = cpstart;
            a += bytes_per_line;
            memset(buff,' ', line_length);
            k = sprintf(buff + 1, "%.2lx", a);
            buff[k + 1] = ' ';
        }
    }
    if (cpos > cpstart)
        printf("%s\n", buff);
}

static void
dStrHexOnly(const char* str, int len, long start)
{
    const char* p = str;
    unsigned char c;
    char buff[MAX_LINE_LENGTH];
    long a = start;
    const int bpstart = BINARY_START_COL;
    int bpos = bpstart;
    int midline_space = (bytes_per_line / 2) + 1;
    int i, k, line_length;

    if (len <= 0)
        return;
    line_length = BINARY_START_COL +
                  (bytes_per_line * CHARS_PER_HEX_BYTE) + 4;
    if (line_length >= MAX_LINE_LENGTH) {
        fprintf(stderr, "bytes_per_line causes maximum line length of %d "
                        "to be exceeded\n", MAX_LINE_LENGTH);
        return;
    }
    memset(buff, ' ', line_length);
    buff[line_length] = '\0';
    k = sprintf(buff + 1, "%.2lx", a);
    buff[k + 1] = ' ';
    if (bpos >= ((bpstart + (midline_space * CHARS_PER_HEX_BYTE))))
        bpos++;

    for(i = 0; i < len; i++) {
        c = *p++;
        bpos += CHARS_PER_HEX_BYTE;
        if (bpos == (bpstart + (midline_space * CHARS_PER_HEX_BYTE)))
            bpos++;
        sprintf(&buff[bpos], "%.2x", (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if (bpos >= (bpstart + (bytes_per_line * CHARS_PER_HEX_BYTE)))
        {
            printf("%s\n", buff);
            bpos = bpstart;
            a += bytes_per_line;
            memset(buff,' ', line_length);
            k = sprintf(buff + 1, "%.2lx", a);
            buff[k + 1] = ' ';
        }
    }
    if (bpos > bpstart)
        printf("%s\n", buff);
}

static void
usage()
{
    fprintf(stderr, "Usage: hxascdmp [-b=<n>] [-h] [-H] [-V] [-?] "
            "[<file>+]\n");
    fprintf(stderr, "  where:\n");
    fprintf(stderr, "    -b=<n>     bytes per line to display "
                    "(def: 16)\n");
    fprintf(stderr, "    -h         print this usage message\n");
    fprintf(stderr, "    -H         print hex only (i.e. no ASCII "
            "to right)\n");
    fprintf(stderr, "    -V         print version string then exits\n");
    fprintf(stderr, "    -?         print this usage message\n");
    fprintf(stderr, "    <file>+    reads file(s) and outputs each "
                    "as hex ASCII\n");
    fprintf(stderr, "               if no <file> then reads stdin\n\n");
    fprintf(stderr, "Sends hex ASCII dump of stdin/file to stdout\n");
}

int
main(int argc, const char ** argv)
{
    char buff[8192];
    int num = 8192;
    long start = 0;
    int res, k, u;
    int inFile = STDIN_FILENO;
    int doHelp = 0;
    int doHex = 0;
    int hasFilename = 0;
    int ret = 0;

    for (k = 1; k < argc; k++) {
        if (0 == strncmp("-b=", argv[k], 3)) {
            res = sscanf(argv[k] + 3, "%d", &u);
            if ((1 != res) || (u < 1)) {
                printf("Bad value after '-b' switch\n");
                usage();
                return 1;
            }
            bytes_per_line = u;
        }
        else if (0 == strcmp("-h", argv[k]))
            doHelp = 1;
        else if (0 == strcmp("-H", argv[k]))
            doHex = 1;
        else if (0 == strcmp("-V", argv[k])) {
            fprintf(stderr, "%s\n", version_str);
            return 0;
        } else if (0 == strcmp("-?", argv[k]))
            doHelp = 1;
        else if (*argv[k] == '-') {
            fprintf(stderr, "unknown switch: %s\n", argv[k]);
            usage();
            return 1;
        } else {
            hasFilename = 1;
            break;
        }
    }
    if (doHelp) {
        usage();
        return 0;
    }

    /* Make sure num to fetch is integral multiple of bytes_per_line */
    if (0 != (num % bytes_per_line))
        num = (num / bytes_per_line) * bytes_per_line;

    if (hasFilename) {
        for ( ; k < argc; k++)
        {
            inFile = open(argv[k], O_RDONLY);
            if (inFile < 0) {
                fprintf(stderr, "Couldn't open file: %s\n", argv[k]);
                ret = 1;
            } else {
                sg_set_binary_mode(inFile);
                start = 0;
                printf("%shex dump of file: %s\n",
                       (doHex ? "" : "ASCII "), argv[k]);
                while ((res = read(inFile, buff, num)) > 0) {
                    if (doHex)
                        dStrHexOnly(buff, res, start);
                    else
                        dStrHex(buff, res, start);
                    start += (long)res;
                }
            }
            close(inFile);
            printf("\n");
        }
    } else {
        sg_set_binary_mode(inFile);
        while ((res = read(inFile, buff, num)) > 0) {
            if (doHex)
                dStrHexOnly(buff, res, start);
            else
                dStrHex(buff, res, start);
            start += (long)res;
        }
    }
    return ret;
}
