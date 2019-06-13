/*
 * Copyright (c) 2004-2019 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#define DEF_BYTES_PER_LINE 16

static int bytes_per_line = DEF_BYTES_PER_LINE;

static const char * version_str = "1.11 20190527";

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

/* Returns the number of times 'ch' is found in string 's' given the
 * string's length. */
static int
num_chs_in_str(const char * s, int slen, int ch)
{
    int res = 0;

    while (--slen >= 0) {
        if (ch == s[slen])
            ++res;
    }
    return res;
}

/* If the number in 'buf' can be decoded or the multiplier is unknown
 * then -1LL is returned. Accepts a hex prefix (0x or 0X) or a decimal
 * multiplier suffix (as per GNU's dd (since 2002: SI and IEC 60027-2)).
 * Main (SI) multipliers supported: K, M, G, T, P. Ignore leading spaces
 * and tabs; accept comma, hyphen, space, tab and hash as terminator. */
int64_t
sg_get_llnum(const char * buf)
{
    int res, len, n;
    int64_t num, ll;
    uint64_t unum;
    char * cp;
    const char * b;
    char c = 'c';
    char c2 = '\0';     /* keep static checker happy */
    char c3 = '\0';     /* keep static checker happy */
    char lb[32];

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1LL;
    len = strlen(buf);
    n = strspn(buf, " \t");
    if (n > 0) {
        if (n == len)
            return -1LL;
        buf += n;
        len -= n;
    }
    /* following hack to keep C++ happy */
    cp = strpbrk((char *)buf, " \t,#-");
    if (cp) {
        len = cp - buf;
        n = (int)sizeof(lb) - 1;
        len = (len < n) ? len : n;
        memcpy(lb, buf, len);
        lb[len] = '\0';
        b = lb;
    } else
        b = buf;
    if (('0' == b[0]) && (('x' == b[1]) || ('X' == b[1]))) {
        res = sscanf(b + 2, "%" SCNx64 , &unum);
        num = unum;
    } else if ('H' == toupper((int)b[len - 1])) {
        res = sscanf(b, "%" SCNx64 , &unum);
        num = unum;
    } else
        res = sscanf(b, "%" SCNd64 "%c%c%c", &num, &c, &c2, &c3);
    if (res < 1)
        return -1LL;
    else if (1 == res)
        return num;
    else {
        if (res > 2)
            c2 = toupper((int)c2);
        if (res > 3)
            c3 = toupper((int)c3);
        switch (toupper((int)c)) {
        case 'C':
            return num;
        case 'W':
            return num * 2;
        case 'B':
            return num * 512;
        case 'K':
            if (2 == res)
                return num * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1024;
            return -1LL;
        case 'M':
            if (2 == res)
                return num * 1048576;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1048576;
            return -1LL;
        case 'G':
            if (2 == res)
                return num * 1073741824;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1073741824;
            return -1LL;
        case 'T':
            if (2 == res)
                return num * 1099511627776LL;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000000LL;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1099511627776LL;
            return -1LL;
        case 'P':
            if (2 == res)
                return num * 1099511627776LL * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000000LL * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1099511627776LL * 1024;
            return -1LL;
        case 'X':
            cp = (char *)strchr(b, 'x');
            if (NULL == cp)
                cp = (char *)strchr(b, 'X');
            if (cp) {
                ll = sg_get_llnum(cp + 1);
                if (-1LL != ll)
                    return num * ll;
            }
            return -1LL;
        default:
            fprintf(stderr, "unrecognized multiplier\n");
            return -1LL;
        }
    }
}

static void
dStrHex(const char* str, int len, long start, int noAddr)
{
    const char* p = str;
    unsigned char c;
    char buff[MAX_LINE_LENGTH];
    long a = start;
    int bpstart, cpstart;
    int j, k, line_length, nl, cpos, bpos, midline_space;

    if (noAddr) {
        bpstart = 0;
        cpstart = ((CHARS_PER_HEX_BYTE * bytes_per_line) + 1) + 5;
    } else {
        bpstart = BINARY_START_COL;
        cpstart = BINARY_START_COL +
                        ((CHARS_PER_HEX_BYTE * bytes_per_line) + 1) + 5;
    }
    cpos = cpstart;
    bpos = bpstart;
    midline_space = ((bytes_per_line + 1) / 2);

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
    if (0 == noAddr) {
        k = sprintf(buff + 1, "%.2lx", a);
        buff[k + 1] = ' ';
    }

    for(j = 0; j < len; j++) {
        nl = (0 == (j % bytes_per_line));
        if ((j > 0) && nl) {
            printf("%s\n", buff);
            bpos = bpstart;
            cpos = cpstart;
            a += bytes_per_line;
            memset(buff,' ', line_length);
            if (0 == noAddr) {
                k = sprintf(buff + 1, "%.2lx", a);
                buff[k + 1] = ' ';
            }
        }
        c = *p++;
        bpos += (nl && noAddr) ?  0 : CHARS_PER_HEX_BYTE;
        if ((bytes_per_line > 4) && ((j % bytes_per_line) == midline_space))
            bpos++;
        sprintf(&buff[bpos], "%.2x", (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if ((c < ' ') || (c >= 0x7f))
            c='.';
        buff[cpos++] = c;
    }
    if (cpos > cpstart)
        printf("%s\n", buff);
}

static void
dStrHexOnly(const char* str, int len, long start, int noAddr)
{
    const char* p = str;
    unsigned char c;
    char buff[MAX_LINE_LENGTH];
    long a = start;
    int bpstart, bpos, nl;
    int midline_space = ((bytes_per_line + 1) / 2);
    int j, k, line_length;

    if (len <= 0)
        return;
    bpstart = (noAddr ? 0 : BINARY_START_COL);
    bpos = bpstart;
    line_length = (noAddr ? 0 : BINARY_START_COL) +
                  (bytes_per_line * CHARS_PER_HEX_BYTE) + 4;
    if (line_length >= MAX_LINE_LENGTH) {
        fprintf(stderr, "bytes_per_line causes maximum line length of %d "
                        "to be exceeded\n", MAX_LINE_LENGTH);
        return;
    }
    memset(buff, ' ', line_length);
    buff[line_length] = '\0';
    if (0 == noAddr) {
        k = sprintf(buff + 1, "%.2lx", a);
        buff[k + 1] = ' ';
    }

    for(j = 0; j < len; j++) {
        nl = (0 == (j % bytes_per_line));
        if ((j > 0) && nl) {
            printf("%s\n", buff);
            bpos = bpstart;
            a += bytes_per_line;
            memset(buff,' ', line_length);
            if (0 == noAddr) {
                k = sprintf(buff + 1, "%.2lx", a);
                buff[k + 1] = ' ';
            }
        }
        c = *p++;
        bpos += (nl && noAddr) ? 0 : CHARS_PER_HEX_BYTE;
        if ((bytes_per_line > 4) && ((j % bytes_per_line) == midline_space))
            bpos++;
        sprintf(&buff[bpos], "%.2x", (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
    }
    if (bpos > bpstart)
        printf("%s\n", buff);
}

static void
usage()
{
    fprintf(stderr, "Usage: hxascdmp [-1] [-2] [-b=<n>] [-h] [-H] [-N] "
            "[-o=<off>] [-q]\n"
            "                [-V] [-?]  [<file>+]\n");
    fprintf(stderr, "  where:\n");
    fprintf(stderr, "    -1         print first byte in hex, prepend '0x' "
            "if '-H' given\n");
    fprintf(stderr, "    -2         like '-1' but print first two bytes\n");
    fprintf(stderr, "    -b=<n>     bytes per line to display "
                    "(def: 16)\n");
    fprintf(stderr, "    -h         print this usage message\n");
    fprintf(stderr, "    -H         print hex only (i.e. no ASCII "
            "to right)\n");
    fprintf(stderr, "    -N         no address, start in first column\n");
    fprintf(stderr, "    -o=<off>    start decoding at byte <off>. Suffix "
            "multipliers allowed\n");
    fprintf(stderr, "    -q         quiet: suppress output of header "
            "info\n");
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
    int64_t offset = 0;
    int res, k, u, len, n;
    int inFile = STDIN_FILENO;
    int doHelp = 0;
    int doHex = 0;
    int noAddr = 0;
    int doVersion = 0;
    int hasFilename = 0;
    int quiet = 0;
    int print1 = 0;
    int print2 = 0;
    int ret = 0;
    const char * cp;

    for (k = 1; k < argc; k++) {
        cp = argv[k];
        len = strlen(cp);
        if (0 == strncmp("-b=", cp, 3)) {
            res = sscanf(cp + 3, "%d", &u);
            if ((1 != res) || (u < 1)) {
                fprintf(stderr, "Bad value after '-b=' option\n");
                usage();
                return 1;
            }
            bytes_per_line = u;
        } else if (0 == strncmp("-o=", cp, 3)) {
            int64_t off = sg_get_llnum(cp + 3);

            if (off == -1) {
                fprintf(stderr, "Bad value after '-o=' option\n");
                usage();
                return 1;
            }
            offset = off;
        } else if ((len > 1) && ('-' == cp[0]) && ('-' != cp[1])) {
            res = 0;
            n = num_chs_in_str(cp + 1, len - 1, '1');
            print1 += n;
            res += n;
            n = num_chs_in_str(cp + 1, len - 1, '2');
            print2 += n;
            res += n;
            n = num_chs_in_str(cp + 1, len - 1, 'h');
            doHelp += n;
            res += n;
            n = num_chs_in_str(cp + 1, len - 1, 'H');
            doHex += n;
            res += n;
            n = num_chs_in_str(cp + 1, len - 1, 'N');
            noAddr += n;
            res += n;
            n = num_chs_in_str(cp + 1, len - 1, 'q');
            quiet += n;
            res += n;
            n = num_chs_in_str(cp + 1, len - 1, 'V');
            doVersion += n;
            res += n;
            n = num_chs_in_str(cp + 1, len - 1, '?');
            doHelp += n;
            res += n;
            if (0 == res) {
                fprintf(stderr, "No option recognized in str: %s\n", cp);
                usage();
                return 1;
            }
        } else if (0 == strcmp("-?", argv[k]))
            ++doHelp;
        else if (*argv[k] == '-') {
            fprintf(stderr, "unknown switch: %s\n", argv[k]);
            usage();
            return 1;
        } else {
            hasFilename = 1;
            break;
        }
        if (print2)
            print1 += print2 + print2;
    }
    if (doVersion) {
        printf("%s\n", version_str);
        return 0;
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
                if (offset > 0) {
                    int err;
                    int64_t off_res;

                    off_res = lseek(inFile, offset, SEEK_SET);
                    if (off_res < 0) {
                        err = errno;
                        fprintf(stderr, "failed moving filepos: wanted=%"
                                PRId64 " [0x%" PRIx64 "]\nlseek error: %s\n",
                                offset, offset, strerror(err));
                        goto fini1;
                    }
                    start = offset;
                } else
                    start = 0;
                if (! (doHex || quiet || print1))
                    printf("ASCII hex dump of file: %s\n", argv[k]);
                while ((res = read(inFile, buff, num)) > 0) {
                    if (print1) {
                        if (1 == print1) {
                            if (doHex)
                                printf("0x%02x\n", (uint8_t)(buff[0]));
                            else
                                printf("%02x\n", (uint8_t)(buff[0]));
                        } else {
                            uint16_t us;

                            memcpy(&us, buff, 2);
                            if (doHex)
                                printf("0x%04x\n", us);
                            else
                                printf("%04x\n", us);
                        }
                        break;
                    }
                    if (doHex)
                        dStrHexOnly(buff, res, start, noAddr);
                    else
                        dStrHex(buff, res, start, noAddr);
                    start += (long)res;
                }
            }
fini1:
            close(inFile);
        }
    } else {
        sg_set_binary_mode(inFile);
        if (offset > 0) {
            start = offset;
            do {        /* eat up offset bytes */
                if ((res = read(inFile, buff,
                                (num > offset ? offset : num))) > 0)
                    offset -= res;
                else {
                    fprintf(stderr, "offset read() error: %s\n",
                            strerror(errno));
                     break;
                }
            } while (offset > 0);
        }
        while ((res = read(inFile, buff, num)) > 0) {
            if (doHex)
                dStrHexOnly(buff, res, start, noAddr);
            else
                dStrHex(buff, res, start, noAddr);
            start += (long)res;
        }
    }
    return ret;
}
