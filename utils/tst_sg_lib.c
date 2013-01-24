/*
 * Copyright (c) 2013 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>

#include "sg_lib.h"

/* A utility program to test sg_libs string handling, specifically
 * related to snprintf().
 *
 */

static char * version_str = "1.00 20130122";


#define MAX_LINE_LEN 1024


static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

const unsigned char desc_sense_data[] = {
   /* unrec_err, excessive_writes, sdat_ovfl, additional_len=? */
    0x72, 0x1, 0x3, 0x2, 0x80, 0x0, 0x0, 32+4+8+4+28,
   /* Information: 0x11223344556677bb */
    0x0, 0xa, 0x80, 0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xbb,
   /* command specific: 0x3344556677bbccff */
    0x1, 0xa, 0x0, 0x0, 0x33, 0x44, 0x55, 0x66, 0x77, 0xbb, 0xcc, 0xff,
   /* sense key specific: SKSV=1, actual_count=257 (hex: 0x101) */
    0x2, 0x6, 0x0, 0x0, 0x80, 0x1, 0x1, 0x0,
   /* field replaceable code=0x45 */
    0x3, 0x2, 0x0, 0x45,
   /* another progress report indicator */
    0xa, 0x6, 0x2, 0x1, 0x2, 0x0, 0x32, 0x01,
   /* incorrect length indicator (ILI) */
    0x5, 0x2, 0x0, 0x20,
   /* user data degment referral */
    0xb, 26, 0x1, 0x0,
        0,0,0,1, 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                 0x1,0x2,0x3,0x4,0x55,0x6,0x7,0x8,
        2,0,0x12,0x34,
    };


static void usage()
{
    fprintf(stderr, "Usage: "
          "tst_sg_lib [--help] [--verbose] [--version]\n"
          "  where: --help|-h          print out usage message\n"
          "         --verbose|-v       increase verbosity\n"
          "         --version|-V       print version string and exit\n\n"
          "xxxxxxxxxxxxxxxxxxxxxxxx\n"
          );

}

/* Want safe, 'n += snprintf(b + n ...)' like function. If cp_max_len is 1
 * then assume cp is pointing to a null char and do nothing. Returns number
 * number of chars placed in cp excluding the trailing null char. So for
 * cp_max_len > 0 the return value is always < cp_max_len; for cp_max_len
 * <= 0 the return value is 0 (and no chars are written to cp). */
static int
my_snprintf(char * cp, int cp_max_len, const char * fmt, ...)
{
    va_list args;
    int n;

    if (cp_max_len < 2)
        return 0;
    va_start(args, fmt);
    n = vsnprintf(cp, cp_max_len, fmt, args);
    va_end(args);
    return (n < cp_max_len) ? n : (cp_max_len - 1);
}

int main(int argc, char * argv[])
{
    int c, n, len;
    int verbose = 0;
    int ret = 1;
    char b[2048];

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

    printf("Testing my_snprintf():\n");
    sg_print_sense("desc_sense_data test", desc_sense_data, (int)sizeof(desc_sense_data), 1);
    printf("\n");

#if 1
    sg_get_sense_str("sg_get_sense_str", desc_sense_data, sizeof(desc_sense_data), 1, sizeof(b), b);
    printf("sg_get_sense_str: strlen(b)->%zd\n", strlen(b));
    printf("%s", b);
    printf("\n");
#endif

    b[0] = '\0';
    len = sizeof(b);
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = -1;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = 0;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = 1;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = 2;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = 3;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = 4;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = 5;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = 6;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    b[0] = '\0';
    len = 7;
    n = my_snprintf(b, len, "%s", "test");
    printf("my_snprintf(,%d,,\"test\") -> %d; strlen(b) -> %zd\n",
           len, n, strlen(b));
    if (strlen(b) > 0)
        printf("Resulting string: %s\n", b);

    return ret;
}
