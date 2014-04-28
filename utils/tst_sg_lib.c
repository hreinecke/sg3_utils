/*
 * Copyright (c) 2013-2014 Douglas Gilbert.
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

static char * version_str = "1.01 20140427";


#define MAX_LINE_LEN 1024


static struct option long_options[] = {
        {"dtsrhex", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"printf", 0, 0, 'p'},
        {"sense", 0, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

const unsigned char desc_sense_data1[] = {
   /* unrec_err, excessive_writes, sdat_ovfl, additional_len=? */
    0x72, 0x1, 0x3, 0x2, 0x80, 0x0, 0x0, 12+12+8+4+8+4+28,
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

const unsigned char desc_sense_data2[] = {
   /* ill_req, inv fld in para list, additional_len=? */
    0x72, 0x5, 0x26, 0x0, 0x0, 0x0, 0x0, 8+4,
   /* sense key specific: SKSV=1, C/D*=0, bitp=7 bytep=34 */
    0x2, 0x6, 0x0, 0x0, 0x8f, 0x0, 0x34, 0x0,
   /* field replaceable code=0x45 */
    0x3, 0x2, 0x0, 0x45,
    };


static void
usage()
{
    fprintf(stderr, "Usage: "
          "tst_sg_lib [--dstrhex] [--help] [--printf] [--sense] "
          "[--verbose]\n"
          "                  [--version]\n"
          "  where: --dstrhex|-d       test dStrHex* variants\n"
          "         --help|-h          print out usage message\n"
          "         --printf|-p        test library printf variants\n"
          "         --sense|-s         test sense data handling\n"
          "         --verbose|-v       increase verbosity\n"
          "         --version|-V       print version string and exit\n\n"
          "Test various parts of sg_lib, see options\n"
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


int
main(int argc, char * argv[])
{
    int k, c, n, len;
    int do_dstrhex = 0;
    int do_printf = 0;
    int do_sense = 0;
    int did_something = 0;
    int verbose = 0;
    int ret = 0;
    char b[2048];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dhpsvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            ++do_dstrhex;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'p':
            ++do_printf;
            break;
        case 's':
            ++do_sense;
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

    if (do_sense ) {
        ++did_something;
        sg_print_sense("desc_sense_data test1", desc_sense_data1,
                       (int)sizeof(desc_sense_data1), 1);
        printf("\n");
#if 1
        sg_get_sense_str("sg_get_sense_str(ds_data1)", desc_sense_data1,
                         sizeof(desc_sense_data1), 1, sizeof(b), b);
        printf("sg_get_sense_str: strlen(b)->%zd\n", strlen(b));
        printf("%s", b);
        printf("\n");
#endif
        sg_print_sense("desc_sense_data test2", desc_sense_data2,
                       (int)sizeof(desc_sense_data2), 1);
        printf("\n");
    }

    if (do_printf) {
        ++did_something;
        printf("Testing my_snprintf():\n");
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
    }
    if (do_dstrhex) {
        char b[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
                    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58};

        ++did_something;
        for (k = 0; k < 18; ++k) {
            printf("k=%d:\n", k);
            dStrHex(b, k, 0);
            dStrHex(b, k, 1);
            dStrHex(b, k, -1);
            printf("\n");
        }
    }

    if (0 == did_something)
        printf("Looks like no tests done, check usage with '-h'\n");
    return ret;
}
