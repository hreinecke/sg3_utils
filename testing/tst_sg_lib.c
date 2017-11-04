/*
 * Copyright (c) 2013-2016 Douglas Gilbert.
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
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#include "sg_lib.h"
#include "sg_unaligned.h"

/* A utility program to test sg_libs string handling, specifically
 * related to snprintf().
 *
 */

static char * version_str = "1.04 20160503";


#define MAX_LINE_LEN 1024


static struct option long_options[] = {
        {"dstrhex",  no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"leadin",  required_argument, 0, 'l'},
        {"printf", no_argument, 0, 'p'},
        {"sense", no_argument, 0, 's'},
        {"unaligned", no_argument, 0, 'u'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},   /* sentinel */
};

static const unsigned char desc_sense_data1[] = {
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

static const unsigned char desc_sense_data2[] = {
   /* ill_req, inv fld in para list, additional_len=? */
    0x72, 0x5, 0x26, 0x0, 0x0, 0x0, 0x0, 8+4,
   /* sense key specific: SKSV=1, C/D*=0, bitp=7 bytep=34 */
    0x2, 0x6, 0x0, 0x0, 0x8f, 0x0, 0x34, 0x0,
   /* field replaceable code=0x45 */
    0x3, 0x2, 0x0, 0x45,
    };

static const unsigned char desc_sense_data3[] = {
   /* medium err, vibration induced ..., additional_len=? */
    0x72, 0x3, 0x9, 0x5, 0x0, 0x0, 0x0, 32+16,
   /* 0xd: block dev: sense key specific: SKSV=1, retry_count=257, fru=0x45
    * info=0x1122334455, command_specific=0x1   */
    0xd, 0x1e, 0xa0, 0x0, 0x80, 0x1, 0x1, 0x45,
    0x0, 0x0, 0x0, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
    /* following sbc3 (standard) and sbc4r10 inconsistency; add padding */
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    /* 0xe: reason: send_to_given+henceforth, lu, naa-5, 0x5333333000001f40 */
    0xe, 0xe, 0x0, 0x1, 0x1, 0x3, 0x0, 0x8,
        0x53, 0x33, 0x33, 0x30, 0x0, 0x0, 0x1f, 0x40,
    };

static const unsigned char desc_sense_data4[] = {
   /* ill_req, inv fld in para list, additional_len=? */
    0x72, 0x5, 0x26, 0x0, 0x0, 0x0, 0x0, 24,
   /* Forwarded sense data, FSDT=0, sd_src=7, f_status=2 */
    0xc, 22, 0x7, 0x2,
   /* ill_req, inv fld in para list, additional_len=? */
    0x72, 0x5, 0x26, 0x0, 0x0, 0x0, 0x0, 8+4,
   /* sense key specific: SKSV=1, C/D*=0, bitp=7 bytep=34 */
    0x2, 0x6, 0x0, 0x0, 0x8f, 0x0, 0x34, 0x0,
   /* field replaceable code=0x45 */
    0x3, 0x2, 0x0, 0x45,
    };

static const unsigned char desc_sense_data5[] = {
   /* no_sense, ATA info available */
    0x72, 0x0, 0x0, 0x1d, 0x0, 0x0, 0x0, 14+14,
   /* ATA descriptor extend=1 */
    0x9, 0xc, 0x1, 0x0, 0x34, 0x12, 0x44, 0x11,
    0x55, 0x22, 0x66, 0x33, 0x1, 0x0,
   /* ATA descriptor extend=0 */
    0x9, 0xc, 0x0, 0x0, 0x34, 0x12, 0x44, 0x11,
    0x55, 0x22, 0x66, 0x33, 0x1, 0x0,
    };

static const unsigned char desc_sense_data6[] = {
   /* UA, req, subsidiary bindinganged */
    0x72, 0x6, 0x3f, 0x1a, 0x0, 0x0, 0x0, 26+12+12,
    /* 0xe: designator, reason: preferred admin lu, uuid */
    0xe, 0x18, 0x0, 0x4, 0x1, 0xa, 0x0, 0x12,
        0x10, 0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xfe, 0xdc,
    /* 0x0: Information(valid): lun */
    0x0, 0xa, 0x80, 0x0,
    0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    /* 0x1: Command specific: 0x1 */
    0x1, 0xa, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
    };

static const char * leadin = NULL;


static void
usage()
{
    fprintf(stderr,
            "Usage: tst_sg_lib [--dstrhex] [--help] [--leadin=STR] "
            "[--printf]\n"
            "                  [--sense] [--unaligned] [--verbose] "
            "[--version]\n"
            "  where: --dstrhex|-d       test dStrHex* variants\n"
            "         --help|-h          print out usage message\n"
            "         --leadin=STR|-l STR    every line output by --sense "
            "should\n"
            "                                be prefixed by STR\n"
            "         --printf|-p        test library printf variants\n"
            "         --sense|-s         test sense data handling\n"
            "         --unaligned|-u     test unaligned data handling\n"
            "         --verbose|-v       increase verbosity\n"
            "         --version|-V       print version string and exit\n\n"
            "Test various parts of sg_lib, see options. Sense data tests "
            "overlap\nsomewhat with examples/sg_sense_test .\n"
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
    int do_unaligned = 0;
    int did_something = 0;
    int verbose = 0;
    int ret = 0;
    char b[2048];
    char bb[256];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "dhl:psuvV", long_options,
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
        case 'l':
            leadin = optarg;
            break;
        case 'p':
            ++do_printf;
            break;
        case 's':
            ++do_sense;
            break;
        case 'u':
            ++do_unaligned;
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
        printf("desc_sense_data test1:\n");
        sg_print_sense(leadin, desc_sense_data1,
                       (int)sizeof(desc_sense_data1), verbose);
        printf("\n");
#if 1
        printf("sg_get_sense_str(ds_data1):\n");
        sg_get_sense_str(leadin, desc_sense_data1,
                         sizeof(desc_sense_data1), verbose, sizeof(b), b);
        printf("sg_get_sense_str: strlen(b)->%zd\n", strlen(b));
        printf("%s", b);
        printf("\n");
#endif
        printf("desc_sense_data test2\n");
        sg_print_sense(leadin, desc_sense_data2,
                       (int)sizeof(desc_sense_data2), verbose);
        printf("\n");
        printf("desc_sense block dev combo plus designator test3\n");
        sg_print_sense(leadin, desc_sense_data3,
                       (int)sizeof(desc_sense_data3), verbose);
        printf("\n");
        printf("desc_sense forwarded sense test4\n");
        sg_print_sense(leadin, desc_sense_data4,
                       (int)sizeof(desc_sense_data4), verbose);
        printf("\n");
        printf("desc_sense ATA Info test5\n");
        sg_print_sense(leadin, desc_sense_data5,
                       (int)sizeof(desc_sense_data5), verbose);
        printf("\n");
        printf("desc_sense UA subsidiary binfing changed test6\n");
        sg_print_sense(leadin, desc_sense_data6,
                       (int)sizeof(desc_sense_data6), verbose);
        printf("\n");
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
            dStrHexStr(b, k, "dSHS_0: ", 0, sizeof(bb), bb);
            printf("%s", bb);
            dStrHex(b, k, 1);
            dStrHexStr(b, k, "dSHS_1: ", 1, sizeof(bb), bb);
            printf("%s", bb);
            dStrHex(b, k, -1);
            printf("\n");
        }
    }
    if (do_unaligned) {
        uint16_t u16 = 0x55aa;
        uint16_t u16r;
        uint32_t u24 = 0x224488;
        uint32_t u24r;
        uint32_t u32 = 0x224488ff;
        uint32_t u32r;
        uint64_t u48 = 0x112233445566ULL;
        uint64_t u48r;
        uint64_t u64 = 0x1122334455667788ULL;
        uint64_t u64r;
        uint8_t u8[64];

        ++did_something;
        if (verbose)
            memset(u8, 0, sizeof(u8));
        printf("u16=0x%" PRIx16 "\n", u16);
        sg_put_unaligned_le16(u16, u8);
        printf("  le16:\n");
        dStrHex((const char *)u8, verbose ? 10 : 2, -1);
        u16r = sg_get_unaligned_le16(u8);
        printf("  u16r=0x%" PRIx16 "\n", u16r);
        sg_put_unaligned_be16(u16, u8);
        printf("  be16:\n");
        dStrHex((const char *)u8, verbose ? 10 : 2, -1);
        u16r = sg_get_unaligned_be16(u8);
        printf("  u16r=0x%" PRIx16 "\n\n", u16r);

        printf("u24=0x%" PRIx32 "\n", u24);
        sg_put_unaligned_le24(u24, u8);
        printf("  le24:\n");
        dStrHex((const char *)u8, verbose ? 10 : 3, -1);
        u24r = sg_get_unaligned_le24(u8);
        printf("  u24r=0x%" PRIx32 "\n", u24r);
        sg_put_unaligned_be24(u24, u8);
        printf("  be24:\n");
        dStrHex((const char *)u8, verbose ? 10 : 3, -1);
        u24r = sg_get_unaligned_be24(u8);
        printf("  u24r=0x%" PRIx32 "\n\n", u24r);

        printf("u32=0x%" PRIx32 "\n", u32);
        sg_put_unaligned_le32(u32, u8);
        printf("  le32:\n");
        dStrHex((const char *)u8, verbose ? 10 : 4, -1);
        u32r = sg_get_unaligned_le32(u8);
        printf("  u32r=0x%" PRIx32 "\n", u32r);
        sg_put_unaligned_be32(u32, u8);
        printf("  be32:\n");
        dStrHex((const char *)u8, verbose ? 10 : 4, -1);
        u32r = sg_get_unaligned_be32(u8);
        printf("  u32r=0x%" PRIx32 "\n\n", u32r);

        printf("u48=0x%" PRIx64 "\n", u48);
        sg_put_unaligned_le48(u48, u8);
        printf("  le48:\n");
        dStrHex((const char *)u8, verbose ? 10 : 6, -1);
        u48r = sg_get_unaligned_le48(u8);
        printf("  u48r=0x%" PRIx64 "\n", u48r);
        sg_put_unaligned_be48(u48, u8);
        printf("  be48:\n");
        dStrHex((const char *)u8, verbose ? 10 : 6, -1);
        u48r = sg_get_unaligned_be48(u8);
        printf("  u48r=0x%" PRIx64 "\n\n", u48r);

        printf("u64=0x%" PRIx64 "\n", u64);
        sg_put_unaligned_le64(u64, u8);
        printf("  le64:\n");
        dStrHex((const char *)u8, verbose ? 10 : 8, -1);
        u64r = sg_get_unaligned_le64(u8);
        printf("  u64r=0x%" PRIx64 "\n", u64r);
        sg_put_unaligned_be64(u64, u8);
        printf("  be64:\n");
        dStrHex((const char *)u8, verbose ? 10 : 8, -1);
        u64r = sg_get_unaligned_be64(u8);
        printf("  u64r=0x%" PRIx64 "\n\n", u64r);
        printf("  be[8]:\n");
        dStrHex((const char *)u8, verbose ? 10 : 8, -1);
        u64r = sg_get_unaligned_be(8, u8);
        printf("  u64r[8]=0x%" PRIx64 "\n\n", u64r);
        printf("  le[8]:\n");
        u64r = sg_get_unaligned_le(8, u8);
        printf("  u64r[8]=0x%" PRIx64 "\n\n", u64r);

    }

    if (0 == did_something)
        printf("Looks like no tests done, check usage with '-h'\n");
    return ret;
}
