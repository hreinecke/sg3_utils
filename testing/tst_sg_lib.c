/*
 * Copyright (c) 2013-2019 Douglas Gilbert.
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
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#include <time.h>

#if defined(__GNUC__) && ! defined(SG_LIB_FREEBSD)
#include <byteswap.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"     /* need this to see if HAVE_BYTESWAP_H */
#endif

#include "sg_lib.h"
#include "sg_pr2serr.h"

/* Uncomment the next two undefs to force use of the generic (i.e. shifting)
 * unaligned functions (i.e. sg_get_* and sg_put_*). Use "-b 16|32|64
 * -n 100m" to see the differences in timing. */
/* #undef HAVE_CONFIG_H */
/* #undef HAVE_BYTESWAP_H */
#include "sg_unaligned.h"

/*
 * A utility program to test sg_libs string handling, specifically
 * related to snprintf().
 */

static const char * version_str = "1.13 20190108";


#define MAX_LINE_LEN 1024


static struct option long_options[] = {
        {"byteswap",  required_argument, 0, 'b'},
        {"exit", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex2",  no_argument, 0, 'H'},
        {"leadin",  required_argument, 0, 'l'},
        {"num",  required_argument, 0, 'n'},
        {"printf", no_argument, 0, 'p'},
        {"sense", no_argument, 0, 's'},
        {"unaligned", no_argument, 0, 'u'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},   /* sentinel */
};

static const uint8_t desc_sense_data1[] = {
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
   /* user data segment referral */
    0xb, 26, 0x1, 0x0,
        0,0,0,1, 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                 0x1,0x2,0x3,0x4,0x55,0x6,0x7,0x8,
        2,0,0x12,0x34,
    };

static const uint8_t desc_sense_data2[] = {
   /* ill_req, inv fld in para list, additional_len=? */
    0x72, 0x5, 0x26, 0x0, 0x0, 0x0, 0x0, 8+4,
   /* sense key specific: SKSV=1, C/D*=0, bitp=7 bytep=34 */
    0x2, 0x6, 0x0, 0x0, 0x8f, 0x0, 0x34, 0x0,
   /* field replaceable code=0x45 */
    0x3, 0x2, 0x0, 0x45,
    };

static const uint8_t desc_sense_data3[] = {
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

static const uint8_t desc_sense_data4[] = {
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

static const uint8_t desc_sense_data5[] = {
   /* no_sense, ATA info available */
    0x72, 0x0, 0x0, 0x1d, 0x0, 0x0, 0x0, 14+14,
   /* ATA descriptor extend=1 */
    0x9, 0xc, 0x1, 0x0, 0x34, 0x12, 0x44, 0x11,
    0x55, 0x22, 0x66, 0x33, 0x1, 0x0,
   /* ATA descriptor extend=0 */
    0x9, 0xc, 0x0, 0x0, 0x34, 0x12, 0x44, 0x11,
    0x55, 0x22, 0x66, 0x33, 0x1, 0x0,
    };

static const uint8_t desc_sense_data6[] = {
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
            "Usage: tst_sg_lib [--exit] [--help] [--hex2] [--leadin=STR] "
            "[--printf]\n"
            "                  [--sense] [--unaligned] [--verbose] "
            "[--version]\n"
            "  where:\n"
#if defined(__GNUC__) && ! defined(SG_LIB_FREEBSD)
            "    --byteswap=B|-b B    B is 16, 32 or 64; tests NUM "
            "byteswaps\n"
            "                         compared to sg_unaligned "
            "equivalent\n"
            "    --exit|-e          test exit status strings\n"
#else
            "    --exit|-e          test exit status strings\n"
#endif
            "    --help|-h          print out usage message\n"
            "    --hex2|-H          test hex2* variants\n"
            "    --leadin=STR|-l STR    every line output by --sense "
            "should\n"
            "                           be prefixed by STR\n"
            "    --num=NUM|-n NUM    number of iterations (def=1)\n"
            "    --printf|-p        test library printf variants\n"
            "    --sense|-s         test sense data handling\n"
            "    --unaligned|-u     test unaligned data handling\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Test various parts of sg_lib, see options. Sense data tests "
            "overlap\nsomewhat with examples/sg_sense_test .\n"
           );

}

static char *
get_exit_status_str(int exit_status, bool longer, int b_len, char * b)
{
    int n;

    n = sg_scnpr(b, b_len, "  ES=%d: ", exit_status);
    if (n >= (b_len - 1))
        return b;
    if (sg_exit2str(exit_status, longer, b_len - n, b + n)) {
        n = (int)strlen(b);
        if (n < (b_len - 1))
            sg_scnpr(b + n, b_len - n, " [ok=true]");
        return b;
    } else
        snprintf(b, b_len, "  No ES string for %d%s", exit_status,
                 (longer ? " [ok=false]" : ""));
    return b;
}

static uint8_t arr[64];

#define OFF 7   /* in byteswap mode, can test different alignments (def: 8) */

int
main(int argc, char * argv[])
{
    bool do_exit_status = false;
    bool ok;
    int k, c, n, len;
    int byteswap_sz = 0;
    int do_hex2 = 0;
    int do_num = 1;
    int do_printf = 0;
    int do_sense = 0;
    int do_unaligned = 0;
    int did_something = 0;
    int vb = 0;
    int ret = 0;
    char b[2048];
    char bb[256];
    const int b_len = sizeof(b);

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:ehHl:n:psuvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            byteswap_sz = sg_get_num(optarg);
            if (! ((16 == byteswap_sz) || (32 == byteswap_sz) ||
                   (64 == byteswap_sz))) {
                fprintf(stderr, "--byteswap= requires 16, 32 or 64\n");
                return 1;
            }
            break;
        case 'e':
            do_exit_status = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex2;
            break;
        case 'l':
            leadin = optarg;
            break;
        case 'n':
            do_num = sg_get_num(optarg);
            if (do_num < 0) {
                fprintf(stderr, "--num= unable decode argument as number\n");
                return 1;
            }
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
            ++vb;
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

    if (do_exit_status) {
        ++did_something;

        printf("Test Exit Status strings (add -v for long version):\n");
        printf("  No error (es=0): %s\n",
               sg_get_category_sense_str(0, b_len, b, vb));
        ok = sg_exit2str(0, true, b_len, b);
        printf("  No error (force verbose): %s\n", b);
        if (vb)
            printf("    for previous line sg_exit2str() returned: %s\n",
                   (ok ? "true" : "false"));
        printf("%s\n", get_exit_status_str(1, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(2, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(3, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(4, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(5, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(6, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(7, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(8, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(25, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(33, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(36, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(48, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(50, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(51, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(96, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(97, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(97, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(255, (vb > 0), b_len, b));
        printf("%s\n", get_exit_status_str(-1, (vb > 0), b_len, b));

        printf("\n");
    }

    if (do_sense ) {
        ++did_something;
        printf("desc_sense_data test1:\n");
        sg_print_sense(leadin, desc_sense_data1,
                       (int)sizeof(desc_sense_data1), vb);
        printf("\n");
#if 1
        printf("sg_get_sense_str(ds_data1):\n");
        sg_get_sense_str(leadin, desc_sense_data1,
                         sizeof(desc_sense_data1), vb, b_len, b);
        printf("sg_get_sense_str: strlen(b)->%u\n", (uint32_t)strlen(b));
        printf("%s", b);
        printf("\n");
#endif
        printf("desc_sense_data test2\n");
        sg_print_sense(leadin, desc_sense_data2,
                       (int)sizeof(desc_sense_data2), vb);
        printf("\n");
        printf("desc_sense block dev combo plus designator test3\n");
        sg_print_sense(leadin, desc_sense_data3,
                       (int)sizeof(desc_sense_data3), vb);
        printf("\n");
        printf("desc_sense forwarded sense test4\n");
        sg_print_sense(leadin, desc_sense_data4,
                       (int)sizeof(desc_sense_data4), vb);
        printf("\n");
        printf("desc_sense ATA Info test5\n");
        sg_print_sense(leadin, desc_sense_data5,
                       (int)sizeof(desc_sense_data5), vb);
        printf("\n");
        printf("desc_sense UA subsidiary binding changed test6\n");
        sg_print_sense(leadin, desc_sense_data6,
                       (int)sizeof(desc_sense_data6), vb);
        printf("\n");
        printf("\n");
    }

    if (do_printf) {
        ++did_something;
        printf("Testing sg_scnpr():\n");
        b[0] = '\0';
        len = b_len;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = -1;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = 0;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = 1;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = 2;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = 3;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = 4;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = 5;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = 6;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);

        b[0] = '\0';
        len = 7;
        n = sg_scnpr(b, len, "%s", "test");
        printf("sg_scnpr(,%d,,\"test\") -> %d; strlen(b) -> %u\n",
               len, n, (uint32_t)strlen(b));
        if (strlen(b) > 0)
            printf("Resulting string: %s\n", b);
    }
    if (do_hex2) {
        uint8_t b[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                       0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
                       0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58};

        ++did_something;
        for (k = 0; k < 18; ++k) {
            printf("k=%d:\n", k);
            hex2stdout(b, k, 0);
            hex2str(b, k, "h2str0: ", 0, sizeof(bb), bb);
            printf("%s", bb);
            hex2stdout(b, k, 1);
            hex2str(b, k, "h2str1: ", 1, sizeof(bb), bb);
            printf("%s", bb);
            hex2stdout(b, k, -1);
            printf("\n");
        }
    }
    if (do_unaligned) {
        uint16_t u16 = 0x55aa;
        uint16_t u16r;
        uint32_t u24 = 0x224488;
        uint32_t u24r;
        uint32_t u32 = 0x224488aa;
        uint32_t u32r;
        uint64_t u48 = 0x112233445566ULL;
        uint64_t u48r;
        uint64_t u64 = 0x1122334455667788ULL;
        uint64_t u64r;
        uint8_t u8[64];

        ++did_something;
        if (vb)
            memset(u8, 0, sizeof(u8));
        printf("u16=0x%" PRIx16 "\n", u16);
        sg_put_unaligned_le16(u16, u8);
        printf("  le16:\n");
        hex2stdout(u8, vb ? 10 : 2, -1);
        u16r = sg_get_unaligned_le16(u8);
        printf("  u16r=0x%" PRIx16 "\n", u16r);
        sg_put_unaligned_be16(u16, u8);
        printf("  be16:\n");
        hex2stdout(u8, vb ? 10 : 2, -1);
        u16r = sg_get_unaligned_be16(u8);
        printf("  u16r=0x%" PRIx16 "\n\n", u16r);

        printf("u24=0x%" PRIx32 "\n", u24);
        sg_put_unaligned_le24(u24, u8);
        printf("  le24:\n");
        hex2stdout(u8, vb ? 10 : 3, -1);
        u24r = sg_get_unaligned_le24(u8);
        printf("  u24r=0x%" PRIx32 "\n", u24r);
        sg_put_unaligned_be24(u24, u8);
        printf("  be24:\n");
        hex2stdout(u8, vb ? 10 : 3, -1);
        u24r = sg_get_unaligned_be24(u8);
        printf("  u24r=0x%" PRIx32 "\n\n", u24r);

        printf("u32=0x%" PRIx32 "\n", u32);
        sg_put_unaligned_le32(u32, u8);
        printf("  le32:\n");
        hex2stdout(u8, vb ? 10 : 4, -1);
        u32r = sg_get_unaligned_le32(u8);
        printf("  u32r=0x%" PRIx32 "\n", u32r);
        sg_put_unaligned_be32(u32, u8);
        printf("  be32:\n");
        hex2stdout(u8, vb ? 10 : 4, -1);
        u32r = sg_get_unaligned_be32(u8);
        printf("  u32r=0x%" PRIx32 "\n\n", u32r);

        printf("u48=0x%" PRIx64 "\n", u48);
        sg_put_unaligned_le48(u48, u8);
        printf("  le48:\n");
        hex2stdout(u8, vb ? 10 : 6, -1);
        u48r = sg_get_unaligned_le48(u8);
        printf("  u48r=0x%" PRIx64 "\n", u48r);
        sg_put_unaligned_be48(u48, u8);
        printf("  be48:\n");
        hex2stdout(u8, vb ? 10 : 6, -1);
        u48r = sg_get_unaligned_be48(u8);
        printf("  u48r=0x%" PRIx64 "\n\n", u48r);

        printf("u64=0x%" PRIx64 "\n", u64);
        sg_put_unaligned_le64(u64, u8);
        printf("  le64:\n");
        hex2stdout(u8, vb ? 10 : 8, -1);
        u64r = sg_get_unaligned_le64(u8);
        printf("  u64r=0x%" PRIx64 "\n", u64r);
        sg_put_unaligned_be64(u64, u8);
        printf("  be64:\n");
        hex2stdout(u8, vb ? 10 : 8, -1);
        u64r = sg_get_unaligned_be64(u8);
        printf("  u64r=0x%" PRIx64 "\n\n", u64r);

        printf("  be[v=8 bytes]:\n");
        hex2stdout(u8, vb ? 10 : 8, -1);
        u64r = sg_get_unaligned_be(8, u8);
        printf("  u64r[v=8 bytes]=0x%" PRIx64 "\n", u64r);
        printf("  le[v=8 bytes]:\n");
        hex2stdout(u8, vb ? 10 : 8, -1);
        u64r = sg_get_unaligned_le(8, u8);
        printf("  u64r[v=8 bytes]=0x%" PRIx64 "\n\n", u64r);
    }

#if defined(__GNUC__) && ! defined(SG_LIB_FREEBSD)
    if (byteswap_sz > 0) {
        uint32_t elapsed_msecs;
        uint16_t count16 = 0;
        uint32_t count32 = 0;
        uint64_t count64 = 0;
        struct timespec start_tm, end_tm;

        ++did_something;
        if (0 != clock_gettime(CLOCK_MONOTONIC, &start_tm)) {
            perror("clock_gettime(CLOCK_MONOTONIC)\n");
            return 1;
        }
        for (k = 0; k < do_num; ++k) {
            switch (byteswap_sz) {
            case 16:
                sg_put_unaligned_be16(count16 + 1, arr + OFF);
                count16 = sg_get_unaligned_be16(arr + OFF);
                break;
            case 32:
                sg_put_unaligned_be32(count32 + 1, arr + OFF);
                count32 = sg_get_unaligned_be32(arr + OFF);
                break;
            case 64:
                sg_put_unaligned_be64(count64 + 1, arr + OFF);
                count64 = sg_get_unaligned_be64(arr + OFF);
                break;
            default:
                break;
            }
        }
        if (0 != clock_gettime(CLOCK_MONOTONIC, &end_tm)) {
            perror("clock_gettime(CLOCK_MONOTONIC)\n");
            return 1;
        }
        elapsed_msecs = (end_tm.tv_sec - start_tm.tv_sec) * 1000;
        elapsed_msecs += (end_tm.tv_nsec - start_tm.tv_nsec) / 1000000;
        if (16 == byteswap_sz)
            printf("  count16=%u\n", count16);
        else if (32 == byteswap_sz)
            printf("  count32=%u\n", count32);
        else
            printf("  count64=%" PRIu64 "\n", count64);
        printf("Unaligned elapsed milliseconds: %u\n", elapsed_msecs);
        count16 = 0;
        count32 = 0;
        count64 = 0;

        if (0 != clock_gettime(CLOCK_MONOTONIC, &start_tm)) {
            perror("clock_gettime(CLOCK_MONOTONIC)\n");
            return 1;
        }
        for (k = 0; k < do_num; ++k) {
            switch (byteswap_sz) {
            case 16:
                count16 = bswap_16(count16 + 1);
                memcpy(arr + OFF, &count16, 2);
                memcpy(&count16, arr + OFF, 2);
                count16 = bswap_16(count16);
                break;
            case 32:
                count32 = bswap_32(count32 + 1);
                memcpy(arr + OFF, &count32, 4);
                memcpy(&count32, arr + OFF, 4);
                count32 = bswap_32(count32);
                break;
            case 64:
                count64 = bswap_64(count64 + 1);
                memcpy(arr + OFF, &count64, 8);
                memcpy(&count64, arr + OFF, 8);
                count64 = bswap_64(count64);
                break;
            default:
                break;
            }
        }
        if (0 != clock_gettime(CLOCK_MONOTONIC, &end_tm)) {
            perror("clock_gettime(CLOCK_MONOTONIC)\n");
            return 1;
        }
        elapsed_msecs = (end_tm.tv_sec - start_tm.tv_sec) * 1000;
        elapsed_msecs += (end_tm.tv_nsec - start_tm.tv_nsec) / 1000000;
        if (16 == byteswap_sz)
            printf("  count16=%u\n", count16);
        else if (32 == byteswap_sz)
            printf("  count32=%u\n", count32);
        else
            printf("  count64=%" PRIu64 "\n", count64);
        printf("Byteswap/memcpy elapsed milliseconds: %u\n", elapsed_msecs);
        count16 = 0;
        count32 = 0;
        count64 = 0;
    }
#endif

    if (0 == did_something)
        printf("Looks like no tests done, check usage with '-h'\n");
    return ret;
}
