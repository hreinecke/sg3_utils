/* This code is does a SCSI READ CAPACITY command on the given device
   and outputs the result.

*  Copyright (C) 1999 - 2013 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program was originally written with Linux 2.4 kernel series.
   It now builds for the Linux 2.6 and 3 kernel series and various other
   operating systems.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"


static char * version_str = "3.88 20130228";

#define ME "sg_readcap: "

#define RCAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

static struct option long_options[] = {
        {"brief", 0, 0, 'b'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"lba", 1, 0, 'L'},
        {"long", 0, 0, 'l'},
        {"16", 0, 0, 'l'},
        {"new", 0, 0, 'N'},
        {"old", 0, 0, 'O'},
        {"pmi", 0, 0, 'p'},
        {"raw", 0, 0, 'r'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_brief;
    int do_help;
    int do_hex;
    int do_lba;
    int do_long;
    int do_pmi;
    int do_raw;
    int do_verbose;
    int do_version;
    uint64_t llba;
    const char * device_name;
    int opt_new;
};

static void usage()
{
    fprintf(stderr, "Usage: sg_readcap [--brief] [--help] [--hex] "
            "[--lba=LBA] [--long] [--16]\n"
            "                  [--pmi] [--raw] [--verbose] [--version] "
            "DEVICE\n"
            "  where:\n"
            "    --brief|-b      brief, two hex numbers: number of blocks "
            "and block size\n"
            "    --help|-h       print this usage message and exit\n"
            "    --hex|-H        output response in hexadecimal to stdout\n"
            "    --lba=LBA|-L LBA    yields the last block prior to (head "
            "movement) delay\n"
            "                        after LBA [in decimal (def: 0) "
            "valid with '--pmi']\n"
            "    --long|-l       use READ CAPACITY (16) cdb (def: use "
            "10 byte cdb)\n"
            "    --16            use READ CAPACITY (16) cdb (same as "
            "--long)\n"
            "    --pmi|-p        partial medium indicator (without this "
            "option shows\n"
            "                    total disk capacity) [made obsolete in "
            "sbc3r26]\n"
            "    --raw|-r        output response in binary to stdout\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version string and exit\n\n"
            "Perform a SCSI READ CAPACITY (10 or 16) command\n");
}

static void usage_old()
{
    fprintf(stderr, "Usage:  sg_readcap [-16] [-b] [-h] [-H] [-lba=LBA] "
            "[-pmi] [-r] [-v] [-V]\n"
            "                   DEVICE\n"
            "  where:\n"
            "    -16    use READ CAPACITY (16) cdb (def: use "
            "10 byte cdb)\n"
            "    -b     brief, two hex numbers: number of blocks "
            "and block size\n"
            "    -h     print this usage message and exit\n"
            "    -H     output response in hexadecimal to stdout\n"
            "    -lba=LBA    yields the last block prior to (head "
            "movement) delay\n"
            "                after LBA [in hex (def: 0) "
            "valid with -pmi]\n"
            "    -pmi   partial medium indicator (without this option "
            "shows total\n"
            "           disk capacity)\n"
            "    -r     output response in binary to stdout\n"
            "    -v     increase verbosity\n"
            "    -V     print version string and exit\n\n"
            "Perform a SCSI READ CAPACITY command\n");
}

static void usage_for(const struct opts_t * optsp)
{
    if (optsp->opt_new)
        usage();
    else
        usage_old();
}

static int process_cl_new(struct opts_t * optsp, int argc, char * argv[])
{
    int c;
    int a_one = 0;
    int64_t nn;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "16bhHlL:NOprvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case '1':
            ++a_one;
            break;
        case '6':
            if (a_one)
                ++optsp->do_long;
            break;
        case 'b':
            ++optsp->do_brief;
            break;
        case 'h':
        case '?':
            ++optsp->do_help;
            break;
        case 'H':
            ++optsp->do_hex;
            break;
        case 'l':
            ++optsp->do_long;
            break;
        case 'L':
            nn = sg_get_llnum(optarg);
            if (-1 == nn) {
                fprintf(stderr, "bad argument to '--lba='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->llba = nn;
            /* force READ_CAPACITY16 for large lbas */
            if (optsp->llba > 0xfffffffeULL)
                ++optsp->do_long;
            ++optsp->do_lba;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            optsp->opt_new = 0;
            return 0;
        case 'p':
            ++optsp->do_pmi;
            break;
        case 'r':
            ++optsp->do_raw;
            break;
        case 'v':
            ++optsp->do_verbose;
            break;
        case 'V':
            ++optsp->do_version;
            break;
        default:
            fprintf(stderr, "unrecognised option code %c [0x%x]\n", c, c);
            if (optsp->do_help)
                break;
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == optsp->device_name) {
            optsp->device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int process_cl_old(struct opts_t * optsp, int argc, char * argv[])
{
    int k, jmp_out, plen, num;
    const char * cp;
    uint64_t uu;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '1':
                    if ('6' == *(cp + 1)) {
                        ++optsp->do_long;
                        ++cp;
                        --plen;
                    } else
                        jmp_out = 1;
                    break;
                case 'b':
                    ++optsp->do_brief;
                    break;
                case 'h':
                case '?':
                    ++optsp->do_help;
                    break;
                case 'H':
                    ++optsp->do_hex;
                    break;
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'p':
                    if (0 == strncmp("pmi", cp, 3)) {
                        ++optsp->do_pmi;
                        cp += 2;
                        plen -= 2;
                    } else
                        jmp_out = 1;
                    break;
                case 'r':
                    ++optsp->do_raw;
                    break;
                case 'v':
                    ++optsp->do_verbose;
                    break;
                case 'V':
                    ++optsp->do_version;
                    break;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("lba=", cp, 4)) {
                num = sscanf(cp + 4, "%" SCNx64 "", &uu);
                if (1 != num) {
                    printf("Bad value after 'lba=' option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                /* force READ_CAPACITY16 for large lbas */
                if (uu > 0xfffffffeULL)
                    ++optsp->do_long;
                optsp->llba = uu;
                ++optsp->do_lba;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == optsp->device_name)
            optsp->device_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", optsp->device_name, cp);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int process_cl(struct opts_t * optsp, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        optsp->opt_new = 0;
        res = process_cl_old(optsp, argc, argv);
        if ((0 == res) && optsp->opt_new)
            res = process_cl_new(optsp, argc, argv);
    } else {
        optsp->opt_new = 1;
        res = process_cl_new(optsp, argc, argv);
        if ((0 == res) && (0 == optsp->opt_new))
            res = process_cl_old(optsp, argc, argv);
    }
    return res;
}

static void dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

int main(int argc, char * argv[])
{
    int sg_fd, k, res, prot_en, p_type;
    uint64_t llast_blk_addr;
    int ret = 0;
    unsigned int last_blk_addr, block_size;
    unsigned char resp_buff[RCAP16_REPLY_LEN];
    struct opts_t opts;

    memset(&opts, 0, sizeof(opts));
    res = process_cl(&opts, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (opts.do_help) {
        usage_for(&opts);
        return 0;
    }
    if (opts.do_version) {
        fprintf(stderr, "Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == opts.device_name) {
        fprintf(stderr, "No DEVICE argument given\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    memset(resp_buff, 0, sizeof(resp_buff));

    if ((0 == opts.do_pmi) && (opts.llba > 0)) {
        fprintf(stderr, ME "lba can only be non-zero when '--pmi' is set\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((sg_fd = sg_cmds_open_device(opts.device_name,
                 (opts.do_long ? 0 /* rw */ : 1), opts.do_verbose)) < 0) {
        fprintf(stderr, ME "error opening file: %s: %s\n", opts.device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (! opts.do_long) {
        res = sg_ll_readcap_10(sg_fd, opts.do_pmi, (unsigned int)opts.llba,
                               resp_buff, RCAP_REPLY_LEN, 1, opts.do_verbose);
        ret = res;
        if (0 == res) {
            if (opts.do_hex || opts.do_raw) {
                if (opts.do_raw)
                    dStrRaw((const char *)resp_buff, RCAP_REPLY_LEN);
                else
                    dStrHex((const char *)resp_buff, RCAP_REPLY_LEN, 1);
                goto good;
            }
            last_blk_addr = ((resp_buff[0] << 24) | (resp_buff[1] << 16) |
                             (resp_buff[2] << 8) | resp_buff[3]);
            if (0xffffffff != last_blk_addr) {
                block_size = ((resp_buff[4] << 24) | (resp_buff[5] << 16) |
                             (resp_buff[6] << 8) | resp_buff[7]);
                if (opts.do_brief) {
                    printf("0x%x 0x%x\n", last_blk_addr + 1, block_size);
                    goto good;
                }
                printf("Read Capacity results:\n");
                if (opts.do_pmi)
                    printf("   PMI mode: given lba=0x%" PRIx64 ", last lba "
                           "before delay=0x%x\n", opts.llba, last_blk_addr);
                else
                    printf("   Last logical block address=%u (0x%x), Number "
                           "of blocks=%u\n", last_blk_addr, last_blk_addr,
                           last_blk_addr + 1);
                printf("   Logical block length=%u bytes\n", block_size);
                if (! opts.do_pmi) {
                    uint64_t total_sz = last_blk_addr + 1;
                    double sz_mb, sz_gb;

                    total_sz *= block_size;
                    sz_mb = ((double)(last_blk_addr + 1) * block_size) /
                            (double)(1048576);
                    sz_gb = ((double)(last_blk_addr + 1) * block_size) /
                            (double)(1000000000L);
                    printf("Hence:\n");
#ifdef SG_LIB_MINGW
                    printf("   Device size: %" PRIu64 " bytes, %g MiB, %g "
                           "GB\n", total_sz, sz_mb, sz_gb);
#else
                    printf("   Device size: %" PRIu64 " bytes, %.1f MiB, "
                           "%.2f GB\n", total_sz, sz_mb, sz_gb);
#endif
                }
                goto good;
            } else {
                printf("READ CAPACITY (10) indicates device capacity too "
                       "large\n  now trying 16 byte cdb variant\n");
                opts.do_long = 1;
            }
        } else if (SG_LIB_CAT_INVALID_OP == res) {
            opts.do_long = 1;
            sg_cmds_close_device(sg_fd);
            if ((sg_fd = sg_cmds_open_device(opts.device_name, 0 /*rw */,
                                             opts.do_verbose))
                < 0) {
                fprintf(stderr, ME "error re-opening file: %s (rw): %s\n",
                        opts.device_name, safe_strerror(-sg_fd));
                return SG_LIB_FILE_ERROR;
            }
            if (opts.do_verbose)
                fprintf(stderr, "READ CAPACITY (10) not supported, trying "
                        "READ CAPACITY (16)\n");
        } else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in READ CAPACITY (10) cdb\n");
        else if (SG_LIB_CAT_NOT_READY == res)
            fprintf(stderr, "READ CAPACITY (10) failed, device not ready\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "READ CAPACITY (10) failed, aborted command\n");
        else if (! opts.do_verbose)
            fprintf(stderr, "READ CAPACITY (10) failed [res=%d], try "
                    "with '-v'\n", res);
    }
    if (opts.do_long) {
        res = sg_ll_readcap_16(sg_fd, opts.do_pmi, opts.llba, resp_buff,
                               RCAP16_REPLY_LEN, 1, opts.do_verbose);
        ret = res;
        if (0 == res) {
            if (opts.do_hex || opts.do_raw) {
                if (opts.do_raw)
                    dStrRaw((const char *)resp_buff, RCAP16_REPLY_LEN);
                else
                    dStrHex((const char *)resp_buff, RCAP16_REPLY_LEN, 1);
                goto good;
            }
            for (k = 0, llast_blk_addr = 0; k < 8; ++k) {
                llast_blk_addr <<= 8;
                llast_blk_addr |= resp_buff[k];
            }
            block_size = ((resp_buff[8] << 24) | (resp_buff[9] << 16) |
                          (resp_buff[10] << 8) | resp_buff[11]);
            if (opts.do_brief) {
                printf("0x%" PRIx64 " 0x%x\n", llast_blk_addr + 1, block_size);
                goto good;
            }
            prot_en = !!(resp_buff[12] & 0x1);
            p_type = ((resp_buff[12] >> 1) & 0x7);
            printf("Read Capacity results:\n");
            printf("   Protection: prot_en=%d, p_type=%d, p_i_exponent=%d",
                   prot_en, p_type, ((resp_buff[13] >> 4) & 0xf));
            if (prot_en)
                printf(" [type %d protection]\n", p_type + 1);
            else
                printf("\n");
            printf("   Logical block provisioning: lbpme=%d, lbprz=%d\n",
                   !!(resp_buff[14] & 0x80), !!(resp_buff[14] & 0x40));
            if (opts.do_pmi)
                printf("   PMI mode: given lba=0x%" PRIx64 ", last lba "
                       "before delay=0x%" PRIx64 "\n", opts.llba,
                       llast_blk_addr);
            else
                printf("   Last logical block address=%" PRIu64 " (0x%"
                       PRIx64 "), Number of logical blocks=%" PRIu64 "\n",
                       llast_blk_addr, llast_blk_addr, llast_blk_addr + 1);
            printf("   Logical block length=%u bytes\n", block_size);
            printf("   Logical blocks per physical block exponent=%d\n",
                   resp_buff[13] & 0xf);
            printf("   Lowest aligned logical block address=%d\n",
                   ((resp_buff[14] & 0x3f) << 8) + resp_buff[15]);
            if (! opts.do_pmi) {
                uint64_t total_sz = llast_blk_addr + 1;
                double sz_mb, sz_gb;

                total_sz *= block_size;
                sz_mb = ((double)(llast_blk_addr + 1) * block_size) /
                        (double)(1048576);
                sz_gb = ((double)(llast_blk_addr + 1) * block_size) /
                        (double)(1000000000L);
                printf("Hence:\n");
#ifdef SG_LIB_MINGW
                printf("   Device size: %" PRIu64 " bytes, %g MiB, %g GB\n",
                       total_sz, sz_mb, sz_gb);
#else
                printf("   Device size: %" PRIu64 " bytes, %.1f MiB, %.2f "
                       "GB\n", total_sz, sz_mb, sz_gb);
#endif
            }
            goto good;
        }
        else if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "READ CAPACITY (16) not supported\n");
        else if (SG_LIB_CAT_NOT_READY == res)
            fprintf(stderr, "READ CAPACITY (16) failed, device not ready\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "READ CAPACITY (16) failed, aborted command\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "bad field in READ CAPACITY (16) cdb "
                    "including unsupported service action\n");
        else if (! opts.do_verbose)
            fprintf(stderr, "READ CAPACITY (16) failed [res=%d], try "
                    "with '-v'\n", res);
    }
    if (opts.do_brief)
        printf("0x0 0x0\n");

good:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
