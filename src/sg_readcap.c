/* This code is does a SCSI READ CAPACITY command on the given device
 * and outputs the result.
 *
 * Copyright (C) 1999 - 2020 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program was originally written with Linux 2.4 kernel series.
 * It now builds for the Linux 2.6, 3 and 4 kernel series and various other
 * operating systems.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"


static const char * version_str = "4.05 20200122";

#define ME "sg_readcap: "

#define RCAP_REPLY_LEN 8
#define RCAP16_REPLY_LEN 32

static struct option long_options[] = {
    {"brief", no_argument, 0, 'b'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"lba", required_argument, 0, 'L'},
    {"long", no_argument, 0, 'l'},
    {"16", no_argument, 0, 'l'},
    {"new", no_argument, 0, 'N'},
    {"old", no_argument, 0, 'O'},
    {"pmi", no_argument, 0, 'p'},
    {"raw", no_argument, 0, 'r'},
    {"readonly", no_argument, 0, 'R'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"zbc", no_argument, 0, 'z'},
    {0, 0, 0, 0},
};

struct opts_t {
    bool do_brief;
    bool do_long;
    bool do_pmi;
    bool do_raw;
    bool o_readonly;
    bool do_zbc;
    bool opt_new;
    bool verbose_given;
    bool version_given;
    int do_help;
    int do_hex;
    int do_lba;
    int verbose;
    uint64_t llba;
    const char * device_name;
};


static void
usage()
{
    pr2serr("Usage: sg_readcap [--16] [--brief] [--help] [--hex] "
            "[--lba=LBA] [--long]\n"
            "                  [--pmi] [--raw] [--readonly] [--verbose] "
            "[--version]\n"
            "                  [--zbc] DEVICE\n"
            "  where:\n"
            "    --16            use READ CAPACITY (16) cdb (same as "
            "--long)\n"
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
            "    --pmi|-p        partial medium indicator (without this "
            "option shows\n"
            "                    total disk capacity) [made obsolete in "
            "sbc3r26]\n"
            "    --raw|-r        output response in binary to stdout\n"
            "    --readonly|-R    open DEVICE read-only (def: RCAP(16) "
            "read-write)\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version string and exit\n"
            "    --old|-O        use old interface (use as first option)\n"
            "    --zbc|-z        show rc_basis ZBC field (implies --16)\n\n"
            "Perform a SCSI READ CAPACITY (10 or 16) command\n");
}

static void
usage_old()
{
    pr2serr("Usage:  sg_readcap [-16] [-b] [-h] [-H] [-lba=LBA] "
            "[-pmi] [-r] [-R]\n"
            "                   [-v] [-V] [-z] DEVICE\n"
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
            "    -R     open DEVICE read-only (def: RCAP(16) read-write)\n"
            "    -v     increase verbosity\n"
            "    -V     print version string and exit\n"
            "    -N|--new   use new interface\n"
            "    -z     show rc_basis ZBC field (implies -16)\n\n"
            "Perform a SCSI READ CAPACITY (10 or 16) command\n");
}

static void
usage_for(const struct opts_t * op)
{
    if (op->opt_new)
        usage();
    else
        usage_old();
}

static int
new_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int c;
    int a_one = 0;
    int64_t nn;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "16bhHlL:NOprRvVz", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case '1':
            ++a_one;
            break;
        case '6':
            if (a_one)
                op->do_long = true;
            break;
        case 'b':
            op->do_brief = true;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'H':
            ++op->do_hex;
            break;
        case 'l':
            op->do_long = true;
            break;
        case 'L':
            nn = sg_get_llnum(optarg);
            if (-1 == nn) {
                pr2serr("bad argument to '--lba='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->llba = nn;
            /* force READ_CAPACITY16 for large lbas */
            if (op->llba > 0xfffffffeULL)
                op->do_long = true;
            ++op->do_lba;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = false;
            return 0;
        case 'p':
            op->do_pmi = true;
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'R':
            op->o_readonly = true;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'z':
            op->do_zbc = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
            if (op->do_help)
                break;
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == op->device_name) {
            op->device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int
old_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    bool jmp_out;
    int k, plen, num;
    const char * cp;
    uint64_t uu;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '1':
                    if ('6' == *(cp + 1)) {
                        op->do_long = true;
                        ++cp;
                        --plen;
                    } else
                        jmp_out = true;
                    break;
                case 'b':
                    op->do_brief = true;
                    break;
                case 'h':
                case '?':
                    ++op->do_help;
                    break;
                case 'H':
                    ++op->do_hex;
                    break;
                case 'N':
                    op->opt_new = true;
                    return 0;
                case 'O':
                    break;
                case 'p':
                    if (0 == strncmp("pmi", cp, 3)) {
                        op->do_pmi = true;
                        cp += 2;
                        plen -= 2;
                    } else
                        jmp_out = true;
                    break;
                case 'r':
                    op->do_raw = true;
                    break;
                case 'R':
                    op->o_readonly = true;
                    break;
                case 'v':
                    op->verbose_given = true;
                    ++op->verbose;
                    break;
                case 'V':
                    op->version_given = true;
                    break;
                case 'z':
                    op->do_zbc = true;
                    break;
                default:
                    jmp_out = true;
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
                    op->do_long = true;
                op->llba = uu;
                ++op->do_lba;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == op->device_name)
            op->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not expecting: %s\n",
                    op->device_name, cp);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int
parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = false;
        res = old_parse_cmd_line(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = new_parse_cmd_line(op, argc, argv);
    } else {
        op->opt_new = true;
        res = new_parse_cmd_line(op, argc, argv);
        if ((0 == res) && (! op->opt_new))
            res = old_parse_cmd_line(op, argc, argv);
    }
    return res;
}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

static const char *
rc_basis_str(int rc_basis, char * b, int blen)
{
    switch (rc_basis) {
    case 0:
        snprintf(b, blen, "last contiguous that's not seq write required");
        break;
    case 1:
        snprintf(b, blen, "last LBA on logical unit");
        break;
    default:
        snprintf(b, blen, "reserved (0x%x)", rc_basis);
        break;
    }
    return b;
}


int
main(int argc, char * argv[])
{
    bool rw_0_flag;
    int res, prot_en, p_type, lbppbe;
    int sg_fd = -1;
    int ret = 0;
    uint32_t last_blk_addr, block_size;
    uint64_t llast_blk_addr;
    uint8_t * resp_buff;
    uint8_t * free_resp_buff;
    const int resp_buff_sz = RCAP16_REPLY_LEN;
    char b[80];
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    memset(op, 0, sizeof(opts));
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return res;
    if (op->do_help) {
        usage_for(op);
        return 0;
    }
#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (op->verbose_given && op->version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->verbose = 0;
    } else if (! op->verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (op->verbose_given && op->version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == op->device_name) {
        pr2serr("No DEVICE argument given\n\n");
        usage_for(op);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }
    if (op->do_zbc) {
        if (! op->do_long)
            op->do_long = true;
    }

    resp_buff = sg_memalign(resp_buff_sz, 0, &free_resp_buff, false);
    if (NULL == resp_buff) {
        pr2serr("Unable to allocate %d bytes on heap\n", resp_buff_sz);
        return sg_convert_errno(ENOMEM);
    }
    if ((! op->do_pmi) && (op->llba > 0)) {
        pr2serr(ME "lba can only be non-zero when '--pmi' is set\n");
        usage_for(op);
        ret = SG_LIB_CONTRADICT;
        goto fini;
    }
    if (op->do_long)
        rw_0_flag = op->o_readonly;
    else
        rw_0_flag = true;  /* RCAP(10) has opened RO in past, so leave */
    if ((sg_fd = sg_cmds_open_device(op->device_name, rw_0_flag,
                                     op->verbose)) < 0) {
        pr2serr(ME "error opening file: %s: %s\n", op->device_name,
                safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    if (! op->do_long) {
        res = sg_ll_readcap_10(sg_fd, op->do_pmi, (unsigned int)op->llba,
                               resp_buff, RCAP_REPLY_LEN, true,
                               op->verbose);
        ret = res;
        if (0 == res) {
            if (op->do_hex || op->do_raw) {
                if (op->do_raw)
                    dStrRaw(resp_buff, RCAP_REPLY_LEN);
                else if (op->do_hex > 2)
                    hex2stdout(resp_buff, RCAP_REPLY_LEN, -1);
                else
                    hex2stdout(resp_buff, RCAP_REPLY_LEN, 1);
                goto fini;
            }
            last_blk_addr = sg_get_unaligned_be32(resp_buff + 0);
            if (0xffffffff != last_blk_addr) {
                block_size = sg_get_unaligned_be32(resp_buff + 4);
                if (op->do_brief) {
                    printf("0x%" PRIx32 " 0x%" PRIx32 "\n",
                           last_blk_addr + 1, block_size);
                    goto fini;
                }
                printf("Read Capacity results:\n");
                if (op->do_pmi)
                    printf("   PMI mode: given lba=0x%" PRIx64 ", last lba "
                           "before delay=0x%" PRIx32 "\n", op->llba,
                           last_blk_addr);
                else
                    printf("   Last LBA=%" PRIu32 " (0x%" PRIx32 "), Number "
                           "of logical blocks=%" PRIu32 "\n", last_blk_addr,
                            last_blk_addr, last_blk_addr + 1);
                printf("   Logical block length=%u bytes\n", block_size);
                if (! op->do_pmi) {
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
                           "GB", total_sz, sz_mb, sz_gb);
#else
                    printf("   Device size: %" PRIu64 " bytes, %.1f MiB, "
                           "%.2f GB", total_sz, sz_mb, sz_gb);
#endif
                    if (sz_gb > 2000) {
#ifdef SG_LIB_MINGW
                        printf(", %g TB", sz_gb / 1000);
#else
                        printf(", %.2f TB", sz_gb / 1000);
#endif
                    }
                    printf("\n");
                }
                goto fini;
            } else {
                printf("READ CAPACITY (10) indicates device capacity too "
                       "large\n  now trying 16 byte cdb variant\n");
                op->do_long = true;
            }
        } else if (SG_LIB_CAT_INVALID_OP == res) {
            op->do_long = true;
            sg_cmds_close_device(sg_fd);
            if ((sg_fd = sg_cmds_open_device(op->device_name, op->o_readonly,
                                             op->verbose)) < 0) {
                pr2serr(ME "error re-opening file: %s (rw): %s\n",
                        op->device_name, safe_strerror(-sg_fd));
                ret = sg_convert_errno(-sg_fd);
                goto fini;
            }
            if (op->verbose)
                pr2serr("READ CAPACITY (10) not supported, trying READ "
                        "CAPACITY (16)\n");
        } else if (res) {
            sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
            pr2serr("READ CAPACITY (10) failed: %s\n", b);
        }
    }
    if (op->do_long) {
        res = sg_ll_readcap_16(sg_fd, op->do_pmi, op->llba, resp_buff,
                               RCAP16_REPLY_LEN, true, op->verbose);
        ret = res;
        if (0 == res) {
            if (op->do_hex || op->do_raw) {
                if (op->do_raw)
                    dStrRaw(resp_buff, RCAP16_REPLY_LEN);
                else if (op->do_hex > 2)
                    hex2stdout(resp_buff, RCAP16_REPLY_LEN, -1);
                else
                    hex2stdout(resp_buff, RCAP16_REPLY_LEN, 1);
                goto fini;
            }
            llast_blk_addr = sg_get_unaligned_be64(resp_buff + 0);
            block_size = sg_get_unaligned_be32(resp_buff + 8);
            if (op->do_brief) {
                printf("0x%" PRIx64 " 0x%" PRIx32 "\n", llast_blk_addr + 1,
                       block_size);
                goto fini;
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
            if (op->do_zbc) {
                int rc_basis = (resp_buff[12] >> 4) & 0x3;

                printf("   ZBC's rc_basis=%d [%s]\n", rc_basis,
                       rc_basis_str(rc_basis, b, sizeof(b)));
            }
            printf("   Logical block provisioning: lbpme=%d, lbprz=%d\n",
                   !!(resp_buff[14] & 0x80), !!(resp_buff[14] & 0x40));
            if (op->do_pmi)
                printf("   PMI mode: given lba=0x%" PRIx64 ", last lba "
                       "before delay=0x%" PRIx64 "\n", op->llba,
                       llast_blk_addr);
            else
                printf("   Last LBA=%" PRIu64 " (0x%" PRIx64 "), Number of "
                       "logical blocks=%" PRIu64 "\n", llast_blk_addr,
                       llast_blk_addr, llast_blk_addr + 1);
            printf("   Logical block length=%" PRIu32 " bytes\n", block_size);
            lbppbe = resp_buff[13] & 0xf;
            printf("   Logical blocks per physical block exponent=%d",
                   lbppbe);
            if (lbppbe > 0)
                printf(" [so physical block length=%u bytes]\n",
                       block_size * (1 << lbppbe));
            else
                printf("\n");
            printf("   Lowest aligned LBA=%d\n",
                   ((resp_buff[14] & 0x3f) << 8) + resp_buff[15]);
            if (! op->do_pmi) {
                uint64_t total_sz = llast_blk_addr + 1;
                double sz_mb, sz_gb;

                total_sz *= block_size;
                sz_mb = ((double)(llast_blk_addr + 1) * block_size) /
                        (double)(1048576);
                sz_gb = ((double)(llast_blk_addr + 1) * block_size) /
                        (double)(1000000000L);
                printf("Hence:\n");
#ifdef SG_LIB_MINGW
                printf("   Device size: %" PRIu64 " bytes, %g MiB, %g GB",
                       total_sz, sz_mb, sz_gb);
#else
                printf("   Device size: %" PRIu64 " bytes, %.1f MiB, %.2f "
                       "GB", total_sz, sz_mb, sz_gb);
#endif
                if (sz_gb > 2000) {
#ifdef SG_LIB_MINGW
                    printf(", %g TB", sz_gb / 1000);
#else
                    printf(", %.2f TB", sz_gb / 1000);
#endif
                }
                printf("\n");
            }
            goto fini;
        } else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            pr2serr("bad field in READ CAPACITY (16) cdb including "
                    "unsupported service action\n");
        else if (res) {
            sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
            pr2serr("READ CAPACITY (16) failed: %s\n", b);
        }
    }
    if (op->do_brief)
        printf("0x0 0x0\n");
fini:
    if (free_resp_buff)
        free(free_resp_buff);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_readcap failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
