/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 1999-2019 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program uses the SCSI command READ BUFFER on the given
 * device, first to find out how big it is and then to read that
 * buffer (data mode, buffer id 0).
 */


#define _XOPEN_SOURCE 600
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

#define RB_MODE_DESC 3
#define RB_MODE_DATA 2
#define RB_MODE_ECHO_DESC 0xb
#define RB_MODE_ECHO_DATA 0xa
#define RB_DESC_LEN 4
#define RB_DEF_SIZE (200*1024*1024)
#define RB_OPCODE 0x3C
#define RB_CMD_LEN 10

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif


static const char * version_str = "5.07 20191226";

static struct option long_options[] = {
        {"buffer", required_argument, 0, 'b'},
        {"dio", no_argument, 0, 'd'},
        {"echo", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"mmap", no_argument, 0, 'm'},
        {"new", no_argument, 0, 'N'},
        {"old", no_argument, 0, 'O'},
        {"quick", no_argument, 0, 'q'},
        {"size", required_argument, 0, 's'},
        {"time", no_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    bool do_dio;
    bool do_echo;
    bool do_mmap;
    bool do_quick;
    bool do_time;
    bool verbose_given;
    bool version_given;
    bool opt_new;
    int do_buffer;
    int do_help;
    int verbose;
    int64_t do_size;
    const char * device_name;
};


static void
usage()
{
    pr2serr("Usage: sg_rbuf [--buffer=EACH] [--dio] [--echo] "
            "[--help] [--mmap]\n"
            "               [--quick] [--size=OVERALL] [--time] [--verbose] "
            "[--version]\n"
            "               SG_DEVICE\n");
    pr2serr("  where:\n"
            "    --buffer=EACH|-b EACH    buffer size to use (in bytes)\n"
            "    --dio|-d        requests dio ('-q' overrides it)\n"
            "    --echo|-e       use echo buffer (def: use data mode)\n"
            "    --help|-h       print usage message then exit\n"
            "    --mmap|-m       requests mmap-ed IO (overrides -q, -d)\n"
            "    --quick|-q      quick, don't xfer to user space\n");
    pr2serr("    --size=OVERALL|-s OVERALL    total size to read (in bytes)\n"
            "                    default: 200 MiB\n"
            "    --time|-t       time the data transfer\n"
            "    --verbose|-v    increase verbosity (more debug)\n"
            "    --old|-O        use old interface (use as first option)\n"
            "    --version|-V    print version string then exit\n\n"
            "Use SCSI READ BUFFER command (data or echo buffer mode, buffer "
            "id 0)\nrepeatedly. This utility only works with Linux sg "
            "devices.\n");
}

static void
usage_old()
{
    printf("Usage: sg_rbuf [-b=EACH_KIB] [-d] [-m] [-q] [-s=OVERALL_MIB] "
           "[-t] [-v] [-V]\n               SG_DEVICE\n");
    printf("  where:\n");
    printf("    -b=EACH_KIB    num is buffer size to use (in KiB)\n");
    printf("    -d       requests dio ('-q' overrides it)\n");
    printf("    -e       use echo buffer (def: use data mode)\n");
    printf("    -m       requests mmap-ed IO (overrides -q, -d)\n");
    printf("    -q       quick, don't xfer to user space\n");
    printf("    -s=OVERALL_MIB    num is total size to read (in MiB) "
           "(default: 200 MiB)\n");
    printf("             maximum total size is 4000 MiB\n");
    printf("    -t       time the data transfer\n");
    printf("    -v       increase verbosity (more debug)\n");
    printf("    -N|--new use new interface\n");
    printf("    -V       print version string then exit\n\n");
    printf("Use SCSI READ BUFFER command (data or echo buffer mode, buffer "
           "id 0)\nrepeatedly. This utility only works with Linux sg "
            "devices.\n");
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
    int c, n;
    int64_t nn;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:dehmNOqs:tvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            n = sg_get_num(optarg);
            if (n < 0) {
                pr2serr("bad argument to '--buffer'\n");
                usage_for(op);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_buffer = n;
            break;
        case 'd':
            op->do_dio = true;
            break;
        case 'e':
            op->do_echo = true;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'm':
            op->do_mmap = true;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = false;
            return 0;
        case 'q':
            op->do_quick = true;
            break;
        case 's':
           nn = sg_get_llnum(optarg);
           if (nn < 0) {
                pr2serr("bad argument to '--size'\n");
                usage_for(op);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_size = nn;
            break;
        case 't':
            op->do_time = true;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
            if (op->do_help)
                break;
            usage_for(op);
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
            usage_for(op);
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
    int64_t nn;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'd':
                    op->do_dio = true;
                    break;
                case 'e':
                    op->do_echo = true;
                    break;
                case 'h':
                case '?':
                    ++op->do_help;
                    break;
                case 'm':
                    op->do_mmap = true;
                    break;
                case 'N':
                    op->opt_new = true;
                    return 0;
                case 'O':
                    break;
                case 'q':
                    op->do_quick = true;
                    break;
                case 't':
                    op->do_time = true;
                    break;
                case 'v':
                    op->verbose_given = true;
                    ++op->verbose;
                    break;
                case 'V':
                    op->version_given = true;
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
            if (0 == strncmp("b=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &op->do_buffer);
                if ((1 != num) || (op->do_buffer <= 0)) {
                    printf("Couldn't decode number after 'b=' option\n");
                    usage_for(op);
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->do_buffer *= 1024;
            }
            else if (0 == strncmp("s=", cp, 2)) {
                nn = sg_get_llnum(optarg);
                if (nn < 0) {
                    printf("Couldn't decode number after 's=' option\n");
                    usage_for(op);
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->do_size = nn;
                op->do_size *= 1024 * 1024;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage_for(op);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == op->device_name)
            op->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not expecting: %s\n",
                    op->device_name, cp);
            usage_for(op);
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


int
main(int argc, char * argv[])
{
#ifdef DEBUG
    bool clear = true;
#endif
    bool dio_incomplete = false;
    int sg_fd, res, err;
    int buf_capacity = 0;
    int buf_size = 0;
    size_t psz;
    unsigned int k, num;
    int64_t total_size = RB_DEF_SIZE;
    struct opts_t * op;
    uint8_t * rbBuff = NULL;
    void * rawp = NULL;
    uint8_t sense_buffer[32];
    uint8_t rb_cdb [RB_CMD_LEN];
    struct sg_io_hdr io_hdr;
    struct timeval start_tm, end_tm;
    struct opts_t opts;

#if defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
    psz = sysconf(_SC_PAGESIZE); /* POSIX.1 (was getpagesize()) */
#else
    psz = 4096;     /* give up, pick likely figure */
#endif
    op = &opts;
    memset(op, 0, sizeof(opts));
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
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

    if (op->do_buffer > 0)
        buf_size = op->do_buffer;
    if (op->do_size > 0)
        total_size = op->do_size;

    sg_fd = open(op->device_name, O_RDONLY | O_NONBLOCK);
    if (sg_fd < 0) {
        err = errno;
        perror("device open error");
        return sg_convert_errno(err);
    }
    if (op->do_mmap) {
        op->do_dio = false;
        op->do_quick = false;
    }
    if (NULL == (rawp = malloc(512))) {
        printf("out of memory (query)\n");
        return SG_LIB_CAT_OTHER;
    }
    rbBuff = (uint8_t *)rawp;

    memset(rb_cdb, 0, RB_CMD_LEN);
    rb_cdb[0] = RB_OPCODE;
    rb_cdb[1] = op->do_echo ? RB_MODE_ECHO_DESC : RB_MODE_DESC;
    rb_cdb[8] = RB_DESC_LEN;
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rb_cdb);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = RB_DESC_LEN;
    io_hdr.dxferp = rbBuff;
    io_hdr.cmdp = rb_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */
    if (op->verbose) {
        char b[128];

        pr2serr("    Read buffer (%sdescriptor) cdb: %s\n",
                (op->do_echo ? "echo " : ""),
                sg_get_command_str(rb_cdb, RB_CMD_LEN, false, sizeof(b), b));
    }

    /* do normal IO to find RB size (not dio or mmap-ed at this stage) */
    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO READ BUFFER descriptor error");
        if (rawp)
            free(rawp);
        return SG_LIB_CAT_OTHER;
    }

    if (op->verbose > 2)
        pr2serr("      duration=%u ms\n", io_hdr.duration);
    /* now for the error processing */
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("READ BUFFER descriptor, continuing", &io_hdr,
                        op->verbose > 1);
#if defined(__GNUC__)
#if (__GNUC__ >= 7)
        __attribute__((fallthrough));
        /* FALL THROUGH */
#endif
#endif
    case SG_LIB_CAT_CLEAN:
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("READ BUFFER descriptor error", &io_hdr,
                        op->verbose > 1);
        if (rawp) free(rawp);
        return (res >= 0) ? res : SG_LIB_CAT_OTHER;
    }

    if (op->do_echo) {
        buf_capacity = 0x1fff & sg_get_unaligned_be16(rbBuff + 2);
        printf("READ BUFFER reports: echo buffer capacity=%d\n",
               buf_capacity);
    } else {
        buf_capacity = sg_get_unaligned_be24(rbBuff + 1);
        printf("READ BUFFER reports: buffer capacity=%d, offset "
               "boundary=%d\n", buf_capacity, (int)rbBuff[0]);
    }

    if (0 == buf_size)
        buf_size = buf_capacity;
    else if (buf_size > buf_capacity) {
        printf("Requested buffer size=%d exceeds reported capacity=%d\n",
               buf_size, buf_capacity);
        if (rawp) free(rawp);
        return SG_LIB_CAT_MALFORMED;
    }
    if (rawp) {
        free(rawp);
        rawp = NULL;
    }

    if (! op->do_dio) {
        k = buf_size;
        if (op->do_mmap && (0 != (k % psz)))
            k = ((k / psz) + 1) * psz;  /* round up to page size */
        res = ioctl(sg_fd, SG_SET_RESERVED_SIZE, &k);
        if (res < 0)
            perror("SG_SET_RESERVED_SIZE error");
    }

    if (op->do_mmap) {
        rbBuff = (uint8_t *)mmap(NULL, buf_size, PROT_READ, MAP_SHARED,
                                       sg_fd, 0);
        if (MAP_FAILED == rbBuff) {
            if (ENOMEM == errno) {
                pr2serr("mmap() out of memory, try a smaller buffer size "
                        "than %d bytes\n", buf_size);
                if (op->opt_new)
                    pr2serr("    [with '--buffer=EACH' where EACH is in "
                            "bytes]\n");
                else
                    pr2serr("    [with '-b=EACH' where EACH is in KiB]\n");
            } else
                perror("error using mmap()");
            return SG_LIB_CAT_OTHER;
        }
    }
    else { /* non mmap-ed IO */
        rawp = (uint8_t *)malloc(buf_size + (op->do_dio ? psz : 0));
        if (NULL == rawp) {
            printf("out of memory (data)\n");
            return SG_LIB_CAT_OTHER;
        }
        /* perhaps use posix_memalign() instead */
        if (op->do_dio)    /* align to page boundary */
            rbBuff= (uint8_t *)(((sg_uintptr_t)rawp + psz - 1) &
                                      (~(psz - 1)));
        else
            rbBuff = (uint8_t *)rawp;
    }

    num = total_size / buf_size;
    if (op->do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }
    /* main data reading loop */
    for (k = 0; k < num; ++k) {
        memset(rb_cdb, 0, RB_CMD_LEN);
        rb_cdb[0] = RB_OPCODE;
        rb_cdb[1] = op->do_echo ? RB_MODE_ECHO_DATA : RB_MODE_DATA;
        sg_put_unaligned_be24((uint32_t)buf_size, rb_cdb + 6);
#ifdef DEBUG
        memset(rbBuff, 0, buf_size);
#endif

        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rb_cdb);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = buf_size;
        if (! op->do_mmap)
            io_hdr.dxferp = rbBuff;
        io_hdr.cmdp = rb_cdb;
        io_hdr.sbp = sense_buffer;
        io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
        io_hdr.pack_id = k;
        if (op->do_mmap)
            io_hdr.flags |= SG_FLAG_MMAP_IO;
        else if (op->do_dio)
            io_hdr.flags |= SG_FLAG_DIRECT_IO;
        else if (op->do_quick)
            io_hdr.flags |= SG_FLAG_NO_DXFER;
        if (op->verbose > 1) {
            char b[128];

            pr2serr("    Read buffer (%sdata) cdb: %s\n",
                    (op->do_echo ? "echo " : ""),
                    sg_get_command_str(rb_cdb, RB_CMD_LEN, false,
                                       sizeof(b), b));
        }
        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
            if (ENOMEM == errno) {
                pr2serr("SG_IO data: out of memory, try a smaller buffer "
                        "size than %d bytes\n", buf_size);
                if (op->opt_new)
                    pr2serr("    [with '--buffer=EACH' where EACH is in "
                            "bytes]\n");
                else
                    pr2serr("    [with '-b=EACH' where EACH is in KiB]\n");
            } else
                perror("SG_IO READ BUFFER data error");
            if (rawp) free(rawp);
            return SG_LIB_CAT_OTHER;
        }

        if (op->verbose > 2)
            pr2serr("      duration=%u ms\n", io_hdr.duration);
        /* now for the error processing */
        res = sg_err_category3(&io_hdr);
        switch (res) {
        case SG_LIB_CAT_CLEAN:
            break;
        case SG_LIB_CAT_RECOVERED:
            sg_chk_n_print3("READ BUFFER data, continuing", &io_hdr,
                            op->verbose > 1);
            break;
        default: /* won't bother decoding other categories */
            sg_chk_n_print3("READ BUFFER data error", &io_hdr,
                            op->verbose > 1);
            if (rawp) free(rawp);
            return (res >= 0) ? res : SG_LIB_CAT_OTHER;
        }
        if (op->do_dio &&
            ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
            dio_incomplete = true;  /* flag that dio not done (completely) */

#ifdef DEBUG
        if (clear) {
            for (j = 0; j < buf_size; ++j) {
                if (rbBuff[j] != 0) {
                    clear = false;
                    break;
                }
            }
        }
#endif
    }
    if (op->do_time && (start_tm.tv_sec || start_tm.tv_usec)) {
        struct timeval res_tm;
        double a, b;

        gettimeofday(&end_tm, NULL);
        res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
        if (res_tm.tv_usec < 0) {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        a = res_tm.tv_sec;
        a += (0.000001 * res_tm.tv_usec);
        b = (double)buf_size * num;
        printf("time to read data from buffer was %d.%06d secs",
               (int)res_tm.tv_sec, (int)res_tm.tv_usec);
        if (a > 0.00001) {
            if (b > 511)
                printf(", %.2f MB/sec", b / (a * 1000000.0));
            printf(", %.2f IOPS", num / a);
        }
        printf("\n");
    }
    if (dio_incomplete)
        printf(">> direct IO requested but not done\n");
    printf("Read %" PRId64 " MiB (actual: %" PRId64 " bytes), buffer "
           "size=%d KiB (%d bytes)\n", (total_size / (1024 * 1024)),
           (int64_t)num * buf_size, buf_size / 1024, buf_size);

    if (rawp) free(rawp);
    res = close(sg_fd);
    if (res < 0) {
        err = errno;
        perror("close error");
        return sg_convert_errno(err);
    }
#ifdef DEBUG
    if (clear)
        printf("read buffer always zero\n");
    else
        printf("read buffer non-zero\n");
#endif
    return res;
}
