#define _XOPEN_SOURCE 500
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 1999-2011 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * This program uses the SCSI command READ BUFFER on the given
 * device, first to find out how big it is and then to read that
 * buffer (data mode, buffer id 0).
 */


#define RB_MODE_DESC 3
#define RB_MODE_DATA 2
#define RB_DESC_LEN 4
#define RB_DEF_SIZE (200*1024*1024)
#define RB_OPCODE 0x3C
#define RB_CMD_LEN 10

/* #define SG_DEBUG */

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif


static char * version_str = "4.89 20110211";

static struct option long_options[] = {
        {"buffer", 1, 0, 'b'},
        {"dio", 0, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"mmap", 0, 0, 'm'},
        {"new", 0, 0, 'N'},
        {"old", 0, 0, 'O'},
        {"quick", 0, 0, 'q'},
        {"size", 1, 0, 's'},
        {"time", 0, 0, 't'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_buffer;
    int do_dio;
    int do_help;
    int do_mmap;
    int do_quick;
    int64_t do_size;
    int do_time;
    int do_verbose;
    int do_version;
    const char * device_name;
    int opt_new;
};


static void
usage()
{
    fprintf(stderr, "Usage: sg_rbuf [--buffer=EACH] [--dio] [--help] "
            "[--mmap] [--quick]\n"
            "               [--size=OVERALL] [--time] [--verbose] "
            "[--version] DEVICE\n");
    fprintf(stderr, "  where:\n"
            "    --buffer=EACH|-b EACH    buffer size to use (in bytes)\n"
            "    --dio|-d        requests dio ('-q' overrides it)\n"
            "    --help|-h       print usage message then exit\n"
            "    --mmap|-m       requests mmap-ed IO (overrides -q, -d)\n"
            "    --quick|-q      quick, don't xfer to user space\n");
    fprintf(stderr,
            "    --size=OVERALL|-s OVERALL    total size to read (in bytes)\n"
            "                    default: 200 MiB\n"
            "    --time|-t       time the data transfer\n"
            "    --verbose|-v    increase verbosity (more debug)\n"
            "    --version|-V    print version string then exit\n\n"
            "Use SCSI READ BUFFER command (data mode, buffer id 0) "
            "repeatedly\n");
}

static void
usage_old()
{
    printf("Usage: sg_rbuf [-b=EACH_KIB] [-d] [-m] [-q] [-s=OVERALL_MIB] "
           "[-t] [-v] [-V]\n               DEVICE\n");
    printf("  where:\n");
    printf("    -b=EACH_KIB    num is buffer size to use (in KiB)\n");
    printf("    -d       requests dio ('-q' overrides it)\n");
    printf("    -m       requests mmap-ed IO (overrides -q, -d)\n");
    printf("    -q       quick, don't xfer to user space\n");
    printf("    -s=OVERALL_MIB    num is total size to read (in MiB) "
           "(default: 200 MiB)\n");
    printf("             maximum total size is 4000 MiB\n");
    printf("    -t       time the data transfer\n");
    printf("    -v       increase verbosity (more debug)\n");
    printf("    -V       print version string then exit\n\n");
    printf("Use SCSI READ BUFFER command (data mode, buffer id 0) "
           "repeatedly\n");
}

static void
usage_for(const struct opts_t * optsp)
{
    if (optsp->opt_new)
        usage();
    else
        usage_old();
}

static int
process_cl_new(struct opts_t * optsp, int argc, char * argv[])
{
    int c, n;
    int64_t nn;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:dhmNOqs:tvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            n = sg_get_num(optarg);
            if (n < 0) {
                fprintf(stderr, "bad argument to '--buffer'\n");
                usage_for(optsp);
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->do_buffer = n;
            break;
        case 'd':
            ++optsp->do_dio;
            break;
        case 'h':
        case '?':
            ++optsp->do_help;
            break;
        case 'm':
            ++optsp->do_mmap;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            optsp->opt_new = 0;
            return 0;
        case 'q':
            ++optsp->do_quick;
            break;
        case 's':
           nn = sg_get_llnum(optarg);
           if (nn < 0) {
                fprintf(stderr, "bad argument to '--size'\n");
                usage_for(optsp);
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->do_size = nn;
            break;
        case 't':
            ++optsp->do_time;
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
            usage_for(optsp);
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
            usage_for(optsp);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int
process_cl_old(struct opts_t * optsp, int argc, char * argv[])
{
    int k, jmp_out, plen, num;
    int64_t nn;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'd':
                    ++optsp->do_dio;
                    break;
                case 'h':
                case '?':
                    ++optsp->do_help;
                    break;
                case 'm':
                    ++optsp->do_mmap;
                    break;
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'q':
                    ++optsp->do_quick;
                    break;
                case 't':
                    ++optsp->do_time;
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
            if (0 == strncmp("b=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &optsp->do_buffer);
                if ((1 != num) || (optsp->do_buffer <= 0)) {
                    printf("Couldn't decode number after 'b=' option\n");
                    usage_for(optsp);
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->do_buffer *= 1024;
            }
            else if (0 == strncmp("s=", cp, 2)) {
                nn = sg_get_llnum(optarg);
                if (nn < 0) {
                    printf("Couldn't decode number after 's=' option\n");
                    usage_for(optsp);
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->do_size = nn;
                optsp->do_size *= 1024 * 1024;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage_for(optsp);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == optsp->device_name)
            optsp->device_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", optsp->device_name, cp);
            usage_for(optsp);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int
process_cl(struct opts_t * optsp, int argc, char * argv[])
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


int
main(int argc, char * argv[])
{
    int sg_fd, res, j;
    unsigned int k, num;
    unsigned char rbCmdBlk [RB_CMD_LEN];
    unsigned char * rbBuff = NULL;
    void * rawp = NULL;
    unsigned char sense_buffer[32];
    int buf_capacity = 0;
    int buf_size = 0;
    int64_t total_size = RB_DEF_SIZE;
    size_t psz = getpagesize();
    int dio_incomplete = 0;
    struct sg_io_hdr io_hdr;
    struct timeval start_tm, end_tm;
#ifdef SG_DEBUG
    int clear = 1;
#endif
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

    if (opts.do_buffer > 0)
        buf_size = opts.do_buffer;
    if (opts.do_size > 0)
        total_size = opts.do_size;

    sg_fd = open(opts.device_name, O_RDONLY | O_NONBLOCK);
    if (sg_fd < 0) {
        perror("device open error");
        return SG_LIB_FILE_ERROR;
    }
    /* Don't worry, being very careful not to write to a none-sg file ... */
    if (opts.do_mmap) {
        opts.do_dio = 0;
        opts.do_quick = 0;
    }
    if (NULL == (rawp = malloc(512))) {
        printf("out of memory (query)\n");
        return SG_LIB_CAT_OTHER;
    }
    rbBuff = (unsigned char *)rawp;

    memset(rbCmdBlk, 0, RB_CMD_LEN);
    rbCmdBlk[0] = RB_OPCODE;
    rbCmdBlk[1] = RB_MODE_DESC; /* data mode, buffer id 0 */
    rbCmdBlk[8] = RB_DESC_LEN;
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rbCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = RB_DESC_LEN;
    io_hdr.dxferp = rbBuff;
    io_hdr.cmdp = rbCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */
    if (opts.do_verbose) {
        fprintf(stderr, "    Read buffer cdb: ");
        for (k = 0; k < RB_CMD_LEN; ++k)
            fprintf(stderr, "%02x ", rbCmdBlk[k]);
        fprintf(stderr, "\n");
    }

    /* do normal IO to find RB size (not dio or mmap-ed at this stage) */
    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO READ BUFFER descriptor error");
        if (rawp) free(rawp);
        return SG_LIB_CAT_OTHER;
    }

    if (opts.do_verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    /* now for the error processing */
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("READ BUFFER descriptor, continuing", &io_hdr,
                        opts.do_verbose > 1);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("READ BUFFER descriptor error", &io_hdr,
                        opts.do_verbose > 1);
        if (rawp) free(rawp);
        return (res >= 0) ? res : SG_LIB_CAT_OTHER;
    }

    buf_capacity = ((rbBuff[1] << 16) | (rbBuff[2] << 8) | rbBuff[3]);
    printf("READ BUFFER reports: buffer capacity=%d, offset boundary=%d\n",
           buf_capacity, (int)rbBuff[0]);

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

    if (! opts.do_dio) {
        k = buf_size;
        if (opts.do_mmap && (0 != (k % psz)))
            k = ((k / psz) + 1) * psz;  /* round up to page size */
        res = ioctl(sg_fd, SG_SET_RESERVED_SIZE, &k);
        if (res < 0)
            perror("SG_SET_RESERVED_SIZE error");
    }

    if (opts.do_mmap) {
        rbBuff = (unsigned char *)mmap(NULL, buf_size, PROT_READ, MAP_SHARED,
                                       sg_fd, 0);
        if (MAP_FAILED == rbBuff) {
            if (ENOMEM == errno) {
                fprintf(stderr, "mmap() out of memory, try a smaller "
                       "buffer size than %d bytes\n", buf_size);
                if (opts.opt_new)
                    fprintf(stderr, "    [with '--buffer=EACH' where EACH "
                            "is in bytes]\n");
                else
                    fprintf(stderr, "    [with '-b=EACH' where EACH is in "
                            "KiB]\n");
            } else
                perror("error using mmap()");
            return SG_LIB_CAT_OTHER;
        }
    }
    else { /* non mmap-ed IO */
        rawp = (unsigned char *)malloc(buf_size + (opts.do_dio ? psz : 0));
        if (NULL == rawp) {
            printf("out of memory (data)\n");
            return SG_LIB_CAT_OTHER;
        }
        if (opts.do_dio)    /* align to page boundary */
            rbBuff= (unsigned char *)(((unsigned long)rawp + psz - 1) &
                                      (~(psz - 1)));
        else
            rbBuff = (unsigned char *)rawp;
    }

    num = total_size / buf_size;
    if (opts.do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }
    /* main data reading loop */
    for (k = 0; k < num; ++k) {
        memset(rbCmdBlk, 0, RB_CMD_LEN);
        rbCmdBlk[0] = RB_OPCODE;
        rbCmdBlk[1] = RB_MODE_DATA;
        rbCmdBlk[6] = 0xff & (buf_size >> 16);
        rbCmdBlk[7] = 0xff & (buf_size >> 8);
        rbCmdBlk[8] = 0xff & buf_size;
#ifdef SG_DEBUG
        memset(rbBuff, 0, buf_size);
#endif

        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = buf_size;
        if (! opts.do_mmap)
            io_hdr.dxferp = rbBuff;
        io_hdr.cmdp = rbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
        io_hdr.pack_id = k;
        if (opts.do_mmap)
            io_hdr.flags |= SG_FLAG_MMAP_IO;
        else if (opts.do_dio)
            io_hdr.flags |= SG_FLAG_DIRECT_IO;
        else if (opts.do_quick)
            io_hdr.flags |= SG_FLAG_NO_DXFER;
        if (opts.do_verbose > 1) {
            fprintf(stderr, "    Read buffer cdb: ");
            for (j = 0; j < RB_CMD_LEN; ++j)
                fprintf(stderr, "%02x ", rbCmdBlk[j]);
            fprintf(stderr, "\n");
        }

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
            if (ENOMEM == errno) {
                fprintf(stderr, "SG_IO data: out of memory, try a smaller "
                       "buffer size than %d bytes\n", buf_size);
                if (opts.opt_new)
                    fprintf(stderr, "    [with '--buffer=EACH' where EACH "
                            "is in bytes]\n");
                else
                    fprintf(stderr, "    [with '-b=EACH' where EACH is in "
                            "KiB]\n");
            } else
                perror("SG_IO READ BUFFER data error");
            if (rawp) free(rawp);
            return SG_LIB_CAT_OTHER;
        }

        if (opts.do_verbose > 2)
            fprintf(stderr, "      duration=%u ms\n",
                    io_hdr.duration);
        /* now for the error processing */
        res = sg_err_category3(&io_hdr);
        switch (res) {
        case SG_LIB_CAT_CLEAN:
            break;
        case SG_LIB_CAT_RECOVERED:
            sg_chk_n_print3("READ BUFFER data, continuing", &io_hdr,
                            opts.do_verbose > 1);
            break;
        default: /* won't bother decoding other categories */
            sg_chk_n_print3("READ BUFFER data error", &io_hdr,
                            opts.do_verbose > 1);
            if (rawp) free(rawp);
            return (res >= 0) ? res : SG_LIB_CAT_OTHER;
        }
        if (opts.do_dio &&
            ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
            dio_incomplete = 1;    /* flag that dio not done (completely) */

#ifdef SG_DEBUG
        if (clear) {
            for (j = 0; j < buf_size; ++j) {
                if (rbBuff[j] != 0) {
                    clear = 0;
                    break;
                }
            }
        }
#endif
    }
    if ((opts.do_time) && (start_tm.tv_sec || start_tm.tv_usec)) {
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
        if ((a > 0.00001) && (b > 511))
            printf(", %.2f MB/sec\n", b / (a * 1000000.0));
        else
            printf("\n");
    }
    if (dio_incomplete)
        printf(">> direct IO requested but not done\n");
    printf("Read %"PRId64" MiB (actual: %"PRId64" bytes), buffer size=%d KiB "
           "(%d bytes)\n", (total_size / (1024 * 1024)),
           (int64_t)num * buf_size, buf_size / 1024, buf_size);

    if (rawp) free(rawp);
    res = close(sg_fd);
    if (res < 0) {
        perror("close error");
        return SG_LIB_FILE_ERROR;
    }
#ifdef SG_DEBUG
    if (clear)
        printf("read buffer always zero\n");
    else
        printf("read buffer non-zero\n");
#endif
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}
