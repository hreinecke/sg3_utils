/*
 * Copyright (C) 2003-2021 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
 * device driver.
 * This C++ program will read a certain number of blocks of a given block
 * size from a given sg device node using struct sg_iovec and write what is
 * retrieved out to a normal file. The purpose is to test the sg_iovec
 * mechanism within the sg_io_hdr and sg_io_v4 structures.
 *
 * struct sg_iovec and struct iovec [in include/uapi/uio.h] are basically
 * the same thing: a pointer followed by a length (of type size_t). If
 * applied to a disk then the pointer will hold a LBA and 'length' will
 * be a number of logical blocks (which usually cannot exceed 2**32-1 .
 *
 */

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>
#include <time.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/bsg.h>

#ifndef HAVE_LINUX_SG_V4_HDR

/* Kernel uapi header contain __user decorations on user space pointers
 * to indicate they are unsafe in the kernel space. However glibc takes
 * all those __user decorations out from headers in /usr/include/linux .
 * So to stop compile errors when directly importing include/uapi/scsi/sg.h
 * undef __user before doing that include. */
#define __user

/* Want to block the original sg.h header from also being included. That
 * causes lots of multiple definition errors. This will only work if this
 * header is included _before_ the original sg.h header.  */
#define _SCSI_GENERIC_H         /* original kernel header guard */
#define _SCSI_SG_H              /* glibc header guard */

#include "uapi_sg.h"    /* local copy of include/uapi/scsi/sg.h */

#else
#define __user
#endif  /* end of: ifndef HAVE_LINUX_SG_V4_HDR */

#include "sg_lib.h"
#include "sg_io_linux.h"
#include "sg_unaligned.h"

// C++ local header
#include "sg_scat_gath.h"

static const char * version_str = "1.08 20210214";

#define ME "sg_iovec_tst: "

#define IOVEC_ELEMS 1024  /* match current UIO_MAXIOV in <linux/uio.h> */

#define DEF_BLK_SZ 512
#define SENSE_BUFF_LEN 32
#define DEF_TIMEOUT 40000       /* 40,000 milliseconds */

static struct sg_iovec iovec[IOVEC_ELEMS];

static int verbose;

static struct option long_options[] = {
        {"async", no_argument, 0, 'a'},
        {"bs", required_argument, 0, 'b'},
        {"elem_size", required_argument, 0, 'e'},
        {"elem-size", required_argument, 0, 'e'},
        {"elemsz", required_argument, 0, 'e'},
        {"fill", required_argument, 0, 'f'},
        {"from_skip", no_argument, 0, 'F'},
        {"from-skip", no_argument, 0, 'F'},
        {"help", no_argument, 0, 'h'},
        {"num", required_argument, 0, 'n'},
        {"num_blks", required_argument, 0, 'n'},
        {"num-blks", required_argument, 0, 'n'},
        {"sgl", required_argument, 0, 'S'},
        {"sgv4", no_argument, 0, '4'},
        {"skip", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage(void)
{
    printf("Usage: sg_iovec_tst [--async] [--bs=BS] [--elem_sz=ES] "
           "[--fill=F_ELEMS]\n"
           "                    [from_skip] [--help] --num=NUM [--sgl=SFN] "
           "[--sgv4]\n"
           "                    [--skip=SKIP] [--verbose] [--version] "
           "SG_DEV OUT_F\n");
    printf("where:\n"
           "    --async|-a       async sg usage (def: use ioctl(SGIO) )\n");
    printf("    --bs=BS|-b BS    logical block size of SG_DEV (def: 512 "
           "bytes)\n");
    printf("    --elem_sz=ES|-e ES    iovec element size (def: BS bytes)\n");
    printf("    --fill=F_ELEMS|-f F_ELEMS    append F_ELEMS*ES zero bytes "
           "onto OUT_F\n"
           "                                 after each iovec element (def: "
           "0)\n");
    printf("    --from_skip|-F    sgl output starts from SKIP (def: 0)\n");
    printf("    --help|-h        this usage message\n");
    printf("    --num=NUM|-n NUM    number of blocks to read from SG_DEV\n");
    printf("    --sgl=SFN|-S SFN    Sgl FileName (SFN) that is written to, "
	   "with\n"
           "                        addresses and lengths having ES as "
	   "their unit\n");
    printf("    --sgv4|-4        use the sg v4 interface (def: v3 "
           "interface)\n");
    printf("    --skip=SKIP|-s SKIP    SKIP blocks before reading S_DEV "
           "(def: 0)\n");
    printf("    --verbose|-v     increase verbosity\n");
    printf("    --version|-V     print version and exit\n\n");
    printf("Reads from SG_DEV and writes that data to OUT_F in binary. Uses "
           "iovec\n(a scatter gather list) in linear mode (i.e. it cuts up "
           "a contiguous\nbuffer). Example:\n"
           "     sg_iovec_tst -n 8k -e 4k /dev/sg3 out.bin\n");
}

/* Returns 0 if everything ok */
static int
sg_read(int sg_fd, uint8_t * buff, int num_blocks, int from_block, int bs,
        int elem_size, int async)
{
    uint8_t rdCmd[10] = {READ_10, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    struct pollfd a_poll;
    int dxfer_len = bs * num_blocks;
    int k, pos, rem, res;
    char b[128];

    sg_put_unaligned_be32((uint32_t)from_block, rdCmd + 2);
    sg_put_unaligned_be16((uint16_t)num_blocks, rdCmd + 7);

    for (k = 0, pos = 0, rem = dxfer_len; k < IOVEC_ELEMS; ++k) {
        iovec[k].iov_base = buff + pos;
        iovec[k].iov_len = (rem > elem_size) ? elem_size : rem;
        if (rem <= elem_size)
            break;
        pos += elem_size;
        rem -= elem_size;
    }
    if (k >= IOVEC_ELEMS) {
        fprintf(stderr, "Can't fit dxfer_len=%d bytes in %d iovec elements "
                "(would need %d)\n", dxfer_len, IOVEC_ELEMS,
                dxfer_len / elem_size);
        fprintf(stderr, "Try expanding elem_size which is currently %d "
                "bytes\n", elem_size);
        return -1;
    }
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rdCmd);
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = dxfer_len;
    io_hdr.iovec_count = k + 1;
    io_hdr.dxferp = iovec;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = from_block;
    if (verbose)
        fprintf(stderr, "cdb: %s\n", sg_get_command_str(rdCmd, 10, true,
                sizeof(b), b));

    if (async) {
        res = write(sg_fd, &io_hdr, sizeof(io_hdr));
        if (res < 0) {
            perror("write(<sg_device>), error");
            return -1;
        } else if (res < (int)sizeof(io_hdr)) {
            fprintf(stderr, "write(<sg_device>) returned %d, expected %d\n",
                    res, (int)sizeof(io_hdr));
            return -1;
        }
        a_poll.fd = sg_fd;
        a_poll.events = POLLIN;
        a_poll.revents = 0;
        res = poll(&a_poll, 1, 2000 /* millisecs */ );
        if (res < 0) {
            perror("poll error on <sg_device>");
            return -1;
        }
        if (0 == (POLLIN & a_poll.revents)) {
            fprintf(stderr, "strange, poll() completed without data to "
                    "read\n");
            return -1;
        }
        res = read(sg_fd, &io_hdr, sizeof(io_hdr));
        if (res < 0) {
            perror("read(<sg_device>), error");
            return -1;
        } else if (res < (int)sizeof(io_hdr)) {
            fprintf(stderr, "read(<sg_device>) returned %d, expected %d\n",
                    res, (int)sizeof(io_hdr));
            return -1;
        }
    } else if (ioctl(sg_fd, SG_IO, &io_hdr)) {
        perror("reading (SG_IO) on sg device, error");
        return -1;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        fprintf(stderr, "Recovered error while reading block=%d, num=%d\n",
               from_block, num_blocks);
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:
        fprintf(stderr, "Unit attention\n");
        return -1;
    default:
        sg_chk_n_print3("reading", &io_hdr, 1);
        return -1;
    }
    return 0;
}

/* Returns 0 if everything ok */
static int
sg_read_v4(int sg_fd, uint8_t * buff, int num_blocks, int from_block, int bs,
           int elem_size, int async)
{
    uint8_t rdCmd[10] = {READ_10, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t senseBuff[SENSE_BUFF_LEN];
    struct sg_io_v4 io_hdr;
    struct pollfd a_poll;
    int dxfer_len = bs * num_blocks;
    int k, pos, rem, res;
    char b[128];

    sg_put_unaligned_be32((uint32_t)from_block, rdCmd + 2);
    sg_put_unaligned_be16((uint16_t)num_blocks, rdCmd + 7);

    for (k = 0, pos = 0, rem = dxfer_len; k < IOVEC_ELEMS; ++k) {
        iovec[k].iov_base = buff + pos;
        iovec[k].iov_len = (rem > elem_size) ? elem_size : rem;
        if (rem <= elem_size)
            break;
        pos += elem_size;
        rem -= elem_size;
    }
    if (k >= IOVEC_ELEMS) {
        fprintf(stderr, "Can't fit dxfer_len=%d bytes in %d iovec elements "
                "(would need %d)\n", dxfer_len, IOVEC_ELEMS,
                dxfer_len / elem_size);
        fprintf(stderr, "Try expanding elem_size which is currently %d "
                "bytes\n", elem_size);
        return -1;
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_v4));
    io_hdr.guard = 'Q';
    io_hdr.request_len = sizeof(rdCmd);
    io_hdr.request = (uint64_t)(uintptr_t)rdCmd;
    io_hdr.din_xfer_len = dxfer_len;
    io_hdr.din_xferp = (uint64_t)(uintptr_t)iovec;
    io_hdr.din_iovec_count = k + 1;
    io_hdr.max_response_len = SG_DXFER_FROM_DEV;
    io_hdr.response = (uint64_t)(uintptr_t)senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.request_extra = from_block;   /* pack_id */
    if (verbose)
        fprintf(stderr, "cdb: %s\n", sg_get_command_str(rdCmd, 10, true,
                sizeof(b), b));

    if (async) {
        res = ioctl(sg_fd, SG_IOSUBMIT, &io_hdr);
        if (res < 0) {
            perror("ioctl(SG_IOSUBMIT <sg_device>), error");
            return -1;
        }
        a_poll.fd = sg_fd;
        a_poll.events = POLLIN;
        a_poll.revents = 0;
        res = poll(&a_poll, 1, 2000 /* millisecs */ );
        if (res < 0) {
            perror("poll error on <sg_device>");
            return -1;
        }
        if (0 == (POLLIN & a_poll.revents)) {
            fprintf(stderr, "strange, poll() completed without data to "
                    "read\n");
            return -1;
        }
        res = ioctl(sg_fd, SG_IORECEIVE, &io_hdr);
        if (res < 0) {
            perror("ioctl(SG_IORECEIVE <sg_device>), error");
            return -1;
        }
    } else if (ioctl(sg_fd, SG_IO, &io_hdr)) {
        perror("ioctl(SG_IO) on sg device, error");
        return -1;
    }

    res = sg_err_category_new(io_hdr.device_status, io_hdr.transport_status,
                              io_hdr.driver_status,
                              (const uint8_t *)(unsigned long)io_hdr.response,
                              io_hdr.response_len);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        fprintf(stderr, "Recovered error while reading block=%d, num=%d\n",
               from_block, num_blocks);
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:
        fprintf(stderr, "Unit attention\n");
        return -1;
    default:
        sg_linux_sense_print("reading", io_hdr.device_status,
                         io_hdr.transport_status, io_hdr.driver_status,
                         senseBuff, io_hdr.response_len, true);
        return -1;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool do_sgv4 = false;
    bool do_async = false;
    bool do_help = false;
    bool from_skip = false;
    bool blk_size_given = false;
    bool elem_size_given = false;
    int sg_fd, fd, c, res, res2, err, dxfer_len;
    unsigned int k;
    int blk_size = DEF_BLK_SZ;
    int elem_size = blk_size;
    int num_blks = 0;
    int f_elems = 0;
    int64_t start_blk = 0;
    char * sg_dev_name = 0;
    char * out_file_name = 0;
    char * sgl_fn = 0;
    uint8_t * buffp;
    uint8_t * fillp = NULL;
    FILE * fp = NULL;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "4ab:e:f:Fhn:s:S:vV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case '4':
            do_sgv4 = true;
            break;
        case 'a':
            do_async = true;
            break;
        case 'b':
            blk_size = sg_get_num(optarg);
            if (blk_size < 1) {
                printf("Couldn't decode positive number after '--bs=' "
                       "option\n");
                sg_dev_name = 0;
            } else
                blk_size_given = true;
            break;
        case 'e':
            elem_size = sg_get_num(optarg);
            if (elem_size < 1) {
                printf("Couldn't decode positive number after '--elem_size=' "
                       "option\n");
                sg_dev_name = 0;
            } else
                elem_size_given = true;
            break;
        case 'f':
            f_elems = sg_get_num(optarg);
            if (f_elems < 0) {
                printf("Couldn't decode number after '--fill=' option\n");
                sg_dev_name = 0;
            }
            break;
        case 'F':
            from_skip = true;
            break;
        case 'h':
            do_help = true;
            break;
        case 'n':
            num_blks = sg_get_num(optarg);
            if (num_blks < 1) {
                printf("Couldn't decode positive number after '--num=' "
                       "option\n");
                sg_dev_name = 0;
            }
            break;
        case 's':
            start_blk = sg_get_llnum(optarg);
            if ((start_blk < 0) || (start_blk > INT_MAX)) {
                printf("Couldn't decode number after '--skip=' option\n");
                sg_dev_name = 0;
            }
            break;
        case 'S':
            if (sgl_fn) {
                printf("Looks like --sgl=SFN has been given twice\n");
                sg_dev_name = 0;
            } else
                sgl_fn = optarg;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            printf("Version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == sg_dev_name) {
            sg_dev_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            if (sg_dev_name) {
                out_file_name = argv[optind];
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
    }
    if (do_help) {
        usage();
        return 0;
    }
    if (NULL == sg_dev_name) {
        printf(">>> need sg node name (e.g. /dev/sg3)\n\n");
        usage();
        return 1;
    }
    if (NULL == out_file_name) {
        printf(">>> need out filename (to place what is fetched by READ\n\n");
        usage();
        return 1;
    }
    if (0 == num_blks) {
        printf(">>> need number of blocks to READ\n\n");
        usage();
        return 1;
    }

    if ((! elem_size_given) && blk_size_given)
        elem_size = blk_size;

    if (do_async)
        sg_fd = open(sg_dev_name, O_RDWR);
    else
        sg_fd = open(sg_dev_name, O_RDONLY);
    if (sg_fd < 0) {
        perror(ME "sg device node open error");
        return 1;
    }
    /* Don't worry, being very careful not to write to a none-sg file ... */
    res = ioctl(sg_fd, SG_GET_VERSION_NUM, &k);
    if ((res < 0) || (k < 30000)) {
        printf(ME "not a sg device, or driver prior to 3.x\n");
        return 1;
    }
    fd = open(out_file_name, O_WRONLY | O_CREAT, 0666);
    if (fd < 0) {
        perror(ME "output file open error");
        return 1;
    }
    if (f_elems > 0) {
        fillp = (uint8_t *)calloc(f_elems, elem_size);
        if (NULL == fillp) {
            fprintf(stderr, "fill calloc for %d bytes failed\n",
                    f_elems * elem_size);
            goto fini;
        }
    }
    if (sgl_fn) {
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        char s[128];

        fp = fopen(sgl_fn, "w");
        if (NULL == fp) {
            err = errno;
            fprintf(stderr, "Unable to open %s, error: %s\n", sgl_fn,
                    strerror(err));
            res = sg_convert_errno(err);
            goto fini;
        }
        strftime(s, sizeof(s), "%c", tm);
        fprintf(fp, "# Scatter gather list generated by sg_iovec_tst  "
                "%s\n#\n", s);
    }

    dxfer_len = num_blks * blk_size;
    buffp = (uint8_t *)calloc(num_blks, blk_size);
    if (buffp) {
        int dx_len;
        int64_t curr_blk = from_skip ? start_blk : 0;

        if (do_sgv4) {
            if (sg_read(sg_fd, buffp, num_blks, (int)start_blk, blk_size,
                        elem_size, do_async))
                goto free_buff;
        } else {
            if (sg_read_v4(sg_fd, buffp, num_blks, (int)start_blk, blk_size,
                           elem_size, do_async))
                goto free_buff;
        }
        if (f_elems > 0) {
            int fill_len = f_elems * elem_size;

            for (dx_len = 0; dx_len < dxfer_len; dx_len += elem_size) {
                if (write(fd, buffp + dx_len, elem_size) < 0) {
                    perror(ME "partial dxfer output write failed");
                    break;
                }
                if (sgl_fn) {
                    fprintf(fp, "%" PRId64 ",1\n", curr_blk);
                    curr_blk += f_elems + 1;
                }
                if (write(fd, fillp, fill_len) < 0) {
                    perror(ME "partial fill output write failed");
                    break;
                }
            }
        } else if (write(fd, buffp, dxfer_len) < 0)
            perror(ME "full output write failed");
        else if (sgl_fn) {
            for (dx_len = 0; dx_len < dxfer_len; dx_len += elem_size)
                fprintf(fp, "%" PRId64 ",1\n", curr_blk++);
        }
free_buff:
        free(buffp);
    } else
        fprintf(stderr, "user space calloc for %d bytes failed\n",
                dxfer_len);
    res = close(fd);
    if (res < 0) {
        perror(ME "output file close error");
        close(sg_fd);
        return 1;
    }
fini:
    res2 = close(sg_fd);
    if (res2 < 0) {
        err = errno;
        perror(ME "sg device close error");
        if (0 == res)
            res = sg_convert_errno(err);
    }
    if (fp)
        fclose(fp);
    return res;
}
