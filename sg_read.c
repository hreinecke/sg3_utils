#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/major.h> 
#include "sg_include.h"
#include "sg_lib.h"
#include "llseek.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2001 - 2005 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program reads data from the given SCSI device (typically a disk
   or cdrom) and discards that data. Its primary goal is to time
   multiple reads all from the same logical address. Its interface
   is a subset of another member of this package: sg_dd which is a 
   "dd" variant. The input file can be a scsi generic device, a block device,
   a raw device or a seekable file. Streams such as stdin are not acceptable.
   The block size ('bs') is assumed to be 512 if not given. 

   This version should compile with Linux sg drivers with version numbers
   >= 30000 . For mmap-ed IO the sg version number >= 30122 .

*/

static const char * version_str = "1.06 20051025";

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define ME "sg_read: "

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 40000       /* 40,000 millisecs == 40 seconds */

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikey value */
#endif 

#define FT_OTHER 0              /* filetype other than sg or raw device */
#define FT_SG 1                 /* filetype is sg char device */
#define FT_RAW 2                /* filetype is raw char device */
#define FT_BLOCK 4              /* filetype is block device */

static int sum_of_resids = 0;

static int dd_count = -1;
static int in_full = 0;
static int in_partial = 0;

static int pack_id_count = 0;
static int verbose = 0;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

static void install_handler (int sig_num, void (*sig_handler) (int sig))
{
    struct sigaction sigact;

    sigaction (sig_num, NULL, &sigact);
    if (sigact.sa_handler != SIG_IGN)
    {
        sigact.sa_handler = sig_handler;
        sigemptyset (&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction (sig_num, &sigact, NULL);
    }
}

void print_stats(int iters)
{
    if (0 != dd_count)
        fprintf(stderr, "  remaining block count=%d\n", dd_count);
    fprintf(stderr, "%d+%d records in", in_full - in_partial, in_partial);
    if (iters > 0)
        fprintf(stderr, ", SCSI commands issued: %d\n", iters);
    else
        fprintf(stderr, "\n");
}

static void interrupt_handler(int sig)
{
    struct sigaction sigact;

    sigact.sa_handler = SIG_DFL;
    sigemptyset (&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction (sig, &sigact, NULL);
    fprintf(stderr, "Interrupted by signal,");
    print_stats(0);
    kill (getpid (), sig);
}

static void siginfo_handler(int sig)
{
    sig = sig;  /* dummy to stop -W warning messages */
    fprintf(stderr, "Progress report, continuing ...\n");
    print_stats(0);
}

int dd_filetype(const char * filename)
{
    struct stat st;

    if (stat(filename, &st) < 0)
        return FT_OTHER;
    if (S_ISCHR(st.st_mode)) {
        if (RAW_MAJOR == major(st.st_rdev))
            return FT_RAW;
        else if (SCSI_GENERIC_MAJOR == major(st.st_rdev))
            return FT_SG;
    } else if (S_ISBLK(st.st_mode))
        return FT_BLOCK;
    return FT_OTHER;
}

void usage()
{
    fprintf(stderr, "Usage: "
           "sg_read  if=<infile> count=<num> [blk_sgio=0|1] [bpt=<num>] "
           "[bs=<num>]\n"
           "                [cdbsz=6|10|12|16] [dio=0|1] [mmap=0|1] "
           "[odir=0|1]\n"
           "                [skip=<num>] [time=<num>] [verbose=<n>] "
           "[--version]\n"
           " blk_sgio 0->normal IO for block devices, 1->SCSI commands via "
           "SG_IO\n"
           " bpt      is blocks_per_transfer (default is 128, or 64 KiB for "
           "def 'bs')\n"
           " bs       must match sector size if 'if' accessed via SCSI "
           "commands (def=512)\n"
           " cdbsz    size of SCSI READ command (default is 10)\n"
           " count    total bytes read will be 'bs'*'count' (if no error)\n"
           " dio      1-> attempt direct IO on sg device, 0->indirect IO "
           "(def)\n"
           " if       an sg, block or raw device, or a seekable file (not "
           "stdin)\n"
           " mmap     1->perform mmaped IO on sg device, 0->indirect IO "
           "(def)\n"
           " odir     1->open block device O_DIRECT, 0->don't (def)\n"
           " skip     each transfer starts at this logical address (def=0)\n"
           " time     0->do nothing(def), 1->time from 1st cmd, 2->time "
           "from 2nd, ...\n"
           " verbose  increase level of verbosity (def: 0)\n"
           " --version  print version number then exit\n");
}

int sg_build_scsi_cdb(unsigned char * cdbp, int cdb_sz, unsigned int blocks,
                      unsigned int start_block)
{
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int sz_ind;

    memset(cdbp, 0, cdb_sz);
    switch (cdb_sz) {
    case 6:
        sz_ind = 0;
        cdbp[0] = (unsigned char)rd_opcode[sz_ind];
        cdbp[1] |= (unsigned char)((start_block >> 16) & 0x1f);
        cdbp[2] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[3] = (unsigned char)(start_block & 0xff);
        cdbp[4] = (256 == blocks) ? 0 : (unsigned char)blocks;
        if (blocks > 256) {
            fprintf(stderr, ME "for 6 byte commands, maximum number of "
                            "blocks is 256\n");
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            fprintf(stderr, ME "for 6 byte commands, can't address blocks"
                            " beyond %d\n", 0x1fffff);
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        cdbp[0] = (unsigned char)rd_opcode[sz_ind];
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[8] = (unsigned char)(blocks & 0xff);
        if (blocks & (~0xffff)) {
            fprintf(stderr, ME "for 10 byte commands, maximum number of "
                            "blocks is %d\n", 0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        cdbp[0] = (unsigned char)rd_opcode[sz_ind];
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[6] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[8] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[9] = (unsigned char)(blocks & 0xff);
        break;
    case 16:
        sz_ind = 3;
        cdbp[0] = (unsigned char)rd_opcode[sz_ind];
        /* can't cope with block number > 32 bits (yet) */
        cdbp[6] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[7] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[8] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[9] = (unsigned char)(start_block & 0xff);
        cdbp[10] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[11] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[12] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[13] = (unsigned char)(blocks & 0xff);
        break;
    default:
        fprintf(stderr, ME "expected cdb size of 6, 10, 12, or 16 but got"
                        "=%d\n", cdb_sz);
        return 1;
    }
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
int sg_bread(int sg_fd, unsigned char * buff, int blocks, int from_block,
             int bs, int cdbsz, int * diop, int do_mmap)
{
    int k;
    unsigned char rdCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (sg_build_scsi_cdb(rdCmd, cdbsz, blocks, from_block)) {
        fprintf(stderr, ME "bad cdb build, from_block=%d, blocks=%d\n",
                from_block, blocks);
        return -1;
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = bs * blocks;
    if (! do_mmap) /* not required: shows dxferp unused during mmap-ed IO */
        io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = pack_id_count++;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;
    else if (do_mmap)
        io_hdr.flags |= SG_FLAG_MMAP_IO;
    if (verbose) {
        fprintf(stderr, "    read cdb: ");
        for (k = 0; k < cdbsz; ++k)
            fprintf(stderr, "%02x ", rdCmd[k]);
        fprintf(stderr, "\n");
    }

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("reading (SG_IO) on sg device, error");
        return -1;
    }

    if (verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_RECOVERED:
        if (verbose > 1)
                sg_chk_n_print3("reading, continue", &io_hdr, 1);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_MEDIA_CHANGED:
        return 2;
    default:
        sg_chk_n_print3("reading", &io_hdr, verbose > 1);
        return -1;
    }
    if (diop && *diop && 
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0;      /* flag that dio not done (completely) */
    sum_of_resids += io_hdr.resid;
    return 0;
}

#define STR_SZ 1024
#define INF_SZ 512
#define EBUFF_SZ 512


int main(int argc, char * argv[])
{
    int skip = 0;
    int bs = 0;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    char str[STR_SZ];
    char * key;
    char * buf;
    char inf[INF_SZ];
    int in_type = FT_OTHER;
    int do_dio = 0;
    int do_odir = 0;
    int do_blk_sgio = 0;
    int do_mmap = 0;
    int do_time = 0;
    int scsi_cdbsz = DEF_SCSI_CDBSZ;
    int dio_incomplete = 0;
    int res, k, t, buf_sz, dio_tmp, iters, orig_count;
    int infd, blocks, flags, blocks_per;
    unsigned char * wrkBuff = NULL;
    unsigned char * wrkPos;
    char ebuff[EBUFF_SZ];
    struct timeval start_tm, end_tm;
    size_t psz = getpagesize();

    inf[0] = '\0';
    if (argc < 3) {
        fprintf(stderr, "'if' and 'count' arguments must be given\n");
        usage();
        return 1;
    }

    for(k = 1; k < argc; k++) {
        if (argv[k]) {
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
        }
        else
            continue;
        for(key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        if (strcmp(key,"if") == 0)
            strncpy(inf, buf, INF_SZ);
        else if (0 == strcmp(key,"bs")) {
            bs = sg_get_num(buf);
            if (-1 == bs) {
                fprintf(stderr, ME "bad argument to 'bs'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"bpt")) {
            bpt = sg_get_num(buf);
            if (-1 == bpt) {
                fprintf(stderr, ME "bad argument to 'bpt'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"skip")) {
            skip = sg_get_num(buf);
            if (-1 == skip) {
                fprintf(stderr, ME "bad argument to 'skip'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"count")) {
            dd_count = sg_get_num(buf);
            if (-1 == dd_count) {
                fprintf(stderr, ME "bad argument to 'count'\n");
                return 1;
            }
        } else if (0 == strcmp(key,"dio"))
            do_dio = sg_get_num(buf);
        else if (0 == strcmp(key,"mmap"))
            do_mmap = sg_get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = sg_get_num(buf);
        else if (0 == strcmp(key,"cdbsz"))
            scsi_cdbsz = sg_get_num(buf);
        else if (0 == strcmp(key,"blk_sgio"))
            do_blk_sgio = sg_get_num(buf);
        else if (0 == strcmp(key,"odir"))
            do_odir = sg_get_num(buf);
        else if (0 == strncmp(key, "verb", 4))
            verbose = sg_get_num(buf);
        else if (0 == strncmp(key, "--vers", 6)) {
            fprintf(stderr, ME ": %s\n", version_str);
            return 0;
        } else {
            fprintf(stderr, "Unrecognized argument '%s'\n", key);
            usage();
            return 1;
        }
    }
    if (bs <= 0) {
        bs = DEF_BLOCK_SIZE;
        fprintf(stderr, "Assume default 'bs' (block size) of %d bytes\n", bs);
    }
    if (dd_count < 0) {
        fprintf(stderr, "'count' must be given\n");
        usage();
        return 1;
    }
    if (skip < 0) {
        fprintf(stderr, "skip cannot be negative\n");
        return 1;
    }
    if (bpt < 1) {
        fprintf(stderr, "bpt must be greater than 0\n");
        return 1;
    }
    if (do_dio && do_mmap) {
        fprintf(stderr, "cannot select both dio and mmap\n");
        return 1;
    }

    install_handler (SIGINT, interrupt_handler);
    install_handler (SIGQUIT, interrupt_handler);
    install_handler (SIGPIPE, interrupt_handler);
    install_handler (SIGUSR1, siginfo_handler);

    if (! inf[0]) {
        fprintf(stderr, "must provide 'if=<filename>'\n");
        usage();
        return 1;
    }
    if (0 == strcmp("-", inf)) {
        fprintf(stderr, "'-' (stdin) invalid as <filename>\n");
        usage();
        return 1;
    }
    in_type = dd_filetype(inf);

    if ((FT_BLOCK & in_type) && do_blk_sgio)
        in_type |= FT_SG;

    if (FT_SG & in_type) {
        flags = O_RDWR;
        if ((do_odir && (FT_BLOCK & in_type)))
            flags |= O_DIRECT;
        if ((infd = open(inf, flags)) < 0) {
            flags = O_RDONLY;
            if ((do_odir && (FT_BLOCK & in_type)))
                flags |= O_DIRECT;
            if ((infd = open(inf, flags)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for sg reading", inf);
                perror(ebuff);
                return 1;
            }
        }
        if (! (FT_BLOCK & in_type)) {
            t = bs * bpt;
            if ((do_mmap) && (0 != (t % psz)))
                t = ((t / psz) + 1) * psz;    /* round up to next pagesize */
            res = ioctl(infd, SG_SET_RESERVED_SIZE, &t);
            if (res < 0)
                perror(ME "SG_SET_RESERVED_SIZE error");
            res = ioctl(infd, SG_GET_VERSION_NUM, &t);
            if ((res < 0) || (t < 30000)) {
                fprintf(stderr, ME "sg driver prior to 3.x.y\n");
                return 1;
            }
            if (do_mmap && (t < 30122)) {
                fprintf(stderr, ME "mmap-ed IO needs a sg driver version "
                        ">= 3.1.22\n");
                return 1;
            }
        }
    }
    else {
        if (do_mmap) {
            fprintf(stderr, ME "mmap-ed IO only support on sg "
                    "devices\n");
            return 1;
        }
        if ((infd = open(inf, O_RDONLY)) < 0) {
            snprintf(ebuff,  EBUFF_SZ,
                     ME "could not open %s for reading", inf);
            perror(ebuff);
            return 1;
        }
        else if (skip > 0) {
            llse_loff_t offset = skip;

            offset *= bs;       /* could exceed 32 bits here! */
            if (llse_llseek(infd, offset, SEEK_SET) < 0) {
                snprintf(ebuff,  EBUFF_SZ,
                    ME "couldn't skip to required position on %s", inf);
                perror(ebuff);
                return 1;
            }
        }
    }

    if (0 == dd_count)
        return 0;
    orig_count = dd_count;

    if (do_dio || (FT_RAW & in_type)) {
        wrkBuff = malloc(bs * bpt + psz);
        if (0 == wrkBuff) {
            fprintf(stderr, "Not enough user memory for raw\n");
            return 1;
        }
        wrkPos = (unsigned char *)(((unsigned long)wrkBuff + psz - 1) &
                                   (~(psz - 1)));
    }
    else if (do_mmap) {
        wrkPos = mmap(NULL, bs * bpt, PROT_READ | PROT_WRITE,
                      MAP_SHARED, infd, 0);
        if (MAP_FAILED == wrkPos) {
            perror(ME "error from mmap()");
            return 1;
        }
    }
    else {
        wrkBuff = malloc(bs * bpt);
        if (0 == wrkBuff) {
            fprintf(stderr, "Not enough user memory\n");
            return 1;
        }
        wrkPos = wrkBuff;
    }

    blocks_per = bpt;
    start_tm.tv_sec = 0;   /* just in case start set condition not met */
    start_tm.tv_usec = 0;

    /* main loop */
    for (iters = 0; dd_count > 0; ++iters) {
        if ((do_time > 0) && (iters == (do_time - 1)))
            gettimeofday(&start_tm, NULL);
        blocks = (dd_count > blocks_per) ? blocks_per : dd_count;
        if (FT_SG & in_type) {
            dio_tmp = do_dio;
            res = sg_bread(infd, wrkPos, blocks, skip, bs, scsi_cdbsz,
                           &dio_tmp, do_mmap);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + bs - 1) / bs;
                blocks = blocks_per;
                fprintf(stderr, 
                        "Reducing read to %d blocks per loop\n", blocks_per);
                res = sg_bread(infd, wrkPos, blocks, skip, bs, scsi_cdbsz,
                               &dio_tmp, do_mmap);
            }
            else if (2 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed, continuing (r)\n");
                res = sg_bread(infd, wrkPos, blocks, skip, bs, scsi_cdbsz,
                               &dio_tmp, do_mmap);
            }
            if (0 != res) {
                fprintf(stderr, ME "failed, skip=%d\n", skip);
                break;
            }
            else {
                in_full += blocks;
                if (do_dio && (0 == dio_tmp))
                    dio_incomplete++;
            }
        }
        else {
            if (iters > 0) { /* subsequent iteration reset skip position */
                llse_loff_t offset = skip;

                offset *= bs;       /* could exceed 32 bits here! */
                if (llse_llseek(infd, offset, SEEK_SET) < 0) {
                    perror(ME "could not reset skip position");
                    break;
                }
            }
            while (((res = read(infd, wrkPos, blocks * bs)) < 0) &&
                   (EINTR == errno))
                ;
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "reading, skip=%d ", skip);
                perror(ebuff);
                break;
            }
            else if (res < blocks * bs) {
                fprintf(stderr, ME "short read: wanted/got=%d/%d bytes"
                        ", stop\n", blocks * bs, res);
                blocks = res / bs;
                if ((res % bs) > 0) {
                    blocks++;
                    in_partial++;
                }
                dd_count -= blocks;
                in_full += blocks;
                break;
            }
            in_full += blocks;
        }
        if (dd_count > 0)
            dd_count -= blocks;
    }
    if (do_time > 0) {
        gettimeofday(&end_tm, NULL);
        if (start_tm.tv_sec || start_tm.tv_usec) {
            struct timeval res_tm;
            double a, b, c;

            res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
            res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
            if (res_tm.tv_usec < 0) {
                --res_tm.tv_sec;
                res_tm.tv_usec += 1000000;
            }
            a = res_tm.tv_sec;
            a += (0.000001 * res_tm.tv_usec);
            b = (double)bs * (orig_count - dd_count);
            if (do_time > 1)
                c = b - ((double)bs * ((do_time - 1.0) * bpt));
            else
                c = 0.0;

            if (1 == do_time) {
                fprintf(stderr, "time for all (SCSI) commands was "
                    "%d.%06d secs", (int)res_tm.tv_sec, (int)res_tm.tv_usec);
                if ((a > 0.00001) && (b > 511))
                    fprintf(stderr, ", %.2f MB/sec\n", b / (a * 1000000.0));
                else
                    fprintf(stderr, "\n");
            }
            else if (2 == do_time) {
                fprintf(stderr, "time from second (SCSI) command to end "
                    "was %d.%06d secs", (int)res_tm.tv_sec, 
                    (int)res_tm.tv_usec);
                if ((a > 0.00001) && (c > 511))
                    fprintf(stderr, ", %.2f MB/sec\n", c / (a * 1000000.0));
                else
                    fprintf(stderr, "\n");
            }
            else { 
                fprintf(stderr, "time from start of (SCSI) command "
                        "#%d to end was %d.%06d secs", do_time,
                        (int)res_tm.tv_sec, (int)res_tm.tv_usec);
                if ((a > 0.00001) && (c > 511))
                    fprintf(stderr, ", %.2f MB/sec\n", c / (a * 1000000.0));
                else
                    fprintf(stderr, "\n");
            }
        }
    }

    if (wrkBuff)
        free(wrkBuff);

    close(infd);
    res = 0;
    if (0 != dd_count) {
        fprintf(stderr, "Some error occurred,");
        res = 2;
    }
    if (FT_SG & in_type)
        print_stats(iters);
    else
        print_stats(0);
    if (dio_incomplete) {
        int fd;
        char c;

        fprintf(stderr, ">> Direct IO requested but incomplete %d times\n", 
                dio_incomplete);
        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    fprintf(stderr, ">>> %s set to '0' but should be set "
                            "to '1' for direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    }
    if (sum_of_resids)
        fprintf(stderr, ">> Non-zero sum of residual counts=%d\n", 
                sum_of_resids);
    return res;
}
