#define _XOPEN_SOURCE 500

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
typedef unsigned char u_char;   /* horrible, for scsi.h */
#include "sg_include.h"
#include "sg_err.h"
#include "llseek.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2001 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program reads data from the given SCSI device (typically a disk
   or cdrom) and discards that data. Its primary goal is to time
   multiple reads all from the same logical address. Its interface
   is a subset of another member of this package: sg_dd which is a 
   "dd" variant. The input file can be a scsi generic device, a raw device
   or a seekable file. Streams such as stdin are not acceptable.
   The block size ('bs') is assumed to be 512 if not given. 
   Various arguments can take a multiplier suffix:
     'c','C'  *1       'b','B' *512      'k' *1024      'K' *1000
     'm' *(1024^2)     'M' *(1000^2)     'g' *(1024^3)  'G' *(1000^3)

   The "bpt" (blocks per transfer) argument controls the maximum number
   of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16KB
   in this case) is read from the sg device in a single SCSI command.

   This version should compile with Linux sg drivers with version numbers
   >= 30000 . For mmap-ed IO the sg version number >= 30122 .

*/

static const char * version_str = "0.92 20011210";

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 40000       /* 40,000 millisecs == 40 seconds */

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikey value */
#endif 

#define FT_OTHER 0              /* filetype other than sg or raw device */
#define FT_SG 1                 /* filetype is sg char device */
#define FT_RAW 2                /* filetype is raw char device */

static int sum_of_resids = 0;

static int dd_count = -1;
static int in_full = 0;
static int in_partial = 0;

static int pack_id_count = 0;

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
    }
    return FT_OTHER;
}

void usage()
{
    fprintf(stderr, "Usage: "
           "sg_read  if=<infile> [skip=<num>] [bs=<num>] [bpt=<num>] "
           "count=<num>\n"
           "                         [dio=<num>] [mmap=<num>] [time=<num>]\n"
           " 'if'  is an sg or raw device, or a seekable file (not stdin)\n"
           " 'bs'  must match sector size (when 'if' is sg device) "
	   "(def=512)\n"
           " 'skip' each transfer starts at this logical address (def=0)\n"
           " 'count' total bytes read will be 'bs'*'count' (if no error)\n"
           " 'bpt' is blocks_per_transfer (default is 128, or 64KB for "
	   "def 'bs')\n"
           " 'dio' is direct IO, 1->attempt, 0->indirect IO (def)\n"
           " 'mmap' is mmap-ed IO, 1->perform, 0->indirect IO (def)\n"
           " 'time' 0->do nothing(def), 1->time from 1st cmd, 2->time "
           "from 2nd cmd\n");
    fprintf(stderr, "\nVersion: %s\n", version_str);
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
int sg_bread(int sg_fd, unsigned char * buff, int blocks, int from_block,
             int bs, int * diop, int do_mmap)
{
    unsigned char rdCmd[10] = {0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char senseBuff[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;
    int res;

    rdCmd[2] = (unsigned char)((from_block >> 24) & 0xFF);
    rdCmd[3] = (unsigned char)((from_block >> 16) & 0xFF);
    rdCmd[4] = (unsigned char)((from_block >> 8) & 0xFF);
    rdCmd[5] = (unsigned char)(from_block & 0xFF);
    rdCmd[7] = (unsigned char)((blocks >> 8) & 0xff);
    rdCmd[8] = (unsigned char)(blocks & 0xff);

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rdCmd);
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

    while (((res = write(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("reading (wr) on sg device, error");
        return -1;
    }

    while (((res = read(sg_fd, &io_hdr, sizeof(io_hdr))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        perror("reading (rd) on sg device, error");
        return -1;
    }
    switch (sg_err_category3(&io_hdr)) {
    case SG_ERR_CAT_CLEAN:
        break;
    case SG_ERR_CAT_RECOVERED:
        fprintf(stderr, "Recovered error while reading block=%d, num=%d\n",
               from_block, blocks);
        break;
    case SG_ERR_CAT_MEDIA_CHANGED:
        return 2;
    default:
        sg_chk_n_print3("reading", &io_hdr);
        return -1;
    }
    if (diop && *diop && 
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0;      /* flag that dio not done (completely) */
    sum_of_resids += io_hdr.resid;
#if SG_DEBUG
    fprintf(stderr, "duration=%u ms\n", io_hdr.duration);
#endif
    return 0;
}

int get_num(char * buf)
{
    int res, num;
    char c;

    res = sscanf(buf, "%d%c", &num, &c);
    if (0 == res)
        return -1;
    else if (1 == res)
        return num;
    else {
        switch (c) {
        case 'c':
        case 'C':
            return num;
        case 'b':
        case 'B':
            return num * 512;
        case 'k':
            return num * 1024;
        case 'K':
            return num * 1000;
        case 'm':
            return num * 1024 * 1024;
        case 'M':
            return num * 1000000;
        case 'g':
            return num * 1024 * 1024 * 1024;
        case 'G':
            return num * 1000000000;
        default:
            fprintf(stderr, "unrecognized multiplier\n");
            return -1;
        }
    }
}


int main(int argc, char * argv[])
{
    int skip = 0;
    int bs = 0;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    char str[512];
    char * key;
    char * buf;
    char inf[512];
    int in_type = FT_OTHER;
    int do_dio = 0;
    int do_mmap = 0;
    int do_time = 0;
    int dio_incomplete = 0;
    int res, k, t, buf_sz, dio_tmp, iters, orig_count;
    int infd, blocks;
    unsigned char * wrkBuff = NULL;
    unsigned char * wrkPos;
    char ebuff[256];
    int blocks_per;
    struct timeval start_tm, end_tm;
    size_t psz = getpagesize();

    inf[0] = '\0';
    if (argc < 3) {
        fprintf(stderr, "'if' and 'count' arguments must be given\n");
        usage();
        return 1;
    }

    for(k = 1; k < argc; k++) {
        if (argv[k])
            strcpy(str, argv[k]);
        else
            continue;
        for(key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        if (strcmp(key,"if") == 0)
            strcpy(inf, buf);
        else if (0 == strcmp(key,"bs"))
            bs = get_num(buf);
        else if (0 == strcmp(key,"bpt"))
            bpt = get_num(buf);
        else if (0 == strcmp(key,"skip"))
            skip = get_num(buf);
        else if (0 == strcmp(key,"count"))
            dd_count = get_num(buf);
        else if (0 == strcmp(key,"dio"))
            do_dio = get_num(buf);
        else if (0 == strcmp(key,"mmap"))
            do_mmap = get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = get_num(buf);
        else {
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
    if (do_dio && do_mmap) {
        fprintf(stderr, "cannot select both dio and mmap\n");
        return 1;
    }

#ifdef SG_DEBUG
    fprintf(stderr, "sg_read: if=%s skip=%d count=%d\n", inf, skip, dd_count);
#endif
    install_handler (SIGINT, interrupt_handler);
    install_handler (SIGQUIT, interrupt_handler);
    install_handler (SIGPIPE, interrupt_handler);
    install_handler (SIGUSR1, siginfo_handler);

    if (! inf[0]) {
        fprintf(stderr, "must provide 'if=<filename>'\n");
        usage();
        return 1;
    }
    in_type = dd_filetype(inf);

    if (FT_SG == in_type) {
        if ((infd = open(inf, O_RDWR)) < 0) {
            sprintf(ebuff, "sg_read: could not open %s for sg reading", inf);
            perror(ebuff);
            return 1;
        }
        t = bs * bpt;
	if ((do_mmap) && (0 != (t % psz)))
	    t = ((t / psz) + 1) * psz;    /* round up to next pagesize */
        res = ioctl(infd, SG_SET_RESERVED_SIZE, &t);
        if (res < 0)
            perror("sg_read: SG_SET_RESERVED_SIZE error");
        res = ioctl(infd, SG_GET_VERSION_NUM, &t);
        if ((res < 0) || (t < 30000)) {
            fprintf(stderr, "sg_read: sg driver prior to 3.x.y\n");
            return 1;
        }
	if (do_mmap && (t < 30122)) {
            fprintf(stderr, "sg_read: mmap-ed IO needs a sg driver version "
		    ">= 3.1.22\n");
            return 1;
        }
    }
    else {
	if (do_mmap) {
            fprintf(stderr, "sg_read: mmap-ed IO only support on sg "
		    "devices\n");
	    return 1;
	}
        if ((infd = open(inf, O_RDONLY)) < 0) {
            sprintf(ebuff, "sg_read: could not open %s for reading", inf);
            perror(ebuff);
            return 1;
        }
        else if (skip > 0) {
            llse_loff_t offset = skip;

            offset *= bs;       /* could exceed 32 bits here! */
            if (llse_llseek(infd, offset, SEEK_SET) < 0) {
                sprintf(ebuff,
                    "sg_read: couldn't skip to required position on %s", inf);
                perror(ebuff);
                return 1;
            }
        }
    }

    if (0 == dd_count)
        return 0;
    orig_count = dd_count;

    if (do_dio || (FT_RAW == in_type)) {
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
	    perror("sg_read: error from mmap()");
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
#ifdef SG_DEBUG
    fprintf(stderr, "Start of loop, count=%d, blocks_per=%d\n", 
            dd_count, blocks_per);
#endif
    start_tm.tv_sec = 0;   /* just in case start set condition not met */
    start_tm.tv_usec = 0;

    /* main loop */
    for (iters = 0; dd_count > 0; ++iters) {
	if ((do_time > 0) && (iters == (do_time - 1)))
	    gettimeofday(&start_tm, NULL);
        blocks = (dd_count > blocks_per) ? blocks_per : dd_count;
        if (FT_SG == in_type) {
            dio_tmp = do_dio;
            res = sg_bread(infd, wrkPos, blocks, skip, bs, &dio_tmp, do_mmap);
            if (1 == res) {     /* ENOMEM, find what's available+try that */
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                blocks_per = (buf_sz + bs - 1) / bs;
                blocks = blocks_per;
                fprintf(stderr, 
                        "Reducing read to %d blocks per loop\n", blocks_per);
                res = sg_bread(infd, wrkPos, blocks, skip, bs, &dio_tmp,
			       do_mmap);
            }
            else if (2 == res) {
                fprintf(stderr, 
                        "Unit attention, media changed, continuing (r)\n");
                res = sg_bread(infd, wrkPos, blocks, skip, bs, &dio_tmp,
			       do_mmap);
            }
            if (0 != res) {
                fprintf(stderr, "sg_read failed, skip=%d\n", skip);
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
		    perror("sg_read: could not reset skip position");
		    break;
		}
	    }
            while (((res = read(infd, wrkPos, blocks * bs)) < 0) &&
                   (EINTR == errno))
                ;
            if (res < 0) {
                sprintf(ebuff, "sg_read: reading, skip=%d ", skip);
                perror(ebuff);
                break;
            }
            else if (res < blocks * bs) {
		fprintf(stderr, "sg_read: short read: wanted/got=%d/%d bytes"
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
    if (FT_SG == in_type)
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
