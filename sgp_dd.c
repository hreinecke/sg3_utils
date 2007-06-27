#define _XOPEN_SOURCE 500

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <linux/major.h>
typedef unsigned char u_char;   /* horrible, for scsi.h */
#include "sg_include.h"
#include "sg_err.h"
#include "llseek.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 1999 - 2002 D. Gilbert and P. Allworth
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program is a specialization of the Unix "dd" command in which
   one or both of the given files is a scsi generic device or a raw
   device. A block size ('bs') is assumed to be 512 if not given. This
   program complains if 'ibs' or 'obs' are given with some other value
   than 'bs'. If 'if' is not given or 'if=-' then stdin is assumed. If
   'of' is not given or 'of=-' then stdout assumed.  Multipliers:
      'c','C'  *1       'b','B' *512      'k' *1024      'K' *1000
      'm' *(1024^2)     'M' *(1000^2)     'g' *(1024^3)  'G' *(1000^3)
   
   A non-standard argument "bpt" (blocks per transfer) is added to control
   the maximum number of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16KB
   in this case) are transferred to or from the sg device in a single SCSI
   command.

   This version should compile with Linux sg drivers with version numbers
   >= 30000 . This version uses posix threads.

*/

static char * version_str = "5.11 20020518";

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define ME "sgp_dd: "

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define SGP_READ10 0x28
#define SGP_WRITE10 0x2a
#define DEF_NUM_THREADS 4
#define MAX_NUM_THREADS SG_MAX_QUEUE

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikey value */
#endif

#define FT_OTHER 0              /* filetype other than sg or raw device */
#define FT_SG 1                 /* filetype is sg char device */
#define FT_RAW 2                /* filetype is raw char device */
#define FT_DEV_NULL 3           /* either "/dev/null" or "." as filename */
#define FT_ST 4                 /* filetype is st char device (tape) */

#define DEV_NULL_MINOR_NUM 3

#define EBUFF_SZ 512


typedef struct request_collection
{       /* one instance visible to all threads */
    int infd;
    int skip;
    int in_type;
    int in_scsi_type;
    int in_blk;                 /* -\ next block address to read */
    int in_count;               /*  | blocks remaining for next read */
    int in_done_count;          /*  | count of completed in blocks */
    int in_partial;             /*  | */
    int in_stop;                /*  | */
    pthread_mutex_t in_mutex;   /* -/ */
    int outfd;
    int seek;
    int out_type;
    int out_scsi_type;
    int out_blk;                /* -\ next block address to write */
    int out_count;              /*  | blocks remaining for next write */
    int out_done_count;         /*  | count of completed out blocks */
    int out_partial;            /*  | */
    int out_stop;               /*  | */
    pthread_mutex_t out_mutex;  /*  | */
    pthread_cond_t out_sync_cv; /* -/ hold writes until "in order" */
    int bs;
    int bpt;
    int fua_mode;
    int dio;
    int dio_incomplete;         /* -\ */
    int sum_of_resids;          /*  | */
    pthread_mutex_t aux_mutex;  /* -/ (also serializes some printf()s */
    int coe;
    int cdbsz;
    int debug;
} Rq_coll;

typedef struct request_element
{       /* one instance per worker thread */
    int infd;
    int outfd;
    int wr;
    int blk;
    int num_blks;
    unsigned char * buffp;
    unsigned char * alloc_bp;
    sg_io_hdr_t io_hdr;
    unsigned char cmd[MAX_SCSI_CDBSZ];
    unsigned char sb[SENSE_BUFF_LEN];
    int bs;
    int fua_mode;
    int dio;
    int dio_incomplete;
    int resid;
    int in_scsi_type;
    int out_scsi_type;
    int cdbsz;
    int debug;
} Rq_elem;

static sigset_t signal_set;
static pthread_t sig_listen_thread_id;

static const char * proc_allow_dio = "/proc/scsi/sg/allow_dio";

void sg_in_operation(Rq_coll * clp, Rq_elem * rep);
void sg_out_operation(Rq_coll * clp, Rq_elem * rep);
int normal_in_operation(Rq_coll * clp, Rq_elem * rep, int blocks);
void normal_out_operation(Rq_coll * clp, Rq_elem * rep, int blocks);
int sg_start_io(Rq_elem * rep);
int sg_finish_io(int wr, Rq_elem * rep, pthread_mutex_t * a_mutp);

/* Following 2 macros from D.R. Butenhof's POSIX threads book:
   ISBN 0-201-63392-2 . [Highly recommended book.] */
#define err_exit(code,text) do { \
    fprintf(stderr, "%s at \"%s\":%d: %s\n", \
        text, __FILE__, __LINE__, strerror(code)); \
    exit(1); \
    } while (0)
#if 0   /* unsued now */
#define errno_exit(text) do { \
    fprintf(stderr, "%s at \"%s\":%d: %s\n", \
        text, __FILE__, __LINE__, strerror(errno)); \
    exit(1); \
    } while (0)
#endif


int dd_filetype(const char * filename)
{
    struct stat st;
    size_t len = strlen(filename);

    if ((1 == len) && ('.' == filename[0]))
        return FT_DEV_NULL;
    if (stat(filename, &st) < 0)
        return FT_OTHER;
    if (S_ISCHR(st.st_mode)) {
        if ((MEM_MAJOR == major(st.st_rdev)) &&
            (DEV_NULL_MINOR_NUM == minor(st.st_rdev)))
            return FT_DEV_NULL;
        if (RAW_MAJOR == major(st.st_rdev))
            return FT_RAW;
        if (SCSI_GENERIC_MAJOR == major(st.st_rdev))
            return FT_SG;
        if (SCSI_TAPE_MAJOR == major(st.st_rdev))
            return FT_ST;
    }
    return FT_OTHER;
}

void usage()
{
    fprintf(stderr, "Usage: "
           "sgp_dd  [if=<infile>] [skip=<n>] [of=<ofile>] [seek=<n>]\n"
           "               [bs=<num>] [bpt=<num>] [count=<n>]\n"
           "               [dio=0|1>] [thr=<n>] [coe=0|1] [time=0|1]\n"
           "               [deb=<n>] [cdbsz=6|10|12|16] [--version]\n"
           " 'bpt' is blocks_per_transfer (default is 128)\n"
           " 'dio' is direct IO, 1->attempt, 0->indirect IO (def)\n"
           " 'thr' is number of threads, must be > 0, default 4, max 16\n");
    fprintf(stderr, " 'coe' continue on error, 0->exit (def), "
    	   "1->zero + continue\n"
	   " 'time' 0->no timing(def), 1->time plus calculate throughput\n"
           " 'fua' force unit access: 0->don't(def), 1->of, 2->if, 3->of+if\n"
           " 'sync' 0->no sync(def), 1->SYNCHRONIZE CACHE on of after xfer\n"
	   " 'cdbsz' size of SCSI READ or WRITE command (default is 10)\n"
           " 'deb' is debug, 0->none (def), > 0->varying degrees of debug\n");
}

static void guarded_stop_in(Rq_coll * clp)
{
    pthread_mutex_lock(&clp->in_mutex);
    clp->in_stop = 1;
    pthread_mutex_unlock(&clp->in_mutex);
}

static void guarded_stop_out(Rq_coll * clp)
{
    pthread_mutex_lock(&clp->out_mutex);
    clp->out_stop = 1;
    pthread_mutex_unlock(&clp->out_mutex);
}

static void guarded_stop_both(Rq_coll * clp)
{
    guarded_stop_in(clp);
    guarded_stop_out(clp);
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
int read_capacity(int sg_fd, int * num_sect, int * sect_sz)
{
    int res;
    unsigned char rcCmdBlk [10] = {READ_CAPACITY, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char rcBuff[64];
    unsigned char sense_b[64];
    sg_io_hdr_t io_hdr;

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = sizeof(rcBuff);
    io_hdr.dxferp = rcBuff;
    io_hdr.cmdp = rcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("read_capacity (SG_IO) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    if (SG_ERR_CAT_MEDIA_CHANGED == res)
        return 2; /* probably have another go ... */
    else if (SG_ERR_CAT_CLEAN != res) {
        sg_chk_n_print3("read capacity", &io_hdr);
        return -1;
    }
    *num_sect = 1 + ((rcBuff[0] << 24) | (rcBuff[1] << 16) |
                (rcBuff[2] << 8) | rcBuff[3]);
    *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
               (rcBuff[6] << 8) | rcBuff[7];
#ifdef SG_DEBUG
    fprintf(stderr, "number of sectors=%d, sector size=%d\n",
            *num_sect, *sect_sz);
#endif
    return 0;
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
int sync_cache(int sg_fd)
{
    int res;
    unsigned char scCmdBlk [10] = {SYNCHRONIZE_CACHE, 0, 0, 0, 0, 0, 0, 
    				   0, 0, 0};
    unsigned char sense_b[64];
    sg_io_hdr_t io_hdr;

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(scCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.dxfer_len = 0;
    io_hdr.dxferp = NULL;
    io_hdr.cmdp = scCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("synchronize_cache (SG_IO) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    if (SG_ERR_CAT_MEDIA_CHANGED == res)
        return 2; /* probably have another go ... */
    else if (SG_ERR_CAT_CLEAN != res) {
        sg_chk_n_print3("synchronize cache", &io_hdr);
        return -1;
    }
    return 0;
}

void * sig_listen_thread(void * v_clp)
{
    Rq_coll * clp = (Rq_coll *)v_clp;
    int sig_number;

    while (1) {
        sigwait(&signal_set, &sig_number);
        if (SIGINT == sig_number) {
            fprintf(stderr, ME "interrupted by SIGINT\n");
	    guarded_stop_both(clp);
            pthread_cond_broadcast(&clp->out_sync_cv);
        }
    }
    return NULL;
}

void cleanup_in(void * v_clp)
{
    Rq_coll * clp = (Rq_coll *)v_clp;

    fprintf(stderr, "thread cancelled while in mutex held\n");
    clp->in_stop = 1;
    pthread_mutex_unlock(&clp->in_mutex);
    guarded_stop_out(clp);
    pthread_cond_broadcast(&clp->out_sync_cv);
}

void cleanup_out(void * v_clp)
{
    Rq_coll * clp = (Rq_coll *)v_clp;

    fprintf(stderr, "thread cancelled while out mutex held\n");
    clp->out_stop = 1;
    pthread_mutex_unlock(&clp->out_mutex);
    guarded_stop_in(clp);
    pthread_cond_broadcast(&clp->out_sync_cv);
}

void * read_write_thread(void * v_clp)
{
    Rq_coll * clp = (Rq_coll *)v_clp;
    Rq_elem rel;
    Rq_elem * rep = &rel;
    size_t psz = 0;
    int sz = clp->bpt * clp->bs;
    int stop_after_write = 0;
    int seek_skip =  clp->seek - clp->skip;
    int blocks, status;

    memset(rep, 0, sizeof(Rq_elem));
    psz = getpagesize();
    if (NULL == (rep->alloc_bp = malloc(sz + psz)))
        err_exit(ENOMEM, "out of memory creating user buffers\n");
    rep->buffp = (unsigned char *)(((unsigned long)rep->alloc_bp + psz - 1) &
				   (~(psz - 1)));
    /* Follow clp members are constant during lifetime of thread */
    rep->bs = clp->bs;
    rep->fua_mode = clp->fua_mode;
    rep->dio = clp->dio;
    rep->infd = clp->infd;
    rep->outfd = clp->outfd;
    rep->debug = clp->debug;
    rep->in_scsi_type = clp->in_scsi_type;
    rep->out_scsi_type = clp->out_scsi_type;
    rep->cdbsz = clp->cdbsz;

    while(1) {
        status = pthread_mutex_lock(&clp->in_mutex);
        if (0 != status) err_exit(status, "lock in_mutex");
        if (clp->in_stop || (clp->in_count <= 0)) {
            /* no more to do, exit loop then thread */
            status = pthread_mutex_unlock(&clp->in_mutex);
            if (0 != status) err_exit(status, "unlock in_mutex");
            break;
        }
        blocks = (clp->in_count > clp->bpt) ? clp->bpt : clp->in_count;
        rep->wr = 0;
        rep->blk = clp->in_blk;
        rep->num_blks = blocks;
        clp->in_blk += blocks;
        clp->in_count -= blocks;

        pthread_cleanup_push(cleanup_in, (void *)clp);
        if (FT_SG == clp->in_type)
            sg_in_operation(clp, rep); /* lets go of in_mutex mid operation */
        else {
            stop_after_write = normal_in_operation(clp, rep, blocks);
	    status = pthread_mutex_unlock(&clp->in_mutex);
	    if (0 != status) err_exit(status, "unlock in_mutex");
	}
        pthread_cleanup_pop(0);

        status = pthread_mutex_lock(&clp->out_mutex);
        if (0 != status) err_exit(status, "lock out_mutex");
	if (FT_DEV_NULL != clp->out_type) {
	    while ((! clp->out_stop) && 
		   ((rep->blk + seek_skip) != clp->out_blk)) {
		/* if write would be out of sequence then wait */
		pthread_cleanup_push(cleanup_out, (void *)clp);
		status = pthread_cond_wait(&clp->out_sync_cv, &clp->out_mutex);
		if (0 != status) err_exit(status, "cond out_sync_cv");
		pthread_cleanup_pop(0);
	    }
	}

        if (clp->out_stop || (clp->out_count <= 0)) {
            if (! clp->out_stop)
                clp->out_stop = 1;
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
            break;
        }
        if (stop_after_write)
            clp->out_stop = 1;
        rep->wr = 1;
        rep->blk = clp->out_blk;
        /* rep->num_blks = blocks; */
        clp->out_blk += blocks;
        clp->out_count -= blocks;

        pthread_cleanup_push(cleanup_out, (void *)clp);
        if (FT_SG == clp->out_type)
            sg_out_operation(clp, rep); /* releases out_mutex mid operation */
	else if (FT_DEV_NULL == clp->out_type) {
	    /* skip actual write operation */
	    clp->out_done_count -= blocks;
	    status = pthread_mutex_unlock(&clp->out_mutex);
	    if (0 != status) err_exit(status, "unlock out_mutex");
	}
        else {
            normal_out_operation(clp, rep, blocks);
	    status = pthread_mutex_unlock(&clp->out_mutex);
	    if (0 != status) err_exit(status, "unlock out_mutex");
	}
        pthread_cleanup_pop(0);

        if (stop_after_write)
            break;
        pthread_cond_broadcast(&clp->out_sync_cv);
    } /* end of while loop */
    if (rep->alloc_bp) free(rep->alloc_bp);
    status = pthread_mutex_lock(&clp->in_mutex);
    if (0 != status) err_exit(status, "lock in_mutex");
    if (! clp->in_stop)
        clp->in_stop = 1;  /* flag other workers to stop */
    status = pthread_mutex_unlock(&clp->in_mutex);
    if (0 != status) err_exit(status, "unlock in_mutex");
    pthread_cond_broadcast(&clp->out_sync_cv);
    return stop_after_write ? NULL : v_clp;
}

int normal_in_operation(Rq_coll * clp, Rq_elem * rep, int blocks)
{
    int res;
    int stop_after_write = 0;

    /* enters holding in_mutex */
    while (((res = read(clp->infd, rep->buffp,
                        blocks * clp->bs)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
	if (clp->coe) {
	    memset(rep->buffp, 0, rep->num_blks * rep->bs);
	    fprintf(stderr, ">> substituted zeros for in blk=%d for "
		    "%d bytes, %s\n", rep->blk, 
		    rep->num_blks * rep->bs, strerror(errno));
	    res = rep->num_blks * clp->bs;
	}
	else {
	    fprintf(stderr, "error in normal read, %s\n", strerror(errno));
	    clp->in_stop = 1;
	    guarded_stop_out(clp);
	    return 1;
	}
    }
    if (res < blocks * clp->bs) {
        int o_blocks = blocks;
        stop_after_write = 1;
        blocks = res / clp->bs;
        if ((res % clp->bs) > 0) {
            blocks++;
            clp->in_partial++;
        }
        /* Reverse out + re-apply blocks on clp */
        clp->in_blk -= o_blocks;
        clp->in_count += o_blocks;
        rep->num_blks = blocks;
        clp->in_blk += blocks;
        clp->in_count -= blocks;
    }
    clp->in_done_count -= blocks;
    return stop_after_write;
}

void normal_out_operation(Rq_coll * clp, Rq_elem * rep, int blocks)
{
    int res;

    /* enters holding out_mutex */
    while (((res = write(clp->outfd, rep->buffp,
                 rep->num_blks * clp->bs)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
	if (clp->coe) {
	    fprintf(stderr, ">> ignored error for out blk=%d for "
		    "%d bytes, %s\n", rep->blk, 
		    rep->num_blks * rep->bs, strerror(errno));
	    res = rep->num_blks * clp->bs;
	}
	else {
	    fprintf(stderr, "error normal write, %s\n", strerror(errno));
	    guarded_stop_in(clp);
	    clp->out_stop = 1;
	    return;
	}
    }
    if (res < blocks * clp->bs) {
        blocks = res / clp->bs;
        if ((res % clp->bs) > 0) {
            blocks++;
            clp->out_partial++;
        }
        rep->num_blks = blocks;
    }
    clp->out_done_count -= blocks;
}

int sg_build_scsi_cdb(unsigned char * cdbp, int cdb_sz, unsigned int blocks,
		      unsigned int start_block, int write_true, int fua,
		      int dpo)
{
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};
    int sz_ind;

    memset(cdbp, 0, cdb_sz);
    if (dpo)
	cdbp[1] |= 0x10;
    if (fua)
	cdbp[1] |= 0x8;
    switch (cdb_sz) {
    case 6:
    	sz_ind = 0;
	cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
					       rd_opcode[sz_ind]);
	cdbp[1] = (unsigned char)((start_block >> 16) & 0x1f);
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
	if (dpo || fua) {
	    fprintf(stderr, ME "for 6 byte commands, neither dpo nor fua"
	    		    " bits supported\n");
	    return 1;
	}
    	break;
    case 10:
    	sz_ind = 1;
	cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
					       rd_opcode[sz_ind]);
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
	cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
					       rd_opcode[sz_ind]);
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
	cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
					       rd_opcode[sz_ind]);
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

void sg_in_operation(Rq_coll * clp, Rq_elem * rep)
{
    int res;
    int status;

    /* enters holding in_mutex */
    while (1) {
        res = sg_start_io(rep);
        if (1 == res)
            err_exit(ENOMEM, "sg starting in command");
        else if (res < 0) {
            fprintf(stderr, ME "inputting to sg failed, blk=%d\n",
		    rep->blk);
	    status = pthread_mutex_unlock(&clp->in_mutex);
	    if (0 != status) err_exit(status, "unlock in_mutex");
	    guarded_stop_both(clp);
	    return;
        }
        /* Now release in mutex to let other reads run in parallel */
        status = pthread_mutex_unlock(&clp->in_mutex);
        if (0 != status) err_exit(status, "unlock in_mutex");

        res = sg_finish_io(rep->wr, rep, &clp->aux_mutex);
        if (res < 0) {
            if (clp->coe) {
                memset(rep->buffp, 0, rep->num_blks * rep->bs);
                fprintf(stderr, ">> substituted zeros for in blk=%d for "
                        "%d bytes\n", rep->blk, rep->num_blks * rep->bs);
            }
            else {
                fprintf(stderr, "error finishing sg in command\n");
		guarded_stop_both(clp);
                return;
            }
        }
        if (res <= 0) { /* looks good, going to return */
            if (rep->dio_incomplete || rep->resid) {
                status = pthread_mutex_lock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "lock aux_mutex");
                clp->dio_incomplete += rep->dio_incomplete;
                clp->sum_of_resids += rep->resid;
                status = pthread_mutex_unlock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "unlock aux_mutex");
            }
            status = pthread_mutex_lock(&clp->in_mutex);
            if (0 != status) err_exit(status, "lock in_mutex");
            clp->in_done_count -= rep->num_blks;
            status = pthread_mutex_unlock(&clp->in_mutex);
            if (0 != status) err_exit(status, "unlock in_mutex");
            return;
        }
        /* else assume 1 == res so try again with same addr, count info */
        /* now re-acquire read mutex for balance */
        /* N.B. This re-read could now be out of read sequence */
        status = pthread_mutex_lock(&clp->in_mutex);
        if (0 != status) err_exit(status, "lock in_mutex");
    }
}

void sg_out_operation(Rq_coll * clp, Rq_elem * rep)
{
    int res;
    int status;

    /* enters holding out_mutex */
    while (1) {
        res = sg_start_io(rep);
        if (1 == res)
            err_exit(ENOMEM, "sg starting out command");
        else if (res < 0) {
            fprintf(stderr, ME "outputting from sg failed, blk=%d\n",
                    rep->blk);
	    status = pthread_mutex_unlock(&clp->out_mutex);
	    if (0 != status) err_exit(status, "unlock out_mutex");
	    guarded_stop_both(clp);
	    return;
        }
        /* Now release in mutex to let other reads run in parallel */
        status = pthread_mutex_unlock(&clp->out_mutex);
        if (0 != status) err_exit(status, "unlock out_mutex");

        res = sg_finish_io(rep->wr, rep, &clp->aux_mutex);
        if (res < 0) {
            if (clp->coe)
                fprintf(stderr, ">> ignored error for out blk=%d for "
                        "%d bytes\n", rep->blk, rep->num_blks * rep->bs);
            else {
                fprintf(stderr, "error finishing sg out command\n");
		guarded_stop_both(clp);
                return;
            }
        }
        if (res <= 0) {
            if (rep->dio_incomplete || rep->resid) {
                status = pthread_mutex_lock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "lock aux_mutex");
                clp->dio_incomplete += rep->dio_incomplete;
                clp->sum_of_resids += rep->resid;
                status = pthread_mutex_unlock(&clp->aux_mutex);
                if (0 != status) err_exit(status, "unlock aux_mutex");
            }
            status = pthread_mutex_lock(&clp->out_mutex);
            if (0 != status) err_exit(status, "lock out_mutex");
            clp->out_done_count -= rep->num_blks;
            status = pthread_mutex_unlock(&clp->out_mutex);
            if (0 != status) err_exit(status, "unlock out_mutex");
            return;
        }
        /* else assume 1 == res so try again with same addr, count info */
        /* now re-acquire out mutex for balance */
        /* N.B. This re-write could now be out of write sequence */
        status = pthread_mutex_lock(&clp->out_mutex);
        if (0 != status) err_exit(status, "lock out_mutex");
    }
}

int sg_start_io(Rq_elem * rep)
{
    sg_io_hdr_t * hp = &rep->io_hdr;
    int fua = rep->wr ? (rep->fua_mode & 1) : (rep->fua_mode & 2);
    int res;

    if (sg_build_scsi_cdb(rep->cmd, rep->cdbsz, rep->num_blks, rep->blk, 
    			  rep->wr, fua, 0)) {
        fprintf(stderr, ME "bad cdb build, start_blk=%d, blocks=%d\n",
                rep->blk, rep->num_blks);
        return -1;
    }
    memset(hp, 0, sizeof(sg_io_hdr_t));
    hp->interface_id = 'S';
    hp->cmd_len = rep->cdbsz;
    hp->cmdp = rep->cmd;
    hp->dxfer_direction = rep->wr ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    hp->dxfer_len = rep->bs * rep->num_blks;
    hp->dxferp = rep->buffp;
    hp->mx_sb_len = sizeof(rep->sb);
    hp->sbp = rep->sb;
    hp->timeout = DEF_TIMEOUT;
    hp->usr_ptr = rep;
    hp->pack_id = rep->blk;
    if (rep->dio)
        hp->flags |= SG_FLAG_DIRECT_IO;
    if (rep->debug > 8) {
        fprintf(stderr, "sg_start_io: SCSI %s, blk=%d num_blks=%d\n",
               rep->wr ? "WRITE" : "READ", rep->blk, rep->num_blks);
        sg_print_command(hp->cmdp);
        fprintf(stderr, "dir=%d, len=%d, dxfrp=%p, cmd_len=%d\n",
                hp->dxfer_direction, hp->dxfer_len, hp->dxferp, hp->cmd_len);
    }

    while (((res = write(rep->wr ? rep->outfd : rep->infd, hp,
                         sizeof(sg_io_hdr_t))) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("starting io on sg device, error");
        return -1;
    }
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> try again */
int sg_finish_io(int wr, Rq_elem * rep, pthread_mutex_t * a_mutp)
{
    int res, status;
    sg_io_hdr_t io_hdr;
    sg_io_hdr_t * hp;
#if 0
    static int testing = 0;     /* thread dubious! */
#endif

    memset(&io_hdr, 0 , sizeof(sg_io_hdr_t));
    /* FORCE_PACK_ID active set only read packet with matching pack_id */
    io_hdr.interface_id = 'S';
    io_hdr.dxfer_direction = rep->wr ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    io_hdr.pack_id = rep->blk;

    while (((res = read(wr ? rep->outfd : rep->infd, &io_hdr,
                        sizeof(sg_io_hdr_t))) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        perror("finishing io on sg device, error");
        return -1;
    }
    if (rep != (Rq_elem *)io_hdr.usr_ptr)
        err_exit(0, "sg_finish_io: bad usr_ptr, request-response mismatch\n");
    memcpy(&rep->io_hdr, &io_hdr, sizeof(sg_io_hdr_t));
    hp = &rep->io_hdr;

    switch (sg_err_category3(hp)) {
        case SG_ERR_CAT_CLEAN:
            break;
        case SG_ERR_CAT_RECOVERED:
            fprintf(stderr, "Recovered error on block=%d, num=%d\n",
                    rep->blk, rep->num_blks);
            break;
        case SG_ERR_CAT_MEDIA_CHANGED:
            return 1;
        default:
            {
                char ebuff[EBUFF_SZ];

                snprintf(ebuff, EBUFF_SZ, 
			 "%s blk=%d", rep->wr ? "writing": "reading", rep->blk);
                status = pthread_mutex_lock(a_mutp);
                if (0 != status) err_exit(status, "lock aux_mutex");
                sg_chk_n_print3(ebuff, hp);
                status = pthread_mutex_unlock(a_mutp);
                if (0 != status) err_exit(status, "unlock aux_mutex");
                return -1;
            }
    }
#if 0
    if (0 == (++testing % 100)) return -1;
#endif
    if (rep->dio &&
        ((hp->info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        rep->dio_incomplete = 1; /* count dios done as indirect IO */
    else
        rep->dio_incomplete = 0;
    rep->resid = hp->resid;
    if (rep->debug > 8)
        fprintf(stderr, "sg_finish_io: completed %s\n", wr ? "WRITE" : "READ");
    return 0;
}

int sg_prepare(int fd, int bs, int bpt, int * scsi_typep)
{
    int res, t;

    res = ioctl(fd, SG_GET_VERSION_NUM, &t);
    if ((res < 0) || (t < 30000)) {
        fprintf(stderr, ME "sg driver prior to 3.x.y\n");
        return 1;
    }
    res = 0;
    t = bs * bpt;
    res = ioctl(fd, SG_SET_RESERVED_SIZE, &t);
    if (res < 0)
        perror(ME "SG_SET_RESERVED_SIZE error");
    t = 1;
    res = ioctl(fd, SG_SET_FORCE_PACK_ID, &t);
    if (res < 0)
        perror(ME "SG_SET_FORCE_PACK_ID error");
    if (scsi_typep) {
        struct sg_scsi_id info;

        res = ioctl(fd, SG_GET_SCSI_ID, &info);
        if (res < 0)
            perror(ME "SG_SET_SCSI_ID error");
        *scsi_typep = info.scsi_type;
    }
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

#define STR_SZ 1024
#define INOUTF_SZ 512


int main(int argc, char * argv[])
{
    int skip = 0;
    int seek = 0;
    int ibs = 0;
    int obs = 0;
    int count = -1;
    char str[STR_SZ];
    char * key;
    char * buf;
    char inf[INOUTF_SZ];
    char outf[INOUTF_SZ];
    int res, k;
    int in_num_sect = 0;
    int out_num_sect = 0;
    int num_threads = DEF_NUM_THREADS;
    pthread_t threads[MAX_NUM_THREADS];
    int do_time = 0;
    int do_sync = 0;
    int in_sect_sz, out_sect_sz, status, infull, outfull;
    void * vp;
    char ebuff[EBUFF_SZ];
    struct timeval start_tm, end_tm;
    Rq_coll rcoll;

    memset(&rcoll, 0, sizeof(Rq_coll));
    rcoll.bpt = DEF_BLOCKS_PER_TRANSFER;
    rcoll.in_type = FT_OTHER;
    rcoll.out_type = FT_OTHER;
    rcoll.cdbsz = DEF_SCSI_CDBSZ;
    inf[0] = '\0';
    outf[0] = '\0';
    if (argc < 2) {
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
            strncpy(inf, buf, INOUTF_SZ);
        else if (strcmp(key,"of") == 0)
            strncpy(outf, buf, INOUTF_SZ);
        else if (0 == strcmp(key,"ibs"))
            ibs = get_num(buf);
        else if (0 == strcmp(key,"obs"))
            obs = get_num(buf);
        else if (0 == strcmp(key,"bs"))
            rcoll.bs = get_num(buf);
        else if (0 == strcmp(key,"bpt"))
            rcoll.bpt = get_num(buf);
        else if (0 == strcmp(key,"skip"))
            skip = get_num(buf);
        else if (0 == strcmp(key,"seek"))
            seek = get_num(buf);
        else if (0 == strcmp(key,"count"))
            count = get_num(buf);
        else if (0 == strcmp(key,"dio"))
            rcoll.dio = get_num(buf);
        else if (0 == strcmp(key,"thr"))
            num_threads = get_num(buf);
        else if (0 == strcmp(key,"coe"))
            rcoll.coe = get_num(buf);
        else if (0 == strcmp(key,"time"))
            do_time = get_num(buf);
        else if (0 == strcmp(key,"cdbsz"))
            rcoll.cdbsz = get_num(buf);
        else if (0 == strcmp(key,"fua"))
            rcoll.fua_mode = get_num(buf);
        else if (0 == strcmp(key,"sync"))
            do_sync = get_num(buf);
        else if (0 == strncmp(key,"deb", 3))
            rcoll.debug = get_num(buf);
        else if (0 == strncmp(key, "--vers", 6)) {
            fprintf(stderr, ME "for sg version 3 driver: %s\n", 
	    	    version_str);
            return 0;
        }
        else {
            fprintf(stderr, "Unrecognized argument '%s'\n", key);
            usage();
            return 1;
        }
    }
    if (rcoll.bs <= 0) {
        rcoll.bs = DEF_BLOCK_SIZE;
        fprintf(stderr, "Assume default 'bs' (block size) of %d bytes\n",
                rcoll.bs);
    }
    if ((ibs && (ibs != rcoll.bs)) || (obs && (obs != rcoll.bs))) {
        fprintf(stderr, "If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return 1;
    }
    if ((skip < 0) || (seek < 0)) {
        fprintf(stderr, "skip and seek cannot be negative\n");
        return 1;
    }
    if ((num_threads < 1) || (num_threads > MAX_NUM_THREADS)) {
        fprintf(stderr, "too few or too many threads requested\n");
        usage();
        return 1;
    }
    if (rcoll.debug)
        fprintf(stderr, ME "if=%s skip=%d of=%s seek=%d count=%d\n",
               inf, skip, outf, seek, count);
    rcoll.infd = STDIN_FILENO;
    rcoll.outfd = STDOUT_FILENO;
    if (inf[0] && ('-' != inf[0])) {
    	rcoll.in_type = dd_filetype(inf);

        if (FT_ST == rcoll.in_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", inf);
            return 1;
        }
        else if (FT_SG == rcoll.in_type) {
            if ((rcoll.infd = open(inf, O_RDWR)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
			 ME "could not open %s for sg reading", inf);
                perror(ebuff);
                return 1;
            }
            if (sg_prepare(rcoll.infd, rcoll.bs, rcoll.bpt,
                           &rcoll.in_scsi_type))
                return 1;
        }
        else {
            if ((rcoll.infd = open(inf, O_RDONLY)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
			 ME "could not open %s for reading", inf);
                perror(ebuff);
                return 1;
            }
            else if (skip > 0) {
                llse_loff_t offset = skip;

                offset *= rcoll.bs;       /* could exceed 32 here! */
                if (llse_llseek(rcoll.infd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
			ME "couldn't skip to required position on %s", inf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
    }
    if (outf[0] && ('-' != outf[0])) {
	rcoll.out_type = dd_filetype(outf);

        if (FT_ST == rcoll.out_type) {
            fprintf(stderr, ME "unable to use scsi tape device %s\n", outf);
            return 1;
        }
        else if (FT_SG == rcoll.out_type) {
	    if ((rcoll.outfd = open(outf, O_RDWR)) < 0) {
                snprintf(ebuff,  EBUFF_SZ,
			 ME "could not open %s for sg writing", outf);
                perror(ebuff);
                return 1;
            }

	    if (sg_prepare(rcoll.outfd, rcoll.bs, rcoll.bpt,
			   &rcoll.out_scsi_type))
		return 1;
        }
	else if (FT_DEV_NULL == rcoll.out_type)
            rcoll.outfd = -1; /* don't bother opening */
	else {
	    if (FT_RAW != rcoll.out_type) {
		if ((rcoll.outfd = open(outf, O_WRONLY | O_CREAT, 0666)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for writing", outf);
                    perror(ebuff);
                    return 1;
                }
	    }
	    else {
		if ((rcoll.outfd = open(outf, O_WRONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for raw writing", outf);
                    perror(ebuff);
                    return 1;
                }
            }
            if (seek > 0) {
                llse_loff_t offset = seek;

                offset *= rcoll.bs;       /* could exceed 32 bits here! */
		if (llse_llseek(rcoll.outfd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
			ME "couldn't seek to required position on %s", outf);
                    perror(ebuff);
                    return 1;
                }
            }
	}
    }
    if ((STDIN_FILENO == rcoll.infd) && (STDOUT_FILENO == rcoll.outfd)) {
        fprintf(stderr, "Disallow both if and of to be stdin and stdout");
        return 1;
    }
    if (count < 0) {
        if (FT_SG == rcoll.in_type) {
            res = read_capacity(rcoll.infd, &in_num_sect, &in_sect_sz);
            if (2 == res) {
                fprintf(stderr, 
			"Unit attention, media changed(in), continuing\n");
                res = read_capacity(rcoll.infd, &in_num_sect, &in_sect_sz);
            }
            if (0 != res) {
                fprintf(stderr, "Unable to read capacity on %s\n", inf);
                in_num_sect = -1;
            }
            else {
                if (in_num_sect > skip)
                    in_num_sect -= skip;
            }
        }
        if (FT_SG == rcoll.out_type) {
            res = read_capacity(rcoll.outfd, &out_num_sect, &out_sect_sz);
            if (2 == res) {
                fprintf(stderr, 	
			"Unit attention, media changed(out), continuing\n");
                res = read_capacity(rcoll.outfd, &out_num_sect, &out_sect_sz);
            }
            if (0 != res) {
                fprintf(stderr, "Unable to read capacity on %s\n", outf);
                out_num_sect = -1;
            }
            else {
                if (out_num_sect > seek)
                    out_num_sect -= seek;
            }
        }
        if (in_num_sect > 0) {
            if (out_num_sect > 0)
                count = (in_num_sect > out_num_sect) ? out_num_sect :
                                                       in_num_sect;
            else
                count = in_num_sect;
        }
        else
            count = out_num_sect;
    }
    if (rcoll.debug > 1)
        fprintf(stderr, "Start of loop, count=%d, in_num_sect=%d, "
                "out_num_sect=%d\n", count, in_num_sect, out_num_sect);
    if (count < 0) {
        fprintf(stderr, "Couldn't calculate count, please give one\n");
        return 1;
    }

    rcoll.in_count = count;
    rcoll.in_done_count = count;
    rcoll.skip = skip;
    rcoll.in_blk = skip;
    rcoll.out_count = count;
    rcoll.out_done_count = count;
    rcoll.seek = seek;
    rcoll.out_blk = seek;
    status = pthread_mutex_init(&rcoll.in_mutex, NULL);
    if (0 != status) err_exit(status, "init in_mutex");
    status = pthread_mutex_init(&rcoll.out_mutex, NULL);
    if (0 != status) err_exit(status, "init out_mutex");
    status = pthread_mutex_init(&rcoll.aux_mutex, NULL);
    if (0 != status) err_exit(status, "init aux_mutex");
    status = pthread_cond_init(&rcoll.out_sync_cv, NULL);
    if (0 != status) err_exit(status, "init out_sync_cv");

    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    status = pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
    if (0 != status) err_exit(status, "pthread_sigmask");
    status = pthread_create(&sig_listen_thread_id, NULL,
                            sig_listen_thread, (void *)&rcoll);
    if (0 != status) err_exit(status, "pthread_create, sig...");

    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }

/* vvvvvvvvvvv  Start worker threads  vvvvvvvvvvvvvvvvvvvvvvvv */
    if ((rcoll.out_done_count > 0) && (num_threads > 0)) {
        /* Run 1 work thread to shake down infant retryable stuff */
        status = pthread_mutex_lock(&rcoll.out_mutex);
        if (0 != status) err_exit(status, "lock out_mutex");
        status = pthread_create(&threads[0], NULL, read_write_thread,
                                (void *)&rcoll);
        if (0 != status) err_exit(status, "pthread_create");
        if (rcoll.debug)
            fprintf(stderr, "Starting worker thread k=0\n");

        /* wait for any broadcast */
        pthread_cleanup_push(cleanup_out, (void *)&rcoll);
        status = pthread_cond_wait(&rcoll.out_sync_cv, &rcoll.out_mutex);
        if (0 != status) err_exit(status, "cond out_sync_cv");
        pthread_cleanup_pop(0);
        status = pthread_mutex_unlock(&rcoll.out_mutex);
        if (0 != status) err_exit(status, "unlock out_mutex");

        /* now start the rest of the threads */
        for (k = 1; k < num_threads; ++k) {
            status = pthread_create(&threads[k], NULL, read_write_thread,
                                    (void *)&rcoll);
            if (0 != status) err_exit(status, "pthread_create");
            if (rcoll.debug)
                fprintf(stderr, "Starting worker thread k=%d\n", k);
        }

        /* now wait for worker threads to finish */
        for (k = 0; k < num_threads; ++k) {
            status = pthread_join(threads[k], &vp);
            if (0 != status) err_exit(status, "pthread_join");
            if (rcoll.debug)
                fprintf(stderr, "Worker thread k=%d terminated\n", k);
        }
    }

    if ((do_time) && (start_tm.tv_sec || start_tm.tv_usec)) {
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
        b = (double)rcoll.bs * (count - rcoll.out_done_count);
        printf("time to transfer data was %d.%06d secs",
               (int)res_tm.tv_sec, (int)res_tm.tv_usec);
        if ((a > 0.00001) && (b > 511))
            printf(", %.2f MB/sec\n", b / (a * 1000000.0));
        else
            printf("\n");
    }
    if (do_sync) {
        if (FT_SG == rcoll.out_type) {
            fprintf(stderr, ">> Synchronizing cache on %s\n", outf);
            res = sync_cache(rcoll.outfd);
            if (2 == res) {
                fprintf(stderr,
                        "Unit attention, media changed(in), continuing\n");
                res = sync_cache(rcoll.outfd);
            }
            if (0 != res)
                fprintf(stderr, "Unable to synchronize cache\n");
        }
    }

    status = pthread_cancel(sig_listen_thread_id);
    if (0 != status) err_exit(status, "pthread_cancel");
    if (STDIN_FILENO != rcoll.infd)
        close(rcoll.infd);
    if ((STDOUT_FILENO != rcoll.outfd) && (FT_DEV_NULL != rcoll.out_type))
        close(rcoll.outfd);
    res = 0;
    if (0 != rcoll.out_count) {
        fprintf(stderr, ">>>> Some error occurred, remaining blocks=%d\n",
               rcoll.out_count);
	res = 2;
    }
    infull = count - rcoll.in_done_count -  rcoll.in_partial;
    fprintf(stderr, "%d+%d records in\n", infull, rcoll.in_partial);
    outfull = count - rcoll.out_done_count - rcoll.out_partial;
    fprintf(stderr, "%d+%d records out\n", outfull, rcoll.out_partial);
    if (rcoll.dio_incomplete) {
        int fd;
        char c;

        fprintf(stderr, ">> Direct IO requested but incomplete %d times\n",
                rcoll.dio_incomplete);
        if ((fd = open(proc_allow_dio, O_RDONLY)) >= 0) {
            if (1 == read(fd, &c, 1)) {
                if ('0' == c)
                    fprintf(stderr, ">>> %s set to '0' but should be set "
                            "to '1' for direct IO\n", proc_allow_dio);
            }
            close(fd);
        }
    } 
    if (rcoll.sum_of_resids)
        fprintf(stderr, ">> Non-zero sum of residual counts=%d\n",
               rcoll.sum_of_resids);
    return res;
}
