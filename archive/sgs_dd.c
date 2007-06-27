/* We need F_SETSIG, (signal redirect), so following define */
#define _GNU_SOURCE 1

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_err.h"

/* Test code for the extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999 D. Gilbert and P. Allworth
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program is a specialization of the Unix "dd" command in which
   one or both of the given files is a scsi generic device. A block size
   ('bs') is assumed to be 512 if not given. This program complains if
   'ibs' or 'obs' are given with some other value than 'bs'.
   If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
   not given of 'of=-' then stdout assumed. The multipliers "c, b, k, m"
   are recognized on numeric arguments.

   A non-standard argument "bpt" (blocks per transfer) is added to control
   the maximum number of blocks in each transfer. The default value is 128.
   For example if "bs=512" and "bpt=32" then a maximum of 32 blocks (16KB
   in this case) are transferred to or from the sg device in a single SCSI
   command.

   BEWARE: If the 'of' file is a 'sg' device (eg a disk) then it _will_
   be written to, potentially destroying its previous contents.

   This version should compile with Linux sg drivers with version numbers
   >= 30000 . Also this version tries to use real time signals.

   Version 3.99 20020126


6 byte commands [READ: 0x08, WRITE: 0x0a]:
[cmd ][had|lu][midAdd][lowAdd][count ][flags ]
10 byte commands [EREAD: 0x28, EWRITE: 0x2a, READ_CAPACITY 0x25]:
[cmd ][   |lu][hiAddr][hmAddr][lmAddr][lowAdd][      ][hiCnt ][lowCnt][flags ]
12 byte commands [LREAD: 0xd8, LWRITE: 0xda]:
[cmd ][   |lu][hiAddr][hmAddr][lmAddr][lowAdd][hiCnt ][hmCnt ][lmCnt ][lowCnt]
 ... [      ][flags ]
*/

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 40000       /* 40,000 millisecs == 40 seconds */
#define S_RW_LEN 10             /* Use SCSI READ(10) and WRITE(10) */
#define SGQ_MAX_RD_AHEAD 4
#define SGQ_MAX_WR_AHEAD 4
#define SGQ_NUM_ELEMS (SGQ_MAX_RD_AHEAD+ SGQ_MAX_WR_AHEAD + 1)

#define SGQ_FREE 0
#define SGQ_IO_STARTED 1
#define SGQ_IO_FINISHED 2
#define SGQ_IO_ERR 3
#define SGQ_IO_WAIT 4

#define SGQ_CAN_DO_NOTHING 0    /* only temporarily in use */
#define SGQ_CAN_READ 1
#define SGQ_CAN_WRITE 2
#define SGQ_TIMEOUT 4


#define STR_SZ 1024
#define INOUTF_SZ 512
#define EBUFF_SZ 512


typedef struct request_element
{
    struct request_element * nextp;
    int state;
    int wr;
    int blk;
    int num_blks;
    unsigned char * buffp;
    sg_io_hdr_t io_hdr;
    unsigned char cmd[S_RW_LEN];
    unsigned char sb[SENSE_BUFF_LEN];
    int result;
    int stop_after_wr;
} Rq_elem;

typedef struct request_collection
{
    int infd;
    int in_is_sg;
    int in_blk;                 /* most recent read */
    int in_count;               /* most recent read */
    int in_done_count;          /* count of completed in blocks */
    int in_partial;
    int outfd;
    int out_is_sg;
    int lowest_seek;
    int out_blk;                /* most recent write */
    int out_count;              /* most recent write */
    int out_done_count;         /* count of completed out blocks */
    int out_partial;
    int bs;
    int bpt;
    int dio;
    int dio_incomplete;
    int sum_of_resids;
    int debug;
    sigset_t blocked_sigs;
    int sigs_waiting;
    Rq_elem * rd_posp;
    Rq_elem * wr_posp;
    Rq_elem elem[SGQ_NUM_ELEMS];
} Rq_coll;


void usage()
{
    printf("Usage: "
           "sgs_dd  [if=<infile>] [skip=<n>] [of=<ofile>] [seek=<n>]\n"
           "              [bs=<num>] [bpt=<num>] [count=<n>]"
           " [dio=<n>] [deb=<n>]\n"
           "            either 'if' or 'of' must be a scsi generic device\n"
           " 'bpt' is blocks_per_transfer (default is 128)\n"
           " 'dio' is direct IO, 1->attempt, 0->indirect IO (def)\n"
           " 'deb' is debug, 1->output some, 0->no debug (def)\n");
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
int read_capacity(int sg_fd, int * num_sect, int * sect_sz)
{
    int res;
    unsigned char rcCmdBlk [10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
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
    printf("number of sectors=%d, sector size=%d\n", *num_sect, *sect_sz);
#endif
    return 0;
}

/* -ve -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM) */
int sg_start_io(Rq_coll * clp, Rq_elem * rep)
{
    sg_io_hdr_t * hp = &rep->io_hdr;
    int res;

    memset(rep->cmd, 0, sizeof(rep->cmd));
    rep->cmd[0] = rep->wr ? 0x2a : 0x28;
    rep->cmd[2] = (unsigned char)((rep->blk >> 24) & 0xFF);
    rep->cmd[3] = (unsigned char)((rep->blk >> 16) & 0xFF);
    rep->cmd[4] = (unsigned char)((rep->blk >> 8) & 0xFF);
    rep->cmd[5] = (unsigned char)(rep->blk & 0xFF);
    rep->cmd[7] = (unsigned char)((rep->num_blks >> 8) & 0xff);
    rep->cmd[8] = (unsigned char)(rep->num_blks & 0xff);
    memset(hp, 0, sizeof(sg_io_hdr_t));
    hp->interface_id = 'S';
    hp->cmd_len = sizeof(rep->cmd);
    hp->cmdp = rep->cmd;
    hp->dxfer_direction = rep->wr ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    hp->dxfer_len = clp->bs * rep->num_blks;
    hp->dxferp = rep->buffp;
    hp->mx_sb_len = sizeof(rep->sb);
    hp->sbp = rep->sb;
    hp->timeout = DEF_TIMEOUT;
    hp->usr_ptr = rep;
    hp->pack_id = rep->blk;
    if (clp->dio)
        hp->flags |= SG_FLAG_DIRECT_IO;
#ifdef SG_DEBUG
    printf("sg_start_io: SCSI %s, blk=%d num_blks=%d\n", 
           rep->wr ? "WRITE" : "READ", rep->blk, rep->num_blks);
    sg_print_command(hp->cmdp);
    printf("dir=%d, len=%d, dxfrp=%p, cmd_len=%d\n", hp->dxfer_direction,
           hp->dxfer_len, hp->dxferp, hp->cmd_len);
#endif

    while (((res = write(rep->wr ? clp->outfd : clp->infd, hp,
                         sizeof(sg_io_hdr_t))) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        if ((EDOM == errno) || (EAGAIN == errno)) {
            rep->state = SGQ_IO_WAIT;   /* busy so wait */
            return 0;
        }
        perror("starting io on sg device, error");
        rep->state = SGQ_IO_ERR;
        return res;
    }
    rep->state = SGQ_IO_STARTED;
    clp->sigs_waiting++;
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> try again */
int sg_finish_io(Rq_coll * clp, int wr, Rq_elem ** repp)
{
    int res;
    sg_io_hdr_t io_hdr;
    sg_io_hdr_t * hp;
    Rq_elem * rep;

    memset(&io_hdr, 0 , sizeof(sg_io_hdr_t));
    while (((res = read(wr ? clp->outfd : clp->infd, &io_hdr,
                        sizeof(sg_io_hdr_t))) < 0) && (EINTR == errno))
        ;
    rep = (Rq_elem *)io_hdr.usr_ptr;
    if (res < 0) {
        perror("finishing io on sg device, error");
        rep->state = SGQ_IO_ERR;
        return -1;
    }
    if (! (rep && (SGQ_IO_STARTED == rep->state))) {
        printf("sg_finish_io: bad usr_ptr\n");
        rep->state = SGQ_IO_ERR;
        return -1;
    }
    memcpy(&rep->io_hdr, &io_hdr, sizeof(sg_io_hdr_t));
    hp = &rep->io_hdr;
    if (repp)
        *repp = rep;

    switch (sg_err_category3(hp)) {
        case SG_ERR_CAT_CLEAN:
            break;
        case SG_ERR_CAT_RECOVERED:
            printf("Recovered error on block=%d, num=%d\n",
                   rep->blk, rep->num_blks);
            break;
        case SG_ERR_CAT_MEDIA_CHANGED:
            return 1;
        default:
            sg_chk_n_print3(rep->wr ? "writing": "reading", hp);
            rep->state = SGQ_IO_ERR;
            return -1;
    }
    if (clp->dio &&
        ((hp->info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        ++clp->dio_incomplete; /* count dios done as indirect IO */
    clp->sum_of_resids += hp->resid;
    rep->state = SGQ_IO_FINISHED;
#ifdef SG_DEBUG
    printf("sg_finish_io: %s  ", wr ? "writing" : "reading");
    printf("    SGQ_IO_FINISHED elem idx=%d\n", rep - clp->elem);
#endif
    return 0;
}

int sz_reserve(int fd, int bs, int bpt)
{
    int res, t, flags;

    res = ioctl(fd, SG_GET_VERSION_NUM, &t);
    if ((res < 0) || (t < 30000)) {
        printf("sgs_dd: sg driver prior to 3.x.y\n");
        return 1;
    }
    res = 0;
    t = bs * bpt;
    res = ioctl(fd, SG_SET_RESERVED_SIZE, &t);
    if (res < 0)
        perror("sgs_dd: SG_SET_RESERVED_SIZE error");
    if (-1 == fcntl(fd, F_SETOWN, getpid())) {
        perror("fcntl(,F_SETOWN,)");
        return 1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (-1 == fcntl(fd, F_SETFL, flags | O_ASYNC)) {
        perror("fcntl(,F_SETFL,)");
        return 1;
    }
    fcntl(fd, F_SETSIG, SIGRTMIN + 1);
    return 0;
}

int get_num(char * buf)
{
    int res, num;
    char c, cc;

    res = sscanf(buf, "%d%c", &num, &c);
    if (0 == res)
        return -1;
    else if (1 == res)
        return num;
    else {
        cc = (char)toupper(c);
        if ('B' == cc)
            return num * 512;
        else if ('C' == cc)
            return num;
        else if ('K' == cc)
            return num * 1024;
        else if ('M' == cc)
            return num * 1024 * 1024;
        else {
            printf("unrecognized multiplier\n");
            return -1;
        }
    }
}

void init_elems(Rq_coll * clp)
{
    Rq_elem * rep;
    int k;

    clp->wr_posp = &clp->elem[0]; /* making ring buffer */
    clp->rd_posp = clp->wr_posp;
    for (k = 0; k < SGQ_NUM_ELEMS - 1; ++k)
        clp->elem[k].nextp = &clp->elem[k + 1];
    clp->elem[SGQ_NUM_ELEMS - 1].nextp = &clp->elem[0];
    for (k = 0; k < SGQ_NUM_ELEMS; ++k) {
        rep = &clp->elem[k];
        rep->state = SGQ_FREE;
        if (NULL == (rep->buffp = malloc(clp->bpt * clp->bs)))
            printf("out of memory creating user buffers\n");
    }
}

int start_read(Rq_coll * clp)
{
    int blocks = (clp->in_count > clp->bpt) ? clp->bpt : clp->in_count;
    Rq_elem * rep = clp->rd_posp;
    int buf_sz, res;
    char ebuff[EBUFF_SZ];

#ifdef SG_DEBUG
    printf("start_read, elem idx=%d\n", rep - clp->elem);
#endif
    rep->wr = 0;
    rep->blk = clp->in_blk;
    rep->num_blks = blocks;
    clp->in_blk += blocks;
    clp->in_count -= blocks;
    if (clp->in_is_sg) {
        res = sg_start_io(clp, rep);
        if (1 == res) {     /* ENOMEM, find what's available+try that */
            if ((res = ioctl(clp->infd, SG_GET_RESERVED_SIZE, &buf_sz)) < 0) {
                perror("RESERVED_SIZE ioctls failed");
                return res;
            }
            clp->bpt = (buf_sz + clp->bs - 1) / clp->bs;
            printf("Reducing blocks per transfer to %d\n", clp->bpt);
            if (clp->bpt < 1)
                return -ENOMEM;
            res = sg_start_io(clp, rep);
            if (1 == res)
                res = -ENOMEM;
        }
        else if (res < 0) {
            printf("sgs_dd inputting from sg failed, blk=%d\n", rep->blk);
            rep->state = SGQ_IO_ERR;
            return res;
        }
    }
    else {
        rep->state = SGQ_IO_STARTED;
        while (((res = read(clp->infd, rep->buffp, blocks * clp->bs)) < 0) &&
               (EINTR == errno))
            ;
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, "sgs_dd: reading, in_blk=%d ", rep->blk);
            perror(ebuff);
            rep->state = SGQ_IO_ERR;
            return res;
        }
        if (res < blocks * clp->bs) {
            int o_blocks = blocks;
            rep->stop_after_wr = 1;
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
        rep->state = SGQ_IO_FINISHED;
    }
    clp->rd_posp = rep->nextp;
    return blocks;
}

int start_write(Rq_coll * clp)
{
    Rq_elem * rep = clp->wr_posp;
    int res, blocks;
    char ebuff[EBUFF_SZ];

    while ((0 != rep->wr) || (SGQ_IO_FINISHED != rep->state)) {
        rep = rep->nextp;
        if (rep == clp->rd_posp)
            return -1;
    }
#ifdef SG_DEBUG
    printf("start_write, elem idx=%d\n", rep - clp->elem);
#endif
    rep->wr = 1;
    blocks = rep->num_blks;
    rep->blk = clp->out_blk;
    clp->out_blk += blocks;
    clp->out_count -= blocks;
    if (clp->out_is_sg) {
        res = sg_start_io(clp, rep);
        if (1 == res)      /* ENOMEM, give up */
            return -ENOMEM;
        else if (res < 0) {
            printf("sgs_dd output to sg failed, blk=%d\n", rep->blk);
            rep->state = SGQ_IO_ERR;
            return res;
        }
    }
    else {
        rep->state = SGQ_IO_STARTED;
        while (((res = write(clp->outfd, rep->buffp,
                     rep->num_blks * clp->bs)) < 0) && (EINTR == errno))
            ;
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, "sgs_dd: output, out_blk=%d ", rep->blk);
            perror(ebuff);
            rep->state = SGQ_IO_ERR;
            return res;
        }
        if (res < blocks * clp->bs) {
            blocks = res / clp->bs;
            if ((res % clp->bs) > 0) {
                blocks++;
                clp->out_partial++;
            }
            rep->num_blks = blocks;
        }
        rep->state = SGQ_IO_FINISHED;
    }
    return blocks;
}

int do_poll(Rq_coll * clp, int fd)
{
    struct pollfd a_pollfd = {0, POLLIN | POLLOUT, 0};
    siginfo_t info;

    a_pollfd.fd = fd;
    if (poll(&a_pollfd, 1, 0) < 0) {
        perror("poll error");
        return 0;
    }
    /* printf("do_poll: revents=0x%x\n", (int)a_pollfd.revents); */
    if (a_pollfd.revents & POLLIN) {
        if (clp->sigs_waiting) {
            while (sigwaitinfo(&clp->blocked_sigs, &info) < 0) {
                if (EINTR != errno) {
                    perror("sigwaitinfo"); /* consume signal */
                    return -1;
                }
            }
            if ((SIGRTMIN + 1) == info.si_signo)
                clp->sigs_waiting--;
            if (SIGIO == info.si_signo) {
                printf("SIGIO received, continue\n");
                clp->sigs_waiting = 0;
            }
            else
                return -1;
        }
        return 1;
    }
    else
        return 0;
}

int can_read_write(Rq_coll * clp)
{
    Rq_elem * rep = NULL;
    int res = 0;
    int reading = 0;
    int writing = 0;
    int writeable = 0;
    int rd_waiting = 0;
    int wr_waiting = 0;
    int sg_finished = 0;
    siginfo_t info;

    /* if write completion pending, then complete it + start read */
    if (clp->out_is_sg) {
        while ((res = do_poll(clp, clp->outfd))) {
            if (res < 0)
                return res;
            res = sg_finish_io(clp, 1, &rep);
            if (res < 0)
                return res;
            else if (1 == res) {
                res = sg_start_io(clp, rep);
                if (0 != res)
                    return -1;  /* give up if any problems with retry */
            }
            else 
                sg_finished++;
        }
        while ((rep = clp->wr_posp) && (SGQ_IO_FINISHED == rep->state) &&
               (1 == rep->wr) && (rep != clp->rd_posp)) {
            rep->state = SGQ_FREE;
            clp->out_done_count -= rep->num_blks;
            clp->wr_posp = rep->nextp;
            if (rep->stop_after_wr)
                return -1;
        }
    }
    else if ((rep = clp->wr_posp) && (1 == rep->wr) &&
             (SGQ_IO_FINISHED == rep->state)) {
        rep->state = SGQ_FREE;
        clp->out_done_count -= rep->num_blks;
        clp->wr_posp = rep->nextp;
        if (rep->stop_after_wr)
            return -1;
    }

    /* if read completion pending, then complete it + start maybe write */
    if (clp->in_is_sg) {
        while ((res = do_poll(clp, clp->infd))) {
            if (res < 0)
                return res;
            res = sg_finish_io(clp, 0, &rep);
            if (res < 0)
                return res;
            if (1 == res) {
                res = sg_start_io(clp, rep);
                if (0 != res)
                    return -1;  /* give up if any problems with retry */
            }
            else {
                sg_finished++;
                clp->in_done_count -= rep->num_blks;
            }
        }
    }

    for (rep = clp->wr_posp, res = 1;
         rep != clp->rd_posp; rep = rep->nextp) {
        if (SGQ_IO_STARTED == rep->state) {
            if (rep->wr)
                ++writing;
            else {
                res = 0;
                ++reading;
            }
        }
        else if ((0 == rep->wr) && (SGQ_IO_FINISHED == rep->state)) {
            if (res)
                writeable = 1;
        }
        else if (SGQ_IO_WAIT == rep->state) {
            res = 0;
            if (rep->wr)
                ++wr_waiting;
            else
                ++rd_waiting;
        }
        else
            res = 0;
    }
    if (clp->debug) {
        if ((clp->debug >= 9) || wr_waiting || rd_waiting)
            printf("%d/%d (nwb/nrb): read=%d/%d (do/wt) "
                   "write=%d/%d (do/wt) writeable=%d sg_fin=%d\n",
                   clp->out_blk, clp->in_blk, reading, rd_waiting, 
                   writing, wr_waiting, writeable, sg_finished);
            fflush(stdout);
    }
    if (writeable && (writing < SGQ_MAX_WR_AHEAD) && (clp->out_count > 0))
        return SGQ_CAN_WRITE;
    if ((reading < SGQ_MAX_RD_AHEAD) && (clp->in_count > 0) &&
        (0 == rd_waiting) && (clp->rd_posp->nextp != clp->wr_posp))
        return SGQ_CAN_READ;

    if (clp->out_done_count <= 0)
        return SGQ_CAN_DO_NOTHING;
        
    /* usleep(10000); */      /* hang about for 10 milliseconds */
    if (clp->sigs_waiting) {
        while (sigwaitinfo(&clp->blocked_sigs, &info) < 0) {
            if (EINTR != errno) {
                perror("sigwaitinfo"); /* consume signal */
                return -1;
            }
        }
        if ((SIGRTMIN + 1) != info.si_signo)
            return -1;
        clp->sigs_waiting--;
    }
    /* Now check the _whole_ buffer for pending requests */
    for (rep = clp->rd_posp->nextp; rep != clp->rd_posp; rep = rep->nextp) {
        if (SGQ_IO_WAIT == rep->state) {
            res = sg_start_io(clp, rep);
            if (res < 0)
                return res;
            if (res > 0)
                return -1;
            break;
        }
    }
    return SGQ_CAN_DO_NOTHING;
}


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
    int in_sect_sz, out_sect_sz, crw;
    char ebuff[EBUFF_SZ];
    Rq_coll rcoll;

    memset(&rcoll, 0, sizeof(Rq_coll));
    rcoll.bpt = DEF_BLOCKS_PER_TRANSFER;
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
        else if (0 == strcmp(key,"deb"))
            rcoll.debug = get_num(buf);
        else {
            printf("Unrecognized argument '%s'\n", key);
            usage();
            return 1;
        }
    }
    if (rcoll.bs <= 0) {
        rcoll.bs = DEF_BLOCK_SIZE;
        printf("Assume default 'bs' (block size) of %d bytes\n", rcoll.bs);
    }
    if ((ibs && (ibs != rcoll.bs)) || (obs && (obs != rcoll.bs))) {
        printf("If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return 1;
    }
    if ((skip < 0) || (seek < 0)) {
        printf("skip and seek cannot be negative\n");
        return 1;
    }
#ifdef SG_DEBUG
    printf("sgs_dd: if=%s skip=%d of=%s seek=%d count=%d\n",
           inf, skip, outf, seek, count);
#endif
    rcoll.infd = STDIN_FILENO;
    rcoll.outfd = STDOUT_FILENO;
    if (inf[0] && ('-' != inf[0])) {
        if ((rcoll.infd = open(inf, O_RDONLY)) < 0) {
            snprintf(ebuff, EBUFF_SZ, "sgs_dd: could not open %s for reading",
	    	     inf);
            perror(ebuff);
            return 1;
        }
        if (ioctl(rcoll.infd, SG_GET_TIMEOUT, 0) < 0) {
            rcoll.in_is_sg = 0;
            if (skip > 0) {
                off_t offset = skip;

                offset *= rcoll.bs;       /* could overflow here! */
                if (lseek(rcoll.infd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                "sgs_dd: couldn't skip to required position on %s", inf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
        else { /* looks like sg device so close then re-open it RW */
            close(rcoll.infd);
            if ((rcoll.infd = open(inf, O_RDWR | O_NONBLOCK)) < 0) {
                printf("If %s is a sg device, need read+write permissions,"
                       " even to read it!\n", inf);
                return 1;
            }
            rcoll.in_is_sg = 1;
            if (sz_reserve(rcoll.infd, rcoll.bs, rcoll.bpt))
                return 1;
        }
    }
    if (outf[0] && ('-' != outf[0])) {
        if ((rcoll.outfd = open(outf, O_RDWR | O_NONBLOCK)) >= 0) {
            if (ioctl(rcoll.outfd, SG_GET_TIMEOUT, 0) < 0) {
                /* not a scsi generic device so now try and open RDONLY */
                close(rcoll.outfd);
            }
            else {
                rcoll.out_is_sg = 1;
                if (sz_reserve(rcoll.outfd, rcoll.bs, rcoll.bpt))
                    return 1;
            }
        }
        if (! rcoll.out_is_sg) {
            if ((rcoll.outfd = open(outf, O_WRONLY | O_CREAT, 0666)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         "sgs_dd: could not open %s for writing", outf);
                perror(ebuff);
                return 1;
            }
            else if (seek > 0) {
                off_t offset = seek;

                offset *= rcoll.bs;       /* could overflow here! */
                if (lseek(rcoll.outfd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                "sgs_dd: couldn't seek to required position on %s", outf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
    }
    if ((STDIN_FILENO == rcoll.infd) && (STDOUT_FILENO == rcoll.outfd)) {
        printf("Can't have both 'if' as stdin _and_ 'of' as stdout\n");
        return 1;
    }
    if (! (rcoll.in_is_sg || rcoll.out_is_sg)) {
        printf("Either 'if' or 'of' must be a scsi generic device\n");
        return 1;
    }
    if (0 == count)
        return 0;
    else if (count < 0) {
        if (rcoll.in_is_sg) {
            res = read_capacity(rcoll.infd, &in_num_sect, &in_sect_sz);
            if (2 == res) {
                printf("Unit attention, media changed(in), try again\n");
                res = read_capacity(rcoll.infd, &in_num_sect, &in_sect_sz);
            }
            if (0 != res) {
                printf("Unable to read capacity on %s\n", inf);
                in_num_sect = -1;
            }
            else {
                if (in_num_sect > skip)
                    in_num_sect -= skip;
            }
        }
        if (rcoll.out_is_sg) {
            res = read_capacity(rcoll.outfd, &out_num_sect, &out_sect_sz);
            if (2 == res) {
                printf("Unit attention, media changed(out), try again\n");
                res = read_capacity(rcoll.outfd, &out_num_sect, &out_sect_sz);
            }
            if (0 != res) {
                printf("Unable to read capacity on %s\n", outf);
                out_num_sect = -1;
            }
            else {
                if (out_num_sect > seek)
                    out_num_sect -= seek;
            }
        }
#ifdef SG_DEBUG
        printf("Start of loop, count=%d, in_num_sect=%d, out_num_sect=%d\n",
               count, in_num_sect, out_num_sect);
#endif
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

#ifdef SG_DEBUG
    printf("Start of loop, count=%d, bpt=%d\n", count, rcoll.bpt);
#endif

    sigemptyset(&rcoll.blocked_sigs);
    sigaddset(&rcoll.blocked_sigs, SIGRTMIN + 1);
    sigaddset(&rcoll.blocked_sigs, SIGINT);
    sigaddset(&rcoll.blocked_sigs, SIGIO);
    sigprocmask(SIG_BLOCK, &rcoll.blocked_sigs, 0);
    rcoll.in_count = count;
    rcoll.in_done_count = count;
    rcoll.in_blk = skip;
    rcoll.out_count = count;
    rcoll.out_done_count = count;
    rcoll.out_blk = seek;
    init_elems(&rcoll);

/* vvvvvvvvvvvvvvvvv  Main Loop  vvvvvvvvvvvvvvvvvvvvvvvv */
    while (rcoll.out_done_count > 0) {
        crw = can_read_write(&rcoll);
        if (crw < 0)
            break;
        if (SGQ_CAN_READ & crw) {
            res = start_read(&rcoll);
            if (res <= 0) {
                printf("start_read: res=%d\n", res);
                break;
            }
        }
        if (SGQ_CAN_WRITE & crw) {
            res = start_write(&rcoll);
            if (res <= 0) {
                printf("start_write: res=%d\n", res);
                break;
            }
        }
    }

    if (STDIN_FILENO != rcoll.infd)
        close(rcoll.infd);
    if (STDOUT_FILENO != rcoll.outfd)
        close(rcoll.outfd);
    if (0 != rcoll.out_count) {
        printf("Some error occurred, remaining blocks=%d\n", rcoll.out_count);
        return 1;
    }
    printf("%d+%d records in\n", count - rcoll.in_done_count, 
           rcoll.in_partial);
    printf("%d+%d records out\n", count - rcoll.out_done_count,
           rcoll.out_partial);
    if (rcoll.dio_incomplete)
        printf(">> Direct IO requested but incomplete %d times\n",
               rcoll.dio_incomplete);
    if (rcoll.sum_of_resids)
        printf(">> Non-zero sum of residual counts=%d\n",
               rcoll.sum_of_resids);
    return 0;
}
