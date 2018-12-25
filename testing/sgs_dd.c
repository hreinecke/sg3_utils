PROPS-END
/* We need F_SETSIG, (signal redirect), so following define */
#define _GNU_SOURCE 1

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sg_lib.h"
#include "sg_linux_inc.h"
#include "sg_io_linux.h"

/* Test code for the extensions to the Linux OS SCSI generic ("sg")
 * device driver.
 * Copyright (C) 1999-2018 D. Gilbert and P. Allworth
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is a specialization of the Unix "dd" command in which
 * one or both of the given files is a scsi generic device. A block size
 * ('bs') is assumed to be 512 if not given. This program complains if
 * 'ibs' or 'obs' are given with some other value than 'bs'.
 * If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
 * not given of 'of=-' then stdout assumed. The multipliers "c, b, k, m"
 * are recognized on numeric arguments.
 *
 * A non-standard argument "bpt" (blocks per transfer) is added to control
 * the maximum number of blocks in each transfer. The default bpt value is
 * (64 * 1024 * 1024 / bs) or 1 if the first expresion is 0. That is an
 * integer division (rounds toward 0). For example if "bs=512" and "bpt=32"
 * are given then a maximum of 32 blocks (16KB in this case) are transferred
 * to or from the sg device in a single SCSI command.
 *
 * BEWARE: If the 'of' file is a 'sg' device (eg a disk) then it _will_
 * be written to, potentially destroying its previous contents.
 *
 * This version should compile with Linux sg drivers with version numbers
 * >= 30000 . Also this version also allows SIGPOLL or a RT signal to be
 * chosen. SIGIO is a synonym for SIGPOLL; SIGIO seems to be deprecated.
 */


static const char * version_str = "4.01 20181223";
static const char * my_name = "sgs_dd";

#define DEF_BLOCK_SIZE 512
#define DEF_BPT_TIMES_BS_SZ (64 * 1024) /* 64 KB */

/* #define SG_DEBUG  1          comment out if not needed */

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
    bool stop_after_wr;
    bool wr;
    int state;
    int blk;
    int num_blks;
    uint8_t * buffp;
    sg_io_hdr_t io_hdr;
    uint8_t cmd[S_RW_LEN];
    uint8_t sb[SENSE_BUFF_LEN];
    int result;
} Rq_elem;

typedef struct request_collection
{
    bool in_is_sg;
    bool out_is_sg;
    bool dio;
    bool use_rt_sig;
    int infd;
    int in_blk;                 /* most recent read */
    int in_count;               /* most recent read */
    int in_done_count;          /* count of completed in blocks */
    int in_partial;
    int outfd;
    int lowest_seek;
    int out_blk;                /* most recent write */
    int out_count;              /* most recent write */
    int out_done_count;         /* count of completed out blocks */
    int out_partial;
    int bs;
    int bpt;
    int dio_incomplete;
    int sum_of_resids;
    int debug;
    sigset_t blocked_sigs;
    int sigs_waiting;
    int sigs_rt_received;
    int sigs_io_received;
    Rq_elem * rd_posp;
    Rq_elem * wr_posp;
    Rq_elem elem[SGQ_NUM_ELEMS];
} Rq_coll;


static void
usage(void)
{
    printf("Usage: "
           "sgs_dd  [if=<ifile>] [skip=<n>] [of=<ofile>] [seek=<n>]\n"
           "               [bs=<num>] [bpt=<num>] [count=<n>]"
           " [deb=<n>] [dio=0|1]\n"
           "               [rt_sig=0|1] [--version]\n"
           "where:\n"
           "  bpt      blocks_per_transfer (default: 65536/bs (or 128 for "
           "bs=512))\n"
           "  bs       not just any block size, the logical block size of "
           "device\n"
           "  dio      direct IO, 1->attempt, 0->indirect IO (def)\n"
           "  rt_sig   0->use SIGIO (def); 1->use RT sig (SIGRTMIN + 1)\n"
           "  deb      debug: 0->no debug (def); > 0 -> more debug\n"
           "  <other operands>     as per dd command\n\n");
    printf("dd clone for testing Linux sg driver SIGPOLL and friends. Either "
           "'if' or 'of'\nmust be a scsi generic device. If 'of' not given "
           "then /dev/null assumed.\n");
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
static int
read_capacity(int sg_fd, int * num_sect, int * sect_sz)
{
    int res;
    uint8_t rcCmdBlk [10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t rcBuff[64];
    uint8_t sense_b[64];
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
    if (SG_LIB_CAT_UNIT_ATTENTION == res)
        return 2; /* probably have another go ... */
    else if (SG_LIB_CAT_CLEAN != res) {
        sg_chk_n_print3("read capacity", &io_hdr, true);
        return -1;
    }
    *num_sect = 1 + ((rcBuff[0] << 24) | (rcBuff[1] << 16) |
                (rcBuff[2] << 8) | rcBuff[3]);
    *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
               (rcBuff[6] << 8) | rcBuff[7];
#ifdef SG_DEBUG
    fprintf(stderr, "number of sectors=%d, sector size=%d\n", *num_sect,
            *sect_sz);
#endif
    return 0;
}

/* -ve -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM) */
static int
sg_start_io(Rq_coll * clp, Rq_elem * rep)
{
    sg_io_hdr_t * hp = &rep->io_hdr;
    int res;

    memset(rep->cmd, 0, sizeof(rep->cmd));
    rep->cmd[0] = rep->wr ? 0x2a : 0x28;
    rep->cmd[2] = (uint8_t)((rep->blk >> 24) & 0xFF);
    rep->cmd[3] = (uint8_t)((rep->blk >> 16) & 0xFF);
    rep->cmd[4] = (uint8_t)((rep->blk >> 8) & 0xFF);
    rep->cmd[5] = (uint8_t)(rep->blk & 0xFF);
    rep->cmd[7] = (uint8_t)((rep->num_blks >> 8) & 0xff);
    rep->cmd[8] = (uint8_t)(rep->num_blks & 0xff);
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
    fprintf(stderr, "%s: SCSI %s, blk=%d num_blks=%d\n", __func__,
           rep->wr ? "WRITE" : "READ", rep->blk, rep->num_blks);
    sg_print_command(hp->cmdp);
    fprintf(stderr, "dir=%d, len=%d, dxfrp=%p, cmd_len=%d\n",
            hp->dxfer_direction, hp->dxfer_len, hp->dxferp, hp->cmd_len);
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
        fprintf(stderr, "%s: write(): %s [%d]\n", __func__, strerror(errno),
                errno);
        rep->state = SGQ_IO_ERR;
        return res;
    }
    rep->state = SGQ_IO_STARTED;
    clp->sigs_waiting++;
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> try again */
static int
sg_finish_io(Rq_coll * clp, bool wr, Rq_elem ** repp)
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
        fprintf(stderr, "%s: read(): %s [%d]\n", __func__, strerror(errno),
                errno);
        if (rep)
            rep->state = SGQ_IO_ERR;
        return -1;
    }
    if (! (rep && (SGQ_IO_STARTED == rep->state))) {
        fprintf(stderr, "%s: bad usr_ptr\n", __func__);
        if (rep)
            rep->state = SGQ_IO_ERR;
        return -1;
    }
    memcpy(&rep->io_hdr, &io_hdr, sizeof(sg_io_hdr_t));
    hp = &rep->io_hdr;
    if (repp)
        *repp = rep;

    switch (sg_err_category3(hp)) {
        case SG_LIB_CAT_CLEAN:
            break;
        case SG_LIB_CAT_RECOVERED:
            fprintf(stderr, "Recovered error on block=%d, num=%d\n",
                   rep->blk, rep->num_blks);
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            return 1;
        default:
            sg_chk_n_print3(rep->wr ? "writing": "reading", hp, true);
            rep->state = SGQ_IO_ERR;
            return -1;
    }
    if (clp->dio &&
        ((hp->info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        ++clp->dio_incomplete; /* count dios done as indirect IO */
    clp->sum_of_resids += hp->resid;
    rep->state = SGQ_IO_FINISHED;
#ifdef SG_DEBUG
    fprintf(stderr, "%s: %s  ", __func__, wr ? "writing" : "reading");
    fprintf(stderr, "    SGQ_IO_FINISHED elem idx=%zd\n", rep - clp->elem);
#endif
    return 0;
}

static int
sz_reserve(int fd, int bs, int bpt, bool rt_sig)
{
    int res, t, flags;

    res = ioctl(fd, SG_GET_VERSION_NUM, &t);
    if ((res < 0) || (t < 30000)) {
        fprintf(stderr, "sgs_dd: sg driver prior to 3.x.y\n");
        return 1;
    }
    res = 0;
    t = bs * bpt;
    res = ioctl(fd, SG_SET_RESERVED_SIZE, &t);
    if (res < 0)
        perror("sgs_dd: SG_SET_RESERVED_SIZE error");
    if (-1 == fcntl(fd, F_SETOWN, getpid())) {
        perror("fcntl(F_SETOWN)");
        return 1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (-1 == fcntl(fd, F_SETFL, flags | O_ASYNC)) {
        perror("fcntl(F_SETFL)");
        return 1;
    }
    if (rt_sig) {       /* displaces SIGIO/SIGPOLL with SIGRTMIN + 1 */
        if (-1 == fcntl(fd, F_SETSIG, SIGRTMIN + 1))
            perror("fcntl(F_SETSIG)");
    }
    return 0;
}

static void
init_elems(Rq_coll * clp)
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
            fprintf(stderr, "out of memory creating user buffers\n");
    }
}

static int
start_read(Rq_coll * clp)
{
    int blocks = (clp->in_count > clp->bpt) ? clp->bpt : clp->in_count;
    Rq_elem * rep = clp->rd_posp;
    int buf_sz, res;
    char ebuff[EBUFF_SZ];

#ifdef SG_DEBUG
    fprintf(stderr, "%s: elem idx=%zd\n", __func__, rep - clp->elem);
#endif
    rep->wr = false;
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
            fprintf(stderr, "Reducing blocks per transfer to %d\n", clp->bpt);
            if (clp->bpt < 1)
                return -ENOMEM;
            res = sg_start_io(clp, rep);
            if (1 == res)
                res = -ENOMEM;
        }
        else if (res < 0) {
            fprintf(stderr, "sgs_dd inputting from sg failed, blk=%d\n",
                    rep->blk);
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
            rep->stop_after_wr = true;
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

static int
start_write(Rq_coll * clp)
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
    fprintf(stderr, "%s: elem idx=%zd\n", __func__, rep - clp->elem);
#endif
    rep->wr = true;
    blocks = rep->num_blks;
    rep->blk = clp->out_blk;
    clp->out_blk += blocks;
    clp->out_count -= blocks;
    if (clp->out_is_sg) {
        res = sg_start_io(clp, rep);
        if (1 == res)      /* ENOMEM, give up */
            return -ENOMEM;
        else if (res < 0) {
            fprintf(stderr, "sgs_dd output to sg failed, blk=%d\n", rep->blk);
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

/* Returns 0 if SGIO/SIGPOLL or (SIGRTMIN + 1) received, else returns negated
 * errno value; -EAGAIN for timeout. */
static int
do_sigwait(Rq_coll * clp, bool inc1_clear0)
{
    siginfo_t info;
    struct timespec ts;

    if (clp->debug > 9)
        fprintf(stderr, "%s: inc1_clear0=%d\n", __func__, (int)inc1_clear0);
    ts.tv_sec = 60;         /* 60 second timeout */
    ts.tv_nsec = 0;
    while (sigtimedwait(&clp->blocked_sigs, &info, &ts) < 0) {
        if (EINTR != errno) {
            int err = errno;

            fprintf(stderr, "%s: sigtimedwait(): %s [%d]\n", __func__,
                    strerror(err), err);        /* EAGAIN is timeout */
            return -err;        /* EAGAIN is timeout error */
        }
    }
    if ((SIGRTMIN + 1) == info.si_signo) {
        if (inc1_clear0) {
            clp->sigs_waiting--;
            clp->sigs_rt_received++;
        } else
            clp->sigs_waiting = 0;
    } else if (SIGPOLL == info.si_signo) {
        if (inc1_clear0) {
            clp->sigs_waiting--;
            clp->sigs_io_received++;
        } else
            clp->sigs_waiting = 0;
    } else {
        fprintf(stderr, "%s: sigwaitinfo() returned si_signo=%d\n",
                __func__, info.si_signo);
        return -EINVAL;
    }
    return 0;
}

/* Returns 1 on success (found), 0 on not found, -1 on error. */
static int
do_poll_for_in(Rq_coll * clp, int fd)
{
    int err;
    struct pollfd a_pollfd = {0, POLLIN | POLLOUT, 0};

    if (clp->sigs_waiting) {
        int res = do_sigwait(clp, true);

        if (res < 0)
            return res;
    }
    a_pollfd.fd = fd;
    if (poll(&a_pollfd, 1, 0) < 0) {
        err = errno;
        fprintf(stderr, "%s: poll(): %s [%d]\n", __func__, strerror(err),
                err);
        return -err;
    }
    /* fprintf(stderr, "%s: revents=0x%x\n", __func__, a_pollfd.revents); */
    return !!(a_pollfd.revents & POLLIN);
}

static int
can_read_write(Rq_coll * clp)
{
    Rq_elem * rep = NULL;
    bool writeable = false;
    int res = 0;
    int reading = 0;
    int writing = 0;
    int rd_waiting = 0;
    int wr_waiting = 0;
    int sg_finished = 0;

    /* if write completion pending, then complete it + start read */
    if (clp->out_is_sg) {
        while ((res = do_poll_for_in(clp, clp->outfd))) {
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
               rep->wr && (rep != clp->rd_posp)) {
            rep->state = SGQ_FREE;
            clp->out_done_count -= rep->num_blks;
            clp->wr_posp = rep->nextp;
            if (rep->stop_after_wr)
                return -1;
        }
    }
    else if ((rep = clp->wr_posp) && rep->wr &&
             (SGQ_IO_FINISHED == rep->state)) {
        rep->state = SGQ_FREE;
        clp->out_done_count -= rep->num_blks;
        clp->wr_posp = rep->nextp;
        if (rep->stop_after_wr)
            return -1;
    }

    /* if read completion pending, then complete it + start maybe write */
    if (clp->in_is_sg) {
        while ((res = do_poll_for_in(clp, clp->infd))) {
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
        else if ((! rep->wr) && (SGQ_IO_FINISHED == rep->state)) {
            if (res)
                writeable = true;
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
            fprintf(stderr, "%d/%d (nwb/nrb): read=%d/%d (do/wt) "
                    "write=%d/%d (do/wt) writeable=%d sg_fin=%d\n",
                    clp->out_blk, clp->in_blk, reading, rd_waiting,
                    writing, wr_waiting, (int)writeable, sg_finished);
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
        res = do_sigwait(clp, false);
        if (res < 0)
            return res;
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


int
main(int argc, char * argv[])
{
    bool bs_given = false;
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
    Rq_coll * clp = &rcoll;

    memset(clp, 0, sizeof(*clp));
    clp->bpt = 0;
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
            ibs = sg_get_num(buf);
        else if (0 == strcmp(key,"obs"))
            obs = sg_get_num(buf);
        else if (0 == strcmp(key,"bs"))
            clp->bs = sg_get_num(buf);
        else if (0 == strcmp(key,"bpt"))
            clp->bpt = sg_get_num(buf);
        else if (0 == strcmp(key,"skip"))
            skip = sg_get_num(buf);
        else if (0 == strcmp(key,"seek"))
            seek = sg_get_num(buf);
        else if (0 == strcmp(key,"count"))
            count = sg_get_num(buf);
        else if (0 == strcmp(key,"dio"))
            clp->dio = !!sg_get_num(buf);
        else if (0 == strcmp(key,"rt_sig"))
            clp->use_rt_sig = !!sg_get_num(buf);
        else if (0 == strcmp(key,"deb"))
            clp->debug = sg_get_num(buf);
        else if ((0 == strcmp(key,"-V")) || (0 == strcmp(key,"--version"))) {
            fprintf(stderr, "%s: version: %s\n", my_name, version_str);
            return 0;
        } else {
            fprintf(stderr, "Unrecognized argument '%s'\n", key);
            usage();
            return 1;
        }
    }
    if (clp->bs <= 0) {
        clp->bs = DEF_BLOCK_SIZE;
    } else
        bs_given = true;

    if ((ibs && (ibs != clp->bs)) || (obs && (obs != clp->bs))) {
        fprintf(stderr, "If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage();
        return 1;
    }
    if (clp->bpt <= 0) {
        clp->bpt = (DEF_BPT_TIMES_BS_SZ / clp->bs);
        if (0 == clp->bpt)
            clp->bpt = 1;
        if (! bs_given)
            fprintf(stderr, "Assume blocks size bs=%d [bytes] and blocks "
                    "per transfer bpt=%d\n", clp->bs, clp->bpt);
    } else if (! bs_given)
        fprintf(stderr, "Assume 'bs' (block size) of %d bytes\n", clp->bs);

    if ((skip < 0) || (seek < 0)) {
        fprintf(stderr, "skip and seek cannot be negative\n");
        return 1;
    }
#ifdef SG_DEBUG
    fprintf(stderr, "sgs_dd: if=%s skip=%d of=%s seek=%d count=%d\n",
           inf, skip, outf, seek, count);
#endif
    /* Need to block signals before SIGPOLL is enabled in sz_reserve() */
    sigemptyset(&clp->blocked_sigs);
    if (clp->use_rt_sig)
        sigaddset(&clp->blocked_sigs, SIGRTMIN + 1);
    sigaddset(&clp->blocked_sigs, SIGINT);
    sigaddset(&clp->blocked_sigs, SIGPOLL);
    sigprocmask(SIG_BLOCK, &clp->blocked_sigs, 0);

    clp->infd = STDIN_FILENO;
    clp->outfd = STDOUT_FILENO;
    if (inf[0] && ('-' != inf[0])) {
        if ((clp->infd = open(inf, O_RDONLY)) < 0) {
            snprintf(ebuff, EBUFF_SZ, "sgs_dd: could not open %s for reading",
                     inf);
            perror(ebuff);
            return 1;
        }
        if (ioctl(clp->infd, SG_GET_TIMEOUT, 0) < 0) {
            clp->in_is_sg = false;
            if (skip > 0) {
                off_t offset = skip;

                offset *= clp->bs;       /* could overflow here! */
                if (lseek(clp->infd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                "sgs_dd: couldn't skip to required position on %s", inf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
        else { /* looks like sg device so close then re-open it RW */
            close(clp->infd);
            if ((clp->infd = open(inf, O_RDWR | O_NONBLOCK)) < 0) {
                fprintf(stderr, "If %s is a sg device, need read+write "
                        "permissions, even to read it!\n", inf);
                return 1;
            }
            clp->in_is_sg = true;
            if (sz_reserve(clp->infd, clp->bs, clp->bpt, clp->use_rt_sig))
                return 1;
        }
    }
    if (outf[0] && ('-' != outf[0])) {
        if ((clp->outfd = open(outf, O_RDWR | O_NONBLOCK)) >= 0) {
            if (ioctl(clp->outfd, SG_GET_TIMEOUT, 0) < 0) {
                /* not a scsi generic device so now try and open RDONLY */
                close(clp->outfd);
            }
            else {
                clp->out_is_sg = true;
                if (sz_reserve(clp->outfd, clp->bs, clp->bpt,
                               clp->use_rt_sig))
                    return 1;
            }
        }
        if (! clp->out_is_sg) {
            if ((clp->outfd = open(outf, O_WRONLY | O_CREAT, 0666)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         "sgs_dd: could not open %s for writing", outf);
                perror(ebuff);
                return 1;
            }
            else if (seek > 0) {
                off_t offset = seek;

                offset *= clp->bs;       /* could overflow here! */
                if (lseek(clp->outfd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                "sgs_dd: couldn't seek to required position on %s", outf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
    } else if ('\0' == outf[0]) {
        if (STDIN_FILENO == clp->infd) {
            fprintf(stderr, "Can't have both 'if' as stdin _and_ 'of' as "
                    "/dev/null\n");
            return 1;
        }
        clp->outfd = open("/dev/null", O_RDWR);
        if (clp->outfd < 0) {
            perror("sgs_dd: could not open /dev/null");
            return 1;
        }
        clp->out_is_sg = false;
        /* ignore any seek */
    } else {    /* must be '-' for stdout */
        if (STDIN_FILENO == clp->infd) {
            fprintf(stderr, "Can't have both 'if' as stdin _and_ 'of' as "
                    "stdout\n");
            return 1;
        }
    }
    if (0 == count)
        return 0;
    else if (count < 0) {
        if (clp->in_is_sg) {
            res = read_capacity(clp->infd, &in_num_sect, &in_sect_sz);
            if (2 == res) {
                fprintf(stderr, "Unit attention, media changed(in), try "
                        "again\n");
                res = read_capacity(clp->infd, &in_num_sect, &in_sect_sz);
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
        if (clp->out_is_sg) {
            res = read_capacity(clp->outfd, &out_num_sect, &out_sect_sz);
            if (2 == res) {
                fprintf(stderr, "Unit attention, media changed(out), try "
                        "again\n");
                res = read_capacity(clp->outfd, &out_num_sect, &out_sect_sz);
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
#ifdef SG_DEBUG
        fprintf(stderr, "Start of loop, count=%d, in_num_sect=%d, "
                "out_num_sect=%d\n", count, in_num_sect, out_num_sect);
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
    fprintf(stderr, "Start of loop, count=%d, bpt=%d\n", count, clp->bpt);
#endif

    clp->in_count = count;
    clp->in_done_count = count;
    clp->in_blk = skip;
    clp->out_count = count;
    clp->out_done_count = count;
    clp->out_blk = seek;
    init_elems(clp);

/* vvvvvvvvvvvvvvvvv  Main Loop  vvvvvvvvvvvvvvvvvvvvvvvv */
    while (clp->out_done_count > 0) {
        crw = can_read_write(clp);
        if (crw < 0)
            break;
        if (SGQ_CAN_READ & crw) {
            res = start_read(clp);
            if (res <= 0) {
                fprintf(stderr, "start_read: res=%d\n", res);
                break;
            }
        }
        if (SGQ_CAN_WRITE & crw) {
            res = start_write(clp);
            if (res <= 0) {
                fprintf(stderr, "start_write: res=%d\n", res);
                break;
            }
        }
    }

    if (STDIN_FILENO != clp->infd)
        close(clp->infd);
    if (STDOUT_FILENO != clp->outfd)
        close(clp->outfd);
    if (0 != clp->out_count) {
        fprintf(stderr, "Some error occurred, remaining blocks=%d\n",
                clp->out_count);
        return 1;
    }
    fprintf(stderr, "%d+%d records in\n", count - clp->in_done_count,
           clp->in_partial);
    fprintf(stderr, "%d+%d records out\n", count - clp->out_done_count,
           clp->out_partial);
    if (clp->dio_incomplete)
        fprintf(stderr, ">> Direct IO requested but incomplete %d times\n",
               clp->dio_incomplete);
    if (clp->sum_of_resids)
        fprintf(stderr, ">> Non-zero sum of residual counts=%d\n",
               clp->sum_of_resids);
    if (clp->debug > 0)
        fprintf(stderr, "SIGIO/SIGPOLL signals received: %d, RT sigs: %d\n",
               clp->sigs_io_received, clp->sigs_rt_received);
    return 0;
}
