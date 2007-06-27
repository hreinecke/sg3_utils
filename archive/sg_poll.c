#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "sg_include.h"
#include "sg_err.h"

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999-2001 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program tests out asynchronous parts of the 'sg' device driver.
   It only uses the SCSI read command on the 'sg' device.
   This program performs unbalanced, non-polling "write-write-read"
   sequences. Asynchronous notification is turned on and signals are
   counted. Due to the imbalance, when the close() is executed there
   are several packets still to be read() [some of which may not yet
   be awaiting a read()]. This tests how the device driver cleans up
   after an unexpected close().
   If the "-deb" flag is given then outputs state to console/log
   (for all active sg devices).

   Version 0.76 20010112
*/


/*
6 byte commands [READ: 0x08, WRITE: 0x0a]:
[cmd ][had|lu][midAdd][lowAdd][count ][flags ]
10 byte commands [EREAD: 0x28, EWRITE: 0x2a, READ_CAPACITY 0x25]:
[cmd ][   |lu][hiAddr][hmAddr][lmAddr][lowAdd][      ][hiCnt ][lowCnt][flags ]
12 byte commands [LREAD: 0xd8, LWRITE: 0xda]:
[cmd ][   |lu][hiAddr][hmAddr][lmAddr][lowAdd][hiCnt ][hmCnt ][lmCnt ][lowCnt]
 ... [      ][flags ]
*/
        
#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
    /* union semun is defined by including <sys/sem.h> */
#else
    /* according to X/OPEN we have to define it ourselves */
union semun {
    int val;                    /* value for SETVAL */
    struct semid_ds *buf;       /* buffer for IPC_STAT, IPC_SET */
    unsigned short int *array;  /* array for GETALL, SETALL */
    struct seminfo *__buf;      /* buffer for IPC_INFO */
};
#endif

#ifdef O_ASYNC
#define MY_ASYNC O_ASYNC
#else
#define MY_ASYNC FASYNC
#endif


// #define SG_DEBUG

#define OFF sizeof(struct sg_header)
// #define NUM_SECTORS 7777
// #define NUM_SECTORS 577
// #define NUM_SECTORS 97
#define NUM_SECTORS 150
#define BLOCK_SIZE 2048

volatile int hand_count = 0;
volatile int signo = 0;
volatile int poll_res = 0;
volatile short revents = 0;
volatile int sg_fd = 0;
int semset_id = 0;

int do_poll()
{
    struct pollfd a_pollfd = {0, POLLIN | POLLOUT, 0};

    a_pollfd.fd = sg_fd;
    if ((poll_res = poll(&a_pollfd, 1, 0)) < 0) {
        perror("poll error");
        return 0;
    }
    revents = a_pollfd.revents;
    return (a_pollfd.revents & POLLIN) ? 1 : 0;
}

void sg_sa_handler(int sig, siginfo_t *si, void * data)
{
    signo = sig;
    if (SIGRTMIN != sig)
    	fprintf(stderr, "Unexpected signal, signum=%d\n", sig);
    if (sg_fd != si->si_fd)
    	fprintf(stderr, "Unexpected fd, fd=%d\n", si->si_fd);
    ++hand_count;
    if (do_poll()) {
        struct sembuf a_sembuf;

        a_sembuf.sem_num = 0;
        a_sembuf.sem_op = 1;
        a_sembuf.sem_flg = 0;
        if (semop(semset_id, &a_sembuf, 1) < 0)
            perror("semop(sh) error");
    }
}

int main(int argc, char * argv[])
{
    int flags;
    int res;
    int k;
    unsigned char rdCmdBlk [10] = {0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char * rdBuff = malloc(OFF + sizeof(rdCmdBlk) + 
                                    (BLOCK_SIZE * NUM_SECTORS));
    unsigned char * rdBuff2 = malloc(OFF + sizeof(rdCmdBlk) + 
                                    (BLOCK_SIZE * NUM_SECTORS));
    int rdInLen = OFF + sizeof(rdCmdBlk);
    int rdOutLen;
    unsigned char * rdCmd = rdBuff + OFF;
    unsigned char * rdCmd2 = rdBuff + OFF;
    struct sg_header * rsghp = (struct sg_header *)rdBuff;
    struct sg_header * rsghp2 = (struct sg_header *)rdBuff2;
    int sectorNo = 10000;
    int sectorNo2;
    int numSectors = NUM_SECTORS;
    const int times = 3;
    struct sigaction s_action;
    union semun a_semun;
    struct sembuf a_sembuf;
    struct sg_scsi_id sg_id;
    char ebuff[256];
    int deb = 0;
    char * file_name = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-deb", argv[k], 4))
            deb = 10;
        else if (*argv[k] != '-')
            file_name = argv[k];
    }
    if (0 == file_name) {
printf("Usage: 'sg_poll [-deb] <generic_device>'  eg: sg_poll /dev/sg0\n");
        return 1;
    }

    semset_id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (-1 == semset_id) {
        perror("semget error");
        return 1;
    }
    a_semun.val = 0;
    res = semctl(semset_id, 0, SETVAL, a_semun);
    if (-1 == res) {
        perror("semctl(val) error");
        return 1;
    }


    sg_fd = open(file_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        sprintf(ebuff, "sg_poll: open error on %s", file_name);
        perror(ebuff);
        return 1;
    }
    res = ioctl(sg_fd, SG_GET_SCSI_ID, &sg_id);
    if (res < 0) {
        /* perror("ioctl on generic device, error"); */
        printf("sg_poll: %s not a scsi generic device\n", file_name);
        return 1;
    }
    printf("scsi%d, channel=%d, device=%d, lun=%d,  scsi_type=%d\n", 
           sg_id.host_no, sg_id.channel, sg_id.scsi_id, sg_id.lun,
           sg_id.scsi_type);

#ifdef SG_DEBUG
    ioctl(sg_fd, SG_SET_DEBUG, &deb);
#endif
    res = ioctl(sg_fd, SG_GET_COMMAND_Q, &k);
    if (res < 0) {
        perror("SG_GET_COMMAND_Q ioctl error");
        return 1;
    }
    if (0 == k) {
        k = 1;
        res = ioctl(sg_fd, SG_SET_COMMAND_Q, &k);
        if (res < 0) {
            perror("SG_SET_COMMAND_Q ioctl error");
            return 1;
        }
    }

    s_action.sa_flags = SA_SIGINFO;
    s_action.sa_sigaction = sg_sa_handler;
    sigemptyset(&s_action.sa_mask);
    res = sigaction(SIGRTMIN, &s_action, NULL);
    if (res == -1) {
        perror("sg_poll: sigaction error");
        return 1;
    }
    res = fcntl(sg_fd, F_SETOWN, getpid());
    if (res == -1) {
        perror("sg_poll: fcntl(setown) error");
        return 1;
    }
    flags = fcntl(sg_fd, F_GETFL);
    res = fcntl(sg_fd, F_SETFL, flags | MY_ASYNC);
    if (res == -1) {
        perror("sg_poll: fcntl(setfl) error");
        return 1;
    }
    fcntl(sg_fd, F_SETSIG, SIGRTMIN);
    
    do_poll();
    printf("pre-loop check, poll_res=%d, revents=%d\n", poll_res, (int)revents); 
    

    for (k = 0; k < times; ++k, sectorNo += numSectors) {
    
    rdOutLen = OFF + (BLOCK_SIZE * numSectors);
    rsghp->pack_len = 999;                /* don't care */
    rsghp->pack_id = k;
    rsghp->reply_len = rdOutLen;
    rsghp->twelve_byte = 0;
    rsghp->result = 0;
    memcpy(rdBuff + OFF, rdCmdBlk, sizeof(rdCmdBlk));
    rdCmd[3] = (unsigned char)((sectorNo >> 16) & 0xFF);
    rdCmd[4] = (unsigned char)((sectorNo >> 8) & 0xFF);
    rdCmd[5] = (unsigned char)(sectorNo & 0xFF);
    rdCmd[7] = (unsigned char)((numSectors >> 8) & 0xff);
    rdCmd[8] = (unsigned char)(numSectors & 0xff);

    res = write(sg_fd, rdBuff, rdInLen);
    if (res < 0) {
        perror("sg_poll: write (rd) error");
        return 1;
    }
    if (res < rdInLen) {
        printf("sg_poll: wrote less (rd), ask=%d, got=%d", rdInLen, res);
        return 1;
    }
    
    rsghp2->pack_len = 888;                /* don't care */
    rsghp2->pack_id = k + 100;
    rsghp2->reply_len = rdOutLen;
    rsghp2->twelve_byte = 0;
    rsghp2->result = 0;
    memcpy(rdBuff2 + OFF, rdCmdBlk, sizeof(rdCmdBlk));
    sectorNo2 = sectorNo + 6666;
    rdCmd2[3] = (unsigned char)((sectorNo2 >> 16) & 0xFF);
    rdCmd2[4] = (unsigned char)((sectorNo2 >> 8) & 0xFF);
    rdCmd2[5] = (unsigned char)(sectorNo2 & 0xFF);
    rdCmd2[7] = (unsigned char)((numSectors >> 8) & 0xff);
    rdCmd2[8] = (unsigned char)(numSectors & 0xff);

#if 1
    res = write(sg_fd, rdBuff2, rdInLen);
    if (res < 0) {
        perror("sg_poll: write2 (rd) error");
        return 1;
    }
    if (res < rdInLen) {
        printf("sg_poll: wrote less (rd), ask=%d, got=%d", rdInLen, res);
        return 1;
    }
#endif

    do_poll();
    printf("pre-write pause, k=%d, " 
           "hand_count=%d, signo=%d, poll_res=%d, revents=%d\n",
           k, hand_count, signo, poll_res, (int)revents); 
#ifdef SG_DEBUG
    ioctl(sg_fd, SG_SET_DEBUG, &deb);
#endif
    system("cat /proc/scsi/sg/debug");

    a_sembuf.sem_num = 0;
    a_sembuf.sem_op = -1;
    a_sembuf.sem_flg = 0;
    while (semop(semset_id, &a_sembuf, 1) < 0) {
        if (EINTR != errno) {
            perror("semop(main) error");
            return 0;
        }
    }
    /* pause(); */

    printf("post-write pause, k=%d, " 
           "hand_count=%d, signo=%d, poll_res=%d, revents=%d\n",
           k, hand_count, signo, poll_res, (int)revents); 
#ifdef SG_DEBUG
    ioctl(sg_fd, SG_SET_DEBUG, &deb);
#endif

    res = read(sg_fd, rdBuff, rdOutLen);
    if (res < 0) {
        perror("sg_poll: read (rd) error");
        return 1;
    }
    if (res < rdOutLen) {
        printf("sg_poll: read less (rd), ask=%d, got=%d", rdOutLen, res);
        return 1;
    }
    sg_chk_n_print("after read(rd)", rsghp->target_status, 
                   rsghp->host_status, rsghp->driver_status, 
                   rsghp->sense_buffer, SG_MAX_SENSE);

    }
    printf("\treq_len=%d, dma_count=%d\n", rsghp->reply_len, rsghp->pack_len);

#ifdef SG_DEBUG
    ioctl(sg_fd, SG_SET_DEBUG, &deb);
#endif
    res = close(sg_fd);
    if (res < 0) {
        perror("sg_poll: close error");
        return 1;
    }
    
    if (deb > 0) {
        sg_fd = open(file_name, O_RDONLY);
        if (sg_fd < 0) {
            sprintf(ebuff, "sg_poll: open (2) error on %s", file_name);
            perror(ebuff);
            return 1;
        }
        res = ioctl(sg_fd, SG_SET_DEBUG, &deb);
        if (res < 0) {
            perror("ioctl (2) error");
            return 1;
        }
        res = close(sg_fd);
        if (res < 0) {
            perror("sg_poll: close (2) error");
            return 1;
        }
    }

    return 0;
}
