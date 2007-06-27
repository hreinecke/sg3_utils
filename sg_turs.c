#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "sg_include.h"
#include "sg_err.h"

/* This program sends a user specified number of TEST UNIT READY commands
   to the given sg device. Since TUR is a simple command involing no
   data transfer (and no REQUEST SENSE command iff the unit is ready)
   then this can be used for timing per SCSI command overheads.

*  Copyright (C) 2000-2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   Invocation: sg_turs [-t] [-n=<number_of_turs>] <sg_device>
   The value give to "-n=" can have the following multipliers:
     'c','C'  *1       'b','B' *512      'k' *1024      'K' *1000
     'm' *(1024^2)     'M' *(1000^2)     'g' *(1024^3)  'G' *(1000^3)

   Version 03.11 (20040602)
*/

#define TUR_CMD_LEN 6

int get_num(char * buf)
{
    int res, num;
    char c;

    res = sscanf(buf, "%d%c", &num, &c);
    if (1 == res)
        return num;
    else if (2 != res)
        return -1;
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

#define EBUFF_SZ 256


int main(int argc, char * argv[])
{
    int sg_fd, k;
    unsigned char turCmdBlk [TUR_CMD_LEN] =
                                {0x00, 0, 0, 0, 0, 0};
    struct sg_io_hdr io_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char sense_buffer[32];
    int num_turs = 1;
    int num_errs = 0;
    int do_time = 0;
    struct timeval start_tm, end_tm;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-n=", argv[k], 3)) {
            num_turs = get_num(argv[k] + 3);
            if (num_turs < 0) {
                printf("Couldn't decode number after '-n' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strcmp("-t", argv[k]))
            do_time = 1;
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            printf("too many arguments\n");
            file_name = 0;
            break;
        }
    }
    if ((0 == file_name) || (num_turs <= 0)) {
        printf("Usage: 'sg_turs [-t] [-n=<num_of_test_unit_readys>] "
               "<sg_device>'\n"
               " where '-n=<num>' number of test_unit_ready commands "
               "(def: 1)\n"
               "                  can take k, K, m, M postfix multipliers\n"
               "       '-t'   outputs total duration and commands per "
               "second\n");
        return 1;
    }

    if ((sg_fd = open(file_name, O_RDONLY)) < 0) {
        snprintf(ebuff, EBUFF_SZ, 
                 "sg_turs: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Prepare TEST UNIT READY command */
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(turCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.cmdp = turCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }
    for (k = 0; k < num_turs; ++k) {
        io_hdr.pack_id = k;
        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
            perror("sg_turs: Test Unit Ready SG_IO ioctl error");
            close(sg_fd);
            return 1;
        }
        if (io_hdr.info & SG_INFO_OK_MASK) {
            ++num_errs;
            if (1 == num_turs) {        /* then print out the error message */
                if (SG_ERR_CAT_CLEAN != sg_err_category3(&io_hdr))
                    sg_chk_n_print3("tur", &io_hdr);
            }
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
        b = (double)num_turs;
        printf("time to perform commands was %d.%06d secs",
               (int)res_tm.tv_sec, (int)res_tm.tv_usec);
        if (a > 0.00001)
            printf("; %.2f operations/sec\n", b / a);
        else
            printf("\n");
    }

    printf("Completed %d Test Unit Ready commands with %d errors\n",
            num_turs, num_errs);
    close(sg_fd);
    return 0;
}
