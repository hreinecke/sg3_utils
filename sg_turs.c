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
#include "sg_lib.h"
#include "sg_cmds.h"

/* This program sends a user specified number of TEST UNIT READY commands
   to the given sg device. Since TUR is a simple command involing no
   data transfer (and no REQUEST SENSE command iff the unit is ready)
   then this can be used for timing per SCSI command overheads.

*  Copyright (C) 2000-2005 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

*/

static char * version_str = "3.17 20050808";

#define EBUFF_SZ 256

static void usage()
{
    printf("Usage: 'sg_turs [-n=<num_of_test_unit_readys>] [-t] "
           "[-v] [-V] <scsi_device>'\n"
           " where '-n=<num>' number of test_unit_ready commands "
           "(def: 1)\n"
           "       '-t'   outputs total duration and commands per "
           "second\n"
           "       '-v'   increase verbosity\n"
           "       '-V'   print version string then exit\n\n"
           "Performs a TEST UNIT READY SCSI command (or many of them)\n");
}

int main(int argc, char * argv[])
{
    int sg_fd, k, plen, jmp_out;
    const char * file_name = 0;
    const char * cp;
    char ebuff[EBUFF_SZ];
    int num_turs = 1;
    int num_errs = 0;
    int do_time = 0;
    int verbose = 0;
    struct timeval start_tm, end_tm;


    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 't':
                    do_time = 1;
                    break;
                case 'v':
                    ++verbose;
                    break;
                case 'V':
                    fprintf(stderr, "Version string: %s\n", version_str);
                    exit(0);
                case '?':
                    usage();
                    return 1;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("n=", cp, 2)) {
                num_turs = sg_get_num(cp + 2);
                if (num_turs <= 0) {
                    printf("Couldn't decode number after 'n=' option\n");
                    usage();
                    return 1;
                }
            } else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage();
                return 1;
            }
        } else if (0 == file_name)
            file_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", file_name, cp);
            usage();
            return 1;
        }
    }
    if (0 == file_name) {
        fprintf(stderr, "No <scsi_device> argument given\n");
        usage();
        return 1;
    }

    if ((sg_fd = open(file_name, O_RDONLY | O_NONBLOCK)) < 0) {
        snprintf(ebuff, EBUFF_SZ, 
                 "sg_turs: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    if (do_time) {
        start_tm.tv_sec = 0;
        start_tm.tv_usec = 0;
        gettimeofday(&start_tm, NULL);
    }
    for (k = 0; k < num_turs; ++k) {
        if (sg_ll_test_unit_ready(sg_fd, k, ((1 == num_turs) ? 1 : 0),
                                  verbose))
            ++num_errs;
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
    return num_errs ? 1 : 0;
}
