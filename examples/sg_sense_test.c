#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_lib.h"

/* This is a simple program that tests the sense data descriptor format
   printout function in sg_lib.c

*  Copyright (C) 2004-20013 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

*/

#define EBUFF_SZ 256

#define ME "sg_sense_test: "



int main(/* int argc, char * argv[] */)
{
    unsigned char err1[] = {0x72, 0x5, 0x4, 0x1, 0, 0, 0, 32,
                            0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                            0, 0xa, 0x80, 0, 1, 2, 3, 4,
                            0xaa, 0xbb, 0xcc, 0xdd,
                            1, 0xa, 0, 0, 1, 2, 3, 4,
                            0xaa, 0xbb, 0xee, 0xff};
    unsigned char err2[] = {0x72, SPC_SK_MEDIUM_ERROR, 0x4, 0x1, 0x80, 0, 0,
                            32,
                            0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                            0, 0xa, 0x80, 0, 1, 2, 3, 4,
                            0xaa, 0xbb, 0xcc, 0xdd,
                            1, 0xa, 0, 0, 1, 2, 3, 4,
                            0xaa, 0xbb, 0xee, 0xff};
                           /* Set SDAT_OVFL */
    unsigned char err3[] = {0x72, SPC_SK_NO_SENSE, 0x4, 0x1, 0, 0, 0, 8,
                            0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0};
    unsigned char err4[] = {0x73, SPC_SK_COPY_ABORTED, 0x4, 0x1, 0, 0, 0, 22,
                            0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                            0x3, 0x2, 0, 0x55,
                            0x5, 0x2, 0, 0x20,
                            0x85, 0x4, 0, 0x20, 0x33, 0x44};
                           /* Set Filemark, EOM, ILI and SDAT_OVFL */
    unsigned char err5[] = {0xf1, 0, (0xf0 | SPC_SK_ILLEGAL_REQUEST), 0x11,
                            0x22, 0x33, 0x44, 0xa,
                            0x0, 0x0, 0, 0, 0x4, 0x1, 0, 0xcf, 0, 5,};
    unsigned char err6[] = {0x72, SPC_SK_NO_SENSE, 0x4, 0x1, 0, 0, 0, 14,
                            0x9, 0xc, 1, 0, 0x11, 0x22, 0x66, 0x33,
                            0x77, 0x44, 0x88, 0x55, 0x1, 0x2};
    unsigned char err7[] = {0xf1, 0, 0xe5, 0x11, 0x22, 0x33, 0x44, 0xa,
                            0x0, 0x0, 0x0, 0x0, 0x24, 0x1, 0xbb,
                            0xc9, 0x0, 0x2};
    char leadin[128];
    char b[2048];
    int k, prev_len;

    sg_print_sense("err1 test", err1, sizeof(err1), 1 /* raw_info */);
    sg_print_sense("\nerr2 test", err2, sizeof(err2), 1);
    sg_print_sense("\nerr3 test", err3, sizeof(err3), 1);
    sg_print_sense("\nerr4 test", err4, sizeof(err4), 1);
    sg_print_sense("\nerr5 test", err5, sizeof(err5), 1);
    sg_print_sense("\nerr6 test", err6, sizeof(err6), 1);
    sg_print_sense("\nerr7 test", err7, sizeof(err7), 1);

    printf("\n\nTry different output string sizes with "
           "sg_get_sense_str(err2):\n");
    for (k = 1, prev_len = -1; k < 512; ++k) {
        snprintf(leadin, sizeof(leadin), "blen=%d", k);
        sg_get_sense_str(leadin, err2, sizeof(err2), 0, k, b);
        printf("%s\n", b);
        if (prev_len == (int)strlen(b))
            break;
        else
            prev_len = strlen(b);
    }

    printf("\n\nTry different output string sizes with "
           "sg_get_sense_str(err4):\n");
    for (k = 1, prev_len = -1; k < 512; ++k) {
        snprintf(leadin, sizeof(leadin), "blen=%d", k);
        sg_get_sense_str(leadin, err4, sizeof(err4), 0, k, b);
        printf("%s\n", b);
        if (prev_len == (int)strlen(b))
            break;
        else
            prev_len = strlen(b);
    }
    return 0;
}
