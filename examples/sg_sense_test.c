#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"

/* This is a simple program that tests the sense data descriptor format
   printout function in sg_lib.c

*  Copyright (C) 2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

*/

#define EBUFF_SZ 256

#define ME "sg_sense_test: "

int main(int argc, char * argv[])
{
    unsigned char err1[] = {0x72, 0x5, 0x4, 0x1, 0, 0, 0, 32,
                            0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                            0, 0xa, 0x80, 0, 1, 2, 3, 4,
                            0xaa, 0xbb, 0xcc, 0xdd,
                            1, 0xa, 0, 0, 1, 2, 3, 4,
                            0xaa, 0xbb, 0xcc, 0xdd};
    unsigned char err2[] = {0x72, MEDIUM_ERROR, 0x4, 0x1, 0, 0, 0, 32,
                            0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                            0, 0xa, 0x80, 0, 1, 2, 3, 4,
                            0xaa, 0xbb, 0xcc, 0xdd,
                            1, 0xa, 0, 0, 1, 2, 3, 4,
                            0xaa, 0xbb, 0xcc, 0xdd};
    unsigned char err3[] = {0x72, NO_SENSE, 0x4, 0x1, 0, 0, 0, 8,
                            0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0};
    unsigned char err4[] = {0x73, COPY_ABORTED, 0x4, 0x1, 0, 0, 0, 22,
                            0x2, 0x6, 0, 0, 0xc8, 0x0, 0x3, 0,
                            0x3, 0x2, 0, 0x55,
                            0x5, 0x2, 0, 0x20,
                            0x85, 0x4, 0, 0x20, 0x33, 0x44};
    unsigned char err5[] = {0xf1, 0, (0xf0 | ILLEGAL_REQUEST), 0x11, 0x22,
                            0x33, 0x44, 0xa,
                            0x0, 0x0, 0, 0, 0x4, 0x1, 0, 0xcf, 0, 5,};

    sg_print_sense("err1 test", err1, sizeof(err1));
    sg_print_sense("\nerr2 test", err2, sizeof(err2));
    sg_print_sense("\nerr3 test", err3, sizeof(err3));
    sg_print_sense("\nerr4 test", err4, sizeof(err4));
    sg_print_sense("\nerr5 test", err5, sizeof(err5));
    return 0;
}
