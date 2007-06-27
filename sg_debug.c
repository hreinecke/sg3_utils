#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include "sg_include.h"


/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs debug information to the console/log for _all_
   active sg devices.

   Version 3.55 (20020115)
*/

#define EBUFF_SZ 256


int main(int argc, char * argv[])
{
    int fd, res, debug, t;
    char ebuff[EBUFF_SZ];
    
    if ((argc != 2) || ('-' == *argv[1])) {
        printf("Usage: sg_debug <sg_device>\n");
        return 1;
    }
    fd = open(argv[1], O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        if (EBUSY == errno)
            printf("Failed trying to open %s because it is busy\n", argv[1]);
        else {
            snprintf(ebuff, EBUFF_SZ, "sg_debug: Error trying to open %s ", 
	    	     argv[1]);
            perror(ebuff);
        }
        return 1;
    }
    res = ioctl(fd, SG_GET_VERSION_NUM, &t);
    if ((res >= 0) || (t >= 30000)) {
        printf("System is using sg version 3 driver. Hence the user can");
        printf(" execute:\n  'cat /proc/scsi/sg/debug' themselves. ");
        printf("Here is an example:\n");
	system("cat /proc/scsi/sg/debug");
        return 0;
    }
    debug = 10;
    res = ioctl(fd, SG_SET_DEBUG, &debug);
    if (res < 0) {
        perror("sg_debug: ioctl error on SG_SET_DEBUG");
        return 1;
    }
    
    res = close(fd);
    if (res < 0) {
        snprintf(ebuff, EBUFF_SZ, "sg_debug: trying to close %s ", argv[1]);
        perror(ebuff);
        return 1;
    }
    return 0;
}
