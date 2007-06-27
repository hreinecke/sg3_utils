#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* The program allows the user to send a trespass command to change the
 * LUN ownership from one Service-Processor to this one on an EMC
 * CLARiiON and potentially other devices.
 *
 * Copyright (C) 2004 Lars Marowsky-Bree <lmb@suse.de>
 *
 * Based on sg_start.c; credits from there also apply.
 * Minor modifications for sg_lib, D. Gilbert 2004/10/19
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 */

static char * version_str = "0.11 20041019";

static int debug = 0;

#define TRESPASS_PAGE           0x22

static void do_trespass(int fd, int hr, int short_cmd)
{
        unsigned char long_trespass_pg[] =
                { 0, 0, 0, 0, 0, 0, 0, 0x00, 
                  TRESPASS_PAGE,        /* Page code */
                  0x09,                 /* Page length - 2 */
                  hr ? 0x01 : 0x81,     /* Trespass code + Honor reservation bit */
                  0xff, 0xff,           /* Trespass target */
                  0, 0, 0, 0, 0, 0      /* Reserved bytes / unknown */
        };
        unsigned char short_trespass_pg[] =
                { 0, 0, 0, 0, 
                  TRESPASS_PAGE,        /* Page code */
                  0x02,                 /* Page length - 2 */
                  hr ? 0x01 : 0x81,     /* Trespass code + Honor reservation bit */
                  0xff,                 /* Trespass target */
        };
        int res;

        if (short_cmd)
                res = sg_ll_mode_select6(fd, 1 /* pf */, 0 /* sp */,
                                 short_trespass_pg, sizeof(short_trespass_pg),
                                 1, (debug ? 2 : 0));
        else
                res = sg_ll_mode_select10(fd, 1 /* pf */, 0 /* sp */,
                                 long_trespass_pg, sizeof(long_trespass_pg),
                                 1, (debug ? 2 : 0));

        switch (res) {
        case 0:
                if (debug)
                        fprintf(stderr, "%s trespass successful\n",
                                        short_cmd ? "short" : "long");
                break;
        case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, "%s form trepass page failed, try again %s "
                        "'-s' option\n", short_cmd ? "short" : "long",
                        short_cmd ? "without" : "with");
                break;
        default:
                if (debug)
                        fprintf(stderr, "%s trespass failed\n",
                                        short_cmd ? "short" : "long");
                break;
        }
}

void usage ()
{
        fprintf(stderr, "Usage:  sg_emc_trespass [-d] [-hr] [-s] "
                        " [-V] <device>\n"
               "  Change ownership of a LUN from another SP to this one.\n"
               "  EMC CLARiiON CX-/AX-family + FC5300/FC4500/FC4700.\n"
               "    -d : output debug\n"
               "    -hr: Set Honor Reservation bit\n"
               "    -s : Send Short Trespass Command page (default: long)\n"
               "         (for FC series)\n"
               "    -V: print version string then exit\n"
               "     <device> sg or block device (latter in lk 2.6.*)\n"
               "        Example: sg_emc_trespass /dev/sda\n");
        exit (1);
}

int main(int argc, char * argv[])
{
        char **argptr;
        char * file_name = 0;
        int k, fd;
        int hr = 0;
        int short_cmd = 0;
        
        if (argc < 2) 
                usage ();

        for (k = 1; k < argc; ++k) {
                argptr = argv + k;
                if (!strcmp (*argptr, "-d"))
                        ++debug;
                else if (!strcmp (*argptr, "-s"))
                        short_cmd = 1;
                else if (!strcmp (*argptr, "-hr"))
                        hr = 1;
                else if (!strcmp (*argptr, "-V")) {
                        printf("Version string: %s\n", version_str);
                        exit(0);
                }
                else if (*argv[k] == '-') {
                        fprintf(stderr, "Unrecognized switch: %s\n", argv[k]);
                        file_name = 0;
                        break;
                }
                else if (0 == file_name)
                        file_name = argv[k];
                else {
                        fprintf(stderr, "too many arguments\n");
                        file_name = 0;
                        break;
                }
        }
        if (0 == file_name) {
                usage();
                return 1;
        }
                
        fd = open(file_name, O_RDWR | O_NONBLOCK);
        if (fd < 0) {
                fprintf(stderr, "Error trying to open %s\n", file_name);
                perror("");
                usage();
                return 2;
        }
       
        do_trespass(fd, hr, short_cmd);
        
        close (fd);
        return 0;
}
