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

/* This program is modeled on the example code in the SCSI Programming
   HOWTO V1.5 by Heiko Eissfeldt dated 7 May 1996.
*
*  Copyright (C) 1999-2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   Since this code has been used in the past to form the backbone of
   some Linux apps based on the "sg" device driver, it has been
   strengthened.

   Start/Stop parameter by Kurt Garloff <garloff at suse dot de>, 6/2000
   Sync cache parameter by Kurt Garloff <garloff at suse dot de>, 1/2001
   Guard block device answering sg's ioctls. 
                    <dgilbert at interlog dot com> 12/2002
   Convert to SG_IO ioctl so can use sg or block devices in 2.6.* 3/2003
 
*/

static char * version_str = "0.41 20041106";

#define START_STOP_CMD          0x1b
#define START_STOP_CMDLEN       6
#define DEF_TIMEOUT 120000       /* 120,000 millisecs == 2 minutes */


/* Returns 0 if successful, else -1. */
static int do_start_stop(int fd, int start, int immed, int loej,
                         int power_conditions, int verbose)
{
        unsigned char cmdblk[START_STOP_CMDLEN] = { 
                START_STOP,     /* Command */
                0,              /* Resvd/Immed */
                0,              /* Reserved */
                0,              /* Reserved */
                0,              /* PowCond/Resvd/LoEj/Start */
                0 };            /* Reserved/Flag/Link */
        unsigned char sense_b[32];
        struct sg_io_hdr io_hdr;
        int k, res;

        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        cmdblk[1] = immed & 1;
        cmdblk[4] = ((power_conditions & 0xf) << 4) | 
                    ((loej & 1) << 1) | (start & 1);
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(cmdblk);
        io_hdr.mx_sb_len = sizeof(sense_b);
        io_hdr.dxfer_direction = SG_DXFER_NONE;
        io_hdr.dxfer_len = 0;
        io_hdr.dxferp = NULL;
        io_hdr.cmdp = cmdblk;
        io_hdr.sbp = sense_b;
        io_hdr.timeout = DEF_TIMEOUT;
        if (verbose) {
                printf("  Start/Stop command:");
                for (k = 0; k < (int)sizeof(cmdblk); ++k)
                        printf (" %02x", cmdblk[k]);
                printf("\n");
        }
        
        if (ioctl(fd, SG_IO, &io_hdr) < 0) {
                perror("start_stop (SG_IO) error");
                return -1;
        }
        res = sg_err_category3(&io_hdr);
        if (SG_LIB_CAT_MEDIA_CHANGED == res) {
                fprintf(stderr, "media change report, try start_stop again\n");
                if (ioctl(fd, SG_IO, &io_hdr) < 0) {
                        perror("start_stop (SG_IO) error");
                        return -1;
                }
                res = sg_err_category3(&io_hdr);
        }
        if (SG_LIB_CAT_CLEAN != res) {
                sg_chk_n_print3("start_stop", &io_hdr);
                return -1;
        }
        return 0;
}

void usage ()
{
        fprintf(stderr, "Usage:  sg_start [0|1] [-imm=0|1] [-loej] "
                        "[-pc=<n>] [-v] [-V] <scsi_device>\n"
               " where: 0: stop unit (e.g. spin down a disk or a cd/dvd)\n"
               "        1: start unit (e.g. spin up a disk or a cd/dvd)\n"
               "        -imm=0|1: 0->await completion, 1->return "
               "immediately(def)\n"
               "        -loej: load the medium if start option '1' is also "
               "given\n"
               "                or stop unit and eject\n"
               "        -pc=<n>: power conditions (in hex, default 0 -> no "
               "power condition)\n"
               "                 1 -> active, 2 -> idle, 3 -> standby\n"
               "        -v: verbose (print out SCSI commands)\n"
               "        -V: print version string then exit\n"
               "         <scsi_device>\n\n"
               "    Example: 'sg_start 0 /dev/sdb' stops unit\n"
               "             'sg_start -loej /dev/sdb' stops unit and "
               "ejects\n");
        exit (1);
}

int main(int argc, char * argv[])
{
        char **argptr;
        int startstop = -1;
        char * file_name = 0;
        int k, fd, num, res;
        unsigned int u;
        int immed = 1;
        int loej = 0;
        int power_conds = 0;
        int verbose = 0;
        
        if (argc < 2) 
                usage ();

        for (k = 1; k < argc; ++k) {
                argptr = argv + k;
                if (!strcmp (*argptr, "-loej"))
                        loej = 1;
                else if (0 == strncmp("-imm=", argv[k], 5)) {
                        num = sscanf(argv[k] + 5, "%x", &u);
                        if ((1 != num) || (u > 1)) {
                                printf("Bad value after '-imm' switch\n");
                                file_name = 0;
                                break;
                        }
                        immed = u;
                }
                else if (0 == strncmp("-pc=", argv[k], 4)) {
                        num = sscanf(argv[k] + 4, "%x", &u);
                        if ((1 != num) || (u > 15)) {
                                printf("Bad value after '-pc' switch\n");
                                file_name = 0;
                                break;
                        }
                        power_conds = u;
                }
                else if (!strcmp (*argptr, "-V")) {
                        printf("Version string: %s\n", version_str);
                        exit(0);
                } else if (!strcmp (*argptr, "-v"))
                        ++verbose;
                else if (!strcmp (*argptr, "0"))
                        startstop = 0;
                else if (!strcmp (*argptr, "1"))
                        startstop = 1;
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
        if ((startstop == -1) && loej)
                startstop = 0;
        if ((startstop == -1) && (0 == power_conds)) {
                fprintf(stderr, "need either start/stop indication (0|1) or"
                        " non-zero power condition\n");
                usage ();
                return 1;
        }
                
        fd = open(file_name, O_RDWR | O_NONBLOCK);
        if (fd < 0) {
                fprintf(stderr, "Error trying to open %s\n", file_name);
                perror("");
                return 2;
        }
        
        res = 0;
        if (power_conds > 0)
                res = do_start_stop(fd, 0, immed, 0, power_conds, verbose);
        else if (startstop != -1)
                res = do_start_stop(fd, startstop, immed, loej, 0, verbose);
        
        close (fd);
        return res ? 1 : 0;
}
