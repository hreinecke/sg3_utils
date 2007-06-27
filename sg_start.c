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

/*
 *  Copyright (C) 1999-2005 D. Gilbert
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

static char * version_str = "0.43 20050603";

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
        if (verbose > 2)
                fprintf(stderr, "      duration=%u ms\n",
                        io_hdr.duration);
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
        fprintf(stderr, "Usage:  sg_start [0|-stop|1|-start] [-imm=0|1] "
                "[-loej] [-pc=<n>] [-v] [-V]\n"
                "                 <scsi_device>\n"
                " where: 0        stop unit (e.g. spin down a disk or a "
                "cd/dvd)\n"
                "        1        start unit (e.g. spin up a disk or a "
                "cd/dvd)\n"
                "        -imm=0|1   0->await completion, 1->return "
                "immediately(def)\n"
                "        -loej    load the medium if '-start' option is "
                "also given\n"
                "                 or stop unit and eject\n"
                "        -pc=<n>  power conditions (in hex, default 0 -> no "
                "power condition)\n"
                "                 1 -> active, 2 -> idle, 3 -> standby\n"
                "        -start   start unit (same as '1')\n"
                "        -stop    stop unit (same as '0')\n"
                "        -v       verbose (print out SCSI commands)\n"
                "        -V       print version string then exit\n\n"
                "    Example: 'sg_start -stop /dev/sdb'   stops unit\n"
                "             'sg_start -loej /dev/scd0'  stops unit and "
                "ejects media\n");
        exit (1);
}

int main(int argc, char * argv[])
{
        int startstop = -1;
        const char * file_name = 0;
        const char * cp;
        int k, fd, num, res, plen, jmp_out;
        unsigned int u;
        int immed = 1;
        int loej = 0;
        int power_conds = 0;
        int verbose = 0;
        
        if (argc < 2) 
                usage ();

        for (k = 1; k < argc; ++k) {
                cp = argv[k];
                plen = strlen(cp);
                if (plen <= 0)
                        continue;
                if ('-' == *cp) {
                        for (--plen, ++cp, jmp_out = 0; plen > 0;
                             --plen, ++cp) {
                                switch (*cp) {
                                case 'l':
                                        if (0 == strncmp(cp, "loej", 4)) {
                                                loej = 1;
                                                cp += 3;
                                                plen -= 3;
                                        } else
                                                jmp_out = 1;
                                        break;
                                case 's':
                                        if (startstop >= 0) {
                                                fprintf(stderr,
                        "please, only one of 0, 1, -start or -stop\n");
                                                usage();
                                                return 1;
                                        }
                                        if (0 == strncmp(cp, "start", 5)) {
                                                startstop = 1;
                                                cp += 4;
                                                plen -= 4;
                                        } else if (0 == strncmp(cp, "stop",
                                                                4)) {
                                                startstop = 0;
                                                cp += 3;
                                                plen -= 3;
                                        } else
                                                jmp_out = 1;
                                        break;
                                case 'v':
                                        ++verbose;
                                        break;
                                case 'V':
                                        fprintf(stderr, "Version string: "
                                                "%s\n", version_str);
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
                        if (0 == strncmp("imm=", cp, 4)) {
                                num = sscanf(cp + 4, "%x", &u);
                                if ((1 != num) || (u > 1)) {
                                        fprintf(stderr, "Bad value after "
                                                "'imm=' option\n");
                                        usage();
                                        return 1;
                                }
                                immed = u;
                        } else if (0 == strncmp("pc=", cp, 3)) {
                                num = sscanf(cp + 3, "%x", &u);
                                if ((1 != num) || (u > 15)) {
                                        fprintf(stderr, "Bad value after "
                                                "after 'pc=' option\n");
                                        usage();
                                        return 1;
                                }
                                power_conds = u;
                        } else if (jmp_out) {
                                fprintf(stderr, "Unrecognized option: %s\n",
                                        cp);
                                usage();
                                return 1;
                        }
                } else if (0 == strcmp("0", cp)) {
                        if (startstop >= 0) {
                                fprintf(stderr, "please, only one of 0, 1, "
                                        "-start or -stop\n");
                                usage();
                                return 1;
                        } else
                                startstop = 0;
                } else if (0 == strcmp("1", cp)) {
                        if (startstop >= 0) {
                                fprintf(stderr, "please, only one of 0, 1, "
                                        "-start or -stop\n");
                                usage();
                                return 1;
                        } else
                                startstop = 1;
                } else if (0 == file_name)
                        file_name = cp;
                else {
                        fprintf(stderr, "too many arguments, got: %s, not "
                                "expecting: %s\n", file_name, cp);
                        usage();
                        return 1;
                }
        }
    
        if (0 == file_name) {
                fprintf(stderr, "No <scsi_device> argument given\n");
                usage();
                return 1;
        }

        if ((startstop == -1) && loej)
                startstop = 0;
        if ((startstop == -1) && (0 == power_conds)) {
                fprintf(stderr, "need either -start|-stop indication or"
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
