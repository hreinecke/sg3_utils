/* The program allows the user to send a trespass command to change the
 * LUN ownership from one Service-Processor to this one on an EMC
 * CLARiiON and potentially other devices.
 *
 * Copyright (C) 2004-2018 Lars Marowsky-Bree <lmb@suse.de>
 *
 * Based on sg_start.c; credits from there also apply.
 * Minor modifications for sg_lib, D. Gilbert 2004/10/19
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pr2serr.h"


static const char * version_str = "0.23 20180219";

static int debug = 0;

#define TRESPASS_PAGE           0x22

static int
do_trespass(int fd, bool hr, bool short_cmd)
{
        uint8_t long_trespass_pg[] =
                { 0, 0, 0, 0, 0, 0, 0, 0x00,
                  TRESPASS_PAGE,        /* Page code */
                  0x09,                 /* Page length - 2 */
                  0x81,                 /* Trespass code + Honor reservation
                                         * bit */
                  0xff, 0xff,           /* Trespass target */
                  0, 0, 0, 0, 0, 0      /* Reserved bytes / unknown */
        };
        uint8_t short_trespass_pg[] =
                { 0, 0, 0, 0,
                  TRESPASS_PAGE,        /* Page code */
                  0x02,                 /* Page length - 2 */
                  0x81,                 /* Trespass code + Honor reservation
                                         * bit */
                  0xff,                 /* Trespass target */
        };
        int res;
        char b[80];

        if (hr) {       /* override Trespass code + Honor reservation bit */
                short_trespass_pg[6] = 0x01;
                long_trespass_pg[10] = 0x01;
        }
        if (short_cmd)
                res = sg_ll_mode_select6(fd, true /* pf */, false /* sp */,
                                 short_trespass_pg, sizeof(short_trespass_pg),
                                 true, (debug ? 2 : 0));
        else
                res = sg_ll_mode_select10(fd, true /* pf */, false /* sp */,
                                 long_trespass_pg, sizeof(long_trespass_pg),
                                 true, (debug ? 2 : 0));

        switch (res) {
        case 0:
                if (debug)
                        pr2serr("%s trespass successful\n",
                                short_cmd ? "short" : "long");
                break;
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
                pr2serr("%s form trepass page failed, try again %s '-s' "
                        "option\n", short_cmd ? "short" : "long",
                        short_cmd ? "without" : "with");
                break;
        case SG_LIB_CAT_NOT_READY:
                pr2serr("device not ready\n");
                break;
        case SG_LIB_CAT_UNIT_ATTENTION:
                pr2serr("unit attention\n");
                break;
        default:
                sg_get_category_sense_str(res, sizeof(b), b, debug);
                pr2serr("%s trespass failed: %s\n",
                        (short_cmd ? "short" : "long"), b);
                break;
        }
        return res;
}

void usage ()
{
        pr2serr("Usage:  sg_emc_trespass [-d] [-hr] [-s] [-V] DEVICE\n"
                "  Change ownership of a LUN from another SP to this one.\n"
                "  EMC CLARiiON CX-/AX-family + FC5300/FC4500/FC4700.\n"
                "    -d : output debug\n"
                "    -hr: Set Honor Reservation bit\n"
                "    -s : Send Short Trespass Command page (default: long)\n"
                "         (for FC series)\n"
                "    -V: print version string then exit\n"
                "     DEVICE   sg or block device (latter in lk 2.6 or lk 3 "
                "series)\n"
                "        Example: sg_emc_trespass /dev/sda\n");
        exit (1);
}

int main(int argc, char * argv[])
{
        char **argptr;
        char * file_name = 0;
        int k, fd;
        bool hr = false;
        bool short_cmd = false;
        int ret = 0;

        if (argc < 2)
                usage ();

        for (k = 1; k < argc; ++k) {
                argptr = argv + k;
                if (!strcmp (*argptr, "-d"))
                        ++debug;
                else if (!strcmp (*argptr, "-s"))
                        short_cmd = true;
                else if (!strcmp (*argptr, "-hr"))
                        hr = true;
                else if (!strcmp (*argptr, "-V")) {
                        printf("Version string: %s\n", version_str);
                        exit(0);
                }
                else if (*argv[k] == '-') {
                        pr2serr("Unrecognized switch: %s\n", argv[k]);
                        file_name = NULL;
                        break;
                }
                else if (NULL == file_name)
                        file_name = argv[k];
                else {
                        pr2serr("too many arguments\n");
                        file_name = NULL;
                        break;
                }
        }
        if (NULL == file_name) {
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }

        fd = open(file_name, O_RDWR | O_NONBLOCK);
        if (fd < 0) {
                pr2serr("Error trying to open %s\n", file_name);
                perror("");
                usage();
                return SG_LIB_FILE_ERROR;
        }

        ret = do_trespass(fd, hr, short_cmd);

        close (fd);
        return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
