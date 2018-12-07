/*
 *  Copyright (C) 1999-2018 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later

    Start/Stop parameter by Kurt Garloff <garloff at suse dot de>, 6/2000
    Sync cache parameter by Kurt Garloff <garloff at suse dot de>, 1/2001
    Guard block device answering sg's ioctls.
                     <dgilbert at interlog dot com> 12/2002
    Convert to SG_IO ioctl so can use sg or block devices in 2.6.* 3/2003

    This utility was written for the Linux 2.4 kernel series. It now
    builds for the Linux 2.6 and 3 kernel series and various other
    Operating Systems.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pr2serr.h"


static const char * version_str = "0.66 20180628";  /* sbc3r14; mmc6r01a */

static struct option long_options[] = {
        {"eject", no_argument, 0, 'e'},
        {"fl", required_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"immed", no_argument, 0, 'i'},
        {"load", no_argument, 0, 'l'},
        {"loej", no_argument, 0, 'L'},
        {"mod", required_argument, 0, 'm'},
        {"noflush", no_argument, 0, 'n'},
        {"new", no_argument, 0, 'N'},
        {"old", no_argument, 0, 'O'},
        {"pc", required_argument, 0, 'p'},
        {"readonly", no_argument, 0, 'r'},
        {"start", no_argument, 0, 's'},
        {"stop", no_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    bool do_eject;
    bool do_immed;
    bool do_load;
    bool do_loej;
    bool do_noflush;
    bool do_readonly;
    bool do_start;
    bool do_stop;
    bool opt_new;
    bool verbose_given;
    bool version_given;
    int do_fl;
    int do_help;
    int do_mod;
    int do_pc;
    int verbose;
    const char * device_name;
};

static void
usage()
{
    pr2serr("Usage: sg_start [--eject] [--fl=FL] [--help] "
            "[--immed] [--load] [--loej]\n"
            "                [--mod=PC_MOD] [--noflush] [--pc=PC] "
            "[--readonly]\n"
            "                [--start] [--stop] [--verbose] "
            "[--version] DEVICE\n"
            "  where:\n"
            "    --eject|-e      stop unit then eject the medium\n"
            "    --fl=FL|-f FL    format layer number (mmc5)\n"
            "    --help|-h       print usage message then exit\n"
            "    --immed|-i      device should return control after "
            "receiving cdb,\n"
            "                    default action is to wait until action "
            "is complete\n"
            "    --load|-l       load medium then start the unit\n"
            "    --loej|-L       load or eject, corresponds to LOEJ bit "
            "in cdb;\n"
            "                    load when START bit also set, else "
            "eject\n"
            "    --mod=PC_MOD|-m PC_MOD    power condition modifier "
            "(def: 0) (sbc)\n"
            "    --noflush|-n    no flush prior to operation that limits "
            "access (sbc)\n"
            "    --pc=PC|-p PC    power condition: 0 (default) -> no "
            "power condition,\n"
            "                    1 -> active, 2 -> idle, 3 -> standby, "
            "5 -> sleep (mmc)\n"
            "    --readonly|-r    open DEVICE read-only (def: read-write)\n"
            "                     recommended if DEVICE is ATA disk\n"
            "    --start|-s      start unit, corresponds to START bit "
            "in cdb,\n"
            "                    default (START=1) if no other options "
            "given\n"
            "    --stop|-S       stop unit (e.g. spin down disk)\n"
            "    --verbose|-v    increase verbosity\n"
            "    --old|-O        use old interface (use as first option)\n"
            "    --version|-V    print version string then exit\n\n"
            "    Example: 'sg_start --stop /dev/sdb'    stops unit\n"
            "             'sg_start --eject /dev/scd0'  stops unit and "
            "ejects medium\n\n"
            "Performs a SCSI START STOP UNIT command\n"
            );
}

static void
usage_old()
{
    pr2serr("Usage:  sg_start [0] [1] [--eject] [--fl=FL] "
            "[-i] [--imm=0|1]\n"
            "                 [--load] [--loej] [--mod=PC_MOD] "
            "[--noflush] [--pc=PC]\n"
            "                 [--readonly] [--start] [--stop] [-v] [-V]\n"
            "                 DEVICE\n"
            "  where:\n"
            "    0          stop unit (e.g. spin down a disk or a "
            "cd/dvd)\n"
            "    1          start unit (e.g. spin up a disk or a "
            "cd/dvd)\n"
            "    --eject    stop then eject the medium\n"
            "    --fl=FL    format layer number (mmc5)\n"
            "    -i         return immediately (same as '--imm=1')\n"
            "    --imm=0|1  0->await completion(def), 1->return "
            "immediately\n"
            "    --load     load then start the medium\n"
            "    --loej     load the medium if '-start' option is "
            "also given\n"
            "               or stop unit and eject\n"
            "    --mod=PC_MOD    power condition modifier "
            "(def: 0) (sbc)\n"
            "    --noflush    no flush prior to operation that limits "
            "access (sbc)\n"
            "    --pc=PC    power condition (in hex, default 0 -> no "
            "power condition)\n"
            "               1 -> active, 2 -> idle, 3 -> standby, "
            "5 -> sleep (mmc)\n"
            "    --readonly|-r    open DEVICE read-only (def: read-write)\n"
            "                     recommended if DEVICE is ATA disk\n"
            "    --start    start unit (same as '1'), default "
            "action\n"
            "    --stop     stop unit (same as '0')\n"
            "    -v         verbose (print out SCSI commands)\n"
            "    -N|--new   use new interface\n"
            "    -V         print version string then exit\n\n"
            "    Example: 'sg_start --stop /dev/sdb'    stops unit\n"
            "             'sg_start --eject /dev/scd0'  stops unit and "
            "ejects medium\n\n"
            "Performs a SCSI START STOP UNIT command\n"
            );
}

static int
new_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int c, n, err;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ef:hilLm:nNOp:rsSvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'e':
            op->do_eject = true;
            op->do_loej = true;
            break;
        case 'f':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 3)) {
                pr2serr("bad argument to '--fl='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_loej = true;
            op->do_start = true;
            op->do_fl = n;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'i':
            op->do_immed = true;
            break;
        case 'l':
            op->do_load = true;
            op->do_loej = true;
            break;
        case 'L':
            op->do_loej = true;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 15)) {
                pr2serr("bad argument to '--mod='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_mod = n;
            break;
        case 'n':
            op->do_noflush = true;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = false;
            return 0;
        case 'p':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 15)) {
                pr2serr("bad argument to '--pc='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_pc = n;
            break;
        case 'r':
            op->do_readonly = true;
            break;
        case 's':
            op->do_start = true;
            break;
        case 'S':
            op->do_stop = true;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
            if (op->do_help)
                break;
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    err = 0;
    for (; optind < argc; ++optind) {
        if (1 == strlen(argv[optind])) {
            if (0 == strcmp("0", argv[optind])) {
                op->do_stop = true;
                continue;
            } else if (0 == strcmp("1", argv[optind])) {
                op->do_start = true;
                continue;
            }
        }
        if (NULL == op->device_name)
            op->device_name = argv[optind];
        else {
            pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            ++err;
        }
    }
    if (err) {
        usage();
        return SG_LIB_SYNTAX_ERROR;
    } else
        return 0;
}

static int
old_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    bool ambigu = false;
    bool jmp_out;
    bool startstop = false;
    bool startstop_set = false;
    int k, plen, num;
    unsigned int u;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0;
                 --plen, ++cp) {
                switch (*cp) {
                case 'i':
                    if ('\0' == *(cp + 1))
                        op->do_immed = true;
                    else
                        jmp_out = true;
                    break;
                case 'r':
                    op->do_readonly = true;
                    break;
                case 'v':
                    op->verbose_given = true;
                    ++op->verbose;
                    break;
                case 'V':
                    op->version_given = true;
                    break;
                case 'h':
                case '?':
                    ++op->do_help;
                    break;
                case 'N':
                    op->opt_new = true;
                    return 0;
                case 'O':
                    break;
                case '-':
                    ++cp;
                    --plen;
                    jmp_out = true;
                    break;
                default:
                    jmp_out = true;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;

            if (0 == strncmp(cp, "eject", 5)) {
                op->do_loej = true;
                if (startstop_set && startstop)
                    ambigu = true;
                else {
                    startstop = false;
                    startstop_set = true;
                }
            } else if (0 == strncmp("fl=", cp, 3)) {
                num = sscanf(cp + 3, "%x", &u);
                if (1 != num) {
                    pr2serr("Bad value after 'fl=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                startstop = true;
                startstop_set = true;
                op->do_loej = true;
                op->do_fl = u;
            } else if (0 == strncmp("imm=", cp, 4)) {
                num = sscanf(cp + 4, "%x", &u);
                if ((1 != num) || (u > 1)) {
                    pr2serr("Bad value after 'imm=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->do_immed = !! u;
            } else if (0 == strncmp(cp, "load", 4)) {
                op->do_loej = true;
                if (startstop_set && (! startstop))
                    ambigu = true;
                else {
                    startstop = true;
                    startstop_set = true;
                }
            } else if (0 == strncmp(cp, "loej", 4))
                op->do_loej = true;
            else if (0 == strncmp("pc=", cp, 3)) {
                num = sscanf(cp + 3, "%x", &u);
                if ((1 != num) || (u > 15)) {
                    pr2serr("Bad value after after 'pc=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->do_pc = u;
            } else if (0 == strncmp("mod=", cp, 4)) {
                num = sscanf(cp + 3, "%x", &u);
                if (1 != num) {
                    pr2serr("Bad value after 'mod=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->do_mod = u;
            } else if (0 == strncmp(cp, "noflush", 7)) {
                op->do_noflush = true;
            } else if (0 == strncmp(cp, "start", 5)) {
                if (startstop_set && (! startstop))
                    ambigu = true;
                else {
                    startstop = true;
                    startstop_set = true;
                }
            } else if (0 == strncmp(cp, "stop", 4)) {
                if (startstop_set && startstop)
                    ambigu = true;
                else {
                    startstop = false;
                    startstop_set = true;
                }
            } else if (0 == strncmp(cp, "old", 3))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp("0", cp)) {
            if (startstop_set && startstop)
                ambigu = true;
            else {
                startstop = false;
                startstop_set = true;
            }
        } else if (0 == strcmp("1", cp)) {
            if (startstop_set && (! startstop))
                ambigu = true;
            else {
                startstop = true;
                startstop_set = true;
            }
        } else if (0 == op->device_name)
                op->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not "
                    "expecting: %s\n", op->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
        if (ambigu) {
            pr2serr("please, only one of 0, 1, --eject, "
                    "--load, --start or --stop\n");
            usage_old();
            return SG_LIB_CONTRADICT;
        } else if (startstop_set) {
            if (startstop)
                op->do_start = true;
            else
                op->do_stop = true;
        }
    }
    return 0;
}

static int
parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = false;
        res = old_parse_cmd_line(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = new_parse_cmd_line(op, argc, argv);
    } else {
        op->opt_new = true;
        res = new_parse_cmd_line(op, argc, argv);
        if ((0 == res) && (! op->opt_new))
            res = old_parse_cmd_line(op, argc, argv);
    }
    return res;
}


int
main(int argc, char * argv[])
{
    int res;
    int sg_fd = -1;
    int ret = 0;
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->do_fl = -1;    /* only when >= 0 set FL bit */
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return res;
    if (op->do_help) {
        if (op->opt_new)
            usage();
        else
            usage_old();
        return 0;
    }

#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (op->verbose_given && op->version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->verbose = 0;
    } else if (! op->verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (op->verbose_given && op->version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }

    if (op->do_start && op->do_stop) {
        pr2serr("Ambiguous to give both '--start' and '--stop'\n");
        return SG_LIB_CONTRADICT;
    }
    if (op->do_load && op->do_eject) {
        pr2serr("Ambiguous to give both '--load' and '--eject'\n");
        return SG_LIB_CONTRADICT;
    }
    if (op->do_load)
       op->do_start = true;
    else if ((op->do_eject) || op->do_stop)
       op->do_start = false;
    else if (op->opt_new && op->do_loej && (! op->do_start))
        op->do_start = true;      /* --loej alone in new interface is load */
    else if ((! op->do_loej) && (-1 == op->do_fl) && (0 == op->do_pc))
       op->do_start = true;
    /* default action is to start when no other active options */

    if (0 == op->device_name) {
        pr2serr("No DEVICE argument given\n");
        if (op->opt_new)
            usage();
        else
            usage_old();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (op->do_fl >= 0) {
        if (! op->do_start) {
            pr2serr("Giving '--fl=FL' with '--stop' (or '--eject') is "
                    "invalid\n");
            return SG_LIB_CONTRADICT;
        }
        if (op->do_pc > 0) {
            pr2serr("Giving '--fl=FL' with '--pc=PC' when PC is non-zero "
                    "is invalid\n");
            return SG_LIB_CONTRADICT;
        }
    }

    sg_fd = sg_cmds_open_device(op->device_name, op->do_readonly,
                                op->verbose);
    if (sg_fd < 0) {
        if (op->verbose)
            pr2serr("Error trying to open %s: %s\n", op->device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    if (op->do_fl >= 0)
        res = sg_ll_start_stop_unit(sg_fd, op->do_immed, op->do_fl, 0 /* pc */,
                                    true /* fl */, true /* loej */,
                                    true /*start */, true /* noisy */,
                                    op->verbose);
    else if (op->do_pc > 0)
        res = sg_ll_start_stop_unit(sg_fd, op->do_immed, op->do_mod,
                                    op->do_pc, op->do_noflush, false, false,
                                    true, op->verbose);
    else
        res = sg_ll_start_stop_unit(sg_fd, op->do_immed, 0, false,
                                    op->do_noflush, op->do_loej,
                                    op->do_start, true, op->verbose);
    ret = res;
    if (res) {
        if (op->verbose < 2) {
            char b[80];

            sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
            pr2serr("%s\n", b);
        }
        pr2serr("START STOP UNIT command failed\n");
    }
fini:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_start failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
